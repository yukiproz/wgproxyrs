//! Proxy front-ends: SOCKS5 and HTTP CONNECT.
//!
//! Both are written against abstract async streams (`AsyncRead +
//! AsyncWrite`), so production uses `TcpStream`s from listeners while
//! tests can drive them over tokio duplex streams or real loopback
//! listeners. Both follow the same rule, with no exceptions:
//!
//! **Fail closed.** If the tunnel has no live handshake, a CONNECT gets a
//! failure reply (SOCKS5 REP / HTTP 502) and nothing is opened. Neither
//! front-end contains any code path to a direct socket — the only way out
//! is [`EngineHandle::open_stream`], which goes through the tunnel.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::stack::{EngineError, EngineHandle};

const SOCKS_VERSION: u8 = 5;
// SOCKS5 reply codes.
const REP_OK: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// A proxy target as requested by the client: either a literal socket
/// address, or a domain name + port to resolve through the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl Target {
    async fn resolve(&self, engine: &EngineHandle) -> Result<SocketAddr, EngineError> {
        match self {
            Target::Addr(addr) => Ok(*addr),
            Target::Domain(name, port) => {
                let ip = engine.resolve(name).await?;
                Ok(SocketAddr::new(ip, *port))
            }
        }
    }
}

fn rep_for(err: &EngineError) -> u8 {
    match err {
        EngineError::Down => REP_CONNECTION_REFUSED,
        EngineError::NotAllowed(_) => REP_NOT_ALLOWED,
        EngineError::ResolveFailed(_) => REP_HOST_UNREACHABLE,
        EngineError::Timeout => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    }
}

/// Relay bytes between the client stream and the engine channels until
/// either side closes. Half-close is honoured: when the client stops
/// sending, the engine sender drops (sending FIN through the tunnel) while
/// remaining inbound bytes are still delivered.
async fn relay<S>(
    stream: S,
    to_stack: mpsc::Sender<Vec<u8>>,
    mut from_stack: mpsc::Receiver<Vec<u8>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_stack.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Dropping to_stack here is what signals FIN to the engine.
    });

    let down = tokio::spawn(async move {
        while let Some(chunk) = from_stack.recv().await {
            if writer.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    // The session ends when the tunnel side closes (down). If the client
    // side ends first (up), give `down` a short grace period so trailing
    // bytes still land before everything is torn down.
    let mut up = up;
    let mut down = down;
    tokio::select! {
        _ = &mut down => {}
        _ = &mut up => {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut down).await;
        }
    }
    up.abort();
    down.abort();
}

/// Open the tunnel stream for a target, mapping engine errors to the
/// caller's protocol-specific failure reporting via `rep_for`.
async fn connect_target(
    engine: &EngineHandle,
    target: &Target,
) -> Result<(mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>), EngineError> {
    if !engine.is_up() {
        return Err(EngineError::Down);
    }
    let addr = target.resolve(engine).await?;
    engine.open_stream(addr).await
}

// ---------------------------------------------------------------------------
// SOCKS5.
// ---------------------------------------------------------------------------

async fn socks_reply<S>(stream: &mut S, rep: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
    let reply = [SOCKS_VERSION, rep, 0, 1, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await
}

/// Handle one SOCKS5 client connection (no-auth, CONNECT only).
pub async fn handle_socks5<S>(mut stream: S, engine: EngineHandle) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // --- greeting --------------------------------------------------------
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Ok(());
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // No acceptable methods (we only speak no-auth).
        stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        return Ok(());
    }
    stream.write_all(&[SOCKS_VERSION, 0x00]).await?;

    // --- request ---------------------------------------------------------
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS_VERSION {
        return Ok(());
    }
    if req[1] != 0x01 {
        // CMD: only CONNECT.
        socks_reply(&mut stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(());
    }
    let target = match req[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Target::Addr(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
            let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
            let name = String::from_utf8_lossy(&buf[..buf.len() - 2]).into_owned();
            Target::Domain(name, port)
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Target::Addr(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        _ => {
            socks_reply(&mut stream, REP_ATYP_NOT_SUPPORTED).await?;
            return Ok(());
        }
    };

    // --- connect through the tunnel (fail closed) -------------------------
    match connect_target(&engine, &target).await {
        Ok((to_stack, from_stack)) => {
            socks_reply(&mut stream, REP_OK).await?;
            relay(stream, to_stack, from_stack).await;
        }
        Err(e) => {
            socks_reply(&mut stream, rep_for(&e)).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP CONNECT.
// ---------------------------------------------------------------------------

async fn http_reply<S>(stream: &mut S, status: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(response.as_bytes()).await
}

fn parse_authority(authority: &str) -> Option<Target> {
    // [v6]:port or host:port or host (default 443 for CONNECT).
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let ip: IpAddr = host.parse().ok()?;
        let port: u16 = port.parse().ok()?;
        return Some(Target::Addr(SocketAddr::new(ip, port)));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 443),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        Some(Target::Addr(SocketAddr::new(ip, port)))
    } else if host.is_empty() {
        None
    } else {
        Some(Target::Domain(host.to_string(), port))
    }
}

/// Handle one HTTP client connection (CONNECT only).
pub async fn handle_http<S>(mut stream: S, engine: EngineHandle) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read request headers up to the blank line (bounded).
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") && buf.len() < 16384 {
        match stream.read(&mut byte).await? {
            0 => return Ok(()),
            _ => buf.push(byte[0]),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let first_line = text.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    if method != "CONNECT" {
        http_reply(&mut stream, "405 Method Not Allowed").await?;
        return Ok(());
    }
    let Some(target) = parse_authority(authority) else {
        http_reply(&mut stream, "400 Bad Request").await?;
        return Ok(());
    };

    match connect_target(&engine, &target).await {
        Ok((to_stack, from_stack)) => {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            relay(stream, to_stack, from_stack).await;
        }
        Err(_) => {
            http_reply(&mut stream, "502 Bad Gateway").await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listeners (production front doors).
// ---------------------------------------------------------------------------

/// Accept SOCKS5 connections forever. Spawned per connection.
pub async fn run_socks5_listener(listener: TcpListener, engine: EngineHandle) -> io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let engine = engine.clone();
        tokio::spawn(async move {
            let _ = handle_socks5(stream, engine).await;
        });
    }
}

/// Accept HTTP CONNECT connections forever. Spawned per connection.
pub async fn run_http_listener(listener: TcpListener, engine: EngineHandle) -> io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let engine = engine.clone();
        tokio::spawn(async move {
            let _ = handle_http(stream, engine).await;
        });
    }
}
