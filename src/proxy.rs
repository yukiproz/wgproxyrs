//! Proxy front-ends: SOCKS5 (CONNECT + UDP ASSOCIATE), HTTP CONNECT, and
//! fixed TCP tunnels.
//!
//! All are written against abstract async streams (`AsyncRead +
//! AsyncWrite`), so production uses `TcpStream`s from listeners while
//! tests can drive them over tokio duplex streams or real loopback
//! listeners. All follow the same rule, with no exceptions:
//!
//! **Fail closed.** If the tunnel has no live handshake, a CONNECT gets a
//! failure reply (SOCKS5 REP / HTTP 502), a UDP ASSOCIATE is refused, a
//! TCP-tunnel connection is dropped, and nothing is opened. No front-end
//! contains any code path to a direct socket — the only way out is
//! through [`EngineHandle`], which goes through the tunnel.
//!
//! Optional proxy authentication (RFC 1929 for SOCKS5, HTTP Basic for
//! CONNECT) is layered *in front of* the engine checks: passing auth
//! never bypasses the tunnel-state check.
//!
//! Not implemented (see ROADMAP.md): the SOCKS5 BIND command, plain-HTTP
//! forwarding (the HTTP listener is CONNECT-only by design), fragmented
//! UDP datagrams (RFC 1928: dropped), transparent/SNI proxying.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use crate::stack::{DatagramRx, DatagramTx, EngineError, EngineHandle};

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
pub enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl Target {
    /// Parse a `host:port` authority (host may be an IP or a domain;
    /// a bare host defaults to port 443, the CONNECT convention).
    pub fn parse(authority: &str) -> Option<Target> {
        parse_authority(authority)
    }

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

/// Username/password pair for proxy authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    pub user: String,
    pub pass: String,
}

impl ProxyAuth {
    /// Credential check (contents compared without early exit; lengths
    /// still leak through timing, which is acceptable for a local proxy).
    pub fn matches(&self, user: &str, pass: &str) -> bool {
        fn ct_eq(a: &[u8], b: &[u8]) -> bool {
            if a.len() != b.len() {
                return false;
            }
            a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
        }
        ct_eq(user.as_bytes(), self.user.as_bytes()) && ct_eq(pass.as_bytes(), self.pass.as_bytes())
    }

    /// Check an HTTP `Proxy-Authorization: Basic ...` header value.
    pub fn matches_basic_header(&self, value: &str) -> bool {
        let Some(b64) = value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))
        else {
            return false;
        };
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            return false;
        };
        let Ok(text) = String::from_utf8(raw) else {
            return false;
        };
        match text.split_once(':') {
            Some((u, p)) => self.matches(u, p),
            None => false,
        }
    }
}

impl std::fmt::Debug for ProxyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the password.
        f.debug_struct("ProxyAuth")
            .field("user", &self.user)
            .field("pass", &"<redacted>")
            .finish()
    }
}

/// Future returned by [`UdpRelayEnd::recv_from`].
pub type UdpRecvFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;
/// Future returned by [`UdpRelayEnd::send_to`].
pub type UdpSendFuture<'a> = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
/// Future returned by a [`UdpRelayFactory`] call.
pub type UdpRelayCreateFuture =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn UdpRelayEnd>>> + Send>>;

/// One end of a UDP relay: the socket (real or channel-backed in tests)
/// that exchanges datagrams with the proxy *client*. The tunnel side of
/// the relay lives in the engine; this trait is only the local leg.
pub trait UdpRelayEnd: Send {
    /// Address placed in the SOCKS5 UDP ASSOCIATE reply (BND.ADDR/PORT).
    fn local_addr(&self) -> SocketAddr;
    fn recv_from<'a>(&'a mut self, buf: &'a mut [u8]) -> UdpRecvFuture<'a>;
    fn send_to<'a>(&'a mut self, buf: &'a [u8], target: SocketAddr) -> UdpSendFuture<'a>;
}

/// Production relay end: a real tokio UDP socket.
struct TokioUdpEnd {
    socket: UdpSocket,
    local: SocketAddr,
}

impl UdpRelayEnd for TokioUdpEnd {
    fn local_addr(&self) -> SocketAddr {
        self.local
    }
    fn recv_from<'a>(&'a mut self, buf: &'a mut [u8]) -> UdpRecvFuture<'a> {
        Box::pin(self.socket.recv_from(buf))
    }
    fn send_to<'a>(&'a mut self, buf: &'a [u8], target: SocketAddr) -> UdpSendFuture<'a> {
        Box::pin(self.socket.send_to(buf, target))
    }
}

/// Creates a relay end for one UDP ASSOCIATE session. The argument is the
/// IP the relay should bind — the interface the client's control
/// connection arrived on, so the BND.ADDR in the reply is reachable.
pub type UdpRelayFactory = Arc<dyn Fn(IpAddr) -> UdpRelayCreateFuture + Send + Sync>;

fn real_udp_factory() -> UdpRelayFactory {
    Arc::new(|ip: IpAddr| {
        Box::pin(async move {
            let socket = UdpSocket::bind((ip, 0)).await?;
            let local = socket.local_addr()?;
            Ok(Box::new(TokioUdpEnd { socket, local }) as Box<dyn UdpRelayEnd>)
        })
    })
}

/// Shared front-end context: the engine, optional auth, and how to build
/// UDP relay ends. Listeners clone this per connection.
#[derive(Clone)]
pub struct ProxyCtx {
    pub engine: EngineHandle,
    pub auth: Option<ProxyAuth>,
    /// IP UDP relays bind to (set by the listener from its own address).
    pub relay_ip: IpAddr,
    pub udp_factory: UdpRelayFactory,
}

impl ProxyCtx {
    pub fn new(engine: EngineHandle) -> Self {
        Self {
            engine,
            auth: None,
            relay_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            udp_factory: real_udp_factory(),
        }
    }

    pub fn with_auth(mut self, auth: Option<ProxyAuth>) -> Self {
        self.auth = auth;
        self
    }

    pub fn with_udp_factory(mut self, factory: UdpRelayFactory) -> Self {
        self.udp_factory = factory;
        self
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

/// Reply carrying a real BND address (UDP ASSOCIATE tells the client
/// where to send its datagrams).
async fn socks_reply_bnd<S>(stream: &mut S, rep: u8, bnd: SocketAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = vec![SOCKS_VERSION, rep, 0];
    match bnd.ip() {
        IpAddr::V4(a) => {
            reply.push(1);
            reply.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            reply.push(4);
            reply.extend_from_slice(&a.octets());
        }
    }
    reply.extend_from_slice(&bnd.port().to_be_bytes());
    stream.write_all(&reply).await
}

/// Greeting + method negotiation. With auth configured, RFC 1929
/// username/password is required and the no-auth method is rejected;
/// without auth, no-auth is required as before. Returns false when the
/// connection should simply be closed (any failure reply has already
/// been sent).
async fn socks_negotiate<S>(stream: &mut S, ctx: &ProxyCtx) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Ok(false);
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    match &ctx.auth {
        None => {
            if !methods.contains(&0x00) {
                stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
                return Ok(false);
            }
            stream.write_all(&[SOCKS_VERSION, 0x00]).await?;
            Ok(true)
        }
        Some(auth) => {
            if !methods.contains(&0x02) {
                stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
                return Ok(false);
            }
            stream.write_all(&[SOCKS_VERSION, 0x02]).await?;
            // RFC 1929 subnegotiation: VER=1, ULEN, UNAME, PLEN, PASSWD.
            let mut sub = [0u8; 2];
            stream.read_exact(&mut sub).await?;
            if sub[0] != 0x01 {
                return Ok(false);
            }
            let mut uname = vec![0u8; sub[1] as usize];
            stream.read_exact(&mut uname).await?;
            let mut plen = [0u8; 1];
            stream.read_exact(&mut plen).await?;
            let mut passwd = vec![0u8; plen[0] as usize];
            stream.read_exact(&mut passwd).await?;
            let ok = String::from_utf8(uname)
                .ok()
                .zip(String::from_utf8(passwd).ok())
                .is_some_and(|(u, p)| auth.matches(&u, &p));
            stream
                .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
                .await?;
            Ok(ok)
        }
    }
}

/// Handle one SOCKS5 client connection: CONNECT and UDP ASSOCIATE.
pub async fn handle_socks5<S>(mut stream: S, ctx: ProxyCtx) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !socks_negotiate(&mut stream, &ctx).await? {
        return Ok(());
    }

    // --- request ---------------------------------------------------------
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS_VERSION {
        return Ok(());
    }
    let cmd = req[1];
    if cmd != 0x01 && cmd != 0x03 {
        // CMD: CONNECT and UDP ASSOCIATE only (BIND is not supported).
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

    match cmd {
        0x01 => {
            // --- connect through the tunnel (fail closed) -----------------
            match connect_target(&ctx.engine, &target).await {
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
        _ => udp_associate(stream, ctx).await,
    }
}

/// SOCKS5 UDP ASSOCIATE (RFC 1928). The request's DST fields — the
/// address the client expects to send datagrams *from*, usually zeroed —
/// have already been parsed by the caller and are ignored here: the
/// relay locks onto the source of the first datagram it receives.
///
/// Fail-closed: with no live handshake the associate is refused. The
/// session ends when the TCP control connection closes (RFC behaviour):
/// the engine flow is dropped, the netstack UDP socket is reaped, and
/// the local relay socket is released.
async fn udp_associate<S>(mut stream: S, ctx: ProxyCtx) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !ctx.engine.is_up() {
        socks_reply(&mut stream, REP_CONNECTION_REFUSED).await?;
        return Ok(());
    }
    let (to_tunnel, from_tunnel) = match ctx.engine.open_udp_flow().await {
        Ok(flow) => flow,
        Err(e) => {
            socks_reply(&mut stream, rep_for(&e)).await?;
            return Ok(());
        }
    };
    let relay_end = (ctx.udp_factory)(ctx.relay_ip).await?;
    socks_reply_bnd(&mut stream, REP_OK, relay_end.local_addr()).await?;
    udp_relay_session(
        stream,
        relay_end,
        ctx.engine.clone(),
        to_tunnel,
        from_tunnel,
    )
    .await;
    Ok(())
}

/// The UDP ASSOCIATE pump, split from the handshake so tests can drive
/// it with channel-backed relay ends. Runs until the control connection
/// ends or the engine flow dies.
///
/// Datagram rules: only the locked client's datagrams are relayed; the
/// SOCKS UDP header must have RSV=0 and FRAG=0 (fragmented datagrams are
/// dropped, per RFC 1928); domain targets are resolved through the
/// tunnel's DNS (replies then carry the responder's IP address).
/// Responses carry the responder's own address in their header.
pub async fn udp_relay_session<S>(
    control: S,
    mut relay_end: Box<dyn UdpRelayEnd>,
    engine: EngineHandle,
    to_tunnel: DatagramTx,
    mut from_tunnel: DatagramRx,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut control_reader, _control_writer) = tokio::io::split(control);
    let mut client: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65535];
    let mut control_buf = [0u8; 64];

    loop {
        tokio::select! {
            // The control connection governs the session's lifetime.
            read_result = control_reader.read(&mut control_buf) => {
                match read_result {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue, // stray bytes on the control conn: ignore
                }
            }
            recv_result = relay_end.recv_from(&mut buf) => {
                let (n, src) = match recv_result {
                    Ok(v) => v,
                    Err(_) => break,
                };
                match client {
                    None => client = Some(src),
                    Some(c) if c != src => continue, // not our client: drop
                    _ => {}
                }
                let Some((target, payload)) = parse_udp_header(&buf[..n]) else {
                    continue; // malformed / fragmented: drop silently
                };
                let dst = match target {
                    Target::Addr(addr) => addr,
                    Target::Domain(name, port) => {
                        match engine.resolve(&name).await {
                            Ok(ip) => SocketAddr::new(ip, port),
                            Err(_) => continue, // unresolvable: drop
                        }
                    }
                };
                if to_tunnel.send((dst, payload.to_vec())).await.is_err() {
                    break;
                }
            }
            incoming = from_tunnel.recv() => {
                let Some((src, payload)) = incoming else { break };
                let Some(dst) = client else { continue };
                let mut out = Vec::with_capacity(payload.len() + 22);
                out.extend_from_slice(&[0, 0, 0]); // RSV + FRAG=0
                match src.ip() {
                    IpAddr::V4(a) => {
                        out.push(1);
                        out.extend_from_slice(&a.octets());
                    }
                    IpAddr::V6(a) => {
                        out.push(4);
                        out.extend_from_slice(&a.octets());
                    }
                }
                out.extend_from_slice(&src.port().to_be_bytes());
                out.extend_from_slice(&payload);
                if relay_end.send_to(&out, dst).await.is_err() {
                    break;
                }
            }
        }
    }
    // Dropping `to_tunnel` (on return) ends the engine-side flow.
}

/// Parse a SOCKS5 UDP request header, returning the target and the
/// payload. `None` for malformed input, RSV != 0, or FRAG != 0
/// (fragments are never reassembled; RFC 1928 says drop them).
fn parse_udp_header(packet: &[u8]) -> Option<(Target, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }
    match packet[3] {
        0x01 => {
            if packet.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some((
                Target::Addr(SocketAddr::new(IpAddr::V4(ip), port)),
                &packet[10..],
            ))
        }
        0x03 => {
            let len = *packet.get(4)? as usize;
            if packet.len() < 7 + len {
                return None;
            }
            let name = String::from_utf8(packet[5..5 + len].to_vec()).ok()?;
            let port = u16::from_be_bytes([packet[5 + len], packet[6 + len]]);
            Some((Target::Domain(name, port), &packet[7 + len..]))
        }
        0x04 => {
            if packet.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            Some((
                Target::Addr(SocketAddr::new(IpAddr::V6(octets.into()), port)),
                &packet[22..],
            ))
        }
        _ => None,
    }
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
pub async fn handle_http<S>(mut stream: S, ctx: ProxyCtx) -> io::Result<()>
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
    let mut lines = text.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    if method != "CONNECT" {
        http_reply(&mut stream, "405 Method Not Allowed").await?;
        return Ok(());
    }

    // Proxy auth, before any tunnel work: a 407 here says nothing about
    // tunnel state, and passing auth does not skip the checks below.
    if let Some(auth) = &ctx.auth {
        let header = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("proxy-authorization")
                    .then_some(value.trim())
            })
            .next();
        let ok = header.is_some_and(|v| auth.matches_basic_header(v));
        if !ok {
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"wgproxyrs\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            return Ok(());
        }
    }

    let Some(target) = parse_authority(authority) else {
        http_reply(&mut stream, "400 Bad Request").await?;
        return Ok(());
    };

    match connect_target(&ctx.engine, &target).await {
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
// TCP tunnels (wireproxy's TCPClient equivalent).
// ---------------------------------------------------------------------------

/// Handle one TCP-tunnel connection: open the fixed target through the
/// tunnel and relay raw bytes — no proxy protocol on the local leg.
/// Fail-closed: while the tunnel is down or the target is outside
/// AllowedIPs the connection simply ends.
pub async fn handle_tcp_tunnel<S>(stream: S, target: Target, ctx: ProxyCtx) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Ok((to_stack, from_stack)) = connect_target(&ctx.engine, &target).await {
        relay(stream, to_stack, from_stack).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listeners (production front doors).
// ---------------------------------------------------------------------------

/// Accept SOCKS5 connections forever. Spawned per connection.
pub async fn run_socks5_listener(listener: TcpListener, mut ctx: ProxyCtx) -> io::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        ctx.relay_ip = addr.ip();
    }
    loop {
        let (stream, _peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle_socks5(stream, ctx).await;
        });
    }
}

/// Accept HTTP CONNECT connections forever. Spawned per connection.
pub async fn run_http_listener(listener: TcpListener, ctx: ProxyCtx) -> io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle_http(stream, ctx).await;
        });
    }
}

/// Accept TCP-tunnel connections forever, forwarding each to the fixed
/// target through the tunnel. Spawned per connection.
pub async fn run_tcp_tunnel_listener(
    listener: TcpListener,
    target: Target,
    ctx: ProxyCtx,
) -> io::Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let ctx = ctx.clone();
        let target = target.clone();
        tokio::spawn(async move {
            let _ = handle_tcp_tunnel(stream, target, ctx).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_parsing() {
        // IPv4 target, port 7777.
        let pkt = [0, 0, 0, 0x01, 10, 0, 0, 1, 0x1e, 0x61, b'h', b'i'];
        let (target, payload) = parse_udp_header(&pkt).unwrap();
        assert_eq!(
            target,
            Target::Addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                7777
            ))
        );
        assert_eq!(payload, b"hi");
        // Fragmented: dropped.
        let mut frag = pkt;
        frag[2] = 1;
        assert!(parse_udp_header(&frag).is_none());
        // Bad RSV: dropped.
        let mut rsv = pkt;
        rsv[0] = 1;
        assert!(parse_udp_header(&rsv).is_none());
        // Domain target.
        let mut dom = vec![0, 0, 0, 0x03, 9];
        dom.extend_from_slice(b"echo.test");
        dom.extend_from_slice(&53u16.to_be_bytes());
        dom.extend_from_slice(b"payload");
        let (target, payload) = parse_udp_header(&dom).unwrap();
        assert_eq!(target, Target::Domain("echo.test".into(), 53));
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn auth_matching() {
        let auth = ProxyAuth {
            user: "hadi".into(),
            pass: "s3cret".into(),
        };
        assert!(auth.matches("hadi", "s3cret"));
        assert!(!auth.matches("hadi", "wrong"));
        assert!(!auth.matches("nobody", "s3cret"));
        let header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("hadi:s3cret")
        );
        assert!(auth.matches_basic_header(&header));
        let bad = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("hadi:nope")
        );
        assert!(!auth.matches_basic_header(&bad));
        assert!(!auth.matches_basic_header("Bearer xyz"));
    }
}
