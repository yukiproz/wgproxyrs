//! End-to-end tests: SOCKS5/HTTP -> proxy -> smoltcp -> WireGuard tunnel
//! -> peer smoltcp stack -> echo services, and back.
//!
//! The peer is a *second* boringtun instance (responder role) plus a
//! second smoltcp stack hosting a TCP echo service, a UDP echo service
//! and a tiny UDP DNS responder. Client and peer are linked by the
//! in-memory transport, so these tests run in environments where UDP is
//! entirely blocked — except the `udp_loopback_*` tests, which are
//! `#[ignore]`d and run explicitly in CI (`cargo test -- --ignored`).
//!
//! Phase 3 coverage on top of the v0.1 set: multi-peer cryptokey
//! routing, SOCKS5 UDP ASSOCIATE (echo + DNS-shaped traffic, fragments
//! dropped, control-connection lifetime), TCP tunnels, proxy auth (both
//! protocols; auth never bypasses fail-closed), and the info endpoint's
//! truthfulness (up after handshake, down when the peer is dead).

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant as StdInstant};

use base64::Engine as _;
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::OsRng;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;

use wgproxyrs::config::Cidr;
use wgproxyrs::info::{run_info_listener, status_is_up};
use wgproxyrs::proxy::{
    ProxyAuth, ProxyCtx, Target, UdpRecvFuture, UdpRelayEnd, UdpRelayFactory, UdpSendFuture,
    run_http_listener, run_socks5_listener, run_tcp_tunnel_listener,
};
use wgproxyrs::stack::{EngineConfig, EngineHandle, PacketDevice, PeerTunnel, spawn_engine};
use wgproxyrs::tunnel::{Transport, UdpTransport, WgTunnel, memory_pair};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ECHO_PORT: u16 = 7777;
const UDP_ECHO_PORT: u16 = 7778;
const PAYLOAD: &[u8] = b"hello wgproxyrs, through the tunnel!";

fn keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn smol_now(epoch: StdInstant) -> SmolInstant {
    SmolInstant::from_millis(epoch.elapsed().as_millis() as i64)
}

// ---------------------------------------------------------------------------
// Peer harness (test code only).
// ---------------------------------------------------------------------------

fn spawn_peer(
    peer_priv: [u8; 32],
    client_pub: [u8; 32],
    transport: Box<dyn Transport>,
    stop: Arc<AtomicBool>,
    peer_ip: Ipv4Addr,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("wgproxyrs-test-peer".into())
        .spawn(move || {
            let epoch = StdInstant::now();
            let mut tunn = WgTunnel::new(peer_priv, client_pub, None, None, transport);
            let mut device = PacketDevice::default();
            let mut iface = Interface::new(
                Config::new(HardwareAddress::Ip),
                &mut device,
                smol_now(epoch),
            );
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(peer_ip.into(), 32));
            });
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);

            let mut sockets = SocketSet::new(Vec::new());
            let mut echo_sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 16384]),
                tcp::SocketBuffer::new(vec![0u8; 16384]),
            );
            echo_sock.listen(ECHO_PORT).expect("peer echo listen");
            let echo_handle = sockets.add(echo_sock);

            let mut dns_sock = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]),
            );
            dns_sock.bind(53).expect("peer dns bind");
            let dns_handle = sockets.add(dns_sock);

            let mut udp_echo_sock = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16384]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 16384]),
            );
            udp_echo_sock
                .bind(UDP_ECHO_PORT)
                .expect("peer udp echo bind");
            let udp_echo_handle = sockets.add(udp_echo_sock);

            let mut staging: VecDeque<u8> = VecDeque::new();
            let mut inbound: Vec<Vec<u8>> = Vec::new();

            while !stop.load(Ordering::Relaxed) {
                inbound.clear();
                tunn.poll(&mut inbound);
                for packet in inbound.drain(..) {
                    device.push_rx(packet);
                }
                iface.poll(smol_now(epoch), &mut device, &mut sockets);
                for packet in device.drain_tx() {
                    tunn.encapsulate_ip(&packet);
                }

                // TCP echo.
                let sock = sockets.get_mut::<tcp::Socket>(echo_handle);
                while sock.can_recv() {
                    let mut buf = [0u8; 4096];
                    match sock.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => staging.extend(&buf[..n]),
                        _ => break,
                    }
                }
                while sock.can_send() && !staging.is_empty() {
                    let (front, _) = staging.as_slices();
                    match sock.send_slice(front) {
                        Ok(n) => {
                            staging.drain(..n);
                        }
                        Err(_) => break,
                    }
                }

                // DNS responder.
                let sock = sockets.get_mut::<udp::Socket>(dns_handle);
                if let Ok((data, meta)) = sock.recv() {
                    let query = data.to_vec();
                    let remote = meta.endpoint;
                    if let Some(response) = build_dns_response(&query, peer_ip) {
                        let _ = sock.send_slice(&response, remote);
                    }
                }

                // UDP echo.
                let sock = sockets.get_mut::<udp::Socket>(udp_echo_handle);
                while sock.can_recv() {
                    match sock.recv() {
                        Ok((data, meta)) => {
                            let payload = data.to_vec();
                            let _ = sock.send_slice(&payload, meta.endpoint);
                        }
                        Err(_) => break,
                    }
                }

                std::thread::sleep(Duration::from_millis(1));
            }
        })
        .expect("spawn peer thread")
}

/// Minimal DNS responder: answers A queries for `echo.test` with the
/// given peer address, NXDOMAIN for everything else.
fn build_dns_response(query: &[u8], answer: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // Parse the question section, collecting the queried name.
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *query.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        let label = query.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }
    let question_end = pos + 4; // QTYPE + QCLASS
    if query.len() < question_end {
        return None;
    }
    let name = labels.join(".");
    let known = name == "echo.test";

    let mut resp = Vec::with_capacity(question_end + 16);
    resp.extend_from_slice(&query[0..2]); // transaction id
    if known {
        resp.extend_from_slice(&[0x81, 0x80]); // QR, RD, RA; RCODE=0
    } else {
        resp.extend_from_slice(&[0x81, 0x83]); // RCODE=3 (NXDOMAIN)
    }
    resp.extend_from_slice(&[0, 1]); // QDCOUNT
    resp.extend_from_slice(if known { &[0, 1] } else { &[0, 0] }); // ANCOUNT
    resp.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT + ARCOUNT
    resp.extend_from_slice(&query[12..question_end]); // question, verbatim
    if known {
        resp.extend_from_slice(&[0xC0, 0x0C]); // name -> offset 12
        resp.extend_from_slice(&[0, 1]); // TYPE A
        resp.extend_from_slice(&[0, 1]); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&[0, 4]); // RDLENGTH
        resp.extend_from_slice(&answer.octets());
    }
    Some(resp)
}

// ---------------------------------------------------------------------------
// Harness assembly.
// ---------------------------------------------------------------------------

struct Harness {
    engine: EngineHandle,
    engine_thread: Option<std::thread::JoinHandle<()>>,
    peer_stop: Arc<AtomicBool>,
    peer_thread: Option<std::thread::JoinHandle<()>>,
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    info_addr: Option<SocketAddr>,
    socks_task: tokio::task::JoinHandle<()>,
    http_task: tokio::task::JoinHandle<()>,
    info_task: Option<tokio::task::JoinHandle<()>>,
}

/// Front-end variations a test can ask the harness for.
#[derive(Default)]
struct HarnessOpts {
    auth: Option<ProxyAuth>,
    udp_factory: Option<UdpRelayFactory>,
    with_info: bool,
}

/// Engine whose peer never answers: the "other end" of the transport is
/// dropped, so no handshake can ever complete.
fn dead_engine() -> (EngineHandle, std::thread::JoinHandle<()>) {
    let (client_priv, _client_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let (mem_a, mem_b) = memory_pair();
    drop(mem_b);
    let tunnel = WgTunnel::new(client_priv, peer_pub, None, None, Box::new(mem_a));
    spawn_engine(
        vec![PeerTunnel {
            tunnel,
            allowed_ips: vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix: 0,
            }],
            endpoint: "absent-peer".to_string(),
        }],
        EngineConfig {
            addresses: vec![Cidr {
                addr: IpAddr::V4(CLIENT_IP),
                prefix: 32,
            }],
            dns_servers: vec![IpAddr::V4(PEER_IP)],
        },
    )
}

fn harness_ctx(engine: &EngineHandle, opts: &HarnessOpts) -> ProxyCtx {
    let mut ctx = ProxyCtx::new(engine.clone());
    if let Some(auth) = &opts.auth {
        ctx = ctx.with_auth(Some(auth.clone()));
    }
    if let Some(factory) = &opts.udp_factory {
        ctx = ctx.with_udp_factory(factory.clone());
    }
    ctx
}

async fn start_harness_with(
    make_transports: impl FnOnce(
        SocketAddr,
        SocketAddr,
    ) -> (
        Box<dyn Transport>,
        Box<dyn Transport>,
        SocketAddr,
        SocketAddr,
    ),
    opts: HarnessOpts,
) -> Harness {
    let (client_priv, client_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();

    // Placeholder addresses; memory transports ignore them, the UDP
    // variant fills in real ones below via the closure's return.
    let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let (client_transport, peer_transport, _a, _b) = make_transports(any, any);

    let peer_stop = Arc::new(AtomicBool::new(false));
    let peer_thread = spawn_peer(
        peer_priv,
        client_pub,
        peer_transport,
        peer_stop.clone(),
        PEER_IP,
    );

    let client_tunnel = WgTunnel::new(client_priv, peer_pub, None, None, client_transport);
    let (engine, engine_thread) = spawn_engine(
        vec![PeerTunnel {
            tunnel: client_tunnel,
            allowed_ips: vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix: 0,
            }],
            endpoint: "memory-peer".to_string(),
        }],
        EngineConfig {
            addresses: vec![Cidr {
                addr: IpAddr::V4(CLIENT_IP),
                prefix: 32,
            }],
            dns_servers: vec![IpAddr::V4(PEER_IP)],
        },
    );

    let ctx = harness_ctx(&engine, &opts);

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_ctx = ctx.clone();
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, socks_ctx).await;
    });

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_ctx = ctx.clone();
    let http_task = tokio::spawn(async move {
        let _ = run_http_listener(http_listener, http_ctx).await;
    });

    let (info_addr, info_task) = if opts.with_info {
        let info_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = info_listener.local_addr().unwrap();
        let info_engine = engine.clone();
        let task = tokio::spawn(async move {
            let _ = run_info_listener(info_listener, info_engine).await;
        });
        (Some(addr), Some(task))
    } else {
        (None, None)
    };

    Harness {
        engine,
        engine_thread: Some(engine_thread),
        peer_stop,
        peer_thread: Some(peer_thread),
        socks_addr,
        http_addr,
        info_addr,
        socks_task,
        http_task,
        info_task,
    }
}

async fn start_memory_harness_with(opts: HarnessOpts) -> Harness {
    start_harness_with(
        |_, _| {
            let (a, b) = memory_pair();
            let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            (Box::new(a), Box::new(b), any, any)
        },
        opts,
    )
    .await
}

async fn start_memory_harness() -> Harness {
    start_memory_harness_with(HarnessOpts::default()).await
}

impl Harness {
    async fn wait_up(&self) {
        let deadline = StdInstant::now() + Duration::from_secs(15);
        while !self.engine.is_up() {
            assert!(
                StdInstant::now() < deadline,
                "tunnel did not come up within 15s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn shutdown(mut self) {
        self.engine.stop();
        self.peer_stop.store(true, Ordering::Relaxed);
        self.socks_task.abort();
        self.http_task.abort();
        if let Some(t) = self.info_task.take() {
            t.abort();
        }
        if let Some(t) = self.engine_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.peer_thread.take() {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 client helpers.
// ---------------------------------------------------------------------------

async fn socks5_handshake(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0], "no-auth must be selected");
}

async fn read_socks_reply(stream: &mut TcpStream) -> u8 {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 5);
    let rep = head[1];
    // Consume BND.ADDR + BND.PORT per ATYP.
    match head[3] {
        1 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.unwrap();
        }
        4 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await.unwrap();
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            let mut rest = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut rest).await.unwrap();
        }
        other => panic!("unexpected ATYP in reply: {other}"),
    }
    rep
}

async fn echo_roundtrip(stream: &mut TcpStream) {
    stream.write_all(PAYLOAD).await.unwrap();
    let mut buf = vec![0u8; PAYLOAD.len()];
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(read, PAYLOAD.len());
    assert_eq!(buf, PAYLOAD, "bytes must come back identical");
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_socks5_ipv4_echo() {
    let harness = start_memory_harness().await;
    harness.wait_up().await;

    let mut stream = TcpStream::connect(harness.socks_addr).await.unwrap();
    socks5_handshake(&mut stream).await;
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&PEER_IP.octets());
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_eq!(rep, 0, "SOCKS5 CONNECT must succeed through the tunnel");
    echo_roundtrip(&mut stream).await;

    // Evidence: real payload crossed the encrypted tunnel both ways.
    let status = harness.engine.status();
    assert!(status.up && status.handshake_age.is_some());

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn e2e_socks5_domain_echo() {
    let harness = start_memory_harness().await;
    harness.wait_up().await;

    let mut stream = TcpStream::connect(harness.socks_addr).await.unwrap();
    socks5_handshake(&mut stream).await;
    let name = b"echo.test";
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_eq!(
        rep, 0,
        "domain CONNECT must resolve via in-tunnel DNS and connect"
    );
    echo_roundtrip(&mut stream).await;

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn e2e_http_connect_echo() {
    let harness = start_memory_harness().await;
    harness.wait_up().await;

    let mut stream = TcpStream::connect(harness.http_addr).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {PEER_IP}:{ECHO_PORT} HTTP/1.1\r\nHost: {PEER_IP}:{ECHO_PORT}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "HTTP CONNECT must succeed, got: {head}"
    );
    echo_roundtrip(&mut stream).await;

    drop(stream);
    harness.shutdown();
}

#[tokio::test]
async fn fail_closed_when_peer_absent() {
    // Client engine whose transport leads nowhere: the peer end is
    // dropped, no handshake can ever complete.
    let (engine, engine_thread) = dead_engine();
    // Give the engine a moment to (fail to) handshake.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!engine.is_up(), "tunnel must be down without a peer");

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_ctx = ProxyCtx::new(engine.clone());
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, socks_ctx).await;
    });

    let mut stream = TcpStream::connect(socks_addr).await.unwrap();
    socks5_handshake(&mut stream).await;
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&PEER_IP.octets());
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_ne!(rep, 0, "CONNECT with a dead tunnel must fail closed");
    drop(stream);

    // UDP ASSOCIATE must fail closed too.
    let mut stream = TcpStream::connect(socks_addr).await.unwrap();
    socks5_handshake(&mut stream).await;
    stream
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_ne!(rep, 0, "UDP ASSOCIATE with a dead tunnel must fail closed");
    drop(stream);

    // HTTP front-end must fail closed too (502).
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_ctx = ProxyCtx::new(engine.clone());
    let http_task = tokio::spawn(async move {
        let _ = run_http_listener(http_listener, http_ctx).await;
    });
    let mut stream = TcpStream::connect(http_addr).await.unwrap();
    stream
        .write_all(format!("CONNECT {PEER_IP}:{ECHO_PORT} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 502"),
        "HTTP CONNECT with a dead tunnel must be 502, got: {head}"
    );
    drop(stream);

    engine.stop();
    socks_task.abort();
    http_task.abort();
    let _ = engine_thread.join();
}

/// Real-UDP variant: two UdpTransports on loopback. Ignored by default
/// because Yuki's VM blocks all UDP sends (even loopback); CI runs it
/// explicitly with `cargo test -- --ignored`.
#[tokio::test]
#[ignore = "needs working UDP loopback; run via `cargo test -- --ignored`"]
async fn udp_loopback_e2e() {
    // Reserve two loopback ports, then hand them to the transports.
    let probe_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let probe_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr_a = probe_a.local_addr().unwrap();
    let addr_b = probe_b.local_addr().unwrap();
    drop(probe_a);
    drop(probe_b);

    let harness = start_harness_with(
        |_, _| {
            let client_t = UdpTransport::new(addr_a, addr_b).unwrap();
            let peer_t = UdpTransport::new(addr_b, addr_a).unwrap();
            (Box::new(client_t), Box::new(peer_t), addr_a, addr_b)
        },
        HarnessOpts::default(),
    )
    .await;
    harness.wait_up().await;

    let mut stream = TcpStream::connect(harness.socks_addr).await.unwrap();
    socks5_handshake(&mut stream).await;
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&PEER_IP.octets());
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_eq!(rep, 0);
    echo_roundtrip(&mut stream).await;

    drop(stream);
    harness.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 3 helpers.
// ---------------------------------------------------------------------------

/// SOCKS5 (no-auth) CONNECT to an IPv4 target; returns the stream and the
/// REP code.
async fn socks5_connect(socks_addr: SocketAddr, target: Ipv4Addr, port: u16) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(socks_addr).await.unwrap();
    socks5_handshake(&mut stream).await;
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&target.octets());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    (stream, rep)
}

/// SOCKS5 greeting offering only username/password auth (RFC 1929),
/// then the subnegotiation; returns (stream, auth status byte).
async fn socks5_auth_negotiate(socks_addr: SocketAddr, user: &str, pass: &str) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(socks_addr).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 2], "server must select username/password auth");
    let mut sub = vec![1, user.len() as u8];
    sub.extend_from_slice(user.as_bytes());
    sub.push(pass.len() as u8);
    sub.extend_from_slice(pass.as_bytes());
    stream.write_all(&sub).await.unwrap();
    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await.unwrap();
    assert_eq!(auth_resp[0], 1, "auth subnegotiation version");
    (stream, auth_resp[1])
}

fn test_auth() -> ProxyAuth {
    ProxyAuth {
        user: "hadi".into(),
        pass: "s3cret".into(),
    }
}

fn basic_header(user_pass: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(user_pass)
    )
}

/// GET the info endpoint and return its JSON body.
async fn http_get_info(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .unwrap();
    let mut raw = String::new();
    timeout(Duration::from_secs(10), stream.read_to_string(&mut raw))
        .await
        .expect("info response timed out")
        .unwrap();
    let (_, body) = raw
        .split_once("\r\n\r\n")
        .expect("HTTP response has a body");
    body.trim().to_string()
}

/// A DNS query packet for `echo.test` (A record), ID 0x4242.
fn dns_query() -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&[0x42, 0x42]); // ID
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["echo", "test"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    q
}

/// Build a SOCKS5 UDP datagram: header for (ip, port) + payload.
fn socks_udp_packet(ip: Ipv4Addr, port: u16, payload: &[u8], frag: u8) -> Vec<u8> {
    let mut pkt = vec![0, 0, frag, 1];
    pkt.extend_from_slice(&ip.octets());
    pkt.extend_from_slice(&port.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

// ---------------------------------------------------------------------------
// Phase 3: multi-peer cryptokey routing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_peer_cryptokey_routing() {
    let (client_priv, client_pub) = keypair();
    let (peer1_priv, peer1_pub) = keypair();
    let (peer2_priv, peer2_pub) = keypair();
    let peer1_ip = Ipv4Addr::new(10, 0, 1, 1);
    let peer2_ip = Ipv4Addr::new(10, 0, 2, 1);

    let (c1, s1) = memory_pair();
    let (c2, s2) = memory_pair();
    let stop = Arc::new(AtomicBool::new(false));
    let peer1_thread = spawn_peer(peer1_priv, client_pub, Box::new(s1), stop.clone(), peer1_ip);
    let peer2_thread = spawn_peer(peer2_priv, client_pub, Box::new(s2), stop.clone(), peer2_ip);

    let (engine, engine_thread) = spawn_engine(
        vec![
            PeerTunnel {
                tunnel: WgTunnel::new(client_priv, peer1_pub, None, None, Box::new(c1)),
                allowed_ips: vec![Cidr {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
                    prefix: 24,
                }],
                endpoint: "peer-one".to_string(),
            },
            PeerTunnel {
                tunnel: WgTunnel::new(client_priv, peer2_pub, None, None, Box::new(c2)),
                allowed_ips: vec![Cidr {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 0)),
                    prefix: 24,
                }],
                endpoint: "peer-two".to_string(),
            },
        ],
        EngineConfig {
            addresses: vec![
                Cidr {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
                    prefix: 32,
                },
                Cidr {
                    addr: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)),
                    prefix: 32,
                },
            ],
            dns_servers: vec![],
        },
    );

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let ctx = ProxyCtx::new(engine.clone());
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, ctx).await;
    });

    // Both peers must complete their handshakes.
    timeout(Duration::from_secs(20), async {
        loop {
            let status = engine.status();
            if status.peers.len() == 2 && status.peers.iter().all(|p| p.up) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("both peers should come up");

    // Each subnet is served by its own peer's echo service.
    let (mut s1, rep) = socks5_connect(socks_addr, peer1_ip, ECHO_PORT).await;
    assert_eq!(rep, 0, "peer 1's subnet must connect");
    echo_roundtrip(&mut s1).await;
    let (mut s2, rep) = socks5_connect(socks_addr, peer2_ip, ECHO_PORT).await;
    assert_eq!(rep, 0, "peer 2's subnet must connect");
    echo_roundtrip(&mut s2).await;

    // A destination owned by neither peer is refused.
    let (_s3, rep) = socks5_connect(socks_addr, Ipv4Addr::new(10, 0, 3, 1), ECHO_PORT).await;
    assert_ne!(
        rep, 0,
        "destination in no peer's AllowedIPs must be refused"
    );

    engine.stop();
    stop.store(true, Ordering::Relaxed);
    socks_task.abort();
    let _ = engine_thread.join();
    let _ = peer1_thread.join();
    let _ = peer2_thread.join();
}

// ---------------------------------------------------------------------------
// Phase 3: SOCKS5 UDP ASSOCIATE over a channel-backed relay end.
// ---------------------------------------------------------------------------

/// Channel-backed relay end: the test plays the role of the client's
/// UDP socket, because this host blocks real UDP entirely.
struct ChannelUdpEnd {
    local: SocketAddr,
    inbound: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    outbound: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl UdpRelayEnd for ChannelUdpEnd {
    fn local_addr(&self) -> SocketAddr {
        self.local
    }
    fn recv_from<'a>(&'a mut self, buf: &'a mut [u8]) -> UdpRecvFuture<'a> {
        Box::pin(async move {
            match self.inbound.recv().await {
                Some((data, src)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, src))
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "channel closed",
                )),
            }
        })
    }
    fn send_to<'a>(&'a mut self, buf: &'a [u8], target: SocketAddr) -> UdpSendFuture<'a> {
        let data = buf.to_vec();
        Box::pin(async move {
            let len = data.len();
            self.outbound
                .send((data, target))
                .await
                .map(|_| len)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"))
        })
    }
}

struct UdpChannels {
    factory: UdpRelayFactory,
    client_send: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    client_recv: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

/// One-shot factory plumbing: the relay end gets the inbound/outbound
/// channel halves; the test keeps the client halves.
fn udp_channels(local: SocketAddr) -> UdpChannels {
    let (client_send, relay_inbound) = mpsc::channel::<(Vec<u8>, SocketAddr)>(32);
    let (relay_outbound, client_recv) = mpsc::channel::<(Vec<u8>, SocketAddr)>(32);
    let slot = Arc::new(Mutex::new(Some((relay_inbound, relay_outbound))));
    let factory: UdpRelayFactory = Arc::new(move |_ip| {
        let slot = slot.clone();
        Box::pin(async move {
            let (inbound, outbound) = slot
                .lock()
                .unwrap()
                .take()
                .expect("channel factory used at most once per test");
            Ok(Box::new(ChannelUdpEnd {
                local,
                inbound,
                outbound,
            }) as Box<dyn UdpRelayEnd>)
        })
    });
    UdpChannels {
        factory,
        client_send,
        client_recv,
    }
}

#[tokio::test]
async fn socks5_udp_associate_echo_and_dns() {
    let relay_local: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    let channels = udp_channels(relay_local);
    let UdpChannels {
        factory,
        client_send,
        mut client_recv,
    } = channels;
    let harness = start_memory_harness_with(HarnessOpts {
        udp_factory: Some(factory),
        ..Default::default()
    })
    .await;
    harness.wait_up().await;

    // Open the control connection and send UDP ASSOCIATE.
    let mut control = TcpStream::connect(harness.socks_addr).await.unwrap();
    socks5_handshake(&mut control).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    // Read the reply manually: BND must be the relay end's address.
    let mut head = [0u8; 4];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 5);
    assert_eq!(
        head[1], 0,
        "UDP ASSOCIATE must succeed while the tunnel is up"
    );
    assert_eq!(head[3], 1, "BND must be IPv4");
    let mut bnd = [0u8; 6];
    control.read_exact(&mut bnd).await.unwrap();
    let bnd_addr = SocketAddr::from((
        [bnd[0], bnd[1], bnd[2], bnd[3]],
        u16::from_be_bytes([bnd[4], bnd[5]]),
    ));
    assert_eq!(bnd_addr, relay_local, "BND must be the relay's address");

    let client_udp: SocketAddr = "127.0.0.1:50000".parse().unwrap();

    // 1) UDP echo round trip, byte-identical payload.
    let payload = b"udp echo through the tunnel".to_vec();
    client_send
        .send((
            socks_udp_packet(PEER_IP, UDP_ECHO_PORT, &payload, 0),
            client_udp,
        ))
        .await
        .unwrap();
    let (resp_pkt, resp_dst) = timeout(Duration::from_secs(15), client_recv.recv())
        .await
        .expect("UDP echo timed out")
        .unwrap();
    assert_eq!(resp_dst, client_udp, "reply must go to the client");
    assert_eq!(&resp_pkt[0..3], &[0, 0, 0], "RSV/FRAG must be zero");
    assert_eq!(resp_pkt[3], 1);
    assert_eq!(
        &resp_pkt[4..8],
        &PEER_IP.octets(),
        "reply source must be the echo server"
    );
    assert_eq!(
        u16::from_be_bytes([resp_pkt[8], resp_pkt[9]]),
        UDP_ECHO_PORT
    );
    assert_eq!(
        &resp_pkt[10..],
        payload.as_slice(),
        "payload must be byte-identical"
    );

    // 2) DNS-shaped round trip through the same association.
    let query = dns_query();
    client_send
        .send((socks_udp_packet(PEER_IP, 53, &query, 0), client_udp))
        .await
        .unwrap();
    let (resp_pkt, _) = timeout(Duration::from_secs(15), client_recv.recv())
        .await
        .expect("DNS round trip timed out")
        .unwrap();
    assert_eq!(u16::from_be_bytes([resp_pkt[8], resp_pkt[9]]), 53);
    let dns_resp = &resp_pkt[10..];
    assert_eq!(
        &dns_resp[0..2],
        &[0x42, 0x42],
        "DNS response ID must match the query"
    );
    assert!(
        dns_resp.ends_with(&PEER_IP.octets()),
        "DNS answer must be the peer's A record"
    );

    // 3) A fragmented datagram (FRAG=1) is dropped — no reply at all.
    client_send
        .send((
            socks_udp_packet(PEER_IP, UDP_ECHO_PORT, b"fragment", 1),
            client_udp,
        ))
        .await
        .unwrap();
    let dropped = timeout(Duration::from_millis(700), client_recv.recv()).await;
    assert!(
        dropped.is_err(),
        "fragmented datagrams must be dropped, not answered"
    );

    // 4) Closing the control connection ends the session. Proof can
    // take three shapes, all fine: the send itself fails (the relay
    // end is already dropped), the reply channel closes (same), or the
    // datagram is swallowed silently. A reply is the only failure.
    drop(control);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = client_send
        .send((
            socks_udp_packet(PEER_IP, UDP_ECHO_PORT, b"after close", 0),
            client_udp,
        ))
        .await;
    match timeout(Duration::from_millis(700), client_recv.recv()).await {
        Err(_) => {}   // timed out: nothing answered
        Ok(None) => {} // channel closed: the relay end is gone
        Ok(Some(pkt)) => panic!("relay answered after control close: {pkt:?}"),
    }

    harness.shutdown();
}

// ---------------------------------------------------------------------------
// Phase 3: TCP tunnels.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_tunnel_forwards_without_proxy_protocol() {
    let harness = start_memory_harness().await;
    harness.wait_up().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = listener.local_addr().unwrap();
    let ctx = ProxyCtx::new(harness.engine.clone());
    let task = tokio::spawn(async move {
        let _ = run_tcp_tunnel_listener(
            listener,
            Target::Addr(SocketAddr::new(IpAddr::V4(PEER_IP), ECHO_PORT)),
            ctx,
        )
        .await;
    });
    // No proxy bytes at all: connect, write, read the echo back.
    let mut stream = TcpStream::connect(tunnel_addr).await.unwrap();
    echo_roundtrip(&mut stream).await;
    drop(stream);
    task.abort();
    harness.shutdown();
}

#[tokio::test]
async fn tcp_tunnel_fail_closed() {
    let (engine, engine_thread) = dead_engine();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!engine.is_up());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tunnel_addr = listener.local_addr().unwrap();
    let ctx = ProxyCtx::new(engine.clone());
    let task = tokio::spawn(async move {
        let _ = run_tcp_tunnel_listener(
            listener,
            Target::Addr(SocketAddr::new(IpAddr::V4(PEER_IP), ECHO_PORT)),
            ctx,
        )
        .await;
    });
    let mut stream = TcpStream::connect(tunnel_addr).await.unwrap();
    stream.write_all(b"must never arrive").await.unwrap();
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("fail-closed connection must end promptly")
        .unwrap_or(0);
    assert_eq!(n, 0, "tunnel must refuse (EOF) while the tunnel is down");
    drop(stream);
    task.abort();
    engine.stop();
    let _ = engine_thread.join();
}

// ---------------------------------------------------------------------------
// Phase 3: proxy authentication.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_auth_required() {
    let harness = start_memory_harness_with(HarnessOpts {
        auth: Some(test_auth()),
        ..Default::default()
    })
    .await;
    harness.wait_up().await;

    // No-auth method is rejected when auth is configured.
    let mut stream = TcpStream::connect(harness.socks_addr).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [5, 0xFF], "no-auth must be rejected when auth is on");
    drop(stream);

    // Wrong password: auth status != 0, connection dropped.
    let (mut stream, status) = socks5_auth_negotiate(harness.socks_addr, "hadi", "wrong").await;
    assert_ne!(status, 0, "wrong password must fail auth");
    let mut byte = [0u8; 1];
    let closed = timeout(Duration::from_secs(5), stream.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "failed auth must close the connection"
    );
    drop(stream);

    // Right credentials: CONNECT + echo succeed.
    let (mut stream, status) = socks5_auth_negotiate(harness.socks_addr, "hadi", "s3cret").await;
    assert_eq!(status, 0, "correct credentials must pass auth");
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&PEER_IP.octets());
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_eq!(rep, 0, "CONNECT after good auth must succeed");
    echo_roundtrip(&mut stream).await;
    drop(stream);

    harness.shutdown();
}

#[tokio::test]
async fn http_proxy_auth_required() {
    let harness = start_memory_harness_with(HarnessOpts {
        auth: Some(test_auth()),
        ..Default::default()
    })
    .await;
    harness.wait_up().await;

    async fn http_connect_status(
        http_addr: SocketAddr,
        auth_header: Option<String>,
    ) -> (TcpStream, String) {
        let mut stream = TcpStream::connect(http_addr).await.unwrap();
        let mut req =
            format!("CONNECT {PEER_IP}:{ECHO_PORT} HTTP/1.1\r\nHost: {PEER_IP}:{ECHO_PORT}\r\n");
        if let Some(v) = auth_header {
            req.push_str(&format!("Proxy-Authorization: {v}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            line.push(byte[0]);
        }
        (stream, String::from_utf8_lossy(&line).into_owned())
    }

    // No credentials -> 407; wrong credentials -> 407.
    let (_s, line) = http_connect_status(harness.http_addr, None).await;
    assert!(
        line.starts_with("HTTP/1.1 407"),
        "missing auth must 407, got: {line}"
    );
    let (_s, line) = http_connect_status(harness.http_addr, Some(basic_header("hadi:nope"))).await;
    assert!(
        line.starts_with("HTTP/1.1 407"),
        "wrong auth must 407, got: {line}"
    );

    // Right credentials -> 200 and a working tunnel.
    let (mut stream, line) =
        http_connect_status(harness.http_addr, Some(basic_header("hadi:s3cret"))).await;
    assert!(
        line.starts_with("HTTP/1.1 200"),
        "good auth must pass, got: {line}"
    );
    // Consume the remaining header bytes up to the blank line.
    let mut rest = Vec::new();
    let mut byte = [0u8; 1];
    while !rest.ends_with(b"\r\n\r\n") && rest.len() < 64 {
        stream.read_exact(&mut byte).await.unwrap();
        rest.push(byte[0]);
        if rest.ends_with(b"\n\n") || rest == b"\r\n" {
            break;
        }
    }
    echo_roundtrip(&mut stream).await;
    drop(stream);

    harness.shutdown();
}

#[tokio::test]
async fn auth_does_not_bypass_fail_closed() {
    // Dead engine + auth-configured front-ends: correct credentials
    // must still be refused by the tunnel-state check.
    let (engine, engine_thread) = dead_engine();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!engine.is_up());

    let ctx = ProxyCtx::new(engine.clone()).with_auth(Some(test_auth()));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_ctx = ctx.clone();
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, socks_ctx).await;
    });
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_task = tokio::spawn(async move {
        let _ = run_http_listener(http_listener, ctx).await;
    });

    // SOCKS5: auth passes, CONNECT still refused.
    let (mut stream, status) = socks5_auth_negotiate(socks_addr, "hadi", "s3cret").await;
    assert_eq!(status, 0, "auth itself passes");
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&PEER_IP.octets());
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let rep = read_socks_reply(&mut stream).await;
    assert_ne!(rep, 0, "auth must not bypass the tunnel-down check");
    drop(stream);

    // HTTP: correct Basic credentials still get 502 while down.
    let mut stream = TcpStream::connect(http_addr).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {PEER_IP}:{ECHO_PORT} HTTP/1.1\r\nProxy-Authorization: {}\r\n\r\n",
                basic_header("hadi:s3cret")
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 502"),
        "authenticated CONNECT while down must be 502, got: {head}"
    );
    drop(stream);

    engine.stop();
    socks_task.abort();
    http_task.abort();
    let _ = engine_thread.join();
}

// ---------------------------------------------------------------------------
// Phase 3: info endpoint truthfulness.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn info_endpoint_reports_up_after_handshake() {
    let harness = start_memory_harness_with(HarnessOpts {
        with_info: true,
        ..Default::default()
    })
    .await;
    let info_addr = harness.info_addr.expect("info listener bound");
    harness.wait_up().await;
    let body = http_get_info(info_addr).await;
    assert!(status_is_up(&body), "info must report up: {body}");
    assert!(body.contains("\"handshake_age_secs\":"), "{body}");
    assert!(
        !body.contains("\"handshake_age_secs\":null"),
        "age must be a number when up: {body}"
    );
    assert!(
        body.contains("\"endpoint\":\"memory-peer\""),
        "endpoint listed: {body}"
    );
    assert!(
        body.contains("\"per_peer\":[{"),
        "per-peer array present: {body}"
    );
    harness.shutdown();
}

#[tokio::test]
async fn info_endpoint_reports_down_when_dead() {
    // Dead engine behind a real info listener.
    let (engine, engine_thread) = dead_engine();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let info_addr = listener.local_addr().unwrap();
    let info_engine = engine.clone();
    let info_task = tokio::spawn(async move {
        let _ = run_info_listener(listener, info_engine).await;
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    let body = http_get_info(info_addr).await;
    assert!(!status_is_up(&body), "info must report down: {body}");
    assert!(body.contains("\"status\":\"down\""), "{body}");
    assert!(body.contains("\"handshake_age_secs\":null"), "{body}");
    engine.stop();
    info_task.abort();
    let _ = engine_thread.join();
}

// ---------------------------------------------------------------------------
// Real-UDP suite: UDP ASSOCIATE through the production relay factory.
// ---------------------------------------------------------------------------

/// Real-UDP variant of the UDP ASSOCIATE test: two UdpTransports on
/// loopback, the proxy's real UDP relay socket, and a real client UDP
/// socket. Ignored by default (this VM blocks UDP); CI runs it.
#[tokio::test]
#[ignore = "needs working UDP loopback; run via `cargo test -- --ignored`"]
async fn udp_loopback_udp_associate() {
    let probe_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let probe_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr_a = probe_a.local_addr().unwrap();
    let addr_b = probe_b.local_addr().unwrap();
    drop(probe_a);
    drop(probe_b);

    let harness = start_harness_with(
        |_, _| {
            let client_t = UdpTransport::new(addr_a, addr_b).unwrap();
            let peer_t = UdpTransport::new(addr_b, addr_a).unwrap();
            (Box::new(client_t), Box::new(peer_t), addr_a, addr_b)
        },
        HarnessOpts::default(),
    )
    .await;
    harness.wait_up().await;

    // Open the control connection, request UDP ASSOCIATE.
    let mut control = TcpStream::connect(harness.socks_addr).await.unwrap();
    socks5_handshake(&mut control).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut head = [0u8; 4];
    control.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0, "associate must succeed");
    assert_eq!(head[3], 1);
    let mut bnd = [0u8; 6];
    control.read_exact(&mut bnd).await.unwrap();
    let relay_addr = SocketAddr::from((
        [bnd[0], bnd[1], bnd[2], bnd[3]],
        u16::from_be_bytes([bnd[4], bnd[5]]),
    ));
    assert_eq!(relay_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Datagrams over the REAL loopback UDP socket.
    let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = socks_udp_packet(PEER_IP, UDP_ECHO_PORT, PAYLOAD, 0);
    client_udp.send_to(&pkt, relay_addr).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _src) = timeout(Duration::from_secs(15), client_udp.recv_from(&mut buf))
        .await
        .expect("UDP ASSOCIATE round trip timed out")
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(&resp[0..3], &[0, 0, 0]);
    assert_eq!(&resp[4..8], &PEER_IP.octets());
    assert_eq!(&resp[10..], PAYLOAD);

    drop(control);
    harness.shutdown();
}
