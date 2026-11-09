//! End-to-end tests: SOCKS5/HTTP -> proxy -> smoltcp -> WireGuard tunnel
//! -> peer smoltcp stack -> TCP echo service, and back.
//!
//! The peer is a *second* boringtun instance (responder role) plus a
//! second smoltcp stack hosting a TCP echo service and a tiny UDP DNS
//! responder. Client and peer are linked by the in-memory transport, so
//! these tests run in environments where UDP is entirely blocked —
//! except `udp_loopback_e2e`, which is `#[ignore]`d and run explicitly
//! in CI (`cargo test -- --ignored`).

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant as StdInstant};

use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::OsRng;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wgproxyrs::config::Cidr;
use wgproxyrs::proxy::{run_http_listener, run_socks5_listener};
use wgproxyrs::stack::{EngineConfig, EngineHandle, PacketDevice, spawn_engine};
use wgproxyrs::tunnel::{Transport, UdpTransport, WgTunnel, memory_pair};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ECHO_PORT: u16 = 7777;
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
                let _ = addrs.push(IpCidr::new(PEER_IP.into(), 32));
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
                    if let Some(response) = build_dns_response(&query) {
                        let _ = sock.send_slice(&response, remote);
                    }
                }

                std::thread::sleep(Duration::from_millis(1));
            }
        })
        .expect("spawn peer thread")
}

/// Minimal DNS responder: answers A queries for `echo.test` with the peer
/// address, NXDOMAIN for everything else.
fn build_dns_response(query: &[u8]) -> Option<Vec<u8>> {
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
        resp.extend_from_slice(&PEER_IP.octets());
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
    socks_task: tokio::task::JoinHandle<()>,
    http_task: tokio::task::JoinHandle<()>,
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
) -> Harness {
    let (client_priv, client_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();

    // Placeholder addresses; memory transports ignore them, the UDP
    // variant fills in real ones below via the closure's return.
    let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let (client_transport, peer_transport, _a, _b) = make_transports(any, any);

    let peer_stop = Arc::new(AtomicBool::new(false));
    let peer_thread = spawn_peer(peer_priv, client_pub, peer_transport, peer_stop.clone());

    let client_tunnel = WgTunnel::new(client_priv, peer_pub, None, None, client_transport);
    let (engine, engine_thread) = spawn_engine(
        client_tunnel,
        EngineConfig {
            addresses: vec![Cidr {
                addr: IpAddr::V4(CLIENT_IP),
                prefix: 32,
            }],
            dns_servers: vec![IpAddr::V4(PEER_IP)],
            allowed_ips: vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix: 0,
            }],
        },
    );

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_engine = engine.clone();
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, socks_engine).await;
    });

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_engine = engine.clone();
    let http_task = tokio::spawn(async move {
        let _ = run_http_listener(http_listener, http_engine).await;
    });

    Harness {
        engine,
        engine_thread: Some(engine_thread),
        peer_stop,
        peer_thread: Some(peer_thread),
        socks_addr,
        http_addr,
        socks_task,
        http_task,
    }
}

async fn start_memory_harness() -> Harness {
    start_harness_with(|_, _| {
        let (a, b) = memory_pair();
        let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        (Box::new(a), Box::new(b), any, any)
    })
    .await
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
    let (client_priv, _client_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let (mem_a, mem_b) = memory_pair();
    drop(mem_b);

    let client_tunnel = WgTunnel::new(client_priv, peer_pub, None, None, Box::new(mem_a));
    let (engine, engine_thread) = spawn_engine(
        client_tunnel,
        EngineConfig {
            addresses: vec![Cidr {
                addr: IpAddr::V4(CLIENT_IP),
                prefix: 32,
            }],
            dns_servers: vec![IpAddr::V4(PEER_IP)],
            allowed_ips: vec![Cidr {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix: 0,
            }],
        },
    );
    // Give the engine a moment to (fail to) handshake.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!engine.is_up(), "tunnel must be down without a peer");

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let socks_engine = engine.clone();
    let socks_task = tokio::spawn(async move {
        let _ = run_socks5_listener(socks_listener, socks_engine).await;
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

    // HTTP front-end must fail closed too (502).
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_engine = engine.clone();
    let http_task = tokio::spawn(async move {
        let _ = run_http_listener(http_listener, http_engine).await;
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

    let harness = start_harness_with(|_, _| {
        let client_t = UdpTransport::new(addr_a, addr_b).unwrap();
        let peer_t = UdpTransport::new(addr_b, addr_a).unwrap();
        (Box::new(client_t), Box::new(peer_t), addr_a, addr_b)
    })
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
