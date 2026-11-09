//! The WireGuard tunnel: a boringtun core behind a transport abstraction.
//!
//! Three transports exist:
//! - [`UdpTransport`] — production, single peer: a plain UDP socket to
//!   the peer endpoint.
//! - [`SharedUdpTransport`] — production, multi-peer: one shared UDP
//!   socket demultiplexed by source address (see
//!   [`shared_udp_transports`]).
//! - [`MemoryTransport`] — tests: in-memory channels carrying the same
//!   encapsulated packets. This matters because some environments (Yuki's
//!   VM) block *all* UDP sends, including loopback; the whole tunnel stack
//!   is therefore testable without a single socket.
//!
//! Fail-closed lives here: [`WgTunnel::is_up`] is the only readiness signal
//! the rest of the program may trust, and it is false until a handshake has
//! actually completed and is younger than the WireGuard session lifetime.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};

/// WireGuard sessions are rejected after 180 s without a fresh handshake
/// (REJECT_AFTER_TIME in the protocol); beyond that the tunnel is down.
pub const SESSION_TTL: Duration = Duration::from_secs(180);

/// Largest packet we ever move: a full 64 KiB IP packet plus WG overhead.
/// This also bounds the configurable-MTU audit (v0.3.0): the largest
/// inner packet is 9000 (`config::MAX_MTU`), and 9000 + worst-case
/// WireGuard overhead (~100 bytes) is far below this buffer, so a
/// configured MTU can never hit a truncation path here. The same holds
/// for the 65535-byte relay/dispatch buffers in `proxy`/`stack`.
pub const MAX_PACKET: usize = 65536;

/// A byte-pipe for encapsulated WireGuard packets.
///
/// Implementations are non-blocking: `recv` returns `Ok(None)` when no
/// packet is available right now. Send failures are reported but callers
/// treat them as non-fatal — a dead transport simply means the tunnel
/// never comes up, and the proxy layer fails closed.
pub trait Transport: Send {
    fn send(&mut self, packet: &[u8]) -> io::Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
}

/// Production transport: UDP socket connected to one peer endpoint.
/// Datagrams from any other source address are ignored.
pub struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl UdpTransport {
    pub fn new(bind: SocketAddr, peer: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, peer })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

impl Transport for UdpTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.socket.send_to(packet, self.peer).map(|_| ())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.socket.recv_from(buf) {
            Ok((n, src)) => {
                if src == self.peer {
                    Ok(Some(n))
                } else {
                    Ok(None) // Not our peer: drop silently.
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// In-memory transport for tests: two channel ends, cross-connected.
pub struct MemoryTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

/// Create a connected pair of in-memory transports.
pub fn memory_pair() -> (MemoryTransport, MemoryTransport) {
    let (a_tx, a_rx) = channel::<Vec<u8>>();
    let (b_tx, b_rx) = channel::<Vec<u8>>();
    (
        MemoryTransport { tx: a_tx, rx: b_rx },
        MemoryTransport { tx: b_tx, rx: a_rx },
    )
}

/// WireGuard has exactly one listen port per interface, so a multi-peer
/// client needs one real UDP socket shared by all peers, demultiplexed by
/// source address. [`shared_udp_transports`] binds that socket once and
/// hands back one [`Transport`] per peer: sends go to the peer's fixed
/// endpoint, receives are fed by a dedicated dispatcher thread reading the
/// shared socket and queueing packets per source address (unknown sources
/// are dropped). The dispatcher thread lives for the process lifetime.
pub struct SharedUdpTransport {
    socket: std::sync::Arc<UdpSocket>,
    peer: SocketAddr,
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
}

pub fn shared_udp_transports(
    bind: SocketAddr,
    peers: &[SocketAddr],
) -> io::Result<Vec<SharedUdpTransport>> {
    use std::sync::mpsc::channel;
    let socket = std::sync::Arc::new(UdpSocket::bind(bind)?);
    let mut senders = Vec::with_capacity(peers.len());
    let mut transports = Vec::with_capacity(peers.len());
    for &peer in peers {
        let (tx, rx) = channel::<Vec<u8>>();
        senders.push((peer, tx));
        transports.push(SharedUdpTransport {
            socket: socket.clone(),
            peer,
            rx,
        });
    }
    let dispatch_socket = socket.clone();
    std::thread::Builder::new()
        .name("wgproxyrs-udp-dispatch".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65535];
            loop {
                match dispatch_socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        if let Some((_, tx)) = senders.iter().find(|(peer, _)| *peer == src) {
                            let _ = tx.send(buf[..n].to_vec());
                        }
                        // Unknown source: not one of our peers — drop.
                    }
                    Err(_) => {
                        // The shared socket is blocking; a receive error
                        // here means the socket is gone. End the thread.
                        return;
                    }
                }
            }
        })?;
    Ok(transports)
}

impl Transport for SharedUdpTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.socket.send_to(packet, self.peer).map(|_| ())
    }
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.rx.try_recv() {
            Ok(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(Some(n))
            }
            Err(std::sync::mpsc::TryRecvError::Empty)
            | Err(std::sync::mpsc::TryRecvError::Disconnected) => Ok(None),
        }
    }
}

impl Transport for MemoryTransport {
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.tx
            .send(packet.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "memory transport closed"))
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.rx.try_recv() {
            Ok(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(Some(n))
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => Ok(None),
        }
    }
}

/// One WireGuard tunnel (single peer) over a [`Transport`].
pub struct WgTunnel {
    tunn: Tunn,
    transport: Box<dyn Transport>,
    dst_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl WgTunnel {
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        transport: Box<dyn Transport>,
    ) -> Self {
        let index = OsRng.next_u32();
        let tunn = Tunn::new(
            StaticSecret::from(private_key),
            PublicKey::from(peer_public_key),
            preshared_key,
            persistent_keepalive,
            index,
            None,
        );
        Self {
            tunn,
            transport,
            dst_buf: vec![0u8; MAX_PACKET],
            recv_buf: vec![0u8; MAX_PACKET],
        }
    }

    /// Ask the peer for a handshake now (no-op if one is already in flight).
    pub fn initiate_handshake(&mut self) {
        let result = self
            .tunn
            .format_handshake_initiation(&mut self.dst_buf, false);
        if let TunnResult::WriteToNetwork(packet) = result {
            let packet = packet.to_vec();
            let _ = self.transport.send(&packet);
        }
    }

    /// Encapsulate one cleartext IP packet towards the peer. If no session
    /// exists yet, boringtun queues the packet and this emits a handshake
    /// initiation instead — the packet goes out once the handshake lands.
    pub fn encapsulate_ip(&mut self, ip_packet: &[u8]) {
        let result = self.tunn.encapsulate(ip_packet, &mut self.dst_buf);
        if let TunnResult::WriteToNetwork(packet) = result {
            let packet = packet.to_vec();
            let _ = self.transport.send(&packet);
        }
    }

    /// Drive the tunnel: timers, plus every transport packet currently
    /// available. Decrypted IP packets are appended to `inbound`.
    /// Returns the number of transport packets processed.
    pub fn poll(&mut self, inbound: &mut Vec<Vec<u8>>) -> usize {
        // Timers first: keepalive / rekey / handshake retransmission.
        let result = self.tunn.update_timers(&mut self.dst_buf);
        if let TunnResult::WriteToNetwork(packet) = result {
            let packet = packet.to_vec();
            let _ = self.transport.send(&packet);
        }

        let mut processed = 0;
        while let Some(n) = self.next_packet() {
            processed += 1;
            let datagram = self.recv_buf[..n].to_vec();
            self.handle_datagram(&datagram, inbound);
        }
        processed
    }

    fn next_packet(&mut self) -> Option<usize> {
        // Transport errors are non-fatal: a dead transport just means the
        // tunnel stays down, and callers fail closed.
        self.transport.recv(&mut self.recv_buf).unwrap_or_default()
    }

    fn handle_datagram(&mut self, datagram: &[u8], inbound: &mut Vec<Vec<u8>>) {
        // boringtun semantics: feed the datagram once, then keep calling
        // with an empty datagram until Done, to flush the packet queue
        // (e.g. handshake response -> keepalive + queued data packets).
        let mut first = true;
        for _ in 0..64 {
            let input: &[u8] = if first { datagram } else { &[] };
            first = false;
            match self.tunn.decapsulate(None, input, &mut self.dst_buf) {
                TunnResult::Done | TunnResult::Err(_) => break,
                TunnResult::WriteToNetwork(packet) => {
                    let packet = packet.to_vec();
                    let _ = self.transport.send(&packet);
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    inbound.push(packet.to_vec());
                }
            }
        }
    }

    /// Time since the last completed handshake, if any.
    pub fn handshake_age(&self) -> Option<Duration> {
        self.tunn.stats().0
    }

    /// The readiness signal: a handshake completed, has not expired inside
    /// boringtun, and is younger than the session TTL.
    pub fn is_up(&self) -> bool {
        if self.tunn.is_expired() {
            return false;
        }
        matches!(self.handshake_age(), Some(age) if age < SESSION_TTL)
    }

    /// (tx_bytes, rx_bytes) of *decrypted* tunnel payload, from boringtun.
    pub fn payload_bytes(&self) -> (usize, usize) {
        let (_, tx, rx, _, _) = self.tunn.stats();
        (tx, rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::public_from_private;

    fn test_tunnel_pair() -> (WgTunnel, WgTunnel) {
        let client_priv: [u8; 32] = std::array::from_fn(|i| i as u8);
        let peer_priv: [u8; 32] = std::array::from_fn(|i| 64 + i as u8);
        let (ta, tb) = memory_pair();
        let client = WgTunnel::new(
            client_priv,
            public_from_private(&peer_priv),
            None,
            None,
            Box::new(ta),
        );
        let peer = WgTunnel::new(
            peer_priv,
            public_from_private(&client_priv),
            None,
            None,
            Box::new(tb),
        );
        (client, peer)
    }

    #[test]
    fn handshake_completes_over_memory_transport() {
        let (mut client, mut peer) = test_tunnel_pair();
        assert!(!client.is_up());
        client.initiate_handshake();
        let mut inbound = Vec::new();
        for _ in 0..50 {
            peer.poll(&mut inbound);
            client.poll(&mut inbound);
            if client.is_up() && peer.is_up() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(client.is_up(), "client handshake must complete");
        assert!(peer.is_up(), "peer handshake must complete");
        assert!(client.handshake_age().is_some());
    }

    #[test]
    fn data_roundtrips_over_memory_transport() {
        let (mut client, mut peer) = test_tunnel_pair();
        client.initiate_handshake();
        let mut inbound = Vec::new();
        for _ in 0..50 {
            if client.is_up() {
                break;
            }
            peer.poll(&mut inbound);
            client.poll(&mut inbound);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(client.is_up());
        inbound.clear();

        // A syntactically valid IPv4 packet (header checksum is not
        // verified by boringtun; the payload is what we check).
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[2] = 0;
        pkt[3] = 32; // total length
        pkt[8] = 64; // TTL
        pkt[9] = 253; // protocol (experimental)
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
        pkt[20..].copy_from_slice(b"hello tunnel");

        client.encapsulate_ip(&pkt);
        peer.poll(&mut inbound);
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0], pkt);
    }
}
