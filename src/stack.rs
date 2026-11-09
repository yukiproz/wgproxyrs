//! The netstack engine: smoltcp + the WireGuard tunnels on one thread.
//!
//! The engine owns one [`WgTunnel`] **per configured peer** and a smoltcp
//! `Interface` whose device is a pair of packet queues (decrypted packets
//! in, cleartext packets out — straight back into a tunnel). Outbound
//! packets are routed by **cryptokey routing**: the destination IP is
//! matched by longest prefix against every peer's AllowedIPs, and the
//! packet is encapsulated by that peer's tunnel. Inbound packets are
//! accepted only when their source IP falls inside the AllowedIPs of the
//! peer they arrived from. Everything else in the program talks to the
//! engine through channels:
//!
//! - proxy front-ends call [`EngineHandle::open_stream`] to get byte
//!   channels bridged to a smoltcp TCP connection through the tunnel;
//! - they call [`EngineHandle::open_udp_flow`] for UDP datagram channels
//!   (SOCKS5 UDP ASSOCIATE) bridged to a smoltcp UDP socket;
//! - they call [`EngineHandle::resolve`] to resolve names with smoltcp's
//!   DNS socket, against the configured DNS server, *through the tunnel*.
//!
//! There is deliberately no API here that could open a direct socket:
//! the only way out is through the tunnel. That is what makes wgproxyrs
//! fail-closed by construction rather than by configuration.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::sync::{mpsc, oneshot};

use crate::config::Cidr;
use crate::tunnel::WgTunnel;

/// Default MTU presented to smoltcp when nothing overrides it: 1280,
/// the IPv6 floor — an inner packet of 1280 bytes plus WireGuard
/// overhead fits any sane underlay path. The value itself is owned by
/// [`crate::config::DEFAULT_MTU`]; the effective MTU for a session is
/// resolved there ([`crate::config::resolve_mtu`]) and arrives via
/// [`EngineConfig::mtu`].
pub const TUNNEL_MTU: usize = crate::config::DEFAULT_MTU as usize;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Interface addresses from the `.conf` (`[Interface] Address`).
    pub addresses: Vec<Cidr>,
    /// DNS servers from the `.conf` (`[Interface] DNS`); queries go through
    /// the tunnel.
    pub dns_servers: Vec<IpAddr>,
    /// Effective tunnel MTU (inner packet size cap for smoltcp),
    /// resolved by [`crate::config::resolve_mtu`].
    pub mtu: usize,
}

/// One peer's tunnel plus the routing facts the engine needs for it.
pub struct PeerTunnel {
    pub tunnel: WgTunnel,
    /// This peer's AllowedIPs (its cryptokey routing table entries).
    pub allowed_ips: Vec<Cidr>,
    /// Endpoint as written in the config (for status reporting).
    pub endpoint: String,
}

/// Readiness of one peer.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerStatus {
    pub endpoint: String,
    pub up: bool,
    pub handshake_age: Option<Duration>,
}

/// Readiness snapshot, shared between the engine thread and callers.
/// `up`/`handshake_age` are the aggregate view (any peer up; freshest
/// handshake); `peers` is the per-peer truth the info endpoint serves.
#[derive(Debug, Clone, Default)]
pub struct TunnelStatus {
    pub up: bool,
    pub handshake_age: Option<Duration>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// No live handshake: fail closed, open nothing.
    Down,
    /// Destination is outside every peer's AllowedIPs.
    NotAllowed(IpAddr),
    /// The engine thread is gone.
    Closed,
    ConnectFailed(String),
    ResolveFailed(String),
    Timeout,
    /// Too many simultaneous UDP flows (SOCKS5 UDP ASSOCIATE sessions).
    TooManyFlows,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Down => write!(f, "tunnel is down (no live handshake)"),
            Self::NotAllowed(ip) => write!(f, "destination {ip} not in AllowedIPs"),
            Self::Closed => write!(f, "engine stopped"),
            Self::ConnectFailed(m) => write!(f, "connect failed: {m}"),
            Self::ResolveFailed(m) => write!(f, "resolve failed: {m}"),
            Self::Timeout => write!(f, "timed out"),
            Self::TooManyFlows => write!(f, "too many UDP flows"),
        }
    }
}
impl std::error::Error for EngineError {}

type ByteTx = mpsc::Sender<Vec<u8>>;
type ByteRx = mpsc::Receiver<Vec<u8>>;

/// A UDP datagram in flight between a proxy session and the engine:
/// (destination or source address, payload).
pub type Datagram = (SocketAddr, Vec<u8>);
pub type DatagramTx = mpsc::Sender<Datagram>;
pub type DatagramRx = mpsc::Receiver<Datagram>;

/// Cap on simultaneous UDP flows (SOCKS5 UDP ASSOCIATE sessions).
const MAX_UDP_FLOWS: usize = 64;

enum Command {
    Connect {
        target: SocketAddr,
        to_stack: ByteRx,
        from_stack: ByteTx,
        ack: oneshot::Sender<Result<(), EngineError>>,
    },
    UdpOpen {
        to_stack: DatagramRx,
        from_stack: DatagramTx,
        ack: oneshot::Sender<Result<(), EngineError>>,
    },
    Resolve {
        name: String,
        reply: oneshot::Sender<Result<IpAddr, EngineError>>,
    },
}

/// Cryptokey routing: which peer owns `ip`? Longest prefix wins; ties go
/// to the earliest configured peer. `None` = no peer may carry it.
pub fn route_peer(peer_routes: &[Vec<Cidr>], ip: IpAddr) -> Option<usize> {
    let mut best: Option<(usize, u8)> = None;
    for (idx, cidrs) in peer_routes.iter().enumerate() {
        for cidr in cidrs {
            if cidr.contains(ip) && best.is_none_or(|(_, p)| cidr.prefix > p) {
                best = Some((idx, cidr.prefix));
            }
        }
    }
    best.map(|(idx, _)| idx)
}

/// Handle to a running engine. Cheap to clone; all state lives in the
/// engine thread plus the shared [`TunnelStatus`].
#[derive(Clone)]
pub struct EngineHandle {
    cmd: mpsc::Sender<Command>,
    status: Arc<Mutex<TunnelStatus>>,
    stop: Arc<AtomicBool>,
    peer_routes: Arc<Vec<Vec<Cidr>>>,
    dns_configured: bool,
}

impl EngineHandle {
    pub fn status(&self) -> TunnelStatus {
        self.status.lock().expect("status lock").clone()
    }

    /// Aggregate readiness: at least one peer has a live handshake.
    pub fn is_up(&self) -> bool {
        self.status().up
    }

    /// Readiness for one destination: its owning peer must exist (else
    /// `NotAllowed`) and be up (else `Down`).
    fn check_destination(&self, ip: IpAddr) -> Result<(), EngineError> {
        let owner = route_peer(&self.peer_routes, ip).ok_or(EngineError::NotAllowed(ip))?;
        let status = self.status();
        match status.peers.get(owner) {
            Some(peer) if peer.up => Ok(()),
            _ => Err(EngineError::Down),
        }
    }

    /// Open a TCP stream to `target` through the tunnel. Resolves once the
    /// smoltcp connection is established; the returned channels then carry
    /// raw bytes in each direction. Dropping the sender half closes the
    /// stream; the receiver ends when the remote side closes.
    pub async fn open_stream(&self, target: SocketAddr) -> Result<(ByteTx, ByteRx), EngineError> {
        self.check_destination(target.ip())?;
        let (to_stack_tx, to_stack_rx) = mpsc::channel::<Vec<u8>>(128);
        let (from_stack_tx, from_stack_rx) = mpsc::channel::<Vec<u8>>(128);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd
            .send(Command::Connect {
                target,
                to_stack: to_stack_rx,
                from_stack: from_stack_tx,
                ack: ack_tx,
            })
            .await
            .map_err(|_| EngineError::Closed)?;
        match tokio::time::timeout(Duration::from_secs(20), ack_rx).await {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => return Err(EngineError::Closed),
            Err(_) => return Err(EngineError::Timeout),
        }
        Ok((to_stack_tx, from_stack_rx))
    }

    /// Open a UDP flow through the tunnel (for SOCKS5 UDP ASSOCIATE).
    /// Datagrams sent into the returned sender are routed per destination
    /// inside the engine and dropped silently when the owning peer is
    /// down or the destination is outside every AllowedIPs (UDP
    /// semantics + fail closed); responses arrive on the returned
    /// receiver tagged with their source address. Dropping both halves
    /// ends the flow.
    pub async fn open_udp_flow(&self) -> Result<(DatagramTx, DatagramRx), EngineError> {
        if !self.is_up() {
            return Err(EngineError::Down);
        }
        let (to_stack_tx, to_stack_rx) = mpsc::channel::<Datagram>(256);
        let (from_stack_tx, from_stack_rx) = mpsc::channel::<Datagram>(256);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.cmd
            .send(Command::UdpOpen {
                to_stack: to_stack_rx,
                from_stack: from_stack_tx,
                ack: ack_tx,
            })
            .await
            .map_err(|_| EngineError::Closed)?;
        match tokio::time::timeout(Duration::from_secs(5), ack_rx).await {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => return Err(EngineError::Closed),
            Err(_) => return Err(EngineError::Timeout),
        }
        Ok((to_stack_tx, from_stack_rx))
    }

    /// Resolve `name` using the config's DNS server, through the tunnel.
    pub async fn resolve(&self, name: &str) -> Result<IpAddr, EngineError> {
        if !self.dns_configured {
            return Err(EngineError::ResolveFailed("no DNS server in config".into()));
        }
        if !self.is_up() {
            return Err(EngineError::Down);
        }
        // Literal IPs resolve to themselves.
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(ip);
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd
            .send(Command::Resolve {
                name: name.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| EngineError::Closed)?;
        match tokio::time::timeout(Duration::from_secs(15), reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(EngineError::Closed),
            Err(_) => Err(EngineError::Timeout),
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Spawn the engine thread around the per-peer tunnels.
pub fn spawn_engine(peers: Vec<PeerTunnel>, cfg: EngineConfig) -> (EngineHandle, JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
    let status = Arc::new(Mutex::new(TunnelStatus {
        up: false,
        handshake_age: None,
        peers: peers
            .iter()
            .map(|p| PeerStatus {
                endpoint: p.endpoint.clone(),
                up: false,
                handshake_age: None,
            })
            .collect(),
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let peer_routes: Vec<Vec<Cidr>> = peers.iter().map(|p| p.allowed_ips.clone()).collect();
    let handle = EngineHandle {
        cmd: cmd_tx,
        status: status.clone(),
        stop: stop.clone(),
        peer_routes: Arc::new(peer_routes),
        dns_configured: !cfg.dns_servers.is_empty(),
    };
    let join = std::thread::Builder::new()
        .name("wgproxyrs-engine".into())
        .spawn(move || run_engine(peers, cfg, cmd_rx, status, stop))
        .expect("spawn engine thread");
    (handle, join)
}

// ---------------------------------------------------------------------------
// Packet device: two queues between the tunnel and smoltcp.
// ---------------------------------------------------------------------------

pub struct PacketDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl Default for PacketDevice {
    fn default() -> Self {
        Self::with_mtu(TUNNEL_MTU)
    }
}

impl PacketDevice {
    pub fn with_mtu(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx_queue.drain(..).collect()
    }
}

pub struct PacketRxToken {
    buffer: Vec<u8>,
}
impl RxToken for PacketRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct PacketTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}
impl TxToken for PacketTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = PacketRxToken;
    type TxToken<'a> = PacketTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|buffer| {
            (
                PacketRxToken { buffer },
                PacketTxToken {
                    queue: &mut self.tx_queue,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(PacketTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        // DeviceCapabilities is non-exhaustive: start from default, mutate.
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = None;
        caps.medium = Medium::Ip;
        // Packets really leave this process (inside WireGuard), so
        // checksums must be computed in software — no `ignored()`.
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

// ---------------------------------------------------------------------------
// Conversions.
// ---------------------------------------------------------------------------

// With smoltcp's `std` feature its wire address types are the std ones,
// so these conversions are plain wrapping/unwrapping.
fn smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}

fn std_ip(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
        IpAddress::Ipv6(a) => IpAddr::V6(a),
        #[allow(unreachable_patterns)]
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

fn smol_cidr(c: &Cidr) -> IpCidr {
    IpCidr::new(smol_ip(c.addr), c.prefix)
}

/// Source / destination IP of a raw IP packet, if it parses as v4 or v6.
fn packet_src(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

fn packet_dst(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Engine thread.
// ---------------------------------------------------------------------------

struct Conn {
    handle: SocketHandle,
    to_stack: ByteRx,
    from_stack: ByteTx,
    ack: Option<oneshot::Sender<Result<(), EngineError>>>,
    staging: VecDeque<u8>,
    client_gone: bool,
    fin_sent: bool,
}

struct PendingDns {
    handle: dns::QueryHandle,
    reply: Option<oneshot::Sender<Result<IpAddr, EngineError>>>,
    name: String,
    tried_v6: bool,
}

struct UdpFlow {
    handle: SocketHandle,
    to_stack: DatagramRx,
    from_stack: DatagramTx,
}

fn run_engine(
    mut peers: Vec<PeerTunnel>,
    cfg: EngineConfig,
    mut cmd_rx: mpsc::Receiver<Command>,
    status: Arc<Mutex<TunnelStatus>>,
    stop: Arc<AtomicBool>,
) {
    let epoch = StdInstant::now();
    let now = || SmolInstant::from_millis(epoch.elapsed().as_millis() as i64);

    let peer_routes: Vec<Vec<Cidr>> = peers.iter().map(|p| p.allowed_ips.clone()).collect();

    let mut device = PacketDevice::with_mtu(cfg.mtu);
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut device, now());
    iface.update_ip_addrs(|addrs| {
        for cidr in &cfg.addresses {
            let _ = addrs.push(smol_cidr(cidr));
        }
    });
    if cfg.addresses.iter().any(|c| c.addr.is_ipv4()) {
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED);
    }
    if cfg.addresses.iter().any(|c| c.addr.is_ipv6()) {
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::UNSPECIFIED);
    }

    let mut sockets = SocketSet::new(Vec::new());
    let dns_servers: Vec<IpAddress> = cfg.dns_servers.iter().map(|&i| smol_ip(i)).collect();
    let dns_handle = sockets.add(dns::Socket::new(&dns_servers, Vec::new()));

    let mut conns: Vec<Conn> = Vec::new();
    let mut udp_flows: Vec<UdpFlow> = Vec::new();
    let mut pending_dns: Vec<PendingDns> = Vec::new();
    let mut next_port: u16 = 49152;
    let mut inbound: Vec<Vec<u8>> = Vec::new();
    let mut last_initiate: Option<StdInstant> = None;

    let alloc_port = |next: &mut u16| {
        let port = *next;
        *next = if *next == u16::MAX { 49152 } else { *next + 1 };
        port
    };

    while !stop.load(Ordering::Relaxed) {
        // --- commands -----------------------------------------------------
        loop {
            match cmd_rx.try_recv() {
                Ok(Command::Connect {
                    target,
                    to_stack,
                    from_stack,
                    ack,
                }) => {
                    let mut sock = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0u8; 65536]),
                        tcp::SocketBuffer::new(vec![0u8; 65536]),
                    );
                    sock.set_nagle_enabled(false);
                    let local_port = alloc_port(&mut next_port);
                    let remote = (smol_ip(target.ip()), target.port());
                    match sock.connect(iface.context(), remote, local_port) {
                        Ok(()) => {
                            let handle = sockets.add(sock);
                            conns.push(Conn {
                                handle,
                                to_stack,
                                from_stack,
                                ack: Some(ack),
                                staging: VecDeque::new(),
                                client_gone: false,
                                fin_sent: false,
                            });
                        }
                        Err(e) => {
                            let _ = ack.send(Err(EngineError::ConnectFailed(e.to_string())));
                        }
                    }
                }
                Ok(Command::UdpOpen {
                    to_stack,
                    from_stack,
                    ack,
                }) => {
                    if udp_flows.len() >= MAX_UDP_FLOWS {
                        let _ = ack.send(Err(EngineError::TooManyFlows));
                        continue;
                    }
                    let mut sock = udp::Socket::new(
                        udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 32],
                            vec![0u8; 65536],
                        ),
                        udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 32],
                            vec![0u8; 65536],
                        ),
                    );
                    let local_port = alloc_port(&mut next_port);
                    match sock.bind(local_port) {
                        Ok(()) => {
                            let handle = sockets.add(sock);
                            udp_flows.push(UdpFlow {
                                handle,
                                to_stack,
                                from_stack,
                            });
                            let _ = ack.send(Ok(()));
                        }
                        Err(e) => {
                            let _ = ack.send(Err(EngineError::ConnectFailed(e.to_string())));
                        }
                    }
                }
                Ok(Command::Resolve { name, reply }) => {
                    let sock = sockets.get_mut::<dns::Socket>(dns_handle);
                    match sock.start_query(iface.context(), &name, DnsQueryType::A) {
                        Ok(query) => pending_dns.push(PendingDns {
                            handle: query,
                            reply: Some(reply),
                            name,
                            tried_v6: false,
                        }),
                        Err(e) => {
                            let _ = reply.send(Err(EngineError::ResolveFailed(e.to_string())));
                        }
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        // --- keep the handshakes coming until every peer is up ----------
        let any_down = peers.iter().any(|p| !p.tunnel.is_up());
        if any_down && last_initiate.is_none_or(|t| t.elapsed() >= Duration::from_millis(250)) {
            for peer in peers.iter_mut() {
                if !peer.tunnel.is_up() {
                    peer.tunnel.initiate_handshake();
                }
            }
            last_initiate = Some(StdInstant::now());
        }

        // --- tunnels <-> device ------------------------------------------
        // Inbound: accept a decrypted packet only when its source IP is
        // inside the AllowedIPs of the peer it arrived from (the inbound
        // half of cryptokey routing).
        for peer in peers.iter_mut() {
            inbound.clear();
            peer.tunnel.poll(&mut inbound);
            for packet in inbound.drain(..) {
                let allowed = packet_src(&packet)
                    .is_some_and(|src| peer.allowed_ips.iter().any(|c| c.contains(src)));
                if allowed {
                    device.push_rx(packet);
                }
            }
        }

        iface.poll(now(), &mut device, &mut sockets);

        // Outbound: route each packet to the peer owning its destination;
        // a destination owned by no peer is dropped here, at the latest.
        for packet in device.drain_tx() {
            let owner = packet_dst(&packet).and_then(|dst| route_peer(&peer_routes, dst));
            if let Some(idx) = owner {
                peers[idx].tunnel.encapsulate_ip(&packet);
            }
        }

        // --- status ---------------------------------------------------------
        {
            let mut s = status.lock().expect("status lock");
            let mut any_up = false;
            let mut freshest: Option<Duration> = None;
            for (i, peer) in peers.iter().enumerate() {
                let up = peer.tunnel.is_up();
                let age = peer.tunnel.handshake_age();
                any_up |= up;
                if up {
                    freshest = Some(match (freshest, age) {
                        (None, a) => a.unwrap_or(Duration::MAX),
                        (Some(cur), a) => cur.min(a.unwrap_or(Duration::MAX)),
                    });
                }
                if let Some(ps) = s.peers.get_mut(i) {
                    ps.up = up;
                    ps.handshake_age = age;
                }
            }
            s.up = any_up;
            s.handshake_age = if any_up {
                freshest.filter(|d| *d != Duration::MAX)
            } else {
                None
            };
        }

        // --- DNS completions --------------------------------------------------
        let mut i = 0;
        while i < pending_dns.len() {
            let sock = sockets.get_mut::<dns::Socket>(dns_handle);
            let result = sock.get_query_result(pending_dns[i].handle);
            match result {
                Ok(addrs) => {
                    let picked = addrs.iter().copied().next();
                    match picked {
                        Some(addr) => {
                            let pd = pending_dns.remove(i);
                            if let Some(reply) = pd.reply {
                                let _ = reply.send(Ok(std_ip(addr)));
                            }
                        }
                        None if !pending_dns[i].tried_v6 => {
                            // No A records: try AAAA before giving up.
                            pending_dns[i].tried_v6 = true;
                            let name = pending_dns[i].name.clone();
                            let sock = sockets.get_mut::<dns::Socket>(dns_handle);
                            match sock.start_query(iface.context(), &name, DnsQueryType::Aaaa) {
                                Ok(q) => pending_dns[i].handle = q,
                                Err(e) => {
                                    let pd = pending_dns.remove(i);
                                    if let Some(reply) = pd.reply {
                                        let _ = reply
                                            .send(Err(EngineError::ResolveFailed(e.to_string())));
                                    }
                                }
                            }
                            i += 1;
                        }
                        None => {
                            let pd = pending_dns.remove(i);
                            if let Some(reply) = pd.reply {
                                let _ = reply.send(Err(EngineError::ResolveFailed(
                                    "no addresses returned".into(),
                                )));
                            }
                        }
                    }
                }
                Err(dns::GetQueryResultError::Pending) => {
                    i += 1;
                }
                Err(dns::GetQueryResultError::Failed) => {
                    if !pending_dns[i].tried_v6 {
                        pending_dns[i].tried_v6 = true;
                        let name = pending_dns[i].name.clone();
                        let sock = sockets.get_mut::<dns::Socket>(dns_handle);
                        match sock.start_query(iface.context(), &name, DnsQueryType::Aaaa) {
                            Ok(q) => {
                                pending_dns[i].handle = q;
                                i += 1;
                            }
                            Err(e) => {
                                let pd = pending_dns.remove(i);
                                if let Some(reply) = pd.reply {
                                    let _ =
                                        reply.send(Err(EngineError::ResolveFailed(e.to_string())));
                                }
                            }
                        }
                    } else {
                        let pd = pending_dns.remove(i);
                        if let Some(reply) = pd.reply {
                            let _ = reply
                                .send(Err(EngineError::ResolveFailed("DNS query failed".into())));
                        }
                    }
                }
            }
        }

        // --- UDP flows --------------------------------------------------------
        let mut dead_flows: Vec<SocketHandle> = Vec::new();
        for flow in udp_flows.iter_mut() {
            let sock = sockets.get_mut::<udp::Socket>(flow.handle);

            // Proxy -> tunnel: drain queued datagrams. Each datagram is
            // routed by destination; an unroutable destination or a down
            // owning peer means a silent drop (UDP semantics, fail closed).
            let mut proxy_gone = false;
            loop {
                match flow.to_stack.try_recv() {
                    Ok((dst, data)) => {
                        let routable = route_peer(&peer_routes, dst.ip())
                            .is_some_and(|idx| peers[idx].tunnel.is_up());
                        if routable {
                            let endpoint = IpEndpoint::new(smol_ip(dst.ip()), dst.port());
                            let _ = sock.send_slice(&data, endpoint);
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        proxy_gone = true;
                        break;
                    }
                }
            }

            // Tunnel -> proxy: forward everything the socket received.
            let mut session_gone = proxy_gone;
            while sock.can_recv() {
                match sock.recv() {
                    Ok((data, meta)) => {
                        let src = SocketAddr::new(std_ip(meta.endpoint.addr), meta.endpoint.port);
                        if flow.from_stack.try_send((src, data.to_vec())).is_err() {
                            session_gone = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if session_gone {
                dead_flows.push(flow.handle);
            }
        }
        if !dead_flows.is_empty() {
            udp_flows.retain(|f| !dead_flows.contains(&f.handle));
            for handle in dead_flows {
                sockets.remove(handle);
            }
        }

        // --- connections ------------------------------------------------------
        let mut remove: Vec<SocketHandle> = Vec::new();
        for conn in conns.iter_mut() {
            let sock = sockets.get_mut::<tcp::Socket>(conn.handle);

            if conn.ack.is_some() {
                match sock.state() {
                    tcp::State::Established => {
                        if let Some(ack) = conn.ack.take() {
                            let _ = ack.send(Ok(()));
                        }
                    }
                    tcp::State::Closed => {
                        if let Some(ack) = conn.ack.take() {
                            let _ = ack.send(Err(EngineError::ConnectFailed(
                                "connection closed before it was established".into(),
                            )));
                        }
                    }
                    _ => {}
                }
            }

            if !conn.client_gone {
                loop {
                    match conn.to_stack.try_recv() {
                        Ok(chunk) => conn.staging.extend(chunk),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            conn.client_gone = true;
                            break;
                        }
                    }
                }
            }
            while sock.can_send() && !conn.staging.is_empty() {
                let (front, _) = conn.staging.as_slices();
                match sock.send_slice(front) {
                    Ok(n) => {
                        conn.staging.drain(..n);
                    }
                    Err(_) => break,
                }
            }
            if conn.client_gone && conn.staging.is_empty() && !conn.fin_sent {
                sock.close();
                conn.fin_sent = true;
            }

            let mut peer_gone = false;
            while sock.can_recv() {
                let mut buf = vec![0u8; 16384];
                match sock.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        if conn.from_stack.try_send(buf).is_err() {
                            peer_gone = true;
                            break;
                        }
                    }
                    _ => break,
                }
            }
            if peer_gone {
                sock.abort();
                remove.push(conn.handle);
                continue;
            }
            if sock.state() == tcp::State::Closed {
                remove.push(conn.handle);
            }
        }
        if !remove.is_empty() {
            conns.retain(|c| !remove.contains(&c.handle));
            for handle in remove {
                sockets.remove(handle);
            }
        }

        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ip;

    #[test]
    fn route_peer_longest_prefix_wins() {
        let routes = vec![
            vec![Cidr::parse("10.0.0.0/8").unwrap()],
            vec![
                Cidr::parse("10.1.0.0/16").unwrap(),
                Cidr::parse("192.168.0.0/16").unwrap(),
            ],
        ];
        assert_eq!(route_peer(&routes, ip("10.1.2.3")), Some(1));
        assert_eq!(route_peer(&routes, ip("10.9.9.9")), Some(0));
        assert_eq!(route_peer(&routes, ip("192.168.1.1")), Some(1));
        assert_eq!(route_peer(&routes, ip("8.8.8.8")), None);
    }

    #[test]
    fn packet_headers_parse() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[12..16].copy_from_slice(&[10, 0, 0, 2]);
        v4[16..20].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(packet_src(&v4), Some(ip("10.0.0.2")));
        assert_eq!(packet_dst(&v4), Some(ip("10.0.0.1")));
        assert_eq!(packet_src(&[]), None);
        assert_eq!(packet_dst(&[0x99]), None);
    }
}
