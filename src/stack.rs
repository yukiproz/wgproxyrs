//! The netstack engine: smoltcp + the WireGuard tunnel on one thread.
//!
//! The engine owns the tunnel and a smoltcp `Interface` whose device is a
//! pair of packet queues (decrypted packets in, cleartext packets out —
//! straight back into the tunnel). Everything else in the program talks to
//! it through channels:
//!
//! - proxy front-ends call [`EngineHandle::open_stream`] to get byte
//!   channels bridged to a smoltcp TCP connection through the tunnel;
//! - they call [`EngineHandle::resolve`] to resolve names with smoltcp's
//!   DNS socket, against the configured DNS server, *through the tunnel*.
//!
//! There is deliberately no API here that could open a direct socket:
//! the only way out is through the tunnel. That is what makes wgproxyrs
//! fail-closed by construction rather than by configuration.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, tcp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    DnsQueryType, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address,
};
use tokio::sync::{mpsc, oneshot};

use crate::config::Cidr;
use crate::tunnel::WgTunnel;

/// MTU presented to smoltcp. Conservative on purpose: an inner packet of
/// 1280 bytes plus WireGuard overhead fits any sane underlay path.
pub const TUNNEL_MTU: usize = 1280;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Interface addresses from the `.conf` (`[Interface] Address`).
    pub addresses: Vec<Cidr>,
    /// DNS servers from the `.conf` (`[Interface] DNS`); queries go through
    /// the tunnel.
    pub dns_servers: Vec<IpAddr>,
    /// Union of all peers' AllowedIPs: the only destinations the engine
    /// will even attempt to reach (WireGuard's cryptokey routing rule).
    pub allowed_ips: Vec<Cidr>,
}

/// Readiness snapshot, shared between the engine thread and callers.
#[derive(Debug, Clone, Copy, Default)]
pub struct TunnelStatus {
    pub up: bool,
    pub handshake_age: Option<Duration>,
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
        }
    }
}
impl std::error::Error for EngineError {}

type ByteTx = mpsc::Sender<Vec<u8>>;
type ByteRx = mpsc::Receiver<Vec<u8>>;

enum Command {
    Connect {
        target: SocketAddr,
        to_stack: ByteRx,
        from_stack: ByteTx,
        ack: oneshot::Sender<Result<(), EngineError>>,
    },
    Resolve {
        name: String,
        reply: oneshot::Sender<Result<IpAddr, EngineError>>,
    },
}

/// Handle to a running engine. Cheap to clone; all state lives in the
/// engine thread plus the shared [`TunnelStatus`].
#[derive(Clone)]
pub struct EngineHandle {
    cmd: mpsc::Sender<Command>,
    status: Arc<Mutex<TunnelStatus>>,
    stop: Arc<AtomicBool>,
    allowed_ips: Arc<Vec<Cidr>>,
    dns_configured: bool,
}

impl EngineHandle {
    pub fn status(&self) -> TunnelStatus {
        *self.status.lock().expect("status lock")
    }

    pub fn is_up(&self) -> bool {
        self.status().up
    }

    /// Open a TCP stream to `target` through the tunnel. Resolves once the
    /// smoltcp connection is established; the returned channels then carry
    /// raw bytes in each direction. Dropping the sender half closes the
    /// stream; the receiver ends when the remote side closes.
    pub async fn open_stream(
        &self,
        target: SocketAddr,
    ) -> Result<(ByteTx, ByteRx), EngineError> {
        if !self.is_up() {
            return Err(EngineError::Down);
        }
        if !self.allowed_ips.iter().any(|c| c.contains(target.ip())) {
            return Err(EngineError::NotAllowed(target.ip()));
        }
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

    /// Resolve `name` using the config's DNS server, through the tunnel.
    pub async fn resolve(&self, name: &str) -> Result<IpAddr, EngineError> {
        if !self.dns_configured {
            return Err(EngineError::ResolveFailed(
                "no DNS server in config".into(),
            ));
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

/// Spawn the engine thread around an already-built tunnel.
pub fn spawn_engine(tunnel: WgTunnel, cfg: EngineConfig) -> (EngineHandle, JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
    let status = Arc::new(Mutex::new(TunnelStatus::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let handle = EngineHandle {
        cmd: cmd_tx,
        status: status.clone(),
        stop: stop.clone(),
        allowed_ips: Arc::new(cfg.allowed_ips.clone()),
        dns_configured: !cfg.dns_servers.is_empty(),
    };
    let join = std::thread::Builder::new()
        .name("wgproxyrs-engine".into())
        .spawn(move || run_engine(tunnel, cfg, cmd_rx, status, stop))
        .expect("spawn engine thread");
    (handle, join)
}

// ---------------------------------------------------------------------------
// Packet device: two queues between the tunnel and smoltcp.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct PacketDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl PacketDevice {
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
        caps.max_transmission_unit = TUNNEL_MTU;
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

fn smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(a) => IpAddress::Ipv4(Ipv4Address::from(a)),
        IpAddr::V6(a) => IpAddress::Ipv6(Ipv6Address::from(a)),
    }
}

fn std_ip(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(a) => IpAddr::V4(Ipv4Addr::from(a)),
        IpAddress::Ipv6(a) => IpAddr::V6(Ipv6Addr::from(a)),
        #[allow(unreachable_patterns)]
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

fn smol_cidr(c: &Cidr) -> IpCidr {
    IpCidr::new(smol_ip(c.addr), c.prefix)
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

fn run_engine(
    mut tunn: WgTunnel,
    cfg: EngineConfig,
    mut cmd_rx: mpsc::Receiver<Command>,
    status: Arc<Mutex<TunnelStatus>>,
    stop: Arc<AtomicBool>,
) {
    let epoch = StdInstant::now();
    let now = || SmolInstant::from_millis(epoch.elapsed().as_millis() as i64);

    let mut device = PacketDevice::default();
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
    let mut pending_dns: Vec<PendingDns> = Vec::new();
    let mut next_port: u16 = 49152;
    let mut inbound: Vec<Vec<u8>> = Vec::new();
    let mut last_initiate: Option<StdInstant> = None;

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
                    let local_port = next_port;
                    next_port = if next_port == u16::MAX {
                        49152
                    } else {
                        next_port + 1
                    };
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

        // --- keep the handshake coming until the tunnel is up ------------
        if !tunn.is_up()
            && last_initiate.is_none_or(|t| t.elapsed() >= Duration::from_millis(250))
        {
            tunn.initiate_handshake();
            last_initiate = Some(StdInstant::now());
        }

        // --- tunnel <-> device --------------------------------------------
        inbound.clear();
        tunn.poll(&mut inbound);
        for packet in inbound.drain(..) {
            device.push_rx(packet);
        }

        iface.poll(now(), &mut device, &mut sockets);

        for packet in device.drain_tx() {
            tunn.encapsulate_ip(&packet);
        }

        // --- status ---------------------------------------------------------
        {
            let mut s = status.lock().expect("status lock");
            s.up = tunn.is_up();
            s.handshake_age = tunn.handshake_age();
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
                                        let _ = reply.send(Err(EngineError::ResolveFailed(
                                            e.to_string(),
                                        )));
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
                                    let _ = reply.send(Err(EngineError::ResolveFailed(
                                        e.to_string(),
                                    )));
                                }
                            }
                        }
                    } else {
                        let pd = pending_dns.remove(i);
                        if let Some(reply) = pd.reply {
                            let _ =
                                reply.send(Err(EngineError::ResolveFailed("DNS query failed".into())));
                        }
                    }
                }
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
