//! Configuration: parsing of a stock WireGuard `.conf` file.
//!
//! Supported surface (the wg-quick subset a client config actually uses):
//!
//! ```ini
//! [Interface]
//! PrivateKey = <base64, 32 bytes>
//! Address = 10.0.0.2/32, fd00::2/128   # one or more, CIDR or bare IP
//! DNS = 10.0.0.1                        # optional, repeatable/comma list
//! ListenPort = 51820                    # optional
//!
//! [Peer]
//! PublicKey = <base64, 32 bytes>
//! PreSharedKey = <base64, 32 bytes>     # optional
//! Endpoint = vpn.example.com:51820
//! AllowedIPs = 0.0.0.0/0, ::/0
//! PersistentKeepalive = 25              # optional
//! ```
//!
//! Key names are matched case-insensitively: real-world configs (eduVPN,
//! wg-quick) write the canonical `PreSharedKey`, and a silently dropped
//! preshared key means a tunnel that never comes up with no error
//! anywhere — the v0.2.1 hotfix exists because of exactly that.
//!
//! Unknown keys in either section (wg-quick's `Table`, `MTU`, `PreUp`, …)
//! are ignored, so real-world configs keep parsing. Key material is never
//! included in error messages or `Debug` output beyond its field name.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Default proxy bind address: localhost only, always, unless the user
/// explicitly configures something wider (DESIGN.md §4.3).
pub fn default_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)
}

/// Runtime settings for one wgproxyrs session (CLI-side, not from the .conf).
#[derive(Debug, Clone)]
pub struct Settings {
    /// Path to a stock WireGuard `.conf` file.
    pub config_path: PathBuf,
    /// Address the SOCKS5 proxy listener binds to.
    pub bind: SocketAddr,
    /// Optional separate HTTP CONNECT listener.
    pub http_bind: Option<SocketAddr>,
    /// Optional health/info endpoint listener (`--info-bind`).
    pub info_bind: Option<SocketAddr>,
    /// Fixed TCP tunnels (`--tcp-tunnel <listen>=<target>`), repeatable.
    pub tcp_tunnels: Vec<TcpTunnel>,
    /// Proxy username (`--proxy-user`); must be set together with the
    /// password — `validate` enforces the pair.
    pub proxy_user: Option<String>,
    /// Proxy password (`--proxy-pass`).
    pub proxy_pass: Option<String>,
}

/// One `--tcp-tunnel` specification: a local listen address and the
/// `host:port` target (IP or domain) reached through the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpTunnel {
    pub listen: SocketAddr,
    pub target: String,
}

impl Settings {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            bind: default_bind(),
            http_bind: None,
            info_bind: None,
            tcp_tunnels: Vec::new(),
            proxy_user: None,
            proxy_pass: None,
        }
    }

    /// Validate cross-field rules that don't belong to a single flag.
    pub fn validate(&self) -> Result<(), String> {
        match (&self.proxy_user, &self.proxy_pass) {
            (Some(_), None) => Err("--proxy-user set without --proxy-pass".into()),
            (None, Some(_)) => Err("--proxy-pass set without --proxy-user".into()),
            _ => Ok(()),
        }
    }
}

/// An IP address with a prefix length, e.g. `10.0.0.2/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, ConfigError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(ConfigError::InvalidCidr(format!("{addr}/{prefix}")));
        }
        Ok(Self { addr, prefix })
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let text = text.trim();
        match text.split_once('/') {
            Some((ip, prefix)) => {
                let addr: IpAddr = ip
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError::InvalidCidr(text.to_string()))?;
                let prefix: u8 = prefix
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError::InvalidCidr(text.to_string()))?;
                Self::new(addr, prefix)
            }
            None => {
                let addr: IpAddr = text
                    .parse()
                    .map_err(|_| ConfigError::InvalidCidr(text.to_string()))?;
                let prefix = match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                Ok(Self { addr, prefix })
            }
        }
    }

    /// True when `ip` falls inside this CIDR (same address family only).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                let mask = if self.prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(net) & mask) == (u32::from(host) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                let mask = if self.prefix == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(net) & mask) == (u128::from(host) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[derive(Clone)]
pub struct InterfaceConfig {
    /// Raw 32-byte private key (base64-decoded). Never logged.
    pub private_key: [u8; 32],
    pub addresses: Vec<Cidr>,
    pub dns: Vec<IpAddr>,
    pub listen_port: Option<u16>,
}

// Manual Debug: a derived Debug would print the private key bytes.
impl fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceConfig")
            .field("private_key", &"<redacted>")
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("listen_port", &self.listen_port)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    /// Raw 32-byte preshared key. Never logged.
    pub preshared_key: Option<[u8; 32]>,
    /// Endpoint as written in the config (`host:port`); resolution to a
    /// socket address happens once at startup (DESIGN.md §4.2).
    pub endpoint: String,
    pub allowed_ips: Vec<Cidr>,
    pub persistent_keepalive: Option<u16>,
}

impl PeerConfig {
    /// The endpoint parsed as a literal socket address, if it is one.
    pub fn endpoint_addr(&self) -> Option<SocketAddr> {
        self.endpoint.parse().ok()
    }
}

/// A parsed WireGuard client configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Io(String),
    MissingInterface,
    MissingPeer,
    MissingField {
        section: &'static str,
        key: &'static str,
    },
    InvalidKey {
        key: &'static str,
        reason: String,
    },
    InvalidCidr(String),
    InvalidIp {
        key: &'static str,
        value: String,
    },
    InvalidEndpoint(String),
    InvalidNumber {
        key: &'static str,
        value: String,
    },
    MalformedLine(String),
    UnknownSection(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "cannot read config: {msg}"),
            Self::MissingInterface => write!(f, "config has no [Interface] section"),
            Self::MissingPeer => write!(f, "config has no [Peer] section"),
            Self::MissingField { section, key } => {
                write!(f, "[{section}] is missing required key {key}")
            }
            Self::InvalidKey { key, reason } => write!(f, "invalid {key}: {reason}"),
            Self::InvalidCidr(v) => write!(f, "invalid CIDR/address: {v}"),
            Self::InvalidIp { key, value } => write!(f, "invalid IP for {key}: {value}"),
            Self::InvalidEndpoint(v) => write!(f, "invalid Endpoint (want host:port): {v}"),
            Self::InvalidNumber { key, value } => write!(f, "invalid number for {key}: {value}"),
            Self::MalformedLine(line) => write!(f, "malformed line (want Key = Value): {line}"),
            Self::UnknownSection(name) => write!(f, "unknown section [{name}]"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn decode_key(key: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = B64
        .decode(value.trim())
        .map_err(|e| ConfigError::InvalidKey {
            key,
            reason: format!("not valid base64 ({e})"),
        })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ConfigError::InvalidKey {
        key,
        reason: format!("must decode to 32 bytes, got {}", bytes.len()),
    })
}

fn parse_u16(key: &'static str, value: &str) -> Result<u16, ConfigError> {
    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidNumber {
            key,
            value: value.trim().to_string(),
        })
}

fn split_list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn validate_endpoint(value: &str) -> Result<String, ConfigError> {
    let value = value.trim();
    if value.parse::<SocketAddr>().is_ok() {
        return Ok(value.to_string());
    }
    // host:port — split at the last colon so bracketed IPv6 hosts work.
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(ConfigError::InvalidEndpoint(value.to_string()));
    };
    if host.is_empty() || port.parse::<u16>().is_err() {
        return Err(ConfigError::InvalidEndpoint(value.to_string()));
    }
    Ok(value.to_string())
}

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<[u8; 32]>,
    addresses: Vec<Cidr>,
    dns: Vec<IpAddr>,
    listen_port: Option<u16>,
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<String>,
    allowed_ips: Vec<Cidr>,
    persistent_keepalive: Option<u16>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        enum Section {
            Interface,
            Peer(usize),
        }

        let mut interface: Option<InterfaceBuilder> = None;
        let mut peers: Vec<PeerBuilder> = Vec::new();
        let mut current: Option<Section> = None;

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') {
                let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
                    return Err(ConfigError::MalformedLine(line.to_string()));
                };
                match name.trim().to_ascii_lowercase().as_str() {
                    "interface" => {
                        interface = Some(InterfaceBuilder::default());
                        current = Some(Section::Interface);
                    }
                    "peer" => {
                        peers.push(PeerBuilder::default());
                        current = Some(Section::Peer(peers.len() - 1));
                    }
                    other => return Err(ConfigError::UnknownSection(other.to_string())),
                }
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(ConfigError::MalformedLine(line.to_string()));
            };
            // Keys match case-insensitively, like the section names above:
            // "PreSharedKey" and "PresharedKey" are the same key.
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            let Some(section) = &current else {
                return Err(ConfigError::MalformedLine(line.to_string()));
            };
            match section {
                Section::Interface => {
                    let b = interface.as_mut().expect("interface builder exists");
                    match key.as_str() {
                        "privatekey" => b.private_key = Some(decode_key("PrivateKey", value)?),
                        "address" => {
                            for item in split_list(value) {
                                b.addresses.push(Cidr::parse(item)?);
                            }
                        }
                        "dns" => {
                            for item in split_list(value) {
                                let ip: IpAddr =
                                    item.parse().map_err(|_| ConfigError::InvalidIp {
                                        key: "DNS",
                                        value: item.to_string(),
                                    })?;
                                b.dns.push(ip);
                            }
                        }
                        "listenport" => b.listen_port = Some(parse_u16("ListenPort", value)?),
                        _ => {} // wg-quick extras (Table, MTU, PreUp, …): ignored.
                    }
                }
                Section::Peer(idx) => {
                    let b = &mut peers[*idx];
                    match key.as_str() {
                        "publickey" => b.public_key = Some(decode_key("PublicKey", value)?),
                        "presharedkey" => {
                            b.preshared_key = Some(decode_key("PreSharedKey", value)?)
                        }
                        "endpoint" => b.endpoint = Some(validate_endpoint(value)?),
                        "allowedips" => {
                            for item in split_list(value) {
                                b.allowed_ips.push(Cidr::parse(item)?);
                            }
                        }
                        "persistentkeepalive" => {
                            b.persistent_keepalive = Some(parse_u16("PersistentKeepalive", value)?)
                        }
                        _ => {}
                    }
                }
            }
        }

        let iface = interface.ok_or(ConfigError::MissingInterface)?;
        if peers.is_empty() {
            return Err(ConfigError::MissingPeer);
        }
        let interface = InterfaceConfig {
            private_key: iface.private_key.ok_or(ConfigError::MissingField {
                section: "Interface",
                key: "PrivateKey",
            })?,
            addresses: {
                if iface.addresses.is_empty() {
                    return Err(ConfigError::MissingField {
                        section: "Interface",
                        key: "Address",
                    });
                }
                iface.addresses
            },
            dns: iface.dns,
            listen_port: iface.listen_port,
        };
        let mut out_peers = Vec::with_capacity(peers.len());
        for peer in peers {
            out_peers.push(PeerConfig {
                public_key: peer.public_key.ok_or(ConfigError::MissingField {
                    section: "Peer",
                    key: "PublicKey",
                })?,
                preshared_key: peer.preshared_key,
                endpoint: peer.endpoint.ok_or(ConfigError::MissingField {
                    section: "Peer",
                    key: "Endpoint",
                })?,
                allowed_ips: {
                    if peer.allowed_ips.is_empty() {
                        return Err(ConfigError::MissingField {
                            section: "Peer",
                            key: "AllowedIPs",
                        });
                    }
                    peer.allowed_ips
                },
                persistent_keepalive: peer.persistent_keepalive,
            });
        }
        Ok(Config {
            interface,
            peers: out_peers,
        })
    }
}

// Convenience so callers can build `IpAddr`s in tests without extra imports.
#[doc(hidden)]
pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid IP literal")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../examples/wgproxyrs.conf.example");

    #[test]
    fn default_bind_is_localhost() {
        let bind = default_bind();
        assert!(bind.ip().is_loopback());
        assert_eq!(bind.port(), 1080);
    }

    #[test]
    fn parses_example_file() {
        let cfg = Config::parse(EXAMPLE).expect("example config must parse");
        assert_eq!(cfg.interface.addresses.len(), 1);
        assert_eq!(cfg.interface.addresses[0].addr, ip("10.0.0.2"));
        assert_eq!(cfg.interface.addresses[0].prefix, 32);
        assert_eq!(cfg.interface.dns, vec![ip("10.0.0.1")]);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].endpoint, "vpn.example.com:51820");
        assert_eq!(cfg.peers[0].persistent_keepalive, Some(25));
        assert!(cfg.peers[0].allowed_ips[0].contains(ip("203.0.113.7")));
    }

    #[test]
    fn parses_multi_address_and_allowed_ips() {
        let text = "\
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.0.0.2/32, 10.0.0.3/32, fd00::2/128
ListenPort = 51820

[Peer]
PublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
PresharedKey = QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=
Endpoint = 203.0.113.10:51820
AllowedIPs = 10.0.0.0/8, 192.168.0.0/16, ::/0
";
        let cfg = Config::parse(text).expect("multi config parses");
        assert_eq!(cfg.interface.addresses.len(), 3);
        assert_eq!(cfg.interface.addresses[2].addr, ip("fd00::2"));
        assert_eq!(cfg.interface.listen_port, Some(51820));
        assert!(cfg.peers[0].preshared_key.is_some());
        assert_eq!(cfg.peers[0].allowed_ips.len(), 3);
        assert!(
            cfg.peers[0].allowed_ips[0].contains(ip("10.9.8.7")),
            "10/8 contains"
        );
        assert!(!cfg.peers[0].allowed_ips[0].contains(ip("11.0.0.1")));
        assert_eq!(
            cfg.peers[0].endpoint_addr(),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                51820
            ))
        );
    }

    #[test]
    fn parses_eduvpn_shaped_config_canonical_spellings() {
        // Shaped like a real eduVPN profile: canonical `PreSharedKey`
        // (capital S), an `MTU` line (wg-quick extra, tolerated), dual-
        // stack Address/DNS, and a full-tunnel AllowedIPs pair. The
        // v0.2.0 parser matched keys case-sensitively and silently
        // dropped the preshared key from exactly this shape of config.
        let text = "\
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.0.0.1, fd00::1
MTU = 1392

[Peer]
PublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
PreSharedKey = QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = eduvpn.example.com:51820
PersistentKeepalive = 25
";
        let cfg = Config::parse(text).expect("eduVPN-shaped config parses");
        // The preshared key must be the exact 32 bytes from the file:
        // base64 "QEFC…" decodes to 0x40..=0x5f.
        let expected_psk: [u8; 32] = std::array::from_fn(|i| 0x40 + i as u8);
        assert_eq!(cfg.peers[0].preshared_key, Some(expected_psk));
        assert_eq!(cfg.interface.addresses.len(), 2);
        assert_eq!(cfg.interface.addresses[0].addr, ip("10.0.0.2"));
        assert_eq!(cfg.interface.addresses[1].addr, ip("fd00::2"));
        assert_eq!(cfg.interface.dns, vec![ip("10.0.0.1"), ip("fd00::1")]);
        assert_eq!(cfg.peers[0].allowed_ips.len(), 2);
        assert!(cfg.peers[0].allowed_ips[0].contains(ip("203.0.113.7")));
        assert!(cfg.peers[0].allowed_ips[1].contains(ip("2001:db8::1")));
        assert_eq!(cfg.peers[0].endpoint, "eduvpn.example.com:51820");
        assert_eq!(cfg.peers[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn parses_mixed_case_key_spellings() {
        // Every known key, in a scrambled case, must produce exactly the
        // config its canonical spelling produces.
        let canonical = "\
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.0.0.2/32, fd00::2/128
DNS = 10.0.0.1
ListenPort = 51820

[Peer]
PublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
PreSharedKey = QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
";
        let mixed = "\
[InTeRfAcE]
privatekey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
ADDRESS = 10.0.0.2/32, fd00::2/128
Dns = 10.0.0.1
LISTENPORT = 51820

[PEER]
publickey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
pReShArEdKeY = QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=
ENDPOINT = vpn.example.com:51820
allowedips = 0.0.0.0/0, ::/0
PersistentKeepAlive = 25
";
        let a = Config::parse(canonical).expect("canonical config parses");
        let b = Config::parse(mixed).expect("mixed-case config parses");
        assert_eq!(a.interface.private_key, b.interface.private_key);
        assert_eq!(a.interface.addresses, b.interface.addresses);
        assert_eq!(a.interface.dns, b.interface.dns);
        assert_eq!(a.interface.listen_port, b.interface.listen_port);
        assert_eq!(a.peers[0].public_key, b.peers[0].public_key);
        assert_eq!(a.peers[0].preshared_key, b.peers[0].preshared_key);
        assert!(b.peers[0].preshared_key.is_some());
        assert_eq!(a.peers[0].endpoint, b.peers[0].endpoint);
        assert_eq!(a.peers[0].allowed_ips, b.peers[0].allowed_ips);
        assert_eq!(
            a.peers[0].persistent_keepalive,
            b.peers[0].persistent_keepalive
        );
    }

    #[test]
    fn error_missing_interface() {
        let text = "[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::MissingInterface)
        ));
    }

    #[test]
    fn error_missing_peer() {
        let text = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n";
        assert!(matches!(Config::parse(text), Err(ConfigError::MissingPeer)));
    }

    #[test]
    fn error_missing_private_key() {
        let text = "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::MissingField {
                key: "PrivateKey",
                ..
            })
        ));
    }

    #[test]
    fn error_missing_endpoint() {
        let text = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::MissingField {
                key: "Endpoint",
                ..
            })
        ));
    }

    #[test]
    fn error_bad_base64_key() {
        let text = "[Interface]\nPrivateKey = !!!not-base64!!!\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::InvalidKey {
                key: "PrivateKey",
                ..
            })
        ));
    }

    #[test]
    fn error_short_key() {
        // Valid base64, but decodes to 3 bytes instead of 32.
        let text = "[Interface]\nPrivateKey = AQID\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::InvalidKey {
                key: "PrivateKey",
                ..
            })
        ));
    }

    #[test]
    fn error_bad_cidr() {
        let text = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/33\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::InvalidCidr(_))
        ));
    }

    #[test]
    fn error_bad_endpoint() {
        let text = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = no-port-here\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::InvalidEndpoint(_))
        ));
    }

    #[test]
    fn error_bad_number() {
        let text = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\nListenPort = soon\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::InvalidNumber {
                key: "ListenPort",
                ..
            })
        ));
    }

    #[test]
    fn error_malformed_line() {
        let text = "[Interface]\nPrivateKey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh4\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::MalformedLine(_))
        ));
    }

    #[test]
    fn error_unknown_section() {
        let text = "[Server]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::UnknownSection(_))
        ));
    }

    #[test]
    fn error_bad_dns_ip() {
        let text = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.2/32\nDNS = not-an-ip\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\nEndpoint = h:1\nAllowedIPs = 0.0.0.0/0\n";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::InvalidIp { key: "DNS", .. })
        ));
    }

    #[test]
    fn private_key_never_in_debug() {
        let cfg = Config::parse(EXAMPLE).unwrap();
        let dbg = format!("{:?}", cfg.interface);
        assert!(!dbg.contains("AAEC"), "debug output must redact keys");
    }
}
