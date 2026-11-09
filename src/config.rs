//! Configuration: a stock WireGuard `.conf` plus proxy settings.
//!
//! Scaffold state: defaults and the settings shape exist; `.conf` parsing
//! lands in Phase 2 of the roadmap.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Default proxy bind address: localhost only, always, unless the user
/// explicitly configures something wider (DESIGN.md §4.3).
pub fn default_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)
}

/// Runtime settings for one wgproxyrs session.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Path to a stock WireGuard `.conf` file.
    pub config_path: PathBuf,
    /// Address the SOCKS5 / HTTP proxy listeners bind to.
    pub bind: SocketAddr,
}

impl Settings {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            bind: default_bind(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_is_localhost() {
        let bind = default_bind();
        assert!(bind.ip().is_loopback());
        assert_eq!(bind.port(), 1080);
    }
}
