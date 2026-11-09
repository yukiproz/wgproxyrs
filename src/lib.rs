//! wgproxyrs — a fully userspace WireGuard client that exposes the tunnel
//! as a local SOCKS5 / HTTP proxy. No interface, no routes, no root.
//!
//! Layout:
//! - [`config`] — stock WireGuard `.conf` parsing.
//! - [`keys`] — X25519 key generation (`genkey`).
//! - [`tunnel`] — boringtun core behind a transport trait (UDP in
//!   production, in-memory channels in tests).
//! - [`stack`] — the smoltcp netstack engine: tunnel + TCP/DNS bridging
//!   on a dedicated thread, reached through byte channels.
//! - [`proxy`] — SOCKS5 and HTTP CONNECT front-ends over abstract async
//!   streams. Fail-closed: no live handshake, no connection, no fallback.

pub mod config;
pub mod keys;
pub mod proxy;
pub mod stack;
pub mod tunnel;
