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
//! - [`proxy`] — SOCKS5 (CONNECT + UDP ASSOCIATE), HTTP CONNECT and TCP
//!   tunnel front-ends over abstract async streams, with optional proxy
//!   authentication. Fail-closed: no live handshake, no connection, no
//!   fallback.
//! - [`info`] — the health/info endpoint: tunnel truth as JSON for
//!   launcher scripts.

pub mod config;
pub mod info;
pub mod keys;
pub mod proxy;
pub mod stack;
pub mod tunnel;
