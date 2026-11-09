//! wgproxyrs — a fully userspace WireGuard client that exposes the tunnel
//! as a local SOCKS5 / HTTP proxy. No interface, no routes, no root.
//!
//! This crate is currently a scaffold: the module layout and CLI surface
//! are in place, the tunnel implementation is not. See `DESIGN.md`.

pub mod config;
pub mod proxy;
pub mod tunnel;
