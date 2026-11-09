//! The WireGuard tunnel: protocol core + userspace netstack.
//!
//! Scaffold state: not implemented. Phase 1 of the roadmap wires the
//! boringtun core (crates.io release) to a smoltcp netstack behind a
//! sans-io style byte boundary, so the core stays swappable.
//!
//! The one property this module must never break: **fail-closed**. When
//! the tunnel is not up, callers get an error — never a direct connection.

/// Whether the tunnel can currently carry traffic.
///
/// Until the tunnel exists, the only honest answer is `Down` — which is
/// exactly what fail-closed means at scaffold stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// No live handshake; the proxy must refuse connections.
    Down,
}

pub fn state() -> TunnelState {
    TunnelState::Down
}
