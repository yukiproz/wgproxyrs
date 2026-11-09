//! Proxy listeners: SOCKS5 first, HTTP CONNECT second.
//!
//! Scaffold state: not implemented. Listeners only ever forward into the
//! tunnel (see `tunnel`); there is deliberately no code path here that can
//! open a direct connection, which is what makes fail-closed structural
//! rather than a configuration promise.
