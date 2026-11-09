//! The health/info endpoint (`--info-bind`).
//!
//! A tiny HTTP service whose only job is to tell launcher scripts the
//! truth about the tunnel: `GET /` (any path) returns
//!
//! ```json
//! {"status":"up","handshake_age_secs":3,"endpoint":"203.0.113.1:51820","per_peer":[{"endpoint":"203.0.113.1:51820","status":"up","handshake_age_secs":3}]}
//! ```
//!
//! - `status` is `up` iff at least one peer has a live handshake;
//! - `handshake_age_secs` is the freshest peer's handshake age, or
//!   `null` while down;
//! - `endpoint` is the first peer's endpoint as written in the config;
//! - `per_peer` carries the per-peer truth behind the aggregate.
//!
//! The HTTP status code is always 200 when the endpoint itself answers —
//! the *body* carries tunnel state, so a launcher can distinguish "the
//! proxy process is gone" (connect failure) from "the proxy is up but
//! the tunnel is down" (200 + `"status":"down"`). `wgproxyrs status
//! --info <addr>` wraps exactly that distinction in an exit code.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::stack::{EngineHandle, TunnelStatus};

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn age_json(age: Option<Duration>) -> String {
    match age {
        Some(d) => d.as_secs().to_string(),
        None => "null".to_string(),
    }
}

/// Render the status document for a [`TunnelStatus`] snapshot.
pub fn render_status_json(status: &TunnelStatus) -> String {
    let endpoint = status
        .peers
        .first()
        .map(|p| p.endpoint.as_str())
        .unwrap_or("");
    let mut per_peer = String::new();
    for (i, peer) in status.peers.iter().enumerate() {
        if i > 0 {
            per_peer.push(',');
        }
        per_peer.push_str(&format!(
            "{{\"endpoint\":\"{}\",\"status\":\"{}\",\"handshake_age_secs\":{}}}",
            json_escape(&peer.endpoint),
            if peer.up { "up" } else { "down" },
            age_json(peer.handshake_age),
        ));
    }
    format!(
        "{{\"status\":\"{}\",\"handshake_age_secs\":{},\"endpoint\":\"{}\",\"per_peer\":[{}]}}",
        if status.up { "up" } else { "down" },
        age_json(status.handshake_age),
        json_escape(endpoint),
        per_peer,
    )
}

/// Handle one info request over any async stream (a real TCP connection
/// in production, a duplex/loopback stream in tests). The request line is
/// read and ignored — every request gets the same document.
pub async fn handle_info<S>(mut stream: S, engine: EngineHandle) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read until the header terminator (bounded), then answer.
    let mut raw: Vec<u8> = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") && raw.len() < 8 * 1024 {
        match stream.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => raw.push(byte[0]),
            Err(e) => return Err(e),
        }
    }
    let body = render_status_json(&engine.status());
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

pub async fn run_info_listener(listener: TcpListener, engine: EngineHandle) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let engine = engine.clone();
                tokio::spawn(async move {
                    let _ = handle_info(stream, engine).await;
                });
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Interpret a fetched info document: is the tunnel up? Deliberately a
/// small hand-rolled parse (no JSON dependency for one field): the
/// *first* `"status"` key is the top-level one — `per_peer` entries
/// follow it and their `"status"` keys appear later in the document.
pub fn status_is_up(body: &str) -> bool {
    let Some(pos) = body.find("\"status\"") else {
        return false;
    };
    let rest = &body[pos + "\"status\"".len()..];
    let Some(colon) = rest.find(':') else {
        return false;
    };
    rest[colon + 1..].trim_start().starts_with("\"up\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::PeerStatus;

    fn status(up: bool) -> TunnelStatus {
        TunnelStatus {
            up,
            handshake_age: if up {
                Some(Duration::from_secs(7))
            } else {
                None
            },
            peers: vec![
                PeerStatus {
                    endpoint: "203.0.113.1:51820".into(),
                    up,
                    handshake_age: if up {
                        Some(Duration::from_secs(7))
                    } else {
                        None
                    },
                },
                PeerStatus {
                    endpoint: "peer2.example.com:51820".into(),
                    up: false,
                    handshake_age: None,
                },
            ],
        }
    }

    #[test]
    fn renders_up_and_down_truthfully() {
        let up_json = render_status_json(&status(true));
        assert!(up_json.starts_with("{\"status\":\"up\""), "{up_json}");
        assert!(up_json.contains("\"handshake_age_secs\":7"), "{up_json}");
        assert!(
            up_json.contains("\"endpoint\":\"203.0.113.1:51820\""),
            "{up_json}"
        );
        assert!(
            up_json.contains("\"per_peer\":[{\"endpoint\":\"203.0.113.1:51820\",\"status\":\"up\""),
            "{up_json}"
        );
        assert!(status_is_up(&up_json));

        let down_json = render_status_json(&status(false));
        assert!(down_json.starts_with("{\"status\":\"down\""), "{down_json}");
        assert!(
            down_json.contains("\"handshake_age_secs\":null"),
            "{down_json}"
        );
        assert!(!status_is_up(&down_json));
    }

    #[test]
    fn status_parse_is_strict() {
        assert!(!status_is_up("not json"));
        assert!(!status_is_up("{\"status\":\"down\"}"));
        assert!(status_is_up("{\"status\":\"up\",\"per_peer\":[]}"));
        assert!(!status_is_up(""));
    }
}
