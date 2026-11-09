# wgproxyrs — Roadmap

## Phase 0 — Scaffold (done 2026-11-09)

- [x] Repository, licence, README, DESIGN
- [x] Compiling binary skeleton: CLI surface (`--config`, `--bind`,
      `--help`, `--version`), module layout (`config`, `tunnel`, `proxy`)
- [x] Prior-art survey recorded in DESIGN.md

## Phase 1 — Tunnel spike (done 2026-11-09)

- [x] boringtun (crates.io release) handshake against a real WireGuard peer
      (second boringtun instance; in-memory transport in the test suite,
      real UDP loopback in CI's ignored test)
- [x] smoltcp netstack wired to the tunnel: one proxied TCP flow end to end
- [x] Fail-closed check: kill the peer, prove the proxy refuses

## Phase 2 — v0.1 (done 2026-11-09, one item partial)

- [x] Stock `.conf` parsing (`[Interface]` / `[Peer]`) + CLI flags
- [x] SOCKS5 TCP CONNECT with DNS through the tunnel (socks5h semantics)
- [x] HTTP CONNECT
- [x] Readiness signal (handshake age) for callers such as bibx
- [x] Bind `127.0.0.1` by default; auth when bound wider
      *(auth landed in Phase 3)*

## Phase 3 — wireproxy parity (done 2026-11-09, released as v0.2.0)

- [x] SOCKS5 UDP ASSOCIATE, complete and tested (RFC 1928; TCP control
      connection governs the session; FRAG != 0 dropped; echo + DNS
      round trips in the e2e suite, plus a real-UDP variant in CI)
- [x] Multi-peer for real: one tunnel per `[Peer]`, cryptokey routing
      (longest-prefix over all AllowedIPs, both directions); the v0.1
      "first peer only" behaviour is gone
- [x] TCP tunnels (`--tcp-tunnel <listen>=<target>`, repeatable) —
      wireproxy's TCPClient equivalent
- [x] Proxy auth for non-localhost binds (`--proxy-user`/`--proxy-pass`:
      RFC 1929 for SOCKS5, HTTP Basic for CONNECT; loud startup warning
      when a non-loopback bind has no auth)
- [x] Health/info endpoint (`--info-bind`, JSON: status, handshake age,
      per-peer detail) + `wgproxyrs status --info <addr>` probe
      (exit 0 only when up)
- [x] Daemon / background mode (`--daemon`, `--pidfile`, `--log-file`,
      `--silent`), smoke-tested in CI
- [ ] Re-evaluate rustyguard as an alternative core (it had no release yet
      at survey time; the core boundary is kept swappable for this reason)

## Explicitly out of scope

- Transparent SNI proxy — needs TLS interception/routing smarts that
  contradict the small, auditable proxy surface; apps that speak SOCKS5
  or CONNECT cover the intended workloads.
- UDP static tunnels (wireproxy's UDPClient/UDPServer) — wireproxy
  itself lists UDP tunnels as TODO; SOCKS5 UDP ASSOCIATE covers dynamic
  UDP needs.
- AmneziaWG obfuscation — a different protocol dialect (junk packets,
  header mangling) aimed at DPI evasion; out of this tool's threat
  model and would fork the boringtun core.
- wireproxy config-format compatibility — stock `.conf` + CLI flags is
  this tool's standing UX edge over wireproxy; it is kept deliberately.
