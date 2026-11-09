# wgproxyrs — Roadmap

## Phase 0 — Scaffold (done 2026-11-09)

- [x] Repository, licence, README, DESIGN
- [x] Compiling binary skeleton: CLI surface (`--config`, `--bind`,
      `--help`, `--version`), module layout (`config`, `tunnel`, `proxy`)
- [x] Prior-art survey recorded in DESIGN.md

## Phase 1 — Tunnel spike

- [ ] boringtun (crates.io release) handshake against a real WireGuard peer
- [ ] smoltcp netstack wired to the tunnel: one proxied TCP flow end to end
- [ ] Fail-closed check: kill the peer, prove the proxy refuses

## Phase 2 — v0.1

- [ ] Stock `.conf` parsing (`[Interface]` / `[Peer]`) + CLI flags
- [ ] SOCKS5 TCP CONNECT with DNS through the tunnel (socks5h semantics)
- [ ] HTTP CONNECT
- [ ] Readiness signal (handshake age) for callers such as bibx
- [ ] Bind `127.0.0.1` by default; auth when bound wider

## Phase 3 — Differentiators

- [ ] SOCKS5 UDP ASSOCIATE, complete and tested
- [ ] Daemon / background mode and health endpoint (parity with wireproxy)
- [ ] Re-evaluate rustyguard as an alternative core (it had no release yet
      at survey time; the core boundary is kept swappable for this reason)
