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
- [ ] Bind `127.0.0.1` by default *(done)*; auth when bound wider
      *(not yet — see README status)*

## Phase 3 — Differentiators

- [ ] SOCKS5 UDP ASSOCIATE, complete and tested
- [ ] Proxy auth for non-localhost binds
- [ ] Daemon / background mode and health endpoint (parity with wireproxy)
- [ ] Re-evaluate rustyguard as an alternative core (it had no release yet
      at survey time; the core boundary is kept swappable for this reason)
