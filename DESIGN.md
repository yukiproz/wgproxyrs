# wgproxyrs — Design

## 1. The pattern

A fully userspace WireGuard client that exposes the tunnel as a local
SOCKS5 / HTTP proxy instead of creating a network interface:

- The WireGuard protocol runs inside an ordinary process; its encrypted UDP
  underlay leaves via the host's main interface like any other app's traffic.
- Only applications pointed at the local proxy port get the tunnel.
- No interface, no routes, no DNS changes, no root / `CAP_NET_ADMIN` / sudo.
- Lifecycle is a plain process, which maps naturally onto session-bounded
  VPN use (e.g. an eduVPN session window).

## 2. Prior art survey (checked 2026-11-09, GitHub + crates.io APIs)

| Project | Same pattern? | Evidence | Verdict |
|---|---|---|---|
| windtf/wireproxy (Go) | Yes | 5,885 stars, 416 forks; latest release v1.1.3 (2026-07-16); last push 2026-10-12 | Mature — the only mature direct equivalent. Gaps: custom config format; SOCKS5 UDP listed as TODO in its README (a Sep 2026 commit fixed a UDP ASSOCIATE binding bug, so support looks partial) |
| cloudflare/boringtun (Rust) | No — protocol core / TUN CLI | 7,254 stars; deployed in Cloudflare WARP on millions of devices; commits to Jun 2026 but latest GitHub release is v0.5.2 (2022) | Mature as a building block only. Its CLI creates a TUN interface and needs `CAP_NET_ADMIN`. README warns master is mid-restructuring — use the crates.io release |
| conradludgate/rustyguard (Rust) | No — protocol library | 87 stars; zero releases; created Jul 2024; actively developed, last push 2026-11-03 | Not mature yet, but alive. Sans-io design is the inspiration for keeping our core swappable |
| wireguard-proxy (crates.io) | No — UDP-over-TCP/TLS tunnel | Single release v0.1.0 (2019); 1,827 downloads total; 169 LOC | Dead, wrong category (a proxyguard-style transport bridge) |
| wgproxy (crates.io, KizzyCode) | No — L4 relay / stateful NAT | v0.3.0 (Jan 2026); 356 downloads; 441 LOC | Wrong category: bridges encrypted WireGuard traffic via a jump host, never terminates it. Also occupies the crate name `wgproxy` |

Conclusion: no mature Rust implementation of this pattern exists. That gap
is why this repo exists.

## 3. Architecture (planned)

```
                ┌──────────────────── wgproxyrs process ────────────────────┐
 proxy-aware    │                                                            │
 apps ──SOCKS5/ ┼─▶ proxy listeners ─▶ smoltcp netstack ─▶ WireGuard core ──┼─▶ UDP socket
        HTTP    │      (tokio)            (userspace TCP/IP)   (boringtun)   │   (main interface)
                └────────────────────────────────────────────────────────────┘
```

- **WireGuard core:** boringtun, pinned to the crates.io release. Kept behind
  a byte-in/byte-out (sans-io style) boundary, following rustyguard's design
  lesson, so the core can be swapped if rustyguard matures.
- **Netstack:** smoltcp — the same combination onetun already proved
  (boringtun + smoltcp) on the Rust side.
- **Runtime:** tokio for the proxy listeners and the tunnel event loop.
- **Proxy protocols:** SOCKS5 first, HTTP CONNECT second. The SOCKS5 surface
  is small and security-relevant; whether it is hand-rolled or a crate is an
  implementation-phase decision.

## 4. Non-negotiable properties

1. **Fail-closed.** Tunnel down or handshake dead ⇒ the proxy refuses
   connections. Never fall back to direct (main-interface) traffic. A silent
   leak defeats the entire purpose of the tool.
2. **DNS inside the tunnel.** Resolution for proxied traffic happens through
   the tunnel (socks5h semantics). The one legitimate outside lookup is
   resolving the WireGuard endpoint hostname itself.
3. **Localhost by default.** Bind `127.0.0.1` unless explicitly configured
   otherwise; proxy auth required when bound wider.
4. **No key material in logs, ever.** Config files hold a private key:
   document `0600` expectations; real configs are gitignored in this repo.
5. **Trustworthy readiness signal.** A caller (e.g. a fetch queue) must be
   able to tell the tunnel is actually up: handshake age / endpoint
   reachability via a status output or health endpoint.

## 5. UX commitments (where we intend to beat wireproxy)

- **Accept a stock WireGuard `.conf` directly** (`[Interface]` / `[Peer]`),
  with proxy settings as CLI flags or a small extra section — no custom
  config format to learn.
- Complete, tested **SOCKS5 UDP ASSOCIATE**, not a TODO.

## 6. Explicit non-goals

- Not a system-wide VPN tool; no kernel or netns mode, no GUI.
- No L4 relaying of encrypted traffic (that is wgproxy-the-crate's job).
- No UDP-over-TCP bridging in the core; a proxyguard-style TCP fallback, if
  ever wanted, is a separate feature.
- Performance parity with kernel WireGuard is not a goal: a userspace
  netstack is slower and uses more CPU. That is acceptable for the intended
  workload (proxy-aware tools fetching documents and data) and is stated
  here, in advance, rather than discovered later.

## 7. Decisions taken in the implementation phase (2026-11-09)

1. Proxy settings live in CLI flags (`--bind`, `--http-bind`); the `.conf`
   stays a pure stock WireGuard config.
2. SOCKS5 is hand-rolled against abstract async streams (small surface,
   fully testable over duplex streams); no proxy-protocol crate.
3. UDP ASSOCIATE is Phase 3; v0.1 ships TCP CONNECT + HTTP CONNECT.
4. Readiness signal: a shared tunnel-status value (up + handshake age)
   in the library, plus up/down transition logging in the binary. A
   health endpoint stays a Phase 3 candidate.
5. The tunnel + netstack live on one dedicated engine thread; proxy
   front-ends reach it only through byte channels and a DNS request
   channel. Multi-peer configs parse today, but v0.1 drives the first
   peer; AllowedIPs from all peers still gate destinations.

## 8. Phase 3 — wireproxy parity (2026-11-09, v0.2.0)

Decision 5 above is superseded: the engine now carries **one tunnel per
peer** and routes by cryptokey routing, exactly like WireGuard itself.

### Parity table

| wireproxy feature | wgproxyrs status |
|---|---|
| SOCKS5 proxy (TCP CONNECT) | ✅ since v0.1 |
| HTTP CONNECT proxy | ✅ since v0.1 |
| SOCKS5 UDP ASSOCIATE | ✅ Phase 3 (RFC 1928; FRAG=0 only; control connection governs lifetime) |
| Multi-peer + AllowedIPs routing | ✅ Phase 3 (longest-prefix, both directions; shared underlay socket demultiplexed by peer endpoint) |
| TCPClient tunnels (fixed forward) | ✅ Phase 3 (`--tcp-tunnel <listen>=<target>`) |
| TCPServer (reverse tunnel) | ❌ Not planned — the local-first use case (apps on this machine reaching into the tunnel) does not need it, and it would expose tunnel-side listeners by design |
| Proxy authentication | ✅ Phase 3 (`--proxy-user`/`--proxy-pass`; RFC 1929 / HTTP Basic) |
| Health/info endpoint | ✅ Phase 3 (`--info-bind` JSON + `wgproxyrs status --info <addr>` probe) |
| Daemon mode | ✅ Phase 3 (`--daemon` / `--pidfile` / `--log-file` / `--silent`) |
| UDPClient/UDPServer static tunnels | ❌ Out of scope — wireproxy lists UDP tunnels as TODO itself; UDP ASSOCIATE covers dynamic UDP |
| Transparent SNI proxy | ❌ Out of scope — see ROADMAP.md |
| AmneziaWG | ❌ Out of scope — different protocol dialect, different threat model |
| Config format | Stock `.conf` + CLI flags (wireproxy uses a custom format; ours is the standing UX edge, kept on purpose) |

### Decisions taken in Phase 3

6. **UDP ASSOCIATE rides the netstack**, not raw sockets: each session
   gets a smoltcp UDP socket in the engine, routed per datagram by the
   same cryptokey table as TCP. The local relay leg is a per-session UDP
   socket bound to the interface the control connection arrived on, so
   BND.ADDR is always reachable. Fragmented datagrams are dropped (RFC
   1928 permits this; reassembly state is an attack surface).
7. **Info endpoint returns HTTP 200 always** (when it answers at all):
   the body carries tunnel state, so a launcher distinguishes "process
   gone" (connect failure) from "tunnel down" (200 + `"status":"down"`).
   The `status` subcommand folds that into an exit code.
8. **Daemon mode forks before the async runtime exists** (fork is only
   safe single-threaded), with a readiness pipe: the parent reports
   success only after the child has setsid'd, redirected stdio and
   written the pidfile. Default pidfile: `./<config-stem>.pid`.
9. **Auth is checked before any tunnel work** and never instead of it:
   a 407 / auth failure reveals nothing about tunnel state, and a passed
   auth still faces the fail-closed destination checks.
