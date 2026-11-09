# wgproxyrs

A fully userspace WireGuard client in Rust that exposes the tunnel as a local
**SOCKS5 / HTTP proxy** — instead of creating a network interface.

Like `ssh -D`, but over WireGuard.

## Why

Setting up a WireGuard interface normally means root, `CAP_NET_ADMIN`, new
routes, and DNS changes that affect the whole machine. wgproxyrs does none of
that:

- The WireGuard protocol runs inside an ordinary process. Its encrypted UDP
  underlay leaves via the host's main interface, like any other app's traffic.
- **No interface is created** — no `wg0`, no new routes, no DNS changes, no
  interaction with the host's other networks (Tailscale included).
- **No root, no sudo** — there is no kernel interface to configure.
- Only applications pointed at the local proxy port use the tunnel. Everything
  else on the machine is untouched, by construction.
- Lifecycle is a plain process: start it when a session opens, kill it when
  the session ends.
- **Fail-closed by design:** if the tunnel is down, the proxy refuses
  connections. It never falls back to direct traffic.

## Status

**v0.3 — wireproxy parity set complete, config MTU honoured** (see
[DESIGN.md](DESIGN.md) and [ROADMAP.md](ROADMAP.md)):

- Stock WireGuard `.conf` parsing, `genkey`, and a `--check` mode that
  validates a config without touching the network.
- boringtun tunnel core + smoltcp netstack, driven by one engine thread;
  transports: real UDP in production (one shared socket, demultiplexed
  per peer, when a config has several peers), in-memory channels in
  tests.
- **Multi-peer for real:** one tunnel per `[Peer]`, cryptokey routing by
  longest-prefix match over all peers' AllowedIPs, in both directions.
- SOCKS5 — CONNECT (IPv4/IPv6/domain) **and UDP ASSOCIATE** (RFC 1928,
  FRAG=0 only) — and HTTP CONNECT. Domain names resolve *through the
  tunnel* via the config's DNS server.
- **TCP tunnels** (`--tcp-tunnel <listen>=<target>`, repeatable):
  wireproxy's TCPClient equivalent, no proxy protocol on the local leg.
- **Proxy auth** (`--proxy-user` / `--proxy-pass`): RFC 1929 for SOCKS5,
  HTTP Basic `Proxy-Authorization` for CONNECT. Binding a non-loopback
  address without auth prints a loud startup warning.
- **Health/info endpoint** (`--info-bind`): tunnel truth as JSON, plus a
  `wgproxyrs status --info <addr>` probe that exits 0 only when the
  tunnel is up — built for launcher scripts.
- **Daemon mode** (`--daemon`, `--pidfile`, `--log-file`, `--silent`).
- **Config MTU honoured** (`MTU` in `[Interface]`, validated
  576..=9000; `--mtu <N>` overrides it — for underlays where the
  profile's MTU does not fit). Default 1280, the IPv6 floor:
  always safe, deliberately not always optimal. `--check` reports
  the effective MTU and where it came from.
- Fail-closed everywhere, verified by tests: with no live handshake,
  CONNECT is refused, UDP ASSOCIATE is refused, TCP tunnels drop
  connections, and proxy auth never bypasses the tunnel-state check.
- Kernel interop proven live: this client against a kernel WireGuard
  server passed SOCKS5 + HTTP CONNECT marker fetches and fail-closed
  checks (2026-11-09).

Deliberately not implemented (see ROADMAP.md): transparent SNI proxy,
UDP static tunnels, AmneziaWG obfuscation, wireproxy config format.

## Usage

```bash
# Generate a keypair (or take one from your WireGuard provider):
wgproxyrs genkey

# Validate a config without any network use:
wgproxyrs --config ./wg0.conf --check

# Run: SOCKS5 on 127.0.0.1:1080, optionally HTTP CONNECT too.
wgproxyrs --config ./wg0.conf --bind 127.0.0.1:1080 --http-bind 127.0.0.1:8080

# Then point proxy-aware applications at it, e.g.:
curl --proxy socks5h://127.0.0.1:1080 https://example.com

# UDP ASSOCIATE works too (DNS over the tunnel, QUIC, game traffic):
curl --proxy socks5h://127.0.0.1:1080 ...

# Fixed TCP tunnel (no proxy protocol on the local leg):
wgproxyrs --config ./wg0.conf --tcp-tunnel 127.0.0.1:15432=10.0.0.5:5432

# Proxy auth (required by clients when set; both flags or neither):
wgproxyrs --config ./wg0.conf --proxy-user hadi --proxy-pass s3cret

# Health endpoint + one-line readiness probe for launchers:
wgproxyrs --config ./wg0.conf --info-bind 127.0.0.1:18099
wgproxyrs status --info 127.0.0.1:18099   # exit 0 only when tunnel is up
curl -s http://127.0.0.1:18099/
# {"status":"up","handshake_age_secs":3,"endpoint":"203.0.113.1:51820","per_peer":[...]}

# Daemon mode (pidfile default: ./<config-stem>.pid next to your shell's cwd):
wgproxyrs --config ./wg0.conf --daemon --log-file ./wgproxyrs.log
kill "$(cat ./wg0.pid)"

# Tunnel MTU: the config's MTU line wins by default; --mtu overrides it
# (e.g. a 1392 profile on a 1360 underlay fits at ~1300):
wgproxyrs --config ./wg0.conf --mtu 1300
```

## Lineage

The pattern was proven in Go by
[wireproxy](https://github.com/windtf/wireproxy) — still the only mature
implementation of it, in any language. No mature Rust equivalent exists:
[boringtun](https://github.com/cloudflare/boringtun) is a production-proven
WireGuard core but builds TUN interfaces, and
[rustyguard](https://github.com/conradludgate/rustyguard) is an elegant
sans-io library with no release yet. wgproxyrs combines their strengths —
see DESIGN.md for the full survey and what is borrowed from each.

## Licence

MIT
