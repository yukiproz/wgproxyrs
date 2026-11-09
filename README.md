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

**v0.1 works end to end** (see [DESIGN.md](DESIGN.md) and
[ROADMAP.md](ROADMAP.md)):

- Stock WireGuard `.conf` parsing, `genkey`, and a `--check` mode that
  validates a config without touching the network.
- boringtun tunnel core + smoltcp netstack, driven by one engine thread;
  transports: real UDP in production, in-memory channels in tests.
- SOCKS5 (no-auth, CONNECT, IPv4/IPv6/domain) and HTTP CONNECT proxies.
  Domain names resolve *through the tunnel* via the config's DNS server.
- Fail-closed, verified by tests: with no live handshake, CONNECT is
  refused and nothing is opened.
- Readiness signal: the binary logs tunnel up/down transitions with
  handshake age, and the library exposes the same status to callers.

Not yet: SOCKS5 UDP ASSOCIATE and proxy auth for non-localhost binds
(Phase 3 — binding wider than localhost is currently possible via
`--bind`, but do it only on networks you trust until auth lands).

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
