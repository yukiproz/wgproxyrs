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

Scaffold. The design is settled (see [DESIGN.md](DESIGN.md) and
[ROADMAP.md](ROADMAP.md)); the tunnel implementation has not started yet.
Running the binary today prints its intended usage and exits.

## Planned usage

```bash
# Accepts a stock WireGuard config directly — no custom config format.
wgproxyrs --config ./wg0.conf --bind 127.0.0.1:1080

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
