# Changelog

## 0.3.0 — 2026-11-09

Config MTU is honoured. Until now the `[Interface] MTU` line was
silently ignored as a wg-quick extra and the netstack hard-coded
1280, so an eduVPN profile declaring `MTU = 1392` ran at 1280 with
no signal anywhere. The line is now parsed and range-checked
(576..=9000; anything else is a hard config error naming the key),
a `--mtu <N>` flag overrides it for operators whose underlay needs
something other than what the profile declares (resolution order:
flag > config > default, in one place — `config::resolve_mtu`).
The default stays 1280, the IPv6 minimum MTU (RFC 8200): the
largest inner packet guaranteed to fit any path once WireGuard's
overhead is added. `--check` prints the effective MTU and its
source; the startup ready line carries `mtu=<n>`.

Coverage: parser tests (canonical + mixed-case spelling, both
range bounds, every invalid class), resolver-order test, and an
end-to-end test that runs both netstacks at MTU 1420 and echoes a
1392-byte UDP payload — a 1420-byte inner packet that a 1280 stack
drops whole — through SOCKS5 UDP ASSOCIATE, byte-identical.

## 0.2.1 — 2026-11-09

Hotfix: config keys are matched case-insensitively.

v0.2.0's parser accepted only the exact spelling `PresharedKey` and
silently ignored anything else as an "unknown key". Real-world configs
— eduVPN profiles and the canonical WireGuard spelling — write
`PreSharedKey` (capital S), so the preshared key was dropped, the
tunnel was built without it, and the server silently discarded every
handshake initiation: tunnel down forever, with no diagnostic anywhere
(WireGuard has no error channel). All keys in `[Interface]` and
`[Peer]` are now matched case-insensitively, the way section names
already were. Unknown keys (wg-quick's `Table`, `MTU`, `PreUp`, …)
are still tolerated.

Regression coverage: parser tests for an eduVPN-shaped config with
canonical spellings and for scrambled-case keys, plus end-to-end
tests proving a PSK-requiring peer handshakes and passes traffic when
the client config carries the matching key spelled `PreSharedKey` —
and never comes up when the client lacks it or carries the wrong one.

## 0.2.0 — 2026-11-09

Wireproxy-parity phase: SOCKS5 UDP ASSOCIATE, multi-peer cryptokey
routing, `--tcp-tunnel` forwards, proxy auth (SOCKS5 RFC 1929 + HTTP
Basic), `--info-bind` health endpoint with `status` probe, daemon
mode. First crates.io release.

## 0.1.0 — 2026-11-09

Initial working release: stock `.conf` parsing, boringtun + smoltcp
engine, SOCKS5 (TCP CONNECT, in-tunnel DNS) and HTTP CONNECT proxies,
fail-closed throughout.
