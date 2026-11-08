# interceptor

A single-binary transparent network monitor and blocker for macOS.

It loads its own pf (packet filter) ruleset, intercepts **all outbound TCP
connections of every program** (Chrome, an Android emulator's qemu, daemons,
anything), relays them unchanged, and shows a live TUI log with the owning
process, destination, sniffed hostname (TLS SNI / HTTP `Host:`) and byte
counts. Hostnames can be blocked with glob patterns.

```
cargo build --release
sudo ./target/release/interceptor [blocklist-path]   # default blocklist: ./blocklist.txt
```

## TUI keys

| key | action |
|-----|--------|
| `/` | filter (nvim-style: live incsearch, Enter to keep, Esc to revert) |
| `b` | block the selected flow's hostname (appends to the blocklist) |
| `B` | open the blocklist: `j`/`k` select, `d`/`x` remove a pattern, `Esc` close |
| `Enter` | inspect a flow: captured request/response headers and bodies |
| `j`/`k`, arrows, PgUp/PgDn | scroll, `g` top, `G` tail |
| `?` | help modal listing all shortcuts (searchable with `/`) |
| `q` or Ctrl-C | quit (restores the original pf ruleset) |

Failed requests are shown in red: connection errors, blocked flows, and
plain-HTTP responses with status ≥ 400.

**Request methods (GET, POST, ...) and inspectable headers/bodies are only
visible for plain HTTP.** For HTTPS everything after the TLS ClientHello is
encrypted — you get the SNI hostname, sizes and timing, but reading methods,
headers or bodies requires a MITM CA (not implemented).

## Blocklist

One glob pattern per line, case-insensitive, `*` and `?` wildcards. The file
is hot-reloaded when saved, so you can edit it while the tool runs. Removing
a pattern with `B` + `d` rewrites the file (comments are dropped):

```
*.doubleclick.net
*.google-analytics.com
93.184.216.34
```

Blocked connections are closed with a TCP RST before any byte reaches the
destination (matching happens on the ClientHello / request headers).

## How it works

```
app ──TCP──▶ pf route-to lo0 ──rdr──▶ 127.0.0.1:9191 (interceptor)
                                            │ DIOCNATLOOK ioctl → original destination
                                            │ sniff ClientHello/HTTP headers
                                            │ blocklist? ── yes → RST close
                                            │ no → relay bytes, count, log to TUI
```

- The proxy's own relays bind source ports 20000–20999 and a pf `pass out
  quick` rule exempts them (otherwise the proxy would intercept itself).
- Process attribution polls `lsof` every 2s and matches connection source
  ports (there is no per-socket pid API on macOS).
- The original `/etc/pf.conf` is preserved and reloaded on exit. If the
  process is killed with SIGKILL, restore manually:
  `sudo pfctl -f /etc/pf.conf`.

## Limitations

- IPv4 only. IPv6 TCP is reset (clients fall back to v4) and IPv6 QUIC is
  blocked, so nothing silently escapes; v6 flows are not shown natively.
- TLS payload stays encrypted — you see hostnames (SNI), not methods, headers or bodies. First 64 KiB per direction is captured for plain-HTTP flows.
- QUIC/HTTP3 (UDP 443) is blocked with ICMP unreachable so browsers fall
  back to TCP; UDP in general (incl. DNS) is not logged.
- Traffic to/from 127.0.0.0/8 is not intercepted (avoids breaking local
  services); emulator → host-loopback traffic therefore isn't shown.
