# debug_conn

Connectivity troubleshooting for a website in one command: DNS, traceroute,
TCP connect (`telnet`), TLS handshake (`openssl s_client -connect`) and an
HTTP request with per-phase timings (`curl -v`). Includes an interactive TUI
and automatic diagnosis of MTU / PMTUD black holes.

## Build

```bash
go build -o debug_conn .
```

Requires Go 1.23+. Traceroute uses the system `traceroute`, `tracepath` or `mtr`.

## Usage

```bash
./debug_conn                                  # interactive TUI, asks for a target
./debug_conn -tui https://example.com         # TUI, starts right away
./debug_conn https://example.com              # plain CLI report
./debug_conn -tests tcp,tls example.com:8443  # only some tests
./debug_conn -copy https://example.com        # also copy the report to the clipboard
./debug_conn -mss 1200 https://example.com    # force a smaller TCP MSS
```

| Flag | Default | Description |
|---|---|---|
| `-tests` | all | `dns,traceroute,tcp,tls,http` (aliases: `telnet`, `openssl`, `curl`) |
| `-timeout` | `5s` | per-operation timeout |
| `-insecure` | off | don't fail on certificate errors (like `curl -k`) |
| `-servername` | host | TLS SNI override (like `openssl -servername`) |
| `-port` | from URL | override port |
| `-hops` | `30` | max traceroute hops |
| `-X` | `GET` | HTTP method |
| `-body N` | `0` | print the first N bytes of the response body |
| `-mss N` | kernel | TCP MSS to advertise and use (Linux/macOS/BSD) |
| `-retry` | `true` | when TCP connects but TLS/HTTP stall, probe for MTU problems |
| `-copy` | off | copy the plain-text report to the clipboard |
| `-tui` | off | interactive UI (default when no target is given) |

Exit code is `1` if any test fails.

## TUI keys

| Key | Action |
|---|---|
| `↑`/`↓`, `j`/`k`, `0`-`5` | select overview / test |
| `r` / `Enter` | run selected test (overview: all) |
| `a` | run all |
| `x` / `Tab` | enable/disable test |
| `c` | cancel |
| `e` / `/` | edit target |
| `i` | toggle insecure |
| `y` / `Y` | copy full report / selected test to clipboard |
| `PgUp`/`PgDn`, mouse wheel | scroll |
| `q` | quit |

## MTU black-hole diagnosis

If the TCP connection succeeds but the TLS handshake times out, the tls test
retries with a small ClientHello (no post-quantum key share) and with reduced
MSS values, binary-searches the largest MSS that works, and reports the
estimated path MTU along with the fix (MSS clamping on the router, or a lower
interface MTU). Disable with `-retry=false`.
