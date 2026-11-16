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

Before tracing, the traceroute test prints the route the OS picks to reach the
target: default gateway (or `none (on-link)` on the local subnet), interface
and source IP. Gateway and interface come from `ip route get` (Linux),
`route -n get` (macOS/BSD) or PowerShell `Find-NetRoute` (Windows):

```
route: gateway 192.168.1.1, interface wlan0, source 192.168.1.20
```

## Usage

```bash
./debug_conn                                  # interactive TUI, asks for a target
./debug_conn -tui https://example.com         # TUI, starts right away
./debug_conn https://example.com              # plain CLI report
./debug_conn -tests tcp,tls example.com:8443  # only some tests
./debug_conn -copy https://example.com        # also copy the report to the clipboard
./debug_conn -mss 1200 https://example.com    # force a smaller TCP MSS
./debug_conn -ip 203.0.113.10 https://example.com   # test one backend, keep Host/SNI
sudo ./debug_conn -pcap run.pcap https://example.com # record a packet capture
```

The target is resolved **once**; TCP, TLS, HTTP, traceroute and the packet
capture all go to that IP, while TLS sends the hostname as SNI and HTTP sends
it as the `Host` header (like `curl --resolve`). With round-robin DNS every
test therefore looks at the same server. `-ip` replaces the DNS answer, so you
can test a specific backend, a CDN edge, or a server before a DNS cutover.
IPv4 is preferred when DNS returns both (`-6` to prefer IPv6).

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
| `-ip` | DNS | connect to this IP; Host header and SNI keep the hostname |
| `-6` | off | prefer an IPv6 address when DNS returns both |
| `-pcap FILE` | off | record traffic to/from the target IP, plus ICMP, with tcpdump (or dumpcap) |
| `-pcap-iface` | `any` | interface for `-pcap` |
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

## Packet capture

`-pcap` runs `tcpdump` in the background with the filter `host <ip> or icmp`.
ICMP is included because traceroute replies and "fragmentation needed"
messages come from routers on the path, not from the target. Open the file in
Wireshark or with `tcpdump -nn -r FILE`. In the TUI each run writes its own
file (`FILE-YYYYMMDD-HHMMSS.pcap`).

Capturing needs root, or capabilities on tcpdump:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
```

If tcpdump fails, Wireshark's `dumpcap` is tried next. Many distros install it
with those capabilities for members of the `pcap` or `wireshark` group, so
with Wireshark installed no sudo is needed.

## MTU black-hole diagnosis

If the TCP connection succeeds but the TLS handshake times out, the tls test
retries with a small ClientHello (no post-quantum key share) and with reduced
MSS values, binary-searches the largest MSS that works, and reports the
estimated path MTU along with the fix (MSS clamping on the router, or a lower
interface MTU). Disable with `-retry=false`.
