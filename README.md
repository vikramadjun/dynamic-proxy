# Dynamic Proxy

A dynamic SOCKS5 / HTTP(S) proxy for Windows (Vista through 11, x86 and x64) that automatically fails over between multiple upstream proxies, includes an optional built-in DNS relay, reloads its configuration live, and can run as a Windows Service.

Single statically-linked executable, no installer, no external DLLs.

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Command-line reference](#command-line-reference)
- [Configuration file reference](#configuration-file-reference)
- [Usage examples](#usage-examples)
- [Running as a Windows Service](#running-as-a-windows-service)
- [Known limitations](#known-limitations)
- [Building from source](#building-from-source)
- [License](#license)

## Overview

Dynamic Proxy sits in front of your network traffic and picks a working outbound path for it automatically. You give it an ordered list of candidates &mdash; an upstream SOCKS5 proxy, an upstream HTTP proxy, a direct connection, or any mix of those &mdash; and it continuously verifies which ones are actually working (a real request, not a ping) and routes traffic through the best available one, in the order you specified.

It listens for SOCKS5 and HTTP(S) client connections on a single port at the same time, so you don't configure separate ports for separate protocols. It can also run a small local DNS server that forwards queries through whichever upstream is currently active, so DNS resolution gets the same failover protection as everything else.

## Features

- **Single port, two protocols.** SOCKS5 and HTTP(S) are both accepted on the same listening port; the protocol is auto-detected per connection, so two different programs can use the proxy at the same time over different protocols without any extra configuration.
- **Multiple upstream routes with priority.** Any number of routes (`direct`, `socks5`, `http`), tried in the order you list them.
- **"Sticky" failover.** Once a route is active, the proxy keeps using it until it actually fails &mdash; it does not preemptively jump back to a higher-priority route just because that route came back online, which avoids needlessly disrupting active connections.
- **Real connectivity checks.** Health checks are genuine HTTP requests to a reliable endpoint, not ICMP pings, so a route that "answers" but has no real internet behind it is correctly detected as down.
- **Upstream authentication.** Username/password for SOCKS5 (RFC 1929) and HTTP (Basic) upstream proxies.
- **Optional built-in DNS relay** (UDP, off by default):
  - Multiple upstream resolvers, tried in order for every query.
  - RCODE-aware cascading: an upstream that answers NXDOMAIN/SERVFAIL/REFUSED is treated as "doesn't know this name", and the next resolver is tried too &mdash; not just on a transport failure. This lets you put a general resolver first and something like Tor's DNSPort second, so names the general resolver can't answer are automatically retried against the second resolver.
  - `upstream = NC` special value: automatically pulls in the DNS servers currently configured on every active (up), non-loopback network adapter.
  - Self-reference protection: an upstream entry that points back at the proxy's own DNS port is detected and dropped, so a misconfiguration can't create a query loop.
  - "Sticky" bind: if `bind = 0.0.0.0` can't be bound (address already in use), the proxy automatically retries on `127.0.0.1` so at least this machine keeps working, and logs that it did so.
  - If the DNS port can't be bound at all (something else already owns it), the proxy logs that once and keeps running normally &mdash; it does not crash and does not affect SOCKS5/HTTP proxying.
- **Live configuration reload.** The `.ini` file is watched for changes; edits are picked up within a few seconds with no restart. This includes the route list, health-check settings, DNS settings, and even the listen address/port (the listening socket is transparently reopened). Connections already in progress are not disrupted.
- **Command-line overrides.** Any setting given on the command line wins over the `.ini` file, and continues to win even across a live reload.
- **Automatic configuration discovery.** If no config path is given, the proxy looks for a `.ini` file with the same name as its own executable, in the same folder.
- **Windows Service support.** `--install` / `--uninstall`, with optional custom name/description/config path. A running service discovers its own registered name from the Service Control Manager at startup (by matching its own process ID), so the installed command line can be as short as `myproxy.exe --service`.
- **Quiet by default.** Logs go to the console only unless a log file is explicitly requested; all console/log output is in English regardless of the system locale/codepage.
- **Versioned.** `--version` / `-v`.
- **Vista-to-11 compatible.** Built with an explicit `_WIN32_WINNT=0x0600` floor and PE subsystem/OS version stamped at 6.0, statically linked against the MinGW-w64 runtime.

## How it works

### Listening side

The proxy opens one TCP listening socket. For every accepted connection, it peeks at the first byte: `0x05` means SOCKS5, anything else is treated as HTTP(S) (either a `CONNECT` tunnel for HTTPS/TLS traffic, or a plain absolute-URI request for HTTP). Each connection is handled on its own thread, so SOCKS5 and HTTP(S) clients are served concurrently without interfering with each other.

### Route selection

Routes are configured as an ordered list (`route1`, `route2`, ...). A background thread runs the following logic:

1. On startup (or whenever there is no currently-active route), scan the list from the top and use the first route that passes a real connectivity check.
2. While a route is active, only *that* route is re-checked periodically. Higher-priority routes are deliberately **not** monitored in the background &mdash; this is the "sticky" behavior: no connection gets rerouted just because something more preferred happened to come back online.
3. If the active route fails its check a configurable number of times in a row, the proxy re-scans the whole list from the top, so priority order is respected again the moment a re-selection actually happens.
4. `direct` only ever gets used if it's explicitly present as one of the routes. If it's absent, and every proxy route is down, new connections are cleanly refused instead of silently falling back to an unproxied connection.

A connectivity check is a real HTTP request over the candidate route to a small set of reliable endpoints (or a custom host/port you configure) &mdash; a route that completes a TCP handshake but doesn't actually carry traffic is correctly detected as broken.

### DNS relay

The optional DNS server listens on UDP. Each incoming query is forwarded to the configured upstream resolver(s) over **DNS-over-TCP**, through whichever route is currently active &mdash; so DNS queries are protected by the exact same failover logic as regular traffic (yes, even when the active route is `direct`: the query still goes out via the built-in relay's own TCP connection, not via the operating system's normal DNS client).

If more than one upstream resolver is configured, they are tried in order for each query; an upstream is only considered to have "answered" if it returns RCODE `NOERROR` (0). Any other response code (NXDOMAIN, SERVFAIL, REFUSED, ...) causes the next upstream to be tried as well, with the first response received kept as a fallback in case nobody has a clean answer &mdash; so the client still gets a real DNS response instead of a timeout whenever at least one upstream was reachable.

### Configuration hot-reload

A background thread checks the `.ini` file's modification time roughly every two seconds. When it changes, the whole configuration is reloaded into a fresh, independent structure, command-line overrides are re-applied on top of it, and the new structure is atomically swapped in under a lock. Connections that are already relaying keep the route they originally grabbed &mdash; they are never disrupted by a reload. The route selection is re-run immediately against the new list. If the listen address/port changed, the listening socket is closed and reopened on the next accept-loop tick; if the new bind fails, the proxy keeps using the previous socket rather than losing service.

### Windows Service

`--install` registers the currently running executable with the Service Control Manager. Unless you pass `--cp` explicitly at install time, no config path is written into the service's command line &mdash; the running service just auto-detects its `.ini` the same way a normal console run would. The service also does not need `--name` baked into its command line: at startup, it asks the SCM "which service corresponds to my own process ID?" and uses whatever name comes back, falling back to whatever `--name` it *was* given (or the default) only if that lookup fails. This keeps the registered command line minimal and means the executable and its `.ini` can be moved together to a different folder without breaking the service registration.

## Quick start

1. Download `proxy_x64.exe` (or `proxy_x86.exe` for older/32-bit systems) from the [Releases](../../releases) page.
2. Put it next to a `.ini` file with the **same name** (e.g. `myproxy.exe` + `myproxy.ini`).
3. Edit the `.ini` (see below) to list your upstream proxies.
4. Run the executable. Point your browser or application at `127.0.0.1` and the port from `[listen]`, as either a SOCKS5 or an HTTP proxy &mdash; both work on the same port.

If no matching `.ini` is found, the proxy still starts and simply falls back to a direct connection.

## Command-line reference

| Flag | Description |
|---|---|
| `-cp <file>`, `--cp <file>`, `--config <file>`, `-c <file>` | Path to the `.ini` file to use. If omitted, a file matching the executable's own name is looked for next to it. |
| `--port <N>`, `-p <N>` | Override the listen port. |
| `--bind <address>` | Override the listen bind address. |
| `--log <file>`, `-l <file>` | Also write the log to this file (console output is always on). |
| `--health-interval <seconds>` | Override the health-check interval. |
| `--version`, `-v` | Print the version and exit. |
| `--install` | Install as a Windows Service (see below). Requires an elevated (Administrator) prompt. |
| `--uninstall` | Remove a previously installed service. Also requires elevation. |
| `--name <name>` | Service name, for `--install`/`--uninstall`. Default: `Dynamic proxy`. |
| `--description <text>` | Service description, for `--install`. Default: `Extended Dynamic proxy`. |
| `--service` | Internal flag used by the Service Control Manager to launch the process in service mode. Not meant to be typed by hand. |

Every flag is optional and can be combined with the others. Anything given on the command line overrides the `.ini`, including across a live reload.

## Configuration file reference

INI format: `[section]` headers, `key = value` lines, `;` for comments. The file is watched live &mdash; save your changes and they apply within a few seconds, no restart needed.

```ini
[listen]
port = 1080
bind = 127.0.0.1        ; 127.0.0.1 = this machine only, 0.0.0.0 = also reachable from the network

[route1]                ; route1, route2, ... route16 - tried in this order
type = socks5            ; socks5 / http / https / direct
host = 1.2.3.4
port = 1080
username =                ; leave blank if no auth is needed
password =

[route2]
type = http
host = 5.6.7.8
port = 8080

[route3]
type = direct             ; only used if present - omit this section to never fall back to direct

[health]
interval_sec = 10
fail_threshold = 2
check_host =                ; optional - overrides the built-in check targets
check_port =

[dns]
enabled = no
bind = 127.0.0.1
port = 53
upstream = 1.1.1.1:53      ; repeat this line for multiple resolvers, tried in order
                            ; special value: upstream = NC pulls DNS servers from active network adapters

[log]
path = proxy.log           ; optional - same effect as --log/-l, which takes priority if both are set
```

`type = https` is currently handled the same as `type = http` (a plain, unencrypted connection to the upstream proxy itself) &mdash; see [Known limitations](#known-limitations).

## Usage examples

**Direct connection only** (no proxying, useful as a baseline or placeholder):

```ini
[route1]
type = direct
```

**One upstream proxy with a direct fallback:**

```ini
[route1]
type = socks5
host = 203.0.113.10
port = 1080

[route2]
type = direct
```

**Priority chain with authentication, never falling back to direct:**

```ini
[route1]
type = socks5
host = 203.0.113.10
port = 1080
username = myuser
password = mypassword

[route2]
type = http
host = 198.51.100.20
port = 8080

; no [route3] with type = direct - refuses new connections instead of leaking traffic unproxied
```

**DNS relay with redundancy and a Tor fallback for `.onion` names:**

```ini
[dns]
enabled = yes
bind = 0.0.0.0
port = 5353          ; a non-standard port avoids fighting anything else for port 53
upstream = 1.1.1.1:53
upstream = NC
upstream = 127.0.0.1:9053   ; Tor's DNSPort - only reached if 1.1.1.1/NC answer NXDOMAIN
```

Note: DNS resolution alone doesn't make `.onion` sites load &mdash; the *connection* has to go through Tor too. The most reliable setup is a dedicated `route` with `type = socks5` pointing at Tor's SOCKS port (usually 9050), so SOCKS5-aware clients resolve and connect through Tor directly without touching DNS at all.

**Custom config file, quick port override, and file logging, all via the command line:**

```
proxy_x64.exe -cp D:\proxy\my-config.ini --port 9090 --log proxy_debug.log
```

## Running as a Windows Service

From an elevated (Administrator) Command Prompt:

```
proxy_x64.exe --install
```

This registers a service named `Dynamic proxy`, set to start automatically on boot, using whatever `.ini` auto-detection would normally find. The actual registered command is just:

```
"<path>\proxy_x64.exe" --service
```

With custom values (all independently optional):

```
proxy_x64.exe --install --name "My proxy" --description "This is a dynamic SOCKS/HTTP proxy" --cp D:\proxy\my-config.ini
```

Start/stop:

```
net start "Dynamic proxy"
net stop "Dynamic proxy"
```

Remove:

```
proxy_x64.exe --uninstall
proxy_x64.exe --uninstall --name "My proxy"
```

Installing a service with a name that's already registered fails cleanly with a message telling you how to remove the existing one first, instead of erroring out unhelpfully.

## Known limitations

- `type = https` for an upstream route does not yet provide real TLS encryption to the upstream proxy itself &mdash; it's handled identically to `type = http`. This has no effect on ordinary HTTPS websites, which are proxied fine regardless (their TLS is between the browser and the site, not something this proxy needs to understand); it only matters for upstream proxies that themselves require a TLS-secured control connection.
- No IPv6 support for target addresses (IPv4 literals and domain names only).
- The route list is `.ini`-only; it can't be set or overridden from the command line (only `[listen]`, individual `[health]` fields, and the config path itself can be).
- The "sticky" DNS bind fallback (`0.0.0.0` &rarr; `127.0.0.1`) can't help when whatever's occupying the port is bound to `127.0.0.1` specifically (a very common default, e.g. for Tor's DNSPort) &mdash; two processes fundamentally cannot bind the same IP:port pair. In that situation, run the DNS relay on a different port instead.

## Building from source

Requires a MinGW-w64 cross-compiler (`mingw-w64` package on Debian/Ubuntu) or an equivalent MinGW-w64 toolchain on Windows/MSYS2.

```bash
# x64
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -D_WIN32_WINNT=0x0600 -static \
  -o proxy_x64.exe src/main.c src/config.c src/log.c src/netutil.c src/upstream.c \
  src/healthcheck.c src/listeners.c src/dns.c src/service.c \
  -lws2_32 -ladvapi32 -liphlpapi \
  -Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,0 \
  -Wl,--major-os-version,6 -Wl,--minor-os-version,0

# x86
i686-w64-mingw32-gcc -O2 -Wall -Wextra -D_WIN32_WINNT=0x0600 -static \
  -o proxy_x86.exe src/main.c src/config.c src/log.c src/netutil.c src/upstream.c \
  src/healthcheck.c src/listeners.c src/dns.c src/service.c \
  -lws2_32 -ladvapi32 -liphlpapi \
  -Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,0 \
  -Wl,--major-os-version,6 -Wl,--minor-os-version,0
```

No third-party libraries are required beyond the standard Windows import libraries (`ws2_32`, `advapi32`, `iphlpapi`) and the MinGW-w64 runtime, which is statically linked in.

## License

MIT &mdash; see [LICENSE](LICENSE).
