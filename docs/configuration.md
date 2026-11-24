# Configuration reference

`rust-vmnet-proxy` reads one YAML config. Resolution order:

1. `--config <path>` command line flag
2. `RUST_VMNET_PROXY_CONFIG` environment variable (non-empty)
3. `~/.config/rust-vmnet-proxy/config.yaml` when the file exists
4. Built-in defaults when none of the above is found. The proxy then
   logs a warning: without `ssh_legs` only the direct SOCKS5 listener
   runs.

A config file that exists but fails to parse or validate is a startup
error, never a silent fallback.

## Bringing up the vmnet socket

`vmnet_socket` (default `/private/var/run/lima/socket_vmnet.bridged`)
points at a `socket_vmnet` daemon. That daemon is a small root process
wrapping `vmnet.framework`: it owns the vmnet interface and exchanges
Ethernet frames with clients over the unix socket. It is the only
component of this setup that needs root, and only once, at install
time. The proxy itself and every SSH leg run unprivileged.

If you already run Lima with socket_vmnet networking, the socket exists
and nothing else is needed.

Otherwise run:

    rust-vmnet-proxy setup-vmnet [--config <path>] [--interface <enX>]

It installs `socket_vmnet` via Homebrew (if missing), writes a
LaunchDaemon plist to `/Library/LaunchDaemons` that starts the daemon
at boot in bridged mode on `--vmnet-interface` (default `en0`), and
polls the socket until it answers. `teardown-vmnet` boots the daemon
out and removes the plist. Both take `--config <path>` and
`--interface <enX>`; reruns are idempotent, and `setup-vmnet` is a
no-op when a working socket is already there.

Security scope: the only sudo use is the one `launchctl bootstrap`
(and the plist move) during setup. The plist is world-readable, and
the proxy never elevates at run time. Both Lima and rust-vmnet-proxy
connect to the same socket as regular clients; sharing it is fine.

## Top-level options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `vmnet_socket` | string (path) | `/private/var/run/lima/socket_vmnet.bridged` | Unix socket of the shared socket_vmnet daemon. The userspace stack connects as one more client of the daemon. |
| `socks_listen` | SocketAddr | `127.0.0.1:1080` | Bind address of the direct SOCKS5 listener. Keep it on localhost unless you intentionally serve other machines. |
| `mac` | string | derived | Source MAC on the bridge, format `aa:bb:cc:dd:ee:ff` (six colon-separated hex byte pairs, case-insensitive, each 00 to FF). Default derives from the FNV-1a hash of the socket path: locally administered (first byte 02), unicast, deterministic across reboots. Two clients on the same daemon must have distinct MACs. |
| `power_mode` | string, `battery` or `performance` | `battery` | Idle wake behavior. See the power section. |
| `ssh_legs` | list | empty | Supervised SSH legs. See below. |
| `relays` | list | empty | LAN relays: inbound listeners on the vmnet stack address. See below. |

## ssh_legs

Each list entry describes one supervised `ssh` process and its
listener:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | u16, 1-65535 | required | Public port of the leg. For masquerade legs this is where `ssh -D` itself listens. For identify legs this is where the chained rust-vmnet-proxy listener listens. |
| `host` | string | required | `Host` alias from `~/.ssh/config`. Credentials, keys, port, and host key checking come from the user's ssh config. rust-vmnet-proxy never weakens host key checking. |
| `mode` | string, `dynamic` or `local_forward` | required | `dynamic` runs `ssh -N -D`. `local_forward` runs `ssh -N -L` with `forward`. |
| `forward` | string, `host:port` | required for `local_forward` | Target endpoint of the forward, e.g. `10.0.0.5:3000`. |
| `source` | string, `masquerade` or `identify` | `masquerade` | How the leg presents traffic. `masquerade`: current behavior, ssh owns the listen port, rust-vmnet-proxy is not in the data path, traffic appears from the bastion. `identify`: chained, ssh binds a private upstream port, rust-vmnet-proxy owns the public listener and prepends PROXY protocol v1, so PROXY-aware receivers log the real client IP. |
| `bind` | IP address | `127.0.0.1` | Bind address for the chained listener (identify legs only). Ignored with a warning on masquerade legs. |
| `upstream` | u16 | `listen + 30000` | Private port where ssh -D listens for an identify leg. Must not collide with any other `listen` or `upstream` in the file, validation error otherwise. |
| `http_headers` | map, see below | absent = no injection | HTTP/1.x forwarding header injection (identify legs only). Ignored with a warning on masquerade legs. |

Validation rules:
- No two legs may share a `listen` or `upstream` port (including
  across kinds: one leg's listen must not equal another's upstream).
- Port 0 is rejected.
- Unknown `source`, `mode`, or `power_mode` values are config errors.
- `bind` or `upstream` or `http_headers` on a masquerade leg: warning,
  ignored.

## relays

Each entry is an inbound TCP port on the vmnet stack's own LAN address
(the DHCP address of the userspace stack) forwarded to a Mac-side
endpoint. The use case: under a flow-level VPN capture like Cloudflare
WARP MASQUE, inbound connections to the Mac's physical interface are
dropped, but the bridged vmnet address sits below the capture. LAN
devices connect to the stack's address directly, and the proxy relays
to services on the Mac (loopback included) or anywhere else reachable
from the Mac's normal stack.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | the listen port | Log-friendly label. |
| `listen` | u16, 1-65535 | required | Port on the vmnet stack's LAN address where LAN clients connect. |
| `target` | SocketAddr | required | Mac-side endpoint the connection is forwarded to, e.g. `127.0.0.1:8787`. Dialed with the normal Mac stack, so it can be a loopback service, another host, or anything the Mac reaches. |

Validation rules:
- Relay listen ports must be unique among relays.
- A relay listen port must not collide with any leg `listen` or
  `upstream` port or with `socks_listen` (config error, even though
  the relay binds a different address space: distinct ports keep the
  map readable).
- Port 0 is rejected.
- Data path: accepted LAN connections join the same connection
  machinery as direct SOCKS5, with the same backpressure (bounded
  pipes, per-connection splice threads). The LAN-facing TCP is
  terminated by the userspace stack; the target connection is a normal
  Mac TCP connection. TLS passes through untouched.

## http_headers (identify legs)

Present the block to enable injection; each header individually
toggleable, all default `true` inside a present block. `http_headers: {}`
injects all five.

```yaml
http_headers:
  x_forwarded_for: true      # client IP, appended to any existing chain
  x_real_ip: true             # client IP, only inserted when absent
  x_forwarded_host: true      # echoes the request's Host header value
  x_forwarded_proto: true      # literal "http" (the leg saw plaintext)
  forwarded: true             # RFC 7239 Forwarded: for=...;host=...;proto=http
```

Injection behavior:
- Only the first request on each connection is inspected. Keep-alive
  connections get headers on the first request only.
- TLS, SSH, HTTP/2 prior-knowledge, and anything that is not a
  plaintext HTTP/1.x request passes through untouched with no added
  delay. Bytes are never buffered beyond the first request's header
  block (8 KiB window).
- `x_forwarded_for` appends `, <ip>` when the request already carries one
  (chain semantics). The other four are only inserted when absent.
- IPv6 client addresses: bare literal in `X-Forwarded-For` and
  `X-Real-IP`, bracketed `for=[...]` form in RFC 7239 `Forwarded`.
- The injected value is the accepted client's peer IP, the same
  identity the PROXY protocol v1 header carries.

## Power modes

All data paths are event-driven: vmnet frames wake the netloop poll,
commands wake it through a pipe, splice threads park on a condvar, socks
accepts park on the listener. `power_mode` only bounds idle wakeups and
shutdown latency, never throughput.

| Behavior | battery | performance |
|----------|---------|-------------|
| netloop poll timeout | uncapped smoltcp timers (DHCP renewal can park minutes) | capped at 500 ms |
| accept loop sleep | 1 s | 100 ms |
| splice take timeout | 2 s | 50 ms |
| shutdown notice latency | within ~2 s | within ~500 ms |

`battery` is the default: idle cost is the DHCP timer and nothing else.
`performance` trades wakeups for snappier connect and shutdown latency.

## Logging

The binary owns its log files; no external rotation daemon is needed.
Logs go to `~/Library/Logs/rust-vmnet-proxy/rust-vmnet-proxy.log` by
default (macOS convention for user agents), with `.1`, `.2`, ... rotated
copies kept beside it. Under launchd, stderr is pointed at
`stderr.log` in the same directory and receives only panics and
pre-logger-init failures.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `logging.level` | string | RUST_LOG, else `info` | error, warn, info, debug, trace, off. Case-insensitive. |
| `logging.file` | bool | `true` | `false` turns the file logger off entirely: log lines go to stderr only. |
| `logging.dir` | path | `~/Library/Logs/rust-vmnet-proxy` | Log directory, created when missing. Relative paths resolve against `$HOME`. |
| `logging.rotate_secs` | u64 | `86400` | Rotate when the current file is older than this many seconds. `0` disables time-based rotation. |
| `logging.keep` | u32 | `3` | Rotated files kept. `0` deletes the previous file at rotation instead of renaming it. |
| `logging.max_bytes` | u64 | `10485760` | Rotate once the current file reaches this size. `0` disables the size cap. |

Rotation age anchors on the file's mtime, so restarts don't reset the
clock on a long-lived log. A `level` value in config always wins over
`RUST_LOG`.

## Formats

- SocketAddr: `ip:port`, IPv4 or IPv6, same as Rust's `SocketAddr`
  parse (`127.0.0.1:1080`, `[::1]:1080`).
- MAC: `aa:bb:cc:dd:ee:ff`, six pairs, hex, colon separated. Parsed
  strictly: exactly six groups, each two hex digits.
- Ports: 1-65535. `listen`/`upstream` 0 rejected.
- Paths: absolute path strings for `vmnet_socket`.
- Booleans: YAML `true`/`false`.
- Unknown top-level or leg keys are currently ignored by the parser
  (serde). Typos in optional keys can therefore not fail startup; the
  required ones (`listen`, `host`, `mode`) do fail when misspelled.

## Full example

See `example/config.example.yaml` in the repository, which mirrors this
document option for option.