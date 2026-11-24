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