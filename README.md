# rust-vmnet-proxy

Rootless macOS proxy that keeps one machine on two networks at once.

A SOCKS5 listener on localhost, a userspace TCP/IP stack (smoltcp) bridged
onto the LAN through `socket_vmnet`, and supervised SSH tunnels. Traffic
sent through the SOCKS5 port leaves the machine through the bridge,
not through the system network stack, so it takes the physical network
path even when a VPN or zero-trust agent (Cloudflare WARP and similar)
claims the default route.

## How it works

    app on this Mac        rust-vmnet-proxy                        LAN / bastion
    --------------         ---------                         -------------
    curl --socks5  ->  SOCKS5 accept thread  ->  netloop thread  ->  ssh -N -D leg
                                                              \-> smoltcp over socket_vmnet (direct)

- `socks_listen` accepts SOCKS5 CONNECT (RFC 1928, no auth) from
  localhost only. Name resolution goes through the DNS server the bridge
  learns by DHCP.
- Direct connections are built inside a smoltcp userspace stack that
  talks to the shared `socket_vmnet` daemon socket (the same one Lima
  uses). No vmnet.framework entitlement, no root, no system route
  changes.
- `ssh_legs` supervise plain `ssh -N -D` / `ssh -N -L` subprocesses with
  exponential-backoff restarts. Hosts are aliases from `~/.ssh/config`.
  Host key checking is never disabled.

## Requirements

- macOS. `socket_vmnet` is installed for you by `setup-vmnet` (next
  section); Lima users already have a compatible daemon and socket.
- Homebrew, or a Rust toolchain to build from source.

## Getting started

Fresh machine, in order:

1. Install:

       brew tap alecuba16/tap
       brew install rust-vmnet-proxy

2. Bring up the vmnet socket (one-time):

       rust-vmnet-proxy setup-vmnet

   Prompts for sudo once. It installs `socket_vmnet` via Homebrew,
   registers the root LaunchDaemon that owns the vmnet interface, and
   verifies the socket answers. If a working socket already exists
   (Lima with socket_vmnet networking), it is a no-op and exits 0.
   Details in docs/configuration.md, "Bringing up the vmnet socket".

3. Copy the example config and edit it:

       mkdir -p ~/.config/rust-vmnet-proxy
       cp example/config.example.yaml ~/.config/rust-vmnet-proxy/config.yaml

   Every option: docs/configuration.md.

4. Run it, either as a service:

       rust-vmnet-proxy install-mac
       rust-vmnet-proxy start-mac

   or in the foreground for a quick try:

       rust-vmnet-proxy run

From source instead of brew: `make install-mac` then `make start-mac`
(builds, copies to ~/.local/bin, registers the LaunchAgent). `make
stop-mac`, `make restart-mac`, `make uninstall-mac` do what they say.
Logs land in `~/Library/Logs/rust-vmnet-proxy/`.

## Configuration

Config lives at `~/.config/rust-vmnet-proxy/config.yaml` (override with
`--config <path>` or `RUST_VMNET_PROXY_CONFIG`). See
`example/config.example.yaml` for every option with comments:

    vmnet_socket: /private/var/run/lima/socket_vmnet.bridged
    socks_listen: 127.0.0.1:1080
    mac: ""                        # default derives from the socket path hash
    power_mode: battery             # battery | performance
    ssh_legs:
      - listen: 1081
        host: bastion-a            # alias from ~/.ssh/config
        mode: dynamic              # ssh -N -D 127.0.0.1:1081
      - listen: 1086
        host: bastion-a
        mode: local_forward        # ssh -N -L 127.0.0.1:1086:10.0.0.5:3000
        forward: 10.0.0.5:3000

Options:

- `vmnet_socket`: path to the shared `socket_vmnet` unix socket.
- `socks_listen`: address the SOCKS5 listener binds. Keep it on 127.0.0.1.
- `mac`: source MAC on the bridge. Default derives deterministically from
  the socket path so reboots do not churn the bridge forwarding table.
  Two clients on the same daemon need distinct MACs.
- `power_mode`: trade-off between battery and latency.
  - `battery` (default): idle wakes are minimal. The netloop sleeps until
    the vmnet socket or the wake pipe has data, timers uncapped. Splice
    threads park up to 2s. First byte through an idle path can cost some
    extra milliseconds.
  - `performance`: defensive short polls (500ms netloop cap, 50ms splice
    poll). Snappier, more wakeups, more battery.
- `ssh_legs`: supervised SSH tunnels. `dynamic` gives a SOCKS5 listener
  via the bastion, `local_forward` relays one TCP endpoint.

## Command reference

| Command | What it does |
|---------|---------------|
| `run` | Run in the foreground. Flag: `--config <path>`. |
| `setup-vmnet` | One-time: install socket_vmnet, register the root LaunchDaemon, verify the socket. No-op if a working socket exists. Flags: `--config <path>`, `--interface <enX>` (default en0). |
| `teardown-vmnet` | Reverse of setup-vmnet: boot out the LaunchDaemon, remove the plist. |
| `install-mac` | Copy the binary and register the user LaunchAgent (or brew services). |
| `update-mac` | Refresh the installed binary and restart, for upgrades. |
| `uninstall-mac` | Stop and remove the LaunchAgent (config and logs kept). |
| `start-mac` | Start the LaunchAgent. |
| `stop-mac` | Stop the LaunchAgent. |
| `restart-mac` | Restart the LaunchAgent. |

The LaunchAgent runs the binary with `--config ~/.config/rust-vmnet-proxy/config.yaml`,
starts at login, restarts on failure, logs to `~/Library/Logs/rust-vmnet-proxy/`.

## Security notes

- The SOCKS5 listener binds localhost and offers no auth. Anything that
  can connect to it can reach your LAN and your bastion legs.
- SSH host key checking stays on. Pin keys with `ssh-keyscan` into
  `~/.ssh/known_hosts`; the proxy never weakens it.
- The bridge is shared: any other client of the same daemon can see
  broadcast traffic. That is the socket_vmnet model, same as any VM on it.

## Source identification (PROXY protocol)

By default each SSH leg masquerades: `ssh -D` binds the listen port
itself and traffic appears to come from the bastion. Legs with
`source: identify` chain through rust-vmnet-proxy instead: ssh binds a private
upstream port, rust-vmnet-proxy owns the public listener and prepends a
PROXY protocol v1 header carrying the real client IP, so
PROXY-protocol-aware receivers (HAProxy/Traefik with `proxy_protocol`
on) can log it. Hostname targets emit a family-matching placeholder in
the header (dst `0.0.0.0` for IPv4 clients, `::` for IPv6; the
upstream resolves the name, we never see the address); the source IP is
always concrete. With `http_headers` the first plaintext HTTP/1.x
request per connection additionally gets X-Forwarded-For, X-Real-IP,
X-Forwarded-Host, X-Forwarded-Proto and RFC 7239 Forwarded headers, each
individually toggleable; TLS and HTTP/2 traffic is left untouched.

    ssh_legs:
      - listen: 1082
        host: bastion-b
        mode: dynamic
        source: identify
        bind: 0.0.0.0        # who may use this leg
        upstream: 31082      # private ssh -D port, default listen + 30000
        http_headers:         # optional, block absent = no injection
          x_forwarded_for: true
          x_real_ip: true
          x_forwarded_host: true
          x_forwarded_proto: true
          forwarded: true

## Development

    make build      # cargo build --release
    make check      # cargo check
    make test       # cargo test

Design notes: `docs/api-notes.md` (pinned smoltcp 0.14 and socket_vmnet
protocol details), `docs/impl-brief.md` (architecture decisions),
`docs/configuration.md` (every option, type, default, format).

License: MIT.