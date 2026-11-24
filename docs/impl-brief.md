# rust-vmnet-proxy implementation brief

## Goal
Replace the Lima VM SOCKS5 gateway (127.0.0.1:1080) with a native Rust daemon.
Two egress modes, one binary:

1. Direct leg (port 1080): SOCKS5 CONNECT/resolve over a userspace TCP/IP
   stack (smoltcp) whose Ethernet frames ride the root socket_vmnet daemon
   (bridged en0). Bypasses WARP entirely: frames leave via L2 bridge.
2. Bastion legs (1081/1082/1083) + grafana forward (1086): plain `ssh -N -D`
   / `-L` subprocesses over the Mac's normal stack (WARP on), supervised
   with restart. These do NOT touch vmnet.

## Status: files present, netloop incomplete
- `src/main.rs` MISSING
- `src/cmds.rs` DONE (NetCmd, ConnectResult, ConnHandle)
- `src/pipe.rs` DONE (condvar byte pipe, backpressure, EOF)
- `src/vmnet_dev.rs` DONE (Device impl, frame filter, tx flush)
- `src/netloop/` partial: `state.rs` DONE, `tcp.rs` BROKEN tail removed — REWRITE tcp.rs
- `docs/api-notes.md` pinned smoltcp 0.14 API cheat sheet. READ IT FIRST.
- Reference examples: ${JCODE_SCRATCH_DIR}/xerj/smoltcp/smoltcp-rs/examples/
  {dhcp_client,tcpdump,httpclient}.rs

## Architecture (frozen)
Netloop thread owns ALL smoltcp state. Client threads talk to it via mpsc
commands + shared pipes. NEVER share smoltcp sockets across threads.

### Thread model
- main: parse config, spawn everything, wait
- netloop: smoltcp Interface + SocketSet; poll(fd) waits on {vmnet fd, wake_r}
- socks listener (port 1080): accept loop, one thread per client
- client threads: SOCKS5 handshake, then splice via pipes + NetCmd::Write
- ssh supervisor (single thread): spawn/monitor/restart ssh legs
- ssh stderr watcher: restart on premature exit, log tail

### Pipe protocol (src/pipe.rs)
- pipe A (tx): client thread pushes bytes -> netloop takes into smoltcp tx
- pipe B (rx): netloop pushes recv bytes -> client thread blocking-takes
- Pipe::close() = writer EOF; take_blocking returns None on closed+empty
- netloop closes pipe A when smoltcp socket FIN'd or aborted; client thread
  closes pipe B when the TCP client socket closes
- SOCKS5 client-thread splice loop: read client tcp socket -> pipe A push;
  pipe B take_blocking(50ms) -> client tcp socket write

### NetCmd (src/cmds.rs)
- Connect{id, remote, resp} -> netloop creates socket, connect(), register.
  Replies ConnectResult once (established, refused, timeout, unreachable).
- Write{id, data} -> netloop feed into smoltcp tx socket. Copy small chunks
  (16KB) per pass; netloop drains pipe each poll.
- Close{id} -> netloop socket.close() (FIN) or abort if not established.
- Resolve{name, resp} -> dns socket query, reply Vec<IpAddr> or None

### Netloop poll discipline
- poll fds: vmnet stream fd (POLLIN), wake_r (POLLIN), timeout from
  iface.poll_delay() clamped to [1ms, 500ms]
- On wake_r readable: drain pipe (8KB reads), process commands from cmd_rx
  (try_recv loop), write 1 wake byte per command sent (senders must nudge)
- Process order per pass: fill_rx from device -> poll smoltcp -> service
  connections (move bytes both directions) -> check deadlines -> flush tx
- fill_rx loop until EAGAIN; flush_tx loop until EAGAIN or empty
- Connected state machine per conn: SYN-SENT (deadline 10s) -> Established
  -> CloseWait handling -> Closed cleanup. RST -> Refused reply if unsent.
- DHCP: initial address. Event::Configured sets iface addr + route + dns
  servers, sets online=true, logs "ONLINE ip=<...>". Deconfigured clears.
- DNS queries: one dns::Socket created after DHCP provides servers. start_query
  per Resolve cmd; deadline 5s; get_query_result each pass; cancel + reply.
- Backpressure: if pipe B full, netloop stops reading from smoltcp socket
  (leaves bytes in socket rx buffer, TCP window closes). If smoltcp tx full,
  netloop stops draining pipe A (client thread blocks in push()).
- Cleanup: conn removed when: state Closed AND pipes both closed&empty, or
  client Close cmd with no bytes pending, or deadline exceeded.

### SOCKS5 listener (src/socks5.rs)
- bind 127.0.0.1:1080 (config)
- handshake: read [ver,nmethods], reply [5,0]; read [ver,cmd,rsv,atyp] + addr
- CMD: CONNECT (01), BIND (02 -> unsupported reply 0x07), UDP (03 -> 0x08)
- atyp: IPv4 (01), name (03, len-prefixed), IPv6 (04 -> reply 0x08)
- hostname: send Resolve to netloop, wait reply (10s timeout), first A record
  - if Resolve fails/empty: reply 0x04 (host unreachable)
- reply format: [5,rep,0,atyp=1,4 bytes,2 bytes] with rep from ConnectResult
- then splice loop described above
- log connections at info: "CONNECT host:port -> ip:port [direct]"

### SSH legs (src/sshlegs.rs)
Supervise plain ssh subprocesses; each has its own thread + restart logic.
Config drives legs:
```yaml
ssh_legs:
  - listen: 1081
    host: bastion-a                     # ssh config alias
    mode: dynamic                       # ssh -N -D 127.0.0.1:1081
  - listen:  1082 host: bastion-b        mode: dynamic
  - listen: 1083 host: jump-host-c       mode: dynamic
  - listen:  1086 host: bastion-a        mode: local_forward
    forward: 10.0.0.5:3000                # ssh -N -L 127.0.0.1:1086:10.0.0.5:3000
```
- ssh flags: -N, -o ExitOnForwardFailure=yes, -o ServerAliveInterval=30,
  -o ServerAliveCountMax=3, -o ConnectTimeout=10, -o BatchMode=yes
- restart: 1s delay, exponential backoff to 30s max on consecutive fails
- log: "leg 1081 up (pid 123)" / "leg 1081 died rc=? -> restart in Ns"
- stdin /dev/null, stderr -> log tail (last 20 lines kept per leg)
- verify forward actually listening: retry connect(127.0.0.1:listen) until
  open or 30s elapsed, before declaring leg up.
- do NOT touch ~/.ssh/config; aliases resolve hostnames/keys/ports.

### Config (src/config.rs, ~/.config/rust-vmnet-proxy/config.yaml)
```yaml
vmnet_socket: /private/var/run/lima/socket_vmnet.bridged
socks_listen: 127.0.0.1:1080
mac: "02:xx:xx:xx:xx:xx"     # optional, random local-admin MAC if absent
ssh_legs: [...]
```
Defaults match current gost.yaml legs. Load order: ~/.config/rust-vmnet-proxy/config.yaml,
then env RUST_VMNET_PROXY_CONFIG. `--config path` flag overrides.

### main.rs
- env_logger::init, parse flags, load config
- spawn netloop, spawn socks listener, spawn ssh legs
- wait on netloop join or socks listener error -> exit 1
- SIGINT/SIGTERM: kill ssh children, exit 0 (via libc::signal handler setting
  an AtomicBool + closing listener, or simple: loop sleep + flag check)

### Build/test
- cargo build --release in ~/Documents/projects/rust-vmnet-proxy (mbx on PATH:
  PATH="$HOME/Library/Application Support/mbx/bin:$PATH" cargo build)
- cargo clippy and fix warnings
- No unit tests required yet; verify compile + clippy clean.
- DO NOT run the binary against the real socket_vmnet in this task.

## Constraints
- Rust 2021 edition (smoltcp is edition 2024 but as a dep it's fine)
- smoltcp 0.14 features exactly as pinned in Cargo.toml
- std-only, no tokio. threads + mpsc + condvar only.
- no unsafe outside libc pipe2/wakeup fds handling
- MAC choice: 02:xx:6 bits unique (locally administered, unicast). Generate
  from a hash of the socket path when not configured.
- all logs via log crate, env_logger default level info
- comments: only non-obvious protocol/design notes, no narration
- names: files netloop/{state,tcp,dhcp,dns,mod}.rs, socks5.rs, sshlegs.rs,
  config.rs, main.rs, pipe.rs, cmds.rs, vmnet_dev.rs

## Non-goals
- UDP ASSOCIATE support
- IPv6 egress
- herdr/ssh LAN relays (VM-internal, revisit after switchover)
- BIND support
- gost-style chains/multi-hop
- metrics/endpoints
- root: no root, rootless only. socket_vmnet daemon must be running.

## Proof
cargo build --release succeeds; cargo clippy -- -D warnings clean; docs
proof commands in this brief.
Report back: files written, build/clippy status, open questions.
### Source identification
Legs default to masquerade: ssh -D binds the listen port, traffic appears
from the bastion. `source: identify` chains instead: ssh -D binds a
private upstream port (default listen + 30000, collision-checked across
all listens and upstreams at config load), rust-vmnet-proxy owns the public
listener on bind:listen (default 127.0.0.1), dials 127.0.0.1:<upstream>
with a no-auth SOCKS5 CONNECT (hostname targets stay ATYP=domain), then
writes a PROXY protocol v1 header before splicing. Hostname targets emit
dst 0.0.0.0 (the upstream resolves the name, we never see the address;
src is always concrete). Optional per-header `http_headers` block injects
X-Forwarded-For/X-Real-IP/X-Forwarded-Host/X-Forwarded-Proto/RFC 7239
Forwarded into the first plaintext HTTP/1.x request per connection; TLS
and HTTP/2 prior-knowledge pass through untouched, and keep-alive
connections only get headers on the first request.
