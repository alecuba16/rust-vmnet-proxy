# Live test plan (alt ports, side-by-side with VM)

Run rust-vmnet-proxy with an alt-port config; VM keeps its real ports. Nothing
production touches the VM until switchover is approved.

## Alt config
`socks_listen: 127.0.0.1:20800`, ssh legs at 20801/20802/20803, grafana 20806.
Same vmnet_socket (shared daemon is fine: it floods frames to all clients,
MAC filtering keeps ours separate; VM's MAC differs).

## Concurrency check first (before starting)
Two clients (VM + rust-vmnet-proxy) on one bridged socket_vmnet daemon:
- daemon floods all frames to all clients (main.c verified)
- VM filters by its MAC, rust-vmnet-proxy by its own -> independent
- DHCP: both request leases -> two different IPs, router DHCP pool handles
- risk: router ARP table sees two MACs on same L2, fine
- risk: duplicate IP if MACs collide -> rust-vmnet-proxy MAC derives from socket
  path hash + VM uses its own -> different by construction

## Tests (in order)
1. Boot: `RUST_LOG=info ./target/release/rust-vmnet-proxy --config deploy/config.alt.yaml`
   Expect log: DHCP ONLINE ip=..., then "socks listening 127.0.0.1:20800"
2. Direct LAN: `curl -sS --socks5 127.0.0.1:20800 -m 8 http://192.0.2.1/ | head -c 200`
   Expect 200 HTML (router page), same as VM leg produces.
3. Direct LAN SSH banner: `nc -X 5 -x 127.0.0.1:20800 192.0.2.2 22 </dev/null | head -1`
   Expect the target's SSH banner.
4. DNS via router: `curl -sS --socks5-hostname 127.0.0.1:20800 -m 8 http://192.0.2.1/`
   (hostname resolution through the smoltcp DNS socket)
5. Internet direct (WARP bypass): `curl -sS --socks5-hostname 127.0.0.1:20800 -m 15 https://ifconfig.me`
   Expect non-WARP public IP (should match VM leg result).
6. Bastion dev leg: `curl -sS --socks5-hostname 127.0.0.1:20801 -m 15 https://k8s.dev.internal.example/status`
   (or whatever internal endpoint the dev bastion reaches; VM leg 1081 same test)
7. Bastion prod/rd legs: analogous on 20802/20803.
8. Grafana relay: `curl -sS -m 15 http://127.0.0.1:20806/api/health`
   Expect {"database":"ok"...} like VM's 1086.
9. Idle hold: 10 min no traffic, then re-run tests 2 and 5. Verifies no
   DHCP expiry/leak, pipes still alive.
10. Load: `curl -sS --socks5-hostname 127.0.0.1:20800 -m 30 -o /dev/null https://speed.cloudflare.com/__down?bytes=10000000`
    Expect >1 MB/s (VM comparison baseline first).
11. Parallel: 20 concurrent curls through 20800 to router, all must succeed.
12. Throughput vs VM: same 10MB download through VM 1080, compare times.

## Results (2026-11-23, commit cdd644a)
All 12 tests pass with VM parity. Exact addresses, leases and exit IPs
are kept in the private ops notes, not in this public repo. Summary:
1. PASS: DHCP lease acquired in ~2s, all 4 ssh legs up.
2. PASS: router page HTML via the direct leg.
3. PASS: LAN SSH banner via the direct leg.
4. PASS: socks5-hostname (DNS through smoltcp) fetch of the router page.
5. PASS: ifconfig.me exit IP identical to the VM leg, WARP bypass
   confirmed (direct WARP shows a different IP).
6. PASS: dev bastion leg endpoint, byte-identical to the VM leg.
7. PASS: prod/rd legs internet exit IPs match the VM legs exactly.
8. PASS: grafana relay health JSON identical to the VM leg.
10. PASS: 10MB download faster than the same download via the VM leg.
11. PASS: 20/20 parallel requests, all 200.
9. pending: idle hold result below.

Fixes landed during testing (cdd644a): SOCKS greeting only read 2 bytes
(client method list desynced every request), connect() rejected port-0
local endpoints (ephemeral ports now allocated from 49152), SIGTERM
never actually stopped the accept/netloop loops (non-blocking accept +
RUNNING checks + ssh child reap). Bastion host keys pinned to
~/.ssh/known_hosts.

## Kill criteria (any -> stop, fix before proceeding)
- daemon socket errors in log (EOF from socket_vmnet)
- DHCP OFFLINE flapping
- SSH leg flapping (restart loop)
- test 2/3 fail (core LAN reachability)
- memory growth visible in Activity Monitor after test 10

## Rollback
Ctrl-C the alt-port process; VM untouched, still serving 1080/1081-1083/1086.