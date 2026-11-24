pub mod dhcp;
pub mod dns;
pub mod relay;
pub mod state;
pub mod tcp;
#[cfg(test)]
pub mod testsupport;
pub mod watchdog;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration as StdDuration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::cmds::{ConnHandle, ConnPipes, ConnectResult, NetCmd};
use crate::netloop::state::{NetState, WatchdogThresholds};
use crate::pipe::Pipe;
use crate::vmnet_dev::VmnetDevice;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// Liveness channel from the netloop to the watchdog thread. The loop
/// publishes its expected poll sleep right before poll(); a pass that
/// completes republishes on the next iteration. The watchdog declares
/// death only when silence exceeds the published expectation plus slack,
/// so a legal long poll (battery mode trusts smoltcp timers, up to the DHCP
/// T1) never trips it, while any park after poll (command handling, socket
/// service) is caught within slack.
#[derive(Default)]
pub struct Liveness {
    /// Wall-clock millis of the last publish (Unix epoch).
    last_ms: AtomicU64,
    /// Expected worst-case millis until the next publish. u64::MAX before
    /// the first publish, so the watchdog ignores a not-yet-started loop.
    expected_ms: AtomicU64,
}

/// Monotonic millis since process start. Liveness must not use the wall
/// clock: an NTP step forward or a wake from sleep would look like a hung
/// loop and false-restart the service.
fn mono_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

impl Liveness {
    pub fn new() -> Liveness {
        Liveness {
            last_ms: AtomicU64::new(0),
            expected_ms: AtomicU64::new(u64::MAX),
        }
    }

    pub fn publish(&self, expected_ms: u64) {
        self.expected_ms.store(expected_ms, Ordering::Relaxed);
        self.last_ms.store(mono_ms(), Ordering::Release);
    }

    /// True when the loop went silent for longer than its published
    /// expectation plus `slack`. u64::MAX expectation means not started yet.
    pub fn is_dead(&self, slack: StdDuration) -> bool {
        let last = self.last_ms.load(Ordering::Acquire);
        let expected = self.expected_ms.load(Ordering::Relaxed);
        if expected == u64::MAX {
            return false;
        }
        mono_ms().saturating_sub(last) > expected.saturating_add(slack.as_millis() as u64)
    }
}

pub(crate) fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Sender wrapper enforcing the wake discipline: every command nudges the
/// wake pipe, otherwise the netloop could sleep in poll() with work queued.
#[derive(Clone)]
pub struct NetApi {
    tx: Sender<NetCmd>,
    wake_w: i32,
}

impl NetApi {
    fn send(&self, cmd: NetCmd) {
        if self.tx.send(cmd).is_ok() {
            let byte = [1u8];
            unsafe {
                let _ = libc::write(self.wake_w, byte.as_ptr() as *const libc::c_void, 1);
            }
        }
    }

    pub fn resolve(&self, name: String, resp: Sender<Option<Vec<std::net::IpAddr>>>) {
        self.send(NetCmd::Resolve { name, resp });
    }

    /// Handle given to a relay forward thread for one LAN connection.
    /// Same wake discipline as SOCKS client handles.
    pub fn relay_handle(&self, conn_id: u64) -> crate::cmds::ConnHandle {
        crate::cmds::ConnHandle::new(conn_id, self.tx.clone(), self.wake_w)
    }

    /// Start a proxied TCP connection. Returns the conn handle (whose
    /// write/close also wake the netloop) plus the pipe pair: rx carries
    /// remote->client bytes, tx carries client->remote bytes.
    pub fn connect(
        &self,
        remote: std::net::SocketAddr,
        resp: Sender<ConnectResult>,
    ) -> (ConnHandle, Arc<Pipe>, Arc<Pipe>) {
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let rx = Arc::new(Pipe::new());
        let tx = Arc::new(Pipe::new());
        let pipes = ConnPipes {
            rx: Arc::clone(&rx),
            tx: Arc::clone(&tx),
        };
        self.send(NetCmd::Connect {
            id,
            remote,
            resp,
            pipes,
        });
        (ConnHandle::new(id, self.tx.clone(), self.wake_w), rx, tx)
    }
}

#[cfg(test)]
impl NetApi {
    /// Test seam: build an api from a raw command channel and wake fd so
    /// socks5's per-client logic can be driven without the vmnet loop.
    pub fn new_for_test(tx: Sender<NetCmd>, wake_w: i32) -> NetApi {
        NetApi { tx, wake_w }
    }
}

pub struct NetLoop {
    pub api: NetApi,
    pub join: JoinHandle<()>,
    /// Liveness channel for the watchdog thread in main. The loop publishes
    /// its expected poll sleep before every poll(); a netloop parked anywhere
    /// else (command handling, socket service) stops publishing and the
    /// watchdog restarts the process. The rx watchdog cannot catch this: it
    /// runs inside the loop and shares the failure domain.
    pub liveness: Arc<Liveness>,
}

/// Create the wake pipe and set both ends nonblocking. macOS libc has no
/// pipe2, so pipe + fcntl(F_SETFL, O_NONBLOCK) per fd.
fn wake_pipe() -> std::io::Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        for fd in fds {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl < 0 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok((fds[0], fds[1]))
}

pub fn spawn(
    socket_path: &str,
    mac: [u8; 6],
    tuning: crate::config::Tuning,
    relays: Vec<crate::config::Relay>,
) -> Result<NetLoop, String> {
    spawn_inner(
        socket_path,
        mac,
        tuning,
        relays,
        WatchdogThresholds::default(),
        std::time::Duration::from_secs(2),
        30,
    )
}

/// Test-only entry: same loop as spawn but with watchdog thresholds and a
/// bounded connect retry (the fake daemon is up before the call, so one
/// attempt suffices).
#[doc(hidden)]
pub fn spawn_for_test(
    socket_path: &str,
    mac: [u8; 6],
    tuning: crate::config::Tuning,
    relays: Vec<crate::config::Relay>,
    watchdog: WatchdogThresholds,
) -> Result<NetLoop, String> {
    spawn_inner(
        socket_path,
        mac,
        tuning,
        relays,
        watchdog,
        std::time::Duration::from_millis(50),
        1,
    )
}

fn spawn_inner(
    socket_path: &str,
    mac: [u8; 6],
    tuning: crate::config::Tuning,
    relays: Vec<crate::config::Relay>,
    watchdog: WatchdogThresholds,
    retry_sleep: std::time::Duration,
    attempts: u32,
) -> Result<NetLoop, String> {
    // Boot race: the socket_vmnet daemon may still be starting when the
    // proxy launches (launchd starts both near-simultaneously). Bounded
    // retry; on final failure the caller exits nonzero and the service
    // supervisor (KeepAlive) respawns.
    let mut dev = None;
    let mut last_err = String::new();
    for attempt in 1..=attempts {
        match VmnetDevice::connect(socket_path, mac) {
            Ok(d) => {
                dev = Some(d);
                break;
            }
            Err(e) => {
                if attempt == 1 {
                    log::warn!("vmnet socket not ready ({e}), retrying");
                }
                last_err = e.to_string();
                std::thread::sleep(retry_sleep);
            }
        }
    }
    let dev = dev.ok_or_else(|| format!("vmnet connect: {last_err}"))?;
    let vmnet_fd = dev.raw_fd();
    let (wake_r, wake_w) = wake_pipe().map_err(|e| format!("wake pipe: {e}"))?;
    let (cmd_tx, cmd_rx): (Sender<NetCmd>, Receiver<NetCmd>) = channel();

    let api = NetApi { tx: cmd_tx, wake_w };
    let loop_api = api.clone();
    let liveness = Arc::new(Liveness::new());
    let loop_liveness = Arc::clone(&liveness);

    let join = std::thread::Builder::new()
        .name("netloop".into())
        .spawn(move || {
            run(
                dev,
                LoopFds { vmnet_fd, wake_r },
                cmd_rx,
                LoopCfg {
                    tuning,
                    relays,
                    api: loop_api,
                    watchdog,
                    liveness: loop_liveness,
                },
            )
        })
        .map_err(|e| format!("spawn netloop: {e}"))?;

    Ok(NetLoop {
        api,
        join,
        liveness,
    })
}

/// File descriptors the loop's poll() watches, moved into the loop thread.
struct LoopFds {
    vmnet_fd: i32,
    wake_r: i32,
}

/// Everything the loop thread needs beyond the device and command channel.
struct LoopCfg {
    tuning: crate::config::Tuning,
    relays: Vec<crate::config::Relay>,
    api: NetApi,
    watchdog: WatchdogThresholds,
    liveness: Arc<Liveness>,
}

fn run(mut dev: VmnetDevice, fds: LoopFds, cmd_rx: Receiver<NetCmd>, cfg: LoopCfg) {
    let LoopCfg {
        tuning,
        relays,
        api,
        watchdog,
        liveness,
    } = cfg;
    let mac = dev.mac();
    let if_cfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    let mut iface = Interface::new(if_cfg, &mut dev, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0));
    });
    let mut sockets = SocketSet::new(vec![]);
    let dhcp_handle = sockets.add(dhcpv4::Socket::new());

    let mut state = NetState {
        dev,
        iface,
        sockets,
        dhcp_handle,
        tcp_conns: std::collections::HashMap::new(),
        relays: std::collections::HashMap::new(),
        dns_pending: std::collections::HashMap::new(),
        next_dns_id: 1,
        dns_handle: None,
        dns_servers: Vec::new(),
        cmd_rx,
        online: false,
        poll_max: tuning.poll_max,
        gateway: None,
        last_rx: SmolInstant::now(),
        ever_rx: false,
        last_unicast_rx: SmolInstant::now(),
        ever_unicast_rx: false,
        demand_pending: false,
        probe_started: None,
        last_watchdog_log: None,
        probe_socket: None,
        heartbeat_socket: None,
        last_heartbeat: None,
        heartbeat_unanswered: 0,
        heartbeat_reply_rx: None,
        watchdog,
        tx_stall: SmolDuration::from_secs(30),
    };

    if let Err(e) = relay::init(&mut state, &relays) {
        log::error!("{e}");
        return;
    }

    loop {
        if !crate::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("netloop shutting down");
            return;
        }
        // poll timeout from poll_delay: max poll_max (None = uncapped,
        // battery mode trusts smoltcp timers), min 1ms, 500ms fallback
        let delay = state
            .iface
            .poll_delay(SmolInstant::now(), &state.sockets)
            .unwrap_or(SmolDuration::from_millis(500));
        let delay = match state.poll_max {
            Some(max) => delay.min(max),
            None => delay,
        }
        .max(SmolDuration::from_millis(1));
        let mut pollfds = [
            libc::pollfd {
                fd: fds.vmnet_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: fds.wake_r,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout_ms = delay.total_millis() as i32;
        // publish the expected sleep so the liveness watchdog can tell a
        // legal long poll from a park; poll is the only legal long wait.
        // The 10s slack in main covers pass work between publishes too
        // (cmd drain, socket service, pipe locks); fine for the current
        // conn scale, revisit if passes ever legitimately approach it.
        liveness.publish(timeout_ms.max(0) as u64);
        let n = unsafe { libc::poll(pollfds.as_mut_ptr(), 2, timeout_ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("poll failed: {err}");
            return;
        }

        if pollfds[1].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 8192];
            loop {
                let n = unsafe {
                    libc::read(fds.wake_r, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    break;
                }
            }
            while let Ok(cmd) = state.cmd_rx.try_recv() {
                match cmd {
                    NetCmd::Connect {
                        id,
                        remote,
                        resp,
                        pipes,
                    } => {
                        // deferred result: start_connect replies on immediate
                        // failure, service() on the TCP state machine outcome
                        tcp::start_connect(&mut state, id, remote, resp, pipes);
                    }
                    NetCmd::Write { id, data } => {
                        if data.is_empty() {
                            // pure wake nudge: never touches pipe capacity,
                            // a full pipe must not park the netloop
                            continue;
                        }
                        let Some(conn) = state.tcp_conns.get_mut(&id) else {
                            continue;
                        };
                        let accepted = conn.tx_pipe.try_push(&data);
                        let rest = &data[accepted..];
                        if rest.is_empty() {
                            continue;
                        }
                        if !conn.spill_write(rest, SmolInstant::now()) {
                            log::warn!(
                                "conn {} tx spill over cap: remote path wedged, closing",
                                id
                            );
                            // abort, not graceful close: a wedged remote never
                            // drains the FIN, and the entry would leak
                            tcp::abort_conn(&mut state, id);
                        }
                    }
                    NetCmd::Close { id } => {
                        tcp::handle_close(&mut state, id);
                    }
                    NetCmd::Resolve { name, resp } => {
                        dns::start(&mut state, name, resp);
                    }
                }
            }
        }

        // fill_rx before poll so inbound frames are processed this pass
        if let Err(e) = state.dev.fill_rx() {
            log::error!("vmnet rx failed: {e}");
            return;
        }

        let rx_before = state.dev.rx_taken();
        let uc_before = state.dev.rx_unicast();
        let _ = state
            .iface
            .poll(SmolInstant::now(), &mut state.dev, &mut state.sockets);
        if state.dev.rx_taken() > rx_before {
            state.last_rx = SmolInstant::now();
            state.ever_rx = true;
        }
        if state.dev.rx_unicast() > uc_before {
            state.last_unicast_rx = SmolInstant::now();
            state.ever_unicast_rx = true;
        }

        // Demand for the vmnet path: a DNS query in flight or a TCP connect
        // still establishing. Unicast silence matters when answers are due.
        state.demand_pending =
            !state.dns_pending.is_empty() || state.tcp_conns.values().any(|c| !c.established);

        dhcp::service(&mut state);
        dns::service(&mut state);
        relay::service(&mut state, &api, tuning.splice_timeout);

        watchdog::heartbeat(&mut state);
        if watchdog::check(&mut state) {
            return;
        }

        let ids: Vec<u64> = state.tcp_conns.keys().copied().collect();
        for id in ids {
            if tcp::service(&mut state, id) {
                state.tcp_conns.remove(&id);
            }
        }

        if let Err(e) = state.dev.flush_tx() {
            log::error!("vmnet tx failed: {e}");
            return;
        }
    }
}
