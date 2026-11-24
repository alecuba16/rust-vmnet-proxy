pub mod dhcp;
pub mod dns;
pub mod relay;
pub mod state;
pub mod tcp;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::cmds::{ConnHandle, ConnPipes, ConnectResult, NetCmd};
use crate::netloop::state::NetState;
use crate::pipe::Pipe;
use crate::vmnet_dev::VmnetDevice;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

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
    // Boot race: the socket_vmnet daemon may still be starting when the
    // proxy launches (launchd starts both near-simultaneously). Bounded
    // retry; on final failure the caller exits nonzero and the service
    // supervisor (KeepAlive) respawns.
    let mut dev = None;
    let mut last_err = String::new();
    for attempt in 1..=30 {
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
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
    }
    let dev = dev.ok_or_else(|| format!("vmnet connect: {last_err}"))?;
    let vmnet_fd = dev.raw_fd();
    let (wake_r, wake_w) = wake_pipe().map_err(|e| format!("wake pipe: {e}"))?;
    let (cmd_tx, cmd_rx): (Sender<NetCmd>, Receiver<NetCmd>) = channel();

    let api = NetApi { tx: cmd_tx, wake_w };
    let loop_api = api.clone();

    let join = std::thread::Builder::new()
        .name("netloop".into())
        .spawn(move || run(dev, vmnet_fd, wake_r, cmd_rx, tuning, relays, loop_api))
        .map_err(|e| format!("spawn netloop: {e}"))?;

    Ok(NetLoop { api, join })
}

fn run(
    mut dev: VmnetDevice,
    vmnet_fd: i32,
    wake_r: i32,
    cmd_rx: Receiver<NetCmd>,
    tuning: crate::config::Tuning,
    relays: Vec<crate::config::Relay>,
    api: NetApi,
) {
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
        let mut fds = [
            libc::pollfd {
                fd: vmnet_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_r,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout_ms = delay.total_millis() as i32;
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("poll failed: {err}");
            return;
        }

        if fds[1].revents & libc::POLLIN != 0 {
            let mut buf = [0u8; 8192];
            loop {
                let n =
                    unsafe { libc::read(wake_r, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
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
                        if let Some(conn) = state.tcp_conns.get_mut(&id) {
                            conn.tx_pipe.push(&data);
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

        let _ = state
            .iface
            .poll(SmolInstant::now(), &mut state.dev, &mut state.sockets);

        dhcp::service(&mut state);
        dns::service(&mut state);
        relay::service(&mut state, &api, tuning.splice_timeout);

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
