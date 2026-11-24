use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::dns::QueryHandle;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::Ipv4Address;

use crate::cmds::{ConnectResult, NetCmd};
use crate::netloop::relay::RelayState;
use crate::pipe::Pipe;
use crate::vmnet_dev::VmnetDevice;

/// Per-connection state held by the netloop.
pub struct TcpConn {
    pub handle: SocketHandle,
    pub remote: SocketAddr,
    /// remote -> SOCKS client thread
    pub rx_pipe: Arc<Pipe>,
    /// SOCKS client thread -> remote
    pub tx_pipe: Arc<Pipe>,
    pub established: bool,
    pub connect_deadline: Option<smoltcp::time::Instant>,
    pub result_tx: Option<Sender<ConnectResult>>,
    pub result_sent: bool,
}

/// Pending DNS query: query id -> (smoltcp query handle, reply channel, deadline).
pub struct DnsPending {
    pub qhandle: QueryHandle,
    pub reply: Sender<Option<Vec<std::net::IpAddr>>>,
    pub deadline: smoltcp::time::Instant,
}

/// Watchdog timing knobs. Production defaults live in Default; the e2e test
/// shortens them so a wedge plays out in seconds.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogThresholds {
    /// Total rx silence while online before the watchdog arms.
    pub silence: SmolDuration,
    /// Unicast rx silence while online before the unicast arm arms.
    pub unicast_silence: SmolDuration,
    /// How long the gateway probe must stay unanswered before exit.
    pub probe_window: SmolDuration,
}

impl Default for WatchdogThresholds {
    fn default() -> Self {
        WatchdogThresholds {
            silence: SmolDuration::from_secs(45),
            unicast_silence: SmolDuration::from_secs(20),
            probe_window: SmolDuration::from_secs(15),
        }
    }
}

/// Complete netloop state. Owned by the netloop thread only.
pub struct NetState<'a> {
    pub dev: VmnetDevice,
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
    pub dhcp_handle: SocketHandle,
    pub tcp_conns: HashMap<u64, TcpConn>,
    /// Relay listeners by relay listen port. Accepted relay conns join
    /// tcp_conns with ids from the shared NEXT_CONN_ID allocator.
    pub relays: HashMap<u16, RelayState>,
    pub dns_pending: HashMap<u64, DnsPending>,
    pub next_dns_id: u64,
    pub dns_handle: Option<SocketHandle>,
    pub dns_servers: Vec<Ipv4Address>,
    pub cmd_rx: std::sync::mpsc::Receiver<NetCmd>,
    pub online: bool,
    /// Cap for the poll_delay() timeout. None = uncapped (battery mode).
    pub poll_max: Option<SmolDuration>,
    /// Default gateway from the DHCP lease; the watchdog probes it when rx
    /// goes silent while online.
    pub gateway: Option<Ipv4Address>,
    /// Smoltcp Instant of the last frame that passed the MAC filter. On a
    /// bridged LAN multicast (ARP, mDNS) never stops, so a long gap while
    /// online means the vmnet rx path is wedged even though the unix socket
    /// stays open.
    pub last_rx: SmolInstant,
    /// Set once any inbound frame arrives; a LAN that is silent even while
    /// healthy would keep the watchdog permanently armed, so it disarms.
    pub ever_rx: bool,
    /// Smoltcp Instant of the last unicast frame for our MAC. Bridged-mode
    /// wedges can pass multicast while unicast forwarding is dead, so the
    /// watchdog tracks unicast silence separately from total silence.
    pub last_unicast_rx: SmolInstant,
    /// Set once any unicast frame arrives; the unicast arm of the watchdog
    /// needs a healthy-unicast baseline before it can declare a wedge.
    pub ever_unicast_rx: bool,
    /// True when traffic is waiting on the vmnet path: a pending DNS query
    /// or a TCP connection still establishing. Unicast silence only counts
    /// as a wedge when something is actually waiting for an answer.
    pub demand_pending: bool,
    /// Probe window start when rx went silent while online and the gateway
    /// is known.
    pub probe_started: Option<SmolInstant>,
    /// Rate limit for watchdog log lines during an ongoing outage.
    pub last_watchdog_log: Option<SmolInstant>,
    /// UDP socket used to force ARP for the gateway while the probe window
    /// runs; removed on disarm.
    pub probe_socket: Option<SocketHandle>,
    /// Timing knobs for the rx watchdog.
    pub watchdog: WatchdogThresholds,
}
