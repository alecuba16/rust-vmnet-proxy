use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::dns::QueryHandle;
use smoltcp::time::Duration as SmolDuration;
use smoltcp::wire::Ipv4Address;

use crate::cmds::{ConnectResult, NetCmd};
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

/// Complete netloop state. Owned by the netloop thread only.
pub struct NetState<'a> {
    pub dev: VmnetDevice,
    pub iface: Interface,
    pub sockets: SocketSet<'a>,
    pub dhcp_handle: SocketHandle,
    pub tcp_conns: HashMap<u64, TcpConn>,
    pub dns_pending: HashMap<u64, DnsPending>,
    pub next_dns_id: u64,
    pub dns_handle: Option<SocketHandle>,
    pub dns_servers: Vec<Ipv4Address>,
    pub cmd_rx: std::sync::mpsc::Receiver<NetCmd>,
    pub online: bool,
    /// Cap for the poll_delay() timeout. None = uncapped (battery mode).
    pub poll_max: Option<SmolDuration>,
}
