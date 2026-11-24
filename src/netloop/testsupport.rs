//! NetState harness shared by the netloop unit tests (watchdog, tcp). The
//! device sits on a dummy unix socket nothing reads; the peer side is
//! leaked so fill_rx() never sees EOF.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
use smoltcp::socket::dhcpv4;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::netloop::state::{NetState, WatchdogThresholds};
use crate::vmnet_dev::VmnetDevice;

static TEST_N: AtomicU32 = AtomicU32::new(0);

/// NetState over a dummy unix socket: nothing reads it in these tests, it
/// just has to exist.
pub fn test_state(online: bool) -> NetState<'static> {
    let n = TEST_N.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "rust-vmnet-proxy-testsupport-{}-{n}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let mut dev = VmnetDevice::connect(path.to_str().unwrap(), [0x02, 0, 0, 0, 0, 0x01]).unwrap();
    std::mem::forget(listener.accept().unwrap());
    let _ = std::fs::remove_file(&path);

    let if_cfg = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(dev.mac())));
    let mut iface = Interface::new(if_cfg, &mut dev, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0));
    });
    let mut sockets = SocketSet::new(vec![]);
    let dhcp_handle = sockets.add(dhcpv4::Socket::new());
    let (_cmd_tx, cmd_rx) = mpsc::channel();
    NetState {
        dev,
        iface,
        sockets,
        dhcp_handle,
        tcp_conns: HashMap::new(),
        relays: HashMap::new(),
        dns_pending: HashMap::new(),
        next_dns_id: 1,
        dns_handle: None,
        dns_servers: Vec::new(),
        cmd_rx,
        online,
        poll_max: None,
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
        watchdog: WatchdogThresholds::default(),
        tx_stall: SmolDuration::from_secs(30),
    }
}
