use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::IpAddress;

use crate::netloop::state::NetState;

/// Detect a wedged vmnet rx path and ask the supervisor for a restart.
///
/// socket_vmnet can wedge half-duplex after a daemon SIGTERM/re-init
/// (observed in the wild: the unix socket stays open, frames never arrive
/// again, DHCP DISCOVERs from fresh clients get no OFFERs). The proxy keeps
/// accepting SOCKS5 clients and answering from its stale DHCP lease, so it
/// looks online while every CONNECT times out. The unix socket staying open
/// also means fill_rx() never errors, so the netloop's own exit path never
/// fires.
///
/// Signal: no frame passes the MAC filter for WATCHDOG_SILENCE while online.
/// On a bridged LAN multicast chatter (ARP, mDNS) never stops, so sustained
/// silence means frames are not reaching us. Confirm with a gateway probe:
/// an outbound UDP packet forces neighbor discovery, which sends ARP for the
/// gateway; zero inbound frames for the whole probe window means the rx
/// path is dead. Returning true exits the netloop, and launchd KeepAlive
/// restarts the proxy, which re-wedges the daemon flood registration via a
/// fresh unix connection (verified recovery path in the field).
///
/// False-positive guards:
/// - offline (no lease): DHCP retries handle recovery, silence is expected
/// - never received anything since boot: the LAN may legitimately be quiet
/// - any inbound frame during the window disarms everything
///
/// Returns true when the netloop should exit.
pub fn check(state: &mut NetState) -> bool {
    let now = SmolInstant::now();
    let silent_for = now - state.last_rx;

    if !state.online || silent_for < WATCHDOG_SILENCE {
        disarm(state);
        return false;
    }

    // A LAN that has been silent since boot: no baseline for "wedge", the
    // probe would arm forever on a quiet-but-healthy network.
    if !state.ever_rx {
        disarm(state);
        return false;
    }

    let Some(gateway) = state.gateway else {
        warn_once(
            state,
            now,
            format!(
                "rx silent for {}s while online with no gateway on the lease; waiting",
                silent_for.secs()
            ),
        );
        return false;
    };

    if state.probe_started.is_none() {
        warn_once(
            state,
            now,
            format!(
                "rx silent for {}s while online; probing gateway {}",
                silent_for.secs(),
                gateway
            ),
        );
        state.probe_started = Some(now);
    }

    // Re-probe every pass while the window runs: neighbor discovery is
    // rate limited by the neighbor cache, and a lost ARP must not end
    // the window on a technicality.
    probe_gateway(state, gateway);

    let probed_for = now - state.probe_started.expect("armed above");
    if probed_for < WATCHDOG_PROBE_WINDOW {
        return false;
    }

    log::error!(
        "vmnet rx wedged: {}s silence while online, gateway {} never answered within {}s; exiting for supervisor restart",
        silent_for.secs(),
        gateway,
        WATCHDOG_PROBE_WINDOW.secs(),
    );
    true
}

/// Drop probe state; called on every healthy pass and on disarm events.
fn disarm(state: &mut NetState) {
    if state.probe_started.take().is_some() {
        if let Some(h) = state.probe_socket.take() {
            let _ = state.sockets.remove(h);
        }
    }
}

/// Local port for the probe socket; bind(0) is rejected by smoltcp, and any
/// fixed nonzero port works: smoltcp has no conflict check within the set.
const PROBE_LOCAL_PORT: u16 = 41111;

/// Queue a one-byte UDP packet to the gateway on the persistent probe
/// socket. Egress neighbor discovery emits ARP for the gateway MAC (rate
/// limited by the neighbor cache to one request per second); any inbound
/// frame, including the ARP reply, resets last_rx on the next pass.
fn probe_gateway(state: &mut NetState, gateway: smoltcp::wire::Ipv4Address) {
    if state.probe_socket.is_none() {
        let mut sock = smoltcp::socket::udp::Socket::new(
            smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 1],
                vec![0u8; 1],
            ),
            smoltcp::socket::udp::PacketBuffer::new(
                vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 1],
                vec![0u8; 1],
            ),
        );
        if sock.bind(PROBE_LOCAL_PORT).is_err() {
            return;
        }
        state.probe_socket = Some(state.sockets.add(sock));
    }
    let Some(h) = state.probe_socket else {
        return;
    };
    let sock = state.sockets.get_mut::<smoltcp::socket::udp::Socket>(h);
    if sock.can_send() {
        let _ = sock.send_slice(
            &[0u8; 1],
            smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(gateway), 9),
        );
    }
}

/// Warn at most once per WATCHDOG_LOG_INTERVAL so long outages do not spam
/// the log.
fn warn_once(state: &mut NetState, now: SmolInstant, msg: String) {
    let due = match state.last_watchdog_log {
        Some(t) => now - t > WATCHDOG_LOG_INTERVAL,
        None => true,
    };
    if due {
        log::warn!("{msg}");
        state.last_watchdog_log = Some(now);
    }
}

const WATCHDOG_SILENCE: SmolDuration = SmolDuration::from_secs(45);
const WATCHDOG_PROBE_WINDOW: SmolDuration = SmolDuration::from_secs(15);
const WATCHDOG_LOG_INTERVAL: SmolDuration = SmolDuration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;

    use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet};
    use smoltcp::socket::dhcpv4;
    use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
    use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

    use crate::netloop::state::NetState;
    use crate::vmnet_dev::VmnetDevice;

    static TEST_N: AtomicU32 = AtomicU32::new(0);

    /// NetState over a dummy unix socket: nothing reads it in these tests, it
    /// just has to exist. The peer side is leaked so the device socket never
    /// sees EOF if a future test calls fill_rx().
    fn test_state(online: bool) -> NetState<'static> {
        let n = TEST_N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rust-vmnet-proxy-watchdog-{}-{n}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut dev =
            VmnetDevice::connect(path.to_str().unwrap(), [0x02, 0, 0, 0, 0, 0x01]).unwrap();
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
            probe_started: None,
            last_watchdog_log: None,
            probe_socket: None,
        }
    }

    #[test]
    fn lan_silent_since_boot_disarms() {
        // Online but nothing ever arrived: no baseline for a wedge.
        let mut state = test_state(true);
        state.last_rx = SmolInstant::now() - SmolDuration::from_secs(600);
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
    }

    #[test]
    fn offline_disarms_even_after_frames() {
        let mut state = test_state(false);
        state.ever_rx = true;
        state.last_rx = SmolInstant::now() - SmolDuration::from_secs(600);
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
    }

    #[test]
    fn fresh_traffic_disarms_and_drops_probe_socket() {
        let mut state = test_state(true);
        state.ever_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now() - SmolDuration::from_secs(60);
        assert!(!check(&mut state)); // arms the probe
        assert!(state.probe_started.is_some());
        assert!(state.probe_socket.is_some());

        state.last_rx = SmolInstant::now(); // any frame arrived
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
        assert!(state.probe_socket.is_none());
    }

    #[test]
    fn missing_gateway_waits_without_arming() {
        let mut state = test_state(true);
        state.ever_rx = true;
        state.last_rx = SmolInstant::now() - SmolDuration::from_secs(600);
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
    }

    #[test]
    fn wedged_rx_orders_exit_after_probe_window() {
        let mut state = test_state(true);
        state.ever_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now() - SmolDuration::from_secs(120);
        // Probe armed a window ago and still no frame: wedged.
        state.probe_started = Some(SmolInstant::now() - SmolDuration::from_secs(16));
        assert!(check(&mut state));
    }

    #[test]
    fn probe_window_not_elapsed_keeps_running() {
        let mut state = test_state(true);
        state.ever_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now() - SmolDuration::from_secs(120);
        state.probe_started = Some(SmolInstant::now() - SmolDuration::from_secs(5));
        assert!(!check(&mut state));
    }
}