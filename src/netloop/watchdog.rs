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
/// Two wedges, two arms:
///
/// 1. Total silence: no frame at all passes the MAC filter while online.
///    On a bridged LAN multicast chatter (ARP, mDNS) never stops, so
///    sustained total silence means the daemon socket itself stopped
///    delivering.
///
/// 2. Unicast silence (lima-vm/socket_vmnet#130 class): multicast keeps
///    flowing but the router/bridge stops forwarding unicast to our MAC, so
///    DNS replies, SYN-ACKs and ARP replies to our own requests never
///    arrive while broadcasts keep arm 1 disarmed. This arm needs demand:
///    a pending DNS query or an establishing TCP connection whose answer is
///    overdue.
///
/// Both arms confirm with a gateway probe: an outbound UDP packet forces
/// neighbor discovery, which sends ARP for the gateway. Zero unicast frames
/// for the whole probe window means the rx path is dead. Returning true exits
/// the netloop, and launchd KeepAlive restarts the proxy, which re-wedges the
/// daemon flood registration via a fresh unix connection (verified recovery
/// path in the field).
///
/// False-positive guards:
/// - offline (no lease): DHCP retries handle recovery, silence is expected
/// - never received anything since boot: the LAN may legitimately be quiet
/// - unicast arm: no unicast baseline, or nothing waiting for an answer
/// - any inbound frame during the window disarms arm 1; unicast frame disarms
///   arm 2 (a broadcast cannot heal a unicast wedge)
///
/// Returns true when the netloop should exit.
pub fn check(state: &mut NetState) -> bool {
    let now = SmolInstant::now();
    let silent_for = now - state.last_rx;
    let uc_silent_for = now - state.last_unicast_rx;
    let th = state.watchdog;

    let total_wedged = state.online
        && state.ever_rx
        && silent_for >= th.silence
        && th.silence != SmolDuration::ZERO;
    let unicast_wedged = state.online
        && state.ever_unicast_rx
        && uc_silent_for >= th.unicast_silence
        && th.unicast_silence != SmolDuration::ZERO
        && state.demand_pending;

    if !total_wedged && !unicast_wedged {
        disarm(state);
        return false;
    }

    let Some(gateway) = state.gateway else {
        let (kind, gap) = if unicast_wedged {
            ("unicast rx", uc_silent_for)
        } else {
            ("rx", silent_for)
        };
        warn_once(
            state,
            now,
            format!(
                "{kind} silent for {}s while online with no gateway on the lease; waiting",
                gap.secs()
            ),
        );
        return false;
    };

    if state.probe_started.is_none() {
        state.probe_started = Some(now);
        state.last_heartbeat = None;
    }

    // Re-probe every pass while the window runs: neighbor discovery is
    // rate limited by the neighbor cache, and a lost ARP must not end
    // the window on a technicality.
    probe_gateway(state, gateway);

    let probed_for = now - state.probe_started.expect("armed above");
    if probed_for < th.probe_window {
        // Benign idle gaps on a quiet LAN arm the window and disarm seconds
        // later when the probe's own ARP reply lands. Only a gateway that
        // stays silent past half the window earns a WARN.
        if probed_for >= th.probe_window / 2 {
            let (kind, gap) = if unicast_wedged {
                ("unicast rx", uc_silent_for)
            } else {
                ("rx", silent_for)
            };
            warn_once(
                state,
                now,
                format!(
                    "{kind} silent for {}s while online; gateway {} not answering",
                    gap.secs(),
                    gateway
                ),
            );
        }
        return false;
    }

    let (kind, gap) = if unicast_wedged {
        ("unicast rx", uc_silent_for)
    } else {
        ("rx", silent_for)
    };
    log::error!(
        "vmnet {kind} wedged: {}s silence while online, gateway {} never answered within {}s; exiting for supervisor restart",
        gap.secs(),
        gateway,
        th.probe_window.secs(),
    );
    true
}

/// Drop probe state; called on every healthy pass and on disarm events.
/// The heartbeat arms probe_socket without touching probe_started, so the
/// socket is taken unconditionally: the heartbeat re-creates it on demand.
fn disarm(state: &mut NetState) {
    state.probe_started = None;
    if let Some(h) = state.probe_socket.take() {
        let _ = state.sockets.remove(h);
    }
    if state.last_heartbeat.is_some() {
        state.heartbeat_unanswered = 0;
        state.last_heartbeat = None;
    }
}

/// Demand-independent gateway heartbeat. Once unicast has been silent past
/// the unicast threshold while online, probe the gateway every
/// `th.heartbeat` regardless of client demand: an idle LAN would otherwise
/// hide a real unicast wedge until a client asks for something (observed:
/// 340s). On a healthy path the probe's ARP reply refreshes
/// `last_unicast_rx`; that refresh must NOT reset this cadence, or the
/// heartbeat fires every `unicast_silence` and the `heartbeat` knob is dead
/// (observed live: 20s cadence). So the heartbeat clock starts when silence
/// first crosses the threshold and keeps ticking through probe-induced
/// refreshes; it only restarts when genuine traffic (client unicast) breaks
/// the silence for real. Unanswered probes escalate visibility one WARN at
/// a time so a demand-less half wedge stays visible in the log.
pub fn heartbeat(state: &mut NetState) {
    if !state.online || state.gateway.is_none() {
        state.last_heartbeat = None;
        state.heartbeat_unanswered = 0;
        return;
    }
    let now = SmolInstant::now();
    let uc_silent_for = now - state.last_unicast_rx;
    let th = state.watchdog;
    if th.heartbeat == SmolDuration::ZERO || !state.ever_unicast_rx {
        state.last_heartbeat = None;
        state.heartbeat_unanswered = 0;
        return;
    }
    if uc_silent_for < th.unicast_silence {
        // Silence is genuinely broken (client unicast, not our own probe
        // reply: a probe reply would keep silence just under the threshold
        // for one pass at most). Restart the heartbeat phase.
        state.last_heartbeat = None;
        state.heartbeat_unanswered = 0;
        return;
    }
    let due = match state.last_heartbeat {
        Some(t) => now - t >= th.heartbeat,
        None => true,
    };
    if due {
        probe_gateway(state, state.gateway.expect("checked above"));
        state.last_heartbeat = Some(now);
        state.heartbeat_unanswered += 1;
        if state.heartbeat_unanswered > 1 {
            // The previous heartbeat's ARP reply never landed: only our own
            // probes are keeping the unicast counter alive, if at all.
            warn_once(
                state,
                now,
                format!(
                    "gateway {} silent across {} heartbeats while unicast idle",
                    state.gateway.expect("checked above"),
                    state.heartbeat_unanswered - 1
                ),
            );
        }
    }
}

/// Force neighbor discovery for the gateway right after a lease lands, so a
/// renewal cycle cannot leave the unicast path riding on a stale neighbor
/// entry (observed: blackouts begin seconds after Configured).
pub fn refresh_gateway(state: &mut NetState, gateway: smoltcp::wire::Ipv4Address) {
    probe_gateway(state, gateway);
    state.last_heartbeat = None;
    state.heartbeat_unanswered = 0;
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

pub const WATCHDOG_LOG_INTERVAL: SmolDuration = SmolDuration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netloop::testsupport::test_state;
    use smoltcp::wire::Ipv4Address;

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

    #[test]
    fn unicast_wedge_with_demand_arms_probe() {
        // The #130 wedge: broadcasts keep arriving (last_rx fresh) but the
        // router stopped forwarding unicast. Pending DNS makes it a wedge.
        let mut state = test_state(true);
        state.ever_rx = true;
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now(); // broadcast traffic still flows
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(60);
        state.demand_pending = true;
        assert!(!check(&mut state)); // arms the probe, does not exit yet
        assert!(state.probe_started.is_some());
        assert!(state.probe_socket.is_some());
    }

    #[test]
    fn unicast_wedge_without_demand_disarms() {
        // Unicast silent but nothing waits for an answer: idle, not wedged.
        let mut state = test_state(true);
        state.ever_rx = true;
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now();
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(60);
        state.demand_pending = false;
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
    }

    #[test]
    fn broadcast_only_traffic_does_not_disarm_unicast_probe() {
        // Once the unicast arm is probing, a broadcast must not reset it:
        // the netloop only refreshes last_unicast_rx on unicast frames.
        let mut state = test_state(true);
        state.ever_rx = true;
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(60);
        state.demand_pending = true;
        assert!(!check(&mut state));
        assert!(state.probe_started.is_some());

        state.last_rx = SmolInstant::now(); // only broadcasts arrived
        assert!(!check(&mut state));
        assert!(state.probe_started.is_some());
    }

    #[test]
    fn unicast_frame_disarms_unicast_probe() {
        let mut state = test_state(true);
        state.ever_rx = true;
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(60);
        state.demand_pending = true;
        assert!(!check(&mut state));
        assert!(state.probe_started.is_some());

        state.last_unicast_rx = SmolInstant::now(); // unicast came back
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
        assert!(state.probe_socket.is_none());
    }

    #[test]
    fn unicast_wedge_orders_exit_after_probe_window() {
        let mut state = test_state(true);
        state.ever_rx = true;
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now();
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(120);
        state.demand_pending = true;
        state.probe_started = Some(SmolInstant::now() - SmolDuration::from_secs(16));
        assert!(check(&mut state));
    }

    #[test]
    fn unicast_no_baseline_disarms_even_with_demand() {
        // Never got unicast since boot: no baseline for a unicast wedge.
        let mut state = test_state(true);
        state.ever_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_rx = SmolInstant::now();
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(120);
        state.demand_pending = true;
        assert!(!check(&mut state));
        assert!(state.probe_started.is_none());
    }

    #[test]
    fn heartbeat_probes_past_unicast_silence_without_demand() {
        // The 340s blind spot: unicast silent, no client demand, nothing
        // would arm the watchdog. The heartbeat keeps the path visible
        // (and heals expired neighbor entries) on its own.
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        state.demand_pending = false;
        heartbeat(&mut state);
        assert!(state.probe_socket.is_some(), "heartbeat armed no probe");
        assert!(state.last_heartbeat.is_some());
        assert!(
            state.probe_started.is_none(),
            "heartbeat must not arm the exit path"
        );
    }

    #[test]
    fn heartbeat_skips_fresh_unicast_offline_and_no_baseline() {
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now(); // unicast flowing
        heartbeat(&mut state);
        assert!(state.probe_socket.is_none());
        assert!(state.last_heartbeat.is_none());

        state.online = false; // offline: DHCP retries own recovery
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(600);
        heartbeat(&mut state);
        assert!(state.probe_socket.is_none());

        state.online = true; // online but never saw unicast: no baseline
        state.ever_unicast_rx = false;
        heartbeat(&mut state);
        assert!(state.probe_socket.is_none());
    }

    #[test]
    fn heartbeat_rate_limits_while_gateway_stays_silent() {
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        heartbeat(&mut state);
        assert!(state.last_heartbeat.is_some());
        // Second call within the interval must not advance the timer or
        // spam the socket.
        let first = state.last_heartbeat;
        heartbeat(&mut state);
        assert_eq!(state.last_heartbeat, first);
    }

    #[test]
    fn heartbeat_keeps_cadence_when_probe_reply_refreshes_unicast() {
        // The self-refresh loop: the probe's own ARP reply lands, unicast
        // silence drops below the threshold... but only because of OUR
        // probe. On the next pass silence crosses again; the heartbeat must
        // keep its 60s clock, not fire again at the 20s arm threshold
        // (observed live: 20s cadence instead of 60s).
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        heartbeat(&mut state);
        assert_eq!(state.heartbeat_unanswered, 1);

        // Probe's own ARP reply arrives: unicast fresh again, but for less
        // than a heartbeat interval. Heartbeat must NOT reset its clock to
        // fire immediately once silence recrosses; genuine client traffic
        // is what resets, and only when silence stays broken.
        state.last_unicast_rx = SmolInstant::now();
        heartbeat(&mut state);
        assert_eq!(state.last_heartbeat, None, "genuine traffic resets phase");

        // Silence recrosses the threshold before the 60s interval elapsed
        // (e.g. 25s after the first heartbeat): the phase restarted above,
        // so a heartbeat fires at the arm threshold. That is the accepted
        // trade: real traffic ends the phase, the next idle gap starts a
        // fresh one.
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        heartbeat(&mut state);
        assert!(state.last_heartbeat.is_some());
        assert_eq!(state.heartbeat_unanswered, 1, "new phase, counter reset");

        // Now the wedge case: silence sustained, gateway never answers.
        // Clock advanced past the interval: next heartbeat fires and the
        // unanswered counter climbs, driving the visibility WARN.
        state.last_heartbeat = Some(SmolInstant::now() - SmolDuration::from_secs(61));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(90);
        heartbeat(&mut state);
        assert_eq!(state.heartbeat_unanswered, 2);
    }

    #[test]
    fn heartbeat_warns_only_when_gateway_stays_silent_across_probes() {
        // First heartbeat of a phase is silent (the reply may still land);
        // a second consecutive unanswered heartbeat means the ARP is not
        // coming back and the half wedge must be visible.
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(90);
        heartbeat(&mut state);
        assert_eq!(state.heartbeat_unanswered, 1); // silent: reply may land

        state.last_heartbeat = Some(SmolInstant::now() - SmolDuration::from_secs(61));
        heartbeat(&mut state);
        assert_eq!(state.heartbeat_unanswered, 2); // WARN fired here
    }

    #[test]
    fn disarm_reclaims_heartbeat_probe_socket() {
        // The heartbeat arms probe_socket without probe_started; disarm on
        // a healthy pass must still reclaim the socket, not leak it into
        // every future iface.poll walk.
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        heartbeat(&mut state);
        assert!(state.probe_socket.is_some());
        assert!(state.probe_started.is_none());

        state.last_unicast_rx = SmolInstant::now(); // traffic resumed
                                                    // disarm runs from check() on a healthy pass
        assert!(!check(&mut state));
        assert!(
            state.probe_socket.is_none(),
            "disarm leaked the heartbeat socket"
        );
        assert_eq!(state.heartbeat_unanswered, 0);
        assert!(state.last_heartbeat.is_none());
    }

    #[test]
    fn refresh_gateway_forces_probe_and_restarts_heartbeat_clock() {
        let mut state = test_state(true);
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_heartbeat = Some(SmolInstant::now());
        refresh_gateway(&mut state, Ipv4Address::new(192, 168, 1, 1));
        assert!(state.probe_socket.is_some(), "lease probe armed no ARP");
        assert!(state.last_heartbeat.is_none());
    }
}
