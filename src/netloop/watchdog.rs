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
    probe_gateway(state, gateway, ProbeSlot::Watchdog);

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

/// Drop the probe-window state; called on every healthy pass. This must
/// NOT touch the heartbeat's phase or socket: the netloop pass order runs
/// heartbeat() (queues the probe packet) after check() in the same pass,
/// and reclaiming the socket here drops the queued packet before the next
/// poll ever transmits it (observed live in 0.2.6: probe storm at pass
/// cadence, nothing on the wire, heartbeat knob dead). The heartbeat owns
/// its socket and ends its own phase on silence-broken/offline/no-gateway.
fn disarm(state: &mut NetState) {
    state.probe_started = None;
    if let Some(h) = state.probe_socket.take() {
        let _ = state.sockets.remove(h);
    }
}

/// Demand-independent gateway heartbeat. Once unicast has been silent past
/// the unicast threshold while online, probe the gateway every
/// `th.heartbeat` regardless of client demand: an idle LAN would otherwise
/// hide a real unicast wedge until a client asks for something (observed:
/// 340s). On a healthy path the probe's ARP reply refreshes
/// `last_unicast_rx`; that refresh must NOT reset this cadence, or the
/// heartbeat fires every `unicast_silence` and the `heartbeat` knob is dead
/// (observed live: pass-rate storm in 0.2.6, threshold-rate cadence in
/// 0.2.7, both with a 60s knob). The distinguisher is the outstanding-probe
/// flag: a unicast refresh while a heartbeat probe is unanswered is our
/// own reply landing, so it pays the debt and keeps the clock; a refresh
/// with no probe outstanding is genuine client traffic and ends the phase.
/// Unanswered probes escalate visibility one WARN at
/// a time so a demand-less half wedge stays visible in the log.
///
/// The heartbeat socket survives healthy passes: disarm() must not reclaim
/// it, or the queued packet dies with the socket before the next poll (the
/// 0.2.6 probe storm). Phase ends here close the socket and clear the debt.
pub fn heartbeat(state: &mut NetState) {
    if !state.online || state.gateway.is_none() {
        end_heartbeat_phase(state);
        return;
    }
    let now = SmolInstant::now();
    let uc_silent_for = now - state.last_unicast_rx;
    let th = state.watchdog;
    if th.heartbeat == SmolDuration::ZERO || !state.ever_unicast_rx {
        end_heartbeat_phase(state);
        return;
    }
    if uc_silent_for < th.unicast_silence {
        // Unicast is flowing again. If a probe is outstanding, this frame is
        // our own probe's ARP reply landing: pay the debt and KEEP the
        // clock, or the phase resets here every interval and the heartbeat
        // degenerates to unicast_silence cadence (observed live in 0.2.7:
        // 20s probes despite a 60s knob). A refresh with no probe
        // outstanding is genuine client traffic; only that ends the phase.
        // Sustained client traffic while a probe happened to be in flight
        // ends the phase one pass later, which is the accepted cost.
        if state.heartbeat_unanswered > 0 {
            state.heartbeat_unanswered = 0;
        } else {
            end_heartbeat_phase(state);
        }
        return;
    }
    // If the heartbeat were tuned faster than unicast_silence, the probe's
    // own reply would keep silence below the threshold forever and the knob
    // would be dead (cadence pinned to unicast_silence). Defaults hold; the
    // e2e tuning shortens both together.
    debug_assert!(th.heartbeat >= th.unicast_silence);
    let due = match state.last_heartbeat {
        Some(t) => now - t >= th.heartbeat,
        None => true,
    };
    if due {
        probe_gateway(
            state,
            state.gateway.expect("checked above"),
            ProbeSlot::Heartbeat,
        );
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

/// Close out a heartbeat phase: drop the probe socket (its queued packet,
/// if any, is no longer wanted) and clear the unanswered debt.
fn end_heartbeat_phase(state: &mut NetState) {
    state.last_heartbeat = None;
    state.heartbeat_unanswered = 0;
    if let Some(h) = state.heartbeat_socket.take() {
        let _ = state.sockets.remove(h);
    }
}

/// Force neighbor discovery for the gateway right after a lease lands, so a
/// renewal cycle cannot leave the unicast path riding on a stale neighbor
/// entry (observed: blackouts begin seconds after Configured).
pub fn refresh_gateway(state: &mut NetState, gateway: smoltcp::wire::Ipv4Address) {
    probe_gateway(state, gateway, ProbeSlot::Heartbeat);
    state.last_heartbeat = None;
    state.heartbeat_unanswered = 0;
}

/// Local port for the probe socket; bind(0) is rejected by smoltcp, and any
/// fixed nonzero port works: smoltcp has no conflict check within the set.
const PROBE_LOCAL_PORT: u16 = 41111;

/// Queue a one-byte UDP packet to the gateway on the probe socket. Two
/// owners share this helper: check()'s probe window (probe_socket) and the
/// heartbeat cadence (heartbeat_socket). Each keeps its own persistent
/// socket so packets queued this pass actually transmit on the next poll;
/// reclaiming a socket in the same pass it was queued (what disarm did in
/// 0.2.6) drops the packet and storms ARP at pass cadence.
fn probe_gateway(state: &mut NetState, gateway: smoltcp::wire::Ipv4Address, slot: ProbeSlot) {
    let handle_slot = match slot {
        ProbeSlot::Watchdog => &mut state.probe_socket,
        ProbeSlot::Heartbeat => &mut state.heartbeat_socket,
    };
    if handle_slot.is_none() {
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
        *handle_slot = Some(state.sockets.add(sock));
    }
    let Some(h) = *handle_slot else {
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

#[derive(Clone, Copy)]
enum ProbeSlot {
    Watchdog,
    Heartbeat,
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
        assert!(state.heartbeat_socket.is_some(), "heartbeat armed no probe");
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
        let first = state.last_heartbeat.expect("heartbeat armed");

        // Probe's own ARP reply arrives: unicast fresh again, but for less
        // than a heartbeat interval. A probe is outstanding, so the refresh
        // pays the debt and KEEPS the 60s clock; firing again at the 20s
        // arm threshold is exactly the 0.2.7 live regression.
        state.last_unicast_rx = SmolInstant::now();
        heartbeat(&mut state);
        assert_eq!(state.heartbeat_unanswered, 0, "probe reply pays the debt");
        assert_eq!(
            state.last_heartbeat,
            Some(first),
            "probe reply must not reset the 60s clock"
        );

        // Silence recrosses the threshold before the 60s interval elapsed
        // (e.g. 25s after the first heartbeat): the clock survived, so no
        // heartbeat fires. That is the fix: the phase only restarts on
        // genuine client traffic with no probe outstanding.
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        heartbeat(&mut state);
        assert_eq!(
            state.last_heartbeat,
            Some(first),
            "threshold recross must not fire a heartbeat"
        );
        assert_eq!(state.heartbeat_unanswered, 0, "nothing outstanding again");

        // Now the wedge case: silence sustained, gateway never answers.
        // Clock advanced past the interval: next heartbeat fires. Debt was
        // paid, so the counter restarts from zero and climbs toward the
        // visibility WARN on the probe after this one.
        state.last_heartbeat = Some(SmolInstant::now() - SmolDuration::from_secs(61));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(90);
        heartbeat(&mut state);
        assert_eq!(state.heartbeat_unanswered, 1);
        assert!(state.last_heartbeat.unwrap() > first);
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
    fn disarm_keeps_heartbeat_socket_and_phase() {
        // The 0.2.6 regression this guards: disarm ran after heartbeat in
        // the same pass and reclaimed the socket, dropping the queued
        // packet before any poll could transmit it. The phase and socket
        // must survive healthy passes; only heartbeat() ends its phase.
        let mut state = test_state(true);
        state.ever_unicast_rx = true;
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(30);
        heartbeat(&mut state);
        assert!(state.heartbeat_socket.is_some());
        assert!(state.probe_started.is_none());

        // healthy pass: silence below the unicast threshold, disarm runs
        state.last_unicast_rx = SmolInstant::now() - SmolDuration::from_secs(5);
        assert!(!check(&mut state));
        assert!(
            state.heartbeat_socket.is_some(),
            "disarm must not reclaim the heartbeat socket mid-phase"
        );
        assert_eq!(state.heartbeat_unanswered, 1);
        assert!(state.last_heartbeat.is_some());

        // Probe reply landed in between (debt paid), then genuine client
        // traffic breaks the silence: no probe outstanding, so heartbeat
        // ends its own phase and reclaims the socket.
        state.heartbeat_unanswered = 0;
        state.last_unicast_rx = SmolInstant::now();
        heartbeat(&mut state);
        assert!(state.heartbeat_socket.is_none());
        assert_eq!(state.heartbeat_unanswered, 0);
        assert!(state.last_heartbeat.is_none());
    }

    #[test]
    fn refresh_gateway_forces_probe_and_restarts_heartbeat_clock() {
        let mut state = test_state(true);
        state.gateway = Some(Ipv4Address::new(192, 168, 1, 1));
        state.last_heartbeat = Some(SmolInstant::now());
        refresh_gateway(&mut state, Ipv4Address::new(192, 168, 1, 1));
        assert!(state.heartbeat_socket.is_some(), "lease probe armed no ARP");
        assert!(state.last_heartbeat.is_none());
    }
}
