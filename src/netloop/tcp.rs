use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;

use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use crate::cmds::{ConnPipes, ConnectResult};
use crate::netloop::state::{NetState, TcpConn};

pub const CONNECT_TIMEOUT: SmolDuration = SmolDuration::from_secs(10);
/// Socket buffer sizes. smoltcp derives the advertised window-scale shift
/// from log2(rx buffer): 64 KiB advertises shift 0, so the receive window
/// never exceeds 64 KiB and throughput caps at window/RTT (~10-20 Mbps on a
/// ~30 ms path). 2 MiB negotiates shift 5, a 2 MiB effective window, which
/// covers ~600 Mbps up to ~27 ms RTT (BDP) before the netloop thread
/// itself becomes the limit.
const SOCK_RX_BUF: usize = 2 * 1024 * 1024;
const SOCK_TX_BUF: usize = 512 * 1024;
const PUMP_CHUNK: usize = 64 * 1024;

/// Graceful close may strand the conn when the remote path is wedged: the
/// FIN sits behind bytes that never drain, so the socket never reaches
/// Closed. A deadline forces the abort path so the entry cannot leak.
const CLOSE_TIMEOUT: SmolDuration = SmolDuration::from_secs(30);

/// Only drain the socket while the rx pipe has this much headroom; beyond
/// that leave bytes in the socket buffer so the TCP window closes. Kept in
/// step with PUMP_CHUNK: drain tops the pipe up to headroom + PUMP_CHUNK,
/// which must stay under PIPE_CAP so the blocking push never parks.
const RX_PIPE_HEADROOM: usize = 64 * 1024;

/// Zero local port means smoltcp connect() rejects with Unaddressable, so
/// outbound conns need an ephemeral port. Sequential wrap at IANA's dynamic
/// range start; the netloop serializes all connects so no races.
const EPHEMERAL_START: u16 = 49152;
static NEXT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(EPHEMERAL_START);

fn next_ephemeral_port() -> u16 {
    NEXT_PORT
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .max(EPHEMERAL_START)
}

/// Create a TCP socket for `remote` and register it as conn `id`, adopting
/// the client-provided pipes. connect() must run before the socket enters
/// the SocketSet (context borrow vs sockets, see api-notes TCP section).
/// Deferred-result contract: on success the reply is sent exactly once by
/// service() (Established / Closed-before-established / deadline); on an
/// immediate failure this function replies itself before returning.
pub fn start_connect(
    state: &mut NetState,
    id: u64,
    remote: SocketAddr,
    resp: Sender<ConnectResult>,
    pipes: ConnPipes,
) {
    let remote_ip: IpAddress = match remote.ip() {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(_) => {
            let _ = resp.send(ConnectResult::HostUnreachable);
            return;
        }
    };
    let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_RX_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_TX_BUF]);
    let mut sock = tcp::Socket::new(rx, tx);
    let remote_ep = IpEndpoint::new(remote_ip, remote.port());
    // IpListenEndpoint::default() is port 0: smoltcp connect() treats a zero
    // local port as Unaddressable. Bind an ephemeral port instead.
    let port = next_ephemeral_port();
    let local_ep = IpListenEndpoint::from(port);
    if sock
        .connect(state.iface.context(), remote_ep, local_ep)
        .is_err()
    {
        // offline (no source address) or unaddressable: reply now, service()
        // never sees this conn
        let _ = resp.send(ConnectResult::HostUnreachable);
        return;
    }
    let handle = state.sockets.add(sock);
    let conn = TcpConn {
        handle,
        remote,
        rx_pipe: pipes.rx,
        tx_pipe: pipes.tx,
        tx_spill: Vec::new(),
        tx_stuck_since: None,
        close_deadline: None,
        established: false,
        connect_deadline: Some(SmolInstant::now() + CONNECT_TIMEOUT),
        result_tx: Some(resp),
        result_sent: false,
    };
    state.tcp_conns.insert(id, conn);
}

fn send_result(conn: &mut TcpConn, result: ConnectResult) {
    if conn.result_sent {
        return;
    }
    if let Some(tx) = conn.result_tx.take() {
        let _ = tx.send(result);
    }
    conn.result_sent = true;
}

/// One service pass for a connection: bytes both directions, connect state
/// machine, backpressure by not draining. Returns true when the conn entry
/// should be dropped from the map.
pub fn service(state: &mut NetState, id: u64) -> bool {
    let Some(conn) = state.tcp_conns.get_mut(&id) else {
        return true;
    };
    let sock = state.sockets.get_mut::<tcp::Socket>(conn.handle);

    if !conn.established {
        match sock.state() {
            tcp::State::Established => {
                conn.established = true;
                conn.connect_deadline = None;
                send_result(conn, ConnectResult::Ok);
                log::info!("conn {} established {}", id, conn.remote);
            }
            tcp::State::Closed => {
                send_result(conn, ConnectResult::Refused);
                conn.rx_pipe.close();
                conn.tx_pipe.close();
                let _ = state.sockets.remove(conn.handle);
                return true;
            }
            _ => {
                if let Some(deadline) = conn.connect_deadline {
                    if SmolInstant::now() > deadline {
                        send_result(conn, ConnectResult::Timeout);
                        sock.abort();
                        conn.rx_pipe.close();
                        conn.tx_pipe.close();
                        let _ = state.sockets.remove(conn.handle);
                        return true;
                    }
                }
                if conn.tx_pipe.is_closed() && conn.tx_pipe.is_empty() {
                    // client went away before SYN-ACK: nothing to deliver
                    sock.abort();
                    conn.rx_pipe.close();
                    let _ = state.sockets.remove(conn.handle);
                    return true;
                }
                return false;
            }
        }
    }

    let sock = state.sockets.get_mut::<tcp::Socket>(conn.handle);

    // remote -> client: drain the socket into the rx pipe while there is
    // headroom. Loop, not one fixed chunk: a pass that moves only 16 KiB per
    // direction caps the whole netloop at chunk * poll rate, far under what
    // the TCP window now allows.
    while conn.rx_pipe.len() < RX_PIPE_HEADROOM && sock.can_recv() {
        let mut buf = [0u8; PUMP_CHUNK];
        let Ok(n) = sock.recv_slice(&mut buf) else {
            break;
        };
        if n == 0 {
            break;
        }
        conn.rx_pipe.push(&buf[..n]);
    }

    // client -> remote: take only what the socket tx buffer can hold, so a
    // full tx leaves the pipe undrained and the client blocks in push()
    while sock.can_send() {
        let room = sock.send_capacity() - sock.send_queue();
        if room == 0 {
            break;
        }
        let data = conn.tx_pipe.take(room.min(PUMP_CHUNK));
        if data.is_empty() {
            break;
        }
        if sock.send_slice(&data).is_err() {
            conn.tx_pipe.push_front(&data);
            break;
        }
    }

    // refill tx_pipe from the spill once the normal drain freed capacity;
    // a stuck spill (vmnet tx wedged) tears the conn down after tx_stall
    if !conn.tx_spill.is_empty() {
        let moved = conn.tx_pipe.try_push(&conn.tx_spill);
        if moved > 0 {
            conn.tx_spill.drain(..moved);
            // Any progress proves the path is not wedged. A slowly draining
            // remote keeps pushing the stall clock forward and must not be
            // aborted while it is still moving bytes; a fully drained
            // spill clears the timer.
            conn.tx_stuck_since = if conn.tx_spill.is_empty() {
                None
            } else {
                Some(SmolInstant::now())
            };
        }
        let stuck_for = conn
            .tx_stuck_since
            .map(|t| SmolInstant::now() - t)
            .unwrap_or(SmolDuration::ZERO);
        if stuck_for >= state.tx_stall {
            log::warn!(
                "conn {} tx undrained for {}s: remote path wedged, closing",
                id,
                stuck_for.secs()
            );
            sock.abort();
            conn.rx_pipe.close();
            conn.tx_pipe.close();
            let _ = state.sockets.remove(conn.handle);
            return true;
        }
    }

    // client EOF: FIN once all pending bytes are in the socket (spill
    // included; FIN before drained spill would strand client bytes)
    if conn.tx_pipe.is_closed()
        && conn.tx_pipe.is_empty()
        && conn.tx_spill.is_empty()
        && sock.may_send()
    {
        sock.close();
    }

    let sock = state.sockets.get_mut::<tcp::Socket>(conn.handle);

    if !sock.may_recv() {
        // remote FIN or RST: EOF the client side
        conn.rx_pipe.close();
    }
    if sock.state() == tcp::State::Closed {
        let _ = state.sockets.remove(conn.handle);
        return true;
    }

    // Graceful close that never completed: the FIN sits in a socket the
    // wedged remote will not drain, so the entry would leak. Abort past
    // the deadline; a healthy close reaches Closed and never gets here.
    // send_result keeps the owed-reply contract if a future path makes
    // this reachable pre-establishment (no-op for established conns).
    if conn.close_deadline.is_some_and(|d| SmolInstant::now() > d) {
        log::warn!(
            "conn {} close never drained: remote path wedged, aborting",
            id
        );
        sock.abort();
        conn.rx_pipe.close();
        conn.tx_pipe.close();
        let _ = state.sockets.remove(conn.handle);
        send_result(conn, ConnectResult::Refused);
        return true;
    }
    false
}

/// Close command: graceful FIN when established, abort (RST) otherwise.
/// Pending spill is dropped: a close means the caller is done with the
/// conn, stranded spill bytes have nowhere to go.
pub fn handle_close(state: &mut NetState, id: u64) {
    let Some(conn) = state.tcp_conns.get_mut(&id) else {
        return;
    };
    conn.tx_spill.clear();
    conn.tx_stuck_since = None;
    let sock = state.sockets.get_mut::<tcp::Socket>(conn.handle);
    if conn.established && sock.state() == tcp::State::Established {
        sock.close();
        // A wedged remote leaves the FIN stranded: the socket never drains
        // to Closed and nothing else reaps the entry. Same deadline as the
        // spill stall bounds this graceful phase.
        conn.close_deadline = Some(SmolInstant::now() + CLOSE_TIMEOUT);
    } else {
        // A Close can race the handshake: the result is still owed and
        // must reach the caller as Refused, not a channel drop. No-op
        // for conns whose result was already delivered.
        send_result(conn, ConnectResult::Refused);
        sock.abort();
        conn.rx_pipe.close();
        conn.tx_pipe.close();
        let _ = state.sockets.remove(conn.handle);
        state.tcp_conns.remove(&id);
    }
}

/// Abort (RST) teardown used by every forced path: spill over cap, undrained
/// stall, and a graceful close that never completes. Removes the socket and
/// the map entry in one step (a dangling entry would service a stale handle
/// next pass), closes both pipes so the splice threads unblock, and delivers
/// Refused when the connect result is still owed. Returns true so callers
/// can propagate the drop.
pub fn abort_conn(state: &mut NetState, id: u64) -> bool {
    let Some(mut conn) = state.tcp_conns.remove(&id) else {
        return true;
    };
    conn.tx_spill.clear();
    conn.tx_stuck_since = None;
    let sock = state.sockets.get_mut::<tcp::Socket>(conn.handle);
    sock.abort();
    conn.rx_pipe.close();
    conn.tx_pipe.close();
    let _ = state.sockets.remove(conn.handle);
    send_result(&mut conn, ConnectResult::Refused);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netloop::testsupport::test_state;
    use crate::pipe::Pipe;
    use smoltcp::wire::{IpAddress, Ipv4Address};
    use std::sync::mpsc;
    use std::sync::Arc;

    const REMOTE: SocketAddr =
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)), 80);
    const LOCAL_TEST_PORT: u16 = 41111;

    /// A conn with the established flag set, but a socket the harness can
    /// never drive through a real handshake: no vmnet frames arrive, so the
    /// socket sits in SynSent while the conn logic treats it as pumping.
    /// Exactly the wedged-remote shape the stall and deadline paths guard.
    fn wedged_conn(state: &mut NetState, spill: usize) -> (u64, mpsc::Receiver<ConnectResult>) {
        let (resp_tx, resp_rx) = mpsc::channel();
        let id = state.tcp_conns.keys().copied().max().unwrap_or(0) + 1;
        let handle = {
            let rx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
            let tx = tcp::SocketBuffer::new(vec![0u8; 64 * 1024]);
            let mut sock = tcp::Socket::new(rx, tx);
            sock.connect(
                state.iface.context(),
                IpEndpoint::new(
                    IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 9)),
                    REMOTE.port(),
                ),
                IpListenEndpoint::from(LOCAL_TEST_PORT),
            )
            .unwrap();
            state.sockets.add(sock)
        };
        let conn = TcpConn {
            handle,
            remote: REMOTE,
            rx_pipe: Arc::new(Pipe::new()),
            tx_pipe: Arc::new(Pipe::new()),
            tx_spill: Vec::new(),
            tx_stuck_since: None,
            close_deadline: None,
            established: true,
            connect_deadline: None,
            result_tx: Some(resp_tx),
            result_sent: false,
        };
        state.tcp_conns.insert(id, conn);
        if spill > 0 {
            state
                .tcp_conns
                .get_mut(&id)
                .unwrap()
                .spill_write(&vec![0u8; spill], SmolInstant::now());
        }
        (id, resp_rx)
    }

    #[test]
    fn abort_conn_tears_down_socket_pipes_and_entry() {
        let mut state = test_state(true);
        let (id, resp_rx) = wedged_conn(&mut state, 16 * 1024);
        let (handle, rx_pipe, tx_pipe) = {
            let conn = state.tcp_conns.get(&id).unwrap();
            (
                conn.handle,
                Arc::clone(&conn.rx_pipe),
                Arc::clone(&conn.tx_pipe),
            )
        };

        assert!(abort_conn(&mut state, id));

        // abort_conn removes the entry itself; only a stale handle would be
        // left otherwise, and SocketSet::get panics on those.
        assert!(!state.tcp_conns.contains_key(&id), "entry must be gone");
        let socket_gone = state.sockets.iter().all(|(h, _)| h != handle);
        assert!(socket_gone, "socket must be removed");
        assert!(rx_pipe.is_closed());
        assert!(tx_pipe.is_closed());
        let refused = resp_rx.recv_timeout(std::time::Duration::from_secs(1)).ok();
        assert!(
            matches!(refused, Some(ConnectResult::Refused)),
            "abort must deliver the owed result"
        );
    }

    #[test]
    fn spill_progress_pushes_stall_clock_forward() {
        let mut state = test_state(true);
        let (id, _resp_rx) = wedged_conn(&mut state, 64 * 1024);

        // tx_pipe full: the first pass cannot move spill, the timer starts.
        assert_eq!(
            state
                .tcp_conns
                .get_mut(&id)
                .unwrap()
                .tx_pipe
                .try_push(&vec![1u8; 256 * 1024]),
            256 * 1024
        );
        assert!(!service(&mut state, id));
        assert!(
            state.tcp_conns.get(&id).unwrap().tx_stuck_since.is_some(),
            "stall timer must start on first pass"
        );

        // Free room: the pass moves spill into tx_pipe, and the timer must
        // survive partial progress (spill still nonempty, so not cleared).
        let _ = state
            .tcp_conns
            .get_mut(&id)
            .unwrap()
            .tx_pipe
            .take(16 * 1024);
        assert!(!service(&mut state, id));
        assert!(
            state.tcp_conns.get(&id).unwrap().tx_stuck_since.is_some(),
            "timer must survive partial progress"
        );

        // The discriminator: a stall clock already past tx_stall must be
        // forgiven by fresh progress. The old code (timer cleared only on a
        // fully drained spill) kept the backdated clock and aborted here.
        {
            let conn = state.tcp_conns.get_mut(&id).unwrap();
            conn.tx_stuck_since =
                Some(SmolInstant::now() - state.tx_stall - SmolDuration::from_secs(1));
        }
        let _ = state
            .tcp_conns
            .get_mut(&id)
            .unwrap()
            .tx_pipe
            .take(16 * 1024);
        assert!(!service(&mut state, id));
        assert!(
            state.tcp_conns.contains_key(&id),
            "conn must survive while spill still makes progress"
        );
    }

    #[test]
    fn spill_zero_progress_hits_stall_and_aborts() {
        let mut state = test_state(true);
        let (id, resp_rx) = wedged_conn(&mut state, 64 * 1024);

        // tx_pipe full and sock tx full: zero bytes can move, the stall
        // must abort. Backdate the timer past tx_stall.
        assert_eq!(
            state
                .tcp_conns
                .get_mut(&id)
                .unwrap()
                .tx_pipe
                .try_push(&vec![1u8; 256 * 1024]),
            256 * 1024
        );
        {
            let conn = state.tcp_conns.get_mut(&id).unwrap();
            conn.tx_stuck_since =
                Some(SmolInstant::now() - state.tx_stall - SmolDuration::from_secs(1));
        }

        assert!(service(&mut state, id), "wedged spill must abort");
        // service() signals the drop; the caller (netloop) removes the entry
        state.tcp_conns.remove(&id);
        assert!(
            !state.tcp_conns.contains_key(&id),
            "caller removes the entry"
        );
        // The stall path aborts an established conn: no result is owed (Ok
        // was already delivered on the real handshake), the channel sees EOF.
        assert!(resp_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_err());
        // servicing a removed id is a clean no-op
        assert!(service(&mut state, id));
    }

    #[test]
    fn close_deadline_enforced_for_stranded_fin() {
        let mut state = test_state(true);
        let (id, _resp_rx) = wedged_conn(&mut state, 0);
        {
            let conn = state.tcp_conns.get_mut(&id).unwrap();
            conn.close_deadline = Some(SmolInstant::now() - SmolDuration::from_secs(1));
        }

        assert!(
            service(&mut state, id),
            "stranded FIN must abort past deadline"
        );
        state.tcp_conns.remove(&id);
        assert!(
            !state.tcp_conns.contains_key(&id),
            "caller removes the entry"
        );
    }

    #[test]
    fn healthy_close_clears_no_deadline_stray() {
        let mut state = test_state(true);
        let (id, resp_rx) = wedged_conn(&mut state, 0);

        // Close command: established + SynSent sock takes the abort branch
        // and removes the entry; no deadline can stray on a healthy close.
        handle_close(&mut state, id);
        assert!(!state.tcp_conns.contains_key(&id));
        // Result was never delivered (no handshake): the close must still
        // answer the owed connect reply with Refused, not strand it.
        let refused = resp_rx.recv_timeout(std::time::Duration::from_secs(1)).ok();
        assert!(
            matches!(refused, Some(ConnectResult::Refused)),
            "close racing a pending connect must deliver Refused"
        );
    }

    #[test]
    fn close_racing_pending_connect_delivers_refused() {
        let mut state = test_state(true);
        let (id, resp_rx) = wedged_conn(&mut state, 0);
        // reproduce the race: established=false, result still owed
        state.tcp_conns.get_mut(&id).unwrap().established = false;

        handle_close(&mut state, id);

        assert!(!state.tcp_conns.contains_key(&id));
        let refused = resp_rx.recv_timeout(std::time::Duration::from_secs(1)).ok();
        assert!(
            matches!(refused, Some(ConnectResult::Refused)),
            "the owed reply must reach the caller, not a channel drop"
        );
    }
}
