use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;

use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use crate::cmds::{ConnPipes, ConnectResult};
use crate::netloop::state::{NetState, TcpConn};

pub const CONNECT_TIMEOUT: SmolDuration = SmolDuration::from_secs(10);
const PUMP_CHUNK: usize = 16 * 1024;
const SOCK_BUF: usize = 64 * 1024;

/// Only drain the socket while the rx pipe has this much headroom; beyond
/// that leave bytes in the socket buffer so the TCP window closes.
const RX_PIPE_HEADROOM: usize = 16 * 1024;

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
    let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
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
                if conn.tx_pipe.is_closed() && conn.tx_pipe.len() == 0 {
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

    if conn.rx_pipe.len() < RX_PIPE_HEADROOM && sock.can_recv() {
        let mut buf = [0u8; PUMP_CHUNK];
        if let Ok(n) = sock.recv_slice(&mut buf) {
            conn.rx_pipe.push(&buf[..n]);
        }
    }

    // client -> remote: take only what the socket tx buffer can hold, so a
    // full tx leaves the pipe undrained and the client blocks in push()
    if sock.can_send() {
        let room = sock.send_capacity() - sock.send_queue();
        if room > 0 {
            let data = conn.tx_pipe.take(room.min(PUMP_CHUNK));
            if !data.is_empty() && sock.send_slice(&data).is_err() {
                conn.tx_pipe.push_front(&data);
            }
        }
    }

    // client EOF: FIN once all pending bytes are in the socket
    if conn.tx_pipe.is_closed() && conn.tx_pipe.len() == 0 && sock.may_send() {
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
    false
}

/// Close command: graceful FIN when established, abort (RST) otherwise.
pub fn handle_close(state: &mut NetState, id: u64) {
    let Some(conn) = state.tcp_conns.get_mut(&id) else {
        return;
    };
    let sock = state.sockets.get_mut::<tcp::Socket>(conn.handle);
    if conn.established && sock.state() == tcp::State::Established {
        sock.close();
    } else {
        sock.abort();
        conn.rx_pipe.close();
        conn.tx_pipe.close();
        let _ = state.sockets.remove(conn.handle);
        state.tcp_conns.remove(&id);
    }
}
