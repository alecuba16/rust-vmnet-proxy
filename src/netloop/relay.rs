use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;

use crate::config::Relay;
use crate::netloop::state::NetState;
use crate::netloop::NetApi;
use crate::pipe::Pipe;

/// Listeners pre-armed per relay. smoltcp 0.14 has no accept queue: the
/// listening socket itself becomes the connection, so every accept needs a
/// fresh listener for the same port in the same pass. Extra slots absorb
/// simultaneous SYNs while the promoted one is being replaced.
const LISTENER_BACKLOG: usize = 4;
const SOCK_BUF: usize = 64 * 1024;
const SPLICE_CHUNK: usize = 16 * 1024;

/// Per-relay runtime state owned by the netloop.
pub struct RelayState {
    pub relay: Relay,
    /// Armed listener handles. The next SYN lands on one of these.
    pub listeners: Vec<smoltcp::iface::SocketHandle>,
}

/// Arm one listening socket on the relay port. Binding the unspecified
/// endpoint covers the stack's single DHCP address.
fn arm_listener(state: &mut NetState, port: u16) -> Result<smoltcp::iface::SocketHandle, String> {
    let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = tcp::Socket::new(rx, tx);
    if sock.listen(IpListenEndpoint::from(port)).is_err() {
        return Err(format!("relay :{port}: listen failed"));
    }
    Ok(state.sockets.add(sock))
}

/// Create RelayState entries for every configured relay. One listener that
/// fails to arm aborts startup with the port named in the error.
pub fn init(state: &mut NetState, relays: &[Relay]) -> Result<(), String> {
    for relay in relays {
        let mut listeners = Vec::with_capacity(LISTENER_BACKLOG);
        for _ in 0..LISTENER_BACKLOG {
            listeners.push(arm_listener(state, relay.listen)?);
        }
        state.relays.insert(
            relay.listen,
            RelayState {
                relay: relay.clone(),
                listeners,
            },
        );
        log::info!(
            "relay {} armed on :{} -> {}",
            relay.name,
            relay.listen,
            relay.target
        );
    }
    Ok(())
}

/// One accept pass over all relay listeners. A listener that reached
/// Established is promoted into the shared TcpConn machinery (pumped by
/// tcp::service) and replaced with a fresh armed listener the same pass.
pub fn service(state: &mut NetState, api: &NetApi, splice_timeout: std::time::Duration) {
    let ports: Vec<u16> = state.relays.keys().copied().collect();
    for port in ports {
        let (relay, established, remaining) = {
            let Some(rs) = state.relays.get(&port) else {
                continue;
            };
            let mut established = None;
            let mut remaining = Vec::with_capacity(rs.listeners.len());
            for &h in &rs.listeners {
                let sock = state.sockets.get_mut::<tcp::Socket>(h);
                if sock.state() == tcp::State::Established {
                    established = Some(h);
                } else {
                    remaining.push(h);
                }
            }
            (rs.relay.clone(), established, remaining)
        };
        let Some(handle) = established else {
            if let Some(rs) = state.relays.get_mut(&port) {
                rs.listeners = remaining;
            }
            continue;
        };
        let remote = {
            let ep = state
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .remote_endpoint();
            match ep {
                Some(ep) => {
                    // proto-ipv4 build: the endpoint address is always Ipv4,
                    // the Ipv6 variant is compiled out
                    let smoltcp::wire::IpAddress::Ipv4(v4) = ep.addr;
                    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(v4.octets())), ep.port)
                }
                None => SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port),
            }
        };
        // Adopt as an established TcpConn: no result channel to answer,
        // tcp::service drives the pump from here on.
        let rx_pipe = Arc::new(Pipe::new());
        let tx_pipe = Arc::new(Pipe::new());
        let conn = crate::netloop::state::TcpConn {
            handle,
            remote,
            rx_pipe: Arc::clone(&rx_pipe),
            tx_pipe: Arc::clone(&tx_pipe),
            established: true,
            connect_deadline: None,
            result_tx: None,
            result_sent: true,
        };
        let conn_id = crate::netloop::next_conn_id();
        state.tcp_conns.insert(conn_id, conn);
        // re-arm a fresh listener before signaling the forward thread, so
        // the next SYN already has a socket to land on
        match arm_listener(state, port) {
            Ok(new_h) => {
                let rs = state.relays.get_mut(&port).unwrap();
                rs.listeners = remaining;
                rs.listeners.push(new_h);
            }
            Err(e) => {
                log::error!("{e}");
                let rs = state.relays.get_mut(&port).unwrap();
                rs.listeners = remaining;
            }
        }
        log::info!(
            "relay {} accepted {} -> {}",
            relay.name,
            remote,
            relay.target
        );
        spawn_forward(&relay, api, conn_id, rx_pipe, tx_pipe, splice_timeout);
    }
}

/// Mac-side half of the relay: dial the target and splice both directions,
/// mirroring the SOCKS5 client splice (two threads, one per direction).
/// Direction names follow the LAN client as "client": up = LAN -> target,
/// down = target -> LAN.
fn spawn_forward(
    relay: &Relay,
    api: &NetApi,
    conn_id: u64,
    rx_pipe: Arc<Pipe>,
    tx_pipe: Arc<Pipe>,
    splice_timeout: std::time::Duration,
) {
    let handle = api.relay_handle(conn_id);
    let target = relay.target;
    let name = relay.name.clone();
    std::thread::Builder::new()
        .name(format!("relay-{name}"))
        .spawn(move || {
            let Ok(mut fwd) = std::net::TcpStream::connect(target) else {
                log::warn!("relay {name}: target {target} unreachable");
                // target dead: FIN the LAN side both ways
                tx_pipe.close();
                rx_pipe.close();
                handle.close();
                return;
            };
            let _ = fwd.set_nodelay(true);
            // LAN -> target
            let Ok(mut up) = fwd.try_clone() else {
                tx_pipe.close();
                rx_pipe.close();
                handle.close();
                return;
            };
            let up_tx = tx_pipe;
            let up_handle = handle.clone();
            let up_thread = std::thread::Builder::new()
                .name(format!("relay-{name}-up"))
                .spawn(move || {
                    let mut buf = [0u8; SPLICE_CHUNK];
                    loop {
                        match up.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                // empty Write after a push: wakes the netloop
                                // so the pipe drains this pass, not at the
                                // next poll timeout
                                if !up_tx.push(&buf[..n]) {
                                    break;
                                }
                                up_handle.write(Vec::new());
                            }
                            Err(_) => break,
                        }
                    }
                    // EOF: netloop FINs once the pipe is drained
                    up_tx.close();
                    up_handle.write(Vec::new());
                })
                .expect("spawn relay up thread");
            // target -> LAN
            loop {
                match rx_pipe.take_blocking_park(SPLICE_CHUNK, splice_timeout) {
                    Some(data) if !data.is_empty() => {
                        if fwd.write_all(&data).is_err() {
                            break;
                        }
                    }
                    // timeout or rx drained: keep waiting unless EOF
                    Some(_) => {
                        if rx_pipe.is_closed() && rx_pipe.is_empty() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            let _ = fwd.shutdown(std::net::Shutdown::Both);
            handle.close();
            let _ = up_thread.join();
        })
        .expect("spawn relay forward thread");
}
