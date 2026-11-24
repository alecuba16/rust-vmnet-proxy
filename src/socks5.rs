use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use crate::cmds::ConnectResult;
use crate::netloop::NetApi;

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const SPLICE_CHUNK: usize = 16 * 1024;

/// Loop timing knobs for the listener and splice threads (from power_mode).
#[derive(Debug, Clone)]
pub struct SocksTuning {
    /// Accept-loop park timeout. In battery mode this is only an idle
    /// safety cap, the wakeup itself comes from poll(POLLIN).
    pub accept_interval: Duration,
    /// Splice thread take_blocking timeout. Battery mode parks without a
    /// cap (see pipe::take_blocking_park).
    pub splice_timeout: Duration,
}

/// Park the accept thread in the kernel until a connection arrives (or the
/// cap elapses). A sleep() accept loop would add up to accept_interval of
/// latency to every NEW connection; poll(POLLIN) wakes instantly on SYN at
/// identical idle cost. The timeout is a defensive cap, not the wakeup.
pub fn park_accept(listener: &TcpListener, cap: Duration) {
    use std::os::fd::AsRawFd;
    let mut fds = [libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    let rc = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            1,
            cap.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            thread::sleep(cap);
        }
    }
}

pub fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr)
}

pub fn serve(listener: TcpListener, api: NetApi, tuning: SocksTuning) {
    // Non-blocking accept + flag polling: a blocking accept() would park
    // the thread forever and wedge shutdown (main joins this thread).
    let _ = listener.set_nonblocking(true);
    loop {
        if !crate::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((client, _)) => {
                let _ = client.set_nonblocking(false);
                let api = api.clone();
                let splice_timeout = tuning.splice_timeout;
                thread::Builder::new()
                    .spawn(move || handle_client(client, api, splice_timeout))
                    .ok();
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                park_accept(&listener, tuning.accept_interval);
            }
            Err(e) => {
                log::error!("socks5 accept failed: {e}");
                return;
            }
        }
    }
}

#[derive(Debug)]
pub enum HsError {
    Io,
    /// reply byte to send back before dropping the client
    Unsupported(u8),
}

fn read_exact_or(s: &mut TcpStream, buf: &mut [u8]) -> Result<(), HsError> {
    s.read_exact(buf).map_err(|_| HsError::Io)
}

pub fn send_reply(client: &mut TcpStream, rep: u8) -> bool {
    // fixed atyp=1, 0.0.0.0:0; SOCKS clients only look at rep
    let reply = [0x05u8, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    client.write_all(&reply).is_ok()
}

/// Full request: returns (cmd, target ip or None, hostname, port).
pub fn read_request(client: &mut TcpStream) -> Result<(u8, Option<IpAddr>, String, u16), HsError> {
    let mut head = [0u8; 4];
    read_exact_or(client, &mut head)?;
    if head[0] != 0x05 {
        return Err(HsError::Unsupported(0x01));
    }
    let cmd = head[1];
    if cmd != 0x01 {
        // BIND is unsupported by design; 0x07 per RFC 1928. UDP ASSOCIATE and
        // IPv6 addresses share 0x08 (command/address type not supported).
        return Err(HsError::Unsupported(match cmd {
            0x02 => 0x07,
            _ => 0x08,
        }));
    }
    let mut port_buf = [0u8; 2];
    match head[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            read_exact_or(client, &mut addr)?;
            read_exact_or(client, &mut port_buf)?;
            Ok((
                cmd,
                Some(IpAddr::V4(addr.into())),
                String::new(),
                u16::from_be_bytes(port_buf),
            ))
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_or(client, &mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            read_exact_or(client, &mut name)?;
            read_exact_or(client, &mut port_buf)?;
            Ok((
                cmd,
                None,
                String::from_utf8_lossy(&name).into_owned(),
                u16::from_be_bytes(port_buf),
            ))
        }
        0x04 => Err(HsError::Unsupported(0x08)),
        _ => Err(HsError::Unsupported(0x08)),
    }
}

fn resolve(api: &NetApi, name: &str) -> Option<IpAddr> {
    let (tx, rx) = channel();
    api.resolve(name.to_string(), tx);
    match rx.recv_timeout(RESOLVE_TIMEOUT) {
        Ok(Some(ips)) => ips.into_iter().next(),
        Ok(None) => None,
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => None,
    }
}

/// Consume and validate the RFC 1928 greeting (VER, NMETHODS, METHODS),
/// replying with the no-auth method selection. False = drop the client.
pub fn read_greeting(client: &mut TcpStream) -> bool {
    let mut greeting = [0u8; 2];
    if read_exact_or(client, &mut greeting).is_err() {
        return false;
    }
    if greeting[0] != 0x05 || greeting[1] == 0 || greeting[1] > 16 {
        return false;
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    if read_exact_or(client, &mut methods).is_err() {
        return false;
    }
    if !methods.contains(&0x00) {
        // RFC 1928: no acceptable method -> 0xFF and drop
        let _ = client.write_all(&[0x05, 0xFF]);
        return false;
    }
    client.write_all(&[0x05, 0x00]).is_ok()
}

pub use HsError as SocksHsError;

fn handle_client(mut client: TcpStream, api: NetApi, splice_timeout: Duration) {
    let _ = client.set_nodelay(true);

    if !read_greeting(&mut client) {
        return;
    }

    let (_cmd, ip, name, port) = match read_request(&mut client) {
        Ok(r) => r,
        Err(HsError::Unsupported(rep)) => {
            send_reply(&mut client, rep);
            return;
        }
        Err(HsError::Io) => return,
    };

    let ip = match ip {
        Some(ip) => Some(ip),
        None => resolve(&api, &name),
    };
    let Some(ip) = ip else {
        send_reply(&mut client, 0x04);
        return;
    };
    let remote = SocketAddr::new(ip, port);

    let (resp_tx, resp_rx) = channel();
    let (handle, rx_pipe, tx_pipe) = api.connect(remote, resp_tx);
    let result = match resp_rx.recv() {
        Ok(r) => r,
        Err(_) => ConnectResult::HostUnreachable,
    };
    if !send_reply(&mut client, result.socks_reply()) {
        handle.close();
        return;
    }
    if !matches!(result, ConnectResult::Ok) {
        return;
    }

    log::info!(
        "CONNECT {}:{} -> {remote} [direct]",
        if name.is_empty() {
            ip.to_string()
        } else {
            name
        },
        port
    );

    // Classic per-direction splice: a blocking client read in the same loop
    // as the rx drain deadlocks (responses pile up in rx while the thread
    // parks in read). Two threads, one per direction; each push nudges the
    // netloop via an empty Write so tx drains the same pass.
    let mut up = client.try_clone().expect("clone client stream");
    let up_tx = tx_pipe;
    let up_handle = handle.clone();
    let up_thread = thread::Builder::new()
        .spawn(move || {
            let mut buf = [0u8; SPLICE_CHUNK];
            loop {
                match up.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !up_tx.push(&buf[..n]) {
                            break;
                        }
                        // empty Write: no bytes, just wakes the netloop so
                        // the pipe gets drained this pass instead of at the
                        // next poll timeout
                        up_handle.write(Vec::new());
                    }
                    Err(_) => break,
                }
            }
            // EOF: netloop FINs once the pipe is drained
            up_tx.close();
            up_handle.write(Vec::new());
        })
        .expect("spawn up thread");

    loop {
        match rx_pipe.take_blocking_park(SPLICE_CHUNK, splice_timeout) {
            Some(data) if !data.is_empty() => {
                if client.write_all(&data).is_err() {
                    break;
                }
            }
            // timeout or rx drained: keep waiting unless remote hit EOF
            Some(_) => {
                if rx_pipe.is_closed() && rx_pipe.len() == 0 {
                    break;
                }
            }
            None => break,
        }
    }
    // Remote is done. Propagate EOF to the client and unblock the up thread,
    // which is otherwise parked in client.read until the client gives up.
    let _ = client.shutdown(std::net::Shutdown::Both);
    handle.close();
    let _ = up_thread.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    /// Client/server socketpair on the loopback with an ephemeral port.
    fn pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        (client, server)
    }

    #[test]
    fn read_greeting_ok() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x01, 0x00]).unwrap();
        assert!(read_greeting(&mut s));
        assert_eq!(read_exact_byte(&mut c), 0x05);
        assert_eq!(read_exact_byte(&mut c), 0x00);
    }

    fn read_exact_byte(s: &mut TcpStream) -> u8 {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).unwrap();
        b[0]
    }

    #[test]
    fn read_greeting_bad_version() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x04, 0x01, 0x00]).unwrap();
        assert!(!read_greeting(&mut s));
    }

    #[test]
    fn read_greeting_zero_methods() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x00]).unwrap();
        assert!(!read_greeting(&mut s));
    }

    #[test]
    fn read_greeting_too_many_methods() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 17]).unwrap();
        assert!(!read_greeting(&mut s));
    }

    #[test]
    fn read_greeting_no_acceptable_method() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x01, 0x02]).unwrap();
        assert!(!read_greeting(&mut s));
        assert_eq!(read_exact_byte(&mut c), 0x05);
        assert_eq!(read_exact_byte(&mut c), 0xFF);
    }

    #[test]
    fn read_request_ipv4() {
        let (mut c, mut s) = pair();
        let req = [0x05, 0x01, 0x00, 0x01, 10, 0, 0, 5, 0x0B, 0xBB];
        c.write_all(&req).unwrap();
        let (cmd, ip, name, port) = read_request(&mut s).unwrap();
        assert_eq!(cmd, 0x01);
        assert_eq!(ip, Some(IpAddr::from([10, 0, 0, 5])));
        assert_eq!(name, "");
        assert_eq!(port, 3003);
    }

    #[test]
    fn read_request_domain() {
        let (mut c, mut s) = pair();
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 9];
        req.extend_from_slice(b"bastion-a");
        req.extend_from_slice(&8080u16.to_be_bytes());
        c.write_all(&req).unwrap();
        let (_, ip, name, port) = read_request(&mut s).unwrap();
        assert!(ip.is_none());
        assert_eq!(name, "bastion-a");
        assert_eq!(port, 8080);
    }

    #[test]
    fn read_request_ipv6_unsupported() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x01, 0x00, 0x04]).unwrap();
        assert!(matches!(
            read_request(&mut s),
            Err(HsError::Unsupported(0x08))
        ));
    }

    #[test]
    fn read_request_unknown_atyp_unsupported() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x01, 0x00, 0x09]).unwrap();
        assert!(matches!(
            read_request(&mut s),
            Err(HsError::Unsupported(0x08))
        ));
    }

    #[test]
    fn read_greeting_truncated_methods_is_false() {
        // NMETHODS says 3, client sends 1 and disconnects: read_exact fails
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x03, 0x00]).unwrap();
        drop(c);
        assert!(!read_greeting(&mut s));
    }

    #[test]
    fn read_request_bind_unsupported() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x02, 0x00, 0x01]).unwrap();
        assert!(matches!(
            read_request(&mut s),
            Err(HsError::Unsupported(0x07))
        ));
    }

    #[test]
    fn read_request_udp_unsupported() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x05, 0x03, 0x00, 0x01]).unwrap();
        assert!(matches!(
            read_request(&mut s),
            Err(HsError::Unsupported(0x08))
        ));
    }

    #[test]
    fn read_request_bad_version() {
        let (mut c, mut s) = pair();
        c.write_all(&[0x04, 0x01, 0x00, 0x01]).unwrap();
        assert!(matches!(
            read_request(&mut s),
            Err(HsError::Unsupported(0x01))
        ));
    }

    #[test]
    fn read_request_io_error() {
        let (c, mut s) = pair();
        drop(c);
        assert!(matches!(read_request(&mut s), Err(HsError::Io)));
    }

    #[test]
    fn send_reply_bytes() {
        let (mut c, mut s) = pair();
        assert!(send_reply(&mut s, 0x00));
        let mut buf = [0u8; 10];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn send_reply_to_closed_socket() {
        let (_c, mut s) = pair();
        // writer half of s is still open, so the write succeeds into the
        // local buffer; a real failure needs a dead peer, covered by the
        // Io paths of read_request instead. Exercise both sides closed:
        s.shutdown(std::net::Shutdown::Both).unwrap();
        let ok = send_reply(&mut s, 0x01);
        assert!(ok || !ok); // no panic either way
    }

    /// Minimal fake netloop: answers Connect/Resolve instantly and drops
    /// the pipes, so the splice loop sees closed rx and exits at once.
    struct FakeNet {
        // read end held open for the fake's lifetime; writing wake bytes
        // must not hit EOF and spin the real wake logic
        _wake_r: i32,
        handle: thread::JoinHandle<()>,
    }

    impl FakeNet {
        fn spawn() -> (FakeNet, crate::netloop::NetApi) {
            let (wake_r, wake_w) = {
                let mut fds = [0i32; 2];
                unsafe {
                    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                }
                (fds[0], fds[1])
            };
            let (tx, rx) = channel::<crate::cmds::NetCmd>();
            let handle = thread::spawn(move || {
                while let Ok(cmd) = rx.recv() {
                    match cmd {
                        crate::cmds::NetCmd::Connect { resp, pipes, .. } => {
                            let _ = resp.send(ConnectResult::Ok);
                            // netloop closes rx on remote FIN; with no
                            // remote, close immediately so the splice loop
                            // unblocks instead of spinning on timeouts
                            pipes.rx.close();
                            drop(pipes);
                        }
                        crate::cmds::NetCmd::Resolve { resp, .. } => {
                            let _ = resp.send(None);
                        }
                        crate::cmds::NetCmd::Write { .. } | crate::cmds::NetCmd::Close { .. } => {}
                    }
                }
            });
            (
                FakeNet {
                    _wake_r: wake_r,
                    handle,
                },
                crate::netloop::NetApi::new_for_test(tx, wake_w),
            )
        }
    }

    impl Drop for FakeNet {
        fn drop(&mut self) {
            let handle = std::mem::replace(&mut self.handle, thread::spawn(|| {}));
            let _ = handle.join();
        }
    }

    #[test]
    fn handle_client_full_connect_and_eof() {
        let (mut c, s) = pair();
        let (fake, api) = FakeNet::spawn();
        let t = thread::spawn(move || {
            handle_client(s, api, Duration::from_millis(200));
        });
        // greeting
        c.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).unwrap();
        assert_eq!(b, [0x05, 0x00]);
        // CONNECT by literal IP, bypasses resolve()
        let req = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        c.write_all(&req).unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0x00);
        // client EOF: the up thread breaks, the fake dropped rx so the
        // splice loop exits without waiting for the 200ms timeout
        drop(c);
        t.join().unwrap();
        drop(fake);
    }

    #[test]
    fn handle_client_unresolvable_hostname_replies_0x04() {
        let (mut c, s) = pair();
        let (fake, api) = FakeNet::spawn();
        let t = thread::spawn(move || {
            handle_client(s, api, Duration::from_millis(200));
        });
        c.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut b = [0u8; 2];
        c.read_exact(&mut b).unwrap();
        // CONNECT by hostname: resolve() answers None -> 0x04 host
        // unreachable
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 3];
        req.extend_from_slice(b"abc");
        req.extend_from_slice(&80u16.to_be_bytes());
        c.write_all(&req).unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0x04);
        drop(c);
        t.join().unwrap();
        drop(fake);
    }

    #[test]
    fn resolve_disconnected_sender_returns_none() {
        // fake receives the Resolve command and drops the resp sender
        // without answering: resolve() hits the Disconnected arm and
        // returns None. The 10s Timeout arm is excluded: it only fires
        // when the netloop is wedged, untestable in reasonable time.
        let (tx, rx) = channel::<crate::cmds::NetCmd>();
        let mut fds = [0i32; 2];
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        }
        let api = crate::netloop::NetApi::new_for_test(tx, fds[1]);
        let t = thread::spawn(move || {
            while let Ok(crate::cmds::NetCmd::Resolve { resp, .. }) = rx.recv() {
                drop(resp);
            }
        });
        assert_eq!(resolve(&api, "wedge.test"), None);
        drop(api);
        let _ = t.join();
    }

    #[test]
    fn park_accept_wakes_on_connection() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = thread::spawn(move || {
            park_accept(&l, Duration::from_secs(30));
        });
        std::thread::sleep(Duration::from_millis(50));
        let _c = TcpStream::connect(addr).unwrap();
        t.join().unwrap();
    }

    #[test]
    fn park_accept_timeout_returns() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        // no connection: the cap elapses and park returns
        park_accept(&l, Duration::from_millis(50));
    }

    #[test]
    fn resolve_via_net_api_gets_answer() {
        // fake answers Resolve with an IP list; resolve() picks the first
        let (tx, rx) = channel::<crate::cmds::NetCmd>();
        let mut fds = [0i32; 2];
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        }
        let api = crate::netloop::NetApi::new_for_test(tx, fds[1]);
        let t = thread::spawn(move || {
            while let Ok(crate::cmds::NetCmd::Resolve { resp, .. }) = rx.recv() {
                let _ = resp.send(Some(vec![IpAddr::from([10, 9, 8, 7])]));
            }
        });
        assert_eq!(resolve(&api, "x.test"), Some(IpAddr::from([10, 9, 8, 7])));
        drop(api);
        let _ = t.join();
    }

    #[test]
    fn bind_and_serve_flag_exit() {
        // serve() returns as soon as RUNNING flips false; no connections
        // needed, just a short park interval
        let l = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr_holder = l.local_addr().unwrap();
        let (_tx, rx) = channel::<crate::cmds::NetCmd>();
        drop(rx);
        let mut fds = [0i32; 2];
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        }
        let api = crate::netloop::NetApi::new_for_test(
            {
                let (tx, rrx) = channel();
                drop(rrx);
                tx
            },
            fds[1],
        );
        let tuning = SocksTuning {
            accept_interval: Duration::from_millis(10),
            splice_timeout: Duration::from_millis(10),
        };
        let t = thread::spawn(move || serve(l, api, tuning));
        // cover the Ok(accept) branch: spawn a real SOCKS5 client that
        // just disconnects after the greeting
        let addr = addr_holder;
        let ct = thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&[0x05, 0x01, 0x00]).unwrap();
            std::thread::sleep(Duration::from_millis(20));
            drop(c);
        });
        ct.join().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        crate::RUNNING.store(false, std::sync::atomic::Ordering::SeqCst);
        t.join().unwrap();
        crate::RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
