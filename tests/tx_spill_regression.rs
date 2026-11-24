//! Regression for the netloop Write deadlock: a full tx pipe used to park
//! the netloop inside Pipe::push (condvar backpressure waiting on a drain
//! only the netloop itself performs), freezing the whole engine including
//! the rx watchdog. The loop must instead stay live (liveness keeps
//! publishing its poll expectation) and tear the wedged conn down.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::Duration as SmolDuration;
use smoltcp::wire::{
    DhcpMessageType, DhcpPacket, DhcpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};

use rust_vmnet_proxy::config::{PowerMode, Relay, Tuning};
use rust_vmnet_proxy::netloop::state::WatchdogThresholds;
use rust_vmnet_proxy::pipe::PIPE_CAP;
use rust_vmnet_proxy::RUNNING;

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x0e, 0x3a];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x0e, 0x01];
const SERVER_IP: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
const CLIENT_IP: Ipv4Address = Ipv4Address::new(192, 0, 2, 100);
const NETMASK: Ipv4Address = Ipv4Address::new(255, 255, 255, 0);
/// Never answers: the connect stays unestablished, tx never drains.
const UNREACHABLE_IP: Ipv4Address = Ipv4Address::new(192, 0, 2, 10);

fn dhcp_reply(msg_type: DhcpMessageType, xid: u32) -> Vec<u8> {
    let repr = DhcpRepr {
        message_type: msg_type,
        transaction_id: xid,
        secs: 0,
        client_hardware_address: EthernetAddress(CLIENT_MAC),
        client_ip: Ipv4Address::UNSPECIFIED,
        your_ip: CLIENT_IP,
        server_ip: SERVER_IP,
        router: Some(SERVER_IP),
        subnet_mask: Some(NETMASK),
        relay_agent_ip: Ipv4Address::UNSPECIFIED,
        broadcast: false,
        requested_ip: None,
        client_identifier: Some(EthernetAddress(CLIENT_MAC)),
        server_identifier: Some(SERVER_IP),
        parameter_request_list: None,
        dns_servers: None,
        max_size: None,
        lease_duration: Some(3600),
        renew_duration: None,
        rebind_duration: None,
        additional_options: &[],
    };
    let payload_len = 8 + repr.buffer_len();
    let mut frame = vec![0u8; 14 + 20 + payload_len];
    EthernetRepr {
        src_addr: EthernetAddress(SERVER_MAC),
        dst_addr: EthernetAddress(CLIENT_MAC),
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut EthernetFrame::new_unchecked(&mut frame[..]));
    Ipv4Repr {
        src_addr: SERVER_IP,
        dst_addr: Ipv4Address::BROADCAST,
        next_header: IpProtocol::Udp,
        payload_len,
        hop_limit: 64,
    }
    .emit(
        &mut Ipv4Packet::new_unchecked(&mut frame[14..]),
        &ChecksumCapabilities::default(),
    );
    UdpRepr {
        src_port: 67,
        dst_port: 68,
    }
    .emit(
        &mut UdpPacket::new_unchecked(&mut frame[34..]),
        &IpAddress::Ipv4(SERVER_IP),
        &IpAddress::Ipv4(Ipv4Address::BROADCAST),
        repr.buffer_len(),
        |payload| repr.emit(&mut DhcpPacket::new_unchecked(payload)).unwrap(),
        &ChecksumCapabilities::default(),
    );
    frame
}

fn parse_client_dhcp(frame: &[u8]) -> Option<(DhcpMessageType, u32)> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    if udp.src_port() != 68 || udp.dst_port() != 67 {
        return None;
    }
    let pkt = DhcpPacket::new_checked(udp.payload()).ok()?;
    let repr = DhcpRepr::parse(&pkt).ok()?;
    Some((repr.message_type, repr.transaction_id))
}

fn send_framed(stream: &mut UnixStream, frame: &[u8]) {
    let mut msg = Vec::with_capacity(4 + frame.len());
    msg.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    msg.extend_from_slice(frame);
    stream.write_all(&msg).unwrap();
}

fn recv_framed(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 65535 {
        return None;
    }
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame).ok()?;
    Some(frame)
}

/// Minimal daemon: answers DHCP, answers nothing else. Unicast silence while
/// a conn establishes is the tx-full shape under test.
fn fake_daemon(mut stream: UnixStream, acked_tx: mpsc::Sender<()>, stop: Arc<AtomicBool>) {
    let mut acked = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Some(frame) = recv_framed(&mut stream) else {
            return;
        };
        let Some((msg, xid)) = parse_client_dhcp(&frame) else {
            continue;
        };
        match msg {
            DhcpMessageType::Discover => {
                send_framed(&mut stream, &dhcp_reply(DhcpMessageType::Offer, xid));
            }
            DhcpMessageType::Request => {
                send_framed(&mut stream, &dhcp_reply(DhcpMessageType::Ack, xid));
                if !acked {
                    acked = true;
                    let _ = acked_tx.send(());
                }
            }
            _ => {}
        }
    }
}

struct Capture(Arc<Mutex<Vec<String>>>);

impl log::Log for Capture {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        self.0.lock().unwrap().push(record.args().to_string());
    }
    fn flush(&self) {}
}

#[test]
fn full_tx_pipe_write_does_not_park_netloop() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    log::set_boxed_logger(Box::new(Capture(Arc::clone(&logs))))
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .unwrap();

    let dir = std::env::temp_dir().join(format!("rvp-spill-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock_path = dir.join("vmnet.sock");
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path).unwrap();

    RUNNING.store(true, Ordering::SeqCst);

    let netloop = rust_vmnet_proxy::netloop::spawn_for_test(
        sock_path.to_str().unwrap(),
        CLIENT_MAC,
        Tuning::from_power_mode(PowerMode::Battery),
        Vec::<Relay>::new(),
        WatchdogThresholds {
            silence: SmolDuration::from_secs(45),
            unicast_silence: SmolDuration::from_secs(2),
            probe_window: SmolDuration::from_secs(2),
            heartbeat: SmolDuration::from_secs(60),
        },
    )
    .unwrap();

    let (daemon_stream, _) = listener.accept().unwrap();
    let _ = std::fs::remove_file(&sock_path);

    let (acked_tx, acked_rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let daemon = {
        let s = Arc::clone(&stop);
        let kill = daemon_stream.try_clone().unwrap();
        thread::spawn(move || {
            fake_daemon(daemon_stream, acked_tx, s);
            kill
        })
    };

    acked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fake daemon never saw the DHCP REQUEST");
    thread::sleep(Duration::from_millis(300));

    let (resp_tx, _resp_rx) = mpsc::channel();
    let (handle, _rx_pipe, tx_pipe) = netloop.api.connect(
        std::net::SocketAddr::from((std::net::IpAddr::V4(UNREACHABLE_IP), 80)),
        resp_tx,
    );

    // Simulate the client pumping into a wedged remote: fill tx to the cap
    // straight through the pipe (what the splice thread does), then keep
    // queueing Write commands the netloop must never park on. Two writes
    // past the spill cap must trigger the teardown path, and the empty
    // nudges reproduce the production wake pattern.
    assert!(tx_pipe.push(&vec![0u8; PIPE_CAP]));
    handle.write(vec![0u8; 48 * 1024]);
    handle.write(vec![0u8; 48 * 1024]);
    handle.write(Vec::new());
    handle.write(Vec::new());

    // The regression: the old code parked the netloop in Pipe::push on the
    // first Write against a full pipe; the liveness channel then went stale.
    // Give the loop generous time to process the commands, then it must
    // still be publishing (a pass happens at least every poll fallback).
    thread::sleep(Duration::from_secs(2));
    let live = !netloop.liveness.is_dead(Duration::from_secs(10));
    assert!(live, "netloop liveness went stale: Write parked the loop");

    // The spill cap must have torn the conn down: pipes closed, and the
    // teardown logged the reason.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut closed = false;
    while std::time::Instant::now() < deadline {
        closed = tx_pipe.is_closed();
        if closed {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let saw_teardown = {
        let logs = logs.lock().unwrap();
        logs.iter()
            .any(|l| l.contains("tx spill over cap") || l.contains("tx undrained"))
    };
    assert!(
        closed || saw_teardown,
        "conn survived a wedged tx path: pipe closed={closed}, teardown logged={saw_teardown}"
    );

    // Clean shutdown for other tests sharing the RUNNING flag. The wake
    // nudge is required: with no timer expiring, battery mode's poll can
    // legally sleep up to the DHCP T1 (1800s) and would hold the daemon's
    // blocking read open for that whole window.
    RUNNING.store(false, Ordering::SeqCst);
    handle.write(Vec::new());
    let exited = {
        let join = netloop.join;
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        thread::spawn(move || {
            let _ = join.join();
            flag.store(true, Ordering::SeqCst);
        });
        let t0 = std::time::Instant::now();
        loop {
            if done.load(Ordering::SeqCst) {
                break true;
            }
            if std::time::Instant::now() - t0 > Duration::from_secs(5) {
                break false;
            }
            thread::sleep(Duration::from_millis(50));
        }
    };
    assert!(exited, "netloop did not shut down cleanly");

    // The netloop exit closed the daemon socket: its blocking read sees EOF.
    stop.store(true, Ordering::SeqCst);
    let kill = daemon.join().unwrap();
    let _ = kill.shutdown(Shutdown::Both);
}
