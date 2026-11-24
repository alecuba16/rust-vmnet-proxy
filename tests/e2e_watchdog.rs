//! End-to-end watchdog validation: a fake socket_vmnet daemon over a real
//! unix socket, the real netloop thread, and the real smoltcp stack. The
//! daemon completes the DHCP handshake, then keeps broadcasting while
//! unicast delivery dies (the lima-vm/socket_vmnet#130 wedge shape). A TCP
//! connect is pending, so the unicast arm of the watchdog arms, probes the
//! gateway, gets no answer, and the netloop must exit for that reason.

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
    ArpOperation, ArpPacket, ArpRepr, DhcpMessageType, DhcpPacket, DhcpRepr, EthernetAddress,
    EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet,
    Ipv4Repr, UdpPacket, UdpRepr,
};

use rust_vmnet_proxy::config::{PowerMode, Relay, Tuning};
use rust_vmnet_proxy::netloop::state::WatchdogThresholds;
use rust_vmnet_proxy::RUNNING;

const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x0e, 0x2e];
const SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x0e, 0x01];
const SERVER_IP: Ipv4Address = Ipv4Address::new(192, 0, 2, 1);
const CLIENT_IP: Ipv4Address = Ipv4Address::new(192, 0, 2, 100);
const NETMASK: Ipv4Address = Ipv4Address::new(255, 255, 255, 0);
/// Target of the never-completing connect; its ARP request is the wedge trigger.
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

/// Broadcast ARP request from a phantom LAN host: keeps total rx alive while
/// unicast is dead, exactly like real bridged-LAN chatter. That is what
/// forces the unicast arm, not the total-silence arm, to fire.
fn lan_chatter(seq: u8) -> Vec<u8> {
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x0e, seq]),
        source_protocol_addr: Ipv4Address::new(192, 0, 2, seq),
        target_hardware_addr: EthernetAddress([0xff; 6]),
        target_protocol_addr: Ipv4Address::new(192, 0, 2, 200),
    };
    let mut frame = vec![0u8; 14 + arp.buffer_len()];
    EthernetRepr {
        src_addr: EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x0e, seq]),
        dst_addr: EthernetAddress([0xff; 6]),
        ethertype: EthernetProtocol::Arp,
    }
    .emit(&mut EthernetFrame::new_unchecked(&mut frame[..]));
    arp.emit(&mut ArpPacket::new_unchecked(&mut frame[14..]));
    frame
}

/// socket_vmnet wire framing: 4-byte big-endian length, then the frame.
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

/// Is this an ARP request for the connect target? That is the moment the
/// demand provably exists on the proxy side, so the wedge starts there.
fn is_arp_for(frame: &[u8], target: Ipv4Address) -> bool {
    let Ok(eth) = EthernetFrame::new_checked(frame) else {
        return false;
    };
    if eth.ethertype() != EthernetProtocol::Arp {
        return false;
    }
    let Ok(arp) = ArpPacket::new_checked(eth.payload()) else {
        return false;
    };
    let Ok(repr) = ArpRepr::parse(&arp) else {
        return false;
    };
    match repr {
        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            target_protocol_addr,
            ..
        } => target_protocol_addr == target,
        _ => false,
    }
}

/// Single writer on the socket. Answers DHCP until the client resolves
/// neighbors for the connect target, then wedges: broadcasts keep flowing
/// from a phantom host, unicast never comes back. Reads until EOF (the
/// netloop exited) or the stop flag.
fn fake_daemon(
    mut stream: UnixStream,
    wedged: Arc<AtomicBool>,
    acked_tx: mpsc::Sender<()>,
    stop: Arc<AtomicBool>,
) {
    let mut seq: u8 = 1;
    let mut acked = false;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let Some(frame) = recv_framed(&mut stream) else {
            return; // EOF: the proxy side went away
        };
        if is_arp_for(&frame, UNREACHABLE_IP) {
            // Demand confirmed; from here on the router stops forwarding our
            // unicast while the LAN keeps broadcasting (#130 shape).
            wedged.store(true, Ordering::SeqCst);
            continue;
        }
        let Some((msg, xid)) = parse_client_dhcp(&frame) else {
            continue; // gateway-probe ARP, TCP retransmits: a wedge answers none
        };
        match msg {
            DhcpMessageType::Discover => {
                send_framed(&mut stream, &dhcp_reply(DhcpMessageType::Offer, xid));
            }
            DhcpMessageType::Request if !wedged.load(Ordering::SeqCst) => {
                send_framed(&mut stream, &dhcp_reply(DhcpMessageType::Ack, xid));
                if !acked {
                    acked = true;
                    let _ = acked_tx.send(());
                }
            }
            _ => {}
        }
        if wedged.load(Ordering::SeqCst) {
            send_framed(&mut stream, &lan_chatter(seq));
            seq = seq.wrapping_add(1);
        }
    }
}

/// Wait for the netloop thread to finish, bounded.
fn join_bounded(join: thread::JoinHandle<()>, secs: u64) -> bool {
    let done = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&done);
    thread::spawn(move || {
        let _ = join.join();
        flag.store(true, Ordering::SeqCst);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if done.load(Ordering::SeqCst) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Captures log output so the test can assert *why* the netloop exited.
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
fn unicast_wedge_with_pending_connect_exits_netloop() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    log::set_boxed_logger(Box::new(Capture(Arc::clone(&logs))))
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .unwrap();

    let dir = std::env::temp_dir().join(format!("rvp-e2e-{}", std::process::id()));
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

    let wedged = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (acked_tx, acked_rx) = mpsc::channel();
    let daemon = {
        let w = Arc::clone(&wedged);
        let s = Arc::clone(&stop);
        let kill = daemon_stream.try_clone().unwrap();
        thread::spawn(move || {
            fake_daemon(daemon_stream, w, acked_tx, s);
            kill
        })
    };

    // DHCP must complete before the connect: offline, start_connect replies
    // HostUnreachable and no demand would exist.
    acked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("fake daemon never saw the DHCP REQUEST");
    thread::sleep(Duration::from_millis(300));

    let (resp_tx, _resp_rx) = mpsc::channel();
    let (_handle, _rx_pipe, _tx_pipe) = netloop.api.connect(
        std::net::SocketAddr::from((std::net::IpAddr::V4(UNREACHABLE_IP), 80)),
        resp_tx,
    );

    // unicast_silence + probe_window + margin for DHCP retries and scheduling
    let exited = join_bounded(netloop.join, 20);

    stop.store(true, Ordering::SeqCst);
    let kill = daemon.join().unwrap();
    let _ = kill.shutdown(Shutdown::Both);

    assert!(
        exited,
        "netloop still running after 20s: watchdog never fired"
    );
    let logs = logs.lock().unwrap();
    assert!(
        logs.iter().any(|l| l.contains("ONLINE ip=")),
        "DHCP lease never completed, log lines: {logs:?}"
    );
    assert!(
        logs.iter().any(|l| l.contains("unicast rx wedged")),
        "netloop exited but not via the unicast watchdog, log lines: {logs:?}"
    );
}
