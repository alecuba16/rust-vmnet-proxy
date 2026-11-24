use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::Ipv4Address;

const FRAME_MAX: usize = 65535;

/// Ethernet frame pipe to the root socket_vmnet daemon.
///
/// Wire protocol (socket_vmnet main.c): SOCK_STREAM unix socket, each message
/// is a 4-byte big-endian length followed by exactly one Ethernet frame. The
/// daemon floods every vmnet frame to every connected client, so received
/// frames are filtered by destination MAC before smoltcp sees them.
pub struct VmnetDevice {
    stream: UnixStream,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    rx_frames: VecDeque<Vec<u8>>,
    tx_frames: VecDeque<Vec<u8>>,
    /// Partially written message (header + frame, raw bytes). Written out
    /// before any new framed message; never re-prefixed.
    tx_residual: Vec<u8>,
    local_mac: [u8; 6],
    /// Frames handed to smoltcp since boot, after the MAC filter. The rx
    /// watchdog samples it around iface.poll() to see if anything arrived.
    rx_taken: u64,
    /// Unicast frames for our MAC only. Bridged-mode wedges can pass
    /// multicast (ARP, mDNS) while the router stops forwarding our unicast,
    /// so the watchdog needs a unicast-only signal.
    rx_unicast: u64,
    /// Unicast ARP REPLY frames for our MAC only. The gateway answering our
    /// own neighbor discovery is solicited traffic: it proves the unicast
    /// path but says nothing about client demand. The heartbeat pays its
    /// debt from this counter.
    rx_arp_reply: u64,
    /// Unicast frames for our MAC that are not ARP replies: client traffic,
    /// the DHCP exchange, DNS answers, anything a peer sent us on purpose.
    /// Only this counter ends heartbeat phases.
    rx_unicast_data: u64,
    /// ARP REQUEST frames transmitted since boot for the ARP target
    /// (the gateway): questions to other LAN peers are not gateway
    /// evidence. Each gateway question has a matching reply on a healthy
    /// path. The heartbeat samples this around poll and accrues its debt
    /// from the delta.
    tx_arp_req: u64,
    /// The only neighbor whose ARP questions count as heartbeat debt.
    /// Debt exists to make the heartbeat's visibility WARN honest: N
    /// unanswered questions to THE GATEWAY mean the gateway is silent.
    /// Questions to other LAN peers (a dead ilo, say) say nothing about
    /// the gateway and must not ring its alarm. None until the first
    /// lease; the netloop sets it via refresh_gateway on every lease.
    arp_target: Option<Ipv4Address>,
}

pub struct PhysRxToken {
    frame: Vec<u8>,
}

pub struct PhysTxToken<'a> {
    frames: &'a mut VecDeque<Vec<u8>>,
    arp_reqs: &'a mut u64,
    arp_target: Option<Ipv4Address>,
}

impl RxToken for PhysRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

impl TxToken for PhysTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        // ARP REQUEST on the wire (ethertype 0x0806, opcode 1 at frame
        // offsets 20..22, target protocol address at 38..42, full frame
        // 14+28 bytes), asked about the gateway. The heartbeat's debt
        // ledger accrues from this counter: a probe fire whose neighbor
        // entry is still valid sends a blind UDP:9 the gateway discards,
        // asks no question, and must not accrue debt, or a healthy idle
        // LAN WARNs on every other fire while the neighbor TTL and the
        // heartbeat knob coincide.
        if frame.len() >= 42
            && frame[12..14] == [0x08, 0x06]
            && frame[20..22] == [0x00, 0x01]
            && self
                .arp_target
                .is_some_and(|t| frame[38..42] == t.octets()[..])
        {
            *self.arp_reqs += 1;
        }
        self.frames.push_back(frame);
        result
    }
}

impl VmnetDevice {
    pub fn connect(socket_path: &str, local_mac: [u8; 6]) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
        Self::from_stream(stream, local_mac)
    }

    /// Build a device on an already-connected stream. Production goes
    /// through [`Self::connect`]; tests build socketpairs.
    pub fn from_stream(stream: UnixStream, local_mac: [u8; 6]) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            rx_buf: Vec::with_capacity(FRAME_MAX),
            rx_pos: 0,
            rx_frames: VecDeque::new(),
            tx_frames: VecDeque::new(),
            tx_residual: Vec::new(),
            local_mac,
            rx_taken: 0,
            rx_unicast: 0,
            rx_arp_reply: 0,
            rx_unicast_data: 0,
            tx_arp_req: 0,
            arp_target: None,
        })
    }

    pub fn mac(&self) -> [u8; 6] {
        self.local_mac
    }

    pub fn raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Frames handed to smoltcp since boot, after the MAC filter. The rx
    /// watchdog samples this counter around iface.poll().
    pub fn rx_taken(&self) -> u64 {
        self.rx_taken
    }

    /// Unicast frames for our MAC since boot, after the MAC filter.
    pub fn rx_unicast(&self) -> u64 {
        self.rx_unicast
    }

    /// Unicast ARP REPLY frames for our MAC since boot. Solicited answers,
    /// most importantly the gateway's reply to the heartbeat's own ARP.
    pub fn rx_arp_reply(&self) -> u64 {
        self.rx_arp_reply
    }

    /// Unicast frames for our MAC that are not ARP replies, since boot.
    /// Genuine peer-to-us traffic.
    pub fn rx_unicast_data(&self) -> u64 {
        self.rx_unicast_data
    }

    /// ARP REQUEST frames transmitted since boot for the target set by
    /// [`Self::set_arp_target`]. The heartbeat's debt accrues from
    /// per-pass deltas of this counter.
    pub fn tx_arp_req(&self) -> u64 {
        self.tx_arp_req
    }

    /// The neighbor whose ARP questions count as heartbeat debt: the
    /// gateway. Called from refresh_gateway on every lease, including
    /// renewals that keep the same address.
    pub fn set_arp_target(&mut self, target: Ipv4Address) {
        self.arp_target = Some(target);
    }

    /// Pull every complete frame currently readable from the daemon socket.
    /// Returns the number of frames queued. A closed daemon is an error: the
    /// netloop exits and the supervisor decides what to do.
    pub fn fill_rx(&mut self) -> std::io::Result<usize> {
        let mut chunk = [0u8; 8192];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "socket_vmnet closed connection",
                    ))
                }
                Ok(n) => {
                    self.rx_buf.extend_from_slice(&chunk[..n]);
                    while self.rx_buf.len() - self.rx_pos >= 4 {
                        let len = u32::from_be_bytes([
                            self.rx_buf[self.rx_pos],
                            self.rx_buf[self.rx_pos + 1],
                            self.rx_buf[self.rx_pos + 2],
                            self.rx_buf[self.rx_pos + 3],
                        ]) as usize;
                        if len == 0 || len > FRAME_MAX {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "socket_vmnet frame length out of range",
                            ));
                        }
                        if self.rx_buf.len() - self.rx_pos < 4 + len {
                            break;
                        }
                        let frame = self.rx_buf[self.rx_pos + 4..self.rx_pos + 4 + len].to_vec();
                        self.rx_pos += 4 + len;
                        self.rx_frames.push_back(frame);
                    }
                    // compact consumed bytes so extend_from_slice stays O(1)
                    if self.rx_pos > 0 {
                        self.rx_buf.drain(..self.rx_pos);
                        self.rx_pos = 0;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(self.rx_frames.len())
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Push all pending tx frames down the socket, one write per message
    /// (header + frame contiguous: the daemon asserts a full frame per read,
    /// and split writes could interleave under load). Frames go out FIFO.
    /// A short write or EAGAIN parks the unwritten tail in tx_residual as
    /// raw bytes; the next pass writes the residual verbatim before any new
    /// message, so the 4-byte header is never re-prefixed.
    pub fn flush_tx(&mut self) -> std::io::Result<()> {
        if !self.tx_residual.is_empty() {
            match self.stream.write(&self.tx_residual) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "socket_vmnet write returned 0",
                    ))
                }
                Ok(n) if n < self.tx_residual.len() => {
                    self.tx_residual.drain(..n);
                    return Ok(());
                }
                Ok(_) => self.tx_residual.clear(),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        while let Some(frame) = self.tx_frames.pop_front() {
            let mut msg = Vec::with_capacity(4 + frame.len());
            msg.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            msg.extend_from_slice(&frame);
            match self.stream.write(&msg) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "socket_vmnet write returned 0",
                    ))
                }
                Ok(n) if n < msg.len() => {
                    self.tx_residual = msg[n..].to_vec();
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.tx_frames.push_front(frame);
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    #[allow(dead_code)] // exposed for future POLLOUT-based tx wakeup in the netloop
    pub fn tx_pending(&self) -> bool {
        !self.tx_frames.is_empty() || !self.tx_residual.is_empty()
    }
}

impl Device for VmnetDevice {
    type RxToken<'a>
        = PhysRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PhysTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // The daemon floods every frame to every client, so unicast frames
        // for other members of the bridged LAN arrive here too. Skip them
        // instead of handing them to smoltcp, and keep looking until a frame
        // for our MAC (or broadcast/multicast) is found.
        while let Some(frame) = self.rx_frames.pop_front() {
            if frame.len() < 14 {
                continue;
            }
            let dst = &frame[0..6];
            let multicast = dst[0] & 1 == 1;
            if dst != self.local_mac && !multicast {
                continue;
            }
            if dst == self.local_mac {
                self.rx_unicast += 1;
                // ARP and data unicast tell different stories. An ARP REPLY
                // to our MAC proves the bridge still forwards unicast to us,
                // but the gateway replying to our own ARP request is an
                // answer we solicited, not client traffic. The heartbeat
                // must not read it as demand: every fire with an expired
                // neighbor entry re-ARPs, the reply lands as a fresh
                // unicast refresh, and treating it as traffic pins the
                // heartbeat back to unicast_silence cadence (observed live:
                // ~1.9 fires/min, phases dying at their first fire with no
                // WARN). Count replies apart so the heartbeat can pay its
                // debt without ending its phase.
                if frame.len() >= 42
                    && frame[12..14] == [0x08, 0x06]
                    && frame[20..22] == [0x00, 0x02]
                {
                    self.rx_arp_reply += 1;
                } else {
                    self.rx_unicast_data += 1;
                }
            }
            self.rx_taken += 1;
            let rx = PhysRxToken { frame };
            let tx = PhysTxToken {
                frames: &mut self.tx_frames,
                arp_reqs: &mut self.tx_arp_req,
                arp_target: self.arp_target,
            };
            return Some((rx, tx));
        }
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PhysTxToken {
            frames: &mut self.tx_frames,
            arp_reqs: &mut self.tx_arp_req,
            arp_target: self.arp_target,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];

    fn test_dev() -> (VmnetDevice, UnixStream) {
        let (peer, ours) = UnixStream::pair().unwrap();
        let dev = VmnetDevice::from_stream(ours, LOCAL_MAC).unwrap();
        (dev, peer)
    }

    fn eth_frame(ethertype: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(&LOCAL_MAC); // dst: us, unicast
        f.extend_from_slice(&[0xc8, 0x33, 0xe5, 0x8e, 0xcc, 0x8c]); // src: gateway
        f.extend_from_slice(&ethertype);
        f.extend_from_slice(payload);
        f
    }

    fn arp_payload(opcode: u16, tpa: [u8; 4]) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&[0x00, 0x01]); // hardware type: ethernet
        p.extend_from_slice(&[0x08, 0x00]); // protocol type: IPv4
        p.push(6); // hardware addr len
        p.push(4); // protocol addr len
        p.extend_from_slice(&opcode.to_be_bytes());
        p.extend_from_slice(&[0x11; 6]); // sender hardware addr
        p.extend_from_slice(&[192, 168, 1, 1]); // sender protocol addr
        p.extend_from_slice(&[0x00; 6]); // target hardware addr
        p.extend_from_slice(&tpa);
        p
    }

    fn feed(dev: &mut VmnetDevice, peer: &mut UnixStream, frame: &[u8]) {
        peer.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
        peer.write_all(frame).unwrap();
        dev.fill_rx().unwrap();
    }

    fn drain_rx(dev: &mut VmnetDevice) {
        while let Some((_rx, _tx)) = dev.receive(Instant::now()) {}
    }

    #[test]
    fn tx_arp_request_to_target_counts() {
        let (mut dev, _peer) = test_dev();
        dev.set_arp_target(Ipv4Address::new(192, 168, 1, 1));
        let frame = eth_frame([0x08, 0x06], &arp_payload(1, [192, 168, 1, 1]));
        let token = dev.transmit(Instant::now()).expect("tx token");
        token.consume(frame.len(), |buf| buf.copy_from_slice(&frame));
        assert_eq!(dev.tx_arp_req(), 1);
    }

    #[test]
    fn tx_arp_request_to_other_ip_is_not_gateway_evidence() {
        // Questions to other LAN peers (ilo, say) must not accrue gateway
        // debt: a dead ilo answering nothing must never WARN "gateway
        // silent".
        let (mut dev, _peer) = test_dev();
        dev.set_arp_target(Ipv4Address::new(192, 168, 1, 1));
        let frame = eth_frame([0x08, 0x06], &arp_payload(1, [192, 168, 1, 50]));
        let token = dev.transmit(Instant::now()).expect("tx token");
        token.consume(frame.len(), |buf| buf.copy_from_slice(&frame));
        assert_eq!(dev.tx_arp_req(), 0);
    }

    #[test]
    fn tx_arp_request_without_target_set_is_ignored() {
        // No lease yet: no gateway, no question worth counting.
        let (mut dev, _peer) = test_dev();
        let frame = eth_frame([0x08, 0x06], &arp_payload(1, [192, 168, 1, 1]));
        let token = dev.transmit(Instant::now()).expect("tx token");
        token.consume(frame.len(), |buf| buf.copy_from_slice(&frame));
        assert_eq!(dev.tx_arp_req(), 0);
    }

    #[test]
    fn tx_arp_reply_is_not_a_question() {
        let (mut dev, _peer) = test_dev();
        dev.set_arp_target(Ipv4Address::new(192, 168, 1, 1));
        let frame = eth_frame([0x08, 0x06], &arp_payload(2, [192, 168, 1, 1]));
        let token = dev.transmit(Instant::now()).expect("tx token");
        token.consume(frame.len(), |buf| buf.copy_from_slice(&frame));
        assert_eq!(dev.tx_arp_req(), 0);
    }

    #[test]
    fn tx_truncated_arp_like_frame_is_safe() {
        // A frame under 42 bytes never reaches the opcode or target reads;
        // blind writes and malformed daemons must not panic the netloop.
        let (mut dev, _peer) = test_dev();
        dev.set_arp_target(Ipv4Address::new(192, 168, 1, 1));
        let token = dev.transmit(Instant::now()).expect("tx token");
        token.consume(20, |buf| {
            buf[..6].copy_from_slice(&LOCAL_MAC);
            buf[6..12].copy_from_slice(&[0x11; 6]);
            buf[12..14].copy_from_slice(&[0x08, 0x06]);
        });
        assert_eq!(dev.tx_arp_req(), 0);
    }

    #[test]
    fn rx_unicast_arp_reply_classifies_as_reply_not_data() {
        let (mut dev, mut peer) = test_dev();
        let frame = eth_frame([0x08, 0x06], &arp_payload(2, [192, 168, 1, 4]));
        feed(&mut dev, &mut peer, &frame);
        drain_rx(&mut dev);
        assert_eq!(dev.rx_taken(), 1);
        assert_eq!(dev.rx_unicast(), 1);
        assert_eq!(dev.rx_arp_reply(), 1);
        assert_eq!(
            dev.rx_unicast_data(),
            0,
            "the gateway's own reply is not demand"
        );
    }

    #[test]
    fn rx_unicast_data_classifies_as_data() {
        let (mut dev, mut peer) = test_dev();
        // 42-byte IPv4 frame: same length as an ARP reply, different story.
        let frame = eth_frame([0x08, 0x00], &[0x45; 28]);
        feed(&mut dev, &mut peer, &frame);
        drain_rx(&mut dev);
        assert_eq!(dev.rx_unicast_data(), 1);
        assert_eq!(dev.rx_arp_reply(), 0);
    }

    #[test]
    fn rx_truncated_arp_ethertype_frame_is_data_and_safe() {
        // A unicast frame under 42 bytes carrying the ARP ethertype must
        // classify as data, not panic on the opcode read. (The guard order
        // bug this pins: len must come before opcode.)
        let (mut dev, mut peer) = test_dev();
        let frame = eth_frame([0x08, 0x06], &[0x00; 6]); // 20 bytes total
        feed(&mut dev, &mut peer, &frame);
        drain_rx(&mut dev);
        assert_eq!(dev.rx_unicast_data(), 1);
        assert_eq!(dev.rx_arp_reply(), 0);
    }

    #[test]
    fn rx_broadcast_arp_request_is_not_unicast() {
        // Other peers' discovery traffic floods the bridge; it says
        // nothing about OUR unicast path.
        let (mut dev, mut peer) = test_dev();
        let mut frame = eth_frame([0x08, 0x06], &arp_payload(1, [192, 168, 1, 4]));
        frame[..6].copy_from_slice(&[0xff; 6]); // broadcast dst
        feed(&mut dev, &mut peer, &frame);
        drain_rx(&mut dev);
        assert_eq!(dev.rx_unicast(), 0);
        assert_eq!(dev.rx_arp_reply(), 0);
        assert_eq!(dev.rx_unicast_data(), 0);
        assert_eq!(dev.rx_taken(), 1, "smoltcp still sees it");
    }

    #[test]
    fn rx_unicast_for_other_member_is_dropped() {
        // The daemon floods every client's frames: a frame addressed to
        // another VM must never touch our counters or smoltcp.
        let (mut dev, mut peer) = test_dev();
        let mut frame = eth_frame([0x08, 0x00], &[0x45; 28]);
        frame[..6].copy_from_slice(&[0x02, 0x00, 0x00, 0xaa, 0xbb, 0xcc]); // foreign unicast, even first byte
        feed(&mut dev, &mut peer, &frame);
        assert_eq!(dev.fill_rx().unwrap(), 1, "frame queued from the wire");
        assert!(
            dev.receive(Instant::now()).is_none(),
            "filtered before smoltcp"
        );
        assert_eq!(dev.rx_taken(), 0);
        assert_eq!(dev.rx_unicast(), 0);
    }
}
