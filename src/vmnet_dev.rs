use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

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
}

pub struct PhysRxToken {
    frame: Vec<u8>,
}

pub struct PhysTxToken<'a> {
    frames: &'a mut VecDeque<Vec<u8>>,
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
        self.frames.push_back(frame);
        result
    }
}

impl VmnetDevice {
    pub fn connect(socket_path: &str, local_mac: [u8; 6]) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path)?;
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
            }
            self.rx_taken += 1;
            let rx = PhysRxToken { frame };
            let tx = PhysTxToken {
                frames: &mut self.tx_frames,
            };
            return Some((rx, tx));
        }
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PhysTxToken {
            frames: &mut self.tx_frames,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1500;
        caps
    }
}
