use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use crate::pipe::Pipe;

pub enum NetCmd {
    Connect {
        id: u64,
        remote: SocketAddr,
        resp: Sender<ConnectResult>,
        pipes: ConnPipes,
    },
    Write {
        id: u64,
        data: Vec<u8>,
    },
    Close {
        id: u64,
    },
    Resolve {
        name: String,
        resp: Sender<Option<Vec<IpAddr>>>,
    },
}

/// Pipe pair created by the client thread and adopted by the netloop when it
/// registers the connection. rx = remote->client, tx = client->remote.
pub struct ConnPipes {
    pub rx: Arc<Pipe>,
    pub tx: Arc<Pipe>,
}

pub enum ConnectResult {
    Ok,
    Refused,
    HostUnreachable,
    Timeout,
}

impl ConnectResult {
    pub fn socks_reply(&self) -> u8 {
        match self {
            ConnectResult::Ok => 0x00,
            ConnectResult::Refused => 0x05,
            ConnectResult::HostUnreachable => 0x04,
            ConnectResult::Timeout => 0x06,
        }
    }
}

/// Handle given to a SOCKS client thread for one proxied TCP connection.
/// Every command nudges the netloop wake pipe, or the netloop could sleep
/// in poll() with this command queued.
pub struct ConnHandle {
    pub id: u64,
    tx: Sender<NetCmd>,
    wake_w: i32,
}

impl Clone for ConnHandle {
    fn clone(&self) -> Self {
        ConnHandle {
            id: self.id,
            tx: self.tx.clone(),
            wake_w: self.wake_w,
        }
    }
}

impl ConnHandle {
    pub fn new(id: u64, tx: Sender<NetCmd>, wake_w: i32) -> Self {
        ConnHandle { id, tx, wake_w }
    }

    fn send(&self, cmd: NetCmd) {
        if self.tx.send(cmd).is_ok() {
            let byte = [1u8];
            unsafe {
                let _ = libc::write(self.wake_w, byte.as_ptr() as *const libc::c_void, 1);
            }
        }
    }

    pub fn write(&self, data: Vec<u8>) {
        self.send(NetCmd::Write { id: self.id, data });
    }

    pub fn close(&self) {
        self.send(NetCmd::Close { id: self.id });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{channel, Receiver};

    fn handle() -> (ConnHandle, Receiver<NetCmd>, i32) {
        let (tx, rx) = channel();
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        (ConnHandle::new(1, tx, fds[1]), rx, fds[1])
    }

    #[test]
    fn send_on_disconnected_channel_skips_wake_write() {
        // tx side dropped: send fails, the wake pipe write must be
        // skipped (no stray byte, no panic)
        let (tx, rx) = channel();
        drop(rx);
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let h = ConnHandle::new(1, tx, fds[1]);
        h.write(vec![1]);
        h.close();
        drop(h);
        unsafe { libc::close(fds[1]) };
        let mut byte = [0u8; 1];
        let n = unsafe { libc::read(fds[0], byte.as_mut_ptr() as *mut libc::c_void, 1) };
        assert_eq!(n, 0);
    }

    #[test]
    fn socks_reply_mapping() {
        assert_eq!(ConnectResult::Ok.socks_reply(), 0x00);
        assert_eq!(ConnectResult::Refused.socks_reply(), 0x05);
        assert_eq!(ConnectResult::HostUnreachable.socks_reply(), 0x04);
        assert_eq!(ConnectResult::Timeout.socks_reply(), 0x06);
    }

    #[test]
    fn write_and_close_send_commands_and_wake() {
        let (h, rx, wake_w) = handle();
        h.write(vec![1, 2, 3]);
        assert!(matches!(
            rx.try_recv(),
            Ok(NetCmd::Write { id: 1, ref data }) if data == &[1, 2, 3]
        ));
        h.close();
        assert!(matches!(rx.try_recv(), Ok(NetCmd::Close { id: 1 })));
        // The wake write lands after tx.send returns, so poll the pipe
        // briefly instead of asserting a byte is already there
        let mut byte = [0u8; 1];
        let mut got = false;
        for _ in 0..200 {
            let n = unsafe { libc::read(wake_w - 1, byte.as_mut_ptr() as *mut libc::c_void, 1) };
            if n > 0 {
                got = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(got, "wake byte never landed in the pipe");
        unsafe {
            libc::close(wake_w);
            libc::close(wake_w - 1);
        }
    }

    #[test]
    fn clone_sends_on_same_channel() {
        let (h, rx, _wake) = handle();
        let h2 = h.clone();
        assert_eq!(h2.id, h.id);
        h2.write(Vec::new());
        assert!(matches!(rx.try_recv(), Ok(NetCmd::Write { .. })));
    }
}
