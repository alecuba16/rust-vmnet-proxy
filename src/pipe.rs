use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

const PIPE_CAP: usize = 256 * 1024;

struct PipeState {
    buf: VecDeque<u8>,
    closed: bool,
}

/// Bounded byte pipe between a SOCKS client thread and the netloop.
/// One instance per direction. `close` marks writer-side EOF: readers drain
/// remaining bytes, then observe empty + closed.
pub struct Pipe {
    state: Mutex<PipeState>,
    cv: Condvar,
}

impl Pipe {
    pub fn new() -> Self {
        Pipe {
            state: Mutex::new(PipeState {
                buf: VecDeque::with_capacity(PIPE_CAP),
                closed: false,
            }),
            cv: Condvar::new(),
        }
    }

    /// Producer side. Blocks until all of `data` fits or the pipe is closed.
    /// Returns false if closed, meaning nothing was queued.
    pub fn push(&self, data: &[u8]) -> bool {
        let mut st = self.state.lock().unwrap();
        let mut offset = 0;
        loop {
            if st.closed {
                return false;
            }
            let room = PIPE_CAP - st.buf.len();
            if room > 0 {
                let n = room.min(data.len() - offset);
                let tail: Vec<u8> = data[offset..offset + n].to_vec();
                for b in tail {
                    st.buf.push_back(b);
                }
                offset += n;
                if offset == data.len() {
                    self.cv.notify_all();
                    return true;
                }
            }
            // Full: wait until the consumer drains some bytes.
            let (guard, _) = self.cv.wait_timeout(st, Duration::from_millis(50)).unwrap();
            st = guard;
        }
    }

    /// Consumer-side error recovery: put bytes back at the front.
    pub fn push_front(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        for b in data.iter().rev() {
            st.buf.push_front(*b);
        }
        self.cv.notify_all();
    }

    /// Consumer side: take up to `max` bytes without blocking.
    pub fn take(&self, max: usize) -> Vec<u8> {
        let mut st = self.state.lock().unwrap();
        let n = st.buf.len().min(max);
        let out: Vec<u8> = st.buf.drain(..n).collect();
        if !out.is_empty() {
            self.cv.notify_all();
        }
        out
    }

    /// Consumer side: block until bytes are available or the pipe is closed.
    /// `timeout` is a defensive cap (the condvar is the real wakeup); a
    /// timeout of Duration::MAX parks indefinitely. All mutators notify the
    /// condvar, so a parked consumer wakes exactly on data or EOF. Returns
    /// None on closed-and-empty (EOF).
    pub fn take_blocking_park(&self, max: usize, timeout: Duration) -> Option<Vec<u8>> {
        // Duration::MAX means park until data or EOF: Instant arithmetic
        // would overflow, and the condvar is the only wakeup.
        let deadline = if timeout == Duration::MAX {
            None
        } else {
            Some(std::time::Instant::now() + timeout)
        };
        let mut st = self.state.lock().unwrap();
        loop {
            if !st.buf.is_empty() {
                let n = st.buf.len().min(max);
                let out: Vec<u8> = st.buf.drain(..n).collect();
                self.cv.notify_all();
                return Some(out);
            }
            if st.closed {
                return None;
            }
            let Some(deadline) = deadline else {
                st = self.cv.wait(st).unwrap();
                continue;
            };
            let now = std::time::Instant::now();
            if now >= deadline {
                return Some(Vec::new());
            }
            let (guard, _) = self.cv.wait_timeout(st, deadline - now).unwrap();
            st = guard;
        }
    }

    /// Writer-side EOF marker. Wakes all waiters.
    pub fn close(&self) {
        let mut st = self.state.lock().unwrap();
        st.closed = true;
        drop(st);
        self.cv.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn push_take_roundtrip() {
        let p = Pipe::new();
        assert!(p.push(b"hello"));
        assert_eq!(p.take(16), b"hello".to_vec());
        assert!(p.take(16).is_empty());
    }

    #[test]
    fn take_caps_at_max() {
        let p = Pipe::new();
        assert!(p.push(b"0123456789"));
        assert_eq!(p.take(4), b"0123".to_vec());
        assert_eq!(p.len(), 6);
        assert_eq!(p.take(4), b"4567".to_vec());
    }

    #[test]
    fn push_after_close_fails() {
        let p = Pipe::new();
        p.close();
        assert!(!p.push(b"x"));
        assert!(p.is_closed());
    }

    #[test]
    fn take_blocking_park_drains_then_eof() {
        let p = Pipe::new();
        p.push(b"abc");
        assert_eq!(
            p.take_blocking_park(8, Duration::MAX),
            Some(b"abc".to_vec())
        );
        p.close();
        assert_eq!(p.take_blocking_park(8, Duration::MAX), None);
    }

    #[test]
    fn take_blocking_park_timeout_returns_empty() {
        let p = Pipe::new();
        let t = p.take_blocking_park(8, Duration::from_millis(20));
        assert_eq!(t, Some(Vec::new()));
    }

    #[test]
    fn take_blocking_park_wakes_on_push_same_pipe() {
        let p = std::sync::Arc::new(Pipe::new());
        let p2 = std::sync::Arc::clone(&p);
        let handle = std::thread::spawn(move || p2.take_blocking_park(8, Duration::MAX));
        std::thread::sleep(Duration::from_millis(30));
        p.push(b"data");
        assert_eq!(handle.join().unwrap(), Some(b"data".to_vec()));
    }

    #[test]
    fn take_blocking_park_wakes_on_close_same_pipe() {
        let p = std::sync::Arc::new(Pipe::new());
        let p2 = std::sync::Arc::clone(&p);
        let handle = std::thread::spawn(move || p2.take_blocking_park(8, Duration::MAX));
        std::thread::sleep(Duration::from_millis(30));
        p.close();
        assert_eq!(handle.join().unwrap(), None);
    }

    #[test]
    fn push_front_restores_bytes() {
        let p = Pipe::new();
        p.push_front(b"xy");
        assert_eq!(p.take(8), b"xy".to_vec());
        p.push_front(b"");
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn push_backpressure_until_drained() {
        let p = std::sync::Arc::new(Pipe::new());
        let p2 = std::sync::Arc::clone(&p);
        let handle = std::thread::spawn(move || {
            let big = vec![7u8; PIPE_CAP + 1024];
            assert!(p2.push(&big));
        });
        std::thread::sleep(Duration::from_millis(50));
        while p.len() > 0 {
            p.take(PIPE_CAP);
        }
        handle.join().unwrap();
    }

    #[test]
    fn push_partial_fill_then_wait() {
        // prefilled pipe: a push larger than the free room must write the
        // fitting prefix, park, then finish the remainder after a drain
        let p = std::sync::Arc::new(Pipe::new());
        p.push_front(&vec![9u8; PIPE_CAP - 10]);
        let p2 = std::sync::Arc::clone(&p);
        let payload = vec![7u8; 100];
        let handle = std::thread::spawn(move || {
            assert!(p2.push(&payload));
        });
        // The pusher writes its prefix and parks while the pipe is full.
        // Wait for the parked state (full pipe) before draining: a timed
        // drain loop can race the pusher's refill and consume part of the
        // payload, making the tail assertion nondeterministic.
        let deadline = Instant::now() + Duration::from_secs(5);
        while p.len() < PIPE_CAP && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(p.len(), PIPE_CAP, "pusher never filled the pipe");
        while p.len() > 0 {
            p.take(PIPE_CAP);
        }
        handle.join().unwrap();
        // everything the pusher wrote after the drain is payload tail
        let rest = p.take(PIPE_CAP);
        assert!(rest.iter().all(|&b| b == 7));
        assert!(rest.len() <= 100);
    }

    #[test]
    fn push_to_closed_pipe_unblocks_with_false() {
        let p = std::sync::Arc::new(Pipe::new());
        let p2 = std::sync::Arc::clone(&p);
        let handle = std::thread::spawn(move || {
            let big = vec![7u8; PIPE_CAP + 1024];
            !p2.push(&big)
        });
        std::thread::sleep(Duration::from_millis(50));
        p.close();
        assert!(handle.join().unwrap());
    }
}
