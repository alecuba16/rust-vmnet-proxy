use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Pipe capacity in bytes. Public for tests that need to fill a pipe.
pub const PIPE_CAP: usize = 256 * 1024;

/// Stall cap for `push_with_deadline`. MAX parks without a deadline (the
/// splice tuning decides); an explicit instant bounds how long a full pipe
/// may park the producer.
#[derive(Clone, Copy)]
pub enum Deadline {
    Max,
    At(Instant),
}

impl Deadline {
    /// Deadline from now plus a Duration, the shape splice callers carry.
    pub fn after(stall: Duration) -> Deadline {
        Deadline::At(Instant::now() + stall)
    }
}

/// Fixed ring of PIPE_CAP bytes with read/write cursors. Contiguous-span
/// copies only: a push or take moves bytes with one or two memcpys, never
/// per-byte deque ops. `front` moves backwards on push_front so a consumer
/// rollback reuses the space take just vacated.
struct Ring {
    buf: Box<[u8]>,
    front: usize,
    len: usize,
}

impl Ring {
    fn new() -> Ring {
        Ring {
            buf: vec![0u8; PIPE_CAP].into_boxed_slice(),
            front: 0,
            len: 0,
        }
    }

    fn room(&self) -> usize {
        PIPE_CAP - self.len
    }

    /// Copy up to `data.len()` bytes in at the tail. Returns bytes written.
    fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.room());
        if n == 0 {
            return 0;
        }
        let tail = (self.front + self.len) % PIPE_CAP;
        let first = (PIPE_CAP - tail).min(n);
        self.buf[tail..tail + first].copy_from_slice(&data[..first]);
        if n > first {
            self.buf[..n - first].copy_from_slice(&data[first..]);
        }
        self.len += n;
        n
    }

    /// Copy up to `data.len()` bytes in at the head, moving `front` back.
    /// Returns bytes written. Only valid when headroom exists, which the
    /// rollback path guarantees: it returns at most what take removed.
    fn write_front(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.room());
        if n == 0 {
            return 0;
        }
        self.front = (self.front + PIPE_CAP - n) % PIPE_CAP;
        let first = (PIPE_CAP - self.front).min(n);
        self.buf[self.front..self.front + first].copy_from_slice(&data[n - first..]);
        if n > first {
            self.buf[PIPE_CAP - (n - first)..].copy_from_slice(&data[..n - first]);
        }
        self.len += n;
        n
    }

    /// Copy out up to `max` bytes from the head into `out` (pre-sized by the
    /// caller). Returns bytes read.
    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        if n == 0 {
            return 0;
        }
        let first = (PIPE_CAP - self.front).min(n);
        out[..first].copy_from_slice(&self.buf[self.front..self.front + first]);
        if n > first {
            out[first..].copy_from_slice(&self.buf[..n - first]);
        }
        self.front = (self.front + n) % PIPE_CAP;
        self.len -= n;
        n
    }
}

struct PipeState {
    ring: Ring,
    closed: bool,
}

/// Bounded byte pipe between a SOCKS client thread and the netloop.
/// One instance per direction. `close` marks writer-side EOF: readers drain
/// remaining bytes, then observe empty + closed.
pub struct Pipe {
    state: Mutex<PipeState>,
    cv: Condvar,
}

impl Default for Pipe {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipe {
    pub fn new() -> Self {
        Pipe {
            state: Mutex::new(PipeState {
                ring: Ring::new(),
                closed: false,
            }),
            cv: Condvar::new(),
        }
    }

    /// Non-blocking producer side for the netloop: take as much as fits,
    /// leave the rest with the caller. Returns the bytes accepted.
    pub fn try_push(&self, data: &[u8]) -> usize {
        let mut st = self.state.lock().unwrap();
        if st.closed {
            return 0;
        }
        let n = st.ring.write(data);
        if n > 0 {
            self.cv.notify_all();
        }
        n
    }

    /// Producer side. Blocks until all of `data` fits or the pipe is closed.
    /// Returns false if closed, meaning nothing was queued. Parks without a
    /// stall cap, matching the splice tuning.
    pub fn push(&self, data: &[u8]) -> bool {
        self.push_with_deadline(data, Deadline::Max)
    }

    pub fn push_with_deadline(&self, data: &[u8], deadline: Deadline) -> bool {
        let mut st = self.state.lock().unwrap();
        let mut offset = 0;
        loop {
            if st.closed {
                return false;
            }
            if st.ring.room() > 0 {
                offset += st.ring.write(&data[offset..]);
                if offset == data.len() {
                    self.cv.notify_all();
                    return true;
                }
            }
            // Full: wait until the consumer drains some bytes or the stall
            // deadline passes. A wedged remote then tears the conn down
            // instead of parking the splice thread forever.
            let (guard, _) = match deadline {
                Deadline::Max => self.cv.wait_timeout(st, Duration::from_millis(50)).unwrap(),
                Deadline::At(d) => {
                    let now = std::time::Instant::now();
                    if now >= d {
                        return false;
                    }
                    self.cv.wait_timeout(st, d - now).unwrap()
                }
            };
            st = guard;
        }
    }

    /// Consumer-side error recovery: put bytes back at the front.
    pub fn push_front(&self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let n = st.ring.write_front(data);
        debug_assert_eq!(n, data.len(), "push_front beyond pipe capacity");
        self.cv.notify_all();
    }

    /// Consumer side: take up to `max` bytes without blocking.
    pub fn take(&self, max: usize) -> Vec<u8> {
        let mut st = self.state.lock().unwrap();
        let n = st.ring.len.min(max);
        let mut out = vec![0u8; n];
        let read = st.ring.read(&mut out);
        debug_assert_eq!(read, n);
        if n > 0 {
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
            if st.ring.len > 0 {
                let n = st.ring.len.min(max);
                let mut out = vec![0u8; n];
                let read = st.ring.read(&mut out);
                debug_assert_eq!(read, n);
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
        self.state.lock().unwrap().ring.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        while !p.is_empty() {
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
        while !p.is_empty() {
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

    #[test]
    fn ring_wraparound_preserves_order() {
        let p = Pipe::new();
        // park the front mid-ring so writes and reads both wrap
        let warm = vec![1u8; PIPE_CAP - 100];
        assert!(p.push(&warm));
        let drained = p.take(PIPE_CAP - 100);
        assert_eq!(drained.len(), PIPE_CAP - 100);
        let a = vec![2u8; 150];
        let b = vec![3u8; 150];
        assert!(p.push(&a));
        assert!(p.push(&b));
        let out = p.take(PIPE_CAP);
        assert_eq!(out.len(), 300);
        assert_eq!(&out[..150], &a[..]);
        assert_eq!(&out[150..], &b[..]);
    }

    #[test]
    fn push_front_after_take_restores_exact_bytes() {
        let p = Pipe::new();
        let payload: Vec<u8> = (0..=255).cycle().take(300).collect();
        assert!(p.push(&payload));
        let taken = p.take(300);
        p.push_front(&taken);
        assert_eq!(p.take(PIPE_CAP), payload);
    }

    #[test]
    fn push_front_wrapped_restores_exact_bytes() {
        let p = Pipe::new();
        // move front near the end so write_front has to split its copy
        let warm = vec![0u8; PIPE_CAP - 8];
        assert!(p.push(&warm));
        p.take(PIPE_CAP - 8);
        let payload = vec![5u8; 32];
        assert!(p.push(&payload));
        let taken = p.take(32);
        p.push_front(&taken);
        assert_eq!(p.take(PIPE_CAP), payload);
    }
}
