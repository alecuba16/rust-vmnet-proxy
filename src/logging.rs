use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::config::Logging;

pub const LOG_FILE: &str = "rust-vmnet-proxy.log";

/// File sink with rotation. Written lines carry the env_logger-style
/// `[timestamp LEVEL target]` prefix; rotation renames to .1, .2, ... and
/// keeps `keep` of them.
struct Sink {
    file: Option<File>,
    path: PathBuf,
    rotate_secs: u64,
    keep: u32,
    max_bytes: u64,
    written: u64,
    /// Rotation age anchor: mtime of the file we opened, so restarts don't
    /// reset the rotation clock of a long-lived log.
    opened_at: SystemTime,
}

impl Sink {
    /// Open (or create) dir/rust-vmnet-proxy.log for append. None when the
    /// directory can't be created or the file can't be opened.
    fn open(dir: &Path) -> Option<Sink> {
        std::fs::create_dir_all(dir).ok()?;
        let path = dir.join(LOG_FILE);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .ok()?;
        let (written, opened_at) = file
            .metadata()
            .and_then(|m| m.modified().map(|t| (m.len(), t)))
            .unwrap_or((0, SystemTime::now()));
        Some(Sink {
            file: Some(file),
            path,
            rotate_secs: 0,
            keep: 0,
            max_bytes: 0,
            written,
            opened_at,
        })
    }

    fn write_line(&mut self, line: &str) {
        let Some(f) = &mut self.file else { return };
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
        self.written += line.len() as u64;
        if self.needs_rotation() {
            self.rotate();
        }
    }

    fn needs_rotation(&self) -> bool {
        if self.max_bytes > 0 && self.written >= self.max_bytes {
            return true;
        }
        if self.rotate_secs > 0 {
            let age = SystemTime::now()
                .duration_since(self.opened_at)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return age >= self.rotate_secs;
        }
        false
    }

    /// rust-vmnet-proxy.log -> .1, old .1 -> .2, ... oldest beyond `keep`
    /// falls off. keep=0 deletes the log instead of renaming it.
    fn rotate(&mut self) {
        if let Some(f) = self.file.take() {
            let _ = f.sync_all();
        }
        for i in (1..self.keep).rev() {
            let from = self.suffixed(i);
            let to = self.suffixed(i + 1);
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }
        if self.keep > 0 {
            let _ = std::fs::rename(&self.path, self.suffixed(1));
        } else {
            let _ = std::fs::remove_file(&self.path);
        }
        self.file = File::create(&self.path).ok();
        self.written = 0;
        self.opened_at = SystemTime::now();
    }

    fn suffixed(&self, n: u32) -> PathBuf {
        let Some(name) = self.path.file_name() else {
            return self.path.clone();
        };
        self.path
            .with_file_name(format!("{}.{}", name.to_string_lossy(), n))
    }
}

/// Level-aware sink set: optional rotating file plus stderr mirroring.
/// stderr mirrors when stderr is a tty (manual runs) or when the file is
/// unavailable, so launchd runs stay quiet and nothing is ever lost.
struct Logger {
    sink: Mutex<Sink>,
    level: log::LevelFilter,
    mirror_stderr: bool,
}

fn timestamp(t: SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let local = unsafe { libc::localtime_r(&secs, &mut tm) };
    if local.is_null() {
        return format!("@{secs}");
    }
    let (year, mon, day, h, min, s) = unsafe {
        (
            (*local).tm_year as i32 + 1900,
            (*local).tm_mon + 1,
            (*local).tm_mday,
            (*local).tm_hour,
            (*local).tm_min,
            (*local).tm_sec,
        )
    };
    format!("{year:04}-{mon:02}-{day:02} {h:02}:{min:02}:{s:02}")
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if record.level() > self.level {
            return;
        }
        let mut line = String::with_capacity(192);
        let _ = writeln!(
            line,
            "[{} {:5} {}] {}",
            timestamp(SystemTime::now()),
            record.level(),
            record.target(),
            record.args()
        );
        if self.mirror_stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
        if let Ok(mut sink) = self.sink.lock() {
            sink.write_line(&line);
        }
    }

    fn flush(&self) {
        if let Ok(mut sink) = self.sink.lock() {
            if let Some(f) = &mut sink.file {
                let _ = f.flush();
            }
        }
    }
}

/// Install the global logger. Returns false when one is already installed
/// (tests) or when the file is wanted but its directory can't be used: in
/// that case stderr becomes the sink, so logs still flow.
pub fn init(logging: &Logging) -> bool {
    let level = logging.effective_level();
    let mut sink = if logging.file {
        Sink::open(&logging.dir).unwrap_or_else(|| Sink {
            file: None,
            path: logging.dir.join(LOG_FILE),
            ..openless_defaults()
        })
    } else {
        Sink {
            file: None,
            path: PathBuf::new(),
            ..openless_defaults()
        }
    };
    sink.rotate_secs = logging.rotate_secs;
    sink.keep = logging.keep;
    sink.max_bytes = logging.max_bytes;
    let mirror_stderr = unsafe { libc::isatty(libc::STDERR_FILENO) == 1 } || sink.file.is_none();
    let logger = Logger {
        sink: Mutex::new(sink),
        level,
        mirror_stderr,
    };
    match log::set_boxed_logger(Box::new(logger)) {
        Ok(()) => {
            log::set_max_level(level);
            true
        }
        Err(_) => false,
    }
}

fn openless_defaults() -> Sink {
    Sink {
        file: None,
        path: PathBuf::new(),
        rotate_secs: 0,
        keep: 0,
        max_bytes: 0,
        written: 0,
        opened_at: SystemTime::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rvp-log-test_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sink_for(dir: &Path, rotate_secs: u64, keep: u32, max_bytes: u64) -> Sink {
        let mut s = Sink::open(dir).unwrap();
        s.rotate_secs = rotate_secs;
        s.keep = keep;
        s.max_bytes = max_bytes;
        s
    }

    const PAD: &str = "0123456789abcdef";

    #[test]
    fn size_cap_rotates_and_shifts() {
        let d = tmpdir("size");
        let mut s = sink_for(&d, 0, 3, 60);
        // each line ~45 bytes; force several rotations
        for i in 0..10 {
            s.write_line(&format!("[line {i} {PAD}]\n"));
        }
        assert!(d.join(LOG_FILE).exists());
        assert!(d.join(format!("{LOG_FILE}.1")).exists());
        assert!(d.join(format!("{LOG_FILE}.2")).exists());
        assert!(d.join(format!("{LOG_FILE}.3")).exists());
        assert!(!d.join(format!("{LOG_FILE}.4")).exists());
        // newest rotated chunk holds the most recent overflow
        let one = std::fs::read_to_string(d.join(format!("{LOG_FILE}.1"))).unwrap();
        assert!(one.contains("line 8") || one.contains("line 7"));
    }

    #[test]
    fn keep_zero_deletes_instead_of_renaming() {
        let d = tmpdir("keep0");
        let mut s = sink_for(&d, 0, 0, 40);
        for i in 0..6 {
            s.write_line(&format!("[x {i} {PAD}]\n"));
        }
        assert!(!d.join(format!("{LOG_FILE}.1")).exists());
        assert!(d.join(LOG_FILE).exists());
    }

    #[test]
    fn time_rotation_uses_opened_at() {
        let d = tmpdir("time");
        let mut s = sink_for(&d, 3600, 3, 0);
        s.write_line("young file stays\n");
        assert!(!d.join(format!("{LOG_FILE}.1")).exists());
        // age the anchor past the window: next write must rotate
        s.opened_at = SystemTime::now() - std::time::Duration::from_secs(3601);
        s.write_line("old file rotates\n");
        assert!(d.join(format!("{LOG_FILE}.1")).exists());
        let one = std::fs::read_to_string(d.join(format!("{LOG_FILE}.1"))).unwrap();
        assert!(one.contains("young file stays"));
    }

    #[test]
    fn append_preserves_existing_content() {
        let d = tmpdir("append");
        std::fs::write(d.join(LOG_FILE), "previous run\n").unwrap();
        let mut s = sink_for(&d, 0, 3, 0);
        s.write_line("new run\n");
        let all = std::fs::read_to_string(d.join(LOG_FILE)).unwrap();
        assert!(all.contains("previous run"));
        assert!(all.contains("new run"));
    }

    #[test]
    fn rotation_disabled_never_renames() {
        let d = tmpdir("noforce");
        let mut s = sink_for(&d, 0, 3, 0);
        for i in 0..50 {
            s.write_line(&format!("[unbounded {i} {PAD}]\n"));
        }
        assert!(!d.join(format!("{LOG_FILE}.1")).exists());
    }

    #[test]
    fn timestamp_local_format() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_760_000_000);
        let s = timestamp(t);
        assert_eq!(s.len(), 19);
        assert!(s.starts_with("20"));
        assert_eq!(s.as_bytes()[4], b'-');
    }
}
