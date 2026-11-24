use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{LegSource, SshLeg, SshMode};

const STDERR_TAIL: usize = 20;
const LISTEN_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SshLegs {
    shutdown: Arc<AtomicBool>,
    children: Arc<Mutex<Vec<u32>>>,
}

impl SshLegs {
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let pids: Vec<u32> = self.children.lock().unwrap().clone();
        for pid in pids {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
    }
}

fn leg_args(leg: &SshLeg) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-N".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "ServerAliveInterval=30".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "BatchMode=yes".into(),
    ];
    // Identify legs chain through rust-vmnet-proxy: ssh -D binds the private
    // upstream port, the public listen port belongs to the legchain
    // listener. Masquerade legs bind the public port directly.
    let bind_port = match leg.source {
        LegSource::Masquerade => leg.listen,
        LegSource::Identify => leg.upstream,
    };
    match &leg.mode {
        SshMode::Dynamic => args.push(format!("-D127.0.0.1:{bind_port}")),
        SshMode::LocalForward(fwd) => args.push(format!("-L127.0.0.1:{}:{}", bind_port, fwd)),
    }
    args.push(leg.host.clone());
    args
}

fn wait_listening(listen: u16, deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, listen)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
    false
}

fn supervise_leg(leg: SshLeg, shutdown: Arc<AtomicBool>, children: Arc<Mutex<Vec<u32>>>) {
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let mut child = match Command::new("ssh")
            .args(leg_args(&leg))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                log::error!("leg {} spawn failed: {e}", leg.listen);
                thread::sleep(backoff);
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        let pid = child.id();
        children.lock().unwrap().push(pid);

        // stderr watcher keeps the last lines so the death log carries context.
        let tail = Arc::new(Mutex::new(Vec::<String>::new()));
        let tail_w = Arc::clone(&tail);
        let listen = leg.listen;
        let stderr = child.stderr.take();
        thread::spawn(move || {
            if let Some(err) = stderr {
                for line in BufReader::new(err).lines().map_while(|l| l.ok()) {
                    let l = line.trim_end().to_string();
                    if l.is_empty() {
                        continue;
                    }
                    log::debug!("leg {listen} stderr: {l}");
                    let mut t = tail_w.lock().unwrap();
                    t.push(l);
                    if t.len() > STDERR_TAIL {
                        t.remove(0);
                    }
                }
            }
        });

        // The forward listens on the upstream port for identify legs, the
        // listen port otherwise; liveness is checked against whichever one
        // ssh actually bound.
        let check_port = match leg.source {
            LegSource::Masquerade => leg.listen,
            LegSource::Identify => leg.upstream,
        };
        if wait_listening(check_port, Instant::now() + LISTEN_TIMEOUT) {
            log::info!("leg {} up (pid {pid})", leg.listen);
            backoff = Duration::from_secs(1);
            let rc = child
                .wait()
                .ok()
                .and_then(|s| s.code())
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into());
            let t = tail.lock().unwrap().join(" | ");
            backoff = (backoff * 2).min(MAX_BACKOFF);
            log::info!(
                "leg {} died rc={rc} -> restart in {}s, stderr tail: {t}",
                leg.listen,
                backoff.as_secs()
            );
        } else {
            // ExitOnForwardFailure should cover this, but kill the stray child
            // instead of leaking an ssh with a broken forward.
            let _ = child.kill();
            let _ = child.wait();
            let t = tail.lock().unwrap().join(" | ");
            log::error!(
                "leg {} never listened within 30s, stderr tail: {t}",
                leg.listen
            );
        }

        children.lock().unwrap().retain(|p| *p != pid);
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(backoff);
    }
}

/// One supervisor thread per leg. Legs restart with exponential backoff
/// (1s doubling, 30s cap) until shutdown().
pub fn spawn_legs(legs: &[SshLeg]) -> SshLegs {
    let shutdown = Arc::new(AtomicBool::new(false));
    let children = Arc::new(Mutex::new(Vec::new()));
    for leg in legs {
        let leg = leg.clone();
        let sd = Arc::clone(&shutdown);
        let ch = Arc::clone(&children);
        thread::Builder::new()
            .name(format!("ssh-leg-{}", leg.listen))
            .spawn(move || supervise_leg(leg, sd, ch))
            .expect("spawn ssh leg thread");
    }
    SshLegs { shutdown, children }
}
