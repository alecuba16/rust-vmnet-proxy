//! `setup-vmnet` / `teardown-vmnet`: bring the root socket_vmnet daemon up
//! (or down) so the rootless proxy has a bridged Ethernet socket. This is
//! the only part of the tool that touches root, once, interactively.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;

pub const LABEL: &str = "com.alecuba16.rust-vmnet-proxy-vmnet";
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.alecuba16.rust-vmnet-proxy-vmnet.plist";
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_INTERVAL: Duration = Duration::from_millis(200);

/// Entry point for both subcommands. `config_path` mirrors the proxy's
/// --config flag resolution; `interface` defaults to en0.
/// Returns the process exit code.
pub fn run(cmd: VmnetCmd, config_path: Option<&str>, interface: Option<&str>) -> i32 {
    let interface = interface.unwrap_or("en0");
    let cfg = match Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 1;
        }
    };
    match cmd {
        VmnetCmd::Setup => setup(&cfg, interface),
        VmnetCmd::Teardown => teardown(&cfg),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmnetCmd {
    Setup,
    Teardown,
}

/// A socket is usable only if connect succeeds: a stale file without a
/// listening daemon must not short-circuit setup.
pub fn socket_alive(path: &str) -> bool {
    match UnixStream::connect(path) {
        Ok(s) => {
            // socket_vmnet expects clients to just send frames; a probe
            // connection is closed immediately and ignored by the daemon
            let _ = s.shutdown(Shutdown::Both);
            true
        }
        Err(_) => false,
    }
}

fn brew_prefix() -> Option<String> {
    let out = Command::new("brew")
        .arg("--prefix")
        .arg("socket_vmnet")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn ensure_brew_formula() -> Result<(), String> {
    let listed = Command::new("brew")
        .args(["list", "--formulas"])
        .stderr(Stdio::null())
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim() == "socket_vmnet")
        });
    match listed {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(_) => return Err("no-brew".into()),
    }
    println!("installing socket_vmnet via Homebrew...");
    let ok = Command::new("brew")
        .args(["install", "socket_vmnet"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err("brew install socket_vmnet failed".into())
    }
}

/// LaunchDaemon plist, shape pinned from Lima's socket_vmnet daemon on this
/// machine. Log dir is created in the same sudo pass as the plist move so
/// the daemon never starts against a missing directory.
pub fn render_plist(prefix: &str, interface: &str, socket_path: &str) -> String {
    let prog = format!("{prefix}/bin/socket_vmnet");
    // /var/run is tmpfs: the socket parent dir is gone after every reboot.
    // socket_vmnet does not mkdir parents (verified: bind ENOENT), so wrap
    // in sh -c and mkdir -p the parent before exec.
    let parent = std::path::Path::new(socket_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/private/var/run".to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>/bin/sh</string>\n\
         \t\t<string>-c</string>\n\
         \t\t<string>/bin/mkdir -p {parent} &amp;&amp; exec {prog} --vmnet-mode=bridged --vmnet-interface={interface} {socket_path}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<true/>\n\
         \t<key>UserName</key>\n\
         \t<string>root</string>\n\
         \t<key>ProcessType</key>\n\
         \t<string>Interactive</string>\n\
         \t<key>StandardOutPath</key>\n\
         \t<string>/var/log/socket_vmnet/stdout.log</string>\n\
         \t<key>StandardErrorPath</key>\n\
         \t<string>/var/log/socket_vmnet/stderr.log</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

fn write_plist_as_root(plist: &str) -> Result<(), String> {
    let tmp = std::env::temp_dir().join("rust-vmnet-proxy-vmnet.plist");
    std::fs::write(&tmp, plist).map_err(|e| format!("write temp plist: {e}"))?;
    // plist is world-readable in /Library/LaunchDaemons by design: clients
    // only need to know the socket path, not read the daemon definition
    eprintln!("sudo> /bin/mkdir -p /var/log/socket_vmnet");
    let mkdir_ok = Command::new("sudo")
        .args(["/bin/mkdir", "-p", "/var/log/socket_vmnet"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !mkdir_ok {
        return Err("sudo mkdir /var/log/socket_vmnet failed".into());
    }
    eprintln!("sudo> /bin/mv {} {}", tmp.display(), PLIST_PATH);
    let mv_ok = Command::new("sudo")
        .args(["/bin/mv", &tmp.to_string_lossy(), PLIST_PATH])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !mv_ok {
        return Err(format!("sudo mv {} {PLIST_PATH} failed", tmp.display()));
    }
    // launchd rejects system LaunchDaemons not owned by root:wheel
    // (bootstrap fails with I/O error 5). sudo mv preserves the user
    // ownership of the temp file, so reset it explicitly.
    eprintln!("sudo> /usr/sbin/chown root:wheel {PLIST_PATH}");
    let chown_ok = Command::new("sudo")
        .args(["/usr/sbin/chown", "root:wheel", PLIST_PATH])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !chown_ok {
        return Err(format!("sudo chown root:wheel {PLIST_PATH} failed"));
    }
    Ok(())
}

fn bootstrap_daemon() -> Result<(), String> {
    let boot = Command::new("sudo")
        .args(["launchctl", "bootstrap", "system", PLIST_PATH])
        .status();
    let ok = boot.map(|s| s.success()).unwrap_or(false);
    if ok {
        return Ok(());
    }
    // Already loaded (Lima's daemon or a previous run): restart in place.
    eprintln!("sudo> launchctl kickstart -k system/{LABEL}");
    let kick = Command::new("sudo")
        .args(["launchctl", "kickstart", "-k", &format!("system/{LABEL}")])
        .status();
    if kick.map(|s| s.success()).unwrap_or(false) {
        Ok(())
    } else {
        Err("launchctl bootstrap/kickstart failed".into())
    }
}

fn poll_socket(socket_path: &str) -> bool {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    while Instant::now() < deadline {
        if socket_alive(socket_path) {
            return true;
        }
        thread::sleep(PROBE_INTERVAL);
    }
    false
}

fn setup(cfg: &Config, interface: &str) -> i32 {
    let socket_path = cfg.vmnet_socket.clone();

    if socket_alive(&socket_path) {
        println!("vmnet socket already available at {socket_path}");
        return 0;
    }

    if let Err(e) = ensure_brew_formula() {
        if e == "no-brew" {
            eprintln!("Homebrew not found. Install socket_vmnet manually:");
            eprintln!("  git clone https://github.com/lima-vm/socket_vmnet && cd socket_vmnet");
            eprintln!("  make && sudo make install");
            eprintln!("then create a bridged daemon socket at {socket_path} and rerun.");
            return 1;
        }
        eprintln!("{e}");
        return 1;
    }

    let Some(prefix) = brew_prefix() else {
        eprintln!("could not resolve brew --prefix socket_vmnet");
        return 1;
    };

    let plist = render_plist(&prefix, interface, &socket_path);
    if let Err(e) = write_plist_as_root(&plist) {
        eprintln!("{e}");
        return 1;
    }
    if let Err(e) = bootstrap_daemon() {
        eprintln!("{e}");
        return 1;
    }

    if poll_socket(&socket_path) {
        println!("vmnet socket up at {socket_path}");
        println!("hint: set vmnet_socket: {socket_path} in your config (already the default)");
        0
    } else {
        eprintln!("socket did not appear within {}s", PROBE_TIMEOUT.as_secs());
        eprintln!(
            "daemon logs: /var/log/socket_vmnet/stdout.log, /var/log/socket_vmnet/stderr.log"
        );
        eprintln!("inspect with: sudo launchctl print system/{LABEL}");
        1
    }
}

fn teardown(_cfg: &Config) -> i32 {
    eprintln!("sudo> launchctl bootout system/{LABEL}");
    let out = Command::new("sudo")
        .args(["launchctl", "bootout", &format!("system/{LABEL}")])
        .output();
    if let Ok(o) = &out {
        if !o.status.success() {
            // "not loaded" is the idempotent-rerun case, anything else is
            // worth surfacing but teardown still tries to remove the plist
            eprintln!(
                "bootout returned nonzero: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
    }
    eprintln!("sudo> /bin/rm -f {PLIST_PATH}");
    let rm = Command::new("sudo")
        .args(["/bin/rm", "-f", PLIST_PATH])
        .status();
    if rm.map(|s| s.success()).unwrap_or(false) {
        println!("vmnet daemon torn down (label {LABEL}, plist removed)");
        0
    } else {
        eprintln!("failed to remove {PLIST_PATH}");
        1
    }
}

/// Parse `--interface <name>` from a subcommand arg slice. Returns
/// (interface, rest) or Err(message) on malformed use.
pub fn parse_flags(args: &[String]) -> Result<(Option<String>, Vec<String>), String> {
    let mut interface = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interface" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| "--interface requires a value".to_string())?;
                interface = Some(v.clone());
                i += 2;
            }
            s if s.starts_with("--interface=") => {
                interface = Some(s["--interface=".len()..].to_string());
                i += 1;
            }
            _ => {
                rest.push(args[i].clone());
                i += 1;
            }
        }
    }
    Ok((interface, rest))
}

#[cfg(test)]
#[path = "setup_vmnet_tests.rs"]
mod tests;
