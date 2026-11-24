use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use serde::Deserialize;
use smoltcp::time::Duration as SmolDuration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerMode {
    #[default]
    Battery,
    Performance,
}

impl PowerMode {
    pub fn parse(s: &str) -> Result<PowerMode, String> {
        match s {
            "battery" => Ok(PowerMode::Battery),
            "performance" => Ok(PowerMode::Performance),
            other => Err(format!(
                "bad power_mode {other}, expected battery or performance"
            )),
        }
    }
}

/// Loop timing knobs derived from power_mode. All data paths are
/// event-driven (vmnet POLLIN on frames, wake pipe on commands, condvar on
/// pipe push), so the timeouts below only bound idle wakeups and shutdown
/// latency, never throughput.
#[derive(Debug, Clone)]
pub struct Tuning {
    /// Cap for the smoltcp poll_delay() timeout. None = uncapped (still
    /// floored at 1ms; 500ms fallback when poll_delay() returns None).
    pub poll_max: Option<SmolDuration>,
    /// Sleep between would-block SOCKS5 accepts.
    pub accept_interval: StdDuration,
    /// Splice thread take_blocking timeout.
    pub splice_timeout: StdDuration,
}

impl Tuning {
    pub fn from_power_mode(mode: PowerMode) -> Tuning {
        match mode {
            PowerMode::Battery => Tuning {
                poll_max: None,
                accept_interval: StdDuration::from_secs(1),
                // condvar is the wakeup; MAX parks indefinitely, no
                // periodic splice wakeups in battery mode
                splice_timeout: StdDuration::MAX,
            },
            PowerMode::Performance => Tuning {
                poll_max: Some(SmolDuration::from_millis(500)),
                accept_interval: StdDuration::from_millis(100),
                splice_timeout: StdDuration::from_millis(50),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshMode {
    Dynamic,
    LocalForward(String),
}

/// How a leg presents its traffic to the bastion.
/// - Masquerade: ssh -D binds the listen port directly, rust-vmnet-proxy is not
///   in the data path, traffic appears to come from the bastion itself.
/// - Identify: chained, ssh -D binds a private upstream port, rust-vmnet-proxy
///   owns the public listener and prepends a PROXY protocol v1 header so
///   PROXY-protocol-aware receivers log the real client IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegSource {
    #[default]
    Masquerade,
    Identify,
}

#[derive(Debug, Clone)]
pub struct SshLeg {
    pub listen: u16,
    pub host: String,
    pub mode: SshMode,
    pub source: LegSource,
    /// Bind address for the chained (identify) listener.
    pub bind: IpAddr,
    /// Private port the ssh -D forward listens on (identify legs).
    pub upstream: u16,
    /// Per-header HTTP injection toggles (identify legs only). None = no
    /// inspection at all.
    pub http_headers: Option<HttpHeaders>,
}

/// Per-header toggles for HTTP/1.x header injection. All default true when
/// the http_headers block is present; the block absent disables injection.
#[derive(Debug, Clone, Copy, Default, serde::Deserialize)]
pub struct HttpHeaders {
    #[serde(default = "default_true")]
    pub x_forwarded_for: bool,
    #[serde(default = "default_true")]
    pub x_real_ip: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_host: bool,
    #[serde(default = "default_true")]
    pub x_forwarded_proto: bool,
    #[serde(default = "default_true")]
    pub forwarded: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct SshLegRaw {
    listen: u16,
    host: String,
    mode: String,
    forward: Option<String>,
    source: Option<String>,
    bind: Option<String>,
    upstream: Option<u16>,
    http_headers: Option<HttpHeaders>,
}

#[derive(Debug, Deserialize)]
struct ConfigRaw {
    vmnet_socket: Option<String>,
    socks_listen: Option<String>,
    mac: Option<String>,
    power_mode: Option<String>,
    logging: Option<LogConfig>,
    ssh_legs: Option<Vec<SshLegRaw>>,
    relays: Option<Vec<RelayRaw>>,
}

/// Raw `logging:` block. Every key optional.
#[derive(Debug, Default, Deserialize)]
struct LogConfig {
    /// Level name: error, warn, info, debug, trace, off (case-insensitive).
    level: Option<String>,
    /// False disables file logging entirely (stderr only).
    file: Option<bool>,
    /// Directory for rust-vmnet-proxy.log. Empty or absent means the
    /// default ~/Library/Logs/rust-vmnet-proxy. Relative paths resolve
    /// against $HOME.
    dir: Option<String>,
    /// Rotate when the file is older than this many seconds.
    /// Default 86400 (daily). 0 disables time rotation.
    rotate_secs: Option<u64>,
    /// Rotated files kept. Default 3. 0 deletes the rotated file at once.
    keep: Option<u32>,
    /// Size cap in bytes that forces a rotation. Default 10 MiB.
    /// 0 disables the size cap.
    max_bytes: Option<u64>,
}

/// Resolved logging setup, what the binary does at startup.
#[derive(Debug, Clone, PartialEq)]
pub struct Logging {
    /// Level name (lowercased) or None to fall back to RUST_LOG/"info".
    pub level: Option<String>,
    /// False = no file logging, everything goes to stderr.
    pub file: bool,
    /// Directory for rust-vmnet-proxy.log, always absolute after load.
    pub dir: PathBuf,
    /// Seconds; 0 disables time rotation.
    pub rotate_secs: u64,
    /// Rotated files kept.
    pub keep: u32,
    /// Size cap in bytes; 0 disables.
    pub max_bytes: u64,
}

impl Default for Logging {
    fn default() -> Self {
        Logging {
            level: None,
            file: true,
            // placeholder: load_with joins it with $HOME
            dir: PathBuf::new(),
            rotate_secs: 86400,
            keep: 3,
            max_bytes: 10 * 1024 * 1024,
        }
    }
}

/// Empty dir -> ~/Library/Logs/rust-vmnet-proxy, relative dir -> against
/// $HOME, absolute kept as-is. Dir is cleared when file logging is off.
fn resolve_log_dir(mut l: Logging, home: &str) -> Logging {
    if !l.file {
        l.dir = PathBuf::new();
        return l;
    }
    if l.dir.as_os_str().is_empty() {
        l.dir = PathBuf::from(home).join("Library/Logs/rust-vmnet-proxy");
    } else if l.dir.is_relative() {
        let d = std::mem::take(&mut l.dir);
        l.dir = PathBuf::from(home).join(d);
    }
    l
}

pub(crate) fn parse_level(s: &str) -> Result<log::LevelFilter, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => Ok(log::LevelFilter::Off),
        "error" => Ok(log::LevelFilter::Error),
        "warn" => Ok(log::LevelFilter::Warn),
        "info" => Ok(log::LevelFilter::Info),
        "debug" => Ok(log::LevelFilter::Debug),
        "trace" => Ok(log::LevelFilter::Trace),
        other => Err(format!(
            "bad logging level {other:?}, expected error, warn, info, debug, trace or off"
        )),
    }
}

impl Logging {
    /// LevelFilter from config, then RUST_LOG's first segment, then info.
    /// RUST_LOG beyond the first segment (module filters) is ignored here.
    pub fn effective_level(&self) -> log::LevelFilter {
        if let Some(l) = &self.level {
            return parse_level(l).unwrap_or(log::LevelFilter::Info);
        }
        if let Ok(env) = std::env::var("RUST_LOG") {
            let first = env.split(',').next().unwrap_or("");
            // env_logger syntax allows "module=level" segments
            let word = first.split('=').next_back().unwrap_or("");
            if let Ok(f) = parse_level(word) {
                return f;
            }
        }
        log::LevelFilter::Info
    }
}

#[derive(Debug, Clone)]
pub struct Relay {
    /// Log-friendly label, defaults to the listen port.
    pub name: String,
    /// Port on the vmnet stack's LAN address where LAN clients connect.
    pub listen: u16,
    /// Mac-side endpoint the connection is forwarded to.
    pub target: SocketAddr,
}

#[derive(Debug, Deserialize)]
struct RelayRaw {
    name: Option<String>,
    listen: u16,
    target: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub vmnet_socket: String,
    pub socks_listen: SocketAddr,
    pub mac: Option<[u8; 6]>,
    pub power_mode: PowerMode,
    pub logging: Logging,
    pub ssh_legs: Vec<SshLeg>,
    pub relays: Vec<Relay>,
    /// True when no config file was found and built-in defaults were used.
    pub from_defaults: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            vmnet_socket: "/private/var/run/lima/socket_vmnet.bridged".into(),
            socks_listen: "127.0.0.1:1080".parse().unwrap(),
            mac: None,
            power_mode: PowerMode::default(),
            logging: Logging::default(),
            ssh_legs: Vec::new(),
            relays: Vec::new(),
            from_defaults: false,
        }
    }
}

/// MAC from FNV-1a of the socket path: locally administered (02), unicast,
/// deterministic so reboots don't churn the bridge's forwarding table.
pub fn mac_from_path(path: &str) -> [u8; 6] {
    let mut h: u32 = 0x811c9dc5;
    for b in path.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    let mut mac = [0u8; 6];
    mac[0] = 0x02;
    for (i, m) in mac[1..].iter_mut().enumerate() {
        // spread hash bytes, re-mix so low bits don't collide across ports
        h = h.wrapping_mul(0x01000193).wrapping_add(i as u32);
        *m = (h >> 24) as u8;
    }
    mac
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

impl Config {
    pub fn load(path: Option<&str>) -> Result<Config, String> {
        let env_cfg = std::env::var("RUST_VMNET_PROXY_CONFIG")
            .ok()
            .filter(|p| !p.is_empty());
        let home = std::env::var("HOME").unwrap_or_default();
        Self::load_with(path, env_cfg, home)
    }

    /// Testable core of load(): path resolution order without touching
    /// process env. --config wins, then RUST_VMNET_PROXY_CONFIG, then
    /// ~/.config/rust-vmnet-proxy/config.yaml, then built-in defaults.
    pub fn load_with(
        path: Option<&str>,
        env_cfg: Option<String>,
        home: String,
    ) -> Result<Config, String> {
        let path: PathBuf = match path {
            Some(p) => p.into(),
            None => match env_cfg {
                Some(p) => p.into(),
                None => {
                    let default =
                        PathBuf::from(home.clone()).join(".config/rust-vmnet-proxy/config.yaml");
                    if default.exists() {
                        default
                    } else {
                        return Ok(Config {
                            from_defaults: true,
                            logging: resolve_log_dir(Logging::default(), &home),
                            ..Config::default()
                        });
                    }
                }
            },
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("read config {}: {e}", path.display()))?;
        let raw: ConfigRaw =
            serde_yaml::from_str(&text).map_err(|e| format!("parse config: {e}"))?;
        let def = Config::default();
        let socks_listen: SocketAddr = match raw.socks_listen.as_deref() {
            Some(s) => s.parse().map_err(|e| format!("bad socks_listen: {e}"))?,
            None => def.socks_listen,
        };
        let mac: Option<[u8; 6]> = match raw.mac.as_deref() {
            Some(s) => Some(parse_mac(s).ok_or_else(|| format!("bad mac: {s}"))?),
            None => def.mac,
        };
        let vmnet_socket = raw.vmnet_socket.unwrap_or_else(|| def.vmnet_socket.clone());
        let power_mode = match raw.power_mode.as_deref() {
            Some(s) => PowerMode::parse(s)?,
            None => def.power_mode,
        };
        let logging = match raw.logging {
            Some(l) => {
                let level = match &l.level {
                    Some(s) => {
                        parse_level(s)?;
                        Some(s.to_ascii_lowercase())
                    }
                    None => None,
                };
                Logging {
                    level,
                    file: l.file.unwrap_or(def.logging.file),
                    dir: l.dir.map(PathBuf::from).unwrap_or_default(),
                    rotate_secs: l.rotate_secs.unwrap_or(def.logging.rotate_secs),
                    keep: l.keep.unwrap_or(def.logging.keep),
                    max_bytes: l.max_bytes.unwrap_or(def.logging.max_bytes),
                }
            }
            None => def.logging,
        };
        let logging = resolve_log_dir(logging, &home);
        let ssh_legs = match raw.ssh_legs {
            Some(legs) => {
                let mut out = Vec::new();
                for l in legs {
                    let mode = match (l.mode.as_str(), &l.forward) {
                        ("dynamic", _) => SshMode::Dynamic,
                        ("local_forward", Some(f)) => SshMode::LocalForward(f.clone()),
                        (m, _) => return Err(format!("bad mode {m} for leg {}", l.listen)),
                    };
                    out.push(SshLeg {
                        listen: l.listen,
                        host: l.host.clone(),
                        mode,
                        source: match l.source.as_deref() {
                            None | Some("masquerade") => LegSource::Masquerade,
                            Some("identify") => LegSource::Identify,
                            Some(s) => {
                                return Err(format!(
                                    "bad source {s} for leg {}, expected masquerade or identify",
                                    l.listen
                                ))
                            }
                        },
                        bind: match l.bind.as_deref() {
                            Some(b) => b
                                .parse()
                                .map_err(|e| format!("bad bind for leg {}: {e}", l.listen))?,
                            None => IpAddr::from([127, 0, 0, 1]),
                        },
                        // listen near u16::MAX would wrap; reject instead
                        upstream: l.upstream.unwrap_or(l.listen.checked_add(30000).ok_or_else(
                            || format!("leg {}: listen too high for default upstream", l.listen),
                        )?),
                        http_headers: l.http_headers,
                    });
                    let leg = out.last().unwrap();
                    if leg.source == LegSource::Masquerade
                        && (l.bind.is_some() || l.upstream.is_some())
                    {
                        log::warn!(
                            "leg {}: bind/upstream only apply to identify legs, ignoring",
                            l.listen
                        );
                    }
                    if leg.source == LegSource::Masquerade && l.http_headers.is_some() {
                        log::warn!(
                            "leg {}: http_headers only applies to identify legs, ignoring",
                            l.listen
                        );
                    }
                }
                out
            }
            None => def.ssh_legs,
        };
        let relays = match raw.relays {
            Some(entries) => {
                let mut out = Vec::new();
                for r in entries {
                    let target: SocketAddr = r
                        .target
                        .parse()
                        .map_err(|e| format!("bad target for relay {}: {e}", r.listen))?;
                    out.push(Relay {
                        name: r.name.unwrap_or_else(|| r.listen.to_string()),
                        listen: r.listen,
                        target,
                    });
                }
                out
            }
            None => def.relays,
        };
        validate_ports(&ssh_legs)?;
        validate_relay_ports(&relays, &ssh_legs, socks_listen)?;
        Ok(Config {
            vmnet_socket,
            socks_listen,
            mac,
            power_mode,
            logging,
            ssh_legs,
            relays,
            from_defaults: false,
        })
    }

    pub fn effective_mac(&self) -> [u8; 6] {
        self.mac
            .unwrap_or_else(|| mac_from_path(&self.vmnet_socket))
    }
}

/// No listen or upstream port may collide with another leg's listen or
/// upstream, otherwise the second ssh -D or chained listener fails to bind
/// at runtime with a confusing error.
fn validate_ports(legs: &[SshLeg]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for leg in legs {
        for (kind, port) in [("listen", leg.listen), ("upstream", leg.upstream)] {
            if port == 0 {
                return Err(format!("leg {}: {kind} port must not be 0", leg.listen));
            }
            if !seen.insert(port) {
                return Err(format!(
                    "leg {}: port {port} ({kind}) collides with another leg listen or upstream",
                    leg.listen
                ));
            }
        }
    }
    Ok(())
}

/// Relay listen ports must be unique among relays and must not collide with
/// any leg listen/upstream port or the direct SOCKS listener: relays bind on
/// the vmnet stack's own address (separate address space from the Mac's
/// stack), but keeping every configured port distinct catches copy-paste
/// mistakes early and keeps the port map easy to read.
fn validate_relay_ports(
    relays: &[Relay],
    legs: &[SshLeg],
    socks_listen: SocketAddr,
) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for relay in relays {
        if relay.listen == 0 {
            return Err(format!("relay {}: listen port must not be 0", relay.name));
        }
        if !seen.insert(relay.listen) {
            return Err(format!(
                "relay {}: listen port {} collides with another relay",
                relay.name, relay.listen
            ));
        }
    }
    for leg in legs {
        if seen.contains(&leg.listen) {
            return Err(format!(
                "relay listen port {} collides with leg {} listen",
                leg.listen, leg.listen
            ));
        }
        if seen.contains(&leg.upstream) {
            return Err(format!(
                "relay listen port {} collides with leg {} upstream",
                leg.upstream, leg.listen
            ));
        }
    }
    if relays.iter().any(|r| r.listen == socks_listen.port()) {
        return Err(format!(
            "relay listen port {} collides with socks_listen {}",
            socks_listen.port(),
            socks_listen
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("rust-vmnet-proxy_test_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_cfg(text: &str) -> PathBuf {
        let d = tmpdir();
        // unique per call: tests run in parallel threads and share the pid
        let p = d.join(format!("cfg_{}_{:p}.yaml", std::process::id(), text));
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!(c.vmnet_socket, "/private/var/run/lima/socket_vmnet.bridged");
        assert_eq!(c.socks_listen.to_string(), "127.0.0.1:1080");
        assert!(c.mac.is_none());
        assert_eq!(c.power_mode, PowerMode::Battery);
        assert!(c.ssh_legs.is_empty());
        assert!(!c.from_defaults);
    }

    #[test]
    fn load_with_explicit_path_happy() {
        let p = write_cfg(
            "vmnet_socket: /tmp/x.sock\nsocks_listen: 127.0.0.1:9999\nmac: \"02:11:22:33:44:55\"\npower_mode: performance\nssh_legs:\n  - listen: 1081\n    host: bastion-a\n    mode: dynamic\n",
        );
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/nonexistent".into()).unwrap();
        assert_eq!(c.vmnet_socket, "/tmp/x.sock");
        assert_eq!(c.socks_listen.to_string(), "127.0.0.1:9999");
        assert_eq!(c.mac, Some([2, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(c.power_mode, PowerMode::Performance);
        assert_eq!(c.ssh_legs.len(), 1);
        assert_eq!(c.ssh_legs[0].listen, 1081);
        assert_eq!(c.ssh_legs[0].source, LegSource::Masquerade);
        assert_eq!(c.ssh_legs[0].bind, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(c.ssh_legs[0].upstream, 1081 + 30000);
        assert!(c.ssh_legs[0].http_headers.is_none());
    }

    #[test]
    fn load_identify_defaults() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1082\n    host: bastion-b\n    mode: dynamic\n    source: identify\n    http_headers: {}\n",
        );
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/nonexistent".into()).unwrap();
        let leg = &c.ssh_legs[0];
        assert_eq!(leg.source, LegSource::Identify);
        assert_eq!(leg.bind, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(leg.upstream, 1082 + 30000);
        let h = leg.http_headers.unwrap();
        assert!(
            h.x_forwarded_for
                && h.x_real_ip
                && h.x_forwarded_host
                && h.x_forwarded_proto
                && h.forwarded
        );
    }

    #[test]
    fn load_identify_explicit_and_local_forward() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1082\n    host: b\n    mode: dynamic\n    source: identify\n    bind: 0.0.0.0\n    upstream: 31082\n    http_headers:\n      x_forwarded_for: false\n      forwarded: false\n  - listen: 1086\n    host: j\n    mode: local_forward\n    forward: 10.0.0.5:3000\n",
        );
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/nonexistent".into()).unwrap();
        let leg = &c.ssh_legs[0];
        assert_eq!(leg.bind.to_string(), "0.0.0.0");
        assert_eq!(leg.upstream, 31082);
        let h = leg.http_headers.unwrap();
        assert!(!h.x_forwarded_for && h.x_real_ip && !h.forwarded);
        assert!(matches!(c.ssh_legs[1].mode, SshMode::LocalForward(_)));
    }

    #[test]
    fn load_no_config_uses_defaults_flag() {
        let c = Config::load_with(None, None, "/nonexistent_home_abc".into()).unwrap();
        assert!(c.from_defaults);
        assert!(c.ssh_legs.is_empty());
    }

    #[test]
    fn load_env_var_path() {
        let p = write_cfg("socks_listen: 127.0.0.1:1234\n");
        let c =
            Config::load_with(None, Some(p.display().to_string()), "/nonexistent".into()).unwrap();
        assert_eq!(c.socks_listen.to_string(), "127.0.0.1:1234");
        assert!(!c.from_defaults);
    }

    #[test]
    fn load_home_default_path() {
        let d = tmpdir();
        let cfg_dir = d.join(".config/rust-vmnet-proxy");
        std::fs::create_dir_all(&cfg_dir).unwrap();
        std::fs::write(
            cfg_dir.join("config.yaml"),
            "socks_listen: 127.0.0.1:1235\n",
        )
        .unwrap();
        let c = Config::load_with(None, None, d.to_string_lossy().into_owned()).unwrap();
        assert_eq!(c.socks_listen.to_string(), "127.0.0.1:1235");
    }

    #[test]
    fn load_missing_file_err() {
        let err = Config::load_with(Some("/nonexistent/x.yaml"), None, String::new()).unwrap_err();
        assert!(err.starts_with("read config"));
    }

    #[test]
    fn load_parse_err() {
        let p = write_cfg("ssh_legs: [not: a, valid: leg\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("parse config")
        );
    }

    #[test]
    fn load_bad_socks_listen() {
        let p = write_cfg("socks_listen: not-an-addr\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("bad socks_listen")
        );
    }

    #[test]
    fn load_bad_mac() {
        let p = write_cfg("mac: \"02:zz\"\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("bad mac")
        );
    }

    #[test]
    fn load_bad_power_mode() {
        let p = write_cfg("power_mode: turbo\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("bad power_mode turbo")
        );
    }

    #[test]
    fn power_mode_parse() {
        assert_eq!(PowerMode::parse("battery").unwrap(), PowerMode::Battery);
        assert_eq!(
            PowerMode::parse("performance").unwrap(),
            PowerMode::Performance
        );
        assert!(PowerMode::parse("x").is_err());
    }

    #[test]
    fn tuning_battery_vs_performance() {
        let b = Tuning::from_power_mode(PowerMode::Battery);
        assert!(b.poll_max.is_none());
        assert_eq!(b.accept_interval, StdDuration::from_secs(1));
        assert_eq!(b.splice_timeout, StdDuration::MAX);
        let p = Tuning::from_power_mode(PowerMode::Performance);
        assert_eq!(p.poll_max, Some(SmolDuration::from_millis(500)));
        assert_eq!(p.accept_interval, StdDuration::from_millis(100));
        assert_eq!(p.splice_timeout, StdDuration::from_millis(50));
    }

    #[test]
    fn load_bad_mode() {
        let p = write_cfg("ssh_legs:\n  - listen: 1081\n    host: h\n    mode: weird\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("bad mode weird")
        );
    }

    #[test]
    fn load_local_forward_missing_forward_err() {
        let p = write_cfg("ssh_legs:\n  - listen: 1081\n    host: h\n    mode: local_forward\n");
        assert!(Config::load_with(Some(p.to_str().unwrap()), None, String::new()).is_err());
    }

    #[test]
    fn load_bad_source() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1081\n    host: h\n    mode: dynamic\n    source: spoof\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("bad source spoof")
        );
    }

    #[test]
    fn load_bad_bind() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1081\n    host: h\n    mode: dynamic\n    source: identify\n    bind: not-an-ip\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("bad bind")
        );
    }

    #[test]
    fn load_duplicate_listen_ports() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1081\n    host: a\n    mode: dynamic\n  - listen: 1081\n    host: b\n    mode: dynamic\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("collides")
        );
    }

    #[test]
    fn load_upstream_collision() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1081\n    host: a\n    mode: dynamic\n    source: identify\n    upstream: 41082\n  - listen: 1082\n    host: b\n    mode: dynamic\n    source: identify\n    upstream: 41082\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("collides")
        );
    }

    #[test]
    fn load_upstream_collides_with_listen() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 20000\n    host: a\n    mode: dynamic\n  - listen: 1082\n    host: b\n    mode: dynamic\n    source: identify\n    upstream: 20000\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("collides")
        );
    }

    #[test]
    fn mac_from_path_deterministic_and_local_admin() {
        let m1 = mac_from_path("/a/b");
        let m2 = mac_from_path("/a/b");
        assert_eq!(m1, m2);
        assert_eq!(m1[0], 0x02);
        assert_ne!(mac_from_path("/a/b"), mac_from_path("/a/c"));
    }

    #[test]
    fn effective_mac_prefers_config() {
        let mut c = Config {
            mac: Some([1, 2, 3, 4, 5, 6]),
            ..Default::default()
        };
        assert_eq!(c.effective_mac(), [1, 2, 3, 4, 5, 6]);
        c.mac = None;
        assert_eq!(c.effective_mac(), mac_from_path(&c.vmnet_socket));
    }

    #[test]
    fn http_headers_unknown_key_is_err() {
        // serde deny unknown fields is not enabled; unknown sub-keys parse
        // silently. Verify the struct itself only exposes known fields.
        let h: HttpHeaders = serde_yaml::from_str("x_forwarded_for: false").unwrap();
        assert!(!h.x_forwarded_for);
    }

    #[test]
    fn load_high_listen_rejects_default_upstream() {
        let p = write_cfg("ssh_legs:\n  - listen: 65535\n    host: a\n    mode: dynamic\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("listen too high")
        );
    }

    #[test]
    fn load_zero_port_rejected() {
        let p = write_cfg("ssh_legs:\n  - listen: 0\n    host: a\n    mode: dynamic\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("must not be 0")
        );
    }

    #[test]
    fn load_masquerade_ignores_identify_fields() {
        // bind/upstream/http_headers on a masquerade leg are warned and
        // dropped; load still succeeds and upstream falls back to default
        let p = write_cfg(
            "ssh_legs:\n  - listen: 10000\n    host: a\n    mode: dynamic\n    bind: 127.0.0.2\n    upstream: 10001\n    http_headers:\n      x_forwarded_for: true\n",
        );
        let c = Config::load_with(Some(p.to_str().unwrap()), None, String::new()).unwrap();
        let leg = &c.ssh_legs[0];
        // warn only: values are stored but inert, masquerade legs use
        // listen for the ssh -D bind and never read upstream or headers
        assert_eq!(leg.upstream, 10001);
        assert!(leg.http_headers.is_some());
    }

    #[test]
    fn load_relays_happy() {
        let p = write_cfg(
            "relays:\n  - name: herdr\n    listen: 8787\n    target: 127.0.0.1:8787\n  - listen: 2222\n    target: 127.0.0.1:22\n",
        );
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/nonexistent".into()).unwrap();
        assert_eq!(c.relays.len(), 2);
        assert_eq!(c.relays[0].name, "herdr");
        assert_eq!(c.relays[0].listen, 8787);
        assert_eq!(c.relays[0].target.to_string(), "127.0.0.1:8787");
        // name defaults to the port when absent
        assert_eq!(c.relays[1].name, "2222");
        assert_eq!(c.relays[1].target.port(), 22);
    }

    #[test]
    fn load_relays_bad_target() {
        let p = write_cfg("relays:\n  - listen: 8787\n    target: nope\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .starts_with("bad target")
        );
    }

    #[test]
    fn load_relays_duplicate_listen() {
        let p = write_cfg(
            "relays:\n  - listen: 8787\n    target: 127.0.0.1:1\n  - listen: 8787\n    target: 127.0.0.1:2\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("collides with another relay")
        );
    }

    #[test]
    fn load_relay_collides_with_socks_listen() {
        let p = write_cfg(
            "socks_listen: 127.0.0.1:1080\nrelays:\n  - listen: 1080\n    target: 127.0.0.1:1\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("collides with socks_listen")
        );
    }

    #[test]
    fn load_relay_collides_with_leg_listen() {
        let p = write_cfg(
            "ssh_legs:\n  - listen: 1081\n    host: h\n    mode: dynamic\nrelays:\n  - listen: 1081\n    target: 127.0.0.1:1\n",
        );
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("collides with leg 1081 listen")
        );
    }

    #[test]
    fn load_relay_zero_listen_rejected() {
        let p = write_cfg("relays:\n  - listen: 0\n    target: 127.0.0.1:1\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, String::new())
                .unwrap_err()
                .contains("must not be 0")
        );
    }

    #[test]
    fn load_relays_absent_defaults_empty() {
        let p = write_cfg("socks_listen: 127.0.0.1:1234\n");
        let c = Config::load_with(Some(p.to_str().unwrap()), None, String::new()).unwrap();
        assert!(c.relays.is_empty());
    }

    #[test]
    fn load_real_env_seam() {
        // exercises Config::load itself: env var + HOME resolution.
        // Serial against any other env-touching test via a file lock.
        let lock = tmpdir().join("env_lock");
        // leave a stale lock from a previous (panicked) run behind once so
        // the retry loop runs at least one Err branch
        let _ = std::fs::File::create(&lock);
        let mut tries = 0;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock)
            {
                Ok(_) => break,
                Err(_) => {
                    tries += 1;
                    if tries > 200 {
                        panic!("env lock stuck");
                    }
                    // break the stale lock after the first Err so the
                    // retry path runs exactly once, no real waiting
                    if tries == 1 {
                        let _ = std::fs::remove_file(&lock);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }
        let home = tmpdir().join("env_home");
        std::fs::create_dir_all(home.join(".config/rust-vmnet-proxy")).unwrap();
        std::fs::write(
            home.join(".config/rust-vmnet-proxy/config.yaml"),
            "socks_listen: 127.0.0.1:9999\n",
        )
        .unwrap();
        let env_p = write_cfg("socks_listen: 127.0.0.1:8888\n");
        let old_env = std::env::var("RUST_VMNET_PROXY_CONFIG").ok();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("RUST_VMNET_PROXY_CONFIG", env_p.display().to_string());
        std::env::set_var("HOME", home.display().to_string());
        let c = Config::load(None).unwrap();
        // exercise the unset-then-absent restore: env var gone entirely
        std::env::remove_var("RUST_VMNET_PROXY_CONFIG");
        assert!(Config::load(None).is_ok());
        if let Some(v) = old_env {
            std::env::set_var("RUST_VMNET_PROXY_CONFIG", v);
        } else {
            std::env::remove_var("RUST_VMNET_PROXY_CONFIG");
        }
        if let Some(v) = old_home {
            std::env::set_var("HOME", v);
        }
        std::fs::remove_file(&lock).unwrap();
        // env var beats HOME default
        assert_eq!(c.socks_listen.to_string(), "127.0.0.1:8888");
    }

    #[test]
    fn load_logging_block_happy() {
        let p = write_cfg(
            "logging:\n  level: Debug\n  dir: /tmp/rvp-logs-test\n  rotate_secs: 3600\n  keep: 5\n  max_bytes: 1048576\n",
        );
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/home/x".into()).unwrap();
        assert_eq!(c.logging.level.as_deref(), Some("debug"));
        assert!(c.logging.file);
        assert_eq!(c.logging.dir, PathBuf::from("/tmp/rvp-logs-test"));
        assert_eq!(c.logging.rotate_secs, 3600);
        assert_eq!(c.logging.keep, 5);
        assert_eq!(c.logging.max_bytes, 1048576);
    }

    #[test]
    fn load_logging_defaults() {
        let p = write_cfg("socks_listen: 127.0.0.1:1234\n");
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/home/y".into()).unwrap();
        assert_eq!(c.logging.level, None);
        assert!(c.logging.file);
        assert_eq!(
            c.logging.dir,
            PathBuf::from("/home/y/Library/Logs/rust-vmnet-proxy")
        );
        assert_eq!(c.logging.rotate_secs, 86400);
        assert_eq!(c.logging.keep, 3);
        assert_eq!(c.logging.max_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn load_logging_relative_dir_resolves_against_home() {
        let p = write_cfg("logging:\n  dir: Logs/proxy\n");
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/home/z".into()).unwrap();
        assert_eq!(c.logging.dir, PathBuf::from("/home/z/Logs/proxy"));
    }

    #[test]
    fn load_logging_file_false_disables() {
        let p = write_cfg("logging:\n  file: false\n  dir: /tmp/ignored\n");
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/home/w".into()).unwrap();
        assert!(!c.logging.file);
        assert!(c.logging.dir.as_os_str().is_empty());
    }

    #[test]
    fn load_logging_bad_level_rejected() {
        let p = write_cfg("logging:\n  level: verbose\n");
        assert!(
            Config::load_with(Some(p.to_str().unwrap()), None, "/home/v".into())
                .unwrap_err()
                .contains("bad logging level")
        );
    }

    #[test]
    fn load_logging_off_level_kept() {
        let p = write_cfg("logging:\n  level: OFF\n");
        let c = Config::load_with(Some(p.to_str().unwrap()), None, "/home/u".into()).unwrap();
        assert_eq!(c.logging.level.as_deref(), Some("off"));
        assert_eq!(c.logging.effective_level(), log::LevelFilter::Off);
    }

    #[test]
    fn effective_level_falls_back_to_info() {
        let l = Logging::default();
        // RUST_LOG may be set by the harness; the fallthrough target is info
        let lv = l.effective_level();
        assert!(matches!(
            lv,
            log::LevelFilter::Info | log::LevelFilter::Debug | log::LevelFilter::Trace
        ));
    }

    #[test]
    fn effective_level_config_beats_env() {
        let l = Logging {
            level: Some("error".into()),
            ..Logging::default()
        };
        assert_eq!(l.effective_level(), log::LevelFilter::Error);
    }

    #[test]
    fn load_no_config_logging_dir_resolved() {
        let c = Config::load_with(None, None, "/home/t".into()).unwrap();
        assert!(c.from_defaults);
        assert_eq!(
            c.logging.dir,
            PathBuf::from("/home/t/Library/Logs/rust-vmnet-proxy")
        );
    }
}
