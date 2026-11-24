mod cmds;
mod config;
mod legchain;
mod logging;
mod netloop;
mod pipe;
mod service;
mod setup_vmnet;
mod socks5;
mod sshlegs;
mod vmnet_dev;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn on_signal(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn install_signal_handlers() {
    let handler = on_signal as *const ();
    unsafe {
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        // splice take_blocking and netloop poll timeouts come from
        // power_mode; battery floors shutdown notice at the main loop's
        // 200ms sleep + splice timeout, performance is snappier.
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

fn print_usage() {
    println!(
        "rust-vmnet-proxy {}: rootless SOCKS5 proxy over socket_vmnet",
        env!("CARGO_PKG_VERSION")
    );
    println!("usage: rust-vmnet-proxy [--config <path>]");
    println!("  --config <path>   config file (default: $RUST_VMNET_PROXY_CONFIG, then ~/.config/rust-vmnet-proxy/config.yaml, then built-in defaults)");
    println!("  --help, -h        this help");
    println!("  --version         print version");
    println!("subcommands:");
    println!("  setup-vmnet       bring up the root socket_vmnet daemon (sudo prompt once)");
    println!("  teardown-vmnet    stop the socket_vmnet daemon and remove its plist");
    println!("  install-mac       install as a macOS LaunchAgent (or brew services)");
    println!("  update-mac        refresh the installed binary and restart");
    println!("  uninstall-mac     stop and remove the LaunchAgent (config and logs kept)");
    println!("  start-mac         start the LaunchAgent");
    println!("  stop-mac          stop the LaunchAgent");
    println!("  restart-mac       restart the LaunchAgent");
}

fn run_service_subcommand(verb: &str) -> i32 {
    let result = match verb {
        "install-mac" => service::install_macos(),
        "update-mac" => service::update_macos(),
        "uninstall-mac" => service::uninstall_macos(),
        "start-mac" => service::start_macos(),
        "stop-mac" => service::stop_macos(),
        "restart-mac" => service::restart_macos(),
        _ => unreachable!(),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{verb}: {e}");
            1
        }
    }
}

fn parse_config_flag() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" {
            return args.get(i + 1).cloned();
        }
        if let Some(v) = args[i].strip_prefix("--config=") {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(String::as_str) {
        Some("--help") | Some("-h") => {
            print_usage();
            return;
        }
        Some("--version") => {
            println!("rust-vmnet-proxy {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(
            verb @ ("install-mac" | "update-mac" | "uninstall-mac" | "start-mac" | "stop-mac"
            | "restart-mac"),
        ) => {
            // extra args (e.g. a stray --help) are rejected so a typo can't
            // fall through into the proxy run path
            if argv.len() > 2 {
                print_usage();
                std::process::exit(2);
            }
            std::process::exit(run_service_subcommand(verb));
        }
        Some(verb @ ("setup-vmnet" | "teardown-vmnet")) => {
            // --config is resolved globally, so strip it from the sub-args
            // before flag parsing; anything parse_flags does not consume is
            // a typo and must not fall through to setup
            let mut sub_args: Vec<String> = Vec::new();
            let mut skip_value = false;
            for a in &argv[2..] {
                if skip_value {
                    skip_value = false;
                    continue;
                }
                if a == "--config" {
                    skip_value = true;
                    continue;
                }
                if a.starts_with("--config=") {
                    continue;
                }
                sub_args.push(a.clone());
            }
            let (interface, rest) = match setup_vmnet::parse_flags(&sub_args) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    print_usage();
                    std::process::exit(2);
                }
            };
            if !rest.is_empty() {
                eprintln!("unknown argument: {}", rest[0]);
                print_usage();
                std::process::exit(2);
            }
            let cmd = if verb == "setup-vmnet" {
                setup_vmnet::VmnetCmd::Setup
            } else {
                setup_vmnet::VmnetCmd::Teardown
            };
            std::process::exit(setup_vmnet::run(
                cmd,
                parse_config_flag().as_deref(),
                interface.as_deref(),
            ));
        }
        _ => {}
    }

    // Config loads before the logger: the logging block decides where logs
    // go. Until init runs, log macros are no-ops; failures here print to
    // stderr raw, which launchd still captures.
    let config_path = parse_config_flag();
    let cfg = match config::Config::load(config_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    logging::init(&cfg.logging);

    install_signal_handlers();

    let mac = cfg.effective_mac();
    log::info!(
        "rust-vmnet-proxy starting: socks on {}, vmnet {} (mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
        cfg.socks_listen,
        cfg.vmnet_socket,
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    let tuning = config::Tuning::from_power_mode(cfg.power_mode);
    let socks_tuning = socks5::SocksTuning {
        accept_interval: tuning.accept_interval,
        splice_timeout: tuning.splice_timeout,
    };

    let legs = sshlegs::spawn_legs(&cfg.ssh_legs);
    if let Err(e) = legchain::spawn_chain_legs(&cfg.ssh_legs, socks_tuning.clone()) {
        eprintln!("chained legs error: {e}");
        std::process::exit(1);
    }
    if cfg.from_defaults && cfg.ssh_legs.is_empty() {
        log::warn!(
            "no config file found and no ssh legs configured: direct SOCKS5 on {} is the only active listener",
            cfg.socks_listen
        );
    }

    let net = match netloop::spawn(&cfg.vmnet_socket, mac, tuning, cfg.relays.clone()) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("netloop error: {e}");
            std::process::exit(1);
        }
    };

    let listener = match socks5::bind(cfg.socks_listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("socks bind {} failed: {e}", cfg.socks_listen);
            std::process::exit(1);
        }
    };

    let socks_api = net.api.clone();
    let socks_handle = std::thread::Builder::new()
        .name("socks5-listener".into())
        .spawn(move || socks5::serve(listener, socks_api, socks_tuning))
        .expect("spawn socks listener");

    // Main waits: netloop exit (vmnet gone) or shutdown signal. The waiter
    // thread consumes the JoinHandle; its liveness is the netloop liveness.
    let netloop_done = Arc::new(AtomicBool::new(false));
    let done_flag = Arc::clone(&netloop_done);
    std::thread::Builder::new()
        .name("netloop-waiter".into())
        .spawn(move || {
            let _ = net.join.join();
            done_flag.store(true, Ordering::SeqCst);
        })
        .expect("spawn waiter");

    loop {
        if !RUNNING.load(Ordering::SeqCst) {
            log::info!("shutdown signal received");
            break;
        }
        if netloop_done.load(Ordering::SeqCst) {
            log::error!("netloop exited");
            legs.shutdown();
            std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    legs.shutdown();
    socks_handle.join().ok();
    log::info!("rust-vmnet-proxy stopped");
}
