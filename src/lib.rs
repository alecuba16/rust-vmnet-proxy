pub mod cmds;
pub mod config;
pub mod legchain;
pub mod logging;
pub mod netloop;
pub mod pipe;
pub mod service;
pub mod setup_vmnet;
pub mod socks5;
pub mod sshlegs;
pub mod vmnet_dev;

use std::sync::atomic::{AtomicBool, Ordering};

pub static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn on_signal(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn install_signal_handlers() {
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
