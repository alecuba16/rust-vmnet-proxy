use std::os::unix::net::UnixListener;

use super::*;

#[test]
fn plist_contains_pinned_shape() {
    let plist = render_plist(
        "/opt/homebrew/opt/socket_vmnet",
        "en7",
        "/private/var/run/lima/socket_vmnet.bridged",
    );
    assert!(plist.contains("<string>com.alecuba16.rust-vmnet-proxy-vmnet</string>"));
    assert!(plist.contains("<string>/bin/sh</string>"));
    assert!(plist.contains("<string>-c</string>"));
    assert!(plist.contains("/bin/mkdir -p /private/var/run/lima &amp;&amp; exec /opt/homebrew/opt/socket_vmnet/bin/socket_vmnet --vmnet-mode=bridged --vmnet-interface=en7 /private/var/run/lima/socket_vmnet.bridged"));
    assert!(plist.contains("<key>RunAtLoad</key>"));
    assert!(plist.contains("<key>KeepAlive</key>"));
    assert!(plist.contains("<string>root</string>"));
    assert!(plist.contains("<string>Interactive</string>"));
    assert!(plist.contains("/var/log/socket_vmnet/stdout.log"));
    assert!(plist.contains("/var/log/socket_vmnet/stderr.log"));
}

#[test]
fn plist_interface_and_socket_substituted() {
    let a = render_plist("/pfx", "en0", "/tmp/a.sock");
    let b = render_plist("/pfx", "en1", "/deep/nest/b.sock");
    assert!(a.contains("--vmnet-interface=en0"));
    assert!(b.contains("--vmnet-interface=en1"));
    assert!(a.contains("exec /pfx/bin/socket_vmnet") && a.contains("/tmp/a.sock"));
    assert!(b.contains("/bin/mkdir -p /deep/nest &amp;&amp;") && b.contains("/deep/nest/b.sock"));
    assert!(!a.contains("/deep/nest") && !b.contains("/tmp/a.sock"));
}

#[test]
fn socket_alive_false_for_missing_path() {
    assert!(!socket_alive("/nonexistent/rust-vmnet-proxy-test.sock"));
}

#[test]
fn socket_alive_false_for_stale_file() {
    // a regular file at the socket path must not count as a live socket
    let dir = std::env::temp_dir().join(format!("rust-vmnet-proxy-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let stale = dir.join("stale.sock");
    std::fs::write(&stale, b"x").unwrap();
    assert!(!socket_alive(stale.to_str().unwrap()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn socket_alive_true_for_listening_socket() {
    let dir = std::env::temp_dir().join(format!("rust-vmnet-proxy-test2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("live.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let p = path.to_str().unwrap().to_string();
    assert!(socket_alive(&p));
    drop(listener);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn poll_socket_succeeds_when_listener_appears() {
    let dir = std::env::temp_dir().join(format!("rust-vmnet-proxy-test3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("poll.sock");
    let p = path.to_str().unwrap().to_string();
    // the listener must outlive the poll, otherwise the socket file is
    // orphaned and connects are refused
    let listener = UnixListener::bind(&path).unwrap();
    assert!(poll_socket(&p));
    drop(listener);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn parse_flags_interface_forms() {
    let (iface, rest) = parse_flags(&["--interface".into(), "en5".into(), "extra".into()]).unwrap();
    assert_eq!(iface.as_deref(), Some("en5"));
    assert_eq!(rest, vec!["extra".to_string()]);

    let (iface, _) = parse_flags(&["--interface=en6".into()]).unwrap();
    assert_eq!(iface.as_deref(), Some("en6"));

    let (iface, rest) = parse_flags(&["x".into()]).unwrap();
    assert_eq!(iface, None);
    assert_eq!(rest, vec!["x".to_string()]);
}

#[test]
fn parse_flags_missing_value_is_error() {
    assert!(parse_flags(&["--interface".into()]).is_err());
}
