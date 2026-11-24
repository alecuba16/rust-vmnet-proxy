use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::thread;

use crate::config::{HttpHeaders, LegSource};
use crate::socks5::{read_greeting, read_request, send_reply, SocksHsError, SocksTuning};

const SPLICE_CHUNK: usize = 16 * 1024;
/// First-request inspection window. A request whose headers don't end within
/// this many bytes is passed through untouched.
const HTTP_SNIFF_LIMIT: usize = 8192;

/// HTTP/1.x request line: uppercase method token (3-8 A-Z chars), space,
/// target, space, "HTTP/1.0" or "HTTP/1.1". Checked against the buffered
/// first bytes so TLS (0x16 ClientHello), SSH ("SSH-"), and HTTP/2
/// prior-knowledge ("PRI * HTTP/2.0") never match.
fn is_http_request_line(line: &str) -> bool {
    let mut parts = line.splitn(3, ' ');
    // splitn always yields at least one piece, possibly empty; the empty
    // method fails the 3..=8 length check below
    let method = parts.next().unwrap_or("");
    if !(3..=8).contains(&method.len()) || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    let target = parts.next().unwrap_or("");
    if target.is_empty() {
        return false;
    }
    matches!(parts.next(), Some("HTTP/1.0") | Some("HTTP/1.1"))
}

/// Header block helpers operate on the bytes before the final CRLFCRLF,
/// split into CRLF-separated lines (the block always ends with CRLF, so a
/// trailing empty piece is dropped).
fn header_lines(block: &[u8]) -> Vec<&[u8]> {
    block
        .split(|&b| b == b'\n')
        // each split piece ends with \r (CRLF), except a final piece that
        // has no trailing newline at all
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect()
}

/// Find a named header line. Returns (line index, offset of the value
/// within the block, trimmed value length).
fn find_header(block: &[u8], name: &str) -> Option<(usize, usize, usize)> {
    for (i, line) in header_lines(block).iter().enumerate() {
        let text = String::from_utf8_lossy(line);
        let Some((hname, _)) = text.split_once(':') else {
            continue;
        };
        if !hname.trim().eq_ignore_ascii_case(name) {
            continue;
        }
        // byte offsets, not trimmed-string offsets: the value runs from
        // the first non-space byte after the colon to the line end
        let line_start = line.as_ptr() as usize - block.as_ptr() as usize;
        let colon = line_start + text.find(':').unwrap();
        let mut vstart = colon + 1;
        while vstart < line_start + line.len() && block[vstart] == b' ' {
            vstart += 1;
        }
        let mut vend = line_start + line.len();
        while vend > vstart && (block[vend - 1] == b' ' || block[vend - 1] == b'\r') {
            vend -= 1;
        }
        return Some((i, vstart, vend - vstart));
    }
    None
}

/// Rewrite the first client request with the forwarding headers. `buf` is
/// the complete first bytes up to and including CRLFCRLF. Returns None when
/// the bytes are not a plaintext HTTP/1.x request (passthrough, untouched).
fn inject_http_headers(buf: &[u8], src_ip: IpAddr, cfg: HttpHeaders) -> Option<Vec<u8>> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let block = &buf[..end];
    let first_line_end = block.iter().position(|&b| b == b'\n')?;
    let request_line = String::from_utf8_lossy(&block[..first_line_end]);
    let request_line = request_line.trim_end_matches('\r');
    if !is_http_request_line(request_line) {
        return None;
    }
    let host = find_header(block, "Host").map(|(_, off, len)| block[off..off + len].to_vec());
    let src = src_ip.to_string();
    let fwd_for = match src_ip {
        IpAddr::V6(_) => format!("[{src}]"),
        IpAddr::V4(_) => src.clone(),
    };

    let mut out = block.to_vec();
    // block excludes the final CRLF of the last header line (it was the
    // first half of the CRLFCRLF terminator), terminate it before appending
    out.extend_from_slice(b"\r\n");
    let mut added = Vec::new();
    if cfg.x_forwarded_for {
        if let Some((_, vstart, vlen)) = find_header(block, "X-Forwarded-For") {
            let old = String::from_utf8_lossy(&block[vstart..vstart + vlen]).into_owned();
            // chain semantics: rewrite the value in place, ", <src>" appended
            out.splice(vstart..vstart + vlen, format!("{old}, {src_ip}").bytes());
        } else {
            added.push(format!("X-Forwarded-For: {src}\r\n"));
        }
    }
    if cfg.x_real_ip && find_header(block, "X-Real-IP").is_none() {
        added.push(format!("X-Real-IP: {src}\r\n"));
    }
    if cfg.x_forwarded_host {
        if let Some(h) = &host {
            if find_header(block, "X-Forwarded-Host").is_none() {
                added.push(format!(
                    "X-Forwarded-Host: {}\r\n",
                    String::from_utf8_lossy(h)
                ));
            }
        }
    }
    if cfg.x_forwarded_proto && find_header(block, "X-Forwarded-Proto").is_none() {
        added.push("X-Forwarded-Proto: http\r\n".into());
    }
    if cfg.forwarded && find_header(block, "Forwarded").is_none() {
        let host_part = host
            .as_deref()
            .map(|h| format!(";host={}", String::from_utf8_lossy(h)))
            .unwrap_or_default();
        added.push(format!(
            "Forwarded: for={fwd_for}{host_part};proto=http\r\n"
        ));
    }
    for line in added {
        out.extend_from_slice(line.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    // tail bytes after CRLFCRLF (e.g. a request body in the same read)
    out.extend_from_slice(&buf[end + 4..]);
    Some(out)
}

/// PROXY protocol v1 header line. src is the accepted client's peer
/// address, dst_ip the resolved target when the client sent a literal IP,
/// None when it sent a hostname (the ssh -D upstream resolves it, we never
/// see the address). PROXY v1 has no "unknown dst" token inside a TCP4/TCP6
/// line, so hostname targets emit a family-matched placeholder (0.0.0.0
/// for TCP4, :: for TCP6): receivers that care use src, which is always
/// concrete. Non-IP peers get the UNKNOWN line, which
/// per spec tells the receiver to fall back to the immediate peer while
/// the connection itself stays valid.
fn proxy_v1_line(src: Option<SocketAddr>, dst_ip: Option<IpAddr>, dst_port: u16) -> String {
    let Some(src) = src else {
        return "PROXY UNKNOWN\r\n".into();
    };
    let src_ip = src.ip();
    let dst = match dst_ip {
        Some(ip) => ip.to_string(),
        // Family-matched placeholder when the target is a hostname: TCP6
        // lines carry IPv6 literals per spec, so "::" there, "0.0.0.0"
        // in TCP4 lines. Receivers that care use src, always concrete.
        None => match src_ip {
            IpAddr::V4(_) => "0.0.0.0".to_string(),
            IpAddr::V6(_) => "::".to_string(),
        },
    };
    match src_ip {
        IpAddr::V4(_) => format!("PROXY TCP4 {src_ip} {dst} {} {dst_port}\r\n", src.port()),
        IpAddr::V6(_) => format!("PROXY TCP6 {src_ip} {dst} {} {dst_port}\r\n", src.port()),
    }
}

/// Dial the leg's ssh -D SOCKS5 listener on 127.0.0.1:<upstream> and issue
/// a no-auth CONNECT for the client's original target. Hostnames stay
/// hostnames (ATYP 0x03): ssh -D resolves them on the bastion side.
fn upstream_connect(
    upstream_port: u16,
    dst_ip: Option<IpAddr>,
    name: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut up = TcpStream::connect(("127.0.0.1", upstream_port))?;
    let _ = up.set_nodelay(true);

    up.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    up.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(std::io::Error::other("upstream socks no-auth refused"));
    }

    let mut req = vec![0x05, 0x01, 0x00];
    match dst_ip {
        Some(IpAddr::V4(v4)) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
        None => {
            if name.is_empty() || name.len() > 255 {
                return Err(std::io::Error::other("bad target hostname"));
            }
            req.push(0x03);
            req.push(name.len() as u8);
            req.extend_from_slice(name.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    up.write_all(&req)?;

    let mut head = [0u8; 4];
    up.read_exact(&mut head)?;
    let tail = match head[3] {
        0x01 => 6,
        0x03 => {
            let mut len = [0u8; 1];
            up.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        0x04 => 18,
        _ => return Err(std::io::Error::other("upstream socks bad reply atyp")),
    };
    let mut rest = vec![0u8; tail];
    up.read_exact(&mut rest)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other("upstream socks connect failed"));
    }
    Ok(up)
}

fn handle_chain_client(
    mut client: TcpStream,
    peer: Option<SocketAddr>,
    listen: u16,
    upstream_port: u16,
    http_headers: Option<HttpHeaders>,
) {
    let _ = client.set_nodelay(true);
    if !read_greeting(&mut client) {
        return;
    }
    let (_cmd, ip, name, port) = match read_request(&mut client) {
        Ok(r) => r,
        Err(SocksHsError::Unsupported(rep)) => {
            send_reply(&mut client, rep);
            return;
        }
        Err(SocksHsError::Io) => return,
    };
    let target = if name.is_empty() {
        format!("{}:{}", ip.map(|i| i.to_string()).unwrap_or_default(), port)
    } else {
        format!("{name}:{port}")
    };

    let mut up = match upstream_connect(upstream_port, ip, &name, port) {
        Ok(u) => u,
        Err(e) => {
            log::info!("leg {listen} upstream connect {target} failed: {e}");
            send_reply(&mut client, 0x01);
            return;
        }
    };
    if up
        .write_all(proxy_v1_line(peer, ip, port).as_bytes())
        .is_err()
    {
        send_reply(&mut client, 0x01);
        return;
    }
    if !send_reply(&mut client, 0x00) {
        return;
    }
    log::info!(
        "CONNECT {} -> {target} [leg {listen} identify]",
        peer.map(|p| p.to_string())
            .unwrap_or_else(|| "unknown".into())
    );

    let peer_ip = peer.map(|p| p.ip());
    // Per-direction threads like the direct legs: one thread reads the
    // client and writes upstream; this thread reads upstream and writes
    // the client. Both sides need a clone since each socket is read by one
    // and written by the other.
    let up_read = match up.try_clone() {
        Ok(u) => u,
        Err(_) => return,
    };
    let mut up_r = match client.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let up_thread = thread::Builder::new()
        .name(format!("leg-{listen}-up"))
        .spawn(move || {
            let mut buf = [0u8; SPLICE_CHUNK];
            let mut first = Vec::new();
            let mut sniffing = http_headers.is_some();
            let cfg = http_headers.unwrap_or_default();
            loop {
                match up_r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = &buf[..n];
                        if sniffing {
                            // Decision is made purely on buffered bytes:
                            // non-HTTP traffic flushes as soon as it clearly
                            // isn't a request (TLS ClientHello 0x16, SSH
                            // banner, HTTP/2 PRI, or the 8192-byte window
                            // fills), so passthrough adds no delay beyond
                            // the first read.
                            first.extend_from_slice(chunk);
                            let verdict = if first.windows(4).any(|w| w == b"\r\n\r\n") {
                                peer_ip.and_then(|ip| inject_http_headers(&first, ip, cfg))
                            } else if first.len() >= HTTP_SNIFF_LIMIT
                                || first.first() == Some(&0x16)
                                || first.starts_with(b"SSH-")
                                || first.starts_with(b"PRI ")
                            {
                                Some(first.clone())
                            } else {
                                None
                            };
                            if let Some(bytes) = verdict {
                                if up.write_all(&bytes).is_err() {
                                    break;
                                }
                                first.clear();
                                sniffing = false;
                            }
                            continue;
                        }
                        if up.write_all(chunk).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // EOF or client death: close the upstream write side so the
            // bastion sees FIN instead of a half-open idle connection.
            if !first.is_empty() {
                let _ = up.write_all(&first);
            }
            let _ = up.shutdown(std::net::Shutdown::Write);
        })
        .expect("spawn up thread");

    let mut up_read = up_read;
    let mut buf = [0u8; SPLICE_CHUNK];
    loop {
        match up_read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    // The up thread parks in client.read until the client gives up;
    // shutdown unblocks it and propagates EOF upstream.
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = up_thread.join();
}

/// Chained (identify) leg listener: accepts SOCKS5 on bind:listen, dials
/// the ssh -D forward on the private upstream port, prepends the PROXY v1
/// header, then splices.
pub fn serve(
    listener: TcpListener,
    listen: u16,
    upstream_port: u16,
    http_headers: Option<HttpHeaders>,
    tuning: SocksTuning,
) {
    let _ = listener.set_nonblocking(true);
    loop {
        if !crate::RUNNING.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match listener.accept() {
            Ok((client, peer)) => {
                let _ = client.set_nonblocking(false);
                thread::Builder::new()
                    .name(format!("leg-{listen}-client"))
                    .spawn(move || {
                        handle_chain_client(client, Some(peer), listen, upstream_port, http_headers)
                    })
                    .ok();
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                crate::socks5::park_accept(&listener, tuning.accept_interval);
            }
            Err(e) => {
                log::error!("leg {listen} chained accept failed: {e}");
                return;
            }
        }
    }
}

/// Bind and spawn the chained listener for every identify leg. Returns the
/// number of listeners started, or the first bind error.
pub fn spawn_chain_legs(
    legs: &[crate::config::SshLeg],
    tuning: SocksTuning,
) -> Result<usize, String> {
    let mut started = 0;
    for leg in legs.iter().filter(|l| l.source == LegSource::Identify) {
        let addr = SocketAddr::new(leg.bind, leg.listen);
        let listener = TcpListener::bind(addr)
            .map_err(|e| format!("leg {} chained bind {addr} failed: {e}", leg.listen))?;
        let listen = leg.listen;
        let upstream = leg.upstream;
        let http_headers = leg.http_headers;
        let t = tuning.clone();
        thread::Builder::new()
            .name(format!("leg-{listen}-chain"))
            .spawn(move || serve(listener, listen, upstream, http_headers, t))
            .map_err(|e| format!("spawn leg {listen} chained listener: {e}"))?;
        started += 1;
    }
    Ok(started)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4], p: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(a), p)
    }

    fn v6(seg: u16, p: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from([0, 0, 0, 0, 0, 0, 0, seg]), p)
    }

    #[test]
    fn tcp4_with_dst_ip() {
        let line = proxy_v1_line(
            Some(v4([192, 168, 1, 42], 51000)),
            Some(IpAddr::from([10, 0, 0, 5])),
            443,
        );
        assert_eq!(line, "PROXY TCP4 192.168.1.42 10.0.0.5 51000 443\r\n");
    }

    #[test]
    fn tcp4_hostname_dst_placeholder() {
        let line = proxy_v1_line(Some(v4([172, 16, 0, 9], 40001)), None, 8080);
        assert_eq!(line, "PROXY TCP4 172.16.0.9 0.0.0.0 40001 8080\r\n");
    }

    #[test]
    fn tcp6_src() {
        let line = proxy_v1_line(Some(v6(1, 51000)), None, 443);
        assert_eq!(line, "PROXY TCP6 ::1 :: 51000 443\r\n");
    }

    #[test]
    fn unknown_peer() {
        let line = proxy_v1_line(None, Some(IpAddr::from([10, 0, 0, 5])), 443);
        assert_eq!(line, "PROXY UNKNOWN\r\n");
    }

    fn all_headers() -> HttpHeaders {
        HttpHeaders {
            x_forwarded_for: true,
            x_real_ip: true,
            x_forwarded_host: true,
            x_forwarded_proto: true,
            forwarded: true,
        }
    }

    #[test]
    fn http_inject_all_headers() {
        let req = b"GET / HTTP/1.1\r\nHost: internal.example\r\nUser-Agent: t\r\n\r\nbody";
        let out = inject_http_headers(req, IpAddr::from([192, 168, 7, 9]), all_headers()).unwrap();
        let expect = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: internal.example\r\n",
            "User-Agent: t\r\n",
            "X-Forwarded-For: 192.168.7.9\r\n",
            "X-Real-IP: 192.168.7.9\r\n",
            "X-Forwarded-Host: internal.example\r\n",
            "X-Forwarded-Proto: http\r\n",
            "Forwarded: for=192.168.7.9;host=internal.example;proto=http\r\n",
            "\r\n",
            "body"
        );
        assert_eq!(String::from_utf8_lossy(&out), expect);
    }

    #[test]
    fn http_inject_xff_append_chain() {
        let req = b"GET / HTTP/1.1\r\nHost: h\r\nx-forwarded-for: 10.1.2.3\r\n\r\n";
        let out = inject_http_headers(req, IpAddr::from([192, 168, 7, 9]), all_headers()).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("x-forwarded-for: 10.1.2.3, 192.168.7.9\r\n"));
        // only one XFF line, the existing one rewritten
        assert_eq!(text.matches("orwarded-for").count(), 1);
        assert!(!text.contains("X-Forwarded-For:"));
    }

    #[test]
    fn http_inject_forwarded_ipv6_brackets() {
        let req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let ip = IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
        let out = inject_http_headers(req, ip, all_headers()).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Forwarded: for=[fe80::1];host=h;proto=http\r\n"));
        // XFF/X-Real-IP use the bare form
        assert!(text.contains("X-Forwarded-For: fe80::1\r\n"));
    }

    #[test]
    fn http_inject_proto_disabled() {
        let cfg = HttpHeaders {
            x_forwarded_proto: false,
            ..all_headers()
        };
        let req = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let out = inject_http_headers(req, IpAddr::from([192, 168, 7, 9]), cfg).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("X-Forwarded-Proto"));
        let expect = concat!(
            "GET / HTTP/1.1\r\n",
            "Host: h\r\n",
            "X-Forwarded-For: 192.168.7.9\r\n",
            "X-Real-IP: 192.168.7.9\r\n",
            "X-Forwarded-Host: h\r\n",
            "Forwarded: for=192.168.7.9;host=h;proto=http\r\n",
            "\r\n"
        );
        assert_eq!(text, expect);
    }

    #[test]
    fn http_passthrough_tls_and_h2() {
        let cfg = all_headers();
        // TLS ClientHello first byte
        assert_eq!(
            inject_http_headers(b"\x16\x03\x01...", IpAddr::from([10, 0, 0, 1]), cfg),
            None
        );
        // HTTP/2 prior knowledge
        assert_eq!(
            inject_http_headers(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                IpAddr::from([10, 0, 0, 1]),
                cfg
            ),
            None
        );
        // SSH banner
        assert_eq!(
            inject_http_headers(
                b"SSH-2.0-OpenSSH_9.0\r\n\r\n",
                IpAddr::from([10, 0, 0, 1]),
                cfg
            ),
            None
        );
        // binary junk with CRLFCRLF inside
        assert_eq!(
            inject_http_headers(
                b"\x00\x01\x02\r\n\r\nrest",
                IpAddr::from([10, 0, 0, 1]),
                cfg
            ),
            None
        );
    }

    #[test]
    fn http_inject_forwarded_no_host_omits_host_part() {
        // no Host header: Forwarded carries only for= and proto=
        let req = b"GET / HTTP/1.1\r\nX-Real-IP: 1.2.3.4\r\nForwarded: for=9.9.9.9\r\nX-Forwarded-Host: other\r\nX-Forwarded-Proto: https\r\n\r\n";
        let out = inject_http_headers(req, IpAddr::from([192, 168, 7, 9]), all_headers()).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("X-Forwarded-For: 192.168.7.9\r\n"));
        assert!(!text.contains("X-Real-IP: 192"));
        assert!(!text.contains("X-Forwarded-Host: 192"));
        assert!(!text.contains("X-Forwarded-Proto: http\r\n"));
        // Forwarded already present: kept as-is, not duplicated
        assert_eq!(text.matches("Forwarded:").count(), 1);
    }

    #[test]
    fn is_http_request_line_edge_cases() {
        assert!(is_http_request_line("GET / HTTP/1.1"));
        assert!(is_http_request_line("CONNECT host:443 HTTP/1.0"));
        assert!(!is_http_request_line(""));
        assert!(!is_http_request_line("GET"));
        assert!(!is_http_request_line("get / HTTP/1.1"));
        assert!(!is_http_request_line("PO / HTTP/1.1"));
        assert!(!is_http_request_line("VERYLONGMETHOD / HTTP/1.1"));
        assert!(!is_http_request_line("GET  HTTP/1.1"));
        assert!(!is_http_request_line("GET / HTTP/2.0"));
        assert!(!is_http_request_line("GET /"));
    }

    #[test]
    fn header_lines_split_and_strip() {
        let block = b"A: 1 \r\nB:2\r\nno-colon line";
        let lines = header_lines(block);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], b"A: 1 ");
        assert_eq!(lines[2], b"no-colon line");
        // leading spaces after the colon and trailing space/CR before the
        // value end are both trimmed
        let (i, off, len) = find_header(block, "A").unwrap();
        assert_eq!(i, 0);
        assert_eq!(&block[off..off + len], b"1");
        let (_, off2, len2) = find_header(block, "b").unwrap();
        assert_eq!(&block[off2..off2 + len2], b"2");
        assert!(find_header(block, "no-colon line").is_none());
        assert!(find_header(block, "C").is_none());
    }

    #[test]
    fn http_inject_splices_tail_body() {
        // request line alone, body bytes already in the same buffer
        let req = b"POST /submit HTTP/1.1\r\nHost: h\r\n\r\nname=value";
        let out = inject_http_headers(req, IpAddr::from([10, 1, 1, 1]), all_headers()).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.ends_with("\r\n\r\nname=value"));
        assert!(text.contains("X-Forwarded-For: 10.1.1.1\r\n"));
    }

    #[test]
    fn http_inject_no_crlfcrlf_is_none() {
        assert_eq!(
            inject_http_headers(
                b"GET / HTTP/1.1\r\nHost: h",
                IpAddr::from([10, 0, 0, 1]),
                all_headers()
            ),
            None
        );
    }

    #[test]
    fn http_inject_bad_request_version_is_none() {
        // full header block with CRLFCRLF, request line parses but is
        // not HTTP/1.x: passthrough
        assert_eq!(
            inject_http_headers(
                b"GET / HTTP/9.9\r\nHost: h\r\n\r\n",
                IpAddr::from([10, 0, 0, 1]),
                all_headers()
            ),
            None
        );
    }

    #[test]
    fn http_inject_xff_disabled_no_host_no_xfh() {
        // x_forwarded_for off and no Host header: only X-Real-IP and
        // Forwarded (without host part) get added
        let cfg = HttpHeaders {
            x_forwarded_for: false,
            x_forwarded_host: true,
            ..all_headers()
        };
        let req = b"GET / HTTP/1.1\r\nX-Real-IP: 1.2.3.4\r\n\r\n";
        let out = inject_http_headers(req, IpAddr::from([192, 168, 7, 9]), cfg).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("X-Forwarded-For"));
        assert!(!text.contains("X-Real-IP: 192"));
        assert!(!text.contains("X-Forwarded-Host"));
        assert!(text.contains("Forwarded: for=192.168.7.9;proto=http\r\n"));
    }
}
