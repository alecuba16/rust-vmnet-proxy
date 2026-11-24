# smoltcp 0.14 API notes (pinned from the PUBLISHED crates.io 0.14.0 source; the
# xerj git clone at c68ace4 differs in several places below)

## Interface setup
```rust
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

let config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
let mut iface = Interface::new(config, &mut device, Instant::now());
iface.update_ip_addrs(|addrs| { addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED), 0)).ok(); });
iface.routes_mut().add_default_ipv4_route(Ipv4Address(a,b,c,d)).unwrap();
iface.routes_mut().remove_default_ipv4_route();
iface.context() // -> &mut InterfaceInner, needed by socket methods
```
CORRECTIONS vs earlier notes:
- There is NO `IpAddress::UNSPECIFIED`; build the Cidr from `IpAddress::Ipv4(Ipv4Address::UNSPECIFIED)`.
- `smoltcp::wire::Ipv4Address` is an ALIAS for `core::net::Ipv4Addr` (`pub use core::net::Ipv4Addr as Address`):
  no tuple constructor `Ipv4Address(octets)` and no `.octets()` needed. Convert with `IpAddress::Ipv4(std_ip_v4)` directly.

## Poll loop
```rust
let res: PollResult = iface.poll(Instant::now(), &mut device, &mut sockets);
let delay: Option<smoltcp::time::Duration> = iface.poll_delay(Instant::now(), &sockets);
// smoltcp::time::Duration::from_millis(n), .total_millis() -> u64
// Instant::now() -> Instant, Instant + Duration supported
```

## TCP socket
```rust
use smoltcp::socket::tcp;
let rx = tcp::SocketBuffer::new(vec![0u8; 64*1024]); // SocketBuffer = RingBuffer<u8>
let tx = tcp::SocketBuffer::new(vec![0u8; 64*1024]);
let mut sock = tcp::Socket::new(rx, tx);
let remote = smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(remote_v4), port);
sock.connect(iface.context(), remote, smoltcp::wire::IpListenEndpoint::default())
    .map_err(|e| format!("{e:?}"))?; // ConnectError
let handle = sockets.add(sock);
let sock = sockets.get_mut::<tcp::Socket>(handle);
let removed_socket = sockets.remove(handle);
sock.state() -> State::{Closed,Listen,SynSent,Established,CloseWait,LastAck,TimeWait,...}
sock.can_send(), sock.can_recv(), sock.may_send(), sock.may_recv() -> bool
sock.send_slice(&data) -> Result<usize, SendError>
sock.recv_slice(&mut buf) -> Result<usize, RecvError>
sock.send_capacity() / sock.send_queue() -> usize // free tx room = capacity - queue
sock.close() // graceful FIN; sock.abort() // RST
```
- `SocketSet` carries a lifetime: `SocketSet<'a>`. Structs embedding it need `NetState<'a>`.

## DHCPv4
```rust
use smoltcp::socket::dhcpv4;
let handle = sockets.add(dhcpv4::Socket::new());
match sockets.get_mut::<dhcpv4::Socket>(handle).poll() {
    Some(dhcpv4::Event::Configured(cfg)) => {
        // cfg.address: Ipv4Cidr, cfg.router: Option<Ipv4Address>,
        // cfg.dns_servers: Vec<Ipv4Address, N>
    }
    Some(dhcpv4::Event::Deconfigured) => {}
    None => {}
}
```

## DNS
```rust
use smoltcp::socket::dns;
use smoltcp::wire::DnsQueryType; // re-export of wire::dns::Type; dns::Type itself is private
let servers: Vec<IpAddress> = vec![IpAddress::Ipv4(dns_server)];
let sock = dns::Socket::new(&servers, vec![]); // queries storage: Vec<Option<DnsQuery>> grows
let handle = sockets.add(sock);
let qh = sock.start_query(iface.context(), "example.com", DnsQueryType::A)?;
match sock.get_query_result(qh) {
    Ok(ips) => { /* slot freed automatically */ } // Vec<IpAddress, N>; Ipv4 variant is std Ipv4Addr
    Err(dns::GetQueryResultError::Pending) => {}
    Err(dns::GetQueryResultError::Failed) => { /* slot freed automatically */ }
}
sock.cancel_query(qh); // only for queries still Pending (e.g. deadline expiry); panics on a freed slot
```

## socket_vmnet protocol (pinned from main.c)
- SOCK_STREAM unix socket, each message: 4-byte BE length + one Ethernet frame
- No handshake, no client hello. Daemon floods ALL frames to ALL clients:
  filter rx by dst MAC (ours or multicast bit set).
- Frame len 0 or > 1518 = protocol error.

## Misc
- No `From<std::net::SocketAddr>` for IpEndpoint: construct manually.
- std::net::IpAddr::V4(v4) -> IpAddress::Ipv4(v4) directly (Ipv4Address IS std Ipv4Addr).
- SocketSet::new(vec![])  // SocketSet<'a> has a lifetime parameter
- Ipv4Address::UNSPECIFIED = 0.0.0.0 (std Ipv4Addr::UNSPECIFIED)
- macOS libc has NO pipe2: use libc::pipe + fcntl(F_SETFL, O_NONBLOCK).
- phy: RxToken::consume takes `&[u8]` (immutable, `self` by value), TxToken::consume takes `&mut [u8]`.
  Device GATs need explicit `where Self: 'a` bounds and the token types must be `pub`
  (they appear in a public trait impl).
- features needed: std, log, medium-ethernet, proto-ipv4, proto-dhcpv4,
  socket-tcp, socket-udp, socket-dhcpv4, socket-dns, socket-tcp-reno,
  auto-icmp-echo-reply (in Cargo.toml already)
- Cargo.toml already has: smoltcp 0.14 (default-features=false), libc, serde,
  serde_yaml, log, env_logger