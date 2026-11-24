use smoltcp::socket::dhcpv4;
use smoltcp::wire::{IpAddress, IpCidr};

use crate::netloop::state::NetState;

/// One pass over the DHCP socket events. Configured sets the interface
/// address, default route, DNS servers (creating the dns socket on first
/// config), flips online, and logs. Deconfigured tears all of that down.
pub fn service(state: &mut NetState) {
    let event = state
        .sockets
        .get_mut::<dhcpv4::Socket>(state.dhcp_handle)
        .poll();
    match event {
        Some(dhcpv4::Event::Configured(cfg)) => {
            let ip = cfg.address;
            if !state.online {
                log::info!("ONLINE ip={ip}");
                state.online = true;
            }
            state.iface.update_ip_addrs(|addrs| {
                addrs.clear();
                let _ = addrs.push(IpCidr::Ipv4(ip));
            });
            if let Some(router) = cfg.router {
                state.gateway = Some(router);
                let _ = state.iface.routes_mut().add_default_ipv4_route(router);
            } else {
                state.gateway = None;
                state.iface.routes_mut().remove_default_ipv4_route();
            }
            state.dns_servers = cfg.dns_servers.iter().copied().collect();
            if state.dns_handle.is_none() {
                let servers: Vec<IpAddress> = state
                    .dns_servers
                    .iter()
                    .map(|s| IpAddress::Ipv4(*s))
                    .collect();
                let sock = smoltcp::socket::dns::Socket::new(&servers, vec![]);
                state.dns_handle = Some(state.sockets.add(sock));
            } else if let Some(h) = state.dns_handle {
                let servers: Vec<IpAddress> = state
                    .dns_servers
                    .iter()
                    .map(|s| IpAddress::Ipv4(*s))
                    .collect();
                state
                    .sockets
                    .get_mut::<smoltcp::socket::dns::Socket>(h)
                    .update_servers(&servers);
            }
        }
        Some(dhcpv4::Event::Deconfigured) => {
            log::warn!("OFFLINE: DHCP lease lost");
            state.online = false;
            state.gateway = None;
            state.probe_started = None;
            if let Some(h) = state.probe_socket.take() {
                let _ = state.sockets.remove(h);
            }
            state.iface.update_ip_addrs(|addrs| addrs.clear());
            state.iface.routes_mut().remove_default_ipv4_route();
            state.dns_servers.clear();
            if let Some(h) = state.dns_handle {
                let _ = state.sockets.remove(h);
                state.dns_handle = None;
            }
        }
        None => {}
    }
}
