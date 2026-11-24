use std::net::IpAddr;

use smoltcp::socket::dns;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{DnsQueryType, IpAddress};

use crate::netloop::state::{DnsPending, NetState};

pub const DNS_TIMEOUT: SmolDuration = SmolDuration::from_secs(5);

/// Start an A-record query for `name`. Fails immediately when no dns socket
/// exists (offline) or the reply channel is dead; otherwise stores the query
/// with a 5s deadline for `service` to resolve.
pub fn start(
    state: &mut NetState,
    name: String,
    reply: std::sync::mpsc::Sender<Option<Vec<IpAddr>>>,
) {
    let Some(handle) = state.dns_handle else {
        let _ = reply.send(None);
        return;
    };
    let sock = state.sockets.get_mut::<dns::Socket>(handle);
    match sock.start_query(state.iface.context(), &name, DnsQueryType::A) {
        Ok(qhandle) => {
            let id = state.next_dns_id;
            state.next_dns_id += 1;
            state.dns_pending.insert(
                id,
                DnsPending {
                    qhandle,
                    reply,
                    deadline: SmolInstant::now() + DNS_TIMEOUT,
                },
            );
        }
        Err(_) => {
            let _ = reply.send(None);
        }
    }
}

/// One pass over pending queries: deliver results, fail and cancel expired
/// ones. Completed/failed slots are freed by get_query_result itself; only
/// deadline expiry needs an explicit cancel_query.
pub fn service(state: &mut NetState) {
    let Some(dns_handle) = state.dns_handle else {
        return;
    };
    let sock = state.sockets.get_mut::<dns::Socket>(dns_handle);
    let now = SmolInstant::now();
    let mut done: Vec<u64> = Vec::new();
    let mut expired: Vec<u64> = Vec::new();
    for (id, pending) in state.dns_pending.iter_mut() {
        match sock.get_query_result(pending.qhandle) {
            Ok(ips) => {
                let addrs: Vec<IpAddr> = ips
                    .iter()
                    .map(|ip| match ip {
                        IpAddress::Ipv4(v4) => IpAddr::V4(*v4),
                    })
                    .collect();
                let _ = pending.reply.send(Some(addrs));
                done.push(*id);
            }
            Err(dns::GetQueryResultError::Pending) => {
                if now > pending.deadline {
                    let _ = pending.reply.send(None);
                    expired.push(*id);
                }
            }
            Err(dns::GetQueryResultError::Failed) => {
                let _ = pending.reply.send(None);
                done.push(*id);
            }
        }
    }
    for id in done {
        state.dns_pending.remove(&id);
    }
    for id in expired {
        if let Some(p) = state.dns_pending.remove(&id) {
            state
                .sockets
                .get_mut::<dns::Socket>(dns_handle)
                .cancel_query(p.qhandle);
        }
    }
}
