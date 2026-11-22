//! Resolves the real client IP behind trusted proxies, and the forwarding chain the
//! upstream receives in `X-Forwarded-For`.

use std::net::IpAddr;

use hyper::header::HeaderMap;

use crate::ipnet::{any_contains, normalize};
use crate::state::State;

/// Client IP: the peer, or — if the peer is a trusted proxy — the right-most untrusted
/// address in the configured header. Every line of the header counts, in order: with
/// two `X-Forwarded-For` lines, the second one holds the entries added last.
pub fn client_ip(state: &State, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    resolve(state, peer, headers).0
}

/// The hops from the client to the gateway: the client first, then the trusted proxies
/// that relayed the request, ending with the peer. Every address in it is the resolved
/// client or a trusted proxy, so entries a client wrote itself never reach the
/// upstream. When the client is the peer (no trusted proxy in front), it is just the peer.
pub(super) fn forwarding_chain(state: &State, peer: IpAddr, headers: &HeaderMap) -> Vec<IpAddr> {
    resolve(state, peer, headers).1
}

/// Walks the configured header right to left while the entries are trusted proxies.
/// The first untrusted entry is the client. An unparsable entry, or a chain made only
/// of trusted proxies, falls back to the peer.
fn resolve(state: &State, peer: IpAddr, headers: &HeaderMap) -> (IpAddr, Vec<IpAddr>) {
    let peer = normalize(peer);
    if !any_contains(&state.trusted, peer) {
        return (peer, vec![peer]);
    }
    let mut chain = vec![peer]; // right to left
    for part in entries(headers, &state.cfg.client_ip.header)
        .into_iter()
        .rev()
    {
        let Ok(ip) = part.trim().parse::<IpAddr>().map(normalize) else {
            break;
        };
        chain.push(ip);
        if !any_contains(&state.trusted, ip) {
            chain.reverse();
            return (ip, chain);
        }
    }
    (peer, vec![peer])
}

/// The comma-separated entries of every line of `name`, in order. A line that is not
/// visible ASCII becomes one unparsable entry.
fn entries<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for line in headers.get_all(name) {
        match line.to_str() {
            Ok(s) => out.extend(s.split(',')),
            Err(_) => out.push(""),
        }
    }
    out
}
