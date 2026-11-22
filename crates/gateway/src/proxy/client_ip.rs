//! Resolves the real client IP behind trusted proxies.

use std::net::IpAddr;

use hyper::header::HeaderMap;

use crate::ipnet::{any_contains, normalize};
use crate::state::State;
use crate::util::header_str;

/// Client IP: the peer, or — if the peer is a trusted proxy — the right-most untrusted
/// address in the configured header.
pub fn client_ip(state: &State, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = normalize(peer);
    if !any_contains(&state.trusted, peer) {
        return peer;
    }
    let Some(v) = header_str(headers, &state.cfg.client_ip.header) else {
        return peer;
    };
    for part in v.rsplit(',') {
        match part.trim().parse::<IpAddr>() {
            Ok(ip) => {
                let ip = normalize(ip);
                if !any_contains(&state.trusted, ip) {
                    return ip;
                }
            }
            Err(_) => return peer,
        }
    }
    peer
}
