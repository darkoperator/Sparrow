//! IP address and UPN normalization (spec §5 conventions).

use std::net::{IpAddr, Ipv4Addr};

/// Normalized IP text: brackets and ports removed, IPv4-mapped IPv6 (`::ffff:a.b.c.d`) given
/// as IPv4, other IPv6 lower-cased and compressed.
/// Values that are not IP addresses are kept, trimmed and lower-cased; empty gives `None`.
/// A `,`-separated proxy chain gives its first entry that is an IP address (originating client
/// first); a chain with no address is kept whole like any other non-IP value.
pub fn normalize_ip(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.contains(',') {
        let first_ip = s
            .split(',')
            .filter_map(normalize_one)
            .find(|piece| piece.parse::<IpAddr>().is_ok());
        if first_ip.is_some() {
            return first_ip;
        }
    }
    normalize_one(s)
}

fn normalize_one(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((inner, _)) = rest.split_once(']') {
            return Some(canonical(inner));
        }
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip_text(ip));
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(v4) = host.parse::<Ipv4Addr>() {
                return Some(v4.to_string());
            }
        }
    }
    Some(s.to_ascii_lowercase())
}

fn ip_text(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

fn canonical(s: &str) -> String {
    s.parse::<IpAddr>()
        .map(ip_text)
        .unwrap_or_else(|_| s.to_ascii_lowercase())
}

/// Trimmed, lower-cased user principal name; `None` when empty.
pub fn normalize_upn(raw: &str) -> Option<String> {
    let s = raw.trim();
    (!s.is_empty()).then(|| s.to_lowercase())
}
