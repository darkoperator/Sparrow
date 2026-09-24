//! IP address and UPN normalization (spec §5 conventions).

use std::net::{IpAddr, Ipv4Addr};

/// Normalized IP text: brackets and ports removed, IPv6 lower-cased and compressed.
/// Values that are not IP addresses are kept, trimmed and lower-cased; empty gives `None`.
pub fn normalize_ip(raw: &str) -> Option<String> {
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
        return Some(ip.to_string());
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

fn canonical(s: &str) -> String {
    s.parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| s.to_ascii_lowercase())
}

/// Trimmed, lower-cased user principal name; `None` when empty.
pub fn normalize_upn(raw: &str) -> Option<String> {
    let s = raw.trim();
    (!s.is_empty()).then(|| s.to_lowercase())
}
