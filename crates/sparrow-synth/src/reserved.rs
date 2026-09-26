//! Values reserved for documentation (spec Addendum B.4): the only domains, addresses and
//! product GUIDs a generated tree may contain, the allocator that hands addresses out, and the
//! scanner tests run over every generated file.
//!
//! - IPv4: RFC 5737 TEST-NET-1/2/3; each block has a role (`Net`).
//! - IPv6: RFC 3849 2001:db8::/32.
//! - Domains: RFC 2606 / RFC 6761 (`*.example`, `*.test`, `example.com|net|org`).

use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

/// RFC 5737 blocks, in `Net` order.
pub const V4_BLOCKS: [[u8; 3]; 3] = [[192, 0, 2], [198, 51, 100], [203, 0, 113]];

/// Role of an address block, so an analyst reading a tree can tell traffic apart:
/// the tenant's offices and homes, travel / mobile / cloud look-alikes, the attacker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Net {
    Office,
    Roaming,
    Attacker,
}

impl Net {
    fn index(self) -> usize {
        match self {
            Net::Office => 0,
            Net::Roaming => 1,
            Net::Attacker => 2,
        }
    }
}

/// Microsoft product constants the collectors compare against or that appear in every real
/// tenant's data (first-party application ids, Microsoft's own tenant ids). They identify
/// products, not customers, so generated data may use them.
pub const WELL_KNOWN_GUIDS: &[(&str, &str)] = &[
    (
        "00000002-0000-0ff1-ce00-000000000000",
        "Office 365 Exchange Online",
    ),
    ("00000003-0000-0000-c000-000000000000", "Microsoft Graph"),
    (
        "00000003-0000-0ff1-ce00-000000000000",
        "Office 365 SharePoint Online",
    ),
    (
        "00000006-0000-0ff1-ce00-000000000000",
        "Microsoft Office 365 Portal",
    ),
    ("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "Microsoft Teams"),
    ("4765445b-32c6-49b0-83e6-1d93765276ca", "OfficeHome"),
    ("d3590ed6-52b3-4102-aeff-aad2292ab01c", "Microsoft Office"),
    (
        "72f988bf-86f1-41af-91ab-2d7cd011db47",
        "Microsoft corporate tenant",
    ),
    (
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        "Microsoft Services tenant",
    ),
];

/// Microsoft product URLs that appear verbatim in collector output (namespaces, not hosts a
/// customer owns): `scan_text` skips them like the well-known GUIDs. The PowerShell
/// serialization namespace heads every `Export-Clixml` file (Hawk 3's `Tenant/XML/*.xml`).
pub const WELL_KNOWN_URLS: &[&str] = &["http://schemas.microsoft.com/powershell/2004/04"];

pub fn is_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            V4_BLOCKS.iter().any(|b| o[..3] == b[..])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

pub fn is_reserved_domain(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.split('.').any(str::is_empty) {
        return false;
    }
    d == "example"
        || d == "test"
        || d.ends_with(".example")
        || d.ends_with(".test")
        || ["example.com", "example.net", "example.org"]
            .iter()
            .any(|r| d == *r || d.ends_with(&format!(".{r}")))
}

/// Hands out distinct documentation addresses per role: host numbers 1..=254 of the role's
/// /24 (wrapping after 254), and IPv6 `2001:db8:<role>:<n>::1`.
#[derive(Debug, Clone, Default)]
pub struct IpAllocator {
    v4: [u32; 3],
    v6: [u32; 3],
}

impl IpAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn v4(&mut self, net: Net) -> Ipv4Addr {
        let i = net.index();
        let host = (self.v4[i] % 254 + 1) as u8;
        self.v4[i] += 1;
        let b = V4_BLOCKS[i];
        Ipv4Addr::new(b[0], b[1], b[2], host)
    }

    pub fn v6(&mut self, net: Net) -> Ipv6Addr {
        let i = net.index();
        self.v6[i] += 1;
        let n = self.v6[i];
        Ipv6Addr::new(
            0x2001,
            0x0db8,
            i as u16 + 1,
            (n >> 16) as u16,
            n as u16,
            0,
            0,
            1,
        )
    }
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

/// Every non-reserved IPv4 / IPv6 address, e-mail domain and URL host in `text`, as
/// `"<kind> <value>"`. Dotted quads that follow `/` or a letter/digit (`Chrome/128.0.0.0`) or
/// a `Version="` attribute are version numbers and are ignored; `WELL_KNOWN_URLS` are skipped.
pub fn scan_text(text: &str) -> Vec<String> {
    let mut owned = None;
    for url in WELL_KNOWN_URLS {
        if text.contains(url) {
            owned = Some(owned.as_deref().unwrap_or(text).replace(url, " "));
        }
    }
    let text = owned.as_deref().unwrap_or(text);
    static V4: OnceLock<Regex> = OnceLock::new();
    static V6: OnceLock<Regex> = OnceLock::new();
    static MAIL: OnceLock<Regex> = OnceLock::new();
    static URL: OnceLock<Regex> = OnceLock::new();
    let mut out = Vec::new();
    for c in re(
        &V4,
        r"(?:^|[^0-9A-Za-z./_-])((?:\d{1,3}\.){3}\d{1,3})(?:$|[^0-9A-Za-z.])",
    )
    .captures_iter(text)
    {
        // `Version="1.1.0.1"` (a CliXml header) is a version number, not an address.
        let before = &text[..c.get(1).map_or(0, |m| m.start())];
        if before.ends_with("Version=\"") {
            continue;
        }
        if let Ok(ip) = c[1].parse::<Ipv4Addr>() {
            if !is_reserved_ip(&IpAddr::V4(ip)) {
                out.push(format!("ipv4 {ip}"));
            }
        }
    }
    for m in re(&V6, r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}").find_iter(text) {
        if let Ok(ip) = m.as_str().parse::<Ipv6Addr>() {
            if !is_reserved_ip(&IpAddr::V6(ip)) {
                out.push(format!("ipv6 {ip}"));
            }
        }
    }
    for c in re(
        &MAIL,
        r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)",
    )
    .captures_iter(text)
    {
        if !is_reserved_domain(&c[1]) {
            out.push(format!("email-domain {}", &c[1]));
        }
    }
    for c in re(&URL, r#"https?://([^/\s"'<>:?#]+)"#).captures_iter(text) {
        let host = &c[1];
        let ok =
            host.parse::<IpAddr>().is_ok_and(|ip| is_reserved_ip(&ip)) || is_reserved_domain(host);
        if !ok {
            out.push(format!("url-host {host}"));
        }
    }
    out
}
