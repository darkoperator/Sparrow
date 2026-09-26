//! A minimal MaxMind DB writer, used by tests and by sparrow-synth to write GeoLite2-style
//! databases for generated trees (spec: docs/superpowers/research/maxmind-db-spec.md): IPv6 tree,
//! 24-bit records, no pointers. IPv4 networks sit at ::a.b.c.d/(96 + prefix).

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum MmdbValue {
    Str(String),
    U16(u16),
    U32(u32),
    U64(u64),
    F64(f64),
    Array(Vec<MmdbValue>),
    Map(Vec<(String, MmdbValue)>),
}

fn control(out: &mut Vec<u8>, type_id: u8, size: usize) {
    let (first, extra): (u8, Vec<u8>) = match size {
        0..=28 => (size as u8, vec![]),
        29..=284 => (29, vec![(size - 29) as u8]),
        285..=65_820 => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
        _ => panic!("value too large for the test writer"),
    };
    if type_id <= 7 {
        out.push((type_id << 5) | first);
    } else {
        out.push(first);
        out.push(type_id - 7);
    }
    out.extend(extra);
}

fn uint(out: &mut Vec<u8>, type_id: u8, v: u64, width: usize) {
    let bytes = &v.to_be_bytes()[8 - width..];
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    control(out, type_id, width - skip);
    out.extend(&bytes[skip..]);
}

fn encode(out: &mut Vec<u8>, v: &MmdbValue) {
    match v {
        MmdbValue::Str(s) => {
            control(out, 2, s.len());
            out.extend(s.as_bytes());
        }
        MmdbValue::F64(f) => {
            control(out, 3, 8);
            out.extend(f.to_be_bytes());
        }
        MmdbValue::U16(n) => uint(out, 5, u64::from(*n), 2),
        MmdbValue::U32(n) => uint(out, 6, u64::from(*n), 4),
        MmdbValue::U64(n) => uint(out, 9, *n, 8),
        MmdbValue::Map(pairs) => {
            control(out, 7, pairs.len());
            for (k, v) in pairs {
                encode(out, &MmdbValue::Str(k.clone()));
                encode(out, v);
            }
        }
        MmdbValue::Array(items) => {
            control(out, 11, items.len());
            for i in items {
                encode(out, i);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Rec {
    Empty,
    Node(usize),
    Data(usize),
}

fn bits(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[12..].copy_from_slice(&v4.octets());
            b
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// A MaxMind DB file with `entries` (network address, prefix length, value).
pub fn write_mmdb(
    database_type: &str,
    build_epoch: u64,
    entries: &[(IpAddr, u8, MmdbValue)],
) -> Vec<u8> {
    let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty, Rec::Empty]];
    let mut data = Vec::new();
    for (ip, prefix, value) in entries {
        let offset = data.len();
        encode(&mut data, value);
        let prefix = usize::from(*prefix) + if ip.is_ipv4() { 96 } else { 0 };
        let b = bits(*ip);
        let mut cur = 0usize;
        for i in 0..prefix {
            let bit = usize::from((b[i / 8] >> (7 - i % 8)) & 1);
            if i + 1 == prefix {
                nodes[cur][bit] = Rec::Data(offset);
            } else {
                cur = match nodes[cur][bit] {
                    Rec::Node(n) => n,
                    Rec::Empty => {
                        nodes.push([Rec::Empty, Rec::Empty]);
                        let n = nodes.len() - 1;
                        nodes[cur][bit] = Rec::Node(n);
                        n
                    }
                    Rec::Data(_) => panic!("overlapping networks in the test database"),
                };
            }
        }
    }
    let node_count = nodes.len();
    let mut out = Vec::new();
    for n in &nodes {
        for r in n {
            let v = match r {
                Rec::Empty => node_count,
                Rec::Node(i) => *i,
                Rec::Data(off) => node_count + 16 + off,
            } as u32;
            out.extend(&v.to_be_bytes()[1..]);
        }
    }
    out.extend([0u8; 16]);
    out.extend(data);
    out.extend(b"\xab\xcd\xefMaxMind.com");
    let meta = MmdbValue::Map(vec![
        ("binary_format_major_version".into(), MmdbValue::U16(2)),
        ("binary_format_minor_version".into(), MmdbValue::U16(0)),
        ("build_epoch".into(), MmdbValue::U64(build_epoch)),
        ("database_type".into(), MmdbValue::Str(database_type.into())),
        (
            "description".into(),
            MmdbValue::Map(vec![(
                "en".into(),
                MmdbValue::Str("Sparrow test database".into()),
            )]),
        ),
        ("ip_version".into(), MmdbValue::U16(6)),
        (
            "languages".into(),
            MmdbValue::Array(vec![MmdbValue::Str("en".into())]),
        ),
        ("node_count".into(), MmdbValue::U32(node_count as u32)),
        ("record_size".into(), MmdbValue::U16(24)),
    ]);
    encode(&mut out, &meta);
    out
}

fn names(en: &str) -> MmdbValue {
    MmdbValue::Map(vec![("en".into(), MmdbValue::Str(en.into()))])
}

/// A GeoIP2/GeoLite2 City record.
pub fn city(iso: &str, country: &str, city_name: &str, lat: f64, lon: f64) -> MmdbValue {
    MmdbValue::Map(vec![
        (
            "city".into(),
            MmdbValue::Map(vec![("names".into(), names(city_name))]),
        ),
        (
            "country".into(),
            MmdbValue::Map(vec![
                ("iso_code".into(), MmdbValue::Str(iso.into())),
                ("names".into(), names(country)),
            ]),
        ),
        (
            "location".into(),
            MmdbValue::Map(vec![
                ("latitude".into(), MmdbValue::F64(lat)),
                ("longitude".into(), MmdbValue::F64(lon)),
            ]),
        ),
    ])
}

/// A GeoLite2 ASN record.
pub fn asn(number: u32, org: &str) -> MmdbValue {
    MmdbValue::Map(vec![
        ("autonomous_system_number".into(), MmdbValue::U32(number)),
        (
            "autonomous_system_organization".into(),
            MmdbValue::Str(org.into()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_city_db_maxminddb_can_read() {
        let bytes = write_mmdb(
            "GeoLite2-City",
            1_790_000_000,
            &[(
                "203.0.113.0".parse().unwrap(),
                24,
                city("NG", "Nigeria", "Lagos", 6.45, 3.39),
            )],
        );
        let reader = maxminddb::Reader::from_source(bytes).unwrap();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let record: maxminddb::geoip2::City = reader
            .lookup(ip)
            .unwrap()
            .decode()
            .unwrap()
            .expect("record present");
        assert_eq!(record.country.iso_code, Some("NG"));
        assert_eq!(record.city.names.english, Some("Lagos"));
        assert_eq!(record.location.latitude, Some(6.45));
        assert_eq!(record.location.longitude, Some(3.39));
    }
}
