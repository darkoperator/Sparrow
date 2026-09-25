use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::enrich::ip::{is_private, refresh_ip_intel};
use sparrow_core::fixtures::mmdb::{asn, city, write_mmdb};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn geoip_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let city_db = write_mmdb(
        "GeoLite2-City",
        1_790_000_000,
        &[
            (
                ip("203.0.113.0"),
                24,
                city("NG", "Nigeria", "Lagos", 6.45, 3.39),
            ),
            (
                ip("2001:db8::"),
                32,
                city("DE", "Germany", "Berlin", 52.5, 13.4),
            ),
        ],
    );
    let asn_db = write_mmdb(
        "GeoLite2-ASN",
        1_790_100_000,
        &[
            (ip("203.0.113.0"), 25, asn(14061, "DIGITALOCEAN-ASN")),
            (ip("198.51.100.0"), 24, asn(64500, "EXAMPLE-ISP")),
        ],
    );
    std::fs::write(dir.path().join("GeoLite2-City.mmdb"), city_db).unwrap();
    std::fs::write(dir.path().join("GeoLite2-ASN.mmdb"), asn_db).unwrap();
    dir
}

fn case_with_ips(ips: &[&str]) -> Case {
    let case = Case::in_memory().unwrap();
    case.conn()
        .execute(
            "INSERT INTO collections (collection_id, tool, root_path, sparrow_version) VALUES (1, 'hawk', '/x', 't')",
            [],
        )
        .unwrap();
    for (i, a) in ips.iter().enumerate() {
        case.conn()
            .execute(
                "INSERT INTO signins (record_key, collection_id, ip) VALUES (?, 1, ?)",
                duckdb::params![format!("s{i}"), a],
            )
            .unwrap();
    }
    case
}

fn row(case: &Case, a: &str) -> String {
    case.conn()
        .query_row(
            "SELECT concat_ws('|', country_iso, city, asn, asn_org, is_hosting, hosting_provider, is_microsoft,
                              microsoft_service_area, is_private)
             FROM ip_intel WHERE ip = ?",
            duckdb::params![a],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn private_ranges() {
    for a in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "fe80::1",
        "::ffff:10.0.0.1",
    ] {
        assert!(is_private(ip(a)), "{a}");
    }
    for a in [
        "203.0.113.5",
        "8.8.8.8",
        "2001:db8::1",
        "::ffff:203.0.113.5",
    ] {
        assert!(!is_private(ip(a)), "{a}");
    }
}

#[test]
fn geolocation_asn_hosting_and_microsoft_ranges() {
    let geo = geoip_dir();
    let ms = sparrow_core::data::ms365_ranges(&DataDirs::default()).unwrap();
    let ms_v4 = ms
        .ranges
        .iter()
        .find(|r| !r.cidr.contains(':'))
        .unwrap()
        .cidr
        .clone();
    let ms_ip = ms_v4.split('/').next().unwrap().to_string();
    let case = case_with_ips(&[
        "203.0.113.10",
        "203.0.113.200",
        "2001:db8::5",
        "10.0.0.1",
        &ms_ip,
        "not-an-ip",
    ]);
    let report = refresh_ip_intel(case.conn(), &DataDirs::default(), Some(geo.path())).unwrap();
    assert_eq!(report.ips, 5);
    assert!(
        report.warnings.iter().any(|w| w.contains("1 value")),
        "{:?}",
        report.warnings
    );
    assert_eq!(
        row(&case, "203.0.113.10"),
        "NG|Lagos|14061|DIGITALOCEAN-ASN|true|DigitalOcean|false|false"
    );
    assert_eq!(
        row(&case, "203.0.113.200"),
        "NG|Lagos|false|false",
        "no ASN: is_hosting NULL"
    );
    assert_eq!(row(&case, "2001:db8::5"), "DE|Berlin|false|false");
    assert_eq!(row(&case, "10.0.0.1"), "false|true");
    assert!(
        row(&case, &ms_ip).starts_with("true|"),
        "{}",
        row(&case, &ms_ip)
    );
    let version = report.source_db_version.unwrap();
    assert!(
        version.contains("GeoLite2-City") && version.contains("2026081400"),
        "{version}"
    );
}

#[test]
fn without_geoip_dir_it_warns_and_keeps_stored_geolocation() {
    let geo = geoip_dir();
    let case = case_with_ips(&["203.0.113.10"]);
    refresh_ip_intel(case.conn(), &DataDirs::default(), Some(geo.path())).unwrap();
    let report = refresh_ip_intel(case.conn(), &DataDirs::default(), None).unwrap();
    assert!(report.warnings.iter().any(|w| w.contains("--geoip-dir")));
    assert!(row(&case, "203.0.113.10").starts_with("NG|Lagos|14061"));
}
