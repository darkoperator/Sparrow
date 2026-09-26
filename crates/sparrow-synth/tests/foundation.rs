use sparrow_synth::names::people;
use sparrow_synth::options::{
    Collector, Culture, GenerateOptions, PsEdition, SigninExport, UalFormat,
};
use sparrow_synth::reserved::{IpAllocator, Net, is_reserved_domain, is_reserved_ip, scan_text};
use sparrow_synth::rng::{Rng, stream};
use std::collections::BTreeSet;
use std::net::IpAddr;

#[test]
fn splitmix64_matches_the_reference_vectors() {
    let mut r = Rng::new(0);
    assert_eq!(r.next_u64(), 0xe220_a839_7b1d_cdaf);
    assert_eq!(r.next_u64(), 0x6e78_9e6a_a1b9_65f4);
    assert_eq!(r.next_u64(), 0x06c4_5d18_8009_454f);
}

#[test]
fn streams_are_independent_and_repeatable() {
    let a1: Vec<u64> = (0..4)
        .map({
            let mut r = stream(42, "ual/0");
            move |_| r.next_u64()
        })
        .collect();
    let a2: Vec<u64> = (0..4)
        .map({
            let mut r = stream(42, "ual/0");
            move |_| r.next_u64()
        })
        .collect();
    let b: Vec<u64> = (0..4)
        .map({
            let mut r = stream(42, "ual/1");
            move |_| r.next_u64()
        })
        .collect();
    let c: Vec<u64> = (0..4)
        .map({
            let mut r = stream(43, "ual/0");
            move |_| r.next_u64()
        })
        .collect();
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
    assert_ne!(a1, c);
}

#[test]
fn draws_stay_in_range() {
    let mut r = Rng::new(7);
    for _ in 0..10_000 {
        assert!(r.below(10) < 10);
        let v = r.range(-3, 3);
        assert!((-3..=3).contains(&v));
        let u = r.unit();
        assert!((0.0..1.0).contains(&u));
    }
    let id = r.uuid();
    assert_eq!(id.get_version_num(), 4);
    assert_eq!(r.hex(8).len(), 8);
    assert!(r.digits(16).chars().all(|c| c.is_ascii_digit()));
    let mean = (0..2000).map(|_| r.poisson(4.0)).sum::<u64>() as f64 / 2000.0;
    assert!((3.6..4.4).contains(&mean), "{mean}");
    let big = (0..200).map(|_| r.poisson(500.0)).sum::<u64>() as f64 / 200.0;
    assert!((480.0..520.0).contains(&big), "{big}");
}

#[test]
fn reserved_values_are_recognized() {
    for ip in [
        "192.0.2.1",
        "198.51.100.254",
        "203.0.113.7",
        "2001:db8::1",
        "2001:db8:ffff::",
    ] {
        assert!(is_reserved_ip(&ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
    for ip in ["192.0.3.1", "10.0.0.1", "8.8.8.8", "2001:db9::1", "fe80::1"] {
        assert!(!is_reserved_ip(&ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
    for d in [
        "contoso.example",
        "mail.fabrikam.test",
        "example.com",
        "a.example.org",
        "outlook.example",
    ] {
        assert!(is_reserved_domain(d), "{d}");
    }
    for d in [
        "contoso.com",
        "outlook.com",
        "example.co",
        "notexample.com",
        "microsoft.com",
        "",
    ] {
        assert!(!is_reserved_domain(d), "{d}");
    }
}

#[test]
fn ip_allocator_never_leaves_documentation_ranges() {
    let mut a = IpAllocator::new();
    let mut seen = BTreeSet::new();
    for net in [Net::Office, Net::Roaming, Net::Attacker] {
        for _ in 0..600 {
            let v4 = a.v4(net);
            assert!(is_reserved_ip(&IpAddr::V4(v4)), "{v4}");
            assert_ne!(v4.octets()[3], 0);
            assert_ne!(v4.octets()[3], 255);
            seen.insert(v4);
            let v6 = a.v6(net);
            assert!(is_reserved_ip(&IpAddr::V6(v6)), "{v6}");
        }
    }
    // Each net owns one /24: 254 hosts each before it wraps.
    assert_eq!(seen.len(), 3 * 254);
    assert_eq!(a.v4(Net::Office).octets()[..3], [192, 0, 2]);
    assert_eq!(a.v4(Net::Roaming).octets()[..3], [198, 51, 100]);
    assert_eq!(a.v4(Net::Attacker).octets()[..3], [203, 0, 113]);
}

#[test]
fn scanner_flags_real_values_and_ignores_versions() {
    let clean = concat!(
        "\"alice@contoso.example\",\"203.0.113.9\",\"2001:db8::10\",",
        "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36\",",
        "\"https://contoso.sharepoint.example/sites/Finance\",\"10:05:39\",\"9/24/2026 10:00:00 AM\""
    );
    assert!(scan_text(clean).is_empty(), "{:?}", scan_text(clean));
    let dirty =
        "\"bob@contoso.com\",\"8.8.8.8\",\"2a00:1450::1\",\"https://graph.microsoft.com/v1.0\"";
    let found = scan_text(dirty);
    assert_eq!(found.len(), 4, "{found:?}");
}

#[test]
fn people_are_unique_and_ascii() {
    let mut r = Rng::new(1);
    let ps = people(&mut r, 300);
    let aliases: BTreeSet<&str> = ps.iter().map(|p| p.alias.as_str()).collect();
    assert_eq!(aliases.len(), 300);
    assert!(ps.iter().all(|p| {
        p.alias
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '.' || c.is_ascii_digit())
    }));
}

#[test]
fn options_round_trip_through_text() {
    assert_eq!("hawk4".parse::<Collector>().unwrap(), Collector::Hawk4);
    assert_eq!("7".parse::<PsEdition>().unwrap(), PsEdition::Ps7);
    assert_eq!("5.1".parse::<PsEdition>().unwrap(), PsEdition::Ps51);
    assert_eq!("de-de".parse::<Culture>().unwrap(), Culture::DeDe);
    assert_eq!(Culture::JaJp.to_string(), "ja-JP");
    assert_eq!("sof-elk".parse::<UalFormat>().unwrap(), UalFormat::SofElk);
    assert_eq!("xlsx".parse::<SigninExport>().unwrap(), SigninExport::Xlsx);
    assert!("hawk5".parse::<Collector>().is_err());
    let o = GenerateOptions::new(Collector::Invictus, 42);
    assert_eq!(
        (o.ps, o.culture, o.ual_format),
        (PsEdition::Ps7, Culture::EnUs, UalFormat::Csv)
    );
    let json = serde_json::to_string(&o).unwrap();
    assert!(
        json.contains("\"collector\":\"invictus\"") && json.contains("\"ps\":\"7\""),
        "{json}"
    );
    assert_eq!(serde_json::from_str::<GenerateOptions>(&json).unwrap(), o);
}
