use sparrow_core::normalize::net::{normalize_ip, normalize_upn};
use sparrow_core::normalize::record_types::{RECORD_TYPES, record_type_name, record_type_value};

#[test]
fn record_type_table_is_sorted_unique_and_complete() {
    assert!(RECORD_TYPES.windows(2).all(|w| w[0].0 < w[1].0));
    assert_eq!(RECORD_TYPES.len(), 261);
}

#[test]
fn record_type_lookups() {
    assert_eq!(record_type_name(1), Some("ExchangeAdmin"));
    assert_eq!(record_type_name(15), Some("AzureActiveDirectoryStsLogon"));
    assert_eq!(record_type_name(19), Some("ExchangeAggregatedOperation"));
    assert_eq!(record_type_name(50), Some("ExchangeItemAggregated"));
    assert_eq!(record_type_name(101), Some("ExchangeSearch"));
    assert_eq!(record_type_name(5), None);
    assert_eq!(record_type_value("exchangeitem"), Some(2));
    assert_eq!(record_type_value("SharePointSharingOperation"), Some(14));
    assert_eq!(record_type_value("Nope"), None);
}

#[test]
fn ip_normalization() {
    assert_eq!(
        normalize_ip("203.0.113.10").as_deref(),
        Some("203.0.113.10")
    );
    assert_eq!(
        normalize_ip(" 203.0.113.10:51000 ").as_deref(),
        Some("203.0.113.10")
    );
    assert_eq!(
        normalize_ip("[2001:DB8::5]:443").as_deref(),
        Some("2001:db8::5")
    );
    assert_eq!(
        normalize_ip("[2001:db8::5]").as_deref(),
        Some("2001:db8::5")
    );
    assert_eq!(
        normalize_ip("2001:DB8:0:0:0:0:0:5").as_deref(),
        Some("2001:db8::5")
    );
    assert_eq!(
        normalize_ip("::ffff:203.0.113.10").as_deref(),
        Some("203.0.113.10")
    );
    assert_eq!(
        normalize_ip("[::FFFF:203.0.113.10]:443").as_deref(),
        Some("203.0.113.10")
    );
    assert_eq!(normalize_ip("  "), None);
    assert_eq!(normalize_ip("Not-An-IP").as_deref(), Some("not-an-ip"));
}

#[test]
fn upn_normalization() {
    assert_eq!(
        normalize_upn(" Alice@Contoso.Example ").as_deref(),
        Some("alice@contoso.example")
    );
    assert_eq!(normalize_upn(""), None);
}

#[test]
fn normalize_ip_chain_takes_first_address() {
    assert_eq!(
        normalize_ip("203.0.113.5, 52.168.116.49,198.51.100.7:51622").as_deref(),
        Some("203.0.113.5")
    );
    assert_eq!(
        normalize_ip("unknown, 203.0.113.5").as_deref(),
        Some("203.0.113.5")
    );
    assert_eq!(
        normalize_ip("[2001:db8::1]:443, 198.51.100.7").as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(normalize_ip("foo, bar").as_deref(), Some("foo, bar"));
    assert_eq!(normalize_ip("203.0.113.5").as_deref(), Some("203.0.113.5"));
}
