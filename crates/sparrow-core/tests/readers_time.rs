use sparrow_core::readers::time::*;

fn iso(s: &str, order: Option<DateOrder>) -> String {
    parse_timestamp(s, order).unwrap().rfc3339()
}

#[test]
fn parses_iso_variants_as_utc() {
    assert_eq!(
        iso("2025-01-15T15:04:05Z", None),
        "2025-01-15T15:04:05+00:00"
    );
    assert_eq!(
        iso("2025-01-15T15:04:05.1234567Z", None),
        "2025-01-15T15:04:05.123456700+00:00"
    );
    assert_eq!(
        iso("2025-01-15T17:04:05+02:00", None),
        "2025-01-15T15:04:05+00:00"
    );
    assert_eq!(
        iso("2025-01-15T15:04:05", None),
        "2025-01-15T15:04:05+00:00"
    );
    assert_eq!(
        iso("2025-01-15 15:04:05Z", None),
        "2025-01-15T15:04:05+00:00"
    );
    assert_eq!(
        iso("2026-09-10 14:15:00", None),
        "2026-09-10T14:15:00+00:00"
    );
}

#[test]
fn parses_dotnet_json_dates() {
    assert_eq!(
        iso(r"\/Date(1736953445000)\/", None),
        "2025-01-15T15:04:05+00:00"
    );
    assert_eq!(
        iso("/Date(1736953445000+0000)/", None),
        "2025-01-15T15:04:05+00:00"
    );
}

#[test]
fn parses_compact_forms() {
    assert_eq!(iso("20260910-141500", None), "2026-09-10T14:15:00+00:00");
    assert_eq!(iso("20260910_141500", None), "2026-09-10T14:15:00+00:00");
    assert_eq!(iso("20260910141500", None), "2026-09-10T14:15:00+00:00");
}

#[test]
fn culture_dates_resolve_by_evidence_or_order() {
    assert_eq!(
        iso("9/24/2026 10:00:00 AM", None),
        "2026-09-24T10:00:00+00:00"
    );
    assert_eq!(
        iso("24/09/2026 22:00:00", None),
        "2026-09-24T22:00:00+00:00"
    );
    assert_eq!(
        iso("24.09.2026 22:00:00", None),
        "2026-09-24T22:00:00+00:00"
    );
    assert_eq!(
        iso("6/12/2026 12:00:00 AM", Some(DateOrder::MonthFirst)),
        "2026-06-12T00:00:00+00:00"
    );
    assert_eq!(
        iso("6/12/2026 12:30:00 PM", Some(DateOrder::DayFirst)),
        "2026-12-06T12:30:00+00:00"
    );
    assert_eq!(
        iso("5/5/2026 1:00:00 PM", None),
        "2026-05-05T13:00:00+00:00"
    );
}

#[test]
fn ambiguous_culture_date_without_order_is_an_error_naming_culture_flag() {
    let err = parse_timestamp("6/12/2026 12:00:00 AM", None).unwrap_err();
    assert!(matches!(err, TimeError::Ambiguous(_)));
    assert!(err.to_string().contains("--culture"));
}

#[test]
fn contradicting_order_is_rejected() {
    assert!(parse_timestamp("24/09/2026 10:00:00", Some(DateOrder::MonthFirst)).is_err());
}

#[test]
fn minute_precision_when_seconds_missing() {
    let t = parse_timestamp("9/24/2026 10:07 PM", None).unwrap();
    assert_eq!(t.precision, Precision::Minute);
    assert_eq!(t.rfc3339(), "2026-09-24T22:07:00+00:00");
    assert_eq!(
        parse_timestamp("2025-01-15T15:04:05Z", None)
            .unwrap()
            .precision,
        Precision::Second
    );
}

#[test]
fn empty_and_garbage() {
    assert_eq!(parse_timestamp("  ", None).unwrap_err(), TimeError::Empty);
    assert!(matches!(
        parse_timestamp("not a date", None).unwrap_err(),
        TimeError::Unrecognized(_)
    ));
    assert!(matches!(
        parse_timestamp("13/13/2026 10:00:00", None).unwrap_err(),
        TimeError::Unrecognized(_)
    ));
}

#[test]
fn parse_culture_maps_common_cultures() {
    assert_eq!(parse_culture("en-US").unwrap(), DateOrder::MonthFirst);
    assert_eq!(parse_culture("mdy").unwrap(), DateOrder::MonthFirst);
    assert_eq!(parse_culture("en-GB").unwrap(), DateOrder::DayFirst);
    assert_eq!(parse_culture("de-DE").unwrap(), DateOrder::DayFirst);
    assert!(parse_culture("xx-YY").unwrap_err().contains("en-US"));
}

#[test]
fn detector_resolves_from_evidence() {
    let mut d = DateOrderDetector::default();
    d.observe("6/12/2026 12:00:00 AM");
    assert!(d.resolve(None).unwrap_err().contains("--culture"));
    d.observe("9/24/2026 10:00:00 AM");
    assert_eq!(d.resolve(None).unwrap(), Some(DateOrder::MonthFirst));
    assert_eq!(
        d.resolve(Some(DateOrder::DayFirst)).unwrap(),
        Some(DateOrder::DayFirst)
    );
    d.observe("24/09/2026 10:00:00");
    assert!(d.resolve(None).is_err());
    let empty = DateOrderDetector::default();
    assert_eq!(empty.resolve(None).unwrap(), None);
}
