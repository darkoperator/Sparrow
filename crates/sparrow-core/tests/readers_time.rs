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
        d.resolve(Some(DateOrder::MonthFirst)).unwrap(),
        Some(DateOrder::MonthFirst)
    );
    assert!(
        d.resolve(Some(DateOrder::DayFirst))
            .unwrap_err()
            .contains("--culture")
    );
    d.observe("24/09/2026 10:00:00");
    assert!(d.resolve(Some(DateOrder::MonthFirst)).is_err());
    assert!(d.resolve(Some(DateOrder::DayFirst)).is_err());
    assert!(d.resolve(None).is_err());
    let empty = DateOrderDetector::default();
    assert_eq!(empty.resolve(None).unwrap(), None);
}

#[test]
fn culture_override_resolves_matching_or_ambiguous_evidence() {
    let mut day = DateOrderDetector::default();
    day.observe("24/9/2026 8:00:00 AM");
    assert_eq!(
        day.resolve(Some(DateOrder::DayFirst)).unwrap(),
        Some(DateOrder::DayFirst)
    );
    let err = day.resolve(Some(DateOrder::MonthFirst)).unwrap_err();
    assert!(err.contains("--culture"), "{err}");

    let mut ambiguous = DateOrderDetector::default();
    ambiguous.observe("6/9/2026 8:00:00 AM");
    assert_eq!(
        ambiguous.resolve(Some(DateOrder::DayFirst)).unwrap(),
        Some(DateOrder::DayFirst)
    );
    assert_eq!(
        ambiguous.resolve(Some(DateOrder::MonthFirst)).unwrap(),
        Some(DateOrder::MonthFirst)
    );
}

#[test]
fn tz_assumed_only_when_the_text_has_no_zone() {
    let assumed = |s: &str| {
        parse_timestamp(s, Some(DateOrder::MonthFirst))
            .unwrap()
            .tz_assumed
    };
    assert!(!assumed("2026-09-01T10:00:00Z"));
    assert!(!assumed("2026-09-01T10:00:00.1234567Z"));
    assert!(!assumed("2026-09-01T12:00:00+02:00"));
    assert!(!assumed(r"\/Date(1788256740000)\/"));
    assert!(!assumed("2026-09-10 14:15:00Z"));
    assert!(assumed("2026-09-01T10:00:00"));
    assert!(assumed("2026-09-01T10:00:00.1234"));
    assert!(assumed("9/1/2026 10:00:00 AM"));
    assert!(assumed("20260901_100000"));
}

#[test]
fn addendum_a_date_formats() {
    assert_eq!(iso("9/14/2026 3:04 PM", None), "2026-09-14T15:04:00+00:00");
    assert_eq!(
        iso("2026-09-01T10:00:00.1234567", None),
        "2026-09-01T10:00:00.123456700+00:00"
    );
    assert_eq!(
        iso("2026-09-01T10:00:00.5", None),
        "2026-09-01T10:00:00.500+00:00"
    );
    assert_eq!(
        iso("09/14/2026 15:04:05", None),
        "2026-09-14T15:04:05+00:00"
    );
    assert_eq!(
        iso("2026-09-02 08:00:00.123", None),
        "2026-09-02T08:00:00.123+00:00"
    );
    assert_eq!(
        iso("2026-09-01T10:00:00.0000000Z", None),
        "2026-09-01T10:00:00+00:00"
    );
    assert_eq!(
        iso(r"\/Date(1788256740000)\/", None),
        "2026-09-01T09:59:00+00:00"
    );
}

#[test]
fn contradiction_with_explicit_order_names_the_culture_flag() {
    let err = parse_timestamp("24/09/2026 10:00:00", Some(DateOrder::MonthFirst)).unwrap_err();
    assert_eq!(err, TimeError::Contradicts("24/09/2026 10:00:00".into()));
    assert!(err.to_string().contains("--culture"));
}

#[test]
fn detector_ignores_same_day_and_month_values() {
    let mut d = DateOrderDetector::default();
    d.observe("5/5/2026 1:00:00 PM");
    d.observe("12/12/2026 1:00:00 PM");
    assert_eq!(d.resolve(None).unwrap(), None);
    assert_eq!(
        parse_timestamp("5/5/2026 1:00:00 PM", None)
            .unwrap()
            .rfc3339(),
        "2026-05-05T13:00:00+00:00"
    );
}

#[test]
fn precision_names() {
    assert_eq!(Precision::Second.as_str(), "second");
    assert_eq!(Precision::Minute.as_str(), "minute");
}

#[test]
fn zone_assumed_whatever_the_day_month_order() {
    use sparrow_core::readers::time::zone_assumed;
    assert!(zone_assumed("9/24/2026 10:00:00 AM"));
    assert!(zone_assumed("24/9/2026 10:00:00"));
    assert!(zone_assumed("6/9/2026 10:00:00 AM"));
    assert!(zone_assumed("2026-09-24T10:00:00"));
    assert!(!zone_assumed("2026-09-24T10:00:00Z"));
    assert!(!zone_assumed("2026-09-24T10:00:00.1234567+02:00"));
    assert!(!zone_assumed("/Date(1788336000000)/"));
    assert!(zone_assumed("garbage"));
}

#[test]
fn detector_reports_evidence_and_ambiguity() {
    let mut d = DateOrderDetector::default();
    assert_eq!((d.evidence(), d.only_ambiguous()), (None, false));
    d.observe("6/9/2026 8:00:00 AM");
    assert_eq!((d.evidence(), d.only_ambiguous()), (None, true));
    d.observe("9/24/2026 8:00:00 AM");
    assert_eq!(
        (d.evidence(), d.only_ambiguous()),
        (Some(DateOrder::MonthFirst), false)
    );
    d.observe("24/9/2026 8:00:00");
    assert_eq!((d.evidence(), d.only_ambiguous()), (None, false));
    assert!(DateOrder::DayFirst.describe().contains("day-first"));
}

#[test]
fn parses_year_first_slash_dates_as_assumed_utc() {
    let t = parse_timestamp("2026/09/14 14:15:01", None).unwrap();
    assert_eq!(t.rfc3339(), "2026-09-14T14:15:01+00:00");
    assert!(t.tz_assumed);
    assert_eq!(iso("2026/9/4 4:05", None), "2026-09-04T04:05:00+00:00");
}
