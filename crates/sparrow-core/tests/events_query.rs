//! Task 2 of the investigate tabs: the events query (Harrier filter syntax, paging, summary, histogram, CSV, search).
//! Most cases insert `events` rows directly: the query reads that table only; the search and detail tests also hold
//! the source rows.

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::Error;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::browse::Sort;
use sparrow_core::case::events::{
    self, AiFilter, CSV_COLUMNS, Entity, EventQuery, Field, FlagFilter, HISTOGRAM_TOP_OPERATIONS,
    HistogramGroup,
};
use sparrow_core::case::marks::{
    FlagLevel, RowRef, ValueKind, flag_rows, flag_value, review_marks, tag_rows,
};
use sparrow_core::detect::test::insert_record;

const T: &str = "contoso";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 1, 10, 0, 0).unwrap()
}

/// One `events` row; unset columns are NULL.
#[derive(Default, Clone)]
struct Ev {
    table: &'static str,
    key: String,
    source: &'static str,
    time: Option<DateTime<Utc>>,
    op: Option<&'static str>,
    actor: Option<&'static str>,
    owner: Option<&'static str>,
    ip: Option<&'static str>,
    country: Option<&'static str>,
    asn: Option<i32>,
    device_id: Option<&'static str>,
    device_object_id: Option<&'static str>,
    device_name: Option<&'static str>,
    session: Option<&'static str>,
}

fn ev(key: &str, source: &'static str, time: DateTime<Utc>) -> Ev {
    Ev {
        table: match source {
            "ual" => "ual_events",
            "message_trace_event" => "message_trace_events",
            "message_trace" => "message_trace",
            s if s.starts_with("signin") => "signins",
            "mail_items_accessed" => "mail_items_accessed",
            _ => "ual_events",
        },
        key: key.into(),
        source,
        time: Some(time),
        ..Ev::default()
    }
}

fn put(case: &Case, e: &Ev) {
    case.conn()
        .execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, operation, actor_upn, \
             owner_upn, ip, ip_country, asn, device_id, device_object_id, device_name, entra_session_id) \
             VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), 'other', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                e.table,
                e.key,
                e.source,
                e.time.map(|t| t.format("%Y-%m-%dT%H:%M:%S%.6f+00").to_string()),
                e.op,
                e.actor,
                e.owner,
                e.ip,
                e.country,
                e.asn,
                e.device_id,
                e.device_object_id,
                e.device_name,
                e.session
            ],
        )
        .unwrap();
}

fn keys(case: &Case, q: &EventQuery) -> Vec<String> {
    let page = events::page(case.conn(), q, None, 0, 500).unwrap();
    assert_eq!(page.total as usize, page.rows.len());
    let mut k: Vec<String> = page.rows.into_iter().map(|r| r.record_key).collect();
    k.sort();
    k
}

fn field(f: Field, text: &str) -> EventQuery {
    EventQuery {
        fields: vec![(f, text.into())],
        ..EventQuery::default()
    }
}

fn scoped(e: Entity) -> EventQuery {
    EventQuery {
        entity: Some(e),
        ..EventQuery::default()
    }
}

/// The six-row case of the filter-syntax tests.
fn six_rows() -> Case {
    let case = Case::in_memory().unwrap();
    type Row = (
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    );
    let rows: [Row; 6] = [
        (
            "k1",
            "login",
            Some("a@contoso.example"),
            None,
            Some("203.0.113.10"),
            Some("US"),
        ),
        (
            "k2",
            "Login",
            Some("b@contoso.example"),
            None,
            Some("203.0.113.20"),
            Some("US"),
        ),
        (
            "k3",
            "AdminAdd",
            Some("c@contoso.example"),
            None,
            Some("198.51.100.7"),
            Some("GB"),
        ),
        (
            "k4",
            "admin-delete",
            Some("a@fabrikam.example"),
            None,
            Some("203.0.113.99"),
            None,
        ),
        (
            "k5",
            "drive",
            Some("b@fabrikam.example"),
            None,
            Some("2001:db8::1"),
            None,
        ),
        ("k6", "Other", None, Some("d@contoso.example"), None, None),
    ];
    for (i, (key, op, actor, owner, ip, country)) in rows.into_iter().enumerate() {
        put(
            &case,
            &Ev {
                op: Some(op),
                actor,
                owner,
                ip,
                country,
                ..ev(key, "ual", t0() + Duration::seconds(i as i64))
            },
        );
    }
    case
}

#[test]
fn field_syntax_matches_harrier() {
    let case = six_rows();
    let table: &[(Field, &str, &[&str])] = &[
        (
            Field::Account,
            "a@contoso.example, b@contoso.example",
            &["k1", "k2"],
        ),
        // The mailbox owner counts as the account: k6 is d@contoso.example's mailbox.
        (
            Field::Account,
            "*@contoso.example, !a@contoso.example",
            &["k2", "k3", "k6"],
        ),
        // Only excludes: everything except these, rows without an actor included.
        (
            Field::Account,
            "!a@contoso.example",
            &["k2", "k3", "k4", "k5", "k6"],
        ),
        (Field::Ip, "203.0.113.*", &["k1", "k2", "k4"]),
        // Surrounding whitespace is trimmed; without a wildcard the match is exact and case-sensitive.
        (Field::Operation, "  login  ", &["k1"]),
        (Field::Operation, "Login", &["k2"]),
        (Field::Operation, "admin*", &["k3", "k4"]),
        (Field::Operation, "!login", &["k2", "k3", "k4", "k5", "k6"]),
        // Accounts compare lower-cased, so a different spelling finds the same rows.
        (Field::Account, "A@CONTOSO.EXAMPLE", &["k1"]),
        // A wildcard value behind a `!`.
        (Field::Account, "!*@contoso.example", &["k4", "k5"]),
        // An excluded value never hides rows that simply have none.
        (Field::Ip, "!203.0.113.*", &["k3", "k5", "k6"]),
        (Field::Country, "!US", &["k3", "k4", "k5", "k6"]),
        (Field::Country, "US, GB", &["k1", "k2", "k3"]),
        // Empty parts are dropped; a blank box is no filter.
        (Field::Operation, "drive,, ,Other", &["k5", "k6"]),
        (Field::Account, "   ", &["k1", "k2", "k3", "k4", "k5", "k6"]),
        // IPv6 in another spelling finds the same row.
        (Field::Ip, "2001:DB8::1", &["k5"]),
    ];
    for (f, text, want) in table {
        assert_eq!(keys(&case, &field(*f, text)), *want, "{f:?} {text:?}");
    }
    // Fields combine with AND.
    let q = EventQuery {
        fields: vec![
            (Field::Account, "*@contoso.example".into()),
            (Field::Operation, "login".into()),
        ],
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["k1"]);
}

#[test]
fn like_metacharacters_in_values_are_literal() {
    let case = Case::in_memory().unwrap();
    for (i, op) in ["a_b", "axb", "100%", "1000", "back\\slash"]
        .into_iter()
        .enumerate()
    {
        put(
            &case,
            &Ev {
                op: Some(op),
                ..ev(&format!("m{i}"), "ual", t0() + Duration::seconds(i as i64))
            },
        );
    }
    assert_eq!(keys(&case, &field(Field::Operation, "a_*")), ["m0"]);
    assert_eq!(keys(&case, &field(Field::Operation, "100%*")), ["m2"]);
    assert_eq!(keys(&case, &field(Field::Operation, "back\\*")), ["m4"]);
    // Exact values are compared, not matched as patterns.
    assert_eq!(keys(&case, &field(Field::Operation, "a_b")), ["m0"]);
}

#[test]
fn filter_values_are_bound_not_formatted() {
    let case = six_rows();
    for f in [Field::Account, Field::Operation, Field::Ip, Field::Tag] {
        let q = field(f, "x'; DROP TABLE events; --");
        let page = events::page(case.conn(), &q, None, 0, 10).unwrap();
        assert_eq!(page.total, 0, "{f:?}");
    }
    let q = EventQuery {
        search: Some("'; DROP TABLE events; --".into()),
        ..EventQuery::default()
    };
    assert_eq!(events::page(case.conn(), &q, None, 0, 10).unwrap().total, 0);
    assert_eq!(keys(&case, &EventQuery::default()).len(), 6);
}

#[test]
fn field_syntax_rejects_degenerate_input() {
    let case = six_rows();
    for (f, name) in [
        (Field::Account, "Account"),
        (Field::Ip, "IP"),
        (Field::Source, "Source"),
        (Field::Tag, "Tag"),
        (Field::Asn, "ASN"),
    ] {
        for bad in ["!", ",,", "!,", "a@contoso.example, !", " ! "] {
            let q = field(f, bad);
            let msg = |e: Error| match e {
                Error::Invalid(m) => m,
                other => panic!("{f:?} {bad:?}: expected Invalid, got {other:?}"),
            };
            let m = msg(events::page(case.conn(), &q, None, 0, 10).unwrap_err());
            assert!(m.contains(name), "{f:?} {bad:?}: {m}");
            // The same refusal from every reader, never a silent match-all.
            msg(events::summary(case.conn(), &q).unwrap_err());
            msg(events::histogram(case.conn(), &q, 60).unwrap_err());
            let out = std::env::temp_dir().join("sparrow-events-degenerate.csv");
            msg(events::export_csv(case.conn(), &q, &out).unwrap_err());
        }
    }
    // A search of only commas is refused too.
    let q = EventQuery {
        search: Some(" , ,".into()),
        ..EventQuery::default()
    };
    assert!(matches!(
        events::page(case.conn(), &q, None, 0, 10),
        Err(Error::Invalid(m)) if m.contains("search")
    ));
}

#[test]
fn entity_scope_matches_all_spellings() {
    let case = Case::in_memory().unwrap();
    let dev = "d3d3d3d3-0000-4000-8000-00000000abcd";
    let obj = "0b1ec700-0000-4000-8000-00000000abcd";
    let ses = "2222aaaa-2222-4222-8222-22222222bbbb";
    let base = t0();
    let rows = [
        Ev {
            actor: Some("jdoe@contoso.example"),
            ip: Some("2001:db8::1"),
            device_id: Some(dev),
            session: Some(ses),
            ..ev("e1", "signin_interactive", base)
        },
        // The mailbox owner is the account too.
        Ev {
            actor: Some("app@contoso.example"),
            owner: Some("jdoe@contoso.example"),
            ip: Some("203.0.113.5"),
            ..ev("e2", "mail_items_accessed", base + Duration::seconds(1))
        },
        // A directory audit names the device by its object id.
        Ev {
            actor: Some("admin@contoso.example"),
            device_object_id: Some(obj),
            ..ev("e3", "ual", base + Duration::seconds(2))
        },
        Ev {
            actor: Some("other@contoso.example"),
            ip: Some("2001:db8::2"),
            session: Some("3333aaaa-3333-4333-8333-33333333cccc"),
            ..ev("e4", "ual", base + Duration::seconds(3))
        },
    ];
    for r in &rows {
        put(&case, r);
    }
    let same = |a: Entity, b: Entity, want: &[&str]| {
        let (ka, kb) = (keys(&case, &scoped(a.clone())), keys(&case, &scoped(b)));
        assert_eq!(ka, want, "{a:?}");
        assert_eq!(kb, want, "{a:?} canonical");
    };
    same(
        Entity::Account("JDoe@Contoso.Example".into()),
        Entity::Account("jdoe@contoso.example".into()),
        &["e1", "e2"],
    );
    same(
        Entity::Account("  jdoe@contoso.example ".into()),
        Entity::Account("jdoe@contoso.example".into()),
        &["e1", "e2"],
    );
    same(
        Entity::Ip("2001:DB8::1".into()),
        Entity::Ip("2001:db8::1".into()),
        &["e1"],
    );
    same(
        Entity::Ip("[2001:db8::1]".into()),
        Entity::Ip("2001:db8::1".into()),
        &["e1"],
    );
    same(
        Entity::Device("D3D3D3D3-0000-4000-8000-00000000ABCD".into()),
        Entity::Device(dev.into()),
        &["e1"],
    );
    // The object id finds the directory audit row; the device id finds the sign-in.
    same(
        Entity::Device("0B1EC700-0000-4000-8000-00000000ABCD".into()),
        Entity::Device(obj.into()),
        &["e3"],
    );
    same(
        Entity::Session("2222AAAA-2222-4222-8222-22222222BBBB".into()),
        Entity::Session(ses.into()),
        &["e1"],
    );
    // The scope combines with the filter boxes.
    let q = EventQuery {
        entity: Some(Entity::Account("JDOE@contoso.example".into())),
        fields: vec![(Field::Source, "mail_items_accessed".into())],
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["e2"]);

    // normalized() gives the stored spelling, and refuses what cannot be a value.
    assert_eq!(
        Entity::Ip("2001:DB8:0:0:0:0:0:1".into())
            .normalized()
            .unwrap(),
        Entity::Ip("2001:db8::1".into())
    );
    assert_eq!(
        Entity::Session(" ABC ".into()).normalized().unwrap(),
        Entity::Session("abc".into())
    );
    for bad in [
        Entity::Ip("not-an-ip".into()),
        Entity::Ip("  ".into()),
        Entity::Account("".into()),
        Entity::Device(" ".into()),
        Entity::Session("".into()),
    ] {
        assert!(
            matches!(bad.clone().normalized(), Err(Error::Invalid(_))),
            "{bad:?}"
        );
        let page = events::page(case.conn(), &scoped(bad.clone()), None, 0, 10);
        assert!(matches!(page, Err(Error::Invalid(_))), "{bad:?}");
    }
}

#[test]
fn range_is_inclusive_and_histogram_edges() {
    let case = Case::in_memory().unwrap();
    let base = t0();
    for (i, s) in [0, 10, 20, 30].into_iter().enumerate() {
        put(
            &case,
            &ev(&format!("r{i}"), "ual", base + Duration::seconds(s)),
        );
    }
    // An event exactly at `to` (and at `from`) is in the page and in the last bucket.
    let q = EventQuery {
        from: Some(base),
        to: Some(base + Duration::seconds(30)),
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["r0", "r1", "r2", "r3"]);
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert_eq!((h.start, h.bucket_seconds), (base, 60));
    assert_eq!(h.series, [("ual".to_string(), vec![4])]);

    // A range narrower than one bucket still returns its rows.
    let q = EventQuery {
        from: Some(base + Duration::seconds(5)),
        to: Some(base + Duration::seconds(25)),
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["r1", "r2"]);
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert_eq!(
        (h.start, h.bucket_seconds),
        (base + Duration::seconds(5), 60)
    );
    assert_eq!(h.series, [("ual".to_string(), vec![2])]);

    // An hour wide with the last event exactly at `to`: 5-minute buckets, 13 of them, the event in the last.
    put(&case, &ev("r4", "ual", base + Duration::hours(1)));
    let q = EventQuery {
        from: Some(base),
        to: Some(base + Duration::hours(1)),
        ..EventQuery::default()
    };
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert_eq!(h.bucket_seconds, 300);
    let mut want = vec![0u64; 13];
    want[0] = 4;
    want[12] = 1;
    assert_eq!(h.series, [("ual".to_string(), want)]);

    // The range is inclusive on both ends of the page, too: one microsecond short drops the last event.
    let q = EventQuery {
        from: Some(base),
        to: Some(base + Duration::hours(1) - Duration::microseconds(1)),
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["r0", "r1", "r2", "r3"]);

    // An empty result is zero buckets, not an error, from every reader.
    let q = field(Field::Operation, "nothing-has-this-operation");
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert!(h.series.is_empty() && h.findings.is_empty());
    assert_eq!(events::page(case.conn(), &q, None, 0, 10).unwrap().total, 0);
    let s = events::summary(case.conn(), &q).unwrap();
    assert_eq!((s.total, s.per_source.len()), (0, 0));
    let q = EventQuery {
        from: Some(base + Duration::days(30)),
        ..EventQuery::default()
    };
    assert!(
        events::histogram(case.conn(), &q, 60)
            .unwrap()
            .series
            .is_empty()
    );
    assert!(matches!(
        events::histogram(case.conn(), &EventQuery::default(), 0),
        Err(Error::Invalid(_))
    ));
}

/// Inserts a finding with evidence on `rows` (`(source_table, record_key)`).
fn finding(
    case: &Case,
    id: &str,
    severity: &str,
    status: &str,
    seen: Option<(&str, &str)>,
    rows: &[(&str, &str)],
) {
    case.conn()
        .execute(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
             title, first_seen, last_seen, status, created_by, created_at, updated_at) \
             VALUES (?, ?, 'contoso', 'SPW-X', 1, 'x', ?, 't', CAST(? AS TIMESTAMPTZ), CAST(? AS TIMESTAMPTZ), \
             CAST(? AS finding_status), 'rule', now(), now())",
            duckdb::params![id, id, severity, seen.map(|s| s.0), seen.map(|s| s.1), status],
        )
        .unwrap();
    for (table, key) in rows {
        case.conn()
            .execute(
                "INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id) \
                 VALUES (?, ?, ?, 'trigger', 1)",
                [id, table, key],
            )
            .unwrap();
    }
}

/// Six events over two days from three sources: the histogram case.
fn two_days() -> Case {
    let case = Case::in_memory().unwrap();
    let d1 = t0();
    let rows = [
        ev("u1", "ual", d1),
        ev(
            "u2",
            "ual",
            d1 + Duration::minutes(59) + Duration::seconds(59),
        ),
        ev("u3", "ual", d1 + Duration::hours(1)),
        ev("s1", "signin_interactive", d1 + Duration::minutes(30)),
        ev("s2", "signin_interactive", d1 + Duration::days(1)),
        ev("m1", "mail_items_accessed", d1 + Duration::days(2)),
    ];
    for r in &rows {
        put(&case, r);
    }
    case
}

#[test]
fn histogram_buckets_and_series() {
    let case = two_days();
    // F1 spans two events, F3 has no times of its own, F2 is a false positive, F4 has evidence outside the account.
    finding(
        &case,
        "F1",
        "high",
        "new",
        Some(("2026-09-01 10:30:00+00", "2026-09-02 10:00:00+00")),
        &[("ual_events", "u1"), ("signins", "s2")],
    );
    finding(
        &case,
        "F2",
        "high",
        "false_positive",
        Some(("2026-09-01 10:00:00+00", "2026-09-01 10:00:00+00")),
        &[("ual_events", "u1")],
    );
    finding(
        &case,
        "F3",
        "low",
        "in_review",
        None,
        &[("ual_events", "u3"), ("ual_events", "u2")],
    );
    // A benign finding is closed like a false positive: not in the lane.
    finding(
        &case,
        "F5",
        "high",
        "benign",
        Some(("2026-09-01 10:00:00+00", "2026-09-01 10:00:00+00")),
        &[("ual_events", "u1")],
    );
    finding(
        &case,
        "F4",
        "medium",
        "new",
        Some(("2026-09-03 10:00:00+00", "2026-09-03 10:00:00+00")),
        &[("mail_items_accessed", "m1")],
    );

    let h = events::histogram(case.conn(), &EventQuery::default(), 60).unwrap();
    // 48 hours of data: 1-hour buckets (49 of them), aligned on the hour.
    assert_eq!((h.start, h.bucket_seconds), (t0(), 3600));
    let counts = |entries: &[(usize, u64)]| {
        let mut v = vec![0u64; 49];
        for (i, n) in entries {
            v[*i] += n;
        }
        v
    };
    assert_eq!(
        h.series,
        [
            ("ual".to_string(), counts(&[(0, 2), (1, 1)])),
            ("signin_interactive".to_string(), counts(&[(0, 1), (24, 1)])),
            // The event at exactly the end of the range is in the last bucket.
            ("mail_items_accessed".to_string(), counts(&[(48, 1)])),
        ]
    );
    let at = |s: &str| {
        Utc.from_utc_datetime(
            &chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap(),
        )
    };
    let marks: Vec<_> = h
        .findings
        .iter()
        .map(|f| {
            (
                f.finding_id.as_str(),
                f.severity.as_str(),
                f.first_seen,
                f.last_seen,
            )
        })
        .collect();
    // F3 has no times of its own: its evidence's first and last. F2 (false positive) and F5 (benign) are not shown.
    assert_eq!(
        marks,
        [
            (
                "F1",
                "high",
                at("2026-09-01 10:30:00"),
                at("2026-09-02 10:00:00")
            ),
            (
                "F3",
                "low",
                at("2026-09-01 10:59:59"),
                at("2026-09-01 11:00:00")
            ),
            (
                "F4",
                "medium",
                at("2026-09-03 10:00:00"),
                at("2026-09-03 10:00:00")
            ),
        ]
    );

    // A smaller bucket budget gives a bigger bucket: 49 buckets of 1h are too many for 40; 3h gives 17.
    let h = events::histogram(case.conn(), &EventQuery::default(), 40).unwrap();
    assert_eq!(h.bucket_seconds, 10_800);
    assert_eq!(h.series[0].1.len(), 17);
    assert_eq!(h.series[0].1.iter().sum::<u64>(), 3);
    // Even a budget of one bucket stops at one day.
    let h = events::histogram(case.conn(), &EventQuery::default(), 1).unwrap();
    assert_eq!(h.bucket_seconds, 86_400);

    // Scoped to the filtered events, the lane shows the findings of those events only.
    let q = field(Field::Source, "signin_interactive");
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert_eq!(
        h.findings
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect::<Vec<_>>(),
        ["F1"]
    );
    assert_eq!(h.series.len(), 1);
    // From a dragged range that starts mid-hour, buckets start at the range, not on the hour.
    let q = EventQuery {
        from: Some(t0() + Duration::minutes(20)),
        to: Some(t0() + Duration::minutes(80)),
        ..EventQuery::default()
    };
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert_eq!(
        (h.start, h.bucket_seconds),
        (t0() + Duration::minutes(20), 300)
    );
    let all: u64 = h.series.iter().flat_map(|s| s.1.iter()).sum();
    assert_eq!(all, 3); // s1 (10:30), u2 (10:59:59), u3 (11:00)
}

#[test]
fn histogram_by_operation_keeps_the_top_ten_and_stacks_the_rest() {
    let case = Case::in_memory().unwrap();
    // Twelve operations: "op01" has 12 events ... "op12" has 1, except that "op10" and "op09" tie on 3 each (so the
    // tie is broken by name) and a real operation named "Other" has 5. The last hour also holds 2 events with no
    // operation. Events go in hour `n % 2` (0 or 1), from source `ual` or `signin_interactive` by parity.
    let ops: [(&str, usize); 12] = [
        ("op01", 12),
        ("op02", 11),
        ("op03", 10),
        ("op04", 9),
        ("op05", 8),
        ("op06", 7),
        ("Other", 5),
        ("op07", 4),
        ("op10", 3),
        ("op09", 3),
        ("op11", 2),
        ("op12", 1),
    ];
    let mut k = 0;
    for (op, n) in &ops {
        for i in 0..*n {
            k += 1;
            let mut e = ev(
                &format!("k{k}"),
                if i % 2 == 0 {
                    "ual"
                } else {
                    "signin_interactive"
                },
                t0() + Duration::hours((i % 2) as i64),
            );
            e.op = Some(op);
            put(&case, &e);
        }
    }
    for i in 0..2 {
        put(
            &case,
            &ev(&format!("none{i}"), "ual", t0() + Duration::hours(1)),
        );
    }

    let by = |q: &EventQuery, g| events::histogram_by(case.conn(), q, 2, g).unwrap();
    let h = by(&EventQuery::default(), HistogramGroup::Operation);
    assert_eq!(h.group, HistogramGroup::Operation);
    assert_eq!((h.start, h.bucket_seconds), (t0(), 3600));
    // A budget of 2 buckets gives 1-hour buckets over this hour. Hour 0 takes the even-numbered events of each operation, hour 1 the odd ones: ceil(n/2) and floor(n/2).
    let split = |n: usize| vec![n.div_ceil(2) as u64, (n / 2) as u64];
    assert_eq!(
        h.series,
        [
            ("op01", 12),
            ("op02", 11),
            ("op03", 10),
            ("op04", 9),
            ("op05", 8),
            ("op06", 7),
            ("Other", 5),
            ("op07", 4),
            ("op09", 3),
            ("op10", 3),
        ]
        .iter()
        .map(|(op, n)| (op.to_string(), split(*n)))
        .collect::<Vec<_>>()
    );
    assert_eq!(h.series.len(), HISTOGRAM_TOP_OPERATIONS);
    // The rest: op11 (2: one per hour), op12 (1: hour 0) and the two events with no operation (hour 1).
    assert_eq!(h.other, Some(vec![2, 3]));

    // The cut follows the query: source `signin_interactive` holds the odd-numbered events only, floor(n/2) each.
    // op12 has none, leaving 11 operations; op09, op10 and op11 tie at 1 and op11 loses on name.
    let q = field(Field::Source, "signin_interactive");
    let h = by(&q, HistogramGroup::Operation);
    let names: Vec<(&str, u64)> = h
        .series
        .iter()
        .map(|(op, c)| (op.as_str(), c.iter().sum()))
        .collect();
    assert_eq!(
        names,
        [
            ("op01", 6),
            ("op02", 5),
            ("op03", 5),
            ("op04", 4),
            ("op05", 4),
            ("op06", 3),
            ("Other", 2),
            ("op07", 2),
            ("op09", 1),
            ("op10", 1),
        ]
    );
    assert_eq!(h.other.as_ref().map(|v| v.iter().sum::<u64>()), Some(1));

    // Ten operations or fewer: no `other`. By source: never an `other`, whatever the operations.
    let q = field(Field::Operation, "op01,op02");
    let h = by(&q, HistogramGroup::Operation);
    assert_eq!(h.series.len(), 2);
    assert_eq!(h.other, None);
    let h = by(&EventQuery::default(), HistogramGroup::Source);
    assert_eq!(h.group, HistogramGroup::Source);
    assert_eq!(h.other, None);
    assert_eq!(
        h.series.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
        ["ual", "signin_interactive"]
    );
    // `histogram` is the by-source histogram.
    assert_eq!(
        events::histogram(case.conn(), &EventQuery::default(), 2)
            .unwrap()
            .series,
        h.series
    );
    // No matching event: no series and no `other`, in either grouping.
    let none = field(Field::Operation, "no_such_operation");
    let h = by(&none, HistogramGroup::Operation);
    assert_eq!((h.series.len(), h.other), (0, None));
}

#[test]
fn summary_counts_per_source() {
    let case = two_days();
    put(&case, &ev("t1", "message_trace_event", t0()));
    put(
        &case,
        &ev("t2", "message_trace_event", t0() + Duration::seconds(1)),
    );
    put(&case, &ev("t3", "message_trace", t0()));
    let s = events::summary(case.conn(), &EventQuery::default()).unwrap();
    assert_eq!(s.total, 7);
    assert_eq!(
        s.per_source,
        [
            ("ual".to_string(), 3),
            ("signin_interactive".to_string(), 2),
            ("mail_items_accessed".to_string(), 1),
            ("message_trace".to_string(), 1),
        ]
    );
    assert_eq!((s.suspicious, s.malicious), (0, 0));
    assert_eq!(s.hidden_trace_events, 2);

    let q = field(Field::Source, "message_trace*");
    let s = events::summary(case.conn(), &q).unwrap();
    assert_eq!(s.total, 3);
    assert_eq!(
        s.per_source,
        [
            ("message_trace".to_string(), 1),
            ("message_trace_event".to_string(), 2)
        ]
    );
    assert_eq!(s.hidden_trace_events, 0);

    // The summary follows the other filters, including the time range.
    let q = EventQuery {
        from: Some(t0() + Duration::days(1)),
        ..EventQuery::default()
    };
    let s = events::summary(case.conn(), &q).unwrap();
    assert_eq!(s.total, 2);
    assert_eq!(
        s.per_source,
        [
            ("signin_interactive".to_string(), 1),
            ("mail_items_accessed".to_string(), 1)
        ]
    );
    assert_eq!(s.hidden_trace_events, 0);
}

#[test]
fn message_trace_events_hidden_until_named() {
    let case = Case::in_memory().unwrap();
    put(
        &case,
        &Ev {
            actor: Some("a@contoso.example"),
            ..ev("t1", "message_trace_event", t0())
        },
    );
    put(
        &case,
        &Ev {
            actor: Some("a@contoso.example"),
            ..ev("t2", "message_trace_event", t0() + Duration::seconds(1))
        },
    );
    put(
        &case,
        &Ev {
            actor: Some("a@contoso.example"),
            ..ev("t3", "message_trace", t0() + Duration::seconds(2))
        },
    );
    put(
        &case,
        &Ev {
            actor: Some("a@contoso.example"),
            ..ev("u1", "ual", t0() + Duration::seconds(3))
        },
    );

    let table: &[(&str, &[&str], u64)] = &[
        // Not named: hidden, and counted aside.
        ("", &["t3", "u1"], 2),
        // The Source box itself can rule them out; then they are not matches to count aside.
        ("ual", &["u1"], 0),
        ("message_trace", &["t3"], 0),
        ("!ual", &["t3"], 2),
        // Named exactly, or by a wildcard that matches.
        ("message_trace_event", &["t1", "t2"], 0),
        ("message_trace*", &["t1", "t2", "t3"], 0),
        ("*trace_event", &["t1", "t2"], 0),
        ("*", &["t1", "t2", "t3", "u1"], 0),
        ("ual, message_trace_event", &["t1", "t2", "u1"], 0),
        // Naming it in an exclude does not show it.
        ("!message_trace_event", &["t3", "u1"], 0),
        // A wildcard that does not match it.
        ("ual*", &["u1"], 0),
    ];
    for (src, want, hidden) in table {
        let q = EventQuery {
            entity: Some(Entity::Account("a@contoso.example".into())),
            fields: vec![(Field::Source, src.to_string())],
            ..EventQuery::default()
        };
        assert_eq!(keys(&case, &q), *want, "source {src:?}");
        let s = events::summary(case.conn(), &q).unwrap();
        assert_eq!(s.total as usize, want.len(), "summary total for {src:?}");
        assert_eq!(s.hidden_trace_events, *hidden, "hidden for {src:?}");
        let h = events::histogram(case.conn(), &q, 60).unwrap();
        let in_histogram: u64 = h.series.iter().flat_map(|s| s.1.iter()).sum();
        assert_eq!(in_histogram as usize, want.len(), "histogram for {src:?}");
    }
    // A blank Source box leaves them hidden as well.
    assert_eq!(keys(&case, &field(Field::Source, "  ")), ["t3", "u1"]);
}

#[test]
fn paging_and_sort() {
    let case = Case::in_memory().unwrap();
    for i in 0..25 {
        put(
            &case,
            &Ev {
                // Two operations alternate, so a sort by operation has ties the order must break.
                op: Some(if i % 2 == 0 { "alpha" } else { "beta" }),
                ..ev(&format!("p{i:02}"), "ual", t0() + Duration::minutes(i))
            },
        );
    }
    // A row without a time sorts last either way.
    put(
        &case,
        &Ev {
            time: None,
            ..ev("pnull", "ual", t0())
        },
    );

    let page = |sort: Option<&Sort>, offset, limit| {
        events::page(case.conn(), &EventQuery::default(), sort, offset, limit).unwrap()
    };
    let first = page(None, 0, 10);
    assert_eq!(
        (first.total, first.total_capped, first.offset),
        (26, false, 0)
    );
    let k = |p: &sparrow_core::case::events::EventsPage| {
        p.rows
            .iter()
            .map(|r| r.record_key.clone())
            .collect::<Vec<_>>()
    };
    // Default: newest first.
    assert_eq!(
        k(&first),
        [
            "p24", "p23", "p22", "p21", "p20", "p19", "p18", "p17", "p16", "p15"
        ]
    );
    assert_eq!(
        k(&page(None, 10, 10)),
        [
            "p14", "p13", "p12", "p11", "p10", "p09", "p08", "p07", "p06", "p05"
        ]
    );
    // The last page holds what is left, the row without a time last.
    let last = page(None, 20, 10);
    assert_eq!(last.total, 26);
    assert_eq!(k(&last), ["p04", "p03", "p02", "p01", "p00", "pnull"]);
    assert_eq!(page(None, 40, 10).rows.len(), 0);

    let asc = Sort {
        column: "event_time".into(),
        descending: false,
    };
    assert_eq!(k(&page(Some(&asc), 0, 3)), ["p00", "p01", "p02"]);
    assert_eq!(k(&page(Some(&asc), 24, 5)), ["p24", "pnull"]);
    let desc = Sort {
        column: "event_time".into(),
        descending: true,
    };
    assert_eq!(k(&page(Some(&desc), 0, 2)), ["p24", "p23"]);

    // Sorted by a column with ties, pages neither overlap nor skip.
    let by_op = Sort {
        column: "operation".into(),
        descending: false,
    };
    let mut seen = Vec::new();
    for off in (0..26).step_by(7) {
        seen.extend(k(&page(Some(&by_op), off, 7)));
    }
    assert_eq!(seen.len(), 26);
    assert_eq!(
        seen.iter().collect::<std::collections::BTreeSet<_>>().len(),
        26
    );
    // All 13 'alpha' rows (even i, plus pnull has no operation: it sorts last) come before the 'beta' rows.
    let ops: Vec<Option<String>> = seen
        .iter()
        .map(|key| {
            case.conn()
                .query_row(
                    "SELECT operation FROM events WHERE record_key = ?",
                    [key],
                    |r| r.get(0),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(
        ops.iter().filter(|o| o.as_deref() == Some("alpha")).count(),
        13
    );
    assert!(ops[..13].iter().all(|o| o.as_deref() == Some("alpha")));
    assert!(ops[13..25].iter().all(|o| o.as_deref() == Some("beta")));
    assert_eq!(ops[25], None);
    // Within the ties: newest first.
    assert_eq!(&seen[..3], ["p24", "p22", "p20"]);

    // Not a column: refused, not interpolated.
    let bad = Sort {
        column: "event_time; DROP TABLE events".into(),
        descending: false,
    };
    assert!(matches!(
        events::page(case.conn(), &EventQuery::default(), Some(&bad), 0, 10),
        Err(Error::Invalid(_))
    ));
    // The total is the filtered total, whatever the page.
    let q = field(Field::Operation, "beta");
    let p = events::page(case.conn(), &q, None, 0, 5).unwrap();
    assert_eq!((p.total, p.rows.len()), (12, 5));
}

#[test]
fn csv_export_columns_and_rows() {
    let case = Case::in_memory().unwrap();
    for i in 0..30 {
        put(
            &case,
            &Ev {
                op: Some(if i < 12 { "Match" } else { "Other" }),
                actor: Some("a@contoso.example"),
                ..ev(&format!("c{i:02}"), "ual", t0() + Duration::seconds(i))
            },
        );
    }
    // One fully filled row, with text a spreadsheet would run and text csv must quote.
    put(
        &case,
        &Ev {
            op: Some("=HYPERLINK(\"x\")"),
            actor: Some("jdoe@contoso.example"),
            owner: Some("shared@contoso.example"),
            ip: Some("203.0.113.5"),
            country: Some("US"),
            asn: Some(64500),
            device_id: Some("dev-1"),
            device_name: Some("LAPTOP, \"one\""),
            session: Some("2222aaaa-2222-4222-8222-22222222bbbb"),
            ..ev(
                "full",
                "signin_interactive",
                t0() + Duration::minutes(5) + Duration::microseconds(250_000),
            )
        },
    );
    case.conn()
        .execute("UPDATE events SET target = 'mailbox', result = 'Success', user_agent = 'UA/1', asn_org = 'Example Net' WHERE record_key = 'full'", [])
        .unwrap();
    for (id, text, at) in [
        ("n1", "first note", "2026-09-02 10:00:00+00"),
        ("n2", "second note", "2026-09-02 11:00:00+00"),
    ] {
        case.conn()
            .execute(
                "INSERT INTO annotations (annotation_id, object_type, object_id, source_table, text, actor, created_at) \
                 VALUES (?, 'evidence', 'full', 'signins', ?, 'analyst:cp', CAST(? AS TIMESTAMPTZ))",
                [id, text, at],
            )
            .unwrap();
    }

    let out = std::env::temp_dir().join(format!("sparrow-events-csv-{}.csv", std::process::id()));
    // 12 matching rows, though a page is smaller than that.
    let q = field(Field::Operation, "Match");
    let n = events::export_csv(case.conn(), &q, &out).unwrap();
    assert_eq!(n, 12);
    let mut rd = csv::Reader::from_path(&out).unwrap();
    assert_eq!(
        rd.headers().unwrap().iter().collect::<Vec<_>>(),
        CSV_COLUMNS
    );
    assert_eq!(
        CSV_COLUMNS.join(","),
        "event_time,source,operation,actor_upn,owner_upn,target,ip,ip_country,asn,asn_org,device_id,device_name,\
         entra_session_id,result,user_agent,flag,tags,latest_note,source_table,record_key"
    );
    let rows: Vec<csv::StringRecord> = rd.records().map(|r| r.unwrap()).collect();
    assert_eq!(rows.len(), 12);
    // The file starts with a UTF-8 BOM, then the header.
    let bytes = std::fs::read(&out).unwrap();
    assert_eq!(&bytes[..3], [0xEF, 0xBB, 0xBF]);
    assert!(bytes[3..].starts_with(b"event_time,source,operation,"));
    // Newest first, ISO 8601 UTC.
    assert_eq!(&rows[0][0], "2026-09-01T10:00:11Z");
    assert_eq!(&rows[11][19], "c00");

    let all = events::export_csv(case.conn(), &EventQuery::default(), &out).unwrap();
    assert_eq!(all, 31);
    let mut rd = csv::Reader::from_path(&out).unwrap();
    let rows: Vec<csv::StringRecord> = rd.records().map(|r| r.unwrap()).collect();
    let full = rows.iter().find(|r| &r[19] == "full").unwrap();
    let got: Vec<&str> = full.iter().collect();
    assert_eq!(
        got,
        [
            "2026-09-01T10:05:00.250Z",
            "signin_interactive",
            // Neutralised: a spreadsheet must not run it.
            "'=HYPERLINK(\"x\")",
            "jdoe@contoso.example",
            "shared@contoso.example",
            "mailbox",
            "203.0.113.5",
            "US",
            "64500",
            "Example Net",
            "dev-1",
            "LAPTOP, \"one\"",
            "2222aaaa-2222-4222-8222-22222222bbbb",
            "Success",
            "UA/1",
            "",
            "",
            "second note",
            "signins",
            "full",
        ]
    );
    // A scoped export holds only the entity's rows.
    let n = events::export_csv(
        case.conn(),
        &scoped(Entity::Account("shared@contoso.example".into())),
        &out,
    )
    .unwrap();
    assert_eq!(n, 1);
    std::fs::remove_file(&out).unwrap();
    // An unwritable path is an error naming the path.
    let bad = std::path::Path::new("/nonexistent-dir-for-sparrow/x.csv");
    assert!(matches!(
        events::export_csv(case.conn(), &q, bad),
        Err(Error::Io { .. })
    ));
}

#[test]
fn search_scans_raw_json() {
    let case = Case::in_memory().unwrap();
    // The needle is in the raw AuditData only; the events row does not carry it.
    insert_record(
        &case,
        T,
        "ual_events",
        &json!({"record_id": "a0000001-0000-4000-8000-000000000001", "event_time": "2026-09-01T10:00:00Z",
                "workload": "Exchange", "operation": "Send", "user_upn": "alice@contoso.example",
                "audit_data": {"Operation": "Send", "ClientInfoString": "Client=Needle-Xyz;Mobile"}}),
        "search",
    )
    .unwrap();
    insert_record(
        &case,
        T,
        "ual_events",
        &json!({"record_id": "a0000002-0000-4000-8000-000000000002", "event_time": "2026-09-01T10:01:00Z",
                "workload": "Exchange", "operation": "Send", "user_upn": "bob@contoso.example",
                "audit_data": {"Operation": "Send", "ClientInfoString": "Client=Outlook;100% sure"}}),
        "search",
    )
    .unwrap();
    insert_record(
        &case,
        T,
        "message_trace",
        &json!({"record_key": "mt-1", "received": "2026-09-01T10:02:00Z", "connector_id": "needle-connector"}),
        "search",
    )
    .unwrap();
    insert_record(
        &case,
        T,
        "signins",
        &json!({"record_key": "si-1", "event_time": "2026-09-01T10:03:00Z", "event_type": "interactive", "user_upn": "alice@contoso.example"}),
        "search",
    )
    .unwrap();
    assert_eq!(events::rebuild(case.conn()).unwrap(), 4);

    let search = |s: &str| EventQuery {
        search: Some(s.into()),
        ..EventQuery::default()
    };
    // Case-insensitive substring of the raw record, in whichever table it is.
    assert_eq!(
        keys(&case, &search("needle-xyz")),
        ["a0000001-0000-4000-8000-000000000001"]
    );
    assert_eq!(
        keys(&case, &search("NEEDLE-XYZ")),
        ["a0000001-0000-4000-8000-000000000001"]
    );
    assert_eq!(keys(&case, &search("needle-conn")), ["mt-1"]);
    // Commas are OR; a wildcard spans text.
    assert_eq!(
        keys(&case, &search("needle-xyz, needle-connector")),
        ["a0000001-0000-4000-8000-000000000001", "mt-1"]
    );
    assert_eq!(
        keys(&case, &search("Client=*Mobile")),
        ["a0000001-0000-4000-8000-000000000001"]
    );
    // `%` is a character, not a pattern.
    assert_eq!(
        keys(&case, &search("100%")),
        ["a0000002-0000-4000-8000-000000000002"]
    );
    assert_eq!(
        keys(&case, &search("100% sure")),
        ["a0000002-0000-4000-8000-000000000002"]
    );
    assert!(keys(&case, &search("zzz-not-present")).is_empty());
    // A signin record is found by what its row holds.
    assert_eq!(keys(&case, &search("si-1")), ["si-1"]);
    // Search ANDs with the other filters, the scope and the range, and feeds the summary and the histogram.
    let q = EventQuery {
        search: Some("needle".into()),
        entity: Some(Entity::Account("bob@contoso.example".into())),
        ..EventQuery::default()
    };
    assert!(keys(&case, &q).is_empty());
    let q = EventQuery {
        search: Some("needle".into()),
        from: Some(t0() + Duration::minutes(1)),
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["mt-1"]);
    let q = search("needle");
    let s = events::summary(case.conn(), &q).unwrap();
    assert_eq!(
        (s.total, s.per_source),
        (2, vec![("ual".into(), 1), ("message_trace".into(), 1)])
    );
    let h = events::histogram(case.conn(), &q, 60).unwrap();
    assert_eq!(h.series.iter().flat_map(|s| s.1.iter()).sum::<u64>(), 2);
}

#[test]
fn search_does_not_cross_tables_on_a_shared_record_key() {
    let case = Case::in_memory().unwrap();
    // The same record_key in two source tables; only the sign-in's raw record holds the term.
    insert_record(
        &case,
        T,
        "signins",
        &json!({"record_key": "dup-1", "event_time": "2026-09-01T10:00:00Z", "event_type": "interactive", "user_agent": "Needle-Dup/1"}),
        "dup",
    )
    .unwrap();
    insert_record(
        &case,
        T,
        "message_trace",
        &json!({"record_key": "dup-1", "received": "2026-09-01T10:01:00Z", "connector_id": "plain"}),
        "dup",
    )
    .unwrap();
    assert_eq!(events::rebuild(case.conn()).unwrap(), 2);
    let search = |s: &str| EventQuery {
        search: Some(s.into()),
        ..EventQuery::default()
    };
    let hits = |q: &EventQuery| {
        events::page(case.conn(), q, None, 0, 10)
            .unwrap()
            .rows
            .into_iter()
            .map(|r| (r.source_table, r.record_key))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        hits(&search("needle-dup")),
        [("signins".to_string(), "dup-1".to_string())]
    );
    assert_eq!(
        hits(&search("plain")),
        [("message_trace".to_string(), "dup-1".to_string())]
    );
    assert_eq!(hits(&search("dup-1")).len(), 2);
}

#[test]
fn flag_and_tag_filters() {
    let case = six_rows();
    let c = case.conn();
    let me = Actor::analyst("carlos").unwrap();
    let ai = Actor::agent("triage", Some("carlos")).unwrap();
    let rows = |keys: &[&str]| -> Vec<RowRef> {
        keys.iter().map(|k| RowRef::new("ual_events", k)).collect()
    };
    // Before any mark: nothing is flagged, tagged or agent-marked, and excluding a tag nobody has leaves every row.
    for flag in [FlagFilter::Suspicious, FlagFilter::Malicious] {
        let q = EventQuery {
            flag,
            ..EventQuery::default()
        };
        assert_eq!(
            events::page(c, &q, None, 0, 10).unwrap().total,
            0,
            "{flag:?}"
        );
    }
    assert!(keys(&case, &field(Field::Tag, "phishing")).is_empty());
    assert_eq!(keys(&case, &field(Field::Tag, "!phishing")).len(), 6);

    // k1 k2 k3 suspicious, k3 k4 malicious (k3's own flag changed to malicious), k5 suspicious by its IP.
    flag_rows(
        c,
        &me,
        &rows(&["k1", "k2", "k3"]),
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    flag_rows(c, &me, &rows(&["k3", "k4"]), Some(FlagLevel::Malicious)).unwrap();
    flag_value(
        c,
        &me,
        ValueKind::Ip,
        "2001:DB8::1",
        None,
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let flagged = |f| EventQuery {
        flag: f,
        ..EventQuery::default()
    };
    assert_eq!(
        keys(&case, &flagged(FlagFilter::Suspicious)),
        ["k1", "k2", "k5"]
    );
    assert_eq!(keys(&case, &flagged(FlagFilter::Malicious)), ["k3", "k4"]);
    assert_eq!(keys(&case, &flagged(FlagFilter::All)).len(), 6);
    let s = events::summary(c, &EventQuery::default()).unwrap();
    assert_eq!((s.total, s.suspicious, s.malicious), (6, 3, 2));
    // The toggle narrows the total; the two counts describe the rest of the query, toggle aside.
    let s = events::summary(c, &flagged(FlagFilter::Suspicious)).unwrap();
    assert_eq!((s.total, s.suspicious, s.malicious), (3, 3, 2));
    // Flags combine with the other filters (AND).
    let q = EventQuery {
        flag: FlagFilter::Suspicious,
        fields: vec![(Field::Account, "*@contoso.example".into())],
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &q), ["k1", "k2"]);

    // Tags: exact and case-insensitive, wildcards, OR lists, and `!` (untagged rows count as lacking the tag).
    tag_rows(c, &me, &rows(&["k1", "k2"]), "Phishing", true).unwrap();
    tag_rows(c, &me, &rows(&["k2"]), "persistence", true).unwrap();
    tag_rows(c, &ai, &rows(&["k3", "k6"]), "ai:odd-login", true).unwrap();
    assert_eq!(keys(&case, &field(Field::Tag, "phishing")), ["k1", "k2"]);
    assert_eq!(keys(&case, &field(Field::Tag, "PHISHING")), ["k1", "k2"]);
    assert_eq!(
        keys(&case, &field(Field::Tag, "ai:*, persistence")),
        ["k2", "k3", "k6"]
    );
    assert_eq!(
        keys(&case, &field(Field::Tag, "!phishing")),
        ["k3", "k4", "k5", "k6"]
    );
    assert_eq!(
        keys(&case, &field(Field::Tag, "!ai:*, !persistence")),
        ["k1", "k4", "k5"]
    );
    assert_eq!(
        keys(&case, &field(Field::Tag, "phishing, !persistence")),
        ["k1"]
    );
    assert!(keys(&case, &field(Field::Tag, "nothing")).is_empty());
    assert_eq!(keys(&case, &field(Field::Tag, "*ish*")), ["k1", "k2"]);

    // The agent filter: k3 (its tag) and k6 are the agent's and unreviewed; confirming k3's tag leaves it marked.
    let marked = |a| EventQuery {
        ai: a,
        ..EventQuery::default()
    };
    assert_eq!(keys(&case, &marked(AiFilter::Marked)), ["k3", "k6"]);
    assert_eq!(keys(&case, &marked(AiFilter::Unreviewed)), ["k3", "k6"]);
    review_marks(
        c,
        &Reviewer::analyst("carlos").unwrap(),
        &rows(&["k3"]),
        true,
    )
    .unwrap();
    assert_eq!(keys(&case, &marked(AiFilter::Marked)), ["k3", "k6"]);
    assert_eq!(keys(&case, &marked(AiFilter::Unreviewed)), ["k6"]);
    let all = EventQuery {
        flag: FlagFilter::All,
        ai: AiFilter::All,
        ..EventQuery::default()
    };
    let p = events::page(c, &all, None, 0, 10).unwrap();
    let k3 = p.rows.iter().find(|r| r.record_key == "k3").unwrap();
    assert_eq!(k3.flag, Some(FlagLevel::Malicious));
    assert_eq!(
        k3.tags
            .iter()
            .map(|t| (t.name.as_str(), t.ai))
            .collect::<Vec<_>>(),
        [("ai:odd-login", false)]
    );
}

#[test]
fn rows_carry_finding_and_note_counts() {
    let case = two_days();
    finding(
        &case,
        "F1",
        "high",
        "new",
        None,
        &[("ual_events", "u1"), ("signins", "s1")],
    );
    finding(
        &case,
        "F2",
        "low",
        "false_positive",
        None,
        &[("ual_events", "u1")],
    );
    case.conn()
        .execute(
            "INSERT INTO annotations (annotation_id, object_type, object_id, source_table, text, actor, created_at) VALUES \
             ('n1', 'evidence', 'u1', 'ual_events', 'old', 'analyst:cp', CAST('2026-09-02 10:00:00+00' AS TIMESTAMPTZ)), \
             ('n2', 'evidence', 'u1', 'ual_events', 'newest', 'analyst:cp', CAST('2026-09-02 12:00:00+00' AS TIMESTAMPTZ)), \
             ('n3', 'evidence', 'u1', 'signins', 'other table, same key', 'analyst:cp', CAST('2026-09-02 13:00:00+00' AS TIMESTAMPTZ)), \
             ('n4', 'finding', 'u1', NULL, 'a finding note', 'analyst:cp', CAST('2026-09-02 14:00:00+00' AS TIMESTAMPTZ))",
            [],
        )
        .unwrap();
    let p = events::page(case.conn(), &EventQuery::default(), None, 0, 50).unwrap();
    let row = |key: &str| p.rows.iter().find(|r| r.record_key == key).unwrap();
    let u1 = row("u1");
    // Both findings count (any status); the notes are the evidence row's own, newest as the latest.
    assert_eq!(
        (u1.finding_count, u1.note_count, u1.latest_note.as_deref()),
        (2, 2, Some("newest"))
    );
    let s1 = row("s1");
    assert_eq!(
        (s1.finding_count, s1.note_count, s1.latest_note.as_deref()),
        (1, 0, None)
    );
    let u2 = row("u2");
    assert_eq!(
        (u2.finding_count, u2.note_count, u2.latest_note.as_deref()),
        (0, 0, None)
    );
    // Evidence listed twice for a finding still counts it once.
    case.conn()
        .execute("INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id) VALUES ('F1', 'ual_events', 'u1', 'context', 2)", [])
        .unwrap();
    let p = events::page(case.conn(), &EventQuery::default(), None, 0, 50).unwrap();
    assert_eq!(
        p.rows
            .iter()
            .find(|r| r.record_key == "u1")
            .unwrap()
            .finding_count,
        2
    );
}

#[test]
fn detail_has_row_raw_refs_and_notes() {
    let case = Case::in_memory().unwrap();
    insert_record(
        &case,
        T,
        "ual_events",
        &json!({"record_id": "a0000001-0000-4000-8000-000000000001", "event_time": "2026-09-01T10:00:00Z",
                "workload": "Exchange", "operation": "Send", "user_upn": "alice@contoso.example",
                "audit_data": {"Operation": "Send", "ClientInfoString": "Client=Needle"}}),
        "detail",
    )
    .unwrap();
    insert_record(&case, T, "signins", &json!({"record_key": "si-1", "event_time": "2026-09-01T10:03:00Z", "event_type": "interactive"}), "detail").unwrap();
    events::rebuild(case.conn()).unwrap();
    case.conn()
        .execute(
            "INSERT INTO annotations (annotation_id, object_type, object_id, source_table, text, actor, created_at) \
             VALUES ('n1', 'evidence', 'si-1', 'signins', 'a note', 'analyst:cp', now())",
            [],
        )
        .unwrap();

    let d = events::detail(
        case.conn(),
        "ual_events",
        "a0000001-0000-4000-8000-000000000001",
    )
    .unwrap();
    assert_eq!(d.row.source, "ual");
    assert_eq!(d.row.operation.as_deref(), Some("Send"));
    assert_eq!(d.raw["audit_data"]["ClientInfoString"], "Client=Needle");
    assert_eq!(d.raw["operation"], "Send");
    assert!(
        d.notes.is_empty() && d.tags.is_empty() && d.flag.is_none() && d.source_refs.is_empty()
    );

    let d = events::detail(case.conn(), "signins", "si-1").unwrap();
    assert_eq!(d.row.source, "signin_interactive");
    assert_eq!(d.raw["record_key"], "si-1");
    assert_eq!(d.notes.len(), 1);
    assert_eq!(d.notes[0].text, "a note");
    assert_eq!(d.row.note_count, 1);

    assert!(matches!(
        events::detail(case.conn(), "signins", "nope"),
        Err(Error::NotFound(_))
    ));
    // Not a table name: refused, never interpolated.
    assert!(matches!(
        events::detail(case.conn(), "events; DROP TABLE events", "x"),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        events::detail(case.conn(), "findings", "x"),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn suggest_completes_from_the_case() {
    let case = six_rows();
    let s = |f, p: &str, n| events::suggest(case.conn(), f, p, n).unwrap();
    assert_eq!(
        s(Field::Account, "a@", 10),
        ["a@contoso.example", "a@fabrikam.example"]
    );
    // Case-insensitive prefix; owners are suggested too.
    assert_eq!(s(Field::Account, "D@", 10), ["d@contoso.example"]);
    assert_eq!(s(Field::Account, "", 3).len(), 3);
    assert_eq!(
        s(Field::Operation, "admin", 10),
        ["AdminAdd", "admin-delete"]
    );
    assert_eq!(
        s(Field::Ip, "203.0.113.", 10),
        ["203.0.113.10", "203.0.113.20", "203.0.113.99"]
    );
    assert_eq!(s(Field::Country, "g", 10), ["GB"]);
    assert_eq!(s(Field::Source, "u", 10), ["ual"]);
    // `%`, `_` and `*` in the prefix are characters.
    assert!(s(Field::Operation, "%", 10).is_empty());
    assert!(s(Field::Operation, "_", 10).is_empty());
    assert!(s(Field::Tag, "a", 10).is_empty());
    assert_eq!(s(Field::Account, "a", 1).len(), 1);
}

/// Wall-clock measurement on a case kept by the synthetic perf harness; nothing to time without it:
/// SPARROW_PERF_KEEP=<dir> cargo test -p sparrow-core --release --test events_query query_timing -- --ignored --nocapture
#[test]
#[ignore = "heavy, wall-clock"]
fn query_timing_on_kept_case() {
    let Some(keep) = std::env::var_os("SPARROW_PERF_KEEP") else {
        println!("SPARROW_PERF_KEEP is not set; nothing to time");
        return;
    };
    let case = Case::create_or_open(&std::path::Path::new(&keep).join("case.duckdb")).unwrap();
    let conn = case.conn();
    let total: i64 = conn
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    println!("events: {total}");
    let busiest: String = conn
        .query_row(
            "SELECT actor_upn FROM events WHERE actor_upn IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let ip: String = conn
        .query_row(
            "SELECT ip FROM events WHERE ip IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let time = |label: &str, f: &dyn Fn() -> String| {
        let t = std::time::Instant::now();
        let out = f();
        println!("{label}: {:.3}s  {out}", t.elapsed().as_secs_f64());
    };
    let scopes: [(&str, EventQuery); 3] = [
        ("whole case", EventQuery::default()),
        ("busiest account", scoped(Entity::Account(busiest.clone()))),
        ("busiest ip", scoped(Entity::Ip(ip.clone()))),
    ];
    for (name, q) in &scopes {
        time(&format!("{name} page"), &|| {
            let p = events::page(conn, q, None, 0, 100).unwrap();
            format!("total {} capped {}", p.total, p.total_capped)
        });
        time(&format!("{name} page sorted by operation"), &|| {
            let s = Sort {
                column: "operation".into(),
                descending: false,
            };
            let p = events::page(conn, q, Some(&s), 1000, 100).unwrap();
            format!("{} rows", p.rows.len())
        });
        time(&format!("{name} summary"), &|| {
            format!("total {}", events::summary(conn, q).unwrap().total)
        });
        time(&format!("{name} histogram"), &|| {
            let h = events::histogram(conn, q, 60).unwrap();
            format!(
                "bucket {}s, {} series, {} findings",
                h.bucket_seconds,
                h.series.len(),
                h.findings.len()
            )
        });
    }
    let filtered = EventQuery {
        fields: vec![
            (Field::Operation, "*Send*, !MailItemsAccessed".into()),
            (Field::Country, "!US".into()),
        ],
        ..EventQuery::default()
    };
    time("wildcard filters page", &|| {
        format!(
            "total {}",
            events::page(conn, &filtered, None, 0, 100).unwrap().total
        )
    });
    time("suggest account prefix", &|| {
        format!(
            "{:?}",
            events::suggest(conn, Field::Account, &busiest[..2], 20)
                .unwrap()
                .len()
        )
    });
    for term in ["Outlook", "zzzz-not-present"] {
        let q = EventQuery {
            search: Some(term.into()),
            ..EventQuery::default()
        };
        time(&format!("search {term:?} whole case page"), &|| {
            format!(
                "total {}",
                events::page(conn, &q, None, 0, 100).unwrap().total
            )
        });
        let q = EventQuery {
            search: Some(term.into()),
            entity: Some(Entity::Account(busiest.clone())),
            ..EventQuery::default()
        };
        time(&format!("search {term:?} busiest account page"), &|| {
            format!(
                "total {}",
                events::page(conn, &q, None, 0, 100).unwrap().total
            )
        });
    }
    let out = std::path::Path::new(&keep).join("events-timing.csv");
    time("csv export of the busiest account", &|| {
        format!(
            "{} rows",
            events::export_csv(conn, &scoped(Entity::Account(busiest.clone())), &out).unwrap()
        )
    });
    let _ = std::fs::remove_file(out);
}

#[test]
fn matching_rows_lists_every_match_in_one_ordered_scan() {
    let case = six_rows();
    let keys_of = |q: &EventQuery, cap: usize| {
        let (rows, capped) = events::matching_rows(case.conn(), q, cap).unwrap();
        let k: Vec<String> = rows.into_iter().map(|r| r.record_key).collect();
        (k, capped)
    };
    let all = EventQuery::default();
    let six: Vec<String> = ["k1", "k2", "k3", "k4", "k5", "k6"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // Oldest first (the rows were made a second apart), and exactly the cap is not "capped".
    assert_eq!(keys_of(&all, 6), (six.clone(), false));
    assert_eq!(keys_of(&all, 100), (six.clone(), false));
    assert_eq!(keys_of(&all, 4), (six[..4].to_vec(), true));
    assert_eq!(keys_of(&all, 5), (six[..5].to_vec(), true));
    assert_eq!(keys_of(&all, 0), (vec![], true));
    // The query's filters apply: the grid's own page and this scan agree.
    for q in [
        field(Field::Account, "*@contoso.example"),
        field(Field::Operation, "!login"),
        scoped(Entity::Ip("2001:DB8::1".into())),
    ] {
        let mut got = keys_of(&q, 100).0;
        assert!(!got.is_empty());
        got.sort();
        assert_eq!(got, keys(&case, &q));
    }
    assert_eq!(
        keys_of(&scoped(Entity::Ip("2001:DB8::1".into())), 100).0,
        vec!["k5"]
    );
    // A time range is inclusive at both ends.
    let q = EventQuery {
        from: Some(t0() + Duration::seconds(1)),
        to: Some(t0() + Duration::seconds(3)),
        ..EventQuery::default()
    };
    assert_eq!(keys_of(&q, 100).0, vec!["k2", "k3", "k4"]);
    // Awkward filter text is refused here too, never read as "everything".
    let err = events::matching_rows(case.conn(), &field(Field::Source, "!"), 10).unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "{err:?}");
}

#[test]
fn histogram_never_exceeds_the_hard_bucket_cap() {
    assert_eq!(events::MAX_HISTOGRAM_BUCKETS, 2_000);
    let day = Duration::days(1);
    let case = Case::in_memory().unwrap();
    put(&case, &ev("a", "ual", t0()));
    let hist = |to: Duration, max: usize| {
        let q = EventQuery {
            from: Some(t0()),
            to: Some(t0() + to),
            ..EventQuery::default()
        };
        let h = events::histogram(case.conn(), &q, max).unwrap();
        let buckets = h.series.first().map_or(0, |(_, c)| c.len());
        (h.bucket_seconds, buckets)
    };
    // Exactly 2,000 one-day buckets (a 1,999-day range) fit, however large the requested maximum.
    assert_eq!(hist(day * 1_999, usize::MAX), (86_400, 2_000));
    assert_eq!(hist(day * 1_999, 5_000), (86_400, 2_000));
    // One day more would be 2,001: the bucket is widened to two days (1,001 buckets), not left at one day.
    assert_eq!(hist(day * 2_000, usize::MAX), (172_800, 1_001));
    // A huge range widens further and still fits the cap.
    let (size, n) = hist(day * 100_000, usize::MAX);
    assert!(
        n <= 2_000 && size % 86_400 == 0 && size > 86_400,
        "{size} {n}"
    );
    // And the fewest whole days: one day less per bucket would exceed the cap.
    let fewer = (100_000 * 86_400 / (size - 86_400)) + 1;
    assert!(fewer > 2_000, "{fewer}");
    // The cap applies below a day too: 2,499 hours is 2,500 hourly buckets, over the cap, so 3-hour buckets (834).
    assert_eq!(hist(Duration::hours(2_499), usize::MAX), (10_800, 834));
    // 2,000 hourly buckets exactly (1,999 hours) fit.
    assert_eq!(hist(Duration::hours(1_999), usize::MAX), (3_600, 2_000));
    // A smaller requested maximum still wins when it is below the cap.
    assert_eq!(hist(Duration::hours(1_999), 100), (86_400, 84));
    // The one-day fallback for a small maximum is unchanged.
    assert_eq!(hist(day * 40, 1), (86_400, 41));
}

#[test]
fn matching_rows_breaks_equal_times_by_table_then_key() {
    let case = Case::in_memory().unwrap();
    // Inserted in a scrambled order, all at one instant, over two tables; plus one later and one earlier row.
    let rows = [
        ("signins", "b", t0()),
        ("ual_events", "a", t0()),
        ("signins", "a", t0()),
        ("ual_events", "b", t0()),
        ("ual_events", "z", t0() + Duration::seconds(1)),
        ("signins", "z", t0() - Duration::seconds(1)),
    ];
    for (table, key, time) in rows {
        let source = if table == "signins" {
            "signin_interactive"
        } else {
            "ual"
        };
        put(
            &case,
            &Ev {
                table,
                ..ev(key, source, time)
            },
        );
    }
    let (got, capped) = events::matching_rows(case.conn(), &EventQuery::default(), 100).unwrap();
    let got: Vec<(String, String)> = got
        .into_iter()
        .map(|r| (r.source_table, r.record_key))
        .collect();
    let want: Vec<(String, String)> = [
        ("signins", "z"),
        ("signins", "a"),
        ("signins", "b"),
        ("ual_events", "a"),
        ("ual_events", "b"),
        ("ual_events", "z"),
    ]
    .iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    assert_eq!((got, capped), (want.clone(), false));
    // A cap in the middle of the tie keeps the first of it, in that order.
    let (cut, capped) = events::matching_rows(case.conn(), &EventQuery::default(), 3).unwrap();
    let cut: Vec<(String, String)> = cut
        .into_iter()
        .map(|r| (r.source_table, r.record_key))
        .collect();
    assert_eq!((cut, capped), (want[..3].to_vec(), true));
}

fn vals(
    case: &Case,
    q: &EventQuery,
    f: Field,
    prefix: &str,
    limit: usize,
) -> (Vec<(String, u64)>, u64) {
    let v = events::values(case.conn(), q, f, prefix, limit).unwrap();
    (
        v.values.into_iter().map(|c| (c.value, c.count)).collect(),
        v.total,
    )
}

fn owned(v: &[(&str, u64)]) -> Vec<(String, u64)> {
    v.iter().map(|(s, n)| (s.to_string(), *n)).collect()
}

#[test]
fn values_count_under_the_other_filters_and_ignore_their_own() {
    let case = six_rows();
    let all = EventQuery::default();
    // Most events first, then by value; NULLs left out.
    assert_eq!(
        vals(&case, &all, Field::Country, "", 10),
        (owned(&[("US", 2), ("GB", 1)]), 2)
    );
    // The field's own filter is left out: the other values stay on offer, with their counts.
    let us = field(Field::Country, "US");
    assert_eq!(
        vals(&case, &us, Field::Country, "", 10),
        (owned(&[("US", 2), ("GB", 1)]), 2)
    );
    // Another field's filter applies.
    let q = field(Field::Account, "*@contoso.example");
    assert_eq!(
        vals(&case, &q, Field::Country, "", 10),
        (owned(&[("US", 2), ("GB", 1)]), 2)
    );
    let q = field(Field::Operation, "login, AdminAdd");
    assert_eq!(
        vals(&case, &q, Field::Country, "", 10),
        (owned(&[("GB", 1), ("US", 1)]), 2)
    );
    // An account is the actor or the mailbox owner: k6 is d@'s mailbox.
    let (accounts, total) = vals(&case, &all, Field::Account, "", 10);
    assert_eq!(total, 6);
    assert!(accounts.contains(&("d@contoso.example".to_string(), 1)));
    // A prefix, case-insensitively; `*` is a wildcard; `%` and `_` are characters.
    assert_eq!(
        vals(&case, &all, Field::Account, "A@", 10),
        (
            owned(&[("a@contoso.example", 1), ("a@fabrikam.example", 1)]),
            2
        )
    );
    assert_eq!(vals(&case, &all, Field::Account, "*fabrikam*", 10).1, 2);
    assert_eq!(vals(&case, &all, Field::Operation, "%", 10).1, 0);
    assert_eq!(vals(&case, &all, Field::Operation, "_", 10).1, 0);
    // The limit cuts the list, the total does not move.
    let (cut, total) = vals(&case, &all, Field::Ip, "", 2);
    assert_eq!((cut.len(), total), (2, 5));
    assert_eq!(
        events::values(case.conn(), &all, Field::Ip, "", 10_000)
            .unwrap()
            .values
            .len(),
        5
    );
    // A limit of 0 is refused, not answered with an empty list and a total of 0.
    match events::values(case.conn(), &all, Field::Ip, "", 0) {
        Err(Error::Invalid(m)) => assert!(m.contains("limit of at least 1"), "{m}"),
        other => panic!("expected Invalid, got {other:?}"),
    }
    // A refused filter of another field is refused here too, naming that field.
    let bad = field(Field::Ip, "!");
    match events::values(case.conn(), &bad, Field::Country, "", 10) {
        Err(Error::Invalid(m)) => assert!(m.contains("IP"), "{m}"),
        other => panic!("expected Invalid, got {other:?}"),
    }
    // ... but its own field's text is not even read.
    assert_eq!(vals(&case, &bad, Field::Ip, "", 10).1, 5);
}

#[test]
fn values_follow_the_scope_the_search_the_flag_and_tags() {
    let case = six_rows();
    let c = case.conn();
    let me = Actor::analyst("carlos").unwrap();
    // An entity scope.
    let q = scoped(Entity::Account("A@CONTOSO.EXAMPLE".into()));
    assert_eq!(
        vals(&case, &q, Field::Operation, "", 10),
        (owned(&[("login", 1)]), 1)
    );
    // The flag toggle.
    flag_rows(
        c,
        &me,
        &[
            RowRef::new("ual_events", "k3"),
            RowRef::new("ual_events", "k4"),
        ],
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    let q = EventQuery {
        flag: FlagFilter::Malicious,
        ..EventQuery::default()
    };
    assert_eq!(
        vals(&case, &q, Field::Operation, "", 10),
        (owned(&[("AdminAdd", 1), ("admin-delete", 1)]), 2)
    );
    // Tags: names in use among the matching events, case folded into one value.
    tag_rows(
        c,
        &me,
        &[
            RowRef::new("ual_events", "k1"),
            RowRef::new("ual_events", "k2"),
        ],
        "phishing",
        true,
    )
    .unwrap();
    tag_rows(
        c,
        &me,
        &[RowRef::new("ual_events", "k2")],
        "persistence",
        true,
    )
    .unwrap();
    assert_eq!(
        vals(&case, &EventQuery::default(), Field::Tag, "", 10),
        (owned(&[("phishing", 2), ("persistence", 1)]), 2)
    );
    let q = field(Field::Tag, "persistence");
    assert_eq!(
        vals(&case, &q, Field::Tag, "", 10),
        (owned(&[("phishing", 2), ("persistence", 1)]), 2)
    );
    let q = field(Field::Operation, "login");
    assert_eq!(
        vals(&case, &q, Field::Tag, "p", 10),
        (owned(&[("phishing", 1)]), 1)
    );
}

#[test]
fn values_under_a_raw_search() {
    let case = Case::in_memory().unwrap();
    for (i, (upn, needle)) in [
        ("alice@contoso.example", "Needle"),
        ("bob@contoso.example", "hay"),
        ("alice@contoso.example", "needle again"),
    ]
    .into_iter()
    .enumerate()
    {
        insert_record(
            &case,
            T,
            "ual_events",
            &json!({"record_id": format!("a000000{i}-0000-4000-8000-000000000001"),
                    "event_time": format!("2026-09-01T10:0{i}:00Z"), "workload": "Exchange", "operation": "Send",
                    "user_upn": upn, "audit_data": {"Operation": "Send", "Note": needle}}),
            "search",
        )
        .unwrap();
    }
    events::rebuild(case.conn()).unwrap();
    let q = EventQuery {
        search: Some("needle".into()),
        ..EventQuery::default()
    };
    assert_eq!(
        vals(&case, &q, Field::Account, "", 10),
        (owned(&[("alice@contoso.example", 2)]), 1)
    );
}

#[test]
fn values_of_source_offer_the_hidden_trace_events() {
    let case = Case::in_memory().unwrap();
    put(&case, &ev("t1", "message_trace_event", t0()));
    put(
        &case,
        &ev("t2", "message_trace_event", t0() + Duration::seconds(1)),
    );
    put(&case, &ev("u1", "ual", t0() + Duration::seconds(2)));
    let q = field(Field::Source, "ual");
    assert_eq!(
        vals(&case, &q, Field::Source, "", 10),
        (owned(&[("message_trace_event", 2), ("ual", 1)]), 2)
    );
    // A quoted name is literal: it names the trace events only when it is their exact name.
    assert!(keys(&case, &field(Field::Source, r#""message_trace*""#)).is_empty());
    assert_eq!(
        keys(&case, &field(Field::Source, r#""message_trace_event""#)),
        ["t1", "t2"]
    );
    // Any other field still sees only what the grid shows.
    assert_eq!(
        vals(&case, &EventQuery::default(), Field::Operation, "", 10),
        (vec![], 0)
    );
}

#[test]
fn values_with_syntax_characters_filter_exactly_when_quoted() {
    let case = Case::in_memory().unwrap();
    let ops = [
        "a,b",
        "a",
        "b",
        "*",
        "x*y",
        "xzy",
        "!bang",
        "bang",
        "say \"hi\"",
        "\"quoted\"",
        " pad ",
    ];
    for (i, op) in ops.into_iter().enumerate() {
        put(
            &case,
            &Ev {
                op: Some(op),
                ..ev(&format!("q{i}"), "ual", t0() + Duration::seconds(i as i64))
            },
        );
    }
    // The text the popover writes for a ticked value (see app/src/events/fieldSyntax.ts, `quoteValue`).
    let table: &[(&str, &[&str])] = &[
        (r#""a,b""#, &["q0"]),
        (r#""*""#, &["q3"]),
        (r#""x*y""#, &["q4"]),
        (r#""!bang""#, &["q6"]),
        (r#"say "hi""#, &["q8"]),
        (r#""""quoted""""#, &["q9"]),
        (r#"" pad ""#, &["q10"]),
        (r#""a,b", a"#, &["q0", "q1"]),
        (
            r#"!"a,b", !a, !b"#,
            &["q10", "q3", "q4", "q5", "q6", "q7", "q8", "q9"],
        ),
        (
            r#"!"*""#,
            &["q0", "q1", "q10", "q2", "q4", "q5", "q6", "q7", "q8", "q9"],
        ),
        // Unquoted, the same characters keep their meaning.
        ("a,b", &["q1", "q2"]),
        ("x*y", &["q4", "q5"]),
    ];
    for (text, want) in table {
        assert_eq!(keys(&case, &field(Field::Operation, text)), *want, "{text}");
    }
    // Every listed value, quoted that way, finds exactly its own events.
    let listed = events::values(
        case.conn(),
        &EventQuery::default(),
        Field::Operation,
        "",
        50,
    )
    .unwrap();
    assert_eq!(listed.total as usize, ops.len());
    for v in listed.values {
        let quoted = format!("\"{}\"", v.value.replace('"', "\"\""));
        let page =
            events::page(case.conn(), &field(Field::Operation, &quoted), None, 0, 50).unwrap();
        assert_eq!(page.total, v.count, "{quoted}");
        assert!(
            page.rows
                .iter()
                .all(|r| r.operation.as_deref() == Some(v.value.as_str())),
            "{quoted}"
        );
    }
    // A quote that is not closed, or text after one, is refused under the field.
    for bad in [r#""a"#, r#""a"b"#] {
        match events::page(case.conn(), &field(Field::Operation, bad), None, 0, 10) {
            Err(Error::Invalid(m)) => assert!(m.starts_with("Operation filter:"), "{m}"),
            other => panic!("{bad}: expected Invalid, got {other:?}"),
        }
    }
    assert!(keys(&case, &field(Field::Operation, r#""a*""#)).is_empty());
}
