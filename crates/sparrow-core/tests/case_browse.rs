//! `case::browse`: typed, parameterised table filters, sort and paging over a synthetic case.

#[path = "common/detect.rs"]
mod detect;

use serde_json::{Value, json};
use sparrow_core::case::browse::{self, Filter, Sort};
use sparrow_core::{Case, Error};

/// `n` sign-ins: users u0..u2 in turn, ips 203.0.113.0.., event_time one minute apart from 09:00, no user agent.
fn case_with_signins(n: usize) -> Case {
    let c = Case::in_memory().unwrap();
    for i in 0..n {
        detect::insert_row(
            &c,
            "signins",
            "t1",
            json!({
                "user_upn": format!("u{}@x.example", i % 3),
                "ip": format!("203.0.113.{i}"),
                "event_time": format!("2026-08-01T09:{:02}:00Z", i),
                "error_code": if i % 2 == 0 { 0 } else { 50126 },
            }),
        );
    }
    c
}

fn upn(v: &str) -> Filter {
    Filter::Eq {
        column: "user_upn".into(),
        value: json!(v),
    }
}

fn by_time(descending: bool) -> Sort {
    Sort {
        column: "event_time".into(),
        descending,
    }
}

#[test]
fn filters_sort_and_page() {
    let c = case_with_signins(30);
    let f = [upn("u1@x.example")];
    let p = browse::page(c.conn(), "signins", &f, Some(&by_time(true)), 0, 5).unwrap();
    assert_eq!(p.total, 10);
    assert!(!p.total_capped);
    assert_eq!(p.rows.len(), 5);
    let ix = p.columns.iter().position(|c| c == "user_upn").unwrap();
    assert!(p.rows.iter().all(|r| r[ix] == json!("u1@x.example")));
    let t = p.columns.iter().position(|c| c == "event_time").unwrap();
    assert!(p.rows.iter().all(|r| r[t].is_string()));
    assert!(
        p.rows
            .windows(2)
            .all(|w| w[0][t].as_str() > w[1][t].as_str())
    );
    let next = browse::page(c.conn(), "signins", &f, Some(&by_time(true)), 5, 5).unwrap();
    assert_eq!(next.rows.len(), 5);
    assert!(next.rows.iter().all(|r| !p.rows.contains(r)));
    assert!(next.rows[0][t].as_str() < p.rows[4][t].as_str());
    assert_eq!(next.offset, 5);
}

#[test]
fn every_operator() {
    let c = case_with_signins(30);
    let n = |f: Filter| {
        browse::page(c.conn(), "signins", &[f], None, 0, 500)
            .unwrap()
            .total
    };
    // .1 and .10-.19
    assert_eq!(
        n(Filter::Contains {
            column: "ip".into(),
            value: "113.1".into()
        }),
        11
    );
    assert_eq!(
        n(Filter::Contains {
            column: "ip".into(),
            value: "203.0.113.1".to_uppercase()
        }),
        11
    );
    assert_eq!(
        n(Filter::In {
            column: "user_upn".into(),
            values: vec![json!("u0@x.example"), json!("u2@x.example")]
        }),
        20
    );
    assert_eq!(
        n(Filter::In {
            column: "user_upn".into(),
            values: vec![]
        }),
        0
    );
    assert_eq!(
        n(Filter::Ne {
            column: "user_upn".into(),
            value: json!("u0@x.example")
        }),
        20
    );
    assert_eq!(
        n(Filter::IsNull {
            column: "user_agent".into()
        }),
        30
    );
    assert_eq!(
        n(Filter::NotNull {
            column: "ip".into()
        }),
        30
    );
    assert_eq!(
        n(Filter::NotNull {
            column: "user_agent".into()
        }),
        0
    );
    assert_eq!(
        n(Filter::Between {
            column: "event_time".into(),
            low: json!("2026-08-01T09:00:00Z"),
            high: json!("2026-08-01T09:09:00Z")
        }),
        10
    );
    // a number column with non-null values: 15 zeros and 15 of 50126
    assert_eq!(
        n(Filter::Between {
            column: "error_code".into(),
            low: json!(1),
            high: json!(60000)
        }),
        15
    );
    assert_eq!(
        n(Filter::Eq {
            column: "error_code".into(),
            value: json!(50126)
        }),
        15
    );
    assert_eq!(
        n(Filter::In {
            column: "error_code".into(),
            values: vec![json!(0), json!("50126")]
        }),
        30
    );
    assert_eq!(
        n(Filter::Ne {
            column: "error_code".into(),
            value: json!(0)
        }),
        15
    );
    // 50126.0 is the integer 50126; 50126.5 is not an integer
    assert_eq!(
        n(Filter::Eq {
            column: "error_code".into(),
            value: json!(50126.0)
        }),
        15
    );
    assert!(matches!(
        browse::page(
            c.conn(),
            "signins",
            &[Filter::Eq {
                column: "error_code".into(),
                value: json!(50126.5)
            }],
            None,
            0,
            10
        )
        .unwrap_err(),
        Error::Invalid(_)
    ));
    assert!(matches!(
        browse::page(
            c.conn(),
            "signins",
            &[Filter::Eq {
                column: "error_code".into(),
                value: json!("abc")
            }],
            None,
            0,
            10
        )
        .unwrap_err(),
        Error::Invalid(_)
    ));
}

#[test]
fn numeric_columns_compare_in_their_own_type() {
    let c = Case::in_memory().unwrap();
    // DOUBLE: 1 and 1.0 are the same value; 1.5 is another
    for (title, score) in [("a", json!(1)), ("b", json!(1.5)), ("c", json!(2))] {
        detect::insert_row(
            &c,
            "secure_score",
            "t1",
            json!({"title": title, "current_score": score}),
        );
    }
    let n = |table: &str, f: Filter| {
        browse::page(c.conn(), table, &[f], None, 0, 10)
            .unwrap()
            .total
    };
    for v in [json!(1), json!(1.0), json!("1"), json!("1.0")] {
        assert_eq!(
            n(
                "secure_score",
                Filter::Eq {
                    column: "current_score".into(),
                    value: v.clone()
                }
            ),
            1,
            "{v}"
        );
    }
    assert_eq!(
        n(
            "secure_score",
            Filter::Between {
                column: "current_score".into(),
                low: json!(1),
                high: json!(1.5)
            }
        ),
        2
    );
    // BIGINT above 2^53: 9007199254740993 is not 9007199254740992
    for (i, size) in [9_007_199_254_740_992_i64, 9_007_199_254_740_993]
        .into_iter()
        .enumerate()
    {
        detect::insert_row(
            &c,
            "message_trace",
            "t1",
            json!({"sender": format!("s{i}@x.example"), "size_bytes": size}),
        );
    }
    let big = |v: Value| {
        n(
            "message_trace",
            Filter::Eq {
                column: "size_bytes".into(),
                value: v,
            },
        )
    };
    assert_eq!(big(json!(9_007_199_254_740_993_i64)), 1);
    assert_eq!(big(json!("9007199254740993")), 1);
    assert_eq!(
        n(
            "message_trace",
            Filter::Between {
                column: "size_bytes".into(),
                low: json!(9_007_199_254_740_993_i64),
                high: json!(9_007_199_254_740_994_i64)
            }
        ),
        1
    );
}

#[test]
fn filters_combine_with_and() {
    let c = case_with_signins(30);
    let p = browse::page(
        c.conn(),
        "signins",
        &[
            upn("u1@x.example"),
            Filter::Contains {
                column: "ip".into(),
                value: "113.1".into(),
            },
        ],
        None,
        0,
        500,
    )
    .unwrap();
    // u1 has i = 1, 4, 7, 10, ..., 28; of those .1, .10, .13, .16, .19 match "113.1"
    assert_eq!(p.total, 5);
}

#[test]
fn contains_treats_like_wildcards_as_text() {
    let c = case_with_signins(30);
    let n = |v: &str| {
        browse::page(
            c.conn(),
            "signins",
            &[Filter::Contains {
                column: "ip".into(),
                value: v.into(),
            }],
            None,
            0,
            500,
        )
        .unwrap()
        .total
    };
    assert_eq!(n("%"), 0);
    assert_eq!(n("_"), 0);
    assert_eq!(n("\\"), 0);
    assert_eq!(n("113.2_"), 0);
}

#[test]
fn browse_injection_shaped_input_is_inert() {
    let c = case_with_signins(3);
    let p = browse::page(
        c.conn(),
        "signins",
        &[Filter::Eq {
            column: "user_upn".into(),
            value: json!("x' OR 1=1 --"),
        }],
        None,
        0,
        10,
    )
    .unwrap();
    assert_eq!(p.total, 0);
    assert!(matches!(
        browse::page(c.conn(), "signins; DROP TABLE findings", &[], None, 0, 10).unwrap_err(),
        Error::Invalid(_)
    ));
    assert!(matches!(
        browse::page(
            c.conn(),
            "signins",
            &[Filter::IsNull {
                column: "ip) OR (1=1".into()
            }],
            None,
            0,
            10
        )
        .unwrap_err(),
        Error::Invalid(_)
    ));
    assert!(matches!(
        browse::page(
            c.conn(),
            "signins",
            &[],
            Some(&Sort {
                column: "1; --".into(),
                descending: false
            }),
            0,
            10
        )
        .unwrap_err(),
        Error::Invalid(_)
    ));
    // the case is untouched
    assert!(
        browse::tables(c.conn())
            .unwrap()
            .contains(&"findings".to_string())
    );
    assert_eq!(
        browse::page(c.conn(), "signins", &[], None, 0, 10)
            .unwrap()
            .total,
        3
    );
}

#[test]
fn unusable_filter_values_are_refused_not_run() {
    let c = case_with_signins(3);
    let bad = |f: Filter| {
        matches!(
            browse::page(c.conn(), "signins", &[f], None, 0, 10).unwrap_err(),
            Error::Invalid(_)
        )
    };
    assert!(bad(Filter::Eq {
        column: "user_upn".into(),
        value: json!(null)
    }));
    assert!(bad(Filter::Eq {
        column: "user_upn".into(),
        value: json!({"a": 1})
    }));
    assert!(bad(Filter::Between {
        column: "event_time".into(),
        low: json!("not a time"),
        high: json!("2026-08-01T09:09:00Z")
    }));
}

#[test]
fn limit_is_capped_and_json_columns_are_text() {
    let c = case_with_signins(3);
    let p = browse::page(c.conn(), "signins", &[], None, 0, 10_000).unwrap();
    assert!(p.rows.len() <= browse::MAX_PAGE);
    assert_eq!(p.rows.len(), 3);
    let raw = p.columns.iter().position(|c| c == "raw").unwrap();
    assert!(p.rows[0][raw].is_string() || p.rows[0][raw].is_null());
    // struct and list columns are text too
    for name in ["device", "location", "auth_methods"] {
        let ix = p.columns.iter().position(|c| c == name).unwrap();
        assert!(
            p.rows
                .iter()
                .all(|r| !r[ix].is_object() && !r[ix].is_array()),
            "{name}"
        );
    }
    assert!(p.rows.iter().all(|r| r.len() == p.columns.len()));
}

#[test]
fn page_is_stable_without_a_sort_and_views_and_tables_list() {
    let c = case_with_signins(30);
    let all = browse::page(c.conn(), "signins", &[], None, 0, 500).unwrap();
    let a = browse::page(c.conn(), "signins", &[], None, 0, 10).unwrap();
    let b = browse::page(c.conn(), "signins", &[], None, 10, 10).unwrap();
    assert_eq!(a.rows[..], all.rows[..10]);
    assert_eq!(b.rows[..], all.rows[10..20]);
    let tables = browse::tables(c.conn()).unwrap();
    assert!(tables.contains(&"signins".to_string()));
    assert!(tables.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn times_come_back_in_the_core_form_and_filter_in_that_form() {
    let c = case_with_signins(30);
    let p = browse::page(c.conn(), "signins", &[], Some(&by_time(false)), 0, 3).unwrap();
    let t = p.columns.iter().position(|c| c == "event_time").unwrap();
    assert_eq!(p.rows[0][t], json!("2026-08-01T09:00:00.000000Z"));
    assert_eq!(p.rows[2][t], json!("2026-08-01T09:02:00.000000Z"));
    // the form the page returns is accepted back, and is inclusive at both ends
    let n = |low: &str, high: &str| {
        browse::page(
            c.conn(),
            "signins",
            &[Filter::Between {
                column: "event_time".into(),
                low: json!(low),
                high: json!(high),
            }],
            None,
            0,
            500,
        )
        .unwrap()
        .total
    };
    assert_eq!(
        n("2026-08-01T09:00:00.000000Z", "2026-08-01T09:09:00.000000Z"),
        10
    );
    assert_eq!(
        n("2026-08-01T09:00:00.000001Z", "2026-08-01T09:09:00.000000Z"),
        9
    );
    let eq = browse::page(
        c.conn(),
        "signins",
        &[Filter::Eq {
            column: "event_time".into(),
            value: json!("2026-08-01T09:05:00.000000Z"),
        }],
        None,
        0,
        10,
    )
    .unwrap();
    assert_eq!(eq.total, 1);
    // collected_at is NULL for these rows and stays null
    let ca = p.columns.iter().position(|c| c == "collected_at").unwrap();
    assert!(p.rows.iter().all(|r| r[ca].is_null()));
}

#[test]
fn every_json_struct_and_list_value_is_text() {
    let c = case_with_signins(3);
    c.conn()
        .execute_batch(
            "UPDATE signins SET raw = CAST('5' AS JSON), \
                 device = {'device_id': 'd1', 'display_name': NULL, 'os': 'Windows', 'browser': NULL, \
                           'is_compliant': true, 'is_managed': NULL, 'trust_type': NULL}, \
                 auth_methods = ['pwd', 'sms'], \
                 ca_policies = CAST('{\"a\": [1, 2]}' AS JSON) \
             WHERE user_upn = 'u0@x.example'",
        )
        .unwrap();
    let p = browse::page(c.conn(), "signins", &[upn("u0@x.example")], None, 0, 10).unwrap();
    let ix = |n: &str| p.columns.iter().position(|c| c == n).unwrap();
    let row = &p.rows[0];
    assert_eq!(row[ix("raw")], json!("5"));
    assert_eq!(row[ix("auth_methods")], json!("[\"pwd\",\"sms\"]"));
    assert_eq!(row[ix("ca_policies")], json!("{\"a\": [1, 2]}"));
    let device: Value = serde_json::from_str(row[ix("device")].as_str().unwrap()).unwrap();
    assert_eq!(device["os"], "Windows");
    // untouched rows: NULL stays NULL, never the text "null"
    let other = browse::page(c.conn(), "signins", &[upn("u1@x.example")], None, 0, 10).unwrap();
    assert!(
        other
            .rows
            .iter()
            .all(|r| r[ix("device")].is_null() && r[ix("raw")].is_null())
    );
}

#[test]
fn equal_sort_values_page_without_losing_or_repeating_rows() {
    let c = case_with_signins(30); // three distinct user_upn values, ten rows each
    let sort = Sort {
        column: "user_upn".into(),
        descending: false,
    };
    let mut seen = Vec::new();
    for offset in (0..30).step_by(7) {
        let p = browse::page(c.conn(), "signins", &[], Some(&sort), offset, 7).unwrap();
        let k = p.columns.iter().position(|c| c == "record_key").unwrap();
        seen.extend(p.rows.iter().map(|r| r[k].as_str().unwrap().to_string()));
    }
    assert_eq!(seen.len(), 30);
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 30, "a row was repeated");
    // and the order is the same every time
    let again = browse::page(c.conn(), "signins", &[], Some(&sort), 14, 7).unwrap();
    let k = again
        .columns
        .iter()
        .position(|c| c == "record_key")
        .unwrap();
    let again: Vec<_> = again
        .rows
        .iter()
        .map(|r| r[k].as_str().unwrap().to_string())
        .collect();
    assert_eq!(again, seen[14..21]);
}

#[test]
fn views_browse_and_the_count_is_capped() {
    let c = case_with_signins(3);
    c.conn()
        .execute_batch(
            "CREATE VIEW small_view AS SELECT user_upn, ip FROM signins WHERE user_upn = 'u0@x.example'; \
             CREATE VIEW big_view AS SELECT i AS n FROM range(1000001) t(i);",
        )
        .unwrap();
    let tables = browse::tables(c.conn()).unwrap();
    assert!(tables.contains(&"small_view".to_string()) && tables.contains(&"big_view".to_string()));
    let p = browse::page(c.conn(), "small_view", &[], None, 0, 10).unwrap();
    assert_eq!(p.columns, ["user_upn", "ip"]);
    assert_eq!((p.total, p.rows.len()), (1, 1));
    let big = browse::page(c.conn(), "big_view", &[], None, 0, 5).unwrap();
    assert_eq!(big.total, browse::COUNT_CAP);
    assert!(big.total_capped);
    assert_eq!(big.rows.len(), 5);
    // exactly COUNT_CAP matches is not capped
    let exact = browse::page(
        c.conn(),
        "big_view",
        &[Filter::Between {
            column: "n".into(),
            low: json!(0),
            high: json!(999_999),
        }],
        None,
        0,
        5,
    )
    .unwrap();
    assert_eq!(exact.total, browse::COUNT_CAP);
    assert!(!exact.total_capped);
}

#[test]
fn evidence_filter_finds_exactly_the_referenced_record() {
    let c = Case::in_memory().unwrap();
    let id = "02A13335-5A42-4CE8-9F05-5B5F0F489146";
    let other = "12a13335-5a42-4ce8-9f05-5b5f0f489146";
    detect::insert_ual(&c, "t1", json!({"record_id": id.to_ascii_lowercase()}));
    detect::insert_ual(&c, "t1", json!({"record_id": other}));
    detect::insert_row(&c, "signins", "t1", json!({"record_key": "sign-1"}));
    detect::insert_row(&c, "signins", "t1", json!({"record_key": "sign-2"}));
    detect::insert_row(
        &c,
        "mail_items_accessed",
        "t1",
        json!({"item_key": "item-1"}),
    );
    detect::insert_row(
        &c,
        "mail_items_accessed",
        "t1",
        json!({"item_key": "item-2"}),
    );
    for (table, key) in [
        ("ual_events", id),
        ("ual_events", &id.to_ascii_lowercase()),
        ("signins", "sign-1"),
        ("mail_items_accessed", "item-1"),
    ] {
        let f = browse::evidence_filter(c.conn(), table, key).unwrap();
        let p = browse::page(c.conn(), table, &f, None, 0, 10).unwrap();
        assert_eq!(p.total, 1, "{table}:{key} -> {f:?}");
    }
}

#[test]
fn evidence_filter_covers_every_browsable_table() {
    let c = Case::in_memory().unwrap();
    let mut keyed = 0;
    for t in browse::tables(c.conn()).unwrap() {
        let r = browse::evidence_filter(c.conn(), &t, "k");
        let info = sparrow_core::db::describe::describe_conn(c.conn(), Some(&t)).unwrap();
        let info = info.iter().find(|i| i.table == t).unwrap();
        let has_key = info.columns.iter().any(|c| c.name == "record_key");
        let evidence_like = t == "ual_events"
            || t == "mail_items_accessed"
            || (has_key
                && info.kind == "table"
                && ![
                    "finding_evidence",
                    "record_sources",
                    "timeline_entry_evidence",
                ]
                .contains(&t.as_str()));
        match r {
            Ok(f) => {
                assert!(evidence_like, "{t} resolved but is not evidence: {f:?}");
                keyed += 1;
            }
            Err(Error::Invalid(_)) => assert!(!evidence_like, "{t} should resolve"),
            Err(e) => panic!("{t}: {e}"),
        }
    }
    assert!(keyed >= 10, "only {keyed} tables resolved");
    assert!(matches!(
        browse::evidence_filter(c.conn(), "no_such_table", "k"),
        Err(Error::Invalid(_))
    ));
}
