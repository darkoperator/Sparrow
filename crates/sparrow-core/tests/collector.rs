//! `case::collector`: the interval index over stored Microsoft-Extractor-Suite collection manifests. What each
//! manifest vouches was fully collected, per tenant x account x source (R2, R3), and which collector gaps stay open
//! (R4, R5). Synthetic manifests only, built with `common/manifest.rs` and loaded through the real ingest.

#[path = "common/manifest.rs"]
mod manifest;

use chrono::DateTime;
use manifest::{M, U, invictus_dir};
use serde_json::json;
use sparrow_core::Case;
use sparrow_core::case::collector::{
    ManifestIndex, OpenGap, Span, Spans, incomplete_collection, load,
};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};

const D1: &str = "2026-09-01T00:00:00Z";
const D2: &str = "2026-09-02T00:00:00Z";
const D3: &str = "2026-09-03T00:00:00Z";
const A: &str = "a@contoso.example";
const B: &str = "b@contoso.example";

fn us(s: &str) -> i64 {
    DateTime::parse_from_rfc3339(s).unwrap().timestamp_micros()
}

/// `[a, b)` from two RFC 3339 times.
fn sp(a: &str, b: &str) -> Span {
    Span {
        start_us: us(a),
        end_us: us(b),
    }
}

fn spans(v: &[(&str, &str)]) -> Spans {
    v.iter().map(|(a, b)| sp(a, b)).collect()
}

fn h(hour: u32) -> String {
    if hour == 24 {
        D2.to_string()
    } else {
        format!("2026-09-01T{hour:02}:00:00Z")
    }
}

/// Collections, each with its tenant (`None` leaves `collections.tenant_key` NULL) and its manifests.
fn index_of(collections: &[(Option<&str>, Vec<M>)]) -> (Case, ManifestIndex) {
    let tmp = tempfile::tempdir().unwrap();
    for (i, (_, ms)) in collections.iter().enumerate() {
        let root = invictus_dir(&tmp.path().join(format!("c{i}")));
        for m in ms {
            m.write(&root);
        }
    }
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        tmp.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM collections", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n as usize, collections.len(), "one collection per folder");
    for (i, (tenant, _)) in collections.iter().enumerate() {
        let changed = case
            .conn()
            .execute(
                "UPDATE collections SET tenant_key = ? WHERE replace(root_path, '\\', '/') LIKE ?",
                duckdb::params![tenant, format!("%/c{i}/CASE_OUTPUT%")],
            )
            .unwrap();
        assert_eq!(changed, 1, "collection c{i}");
    }
    let idx = load(case.conn()).unwrap();
    (case, idx)
}

fn one(tenant: &str, ms: Vec<M>) -> ManifestIndex {
    index_of(&[(Some(tenant), ms)]).1
}

fn day_unit(sources: &[&str], state: &str) -> U {
    U::new(sources, D1, D2, state)
}

#[test]
fn complete_tenant_wide_unit_vouches_every_account() {
    let idx = one(
        "t1",
        vec![M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete"))],
    );
    assert!(!idx.is_empty());
    for acct in [A, B, "anyone@else.example"] {
        assert_eq!(idx.vouched("t1", acct, "ual"), spans(&[(D1, D2)]), "{acct}");
        assert!(idx.account_gaps("t1", acct, "ual").is_empty());
        assert!(idx.vouched("t1", acct, "signins_interactive").is_empty());
    }
    assert!(idx.open_gaps(None).is_empty());
}

#[test]
fn per_user_unit_vouches_only_its_users_case_insensitively() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "complete")
                .unit(day_unit(&["ual"], "complete").users(&[" A@Contoso.example"])),
        ],
    );
    assert_eq!(idx.vouched("t1", A, "ual"), spans(&[(D1, D2)]));
    assert_eq!(
        idx.vouched("t1", " A@CONTOSO.EXAMPLE ", "ual"),
        spans(&[(D1, D2)])
    );
    assert!(idx.vouched("t1", B, "ual").is_empty());
    assert!(idx.vouched_tenant_wide("t1", "ual").is_empty());
}

#[test]
fn partial_unit_vouches_around_its_gap() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial").unit(
                day_unit(&["ual"], "partial")
                    .gap(&h(6), &h(7), "retries_exhausted")
                    .gap_field("detail", json!("HTTP 429 after 5 attempts")),
            ),
        ],
    );
    assert_eq!(
        idx.vouched("t1", A, "ual"),
        spans(&[(D1, &h(6)), (&h(7), D2)])
    );
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(&h(6), &h(7))]));
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    let g = &open[0];
    assert_eq!(g.tenant_key, "t1");
    assert_eq!(g.unit_id, "u-0001");
    assert_eq!(g.cmdlet.as_deref(), Some("Get-UALGraph"));
    assert_eq!(g.sources, vec!["ual".to_string()]);
    assert_eq!(g.user_ids, None);
    assert!(!g.narrowed);
    assert_eq!(g.reason, "retries_exhausted");
    assert_eq!(g.detail.as_deref(), Some("HTTP 429 after 5 attempts"));
    assert_eq!(g.spans, spans(&[(&h(6), &h(7))]));
    assert!(!g.undated);
}

#[test]
fn failed_unit_without_gaps_is_a_whole_range_gap() {
    let idx = one(
        "t1",
        vec![M::run("Get-UALGraph", "failed").unit(day_unit(&["ual"], "failed"))],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(D1, D2)]));
    let open = idx.open_gaps(Some("t1"));
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].reason, "failed");
    assert_eq!(open[0].spans, spans(&[(D1, D2)]));
}

#[test]
fn unknown_state_is_treated_as_failed() {
    let idx = one(
        "t1",
        vec![M::run("Get-UALGraph", "weird").unit(day_unit(&["ual"], "half_done"))],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(D1, D2)]));
    assert_eq!(idx.open_gaps(None)[0].reason, "failed");
}

#[test]
fn search_only_unit_is_a_gap_with_reason_search_only() {
    let idx = one(
        "t1",
        vec![M::run("Get-UALGraph", "search_only").unit(day_unit(&["ual"], "search_only"))],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(D1, D2)]));
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].reason, "search_only");
}

#[test]
fn failed_unit_with_gaps_uses_its_gaps() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "failed").unit(
                day_unit(&["ual"], "failed")
                    .gap(&h(2), &h(5), "search_failed")
                    .search_id("abc-123"),
            ),
        ],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(&h(2), &h(5))]));
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].reason, "search_failed");
    assert_eq!(open[0].search_id.as_deref(), Some("abc-123"));
}

#[test]
fn not_started_unit_uses_its_aborted_gap() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial")
                .unit(day_unit(&["ual"], "not_started").gap(&h(12), D2, "aborted"))
                .unit(U::new(&["signins_interactive"], D1, D2, "not_started")),
        ],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(&h(12), D2)]));
    // No gap listed: the whole range.
    assert_eq!(
        idx.account_gaps("t1", A, "signins_interactive"),
        spans(&[(D1, D2)])
    );
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 2);
    let ual = open.iter().find(|g| g.sources == ["ual"]).unwrap();
    assert_eq!(ual.reason, "aborted");
    assert_eq!(ual.spans, spans(&[(&h(12), D2)]));
}

#[test]
fn output_written_false_neither_vouches_nor_gaps() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "search_only")
                .unit(day_unit(&["ual"], "complete").output_written(false))
                .unit(day_unit(&["signins_interactive"], "search_only").output_written(false))
                .unit(
                    day_unit(&["mail_items_accessed"], "partial")
                        .gap(&h(1), &h(2), "cap_exceeded")
                        .output_written(false),
                ),
        ],
    );
    for s in ["ual", "signins_interactive", "mail_items_accessed"] {
        assert!(idx.vouched("t1", A, s).is_empty(), "{s}");
        assert!(idx.account_gaps("t1", A, s).is_empty(), "{s}");
    }
    assert!(idx.open_gaps(None).is_empty());
    assert!(idx.is_empty());
}

#[test]
fn narrowed_unit_does_not_vouch_but_its_gap_is_open() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-MailItemsAccessed", "partial").unit(
                day_unit(&["mail_items_accessed"], "partial")
                    .operations(&["MailItemsAccessed"])
                    .ips(&["203.0.113.9"])
                    .gap(&h(3), &h(4), "download_incomplete"),
            ),
        ],
    );
    assert!(idx.vouched("t1", A, "mail_items_accessed").is_empty());
    assert!(idx.account_gaps("t1", A, "mail_items_accessed").is_empty());
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert!(open[0].narrowed);
    assert_eq!(open[0].spans, spans(&[(&h(3), &h(4))]));
}

#[test]
fn narrowed_gap_closes_on_identical_scope_or_on_vouching_of_its_sources() {
    let narrowed = || {
        day_unit(&["ual"], "partial")
            .ips(&["203.0.113.9"])
            .gap(&h(3), &h(6), "download_incomplete")
    };
    // Identical scope re-collects 03:00-04:00; a different IP filter closes nothing.
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial").unit(narrowed()),
            M::run("Get-UALGraph", "complete")
                .unit(U::new(&["ual"], &h(3), &h(4), "complete").ips(&["203.0.113.9"]))
                .unit(U::new(&["ual"], &h(4), &h(5), "complete").ips(&["198.51.100.1"])),
        ],
    );
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].spans, spans(&[(&h(4), &h(6))]));
    // A tenant-wide, unfiltered unit vouching the sources closes it too.
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial").unit(narrowed()),
            M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete")),
        ],
    );
    assert!(idx.open_gaps(None).is_empty());
}

#[test]
fn mia_operations_vouch_mail_items_accessed_not_ual() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "complete")
                .unit(day_unit(&["ual"], "complete").operations(&["MailItemsAccessed"])),
            M::run("Get-MailItemsAccessed", "complete").unit(
                U::new(&["mail_items_accessed"], D2, D3, "complete")
                    .operations(&["mailitemsaccessed"]),
            ),
        ],
    );
    assert_eq!(
        idx.vouched("t1", A, "mail_items_accessed"),
        spans(&[(D1, D3)])
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
}

#[test]
fn mia_only_gap_is_a_mail_items_accessed_gap() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial").unit(
                day_unit(&["ual"], "partial")
                    .operations(&["MailItemsAccessed"])
                    .gap(&h(1), &h(2), "cap_exceeded"),
            ),
        ],
    );
    assert!(idx.account_gaps("t1", A, "ual").is_empty());
    assert_eq!(
        idx.account_gaps("t1", A, "mail_items_accessed"),
        spans(&[(&h(1), &h(2))])
    );
    assert_eq!(
        idx.open_gaps(None)[0].sources,
        vec!["mail_items_accessed".to_string()]
    );
}

#[test]
fn message_trace_needs_both_directions() {
    let sender = M::run("Get-MessageTraceLog", "complete").unit(
        day_unit(&["message_trace"], "complete")
            .users(&[A])
            .direction("sender"),
    );
    let idx = one("t1", vec![sender]);
    assert!(idx.vouched("t1", A, "message_trace").is_empty());

    let sender = M::run("Get-MessageTraceLog", "complete").unit(
        day_unit(&["message_trace"], "complete")
            .users(&[A])
            .direction("sender"),
    );
    let recipient = M::run("Get-MessageTraceLog", "complete").unit(
        U::new(
            &["message_trace"],
            &h(12),
            "2026-09-02T12:00:00Z",
            "complete",
        )
        .users(&[A])
        .direction("recipient"),
    );
    let both = M::run("Get-MessageTraceLog", "complete")
        .unit(U::new(&["message_trace"], D2, D3, "complete").users(&[A]));
    let idx = one("t1", vec![sender, recipient, both]);
    assert_eq!(
        idx.vouched("t1", A, "message_trace"),
        spans(&[(&h(12), D3)])
    );
    assert!(idx.vouched("t1", B, "message_trace").is_empty());
}

#[test]
fn signin_pair_unit_vouches_both_sources() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-GraphEntraSignInLogs", "complete").unit(day_unit(
                &["signins_interactive", "signins_noninteractive"],
                "complete",
            )),
        ],
    );
    assert_eq!(
        idx.vouched("t1", A, "signins_interactive"),
        spans(&[(D1, D2)])
    );
    assert_eq!(
        idx.vouched("t1", A, "signins_noninteractive"),
        spans(&[(D1, D2)])
    );
}

#[test]
fn one_signin_type_complete_does_not_vouch_the_other() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-GraphEntraSignInLogs", "partial")
                .unit(day_unit(&["signins_interactive"], "complete"))
                .unit(day_unit(&["signins_noninteractive"], "failed")),
        ],
    );
    assert_eq!(
        idx.vouched("t1", A, "signins_interactive"),
        spans(&[(D1, D2)])
    );
    assert!(idx.vouched("t1", A, "signins_noninteractive").is_empty());
    assert_eq!(
        idx.account_gaps("t1", A, "signins_noninteractive"),
        spans(&[(D1, D2)])
    );
    assert!(idx.account_gaps("t1", A, "signins_interactive").is_empty());
}

#[test]
fn a_later_run_closes_an_earlier_gap() {
    let earlier = || {
        M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").gap(
            &h(6),
            &h(7),
            "retries_exhausted",
        ))
    };
    // A later run in another collection of the same tenant re-collects 05:00-08:00.
    let (_case, idx) = index_of(&[
        (Some("t1"), vec![earlier()]),
        (
            Some("t1"),
            vec![M::run("Get-UALGraph", "complete").unit(U::new(
                &["ual"],
                &h(5),
                &h(8),
                "complete",
            ))],
        ),
    ]);
    assert!(idx.open_gaps(None).is_empty());
    assert!(idx.account_gaps("t1", A, "ual").is_empty());
    assert_eq!(idx.vouched("t1", A, "ual"), spans(&[(D1, D2)]));

    // A later run that covers only half of it leaves the rest open.
    let idx = one(
        "t1",
        vec![
            earlier(),
            M::run("Get-UALGraph", "complete").unit(U::new(
                &["ual"],
                &h(5),
                "2026-09-01T06:30:00Z",
                "complete",
            )),
        ],
    );
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].spans, spans(&[("2026-09-01T06:30:00Z", &h(7))]));
    assert_eq!(
        idx.account_gaps("t1", A, "ual"),
        spans(&[("2026-09-01T06:30:00Z", &h(7))])
    );
}

#[test]
fn tenant_wide_gap_is_not_closed_by_per_user_vouching() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").gap(
                &h(6),
                &h(7),
                "retries_exhausted",
            )),
            M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete").users(&[A])),
        ],
    );
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].spans, spans(&[(&h(6), &h(7))]));
    // Per account, A is vouched for; B is not.
    assert!(idx.account_gaps("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", B, "ual"), spans(&[(&h(6), &h(7))]));
}

#[test]
fn per_user_gap_closes_only_when_every_listed_user_is_vouched() {
    let gapped = || {
        M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").users(&[A, B]).gap(
            &h(6),
            &h(7),
            "retries_exhausted",
        ))
    };
    let only_a =
        || M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete").users(&[A]));
    let only_b =
        || M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete").users(&[B]));
    let idx = one("t1", vec![gapped(), only_a()]);
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].user_ids, Some(vec![A.to_string(), B.to_string()]));
    let idx = one("t1", vec![gapped(), only_a(), only_b()]);
    assert!(idx.open_gaps(None).is_empty());
    // Tenant-wide vouching closes a per-user gap.
    let idx = one(
        "t1",
        vec![
            gapped(),
            M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete")),
        ],
    );
    assert!(idx.open_gaps(None).is_empty());
}

#[test]
fn empty_user_ids_vouch_nobody_and_their_gap_stays_listed() {
    let gapped = || {
        M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").users(&[]).gap(
            &h(6),
            &h(7),
            "retries_exhausted",
        ))
    };
    let idx = one(
        "t1",
        vec![
            gapped(),
            M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete")),
        ],
    );
    // The tenant-wide unit vouches everyone; the [] unit nobody, and its gap applies to no account.
    assert_eq!(idx.vouched("t1", A, "ual"), spans(&[(D1, D2)]));
    assert!(idx.account_gaps("t1", A, "ual").is_empty());
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].user_ids, Some(vec![]));
    let idx = one("t1", vec![gapped()]);
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert!(idx.account_gaps("t1", A, "ual").is_empty());
    // A unit with the identical scope closes it.
    let idx = one(
        "t1",
        vec![
            gapped(),
            M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete").users(&[])),
        ],
    );
    assert!(idx.open_gaps(None).is_empty());
}

#[test]
fn other_tenant_manifest_is_ignored() {
    let (_case, idx) = index_of(&[
        (
            Some("t1"),
            vec![M::run("Get-UALGraph", "failed").unit(day_unit(&["ual"], "failed"))],
        ),
        (
            Some("t2"),
            vec![
                M::run("Get-UALGraph", "partial").unit(
                    day_unit(&["ual"], "partial")
                        .users(&[A])
                        .gap(&h(1), &h(2), "cap_exceeded"),
                ),
            ],
        ),
    ]);
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(D1, D2)]));
    assert_eq!(
        idx.vouched("t2", A, "ual"),
        spans(&[(D1, &h(1)), (&h(2), D2)])
    );
    assert_eq!(idx.account_gaps("t2", A, "ual"), spans(&[(&h(1), &h(2))]));
    assert!(idx.account_gaps("t2", B, "ual").is_empty());
    assert!(idx.vouched("t3", A, "ual").is_empty());
    let t1: Vec<OpenGap> = idx.open_gaps(Some("t1"));
    assert_eq!(t1.len(), 1);
    assert_eq!(t1[0].spans, spans(&[(D1, D2)]));
    let t2 = idx.open_gaps(Some("t2"));
    assert_eq!(t2.len(), 1);
    assert_eq!(t2[0].spans, spans(&[(&h(1), &h(2))]));
    let all = idx.open_gaps(None);
    assert_eq!(
        all.iter()
            .map(|g| g.tenant_key.as_str())
            .collect::<Vec<_>>(),
        ["t1", "t2"]
    );
}

#[test]
fn manifest_of_collection_without_tenant_is_ignored() {
    let (_case, idx) = index_of(&[
        (
            Some("t1"),
            vec![M::run("Get-UALGraph", "failed").unit(day_unit(&["ual"], "failed"))],
        ),
        (
            None,
            vec![M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete"))],
        ),
    ]);
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.open_gaps(None).len(), 1);
}

#[test]
fn open_gaps_are_ordered_by_tenant_start_run_and_unit() {
    let m = M::run("Get-UALGraph", "partial")
        .unit(day_unit(&["ual"], "partial").gap(&h(9), &h(10), "cap_exceeded"))
        .unit(day_unit(&["signins_interactive"], "partial").gap(&h(2), &h(3), "cap_exceeded"))
        .unit(day_unit(&["mail_items_accessed"], "partial").gap(&h(2), &h(3), "cap_exceeded"));
    let idx = one("t1", vec![m]);
    let order: Vec<(String, i64)> = idx
        .open_gaps(None)
        .iter()
        .map(|g| (g.unit_id.clone(), g.spans.iter().next().unwrap().start_us))
        .collect();
    assert_eq!(
        order,
        [
            ("u-0002".to_string(), us(&h(2))),
            ("u-0003".to_string(), us(&h(2))),
            ("u-0001".to_string(), us(&h(9))),
        ]
    );
}

#[test]
fn reversed_range_never_vouches() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "complete")
                .unit(U::new(&["ual"], D2, D1, "complete"))
                .unit(U::new(&["signins_interactive"], D1, D1, "complete"))
                .unit(U::new(
                    &["mail_items_accessed"],
                    "yesterday",
                    D2,
                    "complete",
                )),
            M::run("Get-UALGraph", "failed").unit(U::new(&["entra_audit"], D2, D1, "failed")),
        ],
    );
    for s in [
        "ual",
        "signins_interactive",
        "mail_items_accessed",
        "entra_audit",
    ] {
        assert!(idx.vouched("t1", A, s).is_empty(), "{s}");
        assert!(idx.vouched_tenant_wide("t1", s).is_empty(), "{s}");
        assert!(idx.account_gaps("t1", A, s).is_empty(), "{s}");
    }
    // Every unit without a valid range, whatever its state, is one undated gap: listed without dates.
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 4);
    let mut srcs: Vec<&str> = open.iter().map(|g| g.sources[0].as_str()).collect();
    srcs.sort_unstable();
    assert_eq!(
        srcs,
        [
            "entra_audit",
            "mail_items_accessed",
            "signins_interactive",
            "ual"
        ]
    );
    for g in &open {
        assert!(g.undated, "{}", g.unit_id);
        assert!(g.spans.is_empty(), "{}", g.unit_id);
        assert_eq!(g.reason, "invalid_range", "{}", g.unit_id);
    }
}

#[test]
fn invalid_range_unit_with_dated_gaps_uses_them() {
    // A bad unit range with a gap whose own range is valid: the gap is used as listed, no invalid_range gap.
    let idx = one(
        "t1",
        vec![M::run("Get-UALGraph", "partial").unit(
            U::new(&["ual"], "yesterday", D2, "partial").gap(&h(6), &h(7), "retries_exhausted"),
        )],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(&h(6), &h(7))]));
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].reason, "retries_exhausted");
    assert!(!open[0].undated);
}

#[test]
fn gap_with_bad_range_is_widened_to_its_unit() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").gap(
                &h(7),
                &h(6),
                "retries_exhausted",
            )),
        ],
    );
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert_eq!(idx.account_gaps("t1", A, "ual"), spans(&[(D1, D2)]));
}

#[test]
fn zoneless_range_is_read_as_utc() {
    let idx = one(
        "t1",
        vec![M::run("Get-UALGraph", "complete").unit(U::new(
            &["ual"],
            "2026-09-01T00:00:00",
            "2026-09-02T00:00:00",
            "complete",
        ))],
    );
    assert_eq!(idx.vouched("t1", A, "ual"), spans(&[(D1, D2)]));
}

#[test]
fn tenant_wide_vouching_and_gaps_ignore_per_user_units() {
    let idx = one(
        "t1",
        vec![
            M::run("Get-UALGraph", "partial")
                .unit(day_unit(&["ual"], "partial").gap(&h(6), &h(7), "retries_exhausted"))
                .unit(U::new(&["ual"], D2, D3, "complete").users(&[A]))
                .unit(U::new(&["ual"], D2, D3, "failed").users(&[B])),
            M::run("Get-MessageTraceLog", "complete")
                .unit(day_unit(&["message_trace"], "complete").direction("sender"))
                .unit(U::new(&["message_trace"], &h(12), D3, "complete").direction("recipient"))
                .unit(U::new(&["message_trace"], D1, D3, "complete").users(&[A])),
            M::run("Get-UALGraph", "complete")
                .unit(day_unit(&["signins_interactive"], "complete").ips(&["203.0.113.9"])),
        ],
    );
    assert_eq!(
        idx.vouched_tenant_wide("t1", "ual"),
        spans(&[(D1, &h(6)), (&h(7), D2)])
    );
    assert_eq!(idx.tenant_wide_gaps("t1", "ual"), spans(&[(&h(6), &h(7))]));
    assert_eq!(
        idx.vouched_tenant_wide("t1", "message_trace"),
        spans(&[(&h(12), D2)])
    );
    assert!(
        idx.vouched_tenant_wide("t1", "signins_interactive")
            .is_empty()
    );
    assert!(idx.tenant_wide_gaps("t1", "message_trace").is_empty());
    assert!(idx.vouched_tenant_wide("t2", "ual").is_empty());
}

#[test]
fn a_case_without_manifests_is_an_empty_index() {
    let case = Case::in_memory().unwrap();
    let idx = load(case.conn()).unwrap();
    assert!(idx.is_empty());
    assert!(idx.open_gaps(None).is_empty());
    assert!(idx.vouched("t1", A, "ual").is_empty());
}

// ---- the incomplete-collection banner (Task 7) ----

fn banner(
    collections: &[(Option<&str>, Vec<M>)],
) -> Option<sparrow_core::case::collector::IncompleteCollection> {
    let (case, _) = index_of(collections);
    incomplete_collection(case.conn()).unwrap()
}

#[test]
fn banner_counts_open_gaps_and_names_sources() {
    let later = M::run("Get-UALGraph", "complete").unit(U::new(&["ual"], &h(1), &h(3), "complete"));
    let b = banner(&[
        (
            Some("t1"),
            vec![
                M::run("Get-UALGraph", "partial").unit(
                    day_unit(&["ual"], "partial")
                        .gap(&h(1), &h(2), "retries_exhausted")
                        .gap(&h(10), &h(11), "retries_exhausted"),
                ),
                M::run("Get-MessageTraceV2", "partial").unit(
                    day_unit(&["message_trace"], "partial").gap(&h(4), &h(5), "cap_exceeded"),
                ),
            ],
        ),
        (Some("t1"), vec![later]),
    ])
    .unwrap();
    assert_eq!(b.gaps, 2);
    assert_eq!(b.sources, vec!["ual", "message_trace"]);
    assert_eq!(b.span_us, 2 * 3_600_000_000);
    assert_eq!(
        b.text,
        "Collection incomplete: 2 gaps in Unified audit log, Message trace (2 hours). Re-collect before relying on absence of activity."
    );
}

#[test]
fn banner_text_formats_span() {
    let one = |end: &str, status: &str| {
        banner(&[(
            Some("t1"),
            vec![M::run("Get-UALGraph", status).unit(
                U::new(&["ual"], D1, "2026-09-09T00:00:00Z", "partial").gap(
                    D1,
                    end,
                    "retries_exhausted",
                ),
            )],
        )])
        .unwrap()
        .text
    };
    let t = one("2026-09-01T01:30:00Z", "partial");
    assert_eq!(
        t,
        "Collection incomplete: 1 gap in Unified audit log (1 hour). Re-collect before relying on absence of activity."
    );
    assert!(one("2026-09-02T23:00:00Z", "failed").contains("(47 hours)"));
    assert!(one(D3, "search_only").contains("(2 days)"));
    assert!(one("2026-09-04T00:00:00Z", "partial").contains("(3 days)"));
    assert!(one("2026-09-01T00:00:30Z", "partial").contains("(1 minute)"));
    assert!(one("2026-09-01T00:45:00Z", "partial").contains("(45 minutes)"));
}

#[test]
fn banner_absent_without_manifests() {
    let case = Case::in_memory().unwrap();
    assert!(incomplete_collection(case.conn()).unwrap().is_none());
}

#[test]
fn banner_absent_when_every_run_is_complete() {
    assert!(
        banner(&[(
            Some("t1"),
            vec![M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete"))],
        )])
        .is_none()
    );
}

#[test]
fn banner_clears_after_recollection() {
    let gap_run = || {
        M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").gap(
            &h(6),
            &h(7),
            "retries_exhausted",
        ))
    };
    assert!(banner(&[(Some("t1"), vec![gap_run()])]).is_some());
    let b = banner(&[
        (Some("t1"), vec![gap_run()]),
        (
            Some("t1"),
            vec![M::run("Get-UALGraph", "complete").unit(U::new(
                &["ual"],
                &h(5),
                &h(8),
                "complete",
            ))],
        ),
    ]);
    assert!(b.is_none(), "{b:?}");
}

#[test]
fn reimport_does_not_double_the_count() {
    let m = M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").gap(
        &h(6),
        &h(7),
        "retries_exhausted",
    ));
    // The same manifest in two folders of the case.
    let b = banner(&[(Some("t1"), vec![m.clone_doc()]), (Some("t1"), vec![m])]).unwrap();
    assert_eq!(b.gaps, 1);
}

#[test]
fn banner_counts_undated_gaps_without_span() {
    let m = M::run("Get-UALGraph", "partial").unit(
        U::new(&["ual"], "not a time", "also not", "partial").gap("bad", "worse", "write_failed"),
    );
    let b = banner(&[(Some("t1"), vec![m])]).unwrap();
    assert_eq!(b.gaps, 1);
    assert_eq!(b.span_us, 0);
    assert!(b.text.contains("(unknown span)"), "{}", b.text);
}

#[test]
fn front_matter_has_the_collection_line() {
    use sparrow_core::data::DataDirs;
    use sparrow_core::export::report_md::{self, ReportOpts};
    let render = |ms: Vec<M>| {
        let (case, _) = index_of(&[(Some("t1"), ms)]);
        let mut md = Vec::new();
        report_md::write(
            case.conn(),
            &mut md,
            &ReportOpts {
                reviewed_only: false,
                generated_at: chrono::Utc::now(),
                dirs: DataDirs::default(),
            },
        )
        .unwrap();
        String::from_utf8(md).unwrap()
    };
    let md = render(vec![M::run("Get-UALGraph", "partial").unit(
        day_unit(&["ual"], "partial").gap(&h(6), &h(7), "retries_exhausted"),
    )]);
    let line = "- **Collection:** Collection incomplete: 1 gap in Unified audit log \\(1 hour\\). Re-collect before relying on absence of activity. See *Evidence coverage and what to request*.";
    let at = md.find(line).unwrap_or_else(|| panic!("no line in {md}"));
    assert!(at > md.find("**Decisions shown:**").unwrap());
    assert!(at < md.find("## Scope").unwrap());
    let clean = render(vec![
        M::run("Get-UALGraph", "complete").unit(day_unit(&["ual"], "complete")),
    ]);
    assert!(!clean.contains("**Collection:**"));
}

#[test]
fn banner_counts_a_gap_of_a_run_with_an_unknown_status() {
    let b = banner(&[(
        Some("t1"),
        vec![
            M::run("Get-UALGraph", "weird").unit(day_unit(&["ual"], "partial").gap(
                &h(6),
                &h(7),
                "retries_exhausted",
            )),
        ],
    )])
    .unwrap();
    assert_eq!(b.gaps, 1);
}

// ---- final fix wave: a run that failed before it created any unit ----

/// A `Get-UALGraph -SearchId` run that failed before its unit existed: one undated gap of the run, sources unknown.
#[test]
fn a_failed_run_without_units_is_one_undated_gap() {
    let m = M::run("Get-UALGraph", "failed")
        .param("SearchId", json!("sid-9"))
        .param("StartDate", json!("2026-09-01T00:00:00Z"));
    let run_id = m.run_id();
    let (case, idx) = index_of(&[(Some("t1"), vec![m])]);
    let open = idx.open_gaps(None);
    assert_eq!(open.len(), 1, "{open:?}");
    let g = &open[0];
    assert_eq!(g.tenant_key, "t1");
    assert_eq!(g.run_id, run_id);
    assert!(g.undated);
    assert!(g.spans.is_empty());
    assert!(g.sources.is_empty());
    assert_eq!(g.user_ids, None);
    assert_eq!(g.reason, "run_failed");
    assert_eq!(g.cmdlet.as_deref(), Some("Get-UALGraph"));
    assert_eq!(g.parameters["SearchId"], json!("sid-9"));
    assert_eq!(g.search_id.as_deref(), Some("sid-9"));
    // It vouches nothing and opens no per-account gap.
    assert!(idx.vouched("t1", A, "ual").is_empty());
    assert!(idx.account_gaps("t1", A, "ual").is_empty());
    let b = incomplete_collection(case.conn()).unwrap().unwrap();
    assert_eq!(b.gaps, 1);
    assert!(b.sources.is_empty());
    assert_eq!(
        b.text,
        "Collection incomplete: 1 gap in unknown sources (unknown span). Re-collect before relying on absence of activity."
    );
}

#[test]
fn every_non_complete_run_without_units_is_a_run_gap() {
    for (status, reason) in [
        (json!("partial"), "run_partial"),
        (json!("search_only"), "run_search_only"),
        (json!("weird"), "run_weird"),
        (serde_json::Value::Null, "run_unknown"),
    ] {
        let m = M::run("Get-UALGraph", "x").set("status", status.clone());
        let idx = one("t1", vec![m]);
        let open = idx.open_gaps(None);
        assert_eq!(open.len(), 1, "{status}");
        assert_eq!(open[0].reason, reason, "{status}");
    }
    // A complete run without units, or a failed run whose units are in the manifest, adds no run gap.
    assert!(
        one("t1", vec![M::run("Get-UALGraph", "complete")])
            .open_gaps(None)
            .is_empty()
    );
    assert!(banner(&[(Some("t1"), vec![M::run("Get-UALGraph", "complete")])]).is_none());
    let with_unit = one(
        "t1",
        vec![M::run("Get-UALGraph", "failed").unit(day_unit(&["ual"], "failed"))],
    );
    let open = with_unit.open_gaps(None);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].reason, "failed");
    // A known source of another gap names the banner's sources; the run gap adds none.
    let b = banner(&[(
        Some("t1"),
        vec![
            M::run("Get-UALGraph", "failed"),
            M::run("Get-UALGraph", "partial").unit(day_unit(&["ual"], "partial").gap(
                &h(6),
                &h(7),
                "retries_exhausted",
            )),
        ],
    )])
    .unwrap();
    assert_eq!(b.gaps, 2);
    assert_eq!(
        b.text,
        "Collection incomplete: 2 gaps in Unified audit log (1 hour). Re-collect before relying on absence of activity."
    );
}
