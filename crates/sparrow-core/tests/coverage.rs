//! `case::coverage`: per account and source, the rows, dates and gaps against the reference window, and the pull
//! list. Synthetic case built row by row: tenant `t1` (alice, bob, carol, dave) and tenant `t2` (carol again).
//!
//! t1 events, all UTC: tenant end 2026-07-31 (bob's last UAL row).
//! - alice: 3 UAL rows from the capped export `ual-cap.csv` (07-01 10:00, 07-01 12:00, 07-05 09:00; the last is also
//!   sighted in the uncapped file); no findings, so her window starts at her first row minus 30 days: 06-01.
//! - bob: 2 UAL rows from the uncapped file (07-02, 07-31).
//! - carol: finding first seen 06-16 (window starts 05-17); sign-ins interactive 06-11 and 06-21, non-interactive
//!   06-15 twice; one UAL row 06-12; message trace m1 carol to dave 06-12, m2 dave to carol 06-13, m3 carol to carol
//!   06-14; Entra audit d1 carol initiated / dave target 06-12, d2 dave initiated / CAROL target (key
//!   `UserPrincipalName`) 06-13, d3 carol initiated and targeted 06-14; no MailItemsAccessed, no mailbox audit.
//! - dave: one MailItemsAccessed UAL row 06-20 and one parent-less mail_items_accessed row 06-25.
//!
//! t2 (events up to 2026-08-10): carol, 2 UAL rows (08-01, 08-10), finding first seen 08-05.

#[path = "common/manifest.rs"]
mod manifest;

use chrono::NaiveDate;
use duckdb::params;
use sparrow_core::Case;
use sparrow_core::case::coverage::{
    AccountCoverage, Coverage, CoverageOptions, Gap, RangeCoverage, RangeState, SourceCoverage,
    coverage, coverage_for_range, fill, thousands,
};
use sparrow_core::data::DataDirs;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};

const ORG: &str = "c9c9c9c9-0000-4000-8000-000000000001";
const ALICE: &str = "alice@contoso.example";
const BOB: &str = "bob@contoso.example";
const CAROL: &str = "carol@contoso.example";
const DAVE: &str = "dave@contoso.example";
const CAP: &str = r#"["row count equals known export cap 1000000 — results likely truncated"]"#;

fn d(s: &str) -> NaiveDate {
    NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
}

fn collection(case: &Case, tenant: &str) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO collections (tool, root_path, sparrow_version, tenant_key) \
             VALUES ('invictus', '/x/' || ?, 't', ?) RETURNING collection_id",
            params![tenant, tenant],
            |r| r.get(0),
        )
        .unwrap()
}

fn file(case: &Case, c: i64, rel: &str, warnings: Option<&str>) -> i64 {
    case.conn()
        .query_row(
            "INSERT INTO source_files (collection_id, rel_path, size_bytes, sha256, status, warnings) \
             VALUES (?, ?, 1, 'h' || ?, 'parsed', CAST(? AS JSON)) RETURNING file_id",
            params![c, rel, rel, warnings],
            |r| r.get(0),
        )
        .unwrap()
}

fn sighted(case: &Case, table: &str, key: &str, f: i64) {
    case.conn()
        .execute(
            "INSERT INTO record_sources VALUES (?, ?, ?, 0, 1, 1, 0, 1, 'h')",
            params![table, key, f],
        )
        .unwrap();
}

fn ual(case: &Case, c: i64, f: i64, n: u32, at: &str, op: &str, upn: &str) -> String {
    let id = format!("00000000-0000-4000-8000-{n:012}");
    case.conn()
        .execute(
            "INSERT INTO ual_events (record_id, collection_id, event_time, time_tz_assumed, time_precision, \
                 organization_id, workload, operation, user_upn, audit_data, data_completeness, synthetic_id) \
             VALUES (CAST(? AS UUID), ?, CAST(? AS TIMESTAMPTZ), false, 'second', CAST(? AS UUID), \
                 'Exchange', ?, ?, '{}', 'full', false)",
            params![id, c, format!("{at}+00"), ORG, op, upn],
        )
        .unwrap();
    sighted(case, "ual_events", &id, f);
    id
}

fn signin(case: &Case, c: i64, f: i64, key: &str, at: &str, kind: &str, upn: &str) {
    case.conn()
        .execute(
            "INSERT INTO signins (record_key, collection_id, event_time, event_type, user_upn) \
             VALUES (?, ?, CAST(? AS TIMESTAMPTZ), CAST(? AS signin_event_type), ?)",
            params![key, c, format!("{at}+00"), kind, upn],
        )
        .unwrap();
    sighted(case, "signins", key, f);
}

fn trace(case: &Case, c: i64, f: i64, key: &str, at: &str, sender: &str, recipient: &str) {
    case.conn()
        .execute(
            "INSERT INTO message_trace (record_key, collection_id, received, sender, recipient) \
             VALUES (?, ?, CAST(? AS TIMESTAMPTZ), ?, ?)",
            params![key, c, format!("{at}+00"), sender, recipient],
        )
        .unwrap();
    sighted(case, "message_trace", key, f);
}

fn audit_row(case: &Case, c: i64, f: i64, key: &str, at: &str, actor: &str, targets: &str) {
    case.conn()
        .execute(
            "INSERT INTO directory_audits (record_key, collection_id, event_time, initiated_by_upn, targets) \
             VALUES (?, ?, CAST(? AS TIMESTAMPTZ), ?, CAST(? AS JSON))",
            params![key, c, format!("{at}+00"), actor, targets],
        )
        .unwrap();
    sighted(case, "directory_audits", key, f);
}

fn rollup(case: &Case, tenant: &str, upn: &str) {
    case.conn()
        .execute(
            "INSERT INTO account_rollup (tenant_key, upn, worst_severity, finding_count, by_severity, stages, rules, \
                 addresses, addresses_total, addresses_truncated, computed_run_id) \
             VALUES (?, ?, 'high', 1, '{}', '[]', '[]', '[]', 0, false, 1)",
            params![tenant, upn],
        )
        .unwrap();
}

fn finding(case: &Case, id: &str, tenant: &str, upn: &str, first_seen: &str) {
    case.conn()
        .execute(
            "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, rule_version, rule_sha256, severity, \
                 title, actor_upn, first_seen, created_by, created_at, updated_at) \
             VALUES (?, ?, ?, 'SPW-ID-004', 1, 'x', 'high', 't', ?, CAST(? AS TIMESTAMPTZ), 'rule', now(), now())",
            params![id, id, tenant, upn, format!("{first_seen}+00")],
        )
        .unwrap();
}

fn case() -> Case {
    let case = Case::in_memory().unwrap();
    let c1 = collection(&case, "t1");
    let cap = file(&case, c1, "ual-cap.csv", Some(CAP));
    let ok = file(&case, c1, "ual-ok.csv", None);
    // alice: capped export; the last row is also in the uncapped file.
    ual(&case, c1, cap, 1, "2026-07-01 10:00:00", "Send", ALICE);
    ual(&case, c1, cap, 2, "2026-07-01 12:00:00", "Send", ALICE);
    let id = ual(&case, c1, cap, 3, "2026-07-05 09:00:00", "Send", ALICE);
    sighted(&case, "ual_events", &id, ok);
    // bob: uncapped.
    ual(&case, c1, ok, 4, "2026-07-02 08:00:00", "Send", BOB);
    ual(&case, c1, ok, 5, "2026-07-31 23:30:00", "Send", BOB);
    // carol.
    ual(&case, c1, ok, 6, "2026-06-12 08:00:00", "Send", CAROL);
    signin(
        &case,
        c1,
        ok,
        "s1",
        "2026-06-11 09:00:00",
        "interactive",
        CAROL,
    );
    signin(
        &case,
        c1,
        ok,
        "s2",
        "2026-06-21 09:00:00",
        "interactive",
        CAROL,
    );
    signin(
        &case,
        c1,
        ok,
        "s3",
        "2026-06-15 09:00:00",
        "noninteractive",
        CAROL,
    );
    signin(
        &case,
        c1,
        ok,
        "s4",
        "2026-06-15 10:00:00",
        "noninteractive",
        CAROL,
    );
    // A service principal sign-in carrying carol's name is neither kind.
    signin(
        &case,
        c1,
        ok,
        "s5",
        "2026-06-16 10:00:00",
        "service_principal",
        CAROL,
    );
    trace(&case, c1, ok, "m1", "2026-06-12 10:00:00", CAROL, DAVE);
    trace(&case, c1, ok, "m2", "2026-06-13 10:00:00", DAVE, CAROL);
    trace(&case, c1, ok, "m3", "2026-06-14 10:00:00", CAROL, CAROL);
    audit_row(
        &case,
        c1,
        ok,
        "d1",
        "2026-06-12 11:00:00",
        CAROL,
        r#"[{"userPrincipalName":"dave@contoso.example"}]"#,
    );
    audit_row(
        &case,
        c1,
        ok,
        "d2",
        "2026-06-13 11:00:00",
        DAVE,
        r#"[{"UserPrincipalName":"CAROL@contoso.example"}]"#,
    );
    audit_row(
        &case,
        c1,
        ok,
        "d3",
        "2026-06-14 11:00:00",
        CAROL,
        r#"[{"userPrincipalName":"carol@contoso.example"}]"#,
    );
    // dave: MailItemsAccessed in the UAL and as a parent-less MessageIDs row.
    ual(
        &case,
        c1,
        ok,
        7,
        "2026-06-20 08:00:00",
        "MailItemsAccessed",
        DAVE,
    );
    case.conn()
        .execute(
            "INSERT INTO mail_items_accessed (item_ordinal, collection_id, item_key, event_time, user_upn) \
             VALUES (0, ?, 'k1', CAST('2026-06-25 08:00:00+00' AS TIMESTAMPTZ), ?)",
            params![c1, DAVE],
        )
        .unwrap();
    sighted(&case, "mail_items_accessed", "k1", ok);
    finding(&case, "f1", "t1", CAROL, "2026-06-16 12:00:00");
    rollup(&case, "t1", CAROL);
    rollup(&case, "t1", ALICE);

    let c2 = collection(&case, "t2");
    let f2 = file(&case, c2, "ual-t2.csv", None);
    ual(&case, c2, f2, 8, "2026-08-01 08:00:00", "Send", CAROL);
    ual(&case, c2, f2, 9, "2026-08-10 08:00:00", "Send", CAROL);
    finding(&case, "f2", "t2", CAROL, "2026-08-05 12:00:00");
    rollup(&case, "t2", CAROL);
    case
}

fn run(case: &Case, tenant: Option<&str>, users: &[&str]) -> Coverage {
    coverage(
        case.conn(),
        &CoverageOptions {
            tenant: tenant.map(str::to_string),
            users: users.iter().map(|u| u.to_string()).collect(),
            dirs: DataDirs::default(),
        },
    )
    .unwrap()
}

fn account<'a>(c: &'a Coverage, tenant: &str, upn: &str) -> &'a AccountCoverage {
    c.accounts
        .iter()
        .find(|a| a.tenant_key == tenant && a.upn == upn)
        .unwrap_or_else(|| panic!("no account {tenant}/{upn} in {:?}", c.accounts))
}

fn source<'a>(a: &'a AccountCoverage, id: &str) -> &'a SourceCoverage {
    a.sources.iter().find(|s| s.source == id).unwrap()
}

fn gaps(s: &SourceCoverage) -> Vec<(String, String, &str)> {
    s.gaps
        .iter()
        .map(|g: &Gap| (g.from.to_string(), g.to.to_string(), g.reason.as_str()))
        .collect()
}

fn g(from: &str, to: &str, reason: &'static str) -> (String, String, &'static str) {
    (from.to_string(), to.to_string(), reason)
}

#[test]
fn thousands_separator() {
    assert_eq!(thousands(0), "0");
    assert_eq!(thousands(999), "999");
    assert_eq!(thousands(1_000), "1,000");
    assert_eq!(thousands(1_234_567), "1,234,567");
}

#[test]
fn a_capped_export_is_sampled_and_its_range_is_a_gap() {
    let case = case();
    let c = run(&case, Some("t1"), &[]);
    let alice = account(&c, "t1", ALICE);
    let w = alice.window.unwrap();
    assert_eq!((w.start, w.end), (d("2026-06-01"), d("2026-07-31")));
    let ual = source(alice, "ual");
    assert_eq!((ual.rows, ual.days, ual.sampled), (3, 2, true));
    assert_eq!(ual.first.unwrap().to_rfc3339(), "2026-07-01T10:00:00+00:00");
    assert_eq!(ual.last.unwrap().to_rfc3339(), "2026-07-05T09:00:00+00:00");
    assert_eq!(
        gaps(ual),
        vec![
            g("2026-06-01", "2026-06-30", "before"),
            g("2026-07-01", "2026-07-05", "sampled"),
            g("2026-07-06", "2026-07-31", "after"),
        ]
    );
    // The same kind of rows in an uncapped file are not sampled (bob, by --user).
    let c = run(&case, Some("t1"), &[BOB]);
    let bob = account(&c, "t1", BOB);
    let ual = source(bob, "ual");
    assert_eq!((ual.rows, ual.days, ual.sampled), (2, 2, false));
    // bob's window starts 30 days before his first row (07-02): 06-02; his last row is the tenant's last.
    assert_eq!(gaps(ual), vec![g("2026-06-02", "2026-07-01", "before")]);
}

#[test]
fn signins_split_by_type_and_gaps_are_exact() {
    let case = case();
    let c = run(&case, Some("t1"), &[]);
    let carol = account(&c, "t1", CAROL);
    // Finding first seen 06-16 minus 30 days; the tenant's last event is 07-31.
    let w = carol.window.unwrap();
    assert_eq!((w.start, w.end), (d("2026-05-17"), d("2026-07-31")));
    let i = source(carol, "signins_interactive");
    assert_eq!((i.rows, i.days, i.sampled), (2, 2, false));
    assert_eq!(i.first.unwrap().to_rfc3339(), "2026-06-11T09:00:00+00:00");
    assert_eq!(i.last.unwrap().to_rfc3339(), "2026-06-21T09:00:00+00:00");
    assert_eq!(
        gaps(i),
        vec![
            g("2026-05-17", "2026-06-10", "before"),
            g("2026-06-22", "2026-07-31", "after"),
        ]
    );
    let n = source(carol, "signins_noninteractive");
    assert_eq!((n.rows, n.days), (2, 1));
    assert_eq!(
        gaps(n),
        vec![
            g("2026-05-17", "2026-06-14", "before"),
            g("2026-06-16", "2026-07-31", "after"),
        ]
    );
}

#[test]
fn no_rows_in_a_source_is_absent_over_the_whole_window() {
    let case = case();
    let c = run(&case, Some("t1"), &[]);
    let carol = account(&c, "t1", CAROL);
    for id in ["mail_items_accessed", "mailbox_audit"] {
        let s = source(carol, id);
        assert_eq!((s.rows, s.days, s.sampled), (0, 0, false), "{id}");
        assert!(s.first.is_none() && s.last.is_none(), "{id}");
        assert_eq!(
            gaps(s),
            vec![g("2026-05-17", "2026-07-31", "absent")],
            "{id}"
        );
    }
}

#[test]
fn mail_items_accessed_counts_the_ual_operation_and_the_parentless_rows() {
    let case = case();
    let c = run(&case, Some("t1"), &[DAVE]);
    let dave = account(&c, "t1", DAVE);
    let m = source(dave, "mail_items_accessed");
    assert_eq!((m.rows, m.days), (2, 2));
    assert_eq!(m.first.unwrap().to_rfc3339(), "2026-06-20T08:00:00+00:00");
    assert_eq!(m.last.unwrap().to_rfc3339(), "2026-06-25T08:00:00+00:00");
    // The MailItemsAccessed UAL row is also a UAL row of dave; nothing else is.
    assert_eq!(source(dave, "ual").rows, 1);
}

#[test]
fn message_trace_counts_sender_and_recipient_and_audit_counts_actor_and_target() {
    let case = case();
    let c = run(&case, Some("t1"), &[CAROL, DAVE]);
    let carol = account(&c, "t1", CAROL);
    let dave = account(&c, "t1", DAVE);
    // m1 (sender), m2 (recipient), m3 (sender and recipient: once).
    let t = source(carol, "message_trace");
    assert_eq!((t.rows, t.days), (3, 3));
    assert_eq!(t.first.unwrap().to_rfc3339(), "2026-06-12T10:00:00+00:00");
    assert_eq!(t.last.unwrap().to_rfc3339(), "2026-06-14T10:00:00+00:00");
    // m1 (recipient), m2 (sender).
    assert_eq!(source(dave, "message_trace").rows, 2);
    // d1 (actor), d2 (target, key and value in other case), d3 (actor and target: once).
    let a = source(carol, "entra_audit");
    assert_eq!((a.rows, a.days), (3, 3));
    assert_eq!(a.first.unwrap().to_rfc3339(), "2026-06-12T11:00:00+00:00");
    assert_eq!(a.last.unwrap().to_rfc3339(), "2026-06-14T11:00:00+00:00");
    // d1 (target), d2 (actor).
    assert_eq!(source(dave, "entra_audit").rows, 2);
}

#[test]
fn user_limits_the_accounts_and_an_unknown_user_is_absent_everywhere() {
    let case = case();
    let c = run(&case, Some("t1"), &[CAROL]);
    assert_eq!(c.accounts.len(), 1);
    assert_eq!(
        (
            c.accounts[0].upn.as_str(),
            c.accounts[0].tenant_key.as_str()
        ),
        (CAROL, "t1")
    );
    // Without --user: the accounts with findings, in roll-up order, only.
    let c = run(&case, Some("t1"), &[]);
    let mut upns: Vec<&str> = c.accounts.iter().map(|a| a.upn.as_str()).collect();
    upns.sort();
    assert_eq!(upns, vec![ALICE, CAROL]);
    // Case and spelling do not matter; an unknown user has nothing, over the window of the tenant's data:
    // no finding and no row, so it starts at the tenant's first event (06-11 sign-in? no: 06-11 09:00 is carol's;
    // the first event of t1 is 06-11) and ends at its last (07-31).
    let c = run(&case, Some("t1"), &["Nobody@Contoso.example"]);
    let n = account(&c, "t1", "nobody@contoso.example");
    let w = n.window.unwrap();
    assert_eq!((w.start, w.end), (d("2026-06-11"), d("2026-07-31")));
    assert_eq!(n.sources.len(), 7);
    for s in &n.sources {
        assert_eq!((s.rows, s.days, s.sampled), (0, 0, false), "{}", s.source);
        assert_eq!(
            gaps(s),
            vec![g("2026-06-11", "2026-07-31", "absent")],
            "{}",
            s.source
        );
    }
    // A request for every source.
    assert_eq!(c.requests.len(), 7);
}

#[test]
fn two_tenants_do_not_mix() {
    let case = case();
    let c = run(&case, None, &[]);
    assert_eq!(c.accounts.len(), 3);
    let t1 = account(&c, "t1", CAROL);
    let t2 = account(&c, "t2", CAROL);
    // t1: one UAL row, window 05-17..07-31. t2: two UAL rows, window 07-06..08-10, nothing else.
    assert_eq!(source(t1, "ual").rows, 1);
    assert_eq!(source(t2, "ual").rows, 2);
    let w = t2.window.unwrap();
    assert_eq!((w.start, w.end), (d("2026-07-06"), d("2026-08-10")));
    assert_eq!(t1.window.unwrap().end, d("2026-07-31"));
    for id in [
        "signins_interactive",
        "signins_noninteractive",
        "message_trace",
        "entra_audit",
    ] {
        assert_eq!(source(t2, id).rows, 0, "{id}");
    }
    assert_eq!(
        gaps(source(t2, "ual")),
        vec![g("2026-07-06", "2026-07-31", "before")]
    );
    // --tenant picks one.
    let c = run(&case, Some("t2"), &[]);
    assert_eq!(c.accounts.len(), 1);
    assert_eq!(c.accounts[0].tenant_key, "t2");
}

#[test]
fn the_pull_list_merges_gaps_per_source_and_fills_the_templates() {
    let case = case();
    let c = run(&case, Some("t1"), &[ALICE, CAROL]);
    let req = |user: &str, source: &str| {
        c.requests
            .iter()
            .find(|r| r.user == user && r.source == source)
            .unwrap_or_else(|| panic!("no request {user}/{source}"))
    };
    // alice's UAL: before, sampled and after merge into 06-01..07-31, reasons in order.
    let r = req(ALICE, "ual");
    assert_eq!((r.from, r.to), (d("2026-06-01"), d("2026-07-31")));
    assert_eq!(r.reasons, vec!["before", "sampled", "after"]);
    assert_eq!(
        r.invictus.as_deref(),
        Some("Get-UAL -UserIds alice@contoso.example -StartDate 2026-06-01 -EndDate 2026-08-01")
    );
    assert_eq!(
        r.console.as_deref(),
        Some(
            "Purview portal > Audit > Search: Users = alice@contoso.example, date range 2026-06-01 to 2026-07-31, Search, then Export (a per-user search stays under the 1,000,000-row cap)"
        )
    );
    // Hawk has no per-user UAL export: null stays null.
    assert_eq!(r.hawk, None);
    // carol's non-interactive sign-ins: before and after merge into the whole window.
    let r = req(CAROL, "signins_noninteractive");
    assert_eq!((r.from, r.to), (d("2026-05-17"), d("2026-07-31")));
    assert_eq!(r.reasons, vec!["before", "after"]);
    assert_eq!(
        r.invictus.as_deref(),
        Some(
            "Get-GraphEntraSignInLogs -UserIds carol@contoso.example -startDate 2026-05-17 -endDate 2026-08-01 -EventTypes nonInteractiveUser"
        )
    );
    assert!(
        r.console
            .as_deref()
            .unwrap()
            .contains("(non-interactive) tab")
    );
    assert_eq!(r.hawk, None);
    // Hawk does have a sign-in cmdlet for the interactive ones.
    let r = req(CAROL, "signins_interactive");
    assert_eq!(
        r.hawk.as_deref(),
        Some(
            "Get-HawkUserEntraIDSignInLog -UserPrincipalName carol@contoso.example (Hawk sets the window when it starts, 2026-05-17 to 2026-07-31; Graph allows only the last 14 days there; its filter names no event type, so non-interactive sign-ins are not guaranteed)"
        )
    );
    // carol's absent mailbox audit: one request, reason absent.
    let r = req(CAROL, "mailbox_audit");
    assert_eq!(r.reasons, vec!["absent"]);
    assert_eq!(
        r.invictus.as_deref(),
        Some(
            "Get-MailboxAuditLogLegacy -UserIds carol@contoso.example -StartDate 2026-05-17 -EndDate 2026-08-01"
        )
    );
    assert_eq!(r.hawk, None);
    // One request per account and source with gaps, never two.
    let mut keys: Vec<(&str, &str)> = c
        .requests
        .iter()
        .map(|r| (r.user.as_str(), r.source.as_str()))
        .collect();
    let n = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), n);
    // No gap, no request: carol's message trace and Entra audit end 06-14/06-14 inside a window ending 07-31, so
    // they have `before` and `after` gaps and are requested.
    assert_eq!(req(CAROL, "message_trace").reasons, vec!["before", "after"]);
}

#[test]
fn a_hint_file_can_say_null_and_replaces_the_built_in_by_source() {
    let case = case();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("lists")).unwrap();
    std::fs::write(
        dir.path().join("lists/collection_hints.yaml"),
        "version: 1\nsources:\n  - source: ual\n    console: null\n    hawk: \"H {upn} {from}..{to}\"\n    invictus: null\n",
    )
    .unwrap();
    let c = coverage(
        case.conn(),
        &CoverageOptions {
            tenant: Some("t1".into()),
            users: vec![BOB.into()],
            dirs: DataDirs {
                data: None,
                rules: vec![dir.path().to_path_buf()],
            },
        },
    )
    .unwrap();
    let r = c.requests.iter().find(|r| r.source == "ual").unwrap();
    assert_eq!(r.console, None);
    assert_eq!(r.invictus, None);
    assert_eq!(
        r.hawk.as_deref(),
        Some("H bob@contoso.example 2026-06-02..2026-07-01")
    );
    // The other sources keep the built-in hints.
    let m = c
        .requests
        .iter()
        .find(|r| r.source == "mailbox_audit")
        .unwrap();
    assert!(
        m.invictus
            .as_deref()
            .unwrap()
            .starts_with("Get-MailboxAuditLogLegacy")
    );
}

#[test]
fn it_only_reads() {
    let case = case();
    let count = |sql: &str| -> i64 { case.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    let before = (
        count("SELECT count(*) FROM audit_trail"),
        count("SELECT count(*) FROM ual_events"),
        count("SELECT count(*) FROM findings"),
    );
    run(&case, None, &[]);
    run(&case, None, &[ALICE]);
    let after = (
        count("SELECT count(*) FROM audit_trail"),
        count("SELECT count(*) FROM ual_events"),
        count("SELECT count(*) FROM findings"),
    );
    assert_eq!(before, after);
}

#[test]
fn the_report_lists_ten_accounts_and_counts_the_rest() {
    use chrono::{TimeZone, Utc};
    use sparrow_core::export::report_md::{self, ReportOpts};
    let case = case();
    // 3 accounts so far (t1 alice, t1 carol, t2 carol); add 9 more, 12 in all.
    for i in 0..9 {
        rollup(&case, "t1", &format!("user{i}@contoso.example"));
    }
    // No detection run recorded and the enrichment marked as of run 0: the roll-up counts as current.
    case.conn()
        .execute(
            "INSERT INTO case_meta (key, value) VALUES ('enrichment_run_id', '0')",
            [],
        )
        .unwrap();
    let mut out = Vec::new();
    report_md::write(
        case.conn(),
        &mut out,
        &ReportOpts {
            reviewed_only: false,
            generated_at: Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap(),
            dirs: DataDirs::default(),
        },
    )
    .unwrap();
    let md = String::from_utf8(out).unwrap();
    let section = md
        .split("## Evidence coverage and what to request")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    assert_eq!(section.matches("(tenant ").count(), 10, "{section}");
    assert!(
        section.contains("+2 more accounts: run `sparrow coverage --case <file>` for all of them"),
        "{section}"
    );
    // The command itself lists all 12.
    assert_eq!(run(&case, None, &[]).accounts.len(), 12);
}

#[test]
fn to_next_is_the_day_after_to_including_month_and_year_rollover() {
    let f = |to: &str| {
        fill(
            "{from}|{to}|{to_next}|{upn}",
            "u@contoso.example",
            d("2026-01-01"),
            d(to),
        )
    };
    assert_eq!(
        f("2026-07-31"),
        "2026-01-01|2026-07-31|2026-08-01|u@contoso.example"
    );
    assert_eq!(
        f("2026-12-31"),
        "2026-01-01|2026-12-31|2027-01-01|u@contoso.example"
    );
    assert_eq!(
        f("2028-02-28"),
        "2026-01-01|2028-02-28|2028-02-29|u@contoso.example"
    );
    assert_eq!(
        f("2026-02-28"),
        "2026-01-01|2026-02-28|2026-03-01|u@contoso.example"
    );
}

#[test]
fn collector_hints_state_their_real_limits() {
    let case = case();
    let c = run(&case, Some("t1"), &[CAROL]);
    let req = |s: &str| c.requests.iter().find(|r| r.source == s).unwrap();
    // Every Extractor command ends on the day after the inclusive last day (07-31 -> 08-01).
    for s in [
        "ual",
        "signins_interactive",
        "signins_noninteractive",
        "mail_items_accessed",
        "message_trace",
        "entra_audit",
        "mailbox_audit",
    ] {
        let r = req(s);
        assert_eq!(r.to, d("2026-07-31"), "{s}");
        let cmd = r.invictus.as_deref().unwrap();
        assert!(cmd.contains("2026-08-01"), "{s}: {cmd}");
        assert!(
            !cmd.contains("-endDate 2026-07-31") && !cmd.contains("-EndDate 2026-07-31"),
            "{s}: {cmd}"
        );
    }
    assert!(
        req("mailbox_audit")
            .console
            .as_deref()
            .unwrap()
            .contains("-EndDate 2026-08-01")
    );
    // Entra audit: actor-only dated query, no -All, and the target caveat in the text.
    let a = req("entra_audit").invictus.as_deref().unwrap();
    assert!(a.starts_with("Get-GraphEntraAuditLogs -UserIds carol@contoso.example -startDate 2026-05-17 -endDate 2026-08-01 ("), "{a}");
    assert!(!a.contains("-All -"), "{a}");
    assert!(a.contains("only the target"), "{a}");
    // Hawk commands that ignore dates say so.
    let h = req("message_trace").hawk.as_deref().unwrap();
    assert!(h.contains("ignores dates") && h.contains("7 days"), "{h}");
    let h = req("entra_audit").hawk.as_deref().unwrap();
    assert!(h.contains("ignores dates") && h.contains("30 days"), "{h}");
}

#[test]
fn the_report_keeps_the_tables_when_the_rollup_warns() {
    use chrono::{TimeZone, Utc};
    use sparrow_core::export::report_md::{self, ReportOpts};
    let case = case(); // roll-up rows exist but no enrichment_run_id: the warning applies
    let write = |case: &Case| {
        let mut out = Vec::new();
        report_md::write(
            case.conn(),
            &mut out,
            &ReportOpts {
                reviewed_only: false,
                generated_at: Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap(),
                dirs: DataDirs::default(),
            },
        )
        .unwrap();
        let md = String::from_utf8(out).unwrap();
        md.split("## Evidence coverage and what to request")
            .nth(1)
            .unwrap()
            .split("\n## ")
            .next()
            .unwrap()
            .to_string()
    };
    let section = write(&case);
    assert!(
        section.contains("the account roll-up is not current"),
        "{section}"
    );
    assert_eq!(section.matches("(tenant ").count(), 3, "{section}");
    assert!(section.contains("| Unified audit log | 3 |"), "{section}");
    // With no roll-up rows at all the section says the list is unavailable.
    case.conn()
        .execute("DELETE FROM account_rollup", [])
        .unwrap();
    let section = write(&case);
    assert!(
        section.contains("the account roll-up is not current"),
        "{section}"
    );
    assert!(
        section.contains("_The account list is unavailable._"),
        "{section}"
    );
    assert_eq!(section.matches("(tenant ").count(), 0);
}

// ---- coverage_for_range ----

fn range(
    case: &Case,
    tenant: Option<&str>,
    accounts: &[&str],
    from: &str,
    to: &str,
) -> RangeCoverage {
    let accounts: Vec<String> = accounts.iter().map(|a| a.to_string()).collect();
    coverage_for_range(case.conn(), tenant, &accounts, d(from), d(to)).unwrap()
}

/// `(source, state)` of every listed source, in order.
fn states(r: &RangeCoverage) -> Vec<(&str, RangeState)> {
    r.sources
        .iter()
        .map(|s| (s.source.as_str(), s.state))
        .collect()
}

fn line<'a>(r: &'a RangeCoverage, id: &str) -> &'a sparrow_core::case::coverage::SourceState {
    r.sources
        .iter()
        .find(|s| s.source == id)
        .unwrap_or_else(|| panic!("no {id} in {:?}", states(r)))
}

fn by_state(s: &sparrow_core::case::coverage::SourceState) -> Vec<(&str, Vec<&str>)> {
    s.accounts_by_state
        .iter()
        .map(|(k, v)| (k.as_str(), v.iter().map(String::as_str).collect()))
        .collect()
}

#[test]
fn range_coverage_worst_state_per_source() {
    use RangeState::{Absent, Covered, Sampled};
    let case = case();
    // July, t1: alice's UAL is sampled, bob's is covered, carol has none; nothing else exists in July.
    let r = range(
        &case,
        Some("t1"),
        &[ALICE, BOB, CAROL],
        "2026-07-01",
        "2026-07-31",
    );
    assert_eq!(
        states(&r),
        vec![
            ("ual", Absent),
            ("signins_interactive", Absent),
            ("signins_noninteractive", Absent),
            ("mail_items_accessed", Absent),
            ("message_trace", Absent),
            ("entra_audit", Absent),
            ("mailbox_audit", Absent),
        ]
    );
    assert_eq!(
        by_state(line(&r, "ual")),
        vec![
            ("absent", vec![CAROL]),
            ("covered", vec![BOB]),
            ("sampled", vec![ALICE])
        ]
    );
    assert_eq!(
        by_state(line(&r, "signins_interactive")),
        vec![("absent", vec![ALICE, BOB, CAROL])]
    );
    // Without carol the worst is the sampled one; with bob alone it is covered.
    let r = range(&case, Some("t1"), &[ALICE, BOB], "2026-07-01", "2026-07-31");
    assert_eq!(line(&r, "ual").state, Sampled);
    let r = range(&case, Some("t1"), &[BOB], "2026-07-01", "2026-07-31");
    assert_eq!(line(&r, "ual").state, Covered);
    assert_eq!(by_state(line(&r, "ual")), vec![("covered", vec![BOB])]);
    // The range is whole UTC days, both ends inclusive: bob's 07-31 23:30 row is in, 07-30 alone has none.
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[BOB], "2026-07-31", "2026-07-31"),
            "ual"
        )
        .state,
        Covered
    );
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[BOB], "2026-07-30", "2026-07-30"),
            "ual"
        )
        .state,
        Absent
    );
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[BOB], "2026-07-02", "2026-07-02"),
            "ual"
        )
        .state,
        Covered
    );
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[BOB], "2026-07-03", "2026-07-30"),
            "ual"
        )
        .state,
        Absent
    );
    // June, carol: sign-ins of both kinds, a UAL row, messages and directory audits; no MailItemsAccessed.
    let r = range(&case, Some("t1"), &[CAROL], "2026-06-01", "2026-06-30");
    assert_eq!(
        states(&r),
        vec![
            ("ual", Covered),
            ("signins_interactive", Covered),
            ("signins_noninteractive", Covered),
            ("mail_items_accessed", Absent),
            ("message_trace", Covered),
            ("entra_audit", Covered),
            ("mailbox_audit", Absent),
        ]
    );
    // The service-principal sign-in (06-16) is neither kind.
    let r = range(&case, Some("t1"), &[CAROL], "2026-06-16", "2026-06-16");
    assert_eq!(line(&r, "signins_interactive").state, Absent);
    assert_eq!(line(&r, "signins_noninteractive").state, Absent);
    // dave: MailItemsAccessed from the UAL (06-20) and the parent-less MessageIDs row (06-25).
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[DAVE], "2026-06-20", "2026-06-20"),
            "mail_items_accessed"
        )
        .state,
        Covered
    );
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[DAVE], "2026-06-25", "2026-06-25"),
            "mail_items_accessed"
        )
        .state,
        Covered
    );
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[DAVE], "2026-06-21", "2026-06-24"),
            "mail_items_accessed"
        )
        .state,
        Absent
    );
    // Accounts are matched however they are spelled, and listed once, lower-cased.
    let r = range(
        &case,
        Some("t1"),
        &["BOB@Contoso.example", BOB],
        "2026-07-02",
        "2026-07-02",
    );
    assert_eq!(by_state(line(&r, "ual")), vec![("covered", vec![BOB])]);
}

#[test]
fn range_coverage_is_scoped_to_the_tenant() {
    use RangeState::{Absent, Covered};
    let case = case();
    // carol's August UAL is in t2 only.
    assert_eq!(
        line(
            &range(&case, Some("t2"), &[CAROL], "2026-08-01", "2026-08-10"),
            "ual"
        )
        .state,
        Covered
    );
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[CAROL], "2026-08-01", "2026-08-10"),
            "ual"
        )
        .state,
        Absent
    );
    // No tenant: every tenant counts.
    assert_eq!(
        line(
            &range(&case, None, &[CAROL], "2026-08-01", "2026-08-10"),
            "ual"
        )
        .state,
        Covered
    );
    // Tenant-wide sources are the tenant's own: t2 holds no messages or directory audits in June.
    let r = range(&case, Some("t2"), &[CAROL], "2026-06-12", "2026-06-14");
    assert_eq!(line(&r, "message_trace").state, Absent);
    assert_eq!(line(&r, "entra_audit").state, Absent);
    let r = range(&case, Some("t1"), &[CAROL], "2026-06-12", "2026-06-14");
    assert_eq!(line(&r, "message_trace").state, Covered);
    assert_eq!(line(&r, "entra_audit").state, Covered);
    // A range that ends before it starts is refused.
    let e =
        coverage_for_range(case.conn(), None, &[], d("2026-07-02"), d("2026-07-01")).unwrap_err();
    assert!(e.to_string().contains("ends before it starts"), "{e}");
}

#[test]
fn no_accounts_lists_tenant_wide_only() {
    use RangeState::{Absent, Covered};
    let case = case();
    let r = range(&case, Some("t1"), &[], "2026-06-12", "2026-06-14");
    assert_eq!(
        states(&r),
        vec![("message_trace", Covered), ("entra_audit", Covered)]
    );
    assert!(r.sources.iter().all(|s| s.accounts_by_state.is_empty()));
    let r = range(&case, Some("t1"), &[], "2026-06-15", "2026-06-15");
    assert_eq!(
        states(&r),
        vec![("message_trace", Absent), ("entra_audit", Absent)]
    );
    // Blank account strings are not accounts.
    let r = range(&case, Some("t1"), &["  ", ""], "2026-06-12", "2026-06-14");
    assert_eq!(
        states(&r),
        vec![("message_trace", Covered), ("entra_audit", Covered)]
    );
    // Tenant-wide sources ignore the accounts given: alice sent no mail and did nothing in the directory.
    let r = range(&case, Some("t1"), &[ALICE], "2026-06-12", "2026-06-14");
    assert_eq!(line(&r, "message_trace").state, Covered);
    assert_eq!(line(&r, "entra_audit").state, Covered);
    assert_eq!(line(&r, "ual").state, Absent);
    assert_eq!(r.sources.len(), 7);
}

#[test]
fn sampled_reuses_availability_rule() {
    use RangeState::{Covered, Sampled};
    let case = case();
    let c1: i64 = case
        .conn()
        .query_row(
            "SELECT collection_id FROM collections WHERE tenant_key = 't1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // A file whose warning is not an export cap does not make its rows sampled.
    let other = file(&case, c1, "ual-other.csv", Some(r#"["column x missing"]"#));
    ual(&case, c1, other, 20, "2026-09-02 08:00:00", "Send", DAVE);
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[DAVE], "2026-09-02", "2026-09-02"),
            "ual"
        )
        .state,
        Covered
    );
    // Capped message trace and directory audit rows make the tenant-wide sources sampled.
    let cap = file(&case, c1, "capped-others.csv", Some(CAP));
    trace(&case, c1, cap, "m9", "2026-09-03 10:00:00", DAVE, ALICE);
    audit_row(&case, c1, cap, "d9", "2026-09-03 11:00:00", DAVE, "[]");
    let r = range(&case, Some("t1"), &[], "2026-09-03", "2026-09-03");
    assert_eq!(
        states(&r),
        vec![("message_trace", Sampled), ("entra_audit", Sampled)]
    );
    // The row sighted in both the capped and the uncapped file (alice 07-05) is sampled, as `coverage` has it.
    assert_eq!(
        line(
            &range(&case, Some("t1"), &[ALICE], "2026-07-05", "2026-07-05"),
            "ual"
        )
        .state,
        Sampled
    );
    // The same answer as `coverage` for every account and source over each one's whole span.
    let all = run(&case, Some("t1"), &[ALICE, BOB, CAROL, DAVE]);
    let mut compared = 0;
    for a in &all.accounts {
        for s in &a.sources {
            let (Some(first), Some(last)) = (s.first, s.last) else {
                continue;
            };
            if ["message_trace", "entra_audit"].contains(&s.source.as_str()) {
                continue;
            }
            let r = range(
                &case,
                Some("t1"),
                &[&a.upn],
                &first.date_naive().to_string(),
                &last.date_naive().to_string(),
            );
            let want = if s.sampled { Sampled } else { Covered };
            assert_eq!(line(&r, &s.source).state, want, "{} {}", a.upn, s.source);
            compared += 1;
        }
    }
    // alice ual; bob ual; carol ual and both sign-in kinds; dave ual and mail_items_accessed.
    assert_eq!(compared, 7);
}

#[test]
fn range_coverage_binds_its_values_so_quotes_are_data() {
    use RangeState::{Absent, Covered};
    let case = Case::in_memory().unwrap();
    let odd_tenant = "t'1";
    let odd_account = "o'brien@contoso.example";
    let c = collection(&case, odd_tenant);
    let f = file(&case, c, "ual.csv", None);
    ual(&case, c, f, 1, "2026-07-02 08:00:00", "Send", odd_account);
    let c2 = collection(&case, "t1");
    let f2 = file(&case, c2, "ual2.csv", None);
    ual(&case, c2, f2, 2, "2026-07-02 09:00:00", "Send", BOB);
    let acct = [odd_account.to_string()];
    let run = |tenant: Option<&str>, accounts: &[String]| {
        coverage_for_range(
            case.conn(),
            tenant,
            accounts,
            d("2026-07-02"),
            d("2026-07-02"),
        )
        .unwrap()
    };
    // The apostrophe in the tenant and in the account is matched as text.
    let r = run(Some(odd_tenant), &acct);
    assert_eq!(line(&r, "ual").state, Covered);
    assert_eq!(
        by_state(line(&r, "ual")),
        vec![("covered", vec![odd_account])]
    );
    // Another tenant does not hold it, and a tenant made to look like SQL matches nothing.
    assert_eq!(line(&run(Some("t1"), &acct), "ual").state, Absent);
    assert_eq!(line(&run(Some("x' OR '1'='1"), &acct), "ual").state, Absent);
    assert_eq!(
        line(
            &run(Some("t1"), &["bob@contoso.example' OR '1'='1".to_string()]),
            "ual"
        )
        .state,
        Absent
    );
    assert_eq!(
        line(&run(Some("t1"), &[BOB.to_string()]), "ual").state,
        Covered
    );
    // Tenant-wide sources bind the tenant too.
    trace(&case, c, f, "m1", "2026-07-02 10:00:00", odd_account, BOB);
    assert_eq!(
        line(&run(Some(odd_tenant), &[]), "message_trace").state,
        Covered
    );
    assert_eq!(line(&run(Some("t1"), &[]), "message_trace").state, Absent);
}

#[test]
fn the_scope_follows_the_range_and_falls_back_to_the_whole_case() {
    use chrono::{TimeZone, Utc};
    use sparrow_core::case::entity::coverage_scope;
    use sparrow_core::case::events::{Entity, rebuild};
    let case = case();
    let c1: i64 = case
        .conn()
        .query_row(
            "SELECT collection_id FROM collections WHERE tenant_key = 't1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let ok: i64 = case
        .conn()
        .query_row(
            "SELECT file_id FROM source_files WHERE rel_path = 'ual-ok.csv'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // carol's June messages involve dave; her July message involves bob.
    trace(&case, c1, ok, "m7", "2026-07-10 10:00:00", CAROL, BOB);
    rebuild(case.conn()).unwrap();
    let at = |m, day| Some(Utc.with_ymd_and_hms(2026, m, day, 0, 0, 0).unwrap());
    let who = Entity::Account("CAROL@contoso.example".into());
    let tenants = |from, to| {
        coverage_scope(case.conn(), &who, from, to)
            .unwrap()
            .tenants
            .into_iter()
            .collect::<Vec<_>>()
    };
    let list = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // June: dave, not bob. July: bob, not dave. Carol herself throughout.
    assert_eq!(
        tenants(at(6, 1), at(6, 30)),
        vec![("t1".to_string(), list(&[CAROL, DAVE]))]
    );
    assert_eq!(
        tenants(at(7, 1), at(7, 31)),
        vec![("t1".to_string(), list(&[BOB, CAROL]))]
    );
    // August holds only her t2 UAL.
    assert_eq!(
        tenants(at(8, 1), at(8, 31)),
        vec![("t2".to_string(), list(&[CAROL]))]
    );
    // No range: everything.
    let all = tenants(None, None);
    assert_eq!(
        all,
        vec![
            ("t1".to_string(), list(&[BOB, CAROL, DAVE])),
            ("t2".to_string(), list(&[CAROL]))
        ]
    );
    // A range with none of her events falls back to the whole case, and she is among the accounts.
    assert_eq!(tenants(at(1, 1), at(1, 31)), all);
    // The first and last event are the whole case's whatever the range.
    let s = coverage_scope(case.conn(), &who, at(6, 1), at(6, 30)).unwrap();
    assert_eq!(s.first.unwrap().to_rfc3339(), "2026-06-11T09:00:00+00:00");
    assert_eq!(s.last.unwrap().to_rfc3339(), "2026-08-10T08:00:00+00:00");
    // A tenant whose events name no account, for an IP entity, lists none (a case with events but no IP rows).
    let none = coverage_scope(case.conn(), &Entity::Ip("203.0.113.9".into()), None, None).unwrap();
    assert!(none.first.is_none() && none.tenants.is_empty());
}

#[test]
fn the_scope_leaves_out_accounts_outside_the_tenants_domains() {
    use sparrow_core::case::entity::coverage_scope;
    use sparrow_core::case::events::{Entity, rebuild};
    let case = case();
    let id = |sql: &str| -> i64 { case.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    let c1 = id("SELECT collection_id FROM collections WHERE tenant_key = 't1'");
    let ok = id("SELECT file_id FROM source_files WHERE rel_path = 'ual-ok.csv'");
    // An outside sender writes to carol: its audit log is never in this tenant's evidence.
    trace(
        &case,
        c1,
        ok,
        "m8",
        "2026-06-12 10:00:00",
        "billing@partner.example",
        CAROL,
    );
    rebuild(case.conn()).unwrap();
    let who = Entity::Account(CAROL.into());
    let t1 = |case: &Case| {
        coverage_scope(case.conn(), &who, None, None)
            .unwrap()
            .tenants
            .remove("t1")
            .unwrap()
    };
    // No domains recorded for t1: every account in the events is judged, as before.
    assert!(t1(&case).contains(&"billing@partner.example".to_string()));
    case.conn()
        .execute(
            "INSERT INTO tenant_domains (tenant_key, domain, source, rows_seen) VALUES ('t1', 'contoso.example', 'derived_upn', 1)",
            [],
        )
        .unwrap();
    // With the tenant's domains known, an outside correspondent is not judged; carol stays.
    let accounts = t1(&case);
    assert!(!accounts.contains(&"billing@partner.example".to_string()));
    assert!(accounts.contains(&CAROL.to_string()));
    // Two tenants: ops@subsidiary.example acts in t2's own evidence (a UAL row there) and writes to carol in t2. Its
    // profile identity may be assigned to t1 (the tenant with more of its observations); t2's domains lack its
    // domain. It is still judged in t2, from t2's own events.
    let c2 = id("SELECT collection_id FROM collections WHERE tenant_key = 't2'");
    let f2 = id("SELECT file_id FROM source_files WHERE rel_path = 'ual-t2.csv'");
    ual(
        &case,
        c2,
        f2,
        90,
        "2026-08-02 09:00:00",
        "MailItemsAccessed",
        "ops@subsidiary.example",
    );
    trace(
        &case,
        c2,
        f2,
        "m9",
        "2026-08-02 10:00:00",
        "ops@subsidiary.example",
        CAROL,
    );
    // And a mail-only outside sender in t2, in both trace feeds (message trace and its event detail).
    trace(
        &case,
        c2,
        f2,
        "m10",
        "2026-08-02 11:00:00",
        "billing@partner.example",
        CAROL,
    );
    case.conn()
        .execute(
            "INSERT INTO message_trace_events (record_key, collection_id, event_time, event_id, sender, recipients) \
             VALUES ('e10', ?, CAST('2026-08-02 11:00:01+00' AS TIMESTAMPTZ), 'RECEIVE', 'billing@partner.example', \
                     CAST('[\"carol@contoso.example\"]' AS JSON))",
            params![c2],
        )
        .unwrap();
    sighted(&case, "message_trace_events", "e10", f2);
    rebuild(case.conn()).unwrap();
    case.conn()
        .execute_batch(
            "INSERT INTO tenant_domains (tenant_key, domain, source, rows_seen) VALUES ('t2', 'contoso.example', 'derived_upn', 1); \
             INSERT INTO identities (identity_id, tenant_key, kind, upn, aliases) VALUES ('upn:ops@subsidiary.example', 't1', 'external', 'ops@subsidiary.example', 1); \
             INSERT INTO identity_aliases (alias_type, alias, identity_id) VALUES ('upn', 'ops@subsidiary.example', 'upn:ops@subsidiary.example');",
        )
        .unwrap();
    let t2 = coverage_scope(case.conn(), &who, None, None)
        .unwrap()
        .tenants
        .remove("t2")
        .unwrap();
    assert!(t2.contains(&"ops@subsidiary.example".to_string()), "{t2:?}");
    assert!(
        !t2.contains(&"billing@partner.example".to_string()),
        "{t2:?}"
    );
    assert!(t2.contains(&CAROL.to_string()));
}

// ---- Collector manifests (Task 4): coverage from the collector's intervals. Synthetic manifests only. ----

/// A case of tenant `t1` whose collection holds the manifests `ms` (ingested through the real ingest), plus an
/// empty events collection of `t1` (returned) for rows added with the helpers above, and its uncapped file.
fn manifest_case(ms: Vec<manifest::M>) -> (Case, i64, i64) {
    let tmp = tempfile::tempdir().unwrap();
    let root = manifest::invictus_dir(tmp.path());
    for m in &ms {
        m.write(&root);
    }
    let mut case = Case::in_memory().unwrap();
    ingest_path(
        &mut case,
        tmp.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let changed = case
        .conn()
        .execute("UPDATE collections SET tenant_key = 't1'", [])
        .unwrap();
    assert_eq!(changed, 1, "one manifest collection");
    let c = collection(&case, "t1");
    let f = file(&case, c, "ual-ok.csv", None);
    (case, c, f)
}

const MA: &str = "a@contoso.example";
const MB: &str = "b@contoso.example";

#[test]
fn interior_collector_gap_appears_between_events() {
    // Events on 09-01 and 09-09 (the tenant's last event); the window starts 30 days before 09-01: 08-02. The UAL
    // unit vouches 08-01..09-11 except its retries_exhausted gap on 09-04 and 09-05.
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial").unit(
            manifest::U::new(
                &["ual"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-04T00:00:00Z",
                "2026-09-06T00:00:00Z",
                "retries_exhausted",
            ),
        ),
    ]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MA);
    let cov = run(&case, Some("t1"), &[MA]);
    let a = account(&cov, "t1", MA);
    let w = a.window.unwrap();
    assert_eq!((w.start, w.end), (d("2026-08-02"), d("2026-09-09")));
    let s = source(a, "ual");
    assert_eq!(
        gaps(s),
        vec![g("2026-09-04", "2026-09-05", "collector_gap")]
    );
    assert!(!s.collected_no_events);
    // The collector gap is a request reason like any other.
    let r = cov
        .requests
        .iter()
        .find(|r| r.user == MA && r.source == "ual")
        .unwrap();
    assert_eq!((r.from, r.to), (d("2026-09-04"), d("2026-09-05")));
    assert_eq!(r.reasons, vec!["collector_gap"]);
}

#[test]
fn vouched_range_with_no_events_is_collected_no_events() {
    // UAL rows only; the interactive sign-ins are vouched over the whole window and hold no row.
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-GraphEntraSignInLogs", "complete").unit(manifest::U::new(
            &["signins_interactive"],
            "2026-08-01T00:00:00Z",
            "2026-09-11T00:00:00Z",
            "complete",
        )),
    ]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MA);
    let cov = run(&case, Some("t1"), &[MA]);
    let a = account(&cov, "t1", MA);
    let s = source(a, "signins_interactive");
    assert_eq!(s.rows, 0);
    assert_eq!(gaps(s), vec![]);
    assert!(s.collected_no_events);
    let collected: Vec<(String, String)> = s
        .collected
        .iter()
        .map(|r| (r.from.to_string(), r.to.to_string()))
        .collect();
    assert_eq!(
        collected,
        vec![("2026-08-02".to_string(), "2026-09-09".to_string())]
    );
    let v = serde_json::to_value(s).unwrap();
    assert_eq!(v["collected_no_events"], serde_json::json!(true));
    assert_eq!(
        v["collected"],
        serde_json::json!([{"from": "2026-08-02", "to": "2026-09-09"}])
    );
    // Not vouched: absent as before, and neither field is serialized.
    let n = source(a, "signins_noninteractive");
    assert_eq!(gaps(n), vec![g("2026-08-02", "2026-09-09", "absent")]);
    assert!(!n.collected_no_events && n.collected.is_empty());
    let v = serde_json::to_value(n).unwrap();
    assert!(v.get("collected").is_none() && v.get("collected_no_events").is_none());
    // Nothing to request for the vouched source.
    assert!(
        !cov.requests
            .iter()
            .any(|r| r.source == "signins_interactive")
    );
}

#[test]
fn collector_gap_takes_precedence_over_sampled() {
    // A capped export from 09-01 to 09-09; a failed unit over 09-04..09-05 (whole range gap, vouches nothing).
    let (case, c, _) = manifest_case(vec![manifest::M::run("Get-UALGraph", "failed").unit(
        manifest::U::new(
            &["ual"],
            "2026-09-04T00:00:00Z",
            "2026-09-06T00:00:00Z",
            "failed",
        ),
    )]);
    let cap = file(&case, c, "ual-cap.csv", Some(CAP));
    ual(&case, c, cap, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, cap, 2, "2026-09-09 10:00:00", "Send", MA);
    let cov = run(&case, Some("t1"), &[MA]);
    let s = source(account(&cov, "t1", MA), "ual");
    assert!(s.sampled);
    assert_eq!(
        gaps(s),
        vec![
            g("2026-08-02", "2026-08-31", "before"),
            g("2026-09-01", "2026-09-03", "sampled"),
            g("2026-09-04", "2026-09-05", "collector_gap"),
            g("2026-09-06", "2026-09-09", "sampled"),
        ]
    );
}

#[test]
fn manifest_ending_mid_day_on_the_last_day_leaves_no_after_gap() {
    // a's only UAL row is 09-01; the tenant's last event is b's at 09-09 10:00. The UAL unit vouches up to 09-09
    // 12:00, after the tenant's last event: the window ends at that event (R1), so 09-09 is not an `after` day.
    let (case, c, f) = manifest_case(vec![manifest::M::run("Get-UALGraph", "complete").unit(
        manifest::U::new(
            &["ual"],
            "2026-08-01T00:00:00Z",
            "2026-09-09T12:00:00Z",
            "complete",
        ),
    )]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MB);
    let cov = run(&case, Some("t1"), &[MA]);
    let s = source(account(&cov, "t1", MA), "ual");
    assert_eq!(gaps(s), vec![]);

    // Ending before the tenant's last event (08:00) leaves that last day as `after`.
    let (case, c, f) = manifest_case(vec![manifest::M::run("Get-UALGraph", "complete").unit(
        manifest::U::new(
            &["ual"],
            "2026-08-01T00:00:00Z",
            "2026-09-09T08:00:00Z",
            "complete",
        ),
    )]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MB);
    let cov = run(&case, Some("t1"), &[MA]);
    let s = source(account(&cov, "t1", MA), "ual");
    assert_eq!(gaps(s), vec![g("2026-09-09", "2026-09-09", "after")]);
}

#[test]
fn collector_gap_without_events_splits_the_absent_window() {
    // No sign-in rows; a failed sign-in unit over 08-20..08-21 inside the window: absent around a collector gap.
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-GraphEntraSignInLogs", "failed").unit(manifest::U::new(
            &["signins_interactive"],
            "2026-08-20T00:00:00Z",
            "2026-08-22T00:00:00Z",
            "failed",
        )),
    ]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MA);
    let cov = run(&case, Some("t1"), &[MA]);
    let s = source(account(&cov, "t1", MA), "signins_interactive");
    assert_eq!(
        gaps(s),
        vec![
            g("2026-08-02", "2026-08-19", "absent"),
            g("2026-08-20", "2026-08-21", "collector_gap"),
            g("2026-08-22", "2026-09-09", "absent"),
        ]
    );
    assert!(!s.collected_no_events);
}

#[test]
fn another_tenants_manifest_changes_nothing() {
    // The manifest collection belongs to t2; a's t1 coverage is exactly the manifest-less one.
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial").unit(
            manifest::U::new(
                &["ual"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-04T00:00:00Z",
                "2026-09-06T00:00:00Z",
                "retries_exhausted",
            ),
        ),
    ]);
    case.conn()
        .execute(
            "UPDATE collections SET tenant_key = 't2' WHERE collection_id <> ?",
            params![c],
        )
        .unwrap();
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MA);
    let cov = run(&case, Some("t1"), &[MA]);
    let a = account(&cov, "t1", MA);
    assert_eq!(
        gaps(source(a, "ual")),
        vec![g("2026-08-02", "2026-08-31", "before")]
    );
    assert!(a.sources.iter().all(|s| s.collected.is_empty()));
}

#[test]
fn the_report_prints_collector_gaps_and_collected_no_events() {
    use chrono::{TimeZone, Utc};
    use sparrow_core::export::report_md::{self, ReportOpts};
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial").unit(
            manifest::U::new(
                &["ual", "signins_interactive"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-04T00:00:00Z",
                "2026-09-06T00:00:00Z",
                "retries_exhausted",
            ),
        ),
    ]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-09 10:00:00", "Send", MA);
    rollup(&case, "t1", MA);
    case.conn()
        .execute(
            "INSERT INTO case_meta (key, value) VALUES ('enrichment_run_id', '0')",
            [],
        )
        .unwrap();
    let mut out = Vec::new();
    report_md::write(
        case.conn(),
        &mut out,
        &ReportOpts {
            reviewed_only: false,
            generated_at: Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap(),
            dirs: DataDirs::default(),
        },
    )
    .unwrap();
    let md = String::from_utf8(out).unwrap();
    let section = md
        .split("## Evidence coverage and what to request")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    let row = |title: &str| {
        section
            .lines()
            .find(|l| l.starts_with(&format!("| {title} |")))
            .unwrap_or_else(|| panic!("no {title} row in {section}"))
            .to_string()
    };
    assert!(
        row("Unified audit log").ends_with("| collector\\_gap 2026-09-04 to 2026-09-05 |"),
        "{section}"
    );
    assert!(
        row("Sign-ins \\(interactive\\)").ends_with(
            "| collected, no events 2026-08-02 to 2026-09-09; collector\\_gap 2026-09-04 to 2026-09-05 |"
        ),
        "{section}"
    );
    assert!(
        section.contains("- Unified audit log, 2026-09-04 to 2026-09-05 (collector\\_gap)"),
        "{section}"
    );
}

#[test]
fn a_tenant_with_manifests_keeps_every_sources_gaps_inside_the_window() {
    // t1 has a UAL manifest only. a's finding (09-08) starts the window on 08-09; a's interactive sign-ins end on
    // 08-03, before it. Their `after` gap starts at the window start, not the day after the last sign-in.
    let (case, c, f) = manifest_case(vec![manifest::M::run("Get-UALGraph", "complete").unit(
        manifest::U::new(
            &["ual"],
            "2026-08-01T00:00:00Z",
            "2026-09-11T00:00:00Z",
            "complete",
        ),
    )]);
    signin(&case, c, f, "s1", "2026-08-01 09:00:00", "interactive", MA);
    signin(&case, c, f, "s2", "2026-08-03 09:00:00", "interactive", MA);
    ual(&case, c, f, 1, "2026-09-09 10:00:00", "Send", MA);
    finding(&case, "f1", "t1", MA, "2026-09-08 12:00:00");
    let cov = run(&case, Some("t1"), &[MA]);
    let a = account(&cov, "t1", MA);
    let w = a.window.unwrap();
    assert_eq!((w.start, w.end), (d("2026-08-09"), d("2026-09-09")));
    let s = source(a, "signins_interactive");
    assert_eq!(gaps(s), vec![g("2026-08-09", "2026-09-09", "after")]);
    let r = cov
        .requests
        .iter()
        .find(|r| r.user == MA && r.source == "signins_interactive")
        .unwrap();
    assert_eq!((r.from, r.to), (d("2026-08-09"), d("2026-09-09")));
    assert!(
        cov.requests.iter().all(|r| r.from >= w.start),
        "{:?}",
        cov.requests
    );
}

// ---- Task 5: the pull list of collector gaps. ----

#[test]
fn rerun_command_renders_types_and_replaces_dates() {
    use serde_json::json;
    use sparrow_core::case::collector::Span;
    use sparrow_core::case::coverage::rerun_command;
    let p = json!({
        "UserIds": ["a@x.example", "o'brien@x.example"],
        "StartDate": "2026-01-01",
        "Note": "it's",
        "Count": 5,
        "Verbose": true,
        "Quiet": false,
        "Nested": {"a": 1},
        "Nothing": null,
        "enddate": "2026-02-01",
    });
    let span = Span {
        start_us: 1_788_000_000_000_000, // 2026-08-29T10:40:00Z
        end_us: 1_788_003_600_000_000,
    };
    assert_eq!(
        rerun_command("Get-UAL", &p, Some(span)),
        "Get-UAL -UserIds 'a@x.example','o''brien@x.example' -StartDate '2026-08-29T10:40:00Z' -Note 'it''s' \
         -Count 5 -Verbose -Quiet:$false -enddate '2026-08-29T11:40:00Z'"
    );
    assert_eq!(
        rerun_command("Get-UAL", &p, None),
        "Get-UAL -UserIds 'a@x.example','o''brien@x.example' -StartDate '2026-01-01' -Note 'it''s' \
         -Count 5 -Verbose -Quiet:$false -enddate '2026-02-01'"
    );
}

#[test]
fn collector_requests_list_open_gaps_with_search_id_resume() {
    let (case, _c, _f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial")
            .param("UserIds", serde_json::json!(["a@contoso.example"]))
            .param("StartDate", serde_json::json!("2026-08-01"))
            .param("EndDate", serde_json::json!("2026-09-11"))
            .unit(
                manifest::U::new(
                    &["ual"],
                    "2026-08-01T00:00:00Z",
                    "2026-09-11T00:00:00Z",
                    "partial",
                )
                .gap(
                    "2026-09-04T00:00:00Z",
                    "2026-09-06T00:00:00Z",
                    "search_timeout",
                )
                .search_id("sid-1"),
            ),
    ]);
    let cov = run(&case, Some("t1"), &[]);
    assert_eq!(
        cov.collector_requests.len(),
        1,
        "{:?}",
        cov.collector_requests
    );
    let r = &cov.collector_requests[0];
    assert_eq!(r.tenant_key, "t1");
    assert_eq!(r.cmdlet.as_deref(), Some("Get-UALGraph"));
    assert_eq!(r.sources, vec!["ual"]);
    assert_eq!(r.reason, "search_timeout");
    assert!(!r.undated);
    assert_eq!(
        r.rerun,
        vec![
            "Get-UALGraph -UserIds 'a@contoso.example' -StartDate '2026-09-04T00:00:00Z' -EndDate '2026-09-06T00:00:00Z'"
        ]
    );
    assert_eq!(r.resume.as_deref(), Some("Get-UALGraph -SearchId 'sid-1'"));
    let json = serde_json::to_value(&cov).unwrap();
    assert_eq!(json["collector_requests"].as_array().unwrap().len(), 1);
}

#[test]
fn closed_gaps_are_not_requested() {
    // A second run re-collects the gap, so nothing is open and the key is not serialised.
    let (case, _c, _f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial").unit(
            manifest::U::new(
                &["ual"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-04T00:00:00Z",
                "2026-09-06T00:00:00Z",
                "retries_exhausted",
            ),
        ),
        manifest::M::run("Get-UALGraph", "complete").unit(manifest::U::new(
            &["ual"],
            "2026-09-03T00:00:00Z",
            "2026-09-07T00:00:00Z",
            "complete",
        )),
    ]);
    let cov = run(&case, Some("t1"), &[]);
    assert!(cov.collector_requests.is_empty());
    let json = serde_json::to_value(&cov).unwrap();
    assert!(json.get("collector_requests").is_none());
}

#[test]
fn collector_gaps_show_in_the_report_without_accounts() {
    use chrono::{TimeZone, Utc};
    use sparrow_core::export::report_md::{self, ReportOpts};
    let (case, _c, _f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial").unit(
            manifest::U::new(
                &["ual"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-04T00:00:00Z",
                "2026-09-06T00:00:00Z",
                "retries_exhausted",
            ),
        ),
    ]);
    let mut out = Vec::new();
    report_md::write(
        case.conn(),
        &mut out,
        &ReportOpts {
            reviewed_only: false,
            generated_at: Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap(),
            dirs: DataDirs::default(),
        },
    )
    .unwrap();
    let md = String::from_utf8(out).unwrap();
    let section = md
        .split("## Evidence coverage and what to request")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    assert!(section.contains("### Collector gaps"), "{section}");
    assert!(section.contains("retries\\_exhausted"), "{section}");
}

// ---- Collector manifests (Task 6): range coverage and the entity strip. Synthetic manifests only. ----

#[test]
fn range_with_open_collector_gap_is_collector_gap() {
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-UALGraph", "partial").unit(
            manifest::U::new(
                &["ual"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-04T00:00:00Z",
                "2026-09-06T00:00:00Z",
                "retries_exhausted",
            ),
        ),
    ]);
    ual(&case, c, f, 1, "2026-09-05 10:00:00", "Send", MA);
    ual(&case, c, f, 2, "2026-09-08 10:00:00", "Send", MB);
    let r = range(&case, Some("t1"), &[MA, MB], "2026-09-05", "2026-09-05");
    let s = line(&r, "ual");
    // The row on 09-05 does not hide the gap; the state is the worst, listed under the account.
    assert_eq!(s.state, RangeState::CollectorGap);
    assert_eq!(by_state(s), vec![("collector_gap", vec![MA, MB])]);
    assert_eq!(
        serde_json::to_value(s.state).unwrap(),
        serde_json::json!("collector_gap")
    );
    // A range clear of the gap: vouched throughout, so a with-rows and a no-rows account are both covered.
    let r = range(&case, Some("t1"), &[MA, MB], "2026-09-07", "2026-09-08");
    assert_eq!(line(&r, "ual").state, RangeState::Covered);
    assert_eq!(by_state(line(&r, "ual")), vec![("covered", vec![MA, MB])]);
}

#[test]
fn vouched_empty_range_is_covered() {
    let (case, c, f) = manifest_case(vec![
        manifest::M::run("Get-GraphEntraSignInLogs", "complete").unit(manifest::U::new(
            &["signins_interactive"],
            "2026-08-01T00:00:00Z",
            "2026-09-11T00:00:00Z",
            "complete",
        )),
    ]);
    ual(&case, c, f, 1, "2026-09-01 10:00:00", "Send", MA);
    let r = range(&case, Some("t1"), &[MA], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "signins_interactive").state, RangeState::Covered);
    // Not vouched: absent. A range reaching past the vouched end: absent.
    assert_eq!(line(&r, "signins_noninteractive").state, RangeState::Absent);
    let r = range(&case, Some("t1"), &[MA], "2026-09-10", "2026-09-12");
    assert_eq!(line(&r, "signins_interactive").state, RangeState::Absent);
    // A tenant without manifests keeps today's state.
    let r = range(&case, Some("t9"), &[MA], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "signins_interactive").state, RangeState::Absent);
}

#[test]
fn tenant_wide_message_trace_needs_tenant_wide_units() {
    let wide = |users: Option<&[&str]>, dir: Option<&str>| {
        let mut u = manifest::U::new(
            &["message_trace"],
            "2026-08-01T00:00:00Z",
            "2026-09-11T00:00:00Z",
            "complete",
        );
        if let Some(us) = users {
            u = u.users(us);
        }
        if let Some(d) = dir {
            u = u.direction(d);
        }
        manifest::M::run("Get-MessageTraceV2", "complete").unit(u)
    };
    // Per-user unit: nothing for the tenant-wide source.
    let (case, _, _) = manifest_case(vec![wide(Some(&[MA]), None)]);
    let r = range(&case, Some("t1"), &[MA], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "message_trace").state, RangeState::Absent);
    // Sender only: absent; sender and recipient: covered.
    let (case, _, _) = manifest_case(vec![wide(None, Some("sender"))]);
    let r = range(&case, Some("t1"), &[], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "message_trace").state, RangeState::Absent);
    let (case, _, _) = manifest_case(vec![
        wide(None, Some("sender")),
        wide(None, Some("recipient")),
    ]);
    let r = range(&case, Some("t1"), &[], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "message_trace").state, RangeState::Covered);
    // Tenant-wide, no direction: covered; with a tenant-wide gap in range: collector gap.
    let (case, _, _) = manifest_case(vec![
        manifest::M::run("Get-MessageTraceV2", "partial").unit(
            manifest::U::new(
                &["message_trace"],
                "2026-08-01T00:00:00Z",
                "2026-09-11T00:00:00Z",
                "partial",
            )
            .gap(
                "2026-09-03T00:00:00Z",
                "2026-09-03T06:00:00Z",
                "retries_exhausted",
            ),
        ),
    ]);
    let r = range(&case, Some("t1"), &[], "2026-09-02", "2026-09-02");
    assert_eq!(line(&r, "message_trace").state, RangeState::Covered);
    let r = range(&case, Some("t1"), &[], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "message_trace").state, RangeState::CollectorGap);
}

#[test]
fn vouched_range_with_capped_rows_stays_sampled() {
    // A complete unit vouches the whole range and the rows in it come from a capped export, with no open gap:
    // vouching proves the collector ran, not that the capped export held every record, so it stays sampled.
    let (case, c, _) = manifest_case(vec![manifest::M::run("Get-UALGraph", "complete").unit(
        manifest::U::new(
            &["ual"],
            "2026-08-01T00:00:00Z",
            "2026-09-11T00:00:00Z",
            "complete",
        ),
    )]);
    let cap = file(&case, c, "ual-cap.csv", Some(CAP));
    ual(&case, c, cap, 1, "2026-09-03 10:00:00", "Send", MA);
    let r = range(&case, Some("t1"), &[MA], "2026-09-02", "2026-09-04");
    assert_eq!(line(&r, "ual").state, RangeState::Sampled);
    assert_eq!(by_state(line(&r, "ual")), vec![("sampled", vec![MA])]);
}
