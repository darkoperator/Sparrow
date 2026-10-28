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

use chrono::NaiveDate;
use duckdb::params;
use sparrow_core::Case;
use sparrow_core::case::coverage::{
    AccountCoverage, Coverage, CoverageOptions, Gap, SourceCoverage, coverage, fill, thousands,
};
use sparrow_core::data::DataDirs;

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
