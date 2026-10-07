//! The three exports (Addendum D.6) on synthetic bec-aitm after a scripted agent session: the Markdown report, the
//! Timeline Explorer CSV and the XLSX workbook. The goldens are recorded once with `SPARROW_RECORD_GOLDEN=1` after
//! review by eye (the fixed test clock and case id make every hash, id and timestamp reproducible).

#[path = "common/synth.rs"]
mod synth;

use calamine::{Data, Reader, Xlsx, open_workbook};
use chrono::{DateTime, TimeZone, Utc};
use sparrow_core::Case;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::audit;
use sparrow_core::case::indicators::{self, IndicatorType, Verdict};
use sparrow_core::case::notes::{self, NoteTarget};
use sparrow_core::case::read::{self, FindingFilter};
use sparrow_core::case::review;
use sparrow_core::case::timeline_entries::{self as te, EvidenceRef, NewEntry, Phase};
use sparrow_core::case::write::{self, FindingStatus};
use sparrow_core::export::header;
use sparrow_core::export::report_md::{self, ReportOpts};
use sparrow_core::export::timeline_csv::{self, COLUMNS, CsvOpts, Scope};
use sparrow_core::export::workbook_xlsx::{self, SHEETS};
use sparrow_core::export::{LABEL_AI_PENDING, LABEL_LEGACY_PENDING};
use sparrow_synth::options::PsEdition;
use std::io::Write;

const HOSTILE: &str = "a,b\"c\nd|e 🔥 \u{202E}x";

fn generated_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap()
}

fn agent() -> Actor {
    Actor::agent("claude", Some("example")).unwrap()
}

fn reviewer() -> Reviewer {
    Reviewer::analyst("reviewer").unwrap()
}

/// What the scripted session decided, for the assertions.
struct Script {
    case: Case,
    confirmed: (String, String),
    false_positive: (String, String),
    in_review: (String, String),
    /// (title, narrative) of the three verified entries and the proposed one.
    verified: Vec<(String, String)>,
    proposed: String,
    iocs: Vec<String>,
    note: String,
}

fn detected() -> Case {
    // A private copy of the cached, detected bec-aitm case (the test cache; no tree is shared between runs).
    synth::builtin_detected("bec-aitm", PsEdition::Ps7).case
}

/// The fixed agent session of the plan: detect; three findings decided; two IOCs; three timeline entries verified
/// and one left proposed; one note; one decision accepted and one discarded. `hostile` swaps the text of the IOC
/// note, an entry narrative and the note for [`HOSTILE`].
fn scripted(hostile: bool) -> Script {
    audit::test_clock::set(Some(Utc.with_ymd_and_hms(2026, 10, 2, 12, 0, 0).unwrap()));
    let case = detected();
    // A fresh case id makes the genesis, and so every hash, the same on every run.
    case.conn()
        .execute(
            "UPDATE case_meta SET value = '00000000-0000-4000-8000-000000000005' WHERE key = 'case_id'",
            [],
        )
        .unwrap();
    let c = case.conn();
    let findings = read::finding_list(c, &FindingFilter::default()).unwrap();
    assert!(findings.len() >= 3, "bec-aitm raises several findings");
    let (f0, f1, f2) = (&findings[0], &findings[1], &findings[2]);
    write::set_finding_status(
        c,
        &agent(),
        &f0.finding_id,
        FindingStatus::Confirmed,
        Some("replayed session from the proxy address"),
    )
    .unwrap();
    write::set_finding_status(
        c,
        &agent(),
        &f1.finding_id,
        FindingStatus::FalsePositive,
        Some("the user's own travel"),
    )
    .unwrap();
    write::set_finding_status(c, &agent(), &f2.finding_id, FindingStatus::InReview, None).unwrap();

    let text = |plain: &str| {
        if hostile {
            HOSTILE.to_string()
        } else {
            plain.to_string()
        }
    };
    let ioc_ip = "203.0.113.9";
    let ioc_domain = "login-example.test";
    indicators::add_indicator(
        c,
        &agent(),
        None,
        IndicatorType::Ip,
        ioc_ip,
        Verdict::Malicious,
        Some(&text("AiTM proxy")),
    )
    .unwrap();
    indicators::add_indicator(
        c,
        &agent(),
        None,
        IndicatorType::Domain,
        ioc_domain,
        Verdict::Suspicious,
        Some("look-alike sign-in page"),
    )
    .unwrap();

    // Three verified entries and one proposed, each citing a record of the kind it describes: a sign-in entry a
    // sign-in, the inbox rule a New-InboxRule record, the mailbox read a MailItemsAccessed record.
    let pick = |filter: &str, skip: usize| -> (EvidenceRef, DateTime<Utc>) {
        c.query_row(
            &format!(
                "SELECT source_table, record_key, epoch_us(event_time) FROM timeline WHERE {filter} \
                 ORDER BY event_time, source_table, record_key LIMIT 1 OFFSET {skip}"
            ),
            [],
            |r| {
                Ok((
                    EvidenceRef {
                        source_table: r.get(0)?,
                        record_key: r.get(1)?,
                    },
                    DateTime::from_timestamp_micros(r.get(2)?).unwrap(),
                ))
            },
        )
        .unwrap_or_else(|e| panic!("no timeline row for {filter}: {e}"))
    };
    let refs = [
        pick("source_table = 'signins'", 0),
        pick("operation = 'New-InboxRule'", 0),
        pick("operation = 'MailItemsAccessed'", 0),
        pick("source_table = 'signins'", 1),
    ];
    let specs = [
        (
            "Sign-in from the proxy",
            "The attacker replays the session.",
            Phase::InitialAccess,
        ),
        (
            "Inbox rule created",
            "A rule hides replies.",
            Phase::DefenseEvasion,
        ),
        (
            "Mailbox read",
            "The mailbox is read in bulk.",
            Phase::Collection,
        ),
        ("Cleanup pending", "Not yet verified.", Phase::Remediation),
    ];
    let mut verified = Vec::new();
    let mut proposed = String::new();
    for (i, (title, narrative, phase)) in specs.iter().enumerate() {
        let narrative = if i == 1 {
            text(narrative)
        } else {
            narrative.to_string()
        };
        let (id, _) = te::propose(
            c,
            &agent(),
            NewEntry {
                tenant_key: None,
                event_time: refs[i].1,
                title: title.to_string(),
                narrative: Some(narrative.clone()),
                phase: *phase,
                evidence: vec![refs[i].0.clone()],
            },
        )
        .unwrap();
        if i < 3 {
            te::verify(c, &agent(), &id).unwrap();
            verified.push((title.to_string(), narrative));
        } else {
            proposed = title.to_string();
        }
    }
    notes::add_note(
        c,
        &agent(),
        NoteTarget::Finding(f0.finding_id.clone()),
        &text("Reviewed the sign-in by hand."),
    )
    .unwrap();

    // One decision accepted, one discarded.
    let seq = review::latest_decision_seq(c, "finding", &f0.finding_id)
        .unwrap()
        .unwrap();
    review::review_accept(
        c,
        &reviewer(),
        "finding",
        &f0.finding_id,
        seq,
        Some("agreed"),
    )
    .unwrap();
    let seq = review::latest_decision_seq(c, "finding", &f2.finding_id)
        .unwrap()
        .unwrap();
    review::review_discard(
        c,
        &reviewer(),
        "finding",
        &f2.finding_id,
        seq,
        Some("not enough"),
    )
    .unwrap();
    audit::test_clock::set(None);
    assert!(audit::verify(c).unwrap().ok);
    Script {
        confirmed: (f0.finding_id.clone(), f0.title.clone()),
        false_positive: (f1.finding_id.clone(), f1.title.clone()),
        in_review: (f2.finding_id.clone(), f2.title.clone()),
        verified,
        proposed,
        iocs: vec![ioc_ip.into(), ioc_domain.into()],
        note: text("Reviewed the sign-in by hand."),
        case,
    }
}

fn report(case: &Case, reviewed_only: bool) -> String {
    let mut out = Vec::new();
    report_md::write(
        case.conn(),
        &mut out,
        &ReportOpts {
            reviewed_only,
            generated_at: generated_at(),
        },
    )
    .unwrap();
    String::from_utf8(out).unwrap()
}

fn csv_opts(scope: Scope) -> CsvOpts {
    CsvOpts {
        scope,
        from: None,
        to: None,
        user: None,
        generated_at: generated_at(),
    }
}

fn csv_bytes(case: &Case, opts: &CsvOpts) -> (Vec<u8>, u64) {
    let mut out = Vec::new();
    let n = timeline_csv::write(case.conn(), &mut out, opts).unwrap();
    (out, n)
}

fn csv_records(bytes: &[u8]) -> Vec<Vec<String>> {
    assert_eq!(&bytes[..3], "\u{feff}".as_bytes(), "UTF-8 BOM");
    let mut r = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(&bytes[3..]);
    r.records()
        .map(|rec| rec.unwrap().iter().map(String::from).collect())
        .collect()
}

fn workbook(case: &Case, dir: &tempfile::TempDir) -> Xlsx<std::io::BufReader<std::fs::File>> {
    let path = dir.path().join("case.xlsx");
    workbook_xlsx::write(case.conn(), &path, generated_at()).unwrap();
    open_workbook(&path).unwrap()
}

fn cell_text(d: &Data) -> String {
    match d {
        Data::Empty => String::new(),
        Data::String(s) => s.clone(),
        Data::Int(i) => i.to_string(),
        Data::Float(f) => f.to_string(),
        Data::Bool(b) => b.to_string(),
        Data::DateTime(d) => d
            .as_datetime()
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| format!("{d:?}")),
        other => format!("{other:?}"),
    }
}

fn sheet_rows(wb: &mut Xlsx<std::io::BufReader<std::fs::File>>, name: &str) -> Vec<Vec<String>> {
    let range = wb.worksheet_range(name).unwrap();
    range
        .rows()
        .map(|r| r.iter().map(cell_text).collect())
        .collect()
}

/// `actual` with the Sparrow version and the rule-pack hash replaced by placeholders, so a version bump or a rule
/// edit does not churn the goldens.
fn redact(actual: &str, case: &Case) -> String {
    let h = header::build(case.conn(), generated_at()).unwrap();
    let mut s = actual.to_string();
    if let Some(p) = &h.rule_pack_sha256 {
        s = s.replace(p.as_str(), "<RULE_PACK_SHA256>");
    }
    let v = sparrow_core::VERSION;
    s.replace(
        &format!("Sparrow version:** {v}"),
        "Sparrow version:** <VERSION>",
    )
    .replace(
        &format!("Sparrow version: {v}"),
        "Sparrow version: <VERSION>",
    )
    .replace(&format!("\"{v}\""), "\"<VERSION>\"")
}

fn golden(name: &str, actual: &str, case: &Case) {
    let actual = redact(actual, case);
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    // SPARROW_RECORD_GOLDEN=1 re-records the goldens: a deliberate step whose diff is reviewed and whose reason goes
    // in the commit message. The version and the rule-pack hash are redacted, so a rule edit leaves them alone.
    if std::env::var_os("SPARROW_RECORD_GOLDEN").is_some() {
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("record {path} first"));
    assert_eq!(actual, expected, "{name}");
}

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

// ------------------------------------------------------------------ report

#[test]
fn report_matches_golden() {
    let s = scripted(false);
    golden("export_report.md", &report(&s.case, false), &s.case);
}

#[test]
fn exports_are_reproducible() {
    let (a, b) = (scripted(false), scripted(false));
    assert_eq!(report(&a.case, false), report(&b.case, false));
    assert_eq!(
        csv_bytes(&a.case, &csv_opts(Scope::Verified)).0,
        csv_bytes(&b.case, &csv_opts(Scope::Verified)).0
    );
}

#[test]
fn report_labels_pending_ai_decisions() {
    let s = scripted(false);
    let md = report(&s.case, false);
    // Every pending item carries the label: three verified entries and two indicators (the confirmed finding is
    // accepted, the in_review one discarded, the false positive is not in the report).
    assert_eq!(md.matches(LABEL_AI_PENDING).count(), 3 + 2, "{md}");
    for (title, _) in &s.verified {
        assert!(md.contains(title), "{title}");
    }
    for ioc in &s.iocs {
        assert!(md.contains(ioc), "{ioc}");
    }
    assert!(md.contains("decided by agent:claude on behalf of analyst:example at 2026-10-02"));
    // The reviewed finding shows who accepted it and when, and the reviewer's comment.
    assert!(
        md.contains("accepted by analyst:reviewer at 2026-10-02"),
        "{md}"
    );
    assert!(md.contains("Reviewer comment: agreed"));
    // Only accepted decisions: no pending item, label or title.
    let reviewed = report(&s.case, true);
    assert!(!reviewed.contains(LABEL_AI_PENDING));
    for (title, _) in &s.verified {
        assert!(!reviewed.contains(title), "{title}");
    }
    for ioc in &s.iocs {
        assert!(!reviewed.contains(ioc), "{ioc}");
    }
    assert!(
        reviewed.contains(&s.confirmed.1),
        "the accepted finding stays"
    );
    assert!(!reviewed.contains(&s.proposed));
}

#[test]
fn report_labels_a_decision_recorded_before_the_audit_trail() {
    let s = scripted(false);
    let c = s.case.conn();
    // What the upgrade does for an indicator from before Phase 7: a row decided by an analyst, one
    // `legacy_decision` audit entry.
    c.execute(
        "INSERT INTO case_indicators (indicator_id, tenant_key, type, value, verdict, note, added_by, added_at, \
         decided_by, decided_at, review_state) VALUES ('0123456789abcdef', NULL, 'ip', '198.51.100.77', \
         'malicious', 'old note', 'analyst:sam', CAST('2026-01-01T00:00:00Z' AS TIMESTAMPTZ), 'analyst:sam', \
         CAST('2026-01-01T00:00:00Z' AS TIMESTAMPTZ), 'pending_review')",
        [],
    )
    .unwrap();
    audit::append_at(
        c,
        generated_at(),
        "analyst:sam",
        None,
        "legacy_decision",
        "indicator",
        "0123456789abcdef",
        None,
        Some(&serde_json::json!({"indicator_id": "0123456789abcdef"})),
        None,
    )
    .unwrap();
    let md = report(&s.case, false);
    assert_eq!(md.matches(LABEL_LEGACY_PENDING).count(), 1, "{md}");
    assert!(md.contains("198.51.100.77"));
    assert!(md.contains("decided by analyst:sam"));
    // Its own count in the header, apart from the AI decisions.
    let h = header::build(c, generated_at()).unwrap();
    assert_eq!(h.decisions.legacy, 1);
    assert_eq!(
        h.decisions.pending_review, 7,
        "four entries, two indicators, the false positive"
    );
    assert_eq!(
        (h.decisions.accepted, h.decisions.discarded),
        (1, 1),
        "the accepted and the discarded finding"
    );
    assert!(md.contains("recorded before the audit trail 1"));
}

#[test]
fn report_cites_evidence_with_source_refs() {
    let s = scripted(false);
    let md = report(&s.case, false);
    let timeline = md
        .split("## Timeline by phase")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    let lines: Vec<&str> = timeline.lines().filter(|l| l.starts_with("- **")).collect();
    assert_eq!(lines.len(), s.verified.len(), "{timeline}");
    let marker = regex::Regex::new(r"\[\^\d+\]").unwrap();
    for l in &lines {
        assert!(marker.is_match(l), "no footnote marker: {l}");
    }
    // Every footnote names table:record_key and a file:line source ref.
    let notes: Vec<&str> = md.lines().filter(|l| l.starts_with("[^")).collect();
    assert!(!notes.is_empty());
    let shape = regex::Regex::new(r"^\[\^\d+\]: [a-z\\_]+:\S+ — .+:\d+(-\d+)?").unwrap();
    for n in &notes {
        assert!(shape.is_match(n), "footnote shape: {n}");
        assert!(!n.contains("no source file reference"), "{n}");
    }
    // Every marker used in the text has its footnote.
    for cap in marker.find_iter(&md) {
        let def = format!("{}:", cap.as_str());
        assert!(md.lines().any(|l| l.starts_with(&def)), "{}", cap.as_str());
    }
    // The confirmed finding lists its evidence with footnotes too.
    assert!(md.contains("- Evidence ("));
}

#[test]
fn report_never_writes_an_executive_summary() {
    let s = scripted(false);
    let md = report(&s.case, false);
    let exec = md
        .split("## Executive summary")
        .nth(1)
        .unwrap()
        .split("\n## ")
        .next()
        .unwrap();
    assert_eq!(exec.trim(), "_Analyst to write._");
    // Section order is fixed.
    let order = [
        "## Scope",
        "## Executive summary",
        "## Timeline by phase",
        "## Findings",
        "## Indicators",
        "## Evidence gaps",
        "## Method and integrity",
    ];
    let at: Vec<usize> = order.iter().map(|h| md.find(h).unwrap()).collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}");
}

#[test]
fn a_broken_chain_is_stated_in_every_header() {
    let s = scripted(false);
    s.case
        .conn()
        .execute(
            "UPDATE audit_trail SET actor = 'agent:forged' WHERE seq = 1",
            [],
        )
        .unwrap();
    let h = header::build(s.case.conn(), generated_at()).unwrap();
    assert!(!h.chain_ok);
    assert!(report(&s.case, false).contains("**Audit chain:** BROKEN"));
}

// ------------------------------------------------------------------ CSV

#[test]
fn timeline_csv_matches_golden_and_round_trips() {
    let s = scripted(false);
    let (bytes, n) = csv_bytes(&s.case, &csv_opts(Scope::Verified));
    assert_eq!(n, 3);
    golden(
        "export_timeline.csv",
        std::str::from_utf8(&bytes).unwrap(),
        &s.case,
    );
    let rec = csv_records(&bytes);
    assert_eq!(rec[0], COLUMNS);
    assert_eq!(
        COLUMNS.to_vec(),
        [
            "Timestamp",
            "Source",
            "Category",
            "User",
            "IP",
            "Operation",
            "Summary",
            "Phase",
            "Status",
            "DecidedBy",
            "ReviewState",
            "FindingIds",
            "EvidenceRef"
        ]
    );
    let stamp = regex::Regex::new(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$").unwrap();
    // Three data rows, then the closing header record (no timestamp).
    assert_eq!(rec.len(), 1 + 3 + 1);
    for r in &rec[1..4] {
        assert_eq!(r.len(), COLUMNS.len());
        assert!(stamp.is_match(&r[0]), "{}", r[0]);
        assert_eq!(r[8], "verified");
        assert_eq!(r[9], "agent:claude");
        assert_eq!(r[10], "pending_review");
        assert!(r[12].contains(':'), "evidence ref: {}", r[12]);
    }
    assert_eq!(rec[4][1], "sparrow-export");
    // The closing record sorts with the data: its Timestamp is the generation time.
    assert_eq!(rec[4][0], "2026-10-03 00:00:00");
}

#[test]
fn timeline_csv_streams_all_rows() {
    let s = scripted(false);
    let total = count(&s.case, "SELECT count(*) FROM timeline");
    let (bytes, n) = csv_bytes(&s.case, &csv_opts(Scope::All));
    assert_eq!(n as i64, total);
    assert!(total > 100, "the check needs a real timeline: {total}");
    let rec = csv_records(&bytes);
    assert_eq!(rec.len() as i64, 1 + total + 1);
    let stamp = regex::Regex::new(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$").unwrap();
    for r in &rec[1..rec.len() - 1] {
        assert!(stamp.is_match(&r[0]), "{}", r[0]);
        assert_eq!(r.len(), COLUMNS.len());
    }
    // Rows cited by a verified entry carry its phase and decision.
    assert!(
        rec.iter()
            .any(|r| r[8] == "verified" && r[7] == "initial_access")
    );
    // Streaming: the first bytes of the rows reach the sink while most rows are still unread. The sink records
    // how many rows the statement has handed out when each write arrives; collecting every row first would make
    // that the total at the very first write.
    struct Probe {
        writes: Vec<u64>,
    }
    impl Write for Probe {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.writes.push(timeline_csv::probe::fetched());
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Probe { writes: Vec::new() };
    timeline_csv::write(s.case.conn(), &mut sink, &csv_opts(Scope::All)).unwrap();
    // writes[0] is the BOM; writes[1] is the first flush of the csv writer's buffer: the first data bytes.
    assert!(sink.writes.len() > 8, "{:?}", sink.writes.len());
    assert!(
        sink.writes[1] * 10 < total as u64,
        "{} of {total} rows were fetched when the first data bytes arrived",
        sink.writes[1]
    );
    assert!(sink.writes.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(*sink.writes.last().unwrap(), total as u64);
}

#[test]
fn timeline_csv_filters_by_user_and_time() {
    let s = scripted(false);
    let user: String = s
        .case
        .conn()
        .query_row(
            "SELECT actor_upn FROM timeline WHERE actor_upn IS NOT NULL GROUP BY actor_upn \
             ORDER BY count(*) DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let all = count(&s.case, "SELECT count(*) FROM timeline");
    let mine = count(
        &s.case,
        &format!(
            "SELECT count(*) FROM timeline WHERE lower(actor_upn) = lower('{user}') OR lower(target) = lower('{user}')"
        ),
    );
    assert!(0 < mine && mine < all);
    let mut o = csv_opts(Scope::All);
    o.user = Some(user.to_uppercase());
    assert_eq!(csv_bytes(&s.case, &o).1 as i64, mine);
    // A window with nothing in it.
    let mut o = csv_opts(Scope::All);
    o.from = Some(Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap());
    o.to = Some(Utc.with_ymd_and_hms(2000, 1, 2, 0, 0, 0).unwrap());
    assert_eq!(csv_bytes(&s.case, &o).1, 0);
    // The verified scope honours the same filters: entries are cited by user and time.
    let mut o = csv_opts(Scope::Verified);
    o.to = Some(Utc.with_ymd_and_hms(2000, 1, 2, 0, 0, 0).unwrap());
    assert_eq!(csv_bytes(&s.case, &o).1, 0);
}

// ------------------------------------------------------------------ workbook

#[test]
fn workbook_reopens_with_expected_sheets() {
    let s = scripted(false);
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    assert_eq!(wb.sheet_names(), SHEETS.to_vec());
    assert_eq!(
        SHEETS,
        [
            "Summary",
            "Accounts",
            "Findings",
            "Timeline",
            "Indicators",
            "Evidence gaps",
            "Audit"
        ]
    );
    let findings = sheet_rows(&mut wb, "Findings");
    for h in ["DecidedBy", "OnBehalfOf", "ReviewState", "Analyst notes"] {
        for sheet in ["Findings", "Timeline", "Indicators"] {
            let rows = sheet_rows(&mut wb, sheet);
            assert!(rows[0].iter().any(|c| c == h), "{sheet} lacks {h}");
        }
    }
    // Row counts match the case.
    assert_eq!(
        findings.len() as i64 - 1,
        count(&s.case, "SELECT count(*) FROM findings")
    );
    assert_eq!(
        sheet_rows(&mut wb, "Timeline").len() as i64 - 1,
        count(&s.case, "SELECT count(*) FROM timeline_entries")
    );
    assert_eq!(
        sheet_rows(&mut wb, "Indicators").len() as i64 - 1,
        count(&s.case, "SELECT count(*) FROM case_indicators")
    );
    assert_eq!(
        sheet_rows(&mut wb, "Audit").len() as i64 - 1,
        count(&s.case, "SELECT count(*) FROM audit_trail")
    );
    assert_eq!(
        sheet_rows(&mut wb, "Evidence gaps").len() as i64 - 1,
        count(
            &s.case,
            "SELECT count(*) FROM evidence_availability WHERE CAST(status AS VARCHAR) <> 'collected'"
        )
    );
    // The confirmed finding's row: decision, review, and an empty analyst-notes cell.
    let col = |rows: &Vec<Vec<String>>, h: &str| rows[0].iter().position(|c| c == h).unwrap();
    let row = findings.iter().find(|r| r[0] == s.confirmed.0).unwrap();
    assert_eq!(row[col(&findings, "DecidedBy")], "agent:claude");
    assert_eq!(row[col(&findings, "OnBehalfOf")], "analyst:example");
    assert_eq!(row[col(&findings, "ReviewState")], "accepted");
    assert_eq!(row[col(&findings, "ReviewedBy")], "analyst:reviewer");
    assert_eq!(row[col(&findings, "Analyst notes")], "");
    let row = findings
        .iter()
        .find(|r| r[0] == s.false_positive.0)
        .unwrap();
    assert_eq!(row[col(&findings, "ReviewState")], "pending_review");
    assert_eq!(row[col(&findings, "DecisionLabel")], LABEL_AI_PENDING);
    // The discarded decision: reverted to the state before it, marked discarded with its reviewer.
    let row = findings.iter().find(|r| r[0] == s.in_review.0).unwrap();
    assert_eq!(row[col(&findings, "ReviewState")], "discarded");
    assert_eq!(row[col(&findings, "Status")], "new");
    assert!(row[col(&findings, "DecisionLabel")].starts_with("discarded by analyst:reviewer at "));
    // Dates are real date cells.
    let range = wb.worksheet_range("Timeline").unwrap();
    assert!(
        range
            .rows()
            .skip(1)
            .all(|r| matches!(r[0], Data::DateTime(_))),
        "Timeline timestamps are date cells"
    );
    // The whole workbook against its golden (cell contents as JSON).
    let mut out = Vec::new();
    for name in SHEETS {
        out.push(serde_json::json!({ "sheet": name, "rows": sheet_rows(&mut wb, name) }));
    }
    golden(
        "export_workbook.json",
        &serde_json::to_string_pretty(&out).unwrap(),
        &s.case,
    );
}

// ------------------------------------------------------------------ hostile text and headers

#[test]
fn exports_survive_hostile_text() {
    let plain = scripted(false);
    let s = scripted(true);
    // CSV: the entry narrative re-parses to the same text (cells keep the raw stored text).
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::Verified));
    let rec = csv_records(&bytes);
    let want = format!("{} — {HOSTILE}", s.verified[1].0);
    assert!(rec.iter().any(|r| r[6] == want), "{rec:?}");
    assert_eq!(rec.len(), 1 + 3 + 1, "quoting kept the row count");
    // Markdown: pipes and newlines are escaped, so the tables keep their row count and no line is broken.
    let md = report(&s.case, false);
    let plain_md = report(&plain.case, false);
    let table_lines = |m: &str| m.lines().filter(|l| l.starts_with('|')).count();
    assert_eq!(table_lines(&md), table_lines(&plain_md));
    assert!(md.contains("a,b\"c<br>d\\|e 🔥 \\u{202E}x"), "{md}");
    // The note on the confirmed finding reads back too, its bidi override escaped, its newline kept in the block.
    assert!(md.contains("a,b\"c\n    d\\|e 🔥 \\u{202E}x"), "{md}");
    assert!(
        !md.contains('\u{202E}'),
        "no raw bidi override in the report"
    );
    // XLSX: the narrative cell reads back the same text.
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let tl = sheet_rows(&mut wb, "Timeline");
    let n = tl[0].iter().position(|c| c == "Narrative").unwrap();
    assert!(tl.iter().any(|r| r[n] == HOSTILE), "{tl:?}");
    let ind = sheet_rows(&mut wb, "Indicators");
    let n = ind[0].iter().position(|c| c == "Note").unwrap();
    assert!(ind.iter().any(|r| r[n] == HOSTILE));
    // The chain still verifies: the hash does not depend on how the text is displayed.
    assert!(audit::verify(s.case.conn()).unwrap().ok);
    assert_eq!(s.note, HOSTILE);
}

#[test]
fn control_characters_are_escaped_in_markdown_and_kept_raw_in_csv_and_workbook() {
    let s = scripted(false);
    let c = s.case.conn();
    let (id, _) = te::propose(
        c,
        &agent(),
        NewEntry {
            tenant_key: None,
            event_time: generated_at(),
            title: "t\u{1b}[31mred\u{0}".into(),
            narrative: Some("n\u{7}ote\r\nline\u{200B}two".into()),
            phase: Phase::Impact,
            evidence: vec![
                EvidenceRef::parse(
                    &c.query_row(
                        "SELECT source_table || ':' || record_key FROM timeline LIMIT 1",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ],
        },
    )
    .unwrap();
    te::verify(c, &agent(), &id).unwrap();
    let md = report(&s.case, false);
    for bad in ['\u{1b}', '\u{0}', '\u{7}', '\r', '\u{200B}'] {
        assert!(!md.contains(bad), "raw {:?} in the report", bad);
    }
    assert!(md.contains("t\\u{001B}\\[31mred\\u{0000}"));
    assert!(md.contains("n\\u{0007}ote"));
    assert!(md.contains("line\\u{200B}two"));
    // The workbook keeps the raw stored text (control characters are escaped by the file format, not by Sparrow).
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let tl = sheet_rows(&mut wb, "Timeline");
    let t = tl[0].iter().position(|c| c == "Title").unwrap();
    let n = tl[0].iter().position(|c| c == "Narrative").unwrap();
    let row = tl
        .iter()
        .find(|r| r[t].starts_with("t\u{1b}[31mred"))
        .unwrap_or_else(|| panic!("{tl:?}"));
    assert_eq!(row[t], "t\u{1b}[31mred\u{0}");
    assert_eq!(row[n], "n\u{7}ote\r\nline\u{200B}two");
    // So does the CSV.
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::Verified));
    let rec = csv_records(&bytes);
    assert!(
        rec.iter()
            .any(|r| r[6] == "t\u{1b}[31mred\u{0} — n\u{7}ote\r\nline\u{200B}two")
    );
}

#[test]
fn every_export_carries_the_header() {
    let s = scripted(false);
    let h = header::build(s.case.conn(), generated_at()).unwrap();
    let head = h.head_hash.clone().unwrap();
    let counts = h.decisions_text();
    assert!(counts.contains("AI-decided, not reviewed"));
    let md = report(&s.case, false);
    assert!(md.contains(&head) && md.contains(&counts));
    assert!(md.contains(&h.rule_pack_sha256.clone().unwrap()));
    assert!(md.contains(&format!("**Sparrow version:** {}", sparrow_core::VERSION)));
    assert!(md.contains("**Generated at:** 2026-10-03 00:00:00 UTC"));
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::Verified));
    let csv = String::from_utf8(bytes).unwrap();
    assert!(csv.contains(&head) && csv.contains(&counts));
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let summary: String = sheet_rows(&mut wb, "Summary")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(summary.contains(&head) && summary.contains(&counts));
    // The counts agree with the case: 4 entries + 2 indicators + the false positive pending, 1 accepted, 1 discarded.
    assert_eq!(
        (
            h.decisions.pending_review,
            h.decisions.accepted,
            h.decisions.discarded,
            h.decisions.legacy
        ),
        (7, 1, 1, 0),
        "{h:?}"
    );
}

// ------------------------------------------------------------------ formula injection

/// A new verified entry whose title is `title`, citing the first timeline row.
fn entry_titled(c: &duckdb::Connection, title: &str) {
    let key: String = c
        .query_row(
            "SELECT source_table || ':' || record_key FROM timeline ORDER BY event_time, source_table, record_key LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let (id, _) = te::propose(
        c,
        &agent(),
        NewEntry {
            tenant_key: None,
            event_time: generated_at(),
            title: title.into(),
            narrative: None,
            phase: Phase::Impact,
            evidence: vec![EvidenceRef::parse(&key).unwrap()],
        },
    )
    .unwrap();
    te::verify(c, &agent(), &id).unwrap();
}

#[test]
fn neutralise_prefixes_exactly_the_formula_starters() {
    use sparrow_core::export::timeline_csv::neutralise;
    for first in ['=', '+', '-', '@', '\t', '\r'] {
        let cell = format!("{first}1+1");
        assert_eq!(neutralise(&cell), format!("'{cell}"), "{first:?}");
    }
    // Only the first character counts, and only those six.
    for cell in [
        "a=b",
        "x+1",
        "1-2",
        "mail@example",
        "",
        " =1",
        "'=1",
        "#=1",
        "A\t",
    ] {
        assert_eq!(neutralise(cell), cell, "{cell:?}");
    }
}

#[test]
fn csv_text_cells_that_start_like_a_formula_are_prefixed() {
    let s = scripted(false);
    let c = s.case.conn();
    let titles = [
        "=HYPERLINK(\"http://evil.example\",\"x\")",
        "+cmd|' /C calc'!A0",
        "-2+3",
        "@SUM(1,1)",
        "\tTAB first",
        "\rCR first",
        "mid=dle is left alone",
    ];
    for t in titles {
        entry_titled(c, t);
    }
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::Verified));
    let rec = csv_records(&bytes);
    let summaries: Vec<&str> = rec.iter().map(|r| r[6].as_str()).collect();
    for t in &titles[..6] {
        assert!(
            summaries.contains(&format!("'{t}").as_str()),
            "{t:?} not prefixed in {summaries:?}"
        );
        assert!(!summaries.contains(t), "{t:?} written bare");
    }
    assert!(
        summaries.contains(&titles[6]),
        "a = in the middle is not touched"
    );
    // The timestamp and the id columns are never prefixed; every other cell of every row is either unchanged or
    // starts with a quote because it began with one of the six.
    for r in &rec[1..] {
        assert!(!r[0].starts_with('\''), "{r:?}");
        assert!(!r[11].starts_with('\''), "{r:?}");
    }
    // Scope all goes through the same writer: no cell of any row starts with a formula character.
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::All));
    for r in &csv_records(&bytes)[1..] {
        for (i, cell) in r.iter().enumerate().filter(|(i, _)| *i != 0 && *i != 11) {
            assert!(
                !cell.starts_with(['=', '+', '-', '@', '\t', '\r']),
                "column {i}: {cell:?}"
            );
        }
    }
}

#[test]
fn workbook_cells_are_strings_never_formulas() {
    let s = scripted(false);
    let c = s.case.conn();
    let formula = "=HYPERLINK(\"http://evil.example\",\"click\")";
    entry_titled(c, formula);
    indicators::add_indicator(
        c,
        &agent(),
        None,
        IndicatorType::UserAgent,
        "=cmd|' /C calc'!A0",
        Verdict::Suspicious,
        Some("+SUM(1;1)"),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let find = |wb: &mut Xlsx<std::io::BufReader<std::fs::File>>, sheet: &str, want: &str| {
        let range = wb.worksheet_range(sheet).unwrap();
        range
            .rows()
            .flat_map(|r| r.iter())
            .any(|d| matches!(d, Data::String(t) if t == want))
    };
    assert!(
        find(&mut wb, "Timeline", formula),
        "title reads back as a string"
    );
    assert!(find(&mut wb, "Indicators", "=cmd|' /C calc'!A0"));
    assert!(find(&mut wb, "Indicators", "+SUM(1;1)"));
    // And no cell of any sheet holds a formula.
    for name in SHEETS {
        let formulas = wb.worksheet_formula(name).unwrap();
        let n = formulas
            .rows()
            .flat_map(|r| r.iter())
            .filter(|f| !f.is_empty())
            .count();
        assert_eq!(n, 0, "{name} holds {n} formulas");
    }
}

// ------------------------------------------------------------------ Markdown and HTML injection (B1)

/// An attacker's string: an HTML comment that never closes, a phishing link, a tracking image, a forged footnote
/// reference, emphasis, a code span, an entity, a script tag, and (in a block) a heading, a list and a setext line.
const ATTACK: &str = "AP <!-- [Verify your account](https://evil.example) ![](https://t.example/p.png) [^99] \
     **bold** `code` &amp; <script>x</script>";
const ATTACK_BLOCK: &str = "first line <!--\n# heading\n- fake bullet\n1. one\n===\n> quote";

fn assert_no_live_markup(md: &str) {
    // Not one `<` of attacker text reaches the output: the only `<` left are our own `<br>` in table cells.
    assert_eq!(
        md.matches('<').count(),
        md.matches("<br>").count(),
        "raw HTML in the report"
    );
    assert!(!md.contains("<!--") && !md.contains("<script"));
    assert!(
        md.contains("&lt;\\!--"),
        "the comment opener is shown as text"
    );
    // No link or image syntax: every `](` and `![` is backslash-escaped.
    let link = regex::Regex::new(r"(^|[^\\])\]\(").unwrap();
    assert!(!link.is_match(md), "link syntax");
    assert!(!md.contains("!["), "image syntax");
    assert!(md.contains("\\[Verify your account\\]\\(https://evil.example\\)"));
    // No forged footnote reference: `[^99]` only appears with its brackets escaped.
    let forged = regex::Regex::new(r"(^|[^\\])\[\^99\]").unwrap();
    assert!(!forged.is_match(md), "a forged footnote reference");
    assert!(md.contains("\\[\\^99\\]") || md.contains("\\[^99\\]"));
    // No emphasis, code span or entity of the attacker's survives as markup.
    assert!(!md.contains("**bold**") && !md.contains("`code`"));
    assert!(md.contains("\\*\\*bold\\*\\*") && md.contains("\\`code\\`"));
    assert!(md.contains("&amp;amp;"));
    // No line of an attacker's block starts a heading, a list, a quote or a setext underline.
    for l in md.lines() {
        let t = l.trim_start();
        assert!(
            !(t.starts_with("# heading")
                || t.starts_with("- fake bullet")
                || t.starts_with("1. one")
                || t == "==="
                || t.starts_with("> quote")),
            "structure forged by agent text: {l:?}"
        );
    }
}

#[test]
fn attacker_text_is_escaped_as_markdown_and_html_everywhere() {
    let s = scripted(false);
    let c = s.case.conn();
    // The evidence path: an inbox rule named by the attacker lands in the summary of a cited timeline row.
    c.execute(
        &format!(
            "UPDATE ual_events SET object_id = '{}' WHERE lower(CAST(record_id AS VARCHAR)) IN \
             (SELECT record_key FROM finding_evidence WHERE finding_id = '{}' AND source_table = 'ual_events')",
            ATTACK.replace('\'', "''"),
            s.confirmed.0
        ),
        [],
    )
    .unwrap();
    // The agent path: a verified entry, a note, an indicator value and its note.
    let key: String = c
        .query_row(
            "SELECT source_table || ':' || record_key FROM timeline ORDER BY event_time LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let (id, _) = te::propose(
        c,
        &agent(),
        NewEntry {
            tenant_key: None,
            event_time: generated_at(),
            title: ATTACK.into(),
            narrative: Some(ATTACK_BLOCK.into()),
            phase: Phase::Impact,
            evidence: vec![EvidenceRef::parse(&key).unwrap()],
        },
    )
    .unwrap();
    te::verify(c, &agent(), &id).unwrap();
    notes::add_note(
        c,
        &agent(),
        NoteTarget::Finding(s.confirmed.0.clone()),
        ATTACK_BLOCK,
    )
    .unwrap();
    indicators::add_indicator(
        c,
        &agent(),
        None,
        IndicatorType::RuleName,
        ATTACK,
        Verdict::Suspicious,
        Some(ATTACK_BLOCK),
    )
    .unwrap();
    let md = report(&s.case, false);
    assert_no_live_markup(&md);
    // The labels after the attacker's text are all still there: three entries and the new one, three indicators.
    assert_eq!(md.matches(LABEL_AI_PENDING).count(), 4 + 3, "{md}");
    for section in [
        "## Evidence gaps",
        "## Method and integrity",
        "## Evidence references",
    ] {
        assert!(md.contains(section), "{section} missing");
    }
    // The attacker's text is still readable, escaped: the evidence summary and the table cell show it.
    assert!(md.contains("AP &lt;\\!-- "), "{md}");
    // Our own markup is intact: bold labels, footnote markers and definitions.
    assert!(md.contains("- **Audit chain:**"));
    assert!(md.lines().any(|l| l.starts_with("[^1]: ")));
}

// ------------------------------------------------------------------ notes (S2), dates (S3)

#[test]
fn agent_notes_are_labelled_and_left_out_of_a_reviewed_only_report() {
    let s = scripted(false);
    let md = report(&s.case, false);
    assert!(md.contains(&format!(
        "{} (agent:claude on behalf of analyst:example at ",
        sparrow_core::export::report_md::LABEL_AGENT_NOTE
    )));
    assert!(md.contains(&s.note));
    // The finding is accepted, so it stays in a reviewed-only report; its note does not.
    let reviewed = report(&s.case, true);
    assert!(
        reviewed.contains(&s.confirmed.1),
        "the accepted finding stays"
    );
    assert!(!reviewed.contains(&s.note), "{reviewed}");
    assert!(!reviewed.contains(sparrow_core::export::report_md::LABEL_AGENT_NOTE));
    assert!(!reviewed.contains("- Notes:"));
}

#[test]
fn a_date_outside_excels_range_is_written_as_text() {
    let s = scripted(false);
    let c = s.case.conn();
    let key: String = c
        .query_row(
            "SELECT source_table || ':' || record_key FROM timeline LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let (id, _) = te::propose(
        c,
        &agent(),
        NewEntry {
            tenant_key: None,
            event_time: Utc.with_ymd_and_hms(1, 1, 1, 0, 0, 0).unwrap(),
            title: "A sentinel date".into(),
            narrative: None,
            phase: Phase::Recon,
            evidence: vec![EvidenceRef::parse(&key).unwrap()],
        },
    )
    .unwrap();
    te::verify(c, &agent(), &id).unwrap();
    // And an evidence-availability bound from a sentinel too.
    c.execute(
        "UPDATE evidence_availability SET min_time = CAST('0001-01-01T00:00:00Z' AS TIMESTAMPTZ) \
         WHERE evidence = (SELECT min(evidence) FROM evidence_availability WHERE CAST(status AS VARCHAR) <> 'collected')",
        [],
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let tl = sheet_rows(&mut wb, "Timeline");
    assert!(
        tl.iter().any(|r| r[0]
            == "0001-01-01T00:00:00Z (outside Excel's date range; written as text)"
            && r[2] == "A sentinel date"),
        "{tl:?}"
    );
    let gaps = sheet_rows(&mut wb, "Evidence gaps");
    assert!(
        gaps.iter()
            .any(|r| r[7].starts_with("0001-01-01T00:00:00Z (outside"))
    );
    // In-range dates stay real date cells.
    let range = wb.worksheet_range("Timeline").unwrap();
    assert!(
        range
            .rows()
            .skip(1)
            .any(|r| matches!(r[0], Data::DateTime(_)))
    );
}

// ------------------------------------------------------------------ time zone

/// TIMESTAMPTZ text casts follow the connection's time zone, which can be local. Every time an export renders is
/// explicit UTC (formatted from epoch_us), so the same case gives the same bytes under America/New_York.
#[test]
fn exports_do_not_depend_on_the_connections_time_zone() {
    let s = scripted(false);
    let c = s.case.conn();
    let dir = tempfile::tempdir().unwrap();
    let render = |case: &Case| {
        let mut wb = workbook(case, &dir);
        let sheets: Vec<Vec<Vec<String>>> = SHEETS.iter().map(|n| sheet_rows(&mut wb, n)).collect();
        (
            report(case, false),
            csv_bytes(case, &csv_opts(Scope::Verified)).0,
            csv_bytes(case, &csv_opts(Scope::All)).0,
            sheets,
        )
    };
    let utc = render(&s.case);
    c.execute_batch("SET TimeZone = 'America/New_York'")
        .unwrap();
    // The setting is live (and so the test can fail): a TIMESTAMPTZ cast now reads in New York.
    let cast: String = c
        .query_row(
            "SELECT CAST(TIMESTAMPTZ '2026-08-21 09:47:00+00' AS VARCHAR)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(cast.starts_with("2026-08-21 05:47:00"), "{cast}");
    let ny = render(&s.case);
    assert_eq!(utc.0, ny.0, "the report");
    assert_eq!(utc.1, ny.1, "the verified CSV");
    assert_eq!(utc.2, ny.2, "the full CSV");
    assert_eq!(utc.3, ny.3, "the workbook");
    // And the times in them are UTC: the first sign-in entry reads 14:24:08, not 10:24:08.
    assert!(ny.0.contains("2026-08-11 14:24:08 UTC"));
}

// ------------------------------------------------------------------ accounts and facts (agent accuracy T5)

use sparrow_core::case::read::FactsField;
use sparrow_core::export::facts_text;

/// A finding with stored facts (a persistence finding of bec-aitm), confirmed so the report lists it.
fn confirmed_with_facts(case: &Case) -> String {
    let id: String = case
        .conn()
        .query_row(
            "SELECT finding_id FROM finding_facts ORDER BY finding_id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("bec-aitm raises a persistence finding with facts");
    write::set_finding_status(
        case.conn(),
        &agent(),
        &id,
        FindingStatus::Confirmed,
        Some("a forwarding the owner did not set"),
    )
    .unwrap();
    id
}

fn facts_of(case: &Case, id: &str) -> sparrow_core::detect::enrich::facts::FindingFacts {
    let rules = facts_text::rules().unwrap();
    match read::finding_show(case.conn(), id, &rules).unwrap().facts {
        Some(FactsField::Present { facts }) => facts,
        other => panic!("facts expected, got {other:?}"),
    }
}

/// Not enriched yet: a case detected before the feature.
fn pre_feature(case: &Case) {
    case.conn()
        .execute_batch(
            "DELETE FROM finding_facts; DELETE FROM account_rollup; \
             DELETE FROM case_meta WHERE key IN ('enrichment_run_id', 'enrichment_error');",
        )
        .unwrap();
}

#[test]
fn the_report_has_an_accounts_section_after_the_summary_and_before_the_timeline() {
    let s = scripted(false);
    let accounts = read::accounts(s.case.conn(), None, None).unwrap();
    assert!(accounts.accounts.len() >= 2 && accounts.warnings.is_empty());
    for reviewed_only in [false, true] {
        let md = report(&s.case, reviewed_only);
        let at = |h: &str| md.find(h).unwrap_or_else(|| panic!("{h} missing"));
        assert!(at("## Executive summary") < at("## Accounts"));
        assert!(at("## Accounts") < at("## Timeline by phase"));
        let section = &md[at("## Accounts")..at("## Timeline by phase")];
        assert!(section.contains("facts, not decisions"), "{section}");
        assert!(section.contains(
            "| Account | Worst severity | Stages | First suspicious (UTC) | Addresses |"
        ));
        // One table row per account, worst first, each with its severity and stages.
        let rows: Vec<&str> = section
            .lines()
            .filter(|l| {
                l.starts_with("| ") && !l.starts_with("| Account") && !l.starts_with("| ---")
            })
            .collect();
        assert_eq!(rows.len(), accounts.accounts.len(), "{section}");
        for (row, a) in rows.iter().zip(&accounts.accounts) {
            assert!(
                row.contains(&md_escaped(&a.upn)) && row.contains(&a.worst_severity),
                "{row}"
            );
        }
        // The first account's first address and its reasons are in its row.
        let first = &accounts.accounts[0];
        if let Some(x) = first.addresses.first() {
            assert!(
                rows[0].contains(&md_escaped(&x.ip))
                    && rows[0].contains(&md_escaped(&x.reasons[0])),
                "{}",
                rows[0]
            );
        }
    }
}

/// The account name as the report escapes it (Markdown punctuation backslash-escaped).
fn md_escaped(s: &str) -> String {
    sparrow_core::export::text::md_cell(s)
}

#[test]
fn a_persistence_finding_lists_its_facts_in_fixed_sentences() {
    let s = scripted(false);
    let id = confirmed_with_facts(&s.case);
    let md = report(&s.case, false);
    let facts = facts_of(&s.case, &id);
    let lines = facts_text::fact_lines(&facts);
    assert!(!lines.is_empty());
    // The facts are a bullet list under the finding, in order, each sentence once.
    let at = md.find("- Facts:").expect("a Facts list");
    let after = &md[at..];
    let list: Vec<&str> = after
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with("  - "))
        .collect();
    assert_eq!(list.len(), lines.len(), "{after}");
    for (got, want) in list.iter().zip(&lines) {
        assert_eq!(*got, format!("  - {want}"));
    }
    assert!(
        md[..at].contains(&id),
        "the Facts list sits under its finding"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("earlier day(s) within the capture") || l.contains("unknown")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("Other findings on this account")
                || l.starts_with("No other findings"))
    );
    // Reviewed-only keeps accepted decisions only, so a pending finding and its facts are out of it.
    assert!(!report(&s.case, true).contains("- Facts:"));
}

#[test]
fn facts_say_unavailable_and_the_accounts_section_says_why_it_is_empty() {
    let s = scripted(false);
    let id = confirmed_with_facts(&s.case);
    pre_feature(&s.case);
    let md = report(&s.case, false);
    assert!(md.contains("- Facts unavailable: detection has not run since this version; run \\`sparrow detect\\`."), "{md}");
    assert!(!md.contains("- Facts:"));
    let at = md.find("## Accounts").unwrap();
    let section = &md[at..md.find("## Timeline by phase").unwrap()];
    assert!(
        section.contains("account roll\\-up unavailable")
            || section.contains("roll-up unavailable")
            || section.contains("unavailable"),
        "{section}"
    );
    assert!(
        section.contains("sparrow detect") && !section.contains("| Account |"),
        "{section}"
    );
    // The workbook: an empty Accounts sheet, the reason in the Summary, `facts_unavailable` in the Findings cell.
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let accounts = sheet_rows(&mut wb, "Accounts");
    assert_eq!(accounts.len(), 1, "header only: {accounts:?}");
    let summary = sheet_rows(&mut wb, "Summary");
    let row = summary.iter().find(|r| r[0] == "Accounts").unwrap();
    assert!(row[1].contains("sparrow detect"), "{row:?}");
    let findings = sheet_rows(&mut wb, "Findings");
    let c = findings[0].iter().position(|h| h == "Facts").unwrap();
    let mine = findings.iter().find(|r| r[0] == id).unwrap();
    assert!(
        mine[c].starts_with("{\"facts_unavailable\":"),
        "{}",
        mine[c]
    );
}

#[test]
fn the_workbook_has_an_accounts_sheet_and_a_facts_column() {
    let s = scripted(false);
    let id = confirmed_with_facts(&s.case);
    let accounts = read::accounts(s.case.conn(), None, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let rows = sheet_rows(&mut wb, "Accounts");
    assert_eq!(rows.len() - 1, accounts.accounts.len());
    let col = |h: &str| {
        rows[0]
            .iter()
            .position(|c| c == h)
            .unwrap_or_else(|| panic!("{h}"))
    };
    for (r, a) in rows[1..].iter().zip(&accounts.accounts) {
        assert_eq!(r[col("Account")], a.upn);
        assert_eq!(r[col("WorstSeverity")], a.worst_severity);
        assert_eq!(r[col("FindingCount")], a.finding_count.to_string());
        assert_eq!(r[col("AddressesTotal")], a.addresses_total.to_string());
        // Addresses are joined, one `ip (reasons)` each.
        assert_eq!(
            r[col("Addresses")].split("; ").count(),
            a.addresses.len(),
            "{:?}",
            r[col("Addresses")]
        );
    }
    // The Findings sheet: the stored facts as compact JSON for a finding with facts, empty for one without.
    let findings = sheet_rows(&mut wb, "Findings");
    let c = findings[0].iter().position(|h| h == "Facts").unwrap();
    let mine = findings.iter().find(|r| r[0] == id).unwrap();
    let json: serde_json::Value = serde_json::from_str(&mine[c]).unwrap();
    assert_eq!(json["facts_version"], 1);
    assert_eq!(
        json["actor_ips"].as_array().unwrap().len(),
        facts_of(&s.case, &id).actor_ips.len()
    );
    let with: usize = findings[1..].iter().filter(|r| !r[c].is_empty()).count();
    assert_eq!(
        with as i64,
        count(&s.case, "SELECT count(*) FROM finding_facts")
    );
    assert!(
        with < findings.len() - 1,
        "findings outside the facts families have an empty cell"
    );
}

#[test]
fn account_and_fact_text_is_escaped_in_the_report_and_never_a_formula_in_the_workbook() {
    let s = scripted(false);
    let id = confirmed_with_facts(&s.case);
    let c = s.case.conn();
    // Attacker-controlled text reaches the roll-up (an account name, an address) and the facts (an address).
    c.execute("UPDATE account_rollup SET upn = ? WHERE upn = (SELECT upn FROM account_rollup ORDER BY upn LIMIT 1)", [ATTACK]).unwrap();
    c.execute(
        "UPDATE finding_facts SET facts = json_merge_patch(facts, ?::JSON) WHERE finding_id = ?",
        [format!("{{\"actor_ips\":[{{\"ip\":{},\"asn\":null,\"asn_org\":null,\"is_hosting\":null,\"spray_source\":false,\"user_signin_days_before\":null,\"user_first_signin\":null}}]}}", serde_json::to_string(ATTACK).unwrap()), id.clone()],
    )
    .unwrap();
    let md = report(&s.case, false);
    assert_no_live_markup(&md);
    // And the workbook keeps the text raw, as strings: a formula-looking account stays text.
    c.execute(
        "UPDATE account_rollup SET upn = '=HYPERLINK(\"http://evil.example\",\"x\")' WHERE upn = ?",
        [ATTACK],
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let range = wb.worksheet_range("Accounts").unwrap();
    assert!(
        range
            .rows()
            .skip(1)
            .any(|r| matches!(&r[1], Data::String(t) if t.starts_with("=HYPERLINK")))
    );
    let formulas = wb.worksheet_formula("Accounts").unwrap();
    assert!(
        formulas.rows().all(|r| r.iter().all(String::is_empty)),
        "no cell of Accounts is a formula"
    );
}

#[test]
fn no_generated_fact_sentence_says_benign_or_malicious() {
    let s = scripted(false);
    let rules = facts_text::rules().unwrap();
    let ids: Vec<String> = {
        let mut st = s
            .case
            .conn()
            .prepare("SELECT finding_id FROM finding_facts")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert!(!ids.is_empty());
    let mut sentences = 0;
    for id in ids {
        let d = read::finding_show(s.case.conn(), &id, &rules).unwrap();
        if let Some(FactsField::Present { facts }) = d.facts {
            for line in facts_text::fact_lines(&facts) {
                sentences += 1;
                let l = line.to_lowercase();
                assert!(!l.contains("benign") && !l.contains("malicious"), "{line}");
            }
        }
    }
    assert!(sentences > 0);
    for reason in [
        "detection has not run since this version; run `sparrow detect`",
        "the last enrichment failed: boom",
    ] {
        let l = facts_text::unavailable_line(reason).to_lowercase();
        assert!(!l.contains("benign") && !l.contains("malicious"));
    }
}
