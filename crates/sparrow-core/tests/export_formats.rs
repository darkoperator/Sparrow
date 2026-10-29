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
use sparrow_core::data::DataDirs;
use sparrow_core::detect::load::load_rules;
use sparrow_core::export::devices_csv;
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
                end_time: None,
                event_count: None,
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
            dirs: DataDirs::default(),
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
    workbook_xlsx::write(case.conn(), &path, generated_at(), &DataDirs::default()).unwrap();
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
            "EndTime",
            "EventCount",
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
    let stamp = regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$").unwrap();
    // Three data rows, then the closing header record (no timestamp).
    assert_eq!(rec.len(), 1 + 3 + 1);
    for r in &rec[1..4] {
        assert_eq!(r.len(), COLUMNS.len());
        assert!(stamp.is_match(&r[0]), "{}", r[0]);
        assert_eq!(r[10], "verified");
        assert_eq!(r[11], "agent:claude");
        assert_eq!(r[12], "pending_review");
        assert!(r[14].contains(':'), "evidence ref: {}", r[14]);
        // ungrouped entries: both new cells are empty
        assert_eq!((r[1].as_str(), r[2].as_str()), ("", ""));
    }
    assert_eq!(rec[4][3], "sparrow-export");
    // The closing record sorts with the data: its Timestamp is the generation time.
    assert_eq!(rec[4][0], "2026-10-03T00:00:00Z");
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
    let stamp = regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$").unwrap();
    for r in &rec[1..rec.len() - 1] {
        assert!(stamp.is_match(&r[0]), "{}", r[0]);
        assert_eq!(r.len(), COLUMNS.len());
    }
    // Rows cited by a verified entry carry its phase and decision.
    assert!(
        rec.iter()
            .any(|r| r[10] == "verified" && r[9] == "initial_access")
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
            "Devices",
            "Devices (low confidence)",
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
    assert!(rec.iter().any(|r| r[8] == want), "{rec:?}");
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
            end_time: None,
            event_count: None,
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
            .any(|r| r[8] == "t\u{1b}[31mred\u{0} — n\u{7}ote\r\nline\u{200B}two")
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
    assert!(md.contains("**Generated at:** 2026-10-03T00:00:00Z"));
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
            end_time: None,
            event_count: None,
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
    let summaries: Vec<&str> = rec.iter().map(|r| r[8].as_str()).collect();
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
        assert!(!r[13].starts_with('\''), "{r:?}");
    }
    // Scope all goes through the same writer: no cell of any row starts with a formula character.
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::All));
    for r in &csv_records(&bytes)[1..] {
        for (i, cell) in r.iter().enumerate().filter(|(i, _)| *i > 1 && *i != 13) {
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
            end_time: None,
            event_count: None,
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
            end_time: None,
            event_count: None,
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
            && r[4] == "A sentinel date"),
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
    assert!(ny.0.contains("2026-08-11T14:24:08Z"));
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
    let rules = load_rules(&DataDirs::default()).unwrap();
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
    let md = report(&s.case, false);
    let at = |h: &str| md.find(h).unwrap_or_else(|| panic!("{h} missing"));
    assert!(at("## Executive summary") < at("## Accounts"));
    assert!(at("## Accounts") < at("## Timeline by phase"));
    let section = &md[at("## Accounts")..at("## Timeline by phase")];
    assert!(section.contains("facts, not decisions"), "{section}");
    assert!(section.contains(
        "| Tenant | Account | Worst severity | Stages | First suspicious (UTC) | Sign-in coverage (UTC) | Reviewed | Addresses |"
    ));
    // One table row per account, worst first, each with its tenant, severity and stages.
    let rows: Vec<&str> = section
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| Tenant") && !l.starts_with("| ---"))
        .collect();
    assert_eq!(rows.len(), accounts.accounts.len(), "{section}");
    for (row, a) in rows.iter().zip(&accounts.accounts) {
        assert!(
            row.contains(&md_escaped(&a.tenant_key))
                && row.contains(&md_escaped(&a.upn))
                && row.contains(&a.worst_severity),
            "{row}"
        );
    }
    // The first account's first address and its reasons are in its row.
    let first = &accounts.accounts[0];
    if let Some(x) = first.addresses.first() {
        assert!(
            rows[0].contains(&md_escaped(&x.ip)) && rows[0].contains(&md_escaped(&x.reasons[0])),
            "{}",
            rows[0]
        );
    }
}

#[test]
fn a_reviewed_only_report_has_no_accounts_table_only_the_omission_line() {
    let s = scripted(false);
    let md = report(&s.case, true);
    let at = |h: &str| md.find(h).unwrap_or_else(|| panic!("{h} missing"));
    let section = &md[at("## Accounts")..at("## Timeline by phase")];
    assert!(
        section.contains(
            "_Account roll-up omitted: it is computed from all findings, including ones not yet reviewed._"
        ),
        "{section}"
    );
    assert!(!section.contains('|'), "no table: {section}");
    // No account name of the roll-up appears in that section.
    for a in read::accounts(s.case.conn(), None, None).unwrap().accounts {
        assert!(!section.contains(&md_escaped(&a.upn)), "{section}");
    }
    // The full report keeps the table.
    assert!(report(&s.case, false).contains("| Tenant | Account |"));
}

#[test]
fn the_reviewed_column_counts_the_accounts_findings_with_an_accepted_review() {
    let s = scripted(false);
    let accepted = read::finding_list(
        s.case.conn(),
        &FindingFilter {
            review_state: Some("accepted".into()),
            ..FindingFilter::default()
        },
    )
    .unwrap();
    assert!(
        !accepted.is_empty(),
        "the scripted session accepts a decision"
    );
    let md = report(&s.case, false);
    let section = &md[md.find("## Accounts").unwrap()..md.find("## Timeline by phase").unwrap()];
    let accounts = read::accounts(s.case.conn(), None, None).unwrap().accounts;
    let mut total = 0;
    for a in &accounts {
        let want = accepted
            .iter()
            .filter(|f| {
                f.tenant_key == a.tenant_key
                    && f.actor_upn.as_deref().map(str::to_lowercase) == Some(a.upn.clone())
            })
            .count();
        let row = section
            .lines()
            .find(|l| l.contains(&md_escaped(&a.upn)))
            .unwrap();
        let cells: Vec<&str> = row.split(" | ").collect();
        // Tenant, Account, Worst severity, Stages, First suspicious, Sign-in coverage, Reviewed, Addresses.
        assert_eq!(cells[6].trim(), want.to_string(), "{row}");
        total += want;
    }
    assert!(total >= 1, "some account has a reviewed finding");
    // The workbook has the same column.
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let rows = sheet_rows(&mut wb, "Accounts");
    let c = rows[0].iter().position(|h| h == "Reviewed").unwrap();
    let sum: usize = rows[1..]
        .iter()
        .map(|r| r[c].parse::<usize>().unwrap())
        .sum();
    assert_eq!(sum, total);
}

#[test]
fn the_same_account_in_two_tenants_gets_two_distinct_rows_in_the_report() {
    let s = scripted(false);
    let c = s.case.conn();
    let upn: String = c
        .query_row(
            "SELECT upn FROM account_rollup ORDER BY upn LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    c.execute(
        "INSERT INTO account_rollup SELECT 'second-tenant', upn, 'low', 1, '{\"low\":1}', '[\"persistence\"]', first_suspicious, rules, '[]', 0, false, computed_run_id, signins_first, signins_last FROM account_rollup WHERE upn = ?",
        [&upn],
    )
    .unwrap();
    let md = report(&s.case, false);
    let rows: Vec<&str> = md
        .lines()
        .filter(|l| l.contains(&md_escaped(&upn)) && l.starts_with("| "))
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let tenants: Vec<&str> = rows
        .iter()
        .map(|r| r.split(" | ").next().unwrap())
        .collect();
    assert_ne!(tenants[0], tenants[1], "{rows:?}");
    assert!(
        rows.iter().any(|r| r.starts_with("| second-tenant | ")),
        "{rows:?}"
    );
    // Their severities differ: they are not duplicate claims.
    assert!(
        rows.iter().any(|r| r.contains("| low |")) && rows.iter().any(|r| r.contains("| high |")),
        "{rows:?}"
    );
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let sheet = sheet_rows(&mut wb, "Accounts");
    assert_eq!(sheet.iter().filter(|r| r[1] == upn).count(), 2);
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
    let rules = load_rules(&DataDirs::default()).unwrap();
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

// ---- rules are loaded only when the enrichment is not current, and a failure never aborts an export

fn bad_dirs() -> DataDirs {
    DataDirs {
        data: None,
        rules: vec![std::path::PathBuf::from("/nonexistent/sparrow-rules-dir")],
    }
}

fn report_with(case: &Case, dirs: DataDirs) -> String {
    let mut out = Vec::new();
    report_md::write(
        case.conn(),
        &mut out,
        &ReportOpts {
            reviewed_only: false,
            generated_at: generated_at(),
            dirs,
        },
    )
    .unwrap();
    String::from_utf8(out).unwrap()
}

fn workbook_with(
    case: &Case,
    dir: &tempfile::TempDir,
    dirs: &DataDirs,
) -> Xlsx<std::io::BufReader<std::fs::File>> {
    let path = dir.path().join("w.xlsx");
    workbook_xlsx::write(case.conn(), &path, generated_at(), dirs).unwrap();
    open_workbook(&path).unwrap()
}

#[test]
fn unloadable_rules_do_not_matter_while_the_stored_facts_are_current() {
    assert!(
        load_rules(&bad_dirs()).is_err(),
        "the fixture must really fail to load"
    );
    let s = scripted(false);
    let id = confirmed_with_facts(&s.case);
    let good = report_with(&s.case, DataDirs::default());
    let bad = report_with(&s.case, bad_dirs());
    assert_eq!(bad, good, "current facts need no rules");
    assert!(bad.contains("- Facts:") && !bad.contains("could not be loaded"));
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook_with(&s.case, &dir, &bad_dirs());
    let findings = sheet_rows(&mut wb, "Findings");
    let c = findings[0].iter().position(|h| h == "Facts").unwrap();
    let mine = findings.iter().find(|r| r[0] == id).unwrap();
    assert!(mine[c].contains("\"facts_version\":1"), "{}", mine[c]);
}

#[test]
fn unloadable_rules_with_stale_facts_say_unavailable_and_the_export_still_succeeds() {
    let s = scripted(false);
    let id = confirmed_with_facts(&s.case);
    pre_feature(&s.case);
    let md = report_with(&s.case, bad_dirs());
    // The confirmed finding's line names the facts as unavailable, the reason and why the rules were not used.
    let line = md
        .lines()
        .find(|l| l.starts_with("- Facts unavailable:"))
        .unwrap_or_else(|| panic!("no unavailable line:\n{md}"));
    assert!(
        line.contains("sparrow detect") && line.contains("rules could not be loaded"),
        "{line}"
    );
    // The Accounts section does not need rules and says why it is empty.
    let at = md.find("## Accounts").unwrap();
    let section = &md[at..md.find("## Timeline by phase").unwrap()];
    assert!(
        section.contains("unavailable") && section.contains("sparrow detect"),
        "{section}"
    );
    // The workbook too: the Facts cell of the finding says so, the Accounts sheet is empty.
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook_with(&s.case, &dir, &bad_dirs());
    let findings = sheet_rows(&mut wb, "Findings");
    let c = findings[0].iter().position(|h| h == "Facts").unwrap();
    let mine = findings.iter().find(|r| r[0] == id).unwrap();
    assert!(
        mine[c].starts_with("{\"facts_unavailable\":")
            && mine[c].contains("rules could not be loaded"),
        "{}",
        mine[c]
    );
    assert_eq!(sheet_rows(&mut wb, "Accounts").len(), 1);
    // With loadable rules the same case names only the findings of family rules.
    let good = report_with(&s.case, DataDirs::default());
    assert!(good.contains("- Facts unavailable:") && !good.contains("rules could not be loaded"));
}

// ------------------------------------------------------------------ devices

const D_REMOVED: &str = "dddddddd-0000-0000-0000-00000000000d";
const E_UNKNOWN: &str = "eeeeeeee-0000-0000-0000-00000000000e";
const DEL_ID: &str = "00000000-0000-4000-8000-000000000042";
const BAD_NAME: &str = "=cmd|' /C calc'!A0";
const HOST_IP: &str = "198.51.100.7";

fn dev_insert(case: &Case, table: &str, fields: serde_json::Value, seed: &str) {
    sparrow_core::detect::test::insert_record(case, "t1", table, &fields, seed).unwrap();
}

/// Device D (removed by a Delete device event at line 42) and device E (never removed, named like a formula), both
/// seen on a malicious IP; provenance for each record.
fn devices_case() -> Case {
    use serde_json::json;
    let case = Case::in_memory().unwrap();
    dev_insert(&case, "tenant", json!({"tenant_key": "t1"}), "tenant");
    indicators::add_indicator(
        case.conn(),
        &Actor::analyst("tester").unwrap(),
        Some("t1"),
        IndicatorType::Ip,
        HOST_IP,
        Verdict::Malicious,
        None,
    )
    .unwrap();
    let dev = |id: &str, name: Option<&str>| {
        json!({"device_id": id, "display_name": name, "os": null, "browser": null,
               "is_compliant": null, "is_managed": null, "trust_type": null})
    };
    for (key, id, name, h) in [
        ("si-d", D_REMOVED, None, 8),
        ("si-e", E_UNKNOWN, Some(BAD_NAME), 9),
    ] {
        dev_insert(
            &case,
            "signins",
            json!({"record_key": key, "user_upn": "alice@contoso.example", "ip": HOST_IP,
                   "event_time": format!("2026-03-01T{h:02}:00:00Z"), "app_name": "Office 365", "device": dev(id, name)}),
            key,
        );
    }
    dev_insert(
        &case,
        "ual_events",
        json!({"record_id": DEL_ID, "event_time": "2026-03-02T09:00:00Z", "workload": "AzureActiveDirectory",
               "operation": "Delete device.", "user_upn": "admin@contoso.example", "client_ip": "192.0.2.200",
               "audit_data": {"Operation": "Delete device.", "ModifiedProperties": [
                   {"Name": "TargetId.DeviceId", "NewValue": format!("[\r\n  \"{D_REMOVED}\"\r\n]"), "OldValue": "[]"}]}}),
        "del",
    );
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO source_files (file_id, collection_id, rel_path, size_bytes, sha256, status) \
               SELECT 1, collection_id, 'signins.csv', 1, 'sha-signins', 'parsed' FROM collections WHERE tenant_key = 't1';
             INSERT INTO source_files (file_id, collection_id, rel_path, size_bytes, sha256, status) \
               SELECT 2, collection_id, 'ual.json', 1, 'sha-ual', 'parsed' FROM collections WHERE tenant_key = 't1';
             INSERT INTO record_sources VALUES ('signins', 'si-d', 1, 0, 5, 5, 0, 1, 'x'), ('signins', 'si-e', 1, 1, 6, 6, 0, 1, 'x'),
               ('ual_events', '{DEL_ID}', 2, 0, 42, 44, 0, 1, 'x');"
        ))
        .unwrap();
    case
}

fn devices_csv_records(case: &Case) -> (Vec<Vec<String>>, u64) {
    let mut out = Vec::new();
    let n = devices_csv::write_devices(case.conn(), &mut out).unwrap();
    (csv_records(&out), n)
}

#[test]
fn devices_csv_has_status_and_provenance() {
    let case = devices_case();
    let (rows, n) = devices_csv_records(&case);
    assert_eq!(n, 2);
    assert_eq!(rows[0], devices_csv::DEVICE_COLUMNS);
    assert_eq!(
        devices_csv::DEVICE_COLUMNS.join(","),
        "status,confidence,tenant_key,device_id,object_id,display_name,os,trust_type,is_compliant,is_managed,\
         registered_utc,registered_source,removed_utc,removed_source,disabled_utc,disabled_source,last_active_utc,\
         last_active_source,users,malicious_ips,other_ips,reasons,note,analyst_status,analyst_note,analyst_by,\
         analyst_decided_utc,analyst_warning"
    );
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    // Unknown devices list before removed ones.
    let e = &rows[1];
    let d = &rows[2];
    assert_eq!(
        (e[col("device_id")].as_str(), e[col("status")].as_str()),
        (E_UNKNOWN, "unknown")
    );
    assert_eq!(
        (d[col("device_id")].as_str(), d[col("status")].as_str()),
        (D_REMOVED, "removed")
    );
    assert_eq!(d[col("confidence")], "high");
    assert_eq!(d[col("removed_utc")], "2026-03-02 09:00:00");
    assert_eq!(d[col("removed_source")], "t1/ual.json:42-44");
    assert!(d[col("removed_source")].contains(":42"));
    assert_eq!(d[col("last_active_source")], "t1/signins.csv:5");
    assert_eq!(d[col("malicious_ips")], HOST_IP);
    assert_eq!(d[col("note")], "");
    assert!(d[col("reasons")].starts_with("indicator 198.51.100.7 (malicious)"));
    // The unknown device carries the containment note; its formula-like name is neutralised.
    assert_eq!(
        e[col("note")],
        "treat as active — collect Get-Devices to confirm"
    );
    assert_eq!(e[col("display_name")], format!("'{BAD_NAME}"));
    assert_eq!(e[col("removed_utc")], "");
    assert_eq!(e[col("removed_source")], "");
}

#[test]
fn device_exports_list_the_analyst_status_next_to_the_computed_one() {
    use sparrow_core::case::actor::Actor;
    use sparrow_core::case::audit::test_clock;
    use sparrow_core::case::device_status::{AnalystStatus, set_status};
    let case = devices_case();
    let analyst = Actor::analyst("carlos").unwrap();
    // D is removed by the evidence, the analyst confirms it; E (unknown, last active 1 Mar 09:00) was removed by the
    // responders on 1 Mar 08:30 by the analyst's account, so it was active after that.
    test_clock::set(Some(
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 3, 1, 8, 30, 0).unwrap(),
    ));
    set_status(
        case.conn(),
        &analyst,
        E_UNKNOWN,
        Some(AnalystStatus::Removed),
        Some("=wiped by IT"),
    )
    .unwrap();
    set_status(
        case.conn(),
        &analyst,
        D_REMOVED,
        Some(AnalystStatus::ConfirmedAttacker),
        None,
    )
    .unwrap();
    test_clock::set(None);
    let (rows, _) = devices_csv_records(&case);
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    let e = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == E_UNKNOWN)
        .unwrap();
    let d = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == D_REMOVED)
        .unwrap();
    // The computed status is still there, untouched.
    assert_eq!(
        (e[col("status")].as_str(), d[col("status")].as_str()),
        ("unknown", "removed")
    );
    assert_eq!(e[col("analyst_status")], "removed");
    // The note is analyst text: neutralised like every other cell.
    assert_eq!(e[col("analyst_note")], "'=wiped by IT");
    assert_eq!(e[col("analyst_by")], "analyst:carlos");
    assert_eq!(e[col("analyst_decided_utc")], "2026-03-01 08:30:00");
    assert_eq!(e[col("analyst_warning")], devices_csv::ANALYST_WARNING);
    assert_eq!(d[col("analyst_status")], "confirmed_attacker");
    assert_eq!(d[col("analyst_note")], "");
    assert_eq!(d[col("analyst_warning")], "");
    // The report's contain list shows both on E (D, removed, is not on it).
    let md = report(&case, false);
    let section = devices_section(&md);
    assert!(
        section.contains("| Status | Analyst | Device |"),
        "{section}"
    );
    let line = section.lines().find(|l| l.contains(E_UNKNOWN)).unwrap();
    assert!(line.starts_with("| unknown — treat as active"), "{line}");
    assert!(
        line.contains("removed \\(analyst:carlos, 2026-03-01T08:30:00Z\\)"),
        "{line}"
    );
    assert!(
        line.contains("active after the analyst's removal"),
        "{line}"
    );

    // The workbook's Devices sheet: the five cells, the `=` note as a string (never a formula), the UTC time.
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&case, &dir);
    let rows = sheet_rows(&mut wb, "Devices");
    assert_eq!(rows[0], devices_csv::DEVICE_COLUMNS);
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    let e = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == E_UNKNOWN)
        .unwrap();
    let d = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == D_REMOVED)
        .unwrap();
    assert_eq!(
        [
            e[col("status")].as_str(),
            e[col("analyst_status")].as_str(),
            e[col("analyst_note")].as_str(),
            e[col("analyst_by")].as_str(),
            e[col("analyst_decided_utc")].as_str(),
            e[col("analyst_warning")].as_str(),
        ],
        [
            "unknown",
            "removed",
            "=wiped by IT",
            "analyst:carlos",
            "2026-03-01 08:30:00",
            devices_csv::ANALYST_WARNING
        ]
    );
    assert_eq!(
        (
            d[col("analyst_status")].as_str(),
            d[col("analyst_note")].as_str(),
            d[col("analyst_warning")].as_str()
        ),
        ("confirmed_attacker", "", "")
    );
    let range = wb.worksheet_range("Devices").unwrap();
    let e_row = range
        .rows()
        .find(|r| {
            r.iter()
                .any(|c| matches!(c, Data::String(t) if t == E_UNKNOWN))
        })
        .unwrap();
    assert_eq!(
        e_row[col("analyst_note")],
        Data::String("=wiped by IT".into())
    );
    assert!(matches!(
        e_row[col("analyst_decided_utc")],
        Data::DateTime(_)
    ));
    let formulas = wb.worksheet_formula("Devices").unwrap();
    assert_eq!(
        formulas
            .rows()
            .flat_map(|r| r.iter())
            .filter(|f| !f.is_empty())
            .count(),
        0
    );
}

#[test]
fn device_sightings_csv_resolves_file_and_lines() {
    let case = devices_case();
    insert_intel(&case);
    let mut out = Vec::new();
    let n = devices_csv::write_sightings(case.conn(), &mut out).unwrap();
    let rows = csv_records(&out);
    assert_eq!(n, 2);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], devices_csv::SIGHTING_COLUMNS);
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    for r in &rows[1..] {
        assert!(!r[col("source_file")].is_empty(), "{r:?}");
        assert!(!r[col("line_start")].is_empty());
        assert_eq!(r[col("ip_malicious")], "true");
        assert_eq!(r[col("ip_asn_org")], "Krixe");
        assert_eq!(r[col("ip_country")], "SG");
    }
    let d = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == D_REMOVED)
        .unwrap();
    assert_eq!(d[col("source_file")], "t1/signins.csv");
    assert_eq!(
        (d[col("line_start")].as_str(), d[col("line_end")].as_str()),
        ("5", "5")
    );
    assert_eq!(d[col("source_file_sha256")], "sha-signins");
    assert_eq!(d[col("event_time_utc")], "2026-03-01 08:00:00");
    assert_eq!(d[col("record_key")], "si-d");
}

fn insert_intel(case: &Case) {
    dev_insert(
        case,
        "ip_intel",
        serde_json::json!({"ip": HOST_IP, "asn": 213122, "asn_org": "Krixe", "country_iso": "SG", "is_hosting": true}),
        "intel",
    );
}

#[test]
fn report_lists_devices_to_contain() {
    let case = devices_case();
    let md = report(&case, false);
    let i = md.find("## Devices to contain").expect("section");
    let j = md[i..].find("## Evidence gaps").unwrap() + i;
    // After Indicators, before Evidence gaps.
    assert!(md.find("## Indicators").unwrap() < i);
    let section = &md[i..j];
    assert!(section.contains(E_UNKNOWN), "{section}");
    assert!(section.contains("treat as active"), "{section}");
    // The last-active date names its file and line.
    assert!(
        section.contains("2026-03-01T09:00:00Z \\(t1/signins.csv:6\\)"),
        "{section}"
    );
    // The removed device is not on the contain list.
    assert!(!section.contains(D_REMOVED), "{section}");
    // The formula-like name is shown escaped, never raw.
    assert!(!section.contains(&format!("| {BAD_NAME}")), "{section}");
}

#[test]
fn report_says_when_no_device_was_seen() {
    let case = Case::in_memory().unwrap();
    let md = report(&case, false);
    assert!(md.contains("## Devices to contain"));
    assert!(md.contains("No device was seen on a malicious IP."));
}

/// Makes device E's only link an impossible-travel leg (the indicator is removed; a travel finding cites its sign-in).
fn make_e_low(case: &Case) {
    case.conn()
        .execute_batch(
            "UPDATE case_indicators SET removed_at = now(), removed_by = 'x';
             INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, severity, title, actor_upn, status, created_by, created_at, updated_at)
               VALUES ('f-travel', 'fp', 't1', 'SPW-ID-003', 'medium', 'travel', 'alice@contoso.example', 'new', 'rule', now(), now());
             INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id)
               VALUES ('f-travel', 'signins', 'si-e', 'trigger', 1);",
        )
        .unwrap();
}

fn devices_section(md: &str) -> &str {
    let i = md.find("## Devices to contain").unwrap();
    &md[i..md[i..].find("## Evidence gaps").unwrap() + i]
}

const N_MORE: &str = "more low-confidence devices (reached only through impossible-travel legs) are listed in devices.csv and the app.";
const ONE_MORE: &str = "1 more low-confidence device (reached only through impossible-travel legs) is listed in devices.csv and the app.";

#[test]
fn report_lists_high_confidence_devices_and_counts_the_low_ones() {
    let case = devices_case();
    // D (removed) stays out; E is high. Add two low-confidence devices reached only through a travel leg.
    for (n, id) in [
        ("a", "11111111-0000-0000-0000-000000000001"),
        ("b", "22222222-0000-0000-0000-000000000002"),
    ] {
        dev_insert(
            &case,
            "signins",
            serde_json::json!({"record_key": format!("si-low-{n}"), "user_upn": "bob@contoso.example", "ip": "192.0.2.77",
                   "event_time": "2026-03-01T10:00:00Z", "app_name": "Office 365",
                   "device": {"device_id": id, "display_name": null, "os": null, "browser": null,
                              "is_compliant": null, "is_managed": null, "trust_type": null}}),
            &format!("low-{n}"),
        );
        case.conn()
            .execute_batch(&format!(
                "INSERT INTO findings (finding_id, fingerprint, tenant_key, rule_id, severity, title, actor_upn, status, created_by, created_at, updated_at)
                   VALUES ('f-t-{n}', 'fp-{n}', 't1', 'SPW-ID-003', 'medium', 'travel', 'bob@contoso.example', 'new', 'rule', now(), now());
                 INSERT INTO finding_evidence (finding_id, source_table, record_key, role, added_run_id)
                   VALUES ('f-t-{n}', 'signins', 'si-low-{n}', 'trigger', 1);"
            ))
            .unwrap();
    }
    let section = devices_section(&report(&case, false)).to_string();
    assert!(section.contains(E_UNKNOWN), "{section}");
    assert!(!section.contains(D_REMOVED), "{section}");
    assert!(
        !section.contains("11111111-0000") && !section.contains("22222222-0000"),
        "{section}"
    );
    assert!(section.contains(&format!("2 {N_MORE}")), "{section}");
    // The per-row marker is gone: low devices no longer appear in the report.
    assert!(!section.contains("(low confidence"), "{section}");
    assert!(!section.contains("No high-confidence"), "{section}");
}

#[test]
fn report_with_only_low_confidence_devices_says_so() {
    let case = devices_case();
    make_e_low(&case);
    // D is gone altogether, so E is the one suspect, and low.
    case.conn()
        .execute_batch("DELETE FROM signins WHERE record_key = 'si-d';")
        .unwrap();
    let section = devices_section(&report(&case, false)).to_string();
    assert!(
        section.contains("No high-confidence device was seen on a malicious IP."),
        "{section}"
    );
    assert!(section.contains(ONE_MORE), "{section}");
    assert!(!section.contains(E_UNKNOWN), "{section}");
    assert!(!section.contains("| Status |"), "no table: {section}");
    assert!(!section.contains("has been removed"), "{section}");
    assert!(
        !section.contains("No device was seen on a malicious IP."),
        "{section}"
    );
}

#[test]
fn report_with_only_a_removed_suspect_says_it_was_removed() {
    let case = devices_case();
    // Device E is not seen at all: D, removed, is the only suspect.
    case.conn()
        .execute_batch("DELETE FROM signins WHERE record_key = 'si-e';")
        .unwrap();
    let section = devices_section(&report(&case, false)).to_string();
    assert!(
        section.contains("Every device seen on a malicious IP has been removed (1 removed device is listed in devices.csv)."),
        "{section}"
    );
    assert!(
        !section.contains("No device was seen on a malicious IP."),
        "{section}"
    );
    assert!(!section.contains("| Status |"), "{section}");
    assert!(!section.contains("low-confidence"), "{section}");
}

#[test]
fn report_with_removed_and_low_devices_says_both() {
    let case = devices_case();
    make_e_low(&case);
    // D (removed) and E (not removed) are both low: the removed wording, then the low line.
    let section = devices_section(&report(&case, false)).to_string();
    assert!(
        section.contains("No high-confidence device is left to contain; 1 removed device is listed in devices.csv."),
        "{section}"
    );
    // A low-confidence device is still outstanding, so "every device has been removed" would be false.
    assert!(!section.contains("has been removed"), "{section}");
    assert!(!section.contains("Every device"), "{section}");
    assert!(section.contains(ONE_MORE), "{section}");
    assert!(!section.contains(E_UNKNOWN), "{section}");
}

#[test]
fn workbook_has_devices_sheet() {
    let case = devices_case();
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&case, &dir);
    assert!(wb.sheet_names().contains(&"Devices".to_string()));
    let rows = sheet_rows(&mut wb, "Devices");
    // Every suspect device, removed ones included.
    assert_eq!(rows.len() - 1, 2);
    assert_eq!(rows[0], devices_csv::DEVICE_COLUMNS);
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    let removed = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == D_REMOVED)
        .unwrap();
    assert_eq!(removed[col("status")], "removed");
    assert_eq!(removed[col("removed_utc")], "2026-03-02 09:00:00");
    assert_eq!(removed[col("removed_source")], "t1/ual.json:42-44");
    let unknown = rows[1..]
        .iter()
        .find(|r| r[col("device_id")] == E_UNKNOWN)
        .unwrap();
    // A workbook cell keeps the raw text, as a string.
    assert_eq!(unknown[col("display_name")], BAD_NAME);
}

#[test]
fn sightings_keep_the_name_their_own_record_carried() {
    use serde_json::json;
    let case = devices_case();
    // Device D later appears under another name, from another line of the same file.
    dev_insert(
        &case,
        "signins",
        json!({"record_key": "si-d2", "user_upn": "alice@contoso.example", "ip": HOST_IP,
               "event_time": "2026-03-04T08:00:00Z", "app_name": "Office 365",
               "device": {"device_id": D_REMOVED, "display_name": "Renamed", "os": null, "browser": null,
                          "is_compliant": null, "is_managed": null, "trust_type": null}}),
        "si-d2",
    );
    case.conn()
        .execute_batch(
            "INSERT INTO record_sources VALUES ('signins', 'si-d2', 1, 2, 9, 9, 0, 1, 'x');",
        )
        .unwrap();
    let mut out = Vec::new();
    devices_csv::write_sightings(case.conn(), &mut out).unwrap();
    let rows = csv_records(&out);
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    let mut d: Vec<&Vec<String>> = rows[1..]
        .iter()
        .filter(|r| r[col("device_id")] == D_REMOVED)
        .collect();
    d.sort_by(|a, b| a[col("event_time_utc")].cmp(&b[col("event_time_utc")]));
    assert_eq!(d.len(), 2);
    // The first record carried no name; the later one carried "Renamed". Each keeps its own, with its own line.
    assert_eq!(
        (
            d[0][col("display_name")].as_str(),
            d[0][col("line_start")].as_str()
        ),
        ("", "5")
    );
    assert_eq!(
        (
            d[1][col("display_name")].as_str(),
            d[1][col("line_start")].as_str()
        ),
        ("Renamed", "9")
    );
    // The device row itself shows the current (latest) name.
    let (devs, _) = devices_csv_records(&case);
    let dcol = |name: &str| devs[0].iter().position(|c| c == name).unwrap();
    let row = devs[1..]
        .iter()
        .find(|r| r[dcol("device_id")] == D_REMOVED)
        .unwrap();
    assert_eq!(row[dcol("display_name")], "Renamed");
}

/// 405 sightings of one device, each from its own IPv6 documentation address, with its own source line and its own
/// `ip_intel` row; the first address is malicious. Straddles the 400-per-query batch size of both lookups.
#[test]
fn sightings_export_is_complete_across_the_batch_boundary() {
    use serde_json::json;
    const N: usize = 405;
    let case = Case::in_memory().unwrap();
    dev_insert(&case, "tenant", json!({"tenant_key": "t1"}), "tenant");
    let ip = |i: usize| format!("2001:db8::{i:x}");
    indicators::add_indicator(
        case.conn(),
        &Actor::analyst("tester").unwrap(),
        Some("t1"),
        IndicatorType::Ip,
        &ip(0),
        Verdict::Malicious,
        None,
    )
    .unwrap();
    for i in 0..N {
        dev_insert(
            &case,
            "signins",
            json!({"record_key": format!("s-{i:04}"), "user_upn": "alice@contoso.example", "ip": ip(i),
                   "event_time": format!("2026-03-01T00:{:02}:{:02}Z", i / 60, i % 60), "app_name": "Office 365",
                   "device": {"device_id": D_REMOVED, "display_name": null, "os": null, "browser": null,
                              "is_compliant": null, "is_managed": null, "trust_type": null}}),
            &format!("s-{i}"),
        );
    }
    case.conn()
        .execute_batch(&format!(
            "INSERT INTO source_files (file_id, collection_id, rel_path, size_bytes, sha256, status) \
               SELECT 1, collection_id, 'signins.csv', 1, 'sha-signins', 'parsed' FROM collections WHERE tenant_key = 't1';
             INSERT INTO record_sources SELECT 'signins', 's-' || lpad(CAST(i AS VARCHAR), 4, '0'), 1, i, i + 1000, i + 1000, 0, 1, 'x'
               FROM range({N}) r(i);
             INSERT INTO ip_intel (ip, asn, asn_org, country_iso, is_hosting, is_microsoft, is_private)
               SELECT '2001:db8::' || lower(printf('%x', i)), 64500 + i, 'Org-' || i, 'US', false, false, false FROM range({N}) r(i);"
        ))
        .unwrap();

    let mut out = Vec::new();
    let n = devices_csv::write_sightings(case.conn(), &mut out).unwrap();
    assert_eq!(n as usize, N);
    let rows = csv_records(&out);
    assert_eq!(rows.len(), N + 1);
    let col = |name: &str| rows[0].iter().position(|c| c == name).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for r in &rows[1..] {
        let key = r[col("record_key")].clone();
        let i: usize = key[2..].parse().unwrap();
        assert!(seen.insert(i), "{key} appears twice");
        // Its own source, its own address and that address's own enrichment.
        assert_eq!(r[col("line_start")], (i + 1000).to_string(), "{key}");
        assert_eq!(r[col("source_file")], "t1/signins.csv", "{key}");
        assert_eq!(r[col("ip")], ip(i), "{key}");
        assert_eq!(r[col("ip_asn_org")], format!("Org-{i}"), "{key}");
        assert_eq!(r[col("ip_malicious")], (i == 0).to_string(), "{key}");
    }
    assert_eq!(seen.len(), N);
    // Both sides of the boundary: the 400th and 401st rows (0-based 399, 400), plus the first and the last.
    for i in [0, 399, 400, N - 1] {
        assert!(seen.contains(&i));
    }

    // The device row's other_ips are enriched for the first and last address, past the batch size.
    let (devs, _) = devices_csv_records(&case);
    let dcol = |name: &str| devs[0].iter().position(|c| c == name).unwrap();
    let others = &devs[1][dcol("other_ips")];
    assert_eq!(others.matches("; ").count() + 1, N - 1);
    assert!(
        others.contains(&format!("{} (Org-1, US)", ip(1))),
        "first other IP"
    );
    assert!(
        others.contains(&format!("{} (Org-{}, US)", ip(N - 1), N - 1)),
        "last other IP"
    );
}

#[test]
fn workbook_splits_devices_by_confidence() {
    let case = devices_case();
    // Before: both devices are high.
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&case, &dir);
    let names = wb.sheet_names();
    let i = names.iter().position(|n| n == "Devices").unwrap();
    assert_eq!(names[i + 1], "Devices (low confidence)");
    assert_eq!(sheet_rows(&mut wb, "Devices").len() - 1, 2);
    assert_eq!(
        sheet_rows(&mut wb, "Devices (low confidence)").len(),
        1,
        "header only"
    );
    // After: the shared address is only an impossible-travel leg, so D and E are both low-confidence.
    make_e_low(&case);
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&case, &dir);
    let high = sheet_rows(&mut wb, "Devices");
    let low = sheet_rows(&mut wb, "Devices (low confidence)");
    assert_eq!(high.len(), 1, "no high-confidence device");
    assert_eq!(low.len(), 3);
    assert_eq!(low[0], devices_csv::DEVICE_COLUMNS);
    let col = |name: &str| low[0].iter().position(|c| c == name).unwrap();
    assert!(low[1..].iter().all(|r| r[col("confidence")] == "low"));
    let mut ids: Vec<&str> = low[1..]
        .iter()
        .map(|r| r[col("device_id")].as_str())
        .collect();
    ids.sort();
    assert_eq!(ids, [D_REMOVED, E_UNKNOWN]);
}

#[test]
fn a_grouped_entry_fills_end_time_and_event_count_in_the_csv_and_workbook() {
    let s = scripted(false);
    let c = s.case.conn();
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
            end_time: Some(Utc.with_ymd_and_hms(2026, 9, 1, 12, 30, 15).unwrap()),
            event_count: Some(1234),
            tenant_key: None,
            event_time: Utc.with_ymd_and_hms(2026, 9, 1, 8, 0, 0).unwrap(),
            title: "Spray window".into(),
            narrative: None,
            phase: Phase::InitialAccess,
            evidence: vec![EvidenceRef::parse(&key).unwrap()],
        },
    )
    .unwrap();
    te::verify(c, &agent(), &id).unwrap();
    let (bytes, _) = csv_bytes(&s.case, &csv_opts(Scope::Verified));
    let rec = csv_records(&bytes);
    let row = rec.iter().find(|r| r[8] == "Spray window").unwrap();
    assert_eq!(
        (row[0].as_str(), row[1].as_str(), row[2].as_str()),
        ("2026-09-01T08:00:00Z", "2026-09-01T12:30:15Z", "1234")
    );
    // the three ungrouped entries still have both cells empty
    assert_eq!(
        rec[1..rec.len() - 1]
            .iter()
            .filter(|r| r[1].is_empty() && r[2].is_empty())
            .count(),
        3
    );
    let dir = tempfile::tempdir().unwrap();
    let mut wb = workbook(&s.case, &dir);
    let tl = sheet_rows(&mut wb, "Timeline");
    let t = tl[0].iter().position(|c| c == "Title").unwrap();
    let (e, n) = (
        tl[0].iter().position(|c| c == "EndTime").unwrap(),
        tl[0].iter().position(|c| c == "EventCount").unwrap(),
    );
    assert_eq!((e, n), (1, 2));
    let row = tl.iter().find(|r| r[t] == "Spray window").unwrap();
    assert!(
        row[e].starts_with("2026-09-01") && row[e].contains("12:30:15"),
        "{}",
        row[e]
    );
    assert_eq!(row[n], "1234");
    // the workbook lists every entry, the 3 verified ones and the 1 still proposed
    assert_eq!(
        tl.iter()
            .filter(|r| r[e].is_empty() && r[n].is_empty())
            .count(),
        4
    );
}

#[test]
fn no_time_in_the_report_or_the_csv_header_uses_the_old_space_separated_format() {
    let old = regex::Regex::new(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d").unwrap();
    let iso = regex::Regex::new(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ").unwrap();
    for hostile in [false, true] {
        let s = scripted(hostile);
        for reviewed_only in [false, true] {
            let md = report(&s.case, reviewed_only);
            let hits: Vec<&str> = old.find_iter(&md).map(|m| m.as_str()).collect();
            assert!(hits.is_empty(), "old-format times in the report: {hits:?}");
            // the check is not vacuous: the report does print ISO times
            assert!(iso.find_iter(&md).count() > 20);
        }
        // sign-in coverage, the accounts table's last remaining formatter
        assert!(
            report(&s.case, false).contains("| sign-ins 20"),
            "the accounts table shows sign-in coverage"
        );
    }
    // the CSV closing record carries the header text in ISO too
    let s = scripted(false);
    let rec = csv_records(&csv_bytes(&s.case, &csv_opts(Scope::Verified)).0);
    let closing = rec.last().unwrap();
    assert!(
        closing[8].contains("Generated at: 2026-10-03T00:00:00Z;") && !old.is_match(&closing[8]),
        "{}",
        closing[8]
    );
}
