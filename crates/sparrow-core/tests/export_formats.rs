//! The three exports (Addendum D.6) on synthetic bec-aitm after a scripted agent session: the Markdown report, the
//! Timeline Explorer CSV and the XLSX workbook. The goldens are recorded once with `SPARROW_RECORD_GOLDEN=1` after
//! review by eye (the fixed test clock and case id make every hash, id and timestamp reproducible).

#[path = "common/synth.rs"]
mod synth;

use calamine::{Data, Reader, Xlsx, open_workbook};
use chrono::{DateTime, Duration, TimeZone, Utc};
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
use sparrow_core::detect::run::{DetectOptions, run};
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
    Actor::agent("claude", Some("carlos")).unwrap()
}

fn reviewer() -> Reviewer {
    Reviewer::analyst("dana").unwrap()
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
    let mut g = synth::builtin("bec-aitm", PsEdition::Ps7);
    let set = load_rules(&DataDirs::default()).unwrap();
    let o = DetectOptions {
        now: Some(g.manifest.collected_at + Duration::days(1)),
        ..DetectOptions::default()
    };
    run(&mut g.case, &set, &o).unwrap();
    g.case
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

    // Three verified entries and one proposed, citing evidence rows of the findings (the confirmed one first).
    let rules = load_rules(&DataDirs::default()).unwrap();
    let mut refs: Vec<(EvidenceRef, DateTime<Utc>)> = Vec::new();
    for f in &findings {
        for e in read::finding_show(c, &f.finding_id, &rules)
            .unwrap()
            .evidence
        {
            if let Some(t) = &e.timeline {
                let r = EvidenceRef {
                    source_table: e.source_table.clone(),
                    record_key: e.record_key.clone(),
                };
                if !refs.iter().any(|(x, _)| *x == r) && refs.len() < 4 {
                    refs.push((r, t.event_time));
                }
            }
        }
    }
    assert_eq!(
        refs.len(),
        4,
        "the findings cite at least four timeline rows"
    );
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

fn golden(name: &str, actual: &str) {
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    // SPARROW_RECORD_GOLDEN=1 re-records the goldens: a deliberate step whose diff is reviewed and whose reason goes
    // in the commit message.
    if std::env::var_os("SPARROW_RECORD_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
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
    golden("export_report.md", &report(&s.case, false));
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
    assert!(md.contains("decided by agent:claude on behalf of analyst:carlos at 2026-10-02"));
    // The reviewed finding shows who accepted it and when, and the reviewer's comment.
    assert!(
        md.contains("accepted by analyst:dana at 2026-10-02"),
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
    let shape = regex::Regex::new(r"^\[\^\d+\]: [a-z_]+:\S+ — .+:\d+(-\d+)?").unwrap();
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
    golden("export_timeline.csv", std::str::from_utf8(&bytes).unwrap());
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
    // Streaming: the sink sees many small writes, never one buffer of the whole file.
    struct Chunks {
        max: usize,
        total: usize,
    }
    impl Write for Chunks {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.max = self.max.max(b.len());
            self.total += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Chunks { max: 0, total: 0 };
    timeline_csv::write(s.case.conn(), &mut sink, &csv_opts(Scope::All)).unwrap();
    assert!(
        sink.total > 8 * sink.max,
        "{} bytes in chunks of up to {}",
        sink.total,
        sink.max
    );
    assert!(sink.max <= 64 * 1024);
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
    assert_eq!(row[col(&findings, "OnBehalfOf")], "analyst:carlos");
    assert_eq!(row[col(&findings, "ReviewState")], "accepted");
    assert_eq!(row[col(&findings, "ReviewedBy")], "analyst:dana");
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
    assert!(row[col(&findings, "DecisionLabel")].starts_with("discarded by analyst:dana at "));
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
    assert!(md.contains("a,b\"c\n    d|e 🔥 \\u{202E}x"), "{md}");
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
    assert!(md.contains("t\\u{001B}[31mred\\u{0000}"));
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
