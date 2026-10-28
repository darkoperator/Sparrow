//! End to end: an AI agent triages a generated Invictus bec-aitm case through the `sparrow` binary only (Addendum
//! D.7), a reviewer's decisions are written by the core review functions on the case file, and the three exports
//! are read back. One test, because ingesting the tree costs several seconds and each stage builds on the last.
//!
//! The generated tree comes from the shared test cache (`sparrow_synth::cache`); the case is ingested, detected and
//! triaged by the binary in a temporary directory that goes away with the test.

use assert_cmd::Command;
use calamine::{Data, Reader, Xlsx, open_workbook};
use serde_json::Value;
use sparrow_core::Case;
use sparrow_core::case::actor::Reviewer;
use sparrow_core::case::review::{review_accept, review_discard};
use sparrow_synth::cache::Cache;
use sparrow_synth::options::{Collector, GenerateOptions};
use std::path::Path;

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().expect("sparrow was killed by a signal"),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Run and require exit `code`; the parsed `--json` output.
fn json(args: &[&str], code: i32) -> Value {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    let r = run(&a);
    assert_eq!(r.code, code, "sparrow {a:?}\nstderr: {}", r.err);
    serde_json::from_str(&r.out)
        .unwrap_or_else(|e| panic!("sparrow {a:?} printed no JSON ({e}): {}", r.out))
}

/// The agent flags every write carries.
const AGENT: [&str; 4] = ["--agent", "claude", "--analyst", "example"];

/// One state-changing agent write: exit 0, JSON out. Counts toward the expected audit length.
struct Agent<'a> {
    case: &'a str,
    writes: i64,
}

impl Agent<'_> {
    fn write(&mut self, args: &[&str]) -> Value {
        let mut a: Vec<&str> = args.to_vec();
        a.extend_from_slice(&["--case", self.case]);
        a.extend_from_slice(&AGENT);
        let v = json(&a, 0);
        self.writes += 1;
        v
    }

    fn entries(&self) -> i64 {
        json(&["audit", "verify", "--case", self.case], 0)["entries"]
            .as_i64()
            .unwrap()
    }
}

/// The finding's current decision fields.
fn finding(case: &str, id: &str) -> Value {
    json(&["finding", "show", id, "--case", case], 0)["finding"].clone()
}

/// The newest audit entry that made a decision (not a review) on the object, as the seq a review must name.
fn decision_seq(case: &str, object: &str) -> i64 {
    let log = json(&["audit", "log", "--object", object, "--case", case], 0);
    log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| !e["action"].as_str().unwrap().starts_with("review_"))
        .map(|e| e["seq"].as_i64().unwrap())
        .max()
        .unwrap_or_else(|| panic!("no decision on {object}"))
}

/// The report lines of one `###` block (a finding), from its heading to the next heading.
fn block(md: &str, needle: &str) -> String {
    let lines: Vec<&str> = md.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("{needle} is not in the report"));
    let start = (0..=at).rev().find(|i| lines[*i].starts_with('#')).unwrap();
    let end = (at + 1..lines.len())
        .find(|i| lines[*i].starts_with('#'))
        .unwrap_or(lines.len());
    lines[start..end].join("\n")
}

/// The Indicators table row of an IP indicator: the line `| ip | <value> | ...` (not the first line that mentions the
/// value, which is a finding's evidence).
fn ioc_row(md: &str, value: &str) -> String {
    let start = format!("| ip | {value} |");
    let rows: Vec<&str> = md.lines().filter(|l| l.starts_with(&start)).collect();
    assert_eq!(rows.len(), 1, "one Indicators row for {value}: {rows:?}");
    rows[0].to_string()
}

const LABEL: &str = "AI decision — not reviewed";

/// The audit head hash of a report or CSV header line.
fn header_head(text: &str) -> String {
    let at = text.find("Audit head hash: ").expect("head hash in header");
    text[at + 17..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect()
}

fn csv_records(path: &Path) -> (Vec<String>, Vec<Vec<String>>) {
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(&bytes[..3], b"\xEF\xBB\xBF", "UTF-8 BOM");
    let mut rd = csv::ReaderBuilder::new().from_reader(&bytes[3..]);
    let head = rd.headers().unwrap().iter().map(String::from).collect();
    let rows = rd
        .records()
        .map(|r| r.unwrap().iter().map(String::from).collect())
        .collect();
    (head, rows)
}

#[test]
fn an_agent_triages_a_bec_aitm_case_and_the_exports_carry_its_decisions() {
    let tmp = tempfile::tempdir().unwrap();
    let case_path = tmp.path().join("case.duckdb");
    let case = case_path.to_str().unwrap();
    let out = tmp.path();
    let p = |name: &str| out.join(name).to_string_lossy().into_owned();

    // ---- 1. ingest (no detection) and detect -------------------------------------------------------------
    let cache: Cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let tree = cache
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    let tree_dir = tree.dir.to_str().unwrap();
    // Exactly 6: the only rejected record is the deliberate AllRoles failure row the collector wrote for the
    // role-assignable group (its loss also leaves the next row without a role name). Nothing else fails.
    let ingest = json(&["ingest", tree_dir, "--case", case, "--no-detect"], 6);
    let files = ingest["collections"][0]["files"].as_array().unwrap();
    let failing: Vec<&Value> = files
        .iter()
        .filter(|f| f["records_error"].as_u64().unwrap() > 0)
        .collect();
    assert_eq!(
        failing.len(),
        1,
        "only one file has error records: {failing:?}"
    );
    let roles = failing[0];
    let path = roles["rel_path"].as_str().unwrap();
    assert!(
        path.contains("/Roles/") && path.ends_with("-AllRoles.csv"),
        "the failing file is the AllRoles export: {path}"
    );
    assert_eq!(roles["records_error"], 1);
    assert!(
        roles["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("Role carry-over")),
        "{roles}"
    );
    let bad_status: Vec<&Value> = files
        .iter()
        .filter(|f| f["status"] == "error" || f["status"] == "unrecognized")
        .collect();
    assert!(
        bad_status.is_empty(),
        "unexpected failed files: {bad_status:?}"
    );
    assert!(
        files.iter().all(|f| f["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|w| !w.as_str().unwrap().starts_with("reconciliation mismatch"))),
        "no file may fail to reconcile"
    );
    assert_eq!(
        json(&["audit", "verify", "--case", case], 0)["entries"],
        0,
        "ingest writes no audit entry"
    );
    let d = run(&["detect", "--case", case]);
    assert_eq!(d.code, 0, "{}", d.err);
    assert_eq!(
        json(&["audit", "verify", "--case", case], 0)["entries"],
        0,
        "detection writes no audit entry"
    );

    // ---- 2. the agent triages ------------------------------------------------------------------------------
    let listed = json(&["finding", "list", "--case", case], 0);
    let findings = listed["findings"].as_array().unwrap();
    assert!(findings.len() > 5, "{} findings", findings.len());
    assert!(findings.iter().all(|f| f["decided_by"].is_null()));
    let by_rule = |rule: &str| -> String {
        findings
            .iter()
            .find(|f| f["rule_id"] == rule)
            .unwrap_or_else(|| panic!("the case has no {rule} finding"))["finding_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (confirmed_a, false_pos_b, confirmed_c) = (
        by_rule("SPW-HAWK-010"),
        by_rule("SPW-MAIL-003"),
        by_rule("SPW-MAIL-004"),
    );
    let mut agent = Agent { case, writes: 0 };

    agent.write(&[
        "finding",
        "set-status",
        &confirmed_a,
        "confirmed",
        "--reason",
        "the inbox rule hides mail from the mailbox owner",
    ]);
    agent.write(&[
        "finding",
        "set-status",
        &false_pos_b,
        "false_positive",
        "--reason",
        "keyword match on a newsletter rule",
    ]);
    agent.write(&[
        "finding",
        "set-status",
        &confirmed_c,
        "confirmed",
        "--reason",
        "forwarding to an outside address",
    ]);

    let ioc_a = agent.write(&[
        "ioc",
        "add",
        "--type",
        "ip",
        "--value",
        "203.0.113.2",
        "--verdict",
        "malicious",
        "--note",
        "AiTM relay",
    ])["indicator_id"]
        .as_str()
        .unwrap()
        .to_string();
    let ioc_b = agent.write(&[
        "ioc",
        "add",
        "--type",
        "ip",
        "--value",
        "203.0.113.9",
        "--verdict",
        "suspicious",
    ])["indicator_id"]
        .as_str()
        .unwrap()
        .to_string();
    let ioc_gone = agent.write(&[
        "ioc",
        "add",
        "--type",
        "domain",
        "--value",
        "evil.example",
        "--verdict",
        "malicious",
    ])["indicator_id"]
        .as_str()
        .unwrap()
        .to_string();
    agent.write(&["ioc", "remove", "--id", &ioc_gone]);
    // Removing an inactive indicator is a no-op: it succeeds and writes no audit entry.
    let before = agent.entries();
    let again = run(&[
        "ioc", "remove", "--id", &ioc_gone, "--case", case, "--agent", "claude",
    ]);
    assert_eq!(again.code, 0, "{}", again.err);
    assert_eq!(agent.entries(), before, "a no-op write adds nothing");

    // Evidence for the entries comes from `finding show --json`.
    let shown = json(&["finding", "show", &confirmed_a, "--case", case], 0);
    let evidence: Vec<String> = shown["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["source_table"] == "ual_events")
        .map(|e| {
            format!(
                "{}:{}",
                e["source_table"].as_str().unwrap(),
                e["record_key"].as_str().unwrap()
            )
        })
        .collect();
    assert!(evidence.len() >= 2, "{evidence:?}");
    let propose = |agent: &mut Agent, time: &str, title: &str, phase: &str, ev: &str| -> String {
        agent.write(&[
            "timeline-entry",
            "propose",
            "--time",
            time,
            "--title",
            title,
            "--narrative",
            "narrative with a \"quote\", a comma, and\na second line",
            "--phase",
            phase,
            "--evidence",
            ev,
        ])["object_id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let entry_1 = propose(
        &mut agent,
        "2026-08-21T09:47:00Z",
        "Inbox rule created",
        "persistence",
        &evidence[0],
    );
    let _entry_2 = propose(
        &mut agent,
        "2026-08-21T12:12:00Z",
        "Inbox rule updated",
        "persistence",
        &evidence[1],
    );
    // Hostile text that a spreadsheet would run as a formula.
    let hostile = "=HYPERLINK(\"http://evil.example\",\"click\")";
    let entry_3 = propose(
        &mut agent,
        "2026-08-22T08:00:00Z",
        hostile,
        "collection",
        &evidence[0],
    );
    agent.write(&["timeline-entry", "verify", &entry_1]);
    agent.write(&["timeline-entry", "verify", &entry_3]);
    // entry_2 stays proposed.
    agent.write(&[
        "note",
        "add",
        &format!("finding:{confirmed_a}"),
        "--text",
        "+SUM(1,1) is not a formula here",
    ]);

    // ---- 3. the chain is intact and has exactly one entry per state-changing write ---------------------------
    let v = json(&["audit", "verify", "--case", case], 0);
    assert_eq!(v["ok"], true);
    assert_eq!(
        v["entries"], agent.writes,
        "entries == state-changing writes"
    );
    assert!(agent.writes >= 12);
    let head_before_review = v["head_hash"].as_str().unwrap().to_string();

    // ---- 4. detection again leaves decisions and review state alone --------------------------------------------
    let snapshot: Vec<Value> = [&confirmed_a, &false_pos_b, &confirmed_c]
        .iter()
        .map(|id| finding(case, id))
        .collect();
    for (f, status) in snapshot
        .iter()
        .zip(["confirmed", "false_positive", "confirmed"])
    {
        assert_eq!(f["status"], status);
        assert_eq!(f["decided_by"], "agent:claude");
        assert_eq!(f["on_behalf_of"], "analyst:example");
        assert_eq!(f["review_state"], "pending_review");
    }
    assert_eq!(run(&["detect", "--case", case]).code, 0);
    for (before, id) in snapshot
        .iter()
        .zip([&confirmed_a, &false_pos_b, &confirmed_c])
    {
        let after = finding(case, id);
        for key in [
            "status",
            "decided_by",
            "decided_at",
            "on_behalf_of",
            "review_state",
            "disposition_reason",
        ] {
            assert_eq!(
                after[key], before[key],
                "{id}: {key} changed by a detection re-run"
            );
        }
    }
    let v = json(&["audit", "verify", "--case", case], 0);
    assert_eq!(v["entries"], agent.writes, "detection added no audit entry");
    assert_eq!(v["head_hash"].as_str().unwrap(), head_before_review);

    // ---- 5. exports before any review: everything is labelled -------------------------------------------------
    let report_1 = p("report-1.md");
    assert_eq!(
        run(&["export", "report", "--case", case, "--out", &report_1]).code,
        0
    );
    let md = std::fs::read_to_string(&report_1).unwrap();
    assert!(md.contains(LABEL));
    assert_eq!(
        header_head(&md),
        head_before_review,
        "the report prints the audit head hash"
    );
    assert!(md.contains(&format!("Audit chain:** ok ({} entries)", agent.writes)));
    assert!(block(&md, &format!("`{confirmed_a}`")).contains(LABEL));
    assert!(block(&md, &format!("`{confirmed_c}`")).contains(LABEL));
    assert!(ioc_row(&md, "203.0.113.2").contains(LABEL));
    assert!(ioc_row(&md, "203.0.113.9").contains(LABEL));
    assert!(md.contains("agent note — not reviewed"));

    // ---- 6. review is core-only: the reviewer accepts and discards on the case file ---------------------------
    let seq_a = decision_seq(case, &format!("finding:{confirmed_a}"));
    let seq_c = decision_seq(case, &format!("finding:{confirmed_c}"));
    let seq_ioc = decision_seq(case, &format!("indicator:{ioc_a}"));
    let seq_e1 = decision_seq(case, &format!("timeline_entry:{entry_1}"));
    {
        let c = Case::create_or_open(&case_path).unwrap();
        let r = Reviewer::analyst("example").unwrap();
        review_accept(c.conn(), &r, "finding", &confirmed_a, seq_a, Some("agreed")).unwrap();
        review_accept(c.conn(), &r, "indicator", &ioc_a, seq_ioc, None).unwrap();
        review_accept(c.conn(), &r, "timeline_entry", &entry_1, seq_e1, None).unwrap();
        review_discard(
            c.conn(),
            &r,
            "finding",
            &confirmed_c,
            seq_c,
            Some("not the same sender"),
        )
        .unwrap();
    }
    let reviewed_writes = agent.writes + 4;
    let v = json(&["audit", "verify", "--case", case], 0);
    assert_eq!(v["ok"], true);
    assert_eq!(v["entries"], reviewed_writes, "each review adds one entry");
    let head = v["head_hash"].as_str().unwrap().to_string();
    assert_ne!(head, head_before_review);
    let a = finding(case, &confirmed_a);
    assert_eq!(
        (a["status"].as_str(), a["review_state"].as_str()),
        (Some("confirmed"), Some("accepted"))
    );
    let c = finding(case, &confirmed_c);
    assert_eq!(c["review_state"], "discarded");
    assert_eq!(
        c["status"], "new",
        "a discarded decision reverts to the state before it"
    );
    let b = finding(case, &false_pos_b);
    assert_eq!(b["review_state"], "pending_review");

    // ---- 7. the three exports after review --------------------------------------------------------------------
    let report_2 = p("report-2.md");
    assert_eq!(
        run(&["export", "report", "--case", case, "--out", &report_2]).code,
        0
    );
    let md = std::fs::read_to_string(&report_2).unwrap();
    assert_eq!(
        header_head(&md),
        head,
        "the report prints the head hash `audit verify` printed"
    );
    let fa = block(&md, &format!("`{confirmed_a}`"));
    assert!(
        fa.contains("accepted") && !fa.contains(LABEL),
        "accepted item without the label:\n{fa}"
    );
    assert!(
        !md.contains(&format!("`{confirmed_c}`")),
        "the discarded decision (back to new) is not a confirmed finding"
    );
    assert!(ioc_row(&md, "203.0.113.2").contains("accepted"));
    assert!(!ioc_row(&md, "203.0.113.2").contains(LABEL));
    assert!(
        ioc_row(&md, "203.0.113.9").contains(LABEL),
        "the pending indicator is still labelled"
    );
    assert!(
        md.contains("Inbox rule created"),
        "the verified, accepted entry is in the timeline"
    );
    assert!(
        !md.contains("Inbox rule updated"),
        "an entry nobody verified is not in the report"
    );
    let listed = json(&["ioc", "list", "--include-removed", "--case", case], 0);
    let ioc = |id: &str| {
        listed["indicators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["indicator_id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(ioc(&ioc_b)["review_state"], "pending_review");
    assert!(!ioc(&ioc_gone)["removed_at"].is_null());
    assert!(ioc(&ioc_a)["removed_at"].is_null());
    assert!(
        !md.contains("| domain |"),
        "a removed indicator is not reported"
    );
    assert!(
        md.contains("accepted 3") && md.contains("discarded 1"),
        "review counts in the header"
    );

    // --reviewed-only keeps accepted decisions and drops pending items and agent notes.
    let report_3 = p("report-3.md");
    assert_eq!(
        run(&[
            "export",
            "report",
            "--case",
            case,
            "--reviewed-only",
            "--out",
            &report_3
        ])
        .code,
        0
    );
    let ro = std::fs::read_to_string(&report_3).unwrap();
    assert!(ro.contains(&format!("`{confirmed_a}`")));
    let kept = ioc_row(&ro, "203.0.113.2");
    assert!(kept.contains("accepted") && !kept.contains(LABEL), "{kept}");
    assert!(
        ro.contains("Inbox rule created"),
        "the accepted entry stays"
    );
    assert!(
        !ro.contains("| ip | 203.0.113.9 |"),
        "pending indicator dropped"
    );
    assert!(!ro.contains("HYPERLINK"), "pending entry dropped");
    assert!(!ro.contains("is not a formula here"), "agent notes dropped");
    assert!(!ro.contains(LABEL), "nothing pending is left to label");
    assert_eq!(header_head(&ro), head);

    // CSV: parses, UTC timestamps first, no cell can start a formula.
    for scope in ["verified", "all"] {
        let csv_path = p(&format!("timeline-{scope}.csv"));
        let r = run(&[
            "export", "timeline", "--case", case, "--scope", scope, "--out", &csv_path,
        ]);
        assert_eq!(r.code, 0, "{}", r.err);
        let (head_row, rows) = csv_records(Path::new(&csv_path));
        assert_eq!(head_row[0], "Timestamp");
        assert_eq!(
            head_row.join(","),
            "Timestamp,EndTime,EventCount,Source,Category,User,IP,Operation,Summary,Phase,Status,DecidedBy,ReviewState,FindingIds,EvidenceRef"
        );
        assert!(
            rows.len() >= if scope == "all" { 1000 } else { 3 },
            "{scope}: {} rows",
            rows.len()
        );
        for row in &rows {
            assert_eq!(row.len(), head_row.len());
            assert!(
                chrono::NaiveDateTime::parse_from_str(&row[0], "%Y-%m-%dT%H:%M:%SZ").is_ok(),
                "Timestamp is UTC YYYY-MM-DDTHH:MM:SSZ: {:?}",
                row[0]
            );
            for cell in row {
                assert!(
                    !cell.starts_with(['=', '+', '-', '@', '\t', '\r']),
                    "an unneutralised cell in {scope}: {cell:?}"
                );
            }
        }
        let summaries: Vec<&str> = rows.iter().map(|r| r[8].as_str()).collect();
        if scope == "verified" {
            assert!(
                summaries.iter().any(|s| s.starts_with("'=HYPERLINK(")),
                "the hostile title is neutralised, not dropped: {summaries:?}"
            );
            assert!(
                rows.iter()
                    .any(|r| r[11] == "agent:claude" && r[12] == "accepted")
            );
            assert!(rows.iter().any(|r| r[12] == "pending_review"));
            assert!(
                !summaries.iter().any(|s| s.contains("Inbox rule updated")),
                "the proposed entry is not in the verified export"
            );
            assert!(
                rows.iter().all(|r| r[10] != "proposed"),
                "verified scope has no proposed entry"
            );
        } else {
            // Every event row; the ones a verified entry cites carry its phase, status and decision.
            assert!(
                rows.iter()
                    .any(|r| r[9] == "persistence" && r[10] == "verified" && r[12] == "accepted")
            );
            assert!(
                rows.iter().all(|r| r[10] != "proposed"),
                "a proposed entry is never exported"
            );
        }
    }

    // XLSX opens with calamine and holds the decisions.
    let xlsx = p("case.xlsx");
    let r = run(&["export", "workbook", "--case", case, "--out", &xlsx]);
    assert_eq!(r.code, 0, "{}", r.err);
    let mut wb: Xlsx<_> = open_workbook(&xlsx).unwrap();
    assert_eq!(
        wb.sheet_names(),
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
    let audit_rows = wb.worksheet_range("Audit").unwrap().rows().count() as i64;
    assert_eq!(
        audit_rows,
        reviewed_writes + 1,
        "one row per audit entry and a header"
    );
    let findings_sheet = wb.worksheet_range("Findings").unwrap();
    let text_cells: Vec<String> = findings_sheet
        .rows()
        .flatten()
        .filter_map(|c| {
            if let Data::String(s) = c {
                Some(s.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(
        text_cells.iter().any(|s| s == &confirmed_a),
        "the confirmed finding is in the workbook"
    );
    assert!(text_cells.iter().any(|s| s == "accepted"));

    // ---- 8. exit codes ------------------------------------------------------------------------------------------
    // 1: a refused query; the findings are untouched.
    let count = |case: &str| {
        json(
            &["query", "SELECT count(*) FROM findings", "--case", case],
            0,
        )["rows"][0][0]
            .clone()
    };
    let n = count(case);
    let q = run(&["query", "DELETE FROM findings", "--case", case]);
    assert_eq!(q.code, 1, "{}", q.err);
    assert_eq!(count(case), n);
    // 5: an invalid decision (a reason is required), and the case did not change.
    let bad = run(&[
        "finding",
        "set-status",
        &false_pos_b,
        "benign",
        "--case",
        case,
        "--agent",
        "claude",
    ]);
    assert_eq!(bad.code, 5, "{}", bad.err);
    assert_eq!(
        json(&["audit", "verify", "--case", case], 0)["entries"],
        reviewed_writes
    );
    // 4: another writer holds the case, for a write and for a read.
    {
        let _writer = Case::create_or_open(&case_path).unwrap();
        let w = run(&[
            "finding",
            "set-status",
            &false_pos_b,
            "in_review",
            "--case",
            case,
            "--agent",
            "claude",
        ]);
        assert_eq!(w.code, 4, "{}", w.err);
        assert!(w.err.contains("another writer"), "{}", w.err);
        assert_eq!(run(&["finding", "list", "--case", case]).code, 4);
        assert_eq!(run(&["audit", "verify", "--case", case]).code, 4);
    }
    // 3: a tampered row breaks the chain; verify and writes both report it. Done on a copy.
    let copy = p("tampered.duckdb");
    std::fs::copy(&case_path, &copy).unwrap();
    {
        let c = duckdb::Connection::open(&copy).unwrap();
        c.execute(
            "UPDATE audit_trail SET reason = 'edited later' WHERE seq = 2",
            [],
        )
        .unwrap();
    }
    let v = json(&["audit", "verify", "--case", &copy], 3);
    assert_eq!(v["ok"], false);
    assert_eq!(v["first_bad_seq"], 2);
    let w = run(&[
        "finding",
        "set-status",
        &false_pos_b,
        "in_review",
        "--case",
        &copy,
        "--agent",
        "claude",
    ]);
    assert_eq!(w.code, 3, "{}", w.err);
    // The real case is still intact.
    assert_eq!(json(&["audit", "verify", "--case", case], 0)["ok"], true);
}

/// Every option and argument of the Phase 7 subcommands has help text, and `--help` of the program lists the exit
/// codes an agent has to handle.
#[test]
fn every_agent_workflow_option_is_documented_in_help() {
    let commands: &[&[&str]] = &[
        &["finding", "list"],
        &["finding", "show"],
        &["finding", "set-status"],
        &["finding", "assign"],
        &["finding", "ack-rule-update"],
        &["timeline-entry", "list"],
        &["timeline-entry", "propose"],
        &["timeline-entry", "verify"],
        &["timeline-entry", "reject"],
        &["timeline-entry", "edit"],
        &["note", "add"],
        &["timeline"],
        &["pivot", "ip"],
        &["pivot", "user"],
        &["query"],
        &["export", "report"],
        &["export", "timeline"],
        &["export", "workbook"],
        &["audit", "verify"],
        &["audit", "log"],
        &["ioc", "add"],
        &["ioc", "list"],
        &["ioc", "set-verdict"],
        &["ioc", "remove"],
    ];
    let mut checked = 0;
    for cmd in commands {
        let mut args = cmd.to_vec();
        args.push("--help");
        let r = run(&args);
        assert_eq!(r.code, 0, "{cmd:?}: {}", r.err);
        for line in r.out.lines() {
            let t = line.trim_start();
            if !(t.starts_with("--") || t.starts_with("-h") || t.starts_with('<'))
                || line.starts_with("Usage")
            {
                continue;
            }
            // "<flag or arg>  description": two spaces separate them.
            let described = t
                .split_once("  ")
                .map(|(_, d)| !d.trim().is_empty())
                .unwrap_or(false);
            assert!(described, "{cmd:?}: no help text for `{t}`");
            checked += 1;
        }
    }
    assert!(checked > 100, "only {checked} options checked");

    let top = run(&["--help"]).out;
    for needle in [
        "Exit codes:",
        "3 audit chain broken",
        "4 case open by another writer",
        "5 invalid agent decision",
        "6 ingest completed and the only records not loaded are ones the collector lost",
        "Agent workflow",
    ] {
        assert!(
            top.contains(needle),
            "`sparrow --help` lacks {needle:?}:\n{top}"
        );
    }
    for sub in [
        "finding",
        "timeline-entry",
        "note",
        "pivot",
        "query",
        "export",
        "audit",
        "ioc",
    ] {
        let line = top
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{sub} ")))
            .expect(sub);
        assert!(
            line.trim().len() > sub.len() + 20,
            "a one-liner for {sub}: {line}"
        );
    }
}
