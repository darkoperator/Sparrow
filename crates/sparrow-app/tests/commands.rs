//! Command functions on a synthetic case, without a window.

use sparrow_app::cmd::review::{
    QueueItem, finding_detail, proposal_accept, proposal_discard, review_accept, review_discard,
    review_queue,
};
use sparrow_app::settings::{self, Settings, record_recent, settings_get, settings_set_analyst};
use sparrow_app::state::{AppState, analyst, case_close, case_open, with_case, with_writable};
use sparrow_core::Case;
use sparrow_core::case::actor::{Actor, Reviewer};
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator};
use sparrow_core::case::timeline_entries::{self as te, EvidenceRef, NewEntry, Phase};
use sparrow_core::case::{query, share, write};
use sparrow_core::data::DataDirs;
use sparrow_synth::cache::{Cache, Stage};
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::testing::{detect_into, ingest_into};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static CACHE: LazyLock<Cache> = LazyLock::new(|| sparrow_synth::test_cache!());

/// A private copy of the detected `bec-aitm` case as a file in `dir`.
fn case_file(dir: &Path) -> PathBuf {
    let dest = dir.join("case.duckdb");
    let got = CACHE.builtin_case(
        "bec-aitm",
        &GenerateOptions::new(Collector::Invictus, 17),
        Stage::Detected,
    );
    match got.case.path() {
        Some(src) => {
            got.case.conn().execute_batch("CHECKPOINT").unwrap();
            std::fs::copy(src, &dest).unwrap();
        }
        // SPARROW_NO_CACHE: the cache hands out an in-memory case; build the file the way the cache does.
        None => {
            let mut case = Case::create_or_open(&dest).unwrap();
            ingest_into(&mut case, &got.tree.dir, &got.tree.manifest);
            let rules = sparrow_core::detect::load::load_rules(&DataDirs::default()).unwrap();
            detect_into(&mut case, &got.tree.manifest, &rules);
            case.conn().execute_batch("CHECKPOINT").unwrap();
        }
    }
    dest
}

fn state_with_settings(dir: &Path) -> AppState {
    let state = AppState::default();
    *state.settings_dir.lock().unwrap() = Some(dir.to_path_buf());
    state
}

fn first_finding(case: &Case) -> String {
    case.conn()
        .query_row(
            "SELECT finding_id FROM findings ORDER BY finding_id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn open_reports_case_info_and_locks_down() {
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    let state = state_with_settings(&tmp.path().join("settings"));
    let info = case_open(&state, &path, false).unwrap();
    assert_eq!(info.path, path.display().to_string());
    assert!(info.audit_ok);
    assert!(info.read_only_reason.is_none());
    assert!(!info.tenants.is_empty(), "{:?}", info.tenants);
    assert!(!info.case_id.is_empty());
    assert_eq!(
        info.schema_version,
        sparrow_core::db::migrations::latest_version()
    );
    // Locked down, so the in-process read-only SQL works on the app's own connection.
    let n = with_case(&state, |open| {
        assert!(open.case.is_locked_down().unwrap());
        assert!(!open.rules.rules.is_empty());
        Ok(query::run_on(
            &open.case,
            "SELECT count(*) AS n FROM findings",
            10,
        )?)
    })
    .unwrap();
    assert_eq!(n.rows.len(), 1);
    // The open is remembered in the recent list.
    assert_eq!(
        settings_get(&state).unwrap().recent,
        vec![path.display().to_string()]
    );
}

#[test]
fn open_missing_file_is_not_found_and_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nope.duckdb");
    let state = AppState::default();
    let e = case_open(&state, &path, false).unwrap_err();
    assert_eq!(e.kind, "not_found", "{e:?}");
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
    assert_eq!(with_case(&state, |_| Ok(())).unwrap_err().kind, "no_case");
}

#[test]
fn open_busy_case_reports_writer_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    let other = tmp.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let other = case_file(&other);
    let state = AppState::default();
    let held = Case::create_or_open(&path).unwrap();
    let e = case_open(&state, &path, false).unwrap_err();
    assert_eq!(e.kind, "writer_busy", "{e:?}");
    assert!(
        e.message.contains("open in another process"),
        "{}",
        e.message
    );
    // The app stays usable: nothing is open, and another case opens.
    assert_eq!(with_case(&state, |_| Ok(())).unwrap_err().kind, "no_case");
    assert!(case_open(&state, &other, false).unwrap().audit_ok);
    drop(held);
}

#[test]
fn broken_chain_opens_read_only_and_refuses_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    let seq = {
        let case = Case::create_or_open(&path).unwrap();
        let id = first_finding(&case);
        let agent = Actor::agent("triage", None).unwrap();
        let e = write::set_finding_status(
            case.conn(),
            &agent,
            &id,
            write::FindingStatus::InReview,
            None,
        )
        .unwrap();
        case.conn()
            .execute("UPDATE audit_trail SET reason = 'x' WHERE seq = ?", [e.seq])
            .unwrap();
        e.seq
    };
    let before = std::fs::read(&path).unwrap();
    let state = state_with_settings(&tmp.path().join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    let info = case_open(&state, &path, false).unwrap();
    assert!(!info.audit_ok);
    let reason = info.read_only_reason.expect("read-only reason");
    assert!(reason.contains(&format!("seq {seq}")), "{reason}");
    assert!(
        reason.contains("sparrow audit verify --acknowledge"),
        "{reason}"
    );
    // Reads work; every write is refused before it reaches core, and the connection itself is read-only.
    with_case(&state, |open| {
        assert!(open.case.is_read_only());
        Ok(())
    })
    .unwrap();
    let mut ran = false;
    let e = with_writable(&state, |_| {
        ran = true;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(e.kind, "read_only", "{e:?}");
    assert!(!ran);
    // Never opened for writing: the file is as it was.
    case_close(&state).unwrap();
    assert!(std::fs::read(&path).unwrap() == before, "the file changed");
}

#[test]
fn analyst_setting_round_trips_and_is_validated() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("settings");
    let state = state_with_settings(&dir);
    assert_eq!(analyst(&state).unwrap_err().kind, "invalid");
    for bad in ["a:b", "", "  ", "x\u{1b}y"] {
        assert_eq!(
            settings_set_analyst(&state, bad).unwrap_err().kind,
            "invalid",
            "{bad:?}"
        );
    }
    assert_eq!(settings_get(&state).unwrap().analyst, None);
    let s = settings_set_analyst(&state, " carlos ").unwrap();
    assert_eq!(s.analyst.as_deref(), Some("carlos"));
    assert_eq!(settings::load(&dir), s);
    // A fresh app over the same directory reads it back.
    let again = state_with_settings(&dir);
    assert_eq!(settings_get(&again).unwrap(), s);
    assert_eq!(analyst(&again).unwrap().as_str(), "analyst:carlos");
}

#[test]
fn reopening_another_case_closes_the_first() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let (a, b) = (case_file(&a), case_file(&b));
    let state = state_with_settings(&tmp.path().join("settings"));
    case_open(&state, &a, false).unwrap();
    let info = case_open(&state, &b, false).unwrap();
    assert_eq!(info.path, b.display().to_string());
    // The first case's writer is released.
    drop(Case::create_or_open(&a).unwrap());
    assert_eq!(
        settings_get(&state).unwrap().recent,
        vec![b.display().to_string(), a.display().to_string()]
    );
    case_close(&state).unwrap();
    drop(Case::create_or_open(&b).unwrap());
    assert_eq!(with_case(&state, |_| Ok(())).unwrap_err().kind, "no_case");
}

#[test]
fn settings_survive_a_missing_or_corrupt_file() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        settings::load(&tmp.path().join("absent")),
        Settings::default()
    );
    std::fs::write(tmp.path().join("settings.json"), "{not json").unwrap();
    assert_eq!(settings::load(tmp.path()), Settings::default());
}

/// A case file at schema v20 (before migration 21) with `n` audited agent decisions; `tamper` breaks the chain at
/// seq 1. Built migration by migration, as core's upgrade test does.
fn v20_case(dir: &Path, n: usize, tamper: bool) -> PathBuf {
    use sparrow_core::db::migrations::MIGRATIONS;
    let path = dir.join("v20.duckdb");
    let conn = duckdb::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name VARCHAR NOT NULL,
         applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp);",
    )
    .unwrap();
    for m in MIGRATIONS.iter().filter(|m| m.version <= 20) {
        conn.execute_batch(m.sql).unwrap();
        conn.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
            duckdb::params![m.version as i64, m.name],
        )
        .unwrap();
    }
    for i in 0..n {
        conn.execute_batch("BEGIN TRANSACTION").unwrap();
        sparrow_core::case::audit::append(
            &conn,
            "agent:t",
            None,
            "test",
            "finding",
            &format!("f{i}"),
            None,
            Some(&serde_json::json!({ "i": i })),
            None,
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();
    }
    if tamper {
        conn.execute("UPDATE audit_trail SET actor = 'x' WHERE seq = 1", [])
            .unwrap();
    }
    conn.execute_batch("CHECKPOINT").unwrap();
    path
}

#[test]
fn an_older_intact_case_opens_only_when_the_upgrade_is_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let path = v20_case(tmp.path(), 2, false);
    let before = std::fs::read(&path).unwrap();
    let state = AppState::default();
    let latest = sparrow_core::db::migrations::latest_version();
    let e = case_open(&state, &path, false).unwrap_err();
    assert_eq!(e.kind, "needs_upgrade", "{e:?}");
    assert!(
        e.message.contains("v20") && e.message.contains(&format!("v{latest}")),
        "{}",
        e.message
    );
    assert!(std::fs::read(&path).unwrap() == before, "nothing written");
    assert_eq!(with_case(&state, |_| Ok(())).unwrap_err().kind, "no_case");

    let info = case_open(&state, &path, true).unwrap();
    assert_eq!(info.schema_version, latest);
    assert!(info.audit_ok);
    assert!(info.read_only_reason.is_none());
    with_case(&state, |open| {
        assert!(open.case.is_locked_down().unwrap());
        Ok(())
    })
    .unwrap();
}

#[test]
fn an_older_case_with_a_broken_chain_is_refused_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let path = v20_case(tmp.path(), 2, true);
    let before = std::fs::read(&path).unwrap();
    let state = AppState::default();
    for allow_upgrade in [false, true] {
        let e = case_open(&state, &path, allow_upgrade).unwrap_err();
        assert_eq!(e.kind, "needs_acknowledge", "{e:?}");
        assert!(e.message.contains("seq 1"), "{}", e.message);
        assert!(
            e.message.contains("sparrow audit verify --acknowledge")
                && e.message.contains("sparrow upgrade"),
            "{}",
            e.message
        );
        assert!(std::fs::read(&path).unwrap() == before, "nothing written");
        assert_eq!(with_case(&state, |_| Ok(())).unwrap_err().kind, "no_case");
    }
}

#[test]
fn a_failed_recent_path_write_is_a_warning_not_a_failed_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    // The settings "directory" is a file, so the settings cannot be saved.
    let not_a_dir = tmp.path().join("settings-file");
    std::fs::write(&not_a_dir, "x").unwrap();
    let state = state_with_settings(&not_a_dir);
    let info = case_open(&state, &path, false).unwrap();
    assert!(info.audit_ok);
    assert_eq!(info.warnings.len(), 1, "{:?}", info.warnings);
    assert!(info.warnings[0].contains("recent"), "{:?}", info.warnings);
    with_case(&state, |_| Ok(())).unwrap();
}

#[test]
fn concurrent_settings_updates_keep_every_field() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("settings");
    let state = state_with_settings(&dir);
    let paths: Vec<String> = (0..8).map(|i| format!("/cases/c{i}.duckdb")).collect();
    std::thread::scope(|s| {
        for p in &paths {
            let state = &state;
            s.spawn(move || settings_set_analyst(state, "carlos").unwrap());
            s.spawn(move || record_recent(state, p).unwrap());
        }
    });
    let got = settings::load(&dir);
    assert_eq!(got.analyst.as_deref(), Some("carlos"));
    let mut recent = got.recent.clone();
    recent.sort();
    assert_eq!(recent, paths, "every recent path kept");
    // No temporary file is left behind.
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["settings.json".to_string()]);
}

#[test]
fn overlapping_opens_end_with_the_last_one_and_release_the_other() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let (a, b) = (case_file(&a), case_file(&b));
    let state = state_with_settings(&tmp.path().join("settings"));
    std::thread::scope(|s| {
        let st = &state;
        let ta = s.spawn(|| case_open(st, &a, false).unwrap());
        let tb = s.spawn(|| case_open(st, &b, false).unwrap());
        ta.join().unwrap();
        tb.join().unwrap();
    });
    // The recent list is written inside the transition, so its head is the open that finished last.
    let last = settings_get(&state).unwrap().recent[0].clone();
    let open_path = with_case(&state, |o| Ok(o.path.display().to_string())).unwrap();
    assert_eq!(open_path, last);
    let other = if last == a.display().to_string() {
        &b
    } else {
        &a
    };
    drop(Case::create_or_open(other).unwrap());

    // Open against close: either the case is open or nothing is, and a closed case's writer is released.
    std::thread::scope(|s| {
        let st = &state;
        let to = s.spawn(|| case_open(st, &a, false).unwrap());
        let tc = s.spawn(|| case_close(st).unwrap());
        to.join().unwrap();
        tc.join().unwrap();
    });
    match with_case(&state, |o| Ok(o.path.clone())) {
        Ok(p) => assert_eq!(p, a),
        Err(e) => {
            assert_eq!(e.kind, "no_case");
            drop(Case::create_or_open(&a).unwrap());
        }
    }
}

// ------------------------------------------------------------------ review queue

/// What [`seeded_case`] put in the case.
struct Seeded {
    path: PathBuf,
    /// A finding with a pending agent status decision.
    finding: String,
    /// A pending agent upn indicator.
    indicator: String,
    /// A pending agent-proposed timeline entry citing the finding's first evidence row.
    entry: String,
    /// The bundle imported from a second copy: analyst ann confirmed these two other findings.
    bundle_sha256: String,
    proposed: Vec<String>,
}

fn findings_by_id(case: &Case) -> Vec<String> {
    let mut stmt = case
        .conn()
        .prepare("SELECT finding_id FROM findings ORDER BY finding_id")
        .unwrap();
    stmt.query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A copy of the synthetic case with a pending finding decision, a pending indicator, a pending timeline entry and
/// two open proposals (a bundle from a second copy of the same case).
fn seeded_case(dir: &Path) -> Seeded {
    let a = dir.join("a");
    let b = dir.join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let path = case_file(&a);
    let other = case_file(&b);
    let (bytes, proposed) = {
        let case = Case::create_or_open(&other).unwrap();
        let ids = findings_by_id(&case);
        assert!(ids.len() >= 3, "{ids:?}");
        let ann = Reviewer::analyst("ann").unwrap();
        for id in &ids[1..3] {
            write::set_finding_status(
                case.conn(),
                &ann.as_actor(),
                id,
                write::FindingStatus::Confirmed,
                Some("AiTM relay"),
            )
            .unwrap();
        }
        let bundle = share::export(case.conn(), &ann).unwrap();
        (share::to_bytes(&bundle).unwrap().0, ids[1..3].to_vec())
    };
    let case = Case::create_or_open(&path).unwrap();
    let finding = findings_by_id(&case)[0].clone();
    let agent = Actor::agent("triage", Some("carlos")).unwrap();
    write::set_finding_status(
        case.conn(),
        &agent,
        &finding,
        write::FindingStatus::InReview,
        Some("token replay from a hosting ASN"),
    )
    .unwrap();
    let upn: String = case
        .conn()
        .query_row(
            "SELECT actor_upn FROM findings WHERE finding_id = ?",
            [&finding],
            |r| r.get(0),
        )
        .unwrap();
    let indicator = add_indicator(
        case.conn(),
        &agent,
        None,
        IndicatorType::parse("upn").unwrap(),
        &upn,
        Verdict::parse("suspicious").unwrap(),
        Some("account used from the relay"),
    )
    .unwrap();
    // The entry describes the finding's first evidence row, at that row's time.
    let (evidence, event_us): (String, i64) = case
        .conn()
        .query_row(
            "SELECT source_table || ':' || record_key, epoch_us(event_time) FROM finding_evidence \
             WHERE finding_id = ? AND event_time IS NOT NULL ORDER BY event_time, source_table, record_key LIMIT 1",
            [&finding],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let (entry, _) = te::propose(
        case.conn(),
        &agent,
        NewEntry {
            tenant_key: None,
            event_time: chrono::DateTime::from_timestamp_micros(event_us).unwrap(),
            title: "Sign-in through the AiTM relay".into(),
            narrative: Some("session token replayed".into()),
            phase: Phase::InitialAccess,
            evidence: vec![EvidenceRef::parse(&evidence).unwrap()],
        },
    )
    .unwrap();
    let summary =
        share::import(case.conn(), &Reviewer::analyst("carlos").unwrap(), &bytes).unwrap();
    assert_eq!(summary.new, 2, "{summary:?}");
    drop(case);
    Seeded {
        path,
        finding,
        indicator,
        entry,
        bundle_sha256: summary.bundle_sha256,
        proposed,
    }
}

/// The seeded case open in an app whose analyst is carlos.
fn open_seeded(tmp: &Path) -> (AppState, Seeded) {
    let seeded = seeded_case(tmp);
    let state = state_with_settings(&tmp.join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    case_open(&state, &seeded.path, false).unwrap();
    (state, seeded)
}

fn decision<'a>(
    queue: &'a [QueueItem],
    ty: &str,
    id: &str,
) -> &'a sparrow_core::case::review::PendingDecision {
    queue
        .iter()
        .find_map(|q| match q {
            QueueItem::Decision(d) if d.object_type == ty && d.object_id == id => Some(d),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no pending {ty} {id}"))
}

fn review_state(state: &AppState, table: &str, key: &str, id: &str) -> (String, Option<String>) {
    with_case(state, |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                &format!(
                    "SELECT CAST(review_state AS VARCHAR), reviewed_by FROM {table} WHERE {key} = ?"
                ),
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap())
    })
    .unwrap()
}

#[test]
fn queue_lists_pending_and_open_proposals() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let queue = review_queue(&state).unwrap();
    assert_eq!(queue.len(), 5, "{}", queue.len());
    // Decisions first (oldest first), then proposals.
    let kinds: Vec<&str> = queue
        .iter()
        .map(|q| match q {
            QueueItem::Decision(_) => "decision",
            QueueItem::Proposal(_) => "proposal",
        })
        .collect();
    assert_eq!(
        kinds,
        ["decision", "decision", "decision", "proposal", "proposal"]
    );
    let f = decision(&queue, "finding", &s.finding);
    assert_eq!(f.action, "set_status");
    assert!(f.account.is_some());
    assert_eq!(
        decision(&queue, "indicator", &s.indicator).account,
        f.account
    );
    assert_eq!(
        decision(&queue, "timeline_entry", &s.entry).action,
        "propose_entry"
    );
    // The entry cites the finding's first evidence row, a row of the finding's user.
    assert_eq!(
        decision(&queue, "timeline_entry", &s.entry).account,
        f.account
    );
    let keys: Vec<String> = queue
        .iter()
        .filter_map(|q| match q {
            QueueItem::Proposal(p) => {
                assert_eq!(p.bundle_sha256, s.bundle_sha256);
                assert_eq!(p.source_analyst, "analyst:ann");
                assert_eq!(p.state, "open");
                Some(p.item_key.clone())
            }
            _ => None,
        })
        .collect();
    let expected: Vec<String> = s
        .proposed
        .iter()
        .map(|id| format!("finding:{id}"))
        .collect();
    assert_eq!(keys, expected);
    // The JSON the frontend reads: a `source` tag over the core shapes.
    let v = serde_json::to_value(&queue).unwrap();
    assert_eq!(v[0]["source"], "decision");
    assert!(v[0]["decision_seq"].is_i64());
    assert_eq!(v[3]["source"], "proposal");
    assert_eq!(v[3]["item"]["kind"], "finding");
    // Reading needs an open case.
    case_close(&state).unwrap();
    assert_eq!(review_queue(&state).unwrap_err().kind, "no_case");
}

#[test]
fn accept_and_discard_go_through_core_as_the_analyst() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let queue = review_queue(&state).unwrap();
    let f = decision(&queue, "finding", &s.finding).decision_seq;
    let i = decision(&queue, "indicator", &s.indicator).decision_seq;
    let a = review_accept(
        &state,
        "finding",
        &s.finding,
        f,
        Some("checked the sign-ins"),
    )
    .unwrap();
    assert_eq!(
        (a.actor.as_str(), a.action.as_str()),
        ("analyst:carlos", "review_accept")
    );
    assert_eq!(a.reason.as_deref(), Some("checked the sign-ins"));
    assert_eq!(
        review_state(&state, "findings", "finding_id", &s.finding),
        ("accepted".into(), Some("analyst:carlos".into()))
    );
    let d = review_discard(&state, "indicator", &s.indicator, i, None).unwrap();
    assert_eq!(
        (d.actor.as_str(), d.action.as_str()),
        ("analyst:carlos", "review_discard")
    );
    assert_eq!(
        review_state(&state, "case_indicators", "indicator_id", &s.indicator),
        ("discarded".into(), Some("analyst:carlos".into()))
    );
    // Both left the queue; the entry and the proposals remain.
    assert_eq!(review_queue(&state).unwrap().len(), 3);
}

#[test]
fn proposals_accept_and_discard_as_the_analyst() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let key0 = format!("finding:{}", s.proposed[0]);
    let key1 = format!("finding:{}", s.proposed[1]);
    let applied = proposal_accept(&state, &s.bundle_sha256, &key0).unwrap();
    assert_eq!(applied[0].actor, "analyst:carlos");
    assert_eq!(applied[0].action, "set_status");
    assert_eq!(applied.last().unwrap().action, "accept_proposal");
    assert_eq!(
        review_state(&state, "findings", "finding_id", &s.proposed[0]),
        ("accepted".into(), Some("analyst:carlos".into()))
    );
    let d = proposal_discard(&state, &s.bundle_sha256, &key1, Some("not convinced")).unwrap();
    assert_eq!(
        (d.actor.as_str(), d.action.as_str()),
        ("analyst:carlos", "discard_proposal")
    );
    assert!(
        review_queue(&state)
            .unwrap()
            .iter()
            .all(|q| matches!(q, QueueItem::Decision(_)))
    );
    // A decided proposal cannot be decided again.
    let e = proposal_discard(&state, &s.bundle_sha256, &key0, None).unwrap_err();
    assert_eq!(e.kind, "decision", "{e:?}");
    let e = proposal_accept(&state, &s.bundle_sha256, "finding:nope").unwrap_err();
    assert_eq!(e.kind, "not_found", "{e:?}");
}

#[test]
fn accept_twice_is_refused_as_stale() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "timeline_entry", &s.entry).decision_seq;
    review_accept(&state, "timeline_entry", &s.entry, seq, None).unwrap();
    let e = review_accept(&state, "timeline_entry", &s.entry, seq, None).unwrap_err();
    assert_eq!(e.kind, "decision", "{e:?}");
    assert!(e.message.contains("needs pending_review"), "{}", e.message);
    // A seq that is no longer the latest decision is stale too.
    let f = decision(&queue, "finding", &s.finding).decision_seq;
    let e = review_accept(&state, "finding", &s.finding, f - 1, None).unwrap_err();
    assert_eq!(e.kind, "decision", "{e:?}");
    assert!(e.message.contains("changed since"), "{}", e.message);
    assert_eq!(
        review_state(&state, "findings", "finding_id", &s.finding).0,
        "pending_review"
    );
}

#[test]
fn writes_need_an_analyst_name() {
    let tmp = tempfile::tempdir().unwrap();
    let s = seeded_case(tmp.path());
    let state = state_with_settings(&tmp.path().join("settings"));
    case_open(&state, &s.path, false).unwrap();
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "finding", &s.finding).decision_seq;
    let key = format!("finding:{}", s.proposed[0]);
    let errors = [
        review_accept(&state, "finding", &s.finding, seq, None).unwrap_err(),
        review_discard(&state, "finding", &s.finding, seq, None).unwrap_err(),
        proposal_accept(&state, &s.bundle_sha256, &key).unwrap_err(),
        proposal_discard(&state, &s.bundle_sha256, &key, None).unwrap_err(),
    ];
    for e in errors {
        assert_eq!(e.kind, "invalid", "{e:?}");
        assert!(e.message.contains("analyst name"), "{}", e.message);
    }
    assert_eq!(review_queue(&state).unwrap().len(), 5, "nothing changed");
}

#[test]
fn review_writes_are_refused_on_a_read_only_case() {
    let tmp = tempfile::tempdir().unwrap();
    let s = seeded_case(tmp.path());
    {
        let case = Case::create_or_open(&s.path).unwrap();
        case.conn()
            .execute_batch("UPDATE audit_trail SET reason = 'x' WHERE seq = 1")
            .unwrap();
    }
    let state = state_with_settings(&tmp.path().join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    assert!(
        case_open(&state, &s.path, false)
            .unwrap()
            .read_only_reason
            .is_some()
    );
    // The queue still reads.
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "finding", &s.finding).decision_seq;
    let key = format!("finding:{}", s.proposed[0]);
    let errors = [
        review_accept(&state, "finding", &s.finding, seq, None).unwrap_err(),
        review_discard(&state, "finding", &s.finding, seq, None).unwrap_err(),
        proposal_accept(&state, &s.bundle_sha256, &key).unwrap_err(),
        proposal_discard(&state, &s.bundle_sha256, &key, None).unwrap_err(),
    ];
    for e in errors {
        assert_eq!(e.kind, "read_only", "{e:?}");
    }
}

#[test]
fn finding_detail_has_evidence_and_guidance() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let d = finding_detail(&state, &s.finding).unwrap();
    assert_eq!(d.finding.finding_id, s.finding);
    assert!(!d.evidence.is_empty());
    assert!(d.analyst_guidance.as_deref().is_some_and(|g| !g.is_empty()));
    assert!(d.audit.iter().any(|e| e.action == "set_status"));
    assert_eq!(
        finding_detail(&state, "nope").unwrap_err().kind,
        "not_found"
    );
}

/// Writes the recorded command responses the frontend tests read (`app/src/test/fixtures`), from the seeded
/// synthetic case. Run by hand after a shape change:
/// `CARGO_NET_OFFLINE=true cargo test -p sparrow-app --test commands record_fixtures -- --ignored`.
#[test]
#[ignore]
fn record_fixtures() {
    let tmp = tempfile::tempdir().unwrap();
    let s = seeded_case(tmp.path());
    let state = state_with_settings(&tmp.path().join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    let mut info = case_open(&state, &s.path, false).unwrap();
    // Not the temporary directory of whoever ran it.
    info.path = "/cases/synthetic-bec-aitm.duckdb".into();
    let queue = review_queue(&state).unwrap();
    let detail = finding_detail(&state, &s.finding).unwrap();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/src/test/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, v: serde_json::Value| {
        let mut text = serde_json::to_string_pretty(&v).unwrap();
        text.push('\n');
        std::fs::write(dir.join(name), text).unwrap();
    };
    write("case_info.json", serde_json::to_value(&info).unwrap());
    write("queue.json", serde_json::to_value(&queue).unwrap());
    write(
        "finding_detail.json",
        serde_json::to_value(&detail).unwrap(),
    );
}
