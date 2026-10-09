//! Command functions on a synthetic case, without a window.

use sparrow_app::cmd::review::{
    QueueItem, finding_detail, proposal_accept, proposal_discard, review_accept, review_discard,
    review_queue,
};
use sparrow_app::settings::{self, Settings, record_recent, settings_get, settings_set_analyst};
use sparrow_app::state::{AppState, analyst, case_close, case_open};
use sparrow_app::state::{OpenCase, with_case as with_case_at, with_writable as with_writable_at};

/// The tests that do not care about the ticket take one right at the call.
fn with_case<T>(
    state: &AppState,
    f: impl FnOnce(&OpenCase) -> sparrow_app::CmdResult<T>,
) -> sparrow_app::CmdResult<T> {
    with_case_at(state, state.ticket(), f)
}

fn with_writable<T>(
    state: &AppState,
    f: impl FnOnce(&OpenCase) -> sparrow_app::CmdResult<T>,
) -> sparrow_app::CmdResult<T> {
    with_writable_at(state, state.ticket(), f)
}
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
    let accounts = sparrow_app::cmd::accounts::accounts_list(&state, None).unwrap();
    let more = record_m3_fixtures(tmp.path());
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/src/test/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, v: serde_json::Value| {
        let mut text = serde_json::to_string_pretty(&v).unwrap();
        text.push('\n');
        std::fs::write(dir.join(name), text).unwrap();
    };
    write("case_info.json", serde_json::to_value(&info).unwrap());
    write("queue.json", serde_json::to_value(&queue).unwrap());
    write("accounts.json", serde_json::to_value(&accounts).unwrap());
    write(
        "finding_detail.json",
        serde_json::to_value(&detail).unwrap(),
    );
    for (name, v) in more {
        write(&name, v);
    }
}

// ---- timeline ----

use sparrow_app::cmd::timeline::{
    EntryEditArgs, NewEntryArgs, timeline_edit, timeline_list, timeline_propose, timeline_reject,
    timeline_verify,
};
use sparrow_core::case::timeline_entries;

fn open_as_analyst(tmp: &Path) -> AppState {
    let path = case_file(tmp);
    let state = state_with_settings(&tmp.join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    case_open(&state, &path, false).unwrap();
    state
}

/// Evidence refs that exist in `record_sources`, in a stable order.
fn evidence_refs(state: &AppState, n: usize) -> Vec<String> {
    with_case(state, |open| {
        let mut stmt = open
            .case
            .conn()
            .prepare(
                "SELECT table_name, record_key FROM record_sources ORDER BY table_name, record_key LIMIT ?",
            )
            .unwrap();
        let rows = stmt
            .query_map([n as i64], |r| {
                Ok(format!(
                    "{}:{}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?
                ))
            })
            .unwrap();
        Ok(rows.map(Result::unwrap).collect::<Vec<_>>())
    })
    .unwrap()
}

fn new_args(evidence: Vec<String>) -> NewEntryArgs {
    NewEntryArgs {
        event_time: "2026-03-01T10:00:00Z".into(),
        title: "Attacker signs in".into(),
        narrative: Some("From an unfamiliar ASN".into()),
        phase: "initial_access".into(),
        evidence,
        tenant_key: None,
    }
}

fn no_edit() -> EntryEditArgs {
    EntryEditArgs::default()
}

#[test]
fn timeline_round_trip_as_analyst() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let before = timeline_list(&state).unwrap().len();
    let refs = evidence_refs(&state, 2);
    assert_eq!(refs.len(), 2, "the synthetic case has evidence records");

    let created = timeline_propose(&state, new_args(vec![refs[0].clone()])).unwrap();
    assert_eq!(created.audit.action, "propose_entry");
    let v = timeline_verify(&state, &created.entry_id).unwrap();
    assert_eq!(v.action, "verify_entry");

    // Editing a verified entry creates a successor and leaves the verified one alone.
    let edited = timeline_edit(
        &state,
        &created.entry_id,
        EntryEditArgs {
            title: Some("Attacker signs in (AiTM)".into()),
            evidence: Some(refs.clone()),
            ..no_edit()
        },
    )
    .unwrap();
    assert_ne!(edited.entry_id, created.entry_id);
    let v2 = timeline_verify(&state, &edited.entry_id).unwrap();
    assert_eq!(v2.actor, "analyst:carlos");

    let all = timeline_list(&state).unwrap();
    assert_eq!(all.len(), before + 2);
    let old = all.iter().find(|e| e.entry_id == created.entry_id).unwrap();
    let new = all.iter().find(|e| e.entry_id == edited.entry_id).unwrap();
    assert_eq!(old.status, "superseded");
    assert_eq!(new.status, "verified");
    assert_eq!(new.supersedes.as_deref(), Some(created.entry_id.as_str()));
    assert_eq!(new.evidence.len(), 2);
    for e in [old, new] {
        assert_eq!(e.decided_by, "analyst:carlos", "{}", e.entry_id);
        assert_eq!(e.review_state, "accepted", "{}", e.entry_id);
        assert_eq!(e.reviewed_by.as_deref(), Some("analyst:carlos"));
    }

    // Reject needs a reason; with one it is final.
    let p = timeline_propose(&state, new_args(vec![refs[0].clone()])).unwrap();
    assert_eq!(
        timeline_reject(&state, &p.entry_id, None).unwrap_err().kind,
        "decision"
    );
    let r = timeline_reject(&state, &p.entry_id, Some("not the attacker")).unwrap();
    assert_eq!(r.action, "reject_entry");
    let all = timeline_list(&state).unwrap();
    assert_eq!(
        all.iter()
            .find(|e| e.entry_id == p.entry_id)
            .unwrap()
            .status,
        "rejected"
    );
}

#[test]
fn edit_refused_on_pending_agent_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let refs = evidence_refs(&state, 1);
    let agent = Actor::agent("triage", Some("carlos")).unwrap();
    let (id, _) = with_writable(&state, |open| {
        Ok(timeline_entries::propose(
            open.case.conn(),
            &agent,
            NewEntry {
                tenant_key: None,
                event_time: "2026-03-01T09:00:00Z".parse().unwrap(),
                title: "Agent proposal".into(),
                narrative: None,
                phase: Phase::Recon,
                evidence: vec![EvidenceRef::parse(&refs[0]).unwrap()],
            },
        )
        .unwrap())
    })
    .unwrap();
    let snapshot = |state: &AppState| {
        let e = timeline_list(state)
            .unwrap()
            .into_iter()
            .find(|e| e.entry_id == id)
            .unwrap();
        serde_json::to_string(&e).unwrap()
    };
    let before = snapshot(&state);
    let audit_len = with_case(&state, |o| {
        Ok(sparrow_core::case::audit::log(o.case.conn(), None)
            .unwrap()
            .len())
    })
    .unwrap();
    for edit in [
        EntryEditArgs {
            title: Some("Analyst rewrite".into()),
            ..no_edit()
        },
        EntryEditArgs {
            narrative: Some(None),
            ..no_edit()
        },
    ] {
        let e = timeline_edit(&state, &id, edit).unwrap_err();
        assert_eq!(e.kind, "decision", "{e:?}");
        assert!(e.message.contains("pending"), "{}", e.message);
    }
    assert_eq!(snapshot(&state), before, "nothing changed");
    let after_len = with_case(&state, |o| {
        Ok(sparrow_core::case::audit::log(o.case.conn(), None)
            .unwrap()
            .len())
    })
    .unwrap();
    assert_eq!(after_len, audit_len, "no audit row was written");
}

#[test]
fn bad_time_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let refs = evidence_refs(&state, 1);
    let before = timeline_list(&state).unwrap().len();
    for bad in [
        "yesterday",
        "2026-03-01 10:00:00",
        "2026-13-01T10:00:00Z",
        "",
    ] {
        let mut a = new_args(refs.clone());
        a.event_time = bad.into();
        let e = timeline_propose(&state, a).unwrap_err();
        assert_eq!(e.kind, "invalid", "{bad}: {e:?}");
    }
    let mut a = new_args(refs.clone());
    a.phase = "lateral".into();
    assert_eq!(timeline_propose(&state, a).unwrap_err().kind, "invalid");
    let mut a = new_args(vec!["no-colon".into()]);
    a.title = "x".into();
    assert_eq!(timeline_propose(&state, a).unwrap_err().kind, "invalid");
    assert_eq!(timeline_list(&state).unwrap().len(), before);
    // A bad time on an edit is refused too.
    let ok = timeline_propose(&state, new_args(refs)).unwrap();
    let e = timeline_edit(
        &state,
        &ok.entry_id,
        EntryEditArgs {
            event_time: Some("soon".into()),
            ..no_edit()
        },
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid");
}

#[test]
fn timeline_writes_need_a_writable_case_and_an_analyst() {
    let tmp = tempfile::tempdir().unwrap();
    let state = AppState::default();
    assert_eq!(timeline_list(&state).unwrap_err().kind, "no_case");
    let path = case_file(tmp.path());
    let state = state_with_settings(&tmp.path().join("settings"));
    case_open(&state, &path, false).unwrap();
    let refs = evidence_refs(&state, 1);
    // No analyst name set.
    let e = timeline_propose(&state, new_args(refs)).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(e.message.contains("analyst"), "{}", e.message);
}

#[test]
fn narrative_can_be_cleared() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let refs = evidence_refs(&state, 1);
    let made = timeline_propose(&state, new_args(refs)).unwrap();
    let narrative = |state: &AppState| {
        timeline_list(state)
            .unwrap()
            .into_iter()
            .find(|e| e.entry_id == made.entry_id)
            .unwrap()
            .narrative
    };
    assert_eq!(narrative(&state).as_deref(), Some("From an unfamiliar ASN"));
    // An edit that leaves the narrative out keeps it.
    timeline_edit(
        &state,
        &made.entry_id,
        EntryEditArgs {
            title: Some("Renamed".into()),
            ..no_edit()
        },
    )
    .unwrap();
    assert_eq!(narrative(&state).as_deref(), Some("From an unfamiliar ASN"));
    // The wire shape: absent keeps, null clears.
    let clear: EntryEditArgs = serde_json::from_str(r#"{"narrative": null}"#).unwrap();
    assert_eq!(clear.narrative, Some(None));
    let keep: EntryEditArgs = serde_json::from_str(r#"{"title": "t"}"#).unwrap();
    assert_eq!(keep.narrative, None);
    let e = timeline_edit(&state, &made.entry_id, clear).unwrap();
    assert_eq!(e.entry_id, made.entry_id);
    assert_eq!(narrative(&state), None);
}

#[test]
fn timeline_writes_are_refused_on_a_read_only_case() {
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    {
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
    }
    let state = state_with_settings(&tmp.path().join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    let info = case_open(&state, &path, false).unwrap();
    assert!(info.read_only_reason.is_some());
    // Reads work; every write is read_only, and nothing was added.
    let all = timeline_list(&state).unwrap();
    let refs = evidence_refs(&state, 1);
    let target = all
        .first()
        .map(|e| e.entry_id.clone())
        .unwrap_or_else(|| "x".into());
    assert_eq!(
        timeline_propose(&state, new_args(refs)).unwrap_err().kind,
        "read_only"
    );
    assert_eq!(
        timeline_edit(
            &state,
            &target,
            EntryEditArgs {
                title: Some("t".into()),
                ..no_edit()
            }
        )
        .unwrap_err()
        .kind,
        "read_only"
    );
    assert_eq!(
        timeline_verify(&state, &target).unwrap_err().kind,
        "read_only"
    );
    assert_eq!(
        timeline_reject(&state, &target, Some("r"))
            .unwrap_err()
            .kind,
        "read_only"
    );
    assert_eq!(timeline_list(&state).unwrap().len(), all.len());
}

// ---- accounts and exports ----

use sparrow_app::cmd::accounts::accounts_list;
use sparrow_app::cmd::export::{export_report, export_timeline_csv, export_workbook};

#[test]
fn accounts_list_matches_core() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let page = accounts_list(&state, None).unwrap();
    let core = with_case(&state, |open| {
        Ok(sparrow_core::case::read::accounts(
            open.case.conn(),
            None,
            None,
        )?)
    })
    .unwrap();
    assert!(!core.accounts.is_empty(), "the synthetic case has accounts");
    assert_eq!(
        serde_json::to_value(&page).unwrap(),
        serde_json::to_value(&core).unwrap()
    );
    // A tenant filter reaches core: an unknown tenant has no accounts.
    let none = accounts_list(&state, Some("no-such-tenant")).unwrap();
    assert!(none.accounts.is_empty());
    let tenant = page.accounts[0].tenant_key.clone();
    let one = accounts_list(&state, Some(&tenant)).unwrap();
    assert!(!one.accounts.is_empty() && one.accounts.iter().all(|a| a.tenant_key == tenant));
}

#[test]
fn accounts_need_an_open_case() {
    let e = accounts_list(&AppState::default(), None).unwrap_err();
    assert_eq!(e.kind, "no_case");
}

fn leftovers(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".partial") || n.starts_with(".sparrow-export-"))
        .collect();
    v.sort();
    v
}

#[test]
fn export_report_reviewed_only_writes_file_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    // The analyst's own decision on the finding is reviewed as made.
    let analyst = Reviewer::analyst("carlos").unwrap();
    // Resolve the agent's pending decision first (core refuses to write over it), then decide as the analyst.
    let q = review_queue(&state).unwrap();
    let d = decision(&q, "finding", &s.finding);
    review_accept(&state, "finding", &s.finding, d.decision_seq, None).unwrap();
    with_writable(&state, |open| {
        write::set_finding_status(
            open.case.conn(),
            &analyst.as_actor(),
            &s.finding,
            write::FindingStatus::Confirmed,
            Some("confirmed by the analyst"),
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    let out = tmp.path().join("report.md");
    export_report(&state, &out, true).unwrap();
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("analyst decision"), "{text}");
    assert!(
        leftovers(tmp.path()).is_empty(),
        "{:?}",
        leftovers(tmp.path())
    );
    // The reviewed-only report leaves out the still-pending agent decisions the full one labels.
    let all = tmp.path().join("all.md");
    export_report(&state, &all, false).unwrap();
    assert_ne!(text, std::fs::read_to_string(&all).unwrap());
}

#[test]
fn export_timeline_csv_and_workbook_write_files() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let csv = tmp.path().join("timeline.csv");
    export_timeline_csv(&state, &csv).unwrap();
    assert!(
        std::fs::read(&csv)
            .unwrap()
            .starts_with(&[0xEF, 0xBB, 0xBF])
    );
    let xlsx = tmp.path().join("case.xlsx");
    export_workbook(&state, &xlsx).unwrap();
    // An .xlsx is a zip.
    assert!(std::fs::read(&xlsx).unwrap().starts_with(b"PK"));
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn export_to_missing_dir_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let out = tmp.path().join("no-such-dir").join("report.md");
    let e = export_report(&state, &out, true).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(!tmp.path().join("no-such-dir").exists());
    assert_eq!(export_workbook(&state, &out).unwrap_err().kind, "invalid");
    assert_eq!(
        export_timeline_csv(&state, &out).unwrap_err().kind,
        "invalid"
    );
}

#[test]
fn export_never_overwrites_the_case_and_a_failure_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let before = std::fs::metadata(&s.path).unwrap().len();
    let e = export_report(&state, &s.path, true).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert_eq!(std::fs::metadata(&s.path).unwrap().len(), before);
    // A directory as the target: the rename fails and the partial file is removed.
    let dir = tmp.path().join("target-dir");
    std::fs::create_dir(&dir).unwrap();
    assert!(export_report(&state, &dir, true).is_err());
    assert!(leftovers(tmp.path()).is_empty());
    // A case-less app refuses.
    assert_eq!(
        export_report(&AppState::default(), &tmp.path().join("x.md"), true)
            .unwrap_err()
            .kind,
        "no_case"
    );
}

#[test]
fn a_partial_symlink_to_the_case_is_never_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let before = std::fs::read(&s.path).unwrap();
    let out = tmp.path().join("report.md");
    let wal = PathBuf::from(format!("{}.wal", s.path.display()));
    std::os::unix::fs::symlink(&s.path, tmp.path().join("report.md.partial")).unwrap();
    export_report(&state, &out, true).unwrap();
    assert!(!std::fs::read_to_string(&out).unwrap().is_empty());
    // The link is still there, untouched, and the case is byte for byte what it was.
    assert!(
        std::fs::symlink_metadata(tmp.path().join("report.md.partial"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
    // The workbook writer gets a path of its own too, and a link to the WAL fares no better.
    let _ = std::fs::write(&wal, b"");
    std::os::unix::fs::symlink(&wal, tmp.path().join("case.xlsx.partial")).unwrap();
    export_workbook(&state, &tmp.path().join("case.xlsx")).unwrap();
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
    assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
    let _ = std::fs::remove_file(&wal);
    // The case still opens.
    let again = AppState::default();
    drop(state);
    case_open(&again, &s.path, false).unwrap();
}

#[test]
fn a_pre_existing_partial_file_is_left_intact() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let partial = tmp.path().join("report.md.partial");
    std::fs::write(&partial, b"someone else's file").unwrap();
    export_report(&state, &tmp.path().join("report.md"), true).unwrap();
    assert_eq!(std::fs::read(&partial).unwrap(), b"someone else's file");
    assert!(
        leftovers(tmp.path()).len() == 1,
        "only the user's own .partial: {:?}",
        leftovers(tmp.path())
    );
}

#[test]
fn differently_cased_case_and_wal_names_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let before = std::fs::read(&s.path).unwrap();
    let dir = s.path.parent().unwrap();
    for name in [
        "CASE.duckdb",
        "case.DUCKDB.wal",
        "Case.Duckdb",
        "case.duckdb.wal",
    ] {
        let e = export_report(&state, &dir.join(name), true).unwrap_err();
        assert_eq!(e.kind, "invalid", "{name}: {e:?}");
        let e = export_workbook(&state, &dir.join(name)).unwrap_err();
        assert_eq!(e.kind, "invalid", "{name}: {e:?}");
    }
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn a_symlink_target_is_refused_and_an_earlier_export_is_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let before = std::fs::read(&s.path).unwrap();
    let link = tmp.path().join("link.md");
    std::os::unix::fs::symlink(&s.path, &link).unwrap();
    let e = export_report(&state, &link, true).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
    // A hard link to the case is the same file by identity.
    let hard = tmp.path().join("hard.md");
    std::fs::hard_link(&s.path, &hard).unwrap();
    assert_eq!(
        export_report(&state, &hard, true).unwrap_err().kind,
        "invalid"
    );
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
    // An ordinary earlier export is replaced.
    let out = tmp.path().join("report.md");
    std::fs::write(&out, b"old").unwrap();
    export_report(&state, &out, true).unwrap();
    assert_ne!(std::fs::read(&out).unwrap(), b"old");
    assert!(leftovers(tmp.path()).is_empty());
}

// ---- M3: pivot, browse, SQL with cancel, indicators, share files, highlights ----

use sparrow_app::cmd::browse::{browse_page as browse_page_id, browse_tables};
use sparrow_app::cmd::indicators::indicators_active;
use sparrow_app::cmd::pivot::{cap_of, pivot_ip, pivot_user};
use sparrow_app::cmd::share::{share_export, share_import, share_preview};
use sparrow_app::cmd::sql::query_cancel;
use sparrow_app::cmd::sql::{sql_run as sql_run_id, sql_schema};
use sparrow_app::settings::{
    HighlightRule, HighlightSet, highlights_clear, highlights_get, highlights_set,
};

/// The calls that do not care about cancelling run under a fixed id.
fn sql_run(
    state: &AppState,
    sql: &str,
    limit: Option<usize>,
) -> sparrow_app::CmdResult<query::QueryResult> {
    sql_run_id(state, sql, limit, "t")
}

fn browse_page(
    state: &AppState,
    table: &str,
    filters: &[Filter],
    sort: Option<&browse::Sort>,
    offset: usize,
    limit: usize,
) -> sparrow_app::CmdResult<browse::BrowsePage> {
    browse_page_id(state, table, filters, sort, offset, limit, "t")
}
use sparrow_core::case::browse::{self, Filter};

/// Two private copies of the detected case, each open in its own app with the analyst `name`.
fn two_apps(tmp: &Path, a_name: &str, b_name: &str) -> (AppState, AppState) {
    let open = |sub: &str, name: &str| {
        let dir = tmp.join(sub);
        std::fs::create_dir_all(&dir).unwrap();
        let path = case_file(&dir);
        let state = state_with_settings(&dir.join("settings"));
        settings_set_analyst(&state, name).unwrap();
        case_open(&state, &path, false).unwrap();
        state
    };
    (open("a", a_name), open("b", b_name))
}

fn confirm_findings(state: &AppState, n: usize) -> Vec<String> {
    let me = analyst(state).unwrap();
    with_writable(state, |open| {
        let ids = findings_by_id(&open.case);
        assert!(ids.len() >= n, "{ids:?}");
        for id in &ids[..n] {
            write::set_finding_status(
                open.case.conn(),
                &me.as_actor(),
                id,
                write::FindingStatus::Confirmed,
                Some("AiTM relay"),
            )?;
        }
        Ok(ids[..n].to_vec())
    })
    .unwrap()
}

fn rows(state: &AppState, sql: &str) -> i64 {
    with_case(state, |open| {
        Ok(open.case.conn().query_row(sql, [], |r| r.get(0)).unwrap())
    })
    .unwrap()
}

/// A query that runs for minutes unless interrupted.
const LONG: &str = "SELECT sum(hash(a)) FROM range(100000000000) a";

/// Run `f` on a thread while this thread calls `cancel` every 50 ms until `f` returns (a cancel before the query
/// starts is a no-op by design, so it repeats). Gives the result and how long `f` ran after the first cancel.
fn cancelling<T: Send>(
    f: impl FnOnce() -> T + Send,
    cancel: impl Fn(),
    give_up: std::time::Duration,
) -> (T, std::time::Duration) {
    let started = std::time::Instant::now();
    std::thread::scope(|scope| {
        let runner = scope.spawn(f);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let first = std::time::Instant::now();
        while !runner.is_finished() {
            assert!(started.elapsed() < give_up, "the query ended too late");
            cancel();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        (runner.join().unwrap(), first.elapsed())
    })
}

#[test]
fn cancel_interrupts_a_long_query() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let (result, took) = cancelling(
        || sql_run_id(&state, LONG, None, "q-1"),
        || query_cancel(&state, "q-1").unwrap(),
        std::time::Duration::from_secs(30),
    );
    let e = result.unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
    assert!(took < std::time::Duration::from_secs(2), "{took:?}");
    assert!(
        state.active.lock().unwrap().is_none(),
        "the entry is cleared"
    );
    // The case is usable afterwards: reads, and a write.
    assert_eq!(
        sql_run(&state, "SELECT 1 AS one", None).unwrap().rows.len(),
        1
    );
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "timeline_entry", &s.entry).decision_seq;
    review_accept(&state, "timeline_entry", &s.entry, seq, None).unwrap();
    with_case(&state, |open| {
        open.case.ensure_usable()?;
        Ok(())
    })
    .unwrap();
}

/// A medium query (about a second) run straight on the connection, so only an interrupt can end it early.
const MEDIUM: &str = "SELECT (sum(hash(a)) % 7)::BIGINT FROM range(1500000000) a";

fn direct(open: &sparrow_app::state::OpenCase, sql: &str) -> sparrow_app::CmdResult<()> {
    open.case
        .conn()
        .query_row(sql, [], |r| r.get::<_, Option<i64>>(0).map(|_| ()))
        .map_err(sparrow_core::Error::from)?;
    Ok(())
}

#[test]
fn cancel_with_a_wrong_id_or_nothing_running_does_nothing() {
    let state = AppState::default();
    query_cancel(&state, "idle-1").unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    query_cancel(&state, "idle-1").unwrap();
    assert_eq!(
        sql_run(&state, "SELECT 1 AS one", None).unwrap().rows.len(),
        1
    );
    // Ids are checked.
    for bad in ["", &"x".repeat(65), "a\nb"] {
        assert_eq!(
            query_cancel(&state, bad).unwrap_err().kind,
            "invalid",
            "{bad:?}"
        );
        assert_eq!(
            sql_run_id(&state, "SELECT 1", None, bad).unwrap_err().kind,
            "invalid"
        );
    }
    assert!(query_cancel(&state, &"x".repeat(64)).is_ok());
    // A query running as "q-1" is not touched by cancels for other ids, and finishes with its result.
    let started = std::time::Instant::now();
    let (result, _) = cancelling(
        || {
            sql_run_id(
                &state,
                "SELECT sum(hash(a)) AS s FROM range(1500000000) a",
                None,
                "q-1",
            )
        },
        || {
            query_cancel(&state, "q-2").unwrap();
            query_cancel(&state, "q-1 ").unwrap();
            query_cancel(&state, "Q-1").unwrap();
        },
        std::time::Duration::from_secs(60),
    );
    assert_eq!(result.unwrap().rows.len(), 1);
    assert!(
        started.elapsed() > std::time::Duration::from_millis(250),
        "the query must have been running"
    );
    // After close the entry is gone: a cancel is a no-op again.
    case_close(&state).unwrap();
    query_cancel(&state, "idle-2").unwrap();
    assert!(state.active.lock().unwrap().is_none());
}

#[test]
fn cancel_reaches_a_running_query_while_a_switch_is_queued_behind_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let other = tmp.path().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let other = case_file(&other);
    let g0 = state.generation.load(std::sync::atomic::Ordering::SeqCst);
    let (result, opened, took) = std::thread::scope(|scope| {
        let runner = scope.spawn(|| sql_run_id(&state, LONG, None, "s-1"));
        let t = std::time::Instant::now();
        while state.active.lock().unwrap().is_none() {
            assert!(
                t.elapsed() < std::time::Duration::from_secs(10),
                "never registered"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // The switch is requested (generation bumped) and queues behind the running query.
        let opener = scope.spawn(|| case_open(&state, &other, false));
        while state.generation.load(std::sync::atomic::Ordering::SeqCst) == g0 {
            assert!(t.elapsed() < std::time::Duration::from_secs(10));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!runner.is_finished() && !opener.is_finished());
        let cancelled = std::time::Instant::now();
        // The active entry is matched by id alone, whatever generation the case is moving to.
        while !runner.is_finished() {
            assert!(
                cancelled.elapsed() < std::time::Duration::from_secs(30),
                "not interrupted"
            );
            query_cancel(&state, "s-1").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let took = cancelled.elapsed();
        (runner.join().unwrap(), opener.join().unwrap(), took)
    });
    assert_eq!(result.unwrap_err().kind, "interrupted");
    assert!(took < std::time::Duration::from_secs(2), "{took:?}");
    // The switch then completed.
    assert_eq!(opened.unwrap().path, other.display().to_string());
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "s-2")
            .unwrap()
            .rows
            .len(),
        1
    );
}

#[test]
fn a_cancel_is_never_followed_by_an_interrupt_of_the_next_operation() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    for i in 0..200u64 {
        let id = format!("h-{i}");
        let r = sparrow_app::state::with_cancellable(&state, state.ticket(), &id, |open| {
            query_cancel(&state, &id).unwrap();
            // The repeated interrupt fires at different phases of the operation.
            std::thread::sleep(std::time::Duration::from_millis((i % 5) * 15));
            direct(open, "SELECT count(*) FROM range(2000000)")
        });
        assert_eq!(r.unwrap_err().kind, "interrupted", "iteration {i}");
        // Straight after the teardown, on the same connection: a read, a SQL run and a write, none interrupted.
        with_case(&state, |open| {
            direct(open, "SELECT count(*) FROM range(1000000)")
        })
        .unwrap_or_else(|e| panic!("iteration {i}: follow-on read: {e:?}"));
        sql_run_id(
            &state,
            "SELECT count(*) AS n FROM range(1000000)",
            None,
            &format!("f-{i}"),
        )
        .unwrap_or_else(|e| panic!("iteration {i}: follow-on run: {e:?}"));
        with_writable(&state, |open| {
            write::in_tx(open.case.conn(), |tx| {
                tx.execute_batch(&format!("INSERT INTO case_meta VALUES ('zz_h{i}', '1')"))?;
                Ok(())
            })?;
            Ok(())
        })
        .unwrap_or_else(|e| panic!("iteration {i}: follow-on write: {e:?}"));
    }
    assert_eq!(
        rows(
            &state,
            "SELECT count(*) FROM case_meta WHERE key LIKE 'zz_h%'"
        ),
        200
    );
    assert!(state.active.lock().unwrap().is_none());
}

#[test]
fn a_file_read_before_the_case_lock_does_not_outlive_a_case_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = two_apps(tmp.path(), "ann", "bob");
    confirm_findings(&a, 1);
    let file = tmp.path().join("work.sparrow-share.json");
    let exported = share_export(&a, &file).unwrap();
    // The request is submitted (ticket) ...
    let ticket = b.ticket();
    // ... and the case is switched before it reaches the lock (here: after its file was "read").
    let b_path = with_case(&b, |open| Ok(open.path.clone())).unwrap();
    case_open(&b, &b_path, false).unwrap();
    let e = sparrow_app::cmd::share::share_preview_at(&b, ticket, &file).unwrap_err();
    assert_eq!(e.kind, "no_case", "{e:?}");
    let e =
        sparrow_app::cmd::share::share_import_at(&b, ticket, &file, &exported.sha256).unwrap_err();
    assert_eq!(e.kind, "no_case", "{e:?}");
    assert_eq!(rows(&b, "SELECT count(*) FROM imported_proposals"), 0);
    assert_eq!(
        rows(
            &b,
            "SELECT count(*) FROM audit_trail WHERE action = 'import_share'"
        ),
        0
    );
    // A request submitted after the switch is unaffected.
    assert_eq!(share_preview(&b, &file).unwrap().sha256, exported.sha256);
    share_import(&b, &file, &exported.sha256).unwrap();
}

#[test]
fn a_write_running_concurrently_is_not_interrupted() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let (result, _) = cancelling(
        || {
            with_writable(&state, |open| {
                direct(open, MEDIUM)?;
                // Still a working transaction afterwards.
                write::in_tx(open.case.conn(), |tx| {
                    tx.execute_batch("INSERT INTO case_meta VALUES ('zz_cancel', '1')")?;
                    Ok(())
                })?;
                Ok(())
            })
        },
        // Every id a screen could be using.
        || {
            for id in ["t", "q-1", "q-2"] {
                query_cancel(&state, id).unwrap();
            }
        },
        std::time::Duration::from_secs(60),
    );
    result.unwrap();
    assert_eq!(
        rows(
            &state,
            "SELECT count(*) FROM case_meta WHERE key = 'zz_cancel'"
        ),
        1
    );
    // A review write (the audited path) is equally unaffected, with a cancellable query not in flight.
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "timeline_entry", &s.entry).decision_seq;
    review_accept(&state, "timeline_entry", &s.entry, seq, None).unwrap();
    // A write registers nothing.
    with_writable(&state, |_| {
        assert!(state.active.lock().unwrap().is_none());
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_cancelled_browse_page_leaves_the_case_usable() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    // A view over two billion rows: a text filter on it scans for minutes unless interrupted.
    with_writable(&state, |open| {
        write::in_tx(open.case.conn(), |tx| {
            tx.execute_batch(
                "CREATE VIEW zz_big AS SELECT i, 'x' || (i % 1000)::VARCHAR AS s FROM range(2000000000) t(i)",
            )?;
            Ok(())
        })?;
        Ok(())
    })
    .unwrap();
    assert!(
        browse_tables(&state)
            .unwrap()
            .contains(&"zz_big".to_string())
    );
    let filters = vec![Filter::Contains {
        column: "s".into(),
        value: "zzz".into(),
    }];
    let (result, took) = cancelling(
        || browse_page_id(&state, "zz_big", &filters, None, 0, 50, "b-1"),
        || query_cancel(&state, "b-1").unwrap(),
        std::time::Duration::from_secs(60),
    );
    let e = result.unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
    assert!(took < std::time::Duration::from_secs(2), "{took:?}");
    assert!(state.active.lock().unwrap().is_none());
    // Usable: a page, SQL, a write.
    assert_eq!(
        browse_page(&state, "signins", &[], None, 0, 5)
            .unwrap()
            .rows
            .len(),
        5
    );
    assert_eq!(
        sql_run(&state, "SELECT 1 AS one", None).unwrap().rows.len(),
        1
    );
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "timeline_entry", &s.entry).decision_seq;
    review_accept(&state, "timeline_entry", &s.entry, seq, None).unwrap();
}

#[test]
fn text_that_looks_like_the_interrupt_message_is_not_an_interruption() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let e = browse_page(&state, "INTERRUPT Error", &[], None, 0, 5).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    let bad = vec![Filter::IsNull {
        column: "INTERRUPT Error".into(),
    }];
    let e = browse_page(&state, "signins", &bad, None, 0, 5).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    let e = sql_run(&state, "SELECT * FROM \"INTERRUPT Error\"", None).unwrap_err();
    assert_ne!(e.kind, "interrupted", "{e:?}");
    // SQL that makes DuckDB raise an error quoting that text after its own class prefix.
    let e = sql_run(
        &state,
        "SELECT CAST('INTERRUPT Error: Interrupted!' AS INTEGER)",
        None,
    )
    .unwrap_err();
    assert!(
        e.message.contains("INTERRUPT Error"),
        "the error quotes the text: {e:?}"
    );
    assert_ne!(e.kind, "interrupted", "{e:?}");
    // And a value that is that text matches nothing, quietly.
    let eq = vec![Filter::Eq {
        column: "user_principal_name".into(),
        value: serde_json::json!("INTERRUPT Error"),
    }];
    if let Err(e) = browse_page(&state, "signins", &eq, None, 0, 5) {
        assert_ne!(e.kind, "interrupted", "{e:?}");
    }
}

#[test]
fn import_refuses_a_file_changed_after_preview() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = two_apps(tmp.path(), "ann", "bob");
    let file = tmp.path().join("work.sparrow-share.json");
    confirm_findings(&a, 1);
    share_export(&a, &file).unwrap();
    let preview = share_preview(&b, &file).unwrap();
    // The file is replaced by a different bundle after the preview.
    confirm_findings(&a, 2);
    let replaced = share_export(&a, &file).unwrap();
    assert_ne!(replaced.sha256, preview.sha256);
    let e = share_import(&b, &file, &preview.sha256).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(
        e.message.contains("changed since the preview"),
        "{}",
        e.message
    );
    assert_eq!(rows(&b, "SELECT count(*) FROM imported_proposals"), 0);
    assert_eq!(
        rows(
            &b,
            "SELECT count(*) FROM audit_trail WHERE action = 'import_share'"
        ),
        0
    );
    // The new bytes import with their own sha.
    let fresh = share_preview(&b, &file).unwrap();
    assert_eq!(fresh.sha256, replaced.sha256);
    let summary = share_import(&b, &file, &fresh.sha256).unwrap();
    assert!(
        summary.new + summary.agrees + summary.conflicts >= 1,
        "{summary:?}"
    );
}

#[test]
fn share_round_trip_through_files() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = two_apps(tmp.path(), "ann", "bob");
    let confirmed = confirm_findings(&a, 2);
    let file = tmp.path().join("work.sparrow-share.json");
    let exported = share_export(&a, &file).unwrap();
    assert!(exported.items >= 2, "{exported:?}");
    assert_eq!(
        std::fs::read_dir(tmp.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".sparrow-export-")
            })
            .count(),
        0,
        "no work folder is left behind"
    );

    let queue_before = review_queue(&b).unwrap().len();
    let preview = share_preview(&b, &file).unwrap();
    assert_eq!(preview.sha256, exported.sha256);
    assert_eq!(preview.analyst, "analyst:ann");
    assert_eq!(preview.items, exported.items);
    assert!(chrono::DateTime::parse_from_rfc3339(&preview.exported_at).is_ok());
    assert!(!preview.summary.already_imported);
    assert_eq!(preview.summary.superseded, 0);
    assert!(preview.summary.new + preview.summary.conflicts >= confirmed.len());
    // Nothing stored by the preview.
    assert_eq!(rows(&b, "SELECT count(*) FROM imported_proposals"), 0);
    assert_eq!(review_queue(&b).unwrap().len(), queue_before);

    let summary = share_import(&b, &file, &preview.sha256).unwrap();
    assert_eq!(summary, preview.summary);
    let proposals = review_queue(&b)
        .unwrap()
        .iter()
        .filter(|q| matches!(q, QueueItem::Proposal(_)))
        .count();
    assert_eq!(proposals, summary.new + summary.conflicts);
    assert!(proposals >= 2);
    // Again: previewed and imported before.
    assert!(share_preview(&b, &file).unwrap().summary.already_imported);
}

#[test]
fn share_files_are_checked() {
    let tmp = tempfile::tempdir().unwrap();
    let (a, b) = two_apps(tmp.path(), "ann", "bob");
    let missing = tmp.path().join("nope.json");
    assert_eq!(share_preview(&b, &missing).unwrap_err().kind, "not_found");
    let junk = tmp.path().join("junk.json");
    std::fs::write(&junk, b"{}").unwrap();
    assert_eq!(share_preview(&b, &junk).unwrap_err().kind, "invalid");
    assert_eq!(share_import(&b, &junk, "00").unwrap_err().kind, "invalid");
    // Over the size limit: refused before parsing.
    let big = tmp.path().join("big.json");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(share::MAX_BUNDLE_BYTES as u64 + 1).unwrap();
    let e = share_preview(&b, &big).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(e.message.contains("16 MiB"), "{}", e.message);
    // A directory, and an export over the open case.
    assert_eq!(share_preview(&b, tmp.path()).unwrap_err().kind, "invalid");
    let case_path = with_case(&a, |open| Ok(open.path.clone())).unwrap();
    let e = share_export(&a, &case_path).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(std::fs::metadata(&case_path).unwrap().len() > 1000);
    // Exports and imports need the analyst name.
    let nameless = state_with_settings(&tmp.path().join("nameless"));
    assert_eq!(
        share_export(&nameless, &tmp.path().join("x.json"))
            .unwrap_err()
            .kind,
        "invalid"
    );
}

#[test]
fn pivot_rejects_bad_input() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let huge = "9".repeat(10 * 1024);
    for bad in [
        "not-an-ip",
        "",
        "   ",
        "1.2.3.4 ",
        "1.2.3.4\n",
        "999.1.1.1",
        &huge,
    ] {
        let e = pivot_ip(&state, bad, None).unwrap_err();
        assert_eq!(e.kind, "invalid", "{bad:?}: {e:?}");
    }
    let long_upn = format!("{}@example.com", "a".repeat(320));
    for bad in [
        "",
        "  ",
        "a\u{0}@b.example",
        "a\n@b.example",
        "a\u{202e}\u{7}@b",
        &huge,
        &long_upn,
    ] {
        // U+202E alone is not a control character; the BEL after it is.
        let e = pivot_user(&state, bad, None).unwrap_err();
        assert_eq!(e.kind, "invalid", "{bad:?}: {e:?}");
    }
    // Valid input never errors, even for values the case has never seen.
    let p = pivot_ip(&state, "203.0.113.250", None).unwrap();
    assert!(!p.sections.is_empty());
    assert!(p.sections.iter().all(|s| s.rows.is_empty()));
    assert!(pivot_ip(&state, "2001:db8::1", None).is_ok());
    assert!(pivot_user(&state, "nobody@nowhere.example", None).is_ok());
    // The cap is clamped to 1..=1000, default 200.
    assert_eq!(
        (cap_of(None), cap_of(Some(0)), cap_of(Some(99_999))),
        (200, 1, 1000)
    );
    // It is applied: a real account with more than one row in some section comes back truncated at 1.
    let upn: String = with_case(&state, |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                "SELECT actor_upn FROM findings ORDER BY finding_id LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap())
    })
    .unwrap();
    let capped = pivot_user(&state, &upn, Some(0)).unwrap();
    let full = pivot_user(&state, &upn, None).unwrap();
    let mut checked = 0;
    for (c, f) in capped.sections.iter().zip(&full.sections) {
        assert_eq!(c.name, f.name);
        assert!(c.rows.len() <= 1);
        assert_eq!(c.total, f.total);
        if f.total > 1 {
            assert!(c.truncated && c.rows.len() == 1, "{}", c.name);
            checked += 1;
        }
    }
    assert!(checked > 0, "no section had more than one row to cap");
}

#[test]
fn sql_run_limits_and_refusals() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let before = rows(&state, "SELECT count(*) FROM findings");
    for bad in [
        "DELETE FROM findings",
        "INSERT INTO case_meta VALUES ('k', 'v')",
        "SELECT 1; SELECT 2",
        "ATTACH 'x.db' AS x",
        "SELECT * FROM read_csv('/etc/hosts')",
        "",
    ] {
        let e = sql_run(&state, bad, None).unwrap_err();
        assert!(["invalid", "internal"].contains(&e.kind), "{bad:?}: {e:?}");
    }
    assert_eq!(rows(&state, "SELECT count(*) FROM findings"), before);
    let e = sql_run(
        &state,
        &format!("SELECT '{}'", "x".repeat(2 * 1024 * 1024)),
        None,
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");

    let n = |limit| sql_run(&state, "SELECT * FROM range(20000) t(i)", limit).unwrap();
    let default = n(None);
    assert_eq!((default.rows.len(), default.truncated), (1000, true));
    let big = n(Some(50_000));
    assert_eq!((big.rows.len(), big.truncated), (10_000, true));
    let zero = n(Some(0));
    assert_eq!(zero.rows.len(), 1);
    let all = sql_run(&state, "SELECT * FROM range(5) t(i)", Some(10)).unwrap();
    assert_eq!((all.rows.len(), all.truncated), (5, false));

    let schema = sql_schema(&state, None).unwrap();
    assert!(schema.len() > 5);
    let one = sql_schema(&state, Some("findings")).unwrap();
    assert_eq!(one.len(), 1);
    assert!(!one[0].columns.is_empty());
}

#[test]
fn read_only_case_runs_sql_and_browses_but_refuses_writes() {
    // Decision (probed): lock_down works on a read-only connection, so a broken-chain case is locked down at open
    // and SQL / browse / pivot work on it; share_import and the other writes are refused as read_only.
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    {
        let case = Case::create_or_open(&path).unwrap();
        let id = first_finding(&case);
        let e = write::set_finding_status(
            case.conn(),
            &Actor::agent("triage", None).unwrap(),
            &id,
            write::FindingStatus::InReview,
            None,
        )
        .unwrap();
        case.conn()
            .execute("UPDATE audit_trail SET reason = 'x' WHERE seq = ?", [e.seq])
            .unwrap();
    }
    let state = state_with_settings(&tmp.path().join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    let info = case_open(&state, &path, false).unwrap();
    assert!(info.read_only_reason.is_some());
    with_case(&state, |open| {
        assert!(open.case.is_read_only() && open.case.is_locked_down()?);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        sql_run(&state, "SELECT count(*) AS n FROM findings", None)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert!(!sql_schema(&state, None).unwrap().is_empty());
    assert!(
        browse_tables(&state)
            .unwrap()
            .contains(&"findings".to_string())
    );
    assert!(pivot_ip(&state, "203.0.113.9", None).is_ok());
    let junk = tmp.path().join("b.json");
    std::fs::write(&junk, b"{}").unwrap();
    // The write is refused as read-only before the bundle is even looked at.
    let e = share_import(&state, &junk, "00").unwrap_err();
    assert_eq!(e.kind, "read_only", "{e:?}");
    let ok_file = tmp.path().join("x.json");
    let e = share_export(&state, &ok_file).unwrap_err();
    assert_eq!(e.kind, "invalid", "a broken chain cannot export: {e:?}");
}

#[test]
fn browse_page_passes_filters_through() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let tables = browse_tables(&state).unwrap();
    assert!(tables.contains(&"signins".to_string()), "{tables:?}");
    let first = browse_page(&state, "signins", &[], None, 0, 5).unwrap();
    assert!(!first.rows.is_empty() && first.total > 1, "{}", first.total);
    // A filter on the first non-null text cell of the first row.
    let (col, value) = first
        .columns
        .iter()
        .enumerate()
        .find_map(|(i, c)| match &first.rows[0][i] {
            serde_json::Value::String(s) if !s.is_empty() => Some((c.clone(), s.clone())),
            _ => None,
        })
        .expect("a text cell");
    let filters = vec![Filter::Eq {
        column: col,
        value: serde_json::Value::String(value),
    }];
    let got = browse_page(&state, "signins", &filters, None, 0, 500).unwrap();
    let want = with_case(&state, |open| {
        Ok(browse::page(
            open.case.conn(),
            "signins",
            &filters,
            None,
            0,
            500,
        )?)
    })
    .unwrap();
    assert!(got.total >= 1);
    assert_eq!(
        (got.total, got.total_capped, got.rows.len()),
        (want.total, want.total_capped, want.rows.len())
    );
    assert_eq!(got.rows, want.rows);
    // Paging goes through too.
    let second = browse_page(&state, "signins", &[], None, 2, 2).unwrap();
    assert_eq!(second.offset, 2);
    assert_eq!(second.rows.len(), 2);
    // Refusals are core's: an unknown table or column is invalid, never SQL.
    let e = browse_page(&state, "findings; DROP TABLE findings", &[], None, 0, 5).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    let bad = vec![Filter::IsNull {
        column: "nope".into(),
    }];
    assert_eq!(
        browse_page(&state, "signins", &bad, None, 0, 5)
            .unwrap_err()
            .kind,
        "invalid"
    );
    assert_eq!(
        browse_page(&AppState::default(), "signins", &[], None, 0, 5)
            .unwrap_err()
            .kind,
        "no_case"
    );
}

#[test]
fn indicators_active_lists_malicious_and_suspicious_only() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let me = analyst(&state).unwrap();
    with_writable(&state, |open| {
        let add = |ty: &str, value: &str, verdict: &str| {
            add_indicator(
                open.case.conn(),
                &me.as_actor(),
                None,
                IndicatorType::parse(ty).unwrap(),
                value,
                Verdict::parse(verdict).unwrap(),
                None,
            )
        };
        add("ip", "203.0.113.50", "malicious")?;
        add("ip", "203.0.113.51", "benign")?;
        let gone = add("ip", "203.0.113.52", "malicious")?;
        sparrow_core::case::indicators::remove_indicator(open.case.conn(), &me.as_actor(), &gone)?;
        Ok(())
    })
    .unwrap();
    let got = indicators_active(&state).unwrap();
    let find = |v: &str| got.iter().find(|i| i.value == v);
    assert_eq!(find("203.0.113.50").unwrap().verdict, "malicious");
    assert_eq!(find("203.0.113.50").unwrap().ioc_type, "ip");
    assert!(find("203.0.113.51").is_none(), "benign");
    assert!(find("203.0.113.52").is_none(), "removed");
    // The seeded agent-proposed suspicious indicator is listed (not removed).
    let seeded_value: String = with_case(&state, |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                "SELECT value FROM case_indicators WHERE indicator_id = ?",
                [&s.indicator],
                |r| r.get(0),
            )
            .unwrap())
    })
    .unwrap();
    assert_eq!(find(&seeded_value).unwrap().verdict, "suspicious");
    assert!(
        got.iter()
            .all(|i| ["malicious", "suspicious"].contains(&i.verdict.as_str()))
    );
    assert_eq!(
        indicators_active(&AppState::default()).unwrap_err().kind,
        "no_case"
    );
}

fn rule(column: Option<&str>, op: &str, value: &str, colour: &str) -> HighlightRule {
    HighlightRule {
        column: column.map(str::to_string),
        op: op.into(),
        value: value.into(),
        colour: colour.into(),
    }
}

fn set_of(name: &str, rules: Vec<HighlightRule>) -> HighlightSet {
    HighlightSet {
        name: name.into(),
        rules,
    }
}

#[test]
fn highlights_round_trip_with_caps() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("settings");
    let state = state_with_settings(&dir);
    assert!(highlights_get(&state, "case-1").unwrap().is_empty());
    // A hostile value is stored and returned raw (the screen escapes it when drawing).
    let hostile = "<img src=x onerror=alert(1)>\u{202e}\u{0}\n";
    let sets = vec![
        set_of(
            "relay",
            vec![
                rule(Some("ip"), "eq", "203.0.113.9", "red"),
                rule(None, "contains", hostile, "amber"),
            ],
        ),
        set_of("empty", vec![]),
    ];
    assert_eq!(
        highlights_set(&state, "case-1", sets.clone()).unwrap(),
        sets
    );
    assert_eq!(highlights_get(&state, "case-1").unwrap(), sets);
    // Per case id, and it survives a restart (a new state over the same directory).
    let other = vec![set_of("other", vec![rule(None, "eq", "x", "blue")])];
    highlights_set(&state, "case-2", other.clone()).unwrap();
    let restarted = state_with_settings(&dir);
    assert_eq!(highlights_get(&restarted, "case-1").unwrap(), sets);
    assert_eq!(highlights_get(&restarted, "case-2").unwrap(), other);
    // The settings keep their shape: highlights are not part of them.
    let v = serde_json::to_value(settings_get(&state).unwrap()).unwrap();
    assert_eq!(
        v.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["analyst", "recent"]
    );
    // Clear removes one case only.
    highlights_clear(&state, "case-1").unwrap();
    assert!(highlights_get(&state, "case-1").unwrap().is_empty());
    assert_eq!(highlights_get(&state, "case-2").unwrap(), other);
    highlights_clear(&state, "never-set").unwrap();

    // Caps: 50 sets / 100 rules / 1 KiB values; the limits themselves are fine.
    let n_sets = |n: usize| {
        (0..n)
            .map(|i| set_of(&format!("s{i}"), vec![]))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        highlights_set(&state, "caps", n_sets(50)).unwrap().len(),
        50
    );
    assert_eq!(
        highlights_set(&state, "caps", n_sets(51)).unwrap_err().kind,
        "invalid"
    );
    assert_eq!(
        highlights_get(&state, "caps").unwrap().len(),
        50,
        "a refused set stores nothing"
    );
    let n_rules = |n: usize| {
        vec![set_of(
            "r",
            (0..n).map(|_| rule(None, "eq", "v", "green")).collect(),
        )]
    };
    assert!(highlights_set(&state, "caps", n_rules(100)).is_ok());
    assert_eq!(
        highlights_set(&state, "caps", n_rules(101))
            .unwrap_err()
            .kind,
        "invalid"
    );
    let valued = |len: usize| {
        vec![set_of(
            "v",
            vec![rule(None, "eq", &"é".repeat(len / 2), "purple")],
        )]
    };
    assert!(highlights_set(&state, "caps", valued(1024)).is_ok());
    assert_eq!(
        highlights_set(&state, "caps", valued(1026))
            .unwrap_err()
            .kind,
        "invalid"
    );
    // Enums and names.
    for bad in [
        vec![set_of("c", vec![rule(None, "eq", "v", "pink")])],
        vec![set_of("c", vec![rule(None, "regex", "v", "red")])],
        vec![set_of("", vec![])],
        vec![set_of("bad\nname", vec![])],
        vec![set_of(&"n".repeat(101), vec![])],
        vec![set_of("c", vec![rule(Some(""), "eq", "v", "red")])],
        vec![set_of("c", vec![rule(Some("a\u{0}b"), "eq", "v", "red")])],
    ] {
        assert_eq!(
            highlights_set(&state, "caps", bad).unwrap_err().kind,
            "invalid"
        );
    }
    for bad_id in ["", "a\nb"] {
        assert_eq!(highlights_get(&state, bad_id).unwrap_err().kind, "invalid");
        assert_eq!(
            highlights_set(&state, bad_id, vec![]).unwrap_err().kind,
            "invalid"
        );
    }
    // Without a settings directory (no app config) the commands say so instead of losing the data.
    assert_eq!(
        highlights_get(&AppState::default(), "c").unwrap_err().kind,
        "internal"
    );
}

/// The M3 fixtures: pivot, a filtered browse page, a SQL result, the schema, a share preview and the active
/// indicators, from the seeded synthetic case (two copies for the share).
fn record_m3_fixtures(tmp: &Path) -> Vec<(String, serde_json::Value)> {
    let (a, b) = two_apps(&tmp.join("m3"), "ann", "bob");
    confirm_findings(&a, 2);
    let file = tmp.join("m3-work.sparrow-share.json");
    share_export(&a, &file).unwrap();
    let preview = share_preview(&b, &file).unwrap();
    // The case with an indicator in it, for the pivot and the highlight set.
    let me = analyst(&a).unwrap();
    let (upn, ip): (String, String) = with_case(&a, |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                "SELECT f.actor_upn, t.ip FROM findings f JOIN timeline t ON lower(t.actor_upn) = lower(f.actor_upn) \
                 WHERE t.ip IS NOT NULL ORDER BY f.finding_id, t.event_time LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap())
    })
    .unwrap();
    with_writable(&a, |open| {
        add_indicator(
            open.case.conn(),
            &me.as_actor(),
            None,
            IndicatorType::parse("ip").unwrap(),
            &ip,
            Verdict::parse("malicious").unwrap(),
            Some("relay"),
        )?;
        Ok(())
    })
    .unwrap();
    let signins = browse_page(&a, "signins", &[], None, 0, 5).unwrap();
    let (col, value) = signins
        .columns
        .iter()
        .enumerate()
        .find_map(|(i, c)| match &signins.rows[0][i] {
            serde_json::Value::String(s) if !s.is_empty() => Some((c.clone(), s.clone())),
            _ => None,
        })
        .expect("a text cell");
    let filters = vec![Filter::Eq {
        column: col,
        value: serde_json::Value::String(value),
    }];
    let page = browse_page(&a, "signins", &filters, None, 0, 20).unwrap();
    let json = |v: &dyn erased::Ser| v.value();
    vec![
        ("pivot_ip.json".into(), json(&pivot_ip(&a, &ip, Some(20)).unwrap())),
        ("pivot_user.json".into(), json(&pivot_user(&a, &upn, Some(20)).unwrap())),
        ("browse_page.json".into(), json(&page)),
        (
            "sql_result.json".into(),
            json(&sql_run(&a, "SELECT rule_id, severity, count(*) AS n FROM findings GROUP BY ALL ORDER BY ALL", None).unwrap()),
        ),
        ("schema.json".into(), json(&sql_schema(&a, None).unwrap())),
        ("share_preview.json".into(), json(&preview)),
        ("indicators.json".into(), json(&indicators_active(&a).unwrap())),
    ]
}

mod erased {
    pub trait Ser {
        fn value(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn value(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap()
        }
    }
}

#[test]
fn a_damaged_highlights_file_is_an_error_and_is_left_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("settings");
    let state = state_with_settings(&dir);
    let sets = vec![set_of(
        "relay",
        vec![rule(None, "eq", "203.0.113.9", "red")],
    )];
    highlights_set(&state, "case-1", sets).unwrap();
    let file = dir.join("highlights.json");
    let whole = std::fs::read(&file).unwrap();
    let truncated = &whole[..whole.len() / 2];
    std::fs::write(&file, truncated).unwrap();
    for e in [
        highlights_get(&state, "case-1").unwrap_err(),
        highlights_set(&state, "case-2", vec![]).unwrap_err(),
        highlights_clear(&state, "case-1").unwrap_err(),
    ] {
        assert_eq!(e.kind, "internal", "{e:?}");
        assert!(e.message.contains("highlights.json"), "{}", e.message);
    }
    assert_eq!(
        std::fs::read(&file).unwrap(),
        truncated,
        "the file is not rewritten"
    );
    // Only a missing file means "none yet".
    std::fs::remove_file(&file).unwrap();
    assert!(highlights_get(&state, "case-1").unwrap().is_empty());
    highlights_set(&state, "case-2", vec![]).unwrap();
}

// ---- a cancel that overtakes its query ----

#[test]
fn a_cancel_before_the_query_registers_makes_it_return_interrupted_without_running() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let (result, after_release) = std::thread::scope(|scope| {
        let mut runner = None;
        // The case lock is held here, so the query waits for it.
        with_case(&state, |_| {
            runner = Some(scope.spawn(|| sql_run_id(&state, LONG, None, "p-1")));
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !runner.as_ref().unwrap().is_finished(),
                "it must be waiting"
            );
            assert!(state.active.lock().unwrap().is_none(), "not registered yet");
            query_cancel(&state, "p-1").unwrap();
            Ok(())
        })
        .unwrap();
        let released = std::time::Instant::now();
        let r = runner.unwrap().join().unwrap();
        (r, released.elapsed())
    });
    let e = result.unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
    // LONG would run for minutes: it never ran.
    assert!(
        after_release < std::time::Duration::from_secs(2),
        "{after_release:?}"
    );
    assert!(state.active.lock().unwrap().is_none());
    assert!(
        state.cancelled.lock().unwrap().is_empty(),
        "the record is consumed"
    );
    // The id is free again, and the case is usable.
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "p-1")
            .unwrap()
            .rows
            .len(),
        1
    );
    // A browse page behaves the same.
    query_cancel(&state, "p-2").unwrap();
    let e = browse_page_id(&state, "signins", &[], None, 0, 5, "p-2").unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
    assert_eq!(
        browse_page_id(&state, "signins", &[], None, 0, 5, "p-2")
            .unwrap()
            .rows
            .len(),
        5
    );
}

#[test]
fn a_cancel_recorded_for_a_previous_case_generation_does_not_block_a_new_run() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    query_cancel(&state, "g-1").unwrap();
    assert_eq!(state.cancelled.lock().unwrap().len(), 1);
    // Reopening forgets it.
    let again = tmp.path().join("again");
    std::fs::create_dir_all(&again).unwrap();
    case_open(&state, &case_file(&again), false).unwrap();
    assert!(state.cancelled.lock().unwrap().is_empty());
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "g-1")
            .unwrap()
            .rows
            .len(),
        1
    );
    // Even a stale record that survived (an older generation tag) is ignored.
    let old = state.generation.load(std::sync::atomic::Ordering::SeqCst) - 1;
    state
        .cancelled
        .lock()
        .unwrap()
        .push_back((old, "g-2".into()));
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "g-2")
            .unwrap()
            .rows
            .len(),
        1
    );
    // Closing forgets too.
    query_cancel(&state, "g-3").unwrap();
    case_close(&state).unwrap();
    assert!(state.cancelled.lock().unwrap().is_empty());
}

#[test]
fn the_remembered_cancels_never_grow_past_their_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let cap = sparrow_app::state::MAX_PENDING_CANCELS;
    assert_eq!(cap, 64);
    for n in 0..(cap * 3) {
        query_cancel(&state, &format!("c-{n}")).unwrap();
        assert!(state.cancelled.lock().unwrap().len() <= cap);
    }
    // The same id twice is one record.
    query_cancel(&state, &format!("c-{}", cap * 3 - 1)).unwrap();
    let ids: Vec<String> = state
        .cancelled
        .lock()
        .unwrap()
        .iter()
        .map(|(_, i)| i.clone())
        .collect();
    assert_eq!(ids.len(), cap);
    assert_eq!(ids.last().unwrap(), &format!("c-{}", cap * 3 - 1));
    assert_eq!(ids.first().unwrap(), &format!("c-{}", cap * 2));
    // The newest still cancels its query; the forgotten oldest does not.
    let e = sql_run_id(&state, "SELECT 1", None, &format!("c-{}", cap * 3 - 1)).unwrap_err();
    assert_eq!(e.kind, "interrupted");
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "c-0")
            .unwrap()
            .rows
            .len(),
        1
    );
}

// ---- round 2: a cancel between registration and execution; a case switch while queued ----

#[test]
fn a_cancel_after_registration_but_before_execution_still_stops_the_query() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let started = std::time::Instant::now();
    // The closure runs after registration; the cancel lands before the query starts (an idle connection).
    let e = sparrow_app::state::with_cancellable(&state, state.ticket(), "r-1", |open| {
        query_cancel(&state, "r-1").unwrap();
        direct(open, LONG)
    })
    .unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(state.active.lock().unwrap().is_none());
    // A query that finishes anyway has its result discarded.
    let r = sparrow_app::state::with_cancellable(&state, state.ticket(), "r-2", |open| {
        query_cancel(&state, "r-2").unwrap();
        direct(open, "SELECT 1")
    });
    assert_eq!(r.unwrap_err().kind, "interrupted");
    // Nothing is left interrupting: the case is fully usable, a normal run is not affected, and a write works.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "r-3")
            .unwrap()
            .rows
            .len(),
        1
    );
    let slow = sql_run_id(
        &state,
        "SELECT (sum(hash(a)) % 7)::BIGINT FROM range(300000000) a",
        None,
        "r-4",
    );
    assert!(slow.is_ok(), "{slow:?}");
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "timeline_entry", &s.entry).decision_seq;
    review_accept(&state, "timeline_entry", &s.entry, seq, None).unwrap();
    with_case(&state, |open| {
        open.case.ensure_usable()?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn requests_queued_for_a_case_that_is_then_replaced_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let b_dir = tmp.path().join("b");
    std::fs::create_dir_all(&b_dir).unwrap();
    let b = case_file(&b_dir);
    let queue = review_queue(&state).unwrap();
    let seq = decision(&queue, "timeline_entry", &s.entry).decision_seq;
    let audit_a = rows(&state, "SELECT count(*) FROM audit_trail");
    let (sql, accept, opened) = std::thread::scope(|scope| {
        let (mut q, mut w, mut o) = (None, None, None);
        let g0 = state.generation.load(std::sync::atomic::Ordering::SeqCst);
        // The case lock is held while both requests are submitted for case A and the switch to B is requested.
        with_case(&state, |_| {
            q = Some(scope.spawn(|| sql_run_id(&state, "SELECT 1 AS one", None, "n-1")));
            w = Some(scope.spawn(|| review_accept(&state, "timeline_entry", &s.entry, seq, None)));
            std::thread::sleep(std::time::Duration::from_millis(300));
            o = Some(scope.spawn(|| case_open(&state, &b, false)));
            // Wait until the switch has been requested (it is queued behind the lock too).
            let t = std::time::Instant::now();
            while state.generation.load(std::sync::atomic::Ordering::SeqCst) == g0 {
                assert!(t.elapsed() < std::time::Duration::from_secs(10));
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(())
        })
        .unwrap();
        (
            q.unwrap().join().unwrap(),
            w.unwrap().join().unwrap(),
            o.unwrap().join().unwrap(),
        )
    });
    opened.unwrap();
    let e = sql.unwrap_err();
    assert_eq!(e.kind, "no_case", "{e:?}");
    assert!(
        e.message.contains("changed while this request was waiting"),
        "{}",
        e.message
    );
    let e = accept.unwrap_err();
    assert_eq!(e.kind, "no_case", "{e:?}");
    // Nothing ran on B (no audit rows beyond a fresh case's), and A was not written either.
    let on_b = rows(&state, "SELECT count(*) FROM audit_trail");
    assert!(on_b <= audit_a, "B is a fresh copy: {on_b} vs {audit_a}");
    assert_eq!(
        rows(
            &state,
            "SELECT count(*) FROM audit_trail WHERE action = 'accept'"
        ),
        0
    );
    // A genuinely new request after the switch is unaffected.
    assert_eq!(
        sql_run_id(&state, "SELECT 1 AS one", None, "n-2")
            .unwrap()
            .rows
            .len(),
        1
    );
    assert!(review_queue(&state).is_ok());
    // Closing refuses queued requests the same way.
    let closed = std::thread::scope(|scope| {
        let (mut q, mut c) = (None, None);
        let g0 = state.generation.load(std::sync::atomic::Ordering::SeqCst);
        with_case(&state, |_| {
            q = Some(scope.spawn(|| accounts_for_test(&state)));
            std::thread::sleep(std::time::Duration::from_millis(300));
            c = Some(scope.spawn(|| case_close(&state)));
            while state.generation.load(std::sync::atomic::Ordering::SeqCst) == g0 {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(())
        })
        .unwrap();
        c.unwrap().join().unwrap().unwrap();
        q.unwrap().join().unwrap()
    });
    assert_eq!(closed.unwrap_err().kind, "no_case");
}

fn accounts_for_test(state: &AppState) -> sparrow_app::CmdResult<()> {
    sparrow_app::cmd::accounts::accounts_list(state, None).map(|_| ())
}

#[test]
fn evidence_filter_resolves_ual_and_record_key_tables_to_one_row() {
    use sparrow_app::cmd::browse::evidence_filter;
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    // A real record key from each of a UAL table and a record_key table.
    let (ual_col, signin_col) = ("record_id", "record_key");
    let cell = |table: &str, col: &str| {
        with_case(&state, |open| {
            let sql = format!("SELECT CAST({col} AS VARCHAR) FROM {table} LIMIT 1");
            Ok(open
                .case
                .conn()
                .query_row(&sql, [], |r| r.get::<_, String>(0))
                .map_err(sparrow_core::Error::from)?)
        })
        .unwrap()
    };
    for (table, col) in [("ual_events", ual_col), ("signins", signin_col)] {
        let key = cell(table, col);
        let target = evidence_filter(&state, table, &key).unwrap();
        assert_eq!(target.table, table);
        let page = browse_page(&state, table, &target.filters, None, 0, 10).unwrap();
        assert_eq!(page.total, 1, "{table}:{key}");
    }
    let e = evidence_filter(&state, "no_such_table", "k").unwrap_err();
    assert_eq!(serde_json::to_value(&e).unwrap()["kind"], "invalid");
}
