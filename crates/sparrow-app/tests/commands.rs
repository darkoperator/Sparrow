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
            0,
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
            end_time: None,
            event_count: None,
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
    let devices = sparrow_app::cmd::devices::devices_list(&state, None).unwrap();
    assert!(
        !devices.is_empty(),
        "the synthetic case has a suspect device"
    );
    write(
        "devices_recorded.json",
        serde_json::to_value(&devices).unwrap(),
    );
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
                end_time: None,
                event_count: None,
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

use sparrow_app::cmd::devices::devices_list;

#[test]
fn devices_list_matches_core() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let list = devices_list(&state, None).unwrap();
    let core = with_case(&state, |open| {
        Ok(sparrow_core::case::devices::suspect_devices(
            open.case.conn(),
            None,
        )?)
    })
    .unwrap();
    assert!(!core.is_empty(), "the synthetic case has a suspect device");
    assert_eq!(
        serde_json::to_value(&list).unwrap(),
        serde_json::to_value(&core).unwrap()
    );
    // A tenant filter reaches core.
    assert!(
        devices_list(&state, Some("no-such-tenant"))
            .unwrap()
            .is_empty()
    );
    let tenant = list[0].tenant_key.clone().unwrap();
    let one = devices_list(&state, Some(&tenant)).unwrap();
    assert!(!one.is_empty() && one.iter().all(|d| d.tenant_key.as_deref() == Some(&tenant)));
}

#[test]
fn devices_need_an_open_case() {
    let e = devices_list(&AppState::default(), None).unwrap_err();
    assert_eq!(e.kind, "no_case");
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

// ---- M3: browse, SQL with cancel, indicators, share files, highlights ----

use sparrow_app::cmd::browse::{browse_page as browse_page_id, browse_tables};
use sparrow_app::cmd::indicators::indicators_active;
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
    // and SQL / browse work on it; share_import and the other writes are refused as read_only.
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

/// The M3 fixtures: a filtered browse page, a SQL result, the schema, a share preview and the active
/// indicators, from the seeded synthetic case (two copies for the share).
fn record_m3_fixtures(tmp: &Path) -> Vec<(String, serde_json::Value)> {
    let (a, b) = two_apps(&tmp.join("m3"), "ann", "bob");
    confirm_findings(&a, 2);
    let file = tmp.join("m3-work.sparrow-share.json");
    share_export(&a, &file).unwrap();
    let preview = share_preview(&b, &file).unwrap();
    // The case with an indicator in it, for the highlight set.
    let me = analyst(&a).unwrap();
    let ip: String = with_case(&a, |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                "SELECT t.ip FROM findings f JOIN timeline t ON lower(t.actor_upn) = lower(f.actor_upn) \
                 WHERE t.ip IS NOT NULL ORDER BY f.finding_id, t.event_time LIMIT 1",
                [],
                |r| r.get(0),
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

// ---- SQL features: check, paging, CSV export ----

use sparrow_app::cmd::sql::{sql_check, sql_export_csv, sql_export_csv_capped, sql_run_page};
use sparrow_app::state::with_cancellable_commit;
use sparrow_core::case::query::{CheckKind, Exported};

/// The UTF-16 offsets of the last `needle` in `s` and of its end.
fn span16(s: &str, needle: &str) -> (usize, usize) {
    let b = s.rfind(needle).unwrap();
    let from = s[..b].encode_utf16().count();
    (from, from + needle.encode_utf16().count())
}

#[test]
fn sql_check_marks_the_wrong_part_of_the_users_text() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let cases = [
        (
            "SELECT 'ünïcødé 😀',\n       rule_idd\nFROM findings",
            "rule_idd",
            CheckKind::Binder,
            "rule_id",
        ),
        (
            "-- 日本語\nSELECT *\nFROM finding",
            "finding",
            CheckKind::Catalog,
            "findings",
        ),
        ("SELECT '😀😀', FROM WHERE", "WHERE", CheckKind::Syntax, ""),
    ];
    let mut checked = 0;
    for (sql, token, kind, suggestion) in cases {
        let c = sql_check(&state, sql).unwrap();
        let e = c.error.as_ref().unwrap();
        assert!(!c.ok);
        assert_eq!(e.kind, kind, "{sql:?}: {e:?}");
        let (from, to) = span16(sql, token);
        assert_eq!((e.from, e.to), (Some(from), Some(to)), "{sql:?}: {e:?}");
        if !suggestion.is_empty() {
            assert!(e.suggestions.iter().any(|s| s == suggestion), "{e:?}");
        }
        checked += 1;
    }
    assert_eq!(checked, 3);
    // The wire shape: camelCase-free fields, lowercase kind, absent offsets omitted.
    let v = serde_json::to_value(sql_check(&state, "SELECT nope FROM findings").unwrap()).unwrap();
    assert_eq!(v["ok"], false);
    assert_eq!(v["error"]["kind"], "binder");
    assert!(v["error"]["from"].is_u64() && v["error"]["suggestions"].is_array());
    let v = serde_json::to_value(sql_check(&state, "SELECT 1; SELECT 2").unwrap()).unwrap();
    assert_eq!(v["error"]["kind"], "syntax");
    assert!(v["error"].get("from").is_none(), "{v}");
    assert_eq!(
        serde_json::to_value(sql_check(&state, "SELECT count(*) FROM findings").unwrap()).unwrap(),
        serde_json::json!({ "ok": true })
    );
    let big = format!("SELECT '{}'", "x".repeat(2 * 1024 * 1024));
    assert_eq!(sql_check(&state, &big).unwrap_err().kind, "invalid");
    assert_eq!(
        sql_check(&AppState::default(), "SELECT 1")
            .unwrap_err()
            .kind,
        "no_case"
    );
}

#[test]
fn sql_check_never_executes() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let started = std::time::Instant::now();
    assert!(sql_check(&state, LONG).unwrap().ok);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let boom = "SELECT CASE WHEN i = 2 THEN error('boom') ELSE 'x' END AS v FROM range(3) t(i)";
    assert!(sql_check(&state, boom).unwrap().ok);
    assert!(sql_run(&state, boom, None).is_err());
    // The case is usable and not left in a transaction.
    assert_eq!(
        sql_run(&state, "SELECT 1 AS one", None).unwrap().rows.len(),
        1
    );
}

#[test]
fn sql_run_pages_are_slices_of_an_ordered_query() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let sql = "SELECT i, hash(i) AS h FROM range(5000) t(i) ORDER BY h, i";
    let all = sql_run(&state, sql, Some(3000)).unwrap();
    assert!(all.ordered);
    let mut checked = 0;
    for page in 0..3usize {
        let p = sql_run_page(&state, sql, Some(1000), "p", Some(page * 1000)).unwrap();
        assert!(p.ordered);
        assert_eq!(
            p.rows[..],
            all.rows[page * 1000..(page + 1) * 1000],
            "page {page}"
        );
        checked += p.rows.len();
    }
    assert_eq!(checked, 3000);
    let tail = sql_run_page(&state, sql, Some(1000), "p", Some(4500)).unwrap();
    assert_eq!((tail.rows.len(), tail.truncated), (500, false));
    assert!(
        !sql_run(&state, "SELECT finding_id FROM findings", None)
            .unwrap()
            .ordered
    );
    assert!(
        sql_run(&state, "SELECT finding_id FROM findings ORDER BY 1", None)
            .unwrap()
            .ordered
    );
    let e = sql_run_page(&state, sql, None, "p", Some(100_000_001)).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(
        sql_run_page(&state, sql, None, "p", Some(100_000_000))
            .unwrap()
            .rows
            .is_empty()
    );
}

fn read_csv(path: &Path) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(path).unwrap();
    let text = text.strip_prefix('\u{feff}').unwrap();
    let mut r = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(text.as_bytes());
    r.records()
        .map(|x| x.unwrap().iter().map(String::from).collect())
        .collect()
}

#[test]
fn sql_export_csv_writes_the_whole_result_capped() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let n = rows(&state, "SELECT count(*) FROM findings");
    assert!(n > 3, "{n}");
    let sql = "SELECT finding_id, rule_id FROM findings ORDER BY finding_id";
    let out = tmp.path().join("all.csv");
    let e = sql_export_csv(&state, sql, &out, "x").unwrap();
    assert_eq!(
        e,
        Exported {
            rows: n as u64,
            capped: false
        }
    );
    let got = read_csv(&out);
    assert_eq!(got[0], ["finding_id", "rule_id"]);
    assert_eq!(got.len() as i64, n + 1);
    let first: Vec<String> = sql_run(&state, sql, Some(1)).unwrap().rows[0]
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(got[1], first);
    // A small injected cap.
    let capped = tmp.path().join("capped.csv");
    let e = sql_export_csv_capped(&state, sql, &capped, "x", 3).unwrap();
    assert_eq!(
        e,
        Exported {
            rows: 3,
            capped: true
        }
    );
    assert_eq!(read_csv(&capped).len(), 4);
    let exact = sql_export_csv_capped(&state, sql, &capped, "x", n as u64).unwrap();
    assert_eq!(
        exact,
        Exported {
            rows: n as u64,
            capped: false
        }
    );
    // Formula neutralisation, like the timeline CSV; numbers and timestamps as they are.
    let f = tmp.path().join("f.csv");
    sql_export_csv(
        &state,
        "SELECT '=HYPERLINK(\"http://x\")' AS \"+h\", '@SUM(1)' AS a, -3 AS n, \
         TIMESTAMP '2026-08-14 10:00:00' AS ts, 'a=b' AS m",
        &f,
        "x",
    )
    .unwrap();
    assert_eq!(
        read_csv(&f),
        vec![
            vec!["'+h", "a", "n", "ts", "m"],
            vec![
                "'=HYPERLINK(\"http://x\")",
                "'@SUM(1)",
                "-3",
                "2026-08-14T10:00:00.000000Z",
                "a=b"
            ],
        ]
    );
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn sql_export_csv_refuses_the_case_and_bad_queries_and_leaves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, s) = open_seeded(tmp.path());
    let before = std::fs::read(&s.path).unwrap();
    let wal = PathBuf::from(format!("{}.wal", s.path.display()));
    let upper = s
        .path
        .with_file_name(s.path.file_name().unwrap().to_string_lossy().to_uppercase());
    for target in [&s.path, &wal, &upper] {
        let e = sql_export_csv(&state, "SELECT 1", target, "x").unwrap_err();
        assert_eq!(e.kind, "invalid", "{target:?}: {e:?}");
    }
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
    let out = tmp.path().join("bad.csv");
    for bad in [
        "DELETE FROM findings",
        "SELECT nope FROM findings",
        "SELECT 1; SELECT 2",
    ] {
        assert!(sql_export_csv(&state, bad, &out, "x").is_err(), "{bad}");
        assert!(!out.exists());
    }
    let e = sql_export_csv(
        &state,
        "SELECT 1",
        &tmp.path().join("no-such-dir/x.csv"),
        "x",
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid");
    let big = format!("SELECT '{}'", "x".repeat(2 * 1024 * 1024));
    assert_eq!(
        sql_export_csv(&state, &big, &out, "x").unwrap_err().kind,
        "invalid"
    );
    assert_eq!(
        sql_export_csv(&state, "SELECT 1", &out, "bad\nid")
            .unwrap_err()
            .kind,
        "invalid"
    );
    assert!(leftovers(tmp.path()).is_empty());
    assert_eq!(std::fs::read(&s.path).unwrap(), before);
}

#[test]
fn a_cancelled_sql_export_leaves_no_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    let out = tmp.path().join("long.csv");
    let (result, took) = cancelling(
        || sql_export_csv(&state, LONG, &out, "e-1"),
        || query_cancel(&state, "e-1").unwrap(),
        std::time::Duration::from_secs(30),
    );
    let e = result.unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
    assert!(took < std::time::Duration::from_secs(2), "{took:?}");
    assert!(!out.exists());
    assert!(leftovers(tmp.path()).is_empty());
    assert!(state.active.lock().unwrap().is_none());
    // The case is usable, and the next export works.
    let e = sql_export_csv(&state, "SELECT 1 AS one", &out, "e-2").unwrap();
    assert_eq!(
        e,
        Exported {
            rows: 1,
            capped: false
        }
    );
    assert_eq!(read_csv(&out), vec![vec!["one"], vec!["1"]]);
}

#[test]
fn a_cancel_decides_the_commit_once() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = open_seeded(tmp.path());
    // Cancelled before the commit: the visible step never runs.
    let mut ran = false;
    let r = with_cancellable_commit(&state, state.ticket(), "c-1", |_, commit| {
        query_cancel(&state, "c-1").unwrap();
        commit.commit(|| {
            ran = true;
            Ok(())
        })
    });
    assert_eq!(r.unwrap_err().kind, "interrupted");
    assert!(!ran);
    // Cancelled after the commit: the result stands (the file exists), not `interrupted`.
    let r = with_cancellable_commit(&state, state.ticket(), "c-2", |_, commit| {
        let v = commit.commit(|| Ok(7))?;
        query_cancel(&state, "c-2").unwrap();
        Ok(v)
    });
    assert_eq!(r.unwrap(), 7);
    // Without a commit, a late cancel still discards the result.
    let r = with_cancellable_commit(&state, state.ticket(), "c-3", |_, _| {
        query_cancel(&state, "c-3").unwrap();
        Ok(1)
    });
    assert_eq!(r.unwrap_err().kind, "interrupted");
}

// ---- events grid, entity tabs, marks and add-to-timeline ----

use chrono::{DateTime, SecondsFormat, Utc};
use sparrow_app::cmd::entity::{entity_coverage, entity_findings, entity_pivot, entity_summary};
use sparrow_app::cmd::events::{
    EntityArg, EntityKind, EventQueryArgs, events_detail, events_export_csv, events_histogram,
    events_page, events_suggest, events_summary,
};
use sparrow_app::cmd::marks::{
    marks_flag_rows, marks_flag_value, marks_list_tags, marks_review, marks_tag_rows,
    notes_add_rows,
};
use sparrow_app::cmd::timeline::{AddEventsArgs, AddMode, EACH_MAX, timeline_add_events};
use sparrow_core::case::entity::PivotOf;
use sparrow_core::case::events::{self, AiFilter, Entity, Field, FlagFilter};
use sparrow_core::case::marks::{self, FlagLevel, RowRef, TagRef, ValueKind};

fn iso(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn text_of(state: &AppState, sql: &str) -> String {
    with_case(state, |open| {
        Ok(open.case.conn().query_row(sql, [], |r| r.get(0)).unwrap())
    })
    .unwrap()
}

fn by_source(source: &str) -> EventQueryArgs {
    EventQueryArgs {
        fields: vec![(Field::Source, source.into())],
        ..EventQueryArgs::default()
    }
}

fn first_rows(state: &AppState, q: &EventQueryArgs, n: usize) -> Vec<RowRef> {
    events_page(state, q, None, 0, n, None)
        .unwrap()
        .rows
        .iter()
        .map(|r| RowRef::new(&r.source_table, &r.record_key))
        .collect()
}

fn audit_rows(state: &AppState) -> i64 {
    rows(state, "SELECT count(*) FROM audit_trail")
}

fn entity_arg(kind: EntityKind, value: &str) -> EntityArg {
    EntityArg {
        kind,
        value: value.into(),
    }
}

/// An account, IP, device and session that have many events in the synthetic case.
struct Picked {
    account: String,
    ip: String,
    device: String,
    session: String,
}

fn picked(state: &AppState) -> Picked {
    let top = |col: &str| {
        text_of(
            state,
            &format!(
                "SELECT {col} FROM events WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 1"
            ),
        )
    };
    Picked {
        account: top("actor_upn"),
        ip: top("ip"),
        device: top("device_id"),
        session: top("entra_session_id"),
    }
}

#[test]
fn events_page_summary_histogram_detail_and_suggest_read_the_events_table() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let total = rows(&state, "SELECT count(*) FROM events") as u64;
    assert!(total > 1000, "{total}");
    let all = EventQueryArgs::default();

    // A page: newest first, a total that is the whole table, the next page does not repeat.
    let page = events_page(&state, &all, None, 0, 5, None).unwrap();
    assert_eq!((page.rows.len(), page.offset, page.total), (5, 0, total));
    assert!(!page.total_capped);
    let newest = rows(&state, "SELECT max(epoch_us(event_time)) FROM events");
    assert_eq!(page.rows[0].event_time.unwrap().timestamp_micros(), newest);
    assert!(
        page.rows
            .windows(2)
            .all(|w| w[0].event_time >= w[1].event_time)
    );
    let next = events_page(&state, &all, None, 5, 5, None).unwrap();
    assert_eq!(next.offset, 5);
    assert!(next.rows.iter().all(|r| !page.rows.contains(r)));
    // A sort travels as given.
    let oldest = events_page(
        &state,
        &all,
        Some(&browse::Sort {
            column: "event_time".into(),
            descending: false,
        }),
        0,
        1,
        None,
    )
    .unwrap();
    assert_eq!(
        oldest.rows[0].event_time.unwrap().timestamp_micros(),
        rows(&state, "SELECT min(epoch_us(event_time)) FROM events")
    );
    assert_eq!(
        events_page(
            &state,
            &all,
            Some(&browse::Sort {
                column: "no_such_column".into(),
                descending: false
            }),
            0,
            1,
            None
        )
        .unwrap_err()
        .kind,
        "invalid"
    );

    // The summary bar and the histogram count the same events.
    let summary = events_summary(&state, &all, None).unwrap();
    assert_eq!(summary.total, total);
    assert_eq!(
        summary.per_source.iter().map(|(_, n)| n).sum::<u64>(),
        total
    );
    assert_eq!(summary.hidden_trace_events, 0);
    let h = events_histogram(&state, &all, 12, None).unwrap();
    // The case spans 41 days, so even a day is more than 12 buckets: the largest bucket size is used.
    assert_eq!((h.bucket_seconds, h.series[0].1.len()), (86_400, 41));
    let per_bucket = h.series[0].1.len();
    let finer = events_histogram(&state, &all, 100, None).unwrap();
    assert_eq!(finer.bucket_seconds, 43_200);
    assert!(finer.series[0].1.len() <= 100);
    assert!(h.series.iter().all(|(_, c)| c.len() == per_bucket));
    assert_eq!(
        h.series.iter().flat_map(|(_, c)| c).sum::<u64>(),
        total,
        "every event is in exactly one bucket"
    );
    assert_eq!(
        events_histogram(&state, &all, 0, None).unwrap_err().kind,
        "invalid"
    );
    // The bucket count asked for is bounded: 0 is refused, and anything over 500 is 500 (a case-wide range here would
    // otherwise allow minute buckets). 500, 501 and usize::MAX give the identical histogram: 3-hour buckets (321).
    let at_cap = events_histogram(&state, &all, 500, None).unwrap();
    assert_eq!(
        (at_cap.bucket_seconds, at_cap.series[0].1.len()),
        (10_800, 321)
    );
    for over in [501, 100_000, usize::MAX] {
        let h = events_histogram(&state, &all, over, None).unwrap();
        assert_eq!(
            (h.bucket_seconds, &h.series),
            (at_cap.bucket_seconds, &at_cap.series),
            "{over}"
        );
    }
    // The boundary below it still works as asked: 1 bucket falls back to a day; 321 is the smallest fit for 3 hours.
    assert_eq!(
        events_histogram(&state, &all, 1, None)
            .unwrap()
            .bucket_seconds,
        86_400
    );
    assert_eq!(
        events_histogram(&state, &all, 321, None)
            .unwrap()
            .bucket_seconds,
        10_800
    );
    assert_eq!(
        events_histogram(&state, &all, 320, None)
            .unwrap()
            .bucket_seconds,
        21_600
    );
    // A wide RFC 3339 range cannot blow past core's hard cap either, even asking for the most.
    let wide = EventQueryArgs {
        from: Some("1900-01-01T00:00:00Z".into()),
        to: Some("2100-01-01T00:00:00Z".into()),
        ..EventQueryArgs::default()
    };
    let h = events_histogram(&state, &wide, usize::MAX, None).unwrap();
    assert!(h.series[0].1.len() <= events::MAX_HISTOGRAM_BUCKETS);
    assert_eq!(h.bucket_seconds % 86_400, 0);

    // One row's detail is the page row plus the stored record.
    let first = &page.rows[0];
    let d = events_detail(&state, &first.source_table, &first.record_key).unwrap();
    assert_eq!(&d.row, first);
    assert!(d.raw.is_object(), "{:?}", d.raw);
    assert!(!d.source_refs.is_empty());
    assert_eq!(
        events_detail(&state, &first.source_table, "no-such-record")
            .unwrap_err()
            .kind,
        "not_found"
    );
    assert_eq!(
        events_detail(&state, "ual", "x").unwrap_err().kind,
        "invalid",
        "not an event table"
    );

    // Suggestions: case-insensitive prefix of the case's own values.
    let account = text_of(
        &state,
        "SELECT actor_upn FROM events WHERE actor_upn IS NOT NULL ORDER BY actor_upn LIMIT 1",
    );
    let prefix = account[..4].to_uppercase();
    let got = events_suggest(&state, Field::Account, &prefix).unwrap();
    assert!(got.contains(&account), "{got:?}");
    assert!(
        got.iter()
            .all(|s| s.to_lowercase().starts_with(&prefix.to_lowercase())),
        "{got:?}"
    );
    assert!(got.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn events_query_args_carry_entity_fields_flags_and_iso_times() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let p = picked(&state);
    let sql_count =
        |pred: &str| rows(&state, &format!("SELECT count(*) FROM events WHERE {pred}")) as u64;

    // The entity in another spelling finds the same events.
    let account = EventQueryArgs {
        entity: Some(entity_arg(EntityKind::Account, &p.account.to_uppercase())),
        ..EventQueryArgs::default()
    };
    let want = sql_count(&format!(
        "actor_upn = '{0}' OR owner_upn = '{0}'",
        p.account
    ));
    assert_eq!(events_summary(&state, &account, None).unwrap().total, want);
    // Filter boxes keep Harrier's text; a source plus a range.
    let ual = by_source("ual");
    assert_eq!(
        events_page(&state, &ual, None, 0, 1, None).unwrap().total,
        sql_count("source = 'ual'")
    );
    let not_ual = by_source("!ual");
    assert_eq!(
        events_page(&state, &not_ual, None, 0, 1, None)
            .unwrap()
            .total,
        sql_count("source <> 'ual'")
    );
    // A time range as ISO text, both ends inclusive: a range of one instant returns the events at it.
    let at = events_page(&state, &EventQueryArgs::default(), None, 40, 1, None)
        .unwrap()
        .rows[0]
        .event_time
        .unwrap();
    let ranged = EventQueryArgs {
        from: Some(iso(&at)),
        to: Some(iso(&at)),
        ..EventQueryArgs::default()
    };
    let at_us = at.timestamp_micros();
    let page = events_page(&state, &ranged, None, 0, 500, None).unwrap();
    assert_eq!(
        page.total,
        sql_count(&format!("epoch_us(event_time) = {at_us}"))
    );
    assert!(page.total >= 1);
    assert!(page.rows.iter().all(|r| r.event_time == Some(at)));
    // Whole-second text without fractions is also RFC 3339.
    let secs = EventQueryArgs {
        from: Some(at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        ..EventQueryArgs::default()
    };
    assert!(events_summary(&state, &secs, None).unwrap().total >= page.total);

    // Flag and AI filters parse, and with no marks they match nothing.
    let flagged = EventQueryArgs {
        flag: FlagFilter::Malicious,
        ai: AiFilter::Marked,
        ..EventQueryArgs::default()
    };
    assert_eq!(events_summary(&state, &flagged, None).unwrap().total, 0);
    assert_eq!(
        events_page(&state, &flagged, None, 0, 5, None)
            .unwrap()
            .rows
            .len(),
        0
    );

    // Bad input is refused, never silently matched: a bad time, a lone `!`, an IP that is not one.
    for (what, q) in [
        (
            "time",
            EventQueryArgs {
                from: Some("yesterday".into()),
                ..EventQueryArgs::default()
            },
        ),
        (
            "to",
            EventQueryArgs {
                to: Some("2026-03-01 10:00:00".into()),
                ..EventQueryArgs::default()
            },
        ),
        ("filter", by_source("!")),
        (
            "entity",
            EventQueryArgs {
                entity: Some(entity_arg(EntityKind::Ip, "not-an-ip")),
                ..EventQueryArgs::default()
            },
        ),
    ] {
        for e in [
            events_page(&state, &q, None, 0, 5, None).unwrap_err(),
            events_summary(&state, &q, None).unwrap_err(),
            events_histogram(&state, &q, 10, None).unwrap_err(),
        ] {
            assert_eq!(e.kind, "invalid", "{what}: {e:?}");
        }
    }
    // The wire shape: camelCase keys, `{kind, value}` entity, `[field, text]` pairs.
    let wire: EventQueryArgs = serde_json::from_value(serde_json::json!({
        "entity": { "kind": "session", "value": "ABC" },
        "fields": [["source", "ual"], ["tag", "x"]],
        "search": "needle",
        "from": "2026-03-01T10:00:00Z",
        "flag": "suspicious",
        "ai": "unreviewed"
    }))
    .unwrap();
    assert_eq!(wire.entity, Some(entity_arg(EntityKind::Session, "ABC")));
    assert_eq!(
        wire.fields,
        vec![(Field::Source, "ual".into()), (Field::Tag, "x".into())]
    );
    assert_eq!(
        (wire.search.as_deref(), wire.flag, wire.ai),
        (Some("needle"), FlagFilter::Suspicious, AiFilter::Unreviewed)
    );
    let q = wire.to_query().unwrap();
    assert_eq!(q.entity, Some(Entity::Session("ABC".into())));
    assert_eq!(q.from.unwrap().timestamp(), 1_772_359_200);
    assert_eq!(q.to, None);
    // An empty object is the whole table.
    let empty: EventQueryArgs = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(empty.fields.is_empty() && empty.entity.is_none());
}

#[test]
fn a_raw_search_needs_a_query_id_and_runs_through_the_cancellable_path() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let p = picked(&state);
    let q = EventQueryArgs {
        search: Some(p.ip.clone()),
        ..EventQueryArgs::default()
    };
    // No id: refused by all four readers, so the UI cannot start a search it cannot cancel.
    let out = tmp.path().join("search.csv");
    for e in [
        events_page(&state, &q, None, 0, 5, None).unwrap_err(),
        events_summary(&state, &q, None).unwrap_err(),
        events_histogram(&state, &q, 10, None).unwrap_err(),
        events_export_csv(&state, &q, &out, None).unwrap_err(),
    ] {
        assert_eq!(e.kind, "invalid", "{e:?}");
        assert!(e.message.contains("query id"), "{}", e.message);
    }
    assert!(!out.exists());
    // With one, it returns what the core returns for the same search.
    let core = with_case(&state, |open| {
        let query = q.to_query().unwrap();
        Ok(events::summary(open.case.conn(), &query).unwrap())
    })
    .unwrap();
    assert!(core.total > 0);
    let got = events_summary(&state, &q, Some("s-1")).unwrap();
    assert_eq!(got.total, core.total);
    assert_eq!(
        events_page(&state, &q, None, 0, 5, Some("s-1"))
            .unwrap()
            .total,
        core.total
    );
    assert!(events_histogram(&state, &q, 10, Some("s-1")).is_ok());
    assert!(state.active.lock().unwrap().is_none());
    // A cancel for the id (recorded before the query registers) makes each reader return `interrupted` without
    // running: proof that a search goes through `with_cancellable`. A query without a search ignores the id.
    for (i, run) in [
        (|s: &AppState, q: &EventQueryArgs, id: &str| {
            events_page(s, q, None, 0, 5, Some(id)).map(|_| ())
        }) as fn(&AppState, &EventQueryArgs, &str) -> sparrow_app::CmdResult<()>,
        |s, q, id| events_summary(s, q, Some(id)).map(|_| ()),
        |s, q, id| events_histogram(s, q, 10, Some(id)).map(|_| ()),
        |s, q, id| {
            events_export_csv(
                s,
                q,
                &std::env::temp_dir().join("never-written.csv"),
                Some(id),
            )
            .map(|_| ())
        },
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("s-cancel-{i}");
        query_cancel(&state, &id).unwrap();
        let e = run(&state, &q, &id).unwrap_err();
        assert_eq!(e.kind, "interrupted", "{i}: {e:?}");
        // The record was consumed: the same id runs again.
        run(&state, &q, &id).unwrap_or_else(|e| panic!("{i}: {e:?}"));
    }
    let plain = by_source("ual");
    query_cancel(&state, "plain").unwrap();
    assert!(events_summary(&state, &plain, Some("plain")).is_ok());
    // The id is validated like every query id.
    assert_eq!(
        events_summary(&state, &q, Some("")).unwrap_err().kind,
        "invalid"
    );
    let _ = std::fs::remove_file(std::env::temp_dir().join("never-written.csv"));
}

#[test]
fn events_export_csv_writes_every_matching_event_and_leaves_nothing_on_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let q = by_source("entra_audit");
    let want = rows(
        &state,
        "SELECT count(*) FROM events WHERE source = 'entra_audit'",
    );
    assert!(want > 1, "{want}");
    let out = tmp.path().join("events.csv");
    let n = events_export_csv(&state, &q, &out, None).unwrap();
    assert_eq!(n as i64, want);
    let got = read_csv(&out);
    assert_eq!(got.len() as i64, want + 1, "header + one line per event");
    let col = got[0].iter().position(|c| c == "source").unwrap();
    assert!(got[1..].iter().all(|r| r[col] == "entra_audit"));
    // The same rows with a search and an id (cancellable path), the file replaced atomically.
    let q2 = EventQueryArgs {
        search: Some("".into()),
        ..q.clone()
    };
    drop(q2);
    let qs = EventQueryArgs {
        search: Some("contoso".into()),
        ..q.clone()
    };
    let m = events_export_csv(&state, &qs, &out, Some("x-1")).unwrap();
    assert!(m > 0 && (m as i64) <= want, "{m}");
    assert_eq!(read_csv(&out).len() as u64, m + 1);
    assert!(leftovers(tmp.path()).is_empty());
    // A failing export leaves no file: a filter error, a missing folder, the case itself.
    let missing = tmp.path().join("no-such-dir").join("e.csv");
    assert_eq!(
        events_export_csv(&state, &q, &missing, None)
            .unwrap_err()
            .kind,
        "invalid"
    );
    let case_path = with_case(&state, |open| Ok(open.path.clone())).unwrap();
    assert_eq!(
        events_export_csv(&state, &q, &case_path, None)
            .unwrap_err()
            .kind,
        "invalid"
    );
    let bad = tmp.path().join("bad.csv");
    assert_eq!(
        events_export_csv(&state, &by_source("!"), &bad, None)
            .unwrap_err()
            .kind,
        "invalid"
    );
    assert!(!bad.exists());
    // A cancelled export leaves the earlier file as it was and no work folder.
    let before = std::fs::read(&out).unwrap();
    query_cancel(&state, "x-2").unwrap();
    assert_eq!(
        events_export_csv(&state, &qs, &out, Some("x-2"))
            .unwrap_err()
            .kind,
        "interrupted"
    );
    assert_eq!(std::fs::read(&out).unwrap(), before);
    assert!(leftovers(tmp.path()).is_empty());
}

#[test]
fn entity_commands_match_the_events_and_one_entity_has_one_spelling() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let p = picked(&state);
    let count =
        |pred: String| rows(&state, &format!("SELECT count(*) FROM events WHERE {pred}")) as u64;
    let cases = [
        (
            EntityKind::Account,
            p.account.clone(),
            format!("actor_upn = '{0}' OR owner_upn = '{0}'", p.account),
        ),
        (EntityKind::Ip, p.ip.clone(), format!("ip = '{}'", p.ip)),
        (
            EntityKind::Device,
            p.device.clone(),
            format!("device_id = '{0}' OR device_object_id = '{0}'", p.device),
        ),
        (
            EntityKind::Session,
            p.session.clone(),
            format!("entra_session_id = '{}'", p.session),
        ),
    ];
    for (kind, value, pred) in cases {
        let want = count(pred);
        assert!(want > 0, "{value}");
        let lower = entity_summary(&state, &entity_arg(kind, &value), None, None).unwrap();
        assert_eq!(lower.events, want, "{value}");
        // Padded and upper-cased: the same tab, the same events.
        let spelled = format!("  {}  ", value.to_uppercase());
        let upper = entity_summary(&state, &entity_arg(kind, &spelled), None, None).unwrap();
        assert_eq!(upper, lower, "{value}");
        // A pivot is a page of a table: `limit` rows of `total`.
        let of = match kind {
            EntityKind::Ip => PivotOf::Accounts,
            _ => PivotOf::Ips,
        };
        let full = entity_pivot(&state, &entity_arg(kind, &value), of, None, None, None).unwrap();
        assert!(
            full.total >= 1 && full.rows.len() as u64 == full.total,
            "{value}"
        );
        let one =
            entity_pivot(&state, &entity_arg(kind, &spelled), of, None, None, Some(1)).unwrap();
        assert_eq!((one.rows.len(), one.total), (1, full.total), "{value}");
        assert_eq!(one.rows[0], full.rows[0]);
        assert_eq!(
            entity_pivot(&state, &entity_arg(kind, &value), of, None, None, Some(0))
                .unwrap_err()
                .kind,
            "invalid"
        );
    }
    // An IPv6 address in two spellings is one entity, kept in the stored spelling.
    let a = entity_summary(
        &state,
        &entity_arg(EntityKind::Ip, "2001:DB8::1"),
        None,
        None,
    )
    .unwrap();
    let b = entity_summary(
        &state,
        &entity_arg(EntityKind::Ip, "2001:db8:0::1"),
        None,
        None,
    )
    .unwrap();
    assert_eq!(a, b);
    assert_eq!(a.entity, entity_arg(EntityKind::Ip, "2001:db8::1"));
    // On the wire the entity is `{ kind, value }`, in the stored spelling, and the times are ISO text.
    let wire = serde_json::to_value(&a).unwrap();
    assert_eq!(
        wire["entity"],
        serde_json::json!({ "kind": "ip", "value": "2001:db8::1" })
    );
    assert_eq!(wire["first_seen"], serde_json::Value::Null);
    let live = entity_summary(
        &state,
        &entity_arg(
            EntityKind::Account,
            &format!(" {} ", p.account.to_uppercase()),
        ),
        None,
        None,
    )
    .unwrap();
    assert_eq!(live.entity, entity_arg(EntityKind::Account, &p.account));
    let wire = serde_json::to_value(&live).unwrap();
    assert_eq!(
        wire["entity"],
        serde_json::json!({ "kind": "account", "value": p.account })
    );
    let first = wire["first_seen"].as_str().unwrap();
    assert!(first.ends_with('Z') && first.contains('T'), "{first}");
    assert_eq!(a.events, 0);
    // The range is ISO text; a range with no events empties the tiles and the table.
    let far = Some("2030-01-01T00:00:00Z");
    let none = entity_summary(&state, &entity_arg(EntityKind::Ip, &p.ip), far, None).unwrap();
    assert_eq!(none.events, 0);
    let table = entity_pivot(
        &state,
        &entity_arg(EntityKind::Ip, &p.ip),
        PivotOf::Accounts,
        far,
        None,
        None,
    )
    .unwrap();
    assert_eq!((table.rows.len(), table.total), (0, 0));
    // Bad arguments are `invalid`.
    for e in [
        entity_summary(&state, &entity_arg(EntityKind::Ip, "not-an-ip"), None, None).unwrap_err(),
        entity_summary(&state, &entity_arg(EntityKind::Account, "  "), None, None).unwrap_err(),
        entity_summary(
            &state,
            &entity_arg(EntityKind::Ip, &p.ip),
            Some("soon"),
            None,
        )
        .unwrap_err(),
        entity_findings(
            &state,
            &entity_arg(EntityKind::Ip, &p.ip),
            None,
            Some("soon"),
        )
        .unwrap_err(),
    ] {
        assert_eq!(e.kind, "invalid", "{e:?}");
    }
}

#[test]
fn entity_findings_lists_the_open_findings_that_cite_the_entity() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    // The accounts the findings are about.
    let upn = text_of(
        &state,
        "SELECT f.actor_upn FROM findings f JOIN finding_evidence fe USING (finding_id) \
         JOIN events e ON e.source_table = fe.source_table AND e.record_key = fe.record_key \
         WHERE f.actor_upn IS NOT NULL GROUP BY 1 ORDER BY count(DISTINCT f.finding_id) DESC, 1 LIMIT 1",
    );
    let who = entity_arg(EntityKind::Account, &upn.to_uppercase());
    let found = entity_findings(&state, &who, None, None).unwrap();
    let mut want: Vec<String> = with_case(&state, |open| {
        let mut st = open
            .case
            .conn()
            .prepare(
                "SELECT DISTINCT f.finding_id FROM findings f \
                 JOIN finding_evidence fe ON fe.finding_id = f.finding_id \
                 JOIN events e ON e.source_table = fe.source_table AND e.record_key = fe.record_key \
                 WHERE (e.actor_upn = ? OR e.owner_upn = ?) AND CAST(f.status AS VARCHAR) NOT IN ('false_positive', 'benign')",
            )
            .unwrap();
        Ok(st
            .query_map([&upn, &upn], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect())
    })
    .unwrap();
    want.sort();
    let mut got: Vec<String> = found.iter().map(|f| f.finding_id.clone()).collect();
    got.sort();
    assert!(!want.is_empty());
    assert_eq!(got, want);
    // The tile counts them by severity.
    let tiles = entity_summary(&state, &who, None, None).unwrap();
    assert_eq!(
        tiles.open_findings.values().sum::<u64>() as usize,
        want.len()
    );
    // Past the findings, none.
    assert!(
        entity_findings(&state, &who, Some("2030-01-01T00:00:00Z"), None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn marks_flag_tag_and_note_event_rows_with_one_audit_row_per_action() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let refs = first_rows(&state, &by_source("signin_interactive"), 3);
    assert_eq!(refs.len(), 3);
    let marked = |state: &AppState| {
        events_page(state, &by_source("signin_interactive"), None, 0, 3, None)
            .unwrap()
            .rows
    };

    // Flag: one audit row for three events, shown on the rows.
    let before = audit_rows(&state);
    let a = marks_flag_rows(&state, &refs, Some(FlagLevel::Suspicious)).unwrap();
    assert_eq!(
        (a.action.as_str(), a.object_type.as_str()),
        ("flag_rows", "event_flag")
    );
    assert_eq!(a.actor, "analyst:carlos");
    assert_eq!(audit_rows(&state), before + 1);
    assert!(
        marked(&state)
            .iter()
            .all(|r| r.flag == Some(FlagLevel::Suspicious) && !r.flag_ai)
    );
    assert_eq!(
        events_summary(
            &state,
            &EventQueryArgs {
                flag: FlagFilter::Suspicious,
                ..EventQueryArgs::default()
            },
            None
        )
        .unwrap()
        .total,
        3
    );
    // Clear.
    marks_flag_rows(&state, &refs, None).unwrap();
    assert!(marked(&state).iter().all(|r| r.flag.is_none()));

    // Tags are stored lower-case; one audit row; the tag list counts the rows.
    let before = audit_rows(&state);
    let t = marks_tag_rows(&state, &refs, "  Relay-Session ", true).unwrap();
    assert_eq!(
        (t.action.as_str(), t.object_type.as_str()),
        ("tag_rows", "event_tag")
    );
    assert_eq!(audit_rows(&state), before + 1);
    let tags = marks_list_tags(&state).unwrap();
    assert_eq!(
        tags.iter()
            .map(|t| (t.name.as_str(), t.count, t.agent_unreviewed))
            .collect::<Vec<_>>(),
        vec![("relay-session", 3, 0)]
    );
    assert!(marked(&state).iter().all(|r| r.tags
        == vec![TagRef {
            name: "relay-session".into(),
            ai: false
        }]));
    let tagged = EventQueryArgs {
        fields: vec![(Field::Tag, "RELAY-SESSION".into())],
        ..EventQueryArgs::default()
    };
    assert_eq!(events_summary(&state, &tagged, None).unwrap().total, 3);
    marks_tag_rows(&state, &refs[..1], "relay-session", false).unwrap();
    assert_eq!(events_summary(&state, &tagged, None).unwrap().total, 2);
    assert_eq!(marks_list_tags(&state).unwrap()[0].count, 2);

    // Notes: one per row, each its own audit row, shown on the rows.
    let before = audit_rows(&state);
    let notes = notes_add_rows(&state, &refs, "token replayed from the relay").unwrap();
    assert_eq!(notes.len(), 3);
    assert!(
        notes
            .iter()
            .all(|n| n.action == "add_note" && n.object_type == "annotation")
    );
    assert_eq!(audit_rows(&state), before + 3);
    assert!(
        marked(&state).iter().all(|r| r.note_count == 1
            && r.latest_note.as_deref() == Some("token replayed from the relay"))
    );
    // A bad call adds nothing: an empty note, an unknown row among good ones, no rows, too many rows.
    let before = audit_rows(&state);
    let mut with_ghost = refs.clone();
    with_ghost.push(RowRef::new(&refs[0].source_table, "no-such-record"));
    assert_eq!(
        notes_add_rows(&state, &refs, "  ").unwrap_err().kind,
        "decision"
    );
    assert_eq!(
        notes_add_rows(&state, &with_ghost, "x").unwrap_err().kind,
        "decision"
    );
    assert_eq!(
        notes_add_rows(&state, &[], "x").unwrap_err().kind,
        "invalid"
    );
    let many = first_rows(&state, &EventQueryArgs::default(), 201);
    assert_eq!(
        notes_add_rows(&state, &many, "x").unwrap_err().kind,
        "invalid"
    );
    assert_eq!(
        marks_tag_rows(&state, &with_ghost, "y", true)
            .unwrap_err()
            .kind,
        "decision"
    );
    assert_eq!(audit_rows(&state), before);
    assert!(marked(&state).iter().all(|r| r.note_count == 1));
}

#[test]
fn marks_flag_value_covers_every_event_with_the_value_and_a_scope_narrows_it() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let p = picked(&state);
    let count =
        |pred: String| rows(&state, &format!("SELECT count(*) FROM events WHERE {pred}")) as u64;
    let flagged = |level| EventQueryArgs {
        flag: level,
        ..EventQueryArgs::default()
    };

    // Malicious on an IP: every event with it, an indicator for the IP, one audit row.
    let before = audit_rows(&state);
    let a = marks_flag_value(
        &state,
        ValueKind::Ip,
        &p.ip,
        None,
        Some(FlagLevel::Malicious),
    )
    .unwrap();
    assert_eq!(
        (a.audit.action.as_str(), a.audit.object_type.as_str()),
        ("flag_value", "value_flag")
    );
    // The indicator it made is reported, new.
    assert_eq!(a.indicators.len(), 1);
    assert!(a.indicators[0].created);
    // The flag, and the indicator that a malicious IP also records.
    assert_eq!(audit_rows(&state), before + 2);
    let actions = text_of(
        &state,
        "SELECT string_agg(action, ',' ORDER BY seq) FROM (SELECT seq, action FROM audit_trail ORDER BY seq DESC LIMIT 2)",
    );
    assert_eq!(actions, "add_ioc,flag_value");
    let ip_events = count(format!("ip = '{}'", p.ip));
    assert_eq!(
        events_summary(&state, &flagged(FlagFilter::Malicious), None)
            .unwrap()
            .total,
        ip_events
    );
    let ind = sparrow_app::cmd::indicators::indicators_active(&state).unwrap();
    assert!(
        ind.iter()
            .any(|i| i.ioc_type == "ip" && i.value == p.ip && i.verdict == "malicious"),
        "{ind:?}"
    );
    // Cleared again.
    marks_flag_value(&state, ValueKind::Ip, &p.ip, None, None).unwrap();
    assert_eq!(
        events_summary(&state, &flagged(FlagFilter::Malicious), None)
            .unwrap()
            .total,
        0
    );

    // A suspicious account flag limited to one session flags only the account's events in that session.
    let scope = entity_arg(EntityKind::Session, &p.session.to_uppercase());
    marks_flag_value(
        &state,
        ValueKind::Account,
        &p.account.to_uppercase(),
        Some(&scope),
        Some(FlagLevel::Suspicious),
    )
    .unwrap();
    let want = count(format!(
        "entra_session_id = '{}' AND (actor_upn = '{1}' OR owner_upn = '{1}')",
        p.session, p.account
    ));
    let all_account = count(format!("actor_upn = '{0}' OR owner_upn = '{0}'", p.account));
    assert!(want > 0 && want < all_account, "{want} {all_account}");
    assert_eq!(
        events_summary(&state, &flagged(FlagFilter::Suspicious), None)
            .unwrap()
            .total,
        want
    );
    // Bad kinds and values are refused.
    assert_eq!(
        marks_flag_value(
            &state,
            ValueKind::Ip,
            "not-an-ip",
            None,
            Some(FlagLevel::Suspicious)
        )
        .unwrap_err()
        .kind,
        "invalid"
    );
    assert_eq!(
        marks_flag_value(
            &state,
            ValueKind::Asn,
            "AS-nope",
            None,
            Some(FlagLevel::Suspicious)
        )
        .unwrap_err()
        .kind,
        "invalid"
    );
    // The wire shape of the kind, level and scope.
    let kind: ValueKind = serde_json::from_value(serde_json::json!("ip_prefix")).unwrap();
    assert_eq!(kind, ValueKind::IpPrefix);
}

#[test]
fn marks_review_confirms_or_removes_what_an_agent_marked() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let q = by_source("signin_interactive");
    let refs = first_rows(&state, &q, 4);
    let agent = Actor::agent("triage", Some("carlos")).unwrap();
    with_case(&state, |open| {
        marks::flag_rows(
            open.case.conn(),
            &agent,
            &refs[..2],
            Some(FlagLevel::Malicious),
        )
        .unwrap();
        marks::tag_rows(open.case.conn(), &agent, &refs[2..], "ai:relay", true).unwrap();
        Ok(())
    })
    .unwrap();
    let rows_of = |state: &AppState| events_page(state, &q, None, 0, 4, None).unwrap().rows;
    let now = rows_of(&state);
    assert!(
        now[..2]
            .iter()
            .all(|r| r.flag == Some(FlagLevel::Malicious) && r.flag_ai)
    );
    assert!(now[2..].iter().all(|r| r.tags
        == vec![TagRef {
            name: "ai:relay".into(),
            ai: true
        }]));
    let unreviewed = EventQueryArgs {
        ai: AiFilter::Unreviewed,
        ..EventQueryArgs::default()
    };
    assert_eq!(events_summary(&state, &unreviewed, None).unwrap().total, 4);

    // Confirm the flags: one audit row for the agent's one call, the flag stays and is the analyst's now.
    let before = audit_rows(&state);
    let done = marks_review(&state, &refs[..2], true).unwrap();
    assert_eq!(done.len(), 1, "{done:?}");
    assert_eq!(audit_rows(&state), before + 1);
    let now = rows_of(&state);
    assert!(
        now[..2]
            .iter()
            .all(|r| r.flag == Some(FlagLevel::Malicious) && !r.flag_ai)
    );
    // Remove the tag: gone from the rows.
    let removed = marks_review(&state, &refs[2..], false).unwrap();
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert!(rows_of(&state)[2..].iter().all(|r| r.tags.is_empty()));
    // Nothing pending is an empty answer, not an error; no rows is refused.
    assert!(marks_review(&state, &refs, true).unwrap().is_empty());
    assert_eq!(marks_review(&state, &[], true).unwrap_err().kind, "invalid");
    assert_eq!(events_summary(&state, &unreviewed, None).unwrap().total, 0);
}

/// The case opened read-only (its audit chain is broken) in an app whose analyst is carlos.
fn read_only_app(tmp: &Path) -> AppState {
    let path = case_file(tmp);
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
    let state = state_with_settings(&tmp.join("settings"));
    settings_set_analyst(&state, "carlos").unwrap();
    let info = case_open(&state, &path, false).unwrap();
    assert!(info.read_only_reason.is_some());
    state
}

#[test]
fn every_write_command_refuses_read_only_and_writes_no_audit() {
    let tmp = tempfile::tempdir().unwrap();
    let state = read_only_app(tmp.path());
    // Reads work on a read-only case, and give the rows the writes below name.
    let q = by_source("signin_interactive");
    let refs = first_rows(&state, &q, 3);
    assert_eq!(refs.len(), 3);
    let p = picked(&state);
    let tables = "SELECT (SELECT count(*) FROM audit_trail) || '/' || (SELECT count(*) FROM event_flags) || '/' \
                  || (SELECT count(*) FROM event_tags) || '/' || (SELECT count(*) FROM value_flags) || '/' \
                  || (SELECT count(*) FROM annotations) || '/' || (SELECT count(*) FROM timeline_entries) \
                  || '/' || (SELECT count(*) FROM tags)";
    let snapshot = text_of(&state, tables);
    let add = |mode, rows: Option<Vec<RowRef>>, query: Option<EventQueryArgs>| AddEventsArgs {
        rows,
        query,
        mode,
        title: None,
        phase: None,
    };
    type Write<'a> = Box<dyn Fn() -> sparrow_app::CmdResult<()> + 'a>;
    let writes: Vec<(&str, Write)> = vec![
        (
            "marks_flag_rows",
            Box::new(|| marks_flag_rows(&state, &refs, Some(FlagLevel::Suspicious)).map(|_| ())),
        ),
        (
            "marks_flag_rows clear",
            Box::new(|| marks_flag_rows(&state, &refs, None).map(|_| ())),
        ),
        (
            "marks_flag_value",
            Box::new(|| {
                marks_flag_value(
                    &state,
                    ValueKind::Ip,
                    &p.ip,
                    None,
                    Some(FlagLevel::Malicious),
                )
                .map(|_| ())
            }),
        ),
        (
            "marks_flag_value scoped",
            Box::new(|| {
                marks_flag_value(
                    &state,
                    ValueKind::Account,
                    &p.account,
                    Some(&entity_arg(EntityKind::Session, &p.session)),
                    Some(FlagLevel::Suspicious),
                )
                .map(|_| ())
            }),
        ),
        (
            "marks_tag_rows add",
            Box::new(|| marks_tag_rows(&state, &refs, "relay", true).map(|_| ())),
        ),
        (
            "marks_tag_rows remove",
            Box::new(|| marks_tag_rows(&state, &refs, "relay", false).map(|_| ())),
        ),
        (
            "marks_review accept",
            Box::new(|| marks_review(&state, &refs, true).map(|_| ())),
        ),
        (
            "marks_review remove",
            Box::new(|| marks_review(&state, &refs, false).map(|_| ())),
        ),
        (
            "notes_add_rows",
            Box::new(|| notes_add_rows(&state, &refs, "a note").map(|_| ())),
        ),
        (
            "timeline_add_events each rows",
            Box::new(|| {
                timeline_add_events(&state, add(AddMode::Each, Some(refs.clone()), None))
                    .map(|_| ())
            }),
        ),
        (
            "timeline_add_events group rows",
            Box::new(|| {
                timeline_add_events(&state, add(AddMode::Group, Some(refs.clone()), None))
                    .map(|_| ())
            }),
        ),
        (
            "timeline_add_events group query",
            Box::new(|| {
                timeline_add_events(&state, add(AddMode::Group, None, Some(q.clone()))).map(|_| ())
            }),
        ),
    ];
    let n = writes.len();
    let mut ran = 0;
    for (name, write) in writes {
        let e = write().unwrap_err();
        assert_eq!(e.kind, "read_only", "{name}: {e:?}");
        assert_eq!(text_of(&state, tables), snapshot, "{name} changed the case");
        ran += 1;
    }
    assert_eq!(ran, n);
    // The marks the writes would have shown are not there; the reads that feed the UI still answer.
    assert!(marks_list_tags(&state).unwrap().is_empty());
    assert_eq!(
        events_summary(&state, &q, None).unwrap().total,
        rows(
            &state,
            "SELECT count(*) FROM events WHERE source = 'signin_interactive'"
        ) as u64
    );
}

#[test]
fn marking_needs_an_analyst_name() {
    let tmp = tempfile::tempdir().unwrap();
    let path = case_file(tmp.path());
    let state = state_with_settings(&tmp.path().join("settings"));
    case_open(&state, &path, false).unwrap();
    let refs = first_rows(&state, &by_source("ual"), 1);
    let before = audit_rows(&state);
    for e in [
        marks_flag_rows(&state, &refs, Some(FlagLevel::Suspicious)).unwrap_err(),
        marks_tag_rows(&state, &refs, "x", true).unwrap_err(),
        marks_review(&state, &refs, true).unwrap_err(),
        notes_add_rows(&state, &refs, "x").unwrap_err(),
        timeline_add_events(
            &state,
            AddEventsArgs {
                rows: Some(refs.clone()),
                query: None,
                mode: AddMode::Group,
                title: None,
                phase: None,
            },
        )
        .unwrap_err(),
    ] {
        assert_eq!(e.kind, "invalid", "{e:?}");
    }
    assert_eq!(audit_rows(&state), before);
}

fn add_args(
    mode: AddMode,
    rows: Option<Vec<RowRef>>,
    query: Option<EventQueryArgs>,
) -> AddEventsArgs {
    AddEventsArgs {
        rows,
        query,
        mode,
        title: None,
        phase: None,
    }
}

#[test]
fn timeline_add_events_each_caps_at_200() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    assert_eq!(EACH_MAX, 200);
    let refs = first_rows(&state, &EventQueryArgs::default(), 201);
    assert_eq!(
        refs.iter().collect::<std::collections::BTreeSet<_>>().len(),
        201
    );
    let before = (timeline_list(&state).unwrap().len(), audit_rows(&state));
    // 201 distinct rows: refused, nothing added.
    let e =
        timeline_add_events(&state, add_args(AddMode::Each, Some(refs.clone()), None)).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(
        e.message.contains("201") && e.message.contains("200"),
        "{}",
        e.message
    );
    // The same cap on a query that matches thousands of events.
    let e = timeline_add_events(
        &state,
        add_args(AddMode::Each, None, Some(EventQueryArgs::default())),
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    assert!(e.message.contains("200"), "{}", e.message);
    assert_eq!(
        (timeline_list(&state).unwrap().len(), audit_rows(&state)),
        before
    );
    // 200 distinct rows make 200 verified entries of one event each; a repeated row counts once.
    let mut with_dup = refs[..200].to_vec();
    with_dup.push(refs[1].clone());
    assert_eq!(with_dup.len(), 201);
    let done = timeline_add_events(&state, add_args(AddMode::Each, Some(with_dup), None)).unwrap();
    assert_eq!(done.entry_ids.len(), 200);
    assert_eq!(done.outcome, "Added 200 timeline entries");
    let all = timeline_list(&state).unwrap();
    assert_eq!(all.len(), before.0 + 200);
    for id in &done.entry_ids {
        let e = all.iter().find(|e| &e.entry_id == id).unwrap();
        assert_eq!(
            (e.status.as_str(), e.review_state.as_str(), e.evidence.len()),
            ("verified", "accepted", 1)
        );
        assert!(e.end_time.is_none() && e.event_count.is_none());
        assert_eq!(e.decided_by, "analyst:carlos");
    }
    assert_eq!(
        audit_rows(&state),
        before.1 + 2 * 200,
        "propose + verify for each"
    );
}

#[test]
fn timeline_add_events_group_makes_one_verified_entry_spanning_the_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let q = by_source("signin_interactive");
    let page = events_page(&state, &q, None, 0, 5, None).unwrap();
    let refs: Vec<RowRef> = page
        .rows
        .iter()
        .map(|r| RowRef::new(&r.source_table, &r.record_key))
        .collect();
    // The rows are all sign-ins, so the phase the backend proposes is initial access.
    assert_eq!(
        text_of(
            &state,
            "SELECT string_agg(DISTINCT CAST(category AS VARCHAR), ',') FROM events WHERE source = 'signin_interactive'"
        ),
        "auth"
    );
    let times: Vec<DateTime<Utc>> = page.rows.iter().map(|r| r.event_time.unwrap()).collect();
    let (start, end) = (*times.iter().min().unwrap(), *times.iter().max().unwrap());
    assert!(start < end);
    let before = (timeline_list(&state).unwrap().len(), audit_rows(&state));
    let done =
        timeline_add_events(&state, add_args(AddMode::Group, Some(refs.clone()), None)).unwrap();
    assert_eq!(done.entry_ids.len(), 1);
    assert_eq!(
        done.outcome,
        "Added 1 grouped timeline entry covering 5 events"
    );
    assert_eq!(audit_rows(&state), before.1 + 2, "propose + verify");
    let all = timeline_list(&state).unwrap();
    assert_eq!(all.len(), before.0 + 1);
    let e = all
        .iter()
        .find(|e| e.entry_id == done.entry_ids[0])
        .unwrap();
    assert_eq!(e.status, "verified");
    assert_eq!(
        (e.review_state.as_str(), e.decided_by.as_str()),
        ("accepted", "analyst:carlos")
    );
    assert_eq!(e.phase, "initial_access");
    assert_eq!((e.event_time, e.end_time), (start, Some(end)));
    assert_eq!(e.event_count, Some(5));
    let mut cited: Vec<RowRef> = e
        .evidence
        .iter()
        .map(|r| RowRef::new(&r.source_table, &r.record_key))
        .collect();
    cited.sort();
    let mut want = refs.clone();
    want.sort();
    assert_eq!(cited, want);
    assert_eq!(
        e.title,
        format!(
            "5 events {} to {}",
            start.format("%Y-%m-%dT%H:%M:%SZ"),
            end.format("%Y-%m-%dT%H:%M:%SZ")
        )
    );

    // A given title and phase win; a single row is a span of one moment.
    let one = timeline_add_events(
        &state,
        AddEventsArgs {
            title: Some("  Relay sign-in  ".into()),
            phase: Some("persistence".into()),
            ..add_args(AddMode::Group, Some(refs[..1].to_vec()), None)
        },
    )
    .unwrap();
    assert_eq!(
        one.outcome,
        "Added 1 grouped timeline entry covering 1 event"
    );
    let e = timeline_list(&state)
        .unwrap()
        .into_iter()
        .find(|e| e.entry_id == one.entry_ids[0])
        .unwrap();
    assert_eq!(
        (e.title.as_str(), e.phase.as_str(), e.event_count),
        ("Relay sign-in", "persistence", Some(1))
    );
    assert_eq!(e.end_time, Some(e.event_time));

    // Bad calls add nothing.
    let before = (timeline_list(&state).unwrap().len(), audit_rows(&state));
    let ghost = vec![
        refs[0].clone(),
        RowRef::new(&refs[0].source_table, "no-such-record"),
    ];
    let e = timeline_add_events(&state, add_args(AddMode::Group, Some(ghost.clone()), None))
        .unwrap_err();
    assert_eq!(e.kind, "decision", "{e:?}");
    assert!(e.message.contains("no-such-record"), "{}", e.message);
    assert_eq!(
        timeline_add_events(&state, add_args(AddMode::Each, Some(ghost), None))
            .unwrap_err()
            .kind,
        "decision"
    );
    for (what, args) in [
        ("neither", add_args(AddMode::Group, None, None)),
        (
            "both",
            add_args(AddMode::Group, Some(refs.clone()), Some(q.clone())),
        ),
        ("empty rows", add_args(AddMode::Group, Some(vec![]), None)),
        (
            "phase",
            AddEventsArgs {
                phase: Some("bogus".into()),
                ..add_args(AddMode::Group, Some(refs.clone()), None)
            },
        ),
        (
            "query time",
            add_args(
                AddMode::Group,
                None,
                Some(EventQueryArgs {
                    from: Some("soon".into()),
                    ..EventQueryArgs::default()
                }),
            ),
        ),
        (
            "query filter",
            add_args(AddMode::Group, None, Some(by_source("!"))),
        ),
        (
            "no match",
            add_args(AddMode::Group, None, Some(by_source("no_such_source"))),
        ),
    ] {
        let e = timeline_add_events(&state, args).unwrap_err();
        assert_eq!(e.kind, "invalid", "{what}: {e:?}");
    }
    assert_eq!(
        (timeline_list(&state).unwrap().len(), audit_rows(&state)),
        before
    );
}

#[test]
fn timeline_add_events_from_query_cites_all_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    // More than one core page (500) of rows: the backend resolves every match, not the first page.
    let q = by_source("mailbox_audit");
    let n = rows(
        &state,
        "SELECT count(*) FROM events WHERE source = 'mailbox_audit'",
    );
    assert!(n > 1000, "{n}");
    let (lo, hi) = (
        rows(
            &state,
            "SELECT min(epoch_us(event_time)) FROM events WHERE source = 'mailbox_audit'",
        ),
        rows(
            &state,
            "SELECT max(epoch_us(event_time)) FROM events WHERE source = 'mailbox_audit'",
        ),
    );
    let done =
        timeline_add_events(&state, add_args(AddMode::Group, None, Some(q.clone()))).unwrap();
    assert_eq!(
        done.outcome,
        format!("Added 1 grouped timeline entry covering {n} events")
    );
    let e = timeline_list(&state)
        .unwrap()
        .into_iter()
        .find(|e| e.entry_id == done.entry_ids[0])
        .unwrap();
    assert_eq!(e.event_count, Some(n as u64));
    assert_eq!(e.evidence.len() as i64, n);
    assert_eq!(
        e.evidence
            .iter()
            .map(|r| (&r.source_table, &r.record_key))
            .collect::<std::collections::BTreeSet<_>>()
            .len() as i64,
        n,
        "no repeats"
    );
    assert_eq!(e.event_time.timestamp_micros(), lo);
    assert_eq!(e.end_time.unwrap().timestamp_micros(), hi);
    // Every cited row is a mailbox_audit event, and every mailbox_audit event is cited.
    let cited_in_events = with_case(&state, |open| {
        let mut count = 0i64;
        for r in &e.evidence {
            count += open
                .case
                .conn()
                .query_row(
                    "SELECT count(*) FROM events WHERE source = 'mailbox_audit' AND source_table = ? AND record_key = ?",
                    [&r.source_table, &r.record_key],
                    |x| x.get::<_, i64>(0),
                )
                .unwrap();
        }
        Ok(count)
    })
    .unwrap();
    assert_eq!(cited_in_events, n);

    // The query's entity, range and filters all apply; `each` over a small match makes one entry per event.
    let small = EventQueryArgs {
        entity: Some(entity_arg(
            EntityKind::Account,
            &picked(&state).account.to_uppercase(),
        )),
        fields: vec![(Field::Source, "entra_audit".into())],
        ..EventQueryArgs::default()
    };
    let m = events_summary(&state, &small, None).unwrap().total;
    assert!((1..=200).contains(&m), "{m}");
    let each = timeline_add_events(&state, add_args(AddMode::Each, None, Some(small))).unwrap();
    assert_eq!(each.entry_ids.len() as u64, m);
    // A query too big to cite is refused with the number, and a search runs without an id on this write path.
    let huge = EventQueryArgs::default();
    assert!(
        rows(&state, "SELECT count(*) FROM events") < 100_000,
        "the synthetic case is small"
    );
    let with_search = EventQueryArgs {
        search: Some("no-such-text-anywhere-0xdead".into()),
        ..by_source("azure_activity")
    };
    let e =
        timeline_add_events(&state, add_args(AddMode::Group, None, Some(with_search))).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    drop(huge);
}

fn rows_in(state: &AppState, q: &EventQueryArgs) -> i64 {
    // How many message trace events the query names: all of them if its Source mentions the source or a wildcard.
    let named = q
        .fields
        .iter()
        .any(|(_, t)| t.contains("message_trace_event") || t.trim() == "*");
    if named {
        rows(
            state,
            "SELECT count(*) FROM events WHERE source = 'message_trace_event'",
        )
    } else {
        0
    }
}

#[test]
fn timeline_group_from_query_covers_exactly_what_the_summary_counts() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    // The synthetic case has no message trace events, so relabel seven mailbox audit events (their keys stay citable).
    with_case(&state, |open| {
        open.case
            .conn()
            .execute_batch(
                "UPDATE events SET source = 'message_trace_event' WHERE (source_table, record_key) IN \
                 (SELECT source_table, record_key FROM events WHERE source = 'mailbox_audit' \
                  ORDER BY record_key LIMIT 7)",
            )
            .unwrap();
        Ok(())
    })
    .unwrap();
    let trace = rows(
        &state,
        "SELECT count(*) FROM events WHERE source = 'message_trace_event'",
    );
    assert_eq!(trace, 7);
    // Hidden by default: the group covers the summary total, none of the trace events; naming them adds them.
    let default = EventQueryArgs::default();
    let named = by_source("message_trace_event");
    let wildcard = by_source("*");
    let everything_but = by_source("!ual");
    for (q, hidden) in [
        (default, trace),
        (named, 0),
        (wildcard, 0),
        (everything_but, trace),
    ] {
        let s = events_summary(&state, &q, None).unwrap();
        assert_eq!(s.hidden_trace_events as i64, hidden);
        let done =
            timeline_add_events(&state, add_args(AddMode::Group, None, Some(q.clone()))).unwrap();
        let e = timeline_list(&state)
            .unwrap()
            .into_iter()
            .find(|e| e.entry_id == done.entry_ids[0])
            .unwrap();
        assert_eq!(e.event_count, Some(s.total), "{q:?}");
        assert_eq!(e.evidence.len() as u64, s.total, "{q:?}");
        let trace_cited = with_case(&state, |open| {
            let mut n = 0i64;
            for r in &e.evidence {
                n += open
                    .case
                    .conn()
                    .query_row(
                        "SELECT count(*) FROM events WHERE source = 'message_trace_event' AND source_table = ? AND record_key = ?",
                        [&r.source_table, &r.record_key],
                        |x| x.get::<_, i64>(0),
                    )
                    .unwrap();
            }
            Ok(n)
        })
        .unwrap();
        let want = rows_in(&state, &q);
        assert_eq!(trace_cited, want, "{q:?}");
    }
    // The named and wildcard queries really include the trace events.
    assert_eq!(
        events_summary(&state, &by_source("message_trace_event"), None)
            .unwrap()
            .total as i64,
        trace
    );
}

/// Records the Investigate-tabs responses the web app's fixtures and mock backend are built on, from the synthetic
/// case: `cargo test -p sparrow-app --test commands -- --ignored record_investigate_fixtures`.
#[test]
#[ignore = "writes app/src/test/fixtures/*.json"]
fn record_investigate_fixtures() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let mut p = picked(&state);
    // The account that uses the busiest device, so the account tab has devices to pivot to.
    p.account = text_of(
        &state,
        &format!(
            "SELECT actor_upn FROM events WHERE device_id = '{}' AND actor_upn LIKE '%@%' \
             GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 1",
            p.device
        ),
    );
    // Twelve of the newest events of each source: the mock backend's whole event list.
    let mut list = Vec::new();
    for (source, _) in events_summary(&state, &EventQueryArgs::default(), None)
        .unwrap()
        .per_source
    {
        list.extend(
            events_page(&state, &by_source(&source), None, 0, 12, None)
                .unwrap()
                .rows,
        );
    }
    list.sort_by(|a, b| {
        b.event_time
            .cmp(&a.event_time)
            .then(a.record_key.cmp(&b.record_key))
    });
    let r = |i: usize| RowRef::new(&list[i].source_table, &list[i].record_key);
    // One of each mark the grid shows: both flag levels, an analyst tag, an unreviewed agent tag and agent flag, a note.
    marks_flag_rows(&state, &[r(0)], Some(FlagLevel::Malicious)).unwrap();
    marks_flag_rows(&state, &[r(1), r(2)], Some(FlagLevel::Suspicious)).unwrap();
    marks_tag_rows(&state, &[r(3), r(4)], "phish-lure", true).unwrap();
    notes_add_rows(
        &state,
        &[r(5)],
        "Token replayed from the relay; see the session tab.",
    )
    .unwrap();
    let agent = Actor::agent("triage", Some("carlos")).unwrap();
    with_case(&state, |open| {
        marks::tag_rows(open.case.conn(), &agent, &[r(6)], "ai:relay", true).unwrap();
        marks::flag_rows(
            open.case.conn(),
            &agent,
            &[r(7)],
            Some(FlagLevel::Suspicious),
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    let list: Vec<_> = list
        .iter()
        .map(|row| {
            let d = events_detail(&state, &row.source_table, &row.record_key).unwrap();
            d.row
        })
        .collect();
    let noted = events_detail(&state, &list[5].source_table, &list[5].record_key).unwrap();
    let flagged = events_detail(&state, &list[0].source_table, &list[0].record_key).unwrap();

    let account = entity_arg(EntityKind::Account, &p.account);
    let ip = entity_arg(EntityKind::Ip, &p.ip);
    let device = entity_arg(EntityKind::Device, &p.device);
    let session = entity_arg(EntityKind::Session, &p.session);
    let summaries = serde_json::json!({
        "account": entity_summary(&state, &account, None, None).unwrap(),
        "ip": entity_summary(&state, &ip, None, None).unwrap(),
        "device": entity_summary(&state, &device, None, None).unwrap(),
        "session": entity_summary(&state, &session, None, None).unwrap(),
    });
    let pivot = |e: &EntityArg, of| entity_pivot(&state, e, of, None, None, Some(25)).unwrap();
    // A device that has directory changes, for the device tab's changes table.
    let changed = with_case(&state, |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                "SELECT coalesce(device_id, device_object_id) FROM events WHERE source = 'entra_audit' \
                 AND coalesce(device_id, device_object_id) IS NOT NULL ORDER BY event_time LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok())
    })
    .unwrap()
    .unwrap_or_else(|| p.device.clone());
    let pivots = serde_json::json!({
        "accounts": pivot(&ip, PivotOf::Accounts),
        "ips": pivot(&account, PivotOf::Ips),
        "devices": pivot(&account, PivotOf::Devices),
        "sessions": pivot(&account, PivotOf::Sessions),
        "device_changes": pivot(&entity_arg(EntityKind::Device, &changed), PivotOf::DeviceChanges),
    });
    let upn = text_of(
        &state,
        "SELECT f.actor_upn FROM findings f JOIN finding_evidence fe USING (finding_id) \
         JOIN events e ON e.source_table = fe.source_table AND e.record_key = fe.record_key \
         WHERE f.actor_upn IS NOT NULL GROUP BY 1 ORDER BY count(DISTINCT f.finding_id) DESC, 1 LIMIT 1",
    );
    let added = timeline_add_events(
        &state,
        add_args(AddMode::Group, None, Some(by_source("entra_audit"))),
    )
    .unwrap();
    let out = [
        ("events_list.json", serde_json::to_value(&list).unwrap()),
        (
            "events_page.json",
            serde_json::to_value(
                events_page(&state, &by_source("signin_interactive"), None, 0, 25, None).unwrap(),
            )
            .unwrap(),
        ),
        (
            "events_summary.json",
            serde_json::to_value(events_summary(&state, &EventQueryArgs::default(), None).unwrap())
                .unwrap(),
        ),
        (
            "events_histogram.json",
            serde_json::to_value(
                events_histogram(&state, &EventQueryArgs::default(), 24, None).unwrap(),
            )
            .unwrap(),
        ),
        ("events_detail.json", serde_json::to_value(&noted).unwrap()),
        (
            "events_detail_flagged.json",
            serde_json::to_value(&flagged).unwrap(),
        ),
        (
            "events_suggest.json",
            serde_json::to_value(events_suggest(&state, Field::Account, &p.account[..4]).unwrap())
                .unwrap(),
        ),
        ("entity_summaries.json", summaries),
        ("entity_pivots.json", pivots),
        (
            "entity_findings.json",
            serde_json::to_value(
                entity_findings(&state, &entity_arg(EntityKind::Account, &upn), None, None)
                    .unwrap(),
            )
            .unwrap(),
        ),
        (
            "entity_coverage.json",
            serde_json::to_value(
                entity_coverage(
                    &state,
                    &entity_arg(EntityKind::Account, &p.account),
                    None,
                    None,
                )
                .unwrap(),
            )
            .unwrap(),
        ),
        (
            "marks_tags.json",
            serde_json::to_value(marks_list_tags(&state).unwrap()).unwrap(),
        ),
        ("timeline_added.json", serde_json::to_value(&added).unwrap()),
    ];
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/src/test/fixtures");
    for (name, v) in out {
        let mut text = serde_json::to_string_pretty(&v).unwrap();
        text.push('\n');
        std::fs::write(dir.join(name), text).unwrap();
    }
}

#[test]
fn timeline_add_events_each_is_all_or_nothing() {
    use sparrow_core::case::timeline_entries::test_hooks;
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let refs = first_rows(&state, &by_source("signin_interactive"), 5);
    let snapshot = |state: &AppState| {
        (
            timeline_list(state).unwrap().len(),
            audit_rows(state),
            rows(state, "SELECT count(*) FROM timeline_entry_evidence"),
        )
    };
    let before = snapshot(&state);
    // The failure is injected (core's test hook) into the LAST of the five entries, after it was verified: the four
    // entries before it, and all ten audit rows, roll back with it.
    test_hooks::fail_create_verified_on_call(5);
    let e =
        timeline_add_events(&state, add_args(AddMode::Each, Some(refs.clone()), None)).unwrap_err();
    test_hooks::fail_create_verified_on_call(0);
    assert!(e.message.contains("injected"), "{e:?}");
    assert_eq!(snapshot(&state), before);
    // The same call without the failure adds all five and ten audit rows.
    let done = timeline_add_events(&state, add_args(AddMode::Each, Some(refs), None)).unwrap();
    assert_eq!(done.entry_ids.len(), 5);
    let after = snapshot(&state);
    assert_eq!((after.0, after.1), (before.0 + 5, before.1 + 10));
}

#[test]
fn entity_coverage_judges_the_accounts_in_the_entitys_events_per_tenant() {
    use sparrow_core::case::coverage::{RangeState, coverage_for_range};
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let p = picked(&state);
    // Spelled in capitals: the same account.
    let who = entity_arg(EntityKind::Account, &p.account.to_uppercase());
    let cov = entity_coverage(&state, &who, None, None).unwrap();
    let day = |agg: &str| {
        text_of(
            &state,
            &format!(
                "SELECT strftime(make_timestamp({agg}(epoch_us(event_time))), '%Y-%m-%d') FROM events \
                 WHERE actor_upn = '{0}' OR owner_upn = '{0}'",
                p.account
            ),
        )
    };
    // No range: the entity's first to last event, as UTC days.
    assert_eq!(cov.from.as_deref(), Some(day("min").as_str()));
    assert_eq!(cov.to.as_deref(), Some(day("max").as_str()));
    assert!(!cov.tenants.is_empty());
    let (from, to) = (
        chrono::NaiveDate::parse_from_str(cov.from.as_deref().unwrap(), "%Y-%m-%d").unwrap(),
        chrono::NaiveDate::parse_from_str(cov.to.as_deref().unwrap(), "%Y-%m-%d").unwrap(),
    );
    for t in &cov.tenants {
        // The accounts of this tenant's events (actor and owner), the account itself among them.
        assert!(t.accounts.contains(&p.account), "{t:?}");
        let want: i64 = rows(
            &state,
            &format!(
                "SELECT count(DISTINCT a) FROM (SELECT actor_upn AS a FROM events WHERE tenant_key = '{0}' \
                 AND (actor_upn = '{1}' OR owner_upn = '{1}') UNION ALL SELECT owner_upn FROM events \
                 WHERE tenant_key = '{0}' AND (actor_upn = '{1}' OR owner_upn = '{1}'))",
                t.tenant_key, p.account
            ),
        );
        assert_eq!(t.accounts.len() as i64, want, "{t:?}");
        // The same answer as core's, and all seven sources are listed.
        let direct = with_case(&state, |open| {
            Ok(
                coverage_for_range(open.case.conn(), Some(&t.tenant_key), &t.accounts, from, to)
                    .unwrap(),
            )
        })
        .unwrap();
        assert_eq!(t.sources, direct.sources);
        assert_eq!(t.sources.len(), 7);
    }
    // The wire form: states are lower-case words, the days plain dates.
    let wire = serde_json::to_value(&cov).unwrap();
    let state_text = wire["tenants"][0]["sources"][0]["state"].as_str().unwrap();
    assert!(
        ["covered", "sampled", "absent"].contains(&state_text),
        "{state_text}"
    );
    // A range with none of the entity's events is still judged, for the accounts and tenants of the whole case: every
    // per-account source is absent there, and the account itself is among the accounts.
    let far = entity_coverage(
        &state,
        &who,
        Some("2030-01-01T00:00:00Z"),
        Some("2030-01-02T00:00:00Z"),
    )
    .unwrap();
    assert_eq!(
        (far.from.as_deref(), far.to.as_deref()),
        (Some("2030-01-01"), Some("2030-01-02"))
    );
    assert_eq!(far.tenants.len(), cov.tenants.len());
    for (f, t) in far.tenants.iter().zip(&cov.tenants) {
        assert_eq!((&f.tenant_key, &f.accounts), (&t.tenant_key, &t.accounts));
        assert!(f.accounts.contains(&p.account), "{f:?}");
        assert_eq!(f.sources.len(), 7);
        assert!(
            f.sources.iter().all(|s| s.state == RangeState::Absent),
            "{f:?}"
        );
    }
    // An account with no events anywhere has nothing to judge.
    let nobody = entity_coverage(
        &state,
        &entity_arg(EntityKind::Account, "nobody@contoso.example"),
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        (nobody.from, nobody.to, nobody.tenants.len()),
        (None, None, 0)
    );
    // A bad time is `invalid`.
    let e = entity_coverage(&state, &who, Some("soon"), None).unwrap_err();
    assert_eq!(e.kind, "invalid", "{e:?}");
    // An asked range is the UTC days it spans.
    let one = entity_coverage(
        &state,
        &who,
        Some(&format!("{from}T00:00:00Z")),
        Some(&format!("{from}T23:59:59Z")),
    )
    .unwrap();
    assert_eq!(
        (one.from.as_deref(), one.to.as_deref()),
        (
            Some(from.to_string().as_str()),
            Some(from.to_string().as_str())
        )
    );
}

#[test]
fn entity_coverage_of_an_ip_judges_the_accounts_seen_from_it() {
    let tmp = tempfile::tempdir().unwrap();
    let state = open_as_analyst(tmp.path());
    let p = picked(&state);
    let cov = entity_coverage(&state, &entity_arg(EntityKind::Ip, &p.ip), None, None).unwrap();
    assert!(!cov.tenants.is_empty());
    for t in &cov.tenants {
        let want: i64 = rows(
            &state,
            &format!(
                "SELECT count(DISTINCT a) FROM (SELECT actor_upn AS a FROM events WHERE ip = '{0}' AND tenant_key = '{1}' \
                 UNION ALL SELECT owner_upn FROM events WHERE ip = '{0}' AND tenant_key = '{1}') WHERE a IS NOT NULL",
                p.ip, t.tenant_key
            ),
        );
        assert_eq!(t.accounts.len() as i64, want, "{t:?}");
        // No account: only the two tenant-wide sources; otherwise all seven.
        assert_eq!(t.sources.len(), if want == 0 { 2 } else { 7 }, "{t:?}");
    }
}
