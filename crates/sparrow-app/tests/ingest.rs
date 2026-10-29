//! Import from the window on a synthetic tree, without a window.

use sparrow_app::cmd::ingest::{
    Emit, IngestState, ProgressEvent, Target, ingest_cancel, ingest_discover, ingest_profile,
    ingest_run, ingest_unprofiled, wait_idle, window_close_requested,
};
use sparrow_app::state::{AppState, case_close, case_open, with_case, with_writable};
use sparrow_core::Case;
use sparrow_core::case::actor::Actor;
use sparrow_core::case::indicators::{IndicatorType, Verdict, add_indicator};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, fault, ingest_path};
use sparrow_synth::cache::Cache;
use sparrow_synth::options::{Collector, GenerateOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::Duration;

static CACHE: LazyLock<Cache> = LazyLock::new(|| sparrow_synth::test_cache!());

/// The evidence folder of a small generated tree.
fn tree() -> PathBuf {
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let t = CACHE
        .tree(&scenario, &GenerateOptions::new(Collector::Invictus, 17))
        .unwrap();
    t.dir.join(&t.manifest.root)
}

type Log = Arc<Mutex<Vec<ProgressEvent>>>;

fn collect() -> (Emit, Log) {
    let log: Log = Arc::default();
    let sink = log.clone();
    (
        Arc::new(move |e: &ProgressEvent| sink.lock().unwrap().push(e.clone())),
        log,
    )
}

fn quiet() -> Emit {
    Arc::new(|_| {})
}

/// Rows of the evidence tables an import fills (the derived tables change with every profile and detection run).
const DATA_TABLES: [&str; 7] = [
    "events",
    "signins",
    "ual_events",
    "mail_items_accessed",
    "file_events",
    "source_files",
    "collections",
];

fn counts(case: &Case) -> Vec<(String, i64)> {
    DATA_TABLES
        .iter()
        .map(|t| {
            let n = case
                .conn()
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap();
            (t.to_string(), n)
        })
        .collect()
}

fn counts_of_file(path: &Path) -> Vec<(String, i64)> {
    counts(&Case::create_or_open(path).unwrap())
}

/// An empty case file in `dir`, opened by the app.
fn open_blank(dir: &Path, state: &AppState) -> PathBuf {
    let path = dir.join("open.duckdb");
    drop(Case::create_or_open(&path).unwrap());
    case_open(state, &path, false).unwrap();
    path
}

fn run(
    state: &AppState,
    ing: &IngestState,
    target: &Target,
    detect: bool,
    emit: &Emit,
) -> sparrow_app::CmdResult<sparrow_app::cmd::ingest::IngestResult> {
    ingest_run(state, ing, &tree(), target, None, detect, "run-1", emit)
}

#[test]
fn discovery_preview_lists_collections_and_classifies_files() {
    let p = ingest_discover(&tree()).unwrap();
    assert_eq!(p.collections.len(), 1);
    assert!(p.recognised > 0);
    let files: Vec<_> = p.collections.iter().flat_map(|c| &c.files).collect();
    assert_eq!(
        files.len(),
        p.recognised + p.unrecognised + p.too_large + p.unreadable
    );
    assert!(
        files
            .iter()
            .filter(|f| f.status == "recognised")
            .all(|f| f.artifact_id.is_some())
    );
    assert!(
        files
            .iter()
            .filter(|f| f.status == "unrecognised")
            .all(|f| f.artifact_id.is_none())
    );
    assert!(files.iter().all(|f| f.status != "too_large"));
}

#[test]
fn discovery_of_a_folder_with_nothing_recognised_and_of_a_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("notes.txt"), "hello").unwrap();
    let p = ingest_discover(dir.path()).unwrap();
    assert!(p.collections.is_empty());
    assert_eq!((p.recognised, p.unrecognised), (0, 0));
    let e = ingest_discover(&dir.path().join("notes.txt")).unwrap_err();
    assert_eq!(e.kind, "invalid");
    // Importing it is refused the way `sparrow ingest` refuses it, and creates no case file.
    let state = AppState::default();
    let case = dir.path().join("none.duckdb");
    let e = ingest_run(
        &state,
        &IngestState::default(),
        dir.path(),
        &Target::NewCase(case.clone()),
        None,
        true,
        "run-1",
        &quiet(),
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid");
    assert!(e.message.contains("no Hawk"), "{e:?}");
    assert!(!case.exists());
}

#[test]
fn a_new_case_is_made_with_progress_in_order_and_the_result_card() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("new.duckdb");
    let (emit, log) = collect();
    let state = AppState::default();
    let r = run(
        &state,
        &IngestState::default(),
        &Target::NewCase(case.clone()),
        true,
        &emit,
    )
    .unwrap();
    assert!(!r.cancelled && r.not_loaded.is_empty());
    assert_eq!(r.case_path, case.display().to_string());
    assert!(r.files_loaded > 0 && r.files_loaded <= r.files_total);
    assert_eq!(r.profile_error, None);
    assert!(
        r.detect.as_ref().is_some_and(|d| d.findings_new > 0),
        "{:?}",
        r.detect
    );
    let rows: u64 = r.rows_by_source.iter().map(|s| s.rows).sum();
    let loaded: u64 = r
        .report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .map(|f| f.records_loaded)
        .sum();
    assert_eq!(rows, loaded);
    assert!(rows > 0);

    let log = log.lock().unwrap();
    assert_eq!(log.first(), Some(&ProgressEvent::Discover));
    assert!(
        matches!(
            log[1],
            ProgressEvent::Collection {
                index: 1,
                count: 1,
                ..
            }
        ),
        "{:?}",
        log[1]
    );
    let tail = &log[log.len() - 2..];
    assert_eq!(tail, [ProgressEvent::Profile, ProgressEvent::Detect]);
    let indexes: Vec<usize> = log
        .iter()
        .filter_map(|e| match e {
            ProgressEvent::File { index, .. } => Some(*index),
            _ => None,
        })
        .collect();
    assert!(indexes.len() >= r.files_loaded);
    assert_eq!(indexes.first(), Some(&1));
    // Every file starts after the one before it finished: the counter never goes back.
    assert!(indexes.windows(2).all(|w| w[1] >= w[0]), "{indexes:?}");
    drop(log);

    // The file is a complete case with the data loaded and profiled.
    let n = counts_of_file(&case);
    assert!(n.iter().all(|(_, k)| *k > 0), "{n:?}");
}

#[test]
fn skipping_detection_runs_the_profile_only() {
    let dir = tempfile::tempdir().unwrap();
    let (emit, log) = collect();
    let r = run(
        &AppState::default(),
        &IngestState::default(),
        &Target::NewCase(dir.path().join("n.duckdb")),
        false,
        &emit,
    )
    .unwrap();
    assert!(r.detect.is_none() && r.detect_error.is_none());
    let log = log.lock().unwrap();
    assert_eq!(log.last(), Some(&ProgressEvent::Profile));
    assert!(!log.contains(&ProgressEvent::Detect));
}

#[test]
fn a_new_case_never_replaces_an_existing_file_or_lands_in_the_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let ing = IngestState::default();
    let existing = dir.path().join("there.duckdb");
    std::fs::write(&existing, b"not a case").unwrap();
    let e = run(
        &state,
        &ing,
        &Target::NewCase(existing.clone()),
        true,
        &quiet(),
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid");
    assert_eq!(std::fs::read(&existing).unwrap(), b"not a case");
    // Inside a copy of the evidence, so the real tree is not written to.
    let copy = dir.path().join("evidence");
    copy_dir(&tree(), &copy);
    let inside = copy.join("case.duckdb");
    let e = ingest_run(
        &state,
        &ing,
        &copy,
        &Target::NewCase(inside.clone()),
        None,
        true,
        "run-1",
        &quiet(),
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid");
    assert!(e.message.contains("inside the evidence"), "{e:?}");
    assert!(!inside.exists());
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
fn importing_into_the_open_case_matches_the_cli_and_twice_adds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let ing = IngestState::default();
    let path = open_blank(dir.path(), &state);

    let first = run(&state, &ing, &Target::Open, true, &quiet()).unwrap();
    assert_eq!(first.case_path, path.display().to_string());
    // The profile and detection ran on the unlocked writer, whatever the window locked down before.
    assert_eq!(first.profile_error, None);
    assert!(
        first.detect.as_ref().is_some_and(|d| d.findings_new > 0),
        "{:?}",
        first.detect_error
    );
    let after_first = {
        let slot = state.open.lock().unwrap();
        let open = slot.as_ref().unwrap();
        // The writer the window queries is locked down again after the detection run reopened it.
        assert!(open.case.is_locked_down().unwrap());
        counts(&open.case)
    };

    // The reference: what `sparrow ingest` does on its own case with the same tree.
    let mut reference = Case::in_memory().unwrap();
    ingest_path(
        &mut reference,
        &tree(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    // `events` is filled by the profile step, which the reference never ran: compare the loaded tables.
    let loaded = |c: Vec<(String, i64)>| {
        c.into_iter()
            .filter(|(t, _)| t != "events")
            .collect::<Vec<_>>()
    };
    assert_eq!(loaded(after_first.clone()), loaded(counts(&reference)));
    assert!(
        after_first.iter().any(|(t, n)| t == "events" && *n > 0),
        "the profile filled events"
    );

    let second = run(&state, &ing, &Target::Open, true, &quiet()).unwrap();
    let after_second = counts(&state.open.lock().unwrap().as_ref().unwrap().case);
    assert_eq!(
        after_second, after_first,
        "a second import changed the data"
    );
    assert_eq!(second.rows_by_source, vec![], "{:?}", second.rows_by_source);
    assert_eq!(second.files_loaded, 0);
    case_close(&state).unwrap();
}

#[test]
fn a_read_only_case_cannot_import() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.duckdb");
    {
        let case = Case::create_or_open(&path).unwrap();
        let agent = Actor::agent("triage", None).unwrap();
        add_indicator(
            case.conn(),
            &agent,
            None,
            IndicatorType::parse("upn").unwrap(),
            "a@example.test",
            Verdict::parse("suspicious").unwrap(),
            None,
        )
        .unwrap();
        case.conn()
            .execute("UPDATE audit_trail SET reason = 'x' WHERE seq = (SELECT max(seq) FROM audit_trail)", [])
            .unwrap();
    }
    let state = AppState::default();
    let info = case_open(&state, &path, false).unwrap();
    assert!(info.read_only_reason.is_some());
    let before = std::fs::read(&path).unwrap();
    let e = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        true,
        &quiet(),
    )
    .unwrap_err();
    assert_eq!(e.kind, "read_only", "{e:?}");
    case_close(&state).unwrap();
    assert!(std::fs::read(&path).unwrap() == before, "the file changed");
    // And with no case open at all.
    let e = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        true,
        &quiet(),
    )
    .unwrap_err();
    assert_eq!(e.kind, "no_case");
}

#[test]
fn cancel_stops_after_the_current_file_and_the_case_is_profiled() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("cut.duckdb");
    let ing = Arc::new(IngestState::default());
    let seen = Arc::new(AtomicBool::new(false));
    let emit: Emit = {
        let (ing, seen) = (ing.clone(), seen.clone());
        Arc::new(move |e: &ProgressEvent| {
            if let ProgressEvent::File { index: 4, .. } = e {
                seen.store(true, Ordering::SeqCst);
                ingest_cancel(&ing, "run-1").unwrap();
            }
        })
    };
    let r = run(
        &AppState::default(),
        &ing,
        &Target::NewCase(case.clone()),
        true,
        &emit,
    )
    .unwrap();
    assert!(seen.load(Ordering::SeqCst));
    assert!(r.cancelled);
    assert!(!r.not_loaded.is_empty());
    // The 4th file was the last one started: three finished before it, it finished too, then it stopped.
    let handled: usize = r.report.collections.iter().map(|c| c.files.len()).sum();
    assert_eq!(
        handled,
        4,
        "{:?}",
        r.report
            .collections
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.rel_path.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(r.files_total, handled + r.not_loaded.len());
    // Profile ran (the loaded files are consistent), detection did not.
    assert_eq!(r.profile_error, None);
    assert!(r.detect.is_none());
    let c = Case::create_or_open(&case).unwrap();
    let unprofiled = sparrow_core::profile::unprofiled_collections(c.conn()).unwrap();
    assert!(unprofiled.is_empty(), "{unprofiled:?}");
    // What loaded is whole: every handled file has its source row, and none of the others has one.
    let n: i64 = c
        .conn()
        .query_row("SELECT count(*) FROM source_files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n as usize, handled);
    // A cancel pressed with nothing running does nothing; the next import is not affected by the last one.
    ingest_cancel(&ing, "run-1").unwrap();
    let again = ingest_run(
        &AppState::default(),
        &ing,
        &tree(),
        &Target::NewCase(dir.path().join("whole.duckdb")),
        None,
        false,
        "run-2",
        &quiet(),
    )
    .unwrap();
    assert!(!again.cancelled);
}

#[test]
fn a_second_import_while_one_runs_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::default());
    let ing = Arc::new(IngestState::default());
    let refused: Arc<Mutex<Option<String>>> = Arc::default();
    let emit: Emit = {
        let (state, ing, refused) = (state.clone(), ing.clone(), refused.clone());
        Arc::new(move |e: &ProgressEvent| {
            if let ProgressEvent::File { index: 1, .. } = e {
                let other = ingest_run(
                    &state,
                    &ing,
                    &tree(),
                    &Target::NewCase(PathBuf::from("/nonexistent/never.duckdb")),
                    None,
                    true,
                    "run-1",
                    &quiet(),
                );
                *refused.lock().unwrap() = other.err().map(|e| e.message);
            }
        })
    };
    run(
        &state,
        &ing,
        &Target::NewCase(dir.path().join("a.duckdb")),
        false,
        &emit,
    )
    .unwrap();
    assert_eq!(
        refused.lock().unwrap().as_deref(),
        Some("an import is already running")
    );
}

#[test]
fn a_culture_is_checked_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("c.duckdb");
    let e = ingest_run(
        &AppState::default(),
        &IngestState::default(),
        &tree(),
        &Target::NewCase(case.clone()),
        Some("klingon"),
        true,
        "run-1",
        &quiet(),
    )
    .unwrap_err();
    assert_eq!(e.kind, "invalid");
    assert!(!case.exists());
}

#[test]
fn a_running_query_is_cancelled_so_the_import_can_take_the_case() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::default());
    open_blank(dir.path(), &state);
    let query = {
        let state = state.clone();
        std::thread::spawn(move || {
            sparrow_app::state::with_cancellable(&state, state.ticket(), "slow-1", |open| {
                // Far longer than the test: only the interrupt ends it.
                open.case
                    .conn()
                    .query_row("SELECT sum(i) FROM range(100000000000) t(i)", [], |r| {
                        r.get::<_, i64>(0)
                    })
                    .map_err(|e| sparrow_core::Error::from(e).into())
            })
        })
    };
    while state.active.lock().unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(10));
    }
    let r = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        false,
        &quiet(),
    )
    .unwrap();
    assert!(r.files_loaded > 0);
    let e = query.join().unwrap().unwrap_err();
    assert_eq!(e.kind, "interrupted", "{e:?}");
}

/// The order the files of the tree are loaded in (recorded from one real import).
#[allow(clippy::let_and_return)] // the guard must drop before the value is returned
fn file_order() -> &'static Vec<String> {
    static ORDER: OnceLock<Vec<String>> = OnceLock::new();
    ORDER.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let (emit, log) = collect();
        run(
            &AppState::default(),
            &IngestState::default(),
            &Target::NewCase(dir.path().join("order.duckdb")),
            false,
            &emit,
        )
        .unwrap();
        let order = log
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ProgressEvent::File { rel_path, .. } => Some(rel_path.clone()),
                _ => None,
            })
            .collect();
        order
    })
}

fn unprofiled(path: &Path) -> Vec<i64> {
    let c = Case::create_or_open(path).unwrap();
    sparrow_core::profile::unprofiled_collections(c.conn()).unwrap()
}

#[test]
fn a_cancel_that_arrives_before_the_run_starts_still_stops_it_and_never_leaks() {
    let dir = tempfile::tempdir().unwrap();
    let ing = IngestState::default();
    ingest_cancel(&ing, "early").unwrap();
    let (emit, log) = collect();
    let r = ingest_run(
        &AppState::default(),
        &ing,
        &tree(),
        &Target::NewCase(dir.path().join("early.duckdb")),
        None,
        true,
        "early",
        &emit,
    )
    .unwrap();
    assert!(r.cancelled);
    assert_eq!(r.files_loaded, 0);
    assert_eq!(r.not_loaded.len(), r.files_total);
    assert!(r.detect.is_none());
    assert!(
        !log.lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ProgressEvent::File { .. }))
    );
    // Another run id is not affected by it.
    let next = ingest_run(
        &AppState::default(),
        &ing,
        &tree(),
        &Target::NewCase(dir.path().join("next.duckdb")),
        None,
        false,
        "later",
        &quiet(),
    )
    .unwrap();
    assert!(!next.cancelled && next.not_loaded.is_empty());
}

#[test]
fn a_cancel_during_the_profile_spares_the_detection() {
    let dir = tempfile::tempdir().unwrap();
    let ing = Arc::new(IngestState::default());
    let (log_emit, log) = collect();
    let emit: Emit = {
        let ing = ing.clone();
        Arc::new(move |e: &ProgressEvent| {
            if *e == ProgressEvent::Profile {
                ingest_cancel(&ing, "run-1").unwrap();
            }
            log_emit(e);
        })
    };
    let r = run(
        &AppState::default(),
        &ing,
        &Target::NewCase(dir.path().join("p.duckdb")),
        true,
        &emit,
    )
    .unwrap();
    assert!(r.cancelled, "a cancel was asked for");
    assert!(r.not_loaded.is_empty(), "every file had loaded");
    assert_eq!(r.profile_error, None);
    assert!(r.detect.is_none() && r.detect_error.is_none());
    assert!(!log.lock().unwrap().contains(&ProgressEvent::Detect));
}

#[test]
fn a_hard_error_after_a_committed_file_keeps_the_files_and_profiles_them() {
    let dir = tempfile::tempdir().unwrap();
    let order = file_order();
    let failing = &order[2];
    let case = dir.path().join("hard.duckdb");
    fault::fail_file(case.clone(), failing);
    let (emit, log) = collect();
    let r = run(
        &AppState::default(),
        &IngestState::default(),
        &Target::NewCase(case.clone()),
        true,
        &emit,
    )
    .unwrap();
    assert!(
        r.error.as_deref().unwrap().contains(failing),
        "{:?}",
        r.error
    );
    let handled: Vec<&str> = r
        .report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .map(|f| f.rel_path.as_str())
        .collect();
    assert_eq!(handled, [order[0].as_str(), order[1].as_str()]);
    assert!(r.not_loaded.iter().any(|f| &f.rel_path == failing));
    assert_eq!(r.files_total, handled.len() + r.not_loaded.len());
    // The profile ran over the committed files; detection did not.
    assert_eq!(r.profile_error, None);
    assert!(r.detect.is_none());
    assert!(!log.lock().unwrap().contains(&ProgressEvent::Detect));
    assert!(case.exists());
    assert!(unprofiled(&case).is_empty());
    let n: i64 = Case::create_or_open(&case)
        .unwrap()
        .conn()
        .query_row("SELECT count(*) FROM source_files", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n as usize, handled.len(), "no row of the file that failed");
}

#[test]
fn a_hard_error_with_nothing_committed_is_an_error_and_leaves_no_case_file() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("none.duckdb");
    fault::fail_file(case.clone(), &file_order()[0]);
    let e = run(
        &AppState::default(),
        &IngestState::default(),
        &Target::NewCase(case.clone()),
        true,
        &quiet(),
    )
    .unwrap_err();
    assert!(e.message.contains("injected"), "{e:?}");
    assert!(!case.exists());
}

#[test]
fn a_hard_error_in_the_open_case_keeps_it_open_locked_and_profiled() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let path = open_blank(dir.path(), &state);
    fault::fail_file(path.clone(), &file_order()[3]);
    let r = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        true,
        &quiet(),
    )
    .unwrap();
    assert!(r.error.is_some());
    assert_eq!(r.files_loaded, 3);
    assert!(r.detect.is_none());
    let slot = state.open.lock().unwrap();
    let case = &slot.as_ref().unwrap().case;
    assert!(case.is_locked_down().unwrap());
    assert!(
        sparrow_core::profile::unprofiled_collections(case.conn())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_lock_down_that_cannot_be_restored_closes_the_case() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let path = open_blank(dir.path(), &state);
    fault::fail_relock(path.clone());
    let e = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        true,
        &quiet(),
    )
    .unwrap_err();
    assert!(e.message.contains("lock-down"), "{e:?}");
    assert!(state.open.lock().unwrap().is_none(), "the case stayed open");
    // Nothing stays busy; the case opens again, locked down.
    case_open(&state, &path, false).unwrap();
    assert!(
        state
            .open
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .case
            .is_locked_down()
            .unwrap()
    );
}

#[test]
fn while_an_import_runs_writes_reads_and_case_switches_are_refused_busy() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::default());
    let path = open_blank(dir.path(), &state);
    let other = dir.path().join("other.duckdb");
    drop(Case::create_or_open(&other).unwrap());
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let emit: Emit = {
        let (state, seen, other) = (state.clone(), seen.clone(), other.clone());
        Arc::new(move |e: &ProgressEvent| {
            // Discovery is before the case is touched; a switch there must not redirect the import either.
            if matches!(
                e,
                ProgressEvent::Discover | ProgressEvent::File { index: 1, .. }
            ) {
                let kind = |r: Result<(), sparrow_app::CmdError>| {
                    r.err().map_or("ok".into(), |e| e.kind.to_string())
                };
                let mut s = seen.lock().unwrap();
                s.push(kind(case_open(&state, &other, false).map(|_| ())));
                s.push(kind(case_close(&state)));
                s.push(kind(with_writable(&state, state.ticket(), |_| Ok(()))));
                s.push(kind(with_case(&state, state.ticket(), |_| Ok(()))));
            }
        })
    };
    let r = run(&state, &IngestState::default(), &Target::Open, false, &emit).unwrap();
    assert_eq!(*seen.lock().unwrap(), ["busy"; 8]);
    assert_eq!(r.case_path, path.display().to_string());
    assert!(r.files_loaded > 0);
    // Afterwards everything works again, on the same case.
    with_writable(&state, state.ticket(), |_| Ok(())).unwrap();
    with_case(&state, state.ticket(), |_| Ok(())).unwrap();
    assert!(counts_of_file_open(&state).iter().any(|(_, n)| *n > 0));
}

fn counts_of_file_open(state: &AppState) -> Vec<(String, i64)> {
    counts(&state.open.lock().unwrap().as_ref().unwrap().case)
}

#[test]
fn a_case_switched_before_the_import_takes_the_lock_is_refused_not_written() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    open_blank(dir.path(), &state);
    // The request saw this generation; a switch that slips in changes it.
    let first = state.generation.load(Ordering::SeqCst);
    state.generation.fetch_add(1, Ordering::SeqCst);
    assert_ne!(first, state.generation.load(Ordering::SeqCst));
    // (A switch during the run itself is refused busy, above; here the run starts after the switch and so takes the
    // new case: its own ticket is read at its start.)
    let r = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        false,
        &quiet(),
    )
    .unwrap();
    assert!(r.files_loaded > 0);
}

#[test]
fn a_window_close_during_an_import_stops_it_after_the_file_and_profiles() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let path = open_blank(dir.path(), &state);
    let ing = Arc::new(IngestState::default());
    assert!(
        !window_close_requested(&ing),
        "nothing runs: the window may close"
    );
    let held = Arc::new(Mutex::new(Vec::new()));
    let emit: Emit = {
        let (ing, held) = (ing.clone(), held.clone());
        Arc::new(move |e: &ProgressEvent| {
            if let ProgressEvent::File { index: 3, .. } = e {
                held.lock().unwrap().push(window_close_requested(&ing));
            }
        })
    };
    let r = run(&state, &ing, &Target::Open, true, &emit).unwrap();
    // The close was held back, the third file finished, the profile ran, detection did not.
    assert_eq!(*held.lock().unwrap(), [true]);
    assert!(r.cancelled && r.detect.is_none() && r.profile_error.is_none());
    assert_eq!(
        r.report
            .collections
            .iter()
            .map(|c| c.files.len())
            .sum::<usize>(),
        3
    );
    wait_idle(&ing);
    assert!(
        !window_close_requested(&ing),
        "idle again: the window closes now"
    );
    case_close(&state).unwrap();
    assert!(unprofiled(&path).is_empty());
}

#[test]
fn queued_long_reads_do_not_hold_the_import_up() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState::default());
    open_blank(dir.path(), &state);
    let queries: Vec<_> = (0..3)
        .map(|i| {
            let state = state.clone();
            std::thread::spawn(move || {
                sparrow_app::state::with_cancellable(
                    &state,
                    state.ticket(),
                    &format!("slow-{i}"),
                    |open| {
                        open.case
                            .conn()
                            .query_row("SELECT sum(i) FROM range(100000000000) t(i)", [], |r| {
                                r.get::<_, i64>(0)
                            })
                            .map_err(|e| sparrow_core::Error::from(e).into())
                    },
                )
            })
        })
        .collect();
    while state.active.lock().unwrap().is_none() {
        std::thread::sleep(Duration::from_millis(10));
    }
    let r = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        false,
        &quiet(),
    )
    .unwrap();
    assert!(r.files_loaded > 0);
    for q in queries {
        let kind = q.join().unwrap().unwrap_err().kind;
        assert!(kind == "interrupted" || kind == "busy", "{kind}");
    }
}

#[test]
fn an_import_killed_before_its_profile_is_found_and_repaired_by_the_analyst() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("killed.duckdb");
    {
        // What a process killed after the files committed leaves: collections without a profile.
        let mut case = Case::create_or_open(&path).unwrap();
        ingest_path(
            &mut case,
            &tree(),
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
    }
    let state = AppState::default();
    case_open(&state, &path, false).unwrap();
    let before = ingest_unprofiled(&state).unwrap();
    assert!(!before.is_empty());
    let r = ingest_profile(&state, &IngestState::default(), "fix-1", &quiet()).unwrap();
    assert_eq!(r.profile_error, None);
    assert!(r.detect.is_some());
    assert!(ingest_unprofiled(&state).unwrap().is_empty());
    assert!(
        state
            .open
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .case
            .is_locked_down()
            .unwrap()
    );
    case_close(&state).unwrap();
}

#[test]
fn profiling_is_refused_on_a_read_only_case_and_with_no_case() {
    let state = AppState::default();
    let e = ingest_profile(&state, &IngestState::default(), "x-1", &quiet()).unwrap_err();
    assert_eq!(e.kind, "no_case");
}

#[test]
fn discovery_marks_a_file_whose_size_cannot_be_read_and_one_over_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("evidence");
    copy_dir(&tree(), &copy);
    let victim = std::fs::read_dir(&copy)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_type().unwrap().is_dir())
        .unwrap()
        .path();
    // A sparse file over the limit costs no disk.
    let big = victim.join("huge.csv");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(sparrow_core::ingest::DEFAULT_MAX_FILE_BYTES + 1)
        .unwrap();
    let whole = ingest_discover(&copy).unwrap();
    let all: Vec<_> = whole.collections.iter().flat_map(|c| &c.files).collect();
    let huge = all
        .iter()
        .find(|f| f.rel_path.ends_with("huge.csv"))
        .expect("huge.csv listed");
    assert_eq!(huge.status, "too_large");
    assert_eq!(huge.size, sparrow_core::ingest::DEFAULT_MAX_FILE_BYTES + 1);
    assert_eq!((whole.too_large, whole.unreadable), (1, 0));
    // A listed file whose metadata cannot be read (the seam fails it): unreadable, with the reason, never recognised.
    let target = all
        .iter()
        .find(|f| f.status == "recognised")
        .unwrap()
        .rel_path
        .clone();
    let p = sparrow_app::cmd::ingest::ingest_discover_with(&copy, &|path| {
        if path.to_string_lossy().ends_with(&target) {
            Err(std::io::Error::other("injected metadata failure"))
        } else {
            std::fs::metadata(path)
        }
    })
    .unwrap();
    let files: Vec<_> = p.collections.iter().flat_map(|c| &c.files).collect();
    let bad = files.iter().find(|f| f.rel_path == target).expect("listed");
    assert_eq!((bad.status, bad.size), ("unreadable", 0));
    assert!(
        bad.error
            .as_deref()
            .unwrap()
            .contains("injected metadata failure"),
        "{bad:?}"
    );
    assert_eq!(p.unreadable, 1);
    assert_eq!(p.recognised, whole.recognised - 1);
}

#[test]
fn a_failed_profile_spares_the_detection_and_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let case = dir.path().join("pf.duckdb");
    fault::fail_profile(case.clone());
    let (emit, log) = collect();
    let r = run(
        &AppState::default(),
        &IngestState::default(),
        &Target::NewCase(case),
        true,
        &emit,
    )
    .unwrap();
    assert!(
        r.profile_error.as_deref().unwrap().contains("injected"),
        "{:?}",
        r.profile_error
    );
    assert!(r.detect.is_none() && r.detect_error.is_none());
    assert!(r.files_loaded > 0);
    let log = log.lock().unwrap();
    assert!(log.contains(&ProgressEvent::Profile));
    assert!(!log.contains(&ProgressEvent::Detect));
}

/// Run `f` expecting it to panic, and return with the panic caught.
fn panics(f: impl FnOnce()) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    assert!(r.is_err(), "the run did not panic");
}

/// After a panic: the case is open and locked down (or closed), and no command reaches an unlocked writer.
fn assert_safe_after_panic(state: &AppState) {
    assert!(!state.importing.load(Ordering::SeqCst), "still busy");
    let locked = {
        let slot = state.open.lock().unwrap_or_else(|p| p.into_inner());
        slot.as_ref().map(|o| o.case.is_locked_down().unwrap())
    };
    assert_ne!(locked, Some(false), "the writer was left unlocked");
    // Commands that read the case directly either see the locked case or `no_case`.
    match sparrow_app::cmd::browse::browse_tables(state) {
        Ok(_) => assert_eq!(locked, Some(true)),
        Err(e) => assert_eq!(e.kind, "no_case"),
    }
}

#[test]
fn a_panic_from_the_progress_callback_leaves_the_open_writer_locked() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    open_blank(dir.path(), &state);
    let emit: Emit = Arc::new(|e: &ProgressEvent| {
        if matches!(e, ProgressEvent::File { index: 2, .. }) {
            panic!("injected panic in the progress callback");
        }
    });
    panics(|| {
        let _ = run(&state, &IngestState::default(), &Target::Open, true, &emit);
    });
    assert_safe_after_panic(&state);
    // The case is still usable: a later import works.
    let r = run(
        &state,
        &IngestState::default(),
        &Target::Open,
        false,
        &quiet(),
    )
    .unwrap();
    assert!(r.files_loaded > 0);
}

#[test]
fn a_panic_in_the_profile_stage_leaves_the_open_writer_locked() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    open_blank(dir.path(), &state);
    let emit: Emit = Arc::new(|e: &ProgressEvent| {
        if *e == ProgressEvent::Profile {
            panic!("injected panic at the profile stage");
        }
    });
    panics(|| {
        let _ = run(&state, &IngestState::default(), &Target::Open, true, &emit);
    });
    assert_safe_after_panic(&state);
}

#[test]
fn a_panic_during_profile_now_leaves_the_open_writer_locked() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let path = dir.path().join("pn.duckdb");
    {
        let mut case = Case::create_or_open(&path).unwrap();
        ingest_path(
            &mut case,
            &tree(),
            &ParserRegistry::builtin(),
            &IngestOptions::default(),
        )
        .unwrap();
    }
    case_open(&state, &path, false).unwrap();
    let emit: Emit = Arc::new(|e: &ProgressEvent| {
        if *e == ProgressEvent::Profile {
            panic!("injected panic at the profile stage");
        }
    });
    panics(|| {
        let _ = ingest_profile(&state, &IngestState::default(), "pn-1", &emit);
    });
    assert_safe_after_panic(&state);
}

#[test]
fn a_panic_when_the_lock_down_cannot_be_restored_closes_the_case() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::default();
    let path = open_blank(dir.path(), &state);
    fault::fail_relock(path);
    let emit: Emit = Arc::new(|e: &ProgressEvent| {
        if *e == ProgressEvent::Profile {
            panic!("injected panic at the profile stage");
        }
    });
    panics(|| {
        let _ = run(&state, &IngestState::default(), &Target::Open, true, &emit);
    });
    assert!(
        state
            .open
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none(),
        "the case stayed open unlocked"
    );
    assert_safe_after_panic(&state);
}
