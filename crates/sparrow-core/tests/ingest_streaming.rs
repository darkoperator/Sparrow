//! Ingest reads files as streams: no default size limit, superseded files skip the size check, and a cancel, a read
//! error or a file that changes while it is read fails closed for that file only.

use serde_json::json;
use sparrow_core::Case;
use sparrow_core::discovery::discover_collections;
use sparrow_core::fixtures::{self, csv_line, utf8_bom};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    FileReport, FileStatus, IngestOptions, IngestProgress, IngestReport, ReadEvent, ReadPhase,
    WHOLE_FILE_MAX_BYTES, XLSX_MAX_BYTES, ingest_collections_partial, ingest_path,
};
use sparrow_core::readers::stream::CHUNK_BYTES;
use sparrow_synth::big_file::{BigEncoding, BigKind, write_big_file};
use sparrow_synth::case_dump::dump_case;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn count(case: &Case, sql: &str) -> i64 {
    case.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn files(report: &IngestReport) -> Vec<&FileReport> {
    report.collections.iter().flat_map(|c| &c.files).collect()
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    files(report)
        .into_iter()
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("{rel} not in report: {report:#?}"))
}

/// A Purview audit search CSV (`portal.ual`) of `rows` MailItemsAccessed records whose ids are unique to `seed`.
fn portal_ual(seed: u32, rows: u64) -> String {
    let mut s = String::from(
        "RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitsNames\r\n",
    );
    for i in 0..rows {
        let id = format!("{seed:08x}-0000-4000-8000-{i:012x}");
        let time = format!(
            "2026-01-01T{:02}:{:02}:{:02}",
            i / 3600 % 24,
            i / 60 % 60,
            i % 60
        );
        let audit = json!({
            "CreationTime": time, "Id": id, "Operation": "MailItemsAccessed",
            "OrganizationId": "d5c9185c-9bf3-45a3-92f3-c19c635feb78", "RecordType": 50,
            "ResultStatus": "Succeeded", "UserType": 0, "Version": 1, "Workload": "Exchange",
            "ClientIP": "198.51.100.7", "UserId": "rowan.porter@contoso.example",
            "MailboxOwnerUPN": "rowan.porter@contoso.example", "SessionId": format!("session-{seed}-{i}"),
        });
        s += &csv_line(&[
            &id,
            &format!("{time}.0000000Z"),
            "50",
            "MailItemsAccessed",
            "rowan.porter@contoso.example",
            &audit.to_string(),
            "",
            "",
        ]);
    }
    s
}

const ROWS: u64 = 200;

/// Two portal UAL downloads, `a_ual.csv` then `b_ual.csv`, of [`ROWS`] distinct records each.
fn two_downloads(dir: &Path) -> std::path::PathBuf {
    let root = dir.join("portal");
    fixtures::write(&root, "a_ual.csv", portal_ual(1, ROWS).as_bytes());
    fixtures::write(&root, "b_ual.csv", portal_ual(2, ROWS).as_bytes());
    root
}

/// Options with tiny reads and batches, so a small file spans many reads and batches, and `hook` seeing each read.
fn small_reads(
    hook: impl Fn(&ReadEvent) -> std::io::Result<()> + Send + Sync + 'static,
) -> IngestOptions {
    IngestOptions {
        chunk_bytes: Some(4096),
        batch_rows: 10,
        read_hook: Some(Arc::new(hook)),
        ..IngestOptions::default()
    }
}

fn ual_rows_of(case: &Case, rel: &str) -> i64 {
    count(
        case,
        &format!(
            "SELECT count(*) FROM record_sources rs JOIN source_files f USING (file_id)
             WHERE f.rel_path = '{rel}' AND rs.table_name = 'ual_events'"
        ),
    )
}

#[test]
fn big_file_has_no_default_limit() {
    assert_eq!(IngestOptions::default().max_file_bytes, None);
    assert_eq!(XLSX_MAX_BYTES, 1 << 30);
    assert_eq!(WHOLE_FILE_MAX_BYTES, 256 << 20);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("portal");
    let out = root.join(BigKind::PortalUal.example_rel_path());
    let len = write_big_file(
        BigKind::PortalUal,
        2 * CHUNK_BYTES as u64 + 1,
        BigEncoding::Utf8,
        &out,
    )
    .unwrap();
    // Three reads of CHUNK_BYTES at least.
    assert!(len > 2 * CHUNK_BYTES as u64, "{len}");
    let mut streamed = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut streamed,
        &root,
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    let f = row(&report, BigKind::PortalUal.example_rel_path());
    assert_eq!(f.status, FileStatus::Parsed, "{f:#?}");
    assert!(f.records_loaded > 5_000, "{f:#?}");
    assert_eq!(f.records_loaded, f.records_read);
    // The same file read in one window holding its whole text.
    let mut whole = Case::in_memory().unwrap();
    let opts = IngestOptions {
        chunk_bytes: Some(len as usize + 1),
        ..IngestOptions::default()
    };
    ingest_path(&mut whole, &root, &ParserRegistry::builtin(), &opts).unwrap();
    let (a, b) = (dump_case(&streamed).unwrap(), dump_case(&whole).unwrap());
    assert!(a["ual_events"].len() as u64 == f.records_loaded);
    assert!(a == b, "streamed rows differ from the whole-text ingest");
}

const RAW_HEADER: &[&str] = &[
    "RecordType",
    "CreationDate",
    "UserIds",
    "Operations",
    "AuditData",
    "ResultIndex",
    "ResultCount",
    "AuditSearchRequestMetadata",
    "Identity",
    "IsValid",
    "ObjectState",
];

fn raw_row(id: &str, op: &str) -> String {
    let audit = json!({
        "CreationTime": "2026-09-01T10:20:00", "Id": id, "Operation": op,
        "OrganizationId": "0e0e0e0e-0000-4000-8000-00000000000a", "RecordType": 1,
        "ResultStatus": "True", "UserType": 2, "Version": 1, "Workload": "Exchange",
        "ClientIP": "203.0.113.10", "UserId": "alice@contoso.example", "ObjectId": "alice@contoso.example",
    });
    csv_line(&[
        "ExchangeAdmin",
        "9/1/2026 10:20:00 AM",
        "alice@contoso.example",
        op,
        &audit.to_string(),
        "1",
        "1",
        "",
        id,
        "True",
        "Unchanged",
    ])
}

#[test]
fn superseded_file_over_limit_is_skipped_not_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let window = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv";
    let merged = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";
    let one = raw_row("11111111-1111-4111-8111-111111111111", "Set-Mailbox");
    let two = raw_row("22222222-2222-4222-8222-222222222222", "New-InboxRule");
    let window_bytes = utf8_bom(&format!("{}{one}", csv_line(RAW_HEADER)));
    fixtures::write(&out, window, &window_bytes);
    fixtures::write(
        &out,
        merged,
        &utf8_bom(&format!("{}{one}{two}", csv_line(RAW_HEADER))),
    );
    let limit = window_bytes.len() as u64;
    assert!(std::fs::metadata(out.join(merged)).unwrap().len() > limit);
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        max_file_bytes: Some(limit),
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts).unwrap();
    assert_eq!(row(&report, window).status, FileStatus::Parsed);
    let m = row(&report, merged);
    assert_eq!(m.status, FileStatus::SkippedSuperseded, "{m:#?}");
    assert!(m.warnings.iter().all(|w| !w.contains("limit")), "{m:#?}");
    assert!(
        files(&report).iter().all(|f| f.status != FileStatus::Error),
        "{report:#?}"
    );
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM source_files WHERE status = 'error'"
        ),
        0
    );
}

/// Ingest `root` with `opts`: the run's report and whether it stopped.
fn run(case: &mut Case, root: &Path, opts: &IngestOptions) -> (IngestReport, bool) {
    let collections = discover_collections(root).unwrap();
    let run =
        ingest_collections_partial(case, &collections, &ParserRegistry::builtin(), opts).unwrap();
    assert!(run.error.is_none(), "{:?}", run.error);
    (run.report, run.stopped)
}

/// A cancel that fires once `b_ual.csv` has read `after` bytes in `phase`: what is left of the case, the report,
/// whether the ingest stopped, the bytes `b_ual.csv` read in `phase` and every phase it opened.
fn cancel_in(phase: ReadPhase, after: u64) -> (Case, IngestReport, bool, u64, Vec<ReadPhase>) {
    let dir = tempfile::tempdir().unwrap();
    let root = two_downloads(dir.path());
    let flag = Arc::new(AtomicBool::new(false));
    let read = Arc::new(AtomicU64::new(0));
    let opened = Arc::new(Mutex::new(Vec::new()));
    let (f, r, o) = (flag.clone(), read.clone(), opened.clone());
    let mut opts = small_reads(move |e| {
        if e.rel_path != "b_ual.csv" {
            return Ok(());
        }
        if e.bytes == 0 {
            o.lock().unwrap().push(e.phase);
        }
        if e.phase == phase && r.fetch_add(e.bytes, Ordering::SeqCst) + e.bytes >= after {
            f.store(true, Ordering::SeqCst);
        }
        Ok(())
    });
    let c = flag.clone();
    opts.cancel = Some(Arc::new(move || c.load(Ordering::SeqCst)));
    let mut case = Case::in_memory().unwrap();
    let (report, stopped) = run(&mut case, &root, &opts);
    assert!(flag.load(Ordering::SeqCst), "the cancel never fired");
    let opened = opened.lock().unwrap().clone();
    (case, report, stopped, read.load(Ordering::SeqCst), opened)
}

fn assert_file_two_rolled_back(case: &Case, report: &IngestReport, stopped: bool) {
    assert!(stopped, "the ingest did not stop");
    // As a between-files cancel leaves it: file 1 in the report and loaded, file 2 absent and with no rows.
    let names: Vec<&str> = files(report).iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(names, ["a_ual.csv"], "{report:#?}");
    assert_eq!(row(report, "a_ual.csv").status, FileStatus::Parsed);
    assert_eq!(ual_rows_of(case, "a_ual.csv"), ROWS as i64);
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM source_files WHERE rel_path = 'b_ual.csv'"
        ),
        0
    );
    assert_eq!(count(case, "SELECT count(*) FROM ual_events"), ROWS as i64);
    assert_eq!(
        count(
            case,
            "SELECT count(*) FROM ual_events WHERE CAST(record_id AS VARCHAR) LIKE '00000002-%'"
        ),
        0
    );
    assert_eq!(
        count(case, "SELECT count(*) FROM record_sources"),
        ROWS as i64
    );
    assert_eq!(count(case, "SELECT count(*) FROM parse_errors"), 0);
}

#[test]
fn cancel_mid_file_rolls_back_that_file() {
    let size = portal_ual(2, ROWS).len() as u64;
    // During the load pass (UAL's third), after batches of 10 rows were staged: it stops inside that pass.
    let (case, report, stopped, read, opened) = cancel_in(ReadPhase::Pass(3), size / 2);
    assert_file_two_rolled_back(&case, &report, stopped);
    assert!(read < size, "pass 3 read all {read} bytes");
    assert_eq!(
        opened,
        [
            ReadPhase::Admit,
            ReadPhase::Pass(1),
            ReadPhase::Pass(2),
            ReadPhase::Pass(3)
        ]
    );
    // During the admission of file 2: it stops there, before any record pass.
    let (case, report, stopped, read, opened) = cancel_in(ReadPhase::Admit, 4096);
    assert_file_two_rolled_back(&case, &report, stopped);
    assert!(read < size, "admission read all {read} bytes");
    assert_eq!(opened, [ReadPhase::Admit]);
}

#[test]
fn file_changed_between_passes_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = two_downloads(dir.path());
    let target = root.join("a_ual.csv");
    let extra = portal_ual(9, 1);
    let extra_row = extra.lines().nth(1).unwrap().to_string() + "\r\n";
    let opts = small_reads(move |e| {
        // Opening pass 2 of a_ual.csv: a record is appended to the file.
        if e.rel_path == "a_ual.csv" && e.phase == ReadPhase::Pass(2) && e.bytes == 0 {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&target)
                .unwrap();
            f.write_all(extra_row.as_bytes()).unwrap();
        }
        Ok(())
    });
    let mut case = Case::in_memory().unwrap();
    let (report, stopped) = run(&mut case, &root, &opts);
    assert!(!stopped);
    let a = row(&report, "a_ual.csv");
    assert_eq!(a.status, FileStatus::Error, "{a:#?}");
    assert!(
        a.warnings
            .iter()
            .any(|w| w.contains("file changed while it was read")),
        "{a:#?}"
    );
    assert_eq!(ual_rows_of(&case, "a_ual.csv"), 0);
    assert_eq!(row(&report, "b_ual.csv").status, FileStatus::Parsed);
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), ROWS as i64);
    assert_eq!(
        count(
            &case,
            "SELECT count(*) FROM ual_events WHERE CAST(record_id AS VARCHAR) LIKE '00000002-%'"
        ),
        ROWS as i64
    );
}

#[test]
fn read_error_mid_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = two_downloads(dir.path());
    let read = Arc::new(AtomicU64::new(0));
    let r = read.clone();
    let half = portal_ual(1, ROWS).len() as u64 / 2;
    let opts = small_reads(move |e| {
        if e.rel_path == "a_ual.csv"
            && e.phase == ReadPhase::Pass(3)
            && r.fetch_add(e.bytes, Ordering::SeqCst) + e.bytes >= half
        {
            return Err(std::io::Error::other("injected read error"));
        }
        Ok(())
    });
    let mut case = Case::in_memory().unwrap();
    let (report, stopped) = run(&mut case, &root, &opts);
    assert!(!stopped);
    assert!(
        read.load(Ordering::SeqCst) >= half,
        "the error was never injected"
    );
    let a = row(&report, "a_ual.csv");
    assert_eq!(a.status, FileStatus::Error, "{a:#?}");
    assert!(
        a.warnings.iter().any(|w| w.contains("injected read error")),
        "{a:#?}"
    );
    assert_eq!(ual_rows_of(&case, "a_ual.csv"), 0);
    let a_id = a.file_id.unwrap();
    assert_eq!(
        count(
            &case,
            &format!("SELECT count(*) FROM parse_errors WHERE file_id = {a_id}")
        ),
        0
    );
    assert_eq!(row(&report, "b_ual.csv").status, FileStatus::Parsed);
    assert_eq!(count(&case, "SELECT count(*) FROM ual_events"), ROWS as i64);
}

#[test]
fn whole_file_over_guard_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = fixtures::hawk_tree(dir.path());
    let org = "Tenant/OrgConfig.txt";
    let body = b"\r\nAuditDisabled          : True\r\nMailTipsAllTipsEnabled : True\r\nName                   : Contoso\r\n\r\n";
    fixtures::write(&root, org, body);
    // Under the guard the Format-List file loads.
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(
        &mut case,
        dir.path(),
        &ParserRegistry::builtin(),
        &IngestOptions::default(),
    )
    .unwrap();
    assert_eq!(row(&report, org).status, FileStatus::Parsed);
    // Over it (a test override of WHOLE_FILE_MAX_BYTES), it is an error naming the limit, and nothing loads.
    let limit = body.len() as u64 - 1;
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        whole_max_bytes: Some(limit),
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, dir.path(), &ParserRegistry::builtin(), &opts).unwrap();
    let f = row(&report, org);
    assert_eq!(f.status, FileStatus::Error, "{f:#?}");
    assert!(
        f.warnings
            .iter()
            .any(|w| w.contains(&format!("{limit} byte limit")) && w.contains("read whole")),
        "{f:#?}"
    );
    assert_eq!(count(&case, "SELECT count(*) FROM audit_config"), 0);
}

/// Every progress event of an ingest of `root` with `opts` (its `progress` replaced), and the report.
fn events_of(root: &Path, mut opts: IngestOptions) -> (IngestReport, Vec<IngestProgress>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    opts.progress = Some(Arc::new(move |p: &IngestProgress| {
        s.lock().unwrap().push(p.clone())
    }));
    let mut case = Case::in_memory().unwrap();
    let (report, stopped) = run(&mut case, root, &opts);
    assert!(!stopped);
    let events = seen.lock().unwrap().clone();
    (report, events)
}

/// One `FileStep` event's fields.
#[derive(Debug, Clone, PartialEq)]
struct Step {
    steps: Vec<&'static str>,
    step: usize,
    bytes_done: u64,
    bytes_total: u64,
    records: u64,
    errors: u64,
}

/// The `FileStep` events of `rel`: those between its `File` event and the next `File` event (its last handling, when
/// it is handled twice: deferred, then retried).
fn file_steps(events: &[IngestProgress], rel: &str) -> Vec<Step> {
    let mut out = Vec::new();
    let mut inside = false;
    for e in events {
        match e {
            IngestProgress::File { rel_path, .. } => {
                inside = rel_path == rel;
                if inside {
                    out.clear();
                }
            }
            IngestProgress::FileStep {
                steps,
                step,
                bytes_done,
                bytes_total,
                records,
                errors,
            } if inside => out.push(Step {
                steps: steps.clone(),
                step: *step,
                bytes_done: *bytes_done,
                bytes_total: *bytes_total,
                records: *records,
                errors: *errors,
            }),
            _ => {}
        }
    }
    out
}

/// The events of `steps` grouped by step, in order.
fn by_step(steps: &[Step]) -> Vec<Vec<Step>> {
    let mut out: Vec<Vec<Step>> = Vec::new();
    for s in steps {
        match out.last_mut() {
            Some(g) if g[0].step == s.step => g.push(s.clone()),
            _ => out.push(vec![s.clone()]),
        }
    }
    out
}

/// A clock reading `ms` milliseconds after a fixed start: tests move it.
fn fake_clock(ms: Arc<AtomicU64>) -> sparrow_core::ingest::ClockFn {
    let base = Instant::now();
    Arc::new(move || base + Duration::from_millis(ms.load(Ordering::SeqCst)))
}

const UAL_STEPS: [&str; 3] = ["Checking file", "Checking dates", "Loading records"];

/// [`portal_ual`] of [`ROWS`] records and one more whose AuditData is not JSON (a parse error).
fn ual_with_one_bad_row() -> String {
    portal_ual(1, ROWS)
        + &csv_line(&[
            "ffffffff-0000-4000-8000-000000000000",
            "2026-01-01T05:00:00.0000000Z",
            "50",
            "MailItemsAccessed",
            "rowan.porter@contoso.example",
            "not json",
            "",
            "",
        ])
}

#[test]
fn file_step_events_cover_every_pass() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("portal");
    let body = ual_with_one_bad_row();
    fixtures::write(&root, "a_ual.csv", body.as_bytes());
    let size = body.len() as u64;
    // A clock that moves a second each time it is read: every read reports, so the events follow each pass.
    let ms = Arc::new(AtomicU64::new(0));
    let m = ms.clone();
    let base = Instant::now();
    let opts = IngestOptions {
        chunk_bytes: Some(4096),
        batch_rows: 10,
        clock: Some(Arc::new(move || {
            base + Duration::from_secs(m.fetch_add(1, Ordering::SeqCst))
        })),
        ..IngestOptions::default()
    };
    let (report, events) = events_of(&root, opts);
    let a = row(&report, "a_ual.csv");
    assert_eq!(a.status, FileStatus::Parsed, "{a:#?}");
    assert_eq!((a.records_loaded, a.records_error), (ROWS, 1), "{a:#?}");
    assert!(
        events.contains(&IngestProgress::File {
            collection: 1,
            collections: 1,
            index: 1,
            files: 1,
            rel_path: "a_ual.csv".into(),
            size,
            bytes_done_before: 0,
            bytes_total: size,
        }),
        "{events:#?}"
    );
    let steps = file_steps(&events, "a_ual.csv");
    // A portal download is told from its content: its steps are known from its head, before the first event.
    assert!(
        steps
            .iter()
            .all(|s| s.bytes_total == size && s.steps == UAL_STEPS),
        "{steps:#?}"
    );
    let groups = by_step(&steps);
    let order: Vec<usize> = groups.iter().map(|g| g[0].step).collect();
    assert_eq!(order, [0, 1, 2], "{steps:#?}");
    let reads = size.div_ceil(4096) as usize;
    for g in &groups {
        assert_eq!(g[0].bytes_done, 0, "step {} starts at 0: {g:#?}", g[0].step);
        assert_eq!(
            g.last().unwrap().bytes_done,
            size,
            "step {} ends at 100 %: {g:#?}",
            g[0].step
        );
        assert!(
            g.windows(2).all(|w| w[0].bytes_done <= w[1].bytes_done),
            "step {} goes back: {g:#?}",
            g[0].step
        );
        // Each read of the pass reported (the clock always moved past the throttle); the hash pass from the read
        // that completed the head on (the reads before it are reported with it).
        let head_reads = (sparrow_core::discovery::SNIFF_BYTES as u64)
            .min(size)
            .div_ceil(4096) as usize;
        let reads = if g[0].step == 0 {
            reads - head_reads + 1
        } else {
            reads
        };
        assert!(
            g.len() >= reads,
            "step {}: {} events for {reads} reads",
            g[0].step,
            g.len()
        );
    }
    assert!(
        steps
            .windows(2)
            .all(|w| w[0].records <= w[1].records && w[0].errors <= w[1].errors),
        "{steps:#?}"
    );
    let last = steps.last().unwrap();
    assert_eq!((last.records, last.errors), (ROWS, 1), "{last:#?}");
    // Records count up while the load pass reads, not only at its end.
    assert!(
        groups[2].iter().any(|s| s.records > 0 && s.records < ROWS),
        "{:#?}",
        groups[2]
    );
}

#[test]
fn progress_is_throttled() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("portal");
    let body = portal_ual(1, ROWS);
    fixtures::write(&root, "a_ual.csv", body.as_bytes());
    // A clock that never moves: only each step's start and end are reported, however many reads there are.
    let frozen = IngestOptions {
        chunk_bytes: Some(4096),
        batch_rows: 10,
        clock: Some(fake_clock(Arc::new(AtomicU64::new(0)))),
        ..IngestOptions::default()
    };
    let (_, events) = events_of(&root, frozen);
    let groups = by_step(&file_steps(&events, "a_ual.csv"));
    let counts: Vec<usize> = groups.iter().map(Vec::len).collect();
    assert_eq!(counts, [2, 2, 2], "{groups:#?}");
    // A clock that moves 40 ms with each read: at most one event per 100 ms of it besides each step's start and
    // end, and about that many.
    let ms = Arc::new(AtomicU64::new(0));
    let reads = Arc::new(Mutex::new([0u64; 3]));
    let (m, r) = (ms.clone(), reads.clone());
    let mut moving = small_reads(move |e| {
        if e.bytes > 0 {
            m.fetch_add(40, Ordering::SeqCst);
            let step = match e.phase {
                ReadPhase::Admit => 0,
                ReadPhase::Pass(1 | 2) => 1,
                ReadPhase::Pass(_) => 2,
            };
            r.lock().unwrap()[step] += 1;
        }
        Ok(())
    });
    moving.clock = Some(fake_clock(ms));
    let (_, events) = events_of(&root, moving);
    let groups = by_step(&file_steps(&events, "a_ual.csv"));
    let reads = *reads.lock().unwrap();
    assert_eq!(groups.len(), 3, "{groups:#?}");
    for (g, reads) in groups.iter().zip(reads) {
        assert!(reads > 20, "{reads} reads");
        // The hash pass starts reporting once the head is read (its steps are known then).
        let reads = if g[0].step == 0 {
            reads - (sparrow_core::discovery::SNIFF_BYTES as u64).div_ceil(4096)
        } else {
            reads
        };
        let within = g.len() as u64 - 2;
        let most = reads * 40 / 100;
        assert!(
            within <= most && within >= most / 2,
            "step {}: {within} events within it for {reads} reads of 40 ms",
            g[0].step
        );
    }
}

#[test]
fn overall_bytes_weigh_the_files_to_load() {
    // Two downloads: the second starts after the first's bytes, of both.
    let dir = tempfile::tempdir().unwrap();
    let root = two_downloads(dir.path());
    let a = std::fs::metadata(root.join("a_ual.csv")).unwrap().len();
    let b = std::fs::metadata(root.join("b_ual.csv")).unwrap().len();
    let (_, events) = events_of(&root, IngestOptions::default());
    let files: Vec<(String, u64, u64, u64)> = events
        .iter()
        .filter_map(|e| match e {
            IngestProgress::File {
                rel_path,
                size,
                bytes_done_before,
                bytes_total,
                ..
            } => Some((rel_path.clone(), *size, *bytes_done_before, *bytes_total)),
            _ => None,
        })
        .collect();
    assert_eq!(
        files,
        [
            ("a_ual.csv".to_string(), a, 0, a + b),
            ("b_ual.csv".to_string(), b, a, a + b)
        ]
    );
    // A merged copy known in advance to be superseded by its window file is only hashed: it is left out of the
    // total and adds nothing to it (size 0); its hash pass is still reported, as the "Checking file" step.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let window = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv";
    let merged = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";
    let one = raw_row("11111111-1111-4111-8111-111111111111", "Set-Mailbox");
    let two = raw_row("22222222-2222-4222-8222-222222222222", "New-InboxRule");
    let window_bytes = utf8_bom(&format!("{}{one}", csv_line(RAW_HEADER)));
    let merged_bytes = utf8_bom(&format!("{}{one}{two}", csv_line(RAW_HEADER)));
    fixtures::write(&out, window, &window_bytes);
    fixtures::write(&out, merged, &merged_bytes);
    let w = window_bytes.len() as u64;
    let (report, events) = events_of(dir.path(), IngestOptions::default());
    assert_eq!(row(&report, merged).status, FileStatus::SkippedSuperseded);
    let files: Vec<(String, u64, u64, u64)> = events
        .iter()
        .filter_map(|e| match e {
            IngestProgress::File {
                rel_path,
                size,
                bytes_done_before,
                bytes_total,
                ..
            } => Some((rel_path.clone(), *size, *bytes_done_before, *bytes_total)),
            _ => None,
        })
        .collect();
    assert_eq!(
        files,
        [(window.to_string(), w, 0, w), (merged.to_string(), 0, w, w)]
    );
    let hashed = file_steps(&events, merged);
    let m = merged_bytes.len() as u64;
    assert_eq!(
        hashed.first().map(|s| (s.step, s.bytes_done)),
        Some((0, 0)),
        "{hashed:#?}"
    );
    assert!(
        hashed
            .iter()
            .all(|s| s.steps == ["Checking file"] && s.bytes_total == m),
        "{hashed:#?}"
    );
    assert_eq!(hashed.last().unwrap().bytes_done, m);
}

/// Every handled file of `root` reports each step it reaches once, in order, from 0 to 100 % (a file that failed may
/// stop below), its bytes never going back within a step, its counts never going back.
fn assert_steps_well_formed(root: &Path) -> usize {
    let ms = Arc::new(AtomicU64::new(0));
    let m = ms.clone();
    let base = Instant::now();
    let opts = IngestOptions {
        chunk_bytes: Some(64 * 1024),
        clock: Some(Arc::new(move || {
            base + Duration::from_secs(m.fetch_add(1, Ordering::SeqCst))
        })),
        ..IngestOptions::default()
    };
    let (report, events) = events_of(root, opts);
    let mut multi = 0;
    for f in files(&report) {
        let steps = file_steps(&events, &f.rel_path);
        assert!(!steps.is_empty(), "{}: no step events", f.rel_path);
        let groups = by_step(&steps);
        let order: Vec<usize> = groups.iter().map(|g| g[0].step).collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]) && order[0] == 0,
            "{} ({:?}): steps {order:?}",
            f.rel_path,
            f.artifact_id
        );
        if order.len() > 2 {
            multi += 1;
        }
        for g in &groups {
            let ctx = format!(
                "{} ({:?}) step {}: {g:#?}",
                f.rel_path, f.artifact_id, g[0].step
            );
            assert!(g.iter().all(|s| s.step < s.steps.len()), "{ctx}");
            assert_eq!(g[0].bytes_done, 0, "{ctx}");
            assert!(
                g.windows(2).all(|w| w[0].bytes_done <= w[1].bytes_done),
                "{ctx}"
            );
            if f.status != FileStatus::Error {
                let last = g.last().unwrap();
                assert_eq!(last.bytes_done, last.bytes_total, "{ctx}");
            }
        }
        assert!(
            steps
                .windows(2)
                .all(|w| w[0].records <= w[1].records && w[0].errors <= w[1].errors),
            "{}: {steps:#?}",
            f.rel_path
        );
        if f.status == FileStatus::Parsed {
            let last = steps.last().unwrap();
            assert!(
                last.records >= f.records_loaded && last.errors == f.records_error,
                "{}: {last:#?} vs {f:#?}",
                f.rel_path
            );
        }
    }
    multi
}

#[test]
fn every_parser_reports_its_steps_from_0_to_100_percent() {
    use sparrow_synth::options::{Collector, GenerateOptions};
    let cache = sparrow_synth::test_cache!();
    let scenario = sparrow_synth::scenario::load("bec-aitm").unwrap();
    let mut multi = 0;
    for c in [
        Collector::Invictus,
        Collector::Hawk3,
        Collector::Hawk4,
        Collector::Portal,
    ] {
        let t = cache.tree(&scenario, &GenerateOptions::new(c, 17)).unwrap();
        multi += assert_steps_well_formed(&t.dir.join(&t.manifest.root));
    }
    let dir = tempfile::tempdir().unwrap();
    fixtures::hawk_tree(dir.path());
    assert_steps_well_formed(dir.path());
    // Multi-pass parsers (UAL, sign-ins, message trace detail) were among them.
    assert!(multi > 0);
}

#[test]
fn streamed_parsers_walk_every_step() {
    // Each streamed export alone, small but over several reads: every step of its parser, in order.
    let want: [(BigKind, &[&str]); 4] = [
        (BigKind::PortalUal, &UAL_STEPS),
        (BigKind::UalJson, &UAL_STEPS),
        (
            BigKind::SigninsCsv,
            &[
                "Checking file",
                "Checking columns",
                "Checking dates",
                "Loading records",
            ],
        ),
        (
            BigKind::MessageTraceDetail,
            &[
                "Checking file",
                "Grouping messages",
                "Checking dates",
                "Loading records",
            ],
        ),
    ];
    for (kind, steps) in want {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("portal");
        let rel = kind.example_rel_path();
        write_big_file(kind, 300 * 1024, BigEncoding::Utf8, &root.join(rel)).unwrap();
        assert_eq!(assert_steps_well_formed(dir.path()), 1, "{kind:?}");
        let (report, events) = events_of(dir.path(), IngestOptions::default());
        let f = files(&report)[0];
        assert_eq!(f.status, FileStatus::Parsed, "{kind:?}: {f:#?}");
        let got = file_steps(&events, &f.rel_path);
        let order: Vec<usize> = by_step(&got).iter().map(|g| g[0].step).collect();
        assert_eq!(order, (0..steps.len()).collect::<Vec<_>>(), "{kind:?}");
        assert_eq!(got.last().unwrap().steps, steps, "{kind:?}");
    }
}

/// [`raw_row`] whose AuditData time is the culture-formatted `time` (day/month order unknown when ambiguous).
fn raw_row_at(id: &str, op: &str, time: &str) -> String {
    let audit = json!({
        "CreationTime": time, "Id": id, "Operation": op,
        "OrganizationId": "0e0e0e0e-0000-4000-8000-00000000000a", "RecordType": 1,
        "ResultStatus": "True", "UserType": 2, "Version": 1, "Workload": "Exchange",
        "ClientIP": "203.0.113.10", "UserId": "alice@contoso.example", "ObjectId": "alice@contoso.example",
    });
    csv_line(&[
        "ExchangeAdmin",
        time,
        "alice@contoso.example",
        op,
        &audit.to_string(),
        "1",
        "1",
        "",
        id,
        "True",
        "Unchanged",
    ])
}

#[test]
fn a_copy_parsed_after_its_original_is_deferred_grows_the_total() {
    // The window file's dates are all ambiguous and nothing proved an order yet: it is deferred past the derived
    // stage, so its Merged copy (left out of the total as superseded) is parsed after all, proves the order, and the
    // window file is retried.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("OUT");
    let window = "UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.csv";
    let merged = "UnifiedAuditLog/20260910-100000/Merged/UAL-Combined.csv";
    let one = raw_row_at(
        "11111111-1111-4111-8111-111111111111",
        "Set-Mailbox",
        "9/1/2026 10:20:00 AM",
    );
    let two = raw_row_at(
        "22222222-2222-4222-8222-222222222222",
        "New-InboxRule",
        "9/13/2026 10:20:00 AM",
    );
    let window_bytes = utf8_bom(&format!("{}{one}", csv_line(RAW_HEADER)));
    let merged_bytes = utf8_bom(&format!("{}{one}{two}", csv_line(RAW_HEADER)));
    fixtures::write(&out, window, &window_bytes);
    fixtures::write(&out, merged, &merged_bytes);
    let (w, m) = (window_bytes.len() as u64, merged_bytes.len() as u64);
    let (report, events) = events_of(dir.path(), IngestOptions::default());
    assert_eq!(
        row(&report, window).status,
        FileStatus::Parsed,
        "{report:#?}"
    );
    assert_eq!(
        row(&report, merged).status,
        FileStatus::Parsed,
        "{report:#?}"
    );
    let files: Vec<(String, u64, u64, u64)> = events
        .iter()
        .filter_map(|e| match e {
            IngestProgress::File {
                rel_path,
                size,
                bytes_done_before,
                bytes_total,
                ..
            } => Some((rel_path.clone(), *size, *bytes_done_before, *bytes_total)),
            _ => None,
        })
        .collect();
    assert_eq!(
        files,
        [
            // Counted, deferred: its bytes are done when it is deferred.
            (window.to_string(), w, 0, w),
            // Left out as superseded, parsed after all: the total grows by exactly its size.
            (merged.to_string(), m, w, w + m),
            // The retry adds nothing: it was counted when deferred.
            (window.to_string(), 0, w + m, w + m),
        ]
    );
    // The bar still ends at 100 %.
    let (_, size, before, total) = files.last().unwrap();
    assert_eq!(before + size, *total);
}

#[test]
fn a_file_told_from_its_content_lists_its_steps_from_the_first_event() {
    // A portal download is classified by its header, not its name: its parser's steps are known once the head is
    // read, before the hash pass goes on, so no event of it ever shows "Checking file" alone.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("portal");
    let body = portal_ual(1, ROWS);
    assert!(body.len() > sparrow_core::discovery::SNIFF_BYTES);
    fixtures::write(&root, "a_ual.csv", body.as_bytes());
    let size = body.len() as u64;
    for chunk in [4096, CHUNK_BYTES] {
        let ms = Arc::new(AtomicU64::new(0));
        let m = ms.clone();
        let base = Instant::now();
        let opts = IngestOptions {
            chunk_bytes: Some(chunk),
            clock: Some(Arc::new(move || {
                base + Duration::from_secs(m.fetch_add(1, Ordering::SeqCst))
            })),
            ..IngestOptions::default()
        };
        let (_, events) = events_of(&root, opts);
        let steps = file_steps(&events, "a_ual.csv");
        assert_eq!(
            steps
                .first()
                .map(|s| (s.steps.clone(), s.step, s.bytes_done)),
            Some((UAL_STEPS.to_vec(), 0, 0)),
            "chunk {chunk}: {steps:#?}"
        );
        assert!(
            steps.iter().all(|s| s.steps == UAL_STEPS),
            "chunk {chunk}: {steps:#?}"
        );
        // The hash pass still reports to its end, and the bytes read before the head was told are not lost.
        let hash: Vec<&Step> = steps.iter().filter(|s| s.step == 0).collect();
        assert_eq!(hash.last().unwrap().bytes_done, size, "chunk {chunk}");
        if chunk == 4096 {
            assert!(
                hash.iter().any(|s| s.bytes_done > 0 && s.bytes_done < size),
                "chunk {chunk}: {hash:#?}"
            );
        }
    }
    // A portal workbook is classified from the whole of it: its first event lists the sign-in steps too.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("portal");
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    for (c, h) in ["Date (UTC)", "Request ID", "User agent", "Correlation ID"]
        .iter()
        .enumerate()
    {
        ws.write_string(0, c as u16, *h).unwrap();
    }
    fixtures::write(
        &root,
        "InteractiveSignins.xlsx",
        &wb.save_to_buffer().unwrap(),
    );
    let (_, events) = events_of(&root, IngestOptions::default());
    let steps = file_steps(&events, "InteractiveSignins.xlsx");
    let first = steps.first().expect("a step event");
    assert!(first.steps.len() > 1, "{steps:#?}");
    assert!(steps.iter().all(|s| s.steps == first.steps), "{steps:#?}");
}
