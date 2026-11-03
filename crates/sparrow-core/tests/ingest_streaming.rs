//! Ingest reads files as streams: no default size limit, superseded files skip the size check, and a cancel, a read
//! error or a file that changes while it is read fails closed for that file only.

use serde_json::json;
use sparrow_core::Case;
use sparrow_core::discovery::discover_collections;
use sparrow_core::fixtures::{self, csv_line, utf8_bom};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    FileReport, FileStatus, IngestOptions, IngestReport, ReadEvent, ReadPhase,
    WHOLE_FILE_MAX_BYTES, XLSX_MAX_BYTES, ingest_collections_partial, ingest_path,
};
use sparrow_core::readers::stream::CHUNK_BYTES;
use sparrow_synth::big_file::{BigEncoding, BigKind, write_big_file};
use sparrow_synth::case_dump::dump_case;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
