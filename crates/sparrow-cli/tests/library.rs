//! `sparrow_cli::run` in-process: the output goes to the writers it is given, and a case source that forbids heavy
//! commands refuses them.

#[allow(dead_code)]
mod events_common;

use events_common::{build, run};
use sparrow_cli::{CaseSource, CliIo, FileSource, SharedBuf};
use sparrow_core::Case;
use std::ffi::OsString;
use std::path::Path;
use std::rc::Rc;

fn run_in_process(args: &[&str], cases: Rc<dyn CaseSource>) -> (u8, String, String) {
    let (out, err) = (SharedBuf::default(), SharedBuf::default());
    let io = CliIo::new(Box::new(out.clone()), Box::new(err.clone()), false);
    run_with(args, io, cases, out, err)
}

fn run_with(
    args: &[&str],
    io: CliIo,
    cases: Rc<dyn CaseSource>,
    out: SharedBuf,
    err: SharedBuf,
) -> (u8, String, String) {
    let args: Vec<OsString> = std::iter::once("sparrow")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    let code = sparrow_cli::run(args, io, cases);
    (code, out.text(), err.text())
}

#[test]
fn run_writes_to_the_given_writers() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let p = path.to_str().unwrap();
    let (code, out, _) = run_in_process(&["events", "--case", p, "--json"], Rc::new(FileSource));
    assert_eq!(code, 0);
    let binary = run(&["events", "--case", p, "--json"]);
    assert_eq!(binary.code, 0, "{}", binary.err);
    assert!(!out.is_empty());
    assert_eq!(out, binary.out);
}

#[test]
fn errors_go_to_the_given_error_writer() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("none.duckdb");
    let (code, out, err) = run_in_process(
        &["summary", "--case", missing.to_str().unwrap(), "--json"],
        Rc::new(FileSource),
    );
    assert_eq!(code, 1);
    assert!(err.starts_with("error: "), "{err}");
    assert!(out.contains("\"error\""), "{out}");
}

/// Opens files like [`FileSource`] but forbids the heavy commands, as the app's bridge does.
struct NoHeavy;

impl CaseSource for NoHeavy {
    fn read(&self, path: &Path) -> anyhow::Result<Case> {
        FileSource.read(path)
    }
    fn write(&self, path: &Path) -> anyhow::Result<Case> {
        FileSource.write(path)
    }
    fn heavy_allowed(&self) -> bool {
        false
    }
}

#[test]
fn heavy_commands_refuse_when_not_allowed() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let p = path.to_str().unwrap();
    for args in [
        vec!["profile", "--case", p],
        vec!["detect", "--case", p],
        vec!["upgrade", "--case", p],
        vec!["ingest", tmp.path().to_str().unwrap(), "--case", p],
        vec!["synth", "list"],
        vec!["audit", "verify", "--case", p, "--acknowledge"],
    ] {
        let (code, _, err) = run_in_process(&args, Rc::new(NoHeavy));
        assert_eq!(code, 4, "{args:?}: {err}");
        assert!(
            err.contains("run it from the app, or with the case closed in the app"),
            "{args:?}: {err}"
        );
    }
    // Reads still run.
    let (code, _, err) = run_in_process(&["events", "--case", p], Rc::new(NoHeavy));
    assert_eq!(code, 0, "{err}");
}

/// Refuses every write, like a pipe whose reader went away.
struct Broken;

impl std::io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_failed_output_write_is_not_success() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("case.duckdb");
    build(&path);
    let err = SharedBuf::default();
    let io = CliIo::new(Box::new(Broken), Box::new(err.clone()), false);
    let (code, _, err) = run_with(
        &["events", "--case", path.to_str().unwrap(), "--json"],
        io,
        Rc::new(FileSource),
        SharedBuf::default(),
        err,
    );
    assert_eq!(code, 1);
    assert!(err.contains("writing the output failed"), "{err}");
}

#[test]
fn the_run_reads_its_own_environment() {
    let tmp = tempfile::tempdir().unwrap();
    let (out, err) = (SharedBuf::default(), SharedBuf::default());
    let mut io = CliIo::new(Box::new(out.clone()), Box::new(err.clone()), false);
    let missing = tmp.path().join("no-such-rules");
    io.env = Some([("SPARROW_RULES".to_string(), missing.display().to_string())].into());
    let (code, _, err) = run_with(
        &["rules", "list", "--json"],
        io,
        Rc::new(FileSource),
        out,
        err,
    );
    assert_ne!(code, 0, "the run's SPARROW_RULES was not used");
    assert!(err.contains("no-such-rules"), "{err}");
}
