//! The context one [`crate::run`] works in: where its output goes, which environment it sees and how it opens
//! cases. The binary uses the process's stdout, stderr and environment and opens files ([`FileSource`]); the app's
//! agent bridge runs the same commands in-process against the case it has open, with the output streamed back to the
//! CLI that asked. The context lives in a thread-local for the duration of the call, so the commands print through
//! [`outln!`] / [`errln!`] instead of carrying a parameter.

use anyhow::{Context, Result};
use sparrow_core::Case;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

/// Where a run's output goes.
pub struct CliIo {
    pub out: Box<dyn Write>,
    pub err: Box<dyn Write>,
    /// Whether `out` is a terminal (the CLI's own stdout, or the stdout of the CLI the bridge serves).
    pub out_is_terminal: bool,
    /// Whether `err` is a terminal.
    pub err_is_terminal: bool,
    /// The `SPARROW_*` variables the run sees; `None` reads the process environment.
    pub env: Option<BTreeMap<String, String>>,
}

impl CliIo {
    pub fn new(out: Box<dyn Write>, err: Box<dyn Write>, out_is_terminal: bool) -> CliIo {
        CliIo {
            out,
            err,
            out_is_terminal,
            err_is_terminal: false,
            env: None,
        }
    }

    /// The process's stdout and stderr.
    pub fn std() -> CliIo {
        use std::io::IsTerminal;
        let mut io = CliIo::new(
            Box::new(std::io::stdout()),
            Box::new(std::io::stderr()),
            std::io::stdout().is_terminal(),
        );
        io.err_is_terminal = std::io::stderr().is_terminal();
        io
    }
}

/// How a run opens the case its command names.
pub trait CaseSource {
    /// The case for a read-only command.
    fn read(&self, path: &Path) -> Result<Case>;
    /// The case for an agent decision or another short write.
    fn write(&self, path: &Path) -> Result<Case>;
    /// Whether commands that hold the case for minutes (ingest, profile, detect, upgrade, synth) may run.
    fn heavy_allowed(&self) -> bool;
}

/// Opens the case files directly: the binary's source.
pub struct FileSource;

impl CaseSource for FileSource {
    fn read(&self, path: &Path) -> Result<Case> {
        Ok(Case::open_read_only(path)?)
    }

    fn write(&self, path: &Path) -> Result<Case> {
        if !path.is_file() {
            return Err(
                sparrow_core::Error::NotFound(format!("case database {}", path.display())).into(),
            );
        }
        Case::create_or_open(path).with_context(|| format!("opening {}", path.display()))
    }

    fn heavy_allowed(&self) -> bool {
        true
    }
}

/// A `Write` into a shared buffer, to read a run's output back (tests, the bridge's own checks).
#[derive(Clone, Default)]
pub struct SharedBuf(Rc<RefCell<Vec<u8>>>);

impl SharedBuf {
    pub fn bytes(&self) -> Vec<u8> {
        self.0.borrow().clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.borrow()).into_owned()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Cx {
    pub io: CliIo,
    pub cases: Rc<dyn CaseSource>,
    /// Warnings about the case this run's read command opened ([`crate::open_read`]); every JSON output carries them.
    pub warnings: Vec<String>,
    /// Set when writing to `io.out` failed: the run then cannot report success.
    pub out_failed: bool,
    /// `--snapshot` / `SPARROW_SNAPSHOT=1`: a read of a case another program holds may take a copy.
    pub snapshot_allowed: bool,
    /// The copy this run read (`"snapshot"` in its JSON), and the copies themselves, deleted when the run ends.
    pub snapshot_json: Option<serde_json::Value>,
    pub snapshots: Vec<crate::snapshot::Snapshot>,
    /// `--timings`: the phases timed so far (printed to stderr when the run ends, `timings` in its JSON).
    pub timings: Option<sparrow_core::timings::Timings>,
}

thread_local! {
    static CX: RefCell<Option<Cx>> = const { RefCell::new(None) };
}

/// Installs a context for the current thread and removes it when dropped (also on a panic), so a run never leaks
/// its context into the next.
pub(crate) struct Installed;

impl Installed {
    pub fn new(io: CliIo, cases: Rc<dyn CaseSource>) -> Installed {
        CX.with(|c| {
            *c.borrow_mut() = Some(Cx {
                io,
                cases,
                warnings: Vec::new(),
                out_failed: false,
                snapshot_allowed: false,
                snapshot_json: None,
                snapshots: Vec::new(),
                timings: None,
            })
        });
        Installed
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        if let Some(mut cx) = CX.with(|c| c.borrow_mut().take()) {
            let _ = cx.io.out.flush();
            // A copy of the case that could not be deleted holds case data: say where it is.
            for snap in std::mem::take(&mut cx.snapshots) {
                let dir = snap.case.parent().map(std::path::Path::to_path_buf);
                if let Err(e) = snap.remove() {
                    let _ = writeln!(
                        cx.io.err,
                        "warning: could not delete the snapshot copy in {} ({e}); delete it yourself",
                        dir.map(|d| d.display().to_string()).unwrap_or_default()
                    );
                }
            }
            let _ = cx.io.err.flush();
        }
    }
}

/// Run `f` on the current context; `None` outside a run (unit tests calling a command function directly).
pub(crate) fn with_cx<T>(f: impl FnOnce(Option<&mut Cx>) -> T) -> T {
    CX.with(|c| f(c.borrow_mut().as_mut()))
}

/// Run `f` on the run's stdout (the process's when no run is active). `f` must not print through [`outln!`] or
/// [`errln!`] itself.
pub(crate) fn with_out<T>(f: impl FnOnce(&mut dyn Write) -> T) -> T {
    with_cx(|cx| match cx {
        Some(cx) => f(&mut *cx.io.out),
        None => f(&mut std::io::stdout().lock()),
    })
}

/// Run `f` on the run's stderr (the process's when no run is active).
pub(crate) fn with_err<T>(f: impl FnOnce(&mut dyn Write) -> T) -> T {
    with_cx(|cx| match cx {
        Some(cx) => f(&mut *cx.io.err),
        None => f(&mut std::io::stderr().lock()),
    })
}

/// A failed write does not stop the command half-way (a write it was making still completes), but the run then
/// exits 1 instead of 0 ([`output_failed`]).
pub(crate) fn out_fmt(args: std::fmt::Arguments<'_>) {
    with_cx(|cx| match cx {
        Some(cx) => {
            if cx.io.out.write_fmt(args).is_err() {
                cx.out_failed = true;
            }
        }
        None => {
            let _ = std::io::stdout().lock().write_fmt(args);
        }
    })
}

/// Whether a write to this run's stdout failed.
pub(crate) fn output_failed() -> bool {
    with_cx(|cx| cx.is_some_and(|cx| cx.out_failed))
}

/// Errors writing stderr are ignored: there is nowhere left to report them.
pub(crate) fn err_fmt(args: std::fmt::Arguments<'_>) {
    with_err(|w| {
        let _ = w.write_fmt(args);
    })
}

/// The case source of the current run ([`FileSource`] outside a run).
pub(crate) fn cases() -> Rc<dyn CaseSource> {
    with_cx(|cx| match cx {
        Some(cx) => cx.cases.clone(),
        None => Rc::new(FileSource),
    })
}

/// An environment variable as the current run sees it.
pub(crate) fn env_var(name: &str) -> Option<String> {
    let from_run = with_cx(|cx| cx.and_then(|cx| cx.io.env.as_ref().map(|e| e.get(name).cloned())));
    match from_run {
        Some(v) => v,
        None => std::env::var(name).ok(),
    }
}

/// `println!` into the run's stdout.
#[macro_export]
#[doc(hidden)]
macro_rules! outln {
    () => {
        $crate::cx::out_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {{
        $crate::cx::out_fmt(format_args!($($arg)*));
        $crate::cx::out_fmt(format_args!("\n"));
    }};
}

/// `print!` into the run's stdout.
#[macro_export]
#[doc(hidden)]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::cx::out_fmt(format_args!($($arg)*))
    };
}

/// `eprintln!` into the run's stderr.
#[macro_export]
#[doc(hidden)]
macro_rules! errln {
    () => {
        $crate::cx::err_fmt(format_args!("\n"))
    };
    ($($arg:tt)*) => {{
        $crate::cx::err_fmt(format_args!($($arg)*));
        $crate::cx::err_fmt(format_args!("\n"));
    }};
}

/// `eprint!` into the run's stderr.
#[macro_export]
#[doc(hidden)]
macro_rules! err {
    ($($arg:tt)*) => {
        $crate::cx::err_fmt(format_args!($($arg)*))
    };
}
