//! `sparrow export report|timeline|workbook` (Addendum D.6): the Markdown customer report, the Timeline Explorer CSV
//! and the XLSX workbook. Each opens the case read-only and writes nothing to it. `--out` defaults to stdout for
//! the Markdown and the CSV; the workbook needs `--out`. `--json` prints a one-object summary and needs `--out`.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use sparrow_core::data::DataDirs;
use sparrow_core::export::report_md::{self, ReportOpts};
use sparrow_core::export::timeline_csv::{self, CsvOpts, Scope};
use sparrow_core::export::workbook_xlsx;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum ExportCommand {
    /// The Markdown customer report (pending AI decisions are labelled unless --reviewed-only)
    Report {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Only md
        #[arg(long, default_value = "md")]
        format: String,
        /// Write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Keep accepted decisions only (the Accounts table is then replaced by one line: the roll-up is
        /// computed from all findings)
        #[arg(long)]
        reviewed_only: bool,
        /// Directory overriding the embedded data files; default $SPARROW_DATA
        #[arg(long)]
        data: Option<PathBuf>,
        /// Rule directory (repeatable), used only to say which findings lack facts when detection has not
        /// run since the facts existed; default $SPARROW_RULES
        #[arg(long)]
        rules: Vec<PathBuf>,
    },
    /// The Timeline Explorer CSV (UTF-8 with a BOM)
    Timeline {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Only csv
        #[arg(long, default_value = "csv")]
        format: String,
        /// verified (the curated entries) or all (every timeline row, streamed)
        #[arg(long, default_value = "verified")]
        scope: String,
        /// Inclusive lower bound on the event time (RFC 3339)
        #[arg(long)]
        from: Option<String>,
        /// Inclusive upper bound on the event time (RFC 3339)
        #[arg(long)]
        to: Option<String>,
        /// The actor or target of the rows (case-insensitive)
        #[arg(long)]
        user: Option<String>,
        /// Write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// The XLSX workbook (Summary, Accounts, Findings, Timeline, Indicators, Evidence gaps, Audit)
    Workbook {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Only xlsx
        #[arg(long, default_value = "xlsx")]
        format: String,
        /// The file to write (required)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Directory overriding the embedded data files; default $SPARROW_DATA
        #[arg(long)]
        data: Option<PathBuf>,
        /// Rule directory (repeatable), used only to say which findings lack facts when detection has not
        /// run since the facts existed; default $SPARROW_RULES
        #[arg(long)]
        rules: Vec<PathBuf>,
    },
}

fn time(flag: &str, s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .with_context(|| {
            format!("{flag} must be RFC 3339 (for example 2026-08-03T09:00:00Z), got {s:?}")
        })
}

fn format_is(kind: &str, got: &str, want: &str) -> Result<()> {
    if got != want {
        bail!("export {kind} supports --format {want}, got {got:?}");
    }
    Ok(())
}

/// The canonical form of `p`: the path itself when it exists, else its canonical parent plus the file name (a new
/// output file). An error when the parent does not exist.
fn canonical(p: &Path) -> Result<PathBuf> {
    if p.exists() {
        return Ok(p.canonicalize()?);
    }
    let parent = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = p
        .file_name()
        .with_context(|| format!("{} is not a file name", p.display()))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("the directory of {} does not exist", p.display()))?;
    Ok(parent.join(name))
}

/// Refuse an `--out` that is the case file, its write-ahead log, or inside the test cache root
/// (`$CARGO_TARGET_TMPDIR/sparrow-cache`, when set): the one way an export could write the case, or step on another
/// run's files. Exit code 5.
fn check_out(out: &Path, case: &Path) -> Result<()> {
    let target = canonical(out)?;
    let case = case
        .canonicalize()
        .with_context(|| format!("cannot open the case {}", case.display()))?;
    let mut wal = case.clone().into_os_string();
    wal.push(".wal");
    if target == case || target.as_os_str() == wal.as_os_str() {
        return Err(sparrow_core::Error::Decision(format!(
            "refusing to write the export over the case ({}); choose another --out",
            target.display()
        ))
        .into());
    }
    // The test cache (`<CARGO_TARGET_TMPDIR>/sparrow-cache`, when that variable is set): its trees are shared by
    // test runs. A user folder that merely happens to be named target/tmp is fine.
    if let Some(root) = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(|t| PathBuf::from(t).join("sparrow-cache"))
        .and_then(|r| r.canonicalize().ok())
    {
        if target.starts_with(&root) {
            return Err(sparrow_core::Error::Decision(format!(
                "refusing to write the export inside the test cache ({}); choose another --out",
                root.display()
            ))
            .into());
        }
    }
    Ok(())
}

/// A temp file beside `path`, renamed over it when `f` succeeds and removed when it fails: a failed export never
/// leaves a partial `--out` file.
fn atomic<T>(path: &Path, f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .with_context(|| format!("{} is not a file name", path.display()))?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    match f(&tmp).and_then(|v| {
        std::fs::rename(&tmp, path)
            .with_context(|| format!("cannot write {}", path.display()))
            .map(|_| v)
    }) {
        Ok(v) => Ok(v),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Run `f` on the sink: the file when given (written atomically), else stdout.
fn with_sink<T>(
    out: Option<&Path>,
    json: bool,
    f: impl FnOnce(&mut dyn Write) -> Result<T>,
) -> Result<T> {
    match out {
        Some(path) => atomic(path, |tmp| {
            let mut w = BufWriter::new(
                File::create(tmp).with_context(|| format!("cannot create {}", tmp.display()))?,
            );
            let v = f(&mut w)?;
            w.flush()?;
            Ok(v)
        }),
        None => {
            if json {
                bail!("--json needs --out (the export itself goes to stdout)");
            }
            let stdout = std::io::stdout();
            let mut w = BufWriter::new(stdout.lock());
            let v = f(&mut w)?;
            w.flush()?;
            Ok(v)
        }
    }
}

fn summary(kind: &str, out: &Path, rows: Option<u64>, json: bool) -> Result<()> {
    if json {
        let v =
            serde_json::json!({ "export": kind, "out": out.display().to_string(), "rows": rows });
        println!("{}", crate::with_warnings(&v)?);
    } else {
        match rows {
            Some(n) => println!("wrote {kind} ({n} rows) to {}", out.display()),
            None => println!("wrote {kind} to {}", out.display()),
        }
    }
    Ok(())
}

pub fn run(command: ExportCommand, json: bool) -> Result<ExitCode> {
    let generated_at = Utc::now();
    match command {
        ExportCommand::Report {
            case,
            format,
            out,
            reviewed_only,
            data,
            rules,
        } => {
            format_is("report", &format, "md")?;
            if let Some(o) = &out {
                check_out(o, &case)?;
            }
            let c = crate::open_read(&case)?;
            let opts = ReportOpts {
                reviewed_only,
                generated_at,
                dirs: DataDirs::with_env_fallback(data, rules),
            };
            with_sink(out.as_deref(), json, |w| {
                Ok(report_md::write(c.conn(), w, &opts)?)
            })?;
            if let Some(p) = out {
                summary("report", &p, None, json)?;
            }
        }
        ExportCommand::Timeline {
            case,
            format,
            scope,
            from,
            to,
            user,
            out,
        } => {
            format_is("timeline", &format, "csv")?;
            let scope = match scope.as_str() {
                "verified" => Scope::Verified,
                "all" => Scope::All,
                other => bail!("--scope is verified or all, got {other:?}"),
            };
            let opts = CsvOpts {
                scope,
                from: from.as_deref().map(|s| time("--from", s)).transpose()?,
                to: to.as_deref().map(|s| time("--to", s)).transpose()?,
                user,
                generated_at,
            };
            if let Some(o) = &out {
                check_out(o, &case)?;
            }
            let c = crate::open_read(&case)?;
            let n = with_sink(out.as_deref(), json, |w| {
                Ok(timeline_csv::write(c.conn(), w, &opts)?)
            })?;
            if let Some(p) = out {
                summary("timeline", &p, Some(n), json)?;
            }
        }
        ExportCommand::Workbook {
            case,
            format,
            out,
            data,
            rules,
        } => {
            format_is("workbook", &format, "xlsx")?;
            let Some(out) = out else {
                bail!("export workbook needs --out FILE (a workbook is binary)");
            };
            check_out(&out, &case)?;
            let dirs = DataDirs::with_env_fallback(data, rules);
            let c = crate::open_read(&case)?;
            atomic(&out, |tmp| {
                Ok(workbook_xlsx::write(c.conn(), tmp, generated_at, &dirs)?)
            })?;
            summary("workbook", &out, None, json)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
