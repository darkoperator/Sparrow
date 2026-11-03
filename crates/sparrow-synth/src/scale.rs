//! Task 25 performance harness: generate a (possibly large) tree, ingest it, profile it and
//! compute the capabilities report, timing each stage. `run_perf` is used by the ignored
//! `tests/perf.rs` test; the numbers are the baseline Task 26 improves.

use crate::generate::generate_to_dir;
use crate::options::GenerateOptions;
use crate::scenario::Scenario;
use crate::{Error, Result};
use chrono::Duration;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, IngestOutcome, ingest_path};
use sparrow_core::profile::availability::capabilities_report;
use sparrow_core::profile::{ProfileOptions, refresh};
use std::path::Path;
use std::time::{Duration as StdDuration, Instant};

/// How many of the slowest detect rules the harness reports.
const SLOWEST_RULES: usize = 8;

/// Wall-clock time each stage of a large-tree run took, with the row counts it produced.
#[derive(Debug, Clone)]
pub struct Timings {
    pub generate: StdDuration,
    pub ingest: StdDuration,
    pub profile: StdDuration,
    pub capabilities: StdDuration,
    /// Detection over the whole seed pack (Task 12: all 31 rules; the plan budgets this at
    /// under 10 s for the 1M-row volume case).
    pub detect: StdDuration,
    /// Rules the run planned for, and how many of them errored.
    pub detect_rules: usize,
    pub detect_errors: usize,
    /// The slowest rules of the detect run, (rule id, duration_ms), longest first: what to read
    /// when the detect time is over budget.
    pub detect_slowest: Vec<(String, u64)>,
    /// Wall time per phase of the detect run (name, ms), in the order they ran.
    pub detect_phases: Vec<(String, u64)>,
    pub ual_rows: u64,
    pub signins: u64,
    pub mia_rows: u64,
}

impl Timings {
    /// A human-readable block, printed by the ignored perf test.
    pub fn to_text(&self) -> String {
        let secs = |d: StdDuration| format!("{:.2}s", d.as_secs_f64());
        format!(
            "scale perf\n\
             generate:     {}\n\
             ingest:       {}\n\
             profile:      {}\n\
             capabilities: {}\n\
             detect:       {} ({} rules, {} errored; slowest: {})\n\
             detect phases: {}\n\
             ual_events:   {}\n\
             signins:      {}\n\
             mia:          {}",
            secs(self.generate),
            secs(self.ingest),
            secs(self.profile),
            secs(self.capabilities),
            secs(self.detect),
            self.detect_rules,
            self.detect_errors,
            self.detect_slowest
                .iter()
                .map(|(r, ms)| format!("{r} {ms}ms"))
                .collect::<Vec<_>>()
                .join(", "),
            self.detect_phases
                .iter()
                .map(|(n, ms)| format!("{n} {ms}ms"))
                .collect::<Vec<_>>()
                .join("; "),
            self.ual_rows,
            self.signins,
            self.mia_rows,
        )
    }
}

fn core<T>(r: sparrow_core::Result<T>) -> Result<T> {
    r.map_err(|e| Error::Core(e.to_string()))
}

/// Generate `scenario`/`opts` into `dir`, ingest it into `dir/case.duckdb`, profile and compute
/// the capabilities report, timing each stage. Returns the timings and the table counts.
pub fn run_perf(scenario: &Scenario, opts: &GenerateOptions, dir: &Path) -> Result<Timings> {
    let t = Instant::now();
    let manifest = generate_to_dir(scenario, opts, dir)?;
    let generate = t.elapsed();

    let case_path = dir.join("case.duckdb");
    let t = Instant::now();
    let mut case = core(Case::create_or_open(&case_path))?;
    let report = core(ingest_path(
        &mut case,
        dir,
        &ParserRegistry::builtin(),
        // A 1M-row Invictus tree's merged UAL export exceeds the 1 GiB default file cap; a perf
        // run raises it so the whole tree ingests.
        &IngestOptions {
            max_file_bytes: None,
            ..IngestOptions::default()
        },
    ))?;
    // The collector's own losses (the planted Get-Roles.ps1 failure rows) are not an ingest failure.
    if report.outcome() == IngestOutcome::Problems {
        let bad: Vec<String> = report
            .collections
            .iter()
            .flat_map(|c| &c.files)
            .filter(|f| f.has_problems())
            .map(|f| {
                format!(
                    "{} [{}] errors={} warnings={:?}",
                    f.rel_path,
                    f.status.as_str(),
                    f.records_error,
                    f.warnings
                )
            })
            .take(20)
            .collect();
        return Err(Error::Invalid(format!(
            "the large tree ingested with errors:\n{}",
            bad.join("\n")
        )));
    }
    let ingest = t.elapsed();

    let t = Instant::now();
    core(refresh(&mut case, &ProfileOptions::default()))?;
    let profile = t.elapsed();

    let t = Instant::now();
    core(capabilities_report(
        &case,
        manifest.collected_at + Duration::days(1),
    ))?;
    let capabilities = t.elapsed();

    // The whole seed pack over the case (Task 12). The plan budgets this at under 10 s for the
    // 1M-row volume case; when it is over, the per-rule `duration_ms` in `detection_runs` is
    // what to read, and the architect decides what to do about it.
    let t = Instant::now();
    let detected = core(detect::run::run_with_dirs(
        &mut case,
        &DataDirs::default(),
        &detect::DetectOptions {
            rule_ids: Vec::new(),
            tags: Vec::new(),
            now: Some(manifest.collected_at),
        },
    ))?;
    let detect = t.elapsed();

    let count = |sql: &str| -> Result<u64> {
        let n = case
            .conn()
            .query_row(sql, [], |r| r.get::<_, i64>(0))
            .map_err(|e| Error::Core(e.to_string()))?;
        Ok(n as u64)
    };
    Ok(Timings {
        generate,
        ingest,
        profile,
        capabilities,
        detect,
        detect_rules: detected.rules.len(),
        detect_errors: detected
            .rules
            .iter()
            .filter(|r| r.status == "error")
            .count(),
        detect_phases: detected
            .phases
            .iter()
            .map(|p| (p.name.clone(), p.ms))
            .collect(),
        detect_slowest: {
            let mut slow: Vec<(String, u64)> = detected
                .rules
                .iter()
                .map(|r| (r.rule_id.clone(), r.duration_ms))
                .collect();
            slow.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            slow.truncate(SLOWEST_RULES);
            slow
        },
        ual_rows: count("SELECT count(*) FROM ual_events")?,
        signins: count("SELECT count(*) FROM signins")?,
        mia_rows: count("SELECT count(*) FROM mail_items_accessed")?,
    })
}
