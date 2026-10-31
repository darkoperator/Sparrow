use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use serde::Serialize;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::discovery::{Registry, discover_collections, list_collection_files};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    DEFAULT_MAX_FILE_BYTES, FileReport, IngestOptions, IngestOutcome, ingest_collections,
    no_collections_error,
};
use sparrow_core::profile::availability::capabilities_report;
use sparrow_core::profile::tenant::{
    DomainAction, TenantDomain, list_domains, only_tenant, set_domain,
};
use sparrow_core::profile::{ProfileOptions, ProfileReport, refresh};
use sparrow_core::readers::time::parse_culture;
use sparrow_core::summary::summarize;
use sparrow_core::verify::verify_record;
use sparrow_synth::manifest::Manifest;
use sparrow_synth::options::{
    Collector, Culture, GenerateOptions, PsEdition, SigninExport, UalFormat,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

#[macro_use]
pub mod cx;
pub mod bridge;
pub mod bridge_client;
mod cmd;
mod snapshot;

pub use cx::{CaseSource, CliIo, FileSource, SharedBuf};

#[derive(Parser)]
#[command(
    name = "sparrow",
    version,
    about = "Ingest Hawk / Microsoft-Extractor-Suite output into a DuckDB case database for M365 BEC investigations",
    after_help = "Agent workflow: every command takes --json. Writes (finding set-status|assign|ack-rule-update, ioc, timeline-entry, note, mark) \
are agent decisions recorded in the audit trail with --agent and --analyst; review happens outside the CLI.\n\
\n\
Exit codes: 0 success; 1 other error (including a refused query); 2 completed with problems (ingest, verify, synth coverage/conformance); \
3 audit chain broken; 4 case open by another writer; 5 invalid agent decision, or an export --out over the case; \
6 ingest completed and the only records not loaded are ones the collector lost (it wrote placeholder or error rows).\n\
See the README, section \"Agent workflow\"."
)]
struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,
    /// Open the case file here even when the app has it open (by default the command then runs through the app's
    /// agent bridge); also SPARROW_BRIDGE=off
    #[arg(long, global = true)]
    no_bridge: bool,
    /// For a read-only command on a case another program holds (the app, when its agent bridge cannot serve): read
    /// a private copy, deleted afterwards; also SPARROW_SNAPSHOT=1. Writes never use a copy
    #[arg(long, global = true)]
    snapshot: bool,
    /// Per-phase durations on stderr (and `timings` in --json): access, investigate, entity, detect and export
    #[arg(long, global = true)]
    timings: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List collector outputs under PATH and how each file is classified
    Discover { path: PathBuf },
    /// Ingest collector output into a case database
    #[command(after_help = "Environment:\n  \
        SPARROW_INGEST_CHECKPOINT  DuckDB checkpoint threshold while loading: a size (256MB, 1GiB) or `default` \
        (DuckDB's own); unset: memory_limit / 8, at most 1GB, never below 16MiB\n  \
        SPARROW_INGEST_PROFILE     set to 1 to print stage and per-file timings to stderr\n  \
        SPARROW_MEMORY_LIMIT       DuckDB memory limit of every case instance: a size (2GB, 8GiB) or `default` \
        (DuckDB's own, 80% of RAM); unset: 4GB, or DuckDB's own when that is smaller\n  \
        SPARROW_DATA, SPARROW_RULES  defaults for --data and --rules")]
    Ingest {
        path: PathBuf,
        /// Case database file (created if missing)
        #[arg(long)]
        case: PathBuf,
        /// Day/month order of culture-formatted dates: en-US, en-GB, mdy, dmy, ...
        #[arg(long)]
        culture: Option<String>,
        /// Files larger than this many bytes are recorded as errors instead of loaded
        #[arg(long, default_value_t = DEFAULT_MAX_FILE_BYTES)]
        max_file_size: u64,
        /// Directory overriding the embedded data files (capabilities.yaml, ...); default $SPARROW_DATA
        #[arg(long)]
        data: Option<PathBuf>,
        /// Rule directory (repeatable); replaces embedded rules/lists by id; default $SPARROW_RULES
        #[arg(long)]
        rules: Vec<PathBuf>,
        /// Folder with MaxMind GeoLite2 City / ASN .mmdb files for IP enrichment
        #[arg(long)]
        geoip_dir: Option<PathBuf>,
        /// Skip the detection run that follows the profile step
        #[arg(long)]
        no_detect: bool,
    },
    /// Re-derive the tenant profile, capabilities, IP enrichment and identities of a case
    Profile {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        rules: Vec<PathBuf>,
        #[arg(long)]
        geoip_dir: Option<PathBuf>,
        /// Skip the detection run that follows the profile step
        #[arg(long)]
        no_detect: bool,
    },
    /// Start triage here: the accounts with findings, worst first, with their stages, first suspicious time and
    /// the addresses worth a look (the roll-up detection builds; a case detected before it needs `sparrow detect`)
    Accounts(cmd::read::AccountsArgs),
    /// Evidence coverage per account: rows and dates per source, which dates the evidence does not cover (sampled
    /// exports included), and what to request next with the admin portal, Hawk and Microsoft-Extractor-Suite
    Coverage(cmd::coverage::CoverageArgs),
    /// What the attacker reached through each compromised account (mail read and sent, attachments,
    /// SharePoint/OneDrive, Teams, Copilot, other apps), from the accepted malicious flags; --csv for legal,
    /// --markdown for the final report
    Access(cmd::access::AccessArgs),
    /// Evidence availability: what the case holds, what is missing and why
    Capabilities {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
    /// Tenant, licences, collections, coverage window, row counts, top actors and evidence gaps
    Summary {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
    /// Re-check a record against its original source file(s)
    Verify {
        table: String,
        record_key: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Use this folder as the collection root (when the evidence was moved)
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Upgrade an existing case database to this version's schema
    Upgrade {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
    /// Describe the tables and views `query` can read: their columns, types and comments
    Schema {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Only this table or view (exit 1 with the list of names when there is none)
        #[arg(long = "table", conflicts_with = "table_arg")]
        table: Option<String>,
        /// Only this table or view (same as --table)
        #[arg(value_name = "TABLE")]
        table_arg: Option<String>,
    },
    /// Run the detection rules over a case and merge the hits into its findings
    Detect {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Run only this rule id (repeatable)
        #[arg(long = "rule")]
        rule: Vec<String>,
        /// Run only rules with this tag (repeatable)
        #[arg(long = "tag")]
        tag: Vec<String>,
        /// Directory overriding the embedded data files; default $SPARROW_DATA
        #[arg(long)]
        data: Option<PathBuf>,
        /// Rule directory (repeatable); replaces embedded rules/lists by id; default $SPARROW_RULES
        #[arg(long)]
        rules: Vec<PathBuf>,
    },
    /// Lint, test and list the detection rules
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Case indicators (ip, upn, ...) that rules read through @list:case_iocs.<type>; add, set-verdict and remove are agent decisions
    Ioc {
        #[command(subcommand)]
        command: IocCommand,
    },
    /// Findings: list and show them; set-status, assign and ack-rule-update are agent decisions
    Finding {
        #[command(subcommand)]
        command: cmd::finding::FindingCommand,
    },
    /// Curated timeline entries: propose, verify, reject, edit
    TimelineEntry {
        #[command(subcommand)]
        command: cmd::timeline_entry::TimelineEntryCommand,
    },
    /// Flag or tag event rows (pending until an analyst confirms them in the app)
    Mark {
        #[command(subcommand)]
        command: cmd::mark::MarkCommand,
    },
    /// Notes on findings, timeline entries, indicators and evidence rows
    Note {
        #[command(subcommand)]
        command: cmd::note::NoteCommand,
    },
    /// The Events grid: every event record with account, IP, device and Entra session, filtered like the app's grid
    Events(cmd::events::EventsArgs),
    /// One account, IP, device or Entra session: tiles, pivot tables and findings
    Entity(cmd::entity::EntityArgs),
    /// One account in one window (the customer's dates): its sessions and what each reached, the mail around it,
    /// its configuration changes and its findings' times, with the next commands. Read-only
    Investigate(cmd::investigate::InvestigateArgs),
    /// The evidence timeline (every event record), filtered; capped by --limit
    Timeline(cmd::read::TimelineArgs),
    /// Everything the case knows about an IP or a user, section by section (each capped)
    Pivot {
        #[command(subcommand)]
        command: cmd::read::PivotCommand,
    },
    /// Run one read-only SELECT on a locked-down connection (exit 1 when refused)
    Query {
        /// The SELECT (or WITH ... SELECT) statement
        sql: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// At most this many rows
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// Export the case read-only: the Markdown report, the Timeline Explorer CSV, the XLSX workbook (times in UTC)
    Export {
        #[command(subcommand)]
        command: cmd::export::ExportCommand,
    },
    /// The hash-chained audit trail of agent decisions and reviews: verify it (exit 3 when broken) or read it
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Tenant settings kept by the analyst
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// Generate a synthetic collector tree with its ground-truth manifest (reserved values only)
    #[command(args_conflicts_with_subcommands = true)]
    Synth {
        #[command(subcommand)]
        command: Option<SynthCommand>,
        #[command(flatten)]
        generate: SynthGenArgs,
    },
}

#[derive(Args)]
struct SynthGenArgs {
    /// Built-in scenario name (see `sparrow synth list`) or a scenario YAML file
    #[arg(long)]
    scenario: Option<String>,
    /// Collector to imitate: hawk3, hawk4, invictus or portal
    #[arg(long)]
    collector: Option<Collector>,
    /// PowerShell edition that wrote the files: 5.1 or 7
    #[arg(long, default_value = "7")]
    ps: PsEdition,
    /// Host culture of the collecting machine: en-US, en-GB, de-DE or ja-JP
    #[arg(long, default_value = "en-US")]
    culture: Culture,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Output directory (created if missing; must be empty)
    #[arg(long)]
    out: Option<PathBuf>,
    /// Also pack the output directory into <out>.zip
    #[arg(long)]
    zip: bool,
    /// Microsoft-Extractor-Suite Get-UAL output format
    #[arg(long, default_value = "csv")]
    ual_format: UalFormat,
    /// Portal Entra sign-in export file type: csv or xlsx
    #[arg(long, default_value = "csv")]
    signin_export: SigninExport,
    /// Hawk 4: tenant files from PowerShell 7, user files from Windows PowerShell 5.1
    #[arg(long)]
    hawk_mixed_editions: bool,
    /// PowerShell 7 on macOS/Linux (LF line ends, literal backslash names)
    #[arg(long)]
    non_windows: bool,
    /// Microsoft-Extractor-Suite: do not write TenantLicenses.csv / UserLicenses.csv
    #[arg(long)]
    no_licence_list: bool,
    /// Microsoft-Extractor-Suite Get-Devices: write JSON into the .csv path
    #[arg(long)]
    devices_json: bool,
    /// Total benign UAL filler rows over the window (scale testing; overrides the scenario's
    /// `scale.ual_rows`)
    #[arg(long)]
    ual_rows: Option<u64>,
    /// Total benign filler sign-ins over the window (scale testing; overrides the scenario's
    /// `scale.signins`)
    #[arg(long)]
    signins: Option<u64>,
}

#[derive(Subcommand)]
enum SynthCommand {
    /// Compare a case ingested from a generated tree with the tree's manifest
    Check {
        #[arg(long)]
        manifest: PathBuf,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
    /// Seed-rule coverage of the built-in scenarios (exit 2 when a rule has a gap)
    Coverage {
        /// Seed used for every generated tree
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// Compare generated trees with the recorded real layouts, or a real capture with generated ones
    Conformance {
        /// A generated tree to profile and compare with the recorded layouts
        #[arg(long)]
        tree: Option<PathBuf>,
        /// A real capture to profile and compare with generated trees (aggregates only)
        #[arg(long)]
        real: Option<PathBuf>,
        /// Collector: hawk, invictus or portal
        #[arg(long)]
        collector: Option<ConformanceCollector>,
        /// Seed used for the generated trees in --real mode
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Host culture of the generated tree being compared (--tree mode): picks the
        /// per-culture date forms the layouts record for that culture
        #[arg(long)]
        culture: Option<Culture>,
    },
    /// List the built-in scenarios and the licence and audit profiles
    List,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ConformanceCollector {
    Hawk,
    Invictus,
    Portal,
}

fn cmd_synth_conformance(
    tree: Option<PathBuf>,
    real: Option<PathBuf>,
    collector: Option<ConformanceCollector>,
    seed: u64,
    culture: Option<Culture>,
    json: bool,
) -> Result<ExitCode> {
    let report = match (tree, real) {
        (Some(dir), None) => {
            let c = collector.context("--collector is required with --tree")?;
            let profile = sparrow_synth::conformance::profile_dir(&dir)?;
            sparrow_synth::conformance::conform_layouts(&profile, conformance_collector(c), culture)
        }
        (None, Some(dir)) => {
            let c = collector.context("--collector is required with --real")?;
            let real = sparrow_synth::conformance::profile_dir(&dir)?;
            let (generated, covered) = generated_profiles(c, seed)?;
            let mut report = sparrow_synth::conformance::conform_real(&real, &generated);
            report.variants = covered;
            report.not_covered = REAL_NOT_COVERED.iter().map(|s| s.to_string()).collect();
            report
        }
        _ => anyhow::bail!("pass exactly one of --tree DIR or --real DIR"),
    };
    if json {
        print_json(&report)?;
    } else {
        out!("{}", report.to_text());
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn conformance_collector(c: ConformanceCollector) -> Collector {
    match c {
        ConformanceCollector::Hawk => Collector::Hawk4,
        ConformanceCollector::Invictus => Collector::Invictus,
        ConformanceCollector::Portal => Collector::Portal,
    }
}

/// The collectors a `--real` run generates for `--collector c`. A real Hawk capture holds the
/// portal exports that were pulled beside it (survey §3), so the Hawk run also generates the
/// portal collector.
fn conformance_collectors(c: ConformanceCollector) -> &'static [Collector] {
    match c {
        ConformanceCollector::Hawk => &[Collector::Hawk3, Collector::Hawk4, Collector::Portal],
        ConformanceCollector::Invictus => &[Collector::Invictus],
        ConformanceCollector::Portal => &[Collector::Portal],
    }
}

/// Generator options the `--real` matrix does not vary (named in the report so a clean result is read correctly).
const REAL_NOT_COVERED: [&str; 3] = [
    "ja-JP host culture (the matrix has en-US, en-GB, de-DE)",
    "non_windows (PowerShell 7 on macOS/Linux)",
    "invictus_devices_json (Get-Devices -Output JSON)",
];

/// The per-tree variants of each collector the `--real` matrix covers, for the report: `collector[label; label]`.
fn variant_summary(collectors: &[Collector]) -> Vec<String> {
    collectors
        .iter()
        .map(|c| {
            let labels: Vec<String> = sparrow_synth::conformance::variants(*c)
                .into_iter()
                .map(|v| v.label)
                .collect();
            format!("{c}[{}]", labels.join("; "))
        })
        .collect()
}

/// Profile every built-in scenario (except `volume`) for `collector` with both editions and the
/// three host cultures, once per per-tree variant the generator can take
/// (`sparrow_synth::conformance::variants`: forced, not left to the seed), so `--real` compares a real capture with
/// the whole generated matrix. Also returns the variants covered, for the report.
fn generated_profiles(
    c: ConformanceCollector,
    seed: u64,
) -> Result<(Vec<sparrow_synth::conformance::Profile>, Vec<String>)> {
    let collectors = conformance_collectors(c);
    let mut out = Vec::new();
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        let scenario = sparrow_synth::scenario::load(name)?;
        for collector in collectors {
            for variant in sparrow_synth::conformance::variants(*collector) {
                for ps in [PsEdition::Ps7, PsEdition::Ps51] {
                    for culture in [Culture::EnUs, Culture::EnGb, Culture::DeDe] {
                        let dir = tempfile::tempdir()?;
                        let mut o = GenerateOptions::new(*collector, seed);
                        o.ps = ps;
                        o.culture = culture;
                        variant.apply(&mut o);
                        sparrow_synth::generate::generate_to_dir(&scenario, &o, dir.path())?;
                        out.push(sparrow_synth::conformance::profile_dir(dir.path())?);
                    }
                }
            }
        }
    }
    Ok((out, variant_summary(collectors)))
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Check every rule (columns, lists, regexes, tests) and the coverage matrix; exit 1 on an error
    Lint {
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        rules: Vec<PathBuf>,
    },
    /// Run the inline tests of the rules; exit 1 when one fails
    Test {
        /// Only this rule id
        #[arg(long = "rule")]
        rule: Option<String>,
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        rules: Vec<PathBuf>,
    },
    /// List the rules (id, title, severity, status, requires)
    List {
        /// Only rules requiring this capability
        #[arg(long)]
        requires: Option<String>,
        /// Only rules with this tag
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        rules: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum IocCommand {
    /// Add (or update) an indicator
    Add {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// ip, upn, app_id, domain, user_agent, rule_name, email, url or hash
        #[arg(long = "type")]
        ty: String,
        /// The indicator value (an address, UPN, domain, ...)
        #[arg(long)]
        value: String,
        /// malicious, suspicious or benign
        #[arg(long)]
        verdict: String,
        /// Free-text note shown with the indicator
        #[arg(long)]
        note: Option<String>,
        /// Tenant the indicator applies to; default every tenant of the case
        #[arg(long)]
        tenant: Option<String>,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// List the indicators of the case
    List {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Indicators that apply to this tenant (its own and case-wide)
        #[arg(long)]
        tenant: Option<String>,
        /// Include removed indicators (rules no longer read them)
        #[arg(long)]
        include_removed: bool,
    },
    /// Change the verdict (and optionally the note) of an indicator
    SetVerdict {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Indicator id (see `ioc list`)
        #[arg(long)]
        id: String,
        /// malicious, suspicious or benign
        #[arg(long)]
        verdict: String,
        /// Replaces the note; kept when omitted
        #[arg(long)]
        note: Option<String>,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Remove an indicator by id
    Remove {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Indicator id (see `ioc list`)
        #[arg(long)]
        id: String,
        #[command(flatten)]
        actor: ActorArgs,
    },
}

/// Who makes an agent write (Addendum D.2).
#[derive(Args)]
pub(crate) struct ActorArgs {
    /// The agent making this decision; default $SPARROW_AGENT or "unnamed"
    #[arg(long)]
    agent: Option<String>,
    /// The analyst the decision is made on behalf of (its reviewer, not an identity); default $SPARROW_ANALYST
    #[arg(long)]
    analyst: Option<String>,
}

impl ActorArgs {
    pub(crate) fn resolve(self) -> Result<sparrow_core::case::actor::Actor> {
        cmd::actor::resolve(self.agent, self.analyst)
    }
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Check the audit chain; exit code 3 when it is broken
    Verify {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Record an open break as an audit entry so writes can continue (opens the case for writing)
        #[arg(long)]
        acknowledge: bool,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// List the audit entries in sequence order
    Log {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// Only the entries of this object, as TYPE:ID (for example finding:abc123)
        #[arg(long)]
        object: Option<String>,
    },
}

#[derive(Subcommand)]
enum TenantCommand {
    /// Domains that count as internal to the tenant
    Domains {
        #[command(subcommand)]
        command: DomainCommand,
    },
}

#[derive(Subcommand)]
enum DomainCommand {
    /// Mark a domain as internal to the tenant (kept even if the evidence does not show it)
    Add {
        domain: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        tenant: Option<String>,
        /// Recorded as the actor of this decision; default $SPARROW_ANALYST or "unknown"
        #[arg(long)]
        analyst: Option<String>,
    },
    /// Mark a domain as external to the tenant (dropped even if the evidence shows it)
    Remove {
        domain: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        analyst: Option<String>,
    },
    /// List the tenant's domains
    List {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        tenant: Option<String>,
    },
}

/// The `sparrow` binary: the command goes to the app when it has the case open ([`bridge_client::route`]), else
/// [`run`] on the process's arguments, stdout and stderr, opening case files directly.
pub fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let dir = bridge::discovery_dir();
    if let Some(code) = bridge_client::route(
        &args,
        dir.as_deref(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    ) {
        return ExitCode::from(code);
    }
    ExitCode::from(run(args, CliIo::std(), Rc::new(FileSource)))
}

/// `args` with the value of every path option (`--case`, `--out`, `--csv`, …) made absolute against `cwd`, so the
/// command means the same files when the app runs it.
pub fn absolutize_paths(args: &[OsString], cwd: &Path) -> Vec<OsString> {
    let words: Vec<String> = inspect(args)
        .command
        .split(' ')
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect();
    let root = Cli::command();
    let mut chain = vec![&root];
    for w in &words {
        match chain.last().and_then(|c| c.find_subcommand(w)) {
            Some(c) => chain.push(c),
            None => break,
        }
    }
    let path_type = clap::builder::ValueParser::path_buf().type_id();
    let longs: std::collections::BTreeSet<String> = chain
        .iter()
        .flat_map(|c| c.get_arguments())
        .filter(|a| a.get_value_parser().type_id() == path_type)
        .filter_map(|a| a.get_long().map(String::from))
        .collect();
    let abs = |v: &OsString| -> OsString {
        let p = Path::new(v);
        if p.is_absolute() || v.is_empty() {
            v.clone()
        } else {
            cwd.join(p).into_os_string()
        }
    };
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.iter();
    if let Some(program) = it.next() {
        out.push(program.clone());
    }
    while let Some(a) = it.next() {
        if a == "--" {
            out.push(a.clone());
            out.extend(it.cloned());
            break;
        }
        let text = a.to_str().unwrap_or("");
        if let Some(long) = text.strip_prefix("--") {
            if let Some((name, value)) = long.split_once('=') {
                if longs.contains(name) {
                    let mut joined = OsString::from(format!("--{name}="));
                    joined.push(abs(&OsString::from(value)));
                    out.push(joined);
                    continue;
                }
            } else if longs.contains(long) {
                out.push(a.clone());
                if let Some(v) = it.next() {
                    out.push(abs(v));
                }
                continue;
            }
        }
        out.push(a.clone());
    }
    out
}

/// Run one `sparrow` command line (`args[0]` is the program name) with its output in `io` and its cases from
/// `cases`, and return its exit code. The binary and the app's agent bridge both come through here.
pub fn run(args: Vec<OsString>, io: CliIo, cases: Rc<dyn CaseSource>) -> u8 {
    let (out_is_terminal, err_is_terminal) = (io.out_is_terminal, io.err_is_terminal);
    let _cx = cx::Installed::new(io, cases);
    let json_requested = args.iter().any(|a| a == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            let colour = if e.use_stderr() {
                err_is_terminal
            } else {
                out_is_terminal
            };
            let text = if colour {
                e.render().ansi().to_string()
            } else {
                e.render().to_string()
            };
            if e.use_stderr() {
                err!("{text}");
            } else {
                out!("{text}");
            }
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return 0;
            }
            if json_requested {
                outln!("{}", error_json(e.render().to_string()));
            }
            return 1;
        }
    };
    let json = cli.json;
    let result = dispatch(cli);
    // `--timings`: the phases, on stderr, whatever the outcome.
    for line in cx::with_cx(|cx| cx.and_then(|cx| cx.timings.as_ref().map(|t| t.lines())))
        .unwrap_or_default()
    {
        errln!("timing  {line}");
    }
    match result {
        Ok(code) => {
            let code = exit_number(code);
            if code == 0 && cx::output_failed() {
                errln!("error: writing the output failed");
                return 1;
            }
            code
        }
        Err(e) => {
            let msg = format!("{e:#}");
            errln!("error: {msg}");
            if json {
                outln!("{}", error_json(msg));
            }
            error_exit_code(&e)
        }
    }
}

/// The number behind an `ExitCode` (which does not expose it): every command returns one made from a `u8`.
fn exit_number(code: ExitCode) -> u8 {
    (0..=u8::MAX)
        .find(|n| ExitCode::from(*n) == code)
        .unwrap_or(1)
}

/// A command the run's case source does not allow: exit 4, like a case held by another writer.
#[derive(Debug)]
pub(crate) struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// The refusal of a heavy command (ingest, profile, detect, upgrade, synth) by a source that does not allow them.
const HEAVY_REFUSED: &str = "this command holds the case for minutes and cannot run through the app's agent bridge; \
     run it from the app, or with the case closed in the app";

fn ensure_heavy_allowed() -> Result<()> {
    if cx::cases().heavy_allowed() {
        Ok(())
    } else {
        Err(Refused(HEAVY_REFUSED.to_string()).into())
    }
}

/// The exit code of a failed command: 3 for a broken audit chain, 4 when another writer holds the case, 5 for an
/// invalid agent decision or review, 1 otherwise. (2 means "completed with problems" for ingest and verify.)
fn error_exit_code(e: &anyhow::Error) -> u8 {
    if e.downcast_ref::<Refused>().is_some() {
        return 4;
    }
    match e.downcast_ref::<sparrow_core::Error>() {
        Some(sparrow_core::Error::ChainBroken(_)) => cmd::audit::BROKEN_CHAIN,
        Some(sparrow_core::Error::WriterBusy(_)) => 4,
        Some(sparrow_core::Error::Decision(_)) => 5,
        _ => 1,
    }
}

/// What a command line does to its case, for the app's agent bridge: where it may run and what it changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Reads the case.
    Read,
    /// A short write (an agent decision or a tenant setting); the label names what changes (`marks`, `notes`,
    /// `findings`, `indicators`, `timeline`, `tenant`).
    Write(&'static str),
    /// Holds the case for minutes: ingest, profile, detect, upgrade, synth, audit verify --acknowledge.
    Heavy,
    /// Opens no case (discover, rules, help, version), or does not parse: runs where it is typed.
    Local,
}

/// A command line as [`inspect`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspected {
    pub kind: Kind,
    /// The command words, e.g. `mark tag`.
    pub command: String,
    /// `--case`, as given.
    pub case: Option<PathBuf>,
    /// `--agent` and `--analyst`, as given.
    pub agent: Option<String>,
    pub analyst: Option<String>,
}

/// Read a command line (`args[0]` is the program name) without running it.
pub fn inspect(args: &[OsString]) -> Inspected {
    let mut out = Inspected {
        kind: Kind::Local,
        command: String::new(),
        case: None,
        agent: None,
        analyst: None,
    };
    let Ok(matches) = Cli::command().try_get_matches_from(args) else {
        return out;
    };
    let mut words = Vec::new();
    let mut leaf = &matches;
    while let Some((name, sub)) = leaf.subcommand() {
        words.push(name.to_string());
        leaf = sub;
    }
    let get = |id: &str| leaf.try_get_one::<String>(id).ok().flatten().cloned();
    out.case = leaf.try_get_one::<PathBuf>("case").ok().flatten().cloned();
    out.agent = get("agent");
    out.analyst = get("analyst");
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    let reads_only = matches!(w.last(), Some(&"list" | &"show"));
    out.kind = match w.as_slice() {
        [] | ["discover", ..] | ["rules", ..] => Kind::Local,
        ["ingest" | "profile" | "detect" | "upgrade" | "synth", ..] => Kind::Heavy,
        ["audit", "verify"]
            if leaf
                .try_get_one::<bool>("acknowledge")
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false) =>
        {
            Kind::Heavy
        }
        [_, ..] if reads_only => Kind::Read,
        ["mark", ..] => Kind::Write("marks"),
        ["note", ..] => Kind::Write("notes"),
        ["finding", ..] => Kind::Write("findings"),
        ["ioc", ..] => Kind::Write("indicators"),
        ["timeline-entry", ..] => Kind::Write("timeline"),
        ["tenant", ..] => Kind::Write("tenant"),
        _ => Kind::Read,
    };
    out.command = words.join(" ");
    out
}

fn dispatch(cli: Cli) -> Result<ExitCode> {
    let json = cli.json;
    let snapshot = cli.snapshot || cx::env_var("SPARROW_SNAPSHOT").is_some_and(|v| v.trim() == "1");
    cx::with_cx(|cx| {
        if let Some(cx) = cx {
            cx.snapshot_allowed = snapshot;
            if cli.timings {
                cx.timings = Some(sparrow_core::timings::Timings::new());
            }
        }
    });
    if matches!(
        cli.command,
        Some(
            Command::Ingest { .. }
                | Command::Profile { .. }
                | Command::Detect { .. }
                | Command::Upgrade { .. }
                | Command::Synth { .. }
        )
    ) {
        ensure_heavy_allowed()?;
    }
    // Acknowledging re-verifies the whole chain after each acknowledgement: minutes on a large case.
    if let Some(Command::Audit {
        command: AuditCommand::Verify {
            acknowledge: true, ..
        },
    }) = &cli.command
    {
        ensure_heavy_allowed()?;
    }
    match cli.command {
        None => {
            out!("{}", Cli::command().render_help());
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Discover { path }) => cmd_discover(&path, json),
        Some(Command::Ingest {
            path,
            case,
            culture,
            max_file_size,
            data,
            rules,
            geoip_dir,
            no_detect,
        }) => cmd_ingest(
            &path,
            &case,
            culture.as_deref(),
            max_file_size,
            ProfileOptions {
                dirs: crate::data_dirs(data, rules),
                geoip_dir,
                as_of: None,
            },
            no_detect,
            json,
        ),
        Some(Command::Profile {
            case,
            data,
            rules,
            geoip_dir,
            no_detect,
        }) => cmd_profile(
            &case,
            ProfileOptions {
                dirs: crate::data_dirs(data, rules),
                geoip_dir,
                as_of: None,
            },
            no_detect,
            json,
        ),
        Some(Command::Capabilities { case }) => cmd_capabilities(&case, json),
        Some(Command::Summary { case }) => cmd_summary(&case, json),
        Some(Command::Accounts(a)) => cmd::read::accounts(a, json),
        Some(Command::Coverage(a)) => cmd::coverage::run(a, json),
        Some(Command::Access(a)) => cmd::access::run(a, json),
        Some(Command::Verify {
            table,
            record_key,
            case,
            root,
        }) => cmd_verify(&table, &record_key, &case, root.as_deref(), json),
        Some(Command::Upgrade { case }) => cmd_upgrade(&case, json),
        Some(Command::Schema {
            case,
            table,
            table_arg,
        }) => cmd_schema(&case, table.or(table_arg).as_deref(), json),
        Some(Command::Detect {
            case,
            rule,
            tag,
            data,
            rules,
        }) => cmd_detect(&case, rule, tag, crate::data_dirs(data, rules), json),
        Some(Command::Rules { command }) => cmd_rules(command, json),
        Some(Command::Ioc { command }) => cmd_ioc(command, json),
        Some(Command::Finding { command }) => cmd::finding::run(command, json),
        Some(Command::TimelineEntry { command }) => cmd::timeline_entry::run(command, json),
        Some(Command::Note { command }) => cmd::note::run(command, json),
        Some(Command::Mark { command }) => cmd::mark::run(command, json),
        Some(Command::Events(a)) => cmd::events::run(a, json),
        Some(Command::Entity(a)) => cmd::entity::run(a, json),
        Some(Command::Investigate(a)) => cmd::investigate::run(a, json),
        Some(Command::Timeline(a)) => cmd::read::timeline(a, json),
        Some(Command::Pivot { command }) => cmd::read::pivot(command, json),
        Some(Command::Query { sql, case, limit }) => cmd::read::query(&case, &sql, limit, json),
        Some(Command::Export { command }) => cmd::export::run(command, json),
        Some(Command::Audit { command }) => match command {
            AuditCommand::Verify {
                case,
                acknowledge,
                actor,
            } => cmd::audit::verify(&case, acknowledge, actor.agent, actor.analyst, json),
            AuditCommand::Log { case, object } => cmd::audit::log(&case, object.as_deref(), json),
        },
        Some(Command::Tenant { command }) => cmd_tenant(command, json),
        Some(Command::Synth { command, generate }) => match command {
            None => cmd_synth_generate(generate, json),
            Some(SynthCommand::Check { manifest, case }) => cmd_synth_check(&manifest, &case, json),
            Some(SynthCommand::Coverage { seed }) => cmd_synth_coverage(seed, json),
            Some(SynthCommand::Conformance {
                tree,
                real,
                collector,
                seed,
                culture,
            }) => cmd_synth_conformance(tree, real, collector, seed, culture, json),
            Some(SynthCommand::List) => cmd_synth_list(json),
        },
    }
}

/// The warning a read command gives while the case owes a post-migration step (`db::POST_MIGRATION_PENDING`): its
/// derived relations (`spray_sources`, `cloud_services`) may still be stale.
const PENDING_STEP_WARNING: &str = "case has a pending post-migration step; run `sparrow upgrade`";

/// Open a case read-only: the ONLY way a CLI command opens one, so no read command can skip its warnings. While the
/// case owes a post-migration step, the warning is printed to stderr (stdout stays clean for piped output) and kept
/// for the `warnings` key of the JSON output ([`print_json`]).
pub(crate) fn open_read(path: &Path) -> Result<Case> {
    let case = match cx::cases().read(path) {
        Ok(c) => c,
        Err(e) if writer_busy(&e) => {
            if !cx::with_cx(|cx| cx.is_some_and(|cx| cx.snapshot_allowed)) {
                return Err(e.context(
                    "another program has the case open (the app does, when its agent bridge cannot serve this \
                     command); pass --snapshot to read a copy",
                ));
            }
            open_snapshot(path)?
        }
        Err(e) => return Err(e),
    };
    if case.pending_post_migration()?.is_some() {
        errln!("warning: {PENDING_STEP_WARNING}");
        add_warning(PENDING_STEP_WARNING);
    }
    Ok(case)
}

/// `--data` / `--rules`, else `SPARROW_DATA` / `SPARROW_RULES` as this run sees them ([`cx::env_var`]).
pub(crate) fn data_dirs(data: Option<PathBuf>, rules: Vec<PathBuf>) -> DataDirs {
    DataDirs::with_lookup(data, rules, |k| cx::env_var(k).map(OsString::from))
}

fn writer_busy(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<sparrow_core::Error>(),
        Some(sparrow_core::Error::WriterBusy(_))
    )
}

/// A read-only open of a fresh [`snapshot`] of `path`, kept until the run ends and named on stderr and in the JSON.
fn open_snapshot(path: &Path) -> Result<Case> {
    let snap = snapshot::take(path)?;
    let case = Case::open_read_only(&snap.case)?;
    let taken = snap
        .taken_at
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    errln!(
        "note: read a snapshot of {} taken {taken} (another program, such as the app, has it open)",
        path.display()
    );
    cx::with_cx(|cx| {
        if let Some(cx) = cx {
            cx.snapshot_json =
                Some(serde_json::json!({ "case": path.display().to_string(), "taken_at": taken }));
            cx.snapshots.push(snap);
        }
    });
    Ok(case)
}

/// The file a command that opens the case file again (`query`, `schema`) must read: the snapshot when the run took
/// one, else `path`.
pub(crate) fn file_to_read(case: &Case, path: &Path) -> PathBuf {
    case.path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| path.to_path_buf())
}

/// Run `f` as the timed phase `name` when `--timings` asked for it (else just run it).
pub(crate) fn timed<T>(name: &'static str, f: impl FnOnce() -> T) -> T {
    let on = cx::with_cx(|cx| cx.is_some_and(|cx| cx.timings.is_some()));
    if !on {
        return f();
    }
    let start = std::time::Instant::now();
    let out = f();
    let d = start.elapsed();
    cx::with_cx(|cx| {
        if let Some(t) = cx.and_then(|cx| cx.timings.as_mut()) {
            t.add(name, d);
        }
    });
    out
}

/// Run `f` with this run's timings recorder, when `--timings` asked for one.
pub(crate) fn with_timings<T>(
    f: impl FnOnce(Option<&mut sparrow_core::timings::Timings>) -> T,
) -> T {
    /// Puts the recorder back when `f` returns or panics, so no earlier phase is lost.
    struct Restore(Option<sparrow_core::timings::Timings>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(t) = self.0.take() {
                cx::with_cx(|cx| {
                    if let Some(cx) = cx {
                        cx.timings = Some(t);
                    }
                });
            }
        }
    }
    let mut held = Restore(cx::with_cx(|cx| cx.and_then(|cx| cx.timings.take())));
    f(held.0.as_mut())
}

/// Keep `w` (once) for the `warnings` key of this run's JSON output.
pub(crate) fn add_warning(w: &str) {
    cx::with_cx(|cx| {
        if let Some(cx) = cx {
            if !cx.warnings.iter().any(|x| x == w) {
                cx.warnings.push(w.to_string());
            }
        }
    });
}

/// `value` as JSON with this run's read warnings, when there are any, as a top-level `warnings` array. A value that
/// is not an object is wrapped as `{"result": value, "warnings": [...]}`.
pub(crate) fn with_warnings<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    let mut v = serde_json::to_value(value)?;
    let (warnings, snapshot, timings) = cx::with_cx(|cx| {
        cx.map(|cx| {
            (
                cx.warnings.clone(),
                cx.snapshot_json.clone(),
                cx.timings.as_ref().map(serde_json::to_value).transpose(),
            )
        })
        .unwrap_or((Vec::new(), None, Ok(None)))
    });
    let timings = timings?;
    if warnings.is_empty() && snapshot.is_none() && timings.is_none() {
        return Ok(v);
    }
    if !v.is_object() {
        v = serde_json::json!({ "result": v });
    }
    if let Some(o) = v.as_object_mut() {
        if !warnings.is_empty() {
            o.insert("warnings".into(), warnings.into());
        }
        if let Some(s) = snapshot {
            o.insert("snapshot".into(), s);
        }
        if let Some(t) = timings {
            o.insert("timings".into(), t);
        }
    }
    Ok(v)
}

/// The `--json` error object, with this run's read warnings.
fn error_json(msg: impl Into<String>) -> serde_json::Value {
    let v = serde_json::json!({ "error": msg.into() });
    with_warnings(&v).unwrap_or(v)
}

/// Print `value` as pretty JSON, with this run's read warnings ([`with_warnings`]).
pub(crate) fn print_json<T: Serialize>(value: &T) -> Result<()> {
    outln!("{}", serde_json::to_string_pretty(&with_warnings(value)?)?);
    Ok(())
}

#[derive(Serialize)]
struct DiscoverFile {
    rel_path: String,
    artifact_id: Option<&'static str>,
    target: Option<&'static str>,
    derived: bool,
    subject: Option<String>,
    /// Why the entry could not be read (unreadable directory, ...); absent for readable files.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct DiscoverCollection {
    tool: sparrow_core::discovery::Tool,
    root: String,
    tenant_hint: Option<String>,
    started_hint: Option<String>,
    files: Vec<DiscoverFile>,
}

#[derive(Serialize)]
struct DiscoverOutput {
    collections: Vec<DiscoverCollection>,
}

fn cmd_discover(path: &Path, json: bool) -> Result<ExitCode> {
    let mut out = DiscoverOutput {
        collections: Vec::new(),
    };
    for dc in discover_collections(path)? {
        let listing = list_collection_files(&dc.root, dc.shallow)?;
        let mut files: Vec<DiscoverFile> = listing
            .files
            .into_iter()
            .map(|f| {
                let c = Registry::builtin().classify_file(dc.tool, &f.rel, &f.abs);
                DiscoverFile {
                    artifact_id: c.as_ref().map(|c| c.artifact_id),
                    target: c.as_ref().map(|c| c.target),
                    derived: c.as_ref().is_some_and(|c| c.derived),
                    subject: c.and_then(|c| c.subject),
                    rel_path: f.rel,
                    error: None,
                }
            })
            .collect();
        files.extend(listing.errors.into_iter().map(|e| DiscoverFile {
            rel_path: e.rel,
            artifact_id: None,
            target: None,
            derived: false,
            subject: None,
            error: Some(e.message),
        }));
        out.collections.push(DiscoverCollection {
            tool: dc.tool,
            root: dc.root.display().to_string(),
            tenant_hint: dc.tenant_hint,
            started_hint: dc.started_hint,
            files,
        });
    }
    if json {
        print_json(&out)?;
    } else {
        for c in &out.collections {
            outln!("{} collection: {}", c.tool.as_str(), c.root);
            for f in &c.files {
                match &f.error {
                    Some(err) => outln!("  {:<40} {}  [{err}]", "ERROR", f.rel_path),
                    None => outln!("  {:<40} {}", f.artifact_id.unwrap_or("-"), f.rel_path),
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_ingest(
    path: &Path,
    case_path: &Path,
    culture: Option<&str>,
    max_file_size: u64,
    profile_opts: ProfileOptions,
    no_detect: bool,
    json: bool,
) -> Result<ExitCode> {
    let date_order = culture
        .map(parse_culture)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let opts = IngestOptions {
        date_order,
        max_file_bytes: max_file_size,
        ..IngestOptions::default()
    };
    use sparrow_core::ingest::timing;
    let t_discover = timing::span("cli: discover collections");
    let collections = discover_collections(path)?;
    drop(t_discover);
    if collections.is_empty() {
        return Err(no_collections_error(path).into());
    }
    let case_abs = absolute_file_path(case_path);
    for c in &collections {
        let root = std::fs::canonicalize(&c.root).unwrap_or_else(|_| c.root.clone());
        if case_abs.starts_with(&root) {
            anyhow::bail!(
                "--case {} is inside the evidence folder {}; put the case database outside the evidence",
                case_path.display(),
                c.root.display()
            );
        }
    }
    let t_open = timing::span("cli: open case (+ migrations)");
    let mut case = Case::create_or_open(case_path)
        .with_context(|| format!("opening {}", case_path.display()))?;
    drop(t_open);
    let t_ingest = timing::span("cli: ingest (all collections)");
    let report = ingest_collections(&mut case, &collections, &ParserRegistry::builtin(), &opts)?;
    drop(t_ingest);
    let t_profile = timing::span("cli: profile");
    let profile = refresh(&mut case, &profile_opts).map_err(|e| {
        anyhow::anyhow!(
            "evidence loaded; the profile step failed: {e:#} (fix and run `sparrow profile --case ...`)"
        )
    })?;
    drop(t_profile);
    let t_detect = timing::span("cli: detect");
    let detect = run_detection(&mut case, &profile_opts, no_detect);
    drop(t_detect);
    let t_close = timing::span("cli: close case (final checkpoint)");
    drop(case);
    drop(t_close);
    if json {
        print_json(&IngestOutput {
            report: &report,
            profile: &profile,
            detect: detect.as_ref(),
        })?;
    } else {
        for c in &report.collections {
            outln!(
                "{} collection {} ({})",
                c.tool.as_str(),
                c.collection_id,
                c.root
            );
            for f in &c.files {
                let notes: Vec<String> = rejected_note(f)
                    .into_iter()
                    .chain(f.warnings.clone())
                    .collect();
                outln!(
                    "  {:<18} {:>7} rec  {}{}",
                    f.status.as_str(),
                    f.records_loaded,
                    f.rel_path,
                    if notes.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", notes.join("; "))
                    }
                );
            }
        }
        print_profile_summary(&profile);
        print_detect_summary(detect.as_ref());
    }
    if timing::enabled() {
        err!("{}", timing::report());
    }
    Ok(match report.outcome() {
        IngestOutcome::Clean => ExitCode::SUCCESS,
        IngestOutcome::CollectorLossOnly => ExitCode::from(6),
        IngestOutcome::Problems => ExitCode::from(2),
    })
}

/// The plain-output note for a file's rejected records: "N records rejected (M lost by the collector)", or
/// "M records lost by the collector" when the collector lost them all.
fn rejected_note(f: &FileReport) -> Option<String> {
    let records = |n: u64| format!("{n} record{}", if n == 1 { "" } else { "s" });
    let (error, lost) = (f.records_error, f.records_collector_lost);
    match (error, lost) {
        (0, _) => None,
        (e, 0) => Some(format!("{} rejected", records(e))),
        (e, l) if l >= e => Some(format!("{} lost by the collector", records(l))),
        (e, l) => Some(format!(
            "{} rejected ({l} lost by the collector)",
            records(e)
        )),
    }
}

#[derive(Serialize)]
struct IngestOutput<'a> {
    #[serde(flatten)]
    report: &'a sparrow_core::ingest::IngestReport,
    profile: &'a ProfileReport,
    detect: Option<&'a DetectOutcome>,
}

/// The detection step after a profile: the report, or the error as a message. A detection
/// failure is a warning; it never fails the ingest or the profile.
#[derive(Serialize)]
struct DetectOutcome {
    #[serde(flatten)]
    report: Option<sparrow_core::detect::DetectReport>,
    error: Option<String>,
}

fn run_detection(
    case: &mut Case,
    profile_opts: &ProfileOptions,
    no_detect: bool,
) -> Option<DetectOutcome> {
    if no_detect {
        return None;
    }
    let result = sparrow_core::detect::run::run_with_dirs(
        case,
        &profile_opts.dirs,
        &sparrow_core::detect::DetectOptions {
            now: profile_opts.as_of,
            ..Default::default()
        },
    );
    Some(match result {
        Ok(report) => DetectOutcome {
            report: Some(report),
            error: None,
        },
        Err(e) => DetectOutcome {
            report: None,
            error: Some(format!("{e:#}")),
        },
    })
}

fn print_detect_summary(detect: Option<&DetectOutcome>) {
    let Some(d) = detect else { return };
    match (&d.report, &d.error) {
        (Some(r), _) => {
            let count = |s: &str| r.rules.iter().filter(|x| x.status == s).count();
            outln!(
                "detection: run {}, {} rule runs ({} not applicable, {} errors), {} new findings, {} updated, {} evidence rows",
                r.run_id,
                r.rules.len(),
                count("not_applicable"),
                count("error"),
                r.findings_new,
                r.findings_updated,
                r.evidence_added
            );
            for w in &r.warnings {
                outln!("  warning: {w}");
            }
            for x in r.rules.iter().filter(|x| x.status == "error") {
                outln!(
                    "  warning: rule {} failed for tenant {}: {}",
                    x.rule_id,
                    x.tenant_key,
                    x.reason.as_deref().unwrap_or("?")
                );
            }
        }
        (None, Some(e)) => {
            outln!("warning: detection failed: {e} (run `sparrow profile --case ...` again)")
        }
        (None, None) => {}
    }
}

fn print_profile_summary(profile: &ProfileReport) {
    outln!(
        "profile: {} capabilities, {} tenants, {} identities",
        profile.capabilities,
        profile.tenants,
        profile.identities
    );
    for w in &profile.warnings {
        outln!("  warning: {w}");
    }
}

fn cmd_profile(
    case_path: &Path,
    profile_opts: ProfileOptions,
    no_detect: bool,
    json: bool,
) -> Result<ExitCode> {
    if !case_path.is_file() {
        return Err(sparrow_core::Error::NotFound(format!(
            "case database {}",
            case_path.display()
        ))
        .into());
    }
    let mut case = Case::create_or_open(case_path)
        .with_context(|| format!("opening {}", case_path.display()))?;
    let profile = refresh(&mut case, &profile_opts)?;
    let detect = run_detection(&mut case, &profile_opts, no_detect);
    if json {
        #[derive(Serialize)]
        struct ProfileOutput<'a> {
            #[serde(flatten)]
            profile: &'a ProfileReport,
            detect: Option<&'a DetectOutcome>,
        }
        print_json(&ProfileOutput {
            profile: &profile,
            detect: detect.as_ref(),
        })?;
    } else {
        print_profile_summary(&profile);
        print_detect_summary(detect.as_ref());
    }
    Ok(ExitCode::SUCCESS)
}

/// Human output's warning when some collections have no tenant (the profile is stale).
fn print_stale_warning(stale_collections: &[i64], case_path: &Path) {
    if !stale_collections.is_empty() {
        outln!(
            "warning: profile is stale: {} collections not profiled; run `sparrow profile --case {}`",
            stale_collections.len(),
            case_path.display()
        );
    }
}

fn cmd_capabilities(case_path: &Path, json: bool) -> Result<ExitCode> {
    let case = open_read(case_path)?;
    let report = capabilities_report(&case, chrono::Utc::now())?;
    if report.tenants.is_empty() {
        anyhow::bail!(
            "the case has no tenant profile; run `sparrow profile --case {}` first",
            case_path.display()
        );
    }
    if json {
        let mut v = serde_json::to_value(&report)?;
        v["next"] = serde_json::json!([accounts_next(case_path)]);
        print_json(&v)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_stale_warning(&report.stale_collections, case_path);
    outln!("evaluated at {}", report.as_of);
    for t in &report.tenants {
        outln!();
        outln!(
            "tenant {}{}{}",
            t.tenant_key,
            t.tenant_name
                .as_deref()
                .map(|n| format!("  name {n}"))
                .unwrap_or_default(),
            if t.domains.is_empty() {
                String::new()
            } else {
                format!("  domains {}", t.domains.join(", "))
            }
        );
        outln!("  capabilities:");
        for c in &t.capabilities {
            outln!(
                "    {:<22} {:<13} ({})  {}",
                c.capability_id,
                c.status,
                c.confidence.as_deref().unwrap_or("-"),
                c.basis
            );
        }
        outln!("  evidence:");
        for e in &t.evidence {
            outln!(
                "    {:<22} {:<24} {:>9}  {}",
                e.evidence,
                e.status,
                e.rows,
                e.reason
            );
            if let Some(r) = &e.remediation {
                outln!("      -> {r}");
            }
        }
    }
    print_next(case_path);
    Ok(ExitCode::SUCCESS)
}

/// `s` as one shell word. Plain text: POSIX single quotes with the standard `'\''` escape for an embedded quote,
/// so a space, `;`, `$`, a backtick or a glob in a case path stays data. A string with a control character or a
/// format character (anything `display_safe_line` would escape) cannot be one printable line inside single
/// quotes, so it is written as an ANSI-C `$'...'` word with octal / `\u` escapes (bash, zsh and ksh): the
/// command stays on one line and never carries a raw control character.
pub(crate) fn shell_quote(s: &str) -> String {
    use sparrow_core::case::text::display_safe_line;
    if display_safe_line(s) == s && !s.chars().any(char::is_control) {
        return format!("'{}'", s.replace('\'', "'\\''"));
    }
    let mut out = String::from("$'");
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\{:03o}", c as u32))
            }
            c if display_safe_line(&c.to_string()) != c.to_string() => {
                out.push_str(&format!("\\U{:08x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// The pointer `summary` and `capabilities` give to `sparrow accounts`, the first command of a triage: a runnable
/// command (the case path shell-quoted) and what it shows, kept apart.
fn accounts_next(case_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "command": format!(
            "sparrow accounts --case {} --json",
            shell_quote(&case_path.display().to_string())
        ),
        "about": "one row per account with findings (stages, first suspicious time, addresses worth a look)",
    })
}

/// The plain-text form of [`accounts_next`]: `Next: <command>`, then the about text on its own indented line.
fn print_next(case_path: &Path) {
    let n = accounts_next(case_path);
    outln!();
    outln!("Next: {}", n["command"].as_str().unwrap_or_default());
    outln!("  {}", n["about"].as_str().unwrap_or_default());
}

/// The accounts `summary` shows: up to this many, in `sparrow accounts` order.
const SUMMARY_ACCOUNTS: usize = 3;

/// The top accounts of the roll-up as JSON rows (upn, tenant_key, worst_severity, stages, first_suspicious,
/// addresses_total), `Err(reason)` when the roll-up is not current (the reason `sparrow accounts` gives).
fn top_accounts(case: &Case) -> Result<std::result::Result<Vec<serde_json::Value>, String>> {
    let page = sparrow_core::case::read::accounts(case.conn(), None, Some(SUMMARY_ACCOUNTS))?;
    if let Some(why) = page.warnings.first() {
        return Ok(Err(why.clone()));
    }
    let mut rows = Vec::new();
    for a in &page.accounts {
        let full = serde_json::to_value(a)?;
        let mut row = serde_json::Map::new();
        for k in [
            "upn",
            "tenant_key",
            "worst_severity",
            "stages",
            "first_suspicious",
            "addresses_total",
        ] {
            row.insert(k.to_string(), full[k].clone());
        }
        rows.push(serde_json::Value::Object(row));
    }
    Ok(Ok(rows))
}

fn cmd_summary(case_path: &Path, json: bool) -> Result<ExitCode> {
    let case = open_read(case_path)?;
    let report = summarize(&case)?;
    let top = top_accounts(&case)?;
    if report.tenants.is_empty() {
        anyhow::bail!(
            "the case has no tenant profile; run `sparrow profile --case {}` first",
            case_path.display()
        );
    }
    if json {
        let mut v = serde_json::to_value(&report)?;
        v["next"] = serde_json::json!([accounts_next(case_path)]);
        match &top {
            Ok(rows) => v["top_accounts"] = serde_json::Value::Array(rows.clone()),
            Err(why) => v["top_accounts_unavailable"] = serde_json::json!(why),
        }
        print_json(&v)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_stale_warning(&report.stale_collections, case_path);
    if let Some(at) = &report.profile_evaluated_at {
        outln!("profile evaluated at {at}");
    }
    for t in &report.tenants {
        outln!();
        outln!(
            "tenant {}{}{}",
            t.tenant_key,
            t.tenant_name
                .as_deref()
                .map(|n| format!("  name {n}"))
                .unwrap_or_default(),
            if t.domains.is_empty() {
                String::new()
            } else {
                format!("  domains {}", t.domains.join(", "))
            }
        );
        outln!(
            "  licences: {}",
            if t.licenses.is_empty() {
                "-".to_string()
            } else {
                t.licenses.join(", ")
            }
        );
        outln!("  collections:");
        for c in &t.collections {
            outln!(
                "    {:<5} {:<9} {}  collected {}  window {} .. {}",
                c.collection_id,
                c.tool,
                c.root,
                c.collected_at.as_deref().unwrap_or("-"),
                c.window_start.as_deref().unwrap_or("-"),
                c.window_end.as_deref().unwrap_or("-"),
            );
        }
        outln!("  coverage:");
        for cov in &t.coverage {
            outln!(
                "    {:<22} {:>8} rows  {} .. {}",
                cov.source_table,
                cov.rows,
                cov.first.as_deref().unwrap_or("-"),
                cov.last.as_deref().unwrap_or("-"),
            );
        }
        outln!("  top actors:");
        for a in &t.top_actors {
            outln!("    {:<40} {:>8} rows", a.actor, a.rows);
        }
        outln!(
            "  hosting ips: {}   state rows absent in a newer capture: {}",
            t.hosting_ips,
            t.absent_in_newer
        );
        outln!(
            "  gaps: {}",
            if t.gaps.is_empty() {
                "-".to_string()
            } else {
                t.gaps.join(", ")
            }
        );
    }
    outln!();
    outln!("tables:");
    for tc in &report.tables {
        outln!("  {:<24} {:>10} rows", tc.table, tc.rows);
    }
    outln!();
    use sparrow_core::case::text::display_safe_line;
    match &top {
        Ok(rows) if rows.is_empty() => outln!("Accounts: no account has a finding"),
        Ok(rows) => {
            outln!("Accounts (top {}):", rows.len());
            for r in rows {
                let stages: Vec<&str> = r["stages"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s.as_str())
                    .collect();
                outln!(
                    "  {}  {}  {}  stages {}  first suspicious {}  ({} addresses)",
                    display_safe_line(r["tenant_key"].as_str().unwrap_or("-")),
                    display_safe_line(r["upn"].as_str().unwrap_or("-")),
                    r["worst_severity"].as_str().unwrap_or("-"),
                    if stages.is_empty() {
                        "-".to_string()
                    } else {
                        stages.join(", ")
                    },
                    r["first_suspicious"].as_str().unwrap_or("-"),
                    r["addresses_total"]
                );
            }
        }
        Err(why) => outln!("Accounts: unavailable: {}", display_safe_line(why)),
    }
    print_next(case_path);
    Ok(ExitCode::SUCCESS)
}

/// Absolute form of a file path that may not exist yet (its parent is canonicalized).
fn absolute_file_path(p: &Path) -> PathBuf {
    let parent = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    match p.file_name() {
        Some(name) => parent.join(name),
        None => parent,
    }
}

fn cmd_verify(
    table: &str,
    key: &str,
    case_path: &Path,
    root: Option<&Path>,
    json: bool,
) -> Result<ExitCode> {
    let case = open_read(case_path)?;
    let report = verify_record(&case, table, key, root)?;
    if json {
        print_json(&report)?;
    } else {
        outln!(
            "{} {} -> {}",
            table,
            key,
            if report.ok { "OK" } else { "MISMATCH" }
        );
        for s in &report.sightings {
            outln!(
                "  {}  found={} file_hash_ok={} record_hash_ok={}",
                s.source_ref,
                s.file_found,
                s.file_hash_ok,
                s.record_hash_ok
            );
            if let Some(ex) = &s.excerpt {
                for line in ex.lines() {
                    outln!("    | {line}");
                }
            }
        }
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[derive(Serialize)]
struct UpgradeOutput {
    from: u32,
    to: u32,
}

fn cmd_upgrade(case_path: &Path, json: bool) -> Result<ExitCode> {
    let (from, to) = Case::upgrade(case_path)?;
    if json {
        print_json(&UpgradeOutput { from, to })?;
    } else if from == to {
        outln!("{}: schema already at v{to}", case_path.display());
    } else {
        outln!(
            "{}: schema upgraded from v{from} to v{to}",
            case_path.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Serialize)]
struct SchemaOutput {
    tables: Vec<sparrow_core::db::TableInfo>,
}

fn cmd_schema(case_path: &Path, table: Option<&str>, json: bool) -> Result<ExitCode> {
    // Opened (and closed) first for its warnings; the catalog is read on `query`'s locked connection, so the
    // objects listed are the ones `query` reads.
    // A shared view (the app's agent bridge) is read on its own locked connection: attaching the file again in this
    // process would open a second instance of a database the process already holds.
    let case = open_read(case_path)?;
    let file = file_to_read(&case, case_path);
    let view = case.is_shared_view().then_some(case);
    let schema = |table: Option<&str>| match &view {
        Some(c) => sparrow_core::case::query::schema_on(c, table),
        None => sparrow_core::case::query::schema(&file, table),
    };
    let out = SchemaOutput {
        tables: schema(table)?,
    };
    if let Some(t) = table {
        if out.tables.is_empty() {
            let names: Vec<String> = schema(None)?.into_iter().map(|t| t.table).collect();
            anyhow::bail!(
                "no table named '{t}' in the case database; tables and views: {}",
                names.join(", ")
            );
        }
    }
    if json {
        print_json(&out)?;
    } else {
        for (i, t) in out.tables.iter().enumerate() {
            if i > 0 {
                outln!();
            }
            let suffix = if t.kind == "view" { " (view)" } else { "" };
            outln!(
                "{}{suffix} — {}",
                t.table,
                t.comment.as_deref().unwrap_or("")
            );
            for c in &t.columns {
                outln!(
                    "  {:<22} {:<14} {}",
                    c.name,
                    c.data_type,
                    c.comment.as_deref().unwrap_or("")
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `analyst:<name>` from `--analyst`, else `$SPARROW_ANALYST`, else `analyst:unknown`.
fn analyst_actor(explicit: Option<String>) -> String {
    let name = explicit.or_else(|| cx::env_var("SPARROW_ANALYST").filter(|a| !a.trim().is_empty()));
    match name {
        Some(n) => format!("analyst:{n}"),
        None => "analyst:unknown".to_string(),
    }
}

fn open_case_for_write(case_path: &Path) -> Result<Case> {
    cx::cases().write(case_path)
}

#[derive(Serialize)]
struct DomainActionOutput {
    tenant_key: String,
    domain: String,
    action: &'static str,
    note: &'static str,
}

/// `tenant domains add|remove` rebuilds tenant_domains at once, but identities.kind is derived
/// by the profile step.
const DOMAIN_ACTION_NOTE: &str = "tenant_domains is updated now; identities' external/internal \
     kind updates on the next `sparrow profile`";

fn print_domain_action(
    json: bool,
    tenant_key: &str,
    domain: &str,
    action: &'static str,
) -> Result<ExitCode> {
    if json {
        print_json(&DomainActionOutput {
            tenant_key: tenant_key.to_string(),
            domain: domain.to_string(),
            action,
            note: DOMAIN_ACTION_NOTE,
        })?;
    } else {
        outln!("{tenant_key}  {action} {domain}");
        outln!("note: {DOMAIN_ACTION_NOTE}");
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Serialize)]
struct DomainsOutput {
    domains: Vec<TenantDomain>,
}

fn cmd_tenant(command: TenantCommand, json: bool) -> Result<ExitCode> {
    let TenantCommand::Domains { command } = command;
    match command {
        DomainCommand::Add {
            domain,
            case,
            tenant,
            analyst,
        } => {
            let actor = analyst_actor(analyst);
            let mut c = open_case_for_write(&case)?;
            let normalized = set_domain(
                &mut c,
                tenant.as_deref(),
                &domain,
                DomainAction::Add,
                &actor,
            )?;
            let key = only_tenant(c.conn(), tenant.as_deref())?;
            print_domain_action(json, &key, &normalized, "add")
        }
        DomainCommand::Remove {
            domain,
            case,
            tenant,
            analyst,
        } => {
            let actor = analyst_actor(analyst);
            let mut c = open_case_for_write(&case)?;
            let normalized = set_domain(
                &mut c,
                tenant.as_deref(),
                &domain,
                DomainAction::Remove,
                &actor,
            )?;
            let key = only_tenant(c.conn(), tenant.as_deref())?;
            print_domain_action(json, &key, &normalized, "remove")
        }
        DomainCommand::List { case, tenant } => {
            let c = open_read(&case)?;
            let domains = list_domains(&c, tenant.as_deref())?;
            if json {
                print_json(&DomainsOutput { domains })?;
            } else {
                for d in &domains {
                    outln!("{}  {}  {}", d.tenant_key, d.domain, d.source);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[derive(Serialize)]
struct SynthOutput {
    /// The collection root, relative to the output directory.
    root: String,
    manifest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    zip: Option<String>,
    files: usize,
    /// Expected rows per table.
    tables: std::collections::BTreeMap<String, u64>,
}

fn cmd_synth_generate(args: SynthGenArgs, json: bool) -> Result<ExitCode> {
    let name = args
        .scenario
        .context("--scenario is required (see `sparrow synth list`)")?;
    let collector = args.collector.context("--collector is required")?;
    let out = args.out.context("--out is required")?;
    let scenario = sparrow_synth::scenario::load(&name).with_context(|| {
        format!(
            "scenario '{name}' is neither a built-in ({}) nor a readable file",
            sparrow_synth::scenario::builtin_names().join(", ")
        )
    })?;
    let mut opts = GenerateOptions::new(collector, args.seed);
    opts.ps = args.ps;
    opts.culture = args.culture;
    opts.ual_format = args.ual_format;
    opts.signin_export = args.signin_export;
    opts.hawk_mixed_editions = args.hawk_mixed_editions;
    opts.non_windows = args.non_windows;
    opts.invictus_licence_list = !args.no_licence_list;
    opts.invictus_devices_json = args.devices_json;
    opts.ual_rows = args.ual_rows;
    opts.signins = args.signins;
    let (manifest, zip) = if args.zip {
        let (m, z) = sparrow_synth::generate::generate_zip(&scenario, &opts, &out)?;
        (m, Some(z))
    } else {
        (
            sparrow_synth::generate::generate_to_dir(&scenario, &opts, &out)?,
            None,
        )
    };
    let summary = SynthOutput {
        root: manifest.root.clone(),
        manifest: out
            .join(sparrow_synth::generate::MANIFEST_FILE)
            .display()
            .to_string(),
        zip: zip.map(|z| z.display().to_string()),
        files: manifest.files.len(),
        tables: manifest
            .tables
            .iter()
            .map(|(t, e)| (t.clone(), e.rows))
            .collect(),
    };
    if json {
        print_json(&summary)?;
    } else {
        outln!("root:     {}", out.join(&summary.root).display());
        outln!("manifest: {}", summary.manifest);
        if let Some(z) = &summary.zip {
            outln!("zip:      {z}");
        }
        outln!("files:    {}", summary.files);
        for (t, n) in &summary.tables {
            outln!("  {t:<24} {n:>9} rows");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_synth_coverage(seed: u64, json: bool) -> Result<ExitCode> {
    let report = sparrow_synth::coverage::report(seed)?;
    if json {
        print_json(&report)?;
    } else {
        out!("{}", report.to_text());
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn cmd_synth_check(manifest_path: &Path, case_path: &Path, json: bool) -> Result<ExitCode> {
    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = Manifest::from_json(&text)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    if !case_path.is_file() {
        return Err(sparrow_core::Error::NotFound(format!(
            "case database {}",
            case_path.display()
        ))
        .into());
    }
    let case = open_read(case_path)?;
    let report = sparrow_synth::check::check(&manifest, &case)?;
    if json {
        print_json(&report)?;
    } else {
        if report.ok {
            outln!(
                "ok: collection {} matches {}",
                report.collection_id.unwrap_or_default(),
                manifest_path.display()
            );
        } else {
            outln!("{} problems:", report.problems.len());
            for p in &report.problems {
                outln!("  {p}");
            }
        }
        // Two different counts: every rule of the pack is checked against the latest detection run (its
        // applicability, errors and unexplained hits); the manifest carries hit/no-hit expectations for some of them.
        outln!(
            "{} rules checked against the latest detection run; the manifest has expectations for {} rules ({} of \
             those have no rule file and are not checked)",
            report.detection.rules_checked,
            report.rules_expected,
            report.rules_unchecked
        );
    }
    Ok(if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[derive(Serialize)]
struct SynthListEntry {
    id: String,
    description: String,
}

#[derive(Serialize)]
struct SynthList {
    scenarios: Vec<SynthListEntry>,
    licence_profiles: Vec<SynthListEntry>,
    audit_profiles: Vec<SynthListEntry>,
}

fn cmd_synth_list(json: bool) -> Result<ExitCode> {
    let mut scenarios = Vec::new();
    for name in sparrow_synth::scenario::builtin_names() {
        let s = sparrow_synth::scenario::load(name)?;
        scenarios.push(SynthListEntry {
            id: s.name,
            description: s.description,
        });
    }
    let list = SynthList {
        scenarios,
        licence_profiles: sparrow_synth::profiles::licence_profiles()
            .iter()
            .map(|p| SynthListEntry {
                id: p.id.clone(),
                description: p.title.clone(),
            })
            .collect(),
        audit_profiles: sparrow_synth::profiles::audit_profiles()
            .iter()
            .map(|p| SynthListEntry {
                id: p.id.clone(),
                description: p.title.clone(),
            })
            .collect(),
    };
    if json {
        print_json(&list)?;
    } else {
        for (title, entries) in [
            ("scenarios", &list.scenarios),
            ("licence profiles", &list.licence_profiles),
            ("audit profiles", &list.audit_profiles),
        ] {
            outln!("{title}:");
            for e in entries {
                outln!("  {:<22} {}", e.id, e.description);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------------------------
// detect, rules, ioc

fn cmd_detect(
    case_path: &Path,
    rule_ids: Vec<String>,
    tags: Vec<String>,
    dirs: DataDirs,
    json: bool,
) -> Result<ExitCode> {
    let mut case = timed("open", || open_case_for_write(case_path))?;
    let report = timed("detect", || {
        sparrow_core::detect::run::run_with_dirs(
            &mut case,
            &dirs,
            &sparrow_core::detect::DetectOptions {
                rule_ids,
                tags,
                now: None,
            },
        )
    })?;
    if json {
        print_json(&report)?;
    } else {
        print_detect_summary(Some(&DetectOutcome {
            report: Some(report.clone()),
            error: None,
        }));
        for r in &report.rules {
            outln!(
                "  {:<14} {:<16} {:<15} {} hits{}",
                r.rule_id,
                r.tenant_key,
                r.status,
                r.hits,
                r.reason
                    .as_deref()
                    .map(|x| format!("  ({x})"))
                    .unwrap_or_default()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_rules(command: RulesCommand, json: bool) -> Result<ExitCode> {
    use sparrow_core::detect::compile::CaseSchema;
    use sparrow_core::detect::coverage::CoverageMatrix;
    use sparrow_core::detect::lint::{LintSeverity, lint};
    use sparrow_core::detect::load::load_rules;
    match command {
        RulesCommand::Lint { data, rules } => {
            let set = load_rules(&crate::data_dirs(data, rules))?;
            let case = Case::in_memory()?;
            let schema = CaseSchema::of(case.conn())?;
            let coverage = CoverageMatrix::builtin()?;
            let issues = lint(&set, &schema, Some(&coverage));
            let errors = issues
                .iter()
                .filter(|i| i.severity == LintSeverity::Error)
                .count();
            let name = |s: LintSeverity| match s {
                LintSeverity::Error => "error",
                LintSeverity::Warning => "warning",
            };
            if json {
                print_json(&serde_json::json!({
                    "rules": set.rules.len(),
                    "errors": errors,
                    "warnings": set.warnings,
                    "issues": issues.iter().map(|i| serde_json::json!({
                        "rule_id": i.rule_id, "severity": name(i.severity), "message": i.message,
                    })).collect::<Vec<_>>(),
                }))?;
            } else {
                for w in &set.warnings {
                    outln!("warning: {w}");
                }
                for i in &issues {
                    outln!("{}: {}: {}", name(i.severity), i.rule_id, i.message);
                }
                outln!(
                    "{} rules, {} errors, {} issues",
                    set.rules.len(),
                    errors,
                    issues.len()
                );
            }
            Ok(if errors > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        RulesCommand::Test { rule, data, rules } => {
            let set = load_rules(&crate::data_dirs(data, rules))?;
            let results = sparrow_core::detect::test::run_inline_tests(&set, rule.as_deref())?;
            let failed = results.iter().filter(|r| !r.ok).count();
            if json {
                print_json(&serde_json::json!({ "failed": failed, "results": results }))?;
            } else {
                for r in &results {
                    outln!(
                        "{} {} \"{}\": expected {} hits, got {}{}",
                        if r.ok { "ok  " } else { "FAIL" },
                        r.rule_id,
                        r.name,
                        r.expected,
                        r.got,
                        r.error
                            .as_deref()
                            .map(|e| format!(" ({e})"))
                            .unwrap_or_default()
                    );
                }
                outln!("{} tests, {} failed", results.len(), failed);
            }
            Ok(if failed > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        RulesCommand::List {
            requires,
            tag,
            data,
            rules,
        } => {
            let set = load_rules(&crate::data_dirs(data, rules))?;
            let selected: Vec<_> = set
                .rules
                .iter()
                .map(|r| &r.rule)
                .filter(|r| requires.as_ref().is_none_or(|c| r.requires.contains(c)))
                .filter(|r| tag.as_ref().is_none_or(|t| r.tags.contains(t)))
                .collect();
            let text = |v: serde_json::Value| v.as_str().unwrap_or("").to_string();
            if json {
                print_json(&serde_json::json!({
                    "rules": selected.iter().map(|r| serde_json::json!({
                        "id": r.id, "title": r.title, "severity": r.severity, "status": r.status,
                        "requires": r.requires, "requires_evidence": r.requires_evidence,
                        "tags": r.tags, "version": r.version,
                    })).collect::<Vec<_>>(),
                }))?;
            } else {
                for r in &selected {
                    outln!(
                        "{:<14} {:<9} {:<12} {}{}",
                        r.id,
                        text(serde_json::to_value(r.severity)?),
                        text(serde_json::to_value(r.status)?),
                        r.title,
                        if r.requires.is_empty() {
                            String::new()
                        } else {
                            format!("  [requires {}]", r.requires.join(", "))
                        }
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_ioc(command: IocCommand, json: bool) -> Result<ExitCode> {
    use sparrow_core::case::indicators::{
        IndicatorType, Verdict, add_indicator, list_indicators, remove_indicator, set_verdict,
    };
    use sparrow_core::case::text::display_safe_line;
    // A bad type or verdict is an invalid decision (exit 5).
    let decision = |e: sparrow_core::Error| sparrow_core::Error::Decision(e.to_string());
    match command {
        IocCommand::Add {
            case,
            ty,
            value,
            verdict,
            note,
            tenant,
            actor,
        } => {
            let actor = actor.resolve()?;
            let ty = IndicatorType::parse(&ty).map_err(decision)?;
            let verdict = Verdict::parse(&verdict).map_err(decision)?;
            let c = open_case_for_write(&case)?;
            let id = add_indicator(
                c.conn(),
                &actor,
                tenant.as_deref(),
                ty,
                &value,
                verdict,
                note.as_deref(),
            )?;
            if json {
                let audit =
                    sparrow_core::case::audit::log(c.conn(), Some(("indicator", &id)))?.pop();
                print_json(&serde_json::json!({
                    "indicator_id": id, "type": ty, "value": value.trim(), "verdict": verdict,
                    "tenant_key": tenant, "added_by": actor.as_str(), "on_behalf_of": actor.on_behalf_of(),
                    "review_state": "pending_review", "audit": audit,
                }))?;
            } else {
                outln!(
                    "{id}  {} {}  {}  {}",
                    ty.as_str(),
                    display_safe_line(value.trim()),
                    verdict.as_str(),
                    cmd::finding::provenance(actor.as_str(), actor.on_behalf_of())
                );
            }
        }
        IocCommand::List {
            case,
            tenant,
            include_removed,
        } => {
            let c = open_read(&case)?;
            let items = list_indicators(c.conn(), tenant.as_deref(), include_removed)?;
            if json {
                print_json(&serde_json::json!({ "indicators": items }))?;
            } else {
                for i in &items {
                    outln!(
                        "{}  {:<10} {:<10} {}  by {}{}{}{}",
                        i.indicator_id,
                        i.ty.as_str(),
                        i.verdict.as_str(),
                        display_safe_line(&i.value),
                        display_safe_line(i.decided_by.as_deref().unwrap_or(&i.added_by)),
                        i.review_state
                            .as_deref()
                            .map(|r| format!(" [{r}]"))
                            .unwrap_or_default(),
                        i.note
                            .as_deref()
                            .map(|n| format!("  ({})", display_safe_line(n)))
                            .unwrap_or_default(),
                        if i.removed_at.is_some() {
                            "  REMOVED"
                        } else {
                            ""
                        }
                    );
                }
                outln!("{} indicators", items.len());
            }
        }
        IocCommand::SetVerdict {
            case,
            id,
            verdict,
            note,
            actor,
        } => {
            let actor = actor.resolve()?;
            let verdict = Verdict::parse(&verdict).map_err(decision)?;
            let c = open_case_for_write(&case)?;
            let e = set_verdict(c.conn(), &actor, &id, verdict, note.as_deref())?;
            cmd::finding::print_decision(&e, verdict.as_str(), json)?;
        }
        IocCommand::Remove { case, id, actor } => {
            let actor = actor.resolve()?;
            let c = open_case_for_write(&case)?;
            let removed = remove_indicator(c.conn(), &actor, &id)?;
            if json {
                print_json(&serde_json::json!({ "indicator_id": id, "removed": removed }))?;
            } else if removed {
                outln!(
                    "removed {}  {}",
                    display_safe_line(&id),
                    cmd::finding::provenance(actor.as_str(), actor.on_behalf_of())
                );
            } else {
                outln!("no active indicator {}", display_safe_line(&id));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_note_names_the_collector_losses() {
        let note = |error: u64, lost: u64| {
            rejected_note(&FileReport {
                file_id: Some(1),
                rel_path: "f.csv".into(),
                artifact_id: None,
                status: sparrow_core::ingest::FileStatus::Parsed,
                records_read: 9,
                records_loaded: 9 - error,
                records_duplicate: 0,
                records_error: error,
                records_collector_lost: lost,
                warnings: Vec::new(),
            })
        };
        assert_eq!(note(0, 0), None);
        assert_eq!(note(1, 0).as_deref(), Some("1 record rejected"));
        assert_eq!(
            note(3, 1).as_deref(),
            Some("3 records rejected (1 lost by the collector)")
        );
        assert_eq!(
            note(1, 1).as_deref(),
            Some("1 record lost by the collector")
        );
        assert_eq!(
            note(2, 2).as_deref(),
            Some("2 records lost by the collector")
        );
    }

    /// What the shell reads back from `printf %s <word>`.
    fn shell_reads(shell: &str, quoted: &str) -> Vec<u8> {
        let out = std::process::Command::new(shell)
            .arg("-c")
            .arg(format!("printf %s {quoted}"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{shell} {quoted}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    }

    #[test]
    fn shell_quote_round_trips_through_a_posix_shell() {
        for s in [
            "case.duckdb",
            "my case.duckdb",
            "it's.duckdb",
            "a; touch pwned",
            "$(touch pwned) `touch pwned` $HOME ${x} *?[a]",
            "'''",
            "",
            "back\\slash \"double\" !bang #hash ~tilde",
            "unicode é 🔥",
        ] {
            let q = shell_quote(s);
            assert!(!q.contains('\n') && q.starts_with('\''), "{q}");
            assert_eq!(shell_reads("sh", &q), s.as_bytes(), "{s:?} -> {q}");
        }
    }

    #[test]
    fn shell_quote_keeps_control_and_format_characters_on_one_line() {
        for s in [
            "a\nb",
            "tab\there",
            "esc\u{1b}[31m",
            "bidi \u{202E}evil",
            "crlf \r\n end",
            "q'uote\n",
        ] {
            let q = shell_quote(s);
            assert!(
                q.starts_with("$'") && q.chars().all(|c| !c.is_control()),
                "{q:?}"
            );
            assert_eq!(shell_reads("bash", &q), s.as_bytes(), "{s:?} -> {q}");
        }
    }

    /// A real Hawk capture holds the portal exports beside it, so the Hawk `--real` run must
    /// generate the portal collector too.
    #[test]
    fn hawk_real_mode_generates_the_portal_collector_too() {
        let hawks = conformance_collectors(ConformanceCollector::Hawk);
        assert!(hawks.contains(&Collector::Hawk3), "{hawks:?}");
        assert!(hawks.contains(&Collector::Hawk4), "{hawks:?}");
        assert!(hawks.contains(&Collector::Portal), "{hawks:?}");
        assert_eq!(
            conformance_collectors(ConformanceCollector::Invictus),
            [Collector::Invictus]
        );
        assert_eq!(
            conformance_collectors(ConformanceCollector::Portal),
            [Collector::Portal]
        );
    }

    /// The report names the variants the matrix covered, per collector.
    #[test]
    fn the_real_report_lists_the_covered_variants() {
        let s = variant_summary(conformance_collectors(ConformanceCollector::Hawk));
        assert_eq!(s.len(), 3, "{s:?}");
        assert!(
            s.iter().any(|l| l.starts_with("hawk4[")
                && l.contains("ual-creation=utc")
                && l.contains("ual-creation=unspecified")),
            "{s:?}"
        );
        assert!(
            s.iter()
                .any(|l| l.starts_with("portal[")
                    && l.contains("purview-dates=iso,trace=excel-resave")),
            "{s:?}"
        );
        let report = sparrow_synth::conformance::ConformanceReport {
            ok: true,
            variants: s,
            not_covered: REAL_NOT_COVERED.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        assert!(
            report.to_text().contains("not covered: ja-JP"),
            "{}",
            report.to_text()
        );
        assert!(
            report.to_text().contains("variants covered: hawk3["),
            "{}",
            report.to_text()
        );
    }
}
