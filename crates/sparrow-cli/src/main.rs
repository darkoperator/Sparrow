use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use serde::Serialize;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::discovery::{Registry, discover_collections, list_collection_files};
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{
    DEFAULT_MAX_FILE_BYTES, IngestOptions, ingest_collections, no_collections_error,
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
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sparrow",
    version,
    about = "Ingest Hawk / Microsoft-Extractor-Suite output into a DuckDB case database for M365 BEC investigations"
)]
struct Cli {
    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List collector outputs under PATH and how each file is classified
    Discover { path: PathBuf },
    /// Ingest collector output into a case database
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
    /// Evidence availability: what the case holds, what is missing and why (first call for agents)
    Capabilities {
        #[arg(long)]
        case: PathBuf,
    },
    /// Tenant, licences, collections, coverage window, row counts, top actors and evidence gaps
    Summary {
        #[arg(long)]
        case: PathBuf,
    },
    /// Re-check a record against its original source file(s)
    Verify {
        table: String,
        record_key: String,
        #[arg(long)]
        case: PathBuf,
        /// Use this folder as the collection root (when the evidence was moved)
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Upgrade an existing case database to this version's schema
    Upgrade {
        #[arg(long)]
        case: PathBuf,
    },
    /// Describe the case database tables and columns
    Schema {
        #[arg(long)]
        case: PathBuf,
        table: Option<String>,
    },
    /// Run the detection rules over a case and merge the hits into its findings
    Detect {
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
    /// Case indicators (ip, upn, ...) that rules read through @list:case_iocs.<type>
    Ioc {
        #[command(subcommand)]
        command: IocCommand,
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
    /// Total benign UAL rows (scale testing)
    #[arg(long)]
    ual_rows: Option<u64>,
    /// Total benign sign-ins (scale testing)
    #[arg(long)]
    signins: Option<u64>,
}

#[derive(Subcommand)]
enum SynthCommand {
    /// Compare a case ingested from a generated tree with the tree's manifest
    Check {
        #[arg(long)]
        manifest: PathBuf,
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
            let generated = generated_profiles(c, seed)?;
            sparrow_synth::conformance::conform_real(&real, &generated)
        }
        _ => anyhow::bail!("pass exactly one of --tree DIR or --real DIR"),
    };
    if json {
        print_json(&report)?;
    } else {
        print!("{}", report.to_text());
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

/// Profile every built-in scenario (except `volume`) for `collector` with both editions and the
/// three host cultures, so `--real` compares a real capture with the whole generated matrix.
fn generated_profiles(
    c: ConformanceCollector,
    seed: u64,
) -> Result<Vec<sparrow_synth::conformance::Profile>> {
    let collectors = conformance_collectors(c);
    let mut out = Vec::new();
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        let scenario = sparrow_synth::scenario::load(name)?;
        for collector in collectors {
            for ps in [PsEdition::Ps7, PsEdition::Ps51] {
                for culture in [Culture::EnUs, Culture::EnGb, Culture::DeDe] {
                    let dir = tempfile::tempdir()?;
                    let mut o = GenerateOptions::new(*collector, seed);
                    o.ps = ps;
                    o.culture = culture;
                    sparrow_synth::generate::generate_to_dir(&scenario, &o, dir.path())?;
                    out.push(sparrow_synth::conformance::profile_dir(dir.path())?);
                }
            }
        }
    }
    Ok(out)
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
        #[arg(long)]
        case: PathBuf,
        /// ip, upn, app_id, domain, user_agent, rule_name, email, url or hash
        #[arg(long = "type")]
        ty: String,
        #[arg(long)]
        value: String,
        /// malicious, suspicious or benign
        #[arg(long)]
        verdict: String,
        #[arg(long)]
        note: Option<String>,
        /// Tenant the indicator applies to; default every tenant of the case
        #[arg(long)]
        tenant: Option<String>,
        /// Who is asking; required (or $SPARROW_ANALYST)
        #[arg(long)]
        analyst: Option<String>,
    },
    /// List the indicators of the case
    List {
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        tenant: Option<String>,
    },
    /// Remove an indicator by id
    Remove {
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        analyst: Option<String>,
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
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        analyst: Option<String>,
    },
    /// List the tenant's domains
    List {
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        tenant: Option<String>,
    },
}

fn main() -> ExitCode {
    let json_requested = std::env::args_os().any(|a| a == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            let _ = e.print();
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return ExitCode::SUCCESS;
            }
            if json_requested {
                println!("{}", serde_json::json!({ "error": e.render().to_string() }));
            }
            return ExitCode::from(1);
        }
    };
    let json = cli.json;
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let msg = format!("{e:#}");
            eprintln!("error: {msg}");
            if json {
                println!("{}", serde_json::json!({ "error": msg }));
            }
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let json = cli.json;
    match cli.command {
        None => {
            Cli::command().print_help()?;
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
                dirs: DataDirs::with_env_fallback(data, rules),
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
                dirs: DataDirs::with_env_fallback(data, rules),
                geoip_dir,
                as_of: None,
            },
            no_detect,
            json,
        ),
        Some(Command::Capabilities { case }) => cmd_capabilities(&case, json),
        Some(Command::Summary { case }) => cmd_summary(&case, json),
        Some(Command::Verify {
            table,
            record_key,
            case,
            root,
        }) => cmd_verify(&table, &record_key, &case, root.as_deref(), json),
        Some(Command::Upgrade { case }) => cmd_upgrade(&case, json),
        Some(Command::Schema { case, table }) => cmd_schema(&case, table.as_deref(), json),
        Some(Command::Detect {
            case,
            rule,
            tag,
            data,
            rules,
        }) => cmd_detect(
            &case,
            rule,
            tag,
            DataDirs::with_env_fallback(data, rules),
            json,
        ),
        Some(Command::Rules { command }) => cmd_rules(command, json),
        Some(Command::Ioc { command }) => cmd_ioc(command, json),
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

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
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
            println!("{} collection: {}", c.tool.as_str(), c.root);
            for f in &c.files {
                match &f.error {
                    Some(err) => println!("  {:<40} {}  [{err}]", "ERROR", f.rel_path),
                    None => println!("  {:<40} {}", f.artifact_id.unwrap_or("-"), f.rel_path),
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
    };
    let collections = discover_collections(path)?;
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
    let mut case = Case::create_or_open(case_path)
        .with_context(|| format!("opening {}", case_path.display()))?;
    let report = ingest_collections(&mut case, &collections, &ParserRegistry::builtin(), &opts)?;
    let profile = refresh(&mut case, &profile_opts).map_err(|e| {
        anyhow::anyhow!(
            "evidence loaded; the profile step failed: {e:#} (fix and run `sparrow profile --case ...`)"
        )
    })?;
    let detect = run_detection(&mut case, &profile_opts, no_detect);
    if json {
        print_json(&IngestOutput {
            report: &report,
            profile: &profile,
            detect: detect.as_ref(),
        })?;
    } else {
        for c in &report.collections {
            println!(
                "{} collection {} ({})",
                c.tool.as_str(),
                c.collection_id,
                c.root
            );
            for f in &c.files {
                println!(
                    "  {:<18} {:>7} rec  {}{}",
                    f.status.as_str(),
                    f.records_loaded,
                    f.rel_path,
                    if f.warnings.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", f.warnings.join("; "))
                    }
                );
            }
        }
        print_profile_summary(&profile);
        print_detect_summary(detect.as_ref());
    }
    Ok(if report.has_errors() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
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
            println!(
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
                println!("  warning: {w}");
            }
            for x in r.rules.iter().filter(|x| x.status == "error") {
                println!(
                    "  warning: rule {} failed for tenant {}: {}",
                    x.rule_id,
                    x.tenant_key,
                    x.reason.as_deref().unwrap_or("?")
                );
            }
        }
        (None, Some(e)) => {
            println!("warning: detection failed: {e} (run `sparrow profile --case ...` again)")
        }
        (None, None) => {}
    }
}

fn print_profile_summary(profile: &ProfileReport) {
    println!(
        "profile: {} capabilities, {} tenants, {} identities",
        profile.capabilities, profile.tenants, profile.identities
    );
    for w in &profile.warnings {
        println!("  warning: {w}");
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
        println!(
            "warning: profile is stale: {} collections not profiled; run `sparrow profile --case {}`",
            stale_collections.len(),
            case_path.display()
        );
    }
}

fn cmd_capabilities(case_path: &Path, json: bool) -> Result<ExitCode> {
    let case = Case::open_read_only(case_path)?;
    let report = capabilities_report(&case, chrono::Utc::now())?;
    if report.tenants.is_empty() {
        anyhow::bail!(
            "the case has no tenant profile; run `sparrow profile --case {}` first",
            case_path.display()
        );
    }
    if json {
        print_json(&report)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_stale_warning(&report.stale_collections, case_path);
    println!("evaluated at {}", report.as_of);
    for t in &report.tenants {
        println!();
        println!(
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
        println!("  capabilities:");
        for c in &t.capabilities {
            println!(
                "    {:<22} {:<13} ({})  {}",
                c.capability_id,
                c.status,
                c.confidence.as_deref().unwrap_or("-"),
                c.basis
            );
        }
        println!("  evidence:");
        for e in &t.evidence {
            println!(
                "    {:<22} {:<24} {:>9}  {}",
                e.evidence, e.status, e.rows, e.reason
            );
            if let Some(r) = &e.remediation {
                println!("      -> {r}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_summary(case_path: &Path, json: bool) -> Result<ExitCode> {
    let case = Case::open_read_only(case_path)?;
    let report = summarize(&case)?;
    if report.tenants.is_empty() {
        anyhow::bail!(
            "the case has no tenant profile; run `sparrow profile --case {}` first",
            case_path.display()
        );
    }
    if json {
        print_json(&report)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_stale_warning(&report.stale_collections, case_path);
    if let Some(at) = &report.profile_evaluated_at {
        println!("profile evaluated at {at}");
    }
    for t in &report.tenants {
        println!();
        println!(
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
        println!(
            "  licences: {}",
            if t.licenses.is_empty() {
                "-".to_string()
            } else {
                t.licenses.join(", ")
            }
        );
        println!("  collections:");
        for c in &t.collections {
            println!(
                "    {:<5} {:<9} {}  collected {}  window {} .. {}",
                c.collection_id,
                c.tool,
                c.root,
                c.collected_at.as_deref().unwrap_or("-"),
                c.window_start.as_deref().unwrap_or("-"),
                c.window_end.as_deref().unwrap_or("-"),
            );
        }
        println!("  coverage:");
        for cov in &t.coverage {
            println!(
                "    {:<22} {:>8} rows  {} .. {}",
                cov.source_table,
                cov.rows,
                cov.first.as_deref().unwrap_or("-"),
                cov.last.as_deref().unwrap_or("-"),
            );
        }
        println!("  top actors:");
        for a in &t.top_actors {
            println!("    {:<40} {:>8} rows", a.actor, a.rows);
        }
        println!(
            "  hosting ips: {}   state rows absent in a newer capture: {}",
            t.hosting_ips, t.absent_in_newer
        );
        println!(
            "  gaps: {}",
            if t.gaps.is_empty() {
                "-".to_string()
            } else {
                t.gaps.join(", ")
            }
        );
    }
    println!();
    println!("tables:");
    for tc in &report.tables {
        println!("  {:<24} {:>10} rows", tc.table, tc.rows);
    }
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
    let case = Case::open_read_only(case_path)?;
    let report = verify_record(&case, table, key, root)?;
    if json {
        print_json(&report)?;
    } else {
        println!(
            "{} {} -> {}",
            table,
            key,
            if report.ok { "OK" } else { "MISMATCH" }
        );
        for s in &report.sightings {
            println!(
                "  {}  found={} file_hash_ok={} record_hash_ok={}",
                s.source_ref, s.file_found, s.file_hash_ok, s.record_hash_ok
            );
            if let Some(ex) = &s.excerpt {
                for line in ex.lines() {
                    println!("    | {line}");
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
        println!("{}: schema already at v{to}", case_path.display());
    } else {
        println!(
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
    let case = Case::open_read_only(case_path)?;
    let out = SchemaOutput {
        tables: sparrow_core::db::describe(&case, table)?,
    };
    if let Some(t) = table {
        if out.tables.is_empty() {
            anyhow::bail!("no table named '{t}' in the case database");
        }
    }
    if json {
        print_json(&out)?;
    } else {
        for t in &out.tables {
            let suffix = if t.kind == "view" { " (view)" } else { "" };
            println!(
                "{}{suffix} — {}",
                t.table,
                t.comment.as_deref().unwrap_or("")
            );
            for c in &t.columns {
                println!(
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
    let name = explicit.or_else(|| {
        std::env::var("SPARROW_ANALYST")
            .ok()
            .filter(|a| !a.trim().is_empty())
    });
    match name {
        Some(n) => format!("analyst:{n}"),
        None => "analyst:unknown".to_string(),
    }
}

fn open_case_for_write(case_path: &Path) -> Result<Case> {
    if !case_path.is_file() {
        return Err(sparrow_core::Error::NotFound(format!(
            "case database {}",
            case_path.display()
        ))
        .into());
    }
    Case::create_or_open(case_path).with_context(|| format!("opening {}", case_path.display()))
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
        println!("{tenant_key}  {action} {domain}");
        println!("note: {DOMAIN_ACTION_NOTE}");
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
            let c = Case::open_read_only(&case)?;
            let domains = list_domains(&c, tenant.as_deref())?;
            if json {
                print_json(&DomainsOutput { domains })?;
            } else {
                for d in &domains {
                    println!("{}  {}  {}", d.tenant_key, d.domain, d.source);
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
    if args.ual_rows.is_some() || args.signins.is_some() {
        anyhow::bail!("--ual-rows / --signins are not supported until the scale knobs land");
    }
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
        println!("root:     {}", out.join(&summary.root).display());
        println!("manifest: {}", summary.manifest);
        if let Some(z) = &summary.zip {
            println!("zip:      {z}");
        }
        println!("files:    {}", summary.files);
        for (t, n) in &summary.tables {
            println!("  {t:<24} {n:>9} rows");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_synth_coverage(seed: u64, json: bool) -> Result<ExitCode> {
    let report = sparrow_synth::coverage::report(seed)?;
    if json {
        print_json(&report)?;
    } else {
        print!("{}", report.to_text());
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
    let case = Case::open_read_only(case_path)?;
    let report = sparrow_synth::check::check(&manifest, &case)?;
    if json {
        print_json(&report)?;
    } else {
        if report.ok {
            println!(
                "ok: collection {} matches {}",
                report.collection_id.unwrap_or_default(),
                manifest_path.display()
            );
        } else {
            println!("{} problems:", report.problems.len());
            for p in &report.problems {
                println!("  {p}");
            }
        }
        println!(
            "{} of {} rules checked, {} rule expectations not checked (no rule file)",
            report.detection.rules_checked, report.rules_expected, report.rules_unchecked
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
            println!("{title}:");
            for e in entries {
                println!("  {:<22} {}", e.id, e.description);
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
    let mut case = open_case_for_write(case_path)?;
    let report = sparrow_core::detect::run::run_with_dirs(
        &mut case,
        &dirs,
        &sparrow_core::detect::DetectOptions {
            rule_ids,
            tags,
            now: None,
        },
    )?;
    if json {
        print_json(&report)?;
    } else {
        print_detect_summary(Some(&DetectOutcome {
            report: Some(report.clone()),
            error: None,
        }));
        for r in &report.rules {
            println!(
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
            let set = load_rules(&DataDirs::with_env_fallback(data, rules))?;
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
                    println!("warning: {w}");
                }
                for i in &issues {
                    println!("{}: {}: {}", name(i.severity), i.rule_id, i.message);
                }
                println!(
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
            let set = load_rules(&DataDirs::with_env_fallback(data, rules))?;
            let results = sparrow_core::detect::test::run_inline_tests(&set, rule.as_deref())?;
            let failed = results.iter().filter(|r| !r.ok).count();
            if json {
                print_json(&serde_json::json!({ "failed": failed, "results": results }))?;
            } else {
                for r in &results {
                    println!(
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
                println!("{} tests, {} failed", results.len(), failed);
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
            let set = load_rules(&DataDirs::with_env_fallback(data, rules))?;
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
                    println!(
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

/// `--analyst` or $SPARROW_ANALYST, validated as an [`Actor`] (unlike the tenant commands there
/// is no anonymous fallback: an indicator changes what rules find).
fn required_actor(explicit: Option<String>) -> Result<sparrow_core::case::indicators::Actor> {
    let name = explicit
        .or_else(|| std::env::var("SPARROW_ANALYST").ok())
        .unwrap_or_default();
    sparrow_core::case::indicators::Actor::analyst(&name).map_err(|_| {
        anyhow::anyhow!("an analyst is required: pass --analyst NAME or set SPARROW_ANALYST")
    })
}

fn cmd_ioc(command: IocCommand, json: bool) -> Result<ExitCode> {
    use sparrow_core::case::indicators::{
        IndicatorType, Verdict, add_indicator, list_indicators, remove_indicator,
    };
    match command {
        IocCommand::Add {
            case,
            ty,
            value,
            verdict,
            note,
            tenant,
            analyst,
        } => {
            let actor = required_actor(analyst)?;
            let ty = IndicatorType::parse(&ty)?;
            let verdict = Verdict::parse(&verdict)?;
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
                print_json(&serde_json::json!({
                    "indicator_id": id, "type": ty, "value": value.trim(), "verdict": verdict,
                    "tenant_key": tenant, "added_by": actor.as_str(),
                }))?;
            } else {
                println!(
                    "{id}  {} {}  {}",
                    ty.as_str(),
                    value.trim(),
                    verdict.as_str()
                );
            }
        }
        IocCommand::List { case, tenant } => {
            let c = Case::open_read_only(&case)?;
            let items = list_indicators(c.conn(), tenant.as_deref())?;
            if json {
                print_json(&serde_json::json!({ "indicators": items }))?;
            } else {
                for i in &items {
                    println!(
                        "{}  {:<10} {:<10} {}  by {}{}",
                        i.indicator_id,
                        i.ty.as_str(),
                        i.verdict.as_str(),
                        i.value,
                        i.added_by,
                        i.note
                            .as_deref()
                            .map(|n| format!("  ({n})"))
                            .unwrap_or_default()
                    );
                }
                println!("{} indicators", items.len());
            }
        }
        IocCommand::Remove { case, id, analyst } => {
            let actor = required_actor(analyst)?;
            let c = open_case_for_write(&case)?;
            let removed = remove_indicator(c.conn(), &actor, &id)?;
            if json {
                print_json(&serde_json::json!({ "indicator_id": id, "removed": removed }))?;
            } else if removed {
                println!("removed {id}");
            } else {
                println!("no indicator {id}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
