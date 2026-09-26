use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
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
        /// Directory overriding the embedded rule lists (lists/hosting_asns.yaml); default $SPARROW_RULES
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Folder with MaxMind GeoLite2 City / ASN .mmdb files for IP enrichment
        #[arg(long)]
        geoip_dir: Option<PathBuf>,
    },
    /// Re-derive the tenant profile, capabilities, IP enrichment and identities of a case
    Profile {
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        data: Option<PathBuf>,
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        geoip_dir: Option<PathBuf>,
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
    /// Tenant settings kept by the analyst
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
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
            json,
        ),
        Some(Command::Profile {
            case,
            data,
            rules,
            geoip_dir,
        }) => cmd_profile(
            &case,
            ProfileOptions {
                dirs: DataDirs::with_env_fallback(data, rules),
                geoip_dir,
                as_of: None,
            },
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
        Some(Command::Tenant { command }) => cmd_tenant(command, json),
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
    if json {
        print_json(&IngestOutput {
            report: &report,
            profile: &profile,
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

fn cmd_profile(case_path: &Path, profile_opts: ProfileOptions, json: bool) -> Result<ExitCode> {
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
    if json {
        print_json(&profile)?;
    } else {
        print_profile_summary(&profile);
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
