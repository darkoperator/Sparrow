//! `sparrow notebook`: the SQL notebooks of a case. The built-in notebook ships with Sparrow and is never written; case
//! notebooks hold saved queries. An agent may read and run them, add queries and import notebook files (`add` and
//! `import` are writes, through the app's bridge while it has the case open); renaming, reordering and deleting are
//! the analyst's, in the app.

use crate::ActorArgs;
use anyhow::{Result, bail};
use clap::Subcommand;
use serde_json::json;
use sparrow_core::case::notebooks::{self, store::MAX_IMPORT_BYTES};
use sparrow_core::case::text::{display_safe, display_safe_line};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum NotebookCommand {
    /// The notebooks of the case, the built-in one first, with their queries' titles and [placeholders]
    List {
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
    /// One saved query's text. NOTEBOOK is an id or a name (builtin for the built-in one), QUERY an id or a
    /// position (1, 2, ...)
    Show {
        notebook: String,
        query: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
    /// Run a saved query as `sparrow query` does (exit 1 while it holds [placeholders]: fill them in and run the
    /// SQL with `sparrow query`)
    Run {
        notebook: String,
        query: String,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        /// At most this many rows
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// Add a query to a case notebook (an agent decision, recorded with --agent; not pending review)
    Add {
        /// The case notebook, by id or name
        #[arg(long)]
        notebook: String,
        /// The query text: a -- comment block (its first line is the title), then the SQL
        #[arg(
            long,
            required_unless_present = "file",
            conflicts_with = "file",
            allow_hyphen_values = true
        )]
        sql: Option<String>,
        /// Read the query text from this file instead
        #[arg(long)]
        file: Option<PathBuf>,
        /// Create the notebook when the case has none by that name
        #[arg(long)]
        create: bool,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Import a notebook file (from `notebook export` or the app) as a new case notebook
    Import {
        /// The notebook file (.sql)
        #[arg(long)]
        file: PathBuf,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
        #[command(flatten)]
        actor: ActorArgs,
    },
    /// Write a notebook to a .sql file. Refused (exit 5, nothing written) when its queries hold values from this
    /// case (accounts, IPs, devices, sessions, the tenant's domains, IP ranges), unless --force
    Export {
        notebook: String,
        /// The file to write
        #[arg(long)]
        out: PathBuf,
        /// Export even when the queries hold values from this case (each is still reported on stderr)
        #[arg(long)]
        force: bool,
        /// Case database file
        #[arg(long)]
        case: PathBuf,
    },
}

/// The text of `path`, refused past the import cap without reading the rest.
fn read_capped(path: &Path, what: &str) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_IMPORT_BYTES as u64 + 1).read_to_end(&mut bytes))
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    if bytes.len() > MAX_IMPORT_BYTES {
        bail!("{what} is limited to 4 MiB");
    }
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("{} is not UTF-8 text", path.display()))
}

pub fn run(command: NotebookCommand, json: bool) -> Result<ExitCode> {
    match command {
        NotebookCommand::List { case } => {
            let c = crate::open_read(&case)?;
            let list = notebooks::list(c.conn())?;
            if json {
                outln!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "notebooks": list }))?
                );
                return Ok(ExitCode::SUCCESS);
            }
            for nb in &list {
                let n = nb.queries.len();
                outln!(
                    "{}  {}  ({n} {})",
                    nb.notebook_id,
                    display_safe_line(&nb.name),
                    if n == 1 { "query" } else { "queries" }
                );
                for q in &nb.queries {
                    let mut line = format!("  {}. {}", q.position, display_safe_line(&q.title));
                    if !q.placeholders.is_empty() {
                        let p: Vec<String> =
                            q.placeholders.iter().map(|p| format!("[{p}]")).collect();
                        line.push_str(&format!("  {}", p.join(" ")));
                    }
                    if let Some(by) = q.decided_by.as_deref().filter(|b| b.starts_with("agent:")) {
                        line.push_str(&format!("  (by {})", display_safe_line(by)));
                    }
                    outln!("{line}");
                }
            }
        }
        NotebookCommand::Show {
            notebook,
            query,
            case,
        } => {
            let c = crate::open_read(&case)?;
            let q = notebooks::find_query(c.conn(), &notebook, &query)?;
            if json {
                outln!("{}", serde_json::to_string_pretty(&q)?);
            } else {
                outln!("{}", display_safe(&q.sql));
            }
        }
        NotebookCommand::Run {
            notebook,
            query,
            case,
            limit,
        } => {
            let sql = {
                let c = crate::open_read(&case)?;
                notebooks::find_query(c.conn(), &notebook, &query)?.sql
            };
            if let Err(e) = notebooks::refuse_placeholders(&sql) {
                bail!("{e}");
            }
            return crate::cmd::read::query(&case, &sql, limit, json);
        }
        NotebookCommand::Add {
            notebook,
            sql,
            file,
            create,
            case,
            actor,
        } => {
            let actor = actor.resolve()?;
            let sql = match (sql, file) {
                (Some(s), _) => s,
                (None, Some(f)) => read_capped(&f, "a query file")?,
                (None, None) => bail!("give the query with --sql or --file"),
            };
            let c = crate::open_case_for_write(&case)?;
            let (id, query_id, e) =
                notebooks::add_query_creating(c.conn(), &actor, &notebook, &sql, create)?;
            let (_, name, _) = notebooks::notebook_queries(c.conn(), &id)?;
            if json {
                let mut v = serde_json::to_value(&e)?;
                v["query_id"] = query_id.into();
                v["notebook_id"] = id.into();
                outln!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                outln!("query {query_id} added to {}", display_safe_line(&name));
            }
        }
        NotebookCommand::Import { file, case, actor } => {
            let actor = actor.resolve()?;
            let text = read_capped(&file, "an import file")?;
            let c = crate::open_case_for_write(&case)?;
            let (id, e) = notebooks::import_text(c.conn(), &actor, &text)?;
            let (_, name, qs) = notebooks::notebook_queries(c.conn(), &id)?;
            if json {
                let mut v = serde_json::to_value(&e)?;
                v["notebook_id"] = id.into();
                v["name"] = name.into();
                outln!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                outln!(
                    "imported {} queries as notebook {}",
                    qs.len(),
                    display_safe_line(&name)
                );
            }
        }
        NotebookCommand::Export {
            notebook,
            out,
            force,
            case,
        } => {
            crate::cmd::export::check_out(&out, &case)?;
            let c = crate::open_read(&case)?;
            let (_, name, qs) = notebooks::notebook_queries(c.conn(), &notebook)?;
            let pairs: Vec<(String, String)> = qs
                .into_iter()
                .map(|q| (q.summary.query_id, q.sql))
                .collect();
            let hits = notebooks::case_values_in(c.conn(), &pairs)?;
            for h in &hits {
                errln!(
                    "{}: {}: {}",
                    if force { "warning" } else { "case values" },
                    display_safe_line(&h.title),
                    display_safe_line(&h.values.join(", "))
                );
            }
            if !hits.is_empty() && !force {
                return Err(sparrow_core::Error::Decision(format!(
                    "notebook {} holds values from this case; nothing was written (--force exports anyway)",
                    display_safe_line(&name)
                ))
                .into());
            }
            let text = notebooks::export_text(c.conn(), &notebook, sparrow_core::VERSION)?;
            crate::cmd::export::atomic(&out, |tmp| {
                std::fs::write(tmp, &text)
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", tmp.display()))
            })?;
            if json {
                let v = json!({ "out": out, "notebook": name, "queries": pairs.len(), "case_values": hits });
                outln!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                outln!("wrote {} ({} queries)", out.display(), pairs.len());
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
