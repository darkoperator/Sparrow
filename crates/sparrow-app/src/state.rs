//! The one open case of the window and the guards every command goes through.

use crate::error::{CmdError, CmdResult};
use crate::settings;
use serde::Serialize;
use sparrow_core::Case;
use sparrow_core::case::actor::Reviewer;
use sparrow_core::case::audit;
use sparrow_core::data::DataDirs;
use sparrow_core::db::VerifiedOpen;
use sparrow_core::detect::load::{RuleSet, load_rules};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
pub struct AppState {
    pub open: Mutex<Option<OpenCase>>,
    /// The app config directory (set at startup); `None` in tests that do not need settings.
    pub settings_dir: Mutex<Option<PathBuf>>,
    /// The one cancellable query now running (`sql_run` / `browse_page`), kept outside `open` so `query_cancel` never
    /// waits for the lock the query holds. Registered after the case lock is taken, cleared when the call returns.
    /// Writes and share imports are never registered, so Cancel cannot reach them.
    pub active: Mutex<Option<ActiveQuery>>,
    /// Bumped on every open and close; an [`ActiveQuery`] of another generation is never interrupted.
    pub generation: AtomicU64,
}

pub struct ActiveQuery {
    pub id: String,
    pub generation: u64,
    pub handle: Arc<duckdb::InterruptHandle>,
}

/// The longest query id the frontend may send.
pub const MAX_QUERY_ID: usize = 64;

pub struct OpenCase {
    pub case: Case,
    pub path: PathBuf,
    /// Set when the case opened read-only (a broken audit chain): every write is refused.
    pub read_only_reason: Option<String>,
    pub rules: RuleSet,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseInfo {
    pub path: String,
    pub case_id: String,
    pub schema_version: u32,
    pub audit_ok: bool,
    pub read_only_reason: Option<String>,
    pub tenants: Vec<String>,
    /// Things the analyst should know that did not stop the open (the recent list could not be saved).
    pub warnings: Vec<String>,
}

fn lock(state: &AppState) -> MutexGuard<'_, Option<OpenCase>> {
    state.open.lock().unwrap_or_else(|p| p.into_inner())
}

/// Open the case at `path` (never creating one), closing any open case first. Core decides on the writer
/// connection, before anything is written (`Case::open_verified`):
/// - intact chain (current schema, or older and `allow_upgrade`, which migrates it): open for writing, locked down
///   for the in-process read-only SQL;
/// - current schema, broken chain: the writer is released and the case opens read-only (locked down too, so SQL
///   and the table browser work on it);
/// - older schema with a broken (or unverifiable) chain: refused (`needs_acknowledge`), nothing written;
/// - older schema, intact chain, upgrade not allowed: refused (`needs_upgrade`), nothing written.
///
/// The whole transition, recording the recent path included, holds the open-case lock, so overlapping opens and
/// closes apply in one order and each response describes the case that was open when it returned.
pub fn case_open(state: &AppState, path: &Path, allow_upgrade: bool) -> CmdResult<CaseInfo> {
    let mut slot = lock(state);
    // Release the current case's writer first: reopening the same file would otherwise find it busy.
    *slot = None;
    state.generation.fetch_add(1, Ordering::SeqCst);
    if !path.is_file() {
        return Err(CmdError::new(
            "not_found",
            format!("no case database at {}", path.display()),
        ));
    }
    let (case, read_only_reason, audit_ok) = match Case::open_verified(path, allow_upgrade)
        .map_err(open_error)?
    {
        VerifiedOpen::Writable(case) => {
            case.lock_down()?;
            (case, None, true)
        }
        VerifiedOpen::BrokenChain(report) => (
            {
                // Read-only is no reason to refuse SELECTs: lock the read-only connection down like the writer.
                let case = Case::open_read_only(path).map_err(open_error)?;
                case.lock_down()?;
                case
            },
            Some(format!(
                "the audit chain is broken at seq {}: {}; run sparrow audit verify --acknowledge",
                report.first_bad_seq.unwrap_or_default(),
                report.problem.as_deref().unwrap_or("unknown problem"),
            )),
            false,
        ),
        VerifiedOpen::NeedsAcknowledge {
            schema_version,
            first_bad_seq,
            problem,
        } => {
            let at = first_bad_seq
                .map(|s| format!(" at seq {s}"))
                .unwrap_or_default();
            return Err(CmdError::new(
                "needs_acknowledge",
                format!(
                    "this case was made by an older Sparrow (schema v{schema_version}) and its audit chain is \
                         broken{at}: {problem}; run `sparrow audit verify --acknowledge` and `sparrow upgrade` first"
                ),
            ));
        }
        VerifiedOpen::NeedsUpgrade {
            schema_version,
            latest,
        } => {
            return Err(CmdError::new(
                "needs_upgrade",
                format!(
                    "this case was made by an older Sparrow (schema v{schema_version}; this app uses \
                         v{latest}); opening it upgrades it in place"
                ),
            ));
        }
    };
    let rules = load_rules(&DataDirs::from_env())?;
    let mut info = CaseInfo {
        path: path.display().to_string(),
        case_id: audit::case_id(case.conn())?,
        schema_version: case.schema_version()?,
        audit_ok,
        read_only_reason: read_only_reason.clone(),
        tenants: tenants(&case)?,
        warnings: Vec::new(),
    };
    *slot = Some(OpenCase {
        case,
        path: path.to_path_buf(),
        read_only_reason,
        rules,
    });
    // The case is open; failing to remember it in the recent list is not worth failing the open over.
    if let Err(e) = settings::record_recent(state, &info.path) {
        info.warnings.push(format!(
            "the case was not added to the recent list: {}",
            e.message
        ));
    }
    Ok(info)
}

/// Core's writer-busy error with the reason an analyst will recognise.
fn open_error(e: sparrow_core::Error) -> CmdError {
    match e {
        sparrow_core::Error::WriterBusy(m) => CmdError::new(
            "writer_busy",
            format!(
                "the case is open in another process (the sparrow CLI or another Sparrow window); close it there \
                 and try again ({m})"
            ),
        ),
        other => other.into(),
    }
}

fn tenants(case: &Case) -> CmdResult<Vec<String>> {
    let mut stmt = case
        .conn()
        .prepare("SELECT tenant_key FROM tenant ORDER BY tenant_key")
        .map_err(sparrow_core::Error::from)?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(sparrow_core::Error::from)?;
    Ok(rows
        .collect::<Result<_, _>>()
        .map_err(sparrow_core::Error::from)?)
}

/// A caller-generated query id: 1..=64 characters, no control characters.
pub fn check_query_id(id: &str) -> CmdResult<()> {
    if id.is_empty() || id.chars().count() > MAX_QUERY_ID || id.chars().any(char::is_control) {
        return Err(CmdError::new(
            "invalid",
            format!("a query id is 1 to {MAX_QUERY_ID} characters without control characters"),
        ));
    }
    Ok(())
}

/// Clears the active-query entry when the query's call returns, on every path (also an error or a panic).
struct ActiveGuard<'a>(&'a AppState);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        *self.0.active.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// Like [`with_case`], for a query the analyst can cancel with [`query_cancel`] (`id`): the query is registered once
/// the case lock is held and unregistered when `f` returns.
pub fn with_cancellable<T>(
    state: &AppState,
    id: &str,
    f: impl FnOnce(&OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    check_query_id(id)?;
    with_case(state, |open| {
        *state.active.lock().unwrap_or_else(|p| p.into_inner()) = Some(ActiveQuery {
            id: id.to_string(),
            // Open and close bump the generation under the case lock this call holds, so it is this case's.
            generation: state.generation.load(Ordering::SeqCst),
            handle: open.case.conn().interrupt_handle(),
        });
        let _clear = ActiveGuard(state);
        f(open)
    })
}

/// Interrupt the running cancellable query whose id is `id`. Anything else is a no-op: no query running, another
/// query's id, an entry of another case generation, a write (never registered). Does not take the open-case lock (a
/// running query holds it). The entry's lock is held while interrupting, so the entry cannot be replaced meanwhile.
pub fn query_cancel(state: &AppState, id: &str) -> CmdResult<()> {
    check_query_id(id)?;
    let active = state.active.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(q) = active.as_ref() {
        if q.id == id && q.generation == state.generation.load(Ordering::SeqCst) {
            q.handle.interrupt();
        }
    }
    Ok(())
}

pub fn case_close(state: &AppState) -> CmdResult<()> {
    *lock(state) = None;
    state.generation.fetch_add(1, Ordering::SeqCst);
    Ok(())
}

/// Run `f` on the open case for a read.
pub fn with_case<T>(state: &AppState, f: impl FnOnce(&OpenCase) -> CmdResult<T>) -> CmdResult<T> {
    let slot = lock(state);
    let open = slot
        .as_ref()
        .ok_or_else(|| CmdError::new("no_case", "no case is open"))?;
    f(open)
}

/// Run `f` on the open case for a write: no case, a read-only case and an unusable case are refused first.
pub fn with_writable<T>(
    state: &AppState,
    f: impl FnOnce(&OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    with_case(state, |open| {
        if let Some(reason) = &open.read_only_reason {
            return Err(CmdError::new("read_only", reason.clone()));
        }
        open.case.ensure_usable()?;
        f(open)
    })
}

/// The analyst every write is made as, from the settings; `invalid` when no name is set.
pub fn analyst(state: &AppState) -> CmdResult<Reviewer> {
    let name = settings::settings_get(state)?.analyst.ok_or_else(|| {
        CmdError::new(
            "invalid",
            "set the analyst name (settings) before making a decision",
        )
    })?;
    Ok(Reviewer::analyst(&name)?)
}
