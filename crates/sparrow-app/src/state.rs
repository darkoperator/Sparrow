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
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Default)]
pub struct AppState {
    pub open: Mutex<Option<OpenCase>>,
    /// The app config directory (set at startup); `None` in tests that do not need settings.
    pub settings_dir: Mutex<Option<PathBuf>>,
    /// The one cancellable query now running (`sql_run` / `browse_page`), kept outside `open` so `query_cancel` never
    /// waits for the lock the query holds. Registered after the case lock is taken, cleared when the call returns.
    /// Writes and share imports are never registered, so Cancel cannot reach them.
    pub active: Arc<Mutex<Option<ActiveQuery>>>,
    /// Ids cancelled before their query registered (it was still waiting for the case lock, or the cancel overtook
    /// the run), tagged with the case generation, newest last, at most [`MAX_PENDING_CANCELS`]. Always locked after
    /// `active`.
    pub cancelled: Mutex<VecDeque<(u64, String)>>,
    /// Bumped on every open and close; an [`ActiveQuery`] of another generation is never interrupted.
    pub generation: AtomicU64,
    /// True while an import or a profile run holds the case (see `cmd::ingest`). Writes, reads that queued meanwhile
    /// and case switches are refused `busy` instead of running after it.
    pub importing: AtomicBool,
    /// The agent bridge serving the open case ([`crate::bridge`]).
    pub bridge: crate::bridge::BridgeSlot,
}

/// The refusal while an import runs.
pub fn busy() -> CmdError {
    CmdError::new(
        "busy",
        "an import is running; wait for it to finish (or cancel it) first",
    )
}

pub struct ActiveQuery {
    pub id: String,
    pub handle: Arc<duckdb::InterruptHandle>,
    /// Set by `query_cancel` when it matched this entry: the operation's result is then discarded as `interrupted`.
    pub cancelled: Arc<AtomicBool>,
    /// Set when the operation returned (the entry is cleared): ends the repeated interrupts.
    pub done: Arc<AtomicBool>,
}

/// The case generation a request saw when it was submitted (its first statement). `with_case` and friends refuse the
/// request, after taking the lock, when the case was switched or closed in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);

impl AppState {
    /// Capture a [`Ticket`]. Every public command does this as its first statement, before any I/O.
    pub fn ticket(&self) -> Ticket {
        Ticket(self.generation.load(Ordering::SeqCst))
    }
}

/// How many cancelled-before-start ids are remembered; the oldest is forgotten first.
pub const MAX_PENDING_CANCELS: usize = 64;

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
    if state.importing.load(Ordering::SeqCst) {
        return Err(busy());
    }
    // Requests already queued for the current case are void from now on, whichever gets the lock first.
    new_generation(state);
    let mut slot = lock(state);
    // The bridge's connections to the current case go before it closes (under the lock: no bridge write runs).
    crate::bridge::stop(state);
    // Release the current case's writer first: reopening the same file would otherwise find it busy.
    *slot = None;
    new_generation(state);
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
    if let Some(open) = slot.as_ref() {
        crate::bridge::start(state, open);
    }
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

/// A new case generation: requests that captured the old one are refused, ids cancelled for it are forgotten.
fn new_generation(state: &AppState) {
    state.generation.fetch_add(1, Ordering::SeqCst);
    state
        .cancelled
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clear();
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

/// Ends the query's registration when its call returns, on every path (an error and a panic too): marks it `done`
/// and clears the entry while holding the `active` mutex, so no interrupt can follow the teardown.
struct ActiveGuard<'a>(&'a AppState, Arc<AtomicBool>);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        let mut active = self.0.active.lock().unwrap_or_else(|p| p.into_inner());
        self.1.store(true, Ordering::SeqCst);
        *active = None;
    }
}

/// Interrupt `handle` every 50 ms until `done`: a cancel that lands after the query registered but before it
/// executes would otherwise hit an idle connection and be lost. `done` is checked and the interrupt is sent while
/// holding the `active` mutex, which [`ActiveGuard`] also holds to set `done`, so nothing follows the teardown.
fn keep_interrupting(
    active: Arc<Mutex<Option<ActiveQuery>>>,
    handle: Arc<duckdb::InterruptHandle>,
    done: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        loop {
            {
                let _held = active.lock().unwrap_or_else(|p| p.into_inner());
                if done.load(Ordering::SeqCst) {
                    return;
                }
                handle.interrupt();
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

/// Like [`with_case`], for a query the analyst can cancel with [`query_cancel`] (`id`): the query is registered once
/// the case lock is held and unregistered when `f` returns. A cancel that matched while it ran makes the call return
/// `interrupted` even when `f` finished (its result is discarded).
pub fn with_cancellable<T>(
    state: &AppState,
    ticket: Ticket,
    id: &str,
    f: impl FnOnce(&OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    with_cancellable_commit(state, ticket, id, |open, _| f(open))
}

/// Given to an operation run by [`with_cancellable_commit`], for the one step that makes its result visible.
pub struct Commit<'a> {
    state: &'a AppState,
    cancelled: Arc<AtomicBool>,
    committed: AtomicBool,
}

impl Commit<'_> {
    /// Run `f`, the step that makes the result visible (renaming a finished file into place), unless the operation
    /// was cancelled, which is `interrupted` and `f` never runs. Decided and run while holding the `active` lock, the
    /// one `query_cancel` takes: a cancel lands either before (nothing is made visible) or after `f`, and then no
    /// longer turns the call into `interrupted` (the result exists).
    pub fn commit<T>(&self, f: impl FnOnce() -> CmdResult<T>) -> CmdResult<T> {
        let _held = self.state.active.lock().unwrap_or_else(|p| p.into_inner());
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(sparrow_core::Error::Interrupted.into());
        }
        let out = f()?;
        self.committed.store(true, Ordering::SeqCst);
        Ok(out)
    }
}

/// [`with_cancellable`] for an operation whose result becomes visible in one final step (a file written by an
/// export): `f` runs that step through [`Commit::commit`], so a cancel never reports `interrupted` for a result that
/// was made visible, and never makes one visible after it was cancelled.
pub fn with_cancellable_commit<T>(
    state: &AppState,
    ticket: Ticket,
    id: &str,
    f: impl FnOnce(&OpenCase, &Commit<'_>) -> CmdResult<T>,
) -> CmdResult<T> {
    check_query_id(id)?;
    locked_case(state, ticket, |open, generation| {
        let (cancelled, done) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let mut active = state.active.lock().unwrap_or_else(|p| p.into_inner());
        *active = Some(ActiveQuery {
            id: id.to_string(),
            handle: open.case.conn().interrupt_handle(),
            cancelled: cancelled.clone(),
            done: done.clone(),
        });
        let _clear = ActiveGuard(state, done);
        // A cancel that arrived first was recorded under the `active` lock this call now holds: registering the
        // entry and reading the record are one step, so a cancel is either seen here or interrupts the entry.
        let cancelled_before = {
            let mut pending = state.cancelled.lock().unwrap_or_else(|p| p.into_inner());
            let before = pending.len();
            pending.retain(|(g, i)| !(*g == generation && i == id));
            pending.len() != before
        };
        drop(active);
        if cancelled_before {
            return Err(sparrow_core::Error::Interrupted.into());
        }
        let commit = Commit {
            state,
            cancelled: cancelled.clone(),
            committed: AtomicBool::new(false),
        };
        let out = f(open, &commit);
        if cancelled.load(Ordering::SeqCst)
            && out.is_ok()
            && !commit.committed.load(Ordering::SeqCst)
        {
            return Err(sparrow_core::Error::Interrupted.into());
        }
        out
    })
}

/// Interrupt the running cancellable query whose id is `id`. The active entry is matched by id alone: it is the
/// query holding the case right now and is cleared when it returns. A write (never registered) and another query's
/// id are not touched. An id with no running query is remembered for the current case generation, so a cancel that overtakes its query (still waiting for the case lock) makes it return `interrupted`
/// without running. Does not take the open-case lock (a running query holds it). The `active` lock is held while
/// deciding, so the entry cannot be replaced meanwhile.
pub fn query_cancel(state: &AppState, id: &str) -> CmdResult<()> {
    check_query_id(id)?;
    let active = state.active.lock().unwrap_or_else(|p| p.into_inner());
    let generation = state.generation.load(Ordering::SeqCst);
    if let Some(q) = active.as_ref() {
        if q.id == id {
            q.handle.interrupt();
            // Once: keep interrupting until the operation returns, so a cancel that landed before the query
            // started executing still stops it.
            if !q.cancelled.swap(true, Ordering::SeqCst) {
                keep_interrupting(state.active.clone(), q.handle.clone(), q.done.clone());
            }
            return Ok(());
        }
    }
    let mut pending = state.cancelled.lock().unwrap_or_else(|p| p.into_inner());
    if !pending.iter().any(|(g, i)| *g == generation && i == id) {
        pending.push_back((generation, id.to_string()));
        while pending.len() > MAX_PENDING_CANCELS {
            pending.pop_front();
        }
    }
    Ok(())
}

pub fn case_close(state: &AppState) -> CmdResult<()> {
    if state.importing.load(Ordering::SeqCst) {
        return Err(busy());
    }
    new_generation(state);
    let mut slot = lock(state);
    crate::bridge::stop(state);
    *slot = None;
    new_generation(state);
    Ok(())
}

/// Run `f` on the open case for a read.
pub fn with_case<T>(
    state: &AppState,
    ticket: Ticket,
    f: impl FnOnce(&OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    locked_case(state, ticket, |open, _| f(open))
}

/// Take the open-case lock for a request. The ticket (the case generation, captured when the command started): a request that
/// queued while the case was switched or closed (the generation moved, see [`new_generation`]) is refused instead of
/// running on whatever case is open now. `f` also gets that generation.
fn locked_case<T>(
    state: &AppState,
    ticket: Ticket,
    f: impl FnOnce(&OpenCase, u64) -> CmdResult<T>,
) -> CmdResult<T> {
    let generation = ticket.0;
    // Refused before waiting for a lock the import holds, so a request made during it fails at once.
    if state.importing.load(Ordering::SeqCst) {
        return Err(busy());
    }
    let slot = lock(state);
    if state.importing.load(Ordering::SeqCst) {
        return Err(busy());
    }
    if state.generation.load(Ordering::SeqCst) != generation {
        return Err(CmdError::new(
            "no_case",
            "the case changed while this request was waiting; reload",
        ));
    }
    let open = slot
        .as_ref()
        .ok_or_else(|| CmdError::new("no_case", "no case is open"))?;
    f(open, generation)
}

/// Run `f` on the open case for a write: no case, a read-only case and an unusable case are refused first.
pub fn with_writable<T>(
    state: &AppState,
    ticket: Ticket,
    f: impl FnOnce(&OpenCase) -> CmdResult<T>,
) -> CmdResult<T> {
    with_case(state, ticket, |open| {
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
