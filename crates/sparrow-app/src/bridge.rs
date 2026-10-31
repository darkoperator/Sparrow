//! The agent bridge: while a case is open, an agent's `sparrow` CLI on this computer runs its commands on that case
//! through the app instead of opening the file (which the app holds).
//!
//! The app listens on `127.0.0.1` on a port the OS picks and writes `bridge.json` (port, a per-session token,
//! the case, pid, version) to the per-user local data directory, readable by this user only; the wire format is in
//! `sparrow_cli::bridge`. Requests run one at a time on one worker thread, through the same `sparrow_cli::run` as
//! the binary:
//! - reads run on a second connection to the app's open database, cloned when the case opened, so they never wait
//!   for the app's case lock; each stops at a time limit (`SPARROW_BRIDGE_TIMEOUT`, default 120 s) through DuckDB's
//!   interrupt;
//! - writes (agent decisions, tenant settings) take the app's case lock like the screens do (at most 30 s of
//!   waiting), are signed on behalf of the app's analyst, and run on a connection cloned under that lock;
//! - heavy commands (ingest, profile, detect, upgrade, synth) are refused.
//!
//! Closing or switching the case, or starting an import, stops the bridge first: the running read is interrupted
//! (a running write is short and finishes), queued requests are answered with the close message, the discovery file
//! is deleted and the listener closed, and the bridge's connections are gone before the case closes.

use crate::state::{self, AppState, OpenCase};
use chrono::Utc;
use serde_json::{Value, json};
use sparrow_cli::bridge::{
    self as wire, Discovery, ERR, EXIT, FrameWriter, MAX_REQUEST_LINE, MAX_TOKEN_LINE, OUT,
    Request, TOKEN_BYTES,
};
use sparrow_cli::{CaseSource, CliIo, Inspected, Kind};
use sparrow_core::Case;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::{BufReader, LineWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What the bridge needs from the app around it: the state, and a way to tell the screen something happened.
pub trait BridgeHost: Send + Sync + 'static {
    fn state(&self) -> &AppState;
    fn emit(&self, event: &str, payload: Value);
}

/// The answer to every request the bridge stops before it completes.
pub const CLOSED: &str =
    "the analyst closed the case (or started an import) while this ran; nothing was written";
/// How long a write waits for the app's case lock.
pub const WRITE_WAIT: Duration = Duration::from_secs(30);
/// A read's time limit when `SPARROW_BRIDGE_TIMEOUT` is not set.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// The longest time limit `SPARROW_BRIDGE_TIMEOUT` may set.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
/// How long a connection may take to send its token and request.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How long sending output may stall (a CLI that stopped reading) before the bridge gives up on that request.
const SEND_STALL: Duration = Duration::from_secs(30);
/// How long a stop lets the interrupted request answer before breaking its connection.
const STOP_GRACE: Duration = Duration::from_secs(1);
/// Connections being read at once; more are closed at once.
const MAX_HANDSHAKES: usize = 16;

/// The bridge part of [`AppState`].
#[derive(Default)]
pub struct BridgeSlot {
    host: Mutex<Option<(Arc<dyn BridgeHost>, PathBuf)>>,
    running: Mutex<Option<Bridge>>,
    last_port: Mutex<Option<u16>>,
}

impl BridgeSlot {
    /// The port of the most recent bridge, also after it stopped.
    pub fn last_port(&self) -> Option<u16> {
        *lock(&self.last_port)
    }

    /// The discovery file of the running bridge.
    pub fn discovery(&self) -> Option<Discovery> {
        lock(&self.running).as_ref().map(|b| b.discovery.clone())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Serve the bridge from now on whenever a case is open, writing the discovery file in `dir`. The app does this once
/// at startup; without it no bridge runs.
pub fn enable(state: &AppState, host: Arc<dyn BridgeHost>, dir: PathBuf) {
    *lock(&state.bridge.host) = Some((host, dir));
}

/// Start the bridge for the case that just opened (`open`, under the open-case lock). A bridge that cannot start
/// leaves the case open without one. Skipped while an import holds the case: deciding and starting happen under the
/// bridge lock that [`stop`] takes, so an import that begins meanwhile either sees no bridge start or stops it.
pub(crate) fn start(state: &AppState, open: &OpenCase) {
    start_inner(state, open, false);
}

fn start_inner(state: &AppState, open: &OpenCase, after_import: bool) {
    let Some((host, dir)) = lock(&state.bridge.host).clone() else {
        return;
    };
    let mut running = lock(&state.bridge.running);
    if let Some(old) = running.take() {
        old.stop();
    }
    if !after_import && state.importing.load(Ordering::SeqCst) {
        return;
    }
    match Bridge::start(host, dir, open, state.ticket()) {
        Ok(b) => {
            *lock(&state.bridge.last_port) = Some(b.discovery.port);
            *running = Some(b);
        }
        Err(e) => eprintln!("sparrow: the agent bridge did not start: {e}"),
    }
}

/// Stop the running bridge, if any, before the case closes or switches (called under the open-case lock, so no
/// bridge write is running: a write holds that lock) or an import begins (`importing` already set).
pub(crate) fn stop(state: &AppState) {
    let b = lock(&state.bridge.running).take();
    if let Some(b) = b {
        b.stop();
    }
}

/// Start the bridge again for the case open now, at the end of an import (while `importing` is still set, so no
/// close, switch or second import runs meanwhile).
pub(crate) fn restart(state: &AppState) {
    let slot = lock(&state.open);
    if let Some(open) = slot.as_ref() {
        start_inner(state, open, true);
    }
}

struct Job {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    req: Request,
}

/// What the worker and the stopper share.
struct Shared {
    stopping: AtomicBool,
    queue: Mutex<VecDeque<Job>>,
    wake: Condvar,
    /// The interrupt handles of the read now running (every connection it opened); empty while a write runs.
    reading: Mutex<Vec<Arc<duckdb::InterruptHandle>>>,
    /// The connection of the request now running, so a stop can break a send blocked on a CLI that stopped reading.
    current: Mutex<Option<TcpStream>>,
    handshakes: AtomicUsize,
}

impl Shared {
    fn interrupt_reads(&self) {
        for h in lock(&self.reading).iter() {
            h.interrupt();
        }
    }

    fn new() -> Shared {
        Shared {
            stopping: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            reading: Mutex::new(Vec::new()),
            current: Mutex::new(None),
            handshakes: AtomicUsize::new(0),
        }
    }
}

struct Bridge {
    shared: Arc<Shared>,
    discovery: Discovery,
    dir: PathBuf,
    threads: Vec<JoinHandle<()>>,
}

impl Bridge {
    fn start(
        host: Arc<dyn BridgeHost>,
        dir: PathBuf,
        open: &OpenCase,
        ticket: state::Ticket,
    ) -> anyhow::Result<Bridge> {
        let read_base = open.case.shared_view(true)?;
        let case = std::fs::canonicalize(&open.path)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let mut raw = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("no random token: {e}"))?;
        let discovery = Discovery {
            port: listener.local_addr()?.port(),
            token: hex::encode(raw),
            case: case.clone(),
            pid: std::process::id(),
            version: wire::VERSION.to_string(),
            started: Utc::now(),
        };
        let mut bridge = Bridge {
            shared: Arc::new(Shared::new()),
            discovery,
            dir,
            threads: Vec::new(),
        };
        // The threads first and the discovery file last: a bridge that fails to start leaves neither behind (its
        // `stop` joins what did start).
        let worker = Worker {
            host,
            case,
            ticket,
            read_base,
        };
        let shared = bridge.shared.clone();
        match std::thread::Builder::new()
            .name("sparrow-bridge".into())
            .spawn(move || worker.run(shared))
        {
            Ok(t) => bridge.threads.push(t),
            Err(e) => {
                bridge.stop();
                return Err(e.into());
            }
        }
        let (shared, token) = (bridge.shared.clone(), bridge.discovery.token.clone());
        match std::thread::Builder::new()
            .name("sparrow-bridge-accept".into())
            .spawn(move || accept_loop(listener, shared, token))
        {
            Ok(t) => bridge.threads.push(t),
            Err(e) => {
                bridge.stop();
                return Err(e.into());
            }
        }
        if let Err(e) = wire::write_discovery(&bridge.dir, &bridge.discovery) {
            bridge.stop();
            return Err(e.into());
        }
        Ok(bridge)
    }

    fn stop(self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        // The discovery file goes first: a CLI started from now on runs on its own (and finds the case closing).
        wire::remove_discovery(&self.dir, &self.discovery.token);
        self.shared.interrupt_reads();
        self.shared.wake.notify_all();
        // The interrupted request normally answers within milliseconds (the close message). One still running after
        // a second is stuck sending to a CLI that stopped reading: break its connection.
        let waited = Instant::now();
        while lock(&self.shared.current).is_some() && waited.elapsed() < STOP_GRACE {
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Some(s) = lock(&self.shared.current).as_ref() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>, token: String) {
    while !shared.stopping.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if shared.handshakes.fetch_add(1, Ordering::SeqCst) >= MAX_HANDSHAKES {
                    shared.handshakes.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let (shared, token) = (shared.clone(), token.clone());
                let spawned = std::thread::Builder::new()
                    .name("sparrow-bridge-conn".into())
                    .spawn({
                        let shared = shared.clone();
                        move || {
                            handshake(stream, &shared, &token);
                            shared.handshakes.fetch_sub(1, Ordering::SeqCst);
                        }
                    });
                if spawned.is_err() {
                    shared.handshakes.fetch_sub(1, Ordering::SeqCst);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// Read the token and the request; a wrong token, a malformed request or a slow sender is closed without an
/// answer.
fn handshake(stream: TcpStream, shared: &Shared, token: &str) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(HANDSHAKE));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let Ok(Some(line)) = wire::read_line_limited(&mut reader, MAX_TOKEN_LINE) else {
        return;
    };
    if !wire::token_eq(line.trim_end_matches('\r').as_bytes(), token.as_bytes()) {
        return;
    }
    let Ok(Some(req)) = wire::read_line_limited(&mut reader, MAX_REQUEST_LINE) else {
        return;
    };
    let Ok(req) = serde_json::from_str::<Request>(&req) else {
        return;
    };
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(Some(SEND_STALL));
    let mut job = Job {
        stream,
        reader,
        req,
    };
    let mut queue = lock(&shared.queue);
    if shared.stopping.load(Ordering::SeqCst) {
        drop(queue);
        refuse(&mut job.stream, CLOSED, 4);
        return;
    }
    queue.push_back(job);
    shared.wake.notify_all();
}

/// Answer with `msg` on stderr and exit code `code`.
fn refuse(stream: &mut TcpStream, msg: &str, code: u8) {
    let _ = wire::write_frame(stream, ERR, format!("error: {msg}\n").as_bytes());
    let _ = wire::write_frame(stream, EXIT, &[code]);
}

struct Worker {
    host: Arc<dyn BridgeHost>,
    /// The open case, canonicalised.
    case: PathBuf,
    /// The case generation the bridge serves: a request after a switch is refused.
    ticket: state::Ticket,
    /// The second connection reads are cloned from.
    read_base: Case,
}

/// Ends the bridge when its worker ends, also by a panic: the listener stops and every queued request is answered.
struct WorkerExit(Arc<Shared>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.stopping.store(true, Ordering::SeqCst);
        // A request cut short by a panic gets its connection closed, so its CLI sees the end at once.
        if let Some(s) = lock(&self.0.current).take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        let rest: Vec<Job> = lock(&self.0.queue).drain(..).collect();
        for mut j in rest {
            refuse(&mut j.stream, CLOSED, 4);
        }
    }
}

impl Worker {
    fn run(self, shared: Arc<Shared>) {
        let _exit = WorkerExit(shared.clone());
        loop {
            let job = {
                let mut queue = lock(&shared.queue);
                loop {
                    if shared.stopping.load(Ordering::SeqCst) {
                        break None;
                    }
                    if let Some(j) = queue.pop_front() {
                        break Some(j);
                    }
                    queue = shared
                        .wake
                        .wait_timeout(queue, Duration::from_millis(200))
                        .map(|(q, _)| q)
                        .unwrap_or_else(|p| p.into_inner().0);
                }
            };
            let Some(mut job) = job else { break };
            *lock(&shared.current) = job.stream.try_clone().ok();
            self.serve(&shared, &mut job);
            *lock(&shared.current) = None;
            drop(job.reader);
        }
    }

    fn serve(&self, shared: &Arc<Shared>, job: &mut Job) {
        let req = &job.req;
        if req.version != wire::VERSION {
            let msg = format!(
                "the sparrow CLI (v{}) and the app (v{}) are different versions; update the CLI or the app",
                req.version,
                wire::VERSION
            );
            return refuse(&mut job.stream, &msg, 4);
        }
        let args: Vec<OsString> = std::iter::once(OsString::from("sparrow"))
            .chain(req.args.iter().map(OsString::from))
            .collect();
        let seen = sparrow_cli::inspect(&args);
        let env: BTreeMap<String, String> = req
            .env
            .iter()
            .filter(|(k, _)| k.starts_with("SPARROW_"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut env = env;
        wire::absolutize_env(&mut env, &req.cwd);
        let agent = seen
            .agent
            .clone()
            .or_else(|| env.get("SPARROW_AGENT").cloned())
            .filter(|a| !a.trim().is_empty());
        let activity = |running: bool| {
            json!({
                "agent": agent,
                "command": seen.command,
                "at": Utc::now().to_rfc3339(),
                "running": running,
            })
        };
        match &seen.kind {
            Kind::Local => {
                return refuse(
                    &mut job.stream,
                    "this command opens no case; run it with --no-bridge",
                    1,
                );
            }
            Kind::Heavy => {
                return refuse(
                    &mut job.stream,
                    "this command holds the case for minutes and cannot run through the app's agent bridge; \
                     run it from the app, or with the case closed in the app",
                    4,
                );
            }
            // Tenant settings are signed as an analyst (`analyst:<name>`), not as an agent: through the bridge they
            // would carry the app's analyst's name on an agent's decision.
            Kind::Write("tenant") => {
                return refuse(
                    &mut job.stream,
                    "a tenant domain setting is the analyst's decision, not an agent's: make it in the app, or with \
                     the case closed in the app (sparrow tenant domains ... --analyst NAME)",
                    4,
                );
            }
            Kind::Read | Kind::Write(_) => {}
        }
        if let Err(msg) = self.check_case(&seen, &req.cwd) {
            return refuse(&mut job.stream, &msg, 4);
        }
        let state = self.host.state();
        if state.importing.load(Ordering::SeqCst) || state.ticket() != self.ticket {
            return refuse(&mut job.stream, CLOSED, 4);
        }
        let Ok(out_half) = job.stream.try_clone() else {
            return;
        };
        let Ok(err_half) = job.stream.try_clone() else {
            return;
        };
        let io = CliIo::new(
            Box::new(LineWriter::new(FrameWriter::new(out_half, OUT))),
            Box::new(LineWriter::new(FrameWriter::new(err_half, ERR))),
            req.out_is_terminal,
        );
        self.host.emit("agent-activity", activity(true));
        let code = match seen.kind {
            Kind::Write(changes) => {
                let code = self.write(shared, state, io, args, env, &seen, job);
                if code == Some(0) {
                    self.host
                        .emit("case-changed", json!({ "kinds": [changes] }));
                }
                code
            }
            _ => self.read(shared, io, args, env, job),
        };
        self.host.emit("agent-activity", activity(false));
        if let Some(code) = code {
            let _ = wire::write_frame(&mut job.stream, EXIT, &[code]);
        }
    }

    /// The request names the case the app has open (relative to the CLI's directory).
    fn check_case(&self, seen: &Inspected, cwd: &Path) -> Result<(), String> {
        let Some(case) = &seen.case else {
            return Err("this command names no --case".into());
        };
        let case = if case.is_absolute() {
            case.clone()
        } else {
            cwd.join(case)
        };
        match std::fs::canonicalize(&case) {
            Ok(c) if c == self.case => Ok(()),
            _ => Err(format!(
                "the app has another case open ({}); run with --no-bridge for {}",
                self.case.display(),
                case.display()
            )),
        }
    }

    /// Run a read on clones of the bridge's own connection, outside the app's lock, within the time limit. `None`
    /// when the exit frame was already sent.
    fn read(
        &self,
        shared: &Arc<Shared>,
        mut io: CliIo,
        args: Vec<OsString>,
        env: BTreeMap<String, String>,
        job: &mut Job,
    ) -> Option<u8> {
        // The CLI's own environment decides, as for every SPARROW_* variable of the request.
        let limit = env
            .get("SPARROW_BRIDGE_TIMEOUT")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(|s| Duration::from_secs(s).min(MAX_TIMEOUT))
            .unwrap_or(DEFAULT_TIMEOUT);
        io.env = Some(env);
        let base = match self.read_base.shared_view(true) {
            Ok(b) => b,
            Err(e) => {
                refuse(&mut job.stream, &e.to_string(), 1);
                return None;
            }
        };
        let source = Rc::new(ViewSource {
            base,
            write_ok: false,
            reading: Some(shared.clone()),
        });
        // The handles are registered by `ViewSource` as it opens connections; the watchdog interrupts them at the
        // limit or when the bridge stops.
        let timed_out = AtomicBool::new(false);
        let code = guarded_run(shared, limit, &timed_out, || {
            sparrow_cli::run(args, io, source)
        })
        .unwrap_or_else(|| {
            let _ = wire::write_frame(&mut job.stream, ERR, PANIC_MESSAGE.as_bytes());
            PANICKED
        });
        lock(&shared.reading).clear();
        if shared.stopping.load(Ordering::SeqCst) {
            refuse(&mut job.stream, CLOSED, 4);
            return None;
        }
        if timed_out.load(Ordering::SeqCst) {
            let _ = wire::write_frame(
                &mut job.stream,
                ERR,
                format!(
                    "error: the app's agent bridge stopped this read at its time limit ({} s; set \
                     SPARROW_BRIDGE_TIMEOUT to change it)\n",
                    limit.as_secs()
                )
                .as_bytes(),
            );
            return Some(if code == 0 { 1 } else { code });
        }
        Some(code)
    }

    /// Run a write under the app's case lock, signed on behalf of the app's analyst. `None` when the exit frame was
    /// already sent.
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        shared: &Shared,
        state: &AppState,
        mut io: CliIo,
        mut args: Vec<OsString>,
        mut env: BTreeMap<String, String>,
        seen: &Inspected,
        job: &mut Job,
    ) -> Option<u8> {
        let started = Instant::now();
        let slot = loop {
            // A close waiting for the lock (or holding it) is stopping the bridge: give way at once.
            if shared.stopping.load(Ordering::SeqCst) {
                refuse(&mut job.stream, CLOSED, 4);
                return None;
            }
            match state.open.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if started.elapsed() >= WRITE_WAIT {
                        refuse(
                            &mut job.stream,
                            "the app is busy (a long query or an import); try again",
                            4,
                        );
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        };
        if state.importing.load(Ordering::SeqCst) || state.ticket() != self.ticket {
            refuse(&mut job.stream, CLOSED, 4);
            return None;
        }
        let Some(open) = slot.as_ref() else {
            refuse(&mut job.stream, CLOSED, 4);
            return None;
        };
        if let Some(reason) = &open.read_only_reason {
            refuse(
                &mut job.stream,
                &format!("the case is read-only: {reason}"),
                4,
            );
            return None;
        }
        let analyst = match state::analyst(state) {
            Ok(a) => a,
            Err(e) => {
                refuse(&mut job.stream, &e.message, 5);
                return None;
            }
        };
        let name = analyst
            .as_str()
            .strip_prefix("analyst:")
            .map(str::to_string)
            .unwrap_or_default();
        let given = seen
            .analyst
            .clone()
            .or_else(|| env.get("SPARROW_ANALYST").cloned())
            .filter(|a| !a.trim().is_empty());
        if let Some(g) = given.filter(|g| g.trim() != name) {
            let _ = writeln!(
                io.err,
                "note: signed on behalf of the app's analyst {name} (not {g}): the agent works in their session"
            );
        }
        strip_analyst(&mut args);
        env.insert("SPARROW_ANALYST".into(), name);
        let base = match open.case.shared_view(false) {
            Ok(b) => b,
            Err(e) => {
                refuse(&mut job.stream, &e.to_string(), 1);
                return None;
            }
        };
        io.env = Some(env);
        let source = Rc::new(ViewSource {
            base,
            write_ok: true,
            reading: None,
        });
        // A command that panics must not take the worker down with the app's case lock held.
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sparrow_cli::run(args, io, source)
        }));
        drop(slot);
        Some(code.unwrap_or_else(|_| {
            let _ = wire::write_frame(&mut job.stream, ERR, PANIC_MESSAGE.as_bytes());
            PANICKED
        }))
    }
}

/// The exit code of a command that panicked in the bridge.
const PANICKED: u8 = 1;
const PANIC_MESSAGE: &str =
    "error: the command failed inside the app (an internal error); the app is unaffected\n";

/// Run `f` (a read) with a watchdog that interrupts its connections at `limit` or when the bridge stops. A panic in
/// `f` is caught (`None`) and the watchdog always ends with it: a drop guard says `f` is done on every
/// path, so the worker is never left waiting on a scope that cannot close.
fn guarded_run(
    shared: &Shared,
    limit: Duration,
    timed_out: &AtomicBool,
    f: impl FnOnce() -> u8,
) -> Option<u8> {
    struct Done<'a>(&'a AtomicBool);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| {
            let deadline = Instant::now().checked_add(limit);
            while !done.load(Ordering::SeqCst) {
                if shared.stopping.load(Ordering::SeqCst) {
                    shared.interrupt_reads();
                } else if deadline.is_some_and(|d| Instant::now() >= d) {
                    timed_out.store(true, Ordering::SeqCst);
                    shared.interrupt_reads();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let _done = Done(&done);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).ok()
    })
}

/// Remove `--analyst X` and `--analyst=X` (the app's analyst signs instead).
fn strip_analyst(args: &mut Vec<OsString>) {
    let mut out = Vec::with_capacity(args.len());
    let mut it = std::mem::take(args).into_iter();
    while let Some(a) = it.next() {
        if a == "--analyst" {
            it.next();
            continue;
        }
        if a.to_str().is_some_and(|s| s.starts_with("--analyst=")) {
            continue;
        }
        out.push(a);
    }
    *args = out;
}

/// Hands out connections cloned from `base`: read views always, write views only for a write request.
struct ViewSource {
    base: Case,
    write_ok: bool,
    /// Where a read registers the interrupt handle of each connection it opens.
    reading: Option<Arc<Shared>>,
}

impl CaseSource for ViewSource {
    fn read(&self, _path: &Path) -> anyhow::Result<Case> {
        let c = self.base.shared_view(true)?;
        if let Some(s) = &self.reading {
            lock(&s.reading).push(c.conn().interrupt_handle());
        }
        Ok(c)
    }

    fn write(&self, _path: &Path) -> anyhow::Result<Case> {
        if !self.write_ok {
            anyhow::bail!("internal: a read request asked for a write through the agent bridge");
        }
        Ok(self.base.shared_view(false)?)
    }

    fn heavy_allowed(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_read_answers_and_frees_the_worker() {
        let shared = Shared::new();
        let timed_out = AtomicBool::new(false);
        let started = Instant::now();
        let code = guarded_run(&shared, Duration::from_secs(60), &timed_out, || -> u8 {
            panic!("a command bug")
        });
        assert_eq!(code, None);
        let fine = guarded_run(&shared, Duration::from_secs(60), &timed_out, || 1);
        assert_eq!(fine, Some(1), "an ordinary exit 1 is not a panic");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the watchdog ended with the command"
        );
        assert!(!timed_out.load(Ordering::SeqCst));
    }
}
