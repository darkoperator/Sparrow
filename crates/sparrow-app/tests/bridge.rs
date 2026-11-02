//! The agent bridge without a window: a test host stands in for the Tauri app, requests go over loopback TCP as the
//! CLI sends them.

use serde_json::Value;
use sparrow_app::bridge::{self, BridgeHost};
use sparrow_app::settings::settings_set_analyst;
use sparrow_app::state::{AppState, case_close, case_open, with_case, with_writable};
use sparrow_cli::bridge::{Discovery, Request, VERSION, read_discovery, send};
use sparrow_core::Case;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Host {
    state: AppState,
    events: Mutex<Vec<(String, Value)>>,
    /// An event whose emit panics (a host failure outside the command).
    panic_on: Mutex<Option<&'static str>>,
}

impl BridgeHost for Host {
    fn state(&self) -> &AppState {
        &self.state
    }
    fn emit(&self, event: &str, payload: Value) {
        if *self.panic_on.lock().unwrap() == Some(event) {
            panic!("emit {event} failed");
        }
        self.events
            .lock()
            .unwrap()
            .push((event.to_string(), payload));
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    host: Arc<Host>,
    case: PathBuf,
    dir: PathBuf,
}

impl Fixture {
    fn discovery(&self) -> Discovery {
        read_discovery(&self.dir).expect("the open case has a discovery file")
    }

    fn state(&self) -> &AppState {
        &self.host.state
    }

    fn case_arg(&self) -> String {
        self.case.display().to_string()
    }

    fn ask(&self, args: &[&str]) -> (u8, String, String) {
        self.ask_with(args, BTreeMap::new())
    }

    fn ask_with(&self, args: &[&str], env: BTreeMap<String, String>) -> (u8, String, String) {
        ask(&self.discovery(), args, env)
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.host
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

fn request(args: &[&str], env: BTreeMap<String, String>) -> Request {
    Request {
        version: VERSION.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        cwd: std::env::temp_dir(),
        env,
        out_is_terminal: false,
    }
}

fn ask(d: &Discovery, args: &[&str], env: BTreeMap<String, String>) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = send(d, &request(args, env), &mut out, &mut err).expect("an answer");
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

/// A small synthetic case: two accounts' events.
fn build(path: &Path) {
    let case = Case::create_or_open(path).unwrap();
    let c = case.conn();
    for (key, at, actor, ip) in [
        (
            "u1",
            "2026-09-01 10:00:00",
            "jdoe@contoso.example",
            "203.0.113.45",
        ),
        (
            "u2",
            "2026-09-01 10:05:00",
            "jdoe@contoso.example",
            "203.0.113.45",
        ),
        (
            "x1",
            "2026-09-01 11:00:00",
            "other@contoso.example",
            "192.0.2.9",
        ),
    ] {
        c.execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, tenant_key, actor_upn, \
             operation, ip) VALUES ('ual_events', ?, 'ual', CAST(? AS TIMESTAMPTZ), 'other', 'contoso', ?, 'Send', ?)",
            duckdb::params![key, format!("{at}+00"), actor, ip],
        )
        .unwrap();
    }
}

fn fixture(analyst: Option<&str>) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let case = tmp.path().join("case.duckdb");
    build(&case);
    let settings = tmp.path().join("settings");
    std::fs::create_dir_all(&settings).unwrap();
    let dir = tmp.path().join("bridge");
    let host = Arc::new(Host {
        state: AppState::default(),
        events: Mutex::new(Vec::new()),
        panic_on: Mutex::new(None),
    });
    *host.state.settings_dir.lock().unwrap() = Some(settings);
    if let Some(a) = analyst {
        settings_set_analyst(&host.state, a).unwrap();
    }
    bridge::enable(&host.state, host.clone(), dir.clone());
    case_open(&host.state, &case, false).unwrap();
    Fixture {
        _tmp: tmp,
        host,
        case,
        dir,
    }
}

fn tags(f: &Fixture) -> Vec<(String, String, Option<String>, String)> {
    with_case(f.state(), f.state().ticket(), |open| {
        let mut stmt = open
            .case
            .conn()
            .prepare(
                "SELECT t.name, e.decided_by, e.on_behalf_of, CAST(e.review_state AS VARCHAR) \
                 FROM event_tags e JOIN tags t USING (tag_id) ORDER BY t.name",
            )
            .unwrap();
        Ok(stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap())
    })
    .unwrap()
}

#[test]
fn a_bridge_read_matches_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("direct.duckdb");
    build(&path);
    let direct = sparrow_cli::SharedBuf::default();
    let code = sparrow_cli::run(
        [
            "sparrow",
            "events",
            "--case",
            path.to_str().unwrap(),
            "--json",
        ]
        .map(Into::into)
        .to_vec(),
        sparrow_cli::CliIo::new(Box::new(direct.clone()), Box::new(std::io::sink()), false),
        std::rc::Rc::new(sparrow_cli::FileSource),
    );
    assert_eq!(code, 0);

    let f = fixture(Some("Carol"));
    let (code, out, err) = f.ask(&["events", "--case", &f.case_arg(), "--json"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, direct.text());
    // Lit while it runs, then the last request.
    let activity = f.events("agent-activity");
    assert_eq!(activity.len(), 2);
    assert_eq!(activity[0]["running"], true);
    assert_eq!(activity[1]["running"], false);
    assert_eq!(activity[1]["command"], "events");
    assert!(
        f.events("case-changed").is_empty(),
        "a read changes nothing"
    );
}

#[test]
fn a_wrong_token_is_refused() {
    let f = fixture(Some("Carol"));
    let mut d = f.discovery();
    d.token = "00".repeat(32);
    let row = "ual_events:u1";
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = send(
        &d,
        &request(
            &[
                "mark",
                "tag",
                "--case",
                &f.case_arg(),
                "--row",
                row,
                "--tag",
                "ai:x",
            ],
            BTreeMap::new(),
        ),
        &mut out,
        &mut err,
    );
    assert!(r.is_err(), "no answer for a wrong token");
    assert!(out.is_empty() && err.is_empty());
    // A missing token line (the request JSON first) gets nothing either.
    let mut s = std::net::TcpStream::connect(("127.0.0.1", d.port)).unwrap();
    s.write_all(b"{\"args\":[]}\n").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    assert!(got.is_empty());
    assert!(tags(&f).is_empty(), "nothing was written");
}

#[test]
fn a_bridge_write_is_pending_and_signed_by_the_app_analyst() {
    let f = fixture(Some("Carol"));
    let (code, _, err) = f.ask(&[
        "mark",
        "tag",
        "--case",
        &f.case_arg(),
        "--row",
        "ual_events:u1",
        "--tag",
        "ai:test",
        "--agent",
        "claude",
        "--analyst",
        "Mallory",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("Carol"),
        "the replaced analyst is noted: {err}"
    );
    assert_eq!(
        tags(&f),
        vec![(
            "ai:test".to_string(),
            "agent:claude".to_string(),
            Some("analyst:Carol".to_string()),
            "pending_review".to_string()
        )]
    );
    let changed = f.events("case-changed");
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["kinds"], serde_json::json!(["marks"]));
    let activity = f.events("agent-activity");
    assert_eq!(activity.last().unwrap()["agent"], "claude");
}

#[test]
fn no_analyst_refuses_writes() {
    let f = fixture(None);
    let (code, _, err) = f.ask(&[
        "mark",
        "tag",
        "--case",
        &f.case_arg(),
        "--row",
        "ual_events:u1",
        "--tag",
        "ai:test",
    ]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("set the analyst name"), "{err}");
    assert!(tags(&f).is_empty());
    // Reads need no analyst.
    let (code, _, err) = f.ask(&["events", "--case", &f.case_arg()]);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn reads_run_on_a_second_connection_while_the_app_writes() {
    let f = fixture(Some("Carol"));
    let count_sql = "SELECT count(*) AS n FROM events";
    // The app holds its case lock for a while (a long screen query, or a write): a bridge read does not wait for it.
    std::thread::scope(|s| {
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let state = f.state();
        s.spawn(move || {
            with_writable(state, state.ticket(), |open| {
                held_tx.send(()).unwrap();
                // Rows added in batches of 10 inside transactions while the bridge reads.
                for b in 0..20 {
                    let c = open.case.conn();
                    c.execute_batch("BEGIN").unwrap();
                    for i in 0..10 {
                        c.execute(
                            "INSERT INTO events (source_table, record_key, source, event_time, category, actor_upn) \
                             VALUES ('ual_events', ?, 'ual', TIMESTAMPTZ '2026-09-02 00:00:00+00', 'other', 'w@x')",
                            [format!("w{b}-{i}")],
                        )
                        .unwrap();
                    }
                    c.execute_batch("COMMIT").unwrap();
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(())
            })
            .unwrap();
        });
        held_rx.recv().unwrap();
        let started = Instant::now();
        let mut seen = Vec::new();
        for _ in 0..5 {
            let (code, out, err) = f.ask(&["query", "--case", &f.case_arg(), count_sql, "--json"]);
            assert_eq!(code, 0, "{err}");
            let v: Value = serde_json::from_str(&out).unwrap();
            let n = v["rows"][0][0].as_i64().unwrap_or_else(|| panic!("{v}"));
            // Never half a batch: the read sees whole transactions only.
            assert_eq!((n - 3) % 10, 0, "torn read: {n}");
            seen.push(n);
        }
        assert!(
            started.elapsed() < Duration::from_millis(400) || seen.windows(2).any(|w| w[0] != w[1]),
            "the reads ran while the app held its lock"
        );
    });
    // Temp tables stay per connection: the app's are invisible to the bridge's reads.
    with_case(f.state(), f.state().ticket(), |open| {
        open.case
            .conn()
            .execute_batch("CREATE TEMP TABLE app_only AS SELECT 1 AS x")
            .unwrap();
        Ok(())
    })
    .unwrap();
    let (code, _, err) = f.ask(&["query", "--case", &f.case_arg(), "SELECT x FROM app_only"]);
    assert_ne!(code, 0);
    assert!(err.contains("app_only"), "{err}");
}

/// A read that runs until it is stopped.
const LONG_SQL: &str =
    "SELECT count(*) FROM range(10000000000) a(i), range(1000) b(j) WHERE a.i * b.j = -1";

#[test]
fn a_long_read_stops_at_the_time_limit() {
    let f = fixture(Some("Carol"));
    let started = Instant::now();
    let (code, _, err) = f.ask_with(
        &["query", "--case", &f.case_arg(), LONG_SQL],
        [("SPARROW_BRIDGE_TIMEOUT".to_string(), "1".to_string())].into(),
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_ne!(code, 0);
    assert!(err.contains("time limit"), "{err}");
    // The bridge serves the next request.
    let (code, _, err) = f.ask(&["events", "--case", &f.case_arg()]);
    assert_eq!(code, 0, "{err}");
}

#[test]
fn closing_the_case_interrupts_the_request_and_removes_the_discovery_file() {
    let f = fixture(Some("Carol"));
    let d = f.discovery();
    let case = f.case_arg();
    let asked =
        std::thread::spawn(move || ask(&d, &["query", "--case", &case, LONG_SQL], BTreeMap::new()));
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    case_close(f.state()).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the close was held up"
    );
    let (code, _, err) = asked.join().unwrap();
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("closed the case"), "{err}");
    assert!(read_discovery(&f.dir).is_none());
    let port = f.discovery_port_after_close();
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    // The file can be opened again at once (the bridge's connection is gone).
    case_open(f.state(), &f.case, false).unwrap();
    assert!(read_discovery(&f.dir).is_some());
}

impl Fixture {
    fn discovery_port_after_close(&self) -> u16 {
        self.host.state.bridge.last_port().expect("the bridge ran")
    }
}

#[test]
fn heavy_commands_are_refused() {
    let f = fixture(Some("Carol"));
    for args in [
        vec!["profile", "--case", f.case.to_str().unwrap()],
        vec!["detect", "--case", f.case.to_str().unwrap()],
        vec!["upgrade", "--case", f.case.to_str().unwrap()],
    ] {
        let (code, _, err) = f.ask(&args);
        assert_eq!(code, 4, "{args:?}: {err}");
        assert!(
            err.contains("run it from the app, or with the case closed in the app"),
            "{err}"
        );
    }
}

#[test]
fn another_case_is_refused() {
    let f = fixture(Some("Carol"));
    let other = f._tmp.path().join("other.duckdb");
    build(&other);
    let (code, _, err) = f.ask(&["events", "--case", other.to_str().unwrap()]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("has another case open"), "{err}");
}

#[test]
fn requests_run_one_at_a_time() {
    let f = fixture(Some("Carol"));
    let d = f.discovery();
    let case = f.case_arg();
    let long = std::thread::spawn({
        let (d, case) = (d.clone(), case.clone());
        move || {
            let r = ask(
                &d,
                &["query", "--case", &case, LONG_SQL],
                [("SPARROW_BRIDGE_TIMEOUT".to_string(), "2".to_string())].into(),
            );
            (r, Instant::now())
        }
    });
    std::thread::sleep(Duration::from_millis(300));
    let (r, quick_done) = (
        ask(&d, &["events", "--case", &case], BTreeMap::new()),
        Instant::now(),
    );
    assert_eq!(r.0, 0, "{}", r.2);
    let (_, long_done) = long.join().unwrap();
    assert!(
        quick_done >= long_done,
        "the second request waited for the first"
    );
}

#[test]
fn output_far_larger_than_the_socket_buffers_arrives_whole() {
    let f = fixture(Some("Carol"));
    let case = f.case_arg();
    let sql = "SELECT repeat('x', 100000) AS big FROM range(200)";
    let (code, out, err) = f.ask(&["query", "--case", &case, sql, "--limit", "200", "--json"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.matches('x').count(), 200 * 100_000);
}

#[test]
fn a_client_that_stops_reading_does_not_hold_up_the_close() {
    let f = fixture(Some("Carol"));
    let d = f.discovery();
    // Megabytes of output to a CLI that never reads: the bridge's send blocks on a full socket.
    let sql = "SELECT repeat('x', 100000) AS big FROM range(200)";
    let req = request(
        &[
            "query",
            "--case",
            &f.case_arg(),
            sql,
            "--limit",
            "200",
            "--json",
        ],
        BTreeMap::new(),
    );
    let mut s = std::net::TcpStream::connect(("127.0.0.1", d.port)).unwrap();
    let mut line = format!("{}\n", d.token).into_bytes();
    line.extend(serde_json::to_vec(&req).unwrap());
    line.push(b'\n');
    s.write_all(&line).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let started = Instant::now();
    case_close(f.state()).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the close waited {:?} for a client that does not read",
        started.elapsed()
    );
    drop(s);
}

#[test]
fn a_huge_time_limit_is_bounded() {
    let f = fixture(Some("Carol"));
    let huge = [("SPARROW_BRIDGE_TIMEOUT".to_string(), u64::MAX.to_string())].into();
    let (code, _, err) = f.ask_with(&["events", "--case", &f.case_arg()], huge);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = f.ask(&["events", "--case", &f.case_arg()]);
    assert_eq!(code, 0, "the bridge still serves: {err}");
}

#[test]
fn mark_flag_through_the_bridge_lands_pending() {
    let f = fixture(Some("Carol"));
    let args: Vec<std::ffi::OsString> = [
        "sparrow",
        "mark",
        "flag",
        "--case",
        &f.case_arg(),
        "--row",
        "ual_events:u2",
        "--level",
        "malicious",
        "--agent",
        "claude",
    ]
    .iter()
    .map(Into::into)
    .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    // The CLI's own routing: the app holds the case, so the command goes through the bridge.
    let code = sparrow_cli::bridge_client::route(&args, Some(&f.dir), &mut out, &mut err);
    assert_eq!(code, Some(0), "{}", String::from_utf8_lossy(&err));
    let flags: Vec<(String, String, String)> = with_case(f.state(), f.state().ticket(), |open| {
        let mut stmt = open
            .case
            .conn()
            .prepare(
                "SELECT record_key, decided_by, CAST(review_state AS VARCHAR) FROM event_flags ORDER BY record_key",
            )
            .unwrap();
        Ok(stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap())
    })
    .unwrap();
    assert_eq!(
        flags,
        vec![(
            "u2".to_string(),
            "agent:claude".to_string(),
            "pending_review".to_string()
        )]
    );
    assert_eq!(f.events("case-changed").len(), 1);
}

/// A real case through the bridge, the way an agent uses it: `SPARROW_BRIDGE_REAL_CASE` names a SCRATCH COPY (the
/// test writes an `ai:` tag into it). Prints timings and counts only.
#[test]
#[ignore = "needs SPARROW_BRIDGE_REAL_CASE (a scratch copy of a real case)"]
fn a_real_case_through_the_bridge() {
    let Some(case) = std::env::var_os("SPARROW_BRIDGE_REAL_CASE").map(PathBuf::from) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let settings = tmp.path().join("settings");
    std::fs::create_dir_all(&settings).unwrap();
    let dir = tmp.path().join("bridge");
    let host = Arc::new(Host {
        state: AppState::default(),
        events: Mutex::new(Vec::new()),
        panic_on: Mutex::new(None),
    });
    *host.state.settings_dir.lock().unwrap() = Some(settings);
    settings_set_analyst(&host.state, "Carol").unwrap();
    bridge::enable(&host.state, host.clone(), dir.clone());
    case_open(&host.state, &case, false).unwrap();
    let f = Fixture {
        _tmp: tmp,
        host,
        case,
        dir,
    };
    let c = f.case_arg();
    let timed = |args: &[&str]| {
        let t = Instant::now();
        let (code, out, err) = f.ask(args);
        eprintln!(
            "{:<40} exit {code}  {:>7.2?}  {} bytes",
            args[0..2].join(" "),
            t.elapsed(),
            out.len()
        );
        assert_eq!(code, 0, "{args:?}: {err}");
        out
    };
    timed(&["summary", "--case", &c, "--json"]);
    timed(&["accounts", "--case", &c, "--json"]);
    timed(&["access", "--case", &c, "--json"]);
    // The analyst keeps reading on the app's own connection while a bridge read runs.
    std::thread::scope(|s| {
        s.spawn(|| timed(&["events", "--case", &c, "--json", "--limit", "500"]));
        let t = Instant::now();
        with_case(f.state(), f.state().ticket(), |open| {
            let n: i64 = open
                .case
                .conn()
                .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
                .unwrap();
            eprintln!("app read meanwhile: {n} events in {:.2?}", t.elapsed());
            Ok(())
        })
        .unwrap();
    });
    let row: String = with_case(f.state(), f.state().ticket(), |open| {
        Ok(open
            .case
            .conn()
            .query_row(
                "SELECT source_table || ':' || record_key FROM events ORDER BY event_time, record_key LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap())
    })
    .unwrap();
    let before = tags(&f).len();
    timed(&[
        "mark",
        "tag",
        "--case",
        &c,
        "--row",
        &row,
        "--tag",
        "ai:bridge-test",
        "--agent",
        "claude",
    ]);
    let after = tags(&f);
    assert_eq!(after.len(), before + 1);
    assert!(
        after
            .iter()
            .any(|t| t.0 == "ai:bridge-test" && t.3 == "pending_review")
    );
    assert_eq!(f.events("case-changed").len(), 1);
}

#[test]
fn a_failing_command_never_wedges_the_bridge() {
    // `--pad 1é` once panicked inside the command: the request must answer and the case still close at once.
    let f = fixture(Some("Carol"));
    let (code, _, _) = f.ask(&[
        "investigate",
        "--case",
        &f.case_arg(),
        "--user",
        "jdoe@contoso.example",
        "--on",
        "2026-09-01",
        "--pad",
        "1é",
    ]);
    assert_ne!(code, 0);
    let (code, _, err) = f.ask(&["events", "--case", &f.case_arg()]);
    assert_eq!(code, 0, "the bridge still serves: {err}");
    let started = Instant::now();
    case_close(f.state()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn tenant_settings_are_refused_through_the_bridge() {
    // `tenant domains add|remove` signs as an analyst, not as an agent: through the bridge it would put the app's
    // analyst's name on the agent's decision.
    let f = fixture(Some("Carol"));
    let audit = || -> i64 {
        with_case(f.state(), f.state().ticket(), |open| {
            Ok(open
                .case
                .conn()
                .query_row("SELECT count(*) FROM audit_trail", [], |r| r.get(0))
                .unwrap())
        })
        .unwrap()
    };
    let before = audit();
    let (code, _, err) = f.ask(&[
        "tenant",
        "domains",
        "add",
        "x.example",
        "--case",
        &f.case_arg(),
    ]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("analyst's decision"), "{err}");
    assert_eq!(audit(), before, "nothing was written");
    // Listing them is a read and still works.
    let (code, _, err) = f.ask(&["tenant", "domains", "list", "--case", &f.case_arg()]);
    assert_ne!(code, 4, "{err}");
}

#[test]
fn an_import_starting_during_a_write_lets_it_answer() {
    use sparrow_app::cmd::ingest::{Emit, IngestState, ingest_profile};
    use sparrow_core::case::audit::test_hooks::{delayed_appends, set_append_delay};
    let f = fixture(Some("Carol"));
    let d = f.discovery();
    // A write still running past the stop's one-second grace when the import claims the case.
    set_append_delay(Some(("agent:slow-writer", 2000)));
    let case = f.case_arg();
    let before = delayed_appends();
    let client = std::thread::spawn(move || {
        let args = [
            "mark",
            "tag",
            "--case",
            &case,
            "--row",
            "ual_events:u2",
            "--tag",
            "ai:slow",
            "--agent",
            "slow-writer",
        ];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let r = send(&d, &request(&args, BTreeMap::new()), &mut out, &mut err);
        (
            r.map_err(|e| e.to_string()),
            String::from_utf8_lossy(&err).into_owned(),
        )
    });
    // The write holds the case lock and is in its slow append before the import claims the case.
    let waited = Instant::now();
    while delayed_appends() == before {
        assert!(
            waited.elapsed() < Duration::from_secs(10),
            "the write never started"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let emit: Emit = Arc::new(|_| {});
    let _ = ingest_profile(f.state(), &IngestState::default(), "slow-1", &emit);
    let (answer, err) = client.join().unwrap();
    set_append_delay(None);
    // The write completed under the case lock, so the agent is told so (a retry would duplicate it).
    assert_eq!(answer, Ok(0), "{err}");
    assert_eq!(
        tags(&f).iter().filter(|t| t.0 == "ai:slow").count(),
        1,
        "the write landed once"
    );
}

#[test]
fn a_worker_that_dies_during_a_write_never_blocks_a_close() {
    let f = fixture(Some("Carol"));
    // The write lands, then the host fails emitting its change: the worker unwinds mid-request.
    *f.host.panic_on.lock().unwrap() = Some("case-changed");
    let d = f.discovery();
    let args = [
        "mark",
        "tag",
        "--case",
        &f.case_arg(),
        "--row",
        "ual_events:u1",
        "--tag",
        "ai:x",
        "--agent",
        "claude",
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let _ = send(&d, &request(&args, BTreeMap::new()), &mut out, &mut err);
    // The bridge is gone: its discovery file goes with it, so a later CLI runs on its own instead of being refused.
    assert!(
        read_discovery(&f.dir).is_none(),
        "the dead bridge's discovery file is removed"
    );
    let host = f.host.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(case_close(&host.state).is_ok()).unwrap());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)),
        Ok(true),
        "the close returns"
    );
}

#[test]
fn quitting_the_app_removes_the_discovery_file() {
    let f = fixture(Some("Carol"));
    assert!(read_discovery(&f.dir).is_some());
    bridge::shutdown(f.state());
    assert!(read_discovery(&f.dir).is_none());
}

#[test]
fn an_agent_notebook_add_through_the_bridge_emits_notebooks() {
    let f = fixture(Some("Carol"));
    let (code, out, err) = f.ask(&[
        "notebook",
        "add",
        "--case",
        &f.case_arg(),
        "--notebook",
        "Triage",
        "--create",
        "--sql",
        "-- T\nSELECT 1",
        "--agent",
        "claude",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("added to Triage"), "{out}");
    let changed = f.events("case-changed");
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["kinds"], serde_json::json!(["notebooks"]));
    let l = sparrow_app::cmd::notebooks::notebook_list(f.state()).unwrap();
    let q = &l[1].queries[0];
    assert_eq!(q.decided_by.as_deref(), Some("agent:claude"));
    assert_eq!(q.on_behalf_of.as_deref(), Some("analyst:Carol"));
}
