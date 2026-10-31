//! The CLI side of the agent bridge: before opening a case, send the command to the app when the app has that case
//! open, and print what comes back.

use crate::bridge::{self, Discovery, Request, VERSION};
use crate::{Kind, inspect};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Run `args` through the app's bridge when the app (discovery file in `dir`) holds the case they name, streaming
/// the output into `out` and `err`; the exit code, or `None` to run the command here as usual (no app, another
/// case, a stale discovery file, a command that opens no case, `--no-bridge` or `SPARROW_BRIDGE=off`).
pub fn route(
    args: &[OsString],
    dir: Option<&Path>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Option<u8> {
    if args
        .iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--no-bridge")
        || std::env::var("SPARROW_BRIDGE").is_ok_and(|v| v.eq_ignore_ascii_case("off"))
    {
        return None;
    }
    let seen = inspect(args);
    let wants_snapshot = snapshot_requested(args);
    if !matches!(seen.kind, Kind::Read | Kind::Write(_)) {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    let case = std::fs::canonicalize(cwd.join(seen.case.as_ref()?)).ok()?;
    let d = discovery(dir?, err)?;
    if d.case != case || !pid_alive(d.pid) {
        return None;
    }
    if d.version != VERSION {
        let _ = writeln!(
            err,
            "error: the app (v{}) and this sparrow CLI (v{VERSION}) are different versions; update the CLI or the app",
            d.version
        );
        return Some(4);
    }
    let Some(args): Option<Vec<String>> = crate::absolutize_paths(args, &cwd)
        .into_iter()
        .skip(1)
        .map(|a| a.into_string().ok())
        .collect()
    else {
        let _ = writeln!(
            err,
            "error: the app has this case open, and its agent bridge carries UTF-8 arguments only; rename the file or \
             argument, or close the case in the app and run with --no-bridge"
        );
        return Some(1);
    };
    let env: BTreeMap<String, String> = std::env::vars()
        .filter(|(k, _)| k.starts_with("SPARROW_"))
        .collect();
    let req = Request {
        version: VERSION.to_string(),
        args,
        cwd,
        env,
        out_is_terminal: std::io::IsTerminal::is_terminal(&std::io::stdout()),
    };
    match bridge::send(&d, &req, out, err) {
        Ok(code) => Some(code),
        // Nothing listens: the app is gone (its pid reused) or its bridge is (a crash, an import). Run here: when the app
        // really holds the case, the direct open says so and names --snapshot.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            let _ = writeln!(
                err,
                "note: the app's agent bridge on 127.0.0.1:{} refused the connection ({e}); running here instead (an \
                 agent in a sandbox that blocks localhost sees this too: see the sparrow-triage skill)",
                d.port
            );
            None
        }
        // A read that asked for a snapshot reads a copy here instead.
        Err(e) if seen.kind == Kind::Read && wants_snapshot => {
            let _ = writeln!(
                err,
                "note: the app's agent bridge did not answer on 127.0.0.1:{} ({e}); reading a snapshot instead",
                d.port
            );
            None
        }
        Err(e) => {
            let _ = writeln!(err, "error: {}", unreachable(&d, &e, &seen.kind));
            Some(4)
        }
    }
}

/// `--snapshot` on the command line, or `SPARROW_SNAPSHOT=1`.
fn snapshot_requested(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--snapshot")
        || std::env::var("SPARROW_SNAPSHOT").is_ok_and(|v| v.trim() == "1")
}

/// Why the bridge could not serve, and what to do.
fn unreachable(d: &Discovery, e: &std::io::Error, kind: &Kind) -> String {
    let reads = if *kind == Kind::Read {
        " For a read, pass --snapshot to read a copy of the case instead."
    } else {
        " For a write, try again, or close the case in the app."
    };
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        return format!(
            "the app has this case open, but this process may not connect to its agent bridge on 127.0.0.1:{} \
             ({e}): an agent in a sandbox needs network access to localhost (see the sparrow-triage skill).{reads}",
            d.port
        );
    }
    format!(
        "the app's agent bridge on 127.0.0.1:{} gave no answer ({e}): the app may have closed the case, or this \
         CLI's discovery file is stale.{reads}",
        d.port
    )
}

/// The discovery file in `dir`; a directory this process may not read (a sandbox) gets a note.
fn discovery(dir: &Path, err: &mut dyn Write) -> Option<Discovery> {
    let path: PathBuf = dir.join(bridge::DISCOVERY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).ok(),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let _ = writeln!(
                err,
                "note: cannot read {} ({e}), so the app's agent bridge cannot be used: an agent in a sandbox needs \
                 read access to {} (see the sparrow-triage skill)",
                path.display(),
                dir.display()
            );
            None
        }
        Err(_) => None,
    }
}

/// Whether process `pid` still runs (a discovery file left by an app that crashed names a dead one).
#[cfg(unix)]
pub(crate) fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // Signal 0 checks for the process without signalling it; EPERM means it exists under another user.
    // SAFETY: kill with signal 0 has no effect on the target.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// On Windows the connection attempt decides: a dead app's port refuses it.
#[cfg(not(unix))]
pub(crate) fn pid_alive(_pid: u32) -> bool {
    true
}
