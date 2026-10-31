//! The agent bridge's wire format and discovery file, shared by the app (which serves) and the CLI (which asks).
//!
//! While a case is open, the app listens on `127.0.0.1` and writes `bridge.json` ([`Discovery`]) in the per-user
//! local data directory. A request is one connection: the session token (hex) on the first line, then the
//! [`Request`] as one JSON line. The app answers with frames — a kind byte, a big-endian `u32` length and the
//! bytes: stdout ([`OUT`]) and stderr ([`ERR`]) as the command prints them, and finally the exit code ([`EXIT`],
//! one byte). A wrong token is closed without an answer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

/// The discovery file's name inside [`discovery_dir`].
pub const DISCOVERY_FILE: &str = "bridge.json";
/// Bytes of a session token (sent as hex).
pub const TOKEN_BYTES: usize = 32;
/// The longest token line and request line the app reads.
pub const MAX_TOKEN_LINE: usize = 2 * TOKEN_BYTES + 2;
pub const MAX_REQUEST_LINE: usize = 1 << 20;

/// Frame kinds.
pub const OUT: u8 = 1;
pub const ERR: u8 = 2;
pub const EXIT: u8 = 3;

/// The version both sides must share: the CLI and the app come from one build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What the app writes when it opens a case: where to reach it and how to prove you may.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Discovery {
    pub port: u16,
    pub token: String,
    /// The open case, canonicalised.
    pub case: PathBuf,
    pub pid: u32,
    pub version: String,
    pub started: DateTime<Utc>,
}

/// One command line to run in the app.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    pub version: String,
    /// The arguments after the program name, as UTF-8.
    pub args: Vec<String>,
    /// The CLI's working directory (relative paths in `args` were already made absolute against it).
    pub cwd: PathBuf,
    /// The CLI's `SPARROW_*` environment variables.
    pub env: BTreeMap<String, String>,
    pub out_is_terminal: bool,
}

/// The directory of the discovery file: `$SPARROW_BRIDGE_DIR` when set (macOS and Linux), else `Sparrow/` in the per-user local data
/// directory (`~/Library/Application Support` on macOS, `$XDG_DATA_HOME` or `~/.local/share` on Linux,
/// `%LOCALAPPDATA%` on Windows).
pub fn discovery_dir() -> Option<PathBuf> {
    // On Windows only the profile's own directory is trusted to keep the token private (no ACL is set here).
    if cfg!(unix) {
        if let Some(d) = std::env::var_os("SPARROW_BRIDGE_DIR").filter(|d| !d.is_empty()) {
            return Some(PathBuf::from(d));
        }
    }
    dirs::data_local_dir().map(|d| d.join("Sparrow"))
}

/// Write `d` as `dir/bridge.json`, readable by this user only (0600 in a 0700 directory on Unix; on Windows the
/// per-user profile directory already is), replacing any previous file in one rename.
pub fn write_discovery(dir: &Path, d: &Discovery) -> io::Result<()> {
    create_private_dir(dir)?;
    let tmp = dir.join(format!(".{DISCOVERY_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = private_file(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(d).map_err(io::Error::other)?)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(DISCOVERY_FILE)).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// The discovery file in `dir`, when there is a readable one.
pub fn read_discovery(dir: &Path) -> Option<Discovery> {
    let bytes = std::fs::read(dir.join(DISCOVERY_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Delete `dir/bridge.json` when it is the one with `token` (another app may have replaced it since).
pub fn remove_discovery(dir: &Path, token: &str) {
    if read_discovery(dir).is_some_and(|d| d.token == token) {
        let _ = std::fs::remove_file(dir.join(DISCOVERY_FILE));
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    // A directory made earlier with wider permissions is left as it is; the token file itself is 0600 either way.
    if !dir.is_dir() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn private_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// The path variables (`SPARROW_DATA`, the `SPARROW_RULES` list) of `env` made absolute against `cwd`, the CLI's
/// directory: the app resolves them in its own.
pub fn absolutize_env(env: &mut BTreeMap<String, String>, cwd: &Path) {
    let abs = |p: PathBuf| if p.is_absolute() { p } else { cwd.join(p) };
    if let Some(d) = env.get_mut("SPARROW_DATA").filter(|d| !d.is_empty()) {
        *d = abs(PathBuf::from(&*d)).display().to_string();
    }
    if let Some(r) = env.get_mut("SPARROW_RULES").filter(|r| !r.is_empty()) {
        let joined = std::env::join_paths(std::env::split_paths(&*r).map(abs));
        if let Some(j) = joined.ok().and_then(|j| j.into_string().ok()) {
            *r = j;
        }
    }
}

/// Compare two tokens in time that does not depend on where they differ.
pub fn token_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Write one frame.
pub fn write_frame(w: &mut dyn Write, kind: u8, bytes: &[u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&len.to_be_bytes());
    w.write_all(&head)?;
    w.write_all(bytes)?;
    w.flush()
}

/// The largest frame a client accepts.
pub const MAX_FRAME: u32 = 64 << 20;

/// Read one frame; `None` at a clean end of stream.
pub fn read_frame(r: &mut dyn Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head[..1]) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    r.read_exact(&mut head[1..])?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bridge frame too large",
        ));
    }
    let mut bytes = vec![0; len as usize];
    r.read_exact(&mut bytes)?;
    Ok(Some((head[0], bytes)))
}

/// A `Write` that sends everything written to it as frames of one kind. After one failed send every later write
/// fails at once (a CLI that went away, or stopped reading until the send timed out, is not waited for again).
pub struct FrameWriter<W: Write> {
    inner: W,
    kind: u8,
    failed: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(inner: W, kind: u8) -> FrameWriter<W> {
        FrameWriter {
            inner,
            kind,
            failed: false,
        }
    }
}

impl<W: Write> Write for FrameWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if !buf.is_empty() {
            write_frame(&mut self.inner, self.kind, buf).inspect_err(|_| self.failed = true)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Read one `\n`-terminated line of at most `max` bytes (without the newline); `None` when the line is longer or
/// the stream ends first.
pub fn read_line_limited(r: &mut dyn BufRead, max: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.take(max as u64 + 1).read_until(b'\n', &mut buf)?;
    if n == 0 || buf.last() != Some(&b'\n') {
        return Ok(None);
    }
    buf.pop();
    Ok(String::from_utf8(buf).ok())
}

/// Send `req` to the bridge described by `d` and stream its answer into `out` and `err`; the exit code it ends
/// with. An answer that ends without an exit code (the app refused the token, or went away) is an error.
pub fn send(
    d: &Discovery,
    req: &Request,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<u8> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", d.port))?;
    let _ = stream.set_nodelay(true);
    let mut line = d.token.clone().into_bytes();
    line.push(b'\n');
    line.extend(serde_json::to_vec(req).map_err(io::Error::other)?);
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()?;
    let mut r = io::BufReader::new(stream);
    // A failed write of our own output (a closed pipe) is not success, whatever the app answered.
    let mut out_failed = false;
    loop {
        match read_frame(&mut r)? {
            Some((OUT, b)) => {
                if !out_failed && (out.write_all(&b).is_err() || out.flush().is_err()) {
                    out_failed = true;
                }
            }
            Some((ERR, b)) => {
                let _ = err.write_all(&b);
                let _ = err.flush();
            }
            Some((EXIT, b)) => {
                let code = b.first().copied().unwrap_or(1);
                return Ok(if out_failed && code == 0 { 1 } else { code });
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown bridge frame",
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the app closed the connection without an answer",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, OUT, b"hello").unwrap();
        write_frame(&mut buf, EXIT, &[4]).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap(), Some((OUT, b"hello".to_vec())));
        assert_eq!(read_frame(&mut r).unwrap(), Some((EXIT, vec![4])));
        assert_eq!(read_frame(&mut r).unwrap(), None);
    }

    #[test]
    fn a_failed_frame_writer_fails_fast() {
        struct Once(u32);
        impl Write for Once {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                if self.0 == 1 {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(b.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = FrameWriter::new(Once(0), OUT);
        assert!(w.write(b"a").is_err());
        assert!(w.write(b"b").is_err());
        assert_eq!(w.inner.0, 1, "no second send after a failure");
    }

    #[test]
    fn env_paths_are_made_absolute_against_the_cli_directory() {
        let cwd = Path::new("/work/here");
        let rules = std::env::join_paths(["rules-a", "/abs/rules-b"]).unwrap();
        let mut env: BTreeMap<String, String> = [
            ("SPARROW_DATA".to_string(), "data".to_string()),
            ("SPARROW_RULES".to_string(), rules.into_string().unwrap()),
            ("SPARROW_AGENT".to_string(), "claude".to_string()),
        ]
        .into();
        absolutize_env(&mut env, cwd);
        assert_eq!(env["SPARROW_DATA"], cwd.join("data").display().to_string());
        let got: Vec<PathBuf> = std::env::split_paths(&env["SPARROW_RULES"]).collect();
        assert_eq!(
            got,
            vec![cwd.join("rules-a"), PathBuf::from("/abs/rules-b")]
        );
        assert_eq!(env["SPARROW_AGENT"], "claude");
    }

    #[test]
    fn a_failed_local_write_is_not_success() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut r = io::BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            r.read_line(&mut line).unwrap();
            write_frame(&mut s, OUT, b"answer\n").unwrap();
            write_frame(&mut s, EXIT, &[0]).unwrap();
        });
        let d = Discovery {
            port,
            token: "t".into(),
            case: "/c".into(),
            pid: 1,
            version: VERSION.into(),
            started: Utc::now(),
        };
        let req = Request {
            version: VERSION.into(),
            args: vec![],
            cwd: "/".into(),
            env: BTreeMap::new(),
            out_is_terminal: false,
        };
        let code = send(&d, &req, &mut Broken, &mut Vec::new()).unwrap();
        assert_eq!(code, 1);
    }

    #[test]
    fn token_comparison() {
        assert!(token_eq(b"abc", b"abc"));
        assert!(!token_eq(b"abc", b"abd"));
        assert!(!token_eq(b"abc", b"abcd"));
    }

    #[test]
    fn long_lines_are_refused() {
        let mut r = &b"0123456789\n"[..];
        assert_eq!(read_line_limited(&mut r, 4).unwrap(), None);
        let mut r = &b"0123\n"[..];
        assert_eq!(
            read_line_limited(&mut r, 4).unwrap().as_deref(),
            Some("0123")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_discovery_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Sparrow");
        let d = Discovery {
            port: 1,
            token: "t".into(),
            case: "/c".into(),
            pid: 2,
            version: VERSION.into(),
            started: Utc::now(),
        };
        write_discovery(&dir, &d).unwrap();
        let mode = std::fs::metadata(dir.join(DISCOVERY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(read_discovery(&dir), Some(d));
        remove_discovery(&dir, "other");
        assert!(read_discovery(&dir).is_some());
        remove_discovery(&dir, "t");
        assert!(read_discovery(&dir).is_none());
    }
}
