//! `--snapshot`: a read-only command on a case another process holds (the app, when its agent bridge cannot serve)
//! reads a private copy of it, taken so it is never torn and deleted afterwards.
//!
//! The WAL is copied first and the database second, and both files' size and modification time are compared before
//! and after: a write or a checkpoint during the copy changes them, and the copy is taken again (3 attempts, then
//! exit 4), and the copied bytes must equal the files after the copy. The copy goes beside the case in a hidden
//! `.sparrow-snapshot-<pid>-<random>/` (same volume: nothing is written to
//! the system disk for a case on an external drive), else in the system temp directory, and is refused when it would
//! leave less than 10% of that volume free.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// How many times a copy is taken before giving up.
pub(crate) const ATTEMPTS: usize = 3;

/// A private copy of a case; the directory goes when it is dropped (or [`Snapshot::remove`]).
pub(crate) struct Snapshot {
    dir: Option<tempfile::TempDir>,
    pub case: PathBuf,
    pub taken_at: DateTime<Utc>,
    /// Copies left by runs that ended without cleaning up (Ctrl-C, a kill), removed before this one was taken.
    pub swept: Vec<PathBuf>,
    /// Snapshot directories beside the case that may be such copies but were not removed, with why.
    pub left: Vec<(PathBuf, String)>,
}

/// The file each snapshot directory holds from the start, naming the process and the case it copies: what proves a
/// leftover directory is a copy of this case before it is removed.
const MARKER: &str = ".sparrow-snapshot.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct Marker {
    pid: u64,
    source: PathBuf,
}

impl Snapshot {
    /// Delete the copy now, saying when it could not be.
    pub(crate) fn remove(mut self) -> std::io::Result<()> {
        match self.dir.take() {
            Some(d) => d.close(),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    fn dir(&self) -> PathBuf {
        self.dir
            .as_ref()
            .map(|d| d.path().to_path_buf())
            .unwrap_or_default()
    }
}

/// What tells a changed file: its size and modification time (`None` for a file that does not exist).
pub(crate) type Stamp = Option<(u64, SystemTime)>;

fn stamp(p: &Path) -> std::io::Result<Stamp> {
    match std::fs::metadata(p) {
        Ok(m) => Ok(Some((m.len(), m.modified()?))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The WAL beside `case`.
fn wal_of(case: &Path) -> PathBuf {
    let mut w = case.as_os_str().to_owned();
    w.push(".wal");
    PathBuf::from(w)
}

/// Whether two files hold the same bytes (a missing one never matches).
fn same_bytes(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::io::Read;
    let open = |p: &Path| match std::fs::File::open(p) {
        Ok(f) => Ok(Some(std::io::BufReader::with_capacity(1 << 20, f))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let (Some(mut fa), Some(mut fb)) = (open(a)?, open(b)?) else {
        return Ok(false);
    };
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let na = read_full(&mut fa, &mut ba)?;
        let nb = read_full(&mut fb, &mut bb)?;
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }

    fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            match r.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
}

/// Take a snapshot of `case`.
pub(crate) fn take(case: &Path) -> Result<Snapshot> {
    take_with(case, &mut |p| stamp(p))
}

/// [`take`] with the file stamps read through `stamp` (tests make the files look as if they changed).
///
/// A copy is accepted when both files' stamps are the same before and after it AND the copied bytes equal the
/// files as they are after the copy (a write that keeps the size within the timestamp's granularity still shows).
/// The source is resolved first, so a symlinked `--case` copies the real file's WAL.
pub(crate) fn take_with(
    case: &Path,
    stamp: &mut dyn FnMut(&Path) -> std::io::Result<Stamp>,
) -> Result<Snapshot> {
    let case =
        std::fs::canonicalize(case).with_context(|| format!("reading {}", case.display()))?;
    let wal = wal_of(&case);
    let size =
        std::fs::metadata(&case)?.len() + std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let name = case
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| "case.duckdb".into());
    let (swept, left) = sweep(&case, &parents(&case), &name);
    let dir = private_dir(&case, size)?;
    let marker = Marker {
        pid: std::process::id().into(),
        source: case.clone(),
    };
    std::fs::write(dir.path().join(MARKER), serde_json::to_vec(&marker)?)
        .with_context(|| format!("writing {}", dir.path().display()))?;
    let mut snap = Snapshot {
        case: dir.path().join(&name),
        dir: Some(dir),
        taken_at: Utc::now(),
        swept,
        left,
    };
    let copy_wal = wal_of(&snap.case);
    for _ in 0..ATTEMPTS {
        let before = (stamp(&wal)?, stamp(&case)?);
        let _ = std::fs::remove_file(&copy_wal);
        snap.taken_at = Utc::now();
        if before.0.is_some() {
            std::fs::copy(&wal, &copy_wal).with_context(|| format!("copying {}", wal.display()))?;
        }
        std::fs::copy(&case, &snap.case).with_context(|| format!("copying {}", case.display()))?;
        let after = (stamp(&wal)?, stamp(&case)?);
        if before != after {
            continue;
        }
        let wal_same = match before.0 {
            Some(_) => same_bytes(&wal, &copy_wal)?,
            None => !wal.exists(),
        };
        if wal_same && same_bytes(&case, &snap.case)? {
            return Ok(snap);
        }
    }
    Err(crate::Refused(format!(
        "the case changed while it was being copied ({ATTEMPTS} attempts): the app is writing to it; try again"
    ))
    .into())
}

/// Where copies of `case` go, in order: beside the case, else the system temp directory.
fn parents(case: &Path) -> Vec<PathBuf> {
    case.parent()
        .map(Path::to_path_buf)
        .into_iter()
        .chain([std::env::temp_dir()])
        .collect()
}

/// Remove the copies of `case` that runs which ended without cleaning up (Ctrl-C, a kill) left in `parents`. A
/// `.sparrow-snapshot-<pid>-<random>` directory is removed only when its marker names `case` and that pid, the pid is a
/// valid process id of a process that has ended, this user owns it and it holds nothing but the marker and a copy of
/// `name` (and its WAL). A run still going and another case's copy are left alone silently; anything else that may be
/// a leftover beside the case is left and reported, never guessed at. Returns (removed, left with why).
fn sweep(case: &Path, parents: &[PathBuf], name: &Path) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let (mut removed, mut left) = (Vec::new(), Vec::new());
    for (n, parent) in parents.iter().enumerate() {
        let beside_the_case = n == 0;
        let Ok(entries) = std::fs::read_dir(parent) else {
            continue;
        };
        for e in entries.flatten() {
            let Some(pid) = e
                .file_name()
                .to_str()
                .and_then(|n| n.strip_prefix(".sparrow-snapshot-"))
                .and_then(|rest| rest.split_once('-'))
                .filter(|(pid, random)| {
                    !random.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
                })
                .and_then(|(pid, _)| pid.parse::<u64>().ok())
            else {
                continue;
            };
            let valid = u32::try_from(pid)
                .ok()
                .filter(|p| *p > 0 && i32::try_from(*p).is_ok());
            if valid.is_some_and(|p| p == std::process::id() || crate::bridge_client::pid_alive(p))
            {
                continue;
            }
            let path = e.path();
            let marker = std::fs::read(path.join(MARKER))
                .ok()
                .and_then(|b| serde_json::from_slice::<Marker>(&b).ok());
            if marker.as_ref().is_some_and(|m| m.source != case) {
                continue;
            }
            match leftover_copy(&e, marker.as_ref(), pid, valid.is_some(), name) {
                Ok(()) => match std::fs::remove_dir_all(&path) {
                    Ok(()) => removed.push(path),
                    Err(err) => left.push((path, format!("could not be removed: {err}"))),
                },
                Err(why) if beside_the_case => left.push((path, why)),
                Err(_) => {}
            }
        }
    }
    (removed, left)
}

/// Whether `e` is provably a leftover copy (see [`sweep`]); else why not.
fn leftover_copy(
    e: &std::fs::DirEntry,
    marker: Option<&Marker>,
    pid: u64,
    valid_pid: bool,
    name: &Path,
) -> std::result::Result<(), String> {
    if marker.is_none_or(|m| m.pid != pid) {
        return Err("it has no snapshot marker for this case".into());
    }
    if !valid_pid {
        return Err(format!("{pid} is not a valid process id"));
    }
    if !e.file_type().is_ok_and(|t| t.is_dir()) {
        return Err("it is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if e.metadata().map_err(|err| err.to_string())?.uid() != me {
            return Err("another user owns it".into());
        }
    }
    let wal = wal_of(name);
    let files = std::fs::read_dir(e.path()).map_err(|err| format!("could not be read: {err}"))?;
    for f in files {
        let f = f.map_err(|err| format!("could not be read: {err}"))?;
        let n = PathBuf::from(f.file_name());
        let expected = n == name || n == wal || n == Path::new(MARKER);
        if !expected || !f.file_type().is_ok_and(|t| t.is_file()) {
            return Err(format!(
                "it holds {}, which is not part of a copy",
                n.display()
            ));
        }
    }
    Ok(())
}

/// A new private directory (unique name, created atomically) for a copy of `size` bytes: beside the case, else in the
/// system temp directory.
fn private_dir(case: &Path, size: u64) -> Result<tempfile::TempDir> {
    let mut tried = Vec::new();
    for parent in parents(case) {
        let dir = match tempfile::Builder::new()
            .prefix(&format!(".sparrow-snapshot-{}-", std::process::id()))
            .tempdir_in(&parent)
        {
            Ok(d) => d,
            Err(e) => {
                tried.push(format!("{} ({e})", parent.display()));
                continue;
            }
        };
        let (free, total) = free_space(dir.path())?;
        if free.saturating_sub(size) < total / 10 {
            return Err(crate::Refused(format!(
                "a snapshot of the case ({size} bytes) would leave less than 10% free on the volume of {}",
                parent.display()
            ))
            .into());
        }
        return Ok(dir);
    }
    anyhow::bail!(
        "cannot create a snapshot directory (tried {})",
        tried.join(", ")
    )
}

/// Bytes available to this user and the volume's size.
#[cfg(unix)]
fn free_space(dir: &Path) -> Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    // SAFETY: an all-zero statvfs is a valid value of the plain C struct.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `path` is a valid C string and `s` a writable statvfs.
    if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
        return Err(anyhow::anyhow!(
            "cannot measure the free space of {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    let frsize = s.f_frsize as u64;
    #[allow(clippy::unnecessary_cast)]
    Ok((s.f_bavail as u64 * frsize, s.f_blocks as u64 * frsize))
}

/// Not measured on Windows (no system API in the dependencies): the copy fails on its own when the disk fills.
#[cfg(not(unix))]
fn free_space(_dir: &Path) -> Result<(u64, u64)> {
    Ok((u64::MAX, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let case = tmp.path().join("case.duckdb");
        std::fs::write(&case, b"database").unwrap();
        std::fs::write(wal_of(&case), b"wal").unwrap();
        (tmp, case)
    }

    /// Stamps that differ between the before and after reads of the first `changes` attempts.
    fn flipping(changes: usize) -> impl FnMut(&Path) -> std::io::Result<Stamp> {
        let mut reads = 0usize;
        move |p: &Path| {
            let real = stamp(p)?;
            reads += 1;
            // Two reads (wal, case) per stamp, two stamps per attempt: the "after" pair of attempt k is reads 4k+3..4k+4.
            let attempt = (reads - 1) / 4;
            let after = (reads - 1) % 4 >= 2;
            Ok(if after && attempt < changes {
                real.map(|(n, t)| (n + 1, t))
            } else {
                real
            })
        }
    }

    #[test]
    fn snapshot_retries_when_the_files_change() {
        let (_tmp, case) = files();
        let snap = take_with(&case, &mut flipping(2)).expect("settles on the third attempt");
        assert_eq!(std::fs::read(&snap.case).unwrap(), b"database");
        assert_eq!(std::fs::read(wal_of(&snap.case)).unwrap(), b"wal");
        let dir = snap.dir();
        drop(snap);
        assert!(!dir.exists(), "the copy is deleted");

        let e = take_with(&case, &mut flipping(usize::MAX))
            .err()
            .expect("always changing fails");
        assert!(e.downcast_ref::<crate::Refused>().is_some(), "{e:#}");
        assert!(
            e.to_string().contains("changed while it was being copied"),
            "{e:#}"
        );
    }

    /// The pid of a process that has ended.
    #[cfg(unix)]
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// A copy left beside `case` by process `pid`, holding `files` and, when `marked_for` is given, the marker a
    /// snapshot writes (naming that case and `pid`).
    fn leftover(case: &Path, pid: u64, marked_for: Option<&Path>, files: &[&str]) -> PathBuf {
        let dir = case
            .parent()
            .unwrap()
            .join(format!(".sparrow-snapshot-{pid}-abc123"));
        std::fs::create_dir(&dir).unwrap();
        for f in files {
            std::fs::write(dir.join(f), b"copy").unwrap();
        }
        if let Some(source) = marked_for {
            let m =
                serde_json::json!({ "pid": pid, "source": std::fs::canonicalize(source).unwrap() });
            std::fs::write(dir.join(MARKER), m.to_string()).unwrap();
        }
        dir
    }

    fn canon(dir: &Path) -> PathBuf {
        std::fs::canonicalize(dir.parent().unwrap())
            .unwrap()
            .join(dir.file_name().unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn a_copy_left_by_an_ended_run_is_removed_and_named() {
        let (_tmp, case) = files();
        let old = leftover(
            &case,
            dead_pid().into(),
            Some(&case),
            &["case.duckdb", "case.duckdb.wal"],
        );
        let want = canon(&old);
        let snap = take(&case).unwrap();
        assert!(!old.exists(), "the interrupted run's copy is gone");
        assert_eq!(snap.swept, vec![want]);
        assert!(snap.left.is_empty(), "{:?}", snap.left);
    }

    #[cfg(unix)]
    #[test]
    fn a_running_run_or_another_cases_copy_is_kept_silently() {
        let (tmp, case) = files();
        let other = tmp.path().join("elsewhere");
        std::fs::create_dir(&other).unwrap();
        let other_case = other.join("case.duckdb");
        std::fs::write(&other_case, b"x").unwrap();
        let live = leftover(
            &case,
            std::process::id().into(),
            Some(&case),
            &["case.duckdb"],
        );
        let theirs = leftover(
            &case,
            dead_pid().into(),
            Some(&other_case),
            &["case.duckdb"],
        );
        let snap = take(&case).unwrap();
        assert!(live.exists() && theirs.exists());
        assert!(
            snap.swept.is_empty() && snap.left.is_empty(),
            "{:?}",
            snap.left
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unproven_leftover_is_reported_not_deleted() {
        let (_tmp, case) = files();
        // No marker; a marker but a file that is not part of a copy; a marker whose pid is not a valid process id.
        let unmarked = leftover(&case, dead_pid().into(), None, &["case.duckdb"]);
        let extra = leftover(
            &case,
            u64::from(dead_pid()) + 1_000_000,
            Some(&case),
            &["case.duckdb", "notes.txt"],
        );
        let bad_pid = leftover(&case, 2_147_483_648, Some(&case), &["case.duckdb"]);
        let snap = take(&case).unwrap();
        for d in [&unmarked, &extra, &bad_pid] {
            assert!(d.exists(), "{} kept", d.display());
        }
        assert!(snap.swept.is_empty());
        let mut reported: Vec<_> = snap.left.iter().map(|(d, _)| d.clone()).collect();
        reported.sort();
        let mut want = vec![canon(&unmarked), canon(&extra), canon(&bad_pid)];
        want.sort();
        assert_eq!(reported, want);
    }

    #[test]
    fn the_copy_goes_beside_the_case() {
        let (tmp, case) = files();
        let snap = take(&case).unwrap();
        let dir = snap.dir();
        let parent = std::fs::canonicalize(tmp.path()).unwrap();
        assert_eq!(dir.parent(), Some(parent.as_path()));
        assert!(
            dir.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".sparrow-snapshot-")
        );
    }

    #[test]
    fn an_existing_directory_beside_the_case_is_never_touched() {
        let (tmp, case) = files();
        let mine = tmp
            .path()
            .join(format!(".sparrow-snapshot-{}", std::process::id()));
        std::fs::create_dir(&mine).unwrap();
        std::fs::write(mine.join("keep.txt"), b"x").unwrap();
        let snap = take(&case).unwrap();
        assert_ne!(snap.case.parent(), Some(mine.as_path()));
        drop(snap);
        assert!(
            mine.join("keep.txt").is_file(),
            "someone else's directory survives"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_case_copies_the_real_files_wal() {
        let (tmp, case) = files();
        let link = tmp.path().join("link.duckdb");
        std::os::unix::fs::symlink(&case, &link).unwrap();
        let snap = take(&link).unwrap();
        assert_eq!(std::fs::read(wal_of(&snap.case)).unwrap(), b"wal");
    }

    #[test]
    fn same_bytes_compares_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b, c) = (
            tmp.path().join("a"),
            tmp.path().join("b"),
            tmp.path().join("c"),
        );
        std::fs::write(&a, b"same bytes").unwrap();
        std::fs::write(&b, b"same bytes").unwrap();
        std::fs::write(&c, b"same bytez").unwrap();
        assert!(same_bytes(&a, &b).unwrap());
        assert!(!same_bytes(&a, &c).unwrap());
        assert!(!same_bytes(&a, &tmp.path().join("missing")).unwrap());
    }

    #[test]
    fn a_case_without_a_wal_copies_the_database_only() {
        let (_tmp, case) = files();
        std::fs::remove_file(wal_of(&case)).unwrap();
        let snap = take(&case).unwrap();
        assert!(snap.case.is_file());
        assert!(!wal_of(&snap.case).exists());
    }
}
