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
    let dir = private_dir(&case, size)?;
    let name = case
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| "case.duckdb".into());
    let mut snap = Snapshot {
        case: dir.path().join(&name),
        dir: Some(dir),
        taken_at: Utc::now(),
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

/// A new private directory (unique name, created atomically) for a copy of `size` bytes: beside the case, else in the
/// system temp directory.
fn private_dir(case: &Path, size: u64) -> Result<tempfile::TempDir> {
    let mut tried = Vec::new();
    for parent in case
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .chain([std::env::temp_dir()])
    {
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
