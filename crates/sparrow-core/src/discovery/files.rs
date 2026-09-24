//! Listing the files of a collection.

use crate::{Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct CollectionFile {
    pub abs: PathBuf,
    /// True path relative to the collection root: its components joined with `/`. A
    /// backslash inside a component (PowerShell 7 on macOS/Linux writes a folder literally
    /// named `\Tenant`) is preserved, so the path round-trips to the real file.
    pub rel: String,
}

pub fn is_os_junk(name: &str) -> bool {
    matches!(name, ".DS_Store" | "Thumbs.db" | "desktop.ini") || name.starts_with("._")
}

/// `path` relative to `root`, components joined with `/`.
fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("walkdir stays under root")
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// All regular files under `root`, sorted by path, excluding OS junk files.
pub fn list_collection_files(root: &Path) -> Result<Vec<CollectionFile>> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry =
            entry.map_err(|e| Error::Invalid(format!("cannot walk {}: {e}", root.display())))?;
        if !entry.file_type().is_file() || is_os_junk(&entry.file_name().to_string_lossy()) {
            continue;
        }
        out.push(CollectionFile {
            abs: entry.path().to_path_buf(),
            rel: rel_path(root, entry.path()),
        });
    }
    Ok(out)
}

/// Canonical absolute path as a display string (without the Windows verbatim prefix).
pub fn canonical_root_string(p: &Path) -> String {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    strip_verbatim_prefix(&c.to_string_lossy())
}

/// `\\?\UNC\server\share` becomes `\\server\share`; `\\?\C:\x` becomes `C:\x`.
fn strip_verbatim_prefix(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::strip_verbatim_prefix;

    #[test]
    fn strips_windows_verbatim_prefixes() {
        assert_eq!(strip_verbatim_prefix(r"\\?\C:\x"), r"C:\x");
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\srv\share\x"),
            r"\\srv\share\x"
        );
        assert_eq!(strip_verbatim_prefix("/tmp/x"), "/tmp/x");
    }
}
