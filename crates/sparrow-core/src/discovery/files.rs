//! Listing the files of a collection.

use crate::discovery::registry::normalize_rel_path;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct CollectionFile {
    pub abs: PathBuf,
    /// Path relative to the collection root, forward slashes.
    pub rel: String,
}

pub fn is_os_junk(name: &str) -> bool {
    matches!(name, ".DS_Store" | "Thumbs.db" | "desktop.ini") || name.starts_with("._")
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
        let rel = entry
            .path()
            .strip_prefix(root)
            .expect("walkdir stays under root")
            .to_string_lossy();
        out.push(CollectionFile {
            abs: entry.path().to_path_buf(),
            rel: normalize_rel_path(&rel),
        });
    }
    Ok(out)
}

/// Canonical absolute path as a display string (without the Windows `\\?\` prefix).
pub fn canonical_root_string(p: &Path) -> String {
    let c = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = c.to_string_lossy().to_string();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => rest.to_string(),
        None => s,
    }
}
