//! The build fingerprint of the test-tree cache (`cache`): a hash of everything whose change can
//! change what the generator writes or what ingest and profile make of it. It is computed at
//! build time by `build.rs` (this file is `#[path]`-included there) and embedded in the library
//! as `SPARROW_BUILD_FINGERPRINT`, so a stale cache entry from before a source edit can never
//! be mistaken for a current one. Test code under `tests/` is not part of it: tests do not
//! shape the data.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Paths (relative to the workspace root) whose files are hashed: the generator, the parsers,
/// the profile, the schema, the embedded rules and data, the scenarios, and the dependency
/// lock. Directories are walked recursively; `tests/` and `target/` are never entered.
pub const ROOTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rules",
    "data",
    "crates/sparrow-core/Cargo.toml",
    "crates/sparrow-core/build.rs",
    "crates/sparrow-core/src",
    "crates/sparrow-core/migrations",
    "crates/sparrow-synth/Cargo.toml",
    "crates/sparrow-synth/build.rs",
    "crates/sparrow-synth/src",
    "crates/sparrow-synth/scenarios",
    "crates/sparrow-synth/data",
    "crates/sparrow-synth/conformance",
];

fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = fs::metadata(path) else {
        return;
    };
    if meta.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    let Ok(rd) = fs::read_dir(path) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if name == "tests" || name == "target" || name == ".git" {
            continue;
        }
        collect(&e.path(), out);
    }
}

/// SHA-256 (hex) of the relative path and bytes of every file under [`ROOTS`] of `repo`, in
/// path order, plus `extra` (the compiler version).
pub fn fingerprint(repo: &Path, extra: &str) -> String {
    let mut files = Vec::new();
    for r in ROOTS {
        collect(&repo.join(r), &mut files);
    }
    files.sort();
    let mut h = Sha256::new();
    h.update(extra.as_bytes());
    h.update([0]);
    for f in files {
        let rel = f.strip_prefix(repo).unwrap_or(&f);
        h.update(rel.to_string_lossy().replace('\\', "/").as_bytes());
        h.update([0]);
        h.update(fs::read(&f).unwrap_or_default());
        h.update([0xff]);
    }
    let digest = h.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
