//! Embeds the build fingerprint of the generator, parsers, profile, schema, rules and scenarios
//! (see `src/fingerprint.rs`) so the test-tree cache can tell a current entry from a stale one.

#[path = "src/fingerprint.rs"]
mod fingerprint;

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let repo = manifest.join("../..");
    for r in fingerprint::ROOTS {
        println!("cargo:rerun-if-changed={}", repo.join(r).display());
    }
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!(
        "cargo:rustc-env=SPARROW_BUILD_FINGERPRINT={}",
        fingerprint::fingerprint(&repo, &version)
    );
}
