//! Embeds the build fingerprint of the generator, parsers, profile, schema, rules and scenarios
//! (see `src/fingerprint.rs`) so the test-tree cache can tell a current entry from a stale one.

#[path = "src/fingerprint.rs"]
mod fingerprint;

use std::path::PathBuf;
use std::process::Command;

/// How this crate is compiled, for the test cache key.
fn build_config() -> String {
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(k, _)| k.strip_prefix("CARGO_FEATURE_").map(str::to_string))
        .collect();
    features.sort();
    format!(
        "profile={};opt={};debug={};debug_assertions={};features={};rustflags={}",
        var("PROFILE"),
        var("OPT_LEVEL"),
        var("DEBUG"),
        std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some(),
        features.join(","),
        var("CARGO_ENCODED_RUSTFLAGS").replace('\x1f', " "),
    )
}

fn main() {
    println!(
        "cargo:rustc-env=SPARROW_SYNTH_BUILD_CONFIG={}",
        build_config()
    );
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
