//! Test helper shared by the writer tasks' tests: ingest a generated tree the way an analyst
//! would and profile it at the manifest's evaluation time.

use crate::manifest::Manifest;
use chrono::Duration;
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use sparrow_core::profile::{ProfileOptions, refresh};
use sparrow_core::readers::time::parse_culture;
use std::path::Path;

/// Ingests `<dir>/<manifest.root>` into an in-memory case (with the manifest's
/// `ingest_culture`), then profiles it with `--geoip-dir <dir>/<geoip_dir>` and
/// `as_of = collected_at + 1 day`. Panics with the cause when ingest or profile fails.
pub fn ingest_generated(dir: &Path, manifest: &Manifest) -> Case {
    ingest_and_profile(dir, manifest)
}

/// [`ingest_generated`], then the detection step with the built-in rules (what `sparrow ingest`
/// does), at the same evaluation time. The detection gate of `check` needs it.
pub fn ingest_generated_detected(dir: &Path, manifest: &Manifest) -> Case {
    let set = sparrow_core::detect::load::load_rules(&DataDirs::default())
        .unwrap_or_else(|e| panic!("rules: {e}"));
    ingest_generated_with_rules(dir, manifest, &set)
}

/// [`ingest_generated_detected`] with an explicit rule set.
pub fn ingest_generated_with_rules(
    dir: &Path,
    manifest: &Manifest,
    set: &sparrow_core::detect::load::RuleSet,
) -> Case {
    let mut case = ingest_and_profile(dir, manifest);
    let opts = sparrow_core::detect::DetectOptions {
        now: Some(manifest.collected_at + Duration::days(1)),
        ..Default::default()
    };
    if let Err(e) = sparrow_core::detect::run::run(&mut case, set, &opts) {
        panic!("detection of {} failed: {e}", manifest.root);
    }
    case
}

fn ingest_and_profile(dir: &Path, manifest: &Manifest) -> Case {
    let date_order = manifest
        .ingest_culture
        .as_deref()
        .map(|c| parse_culture(c).unwrap_or_else(|e| panic!("ingest_culture: {e}")));
    let opts = IngestOptions {
        date_order,
        ..IngestOptions::default()
    };
    let mut case = Case::in_memory().expect("in-memory case");
    let root = dir.join(&manifest.root);
    if let Err(e) = ingest_path(&mut case, &root, &ParserRegistry::builtin(), &opts) {
        panic!("ingest of {} failed: {e}", root.display());
    }
    let profile = ProfileOptions {
        dirs: DataDirs::default(),
        geoip_dir: manifest.geoip_dir.as_ref().map(|g| dir.join(g)),
        as_of: Some(manifest.collected_at + Duration::days(1)),
    };
    if let Err(e) = refresh(&mut case, &profile) {
        panic!("profile of {} failed: {e}", root.display());
    }
    case
}
