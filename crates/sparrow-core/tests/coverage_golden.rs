//! Task 1 of the collector-manifests work: the outputs of a case WITHOUT collector manifests, frozen as goldens.
//! Later tasks teach Sparrow to read manifests; for a case that has none, every output here must stay byte-identical.
//!
//! Each of two synthetic cases (Invictus and Hawk4, seed 21, scenario `bec-aitm`, ingested and detected) is
//! rendered as the `coverage()` JSON, the `coverage_for_range()` JSON of its first account over that account's
//! window, the `summarize_conn` JSON and the report Markdown. `SPARROW_RECORD_GOLDEN=1` re-records the goldens (a
//! deliberate step whose diff is reviewed); otherwise the outputs must match byte for byte.
//!
//! Inputs are fixed instead of masked wherever possible: the seed, the cached synthetic tree and the report's
//! `generated_at`. What a fresh temp directory or the clock still leaks into is masked in [`normalise`].

use chrono::{TimeZone, Utc};
use sparrow_core::Case;
use sparrow_core::case::coverage::{CoverageOptions, coverage, coverage_for_range};
use sparrow_core::data::DataDirs;
use sparrow_core::export::report_md::{self, ReportOpts};
use sparrow_core::summary::summarize_conn;
use sparrow_synth::cache::{Cache, Stage};
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scenario::load;
use std::path::Path;
use std::sync::LazyLock;

static CACHE: LazyLock<Cache> = LazyLock::new(|| sparrow_synth::test_cache!());

/// `text` with the run-specific parts masked:
/// * the tree directory and the case file's directory -> `<ROOT>` / `<CASE>` (every run uses a fresh temp tree);
/// * the case file's own path is masked before its directory, so `<CASE>` wins over `<ROOT>`;
/// * the Sparrow version in the report -> `<VERSION>` (a version bump must not churn the goldens);
/// * the rule-pack SHA-256 in the report -> `<RULE_PACK_SHA256>` (a rule edit must not churn the goldens);
/// * the value of any `profile_evaluated_at` JSON field -> `<TIME>` (the clock of the profile step).
fn normalise(text: &str, tree: &Path, case: &Path) -> String {
    let mut s = text.to_string();
    for (p, mask) in [
        (case.to_path_buf(), "<CASE>"),
        (tree.to_path_buf(), "<ROOT>"),
    ] {
        if !p.as_os_str().is_empty() {
            s = s.replace(p.to_string_lossy().as_ref(), mask);
        }
    }
    s = s.replace(sparrow_core::VERSION, "<VERSION>");
    let mut out = String::new();
    for line in s.lines() {
        let line = &mask_rule_pack(line);
        match line.find("\"profile_evaluated_at\":") {
            Some(i) => {
                let comma = if line.trim_end().ends_with(',') {
                    ","
                } else {
                    ""
                };
                out.push_str(&format!(
                    "{}\"profile_evaluated_at\": \"<TIME>\"{comma}",
                    &line[..i]
                ));
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    if !text.ends_with('\n') {
        out.pop();
    }
    out
}

fn check(name: &str, actual: &str) {
    let path = format!(
        "{}/tests/golden/coverage/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    if std::env::var_os("SPARROW_RECORD_GOLDEN").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("record {path} first"));
    assert_eq!(actual, expected, "{name}");
}

fn outputs(label: &str, collector: Collector) {
    let o = GenerateOptions::new(collector, 21);
    let got = CACHE
        .case(&load("bec-aitm").unwrap(), &o, Stage::Detected)
        .unwrap_or_else(|e| panic!("cached detected case ({label}): {e}"));
    let (tree, case): (&Path, &Case) = (&got.tree.dir, &got.case);
    let case_dir = case
        .path()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let norm = |t: &str| normalise(t, tree, &case_dir);
    let conn = case.conn();

    let cov = coverage(conn, &CoverageOptions::default()).unwrap();
    check(
        &format!("{label}_coverage.json"),
        &norm(&serde_json::to_string_pretty(&cov).unwrap()),
    );

    let first = cov.accounts.first().expect("the case has an account");
    let w = first.window.expect("the first account has a window");
    let range =
        coverage_for_range(conn, None, std::slice::from_ref(&first.upn), w.start, w.end).unwrap();
    check(
        &format!("{label}_range.json"),
        &norm(&serde_json::to_string_pretty(&range).unwrap()),
    );

    let summary = summarize_conn(conn).unwrap();
    check(
        &format!("{label}_summary.json"),
        &norm(&serde_json::to_string_pretty(&summary).unwrap()),
    );

    let mut md = Vec::new();
    report_md::write(
        conn,
        &mut md,
        &ReportOpts {
            reviewed_only: false,
            generated_at: Utc.with_ymd_and_hms(2026, 10, 3, 0, 0, 0).unwrap(),
            dirs: DataDirs::default(),
        },
    )
    .unwrap();
    check(
        &format!("{label}_report.md"),
        &norm(&String::from_utf8(md).unwrap()),
    );
}

#[test]
fn no_manifest_outputs_are_unchanged() {
    outputs("invictus", Collector::Invictus);
    outputs("hawk4", Collector::Hawk4);
}

/// `line` with the 64 hex digits after `Rule pack SHA-256:` replaced by a placeholder; a line without exactly 64 hex digits there is left unchanged.
fn mask_rule_pack(line: &str) -> String {
    const KEY: &str = "Rule pack SHA-256:";
    match line.find(KEY) {
        Some(i) => {
            let head = &line[..i + KEY.len()];
            let tail = &line[i + KEY.len()..];
            let hash_at = tail
                .find(|c: char| c.is_ascii_hexdigit())
                .unwrap_or(tail.len());
            let hex_len = tail[hash_at..]
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .count();
            // Only a real 64-digit hash is masked: a missing or malformed value stays visible and fails the golden.
            if hex_len != 64 {
                return line.to_string();
            }
            format!(
                "{head}{}<RULE_PACK_SHA256>{}",
                &tail[..hash_at],
                &tail[hash_at + hex_len..]
            )
        }
        None => line.to_string(),
    }
}
