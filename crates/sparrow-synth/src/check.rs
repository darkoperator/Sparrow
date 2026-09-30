//! `sparrow synth check`: compares a case ingested (and profiled) from a generated tree with
//! the tree's manifest, and lists every difference.

use crate::manifest::{Manifest, RuleOutcome, TableExpect};
use crate::{Error, Result};
use chrono::Duration;
use duckdb::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_core::data::DataDirs;
use sparrow_core::detect::coverage::BaselineAllow;
use sparrow_core::detect::load::{RuleSet, load_rules};
use sparrow_core::profile::availability::capabilities_report;
use std::collections::{BTreeMap, BTreeSet};

/// At most this many example keys are listed per table and direction.
const MAX_EXAMPLES: usize = 20;

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub ok: bool,
    pub collection_id: Option<i64>,
    pub problems: Vec<String>,
    /// Manifest rules that have no rule file yet: their expectations are not checked.
    pub rules_unchecked: usize,
    /// The detection gate (`check_detection`).
    pub detection: DetectionCheck,
}

/// The detection gate's findings. `ok` of the report includes every list being empty.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DetectionCheck {
    /// Rules with a rule file whose latest run for the tenant was compared.
    pub rules_checked: usize,
    /// A `hit` storyline no finding of its rule cites.
    pub missing_hits: Vec<String>,
    /// A finding on a `no_hit` storyline, or on records no `hit` storyline explains (and no
    /// `baseline_allow` entry excuses).
    pub unexpected_hits: Vec<String>,
    /// A tenant-wide `not_applicable` the run log does not show, or a rule that errored.
    pub applicability: Vec<String>,
    /// Why the gate did not run: only set by [`check_without_detection`], the explicit opt-out
    /// for tests that ingest without detection. A case with no detection run fails the gate
    /// otherwise.
    pub skipped: Option<String>,
}

fn db(e: duckdb::Error) -> Error {
    Error::Core(e.to_string())
}

fn core(e: sparrow_core::Error) -> Error {
    Error::Core(e.to_string())
}

/// Compare an ingested (and profiled) case with `manifest`. `as_of` for availability is
/// `manifest.collected_at + 1 day`. The detection gate uses the built-in rules and the
/// `baseline_allow` entries of `rules/coverage.yaml`.
pub fn check(manifest: &Manifest, case: &sparrow_core::Case) -> Result<CheckReport> {
    let set = load_rules(&DataDirs::default()).map_err(core)?;
    let allow = crate::coverage::rules()
        .iter()
        .map(|r| (r.id.clone(), r.baseline_allow.clone()))
        .collect();
    check_with(manifest, case, &set, &allow)
}

/// [`check`] with an explicit rule set (the rules the case's detection ran) and baseline
/// exceptions per rule id.
pub fn check_with(
    manifest: &Manifest,
    case: &sparrow_core::Case,
    set: &RuleSet,
    baseline_allow: &BTreeMap<String, Vec<BaselineAllow>>,
) -> Result<CheckReport> {
    check_inner(manifest, case, Some((set, baseline_allow)))
}

/// [`check`] without the detection gate, for tests that deliberately ingest without detection
/// (`ingest_generated`). The report's `detection.skipped` says so; a case that was meant to be
/// detected must go through [`check`], which fails when detection did not run.
pub fn check_without_detection(
    manifest: &Manifest,
    case: &sparrow_core::Case,
) -> Result<CheckReport> {
    check_inner(manifest, case, None)
}

fn check_inner(
    manifest: &Manifest,
    case: &sparrow_core::Case,
    detect: Option<(&RuleSet, &BTreeMap<String, Vec<BaselineAllow>>)>,
) -> Result<CheckReport> {
    let mut problems = Vec::new();
    let mut detection = DetectionCheck::default();
    let collection = find_collection(manifest, case, &mut problems)?;
    if let Some((cid, tenant_key)) = &collection {
        let file_ids = check_files(manifest, case, *cid, &mut problems)?;
        check_tables(manifest, case, *cid, &mut problems)?;
        match tenant_key {
            Some(tk) => {
                check_tenant(manifest, case, tk, &mut problems)?;
                check_capabilities(manifest, case, tk, &mut problems)?;
                check_evidence(manifest, case, tk, &mut problems)?;
                detection = match detect {
                    Some((set, allow)) => check_detection(manifest, case, *cid, tk, set, allow)?,
                    None => DetectionCheck {
                        skipped: Some("detection not checked (check_without_detection)".into()),
                        ..DetectionCheck::default()
                    },
                };
                problems.extend(
                    detection
                        .missing_hits
                        .iter()
                        .chain(&detection.unexpected_hits)
                        .chain(&detection.applicability)
                        .map(|p| format!("detection: {p}")),
                );
            }
            None => problems.push(format!(
                "collection {cid} has no tenant_key (was the case profiled?)"
            )),
        }
        check_sightings(manifest, case, *cid, &file_ids, &mut problems)?;
    }
    Ok(CheckReport {
        ok: problems.is_empty(),
        collection_id: collection.map(|(cid, _)| cid),
        problems,
        rules_unchecked: manifest
            .rules
            .iter()
            .map(|r| r.rule_id.as_str())
            .filter(|id| detect.is_none_or(|(set, _)| !set.rules.iter().any(|r| r.rule.id == *id)))
            .collect::<BTreeSet<_>>()
            .len(),
        detection,
    })
}

/// Check 1: the one collection whose root folder is the manifest's root.
fn find_collection(
    manifest: &Manifest,
    case: &Case,
    problems: &mut Vec<String>,
) -> Result<Option<(i64, Option<String>)>> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT collection_id, root_path, tenant_key FROM collections ORDER BY collection_id",
        )
        .map_err(db)?;
    let rows: Vec<(i64, String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)?;
    let (slash, backslash) = (
        format!("/{}", manifest.root),
        format!("\\{}", manifest.root),
    );
    let found: Vec<_> = rows
        .into_iter()
        .filter(|(_, root, _)| {
            let root = root.trim_end_matches(['/', '\\']);
            root.ends_with(&slash) || root.ends_with(&backslash) || root == manifest.root
        })
        .collect();
    match found.as_slice() {
        [(cid, _, tk)] => Ok(Some((*cid, tk.clone()))),
        [] => {
            problems.push(format!("no collection has root folder {}", manifest.root));
            Ok(None)
        }
        many => {
            problems.push(format!(
                "{} collections have root folder {}",
                many.len(),
                manifest.root
            ));
            Ok(None)
        }
    }
}

/// Check 2: every manifest file has its `source_files` row (status, artifact) and no other
/// file was recorded. Returns the file ids by path.
fn check_files(
    manifest: &Manifest,
    case: &Case,
    cid: i64,
    problems: &mut Vec<String>,
) -> Result<BTreeMap<String, i64>> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT file_id, rel_path, CAST(status AS VARCHAR), artifact_type
             FROM source_files WHERE collection_id = ? ORDER BY rel_path",
        )
        .map_err(db)?;
    let rows: Vec<(i64, String, String, Option<String>)> = stmt
        .query_map(params![cid], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)?;
    let actual: BTreeMap<&str, (&str, Option<&str>)> = rows
        .iter()
        .map(|(_, p, s, a)| (p.as_str(), (s.as_str(), a.as_deref())))
        .collect();
    for f in &manifest.files {
        match actual.get(f.rel_path.as_str()) {
            None => problems.push(format!("file {}: no source_files row", f.rel_path)),
            Some((status, artifact)) => {
                if *status != f.status {
                    problems.push(format!(
                        "file {}: status {status}, expected {}",
                        f.rel_path, f.status
                    ));
                }
                if *artifact != f.artifact_id.as_deref() {
                    problems.push(format!(
                        "file {}: artifact {}, expected {}",
                        f.rel_path,
                        artifact.unwrap_or("-"),
                        f.artifact_id.as_deref().unwrap_or("-")
                    ));
                }
            }
        }
    }
    let listed: BTreeSet<&str> = manifest.files.iter().map(|f| f.rel_path.as_str()).collect();
    for (_, p, s, _) in &rows {
        if !listed.contains(p.as_str()) {
            problems.push(format!("file {p}: recorded ({s}) but not in the manifest"));
        }
    }
    Ok(rows.into_iter().map(|(id, p, _, _)| (p, id)).collect())
}

/// The SQL expression of a table's record key.
fn key_expr(table: &str) -> &'static str {
    if table == "ual_events" {
        "lower(CAST(record_id AS VARCHAR))"
    } else {
        "record_key"
    }
}

fn valid_table_name(t: &str) -> bool {
    !t.is_empty()
        && t.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn sha256_keys(keys: &BTreeSet<String>) -> String {
    let joined = keys
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    hex::encode(Sha256::digest(joined.as_bytes()))
}

fn examples<'a>(it: impl Iterator<Item = &'a String>) -> String {
    it.take(MAX_EXAMPLES)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ")
}

/// Check 3: every table's rows, case-wide (tables merge across collections).
fn check_tables(
    manifest: &Manifest,
    case: &Case,
    cid: i64,
    problems: &mut Vec<String>,
) -> Result<()> {
    for (table, expect) in &manifest.tables {
        if !valid_table_name(table) {
            problems.push(format!("table {table}: not a table name"));
            continue;
        }
        if let Err(e) = check_table(case, cid, table, expect, problems) {
            problems.push(format!("table {table}: {e}"));
        }
    }
    Ok(())
}

fn check_table(
    case: &Case,
    cid: i64,
    table: &str,
    expect: &TableExpect,
    problems: &mut Vec<String>,
) -> Result<()> {
    let conn = case.conn();
    let counted = expect.keys_sha256.is_none() && expect.keys.is_empty();
    if counted {
        let n: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .map_err(db)?;
        let n = n as u64;
        if (expect.exact && n != expect.rows) || (!expect.exact && n < expect.rows) {
            problems.push(format!(
                "table {table}: {n} rows, expected {}{}",
                if expect.exact { "" } else { "at least " },
                expect.rows
            ));
        }
        return Ok(());
    }
    let mut stmt = conn
        .prepare(&format!("SELECT DISTINCT {} FROM {table}", key_expr(table)))
        .map_err(db)?;
    let actual: BTreeSet<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)?;
    if !expect.exact {
        if (actual.len() as u64) < expect.rows {
            problems.push(format!(
                "table {table}: {} rows, expected at least {}",
                actual.len(),
                expect.rows
            ));
        }
        return Ok(());
    }
    let total: i64 = conn
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .map_err(db)?;
    if total as u64 != expect.rows {
        problems.push(format!(
            "table {table}: {total} rows, expected {}",
            expect.rows
        ));
    }
    if expect.keys.is_empty() {
        // Only the hash: tables this large never carry the `{cid}` placeholder.
        let hash = expect.keys_sha256.as_deref().unwrap_or_default();
        if sha256_keys(&actual) != hash {
            problems.push(format!(
                "table {table}: key set differs from the manifest's hash ({} keys, expected {}); missing and extra keys cannot be listed",
                actual.len(),
                expect.rows
            ));
        }
        return Ok(());
    }
    let cid = cid.to_string();
    let expected: BTreeSet<String> = expect
        .keys
        .iter()
        .map(|k| k.replace(crate::keys::CID, &cid))
        .collect();
    let missing: Vec<&String> = expected.difference(&actual).collect();
    let extra: Vec<&String> = actual.difference(&expected).collect();
    if !missing.is_empty() {
        problems.push(format!(
            "table {table}: {} missing keys: {}",
            missing.len(),
            examples(missing.iter().copied())
        ));
    }
    if !extra.is_empty() {
        problems.push(format!(
            "table {table}: {} extra keys: {}",
            extra.len(),
            examples(extra.iter().copied())
        ));
    }
    Ok(())
}

/// Check 4: the tenant id and the expected domains.
fn check_tenant(
    manifest: &Manifest,
    case: &Case,
    tenant_key: &str,
    problems: &mut Vec<String>,
) -> Result<()> {
    let conn = case.conn();
    let id: Option<Option<String>> = conn
        .query_row(
            "SELECT tenant_id FROM tenant WHERE tenant_key = ?",
            params![tenant_key],
            |r| r.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            duckdb::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })
        .map_err(db)?;
    let want = manifest.tenant.tenant_id.to_lowercase();
    match id {
        None => problems.push(format!("tenant {tenant_key}: no tenant row")),
        Some(got) if got.as_deref().map(str::to_lowercase) != Some(want.clone()) => {
            problems.push(format!(
                "tenant {tenant_key}: tenant_id {}, expected {want}",
                got.as_deref().unwrap_or("NULL")
            ))
        }
        Some(_) => {}
    }
    let mut stmt = conn
        .prepare("SELECT lower(domain) FROM tenant_domains WHERE tenant_key = ?")
        .map_err(db)?;
    let domains: BTreeSet<String> = stmt
        .query_map(params![tenant_key], |r| r.get(0))
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)?;
    for d in &manifest.tenant.domains {
        if !domains.contains(&d.to_lowercase()) {
            problems.push(format!(
                "tenant {tenant_key}: domain {d} not in tenant_domains"
            ));
        }
    }
    Ok(())
}

/// Check 5: every listed capability's status and confidence.
fn check_capabilities(
    manifest: &Manifest,
    case: &Case,
    tenant_key: &str,
    problems: &mut Vec<String>,
) -> Result<()> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT capability_id, CAST(status AS VARCHAR), CAST(confidence AS VARCHAR)
             FROM tenant_capabilities WHERE tenant_key = ?",
        )
        .map_err(db)?;
    let actual: BTreeMap<String, (String, Option<String>)> = stmt
        .query_map(params![tenant_key], |r| {
            Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?)))
        })
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)?;
    for (cap, want) in &manifest.capabilities {
        let show = |s: &str, c: Option<&str>| format!("{s}/{}", c.unwrap_or("-"));
        let expected = show(&want.status, want.confidence.as_deref());
        match actual.get(cap) {
            None => problems.push(format!("capability {cap}: missing, expected {expected}")),
            Some((s, c)) if *s != want.status || c.as_deref() != want.confidence.as_deref() => {
                problems.push(format!(
                    "capability {cap}: {}, expected {expected}",
                    show(s, c.as_deref())
                ))
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Check 6: evidence availability at `collected_at + 1 day`.
fn check_evidence(
    manifest: &Manifest,
    case: &Case,
    tenant_key: &str,
    problems: &mut Vec<String>,
) -> Result<()> {
    let report =
        capabilities_report(case, manifest.collected_at + Duration::days(1)).map_err(core)?;
    let Some(tenant) = report.tenants.iter().find(|t| t.tenant_key == tenant_key) else {
        problems.push(format!(
            "tenant {tenant_key}: not in the capabilities report"
        ));
        return Ok(());
    };
    for (id, want) in &manifest.evidence {
        match tenant.evidence.iter().find(|e| e.evidence == *id) {
            None => problems.push(format!("evidence {id}: not reported")),
            Some(row) if !want.allowed.contains(&row.status) => problems.push(format!(
                "evidence {id}: {} ({}), expected one of {} ({})",
                row.status,
                row.reason,
                want.allowed.join(", "),
                want.why
            )),
            Some(_) => {}
        }
    }
    Ok(())
}

/// Check 7: every delivered storyline sighting has its provenance row.
fn check_sightings(
    manifest: &Manifest,
    case: &Case,
    cid: i64,
    file_ids: &BTreeMap<String, i64>,
    problems: &mut Vec<String>,
) -> Result<()> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT count(*) FROM record_sources
             WHERE table_name = ? AND record_key = ? AND file_id = ?
               AND line_start = ? AND line_end = ?",
        )
        .map_err(db)?;
    let cid = cid.to_string();
    for story in &manifest.storylines {
        for ev in &story.evidence {
            for landed in &ev.delivered {
                let s = &landed.sighting;
                let at = format!("{}:{}-{}", s.rel_path, s.line_start, s.line_end);
                let Some(key) = &landed.record_key else {
                    problems.push(format!(
                        "storyline {}: {} in {} at {at} has no record key",
                        story.id, ev.what, landed.table
                    ));
                    continue;
                };
                let Some(file_id) = file_ids.get(&s.rel_path) else {
                    // A listed file without its row is reported by the file check.
                    if !manifest.files.iter().any(|f| f.rel_path == s.rel_path) {
                        problems.push(format!(
                            "storyline {}: {} in {} at {at}: file not in the manifest",
                            story.id, ev.what, landed.table
                        ));
                    }
                    continue;
                };
                let key = key.replace(crate::keys::CID, &cid);
                let n: i64 = stmt
                    .query_row(
                        params![landed.table, key, file_id, s.line_start, s.line_end],
                        |r| r.get(0),
                    )
                    .map_err(db)?;
                if n == 0 {
                    problems.push(format!(
                        "storyline {}: no {} provenance for {key} at {at}",
                        story.id, landed.table
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Whether the rule is `not_applicable` for the whole tenant under this manifest: a required
/// capability is not licensed, or a required evidence is never available (not licensed / not
/// enabled). The runner decides per tenant; a storyline that is `not_applicable` only because it
/// falls in a logging gap (audit-tamper) is a different cause and is checked as "no finding".
fn tenant_wide_not_applicable(
    manifest: &Manifest,
    rule: &sparrow_core::detect::rule::Rule,
) -> bool {
    rule.requires.iter().any(|c| {
        manifest
            .capabilities
            .get(c)
            .is_some_and(|e| e.status == "not_licensed")
    }) || rule.requires_evidence.iter().any(|e| {
        manifest.evidence.get(e).is_some_and(|x| {
            !x.allowed.is_empty()
                && x.allowed
                    .iter()
                    .all(|a| a == "not_licensed" || a == "not_enabled")
        })
    })
}

/// The exact detection gate (Addendum C.3) for every rule that has a rule file.
///
/// 1. `hit` storyline: a finding of the rule cites one of the storyline's delivered records in
///    one of the rule's tables.
/// 2. `no_hit` storyline: no finding of the rule cites its records.
/// 3. `not_applicable`: for a tenant-wide cause the run log has the rule `not_applicable`;
///    for a logging-gap cause (audit-tamper) the storyline is treated like `no_evidence`, plus
///    no finding of the rule may cite its records.
/// 4. Baseline: every finding must cite the records of a `hit` storyline of its rule, unless the
///    kinds it cites are listed in `baseline_allow`. Otherwise it is an extra finding.
/// 5. `no_evidence` is skipped.
fn check_detection(
    manifest: &Manifest,
    case: &Case,
    cid: i64,
    tenant_key: &str,
    set: &RuleSet,
    baseline_allow: &BTreeMap<String, Vec<BaselineAllow>>,
) -> Result<DetectionCheck> {
    let mut out = DetectionCheck::default();
    // The latest run's statuses for the tenant.
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT rule_id, CAST(status AS VARCHAR), reason FROM detection_runs \
             WHERE tenant_key = ? AND run_id = (SELECT max(run_id) FROM detection_runs) ORDER BY rule_id",
        )
        .map_err(db)?;
    let runs: BTreeMap<String, (String, Option<String>)> = stmt
        .query_map(params![tenant_key], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?),
            ))
        })
        .map_err(db)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db)?;
    if runs.is_empty() {
        out.applicability.push(
            "the case holds no detection run for the tenant (ingest with detection, or use \
             check_without_detection)"
                .to_string(),
        );
        return Ok(out);
    }

    // What each storyline delivered, and who owns each record.
    let cid = cid.to_string();
    let mut records: BTreeMap<&str, BTreeSet<(String, String)>> = BTreeMap::new();
    let mut owners: BTreeMap<(String, String), Vec<&str>> = BTreeMap::new();
    let kind_of: BTreeMap<&str, &str> = manifest
        .storylines
        .iter()
        .map(|s| (s.id.as_str(), s.kind.as_str()))
        .collect();
    for story in &manifest.storylines {
        for ev in &story.evidence {
            for landed in &ev.delivered {
                let Some(key) = &landed.record_key else {
                    continue;
                };
                let rec = (landed.table.clone(), key.replace(crate::keys::CID, &cid));
                records
                    .entry(story.id.as_str())
                    .or_default()
                    .insert(rec.clone());
                owners.entry(rec).or_default().push(story.id.as_str());
            }
        }
    }

    // The findings of the tenant: rule -> finding -> the records that triggered it.
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT f.rule_id, f.finding_id, e.source_table, e.record_key FROM findings f \
             JOIN finding_evidence e USING (finding_id) \
             WHERE f.tenant_key = ? AND f.rule_id IS NOT NULL AND CAST(e.role AS VARCHAR) = 'trigger' \
             ORDER BY f.rule_id, f.finding_id, e.source_table, e.record_key",
        )
        .map_err(db)?;
    let mut findings: BTreeMap<String, BTreeMap<String, BTreeSet<(String, String)>>> =
        BTreeMap::new();
    for row in stmt
        .query_map(params![tenant_key], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(db)?
    {
        let (rule, fid, table, key) = row.map_err(db)?;
        findings
            .entry(rule)
            .or_default()
            .entry(fid)
            .or_default()
            .insert((table, key));
    }

    let no_findings = BTreeMap::new();
    for lr in &set.rules {
        let id = lr.rule.id.as_str();
        let Some((status, reason)) = runs.get(id) else {
            out.applicability.push(format!(
                "{id}: the latest detection run has no result for this rule (a partial run)"
            ));
            continue;
        };
        out.rules_checked += 1;
        if status == "error" {
            out.applicability.push(format!(
                "{id}: the rule failed: {}",
                reason.as_deref().unwrap_or("?")
            ));
            continue;
        }
        let rule_findings = findings.get(id).unwrap_or(&no_findings);
        let cites = |story: &str, tables: Option<&[String]>| -> bool {
            let Some(recs) = records.get(story) else {
                return false;
            };
            rule_findings.values().any(|ev| {
                ev.iter()
                    .any(|e| recs.contains(e) && tables.is_none_or(|t| t.contains(&e.0)))
            })
        };
        let mut explained: BTreeSet<&str> = BTreeSet::new();
        let mut reported: BTreeSet<&str> = BTreeSet::new();
        for ex in manifest.rules.iter().filter(|r| r.rule_id == id) {
            match ex.outcome {
                RuleOutcome::Hit => {
                    explained.insert(ex.storyline.as_str());
                    if !cites(&ex.storyline, Some(&ex.tables)) {
                        out.missing_hits.push(format!(
                            "{id}: storyline {} ({}) should hit but no finding cites its records in {}",
                            ex.storyline,
                            kind_of.get(ex.storyline.as_str()).copied().unwrap_or("?"),
                            ex.tables.join(", ")
                        ));
                    }
                }
                RuleOutcome::NoHit => {
                    if cites(&ex.storyline, None) {
                        reported.insert(ex.storyline.as_str());
                        out.unexpected_hits.push(format!(
                            "{id}: look-alike storyline {} ({}) triggered a finding",
                            ex.storyline,
                            kind_of.get(ex.storyline.as_str()).copied().unwrap_or("?"),
                        ));
                    }
                }
                RuleOutcome::NotApplicable => {
                    if tenant_wide_not_applicable(manifest, &lr.rule) {
                        if status != "not_applicable" {
                            out.applicability.push(format!(
                                "{id}: storyline {} is not applicable for the tenant but the run log says {status}",
                                ex.storyline
                            ));
                        }
                    } else if cites(&ex.storyline, None) {
                        reported.insert(ex.storyline.as_str());
                        out.unexpected_hits.push(format!(
                            "{id}: storyline {} ({}) is not applicable ({}) yet a finding cites its records",
                            ex.storyline,
                            kind_of.get(ex.storyline.as_str()).copied().unwrap_or("?"),
                            ex.reason
                        ));
                    }
                }
                RuleOutcome::NoEvidence => {}
            }
        }
        // Rule 4: findings no `hit` storyline explains.
        let allow = baseline_allow.get(id).map(Vec::as_slice).unwrap_or(&[]);
        let hit_records: BTreeSet<&(String, String)> = explained
            .iter()
            .filter_map(|s| records.get(s))
            .flatten()
            .collect();
        for (fid, evidence) in rule_findings {
            // Every trigger record must be explained: owned by a `hit` storyline of this rule,
            // or of a kind `baseline_allow` lists (`baseline` for records no storyline owns).
            // A record of a look-alike that was reported above is not reported twice.
            let mut kinds = BTreeSet::new();
            for e in evidence {
                if hit_records.contains(e) {
                    continue;
                }
                match owners.get(e) {
                    Some(stories) => {
                        if stories.iter().any(|s| reported.contains(s)) {
                            continue;
                        }
                        for s in stories {
                            kinds.insert(kind_of.get(s).copied().unwrap_or("?").to_string());
                        }
                    }
                    None => {
                        kinds.insert("baseline".to_string());
                    }
                }
            }
            if kinds.iter().all(|k| allow.iter().any(|a| &a.kind == k)) {
                continue;
            }
            out.unexpected_hits.push(format!(
                "{id}: finding {fid} cites records of {} that no hit storyline explains",
                kinds.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    Ok(out)
}
