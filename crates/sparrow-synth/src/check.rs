//! `sparrow synth check`: compares a case ingested (and profiled) from a generated tree with
//! the tree's manifest, and lists every difference.

use crate::manifest::{Manifest, TableExpect};
use crate::{Error, Result};
use chrono::Duration;
use duckdb::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sparrow_core::Case;
use sparrow_core::profile::availability::capabilities_report;
use std::collections::{BTreeMap, BTreeSet};

/// At most this many example keys are listed per table and direction.
const MAX_EXAMPLES: usize = 20;

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub ok: bool,
    pub collection_id: Option<i64>,
    pub problems: Vec<String>,
    /// Rule expectations are not checked until Phase 6 (the detection engine).
    pub rules_unchecked: usize,
}

fn db(e: duckdb::Error) -> Error {
    Error::Core(e.to_string())
}

fn core(e: sparrow_core::Error) -> Error {
    Error::Core(e.to_string())
}

/// Compare an ingested (and profiled) case with `manifest`. `as_of` for availability is
/// `manifest.collected_at + 1 day`.
pub fn check(manifest: &Manifest, case: &sparrow_core::Case) -> Result<CheckReport> {
    let mut problems = Vec::new();
    let collection = find_collection(manifest, case, &mut problems)?;
    if let Some((cid, tenant_key)) = &collection {
        let file_ids = check_files(manifest, case, *cid, &mut problems)?;
        check_tables(manifest, case, *cid, &mut problems)?;
        match tenant_key {
            Some(tk) => {
                check_tenant(manifest, case, tk, &mut problems)?;
                check_capabilities(manifest, case, tk, &mut problems)?;
                check_evidence(manifest, case, tk, &mut problems)?;
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
        rules_unchecked: manifest.rules.len(),
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
                    // Reported by the file check.
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
