//! `sparrow summary` (spec §10): tenant identity, licences, collections, coverage window, row
//! counts, top actors and evidence gaps for every tenant in the case. Read-only: it presents what
//! `profile::refresh` already derived (`tenant`, `tenant_domains`, `licenses`,
//! `evidence_availability`) plus `timeline` and `ip_intel`. Findings by severity (Phase 6) are
//! out of scope.
//!
//! Attribution: `timeline` itself carries no tenant column (its rows come from several evidence
//! tables, each with its own `collection_id`). Coverage, top actors and hosting IPs are
//! attributed to a tenant through the same provenance chain `record_source_refs` and `verify`
//! use: `record_sources` -> `source_files` -> `collections.tenant_key`, matched on
//! `(source_table, record_key)`. This is more general than re-deriving `timeline`'s own per-table
//! union (which would need to be kept in lockstep with that view), and is exact even when a
//! record was sighted in files from more than one collection. `state_absent_in_newer` (Task 10)
//! carries no tenant column either; it is attributed through `last_seen_collection_id` ->
//! `collections.tenant_key`, the collection the record was last actually seen in. For a case
//! holding a single tenant (as in the tests) every choice here yields the same counts.

use crate::{Case, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use duckdb::{Connection, params};
use serde::Serialize;

/// Every timeline row attributable to `tenant_key` (bound as the sole `?`), via
/// `record_sources` -> `source_files` -> `collections`.
const TENANT_TIMELINE_EXISTS: &str = "EXISTS (
    SELECT 1 FROM record_sources rs
    JOIN source_files sf ON sf.file_id = rs.file_id
    JOIN collections c ON c.collection_id = sf.collection_id
    WHERE rs.table_name = tl.source_table AND rs.record_key = tl.record_key AND c.tenant_key = ?
)";

fn from_ms(ms: Option<i64>) -> Option<String> {
    ms.and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|t| t.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

/// Friendly label for a `licenses.source` value.
fn source_label(source: &str) -> &str {
    match source {
        "hawk_log" => "Hawk.log",
        "invictus_tenant_licenses" => "Microsoft-Extractor-Suite",
        other => other,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Some collections have no tenant yet (`stale_collections`): the profile failed after an
    /// ingest or has not run since; their evidence is missing from every tenant below.
    pub stale: bool,
    /// Collections with no `tenant_key` (see `profile::unprofiled_collections`).
    pub stale_collections: Vec<i64>,
    pub tenants: Vec<TenantSummary>,
    /// Rows per evidence table (every table with a record_key or record_id, plus ip_intel and
    /// identities).
    pub tables: Vec<TableCount>,
    pub profile_evaluated_at: Option<String>,
    /// Open collector gaps of partial, failed or search-only runs; absent without manifests or gaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete_collection: Option<crate::case::collector::IncompleteCollection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantSummary {
    pub tenant_key: String,
    pub tenant_id: Option<String>,
    pub tenant_name: Option<String>,
    pub domains: Vec<String>,
    /// Hawk tier and/or SKU part numbers of the newest licence report, with confidence.
    pub licenses: Vec<String>,
    pub collections: Vec<CollectionSummary>,
    /// Earliest and latest event time over the timeline, per source table.
    pub coverage: Vec<Coverage>,
    /// Top 10 actors by timeline rows.
    pub top_actors: Vec<ActorCount>,
    /// Evidence sources whose status is not collected.
    pub gaps: Vec<String>,
    pub hosting_ips: i64,
    pub absent_in_newer: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollectionSummary {
    pub collection_id: i64,
    pub tool: String,
    pub root: String,
    pub collected_at: Option<String>,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub source_table: String,
    pub rows: i64,
    pub first: Option<String>,
    pub last: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActorCount {
    pub actor: String,
    pub rows: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TableCount {
    pub table: String,
    pub rows: i64,
}

/// Everything Phase 4 knows about the case: tenant identity, licences, collections, coverage,
/// top actors, evidence gaps and row counts (spec §10). Read-only; opens fine on a read-only
/// connection.
pub fn summarize(case: &Case) -> Result<Summary> {
    summarize_conn(case.conn())
}

/// [`summarize`] on a bare connection (the exports read a case through one).
pub fn summarize_conn(conn: &Connection) -> Result<Summary> {
    let tenants: Vec<(String, Option<String>, Option<String>)> = {
        let mut stmt = conn
            .prepare("SELECT tenant_key, tenant_id, tenant_name FROM tenant ORDER BY tenant_key")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };

    let mut out = Vec::with_capacity(tenants.len());
    for (tenant_key, tenant_id, tenant_name) in tenants {
        out.push(tenant_summary(conn, &tenant_key, tenant_id, tenant_name)?);
    }

    let stale_collections = crate::profile::unprofiled_collections(conn)?;
    Ok(Summary {
        stale: !stale_collections.is_empty(),
        stale_collections,
        tenants: out,
        tables: table_counts(conn)?,
        profile_evaluated_at: profile_evaluated_at(conn)?,
        incomplete_collection: crate::case::collector::incomplete_collection(conn)?,
    })
}

fn profile_evaluated_at(conn: &Connection) -> Result<Option<String>> {
    let ms: Option<i64> = conn.query_row(
        "SELECT epoch_ms(max(evaluated_at)) FROM evidence_availability",
        [],
        |r| r.get(0),
    )?;
    Ok(from_ms(ms))
}

fn tenant_summary(
    conn: &Connection,
    tenant_key: &str,
    tenant_id: Option<String>,
    tenant_name: Option<String>,
) -> Result<TenantSummary> {
    let domains: Vec<String> = {
        let mut stmt =
            conn.prepare("SELECT domain FROM tenant_domains WHERE tenant_key = ? ORDER BY domain")?;
        stmt.query_map(params![tenant_key], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };

    Ok(TenantSummary {
        tenant_key: tenant_key.to_string(),
        tenant_id,
        tenant_name,
        domains,
        licenses: newest_licenses(conn, tenant_key)?,
        collections: collections_of(conn, tenant_key)?,
        coverage: coverage_of(conn, tenant_key)?,
        top_actors: top_actors_of(conn, tenant_key)?,
        gaps: gaps_of(conn, tenant_key)?,
        hosting_ips: hosting_ips_of(conn, tenant_key)?,
        absent_in_newer: absent_in_newer_of(conn, tenant_key)?,
    })
}

/// Licences of the tenant's newest licence report (the collection, among those with a `licenses`
/// row, with the latest `collected_at`, collection_id breaking ties/unknowns).
fn newest_licenses(conn: &Connection, tenant_key: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "WITH lic AS (
             SELECT l.source, l.sku_part_number, l.license_tier,
                    CAST(l.confidence AS VARCHAR) AS confidence, c.collected_at, c.collection_id AS cid
             FROM licenses l JOIN collections c ON c.collection_id = l.collection_id
             WHERE c.tenant_key = ?
         ),
         newest AS (
             SELECT cid FROM lic
             QUALIFY row_number() OVER (ORDER BY collected_at DESC NULLS LAST, cid DESC) = 1
         )
         SELECT lic.source, lic.sku_part_number, lic.license_tier, lic.confidence
         FROM lic JOIN newest ON newest.cid = lic.cid
         ORDER BY lic.license_tier NULLS LAST, lic.sku_part_number NULLS LAST",
    )?;
    let rows = stmt.query_map(params![tenant_key], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (source, sku, tier, confidence) = row?;
        let value = tier.or(sku).unwrap_or_else(|| "?".to_string());
        let confidence = confidence.unwrap_or_else(|| "unknown".to_string());
        out.push(format!("{value} ({confidence}, {})", source_label(&source)));
    }
    Ok(out)
}

fn collections_of(conn: &Connection, tenant_key: &str) -> Result<Vec<CollectionSummary>> {
    let mut stmt = conn.prepare(
        "SELECT collection_id, CAST(tool AS VARCHAR), root_path,
                epoch_ms(collected_at), epoch_ms(window_start), epoch_ms(window_end)
         FROM collections WHERE tenant_key = ? ORDER BY collection_id",
    )?;
    let rows = stmt.query_map(params![tenant_key], |r| {
        Ok(CollectionSummary {
            collection_id: r.get(0)?,
            tool: r.get(1)?,
            root: r.get(2)?,
            collected_at: from_ms(r.get(3)?),
            window_start: from_ms(r.get(4)?),
            window_end: from_ms(r.get(5)?),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn coverage_of(conn: &Connection, tenant_key: &str) -> Result<Vec<Coverage>> {
    let sql = format!(
        "SELECT tl.source_table, count(*), epoch_ms(min(tl.event_time)), epoch_ms(max(tl.event_time))
         FROM timeline tl
         WHERE {TENANT_TIMELINE_EXISTS}
         GROUP BY tl.source_table ORDER BY tl.source_table"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![tenant_key], |r| {
        Ok(Coverage {
            source_table: r.get(0)?,
            rows: r.get(1)?,
            first: from_ms(r.get(2)?),
            last: from_ms(r.get(3)?),
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn top_actors_of(conn: &Connection, tenant_key: &str) -> Result<Vec<ActorCount>> {
    let sql = format!(
        "SELECT tl.actor_upn, count(*) AS rows
         FROM timeline tl
         WHERE tl.actor_upn IS NOT NULL AND {TENANT_TIMELINE_EXISTS}
         GROUP BY tl.actor_upn
         ORDER BY rows DESC, tl.actor_upn ASC
         LIMIT 10"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![tenant_key], |r| {
        Ok(ActorCount {
            actor: r.get(0)?,
            rows: r.get(1)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn gaps_of(conn: &Connection, tenant_key: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT evidence FROM evidence_availability
         WHERE tenant_key = ? AND CAST(status AS VARCHAR) <> 'collected'
         ORDER BY evidence",
    )?;
    let rows = stmt.query_map(params![tenant_key], |r| r.get(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn hosting_ips_of(conn: &Connection, tenant_key: &str) -> Result<i64> {
    let sql = format!(
        "SELECT count(DISTINCT tl.ip)
         FROM timeline tl
         JOIN ip_intel i ON i.ip = tl.ip
         WHERE i.is_hosting AND {TENANT_TIMELINE_EXISTS}"
    );
    Ok(conn.query_row(&sql, params![tenant_key], |r| r.get(0))?)
}

fn absent_in_newer_of(conn: &Connection, tenant_key: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT count(*) FROM state_absent_in_newer s
         JOIN collections c ON c.collection_id = s.last_seen_collection_id
         WHERE c.tenant_key = ?",
        params![tenant_key],
        |r| r.get(0),
    )?)
}

/// Row counts for every evidence table (any base table with a `record_key` or `record_id`
/// column), plus `ip_intel` and `identities` (keyed on `ip` / `identity_id` instead), sorted by
/// table name.
fn table_counts(conn: &Connection) -> Result<Vec<TableCount>> {
    let mut tables: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT c.table_name
             FROM information_schema.columns c
             JOIN information_schema.tables t
               ON t.table_schema = c.table_schema AND t.table_name = c.table_name
             WHERE c.table_schema = 'main' AND t.table_type = 'BASE TABLE'
               AND c.column_name IN ('record_key', 'record_id')",
        )?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for extra in ["ip_intel", "identities"] {
        if !tables.iter().any(|t| t == extra) {
            tables.push(extra.to_string());
        }
    }
    tables.sort();

    let mut out = Vec::with_capacity(tables.len());
    for table in tables {
        let rows: i64 = conn.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
            r.get(0)
        })?;
        out.push(TableCount { table, rows });
    }
    Ok(out)
}
