//! Tenant resolution (spec §7): group collections into tenants, merge their org-level state
//! (`tenant_audit_config`, `tenant_settings_current` views) and derive `tenant_domains`, with
//! analyst overrides kept in `tenant_domain_overrides`.

use crate::{Case, Error, Result};
use duckdb::{Connection, params};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainAction {
    Add,
    Remove,
}

impl DomainAction {
    fn as_sql(self) -> &'static str {
        match self {
            DomainAction::Add => "add",
            DomainAction::Remove => "remove",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantDomain {
    pub tenant_key: String,
    pub domain: String,
    pub source: String,
}

/// Group `collections` into tenants: `collections.tenant_key` is set and the `tenant` table is
/// rewritten with one row per key. Returns the number of tenants.
///
/// A collection's tenant id evidence is counted through its own sightings (`record_sources` ->
/// `source_files.collection_id`), so a record first loaded by another collection of the same
/// tenant still counts for this collection. `tenant_key` is the tenant id (lower-case GUID) when
/// found, else `name:<lower tenant_name_reported>` when a name was reported, else
/// `collection:<collection_id>`. A collection with a name but no id joins a collection of the
/// same (case-insensitive) name that has an id.
pub fn resolve_tenants(conn: &Connection) -> Result<usize> {
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE tenant_evidence AS
         SELECT * FROM (
             SELECT sf.collection_id, lower(CAST(u.organization_id AS VARCHAR)) AS tenant_id,
                    'ual_organization_id' AS source, 1 AS source_rank, count(*) AS n
             FROM record_sources rs
             JOIN source_files sf ON sf.file_id = rs.file_id
             JOIN ual_events u ON rs.table_name = 'ual_events' AND rs.record_key = CAST(u.record_id AS VARCHAR)
             WHERE u.organization_id IS NOT NULL
             GROUP BY ALL
             UNION ALL
             SELECT sf.collection_id, lower(s.resource_tenant_id), 'signin_resource_tenant', 2, count(*)
             FROM record_sources rs
             JOIN source_files sf ON sf.file_id = rs.file_id
             JOIN signins s ON rs.table_name = 'signins' AND rs.record_key = s.record_key
             WHERE s.resource_tenant_id IS NOT NULL AND s.resource_tenant_id <> ''
             GROUP BY ALL
         ) e
         QUALIFY row_number() OVER (PARTITION BY collection_id ORDER BY n DESC, source_rank, tenant_id) = 1;",
    )?;

    // Reset first: otherwise passes 2-4 (WHERE tenant_key IS NULL) never revisit a key set by
    // an earlier profile run, so a collection whose evidence changes (or newly arrives on a
    // later collection of the same tenant) can never move off a stale key.
    conn.execute("UPDATE collections SET tenant_key = NULL", [])?;

    // Pass 1: a collection with tenant id evidence takes that id.
    conn.execute(
        "UPDATE collections SET tenant_key = e.tenant_id
         FROM tenant_evidence e WHERE collections.collection_id = e.collection_id",
        [],
    )?;

    // Pass 2: a collection with a reported name but no id joins the id of the same-name
    // collection group with the most members (smallest id text on a tie).
    conn.execute(
        "UPDATE collections c SET tenant_key = m.tenant_key
         FROM (
             SELECT lower(trim(tenant_name_reported)) AS name, tenant_key, count(*) AS cnt,
                    row_number() OVER (PARTITION BY lower(trim(tenant_name_reported))
                                       ORDER BY count(*) DESC, tenant_key) AS rn
             FROM collections
             WHERE tenant_key IS NOT NULL AND tenant_name_reported IS NOT NULL
             GROUP BY lower(trim(tenant_name_reported)), tenant_key
         ) m
         WHERE c.tenant_key IS NULL AND c.tenant_name_reported IS NOT NULL
               AND lower(trim(c.tenant_name_reported)) = m.name AND m.rn = 1",
        [],
    )?;

    // Pass 3: a collection with a reported name but no id join falls back to a name-only key.
    conn.execute(
        "UPDATE collections SET tenant_key = 'name:' || lower(trim(tenant_name_reported))
         WHERE tenant_key IS NULL AND tenant_name_reported IS NOT NULL",
        [],
    )?;

    // Pass 4: a collection with neither an id nor a name stands alone.
    conn.execute(
        "UPDATE collections SET tenant_key = 'collection:' || collection_id WHERE tenant_key IS NULL",
        [],
    )?;

    conn.execute("DELETE FROM tenant", [])?;
    let tenants = conn.execute(
        "INSERT INTO tenant (tenant_key, tenant_id, tenant_id_source, tenant_name, tenant_name_source,
             collections, first_collected_at, last_collected_at)
         WITH ev AS (
             SELECT c.tenant_key, e.source, e.source_rank, sum(e.n) AS total_n
             FROM tenant_evidence e JOIN collections c ON c.collection_id = e.collection_id
             GROUP BY c.tenant_key, e.source, e.source_rank
         ),
         best_source AS (
             SELECT tenant_key, source
             FROM ev
             QUALIFY row_number() OVER (PARTITION BY tenant_key ORDER BY total_n DESC, source_rank) = 1
         ),
         ids AS (
             SELECT DISTINCT c.tenant_key
             FROM tenant_evidence e JOIN collections c ON c.collection_id = e.collection_id
         ),
         -- Newest tenant_name_reported per tenant_key. Bug fix (Task 11): arg_max(name,
         -- collected_at) silently drops a group whose only row has a NULL collected_at (a Hawk
         -- capture whose root folder does not carry a Hawk_<tenant>_<timestamp> name), the same
         -- pitfall Task 10's sparrow_collection_is_newer works around; ranked with collection_id
         -- as the tie-break/fallback instead.
         names AS (
             SELECT tenant_key, tenant_name FROM (
                 SELECT tenant_key, lower(trim(tenant_name_reported)) AS tenant_name,
                        row_number() OVER (PARTITION BY tenant_key
                                           ORDER BY collected_at DESC NULLS LAST, collection_id DESC) AS rn
                 FROM collections
                 WHERE tenant_name_reported IS NOT NULL
             ) WHERE rn = 1
         ),
         agg AS (
             SELECT tenant_key, count(*) AS collections, min(collected_at) AS first_collected_at,
                    max(collected_at) AS last_collected_at
             FROM collections
             GROUP BY tenant_key
         )
         SELECT a.tenant_key,
                CASE WHEN ids.tenant_key IS NOT NULL THEN a.tenant_key ELSE NULL END AS tenant_id,
                bs.source AS tenant_id_source,
                n.tenant_name,
                CASE WHEN n.tenant_name IS NOT NULL THEN 'collector_reported' ELSE NULL END AS tenant_name_source,
                a.collections, a.first_collected_at, a.last_collected_at
         FROM agg a
         LEFT JOIN ids ON ids.tenant_key = a.tenant_key
         LEFT JOIN best_source bs ON bs.tenant_key = a.tenant_key
         LEFT JOIN names n ON n.tenant_key = a.tenant_key",
        [],
    )?;
    Ok(tenants)
}

/// One `ProfileReport` warning per collection `resolve_tenants` pass 4 left on its own
/// `collection:<id>` key because its evidence carried no tenant id and its collector reported no
/// tenant name: its data is not merged with any other capture of the same tenant.
pub fn unidentified_collection_warnings(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT collection_id, root_path FROM collections
         WHERE tenant_key = 'collection:' || collection_id ORDER BY collection_id",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (id, root) = row?;
        let folder = std::path::Path::new(&root)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or(root);
        out.push(format!(
            "collection {id} ({folder}) carries no tenant id or name; it is profiled as its own \
             tenant `collection:{id}`"
        ));
    }
    Ok(out)
}

/// Rebuild `tenant_domains` for `tenant_key` (all tenants when `None`) from the evidence plus
/// `tenant_domain_overrides`. Returns a warning when overrides exist whose `tenant_key` no
/// longer names a current tenant, even after the `name:<n>` fallback lookup below (only
/// computed for a full, unscoped rebuild — `tenant_key: None`).
///
/// An override's `tenant_key` is fixed at the moment `set_domain` wrote it, but `resolve_tenants`
/// can later replace a `name:<n>` key with the tenant's Entra id once evidence arrives. To keep
/// such overrides from being orphaned, an override whose literal `tenant_key` no longer exists in
/// `tenant` is remapped to the current tenant whose `tenant_name` equals the name it carries
/// (case-insensitive; `tenant.tenant_name` is already stored lower-case). Overrides that still
/// resolve to no tenant (their key was `collection:<id>`, or no current tenant reports that name)
/// are left unapplied and reported back for `ProfileReport.warnings`.
pub fn rebuild_domains(conn: &Connection, tenant_key: Option<&str>) -> Result<Option<String>> {
    conn.execute(
        "DELETE FROM tenant_domains WHERE (CAST(? AS VARCHAR) IS NULL OR tenant_key = ?)",
        params![tenant_key, tenant_key],
    )?;

    conn.execute(
        "WITH derived AS (
             SELECT tenant_key, domain, sum(n) AS n FROM (
                 SELECT c.tenant_key, lower(split_part(u.upn, '@', -1)) AS domain, count(*) AS n
                 FROM users u JOIN collections c ON c.collection_id = u.collection_id
                 WHERE u.upn LIKE '%@%' AND u.upn NOT LIKE '%#ext#%'
                       AND (u.user_type IS NULL OR lower(u.user_type) <> 'guest')
                 GROUP BY ALL
                 UNION ALL
                 SELECT c.tenant_key, lower(split_part(m.upn, '@', -1)), count(*)
                 FROM mailboxes m JOIN collections c ON c.collection_id = m.collection_id
                 WHERE m.upn LIKE '%@%' AND m.upn NOT LIKE '%#ext#%'
                 GROUP BY ALL
                 UNION ALL
                 SELECT c.tenant_key, lower(split_part(s.user_upn, '@', -1)), count(*)
                 FROM signins s
                 JOIN collections c ON c.collection_id = s.collection_id
                 JOIN tenant t ON t.tenant_key = c.tenant_key
                 WHERE s.user_upn LIKE '%@%' AND s.user_upn NOT LIKE '%#ext#%'
                       AND lower(s.home_tenant_id) = t.tenant_id
                 GROUP BY ALL
             ) x
             WHERE (CAST(? AS VARCHAR) IS NULL OR tenant_key = ?)
             GROUP BY tenant_key, domain
         ),
         trace AS (
             SELECT c.tenant_key, lower(trim(mt.organization)) AS domain, count(*) AS n
             FROM message_trace mt JOIN collections c ON c.collection_id = mt.collection_id
             WHERE mt.organization IS NOT NULL AND trim(mt.organization) <> ''
                   AND (CAST(? AS VARCHAR) IS NULL OR c.tenant_key = ?)
             GROUP BY ALL
         )
         INSERT INTO tenant_domains (tenant_key, domain, source, rows_seen)
         SELECT coalesce(d.tenant_key, t.tenant_key), coalesce(d.domain, t.domain),
                CASE WHEN d.n IS NOT NULL THEN 'derived_upn' ELSE 'message_trace_org' END,
                coalesce(d.n, 0) + coalesce(t.n, 0)
         FROM derived d FULL OUTER JOIN trace t ON t.tenant_key = d.tenant_key AND t.domain = d.domain",
        params![tenant_key, tenant_key, tenant_key, tenant_key],
    )?;

    // Resolve every override to its current tenant: an exact tenant_key match, else (for a
    // name:<n> key) the tenant currently reporting that name; NULL when neither resolves. Ties
    // within a (tenant, domain) pair break on `rowid` (insertion order), since two decisions in
    // one transaction can share `changed_at`.
    conn.execute_batch(
        "CREATE OR REPLACE TEMP TABLE resolved_overrides AS
         SELECT o.tenant_key AS original_tenant_key, o.domain, o.action, o.changed_at, o.rowid,
                COALESCE(
                    (SELECT t.tenant_key FROM tenant t WHERE t.tenant_key = o.tenant_key),
                    (SELECT t.tenant_key FROM tenant t
                     WHERE o.tenant_key LIKE 'name:%' AND t.tenant_name = substr(o.tenant_key, 6)
                     ORDER BY t.tenant_key LIMIT 1)
                ) AS effective_tenant_key
         FROM tenant_domain_overrides o;

         CREATE OR REPLACE TEMP TABLE latest_overrides AS
         SELECT effective_tenant_key AS tenant_key, domain, action
         FROM resolved_overrides
         WHERE effective_tenant_key IS NOT NULL
         QUALIFY row_number() OVER (PARTITION BY effective_tenant_key, domain
                                    ORDER BY changed_at DESC, rowid DESC) = 1;",
    )?;
    conn.execute(
        "DELETE FROM tenant_domains
         WHERE (CAST(? AS VARCHAR) IS NULL OR tenant_key = ?)
               AND (tenant_key, domain) IN (
                   SELECT tenant_key, domain FROM latest_overrides WHERE action = 'remove'
               )",
        params![tenant_key, tenant_key],
    )?;
    conn.execute(
        "INSERT INTO tenant_domains (tenant_key, domain, source, rows_seen)
         SELECT o.tenant_key, o.domain, 'analyst', NULL FROM latest_overrides o
         WHERE o.action = 'add'
               AND (CAST(? AS VARCHAR) IS NULL OR o.tenant_key = ?)
               AND NOT EXISTS (
                   SELECT 1 FROM tenant_domains td WHERE td.tenant_key = o.tenant_key AND td.domain = o.domain
               )",
        params![tenant_key, tenant_key],
    )?;

    if tenant_key.is_some() {
        return Ok(None);
    }
    let mut stmt = conn.prepare(
        "SELECT original_tenant_key FROM (
             SELECT original_tenant_key, domain
             FROM resolved_overrides
             WHERE effective_tenant_key IS NULL
             QUALIFY row_number() OVER (PARTITION BY original_tenant_key, domain
                                        ORDER BY changed_at DESC, rowid DESC) = 1
         ) ORDER BY original_tenant_key",
    )?;
    let orphan_decisions: Vec<String> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if orphan_decisions.is_empty() {
        return Ok(None);
    }
    let count = orphan_decisions.len();
    let mut keys = orphan_decisions;
    keys.sort();
    keys.dedup();
    Ok(Some(format!(
        "{count} analyst domain decisions refer to tenants no longer in the case: {}",
        keys.join(", ")
    )))
}

/// Resolve `tenant_key` to a tenant that exists (`Error::NotFound` when named but absent);
/// `None` requires the case to have exactly one tenant (`Error::Invalid` otherwise).
pub fn only_tenant(conn: &Connection, tenant_key: Option<&str>) -> Result<String> {
    match tenant_key {
        Some(k) => {
            let exists: i64 = conn.query_row(
                "SELECT count(*) FROM tenant WHERE tenant_key = ?",
                params![k],
                |r| r.get(0),
            )?;
            if exists > 0 {
                Ok(k.to_string())
            } else {
                Err(Error::NotFound(format!("tenant {k}")))
            }
        }
        None => {
            let mut stmt = conn.prepare("SELECT tenant_key FROM tenant ORDER BY tenant_key")?;
            let keys: Vec<String> = stmt
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            match keys.len() {
                1 => Ok(keys.into_iter().next().expect("len checked")),
                0 => Err(Error::Invalid(
                    "the case has no tenants yet; run `sparrow profile --case <path>` (or \
                     `sparrow ingest`) first"
                        .to_string(),
                )),
                n => Err(Error::Invalid(format!(
                    "the case has {n} tenants; pass --tenant (one of: {})",
                    keys.join(", ")
                ))),
            }
        }
    }
}

/// Validate and normalize a domain: trim, lower-case, non-empty, no `@`, contains a `.`.
fn normalize_domain(domain: &str) -> Result<String> {
    let d = domain.trim().to_lowercase();
    if d.is_empty() || d.contains('@') || !d.contains('.') {
        return Err(Error::Invalid(format!("not a valid domain: {domain:?}")));
    }
    Ok(d)
}

/// Record an analyst decision about a tenant domain and rebuild `tenant_domains` for that
/// tenant immediately. Returns the normalized domain.
pub fn set_domain(
    case: &mut Case,
    tenant_key: Option<&str>,
    domain: &str,
    action: DomainAction,
    actor: &str,
) -> Result<String> {
    let domain = normalize_domain(domain)?;
    let tx = case.conn_mut().transaction()?;
    let key = only_tenant(&tx, tenant_key)?;
    tx.execute(
        "INSERT INTO tenant_domain_overrides (tenant_key, domain, action, actor) VALUES (?, ?, ?, ?)",
        params![key, domain, action.as_sql(), actor],
    )?;
    rebuild_domains(&tx, Some(&key))?;
    tx.commit()?;
    Ok(domain)
}

/// `tenant_domains` rows for `tenant_key` (all tenants when `None`), ordered by tenant then
/// domain.
pub fn list_domains(case: &Case, tenant_key: Option<&str>) -> Result<Vec<TenantDomain>> {
    let mut stmt = case.conn().prepare(
        "SELECT tenant_key, domain, CAST(source AS VARCHAR) FROM tenant_domains
         WHERE (CAST(? AS VARCHAR) IS NULL OR tenant_key = ?)
         ORDER BY tenant_key, domain",
    )?;
    let rows = stmt.query_map(params![tenant_key, tenant_key], |r| {
        Ok(TenantDomain {
            tenant_key: r.get(0)?,
            domain: r.get(1)?,
            source: r.get(2)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}
