//! Capability definitions (Task 2) and, per tenant, whether each is licensed (Task 5).

use crate::data::CapabilityDef;
use crate::{Case, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value;
use duckdb::{Connection, params};
use serde::Serialize;
use std::collections::HashMap;

/// A `VARCHAR[]` column read back as `Value::List`, flattened to strings (NULL elements dropped).
fn string_list(v: Value) -> Vec<String> {
    match v {
        Value::List(items) | Value::Array(items) => items
            .into_iter()
            .filter_map(|i| match i {
                Value::Text(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Replace the `capabilities` table with `defs`. Returns the number of rows.
pub fn store_definitions(case: &mut Case, defs: &[CapabilityDef]) -> Result<usize> {
    let tx = case.conn_mut().transaction()?;
    tx.execute("DELETE FROM capabilities", [])?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO capabilities (capability_id, title, baseline, unlocked_by_service_plans,
                 hawk_license_tiers, retention_days, evidence, notes, sources, as_of, origin)
             VALUES (?, ?, ?, CAST(CAST(? AS JSON) AS VARCHAR[]), CAST(CAST(? AS JSON) AS VARCHAR[]),
                     ?, CAST(CAST(? AS JSON) AS VARCHAR[]), ?, CAST(CAST(? AS JSON) AS VARCHAR[]),
                     CAST(? AS DATE), ?)",
        )?;
        let list = |v: &Vec<String>| serde_json::to_string(v).expect("strings serialize");
        for d in defs {
            stmt.execute(params![
                d.id,
                d.title,
                d.baseline,
                list(&d.unlocked_by_service_plans),
                list(&d.hawk_license_tiers),
                d.retention_days.map(i64::from),
                list(&d.evidence),
                d.notes,
                list(&d.sources),
                d.as_of,
                d.origin
            ])?;
        }
    }
    tx.commit()?;
    Ok(defs.len())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapStatus {
    Licensed,
    NotLicensed,
    Unknown,
}

impl CapStatus {
    fn as_sql(self) -> &'static str {
        match self {
            CapStatus::Licensed => "licensed",
            CapStatus::NotLicensed => "not_licensed",
            CapStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    High,
    Low,
}

impl Confidence {
    fn as_sql(self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Low => "low",
        }
    }
}

/// One piece of evidence about a tenant's capability.
#[derive(Debug, Clone)]
struct Claim {
    status: CapStatus,
    confidence: Confidence,
    basis: String,
}

/// Rank: licensed-high, not_licensed-high, licensed-low, not_licensed-low (ascending: strongest
/// first, since `Confidence::High < Confidence::Low` and `CapStatus::Licensed < NotLicensed`).
fn rank(c: &Claim) -> (Confidence, CapStatus) {
    (c.confidence, c.status)
}

struct CapDef {
    id: String,
    baseline: bool,
    unlocked_by_service_plans: Vec<String>,
    hawk_license_tiers: Vec<String>,
    retention_days: Option<i64>,
}

/// Re-derive `tenant_capabilities` for every tenant x capability from, strongest first: a
/// high-confidence licence list, evidence signals, the Hawk.log tier, and baseline assumptions
/// (spec `task-5-brief.md`). Rewrites the whole table; returns the row count.
pub fn derive(conn: &Connection) -> Result<usize> {
    let defs: Vec<CapDef> = {
        let mut stmt = conn.prepare(
            "SELECT capability_id, baseline, unlocked_by_service_plans, hawk_license_tiers, retention_days
             FROM capabilities",
        )?;
        stmt.query_map([], |r| {
            Ok(CapDef {
                id: r.get(0)?,
                baseline: r.get(1)?,
                unlocked_by_service_plans: string_list(r.get(2)?),
                hawk_license_tiers: string_list(r.get(3)?),
                retention_days: r.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };

    let tenants: Vec<String> = {
        let mut stmt = conn.prepare("SELECT tenant_key FROM tenant")?;
        stmt.query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };

    let mut claims: HashMap<(String, String), Vec<Claim>> = HashMap::new();
    let mut push = |tenant_key: &str, capability_id: &str, claim: Claim| {
        claims
            .entry((tenant_key.to_string(), capability_id.to_string()))
            .or_default()
            .push(claim);
    };

    // High-confidence licence lists: the tenant's newest collection with any high-confidence row.
    {
        let mut stmt = conn.prepare(
            "WITH lic AS (
                 SELECT c.tenant_key, l.sku_part_number, l.service_plans, l.capability_status,
                        c.collected_at, c.collection_id AS cid
                 FROM licenses l JOIN collections c ON c.collection_id = l.collection_id
                 WHERE l.confidence = 'high'
             ),
             newest AS (
                 SELECT tenant_key, cid FROM lic
                 QUALIFY row_number() OVER (PARTITION BY tenant_key
                                            ORDER BY collected_at DESC NULLS LAST, cid DESC) = 1
             )
             SELECT lic.tenant_key, lic.sku_part_number, upper(trim(p.plan)) AS plan
             FROM lic JOIN newest USING (tenant_key, cid)
             CROSS JOIN UNNEST(coalesce(lic.service_plans, []::VARCHAR[])) AS p(plan)
             WHERE lic.capability_status IS NULL OR lic.capability_status = 'Enabled'",
        )?;
        let rows: Vec<(String, Option<String>, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Per tenant: plan (upper, trimmed) -> the first SKU that carries it.
        let mut tenant_plans: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (tenant_key, sku, plan) in &rows {
            tenant_plans
                .entry(tenant_key.clone())
                .or_default()
                .entry(plan.clone())
                .or_insert_with(|| sku.clone().unwrap_or_else(|| "?".to_string()));
        }

        for (tenant_key, plans) in &tenant_plans {
            for def in &defs {
                if def.unlocked_by_service_plans.is_empty() {
                    continue;
                }
                let required: Vec<String> = def
                    .unlocked_by_service_plans
                    .iter()
                    .map(|p| p.trim().to_uppercase())
                    .collect();
                let matched = required
                    .iter()
                    .find_map(|p| plans.get(p).map(|sku| (p, sku)));
                let claim = match matched {
                    Some((plan, sku)) => Claim {
                        status: CapStatus::Licensed,
                        confidence: Confidence::High,
                        basis: format!("SKU {sku} includes {plan}"),
                    },
                    None => Claim {
                        status: CapStatus::NotLicensed,
                        confidence: Confidence::High,
                        basis: format!(
                            "no subscribed SKU includes {}",
                            def.unlocked_by_service_plans.join(", ")
                        ),
                    },
                };
                push(tenant_key, &def.id, claim);
            }
        }
    }

    // Evidence signal: signin_risk_visible / signin_risk_hidden -> identity_protection.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key,
                    count(*) FILTER (WHERE lower(s.risk_level_during) IN ('none','low','medium','high')
                                        OR lower(s.risk_level_aggregated) IN ('none','low','medium','high')) AS visible,
                    count(*) FILTER (WHERE lower(s.risk_level_during) = 'hidden' OR lower(s.risk_level_aggregated) = 'hidden') AS hidden
             FROM signins s JOIN collections c ON c.collection_id = s.collection_id
             GROUP BY c.tenant_key",
        )?;
        let rows: Vec<(String, i64, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (tenant_key, visible, hidden) in rows {
            if visible > 0 {
                push(
                    &tenant_key,
                    "identity_protection",
                    Claim {
                        status: CapStatus::Licensed,
                        confidence: Confidence::High,
                        basis: format!(
                            "{visible} sign-ins carry a risk level (Entra ID P2 shows risk levels; below P2 they read hidden)"
                        ),
                    },
                );
            } else if hidden > 0 {
                push(
                    &tenant_key,
                    "identity_protection",
                    Claim {
                        status: CapStatus::NotLicensed,
                        confidence: Confidence::High,
                        basis: "sign-ins report risk as hidden (Entra ID P2 not active when they were collected)"
                            .to_string(),
                    },
                );
            }
        }
    }

    // Evidence signal: graph_signins -> entra_id_p1.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, count(DISTINCT rs.record_key)
             FROM record_sources rs JOIN source_files sf ON sf.file_id = rs.file_id
             JOIN collections c ON c.collection_id = sf.collection_id
             WHERE rs.table_name = 'signins' AND sf.artifact_type IS NOT NULL AND sf.artifact_type NOT LIKE 'portal.%'
             GROUP BY c.tenant_key",
        )?;
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (tenant_key, n) in rows {
            if n > 0 {
                push(
                    &tenant_key,
                    "entra_id_p1",
                    Claim {
                        status: CapStatus::Licensed,
                        confidence: Confidence::High,
                        basis: format!(
                            "{n} sign-ins were downloaded through Microsoft Graph, which needs Entra ID P1 or P2"
                        ),
                    },
                );
            }
        }
    }

    // Evidence signal: no_premium_license -> entra_id_p1 and identity_protection.
    {
        let mut stmt = conn.prepare(
            "SELECT tenant_key FROM tenant_settings_current
             WHERE source = 'entra_security_defaults' AND lower(name) = 'haspremiumlicense'
               AND lower(trim(value->>'$')) = 'no'",
        )?;
        let rows: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for tenant_key in rows {
            let basis = "Microsoft-Extractor-Suite found no E3/E5-named SKU and no AAD_PREMIUM / \
                          AAD_PREMIUM_P2 plan (EntraSecurityDefaults HasPremiumLicense = No)"
                .to_string();
            for capability_id in ["entra_id_p1", "identity_protection"] {
                push(
                    &tenant_key,
                    capability_id,
                    Claim {
                        status: CapStatus::NotLicensed,
                        confidence: Confidence::High,
                        basis: basis.clone(),
                    },
                );
            }
        }
    }

    // Evidence signal: ual_beyond_standard_retention -> audit_premium.
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, min(epoch(u.event_time))::BIGINT
             FROM ual_events u JOIN collections c ON c.collection_id = u.collection_id
             WHERE c.collected_at IS NOT NULL
               AND u.workload IN ('Exchange', 'AzureActiveDirectory', 'SharePoint', 'OneDrive')
               AND epoch(u.event_time) < epoch(c.collected_at) - 182 * 86400
             GROUP BY c.tenant_key",
        )?;
        let rows: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (tenant_key, epoch_secs) in rows {
            let date = DateTime::<Utc>::from_timestamp(epoch_secs, 0)
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            push(
                &tenant_key,
                "audit_premium",
                Claim {
                    status: CapStatus::Licensed,
                    confidence: Confidence::High,
                    basis: format!(
                        "UAL records from {date} are older than 180 days at collection time: Audit (Premium) retention"
                    ),
                },
            );
        }
    }

    // Hawk tier: newest hawk_log row per tenant.
    {
        let mut stmt = conn.prepare(
            "WITH hawk AS (
                 SELECT c.tenant_key, l.license_tier, c.collected_at, c.collection_id AS cid
                 FROM licenses l JOIN collections c ON c.collection_id = l.collection_id
                 WHERE l.source = 'hawk_log'
             ),
             newest AS (
                 SELECT tenant_key, cid FROM hawk
                 QUALIFY row_number() OVER (PARTITION BY tenant_key
                                            ORDER BY collected_at DESC NULLS LAST, cid DESC) = 1
             )
             SELECT hawk.tenant_key, hawk.license_tier
             FROM hawk JOIN newest USING (tenant_key, cid)",
        )?;
        let rows: Vec<(String, Option<String>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (tenant_key, tier) in rows {
            let Some(tier) = tier else { continue };
            let tier_upper = tier.trim().to_uppercase();
            for def in &defs {
                if def
                    .hawk_license_tiers
                    .iter()
                    .any(|t| t.trim().to_uppercase() == tier_upper)
                {
                    push(
                        &tenant_key,
                        &def.id,
                        Claim {
                            status: CapStatus::Licensed,
                            confidence: Confidence::Low,
                            basis: format!(
                                "Hawk.log reports licence tier {tier} (Hawk matches SKU-name substrings; not proof)"
                            ),
                        },
                    );
                }
            }
        }
    }

    // Baseline assumptions, for every tenant.
    for tenant_key in &tenants {
        for def in &defs {
            if def.baseline {
                push(
                    tenant_key,
                    &def.id,
                    Claim {
                        status: CapStatus::Licensed,
                        confidence: Confidence::Low,
                        basis: "assumed: part of every Microsoft 365 plan with Exchange Online"
                            .to_string(),
                    },
                );
            }
        }
    }

    conn.execute("DELETE FROM tenant_capabilities", [])?;
    let mut inserted = 0usize;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO tenant_capabilities (tenant_key, capability_id, status, confidence, basis, retention_days)
             VALUES (?, ?, CAST(? AS capability_status), CAST(? AS license_confidence), ?, ?)",
        )?;
        for tenant_key in &tenants {
            for def in &defs {
                let key = (tenant_key.clone(), def.id.clone());
                let mut tenant_claims = claims.remove(&key).unwrap_or_default();
                let (status, confidence, basis) = if tenant_claims.is_empty() {
                    (
                        CapStatus::Unknown,
                        None,
                        "no licence list or evidence about this capability".to_string(),
                    )
                } else {
                    tenant_claims.sort_by_key(rank);
                    let winner = tenant_claims[0].clone();
                    let mut basis = winner.basis.clone();
                    if winner.status == CapStatus::Licensed && winner.confidence == Confidence::High
                    {
                        if let Some(disagreeing) = tenant_claims.iter().find(|c| {
                            c.status == CapStatus::NotLicensed && c.confidence == Confidence::High
                        }) {
                            basis = format!("{basis}; disagrees: {}", disagreeing.basis);
                        }
                    }
                    (winner.status, Some(winner.confidence), basis)
                };
                stmt.execute(params![
                    tenant_key,
                    def.id,
                    status.as_sql(),
                    confidence.map(Confidence::as_sql),
                    basis,
                    def.retention_days,
                ])?;
                inserted += 1;
            }
        }
    }
    Ok(inserted)
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantCapability {
    pub tenant_key: String,
    pub capability_id: String,
    pub status: String,
    pub confidence: Option<String>,
    pub basis: String,
    pub retention_days: Option<i64>,
}

/// `tenant_capabilities` rows for `tenant_key`, ordered by `capability_id`.
pub fn tenant_capabilities(conn: &Connection, tenant_key: &str) -> Result<Vec<TenantCapability>> {
    let mut stmt = conn.prepare(
        "SELECT tenant_key, capability_id, CAST(status AS VARCHAR), CAST(confidence AS VARCHAR), basis, retention_days
         FROM tenant_capabilities WHERE tenant_key = ? ORDER BY capability_id",
    )?;
    let rows = stmt.query_map(params![tenant_key], |r| {
        Ok(TenantCapability {
            tenant_key: r.get(0)?,
            capability_id: r.get(1)?,
            status: r.get(2)?,
            confidence: r.get(3)?,
            basis: r.get(4)?,
            retention_days: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}
