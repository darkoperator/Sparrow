//! The profile step (spec §2 "enrich → profile tenant"): everything Phase 4 derives from the
//! loaded evidence. It never changes evidence rows; it rewrites derived tables only, so it
//! can run any number of times (after every ingest, or `sparrow profile`).

pub mod availability;
pub mod capabilities;
pub mod catalog;
pub mod cloud_services;
pub mod identities;
pub mod spray;
pub mod tenant;

use crate::data::DataDirs;
use crate::enrich::ip::IpIntelReport;
use crate::{Case, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct ProfileOptions {
    pub dirs: DataDirs,
    /// Folder holding MaxMind GeoLite2/GeoIP2 City and ASN `.mmdb` files (Task 7).
    pub geoip_dir: Option<PathBuf>,
    /// Evaluation time for retention decisions; None = now.
    pub as_of: Option<DateTime<Utc>>,
}

impl ProfileOptions {
    pub fn now(&self) -> DateTime<Utc> {
        self.as_of.unwrap_or_else(Utc::now)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProfileReport {
    pub capabilities: usize,
    pub tenants: usize,
    pub identities: usize,
    /// Password-spray source addresses (`spray_sources`).
    pub spray_sources: usize,
    /// Tenant-wide cloud services (`cloud_services`).
    pub cloud_services: usize,
    pub ip_intel: Option<IpIntelReport>,
    pub warnings: Vec<String>,
}

/// Collections the profile has not assigned to a tenant (`collections.tenant_key` NULL): the
/// profile step failed after an ingest, or never ran after new collections were loaded. Reports
/// that read the derived tables (`sparrow capabilities`, `sparrow summary`) are stale while any
/// exist. Sorted by collection id.
pub fn unprofiled_collections(conn: &duckdb::Connection) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare(
        "SELECT collection_id FROM collections WHERE tenant_key IS NULL ORDER BY collection_id",
    )?;
    let ids = stmt
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<Vec<i64>, _>>()?;
    Ok(ids)
}

/// Re-derive the profile. Steps, in order (later tasks fill in the commented ones):
/// 1. data tables: capabilities (Task 2), operation_catalog (Task 9);
/// 2. tenants, collections.tenant_key, tenant_domains (Task 3);
/// 3. ip_intel (Task 7);
/// 4. spray_sources (after ip_intel, before identities), identities (Task 8);
/// 5. tenant_capabilities (Task 5);
/// 6. evidence_availability snapshot (Task 6).
pub fn refresh(case: &mut Case, opts: &ProfileOptions) -> Result<ProfileReport> {
    case.ensure_usable()?;
    let mut report = ProfileReport::default();
    let defs = crate::data::capabilities(&opts.dirs)?;
    let ops = crate::data::operation_catalog(&opts.dirs)?;

    // One transaction for every derived table, the data tables included: a failed profile
    // never leaves new capability or catalog rows next to stale tenants and availability.
    let tx = case.conn_mut().transaction()?;
    report.capabilities = capabilities::store_definitions(&tx, &defs)?;
    catalog::store(&tx, &ops)?;
    report.tenants = tenant::resolve_tenants(&tx)?;
    report
        .warnings
        .extend(tenant::unidentified_collection_warnings(&tx)?);
    if let Some(warning) = tenant::rebuild_domains(&tx, None)? {
        report.warnings.push(warning);
    }
    let ip_intel = crate::enrich::ip::refresh_ip_intel(&tx, &opts.dirs, opts.geoip_dir.as_deref())?;
    report.warnings.extend(ip_intel.warnings.clone());
    report.ip_intel = Some(ip_intel);
    report.spray_sources = spray::rebuild(&tx, &spray::credential_failure_codes(&opts.dirs)?)?;
    report.cloud_services = cloud_services::rebuild(&tx)?;
    let ids = identities::rebuild(&tx)?;
    report.identities = ids.identities;
    if ids.conflicts > 0 {
        report.warnings.push(format!(
            "{} identifiers link to more than one Entra object id (e.g. a UPN reused after the \
             account was recreated); each stays with the first",
            ids.conflicts
        ));
    }
    capabilities::derive(&tx)?;
    availability::snapshot(&tx, opts.now())?;
    tx.commit()?;

    Ok(report)
}
