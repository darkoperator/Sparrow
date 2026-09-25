//! The profile step (spec §2 "enrich → profile tenant"): everything Phase 4 derives from the
//! loaded evidence. It never changes evidence rows; it rewrites derived tables only, so it
//! can run any number of times (after every ingest, or `sparrow profile`).

pub mod availability;
pub mod capabilities;
pub mod identities;
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
    pub ip_intel: Option<IpIntelReport>,
    pub warnings: Vec<String>,
}

/// Re-derive the profile. Steps, in order (later tasks fill in the commented ones):
/// 1. data tables: capabilities (Task 2), operation_catalog (Task 9);
/// 2. tenants, collections.tenant_key, tenant_domains (Task 3);
/// 3. ip_intel (Task 7);
/// 4. identities (Task 8);
/// 5. tenant_capabilities (Task 5);
/// 6. evidence_availability snapshot (Task 6).
pub fn refresh(case: &mut Case, opts: &ProfileOptions) -> Result<ProfileReport> {
    let mut report = ProfileReport::default();
    let defs = crate::data::capabilities(&opts.dirs)?;
    report.capabilities = capabilities::store_definitions(case, &defs)?;

    let tx = case.conn_mut().transaction()?;
    report.tenants = tenant::resolve_tenants(&tx)?;
    if let Some(warning) = tenant::rebuild_domains(&tx, None)? {
        report.warnings.push(warning);
    }
    let ip_intel = crate::enrich::ip::refresh_ip_intel(&tx, &opts.dirs, opts.geoip_dir.as_deref())?;
    report.warnings.extend(ip_intel.warnings.clone());
    report.ip_intel = Some(ip_intel);
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
