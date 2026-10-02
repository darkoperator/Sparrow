//! Tenant-wide cloud services (derived table `cloud_services`): one definition, per tenant, that
//! SPW-ID-002 (hosting sign-in) and SPW-ID-003 (impossible travel) share.
//!
//! Third-party SaaS products that read a tenant on the users' behalf sign users in from their own
//! public-cloud backend (an Azure or AWS ASN, scripted user agents), for many users, every day; the
//! portal's InteractiveSignIns export records those rows as INTERACTIVE, so interactive and
//! non-interactive sign-ins both count. A service is an (application, hosting ASN) pair: at least
//! [`MIN_USERS`] distinct users with known successes (`error_code = 0`) to the application from that
//! hosting ASN on at least [`MIN_DAYS`] distinct UTC days, and those sign-ins are at least
//! [`SHARE_PERCENT`] percent of the application's known successes.
//!
//! An (application, ASN) pair does NOT qualify when either holds: any of its users (a user with a known
//! success to the application from that ASN) has a credential failure (interactive or of unknown kind,
//! the shared `credential_failure_codes` list) from a spray source of the tenant, or any credential
//! failure to the application comes from that ASN. Accounts taken from a spray, or typed wrongly on a
//! VPS first, never make their VPS a connector. Residual, documented: five or more PHISHED (not
//! sprayed) accounts used from one VPS on the same application for three days with no failures look
//! exactly like a connector and are excused.
//!
//! The profile is established from the WHOLE case, no prefix: a capture is a window, and a connector in
//! use since before it starts would only be "established" a few days before the window ends, leaving
//! every earlier day counting. A rule excuses every sign-in to that application from that same ASN; a
//! spray source and a UAL UserLoggedIn always count, and the key is (application, ASN), so the same
//! application from another hosting ASN counts. Residual, documented: an attacker who uses the same
//! application from the same cloud ASN as an established connector is excused, and a connector's first
//! days (cold start) are excused too. No application name or id is involved, and an unknown result
//! never helps establish a connector.

use crate::Result;
use duckdb::Connection;
use std::collections::{BTreeMap, BTreeSet};

pub const MIN_USERS: usize = 5;
pub const MIN_DAYS: usize = 3;
pub const SHARE_PERCENT: i64 = 80;

/// Rewrite `cloud_services` from `signins`, `ip_intel` and `spray_sources` (rebuilt first), where a
/// credential failure is one of `codes`; returns the number of services.
pub fn rebuild(conn: &Connection, codes: &[i64]) -> Result<usize> {
    conn.execute_batch("DELETE FROM cloud_services")?;
    // Per (tenant, app): day -> all known successes; per (tenant, app, hosting asn): day -> (users, n).
    type Totals = BTreeMap<i64, i64>;
    type PerAsn = BTreeMap<i64, (BTreeSet<String>, i64)>;
    let mut totals: BTreeMap<(String, String), Totals> = BTreeMap::new();
    let mut by_asn: BTreeMap<(String, String, i64), PerAsn> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, lower(g.app_id), epoch_ms(g.event_time) // 86400000,
                    lower(g.user_upn), CASE WHEN coalesce(i.is_hosting, false) THEN i.asn END,
                    count(*)
             FROM signins g JOIN collections c ON c.collection_id = g.collection_id
             LEFT JOIN ip_intel i ON i.ip = g.ip
             WHERE c.tenant_key IS NOT NULL AND g.error_code = 0
               AND g.app_id IS NOT NULL AND g.app_id <> '' AND g.user_upn IS NOT NULL
               AND g.event_time IS NOT NULL
             GROUP BY 1, 2, 3, 4, 5",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows {
            let (tenant, app, day, user, asn, n) = row?;
            *totals
                .entry((tenant.clone(), app.clone()))
                .or_default()
                .entry(day)
                .or_default() += n;
            if let Some(asn) = asn {
                let d = by_asn
                    .entry((tenant, app, asn))
                    .or_default()
                    .entry(day)
                    .or_default();
                d.0.insert(user);
                d.1 += n;
            }
        }
    }
    let codes = codes
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let codes = if codes.is_empty() {
        "NULL".to_string()
    } else {
        codes
    };
    // Disqualifiers. Users with a credential failure from a spray source of their tenant (sprayed).
    let mut sprayed: BTreeSet<(String, String)> = BTreeSet::new();
    {
        let mut stmt = conn.prepare(&format!(
            "SELECT DISTINCT c.tenant_key, lower(g.user_upn)
             FROM signins g JOIN collections c ON c.collection_id = g.collection_id
             JOIN spray_sources p ON p.tenant_key = c.tenant_key AND p.ip = g.ip
             WHERE c.tenant_key IS NOT NULL AND g.user_upn IS NOT NULL
               AND coalesce(g.is_interactive, true) AND g.error_code IN ({codes})"
        ))?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            sprayed.insert(row?);
        }
    }
    // (tenant, app, asn) with a credential failure to the app from an address of that ASN.
    let mut failed_from: BTreeSet<(String, String, i64)> = BTreeSet::new();
    {
        let mut stmt = conn.prepare(&format!(
            "SELECT DISTINCT c.tenant_key, lower(g.app_id), i.asn
             FROM signins g JOIN collections c ON c.collection_id = g.collection_id
             JOIN ip_intel i ON i.ip = g.ip
             WHERE c.tenant_key IS NOT NULL AND g.app_id IS NOT NULL AND g.app_id <> ''
               AND i.asn IS NOT NULL
               AND coalesce(g.is_interactive, true) AND g.error_code IN ({codes})"
        ))?;
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })? {
            failed_from.insert(row?);
        }
    }
    let mut n = 0;
    let mut stmt = conn.prepare(
        "INSERT INTO cloud_services
         (tenant_key, app_id, asn, hosting_users, hosting_days, signins, hosting_signins)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )?;
    for ((tenant, app, asn), days) in &by_asn {
        let users: BTreeSet<&String> = days.values().flat_map(|(u, _)| u.iter()).collect();
        let hosting: i64 = days.values().map(|(_, n)| n).sum();
        let all: i64 = totals[&(tenant.clone(), app.clone())].values().sum();
        let disqualified = failed_from.contains(&(tenant.clone(), app.clone(), *asn))
            || users
                .iter()
                .any(|u| sprayed.contains(&(tenant.clone(), (*u).clone())));
        if !disqualified
            && users.len() >= MIN_USERS
            && days.len() >= MIN_DAYS
            && hosting * 100 >= all * SHARE_PERCENT
        {
            stmt.execute(duckdb::params![
                tenant,
                app,
                asn,
                users.len() as i64,
                days.len() as i64,
                all,
                hosting
            ])?;
            n += 1;
        }
    }
    Ok(n)
}
