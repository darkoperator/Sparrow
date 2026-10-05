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
//! An (application, ASN) pair does NOT qualify when either holds:
//! (a) SPRAYED users make up at least [`SPRAYED_PERCENT`] percent of its users (a user with a known
//!     success to the application from that ASN), or at least [`SPRAYED_USERS`] of them are sprayed; a
//!     sprayed user has a credential failure (interactive or of unknown kind, the shared
//!     `credential_failure_codes` list) from a spray source of the tenant; or
//! (b) at least [`FAILING_USERS`] distinct users (any user, not only the pair's) have a credential
//!     failure of that kind to the application from that ASN.
//! A failure row with no user name never counts toward (b) (Entra records the typed name for unknown
//! users, so this should not lose real failures).
//! Accounts taken from a spray, or typed wrongly on a VPS first, never make their VPS a connector, but a
//! departed account (50057, 50034) retried by a device, or one or two sprayed users, no longer take a
//! real connector's findings back. Residuals, documented, exactly what is excused:
//! - up to 2 sprayed users, while they are under 20% of the pair's users (so only when the pair has 11 or
//!   more users): used from the connector's own (application, ASN) from an address that is not itself a
//!   spray source, they are reported by NEITHER ID-002, ID-003 NOR ID-005 (ID-005 reads only successes
//!   from a spray-source address);
//! - up to 2 distinct users with credential failures from the ASN to the application;
//! - five or more PHISHED (not sprayed) accounts used from one VPS on the same application for three
//!   days with no failures, which look exactly like a connector.
//!
//! A Microsoft FIRST-PARTY application (the `microsoft_first_party_apps` list: Office, Outlook, Exchange
//! Online, SharePoint, Teams, OneDrive, the Azure and Graph tools, ids from public Microsoft Learn pages)
//! never qualifies, whatever its users or days: a real connector is a third-party application, while
//! accounts phished and used from a VPS sign in to Office and Outlook. Residual, documented: an
//! attacker's third-party application (it needs a consent, which APP-001 / APP-002 report) and a
//! first-party application the list does not have.
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
/// Disqualifier (a): sprayed users are at least this percent of the pair's users, ...
pub const SPRAYED_PERCENT: usize = 20;
/// ... or at least this many of them are sprayed.
pub const SPRAYED_USERS: usize = 3;
/// Disqualifier (b): this many distinct users with an interactive credential failure from the ASN.
pub const FAILING_USERS: usize = 3;
/// The `rules/lists` list of Microsoft first-party application ids no (application, ASN) pair of which
/// is ever a cloud service.
pub const FIRST_PARTY_LIST: &str = "microsoft_first_party_apps";

/// The built-in (or custom) first-party application ids, lower-cased.
pub fn first_party_apps(dirs: &crate::data::DataDirs) -> Result<Vec<String>> {
    Ok(crate::detect::load::list_values(dirs, FIRST_PARTY_LIST)?
        .into_iter()
        .map(|v| v.trim().to_lowercase())
        .collect())
}

/// Rewrite `cloud_services` from `signins`, `ip_intel` and `spray_sources` (rebuilt first), where a
/// credential failure is one of `codes` and an application in `first_party` (lower-case ids) is never a
/// service; returns the number of services.
pub fn rebuild(conn: &Connection, codes: &[i64], first_party: &[String]) -> Result<usize> {
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
    // (tenant, app, asn) -> the distinct users with a credential failure to the app from that ASN.
    let mut failed_from: BTreeMap<(String, String, i64), BTreeSet<String>> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(&format!(
            "SELECT DISTINCT c.tenant_key, lower(g.app_id), i.asn, lower(g.user_upn)
             FROM signins g JOIN collections c ON c.collection_id = g.collection_id
             JOIN ip_intel i ON i.ip = g.ip
             WHERE c.tenant_key IS NOT NULL AND g.app_id IS NOT NULL AND g.app_id <> ''
               AND i.asn IS NOT NULL AND g.user_upn IS NOT NULL
               AND coalesce(g.is_interactive, true) AND g.error_code IN ({codes})"
        ))?;
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })? {
            let (tenant, app, asn, user) = row?;
            failed_from
                .entry((tenant, app, asn))
                .or_default()
                .insert(user);
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
        let n_sprayed = users
            .iter()
            .filter(|u| sprayed.contains(&(tenant.clone(), (*u).to_string())))
            .count();
        let n_failing = failed_from
            .get(&(tenant.clone(), app.clone(), *asn))
            .map_or(0, BTreeSet::len);
        let disqualified = first_party.iter().any(|a| a == app)
            || (n_sprayed > 0 && n_sprayed * 100 >= users.len() * SPRAYED_PERCENT)
            || n_sprayed >= SPRAYED_USERS
            || n_failing >= FAILING_USERS;
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
