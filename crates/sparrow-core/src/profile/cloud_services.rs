//! Tenant-wide cloud services (derived table `cloud_services`): one definition, per tenant, that
//! SPW-ID-002 (hosting sign-in) and SPW-ID-003 (impossible travel) share.
//!
//! Third-party SaaS products that read a tenant on the users' behalf sign in from their own
//! public-cloud backend (an Azure or AWS ASN, scripted user agents such as python-httpx), for many
//! users, every day. An application is a tenant-wide cloud service when, in the tenant, at least
//! [`MIN_USERS`] distinct users have successful sign-ins to it from hosting ASNs on at least
//! [`MIN_DAYS`] distinct UTC days AND those hosting sign-ins are at least [`SHARE_PERCENT`] percent
//! of the application's successful sign-ins. No application name or id is involved. Only KNOWN
//! successes (`error_code = 0`) count: an unknown result never excuses an application.

use crate::Result;
use duckdb::Connection;

pub const MIN_USERS: i64 = 5;
pub const MIN_DAYS: i64 = 3;
pub const SHARE_PERCENT: i64 = 80;

/// Rewrite `cloud_services` from `signins` and `ip_intel`; returns the number of services.
pub fn rebuild(conn: &Connection) -> Result<usize> {
    conn.execute_batch("DELETE FROM cloud_services")?;
    let n = conn.execute(
        &format!(
            "INSERT INTO cloud_services
             SELECT c.tenant_key, lower(g.app_id) AS app_id,
                    count(DISTINCT lower(g.user_upn)) FILTER (WHERE coalesce(i.is_hosting, false)),
                    count(DISTINCT epoch_ms(g.event_time) // 86400000)
                      FILTER (WHERE coalesce(i.is_hosting, false)),
                    count(*),
                    count(*) FILTER (WHERE coalesce(i.is_hosting, false))
             FROM signins g JOIN collections c ON c.collection_id = g.collection_id
             LEFT JOIN ip_intel i ON i.ip = g.ip
             WHERE c.tenant_key IS NOT NULL AND g.error_code = 0 AND g.app_id IS NOT NULL
               AND g.app_id <> '' AND g.user_upn IS NOT NULL AND g.event_time IS NOT NULL
             GROUP BY c.tenant_key, lower(g.app_id)
             HAVING count(DISTINCT lower(g.user_upn)) FILTER (WHERE coalesce(i.is_hosting, false)) >= {MIN_USERS}
                AND count(DISTINCT epoch_ms(g.event_time) // 86400000)
                      FILTER (WHERE coalesce(i.is_hosting, false)) >= {MIN_DAYS}
                AND count(*) FILTER (WHERE coalesce(i.is_hosting, false)) * 100 >= count(*) * {SHARE_PERCENT}
             ORDER BY c.tenant_key, lower(g.app_id)"
        ),
        [],
    )?;
    Ok(n)
}
