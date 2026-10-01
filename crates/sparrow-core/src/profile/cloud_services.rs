//! Tenant-wide cloud services (derived table `cloud_services`): one definition, per tenant, that
//! SPW-ID-002 (hosting sign-in) and SPW-ID-003 (impossible travel) share.
//!
//! Third-party SaaS products that read a tenant on the users' behalf refresh tokens from their own
//! public-cloud backend (an Azure or AWS ASN, scripted user agents such as python-httpx), for many
//! users, every day. Those are NON-interactive sign-ins. An application is a tenant-wide cloud
//! service when, counting its non-interactive successful sign-ins, at least [`MIN_USERS`] distinct
//! users signed in from hosting ASNs on at least [`MIN_DAYS`] distinct UTC days AND those hosting
//! sign-ins are at least [`SHARE_PERCENT`] percent of the application's non-interactive successes.
//!
//! The profile is ESTABLISHED from a prefix of the history: `established_day` is the first UTC day at
//! whose end the counts up to and including that day meet the thresholds. A rule excuses only the
//! non-interactive hosting sign-ins of a later day, so an attacker whose later volume makes an
//! application look like a connector never excuses the earlier sign-ins, and an interactive sign-in
//! (an attacker in a browser) always counts. No application name or id is involved, and only KNOWN
//! successes (`error_code = 0`) count: an unknown result never helps establish a connector.

use crate::Result;
use duckdb::Connection;
use std::collections::{BTreeMap, BTreeSet};

pub const MIN_USERS: usize = 5;
pub const MIN_DAYS: usize = 3;
pub const SHARE_PERCENT: i64 = 80;

/// Rewrite `cloud_services` from `signins` and `ip_intel`; returns the number of services.
pub fn rebuild(conn: &Connection) -> Result<usize> {
    conn.execute_batch("DELETE FROM cloud_services")?;
    // (tenant, app) -> day -> (hosting users, hosting sign-ins, all sign-ins)
    type Daily = BTreeMap<i64, (BTreeSet<String>, i64, i64)>;
    let mut by_app: BTreeMap<(String, String), Daily> = BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT c.tenant_key, lower(g.app_id), epoch_ms(g.event_time) // 86400000,
                    lower(g.user_upn), coalesce(i.is_hosting, false), count(*)
             FROM signins g JOIN collections c ON c.collection_id = g.collection_id
             LEFT JOIN ip_intel i ON i.ip = g.ip
             WHERE c.tenant_key IS NOT NULL AND g.error_code = 0 AND NOT coalesce(g.is_interactive, true)
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
                r.get::<_, bool>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        for row in rows {
            let (tenant, app, day, user, hosting, n) = row?;
            let d = by_app
                .entry((tenant, app))
                .or_default()
                .entry(day)
                .or_default();
            d.2 += n;
            if hosting {
                d.0.insert(user);
                d.1 += n;
            }
        }
    }
    let mut n = 0;
    let mut stmt = conn.prepare(
        "INSERT INTO cloud_services
         (tenant_key, app_id, hosting_users, hosting_days, signins, hosting_signins, established_day)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )?;
    for ((tenant, app), days) in &by_app {
        let (mut users, mut hosting_days, mut hosting, mut all) =
            (BTreeSet::new(), 0usize, 0i64, 0i64);
        for (day, (u, h, a)) in days {
            users.extend(u.iter().cloned());
            if *h > 0 {
                hosting_days += 1;
            }
            hosting += h;
            all += a;
            if users.len() >= MIN_USERS
                && hosting_days >= MIN_DAYS
                && hosting * 100 >= all * SHARE_PERCENT
            {
                stmt.execute(duckdb::params![
                    tenant,
                    app,
                    users.len() as i64,
                    hosting_days as i64,
                    all,
                    hosting,
                    day
                ])?;
                n += 1;
                break;
            }
        }
    }
    Ok(n)
}
