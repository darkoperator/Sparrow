//! Password-spray sources (derived table `spray_sources`): one definition, per tenant, that every
//! detection rule shares.
//!
//! An address is a spray source when both hold, counting the tenant's sign-ins in the case:
//! - at least [`MIN_USERS`] distinct users have an interactive credential failure from it and NEVER a
//!   known success (`error_code = 0`) from it ("failed-only" users);
//! - those failed-only users outnumber the distinct users with a known success from it.
//!
//! Spray is distributed: each source touches a handful of accounts and none of them gets in from
//! there, so failed-only users are what a spray looks like. An office NAT or VPN egress is where
//! users mistype a password and then succeed (they are not failed-only), where a few stale devices of
//! disabled accounts keep failing next to many more users who sign in (failed-only users do not
//! outnumber the successes), and so is not a source; a capture is a window, so no history before the
//! first failure is assumed. A proxy that sprays many accounts and takes over a few stays a source,
//! because the taken accounts are fewer than the failed-only ones. The source's network type is not
//! part of the definition (compromised ISP routers and residential proxies spray as much as hosting
//! providers) and no GeoIP is needed.
//!
//! A failure is an INTERACTIVE sign-in (a row of unknown kind counts as interactive: a portal file whose
//! name says neither leaves `is_interactive` NULL, and a ROPC spray is interactive) whose `error_code` is in the shared `credential_failure_codes`
//! list (rules/lists: rejected credentials, 50126 / 50053 / 50034 / ...), the same list SPW-ID-005 and
//! SPW-ID-006 read. Conditional Access blocks, token-refresh errors, Seamless SSO errors, MFA prompts
//! and non-interactive rows are not credential failures. Only KNOWN results are judged: a NULL result
//! is never a failure and never a success.

use crate::Result;
use duckdb::Connection;

/// Failed-only users a source needs.
pub const MIN_USERS: i64 = 5;

/// The credential-failure codes of the built-in (or custom) `credential_failure_codes` list.
pub fn credential_failure_codes(dirs: &crate::data::DataDirs) -> Result<Vec<i64>> {
    crate::detect::load::list_values(dirs, "credential_failure_codes")?
        .iter()
        .map(|v| {
            v.parse::<i64>().map_err(|_| {
                crate::Error::Invalid(format!(
                    "credential_failure_codes: {v:?} is not an error code"
                ))
            })
        })
        .collect()
}

/// Rewrite `spray_sources` from `signins` (tenant by the collection's `tenant_key`), failing on
/// `codes`; returns the number of sources.
pub fn rebuild(conn: &Connection, codes: &[i64]) -> Result<usize> {
    conn.execute_batch("DELETE FROM spray_sources")?;
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
    let n = conn.execute(
        &format!(
            "INSERT INTO spray_sources
             WITH s AS (
               SELECT c.tenant_key, lower(g.user_upn) AS upn, g.ip, g.error_code, g.event_time,
                      coalesce(g.is_interactive, true) AS interactive
               FROM signins g JOIN collections c ON c.collection_id = g.collection_id
               WHERE c.tenant_key IS NOT NULL AND g.ip IS NOT NULL AND g.ip <> ''
                 AND g.user_upn IS NOT NULL AND g.user_upn <> '' AND g.event_time IS NOT NULL
             ),
             fail AS (
               SELECT tenant_key, ip, upn, count(*) AS n, min(event_time) AS first_t,
                      max(event_time) AS last_t
               FROM s WHERE interactive AND error_code IN ({codes})
               GROUP BY tenant_key, ip, upn
             ),
             ok AS (
               SELECT DISTINCT tenant_key, ip, upn FROM s WHERE error_code = 0
             ),
             src AS (
               SELECT f.tenant_key, f.ip, count(*) AS users_targeted, sum(f.n) AS failures,
                      min(f.first_t) AS first_failure, max(f.last_t) AS last_failure,
                      count(*) FILTER (WHERE o.upn IS NULL) AS failed_only_users
               FROM fail f LEFT JOIN ok o
                 ON o.tenant_key = f.tenant_key AND o.ip = f.ip AND o.upn = f.upn
               GROUP BY f.tenant_key, f.ip
             ),
             succ AS (
               SELECT tenant_key, ip, count(*) AS success_users FROM ok GROUP BY tenant_key, ip
             )
             SELECT src.tenant_key, src.ip, src.users_targeted, CAST(src.failures AS BIGINT),
                    src.first_failure, src.last_failure, src.failed_only_users,
                    coalesce(succ.success_users, 0)
             FROM src LEFT JOIN succ ON succ.tenant_key = src.tenant_key AND succ.ip = src.ip
             WHERE src.failed_only_users >= {MIN_USERS}
               AND src.failed_only_users > coalesce(succ.success_users, 0)
             ORDER BY src.tenant_key, src.ip"
        ),
        [],
    )?;
    Ok(n)
}
