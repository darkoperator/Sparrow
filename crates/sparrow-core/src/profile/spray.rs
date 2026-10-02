//! Password-spray sources (derived table `spray_sources`): one definition, per tenant, that every
//! detection rule shares.
//!
//! For each (address, user) with an interactive credential failure from the address, the user is
//! EXCUSED only if they have a known success (`error_code = 0`) from that address either BEFORE their
//! first credential failure there (the address was already theirs) or within [`TYPO_MINUTES`] minutes
//! AFTER one of their failures there (a typo correction). Every other failed user is a SPRAYED user,
//! including a user whose only successes there come later (the takeover pattern: the attacker used the
//! account it sprayed). An address is a spray source when
//! - at least [`MIN_USERS`] users were sprayed, AND
//! - the sprayed users outnumber the excusing users: the distinct users with a known success from the
//!   address, minus the late-takeover users (sprayed users who have a success there).
//!
//! An office NAT or VPN egress is where users mistype a password and succeed within minutes, have
//! signed in for days, or are a few stale devices of disabled accounts next to many more users who
//! sign in; it is not a source, and a capture is a window, so no history before the first failure is
//! assumed. A proxy that sprays and takes accounts over stays a source however many it takes. The
//! source's network type is not part of the definition (compromised ISP routers and residential
//! proxies spray as much as hosting providers) and no GeoIP is needed.
//!
//! A failure is an INTERACTIVE sign-in (a row of unknown kind counts as interactive: a portal file whose
//! name says neither leaves `is_interactive` NULL, and a ROPC spray is interactive) whose `error_code` is in the shared `credential_failure_codes`
//! list (rules/lists: rejected credentials, 50126 / 50053 / 50034 / ...), the same list SPW-ID-005 and
//! SPW-ID-006 read. Conditional Access blocks, token-refresh errors, Seamless SSO errors, MFA prompts
//! and non-interactive rows are not credential failures. Only KNOWN results are judged: a NULL result
//! is never a failure and never a success.

use crate::Result;
use duckdb::Connection;

/// Sprayed users a source needs.
pub const MIN_USERS: i64 = 5;
/// A success this many minutes after a failure from the same address is a typo correction.
pub const TYPO_MINUTES: i64 = 30;
const TYPO_MS: i64 = TYPO_MINUTES * 60_000;

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
             fr AS (
               SELECT tenant_key, ip, upn, event_time FROM s
               WHERE interactive AND error_code IN ({codes})
             ),
             fail AS (
               SELECT tenant_key, ip, upn, count(*) AS n, min(event_time) AS first_t,
                      max(event_time) AS last_t
               FROM fr GROUP BY tenant_key, ip, upn
             ),
             ok AS (
               SELECT tenant_key, ip, upn, event_time FROM s WHERE error_code = 0
             ),
             ok_users AS (
               SELECT DISTINCT tenant_key, ip, upn FROM ok
             ),
             excused AS (
               SELECT DISTINCT f.tenant_key, f.ip, f.upn
               FROM fail f JOIN ok o
                 ON o.tenant_key = f.tenant_key AND o.ip = f.ip AND o.upn = f.upn
               WHERE o.event_time < f.first_t
                  OR EXISTS (SELECT 1 FROM fr x
                             WHERE x.tenant_key = o.tenant_key AND x.ip = o.ip AND x.upn = o.upn
                               AND x.event_time < o.event_time
                               AND epoch_ms(o.event_time) <= epoch_ms(x.event_time) + {TYPO_MS})
             ),
             src AS (
               SELECT f.tenant_key, f.ip, count(*) AS users_targeted, sum(f.n) AS failures,
                      min(f.first_t) AS first_failure, max(f.last_t) AS last_failure,
                      count(*) FILTER (WHERE o.upn IS NULL) AS failed_only_users,
                      count(*) FILTER (WHERE e.upn IS NULL) AS sprayed_users,
                      count(*) FILTER (WHERE e.upn IS NULL AND o.upn IS NOT NULL) AS takeover_users
               FROM fail f
               LEFT JOIN ok_users o
                 ON o.tenant_key = f.tenant_key AND o.ip = f.ip AND o.upn = f.upn
               LEFT JOIN excused e
                 ON e.tenant_key = f.tenant_key AND e.ip = f.ip AND e.upn = f.upn
               GROUP BY f.tenant_key, f.ip
             ),
             succ AS (
               SELECT tenant_key, ip, count(*) AS success_users FROM ok_users GROUP BY tenant_key, ip
             )
             SELECT src.tenant_key, src.ip, src.users_targeted, CAST(src.failures AS BIGINT),
                    src.first_failure, src.last_failure, src.failed_only_users,
                    coalesce(succ.success_users, 0), src.sprayed_users, src.takeover_users
             FROM src LEFT JOIN succ ON succ.tenant_key = src.tenant_key AND succ.ip = src.ip
             WHERE src.sprayed_users >= {MIN_USERS}
               AND src.sprayed_users > coalesce(succ.success_users, 0) - src.takeover_users
             ORDER BY src.tenant_key, src.ip"
        ),
        [],
    )?;
    Ok(n)
}
