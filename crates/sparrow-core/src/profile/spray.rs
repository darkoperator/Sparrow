//! Password-spray sources (derived table `spray_sources`): one definition, per tenant, that every
//! detection rule shares.
//!
//! A spray source is an address with credential failures against at least [`MIN_USERS`] distinct
//! users of the tenant in the case, that is not the tenant's regular egress: an address from which at
//! least [`MIN_USERS`] distinct users signed in successfully (`error_code = 0`) on at least
//! [`EGRESS_DAYS`] distinct UTC days BEFORE the address's first credential failure (an office NAT
//! where several users mistype a password on ordinary days; successes that follow the spray never
//! excuse a proxy that took accounts and used them). The source's network type is not part of the
//! definition: attackers spray from compromised ISP routers and residential proxies as much as from
//! hosting providers, and an address with sign-ins but no `ip_intel` row can be a source, so no GeoIP
//! is needed.
//!
//! A failure is an INTERACTIVE sign-in whose `error_code` is in the shared `credential_failure_codes`
//! list (rules/lists: rejected credentials, 50126 / 50053 / 50034 / ...), the same list SPW-ID-005 and
//! SPW-ID-006 read. Conditional Access blocks, token-refresh errors, Seamless SSO errors, MFA prompts
//! and non-interactive rows are not credential failures. Only KNOWN results are judged: a NULL result
//! is never a failure and an unknown result never excuses a source (the egress exemption needs
//! `error_code = 0`).

use crate::Result;
use duckdb::Connection;

/// Distinct users a source must fail against, and the distinct users that make an address the
/// tenant's regular egress.
pub const MIN_USERS: i64 = 5;
/// Distinct UTC days of successful sign-ins that make an address regular egress.
pub const EGRESS_DAYS: i64 = 3;

/// The credential-failure codes of the built-in (or custom) `credential_failure_codes` list.
pub fn credential_failure_codes(dirs: &crate::data::DataDirs) -> Result<Vec<i64>> {
    crate::detect::load::list_values(dirs, "credential_failure_codes")?
        .iter()
        .map(|v| {
            v.parse::<i64>().map_err(|_| {
                crate::Error::Invalid(format!("credential_failure_codes: {v:?} is not an error code"))
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
    let codes = if codes.is_empty() { "NULL".to_string() } else { codes };
    let n = conn.execute(
        &format!(
            "INSERT INTO spray_sources
             WITH s AS (
               SELECT c.tenant_key, lower(g.user_upn) AS upn, g.ip, g.error_code, g.event_time,
                      coalesce(g.is_interactive, false) AS interactive
               FROM signins g JOIN collections c ON c.collection_id = g.collection_id
               WHERE c.tenant_key IS NOT NULL AND g.ip IS NOT NULL AND g.ip <> ''
                 AND g.user_upn IS NOT NULL AND g.user_upn <> '' AND g.event_time IS NOT NULL
             ),
             src AS (
               SELECT tenant_key, ip, count(DISTINCT upn) AS users_targeted, count(*) AS failures,
                      min(event_time) AS first_failure, max(event_time) AS last_failure
               FROM s
               WHERE interactive AND error_code IN ({codes})
               GROUP BY tenant_key, ip
               HAVING count(DISTINCT upn) >= {MIN_USERS}
             ),
             egress AS (
               SELECT s.tenant_key, s.ip
               FROM s JOIN src ON src.tenant_key = s.tenant_key AND src.ip = s.ip
               WHERE s.error_code = 0 AND s.event_time < src.first_failure
               GROUP BY s.tenant_key, s.ip
               HAVING count(DISTINCT s.upn) >= {MIN_USERS}
                  AND count(DISTINCT epoch_ms(s.event_time) // 86400000) >= {EGRESS_DAYS}
             )
             SELECT src.tenant_key, src.ip, src.users_targeted, src.failures, src.first_failure,
                    src.last_failure
             FROM src
             WHERE NOT EXISTS (SELECT 1 FROM egress e WHERE e.tenant_key = src.tenant_key AND e.ip = src.ip)
             ORDER BY src.tenant_key, src.ip"
        ),
        [],
    )?;
    Ok(n)
}
