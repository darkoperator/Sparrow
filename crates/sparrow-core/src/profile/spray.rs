//! Password-spray sources (derived table `spray_sources`): one definition, per tenant, that every
//! detection rule shares.
//!
//! A spray source is an address with failed sign-ins against at least [`MIN_USERS`] distinct users
//! of the tenant in the case, that is not the tenant's regular egress: an address from which at
//! least [`MIN_USERS`] distinct users signed in successfully (`error_code = 0`) on at least
//! [`EGRESS_DAYS`] distinct UTC days (an office NAT where several users mistype a password on
//! ordinary days). The source's network type is not part of the definition: attackers spray from
//! compromised ISP routers and residential proxies as much as from hosting providers, and an
//! address with sign-ins but no `ip_intel` row can be a source, so no GeoIP is needed.
//!
//! Only KNOWN results are judged: a failure is a non-zero `error_code` (a NULL result is never a
//! failure) and the egress exemption needs KNOWN successes (`error_code = 0`; an unknown result must
//! never excuse a source).
//!
//! A failure is a sign-in with a non-zero `error_code` other than the interrupt codes a normal
//! prompt produces (Microsoft Entra authentication and authorization error codes: 50055 password
//! expired, 50072 / 50074 / 50076 / 50079 MFA required or enrolment, 50125 sign-in interrupted by
//! password reset or registration, 50140 keep-me-signed-in prompt, 50158 external security
//! challenge): those are the user being asked something, not a rejected password.

use crate::Result;
use duckdb::Connection;

/// Distinct users a source must fail against, and the distinct users that make an address the
/// tenant's regular egress.
pub const MIN_USERS: i64 = 5;
/// Distinct UTC days of successful sign-ins that make an address regular egress.
pub const EGRESS_DAYS: i64 = 3;
/// Sign-in error codes that are prompts, not failures.
pub const INTERRUPT_CODES: [i64; 8] = [50055, 50072, 50074, 50076, 50079, 50125, 50140, 50158];

/// Rewrite `spray_sources` from `signins` (tenant by the collection's `tenant_key`); returns the
/// number of sources.
pub fn rebuild(conn: &Connection) -> Result<usize> {
    conn.execute_batch("DELETE FROM spray_sources")?;
    let interrupts = INTERRUPT_CODES
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let n = conn.execute(
        &format!(
            "INSERT INTO spray_sources
             WITH s AS (
               SELECT c.tenant_key, lower(g.user_upn) AS upn, g.ip, g.error_code, g.event_time
               FROM signins g JOIN collections c ON c.collection_id = g.collection_id
               WHERE c.tenant_key IS NOT NULL AND g.ip IS NOT NULL AND g.ip <> ''
                 AND g.user_upn IS NOT NULL AND g.user_upn <> ''
             ),
             src AS (
               SELECT tenant_key, ip, count(DISTINCT upn) AS users_targeted, count(*) AS failures,
                      min(event_time) AS first_failure, max(event_time) AS last_failure
               FROM s
               WHERE error_code IS NOT NULL AND error_code <> 0 AND error_code NOT IN ({interrupts})
                 AND event_time IS NOT NULL
               GROUP BY tenant_key, ip
               HAVING count(DISTINCT upn) >= {MIN_USERS}
             ),
             egress AS (
               SELECT tenant_key, ip
               FROM s
               WHERE error_code = 0 AND event_time IS NOT NULL
               GROUP BY tenant_key, ip
               HAVING count(DISTINCT upn) >= {MIN_USERS}
                  AND count(DISTINCT epoch_ms(event_time) // 86400000) >= {EGRESS_DAYS}
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
