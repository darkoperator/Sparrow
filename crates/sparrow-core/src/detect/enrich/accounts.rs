//! `account_rollup`: one row per tenant and account (lower-case actor_upn) with at least one
//! finding: its worst severity, stages, first suspicious time, rules, and the addresses worth a
//! look. Facts only; the definitions are the table's column comments (migration 0020).
//!
//! Addresses worth a look, per account (spec §3.3), by reason:
//! - `finding_evidence`: on the evidence rows of one of the account's findings;
//! - `acts_without_signin`: acts for the account in ual_events, mail_items_accessed (parent-less
//!   rows), mailbox_audit_legacy (owner logons on the account's mailbox) or message_trace (mail the
//!   account sent) but never appears in the account's sign-ins;
//! - `hosting`, `spray_source`, `risky_signin`: appears for the account in any table and is a
//!   hosting address, a spray source of the tenant, or the address of a risky sign-in of the account
//!   (sign-in or user risk medium or high) or of a risk detection of the account.

use super::facts::EVIDENCE_IPS;
use super::{at_us, ts_opt};
use crate::Result;
use crate::detect::load::RuleSet;
use crate::detect::rule::Stage;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Address {
    pub ip: String,
    /// "finding_evidence" | "acts_without_signin" | "hosting" | "spray_source" | "risky_signin",
    /// in that order.
    pub reasons: Vec<String>,
    /// The tables the address appears in for the account, sorted.
    pub tables: Vec<String>,
    #[serde(default, with = "ts_opt")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(default, with = "ts_opt")]
    pub last_seen: Option<DateTime<Utc>>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub is_hosting: Option<bool>,
    pub spray_source: bool,
    pub in_user_signins: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountRow {
    pub tenant_key: String,
    pub upn: String,
    pub worst_severity: String,
    pub finding_count: u32,
    pub by_severity: BTreeMap<String, u32>,
    pub stages: Vec<Stage>,
    #[serde(default, with = "ts_opt")]
    pub first_suspicious: Option<DateTime<Utc>>,
    pub rules: Vec<String>,
    pub addresses: Vec<Address>,
    pub addresses_total: u32,
    pub addresses_truncated: bool,
}

pub const MAX_ADDRESSES: usize = 20;

/// The reader order of `account_rollup` (spec §3.3): worst severity, then number of stages
/// (descending), then first_suspicious, then upn (and tenant).
pub const ACCOUNT_ORDER: &str = "CASE worst_severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
     WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END, \
     json_array_length(stages) DESC, first_suspicious NULLS LAST, upn, tenant_key";

/// The rule whose `takeover` evidence context marks a credential takeover.
const TAKEOVER_RULE: &str = "SPW-ID-005";

/// Tables where an address acting for the account without signing it in is worth a look.
const ACTING_TABLES: &str =
    "'ual_events', 'mail_items_accessed', 'mailbox_audit_legacy', 'message_trace'";

const REASONS: [&str; 5] = [
    "finding_evidence",
    "acts_without_signin",
    "hosting",
    "spray_source",
    "risky_signin",
];

#[derive(Default)]
struct Acc {
    worst: usize,
    count: u32,
    by_severity: BTreeMap<String, u32>,
    stages: BTreeSet<Stage>,
    first_suspicious: Option<DateTime<Utc>>,
    rules: BTreeSet<String>,
}

fn rank(severity: &str) -> usize {
    ["critical", "high", "medium", "low", "info"]
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(5)
}

/// The findings with an actor, keyed by account.
const ACTOR_FINDINGS: &str = "elig AS (SELECT finding_id, tenant_key, lower(trim(actor_upn)) AS actor \
     FROM findings WHERE actor_upn IS NOT NULL AND trim(actor_upn) <> '')";

/// Rewrite `account_rollup` (already emptied by the caller, inside its transaction); returns the
/// rows written.
pub(crate) fn rebuild(conn: &Connection, set: &RuleSet, run_id: i64) -> Result<u64> {
    let stage_of: BTreeMap<&str, &[Stage]> = set
        .rules
        .iter()
        .map(|r| (r.rule.id.as_str(), r.rule.stage.as_slice()))
        .collect();

    let mut accounts: BTreeMap<(String, String), Acc> = BTreeMap::new();
    {
        let mut st = conn.prepare(&format!(
            "WITH {ACTOR_FINDINGS}
             SELECT l.tenant_key, l.actor, f.rule_id, f.severity, epoch_us(f.first_seen)
             FROM elig l JOIN findings f USING (finding_id)
             ORDER BY l.tenant_key, l.actor, f.finding_id"
        ))?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
            ))
        })?;
        for row in rows {
            let (tenant, upn, rule_id, severity, first) = row?;
            let a = accounts.entry((tenant, upn)).or_insert_with(|| Acc {
                worst: usize::MAX,
                ..Acc::default()
            });
            a.worst = a.worst.min(rank(&severity));
            a.count += 1;
            *a.by_severity.entry(severity.clone()).or_default() += 1;
            if let Some(id) = &rule_id {
                a.stages
                    .extend(stage_of.get(id.as_str()).copied().unwrap_or_default());
                a.rules.insert(id.clone());
            }
            if rank(&severity) <= rank("medium") {
                if let Some(t) = at_us(first) {
                    a.first_suspicious = Some(a.first_suspicious.map_or(t, |x| x.min(t)));
                }
            }
        }
    }
    if accounts.is_empty() {
        return Ok(0);
    }

    // credential_takeover: an SPW-ID-005 evidence row of the account says takeover = true.
    {
        let mut st = conn.prepare(&format!(
            "WITH {ACTOR_FINDINGS}
             SELECT DISTINCT l.tenant_key, l.actor
             FROM elig l JOIN findings f USING (finding_id)
             JOIN finding_evidence e USING (finding_id)
             WHERE f.rule_id = '{TAKEOVER_RULE}' AND json_extract_string(e.context, '$.takeover') = 'true'"
        ))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            if let Some(a) = accounts.get_mut(&row?) {
                a.stages.insert(Stage::CredentialTakeover);
            }
        }
    }

    let mut addresses = addresses(conn)?;

    let mut insert = conn.prepare(
        "INSERT INTO account_rollup (tenant_key, upn, worst_severity, finding_count, by_severity, \
         stages, first_suspicious, rules, addresses, addresses_total, addresses_truncated, computed_run_id) \
         VALUES (?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), CAST(? AS TIMESTAMPTZ), \
                 CAST(? AS JSON), CAST(? AS JSON), ?, ?, ?)",
    )?;
    let mut n = 0u64;
    for ((tenant, upn), a) in accounts {
        let mut list = addresses
            .remove(&(tenant.clone(), upn.clone()))
            .unwrap_or_default();
        list.sort_by(|x, y| {
            (strength(x), x.first_seen.is_none(), x.first_seen, &x.ip).cmp(&(
                strength(y),
                y.first_seen.is_none(),
                y.first_seen,
                &y.ip,
            ))
        });
        let total = list.len();
        list.truncate(MAX_ADDRESSES);
        let stages: Vec<Stage> = a.stages.into_iter().collect();
        let rules: Vec<String> = a.rules.into_iter().collect();
        let worst = ["critical", "high", "medium", "low", "info"]
            .get(a.worst)
            .copied()
            .unwrap_or("info");
        insert.execute(duckdb::params![
            tenant,
            upn,
            worst,
            a.count,
            to_json(&a.by_severity)?,
            to_json(&stages)?,
            a.first_suspicious
                .map(|t| t.format("%Y-%m-%d %H:%M:%S%.6f+00").to_string()),
            to_json(&rules)?,
            to_json(&list)?,
            u32::try_from(total).unwrap_or(u32::MAX),
            total > MAX_ADDRESSES,
            run_id,
        ])?;
        n += 1;
    }
    Ok(n)
}

/// 0 for an address on a finding's evidence, 1 for one acting without a sign-in, 2 otherwise.
fn strength(a: &Address) -> usize {
    if a.reasons.iter().any(|r| r == "finding_evidence") {
        0
    } else if a.reasons.iter().any(|r| r == "acts_without_signin") {
        1
    } else {
        2
    }
}

fn to_json<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| crate::Error::Invalid(e.to_string()))
}

fn from_json<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(|e| crate::Error::Invalid(format!("account_rollup: {e}")))
}

/// (tenant, account) -> its addresses worth a look, unordered and uncapped.
type AddressMap = BTreeMap<(String, String), Vec<Address>>;

fn addresses(conn: &Connection) -> Result<AddressMap> {
    let sql = format!(
        "WITH {ACTOR_FINDINGS}, {EVIDENCE_IPS},
         acct AS (SELECT DISTINCT tenant_key, actor AS upn FROM elig),
         act AS (
           SELECT c.tenant_key, lower(s.user_upn) AS upn, s.ip, 'signins' AS tbl, s.event_time AS t,
                  (lower(coalesce(s.risk_level_during, '')) IN ('medium', 'high')
                   OR lower(coalesce(s.risk_level_aggregated, '')) IN ('medium', 'high')) AS risky
           FROM signins s JOIN collections c ON c.collection_id = s.collection_id
           UNION ALL
           SELECT c.tenant_key, lower(u.user_upn), u.client_ip, 'ual_events', u.event_time, false
           FROM ual_events u JOIN collections c ON c.collection_id = u.collection_id
           UNION ALL
           SELECT c.tenant_key, lower(m.user_upn), m.client_ip, 'mail_items_accessed', m.event_time, false
           FROM mail_items_accessed m JOIN collections c ON c.collection_id = m.collection_id
           WHERE m.record_id IS NULL
           UNION ALL
           SELECT c.tenant_key, lower(l.mailbox_upn), l.client_ip, 'mailbox_audit_legacy', l.event_time, false
           FROM mailbox_audit_legacy l JOIN collections c ON c.collection_id = l.collection_id
           WHERE lower(coalesce(l.logon_type, '')) = 'owner'
           UNION ALL
           SELECT c.tenant_key, lower(t.sender), t.from_ip, 'message_trace', t.received, false
           FROM message_trace t JOIN collections c ON c.collection_id = t.collection_id
           UNION ALL
           SELECT c.tenant_key, lower(r.user_upn), r.ip, 'risk_detections',
                  coalesce(r.activity_time, r.detected_time), true
           FROM risk_detections r JOIN collections c ON c.collection_id = r.collection_id
           UNION ALL
           SELECT c.tenant_key, lower(d.initiated_by_upn), d.initiated_by_ip, 'directory_audits', d.event_time, false
           FROM directory_audits d JOIN collections c ON c.collection_id = d.collection_id
           UNION ALL
           SELECT c.tenant_key, lower(a.caller), a.client_ip, 'admin_audit_events', a.run_time, false
           FROM admin_audit_events a JOIN collections c ON c.collection_id = a.collection_id
           UNION ALL
           SELECT c.tenant_key, lower(z.caller), z.ip, 'azure_activity', z.event_time, false
           FROM azure_activity z JOIN collections c ON c.collection_id = z.collection_id
         ),
         seen AS (
           SELECT a.tenant_key, a.upn, a.ip, a.tbl, a.t, a.risky, false AS evidence
           FROM act a JOIN acct k ON k.tenant_key = a.tenant_key AND k.upn = a.upn
           WHERE a.ip IS NOT NULL AND a.ip <> ''
           UNION ALL
           SELECT l.tenant_key, l.actor, e.ip, e.source_table, e.event_time, false, true
           FROM ev e JOIN elig l USING (finding_id)
           WHERE e.ip IS NOT NULL AND e.ip <> ''
         ),
         per AS (
           SELECT tenant_key, upn, ip, list(DISTINCT tbl ORDER BY tbl) AS tables,
                  min(t) AS first_seen, max(t) AS last_seen, bool_or(evidence) AS evidence,
                  bool_or(tbl = 'signins' AND NOT evidence) AS in_signins,
                  bool_or(NOT evidence AND tbl IN ({ACTING_TABLES})) AS acts,
                  bool_or(risky) AS risky
           FROM seen GROUP BY tenant_key, upn, ip
         ),
         intel AS (
           SELECT ip, min(asn) AS asn, min(asn_org) AS asn_org, bool_or(is_hosting) AS is_hosting
           FROM ip_intel GROUP BY ip
         ),
         spray AS (SELECT DISTINCT tenant_key, ip FROM spray_sources)
         SELECT p.tenant_key, p.upn, p.ip, CAST(to_json(p.tables) AS VARCHAR),
                epoch_us(p.first_seen), epoch_us(p.last_seen),
                p.evidence, p.in_signins, p.acts, p.risky, i.asn, i.asn_org, i.is_hosting,
                sp.ip IS NOT NULL
         FROM per p
         LEFT JOIN intel i ON i.ip = p.ip
         LEFT JOIN spray sp ON sp.tenant_key = p.tenant_key AND sp.ip = p.ip
         WHERE p.evidence OR (p.acts AND NOT p.in_signins) OR coalesce(i.is_hosting, false)
            OR sp.ip IS NOT NULL OR p.risky
         ORDER BY p.tenant_key, p.upn, p.ip"
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<i64>>(5)?,
            [
                r.get::<_, bool>(6)?,
                r.get::<_, bool>(7)?,
                r.get::<_, bool>(8)?,
                r.get::<_, bool>(9)?,
            ],
            r.get::<_, Option<i64>>(10)?,
            r.get::<_, Option<String>>(11)?,
            r.get::<_, Option<bool>>(12)?,
            r.get::<_, bool>(13)?,
        ))
    })?;
    let mut out: AddressMap = BTreeMap::new();
    for row in rows {
        let (tenant, upn, ip, tables, first, last, flags, asn, asn_org, is_hosting, spray) = row?;
        let [evidence, in_signins, acts, risky] = flags;
        let hosting = is_hosting == Some(true);
        let has = [evidence, acts && !in_signins, hosting, spray, risky];
        let reasons: Vec<String> = REASONS
            .iter()
            .zip(has)
            .filter(|(_, on)| *on)
            .map(|(r, _)| r.to_string())
            .collect();
        out.entry((tenant, upn)).or_default().push(Address {
            ip,
            reasons,
            tables: from_json(&tables)?,
            first_seen: at_us(first),
            last_seen: at_us(last),
            asn: asn.and_then(|a| u32::try_from(a).ok()),
            asn_org,
            is_hosting,
            spray_source: spray,
            in_user_signins: in_signins,
        });
    }
    Ok(out)
}

/// `account_rollup` in reader order (`ACCOUNT_ORDER`).
pub fn read_accounts(conn: &Connection) -> Result<Vec<AccountRow>> {
    let mut st = conn.prepare(&format!(
        "SELECT tenant_key, upn, worst_severity, finding_count, CAST(by_severity AS VARCHAR), \
                CAST(stages AS VARCHAR), epoch_us(first_suspicious), CAST(rules AS VARCHAR), \
                CAST(addresses AS VARCHAR), addresses_total, addresses_truncated \
         FROM account_rollup ORDER BY {ACCOUNT_ORDER}"
    ))?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<i64>>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, i64>(9)?,
            r.get::<_, bool>(10)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            tenant_key,
            upn,
            worst_severity,
            count,
            by_sev,
            stages,
            first,
            rules,
            addrs,
            total,
            truncated,
        ) = row?;
        out.push(AccountRow {
            tenant_key,
            upn,
            worst_severity,
            finding_count: u32::try_from(count).unwrap_or(u32::MAX),
            by_severity: from_json(&by_sev)?,
            stages: from_json(&stages)?,
            first_suspicious: at_us(first),
            rules: from_json(&rules)?,
            addresses: from_json(&addrs)?,
            addresses_total: u32::try_from(total).unwrap_or(u32::MAX),
            addresses_truncated: truncated,
        });
    }
    Ok(out)
}
