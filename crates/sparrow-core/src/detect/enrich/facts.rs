//! `finding_facts`: per-finding facts for the persistence, consent and MFA families (the findings
//! whose rule's `stage:` includes `persistence`, `consent` or `mfa_change`). The definitions are
//! the table's column comments (migration 0020); in short:
//! - `window_start`: the tenant's first sign-in of any kind, so "earlier" reads "earlier within the
//!   capture" (a capture is a time window; nothing here assumes activity before it);
//! - `actor_ips`: each address on the finding's evidence, with its ip_intel facts, whether it is a
//!   spray source, and on how many distinct UTC days the actor had a successful sign-in from it
//!   strictly before the evidence event;
//! - `other_signals`: the actor's other findings;
//! - `targets`: every forwarding / redirect address the evidence carries, scoped by the tenant's
//!   domains, with the earlier message-trace rows between the actor and it.

use super::{FACTS_VERSION, at_us, lit, ts_opt};
use crate::Result;
use crate::detect::load::RuleSet;
use crate::detect::rule::Stage;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActorIp {
    pub ip: String,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub is_hosting: Option<bool>,
    pub spray_source: bool,
    pub user_signin_days_before: u32,
    #[serde(default, with = "ts_opt")]
    pub user_first_signin: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub rule_id: String,
    pub severity: String,
    #[serde(default, with = "ts_opt")]
    pub first_seen: Option<DateTime<Utc>>,
}

/// The actor's other findings: `items` holds at most 5, in finding-list order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OtherSignals {
    pub total: u32,
    pub items: Vec<Signal>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub address: String,
    pub domain: String,
    /// `internal` or `external`.
    pub scope: String,
    pub prior_messages: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingFacts {
    pub facts_version: u32,
    #[serde(default, with = "ts_opt")]
    pub window_start: Option<DateTime<Utc>>,
    pub actor_ips: Vec<ActorIp>,
    pub other_signals: OtherSignals,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Target>>,
}

/// The stages whose findings get facts.
const FAMILIES: [Stage; 3] = [Stage::Persistence, Stage::Consent, Stage::MfaChange];

/// Most items `other_signals` lists.
const MAX_SIGNALS: i64 = 5;

/// `ORDER BY` rank of a severity column (critical first), as `finding list` orders.
pub(crate) fn severity_rank(col: &str) -> String {
    format!(
        "CASE {col} WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 \
         WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"
    )
}

/// The evidence rows of the findings in `elig` (`finding_id`), with the address each row's table
/// records (the `timeline` view's `ip` column), read straight from the evidence tables so only the
/// cited rows are touched.
pub(crate) const EVIDENCE_IPS: &str = "
  fe AS (
    SELECT fe.finding_id, fe.source_table, fe.record_key, fe.event_time
    FROM finding_evidence fe JOIN elig USING (finding_id)
  ),
  ev AS (
    SELECT f.finding_id, f.source_table, f.event_time, u.client_ip AS ip
    FROM (SELECT * FROM fe WHERE source_table = 'ual_events') f
    JOIN ual_events u ON u.record_id = TRY_CAST(f.record_key AS UUID)
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, s.ip
    FROM (SELECT * FROM fe WHERE source_table = 'signins') f JOIN signins s ON s.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, d.initiated_by_ip
    FROM (SELECT * FROM fe WHERE source_table = 'directory_audits') f
    JOIN directory_audits d ON d.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, t.from_ip
    FROM (SELECT * FROM fe WHERE source_table = 'message_trace') f
    JOIN message_trace t ON t.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, l.client_ip
    FROM (SELECT * FROM fe WHERE source_table = 'mailbox_audit_legacy') f
    JOIN mailbox_audit_legacy l ON l.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, a.client_ip
    FROM (SELECT * FROM fe WHERE source_table = 'admin_audit_events') f
    JOIN admin_audit_events a ON a.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, r.ip
    FROM (SELECT * FROM fe WHERE source_table = 'risk_detections') f
    JOIN risk_detections r ON r.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, a.ip
    FROM (SELECT * FROM fe WHERE source_table = 'azure_activity') f
    JOIN azure_activity a ON a.record_key = f.record_key
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, m.client_ip
    FROM (SELECT * FROM fe WHERE source_table = 'mail_items_accessed') f
    JOIN mail_items_accessed m ON m.item_key = f.record_key AND m.record_id IS NULL
    UNION ALL
    SELECT f.finding_id, f.source_table, f.event_time, s.affected_ips[1]
    FROM (SELECT * FROM fe WHERE source_table = 'security_alerts') f
    JOIN security_alerts s ON s.record_key = f.record_key
  )";

/// Cmdlet parameters (lower-case) that name a forwarding or redirect destination.
const TARGET_PARAMS: &str = "'forwardingsmtpaddress', 'forwardingaddress', 'forwardto', \
     'forwardasattachmentto', 'redirectto', 'redirectmessageto', 'blindcopyto', 'copyto', 'addtorecipients'";

/// Finding -> the raw forwarding values of its evidence rows, each with the row's time (epoch us).
type TargetValues = BTreeMap<String, Vec<(Option<i64>, String)>>;

struct Eligible {
    finding_id: String,
    tenant_key: String,
    actor: Option<String>,
}

/// Rewrite `finding_facts` (already emptied by the caller, inside its transaction); returns the
/// rows written.
pub(crate) fn rebuild(conn: &Connection, set: &RuleSet, run_id: i64) -> Result<u64> {
    let ids: Vec<String> = set
        .rules
        .iter()
        .filter(|r| r.rule.stage.iter().any(|s| FAMILIES.contains(s)))
        .map(|r| lit(&r.rule.id))
        .collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let elig = format!(
        "elig AS (SELECT finding_id, tenant_key, lower(actor_upn) AS actor FROM findings \
         WHERE rule_id IN ({}))",
        ids.join(", ")
    );

    let findings: Vec<Eligible> = {
        let mut st = conn.prepare(&format!(
            "WITH {elig} SELECT finding_id, tenant_key, actor FROM elig ORDER BY finding_id"
        ))?;
        st.query_map([], |r| {
            Ok(Eligible {
                finding_id: r.get(0)?,
                tenant_key: r.get(1)?,
                actor: r.get(2)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?
    };

    let window = window_starts(conn)?;
    let mut ips = actor_ips(conn, &elig)?;
    let mut signals = other_signals(conn, &elig)?;
    let mut raw_targets = target_values(conn, &elig)?;
    let domains = tenant_domains(conn)?;
    let own = own_addresses(conn)?;
    let has_trace: bool =
        conn.query_row("SELECT count(*) > 0 FROM message_trace", [], |r| r.get(0))?;

    let mut insert = conn.prepare(
        "INSERT INTO finding_facts (finding_id, facts_version, facts, computed_run_id) \
         VALUES (?, ?, CAST(? AS JSON), ?)",
    )?;
    let mut n = 0u64;
    for f in &findings {
        let mine: BTreeSet<String> = match &f.actor {
            Some(a) => {
                let mut s = own
                    .get(&(f.tenant_key.clone(), a.clone()))
                    .cloned()
                    .unwrap_or_default();
                s.insert(a.clone());
                s
            }
            None => BTreeSet::new(),
        };
        let targets = match raw_targets.remove(&f.finding_id) {
            Some(values) => {
                let empty = BTreeSet::new();
                let tenant_domains = domains.get(&f.tenant_key).unwrap_or(&empty);
                let list = targets_of(
                    conn,
                    &values,
                    &f.tenant_key,
                    &mine,
                    tenant_domains,
                    has_trace,
                )?;
                (!list.is_empty()).then_some(list)
            }
            None => None,
        };
        let facts = FindingFacts {
            facts_version: FACTS_VERSION,
            window_start: window.get(&f.tenant_key).copied(),
            actor_ips: ips.remove(&f.finding_id).unwrap_or_default(),
            other_signals: signals.remove(&f.finding_id).unwrap_or(OtherSignals {
                total: 0,
                items: Vec::new(),
            }),
            targets,
        };
        let json =
            serde_json::to_string(&facts).map_err(|e| crate::Error::Invalid(e.to_string()))?;
        insert.execute(duckdb::params![f.finding_id, FACTS_VERSION, json, run_id])?;
        n += 1;
    }
    Ok(n)
}

/// Tenant -> its first sign-in of any kind.
fn window_starts(conn: &Connection) -> Result<BTreeMap<String, DateTime<Utc>>> {
    let mut st = conn.prepare(
        "SELECT c.tenant_key, epoch_us(min(s.event_time)) FROM signins s \
         JOIN collections c ON c.collection_id = s.collection_id \
         WHERE c.tenant_key IS NOT NULL AND s.event_time IS NOT NULL GROUP BY c.tenant_key",
    )?;
    let rows = st.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (tenant, us) = row?;
        if let Some(t) = at_us(us) {
            out.insert(tenant, t);
        }
    }
    Ok(out)
}

/// Finding -> its evidence addresses, ordered by first evidence time, then address.
fn actor_ips(conn: &Connection, elig: &str) -> Result<BTreeMap<String, Vec<ActorIp>>> {
    let sql = format!(
        "WITH {elig}, {EVIDENCE_IPS},
         fi AS (
           SELECT e.finding_id, l.tenant_key, l.actor, e.ip, min(e.event_time) AS t
           FROM ev e JOIN elig l USING (finding_id)
           WHERE e.ip IS NOT NULL AND e.ip <> ''
           GROUP BY ALL
         ),
         si AS (
           SELECT c.tenant_key, lower(s.user_upn) AS actor, s.ip, s.event_time
           FROM signins s JOIN collections c ON c.collection_id = s.collection_id
           WHERE coalesce(s.error_code, 0) = 0 AND s.user_upn IS NOT NULL AND s.event_time IS NOT NULL
         ),
         intel AS (
           SELECT ip, min(asn) AS asn, min(asn_org) AS asn_org, bool_or(is_hosting) AS is_hosting
           FROM ip_intel GROUP BY ip
         ),
         spray AS (SELECT DISTINCT tenant_key, ip FROM spray_sources)
         SELECT fi.finding_id, fi.ip, i.asn, i.asn_org, i.is_hosting, sp.ip IS NOT NULL,
                CAST(count(DISTINCT epoch_ms(si.event_time) // 86400000) AS BIGINT),
                epoch_us(min(si.event_time))
         FROM fi
         LEFT JOIN si ON si.tenant_key = fi.tenant_key AND si.actor = fi.actor AND si.ip = fi.ip
                     AND si.event_time < fi.t
         LEFT JOIN intel i ON i.ip = fi.ip
         LEFT JOIN spray sp ON sp.tenant_key = fi.tenant_key AND sp.ip = fi.ip
         GROUP BY fi.finding_id, fi.ip, fi.t, i.asn, i.asn_org, i.is_hosting, sp.ip
         ORDER BY fi.finding_id, fi.t NULLS LAST, fi.ip"
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            ActorIp {
                ip: r.get(1)?,
                asn: r
                    .get::<_, Option<i64>>(2)?
                    .and_then(|a| u32::try_from(a).ok()),
                asn_org: r.get(3)?,
                is_hosting: r.get(4)?,
                spray_source: r.get(5)?,
                user_signin_days_before: u32::try_from(r.get::<_, i64>(6)?).unwrap_or(u32::MAX),
                user_first_signin: at_us(r.get(7)?),
            },
        ))
    })?;
    let mut out: BTreeMap<String, Vec<ActorIp>> = BTreeMap::new();
    for row in rows {
        let (id, ip) = row?;
        out.entry(id).or_default().push(ip);
    }
    Ok(out)
}

/// Finding -> the actor's other findings (same tenant, actor compared case-insensitively).
fn other_signals(conn: &Connection, elig: &str) -> Result<BTreeMap<String, OtherSignals>> {
    let rank = severity_rank("o.severity");
    let sql = format!(
        "WITH {elig}
         SELECT l.finding_id, coalesce(o.rule_id, ''), o.severity, epoch_us(o.first_seen),
                count(*) OVER (PARTITION BY l.finding_id) AS total,
                row_number() OVER (PARTITION BY l.finding_id
                                   ORDER BY {rank}, o.last_seen DESC NULLS LAST, o.finding_id) AS rn
         FROM elig l
         JOIN findings o ON o.tenant_key = l.tenant_key AND lower(o.actor_upn) = l.actor
                        AND o.finding_id <> l.finding_id
         QUALIFY rn <= {MAX_SIGNALS}
         ORDER BY l.finding_id, rn"
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            Signal {
                rule_id: r.get(1)?,
                severity: r.get(2)?,
                first_seen: at_us(r.get(3)?),
            },
            r.get::<_, i64>(4)?,
        ))
    })?;
    let mut out: BTreeMap<String, OtherSignals> = BTreeMap::new();
    for row in rows {
        let (id, signal, total) = row?;
        let e = out.entry(id).or_insert(OtherSignals {
            total: u32::try_from(total).unwrap_or(u32::MAX),
            items: Vec::new(),
        });
        e.items.push(signal);
    }
    Ok(out)
}

/// Finding -> the raw forwarding / redirect values its evidence rows carry, each with the
/// evidence row's time (epoch us).
fn target_values(conn: &Connection, elig: &str) -> Result<TargetValues> {
    let sql = format!(
        "WITH {elig},
         fe AS (
           SELECT fe.finding_id, fe.source_table, fe.record_key, fe.event_time
           FROM finding_evidence fe JOIN elig USING (finding_id)
         ),
         raw AS (
           SELECT f.finding_id, f.event_time,
                  unnest(list_concat(coalesce(r.forward_to, CAST([] AS VARCHAR[])),
                                     coalesce(r.forward_as_attachment_to, CAST([] AS VARCHAR[])),
                                     coalesce(r.redirect_to, CAST([] AS VARCHAR[])))) AS v
           FROM (SELECT * FROM fe WHERE source_table = 'inbox_rules') f
           JOIN inbox_rules r ON r.record_key = f.record_key
           UNION ALL
           SELECT f.finding_id, f.event_time, unnest([m.forwarding_smtp_address, m.forwarding_address])
           FROM (SELECT * FROM fe WHERE source_table = 'mailboxes') f
           JOIN mailboxes m ON m.record_key = f.record_key
           UNION ALL
           SELECT f.finding_id, f.event_time,
                  unnest(list_concat(coalesce(t.redirect_to, CAST([] AS VARCHAR[])),
                                     coalesce(t.blind_copy_to, CAST([] AS VARCHAR[])),
                                     coalesce(t.copy_to, CAST([] AS VARCHAR[])),
                                     coalesce(t.add_to_recipients, CAST([] AS VARCHAR[]))))
           FROM (SELECT * FROM fe WHERE source_table = 'transport_rules') f
           JOIN transport_rules t ON t.record_key = f.record_key
           UNION ALL
           SELECT f.finding_id, f.event_time, x.e.value
           FROM (SELECT * FROM fe WHERE source_table = 'ual_events') f
           JOIN ual_events u ON u.record_id = TRY_CAST(f.record_key AS UUID),
                unnest(map_entries(u.parameters)) AS x(e)
           WHERE lower(x.e.key) IN ({TARGET_PARAMS})
           UNION ALL
           SELECT f.finding_id, f.event_time, x.e.value
           FROM (SELECT * FROM fe WHERE source_table = 'admin_audit_events') f
           JOIN admin_audit_events a ON a.record_key = f.record_key,
                unnest(map_entries(a.parameters)) AS x(e)
           WHERE lower(x.e.key) IN ({TARGET_PARAMS})
         )
         SELECT finding_id, epoch_us(event_time), v FROM raw
         WHERE v IS NOT NULL AND trim(v) <> ''
         ORDER BY finding_id, event_time NULLS LAST, v"
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<i64>>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out: TargetValues = BTreeMap::new();
    for row in rows {
        let (id, t, v) = row?;
        out.entry(id).or_default().push((t, v));
    }
    Ok(out)
}

/// Tenant -> its domains (lower-case, trailing dots removed). `tenant_domains` already carries the
/// analyst overrides (every profile run and every `tenant domains add|remove` rebuilds it).
fn tenant_domains(conn: &Connection) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut st = conn.prepare(
        "SELECT DISTINCT tenant_key, lower(rtrim(trim(domain), '.')) FROM tenant_domains \
         WHERE domain IS NOT NULL",
    )?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let (t, d) = row?;
        out.entry(t).or_default().insert(d);
    }
    Ok(out)
}

/// (tenant, lower-case UPN) -> the mailbox's primary SMTP address(es), lower-case.
fn own_addresses(conn: &Connection) -> Result<BTreeMap<(String, String), BTreeSet<String>>> {
    let mut st = conn.prepare(
        "SELECT DISTINCT c.tenant_key, lower(m.upn), lower(trim(m.primary_smtp_address)) \
         FROM mailboxes m JOIN collections c ON c.collection_id = m.collection_id \
         WHERE c.tenant_key IS NOT NULL AND m.upn IS NOT NULL \
           AND m.primary_smtp_address LIKE '%@%'",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let (t, upn, addr) = row?;
        out.entry((t, upn)).or_default().insert(addr);
    }
    Ok(out)
}

fn address_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)[a-z0-9._%+'-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?").unwrap()
    })
}

/// The addresses in one forwarding value, normalised: Exchange's `"Name" [SMTP:a@b]`, a
/// `smtp:` prefix, `;`-separated lists and trailing dots all reduce to `a@b`, lower-case. A value
/// with no address (a display name, a distinguished name) yields none.
pub fn addresses_in(value: &str) -> Vec<String> {
    address_re()
        .find_iter(value)
        .map(|m| m.as_str().trim_end_matches('.').to_lowercase())
        .filter(|a| {
            a.rsplit_once('@')
                .is_some_and(|(local, d)| !local.is_empty() && !d.is_empty())
        })
        .collect()
}

/// True when `domain` or one of its parent domains is in `domains`.
fn in_domains(domain: &str, domains: &BTreeSet<String>) -> bool {
    let mut d = domain;
    loop {
        if domains.contains(d) {
            return true;
        }
        match d.split_once('.') {
            Some((_, rest)) if !rest.is_empty() => d = rest,
            _ => return false,
        }
    }
}

fn targets_of(
    conn: &Connection,
    values: &[(Option<i64>, String)],
    tenant: &str,
    mine: &BTreeSet<String>,
    domains: &BTreeSet<String>,
    has_trace: bool,
) -> Result<Vec<Target>> {
    // address -> earliest evidence time carrying it (None when every such row has no time).
    let mut first: BTreeMap<String, Option<i64>> = BTreeMap::new();
    for (t, v) in values {
        for a in addresses_in(v) {
            let e = first.entry(a).or_insert(*t);
            *e = match (*e, *t) {
                (Some(x), Some(y)) => Some(x.min(y)),
                (x, y) => x.or(y),
            };
        }
    }
    let actor_in = mine.iter().map(|a| lit(a)).collect::<Vec<_>>().join(", ");
    let mut out = Vec::new();
    for (address, t) in first {
        let domain = address
            .rsplit_once('@')
            .map(|(_, d)| d.to_string())
            .unwrap_or_default();
        let internal = mine.contains(&address) || in_domains(&domain, domains);
        let prior_messages = match t {
            Some(t) if has_trace && !mine.is_empty() => {
                let target = lit(&address);
                let n: i64 = conn.query_row(
                    &format!(
                        "SELECT count(*) FROM message_trace m \
                         JOIN collections c ON c.collection_id = m.collection_id \
                         WHERE c.tenant_key = ? AND epoch_us(m.received) < ? \
                           AND ((lower(m.sender) IN ({actor_in}) AND lower(m.recipient) = {target}) \
                             OR (lower(m.sender) = {target} AND lower(m.recipient) IN ({actor_in})))"
                    ),
                    duckdb::params![tenant, t],
                    |r| r.get(0),
                )?;
                Some(u32::try_from(n).unwrap_or(u32::MAX))
            }
            _ => None,
        };
        out.push(Target {
            address,
            domain,
            scope: if internal { "internal" } else { "external" }.to_string(),
            prior_messages,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_normalised() {
        assert_eq!(
            addresses_in("SMTP:Bob@Partner.Example."),
            vec!["bob@partner.example"]
        );
        assert_eq!(
            addresses_in("\"Last, First\" [SMTP:First.Last@Contoso.example];x@y.example"),
            vec!["first.last@contoso.example", "x@y.example"]
        );
        assert_eq!(addresses_in("Bob Smith"), Vec::<String>::new());
        assert_eq!(
            addresses_in("contoso.example/Users/Bob"),
            Vec::<String>::new()
        );
        assert_eq!(addresses_in(""), Vec::<String>::new());
    }

    #[test]
    fn parent_domains_are_internal() {
        let d: BTreeSet<String> = ["contoso.example".to_string()].into();
        assert!(in_domains("contoso.example", &d));
        assert!(in_domains("eu.contoso.example", &d));
        assert!(!in_domains("notcontoso.example", &d));
        assert!(!in_domains("example", &d));
    }
}
