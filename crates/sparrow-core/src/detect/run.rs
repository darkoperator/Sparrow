//! The detection runner (spec §8.3, Addendum C.4).
//!
//! Order of a run:
//! 1. read what the plan needs from the case (tenants, licences, evidence availability, case
//!    indicators, the schema) on the writer connection;
//! 2. decide per (tenant, rule): not applicable (a required capability is `not_licensed`, a
//!    required evidence is `not_licensed` / `not_enabled`), compile error, or run;
//! 3. run every rule on a separate, locked, tenant-scoped rule instance
//!    (`rule_conn::with_rule_conn`; the writer is released meanwhile) collecting hits in Rust;
//! 4. merge everything into the case in one transaction on the writer.

use crate::case::indicators::{Verdict, list_indicators};
use crate::data::DataDirs;
use crate::detect::compile::{CaseSchema, Compiled, compile_with_meta};
use crate::detect::findings::{Outcome, RunStatus, merge_hits, next_run_id, write_run_row};
use crate::detect::load::{LoadedRule, RuleSet, load_rules};
use crate::detect::phase::{self, Phase};
use crate::detect::rule_conn::with_rule_conn;
use crate::{Case, Error, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub use crate::detect::findings::fingerprint;

#[derive(Debug, Clone, Default)]
pub struct DetectOptions {
    /// Run only these rules (empty = all).
    pub rule_ids: Vec<String>,
    /// Run only rules carrying one of these tags (empty = all).
    pub tags: Vec<String>,
    /// The run's clock (`started_at`, `created_at`, `updated_at`); None = now.
    pub now: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleRunReport {
    pub rule_id: String,
    pub tenant_key: String,
    pub status: String,
    pub reason: Option<String>,
    pub hits: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DetectReport {
    pub run_id: i64,
    pub rules: Vec<RuleRunReport>,
    pub findings_new: u64,
    pub findings_updated: u64,
    pub evidence_added: u64,
    pub warnings: Vec<String>,
    /// Wall time per phase of this run, in the order they ran (the sum of the per-rule
    /// `duration_ms` is only the "rules" part).
    pub phases: Vec<Phase>,
}

enum Plan {
    NotApplicable(String),
    Error(String),
    Run {
        compiled: usize,
        iocs: BTreeMap<String, Vec<String>>,
        sha256: String,
    },
}

struct Planned {
    tenant: String,
    rule: usize,
    plan: Plan,
}

fn selected<'a>(
    set: &'a RuleSet,
    opts: &DetectOptions,
    warnings: &mut Vec<String>,
) -> Vec<&'a LoadedRule> {
    for id in &opts.rule_ids {
        if !set.rules.iter().any(|r| &r.rule.id == id) {
            warnings.push(format!("unknown rule id {id}"));
        }
    }
    set.rules
        .iter()
        .filter(|r| opts.rule_ids.is_empty() || opts.rule_ids.contains(&r.rule.id))
        .filter(|r| opts.tags.is_empty() || r.rule.tags.iter().any(|t| opts.tags.contains(t)))
        .collect()
}

/// `sha256(rule_sha256 + "\n" + sorted "type\tvalue" lines)` of the indicators the rule read.
fn ioc_sha(rule_sha: &str, iocs: &BTreeMap<String, Vec<String>>) -> String {
    let mut lines: Vec<String> = iocs
        .iter()
        .flat_map(|(ty, values)| values.iter().map(move |v| format!("{ty}\t{v}")))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    h.update(rule_sha.as_bytes());
    h.update(b"\n");
    h.update(lines.join("\n").as_bytes());
    hex::encode(h.finalize())
}

fn status_map(case: &Case, sql: &str) -> Result<BTreeMap<(String, String), String>> {
    let mut st = case.conn().prepare(sql)?;
    let rows = st.query_map([], |r| {
        Ok((
            (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
            r.get::<_, String>(2)?,
        ))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The tenants with GeoIP data: at least one IP in the tenant's sign-ins, UAL, directory audits
/// or admin audit log has an `ip_intel` row with an ASN, a country or a latitude. `ip_intel` is
/// shared by the whole case, so each tenant is judged by its own IPs; a tenant whose IPs are all
/// private or unresolved (ingested without `--geoip-dir`, or not in the databases) has none.
fn tenants_with_geoip(case: &Case) -> Result<BTreeSet<String>> {
    let mut st = case.conn().prepare(
        "SELECT DISTINCT c.tenant_key \
         FROM (SELECT collection_id, ip FROM signins \
               UNION ALL SELECT collection_id, client_ip FROM ual_events \
               UNION ALL SELECT collection_id, initiated_by_ip FROM directory_audits \
               UNION ALL SELECT collection_id, client_ip FROM admin_audit_events) e \
         JOIN collections c ON c.collection_id = e.collection_id \
         JOIN ip_intel i ON i.ip = e.ip \
         WHERE i.asn IS NOT NULL OR i.country_iso IS NOT NULL OR i.latitude IS NOT NULL",
    )?;
    let rows = st.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Distinct users (lower-cased UPN) in each tenant's sign-ins.
fn signin_users_by_tenant(case: &Case) -> Result<std::collections::BTreeMap<String, u32>> {
    let mut st = case.conn().prepare(
        "SELECT c.tenant_key, CAST(count(DISTINCT lower(s.user_upn)) AS INTEGER) \
         FROM signins s JOIN collections c ON c.collection_id = s.collection_id \
         WHERE c.tenant_key IS NOT NULL AND s.user_upn IS NOT NULL GROUP BY c.tenant_key",
    )?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?)))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Run the rules of `set` over every tenant of the case and merge the hits into the findings.
pub fn run(case: &mut Case, set: &RuleSet, opts: &DetectOptions) -> Result<DetectReport> {
    case.ensure_usable()?;
    if case.is_read_only() {
        return Err(Error::Invalid("the case database is open read-only".into()));
    }
    let now = opts.now.unwrap_or_else(Utc::now);
    let mut report = DetectReport::default();
    let rules = selected(set, opts, &mut report.warnings);

    let _ = phase::take();
    // 1. Inputs, on the writer.
    let t = Instant::now();
    let schema = CaseSchema::of(case.conn())?;
    let tenants: Vec<String> = {
        let mut st = case
            .conn()
            .prepare("SELECT tenant_key FROM tenant ORDER BY tenant_key")?;
        st.query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?
    };
    if tenants.is_empty() {
        report
            .warnings
            .push("the case has no tenant profile; run the profile step first".to_string());
        return Ok(report);
    }
    let caps = status_map(
        case,
        "SELECT tenant_key, capability_id, CAST(status AS VARCHAR) FROM tenant_capabilities",
    )?;
    let evidence = status_map(
        case,
        "SELECT tenant_key, evidence, CAST(status AS VARCHAR) FROM evidence_availability",
    )?;
    let indicators = list_indicators(case.conn(), None, false)?;
    phase::record("inputs", t);
    let t = Instant::now();
    let geo_tenants = if rules.iter().any(|r| r.rule.needs_geoip) {
        tenants_with_geoip(case)?
    } else {
        BTreeSet::new()
    };

    let signin_users = if rules.iter().any(|r| r.rule.min_signin_users.is_some()) {
        signin_users_by_tenant(case)?
    } else {
        std::collections::BTreeMap::new()
    };
    phase::record("geoip tenants", t);
    // 2. The plan.
    let t = Instant::now();
    let mut compiled: Vec<Compiled> = Vec::new();
    let mut compile_of: Vec<std::result::Result<usize, String>> = Vec::new();
    for lr in &rules {
        compile_of.push(
            match compile_with_meta(&lr.rule, &set.lists, &set.list_meta, &schema) {
                Ok(c) => {
                    compiled.push(c);
                    Ok(compiled.len() - 1)
                }
                Err(e) => Err(e.to_string()),
            },
        );
    }
    let mut plans: Vec<Planned> = Vec::new();
    for tenant in &tenants {
        for (i, lr) in rules.iter().enumerate() {
            let r = &lr.rule;
            let not_licensed = r.requires.iter().find(|c| {
                caps.get(&(tenant.clone(), (*c).clone()))
                    .map(String::as_str)
                    == Some("not_licensed")
            });
            let missing_evidence = r.requires_evidence.iter().find_map(|e| {
                match evidence
                    .get(&(tenant.clone(), e.clone()))
                    .map(String::as_str)
                {
                    Some(s @ ("not_licensed" | "not_enabled")) => Some((e, s)),
                    _ => None,
                }
            });
            let plan = if r.needs_geoip && !geo_tenants.contains(tenant) {
                Plan::NotApplicable("no GeoIP data".to_string())
            } else if let Some(n) = r
                .min_signin_users
                .filter(|n| signin_users.get(tenant).copied().unwrap_or(0) < *n)
            {
                let have = signin_users.get(tenant).copied().unwrap_or(0);
                Plan::NotApplicable(if have == 0 {
                    format!(
                        "no sign-ins were collected for the tenant (the rule's population threshold needs {n} distinct users)"
                    )
                } else {
                    format!(
                        "sign-ins cover {have} distinct users, fewer than the {n} the rule's population threshold needs (a per-user collection such as Hawk's cannot show it)"
                    )
                })
            } else if let Some(c) = not_licensed {
                Plan::NotApplicable(format!("capability {c} is not_licensed"))
            } else if let Some((e, s)) = missing_evidence {
                Plan::NotApplicable(format!("evidence {e} is {s}"))
            } else {
                match &compile_of[i] {
                    Err(msg) => Plan::Error(msg.clone()),
                    Ok(ci) => {
                        let mut iocs: BTreeMap<String, Vec<String>> = BTreeMap::new();
                        for l in &compiled[*ci].lists {
                            let Some(ty) = l.strip_prefix("case_iocs.") else {
                                continue;
                            };
                            let mut values: BTreeSet<String> = BTreeSet::new();
                            for ind in &indicators {
                                let applies = ind.tenant_key.is_none()
                                    || ind.tenant_key.as_deref() == Some(tenant.as_str());
                                if applies
                                    && ind.verdict != Verdict::Benign
                                    && ind.ty.as_str() == ty
                                {
                                    values.insert(ind.value.clone());
                                }
                            }
                            iocs.insert(ty.to_string(), values.into_iter().collect());
                        }
                        let sha256 = if iocs.is_empty() {
                            lr.sha256.clone()
                        } else {
                            ioc_sha(&lr.sha256, &iocs)
                        };
                        Plan::Run {
                            compiled: *ci,
                            iocs,
                            sha256,
                        }
                    }
                }
            };
            plans.push(Planned {
                tenant: tenant.clone(),
                rule: i,
                plan,
            });
        }
    }

    phase::record("plan (compile)", t);
    // 3. Execute on the rule instance.
    let t = Instant::now();
    let outcomes: Vec<Outcome> = with_rule_conn(case, |rc| {
        let mut out = Vec::new();
        let mut scoped: Option<&str> = None;
        for p in &plans {
            let lr = rules[p.rule];
            let base = Outcome {
                tenant_key: p.tenant.clone(),
                rule_id: lr.rule.id.clone(),
                status: RunStatus::Ran,
                reason: None,
                hits: Vec::new(),
                duration_ms: 0,
                sha256: lr.sha256.clone(),
            };
            out.push(match &p.plan {
                Plan::NotApplicable(reason) => Outcome {
                    status: RunStatus::NotApplicable,
                    reason: Some(reason.clone()),
                    ..base
                },
                Plan::Error(msg) => Outcome {
                    status: RunStatus::Error,
                    reason: Some(msg.clone()),
                    ..base
                },
                Plan::Run {
                    compiled: ci,
                    iocs,
                    sha256,
                } => {
                    if scoped != Some(p.tenant.as_str()) {
                        rc.scope(&p.tenant)?;
                        scoped = Some(p.tenant.as_str());
                    }
                    let t0 = Instant::now();
                    let result = rc.run(&compiled[*ci], iocs);
                    let duration_ms = t0.elapsed().as_millis() as u64;
                    phase::record("rules (sum)", t0);
                    match result {
                        Ok(hits) => Outcome {
                            hits,
                            duration_ms,
                            sha256: sha256.clone(),
                            ..base
                        },
                        Err(e) => Outcome {
                            status: RunStatus::Error,
                            reason: Some(e.to_string()),
                            duration_ms,
                            sha256: sha256.clone(),
                            ..base
                        },
                    }
                }
            });
        }
        Ok(out)
    })?;

    phase::record("execute (total, with release)", t);
    // 4. Merge, one transaction on the writer.
    let t = Instant::now();
    let by_id: BTreeMap<&str, &LoadedRule> =
        rules.iter().map(|r| (r.rule.id.as_str(), *r)).collect();
    let tx = case.conn_mut().transaction()?;
    let run_id = next_run_id(&tx)?;
    report.run_id = run_id;
    for o in &outcomes {
        let lr = by_id[o.rule_id.as_str()];
        write_run_row(&tx, run_id, now, &lr.rule, o)?;
        if o.status == RunStatus::Ran {
            let c = merge_hits(&tx, run_id, now, &lr.rule, o)?;
            report.findings_new += c.findings_new;
            report.findings_updated += c.findings_updated;
            report.evidence_added += c.evidence_added;
        }
        report.rules.push(RuleRunReport {
            rule_id: o.rule_id.clone(),
            tenant_key: o.tenant_key.clone(),
            status: o.status.as_str().to_string(),
            reason: o.reason.clone(),
            hits: o.hits.len() as u64,
            duration_ms: o.duration_ms,
        });
    }
    tx.commit()?;
    phase::record("merge", t);
    report.phases = phase::take();
    Ok(report)
}

/// Load the built-in rules and lists (plus the custom ones of `dirs`) and run them: what
/// `sparrow ingest` and `sparrow profile` do after the profile step.
pub fn run_with_dirs(
    case: &mut Case,
    dirs: &DataDirs,
    opts: &DetectOptions,
) -> Result<DetectReport> {
    let set = load_rules(dirs)?;
    let mut report = run(case, &set, opts)?;
    let mut warnings = set.warnings.clone();
    warnings.append(&mut report.warnings);
    report.warnings = warnings;
    Ok(report)
}
