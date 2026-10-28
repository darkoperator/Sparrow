//! The computed facts as text for the report and the workbook (agent accuracy T5). Facts only: every sentence is a
//! fixed template filled with stored values, never a verdict, label or score (no sentence says "benign" or
//! "malicious"). A count that cannot be compared is "unknown", never 0. Values are escaped like the rest of the
//! report ([`one`]: Markdown and HTML escaping on top of `display_safe_line`).

use super::text::single_line as one;
use crate::Result;
use crate::case::read::FactsField;
use crate::data::DataDirs;
use crate::detect::enrich::accounts::AccountRow;
use crate::detect::enrich::facts::FindingFacts;
use crate::detect::enrich::{EnrichState, enrichment_state};
use crate::detect::load::{RuleSet, load_rules};
use duckdb::Connection;
use std::collections::BTreeMap;

/// The addresses of an account named in the report's table before "+N more".
pub const ADDRESSES_SHOWN: usize = 5;

/// The rule set the exports pass to `read::finding_show` / `read::finding_facts`, which need it ONLY to tell which findings should have
/// facts when the enrichment is not current. So it is loaded lazily, from the same `DataDirs` as the other commands
/// (`--data`, `--rules`, `SPARROW_DATA`, `SPARROW_RULES`), and only when the enrichment is not [`EnrichState::Ok`]:
/// current stored facts are shown whatever rules are on disk. A rule set that cannot be loaded is not an export
/// failure: the set is empty, every finding of a rule then reads "facts unavailable", and
/// [`FactRules::note`] adds why.
pub struct FactRules {
    pub set: RuleSet,
    /// Why the rules could not be loaded, when they could not.
    pub load_error: Option<String>,
}

impl FactRules {
    pub fn for_case(conn: &Connection, dirs: &DataDirs) -> Result<FactRules> {
        let empty = RuleSet {
            rules: Vec::new(),
            lists: BTreeMap::new(),
            list_meta: BTreeMap::new(),
            warnings: Vec::new(),
        };
        if matches!(enrichment_state(conn)?, EnrichState::Ok { .. }) {
            return Ok(FactRules {
                set: empty,
                load_error: None,
            });
        }
        Ok(match load_rules(dirs) {
            Ok(set) => FactRules {
                set,
                load_error: None,
            },
            Err(e) => FactRules {
                set: empty,
                load_error: Some(e.to_string()),
            },
        })
    }

    /// `reason`, with why the rules were not loaded when that is the case.
    pub fn note(&self, reason: &str) -> String {
        match &self.load_error {
            Some(e) => format!("{reason} (the rules could not be loaded: {e})"),
            None => reason.to_string(),
        }
    }
}

/// The sentence for facts that are not available.
pub fn unavailable_line(reason: &str) -> String {
    format!("Facts unavailable: {}.", one(reason.trim_end_matches('.')))
}

/// The facts of one finding as sentences, in a fixed order: one per actor address, the actor's other findings, one
/// per target.
pub fn fact_lines(facts: &FindingFacts) -> Vec<String> {
    let since = facts
        .window_start
        .as_ref()
        .map(|d| format!(" (since {})", d.format("%Y-%m-%d")))
        .unwrap_or_default();
    let mut out = Vec::new();
    for ip in &facts.actor_ips {
        let mut s = match ip.user_signin_days_before {
            Some(n) => format!(
                "Address {} — this user signed in from it on {n} earlier day(s) within the capture{since}.",
                one(&ip.ip)
            ),
            None => format!(
                "Address {} — earlier sign-ins from it by this user: unknown (not comparable within the capture).",
                one(&ip.ip)
            ),
        };
        if ip.is_hosting == Some(true) {
            s.push_str(&match &ip.asn_org {
                Some(org) => format!(" It is in a hosting provider network ({}).", one(org)),
                None => " It is in a hosting provider network.".to_string(),
            });
        }
        if ip.spray_source {
            s.push_str(" It is a password-spray source of this tenant.");
        }
        out.push(s);
    }
    let other = &facts.other_signals;
    if other.total == 0 {
        out.push("No other findings on this account.".to_string());
    } else {
        let items: Vec<String> = other
            .items
            .iter()
            .map(|s| format!("{} {}", one(&s.rule_id), one(&s.severity)))
            .collect();
        let more = other.total as usize - other.items.len().min(other.total as usize);
        out.push(format!(
            "Other findings on this account: {} ({}{}).",
            other.total,
            items.join(", "),
            if more > 0 {
                format!(", +{more} more")
            } else {
                String::new()
            }
        ));
    }
    for t in facts.targets.iter().flatten() {
        out.push(match t.prior_messages {
            Some(n) => format!(
                "Target {} — {}; {n} earlier message(s) with this user.",
                one(&t.address),
                one(&t.scope)
            ),
            None => format!(
                "Target {} — {}; earlier messages with this user: unknown (not comparable within the capture).",
                one(&t.address),
                one(&t.scope)
            ),
        });
    }
    out
}

/// The facts of a finding for the Findings sheet: the stored shape as compact JSON, or `{"facts_unavailable":...}`.
pub fn facts_json(f: &FactsField, rules: &FactRules) -> String {
    match f {
        FactsField::Present { facts } => serde_json::to_string(facts).unwrap_or_default(),
        FactsField::Unavailable { facts_unavailable } => {
            serde_json::json!({ "facts_unavailable": rules.note(facts_unavailable) }).to_string()
        }
    }
}

/// An account's sign-in coverage in one line: `first to last` (ISO 8601 UTC), or `no sign-ins collected`.
pub fn signin_coverage(a: &AccountRow) -> String {
    match (a.signins_first, a.signins_last) {
        (Some(first), Some(last)) => format!(
            "sign-ins {} to {}",
            first.format("%Y-%m-%dT%H:%M:%SZ"),
            last.format("%Y-%m-%dT%H:%M:%SZ")
        ),
        _ => "no sign-ins collected".to_string(),
    }
}

/// An account's addresses in one line each: `ip (reasons)`, at most [`ADDRESSES_SHOWN`], then the rest counted.
pub fn address_items(a: &AccountRow, shown: usize) -> (Vec<String>, usize) {
    let items: Vec<String> = a
        .addresses
        .iter()
        .take(shown)
        .map(|x| format!("{} ({})", x.ip, x.reasons.join(", ")))
        .collect();
    let more = (a.addresses_total as usize).saturating_sub(items.len());
    (items, more)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::enrich::facts::{ActorIp, OtherSignals, Signal, Target};
    use chrono::{TimeZone, Utc};

    fn facts() -> FindingFacts {
        FindingFacts {
            facts_version: 1,
            window_start: Some(Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap()),
            actor_ips: vec![
                ActorIp {
                    ip: "198.51.100.7".into(),
                    asn: Some(64500),
                    asn_org: Some("Example Hosting".into()),
                    is_hosting: Some(true),
                    spray_source: true,
                    user_signin_days_before: Some(3),
                    user_first_signin: None,
                },
                ActorIp {
                    ip: "203.0.113.9".into(),
                    asn: None,
                    asn_org: None,
                    is_hosting: None,
                    spray_source: false,
                    user_signin_days_before: None,
                    user_first_signin: None,
                },
            ],
            other_signals: OtherSignals {
                total: 7,
                items: vec![Signal {
                    rule_id: "SPW-ID-004".into(),
                    severity: "high".into(),
                    first_seen: None,
                }],
            },
            targets: Some(vec![
                Target {
                    address: "bob@partner.example".into(),
                    domain: "partner.example".into(),
                    scope: "external".into(),
                    prior_messages: Some(14),
                },
                Target {
                    address: "carol@contoso.example".into(),
                    domain: "contoso.example".into(),
                    scope: "internal".into(),
                    prior_messages: None,
                },
            ]),
        }
    }

    #[test]
    fn the_sentences_are_the_fixed_templates_with_unknown_for_null() {
        let lines = fact_lines(&facts());
        assert_eq!(
            lines,
            vec![
                "Address 198.51.100.7 — this user signed in from it on 3 earlier day(s) within the capture (since 2026-08-01). It is in a hosting provider network (Example Hosting). It is a password-spray source of this tenant.",
                "Address 203.0.113.9 — earlier sign-ins from it by this user: unknown (not comparable within the capture).",
                "Other findings on this account: 7 (SPW-ID-004 high, +6 more).",
                "Target bob@partner.example — external; 14 earlier message(s) with this user.",
                "Target carol@contoso.example — internal; earlier messages with this user: unknown (not comparable within the capture).",
            ]
        );
        let none = FindingFacts {
            other_signals: OtherSignals {
                total: 0,
                items: vec![],
            },
            actor_ips: vec![],
            targets: None,
            ..facts()
        };
        assert_eq!(
            fact_lines(&none),
            vec!["No other findings on this account."]
        );
    }

    #[test]
    fn no_generated_sentence_says_benign_or_malicious() {
        let mut all = fact_lines(&facts());
        all.push(unavailable_line(
            "detection has not run since this version; run `sparrow detect`",
        ));
        for line in &all {
            let l = line.to_lowercase();
            assert!(!l.contains("benign") && !l.contains("malicious"), "{line}");
        }
    }

    #[test]
    fn values_are_escaped_and_the_unavailable_reason_keeps_its_fix() {
        let mut f = facts();
        f.actor_ips[0].ip = "x <!-- [^1](http://evil.example)".into();
        let s = &fact_lines(&f)[0];
        assert!(
            !s.contains("<!--") && !s.contains("](") && s.contains("&lt;"),
            "{s}"
        );
        let u = unavailable_line("run `sparrow detect`");
        assert_eq!(u, "Facts unavailable: run \\`sparrow detect\\`.");
    }
}
