//! Expectations a tree's manifest carries beyond its files and rows: which licence evidence the
//! tree delivers, the capability outcomes (from the licence profile table), the
//! evidence-availability statuses Sparrow's profile may report, and the outcome each seed rule
//! must have on each storyline. Every rule is written here from the scenario and the writers'
//! outcome, never computed by Sparrow's code.

use crate::coverage::{RuleDef, rules};
use crate::events::Ual;
use crate::manifest::{CapExpect, EvidenceExpect, RuleExpect, RuleOutcome};
use crate::options::{Collector, GenerateOptions};
use crate::profiles::Delivery;
use crate::story::{Evidence, StoryRecord};
use crate::tree::TreeOutcome;
use crate::world::World;
use crate::writers::parsed_by_sparrow;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// `ual_events` and its child tables: a delivered UAL record counts for each of them.
const UAL_FAMILY: &[&str] = &[
    "ual_events",
    "mail_items_accessed",
    "file_events",
    "sharing_events",
    "search_queries",
];

/// Which licence evidence the tree delivers: Hawk 4 → `Hawk4`; Hawk 3 → `Hawk3`; portal →
/// `Portal`; Microsoft-Extractor-Suite → `InvictusList` when the tree writes the licence list
/// (`opts.invictus_licence_list`) and Sparrow parses it (`licence_list_parsed`, i.e.
/// `parsed_by_sparrow("inv.licenses.tenant")`), else `InvictusNoList`.
pub fn delivery(opts: &GenerateOptions, licence_list_parsed: bool) -> Delivery {
    match opts.collector {
        Collector::Hawk4 => Delivery::Hawk4,
        Collector::Hawk3 => Delivery::Hawk3,
        Collector::Portal => Delivery::Portal,
        Collector::Invictus if opts.invictus_licence_list && licence_list_parsed => {
            Delivery::InvictusList
        }
        Collector::Invictus => Delivery::InvictusNoList,
    }
}

/// The capability outcomes: the licence profile's hand-written `expect` line for `delivery`,
/// verbatim.
pub fn capabilities(world: &World, delivery: Delivery) -> BTreeMap<String, CapExpect> {
    world
        .licence
        .expect
        .get(&delivery)
        .cloned()
        .unwrap_or_default()
}

fn rows(out: &TreeOutcome, table: &str) -> u64 {
    out.tables.get(table).map_or(0, |t| t.rows)
}

fn allowed(statuses: &[&str], why: &str) -> EvidenceExpect {
    EvidenceExpect {
        allowed: statuses.iter().map(|s| s.to_string()).collect(),
        why: why.to_string(),
    }
}

/// UAL ingestion is off for the whole window (from before its start).
fn ual_off_all_window(w: &World) -> bool {
    match w.audit.ual_disabled_at {
        Some(t) => t <= w.window_start(),
        None => !w.audit.ual_ingestion_enabled,
    }
}

/// Organization mailbox auditing is off for the whole window.
fn org_audit_off_all_window(w: &World) -> bool {
    match w.audit.org_audit_disabled_at {
        Some(t) => t <= w.window_start(),
        None => w.audit.org_audit_disabled,
    }
}

/// The evidence-availability statuses Sparrow's profile may report, for these ids only (any
/// other id is not predicted):
/// - `ual`: UAL rows delivered → Hawk `{partial}` (Hawk searches selected operations only),
///   otherwise `{collected}`. None delivered because ingestion was off for the whole window →
///   Hawk (which writes `AdminAuditLogConfig.txt`) `{not_enabled}`, Microsoft-Extractor-Suite
///   `{collected}` (the run folder is written, nothing found).
/// - `mail_items_accessed`: rows delivered → `{collected, partial}`; none delivered, every
///   mailbox's owner list lacks MailItemsAccessed and the collector exports per-mailbox audit
///   settings (Microsoft-Extractor-Suite MailboxAuditStatus) → `{not_enabled}`; organization
///   auditing off for the whole window and the collector exports it (Hawk `OrgConfig.txt`,
///   Microsoft-Extractor-Suite EffectiveAuditState `Disabled`) → `{not_enabled}`.
/// - `signins`: Hawk 4 and Microsoft-Extractor-Suite (without Entra ID P1 the collector ran and
///   Graph refused, which Sparrow reads as "ran"), the portal, and any tree with P1 →
///   `{collected}`.
/// - `risk_detections`: expected `identity_protection` capability `not_licensed` →
///   `{not_licensed}`; with Entra ID P2 and rows delivered → `{collected}`.
/// - `licenses`: `InvictusList` delivery → `{collected}`.
pub fn evidence(
    world: &World,
    opts: &GenerateOptions,
    out: &TreeOutcome,
) -> BTreeMap<String, EvidenceExpect> {
    let mut m = BTreeMap::new();
    let hawk = matches!(opts.collector, Collector::Hawk3 | Collector::Hawk4);
    let invictus = opts.collector == Collector::Invictus;

    if rows(out, "ual_events") > 0 {
        let e = if hawk {
            allowed(&["partial"], "Hawk searches selected UAL operations only")
        } else {
            allowed(&["collected"], "UAL rows delivered")
        };
        m.insert("ual".to_string(), e);
    } else if ual_off_all_window(world) {
        if hawk {
            m.insert(
                "ual".to_string(),
                allowed(
                    &["not_enabled"],
                    "UAL ingestion disabled for the whole window (AdminAuditLogConfig.txt)",
                ),
            );
        } else if invictus {
            m.insert(
                "ual".to_string(),
                allowed(&["collected"], "Get-UAL ran and found nothing"),
            );
        }
    }

    if rows(out, "mail_items_accessed") > 0 {
        m.insert(
            "mail_items_accessed".to_string(),
            allowed(
                &["collected", "partial"],
                "MailItemsAccessed rows delivered",
            ),
        );
    } else if invictus
        && world
            .mailboxes
            .values()
            .all(|mb| !mb.audit_owner.iter().any(|a| a == "MailItemsAccessed"))
    {
        m.insert(
            "mail_items_accessed".to_string(),
            allowed(
                &["not_enabled"],
                "no mailbox audits MailItemsAccessed (MailboxAuditStatus)",
            ),
        );
    } else if (hawk || invictus) && org_audit_off_all_window(world) {
        m.insert(
            "mail_items_accessed".to_string(),
            allowed(
                &["not_enabled"],
                "organization mailbox auditing disabled for the whole window",
            ),
        );
    }

    let signins_collected = matches!(
        opts.collector,
        Collector::Hawk4 | Collector::Invictus | Collector::Portal
    ) || world.licence.p1();
    if signins_collected {
        m.insert(
            "signins".to_string(),
            allowed(&["collected"], "the sign-in collector ran"),
        );
    }

    let caps = capabilities(
        world,
        delivery(opts, parsed_by_sparrow("inv.licenses.tenant")),
    );
    let ip_not_licensed = caps
        .get("identity_protection")
        .is_some_and(|c| c.status == "not_licensed");
    if ip_not_licensed {
        m.insert(
            "risk_detections".to_string(),
            allowed(&["not_licensed"], "identity_protection is not_licensed"),
        );
    } else if world.licence.p2() && rows(out, "risk_detections") > 0 {
        m.insert(
            "risk_detections".to_string(),
            allowed(&["collected"], "Entra ID P2 and risk detections delivered"),
        );
    }

    if delivery(opts, parsed_by_sparrow("inv.licenses.tenant")) == Delivery::InvictusList {
        m.insert(
            "licenses".to_string(),
            allowed(&["collected"], "TenantLicenses.csv delivered and parsed"),
        );
    }
    m
}

/// The collector that wrote the tree, named from its files' artifact ids.
fn collector_name(out: &TreeOutcome) -> &'static str {
    let first = out.files.iter().find_map(|f| f.artifact_id.as_deref());
    match first.and_then(|a| a.split('.').next()) {
        Some("hawk") => "Hawk",
        Some("inv") => "Microsoft-Extractor-Suite",
        Some("portal") => "the portal export",
        _ => "the collector",
    }
}

/// The tables evidence `e` counts for: the tables it was delivered into, a UAL record's
/// `ual_events` delivery also counting for the child tables.
fn delivered_tables(e: &Evidence, out: &TreeOutcome) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (table, _) in out.delivered.get(e).into_iter().flatten() {
        if matches!(e, Evidence::Ual(_)) && table == "ual_events" {
            set.extend(UAL_FAMILY.iter().map(|t| t.to_string()));
        }
        set.insert(table.clone());
    }
    set
}

/// The outcome of every rule on every storyline record whose kind it lists (positive or
/// look-alike):
/// 1. a `requires` capability expected `not_licensed` → `not_applicable` (reason names it);
/// 2. else, when the rule has `requires_evidence` and every UAL evidence item of the storyline
///    that maps to the rule's tables (`ual_events` and its child tables) was not logged →
///    `not_applicable` (reason = `World::why_not_logged`);
/// 3. else, when any evidence item was delivered into one of the rule's tables (UAL evidence
///    delivered to `ual_events` counts for its child tables `mail_items_accessed`,
///    `file_events`, `sharing_events`, `search_queries`; a Hawk 3 writer delivers an
///    admin-audit rendering to `admin_audit_events` itself) → `hit` for a positive kind,
///    `no_hit` for a look-alike (`tables` = the rule's tables that received evidence);
/// 4. else `no_evidence` (the collector cannot supply it; reason names the collector).
pub fn rule_outcomes(
    world: &World,
    records: &[StoryRecord],
    caps: &BTreeMap<String, CapExpect>,
    out: &TreeOutcome,
) -> Vec<RuleExpect> {
    let ual: BTreeMap<Uuid, &Ual> = world.story.ual.iter().map(|u| (u.id, u)).collect();
    let mut v = Vec::new();
    for r in records {
        for rule in rules() {
            let positive = rule.positives.contains(&r.kind);
            if !positive && !rule.lookalikes.contains(&r.kind) {
                continue;
            }
            let (outcome, reason, tables) = outcome(world, &ual, r, rule, positive, caps, out);
            v.push(RuleExpect {
                rule_id: rule.id.clone(),
                storyline: r.id.clone(),
                outcome,
                reason,
                tables,
            });
        }
    }
    v
}

fn outcome(
    world: &World,
    ual: &BTreeMap<Uuid, &Ual>,
    r: &StoryRecord,
    rule: &RuleDef,
    positive: bool,
    caps: &BTreeMap<String, CapExpect>,
    out: &TreeOutcome,
) -> (RuleOutcome, String, Vec<String>) {
    if let Some(cap) = rule.requires.iter().find(|c| {
        caps.get(c.as_str())
            .is_some_and(|e| e.status == "not_licensed")
    }) {
        return (
            RuleOutcome::NotApplicable,
            format!("capability {cap} is not_licensed"),
            rule.tables.clone(),
        );
    }
    let ual_tables = rule.tables.iter().any(|t| UAL_FAMILY.contains(&t.as_str()));
    if !rule.requires_evidence.is_empty() && ual_tables {
        let reasons: Vec<Option<&'static str>> = r
            .evidence
            .iter()
            .filter_map(|e| match e {
                Evidence::Ual(id) => ual.get(id).map(|u| world.why_not_logged(u)),
                _ => None,
            })
            .collect();
        if !reasons.is_empty() && reasons.iter().all(Option::is_some) {
            return (
                RuleOutcome::NotApplicable,
                reasons[0].unwrap_or_default().to_string(),
                rule.tables.clone(),
            );
        }
    }
    let got: BTreeSet<String> = r
        .evidence
        .iter()
        .flat_map(|e| delivered_tables(e, out))
        .collect();
    let hit: Vec<String> = rule
        .tables
        .iter()
        .filter(|t| got.contains(t.as_str()))
        .cloned()
        .collect();
    if !hit.is_empty() {
        let (o, why) = if positive {
            (
                RuleOutcome::Hit,
                "evidence delivered into the rule's tables",
            )
        } else {
            (
                RuleOutcome::NoHit,
                "look-alike evidence delivered into the rule's tables",
            )
        };
        return (o, why.to_string(), hit);
    }
    (
        RuleOutcome::NoEvidence,
        format!(
            "{} delivered none of the storyline's evidence into {}",
            collector_name(out),
            rule.tables.join(", ")
        ),
        rule.tables.clone(),
    )
}
