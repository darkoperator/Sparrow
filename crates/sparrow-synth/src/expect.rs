//! Expectations a tree's manifest carries beyond its files and rows: which licence evidence the
//! tree delivers, the capability outcomes (from the licence profile table), the
//! evidence-availability statuses Sparrow's profile may report, and the outcome each seed rule
//! must have on each storyline. Every rule is written here from the scenario and the writers'
//! outcome, never computed by Sparrow's code.

use crate::coverage::{RuleDef, rules};
use crate::events::{RecordType, Ual};
use crate::manifest::{CapExpect, EvidenceExpect, RuleExpect, RuleOutcome};
use crate::options::{Collector, GenerateOptions};
use crate::profiles::Delivery;
use crate::story::{Evidence, StoryRecord};
use crate::tree::TreeOutcome;
use crate::world::World;
use crate::writers::parsed_by_sparrow;
use crate::writers::portal::PURVIEW_EXPORT_CAP;
use chrono::Duration;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Entra ID sign-in and audit log retention with P1/P2 (Microsoft Learn
/// reference-reports-data-retention, as of 2026-09-25).
const ENTRA_P1_RETENTION_DAYS: i64 = 30;

/// The tables a UAL record lands in when a collector delivers it as a UAL record: always
/// `ual_events`, plus the child table its operation feeds (MailItemsAccessed →
/// `mail_items_accessed`; SearchQueryInitiated* → `search_queries`; SharePoint / OneDrive file
/// operations → `file_events`; sharing operations → `sharing_events`).
pub fn ual_tables(u: &Ual) -> Vec<&'static str> {
    let mut v = vec!["ual_events"];
    if u.operation == "MailItemsAccessed" {
        v.push("mail_items_accessed");
    } else if u.operation.starts_with("SearchQueryInitiated") {
        v.push("search_queries");
    } else if matches!(
        u.record_type,
        RecordType::SharePointFileOperation | RecordType::OneDrive
    ) {
        v.push("file_events");
    } else if u.record_type == RecordType::SharePointSharingOperation {
        v.push("sharing_events");
    }
    v
}

/// The tables UAL record `u` can land in under any collector: `ual_tables`, and
/// `admin_audit_events` for an Exchange admin cmdlet (Hawk 3 renders those as admin-audit
/// records).
fn ual_reach(u: &Ual) -> Vec<&'static str> {
    let mut v = ual_tables(u);
    if u.record_type == RecordType::ExchangeAdmin {
        v.push("admin_audit_events");
    }
    v
}

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
/// - `ual`: UAL rows delivered → Hawk `{partial}` (Hawk searches selected operations only);
///   portal with at least `PURVIEW_EXPORT_CAP` rows `{partial}` (the first export file holds
///   exactly the cap, which Sparrow flags as likely truncated); otherwise `{collected}`. None
///   delivered because ingestion was off for the whole window → Hawk (which writes
///   `AdminAuditLogConfig.txt`) `{not_enabled}`, Microsoft-Extractor-Suite `{collected}` (the
///   run folder is written, nothing found).
/// - `mail_items_accessed`: rows delivered → `{collected, partial}`; none delivered, every
///   mailbox's owner list lacks MailItemsAccessed and the tree delivers per-mailbox audit
///   settings (a parsed Microsoft-Extractor-Suite MailboxAuditStatus file) → `{not_enabled}`;
///   organization auditing off for the whole window and the tree delivers it (Hawk
///   `OrgConfig.txt`, MailboxAuditStatus EffectiveAuditState `Disabled`) → `{not_enabled}`.
/// - `signins`: Hawk 3 (no sign-in collector, no window in its log) →
///   `{available_not_collected}` (spec §7: available, not collected; with no window, Sparrow's
///   window end is `collected_at`); Hawk 4 rows → `{partial}` when the investigated
///   users are only some of the tenant's users (spec §7: "Hawk per-user collection covering only some users") or the window
///   starts before P1's retention, else `{collected}`; Hawk 4 and
///   Microsoft-Extractor-Suite (without Entra ID P1 the collector ran and Graph refused, which
///   Sparrow reads as "ran") and the portal → `{collected}`; except
///   Microsoft-Extractor-Suite rows with Entra ID P1 expected licensed
///   and a window starting more than P1's 30-day log retention before collection →
///   `{partial}` (Graph cannot reach the start of the window; the run stamps date the
///   collection).
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
    let audit_status = out
        .files
        .iter()
        .any(|f| f.artifact_id.as_deref() == Some("inv.audit_status") && f.status == "parsed");

    if rows(out, "ual_events") > 0 {
        let e = if hawk {
            allowed(&["partial"], "Hawk searches selected UAL operations only")
        } else if opts.collector == Collector::Portal
            && rows(out, "ual_events") >= PURVIEW_EXPORT_CAP as u64
        {
            allowed(
                &["partial"],
                "a Purview export file holds exactly the 50,000-row export cap",
            )
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
    } else if audit_status
        && !world.mailboxes.is_empty()
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
    } else if (hawk || audit_status) && org_audit_off_all_window(world) {
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
    );
    let caps = capabilities(
        world,
        delivery(opts, parsed_by_sparrow("inv.licenses.tenant")),
    );
    let p1_retention_short = caps
        .get("entra_id_p1")
        .is_some_and(|c| c.status == "licensed")
        && world.window_start() < world.collected_at() - Duration::days(ENTRA_P1_RETENTION_DAYS);
    let hawk_some_users =
        crate::writers::hawk::hawk_users(world).len() < world.all_people().count();
    if opts.collector == Collector::Hawk4 && rows(out, "signins") > 0 {
        let e = if hawk_some_users {
            allowed(
                &["partial"],
                "Hawk collected sign-ins for only some of the tenant's users",
            )
        } else if p1_retention_short {
            allowed(
                &["partial"],
                "the window starts before Entra ID P1's 30-day sign-in retention",
            )
        } else {
            allowed(&["collected"], "Hawk collected sign-ins for every user")
        };
        m.insert("signins".to_string(), e);
    } else if invictus && rows(out, "signins") > 0 && p1_retention_short {
        m.insert(
            "signins".to_string(),
            allowed(
                &["partial"],
                "the window starts before Entra ID P1's 30-day sign-in retention",
            ),
        );
    } else if signins_collected {
        m.insert(
            "signins".to_string(),
            allowed(&["collected"], "the sign-in collector ran"),
        );
    } else if opts.collector == Collector::Hawk3 {
        m.insert(
            "signins".to_string(),
            allowed(
                &["available_not_collected"],
                "Hawk 3 has no sign-in collector and logs no collection window, so Sparrow takes collected_at as the window end, which is within retention at evaluation (collection + 1 day)",
            ),
        );
    }

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
/// `ual_events` delivery standing for every table of `ual_tables` (an admin-audit rendering is
/// delivered to `admin_audit_events` by the writer itself).
fn delivered_tables(
    world: &World,
    e: &Evidence,
    rule: &RuleDef,
    ual: &BTreeMap<Uuid, &Ual>,
    out: &TreeOutcome,
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (table, sighting) in out.delivered.get(e).into_iter().flatten() {
        if table == "inbox_rules" && !state_row_meets(world, rule, e) {
            continue;
        }
        if table == "mailboxes" && !mailbox_file_carries(rule, &sighting.rel_path, out) {
            continue;
        }
        if let (Evidence::Ual(id), "ual_events") = (e, table.as_str()) {
            if let Some(u) = ual.get(id) {
                set.extend(ual_tables(u).iter().map(|t| t.to_string()));
            }
        }
        set.insert(table.clone());
    }
    set
}

/// Finance keywords and hiding folders of the rule pack, read once.
fn pack_lists() -> &'static BTreeMap<String, Vec<String>> {
    static LISTS: std::sync::OnceLock<BTreeMap<String, Vec<String>>> = std::sync::OnceLock::new();
    LISTS.get_or_init(|| {
        sparrow_core::detect::load::load_rules(&sparrow_core::data::DataDirs::default())
            .map(|s| s.lists)
            .unwrap_or_default()
    })
}

/// Whether the collected state row of an inbox rule meets the CONTENT `rule` reads (a row
/// delivered into `inbox_rules` is evidence only when what it says is what the rule looks for;
/// the qualifying part of a storyline may have been a cmdlet that was never logged, and the row
/// that survived a different rule of the same storyline). Rules that read an inbox rule's
/// content are decided from the world's rule; any other rule, or a rule the world no longer
/// holds, accepts the row.
fn state_row_meets(world: &World, rule: &RuleDef, e: &Evidence) -> bool {
    let Evidence::InboxRule {
        mailbox, identity, ..
    } = e
    else {
        return true;
    };
    let Some(r) = world
        .inbox_rules
        .iter()
        .find(|r| &r.mailbox == mailbox && r.identity.to_string() == *identity)
    else {
        return true;
    };
    let lists = pack_lists();
    let listed = |name: &str, v: &str| {
        lists
            .get(name)
            .is_some_and(|l| l.iter().any(|x| x.eq_ignore_ascii_case(v)))
    };
    let forwards = !r.forward_to.is_empty()
        || !r.forward_as_attachment_to.is_empty()
        || !r.redirect_to.is_empty();
    match rule.id.as_str() {
        "SPW-HAWK-010" => r.delete_message || forwards,
        "SPW-MAIL-003" => {
            let words = r
                .subject_contains
                .iter()
                .chain(&r.body_contains)
                .chain(&r.subject_or_body_contains);
            let keyword = words.into_iter().any(|w| {
                lists.get("finance_keywords").is_some_and(|l| {
                    l.iter()
                        .any(|k| w.to_lowercase().contains(&k.to_lowercase()))
                })
            });
            let folder = r
                .move_to_folder
                .as_deref()
                .is_some_and(|f| listed("hiding_folders", f) || f.chars().count() == 1);
            keyword || folder
        }
        "SPW-MAIL-004" => r
            .forward_to
            .iter()
            .chain(&r.forward_as_attachment_to)
            .chain(&r.redirect_to)
            .any(|a| {
                let domain = a
                    .rsplit_once('@')
                    .map_or("", |(_, d)| d.trim_end_matches(']'));
                !world
                    .tenant
                    .domains
                    .iter()
                    .chain([&world.tenant.initial_domain])
                    .any(|d| d.eq_ignore_ascii_case(domain))
            }),
        _ => true,
    }
}

/// Forwarding rules read a forwarding attribute of the mailbox row. The Microsoft-Extractor-Suite
/// mailbox files (permissions, audit status) list every mailbox but carry no forwarding field, so
/// a mailbox row delivered from them is not evidence for these rules.
const FORWARDING_RULES: [&str; 2] = ["SPW-HAWK-011", "SPW-MAIL-004"];

fn mailbox_file_carries(rule: &RuleDef, rel_path: &str, out: &TreeOutcome) -> bool {
    if !FORWARDING_RULES.contains(&rule.id.as_str()) {
        return true;
    }
    let artifact = out
        .files
        .iter()
        .find(|f| f.rel_path == rel_path)
        .and_then(|f| f.artifact_id.as_deref());
    !artifact.is_some_and(|a| a.starts_with("inv."))
}

/// The outcome of every rule on every storyline record whose kind it lists (positive or
/// look-alike):
/// 1. a `requires` capability expected `not_licensed` → `not_applicable` (reason names it);
/// 2. else, when the rule has `requires_evidence` and every UAL evidence item of the storyline
///    that maps to the rule's tables (`ual_tables`, plus `admin_audit_events` for Exchange
///    admin cmdlets) was not logged → `not_applicable` (reason = `World::why_not_logged`);
/// 3. else, when any evidence item was delivered into one of the rule's tables (a UAL record
///    delivered to `ual_events` counts for its `ual_tables`; a Hawk 3 writer delivers an
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
            let complete = !matches!(outcome, RuleOutcome::Hit | RuleOutcome::NoHit)
                || halves_distinct(world, r, records, rule, &ual, out);
            v.push(RuleExpect {
                rule_id: rule.id.clone(),
                storyline: r.id.clone(),
                outcome,
                reason,
                tables,
                complete,
            });
        }
    }
    v
}

/// Child tables a UAL record feeds; a group that lists one next to `ual_events` names the
/// record kind of that half (the upload or the sharing), so only the child table counts for it.
const UAL_CHILDREN: [&str; 4] = [
    "file_events",
    "sharing_events",
    "mail_items_accessed",
    "search_queries",
];

/// Whether every `evidence_all_of` group of `rule` is covered by a DISTINCT delivered evidence
/// item (one delivered UAL record cannot stand for both halves of a correlation). The items are
/// the storyline's own plus those of the other storylines of the same user (the risky sign-in
/// half of an anonymous link comes from the AiTM storyline); at least one must be the
/// storyline's own. A rule with a single group is always complete.
fn halves_distinct(
    world: &World,
    r: &StoryRecord,
    all: &[StoryRecord],
    rule: &RuleDef,
    ual: &BTreeMap<Uuid, &Ual>,
    out: &TreeOutcome,
) -> bool {
    if rule.evidence_all_of.len() < 2 {
        return true;
    }
    let mut items: Vec<(bool, BTreeSet<String>)> = Vec::new();
    for other in all.iter().filter(|o| o.actor == r.actor) {
        for e in &other.evidence {
            let t = delivered_tables(world, e, rule, ual, out);
            if !t.is_empty() {
                items.push((other.id == r.id, t));
            }
        }
    }
    let covers = |item: &BTreeSet<String>, group: &[String]| -> bool {
        let child = group.iter().any(|t| UAL_CHILDREN.contains(&t.as_str()));
        group
            .iter()
            .any(|t| item.contains(t) && !(child && t == "ual_events"))
    };
    fn assign(
        g: usize,
        groups: &[Vec<String>],
        items: &[(bool, BTreeSet<String>)],
        used: &mut Vec<bool>,
        own_used: bool,
        covers: &dyn Fn(&BTreeSet<String>, &[String]) -> bool,
    ) -> bool {
        if g == groups.len() {
            return own_used;
        }
        for i in 0..items.len() {
            if !used[i] && covers(&items[i].1, &groups[g]) {
                used[i] = true;
                if assign(g + 1, groups, items, used, own_used || items[i].0, covers) {
                    return true;
                }
                used[i] = false;
            }
        }
        false
    }
    assign(
        0,
        &rule.evidence_all_of,
        &items,
        &mut vec![false; items.len()],
        false,
        &covers,
    )
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
    if !rule.requires_evidence.is_empty() {
        let reasons: Vec<Option<&'static str>> = r
            .evidence
            .iter()
            .filter_map(|e| match e {
                Evidence::Ual(id) => ual
                    .get(id)
                    .filter(|u| {
                        ual_reach(u)
                            .iter()
                            .any(|t| rule.tables.iter().any(|r| r == t))
                    })
                    .map(|u| world.why_not_logged(u)),
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
        .flat_map(|e| delivered_tables(world, e, rule, ual, out))
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

/// Restrict the outcomes to what `collector` can supply, as `rules/coverage.yaml` documents it
/// (`collectors` for a positive kind, `lookalike_collectors` for a look-alike). A tree can carry
/// a row for the evidence (Microsoft-Extractor-Suite lists every mailbox) without the attribute
/// the rule reads (its mailbox list has no forwarding address); the outcome there is
/// `no_evidence`, not `hit` / `no_hit`. Decided from the coverage file, never from Sparrow.
pub fn restrict_to_collector(rules: &mut [RuleExpect], collector: Collector) {
    for r in rules {
        if !matches!(r.outcome, RuleOutcome::Hit | RuleOutcome::NoHit) {
            continue;
        }
        let Some(def) = crate::coverage::rule(&r.rule_id) else {
            continue;
        };
        let supplied = if r.outcome == RuleOutcome::Hit {
            def.collectors.contains(&collector)
        } else {
            def.lookalike_collectors.contains(&collector)
        };
        if !supplied {
            r.outcome = RuleOutcome::NoEvidence;
            r.reason = format!(
                "{} cannot supply {}'s evidence (coverage.yaml collectors)",
                collector.as_str(),
                r.rule_id
            );
        }
    }
}
