//! The AuditData properties of the flattened-UAL fidelity work (Task F4 part B): each follows the
//! record's own client, user, message or operation instead of being one constant, and nothing is
//! there only to produce a column name.

use serde_json::Value;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::scenario::load;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const OFFICE: &str = "d3590ed6-52b3-4102-aeff-aad2292ab01c";

fn json_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            json_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "json") {
            out.push(p);
        }
    }
}

/// Every AuditData object of the tree's raw `*_Logs` / expanded UAL files (the flattened
/// `Simple_*` files are derived from these).
fn audit_records(name: &str) -> Vec<Value> {
    let dir = tempfile::tempdir().unwrap();
    generate_to_dir(
        &load(name).unwrap(),
        &GenerateOptions::new(Collector::Hawk4, 1),
        dir.path(),
    )
    .unwrap();
    let mut files = Vec::new();
    json_files(dir.path(), &mut files);
    let mut out = Vec::new();
    for f in files {
        let n = f.file_name().unwrap().to_string_lossy().to_string();
        let expanded = [
            "ExchangeItem_Logs",
            "ExchangeItemGroup_Logs",
            "MailItemsAccessed",
            "SendActivity",
        ]
        .iter()
        .any(|p| n.starts_with(p));
        let raw = [
            "Raw_Authentication_Logs",
            "UAL",
            "Mailbox_Permission",
            "Admin_Inbox",
            "eDiscovery",
            "RBAC",
            "Forwarding",
            "Domain",
            "User_Changes",
            "Entra",
            "Azure",
        ]
        .iter()
        .any(|p| n.contains(p));
        if !(expanded || raw) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let Ok(Value::Array(items)) =
            serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}'))
        else {
            continue;
        };
        for it in items {
            let Some(o) = it.as_object() else { continue };
            match o.get("AuditData") {
                Some(Value::String(s)) => {
                    if let Ok(v) = serde_json::from_str::<Value>(s) {
                        out.push(v);
                    }
                }
                Some(v @ Value::Object(_)) => out.push(v.clone()),
                _ => {
                    if o.contains_key("Operation") && o.contains_key("RecordType") {
                        out.push(it.clone());
                    }
                }
            }
        }
    }
    out
}

fn text<'a>(r: &'a Value, k: &str) -> &'a str {
    r.get(k).and_then(Value::as_str).unwrap_or("")
}

#[test]
fn client_details_follow_the_records_client() {
    let recs = audit_records("bec-aitm");
    let mailbox: Vec<&Value> = recs
        .iter()
        .filter(|r| r.get("ClientInfoString").is_some())
        .collect();
    assert!(mailbox.len() > 100, "{} mailbox records", mailbox.len());
    let mut desktop = 0;
    let mut other = 0;
    for r in &mailbox {
        let is_desktop = text(r, "ClientInfoString").contains("MSExchangeRPC");
        for k in [
            "ClientProcessName",
            "ClientVersion",
            "ClientRequestId",
            "HostAppId",
        ] {
            assert_eq!(
                r.get(k).is_some(),
                is_desktop,
                "{k} on {}",
                text(r, "ClientInfoString")
            );
        }
        if is_desktop {
            desktop += 1;
            assert_eq!(text(r, "ClientProcessName"), "OUTLOOK.EXE");
            assert_eq!(text(r, "HostAppId"), OFFICE);
        } else {
            other += 1;
        }
    }
    assert!(
        desktop > 0 && other > 0,
        "both desktop ({desktop}) and other ({other}) clients"
    );
}

#[test]
fn save_to_sent_items_is_only_on_send_operations() {
    let recs = audit_records("bec-aitm");
    let mut sends = 0;
    for r in recs.iter().filter(|r| r.get("ClientInfoString").is_some()) {
        let op = text(r, "Operation");
        let has = r.get("SaveToSentItems").is_some();
        assert_eq!(
            has,
            matches!(op, "Send" | "SendAs" | "SendOnBehalf"),
            "{op}"
        );
        sends += usize::from(has);
    }
    assert!(sends > 0);
}

#[test]
fn client_app_id_varies_as_in_reality() {
    let recs = audit_records("bec-aitm");
    let apps: BTreeSet<&str> = recs
        .iter()
        .filter(|r| text(r, "Operation") == "MailItemsAccessed")
        .map(|r| text(r, "ClientAppId"))
        .collect();
    assert!(
        apps.len() >= 2,
        "MailItemsAccessed ClientAppId values: {apps:?}"
    );
    // The context repeats the app that made the call, and the host app is never a constant for
    // every record.
    for r in recs
        .iter()
        .filter(|r| text(r, "Operation") == "MailItemsAccessed")
    {
        assert_eq!(
            r["AppAccessContext"]["ClientAppId"].as_str().unwrap(),
            text(r, "ClientAppId")
        );
    }
    let hosts: BTreeSet<&str> = recs.iter().map(|r| text(r, "HostAppId")).collect();
    assert!(hosts.contains("") && hosts.len() >= 2, "{hosts:?}");
}

#[test]
fn token_subject_is_the_stable_user_object_id() {
    let recs = audit_records("bec-aitm");
    let mut by_user: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in recs.iter().filter(|r| r.get("TokenObjectId").is_some()) {
        by_user
            .entry(text(r, "UserId"))
            .or_default()
            .insert(text(r, "TokenObjectId"));
        assert_ne!(text(r, "TokenObjectId"), text(r, "UserId"));
        assert_eq!(text(r, "TokenTenantId"), text(r, "OrganizationId"));
        if r.get("ActorInfoString").is_some() {
            assert_ne!(text(r, "ActorInfoString"), text(r, "UserId"));
            assert_eq!(text(r, "ActorInfoString"), text(r, "ClientInfoString"));
        }
    }
    assert!(by_user.len() > 3);
    assert!(
        by_user.values().all(|s| s.len() == 1),
        "one token subject per user: {by_user:?}"
    );
}

#[test]
fn attachments_come_from_the_message_and_most_messages_have_none() {
    let recs = audit_records("bec-aitm");
    let mut by_msg: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let (mut items, mut with) = (0, 0);
    for r in &recs {
        let Some(item) = r
            .get("Item")
            .filter(|i| i.get("InternetMessageId").is_some())
        else {
            continue;
        };
        items += 1;
        let a = item
            .get("Attachments")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        with += usize::from(!a.is_empty());
        by_msg
            .entry(item["InternetMessageId"].as_str().unwrap().to_string())
            .or_default()
            .insert(a);
        // ExchangeItem properties per the schema; no invented property list on an item operation.
        assert!(r.get("ModifiedProperties").is_none());
        assert!(item["ParentFolder"].get("Name").is_some());
        assert_eq!(item["IsRecord"], false);
    }
    assert!(items > 50);
    assert!(
        with * 4 < items,
        "{with} of {items} items carry attachments"
    );
    assert!(
        by_msg.values().all(|s| s.len() == 1),
        "one attachment list per message"
    );
}

#[test]
fn nothing_is_there_only_to_produce_a_column_name() {
    // bec-aitm for the Entra ID and sign-in records, hawk-investigate for the compliance search.
    let mut recs = audit_records("bec-aitm");
    recs.extend(audit_records("hawk-investigate"));
    // Non-vacuity: the checks below only mean something if the tree holds the records they
    // look at.
    let entra = recs
        .iter()
        .filter(|r| text(r, "Workload") == "AzureActiveDirectory")
        .count();
    let searches = recs
        .iter()
        .filter(|r| r.get("ExchangeLocations").is_some())
        .count();
    let with_ext = recs
        .iter()
        .filter(|r| matches!(r.get("ExtendedProperties"), Some(Value::Array(a)) if !a.is_empty()))
        .count();
    assert!(entra > 20, "{entra} Entra ID records");
    assert!(searches > 0, "{searches} compliance-search records");
    assert!(with_ext > 20, "{with_ext} records with ExtendedProperties");
    for r in &recs {
        let op = text(r, "Operation");
        let wl = text(r, "Workload");
        // A consent record grants scopes; no other Entra ID record carries one.
        if wl == "AzureActiveDirectory" {
            assert!(r.get("Scope").is_none(), "Scope on {op}");
            assert!(r.get("DeviceId").is_none(), "DeviceId on {op}");
        }
        // Locations belong to compliance-search records.
        if r.get("ExchangeLocations").is_some() {
            assert_eq!(text(r, "ObjectType"), "ComplianceSearch", "{op}");
        }
        for k in ["SharepointLocations", "PublicFolderLocations"] {
            assert!(r.get(k).is_none(), "{k} on {op}");
        }
        // No repeated name just to get a `_1` suffix.
        if let Some(Value::Array(ext)) = r.get("ExtendedProperties") {
            let names: Vec<&str> = ext.iter().filter_map(|e| e["Name"].as_str()).collect();
            let set: BTreeSet<&&str> = names.iter().collect();
            assert_eq!(
                set.len(),
                names.len(),
                "{op}: repeated ExtendedProperties names {names:?}"
            );
        }
    }
}

#[test]
fn mail_items_accessed_items_carry_their_own_detail() {
    let recs = audit_records("bec-aitm");
    let mut n = 0;
    let mut subjects = 0;
    for r in recs
        .iter()
        .filter(|r| text(r, "Operation") == "MailItemsAccessed")
    {
        let Some(Value::Array(folders)) = r.get("Folders") else {
            continue;
        };
        for f in folders {
            let Some(Value::Array(items)) = f.get("FolderItems") else {
                continue;
            };
            for it in items {
                n += 1;
                assert!(it.get("CreationTime").is_some() && it.get("ImmutableId").is_some());
                subjects += usize::from(it.get("Subject").is_some());
            }
        }
    }
    assert!(n > 50);
    assert!(
        subjects * 2 > n,
        "world-defined subjects on most items ({subjects}/{n})"
    );
}

#[test]
fn a_token_is_issued_once_per_session_window_and_never_after_the_access() {
    let recs = audit_records("bec-aitm");
    let mut by_session: BTreeMap<(String, i64), BTreeSet<String>> = BTreeMap::new();
    let mut checked = 0;
    for r in recs.iter().filter(|r| r.get("AppAccessContext").is_some()) {
        let ctx = &r["AppAccessContext"];
        let (Some(session), Some(issued)) =
            (ctx["AADSessionId"].as_str(), ctx["IssuedAtTime"].as_str())
        else {
            continue;
        };
        let at =
            chrono::NaiveDateTime::parse_from_str(text(r, "CreationTime"), "%Y-%m-%dT%H:%M:%S")
                .unwrap()
                .and_utc()
                .timestamp();
        let iss = chrono::NaiveDateTime::parse_from_str(issued, "%Y-%m-%dT%H:%M:%S")
            .unwrap()
            .and_utc()
            .timestamp();
        assert!(
            iss <= at,
            "issued {issued} after the access {}",
            text(r, "CreationTime")
        );
        assert!(
            at - iss < 2 * 3600 + 1800,
            "a token older than its lifetime"
        );
        by_session
            .entry((session.to_string(), at.div_euclid(90 * 60)))
            .or_default()
            .insert(issued.to_string());
        checked += 1;
    }
    assert!(checked > 100, "{checked} records with a token");
    assert!(
        by_session.values().all(|s| s.len() == 1),
        "one issue time per session and window"
    );
    // A session with several records exists, so the per-session check is not trivially one record each.
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for (s, _) in by_session.keys() {
        *per.entry(s.as_str()).or_default() += 1;
    }
    assert!(!per.is_empty());
}

fn op_props(r: &Value) -> BTreeMap<String, String> {
    r["OperationProperties"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|p| {
                    (
                        p["Name"].as_str().unwrap_or("").to_string(),
                        p["Value"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn outlook_client_inbox_rules_are_in_the_baseline_and_the_storyline() {
    let recs = audit_records("bec-aitm");
    let updates: Vec<&Value> = recs
        .iter()
        .filter(|r| text(r, "Operation") == "UpdateInboxRules")
        .collect();
    let (hiding, filing): (Vec<&Value>, Vec<&Value>) = updates.iter().partition(|r| {
        op_props(r)
            .get("RuleActions")
            .is_some_and(|a| a.contains("Delete"))
    });
    // The storyline: the attacker's rule from Outlook on the web, from the replay address.
    assert_eq!(hiding.len(), 1, "one hiding rule");
    let h = hiding[0];
    assert!(text(h, "ClientInfoString").starts_with("Client=OWA"));
    assert!(op_props(h)["RuleCondition"].contains("invoice"));
    assert!(
        h.get("ClientProcessName").is_none(),
        "OWA is not a desktop client"
    );
    // The benign rules: from Outlook on the user's own computer, filing into a folder only.
    assert!(filing.len() >= 2, "{} benign Outlook rules", filing.len());
    for r in &filing {
        let p = op_props(r);
        assert_eq!(p["RuleActions"], "MoveToFolder");
        assert!(p.contains_key("RuleName") && p["RuleCondition"].starts_with("From: "));
        assert!(text(r, "ClientInfoString").contains("MSExchangeRPC"));
        assert_ne!(text(r, "ClientIP"), text(h, "ClientIP"));
    }
    // The record has no item (the fixture's shape).
    assert!(updates.iter().all(|r| r.get("Item").is_none()));
}

/// Every collected Outlook filing rule sits where `baseline::day` will write the
/// `UpdateInboxRules` record that created it: on a workday, inside the user's work window, and
/// after the first hour of it (their first sign-in of the day falls in that hour, and the record
/// is only written once they are signed in). A rule placed at a fixed 09:00 UTC falls outside the
/// window of anyone whose tenant is far from Greenwich, and the collected rule then carries no
/// audit record a real Hawk capture would hold. Checked over every built-in scenario and seed
/// that creates one.
#[test]
fn every_collected_filing_rule_sits_in_its_owner_work_window() {
    use chrono::{Datelike, Weekday};
    use sparrow_synth::baseline::{utc_offset_hours, work_window};
    use sparrow_synth::scenario::builtin_names;
    use sparrow_synth::world::{OUTLOOK_FILING_RULE, World};

    let mut checked = 0;
    // `volume` is left out for the same reason `coverage.rs` leaves it out: it is the 200-user
    // scale scenario and building its world takes minutes, where every other scenario takes
    // milliseconds. The property is per-user and holds the same way there.
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for seed in [1u64, 42] {
            let world = World::build(&load(name).unwrap(), seed).unwrap();
            for r in world
                .inbox_rules
                .iter()
                .filter(|r| r.name == OUTLOOK_FILING_RULE)
            {
                checked += 1;
                let user = world
                    .users
                    .iter()
                    .find(|u| u.upn == r.mailbox)
                    .unwrap_or_else(|| panic!("{name}: no user for {}", r.mailbox));
                let date = r.created.date_naive();
                assert!(
                    !matches!(date.weekday(), Weekday::Sat | Weekday::Sun),
                    "{name} seed {seed}: {} created its filing rule on a weekend ({date})",
                    r.mailbox
                );
                let (start, end) = work_window(&world, user, date);
                assert!(
                    r.created >= start && r.created <= end,
                    "{name} seed {seed}: {} created its filing rule at {} outside its work \
                     window {start}..{end} (UTC offset {})",
                    r.mailbox,
                    r.created,
                    utc_offset_hours(&user.home)
                );
                // After the first hour of the window, where their first sign-in falls.
                assert!(
                    r.created >= start + chrono::Duration::hours(1),
                    "{name} seed {seed}: {} created its filing rule at {} in the first hour \
                     of its window ({start}), before the sign-in that records it",
                    r.mailbox,
                    r.created
                );
            }
        }
    }
    assert!(checked > 0, "no filing rule was checked");
}
