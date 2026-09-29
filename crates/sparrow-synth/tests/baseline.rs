use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::Value;
use sparrow_synth::baseline::{day, directory_audits};
use sparrow_synth::scenario::load;
use sparrow_synth::world::World;
use std::collections::{BTreeMap, BTreeSet};

fn w(name: &str) -> World {
    World::build(&load(name).unwrap(), 42).unwrap()
}

fn first_monday(w: &World) -> NaiveDate {
    let mut d = w.window_start().date_naive();
    while d.format("%a").to_string() != "Mon" {
        d += Duration::days(1);
    }
    d
}

/// The sign-in records (`AzureActiveDirectoryStsLogon`) of one day.
fn sts_records_on(w: &World, date: NaiveDate) -> Vec<sparrow_synth::events::Ual> {
    day(w, date)
        .ual
        .into_iter()
        .filter(|u| u.record_type.number() == 15)
        .collect()
}

#[test]
fn a_day_is_deterministic_and_sorted() {
    let world = w("bec-aitm");
    let d = first_monday(&world);
    let a = day(&world, d);
    let b = day(&world, d);
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
    assert!(!a.ual.is_empty() && !a.signins.is_empty() && !a.trace.is_empty());
    assert!(
        a.ual
            .windows(2)
            .all(|p| (p[0].time, p[0].id) <= (p[1].time, p[1].id))
    );
    assert!(a.ual.iter().all(|u| u.time.date_naive() == d));
}

#[test]
fn audit_data_has_the_common_keys_in_order() {
    let world = w("bec-aitm");
    let d = day(&world, first_monday(&world));
    for u in &d.ual {
        let keys: Vec<&str> = u.audit.keys().map(String::as_str).take(4).collect();
        assert_eq!(
            keys,
            ["CreationTime", "Id", "Operation", "OrganizationId"],
            "{}",
            u.operation
        );
        assert_eq!(u.audit["Id"], u.id.to_string());
        assert_eq!(
            u.audit["CreationTime"],
            u.time.format("%Y-%m-%dT%H:%M:%S").to_string()
        );
        assert_eq!(
            u.audit["OrganizationId"],
            world.tenant.tenant_id.to_string()
        );
    }
}

#[test]
fn one_story_across_sources() {
    let world = w("bec-aitm");
    let d = day(&world, first_monday(&world));
    let sessions: BTreeSet<String> = d.signins.iter().map(|s| s.session_id.to_string()).collect();
    let msg_ids: BTreeSet<&str> = d
        .trace
        .iter()
        .map(|t| t.internet_message_id.as_str())
        .collect();
    let mia: Vec<_> = d
        .ual
        .iter()
        .filter(|u| u.operation == "MailItemsAccessed")
        .collect();
    assert!(!mia.is_empty());
    for u in &mia {
        let sid = u.audit["AppAccessContext"]["AADSessionId"]
            .as_str()
            .unwrap();
        assert!(sessions.contains(sid), "MIA session {sid} has no sign-in");
        for f in u.audit["Folders"].as_array().unwrap() {
            for item in f["FolderItems"].as_array().into_iter().flatten() {
                assert!(msg_ids.contains(item["InternetMessageId"].as_str().unwrap()));
            }
        }
    }
    assert!(d.ual.iter().any(|u| u.operation == "Send"));
}

#[test]
fn audit_settings_decide_what_is_logged() {
    let gaps = w("bec-e3-audit-gaps");
    let d = day(&gaps, first_monday(&gaps));
    assert!(
        !d.ual
            .iter()
            .any(|u| u.operation == "MailItemsAccessed" || u.operation == "Send")
    );
    assert!(d.ual.iter().any(|u| u.operation == "FileAccessed"));
    let off = w("business-basic");
    let d = day(&off, first_monday(&off));
    assert!(
        !d.ual
            .iter()
            .any(|u| matches!(u.record_type.number(), 2 | 3 | 50))
    );
    // Without P2 every sign-in risk level reads hidden; with P2 they are visible.
    assert!(
        day(&gaps, first_monday(&gaps))
            .signins
            .iter()
            .all(|s| s.risk_during == "hidden")
    );
    let e5 = w("bec-aitm");
    assert!(
        day(&e5, first_monday(&e5))
            .signins
            .iter()
            .all(|s| s.risk_during != "hidden")
    );
}

#[test]
fn directory_audits_cover_the_window() {
    let world = w("hawk-investigate");
    let audits = directory_audits(&world);
    assert!(!audits.is_empty());
    assert!(
        audits
            .iter()
            .all(|a| a.time >= world.window_start() && a.time < world.window_end())
    );
}

fn day_text(d: &sparrow_synth::events::Day) -> String {
    let mut text = String::new();
    for u in &d.ual {
        text.push_str(&u.audit_data_text());
        text.push('\n');
    }
    for s in &d.signins {
        text.push_str(&format!("{s:?}\n"));
    }
    for t in &d.trace {
        text.push_str(&format!("{t:?}\n"));
    }
    text
}

#[test]
fn generated_values_are_reserved() {
    for name in sparrow_synth::scenario::builtin_names() {
        let world = w(name);
        let mut text = day_text(&day(&world, first_monday(&world)));
        text.push_str(&format!("{:?}", directory_audits(&world)));
        text.push_str(&format!("{:?}", sparrow_synth::baseline::risk(&world)));
        let bad = sparrow_synth::reserved::scan_text(&text);
        assert!(bad.is_empty(), "{name}: {bad:?}");
    }
}

#[test]
fn ual_cut_off_and_mailbox_bypass_are_honoured() {
    let mut world = w("bec-aitm");
    let d = first_monday(&world);
    let noon = d.and_hms_opt(12, 0, 0).unwrap().and_utc();
    world.audit.ual_disabled_at = Some(noon);
    assert!(day(&world, d).ual.iter().all(|u| u.time < noon));

    let mut world = w("bec-aitm");
    let upn = world.user(1).upn.clone();
    let mb = world.mailboxes.get_mut(&upn).unwrap();
    mb.bypass = true;
    mb.bypass_since = None;
    let dd = day(&world, d);
    assert!(
        !dd.ual
            .iter()
            .any(|u| matches!(u.record_type.number(), 2 | 3 | 50)
                && u.audit["MailboxOwnerUPN"] == upn.as_str())
    );
    assert!(dd.ual.iter().any(|u| u.record_type.number() == 50));
}

/// SPW-HAWK-015 (coverage.yaml:263-271) fires on a UAL `Set-MailboxAutoReplyConfiguration`
/// whose `AutoReplyState` is `Enabled` or `Scheduled`, so no baseline day may emit one: the
/// benign event is a user switching their out-of-office off. Checked over every built-in
/// scenario, every day of its window, and several seeds.
#[test]
fn the_baseline_never_enables_an_out_of_office() {
    let mut total = 0usize;
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        for seed in [1u64, 7, 42] {
            let world = World::build(&load(name).unwrap(), seed).unwrap();
            let mut d = world.window_start().date_naive();
            while d < world.window_end().date_naive() {
                for u in &day(&world, d).ual {
                    if u.operation != "Set-MailboxAutoReplyConfiguration" {
                        continue;
                    }
                    total += 1;
                    let state = u.audit["Parameters"]
                        .as_array()
                        .map(|ps| {
                            ps.iter()
                                .filter(|p| p["Name"] == "AutoReplyState")
                                .map(|p| p["Value"].as_str().unwrap_or_default().to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    assert!(
                        !state.eq_ignore_ascii_case("Enabled")
                            && !state.eq_ignore_ascii_case("Scheduled"),
                        "{name} seed {seed} {d}: {state}"
                    );
                }
                d += Duration::days(1);
            }
        }
    }
    // Not vacuous: the benign event really is emitted across the built-in scenarios.
    assert!(total > 0, "no baseline out-of-office change at all");
}

/// Task F4a fix: the sign-in session properties of an `AzureActiveDirectoryStsLogon` record are
/// typed the way the real captures hold them. `UserAuthenticationMethod` is an integer on every
/// failed logon and on a user's first sign-in of the day (and empty on that user's later
/// same-day sign-ins), `KeepMeSignedIn` is a boolean on a small share of the successful
/// authentications that showed the "Stay signed in?" prompt and empty otherwise, and `ZipCode`
/// is always empty.
#[test]
fn sts_logon_session_properties_are_typed_like_the_real_records() {
    // The authentication-method codes are inferred, not documented (see `ual::sts_logon`).
    const CODES: [i64; 3] = [1, 2, 3];
    let mut failed = 0;
    let mut first = 0;
    let mut later = 0;
    let mut kept_yes = 0;
    let mut kept_no = 0;
    let mut seen = 0;
    for name in ["bec-aitm", "volume"] {
        let world = w(name);
        let start = world.window_start().date_naive();
        let days = (world.collected_at().date_naive() - start).num_days();
        for d in 0..=days {
            let recs = sts_records_on(&world, start + Duration::days(d));
            // The first sign-in of each user that day, as the baseline counts it.
            let mut earliest: BTreeMap<&str, DateTime<Utc>> = BTreeMap::new();
            for u in &recs {
                earliest
                    .entry(u.user_id.as_str())
                    .and_modify(|t| *t = (*t).min(u.time))
                    .or_insert(u.time);
            }
            for u in &recs {
                seen += 1;
                // The properties are always present, so the columns are always in the files.
                for k in ["UserAuthenticationMethod", "KeepMeSignedIn", "ZipCode"] {
                    assert!(u.audit.get(k).is_some(), "{name}: {k} is missing");
                }
                assert_eq!(u.audit["ZipCode"], "");
                let is_first = earliest[u.user_id.as_str()] == u.time;
                let failed_logon = u.audit["ResultStatus"] == "Failed";
                // Every failed logon carries the method, and so does every successful
                // first-of-day sign-in; the later same-day sign-ins carry none.
                match u.audit["UserAuthenticationMethod"].as_i64() {
                    Some(code) => {
                        assert!(CODES.contains(&code), "{name}: code {code}");
                        assert!(
                            failed_logon || is_first,
                            "{name}: a code on a later sign-in"
                        );
                        if failed_logon {
                            failed += 1;
                        } else {
                            first += 1;
                        }
                    }
                    None => {
                        assert_eq!(u.audit["UserAuthenticationMethod"], "");
                        assert!(
                            !failed_logon && !is_first,
                            "{name}: a failed or first sign-in without a code"
                        );
                        later += 1;
                    }
                }
                // The "Stay signed in?" prompt only follows a successful authentication, and the
                // user answers it either way.
                match &u.audit["KeepMeSignedIn"] {
                    Value::Bool(true) => {
                        assert!(
                            !failed_logon,
                            "{name}: a failed logon that kept the session"
                        );
                        kept_yes += 1;
                    }
                    Value::Bool(false) => {
                        assert!(
                            !failed_logon,
                            "{name}: a failed logon that kept the session"
                        );
                        kept_no += 1;
                    }
                    Value::String(s) => assert!(s.is_empty(), "{name}: {s}"),
                    other => panic!("{name}: {other}"),
                }
            }
        }
    }
    assert!(seen > 20, "only {seen} sign-in records");
    // Every failed logon and every successful first-of-day sign-in carries the method, and
    // there are later same-day sign-ins that do not.
    assert!(
        failed > 0 && first > 0 && later > 0,
        "{failed} failed, {first} first of day, {later} later"
    );
    // Both answers to the prompt occur, on a small share of the records.
    assert!(kept_yes > 0 && kept_no > 0, "{kept_yes} yes, {kept_no} no");
    let share = (kept_yes + kept_no) as f64 / seen as f64;
    assert!(
        (0.005..0.05).contains(&share),
        "{} of {seen} records keep the flag ({share})",
        kept_yes + kept_no
    );
}

/// A real tenant cannot create the same role assignment twice: the cmdlet fails on a
/// duplicate, so a tree must not log the same identity twice. Each of the world's built-in
/// role assignments is created at most once per tree.
#[test]
fn each_role_assignment_is_created_at_most_once() {
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        for seed in [1u64, 7, 42] {
            let world = World::build(&load(name).unwrap(), seed).unwrap();
            let mut d = world.window_start().date_naive();
            let mut seen: BTreeMap<String, NaiveDate> = BTreeMap::new();
            let mut total = 0usize;
            while d < world.window_end().date_naive() {
                for u in &day(&world, d).ual {
                    if u.operation != "New-ManagementRoleAssignment" {
                        continue;
                    }
                    total += 1;
                    let identity = u.audit["ObjectId"].as_str().unwrap_or_default().to_string();
                    assert!(
                        seen.insert(identity.clone(), d).is_none(),
                        "{name} seed {seed}: {identity} created twice ({:?} and {d})",
                        seen.get(&identity)
                    );
                }
                d += Duration::days(1);
            }
            // Not vacuous: the event really is emitted, and never more than once per identity.
            assert!(total > 0, "{name} seed {seed}: no role assignment at all");
            assert!(
                total <= world.exchange_role_assignments.len(),
                "{name} seed {seed}: {total} records for {} assignments",
                world.exchange_role_assignments.len()
            );
        }
    }
}
