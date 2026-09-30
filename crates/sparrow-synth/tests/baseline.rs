use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::Value;
use sparrow_synth::baseline::{day, directory_audits};
use sparrow_synth::scenario::{builtin_names, load};
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
    let mut interrupts = 0;
    let mut kept_yes = 0;
    let mut kept_no = 0;
    let mut seen = 0;
    for name in ["bec-aitm", "volume"] {
        let world = w(name);
        let start = world.window_start().date_naive();
        let days = (world.collected_at().date_naive() - start).num_days();
        for d in 0..=days {
            let recs = sts_records_on(&world, start + Duration::days(d));
            // The first *completed* sign-in of each user that day, as the baseline counts it: a
            // failed first attempt does not count, and carries a code as a failed logon. A sign-in
            // interrupt (`UserLoginFailed` + `Success`) is not a completed sign-in either, so it
            // is left out of "first" — it is its own case below.
            let mut earliest: BTreeMap<&str, DateTime<Utc>> = BTreeMap::new();
            for u in recs.iter().filter(|u| u.operation == "UserLoggedIn") {
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
                let interrupt = u.operation == "UserLoginFailed" && !failed_logon;
                // Every failed logon carries the method, and so does every successful
                // first-of-day sign-in; the later same-day sign-ins carry none.
                match u.audit["UserAuthenticationMethod"].as_i64() {
                    Some(code) => {
                        assert!(CODES.contains(&code), "{name}: code {code}");
                        assert!(
                            failed_logon || interrupt || is_first,
                            "{name}: a code on a later sign-in"
                        );
                        if failed_logon {
                            failed += 1;
                        } else if interrupt {
                            interrupts += 1;
                        } else {
                            first += 1;
                        }
                    }
                    None => {
                        assert_eq!(u.audit["UserAuthenticationMethod"], "");
                        assert!(
                            !failed_logon && !interrupt && !is_first,
                            "{name}: a failed or first sign-in without a code"
                        );
                        later += 1;
                    }
                }
                // The "Stay signed in?" prompt only follows a completed sign-in, and the
                // user answers it either way. An interrupt is not one: the prompt it stopped
                // at is the one being answered, so it never carries the answer.
                match &u.audit["KeepMeSignedIn"] {
                    Value::Bool(true) => {
                        assert!(
                            !failed_logon && !interrupt,
                            "{name}: a failed logon that kept the session"
                        );
                        kept_yes += 1;
                    }
                    Value::Bool(false) => {
                        assert!(
                            !failed_logon && !interrupt,
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
        failed > 0 && first > 0 && later > 0 && interrupts > 0,
        "{failed} failed, {interrupts} interrupted, {first} first of day, {later} later"
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

/// Every `New-ManagementRoleAssignment` the baseline logs, as (identity, role, group, time,
/// session).
fn rbac_assignments(w: &World) -> Vec<(String, String, String, DateTime<Utc>, String)> {
    let mut out = Vec::new();
    let mut d = w.window_start().date_naive();
    while d < w.window_end().date_naive() {
        for u in &day(w, d).ual {
            if u.operation != "New-ManagementRoleAssignment" {
                continue;
            }
            let param = |n: &str| -> String {
                u.audit["Parameters"]
                    .as_array()
                    .and_then(|ps| {
                        ps.iter()
                            .find(|p| p["Name"] == n)
                            .map(|p| p["Value"].as_str().unwrap_or_default().to_string())
                    })
                    .unwrap_or_default()
            };
            out.push((
                u.audit["ObjectId"].as_str().unwrap_or_default().to_string(),
                param("Role"),
                param("RoleGroup"),
                u.time,
                u.audit["SessionId"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            ));
        }
        d += Duration::days(1);
    }
    out
}

/// A built-in role assignment already exists in the tenant (its `EDiscoveryRoleAssignments`
/// row says `WhenCreated = tenant.created`), so logging its creation would be impossible. The
/// baseline logs one new CUSTOM assignment instead, and it never logs a built-in.
#[test]
fn the_baseline_rbac_change_is_a_new_custom_assignment() {
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        for seed in [1u64, 7, 42] {
            let world = World::build(&load(name).unwrap(), seed).unwrap();
            let logged = rbac_assignments(&world);
            assert!(!logged.is_empty(), "{name} seed {seed}: no RBAC change");
            // The built-ins are the assignments that predate the window; the custom one the
            // baseline logs is the assignment it creates, so it is not "already there".
            let built_in: BTreeSet<(&str, &str)> = world
                .exchange_role_assignments
                .iter()
                .filter(|a| a.group != sparrow_synth::world::CUSTOM_ROLE_GROUP)
                .map(|a| (a.role.as_str(), a.group.as_str()))
                .collect();
            for (identity, role, group, _, _) in &logged {
                assert!(
                    !built_in.contains(&(role.as_str(), group.as_str())),
                    "{name} seed {seed}: re-logged the built-in {role}/{group}"
                );
                assert!(!identity.is_empty(), "{name} seed {seed}: empty identity");
            }
            // The state and the log agree: the world carries the custom assignment with the
            // creation time the log stamped, and no built-in is ever re-logged.
            let custom = world
                .exchange_role_assignments
                .iter()
                .find(|a| a.group == sparrow_synth::world::CUSTOM_ROLE_GROUP)
                .expect("the world has the custom assignment");
            let logged_custom: Vec<_> = logged
                .iter()
                .filter(|(_, role, group, ..)| *role == custom.role && *group == custom.group)
                .collect();
            if !logged.is_empty() {
                assert_eq!(logged_custom.len(), 1, "{name} seed {seed}");
                assert_eq!(
                    logged_custom[0].3, custom.created,
                    "{name} seed {seed}: the log time and the state time differ"
                );
            }
        }
    }
}

/// The benign baseline must not assign `Mailbox Import Export`: granting it is a BEC /
/// persistence step a future rule would flag, so the baseline stays clear of it.
#[test]
fn the_baseline_never_assigns_mailbox_import_export() {
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        for seed in [1u64, 7, 42] {
            for (_, role, group, _, _) in
                rbac_assignments(&World::build(&load(name).unwrap(), seed).unwrap())
            {
                assert!(
                    !role.eq_ignore_ascii_case("Mailbox Import Export"),
                    "{name} seed {seed}: baseline assigned {role} to {group}"
                );
            }
        }
    }
}

/// The change lands on a day chosen by the seed, so it is not clustered on the first weekdays
/// of every window.
#[test]
fn the_rbac_change_day_varies_across_seeds() {
    let mut days = BTreeSet::new();
    for seed in [1u64, 7, 42, 99, 2024] {
        let world = World::build(&load("bec-aitm").unwrap(), seed).unwrap();
        for (_, _, _, t, _) in rbac_assignments(&world) {
            days.insert(t.date_naive());
        }
    }
    assert!(
        days.len() > 1,
        "the RBAC change lands on the same day in every seed: {days:?}"
    );
}

/// The change is run by an admin who actually signed in that day: the record reuses that
/// sign-in's session and client address.
#[test]
fn the_rbac_change_reuses_an_admin_sign_in_that_day() {
    for name in sparrow_synth::scenario::builtin_names()
        .iter()
        .filter(|n| **n != "volume")
    {
        for seed in [1u64, 7, 42] {
            let world = World::build(&load(name).unwrap(), seed).unwrap();
            for (identity, _, _, t, session) in rbac_assignments(&world) {
                let d = t.date_naive();
                let admin_ids: BTreeSet<String> =
                    world.admins.iter().map(|a| a.upn.clone()).collect();
                let day_events = day(&world, d);
                let same_day: Vec<&sparrow_synth::events::SignIn> = day_events
                    .signins
                    .iter()
                    .filter(|s| admin_ids.contains(&s.user))
                    .collect();
                assert!(
                    same_day.iter().any(|s| s.session_id.to_string() == session),
                    "{name} seed {seed}: {identity} has no admin sign-in on {d} with session {session}"
                );
            }
        }
    }
}

/// A user a storyline has sent on a trip does not also sign in from home: while the flight is
/// in the air there is no sign-in of theirs at all, and from the arrival until the end of the
/// window their sign-ins come from where they landed. Task 10's ID-003 look-alike depends on
/// this, because a home sign-in an hour after an arrival half a world away is impossible.
#[test]
fn a_travelling_user_signs_in_from_where_they_are() {
    for name in [
        "bec-aitm",
        "bec-e3-audit-gaps",
        "bec-o365-no-p1",
        "business-basic",
    ] {
        let mut world = w(name);
        let (w2, recs) = {
            let recs = sparrow_synth::story::apply(&mut world).unwrap();
            (world, recs)
        };
        let trips: Vec<_> = w2
            .trips
            .iter()
            .map(|t| (t.user.clone(), t.departure, t.arrival, t.location.clone()))
            .collect();
        assert!(!trips.is_empty(), "{name}: no trip");
        for (user, departure, arrival, location) in &trips {
            let home_ip = w2.user_by_upn(user).unwrap().home_ip;
            let days = (w2.collected_at().date_naive() - w2.window_start().date_naive()).num_days();
            for d in 0..=days {
                let day = w2.window_start().date_naive() + Duration::days(d);
                for s in sts_and_all_signins(&w2, day) {
                    if s.user != *user {
                        continue;
                    }
                    // In the air: no sign-in of theirs at all.
                    assert!(
                        s.time < *departure || s.time >= *arrival,
                        "{name}: a sign-in in the air at {}",
                        s.time
                    );
                    if s.time >= *arrival {
                        // Away: the destination, never home.
                        assert_ne!(s.ip, home_ip, "{name}: a home sign-in at {}", s.time);
                        assert_eq!(s.location.city, location.city, "{name}: {}", s.time);
                    }
                }
            }
        }
        assert!(!recs.is_empty());
    }
}

/// The sign-in records of a day (every event type, not just the logon ones).
fn sts_and_all_signins(w: &World, date: NaiveDate) -> Vec<sparrow_synth::events::SignIn> {
    day(w, date).signins
}

/// A user in the air has no sign-in at all, in any channel: not in the sign-in table and not
/// in the audit log either, which is where a parser reads a logon back from. Between the
/// departure and the arrival there is nothing but the departure sign-in itself.
#[test]
fn a_travelling_user_has_no_sign_in_while_in_the_air() {
    for name in builtin_names() {
        for seed in [7u64, 21, 42] {
            let mut world = World::build(&load(name).unwrap(), seed).unwrap();
            sparrow_synth::story::apply(&mut world).unwrap();
            let trips: Vec<_> = world
                .trips
                .iter()
                .map(|t| (t.user.clone(), t.departure, t.arrival))
                .collect();
            for (user, departure, arrival) in &trips {
                let days = (world.collected_at().date_naive() - world.window_start().date_naive())
                    .num_days();
                for d in 0..=days {
                    let date = world.window_start().date_naive() + Duration::days(d);
                    let records = day(&world, date);
                    for s in records.signins.iter().filter(|s| &s.user == user) {
                        assert!(
                            s.time < *departure || s.time >= *arrival,
                            "{name} seed {seed}: a sign-in in the air at {} ({:?})",
                            s.time,
                            s.ip
                        );
                    }
                    // The logons the files carry: the audit log is what a parser turns back
                    // into a sign-in, so a sign-in in the air there is a sign-in in the air.
                    for u in records
                        .ual
                        .iter()
                        .filter(|u| u.record_type.number() == 15 && &u.user_id == user)
                    {
                        assert!(
                            u.time < *departure || u.time >= *arrival,
                            "{name} seed {seed}: a logon in the air at {} from {}",
                            u.time,
                            u.audit["ClientIP"]
                        );
                    }
                }
            }
        }
    }
}

/// A session's activity comes from the address that session signed in from: one session never
/// shows two IPs, over its sign-ins *and* its audit records. A session that moves is the
/// token-replay signal (SPW-ID-004), so a benign baseline must not produce one; only a storyline
/// may. The storylines are applied, since a traveller's session is the one that moves.
#[test]
fn a_session_keeps_the_address_it_signed_in_from() {
    for name in builtin_names() {
        for seed in [7u64, 21, 42] {
            // With the storylines applied: a traveller's session is the one that moves
            // address, so a world without them would never see one.
            let mut world = World::build(&load(name).unwrap(), seed).unwrap();
            sparrow_synth::story::apply(&mut world).unwrap();
            let days =
                (world.collected_at().date_naive() - world.window_start().date_naive()).num_days();
            for d in 0..=days {
                let date = world.window_start().date_naive() + Duration::days(d);
                let day = day(&world, date);
                // session -> the addresses that session shows, over its sign-ins and its audit
                // records.
                let mut ips: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                for s in &day.signins {
                    ips.entry(s.session_id.to_string())
                        .or_default()
                        .insert(s.ip.to_string());
                }
                for u in &day.ual {
                    let Some(session) = u.audit.get("SessionId").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let Some(ip) = u.audit.get("ClientIP").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    ips.entry(session.to_string())
                        .or_default()
                        .insert(ip.to_string());
                }
                for (session, seen) in &ips {
                    assert!(
                        seen.len() == 1,
                        "{name} seed {seed} {date}: session {session} shows {seen:?}"
                    );
                }
            }
        }
    }
}

/// A traveller's mailbox and OneDrive activity follows them: from the arrival it comes from the
/// destination, and in the flight window it does not exist at all. Left at home it would be a
/// session showing two addresses (SPW-ID-004) on the very look-alike meant to be a plausible
/// trip.
#[test]
fn mailbox_activity_follows_the_traveller() {
    // Counted over the whole matrix: a small tenant's traveller may have no mail of their own
    // after the arrival, but the property has to be exercised somewhere to be worth asserting.
    let mut away_total = 0;
    for name in builtin_names() {
        for seed in [7u64, 21, 42] {
            let mut world = World::build(&load(name).unwrap(), seed).unwrap();
            sparrow_synth::story::apply(&mut world).unwrap();
            for trip in world.trips.clone() {
                let days = (world.collected_at().date_naive() - world.window_start().date_naive())
                    .num_days();
                let mut away = 0;
                for d in 0..=days {
                    let date = world.window_start().date_naive() + Duration::days(d);
                    for u in day(&world, date).ual {
                        // The user's own records: the logon and the mailbox, mail and file
                        // activity, the ones a session carries.
                        if u.user_id != trip.user
                            || u.audit.get("SessionId").is_none()
                            || u.record_type.number() == 15
                        {
                            continue;
                        }
                        let ip = u.audit["ClientIP"].as_str().unwrap_or_default().to_string();
                        assert!(
                            u.time < trip.departure || u.time >= trip.arrival,
                            "{name} seed {seed}: {} in the air at {} from {ip}",
                            u.operation,
                            u.time
                        );
                        if u.time >= trip.arrival {
                            away += 1;
                            assert_eq!(
                                ip,
                                trip.ip.to_string(),
                                "{name} seed {seed}: {} at {} is not from the destination",
                                u.operation,
                                u.time
                            );
                        }
                    }
                }
                away_total += away;
            }
        }
    }
    assert!(
        away_total > 50,
        "only {away_total} records were checked after an arrival"
    );
}

/// A sign-in interrupt of a day: the `UserLoginFailed` records whose `ResultStatus` is
/// `Success`. The captures hold many of them (roughly 20-85% of all `UserLoginFailed` rows per
/// capture): the MFA / "Stay signed in?" prompt an interactive sign-in passes through, not a
/// failure.
fn interrupts_on(w: &World, date: NaiveDate) -> Vec<sparrow_synth::events::Ual> {
    sts_records_on(w, date)
        .into_iter()
        .filter(|u| u.operation == "UserLoginFailed" && u.audit["ResultStatus"] == "Success")
        .collect()
}

fn span(w: &World) -> impl Iterator<Item = NaiveDate> + '_ {
    let start = w.window_start().date_naive();
    let days = (w.collected_at().date_naive() - start).num_days();
    (0..=days).map(move |d| start + Duration::days(d))
}

#[test]
fn sign_in_interrupts_are_named_and_precede_the_sign_in_they_interrupt() {
    let mut seen = 0;
    for name in ["bec-aitm", "volume", "hawk-investigate"] {
        let world = w(name);
        for date in span(&world) {
            let recs = sts_records_on(&world, date);
            for i in interrupts_on(&world, date) {
                seen += 1;
                // An interrupt always names why it interrupted, with a documented Entra sign-in
                // error code (Microsoft Learn, "Microsoft Entra authentication and authorization
                // error codes", linked from `ual::logon_error`).
                let error = i.audit["LogonError"].as_str().unwrap_or_default();
                assert!(error.ends_with("Interrupt"), "{name}: {error:?}");
                assert!(
                    matches!(
                        error,
                        "UserStrongAuthMFARequiredInterrupt"
                            | "UserStrongAuthClientAuthNRequiredInterrupt"
                            | "UserStrongAuthEnrollmentRequiredInterrupt"
                    ),
                    "{name}: {error:?}"
                );
                let number: i64 = i.audit["ErrorNumber"]
                    .as_str()
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or_default();
                assert!(number > 0, "{name}: ErrorNumber {number}");
                // The "Stay signed in?" answer lives on the `UserLoggedIn`, never on the
                // interrupt that led to it.
                assert_eq!(i.audit["KeepMeSignedIn"], "");

                // It precedes a `UserLoggedIn` Success of the same user, from the same address,
                // for the same application and client, a few seconds later.
                let gap = recs
                    .iter()
                    .filter(|u| {
                        u.operation == "UserLoggedIn"
                            && u.user_id == i.user_id
                            && u.audit["ClientIP"] == i.audit["ClientIP"]
                            && u.audit["ObjectId"] == i.audit["ObjectId"]
                            && u.audit["ExtendedProperties"]["UserAgent"]
                                == i.audit["ExtendedProperties"]["UserAgent"]
                    })
                    .map(|u| (u.time - i.time).num_seconds())
                    .filter(|s| (1..=60).contains(s))
                    .min();
                assert!(
                    gap.is_some(),
                    "{name}: no UserLoggedIn 1..60 s after the {error} of {} at {}",
                    i.user_id,
                    i.time
                );
            }
        }
    }
    assert!(seen > 20, "only {seen} sign-in interrupts");
}

#[test]
fn interrupts_are_a_share_of_the_sign_ins_and_of_the_failed_logons() {
    // The captures measure two things: interrupts are a share of the interactive sign-ins, and
    // 20-85% of all `UserLoginFailed` rows (the brief's band). Both are asserted, over scenarios
    // and seeds, so a share that drifts out of the measured range fails here.
    for name in ["bec-aitm", "volume", "hawk-investigate"] {
        for seed in [42u64, 7] {
            let world = sparrow_synth::world::World::build(&load(name).unwrap(), seed).unwrap();
            let (mut interrupts, mut failed, mut signins) = (0u64, 0u64, 0u64);
            for date in span(&world) {
                for u in sts_records_on(&world, date) {
                    match (
                        u.operation.as_str(),
                        u.audit["ResultStatus"].as_str().unwrap_or_default(),
                    ) {
                        ("UserLoginFailed", "Success") => interrupts += 1,
                        ("UserLoginFailed", "Failed") => failed += 1,
                        ("UserLoggedIn", "Success") => signins += 1,
                        _ => {}
                    }
                }
            }
            assert!(
                interrupts > 0 && failed > 0 && signins > 0,
                "{name} seed {seed}: {interrupts} interrupts, {failed} failed, {signins} sign-ins"
            );
            // A share of the sign-ins the interactive users make, small but not vanishing.
            let share = interrupts as f64 / (interrupts + signins) as f64;
            assert!(
                (0.02..0.35).contains(&share),
                "{name} seed {seed}: interrupts are {share:.3} of the successful sign-ins"
            );
            // The measured band: 20-85% of all UserLoginFailed rows.
            let of_failed = interrupts as f64 / (interrupts + failed) as f64;
            assert!(
                (0.20..0.85).contains(&of_failed),
                "{name} seed {seed}: interrupts are {of_failed:.3} of the UserLoginFailed rows"
            );
        }
    }
}

#[test]
fn a_real_failed_logon_keeps_its_own_result_status() {
    // The interrupt must not swallow the failure: a genuine failed logon still reads
    // ResultStatus Failed, keeps its own LogonError, and keeps no session to keep. A failure
    // never carries a code whose LogonError is an `…Interrupt` name -- that name means the user
    // answered a prompt, which is a success the audit log records under UserLoginFailed. The
    // ResultStatus is what separates the two, and the code must agree with it.
    const FAILURE_CODES: [i64; 2] = [50126, 50053];
    let world = w("bec-aitm");
    let mut failed = 0;
    let mut seen_codes: BTreeSet<i64> = BTreeSet::new();
    for date in span(&world) {
        for u in sts_records_on(&world, date)
            .into_iter()
            .filter(|u| u.audit["ResultStatus"] == "Failed")
        {
            failed += 1;
            assert_eq!(u.operation, "UserLoginFailed");
            let error = u.audit["LogonError"].as_str().unwrap_or_default();
            assert!(
                !error.is_empty(),
                "{date}: a failed logon with no LogonError"
            );
            assert!(
                !error.ends_with("Interrupt"),
                "{date}: a genuine failure labelled {error:?}"
            );
            let number: i64 = u.audit["ErrorNumber"]
                .as_str()
                .unwrap_or_default()
                .parse::<i64>()
                .unwrap();
            assert!(
                FAILURE_CODES.contains(&number),
                "{date}: a failure with the unexpected code {number} ({error})"
            );
            seen_codes.insert(number);
            assert_eq!(u.audit["KeepMeSignedIn"], "");
        }
    }
    assert!(failed > 0, "no failed logons");
    // Both genuine failure codes occur, so the pool is not one code in practice.
    assert_eq!(seen_codes.len(), 2, "{seen_codes:?}");
}

/// A sign-in interrupt follows the traveller like every other record of theirs: none exists in
/// the flight window, and from the arrival the address is the destination's. An interrupt is a
/// `StsLogon` record (record type 15), which `mailbox_activity_follows_the_traveller` skips, so
/// the property is asserted here.
#[test]
fn a_sign_in_interrupt_follows_the_traveller() {
    let mut away_total = 0;
    for name in builtin_names() {
        for seed in [7u64, 21, 42] {
            let mut world = World::build(&load(name).unwrap(), seed).unwrap();
            sparrow_synth::story::apply(&mut world).unwrap();
            for trip in world.trips.clone() {
                let days = (world.collected_at().date_naive() - world.window_start().date_naive())
                    .num_days();
                let mut away = 0;
                for d in 0..=days {
                    let date = world.window_start().date_naive() + Duration::days(d);
                    for u in interrupts_on(&world, date) {
                        if u.user_id != trip.user {
                            continue;
                        }
                        assert!(
                            u.time < trip.departure || u.time >= trip.arrival,
                            "{name} seed {seed}: an interrupt in the air at {}",
                            u.time
                        );
                        if u.time >= trip.arrival {
                            away += 1;
                            assert_eq!(
                                u.audit["ClientIP"].as_str().unwrap_or_default(),
                                trip.ip.to_string(),
                                "{name} seed {seed}: an interrupt at {} is not from the destination",
                                u.time
                            );
                        }
                    }
                }
                away_total += away;
            }
        }
    }
    assert!(
        away_total > 0,
        "no sign-in interrupt was checked after an arrival"
    );
}
