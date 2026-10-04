//! The computed expectations (`computed:` in `rules/coverage.yaml`, `sparrow_synth::oracle`): the rows
//! the oracle reads are the rows Sparrow ingests, the gate checks a computed outcome exactly in both
//! directions, and the shipped matrix tolerates nothing.

use sparrow_core::Case;
use sparrow_synth::cache::{Cache, Stage};
use sparrow_synth::check::check;
use sparrow_synth::generate::oracle_facts;
use sparrow_synth::manifest::{Manifest, RuleOutcome};
use sparrow_synth::options::{Collector, GenerateOptions};
use sparrow_synth::oracle::{AdminRow, Facts, SignInRow, UalRow};
use sparrow_synth::scenario::{builtin_names, load};
use std::collections::BTreeSet;
use std::net::IpAddr;

static CACHE: std::sync::LazyLock<Cache> =
    std::sync::LazyLock::new(|| sparrow_synth::test_cache!());

/// The manifest and a private copy of the detected case of a built-in scenario's tree.
fn detected(name: &str, c: Collector, seed: u64) -> (Manifest, Case) {
    let scenario = load(name).unwrap();
    let opts = GenerateOptions::new(c, seed);
    let cached = CACHE
        .case(&scenario, &opts, Stage::Detected)
        .unwrap_or_else(|e| panic!("{name} {c:?} seed {seed}: {e}"));
    (cached.tree.manifest.clone(), cached.case)
}

#[test]
fn the_shipped_coverage_has_no_baseline_allow() {
    let allowed: Vec<&str> = sparrow_synth::coverage::rules()
        .iter()
        .filter(|r| !r.baseline_allow.is_empty())
        .map(|r| r.id.as_str())
        .collect();
    assert!(allowed.is_empty(), "baseline_allow in {allowed:?}");
}

/// Every computed (rule, kind) of `rules/coverage.yaml` computed a `hit` that the gate confirmed
/// (flipped to `no_hit`, the finding became unexpected) somewhere in `seen`, unless the entry
/// declares `never_hits`, which must then still be true. Read from the file, not a list here.
fn assert_every_computed_kind_hits(seen: &BTreeSet<(String, String, &'static str)>) {
    let mut problems = Vec::new();
    for r in sparrow_synth::coverage::rules() {
        for c in &r.computed {
            let kind = c.kind.as_str().to_string();
            let hit = seen.contains(&(r.id.clone(), kind.clone(), "unexpected"));
            match (&c.never_hits, hit) {
                (None, false) => problems.push(format!(
                    "{} {kind}: computed but never a confirmed hit on these trees (declare never_hits with a reason, or make it a look-alike)",
                    r.id
                )),
                (Some(why), true) => problems.push(format!(
                    "{} {kind}: declares never_hits ({why}) but hits",
                    r.id
                )),
                _ => {}
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

fn ip(s: &str) -> IpAddr {
    s.parse()
        .unwrap_or_else(|_| panic!("not an address: {s:?}"))
}

fn some(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// Every difference between what the oracle reads for a tree and what Sparrow ingested from it:
/// the delivered sign-in, UAL and admin audit rows (each field a computed condition reads), the
/// addresses' `ip_intel`, and the spray sources and cloud services.
fn view_differences(name: &str, c: Collector) -> Vec<String> {
    let scenario = load(name).unwrap();
    let facts: Facts = oracle_facts(&scenario, &GenerateOptions::new(c, 1)).unwrap();
    let (_, case) = detected(name, c, 1);
    let conn = case.conn();
    let mut diffs = Vec::new();
    let mut st = conn
        .prepare(
            "SELECT record_key, epoch_ms(event_time), lower(user_upn), ip, error_code,
                    coalesce(is_interactive, true), session_id,
                    lower(coalesce(auth_requirement, '')) LIKE 'multifactor%'
                      OR lower(coalesce(mfa_result, '')) LIKE '%mfa successfully completed%',
                    lower(coalesce(risk_level_during, '')) IN ('medium', 'high'),
                    lower(coalesce(app_id, '')), coalesce(user_agent, '')
             FROM signins ORDER BY record_key",
        )
        .unwrap();
    let got: Vec<SignInRow> = st
        .query_map([], |r| {
            Ok(SignInRow {
                key: r.get(0)?,
                t: r.get(1)?,
                upn: some(r.get(2)?),
                ip: ip(&r.get::<_, String>(3)?),
                error: r.get::<_, Option<i64>>(4)?.unwrap_or(i64::MIN),
                interactive: r.get(5)?,
                session: some(r.get(6)?),
                mfa: r.get(7)?,
                risky: r.get(8)?,
                app: r.get(9)?,
                user_agent: r.get(10)?,
            })
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut want = facts.signins.clone();
    want.sort_by(|a, b| a.key.cmp(&b.key));
    compare(&mut diffs, "signins", &got, &want, |r| r.key.clone());

    let mut st = conn
        .prepare(
            "SELECT lower(CAST(record_id AS VARCHAR)), epoch_ms(event_time), user_upn, client_ip,
                    lower(trim(operation)), session_id, lower(app_id), user_agent,
                    lower(coalesce(result_status, '')) = 'failed'
             FROM ual_events ORDER BY 1",
        )
        .unwrap();
    let got: Vec<UalRow> = st
        .query_map([], |r| {
            Ok(UalRow {
                key: r.get(0)?,
                t: r.get(1)?,
                upn: some(r.get(2)?),
                ip: r.get::<_, Option<String>>(3)?.map(|s| ip(&s)),
                op: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                session: some(r.get(5)?),
                app: some(r.get(6)?),
                user_agent: some(r.get(7)?),
                failed: r.get(8)?,
            })
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut want = facts.ual.clone();
    want.sort_by(|a, b| a.key.cmp(&b.key));
    compare(&mut diffs, "ual_events", &got, &want, |r| r.key.clone());

    let mut st = conn
        .prepare(
            "SELECT record_key, epoch_ms(run_time), lower(caller), lower(cmdlet)
             FROM admin_audit_events ORDER BY record_key",
        )
        .unwrap();
    let got: Vec<AdminRow> = st
        .query_map([], |r| {
            Ok(AdminRow {
                key: r.get(0)?,
                t: r.get(1)?,
                caller: some(r.get(2)?),
                cmdlet: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            })
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut want = facts.admin.clone();
    want.sort_by(|a, b| a.key.cmp(&b.key));
    compare(&mut diffs, "admin_audit_events", &got, &want, |r| {
        r.key.clone()
    });

    let mut st = conn
        .prepare(
            "SELECT latitude, longitude, country_iso, asn, coalesce(is_hosting, false), is_microsoft
             FROM ip_intel WHERE ip = ?",
        )
        .unwrap();
    for (addr, f) in facts.ip_facts() {
        let row = st
            .query_row([addr.to_string()], |r| {
                Ok((
                    r.get::<_, Option<f64>>(0)?,
                    r.get::<_, Option<f64>>(1)?,
                    some(r.get(2)?),
                    r.get::<_, Option<i64>>(3)?.map(|a| a as u32),
                    r.get::<_, bool>(4)?,
                    r.get::<_, bool>(5)?,
                ))
            })
            .ok();
        let want = (
            f.lat,
            f.lon,
            f.country.clone(),
            f.asn,
            f.hosting,
            f.microsoft,
        );
        if row.as_ref() != Some(&want) {
            diffs.push(format!(
                "ip_intel {addr}: {row:?}, the oracle reads {want:?}"
            ));
        }
    }

    let mut st = conn.prepare("SELECT ip FROM spray_sources").unwrap();
    let spray: BTreeSet<IpAddr> = st
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| ip(&r.unwrap()))
        .collect();
    if spray != facts.spray {
        diffs.push(format!(
            "spray_sources {spray:?}, the oracle computes {:?}",
            facts.spray
        ));
    }
    let mut st = conn
        .prepare("SELECT app_id, asn FROM cloud_services")
        .unwrap();
    let cloud: BTreeSet<(String, u32)> = st
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    if cloud != facts.cloud {
        diffs.push(format!(
            "cloud_services {cloud:?}, the oracle computes {:?}",
            facts.cloud
        ));
    }
    diffs
        .into_iter()
        .map(|d| format!("{name} {c:?}: {d}"))
        .collect()
}

/// Row-by-row differences (missing, extra, different), at most a few per table.
fn compare<T: PartialEq + std::fmt::Debug>(
    diffs: &mut Vec<String>,
    table: &str,
    got: &[T],
    want: &[T],
    key: impl Fn(&T) -> String,
) {
    let mut n = 0;
    let mut push = |d: String| {
        n += 1;
        if n <= 5 {
            diffs.push(format!("{table}: {d}"));
        }
    };
    for w in want {
        match got.iter().find(|g| key(g) == key(w)) {
            None => push(format!("{} missing from the case", key(w))),
            Some(g) if g != w => push(format!("Sparrow {g:?}, the oracle reads {w:?}")),
            Some(_) => {}
        }
    }
    for g in got {
        if !want.iter().any(|w| key(w) == key(g)) {
            push(format!("{} not delivered according to the oracle", key(g)));
        }
    }
    if n > 5 {
        diffs.push(format!("{table}: {} more differences", n - 5));
    }
}

#[test]
fn the_oracle_reads_the_rows_sparrow_ingests() {
    let mut diffs = Vec::new();
    for c in Collector::ALL {
        diffs.extend(view_differences("bec-aitm", *c));
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn the_oracle_reads_the_rows_sparrow_ingests_on_every_scenario_and_collector() {
    let mut diffs = Vec::new();
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            diffs.extend(view_differences(name, *c));
        }
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}

/// Flips each computed `hit` / `no_hit` of a tree's manifest in turn and checks that the gate fails
/// in that direction for that storyline (a flipped `hit` is an unexpected finding; a flipped
/// `no_hit` a missing one), and passes with the computed outcomes. Returns the directions seen,
/// as (rule, kind, "unexpected" | "missing").
fn flips(name: &str, c: Collector, seed: u64) -> BTreeSet<(String, String, &'static str)> {
    let (m, case) = detected(name, c, seed);
    let r = check(&m, &case).unwrap();
    assert!(r.ok, "{name} {c:?} seed {seed}: {:#?}", r.problems);
    let kind = |story: &str| {
        m.storylines
            .iter()
            .find(|s| s.id == story)
            .map(|s| s.kind.clone())
            .unwrap_or_default()
    };
    let mut seen = BTreeSet::new();
    for (i, e) in m.rules.iter().enumerate() {
        if e.computed.is_none() || !matches!(e.outcome, RuleOutcome::Hit | RuleOutcome::NoHit) {
            continue;
        }
        let mut flipped = m.clone();
        let (to, direction) = match e.outcome {
            RuleOutcome::Hit => (RuleOutcome::NoHit, "unexpected"),
            _ => (RuleOutcome::Hit, "missing"),
        };
        flipped.rules[i].outcome = to;
        let r = check(&flipped, &case).unwrap();
        let listed = if direction == "unexpected" {
            &r.detection.unexpected_hits
        } else {
            &r.detection.missing_hits
        };
        let what = format!(
            "{name} {c:?} seed {seed}: {} on {} flipped to {to:?}",
            e.rule_id, e.storyline
        );
        assert!(!r.ok, "{what}: the gate passed");
        assert!(
            listed
                .iter()
                .any(|p| p.starts_with(&e.rule_id) && p.contains(&e.storyline)),
            "{what}: {:#?}",
            r.detection
        );
        seen.insert((e.rule_id.clone(), kind(&e.storyline), direction));
    }
    seen
}

#[test]
fn flipping_a_computed_outcome_fails_the_gate_in_both_directions() {
    let mut seen = BTreeSet::new();
    for (name, c) in [
        ("bec-aitm", Collector::Invictus),
        ("bec-aitm", Collector::Hawk4),
        ("bec-aitm", Collector::Hawk3),
        ("bec-o365-no-p1", Collector::Invictus),
        ("hawk-investigate", Collector::Invictus),
    ] {
        seen.extend(flips(name, c, 1));
    }
    assert_every_computed_kind_hits(&seen);
}

/// Seeds 1-3: the generator's computed outcomes must hold exactly on every scenario and collector.
const SEEDS: [u64; 3] = [1, 2, 3];

#[test]
#[ignore = "heavy: run with cargo test --workspace -- --ignored"]
fn the_gate_passes_with_the_computed_outcomes_on_seeds_1_to_3() {
    let mut failed = Vec::new();
    let mut seen = BTreeSet::new();
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            for seed in SEEDS {
                let (m, case) = detected(name, *c, seed);
                let r = check(&m, &case).unwrap();
                if r.ok {
                    // Every computed outcome of the tree, flipped, fails the gate.
                    seen.extend(flips(name, *c, seed));
                } else {
                    failed.push(format!("{name} {c:?} seed {seed}: {:#?}", r.problems));
                }
            }
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    assert_every_computed_kind_hits(&seen);
}
