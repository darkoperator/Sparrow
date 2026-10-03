#[path = "common/synth.rs"]
mod synth;

use chrono::Duration;
use sparrow_core::Case;
use sparrow_core::case::actor::Actor;
use sparrow_core::case::read::{self, FindingFilter, TimelineFilter};
use sparrow_core::case::write::{self, FindingStatus};
use sparrow_core::case::{notes, review};
use sparrow_core::data::DataDirs;
use sparrow_core::detect::load::{RuleSet, load_rules};
use sparrow_core::detect::run::{DetectOptions, run};
use sparrow_synth::options::PsEdition;

/// Synthetic bec-aitm (Invictus, PS7), ingested and detected.
fn detected() -> (Case, RuleSet) {
    let mut g = synth::builtin("bec-aitm", PsEdition::Ps7);
    let set = load_rules(&DataDirs::default()).unwrap();
    let o = DetectOptions {
        now: Some(g.manifest.collected_at + Duration::days(1)),
        ..DetectOptions::default()
    };
    run(&mut g.case, &set, &o).unwrap();
    (g.case, set)
}

fn agent() -> Actor {
    Actor::agent("claude", Some("carlos")).unwrap()
}

fn rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        other => panic!("severity {other}"),
    }
}

#[test]
fn finding_list_sorts_by_severity_then_recency() {
    let (c, _) = detected();
    let all = read::finding_list(c.conn(), &FindingFilter::default()).unwrap();
    let n: i64 = c
        .conn()
        .query_row("SELECT count(*) FROM findings", [], |r| r.get(0))
        .unwrap();
    assert!(n >= 3, "bec-aitm must raise several findings: {n}");
    assert_eq!(all.len() as i64, n);
    let best = all.iter().map(|f| rank(&f.severity)).min().unwrap();
    assert_eq!(rank(&all[0].severity), best);
    assert!(
        all.iter().any(|f| rank(&f.severity) != best),
        "the order check needs two severities"
    );
    for w in all.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        let ok = rank(&a.severity) < rank(&b.severity)
            || (rank(&a.severity) == rank(&b.severity)
                && (a.last_seen >= b.last_seen || b.last_seen.is_none())
                && (a.last_seen != b.last_seen || a.finding_id < b.finding_id));
        assert!(
            ok,
            "{} {:?} before {} {:?}",
            a.severity, a.last_seen, b.severity, b.last_seen
        );
    }
    for f in &all {
        let ev: i64 = c
            .conn()
            .query_row(
                "SELECT count(*) FROM finding_evidence WHERE finding_id = ?",
                [&f.finding_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(f.evidence_count, ev);
        assert!(ev > 0);
    }
}

#[test]
fn finding_list_filters() {
    let (c, _) = detected();
    let all = read::finding_list(c.conn(), &FindingFilter::default()).unwrap();
    let f0 = &all[0];
    let by = |f: FindingFilter| read::finding_list(c.conn(), &f).unwrap();
    let sev = by(FindingFilter {
        severity: Some(f0.severity.clone()),
        ..Default::default()
    });
    assert!(!sev.is_empty() && sev.iter().all(|f| f.severity == f0.severity));
    assert!(sev.len() < all.len());
    let rule = f0.rule_id.clone().unwrap();
    let r = by(FindingFilter {
        rule: Some(rule.clone()),
        ..Default::default()
    });
    assert!(
        !r.is_empty()
            && r.iter()
                .all(|f| f.rule_id.as_deref() == Some(rule.as_str()))
    );
    let with_user = all
        .iter()
        .find(|f| f.actor_upn.is_some())
        .expect("a finding with an actor");
    let upn = with_user.actor_upn.clone().unwrap().to_uppercase();
    let u = by(FindingFilter {
        user: Some(upn.clone()),
        ..Default::default()
    });
    assert!(
        !u.is_empty()
            && u.iter()
                .all(|f| f.actor_upn.as_deref().map(str::to_uppercase) == Some(upn.clone()))
    );
    // Status and review state follow agent decisions.
    write::set_finding_status(
        c.conn(),
        &agent(),
        &f0.finding_id,
        FindingStatus::Confirmed,
        Some("AiTM"),
    )
    .unwrap();
    let confirmed = by(FindingFilter {
        status: Some("confirmed".into()),
        ..Default::default()
    });
    assert_eq!(
        confirmed
            .iter()
            .map(|f| f.finding_id.as_str())
            .collect::<Vec<_>>(),
        [f0.finding_id.as_str()]
    );
    assert_eq!(confirmed[0].decided_by.as_deref(), Some("agent:claude"));
    let pending = by(FindingFilter {
        review_state: Some("pending_review".into()),
        ..Default::default()
    });
    assert_eq!(pending.len(), 1);
    assert_eq!(
        by(FindingFilter {
            rule_updated: Some(true),
            ..Default::default()
        })
        .len(),
        0
    );
    assert_eq!(
        by(FindingFilter {
            rule_updated: Some(false),
            ..Default::default()
        })
        .len(),
        all.len()
    );
    let t = by(FindingFilter {
        tenant: Some(f0.tenant_key.clone()),
        ..Default::default()
    });
    assert_eq!(t.len(), all.len());
    assert!(
        by(FindingFilter {
            tenant: Some("nope".into()),
            ..Default::default()
        })
        .is_empty()
    );
    for bad in [
        FindingFilter {
            status: Some("closed".into()),
            ..Default::default()
        },
        FindingFilter {
            severity: Some("huge".into()),
            ..Default::default()
        },
        FindingFilter {
            review_state: Some("ok".into()),
            ..Default::default()
        },
    ] {
        assert!(read::finding_list(c.conn(), &bad).is_err());
    }
}

#[test]
fn finding_show_resolves_evidence_and_guidance() {
    let (c, set) = detected();
    let f = read::finding_list(c.conn(), &FindingFilter::default())
        .unwrap()
        .remove(0);
    let d = write::set_finding_status(
        c.conn(),
        &agent(),
        &f.finding_id,
        FindingStatus::InReview,
        None,
    )
    .unwrap();
    review::review_accept(
        c.conn(),
        &sparrow_core::case::actor::Reviewer::analyst("carlos").unwrap(),
        "finding",
        &f.finding_id,
        d.seq,
        None,
    )
    .unwrap();
    notes::add_note(
        c.conn(),
        &agent(),
        notes::NoteTarget::Finding(f.finding_id.clone()),
        "looks real",
    )
    .unwrap();
    let s = read::finding_show(c.conn(), &f.finding_id, &set).unwrap();
    assert_eq!(s.finding.finding_id, f.finding_id);
    assert_eq!(s.finding.review_state.as_deref(), Some("accepted"));
    assert_eq!(s.evidence.len() as i64, f.evidence_count);
    for e in &s.evidence {
        assert!(!e.source_refs.is_empty(), "{e:?}");
        assert!(e.source_refs.iter().all(|r| r.contains(':')), "{e:?}");
    }
    assert!(
        s.evidence.iter().any(|e| e.timeline.is_some()),
        "a timeline table is resolved to its row"
    );
    for e in s
        .evidence
        .iter()
        .filter_map(|e| e.timeline.as_ref().map(|t| (e, t)))
    {
        assert_eq!(
            (&e.0.source_table, &e.0.record_key),
            (&e.1.source_table, &e.1.record_key)
        );
        assert!(e.1.finding_ids.contains(&f.finding_id));
    }
    assert!(
        !s.analyst_guidance
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    );
    assert_eq!(s.notes.len(), 1);
    assert_eq!(s.notes[0].text, "looks real");
    assert_eq!(
        s.audit
            .iter()
            .map(|e| e.action.as_str())
            .collect::<Vec<_>>(),
        ["set_status", "review_accept"]
    );
    assert!(read::finding_show(c.conn(), "nope", &set).is_err());
}

#[test]
fn timeline_filters_by_user_and_window() {
    let (c, _) = detected();
    let (user, from, to): (String, i64, i64) = c
        .conn()
        .query_row(
            "SELECT actor_upn, epoch_us(min(event_time)), epoch_us(max(event_time)) FROM timeline \
             WHERE actor_upn LIKE '%@%' GROUP BY actor_upn ORDER BY count(*) DESC, actor_upn LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let mid = from + (to - from) / 2;
    let at = |us: i64| chrono::DateTime::from_timestamp_micros(us).unwrap();
    let page = read::timeline_query(
        c.conn(),
        &TimelineFilter {
            user: Some(user.to_uppercase()),
            from: Some(at(from)),
            to: Some(at(mid)),
            limit: 100_000,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!page.rows.is_empty());
    assert!(!page.truncated);
    assert_eq!(page.total, page.rows.len() as i64);
    for r in &page.rows {
        let matches =
            |v: &Option<String>| v.as_deref().is_some_and(|v| v.eq_ignore_ascii_case(&user));
        assert!(matches(&r.actor_upn) || matches(&r.target), "{r:?}");
        assert!(r.event_time >= at(from) && r.event_time <= at(mid), "{r:?}");
    }
    let whole = read::timeline_query(
        c.conn(),
        &TimelineFilter {
            user: Some(user.clone()),
            limit: 100_000,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        whole.total > page.total,
        "the window must exclude something"
    );
    for w in whole.rows.windows(2) {
        assert!(w[0].event_time <= w[1].event_time);
    }
}

#[test]
fn timeline_filters_by_ip_category_and_finding_and_pages() {
    let (c, _) = detected();
    let all: i64 = c
        .conn()
        .query_row("SELECT count(*) FROM timeline", [], |r| r.get(0))
        .unwrap();
    let page = read::timeline_query(
        c.conn(),
        &TimelineFilter {
            limit: 7,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        (page.rows.len(), page.total, page.truncated),
        (7, all, true)
    );
    let ip: String = c
        .conn()
        .query_row("SELECT ip FROM timeline WHERE ip IS NOT NULL GROUP BY ip ORDER BY count(*) DESC, ip LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let p = read::timeline_query(
        c.conn(),
        &TimelineFilter {
            ip: Some(ip.clone()),
            limit: 100_000,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!p.rows.is_empty() && p.rows.iter().all(|r| r.ip.as_deref() == Some(ip.as_str())));
    let p = read::timeline_query(
        c.conn(),
        &TimelineFilter {
            category: Some("auth".into()),
            limit: 100_000,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!p.rows.is_empty() && p.rows.iter().all(|r| r.category == "auth"));
    let fid: String = c
        .conn()
        .query_row(
            "SELECT finding_id FROM findings ORDER BY finding_id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let p = read::timeline_query(
        c.conn(),
        &TimelineFilter {
            finding: Some(fid.clone()),
            limit: 100_000,
            ..Default::default()
        },
    )
    .unwrap();
    let ev: i64 = c
        .conn()
        .query_row(
            "SELECT count(*) FROM finding_evidence fe WHERE finding_id = ? AND EXISTS \
             (SELECT 1 FROM timeline t WHERE t.source_table = fe.source_table AND t.record_key = fe.record_key)",
            [&fid],
            |r| r.get(0),
        )
        .unwrap();
    assert!(ev > 0);
    assert_eq!(p.total, ev);
    assert!(p.rows.iter().all(|r| r.finding_ids.contains(&fid)));
    assert!(
        read::timeline_query(
            c.conn(),
            &TimelineFilter {
                category: Some("bogus".into()),
                limit: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn pivot_reports_truncation() {
    let (c, _) = detected();
    let busiest: String = c
        .conn()
        .query_row(
            "SELECT lower(actor_upn) FROM timeline WHERE actor_upn LIKE '%@%' GROUP BY lower(actor_upn) \
             ORDER BY count(*) DESC, 1 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let p = read::pivot_user(c.conn(), &busiest, 5).unwrap();
    let names: Vec<&str> = p.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "identity",
            "directory",
            "roles",
            "mfa",
            "timeline",
            "findings",
            "indicators"
        ]
    );
    let tl = p.sections.iter().find(|s| s.name == "timeline").unwrap();
    assert_eq!(tl.rows.len(), 5);
    assert!(tl.total > 5, "{}", tl.total);
    assert!(tl.truncated);
    for s in &p.sections {
        assert_eq!(s.truncated, s.total > s.rows.len() as i64, "{}", s.name);
        assert!(s.rows.len() <= 5);
    }
    let id = p.sections.iter().find(|s| s.name == "identity").unwrap();
    assert!(id.total >= 1, "the busiest actor is a known identity");
    // Uncapped enough: nothing truncated in the identity section.
    let big = read::pivot_user(c.conn(), &busiest, 100_000).unwrap();
    assert!(big.sections.iter().all(|s| !s.truncated));
    assert_eq!(
        big.sections
            .iter()
            .find(|s| s.name == "timeline")
            .unwrap()
            .rows
            .len() as i64,
        tl.total
    );
}

#[test]
fn pivot_ip_gathers_its_sections() {
    let (c, _) = detected();
    let ip: String = c
        .conn()
        .query_row(
            "SELECT t.ip FROM timeline t JOIN ip_intel i ON i.ip = t.ip WHERE t.finding_count > 0 \
             GROUP BY t.ip ORDER BY count(*) DESC, t.ip LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    sparrow_core::case::indicators::add_indicator(
        c.conn(),
        &agent(),
        None,
        sparrow_core::case::indicators::IndicatorType::Ip,
        &ip,
        sparrow_core::case::indicators::Verdict::Malicious,
        None,
    )
    .unwrap();
    let p = read::pivot_ip(c.conn(), &ip, 50).unwrap();
    let names: Vec<&str> = p.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "ip_intel",
            "spray_source",
            "timeline",
            "findings",
            "indicators"
        ]
    );
    let get = |n: &str| p.sections.iter().find(|s| s.name == n).unwrap();
    assert_eq!(get("ip_intel").total, 1);
    assert_eq!(get("ip_intel").rows[0]["ip"], ip.as_str());
    assert!(get("timeline").total > 0);
    assert!(get("timeline").rows.iter().all(|r| r["ip"] == ip.as_str()));
    assert!(get("findings").total > 0);
    assert_eq!(get("indicators").total, 1);
    assert_eq!(get("indicators").rows[0]["verdict"], "malicious");
}
