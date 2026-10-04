//! `--real` conformance compares a real capture with the UNION of every per-tree variant the generator can
//! produce (fu-wave3-real), not with the one variant a seed happens to pick.

use sparrow_synth::cache::Cache;
use sparrow_synth::conformance::{Profile, Variant, conform_real, profile_dir, variants};
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::load;

static CACHE: std::sync::LazyLock<Cache> =
    std::sync::LazyLock::new(|| sparrow_synth::test_cache!());

/// The profile of a bec-aitm tree generated with `seed` and the forced `variant` (None: the seed's own pick).
fn profile(collector: Collector, seed: u64, variant: Option<&Variant>) -> Profile {
    let mut o = GenerateOptions::new(collector, seed);
    o.ps = PsEdition::Ps7;
    if let Some(v) = variant {
        v.apply(&mut o);
    }
    let tree = CACHE
        .tree(&load("bec-aitm").unwrap(), &o)
        .unwrap_or_else(|e| panic!("tree: {e}"));
    profile_dir(&tree.dir).unwrap()
}

fn find(collector: Collector, pick: impl Fn(&Variant) -> bool) -> Variant {
    variants(collector)
        .into_iter()
        .find(pick)
        .unwrap_or_else(|| panic!("no such variant for {collector:?}"))
}

/// Profiles of every variant of `collector`, all from `seed`'s tree: the variants differ only in the forced choices,
/// so a comparison with a tree of the same seed isolates them from the seed's content (names, storylines).
fn union(collector: Collector, seed: u64) -> Vec<Profile> {
    variants(collector)
        .iter()
        .map(|v| profile(collector, seed, Some(v)))
        .collect()
}

#[test]
fn each_collector_lists_the_variants_its_writers_choose_per_tree() {
    let labels = |c| variants(c).into_iter().map(|v| v.label).collect::<Vec<_>>();
    // Portal: the Purview CreationDate form x the message-trace Excel re-save; Hawk: the UAL CreationDate kind.
    assert_eq!(
        variants(Collector::Portal).len(),
        4,
        "{:?}",
        labels(Collector::Portal)
    );
    assert_eq!(variants(Collector::Hawk3).len(), 2);
    assert_eq!(variants(Collector::Hawk4).len(), 2);
    assert_eq!(variants(Collector::Invictus).len(), 1);
    for c in Collector::ALL {
        let l = labels(*c);
        let unique: std::collections::BTreeSet<_> = l.iter().collect();
        assert_eq!(unique.len(), l.len(), "labels are unique: {l:?}");
    }
}

/// The method gap itself: a stand-in "real" tree that took variant A, compared with a matrix whose seed took
/// variant B, reports the item as real-only; compared with the union of the variants, it reports nothing.
#[test]
fn a_real_tree_with_another_variant_than_the_seed_is_no_longer_real_only() {
    let cases: Vec<(&str, Collector, Variant, Variant, &str)> = vec![
        (
            "purview CreationDate form",
            Collector::Portal,
            find(Collector::Portal, |v| {
                v.purview_culture_dates == Some(true) && v.message_trace_excel_resave == Some(false)
            }),
            find(Collector::Portal, |v| {
                v.purview_culture_dates == Some(false)
                    && v.message_trace_excel_resave == Some(false)
            }),
            "CreationDate",
        ),
        (
            "message-trace Excel re-save encoding",
            Collector::Portal,
            find(Collector::Portal, |v| {
                v.purview_culture_dates == Some(false) && v.message_trace_excel_resave == Some(true)
            }),
            find(Collector::Portal, |v| {
                v.purview_culture_dates == Some(false)
                    && v.message_trace_excel_resave == Some(false)
            }),
            "encoding",
        ),
    ];
    for (what, collector, a, b, finding) in cases {
        let real = profile(collector, 3, Some(&a));
        let only_b = vec![profile(collector, 3, Some(&b))];
        // The two variants really differ (a vacuous pair would prove nothing).
        assert_ne!(
            real, only_b[0],
            "{what}: variants A and B produce the same profile"
        );
        let before = conform_real(&real, &only_b);
        assert!(
            before
                .findings
                .iter()
                .any(|f| f.contains(finding) && f.contains("real tree only")),
            "{what}: the single-variant matrix must report it:\n{}",
            before.to_text()
        );
        let after = conform_real(&real, &union(collector, 3));
        assert!(
            after.ok,
            "{what}: the union of variants reports nothing:\n{}",
            after.to_text()
        );
    }
}

/// The same for the Hawk UAL CreationDate kind (Utc vs Unspecified), on both Hawk collectors: whichever kind the
/// real tree has, the union covers it. (Before: the seed picked one kind per tree.)
#[test]
fn a_real_hawk_tree_of_either_ual_creation_kind_is_covered() {
    for c in [Collector::Hawk3, Collector::Hawk4] {
        let utc = find(c, |v| v.hawk_ual_creation_utc == Some(true));
        let unspecified = find(c, |v| v.hawk_ual_creation_utc == Some(false));
        let u = union(c, 7);
        for v in [&utc, &unspecified] {
            let real = profile(c, 7, Some(v));
            let r = conform_real(&real, &u);
            assert!(r.ok, "{c:?} {}:\n{}", v.label, r.to_text());
        }
        // The two kinds are really different trees.
        assert_ne!(
            profile(c, 7, Some(&utc)),
            profile(c, 7, Some(&unspecified)),
            "{c:?}"
        );
    }
}

/// A shape no variant produces is still a finding: widening the matrix did not turn the comparison into a pass-all.
#[test]
fn a_shape_no_variant_produces_is_still_reported() {
    let mut real = profile(Collector::Portal, 3, None);
    let artifact = real.artifacts.keys().next().cloned().expect("an artifact");
    real.artifacts
        .get_mut(&artifact)
        .unwrap()
        .headers
        .insert(vec!["ZzNoVariantHasThisColumn".to_string()], 1);
    let r = conform_real(&real, &union(Collector::Portal, 3));
    assert!(!r.ok);
    assert!(
        r.findings
            .iter()
            .any(|f| f.contains("real columns never generated")),
        "{}",
        r.to_text()
    );
}

/// The drift guard: whatever a seed picks must be among the forced variants. A new per-tree seeded choice that
/// `variants()` does not cover would show up as a real-only finding here.
#[test]
fn every_seeds_own_pick_is_covered_by_the_variants() {
    for c in [Collector::Portal, Collector::Hawk3, Collector::Hawk4] {
        for seed in 1..=8 {
            let u = union(c, seed);
            let seeded = profile(c, seed, None);
            let r = conform_real(&seeded, &u);
            assert!(r.ok, "{c:?} seed {seed}:\n{}", r.to_text());
        }
    }
}
