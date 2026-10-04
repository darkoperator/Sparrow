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

/// The known choices' value lists are complete: whatever value a seed gives a KNOWN per-tree choice is one of the
/// forced variants. (Dropping a value from `variants()` makes this fail.) It cannot see a choice `variants()` does not
/// force at all; `a_forced_variant_does_not_depend_on_the_seed` is the guard for that.
#[test]
fn every_seeds_own_pick_of_a_known_choice_is_a_listed_variant() {
    for c in [Collector::Portal, Collector::Hawk3, Collector::Hawk4] {
        for seed in 1..=8 {
            let u = union(c, seed);
            let seeded = profile(c, seed, None);
            let r = conform_real(&seeded, &u);
            assert!(r.ok, "{c:?} seed {seed}:\n{}", r.to_text());
        }
    }
}

/// What `conform_real` compares, as key sets (never counts): per artifact the column SET, the encodings, the date
/// forms per column and the JSON shapes. Header order and counts do not matter to it, so they are not compared.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    columns: std::collections::BTreeSet<String>,
    encodings: std::collections::BTreeSet<String>,
    dates: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    json_shapes: std::collections::BTreeSet<String>,
}

fn shapes(p: &Profile) -> std::collections::BTreeMap<String, Shape> {
    p.artifacts
        .iter()
        .map(|(a, ap)| {
            (
                a.clone(),
                Shape {
                    columns: ap.headers.keys().flatten().cloned().collect(),
                    encodings: ap.encodings.keys().cloned().collect(),
                    dates: ap.dates.clone(),
                    json_shapes: ap.json_shapes.keys().cloned().collect(),
                },
            )
        })
        .collect()
}

/// Artifacts whose COLUMN SET legitimately varies with the seed today: their columns are the flattened AuditData /
/// event properties of whichever records the seed generated (`Folders_*`, `Param_*`, `Item_Attachments`,
/// `TargetUserOrGroup*`), i.e. CONTENT, not a per-tree form. Found by this test (seeds 1-8, Hawk 4); a variant cannot
/// cover them, and `--real` covers them by comparing against every scenario. Their encodings, date forms (on columns
/// both trees have) and JSON shapes are still held to seed-independence below. Header ORDER also varies by seed on
/// several Hawk artifacts; `conform_real` compares column sets, so order is not compared here.
const CONTENT_DRIVEN_COLUMNS: &[&str] = &["hawk.user.simple_ual", "hawk.ip.events"];

/// The guard for a NEW per-tree choice: hold the variant fixed and vary the seed. Everything `--real` compares must
/// stay the same, so a form a writer picks per tree from the seed and `variants()` does not force shows up as a
/// seed-dependent shape (a fair-coin choice escapes seeds 2-8 with probability 2^-7). The comparison of the stand-in
/// with the union cannot see it: it builds the union from the same seed, so both sides agree on that choice.
#[test]
fn a_forced_variant_does_not_depend_on_the_seed() {
    let mut content_driven_seen = false;
    for c in [Collector::Portal, Collector::Hawk3, Collector::Hawk4] {
        for v in variants(c) {
            let base = shapes(&profile(c, 1, Some(&v)));
            assert!(!base.is_empty(), "{c:?} {}: no artifacts profiled", v.label);
            for seed in 2..=8 {
                let other = shapes(&profile(c, seed, Some(&v)));
                let who = format!("{c:?} {} seed 1 vs {seed}", v.label);
                assert_eq!(
                    base.keys().collect::<Vec<_>>(),
                    other.keys().collect::<Vec<_>>(),
                    "{who}: the artifacts differ"
                );
                for (a, x) in &base {
                    let y = &other[a];
                    assert_eq!(
                        x.encodings, y.encodings,
                        "{who}: {a} encodings depend on the seed"
                    );
                    assert_eq!(
                        x.json_shapes, y.json_shapes,
                        "{who}: {a} JSON shapes depend on the seed"
                    );
                    if CONTENT_DRIVEN_COLUMNS.contains(&a.as_str()) {
                        content_driven_seen |= x.columns != y.columns;
                        // Date forms only on the columns both trees have.
                        let common: std::collections::BTreeSet<&String> =
                            x.columns.intersection(&y.columns).collect();
                        let pick = |s: &Shape| {
                            s.dates
                                .iter()
                                .filter(|(col, _)| common.contains(col))
                                .map(|(c, f)| (c.clone(), f.clone()))
                                .collect::<std::collections::BTreeMap<_, _>>()
                        };
                        assert_eq!(pick(x), pick(y), "{who}: {a} date forms depend on the seed");
                    } else {
                        assert_eq!(
                            x.columns, y.columns,
                            "{who}: {a} columns depend on the seed"
                        );
                        assert_eq!(x.dates, y.dates, "{who}: {a} date forms depend on the seed");
                    }
                }
            }
        }
    }
    assert!(
        content_driven_seen,
        "the content-driven allow-list no longer varies by seed: delete CONTENT_DRIVEN_COLUMNS"
    );
}
