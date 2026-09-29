use sparrow_synth::conformance::{conform_layouts, conform_real, profile_dir};
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition};
use sparrow_synth::scenario::{builtin_names, load};

fn r#gen(
    name: &str,
    c: Collector,
    ps: PsEdition,
) -> (tempfile::TempDir, sparrow_synth::manifest::Manifest) {
    let dir = tempfile::tempdir().unwrap();
    let mut o = GenerateOptions::new(c, 5);
    o.ps = ps;
    let m = generate_to_dir(&load(name).unwrap(), &o, dir.path()).unwrap();
    (dir, m)
}

/// Every built-in scenario (except `volume`) for every collector and edition must match the
/// recorded layouts.
#[test]
fn generated_trees_conform_to_the_recorded_layouts() {
    for name in builtin_names().iter().filter(|n| **n != "volume") {
        for c in Collector::ALL {
            for ps in [PsEdition::Ps7, PsEdition::Ps51] {
                let (dir, _) = r#gen(name, *c, ps);
                let p = profile_dir(dir.path()).unwrap();
                let r = conform_layouts(&p, *c);
                assert!(r.ok, "{name} {c:?} {ps:?}:\n{}", r.to_text());
                assert!(r.checked > 0, "{name} {c:?} {ps:?}: nothing checked");
            }
        }
    }
}

/// Hawk 3's `Tenant/All_InboxRules` is a single JSON document (capture survey §2b: it is
/// byte-identical to a user's `InboxRules_<u>`), so its shape is a bare object or an array,
/// never the concatenated documents a per-user `-Append` would leave.
#[test]
fn hawk3_all_inbox_rules_is_a_single_json_document() {
    let (dir, _) = r#gen("bec-aitm", Collector::Hawk3, PsEdition::Ps7);
    let p = profile_dir(dir.path()).unwrap();
    let ap = p
        .artifacts
        .get("hawk.tenant.all_inbox_rules")
        .expect("hawk.tenant.all_inbox_rules");
    assert!(ap.json_shapes.contains_key("array"), "{:?}", ap.json_shapes);
    assert!(
        !ap.json_shapes.contains_key("concatenated"),
        "{:?}",
        ap.json_shapes
    );
}

/// The world now holds a partner remote domain and 3+ eDiscovery role assignments, so the
/// generated trees produce arrays for both (the real captures' shape).
#[test]
fn generated_remote_domain_and_ediscovery_role_assignments_are_arrays() {
    for c in [Collector::Hawk3, Collector::Hawk4] {
        let (dir, _) = r#gen("bec-aitm", c, PsEdition::Ps7);
        let p = profile_dir(dir.path()).unwrap();
        for a in [
            "hawk.tenant.remote_domain",
            "hawk.tenant.ediscovery_role_assignments",
        ] {
            let Some(ap) = p.artifacts.get(a) else {
                continue;
            };
            assert!(
                ap.json_shapes.contains_key("array"),
                "{a} {c:?}: {:?}",
                ap.json_shapes
            );
            assert!(
                !ap.json_shapes.contains_key("bare"),
                "{a} {c:?}: {:?}",
                ap.json_shapes
            );
        }
    }
}

/// A real Hawk capture can hold the portal exports pulled beside it. `conform_real` compares
/// them when the generated side includes the portal collector (0 findings), and reports them
/// when it does not — the guard that keeps the comparison non-vacuous.
#[test]
fn conform_real_compares_portal_exports_beside_a_hawk_capture() {
    let (hawk_dir, _) = r#gen("bec-aitm", Collector::Hawk4, PsEdition::Ps7);
    let hawk = profile_dir(hawk_dir.path()).unwrap();
    let (portal_dir, _) = r#gen("bec-aitm", Collector::Portal, PsEdition::Ps7);
    let portal = profile_dir(portal_dir.path()).unwrap();

    // The stand-in real tree: the Hawk artifacts plus the portal exports beside them.
    let mut real = hawk.clone();
    for (artifact, ap) in &portal.artifacts {
        real.artifacts.insert(artifact.clone(), ap.clone());
    }

    let with_portal = vec![hawk.clone(), portal.clone()];
    let r = conform_real(&real, &with_portal);
    assert!(r.ok, "{}", r.to_text());

    let without_portal = vec![hawk];
    let r = conform_real(&real, &without_portal);
    assert!(!r.ok);
    assert!(
        r.findings.iter().any(|f| f.starts_with("portal.")),
        "{}",
        r.to_text()
    );
}

#[test]
fn a_real_mode_report_prints_no_values() {
    // A stand-in "real" tree: a generated one with recognisable values planted in it.
    let (dir, m) = r#gen("bec-aitm", Collector::Hawk4, PsEdition::Ps7);
    let root = dir.path().join(&m.root);
    let secret_user = "secret.person@contoso.example";
    let secret_ip = "203.0.113.99";
    std::fs::create_dir_all(root.join(secret_user)).unwrap();
    std::fs::write(
        root.join(secret_user).join("InboxRules_secret.person.csv"),
        format!("\"Name\",\"From\",\"{secret_user}\"\r\n\"Rule\",\"{secret_ip}\",\"x\"\r\n"),
    )
    .unwrap();
    let real = profile_dir(dir.path()).unwrap();
    let (gdir, _) = r#gen("bec-aitm", Collector::Hawk4, PsEdition::Ps51);
    let generated = vec![profile_dir(gdir.path()).unwrap()];
    let text = conform_real(&real, &generated).to_text();
    assert!(
        !text.contains(secret_user) && !text.contains(secret_ip) && !text.contains("secret"),
        "{text}"
    );
    assert!(text.contains("<masked>"));
}
