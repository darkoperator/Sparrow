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
