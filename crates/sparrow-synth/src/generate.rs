//! From scenario to tree: builds the world, applies the storylines, renders the collector's
//! files through a `Tree`, writes the GeoIP databases and assembles the manifest.

use crate::expect;
use crate::geo;
use crate::manifest::{self, Manifest};
use crate::options::{Collector, GenerateOptions};
use crate::scenario::Scenario;
use crate::story::{self, Evidence};
use crate::tree::{CulturePolicy, DirSink, Sink, Tree};
use crate::world::World;
use crate::writers;
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The folder (relative to the output directory) that receives the GeoLite2 databases.
pub const GEOIP_DIR: &str = "geoip";

/// The manifest's file name in the output directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Render `scenario` for `opts` into `sink` and return the manifest. Deterministic: same
/// inputs, same bytes.
pub fn generate(
    scenario: &Scenario,
    opts: &GenerateOptions,
    sink: &mut dyn Sink,
) -> Result<Manifest> {
    generate_with_policy(
        scenario,
        opts,
        sink,
        CulturePolicy::Auto(opts.culture.to_string()),
    )
}

/// `generate` with an explicit day/month policy (tests of the all-ambiguous case use `Never`).
pub fn generate_with_policy(
    scenario: &Scenario,
    opts: &GenerateOptions,
    sink: &mut dyn Sink,
    policy: CulturePolicy,
) -> Result<Manifest> {
    if !matches!(
        opts.collector,
        Collector::Portal | Collector::Invictus | Collector::Hawk3 | Collector::Hawk4
    ) {
        return Err(Error::Invalid(format!(
            "collector {} is not implemented yet",
            opts.collector
        )));
    }
    let mut world = World::build(scenario, opts.seed)?;
    world.culture = opts.culture;
    world.apply_scale(opts);
    let records = story::apply(&mut world)?;
    let tracked: BTreeSet<Evidence> = records
        .iter()
        .flat_map(|r| r.evidence.iter().cloned())
        .collect();
    let root = writers::root_name(&world, opts);
    let mut tree = Tree::new(sink, &root, tracked, policy);
    match opts.collector {
        Collector::Invictus => writers::invictus::write(&world, opts, &mut tree)?,
        Collector::Hawk3 => writers::hawk::write_v3(&world, opts, &mut tree)?,
        Collector::Hawk4 => writers::hawk::write_v4(&world, opts, &mut tree)?,
        _ => writers::portal::write(&world, opts, &mut tree)?,
    }
    let out = tree.finish()?;
    geo::write_geoip(&world, sink, GEOIP_DIR)?;
    let caps = expect::capabilities(
        &world,
        expect::delivery(opts, writers::parsed_by_sparrow("inv.licenses.tenant")),
    );
    Ok(Manifest {
        format: 1,
        generator: format!("sparrow-synth {}", env!("CARGO_PKG_VERSION")),
        scenario: scenario.name.clone(),
        options: opts.clone(),
        root,
        geoip_dir: Some(GEOIP_DIR.into()),
        ingest_culture: out.ingest_culture.clone(),
        window_start: world.window_start(),
        window_end: world.window_end(),
        collected_at: world.collected_at(),
        licence_profile: world.licence.id.clone(),
        audit_profile: world.audit_profile.id.clone(),
        tenant: manifest::tenant_expect(&world, opts),
        evidence: expect::evidence(&world, opts, &out),
        rules: {
            let mut rules = expect::rule_outcomes(&world, &records, &caps, &out);
            let kinds: std::collections::BTreeMap<String, String> = records
                .iter()
                .map(|r| (r.id.clone(), r.kind.as_str().to_string()))
                .collect();
            expect::restrict_to_collector(&mut rules, opts.collector, &kinds);
            rules
        },
        storylines: manifest::story_expects(&world, &records, &out),
        capabilities: caps,
        files: out.files,
        empty_dirs: out.empty_dirs,
        tables: out.tables,
    })
}

/// Write the tree and `manifest.json` into `out` (created if missing; must be empty).
pub fn generate_to_dir(
    scenario: &Scenario,
    opts: &GenerateOptions,
    out: &Path,
) -> Result<Manifest> {
    std::fs::create_dir_all(out).map_err(|e| Error::io(out, e))?;
    let mut entries = std::fs::read_dir(out).map_err(|e| Error::io(out, e))?;
    if entries.next().is_some() {
        return Err(Error::Invalid(format!(
            "output directory {} is not empty",
            out.display()
        )));
    }
    let mut sink = DirSink::new(out);
    let manifest = generate(scenario, opts, &mut sink)?;
    let path = out.join(MANIFEST_FILE);
    std::fs::write(&path, manifest.to_json_pretty()).map_err(|e| Error::io(&path, e))?;
    Ok(manifest)
}

/// `generate_to_dir`, then pack `out` into `<out>.zip` (sorted entries, Stored, fixed
/// 1980-01-01 timestamps; the manifest is included) and return its path.
pub fn generate_zip(
    scenario: &Scenario,
    opts: &GenerateOptions,
    out: &Path,
) -> Result<(Manifest, PathBuf)> {
    let manifest = generate_to_dir(scenario, opts, out)?;
    let mut name = out
        .file_name()
        .ok_or_else(|| Error::Invalid(format!("{} has no folder name", out.display())))?
        .to_os_string();
    name.push(".zip");
    let zip_path = out.with_file_name(name);
    zip_dir(out, &zip_path)?;
    Ok((manifest, zip_path))
}

/// Every file (and every empty directory, with a trailing `/`) below `dir`, as `/`-separated
/// paths relative to it, sorted.
fn list_entries(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
        let mut children = Vec::new();
        for e in std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
            let e = e.map_err(|e| Error::io(dir, e))?;
            children.push(e.path());
        }
        if children.is_empty() && !prefix.is_empty() {
            out.push((prefix.to_string(), dir.to_path_buf()));
        }
        for path in children {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if path.is_dir() {
                walk(&path, &format!("{prefix}{name}/"), out)?;
            } else {
                out.push((format!("{prefix}{name}"), path.clone()));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out)?;
    out.sort();
    Ok(out)
}

fn zip_err(path: &Path, e: zip::result::ZipError) -> Error {
    Error::Invalid(format!("{}: zip: {e}", path.display()))
}

/// Packs the contents of `dir` into `zip_path` deterministically.
fn zip_dir(dir: &Path, zip_path: &Path) -> Result<()> {
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, DateTime, ZipWriter};
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644);
    let file = std::fs::File::create(zip_path).map_err(|e| Error::io(zip_path, e))?;
    let mut zip = ZipWriter::new(file);
    for (name, path) in list_entries(dir)? {
        if name.ends_with('/') {
            zip.add_directory(name.as_str(), options.unix_permissions(0o755))
                .map_err(|e| zip_err(zip_path, e))?;
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
        zip.start_file(name.as_str(), options)
            .map_err(|e| zip_err(zip_path, e))?;
        zip.write_all(&bytes).map_err(|e| Error::io(zip_path, e))?;
    }
    zip.finish().map_err(|e| zip_err(zip_path, e))?;
    Ok(())
}
