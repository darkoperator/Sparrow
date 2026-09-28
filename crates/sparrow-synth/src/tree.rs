//! Writing one collection root: files go through a `Sink` (a directory or memory) while the
//! `Tree` records, per file, its encoding, size, SHA-256 and date evidence, the rows it will load
//! (table + record key) and where tracked storyline evidence landed (file and line span).
//! `Tree::finish` predicts the status Sparrow gives every file by replaying the ingest rules
//! (spec §4, Addendum A.4, Phase 3) and assembles the manifest's file, table and delivery parts.

use crate::manifest::{FileExpect, Sighting, TableExpect};
use crate::ps::{DateEvidence, Encoding};
use crate::story::Evidence;
use crate::writers::parsed_by_sparrow;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Where generated files go. `rel` is relative to the output directory and `/`-separated;
/// `append` creates the file (and its parents) on first use, and `append(rel, &[])` creates an
/// empty file.
pub trait Sink {
    fn dir(&mut self, rel: &str) -> Result<()>;
    fn append(&mut self, rel: &str, bytes: &[u8]) -> Result<()>;
}

/// Writes below a directory on disk. A file this sink has not written yet is truncated on its
/// first `append`, so re-generating into the same directory never extends an old file.
pub struct DirSink {
    out: PathBuf,
    opened: BTreeSet<String>,
}

impl DirSink {
    pub fn new(out: &Path) -> DirSink {
        DirSink {
            out: out.to_path_buf(),
            opened: BTreeSet::new(),
        }
    }

    fn path(&self, rel: &str) -> PathBuf {
        rel.split('/').fold(self.out.clone(), |p, c| p.join(c))
    }
}

impl Sink for DirSink {
    fn dir(&mut self, rel: &str) -> Result<()> {
        let path = self.path(rel);
        std::fs::create_dir_all(&path).map_err(|e| Error::io(&path, e))
    }

    fn append(&mut self, rel: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path(rel);
        let first = self.opened.insert(rel.to_string());
        if first {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(first)
            .append(!first)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        file.write_all(bytes).map_err(|e| Error::io(&path, e))
    }
}

/// Keeps files in memory (tests, `sparrow synth` dry runs).
#[derive(Debug, Default)]
pub struct MemSink {
    pub files: BTreeMap<String, Vec<u8>>,
    pub dirs: BTreeSet<String>,
}

impl Sink for MemSink {
    fn dir(&mut self, rel: &str) -> Result<()> {
        self.dirs.insert(rel.to_string());
        Ok(())
    }

    fn append(&mut self, rel: &str, bytes: &[u8]) -> Result<()> {
        self.files
            .entry(rel.to_string())
            .or_default()
            .extend_from_slice(bytes);
        Ok(())
    }
}

/// How the ingest resolves day/month order for files whose culture dates are all ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CulturePolicy {
    /// The ingest passes `--culture <c>`: every such file parses.
    Given(String),
    /// Add `--culture <c>` to the manifest when the collection proves no order.
    Auto(String),
    /// No `--culture`: all-ambiguous files fail unless another file proves the order.
    Never,
}

/// One file as a writer declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    /// Path within the collection root, `/`-separated.
    pub rel: String,
    /// The artifact id Sparrow's registry classifies the file as (`None`: unrecognized).
    pub artifact: Option<&'static str>,
    /// Sparrow's registry marks the artifact derived (processed after raw files, superseded by
    /// its raw counterpart).
    pub derived: bool,
    /// The ingest parses a higher-priority file after the other files of its stage; a summary
    /// that reads another file's ingested row declares 1.
    pub priority: i16,
    /// The subject Sparrow takes from the path (a user folder's UPN...). Required for
    /// per-subject artifacts (Hawk user files and the like): without it, byte-identical files of
    /// different users replay as `duplicate_file`.
    pub subject: Option<String>,
    pub encoding: Encoding,
    /// The writer derived the content from another file of the tree.
    pub source_derived: bool,
    /// A deliberate status (a shape the parser rejects, a broken file), applied when no earlier
    /// replay rule (unrecognized, duplicate, superseded, no parser) decides the file.
    pub expect_status: Option<&'static str>,
}

impl FileSpec {
    pub fn new(rel: &str, artifact: Option<&'static str>, encoding: Encoding) -> FileSpec {
        FileSpec {
            rel: rel.to_string(),
            artifact,
            derived: false,
            priority: 0,
            subject: None,
            encoding,
            source_derived: false,
            expect_status: None,
        }
    }

    pub fn derived(mut self) -> FileSpec {
        self.derived = true;
        self
    }

    /// The file reads another file's ingested row: parsed after the ordinary files of its
    /// stage (`priority: 1`, matching the registry).
    pub fn after(mut self) -> FileSpec {
        self.priority = 1;
        self
    }

    pub fn subject(mut self, s: String) -> FileSpec {
        self.subject = Some(s);
        self
    }

    pub fn source_derived(mut self) -> FileSpec {
        self.source_derived = true;
        self
    }

    pub fn status(mut self, s: &'static str) -> FileSpec {
        self.expect_status = Some(s);
        self
    }
}

/// The manifest parts a finished tree produces.
#[derive(Debug, Clone)]
pub struct TreeOutcome {
    /// Every file, sorted by path.
    pub files: Vec<FileExpect>,
    /// Directories created with nothing below them, sorted.
    pub empty_dirs: Vec<String>,
    /// Rows the parsed files load, per table.
    pub tables: BTreeMap<String, TableExpect>,
    /// Where each tracked evidence item landed in parsed files: (table, sighting), sorted.
    pub delivered: BTreeMap<Evidence, Vec<(String, Sighting)>>,
    /// The `--culture` the ingest must pass (`CulturePolicy::Given`, or `Auto` when no file of
    /// the collection proves the day/month order).
    pub ingest_culture: Option<String>,
}

/// Lists at most this many keys per table in the manifest (the hash covers all).
const MAX_LISTED_KEYS: usize = 5000;

struct FileState {
    spec: FileSpec,
    bytes: u64,
    sha: Sha256,
    lines: u32,
    rows: Vec<(&'static str, String)>,
    counted: Vec<(&'static str, u64)>,
    deliveries: Vec<(Evidence, &'static str, (u32, u32))>,
    date: Option<DateEvidence>,
}

/// One collection root being written.
pub struct Tree<'a> {
    sink: &'a mut dyn Sink,
    root: String,
    tracked: BTreeSet<Evidence>,
    culture: CulturePolicy,
    files: BTreeMap<String, FileState>,
    dirs: BTreeSet<String>,
}

impl<'a> Tree<'a> {
    /// A tree whose files go to `<root>/<rel>` in `sink` (directly `<rel>` when `root` is
    /// empty). Deliveries are recorded only for `tracked` evidence.
    pub fn new(
        sink: &'a mut dyn Sink,
        root: &str,
        tracked: BTreeSet<Evidence>,
        culture: CulturePolicy,
    ) -> Tree<'a> {
        Tree {
            sink,
            root: root.to_string(),
            tracked,
            culture,
            files: BTreeMap::new(),
            dirs: BTreeSet::new(),
        }
    }

    fn full(&self, rel: &str) -> String {
        if self.root.is_empty() {
            rel.to_string()
        } else if rel.is_empty() {
            self.root.clone()
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    /// Creates directory `rel` (listed in `empty_dirs` when nothing is written below it).
    pub fn dir(&mut self, rel: &str) -> Result<()> {
        let full = self.full(rel);
        self.sink.dir(&full)?;
        self.dirs.insert(rel.to_string());
        Ok(())
    }

    fn state(&mut self, spec: &FileSpec) -> &mut FileState {
        self.files
            .entry(spec.rel.clone())
            .or_insert_with(|| FileState {
                spec: spec.clone(),
                bytes: 0,
                sha: Sha256::new(),
                lines: 0,
                rows: Vec::new(),
                counted: Vec::new(),
                deliveries: Vec::new(),
                date: None,
            })
    }

    fn put(&mut self, spec: &FileSpec, bytes: &[u8]) -> Result<()> {
        let full = self.full(&spec.rel);
        self.sink.append(&full, bytes)?;
        let st = self.state(spec);
        st.bytes += bytes.len() as u64;
        st.sha.update(bytes);
        Ok(())
    }

    /// Appends `text` to the file, encoded with the spec's encoding (a byte-order mark only on
    /// the file's first chunk). Returns the number of lines (`\n`) already in the file before
    /// this chunk, so a writer can turn a chunk's 1-based spans into file lines.
    pub fn write(&mut self, spec: &FileSpec, text: &str) -> Result<u32> {
        let first = !self.files.contains_key(&spec.rel);
        let mut bytes = spec.encoding.encode(text);
        if !first {
            bytes.drain(..bom_len(spec.encoding));
        }
        self.put(spec, &bytes)?;
        let st = self.state(spec);
        let before = st.lines;
        st.lines += text.matches('\n').count() as u32;
        Ok(before)
    }

    /// Appends `bytes` to `out_rel`, a path relative to the output directory rather than the
    /// root, that the manifest does not list (Microsoft-Extractor-Suite's `Output\LogFile.txt`
    /// written beside `Output/` on macOS/Linux).
    pub fn write_unlisted(&mut self, out_rel: &str, bytes: &[u8]) -> Result<()> {
        self.sink.append(out_rel, bytes)
    }

    /// Appends raw bytes (XLSX, zip, MaxMind databases) to the file.
    pub fn write_bytes(&mut self, spec: &FileSpec, bytes: &[u8]) -> Result<()> {
        self.put(spec, bytes)
    }

    fn written(&mut self, rel: &str) -> &mut FileState {
        self.files
            .get_mut(rel)
            .unwrap_or_else(|| panic!("tree: {rel} was not written"))
    }

    /// File `rel` loads a row with record key `key` into `table` (when it is parsed).
    pub fn row(&mut self, rel: &str, table: &'static str, key: String) {
        self.written(rel).rows.push((table, key));
    }

    /// File `rel` loads `n` rows into count-only `table`.
    pub fn rows_counted(&mut self, rel: &str, table: &'static str, n: u64) {
        self.written(rel).counted.push((table, n));
    }

    /// File `rel` (already written) gets deliberate status `status` (see
    /// `FileSpec::expect_status`).
    pub fn expect_status(&mut self, rel: &str, status: &'static str) {
        self.written(rel).spec.expect_status = Some(status);
    }

    /// Evidence `e` landed in `table` from lines `lines` (1-based, inclusive) of file `rel`.
    /// Ignored for evidence the tree does not track.
    pub fn deliver(&mut self, e: &Evidence, table: &'static str, rel: &str, lines: (u32, u32)) {
        if self.tracked.contains(e) {
            self.written(rel).deliveries.push((e.clone(), table, lines));
        }
    }

    /// Adds `ev` to file `rel`'s culture-date evidence.
    pub fn date_evidence(&mut self, rel: &str, ev: DateEvidence) {
        let st = self.written(rel);
        st.date.get_or_insert_with(DateEvidence::default).merge(&ev);
    }

    /// Replays Sparrow's file-status rules and assembles the manifest parts.
    pub fn finish(self) -> Result<TreeOutcome> {
        let facts: Vec<Facts> = self.files.values().map(Facts::of).collect();
        let (statuses, ingest_culture) = match &self.culture {
            CulturePolicy::Given(c) => (replay(&facts, true), Some(c.clone())),
            CulturePolicy::Never => (replay(&facts, false), None),
            CulturePolicy::Auto(c) => {
                let s = replay(&facts, false);
                if s.values().any(|st| *st == Status::NoOrder) {
                    (replay(&facts, true), Some(c.clone()))
                } else {
                    (s, None)
                }
            }
        };

        let mut files = Vec::new();
        let mut keys: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        let mut counted: BTreeMap<&'static str, u64> = BTreeMap::new();
        let mut delivered: BTreeMap<Evidence, Vec<(String, Sighting)>> = BTreeMap::new();
        for (fact, (rel, st)) in facts.iter().zip(&self.files) {
            let status = statuses[rel.as_str()].as_str();
            if status == "parsed" {
                for (table, key) in &st.rows {
                    keys.entry(table).or_default().insert(key.clone());
                }
                for (table, n) in &st.counted {
                    *counted.entry(table).or_default() += n;
                }
                for (e, table, (start, end)) in &st.deliveries {
                    delivered.entry(e.clone()).or_default().push((
                        table.to_string(),
                        Sighting {
                            rel_path: rel.clone(),
                            line_start: *start,
                            line_end: *end,
                        },
                    ));
                }
            }
            files.push(FileExpect {
                rel_path: rel.clone(),
                artifact_id: st.spec.artifact.map(str::to_string),
                status: status.to_string(),
                source_derived: st.spec.source_derived,
                encoding: st.spec.encoding.name().to_string(),
                bytes: st.bytes,
                sha256: fact.sha256.clone(),
                date_evidence: st.date,
            });
        }
        for v in delivered.values_mut() {
            v.sort();
        }

        let mut tables = BTreeMap::new();
        let names: BTreeSet<&'static str> = keys.keys().chain(counted.keys()).copied().collect();
        for name in names {
            let k = keys.remove(name).unwrap_or_default();
            let n = counted.get(name).copied().unwrap_or(0);
            let keys_sha256 = (!k.is_empty()).then(|| {
                let joined = k.iter().map(String::as_str).collect::<Vec<_>>().join("\n");
                hex::encode(Sha256::digest(joined.as_bytes()))
            });
            let rows = k.len() as u64 + n;
            if k.len() > MAX_LISTED_KEYS && k.iter().any(|key| key.contains(crate::keys::CID)) {
                // Only the hash would be listed, and `synth check` cannot rebuild `{cid}` keys
                // from the case's keys.
                return Err(Error::Invalid(format!(
                    "table {name}: {} keys carry the {} placeholder; at most {MAX_LISTED_KEYS} can be checked",
                    k.len(),
                    crate::keys::CID
                )));
            }
            let listed = if k.len() <= MAX_LISTED_KEYS {
                k.into_iter().collect()
            } else {
                Vec::new()
            };
            tables.insert(
                name.to_string(),
                TableExpect {
                    rows,
                    exact: true,
                    keys_sha256,
                    keys: listed,
                },
            );
        }

        let empty_dirs = self
            .dirs
            .iter()
            .filter(|d| {
                let prefix = format!("{d}/");
                !self.files.keys().any(|f| f.starts_with(&prefix))
                    && !self.dirs.iter().any(|o| o.starts_with(&prefix))
            })
            .cloned()
            .collect();

        Ok(TreeOutcome {
            files,
            empty_dirs,
            tables,
            delivered,
            ingest_culture,
        })
    }
}

/// Byte-order mark length of `enc`'s encoded text.
fn bom_len(enc: Encoding) -> usize {
    match enc {
        Encoding::Utf8Bom => 3,
        Encoding::Utf16LeBom => 2,
        _ => 0,
    }
}

/// What the status replay needs to know about one file.
struct Facts {
    rel: String,
    artifact: Option<&'static str>,
    derived: bool,
    priority: i16,
    subject: Option<String>,
    size: u64,
    sha256: String,
    expect_status: Option<&'static str>,
    date: DateEvidence,
}

impl Facts {
    fn of(st: &FileState) -> Facts {
        Facts {
            rel: st.spec.rel.clone(),
            artifact: st.spec.artifact,
            derived: st.spec.derived,
            priority: st.spec.priority,
            subject: st.spec.subject.clone(),
            size: st.bytes,
            sha256: hex::encode(st.sha.clone().finalize()),
            expect_status: st.spec.expect_status,
            date: st.date.unwrap_or_default(),
        }
    }
}

/// A replayed file status. `NoOrder` is an `error` because no file of the collection proved the
/// day/month order (with `CulturePolicy::Auto`, the tree is replayed with `--culture` instead).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Named(&'static str),
    NoOrder,
}

impl Status {
    fn as_str(&self) -> &'static str {
        match self {
            Status::Named(s) => s,
            Status::NoOrder => "error",
        }
    }
}

/// Handled (`parsed`, `duplicate_file`) and failed (`not_supported`, `error`, deferred) files
/// so far, by lower-cased path.
#[derive(Default)]
struct Handled {
    ok: BTreeSet<String>,
    failed: BTreeSet<String>,
    /// Lower-cased relative path → artifact id, for every listed file (whether or not it
    /// parses), for the rules that must know which files are QuickUAL exports.
    artifacts: BTreeMap<String, &'static str>,
}

impl Handled {
    fn insert(&mut self, rel: &str) {
        let l = rel.to_lowercase();
        self.failed.remove(&l);
        self.ok.insert(l);
    }

    fn insert_failed(&mut self, rel: &str) {
        let l = rel.to_lowercase();
        if !self.ok.contains(&l) {
            self.failed.insert(l);
        }
    }

    /// Record a listed file's artifact id, before any file is decided.
    fn note_artifact(&mut self, rel: &str, artifact: Option<&'static str>) {
        if let Some(a) = artifact {
            self.artifacts.insert(rel.to_lowercase(), a);
        }
    }

    /// True when a combined export is redundant: at least one `inv.quickual.operation` file sits
    /// directly in `dir` and none failed. A per-operation JSON and its CSV twin are one export,
    /// so the CSV's `skipped_superseded` still counts; a failed file means the combined file is
    /// the only surviving copy of its records, so it is parsed.
    fn quickual_operations_all_parsed(&self, dir: &str) -> bool {
        let prefix = format!("{dir}/");
        let directly = |p: &str| p.strip_prefix(&prefix).is_some_and(|r| !r.contains('/'));
        let mut found = false;
        for (lower, artifact) in &self.artifacts {
            if *artifact != "inv.quickual.operation" || !directly(lower) {
                continue;
            }
            found = true;
            if self.failed.contains(lower) {
                return false;
            }
        }
        found
    }

    /// Rule 5: a CSV whose same-folder JSON twin was handled; a derived file whose counterpart
    /// stem was handled in the same folder as `.json` or `.csv`; a derived file in a `Merged/`
    /// folder whose parent holds a handled file and no failed one.
    fn superseded(&self, rel: &str, derived: bool) -> bool {
        let lower = rel.to_lowercase();
        let (dir, file) = match lower.rsplit_once('/') {
            Some((d, f)) => (Some(d), f),
            None => (None, lower.as_str()),
        };
        let Some((stem, ext)) = file.rsplit_once('.') else {
            return false;
        };
        let join = |name: String| match dir {
            Some(d) => format!("{d}/{name}"),
            None => name,
        };
        if ext == "csv" && self.ok.contains(&join(format!("{stem}.json"))) {
            return true;
        }
        if !derived {
            return false;
        }
        for c in counterpart_stems(stem) {
            for e in ["json", "csv"] {
                if self.ok.contains(&join(format!("{c}.{e}"))) {
                    return true;
                }
            }
        }
        if stem == "ual-operations-combined" {
            if let Some(dir) = dir {
                if self.quickual_operations_all_parsed(dir) {
                    return true;
                }
            }
        }
        if let Some((parent, "merged")) = dir.and_then(|d| d.rsplit_once('/')) {
            let prefix = format!("{parent}/");
            let directly = |p: &&String| p.strip_prefix(&prefix).is_some_and(|r| !r.contains('/'));
            return self.ok.iter().any(|p| directly(&p))
                && !self.failed.iter().any(|p| directly(&p));
        }
        false
    }
}

/// The raw stems (lower-case) that supersede derived stem `stem` (lower-case): `simple_x` →
/// `x`, `xs`; `exchangeitem[group]_simple_u` → `exchangeitem[group]_logs_u`;
/// `converted_authentication_logs_u` → `raw_authentication_logs_u`.
fn counterpart_stems(stem: &str) -> Vec<String> {
    for (from, to) in [
        ("exchangeitemgroup_simple_", "exchangeitemgroup_logs_"),
        ("exchangeitem_simple_", "exchangeitem_logs_"),
        ("converted_authentication_logs_", "raw_authentication_logs_"),
    ] {
        if let Some(rest) = stem.strip_prefix(from) {
            return vec![format!("{to}{rest}")];
        }
    }
    match stem.strip_prefix("simple_") {
        Some(rest) => vec![rest.to_string(), format!("{rest}s")],
        None => Vec::new(),
    }
}

/// Replays the ingest over `files` (`culture_given`: the ingest passes `--culture`). Files are
/// processed in Sparrow's order `(derived, is_csv, rel_path)`, raw files first and derived ones
/// second, each stage with its own retry: with no `--culture`, a file whose culture dates are all
/// ambiguous is deferred to its stage's retry pass and parses only when a parsed file proved the
/// order (decisive dates) by then. A raw file no raw file could order is retried after the
/// derived stage instead.
fn replay(files: &[Facts], culture_given: bool) -> BTreeMap<&str, Status> {
    let mut order: Vec<&Facts> = files.iter().collect();
    order.sort_by_key(|f| {
        (
            f.derived,
            f.rel.to_lowercase().ends_with(".csv"),
            f.priority,
            f.rel.clone(),
        )
    });
    let (raw, derived): (Vec<&Facts>, Vec<&Facts>) = order.into_iter().partition(|f| !f.derived);

    let mut out: BTreeMap<&str, Status> = BTreeMap::new();
    let mut handled = Handled::default();
    for f in files {
        handled.note_artifact(&f.rel, f.artifact);
    }
    let mut parsed: BTreeSet<(String, Option<&'static str>, Option<String>)> = BTreeSet::new();
    let mut proved = false;
    let first = if culture_given {
        Pass::CultureGiven
    } else {
        Pass::First
    };
    // Raw files no raw file could order wait for the derived files' proof.
    let mut carried: Vec<&Facts> = Vec::new();
    for (i, stage) in [raw, derived].into_iter().enumerate() {
        let last = i == 1;
        let mut deferred = Vec::new();
        for f in stage {
            match decide(f, &handled, &parsed, first, proved) {
                None => {
                    handled.insert_failed(&f.rel);
                    deferred.push(f);
                }
                Some(st) => {
                    if st == Status::Named("parsed") && f.date.decisive > 0 {
                        proved = true;
                    }
                    record(f, &st, &mut handled, &mut parsed);
                    out.insert(&f.rel, st);
                }
            }
        }
        if !last && !proved {
            carried.append(&mut deferred);
            continue;
        }
        let retry: Vec<&Facts> = if last {
            std::mem::take(&mut carried)
                .into_iter()
                .chain(deferred)
                .collect()
        } else {
            deferred
        };
        for f in retry {
            let st = decide(f, &handled, &parsed, Pass::Retry, proved)
                .expect("the retry pass never defers");
            record(f, &st, &mut handled, &mut parsed);
            out.insert(&f.rel, st);
        }
    }
    out
}

/// Which pass of the replay a file is decided in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// `--culture` given: nothing is deferred.
    CultureGiven,
    /// No `--culture`: all-ambiguous files are deferred.
    First,
    /// The deferred files, parsed only when the first pass proved the order.
    Retry,
}

/// The status of one file (rules 3-9, with unrecognized checked after duplicate and superseded
/// as Sparrow does), or `None` to defer it.
fn decide(
    f: &Facts,
    handled: &Handled,
    parsed: &BTreeSet<(String, Option<&'static str>, Option<String>)>,
    pass: Pass,
    proved: bool,
) -> Option<Status> {
    // Sparrow's order: duplicate, superseded, then unrecognized (an unclassified file is never
    // a duplicate, since only classified files are parsed).
    if f.size > 0 && parsed.contains(&(f.sha256.clone(), f.artifact, f.subject.clone())) {
        return Some(Status::Named("duplicate_file"));
    }
    if handled.superseded(&f.rel, f.derived) {
        return Some(Status::Named("skipped_superseded"));
    }
    let Some(artifact) = f.artifact else {
        return Some(Status::Named("unrecognized"));
    };
    if !parsed_by_sparrow(artifact) {
        return Some(Status::Named("not_supported"));
    }
    if let Some(s) = f.expect_status {
        return Some(Status::Named(s));
    }
    if f.date.all_ambiguous() {
        match pass {
            Pass::CultureGiven => {}
            Pass::First => return None,
            Pass::Retry if proved => {}
            Pass::Retry => return Some(Status::NoOrder),
        }
    }
    Some(Status::Named("parsed"))
}

fn record(
    f: &Facts,
    st: &Status,
    handled: &mut Handled,
    parsed: &mut BTreeSet<(String, Option<&'static str>, Option<String>)>,
) {
    match st.as_str() {
        "parsed" => {
            parsed.insert((f.sha256.clone(), f.artifact, f.subject.clone()));
            handled.insert(&f.rel);
        }
        "duplicate_file" => handled.insert(&f.rel),
        "not_supported" | "error" => handled.insert_failed(&f.rel),
        _ => {}
    }
}
