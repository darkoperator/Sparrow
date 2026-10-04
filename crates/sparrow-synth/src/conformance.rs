//! Structure-only conformance check against the recorded real collector layouts
//! (`conformance/layouts.yaml`, transcribed from the surveys' tables) and against a real
//! capture's structure profile. Values are never stored: the profile keeps artifact ids,
//! formats, encodings, line ends, header column names, JSON shapes and top-level keys, and the
//! set of date form classes per column/key. Column/key names that could carry a value (they
//! contain `@` or look like an IP) are masked to `<masked>`, and reports print only artifact
//! ids, masked names, encodings, date forms and counts — never a path, a file name or a value.

use crate::options::{Collector, Culture, GenerateOptions};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sparrow_core::discovery::{
    FileFormat, Registry, discover_collections, format_from_path, list_collection_files,
};
use sparrow_core::readers::csv_scan::{normalize_headers, read_csv};
use sparrow_core::readers::json_scan::{JsonShape, scan_json};
use sparrow_core::readers::text::{TextEncoding, decode};
use sparrow_core::readers::xlsx::xlsx_headers;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

const LAYOUTS_YAML: &str = include_str!("../conformance/layouts.yaml");

/// The masked replacement for a column/key name that could carry a value.
pub const MASKED: &str = "<masked>";

/// One artifact's recorded layout (structure only).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutDef {
    pub artifact: String,
    pub collector: String,
    pub source: String,
    /// Optional file-name pattern distinguishing shapes that share one registry artifact id
    /// (`hawk.user.raw_ual`, `hawk.tenant.raw_ual`). The profile is per artifact, so the check
    /// accepts a header when any entry for the artifact accepts it; the pattern is documentation
    /// and a future per-file routing key.
    #[serde(default)]
    pub file_pattern: Option<String>,
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub encodings: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub line_ends: Option<String>,
    /// Accepted CSV header variants (exact column names in order).
    #[serde(default)]
    pub columns: Vec<Vec<String>>,
    /// Required CSV columns (used when the header order/set is capture-specific).
    #[serde(default)]
    pub columns_required: Vec<String>,
    /// Keys every JSON record has.
    #[serde(default)]
    pub json_keys: Vec<String>,
    /// The JSON shapes the source can produce for this artifact: `bare` for one record in a
    /// call, `array` for several, `concatenated` when the collector calls the writer once per
    /// record with `-Append`. Empty means the shape is unchecked. This is the allowed set for
    /// a real capture, where the record count can differ.
    #[serde(default)]
    pub json_shape: Vec<String>,
    /// The JSON shape(s) the generated trees must produce (a stricter subset of `json_shape`
    /// for artifacts whose generated counts now fix the shape). Empty means only `json_shape`
    /// is enforced.
    #[serde(default)]
    pub json_shape_expected: Vec<String>,
    /// Date form classes seen per column/key. A column's value is either the forms observed in
    /// every culture, or a per-culture map (`any:` plus `en-gb:` / `de-de:` … keys) so a
    /// culture-specific rendering is only allowed on the culture that produces it.
    #[serde(default)]
    pub dates: BTreeMap<String, DateForms>,
    /// True when a `dates` entry is an inference (e.g. a PS 5.1 form the survey only saw on PS7),
    /// not an observation in the tested edition.
    #[serde(default)]
    pub inferred: bool,
    /// Documentation only (the profile does not parse embedded JSON).
    #[serde(default)]
    pub embedded_json: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutsFile {
    version: u32,
    artifacts: Vec<LayoutDef>,
}

/// One column's recorded date forms. `Plain` applies to every host culture; `PerCulture` keys the
/// extra forms by culture (`any` is the fallback).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DateForms {
    Plain(Vec<String>),
    PerCulture(BTreeMap<String, Vec<String>>),
}

impl DateForms {
    /// The forms allowed on `culture`: the `any` entry plus that culture's own.
    fn for_culture(&self, culture: Option<crate::options::Culture>) -> BTreeSet<&str> {
        match self {
            DateForms::Plain(v) => v.iter().map(String::as_str).collect(),
            DateForms::PerCulture(m) => {
                let key = culture.map(culture_key).unwrap_or("any");
                let mut out: BTreeSet<&str> = m
                    .get("any")
                    .into_iter()
                    .flatten()
                    .map(String::as_str)
                    .collect();
                if key != "any" {
                    out.extend(m.get(key).into_iter().flatten().map(String::as_str));
                }
                out
            }
        }
    }
}

/// The `layouts.yaml` key for a host culture.
fn culture_key(c: crate::options::Culture) -> &'static str {
    use crate::options::Culture::{DeDe, EnGb, EnUs, JaJp};
    match c {
        EnUs => "en-us",
        EnGb => "en-gb",
        DeDe => "de-de",
        JaJp => "ja-jp",
    }
}

fn layouts() -> &'static [LayoutDef] {
    static L: OnceLock<Vec<LayoutDef>> = OnceLock::new();
    L.get_or_init(|| {
        let file: LayoutsFile = serde_norway::from_str(LAYOUTS_YAML)
            .unwrap_or_else(|e| panic!("conformance/layouts.yaml: {e}"));
        assert_eq!(file.version, 1, "conformance/layouts.yaml: unknown version");
        file.artifacts
    })
}

/// Date column/key names from the surveys that `layouts.yaml` does not list under `dates:`
/// (mostly `WhenChanged`/`WhenCreated` family columns of Exchange objects, and the risk and
/// sign-in timestamps). The classifier only ever looks at names: a column's values never make
/// it a date column.
const CURATED_DATE_COLUMNS: &[&str] = &[
    "CreationTime",
    "CreationDate",
    "CreatedDateTime",
    "createdDateTime",
    "DateCreated",
    "activityDateTime",
    "ActivityDateTime",
    "RunDate",
    "Received",
    "WhenChanged",
    "WhenCreated",
    "WhenChangedUTC",
    "WhenCreatedUTC",
    "LastSignInDateTime",
    "LastSuccessfulSignInDateTime",
    "LastPasswordChangeDateTime",
    "LastModifiedDateTime",
    "DeletedDateTime",
    "ModifiedTime",
    "UserStateChangedOn",
    "FirstSyncTime",
    "LastAccessed",
    "StartDate",
    "EndDate",
    "CheckDate",
    "TimeStamp",
    "Timestamp",
    "origin_timestamp_utc",
    "Param_StartTime",
    "Param_EndTime",
];

/// The set of column/key names whose values may carry a date form: every `dates:` key in
/// `layouts.yaml` plus the curated survey list.
fn known_date_columns() -> &'static BTreeSet<&'static str> {
    static COLUMNS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    COLUMNS.get_or_init(|| {
        let mut set: BTreeSet<&'static str> = layouts()
            .iter()
            .flat_map(|d| d.dates.keys().map(String::as_str))
            .collect();
        set.extend(CURATED_DATE_COLUMNS.iter().copied());
        set
    })
}

/// Whether a column/key is a known date column. Values are never consulted.
fn is_date_column(name: &str) -> bool {
    known_date_columns().contains(name)
}

fn collector_str(c: Collector) -> &'static str {
    match c {
        Collector::Hawk3 | Collector::Hawk4 => "hawk",
        Collector::Invictus => "invictus",
        Collector::Portal => "portal",
    }
}

/// A column/key name as the report prints it: masked when it could carry a value.
pub fn mask(name: &str) -> String {
    if name.contains('@') || name.parse::<std::net::IpAddr>().is_ok() {
        MASKED.to_string()
    } else {
        name.to_string()
    }
}

/// The structure of one artifact seen in a tree.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactProfile {
    pub files: u64,
    pub formats: BTreeMap<String, u64>,
    pub encodings: BTreeMap<String, u64>,
    pub line_ends: BTreeMap<String, u64>,
    /// CSV headers (column names in order) → file count.
    pub headers: BTreeMap<Vec<String>, u64>,
    pub json_shapes: BTreeMap<String, u64>,
    /// Union of top-level JSON keys over the first records.
    pub keys: BTreeSet<String>,
    /// Column/key → the date form classes seen in its values.
    pub dates: BTreeMap<String, BTreeSet<String>>,
}

/// Every artifact's structure in one tree.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub artifacts: BTreeMap<String, ArtifactProfile>,
    pub unrecognized: u64,
    pub errors: u64,
}

/// A structure-only comparison's result. Findings never contain a path, a file name or a value.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub ok: bool,
    pub checked: u64,
    pub not_checked: u64,
    pub findings: Vec<String>,
    /// `--real`: the per-tree variants the generated matrix covered (`variants`), by label.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<String>,
}

impl ConformanceReport {
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "ok: {}\nchecked: {}, not checked: {}\n",
            self.ok, self.checked, self.not_checked
        );
        if !self.variants.is_empty() {
            out.push_str(&format!("variants covered: {}\n", self.variants.join("; ")));
        }
        if self.findings.is_empty() {
            out.push_str("findings: none\n");
        } else {
            out.push_str(&format!("findings ({}):\n", self.findings.len()));
            for f in &self.findings {
                out.push_str(&format!("  {f}\n"));
            }
        }
        out
    }
}

fn core_err(e: sparrow_core::Error) -> Error {
    Error::Core(e.to_string())
}

/// The JSON shapes `layouts.yaml` allows for `artifact` (empty when it records none).
fn allowed_json_shapes(artifact: &str) -> BTreeSet<&'static str> {
    layouts()
        .iter()
        .filter(|d| d.artifact == artifact)
        .flat_map(|d| d.json_shape.iter().map(String::as_str))
        .collect()
}

/// Every per-culture date form `layouts.yaml` records, as (artifact, column, culture, form).
///
/// A per-culture form is a claim that the writer renders that column in the host culture, so
/// a generated tree must actually show it; `no_dead_culture_forms_are_recorded` proves that
/// over the whole matrix. Only columns whose value is a `host.culture_date` / `Export-Csv`
/// typed date may carry one.
pub fn recorded_culture_forms() -> Vec<(String, String, Culture, String)> {
    let mut out = Vec::new();
    for d in layouts() {
        for (column, forms) in &d.dates {
            if let DateForms::PerCulture(by) = forms {
                for (culture, list) in by {
                    if culture == "any" {
                        continue;
                    }
                    let Some(c) = culture_from_key(culture) else {
                        continue;
                    };
                    for form in list {
                        out.push((d.artifact.clone(), column.clone(), c, form.clone()));
                    }
                }
            }
        }
    }
    out
}

/// The `layouts.yaml` culture key -> [`Culture`].
fn culture_from_key(key: &str) -> Option<Culture> {
    use crate::options::Culture::{DeDe, EnGb, EnUs, JaJp};
    match key {
        "en-us" => Some(EnUs),
        "en-gb" => Some(EnGb),
        "de-de" => Some(DeDe),
        "ja-jp" => Some(JaJp),
        _ => None,
    }
}

/// Profile every collection found under `path` (structure only).
pub fn profile_dir(path: &Path) -> Result<Profile> {
    let mut profile = Profile::default();
    let reg = Registry::builtin();
    for collection in discover_collections(path).map_err(core_err)? {
        let listing =
            list_collection_files(&collection.root, collection.shallow).map_err(core_err)?;
        profile.errors += listing.errors.len() as u64;
        for file in &listing.files {
            let Some(class) = reg.classify_file(collection.tool, &file.rel, &file.abs) else {
                profile.unrecognized += 1;
                continue;
            };
            let bytes = match std::fs::read(&file.abs) {
                Ok(b) => b,
                Err(e) => {
                    profile.errors += 1;
                    let _ = Error::io(&file.abs, e);
                    continue;
                }
            };
            profile
                .artifacts
                .entry(class.artifact_id.to_string())
                .or_default()
                .observe(&file.rel, &bytes);
        }
    }
    Ok(profile)
}

impl ArtifactProfile {
    fn observe(&mut self, rel: &str, bytes: &[u8]) {
        self.files += 1;
        let format = format_from_path(rel);
        *self.formats.entry(format.as_str().to_string()).or_default() += 1;
        if format == FileFormat::Xlsx {
            if let Some(headers) = xlsx_headers(bytes) {
                // A workbook's header row is cleaned like a CSV header's (the portal sign-in
                // export spells `Application ID ` and `Autonomous system  number` with the
                // spaces the CSV carries), so a real workbook and a generated CSV compare
                // equal. `sparrow_core::parsers::signins` keys its rows the same way.
                let headers = normalize_headers(headers.iter().map(String::as_str));
                *self.headers.entry(mask_header(&headers)).or_default() += 1;
            }
            return;
        }
        let decoded = decode(bytes);
        let encoding = match decoded.encoding {
            TextEncoding::Utf16Le if decoded.bom_len > 0 => "utf-16le-bom",
            TextEncoding::Utf16Be if decoded.bom_len > 0 => "utf-16be-bom",
            other => other.as_str(),
        };
        *self.encodings.entry(encoding.to_string()).or_default() += 1;
        *self
            .line_ends
            .entry(line_ends(&decoded.text).to_string())
            .or_default() += 1;
        match format {
            FileFormat::Csv => self.observe_csv(&decoded.text),
            FileFormat::Json | FileFormat::Jsonl => self.observe_json(&decoded.text),
            _ => {}
        }
    }

    fn observe_csv(&mut self, text: &str) {
        let table = read_csv(text);
        let header = mask_header(&table.headers);
        *self.headers.entry(header.clone()).or_default() += 1;
        for row in &table.rows {
            for (i, value) in row.fields.iter().enumerate() {
                let Some(column) = header.get(i) else {
                    continue;
                };
                if !is_date_column(column) {
                    continue;
                }
                if let Some(form) = classify_date(value) {
                    self.dates
                        .entry(column.clone())
                        .or_default()
                        .insert(form.to_string());
                }
            }
        }
    }

    fn observe_json(&mut self, text: &str) {
        let scan = scan_json(text);
        *self
            .json_shapes
            .entry(shape_name(scan.shape).to_string())
            .or_default() += 1;
        for record in scan.records.iter().take(200) {
            let Some(map) = record.value.as_object() else {
                continue;
            };
            for (key, value) in map {
                let key = mask(key);
                self.keys.insert(key.clone());
                if !is_date_column(&key) {
                    continue;
                }
                if let Some(s) = value.as_str() {
                    if let Some(form) = classify_date(s) {
                        self.dates.entry(key).or_default().insert(form.to_string());
                    }
                }
            }
        }
    }
}

fn mask_header(header: &[String]) -> Vec<String> {
    header.iter().map(|c| mask(c)).collect()
}

fn shape_name(shape: JsonShape) -> &'static str {
    match shape {
        JsonShape::Empty => "empty",
        JsonShape::SingleObject => "bare",
        JsonShape::Array => "array",
        JsonShape::Concatenated => "concatenated",
    }
}

fn line_ends(text: &str) -> &'static str {
    let crlf = text.contains("\r\n");
    // A bare `\n` not preceded by `\r`.
    let lf = text
        .bytes()
        .enumerate()
        .any(|(i, b)| b == b'\n' && (i == 0 || text.as_bytes()[i - 1] != b'\r'));
    let cr = text.contains('\r') && !crlf;
    match (crlf, lf, cr) {
        (true, true, _) => "mixed",
        (true, false, _) => "crlf",
        (false, true, _) => "lf",
        (false, false, true) => "cr",
        _ => "none",
    }
}

/// The date form class of `s`, or `None` when it does not look like a date.
pub fn classify_date(s: &str) -> Option<&'static str> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with("/Date(") && t.ends_with(")/") {
        return Some("msdate");
    }
    let b = t.as_bytes();
    // ISO `yyyy-MM-ddTHH:MM:SS`.
    if b.len() >= 19
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[10] == b'T'
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[16] == b':'
        && b[17..19].iter().all(u8::is_ascii_digit)
    {
        let rest = &t[19..];
        if rest.ends_with('Z') {
            return Some("iso_z");
        }
        if rest.starts_with('+') || rest.starts_with('-') {
            return Some("iso_offset");
        }
        return Some("iso_nozone");
    }
    // `yyyy-MM-dd HH:MM:SS` (local log / DB text).
    if b.len() >= 19
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b' '
        && b[13] == b':'
        && b[16] == b':'
    {
        return Some("local_log");
    }
    // `yyyy/MM/dd ...`.
    if b.len() >= 10
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'/'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'/'
    {
        return Some("culture_ymd");
    }
    let upper = t.to_ascii_uppercase();
    let am_pm = upper.ends_with("AM") || upper.ends_with("PM");
    // de-DE's `dd.MM.yyyy HH:mm:ss` is day-first with dots, so it is its own class: a
    // dotted 24-hour rendering never comes from an en-US/en-GB `Export-Csv` DateTime.
    let dotted = t.contains('.') && !t.contains('/');
    if dotted && t.matches(':').count() >= 2 && am_pm {
        return Some("culture_dmy_de");
    }
    let has_slash_or_dot = t.contains('/') || t.contains('.');
    if has_slash_or_dot {
        let colons = t.matches(':').count();
        if am_pm {
            return Some(if colons >= 2 {
                "culture_mdy"
            } else {
                "short_g"
            });
        }
        if colons >= 2 {
            return Some(if dotted {
                "culture_dmy_de"
            } else {
                "culture_dmy"
            });
        }
        if colons == 1 {
            return Some("short_g");
        }
    }
    None
}

/// Compare one generated tree's profile with the recorded layouts for `collector`.
/// `culture` is the host culture the tree was generated with; it selects the per-culture date
/// forms. `None` accepts every recorded culture's forms (the union).
pub fn conform_layouts(
    profile: &Profile,
    collector: Collector,
    culture: Option<Culture>,
) -> ConformanceReport {
    let want = collector_str(collector);
    let mut report = ConformanceReport {
        ok: true,
        ..ConformanceReport::default()
    };
    for (artifact, ap) in &profile.artifacts {
        let defs: Vec<&LayoutDef> = layouts()
            .iter()
            .filter(|d| d.artifact == *artifact && d.collector == want)
            .collect();
        if defs.is_empty() {
            report.not_checked += 1;
            continue;
        }
        report.checked += 1;
        check_artifact(artifact, ap, &defs, culture, &mut report.findings);
    }
    report.ok = report.findings.is_empty();
    report
}

/// Whether one entry accepts a profile header: an exact `columns` variant, or every
/// `columns_required` column is present.
fn header_matches(def: &LayoutDef, header: &[String]) -> bool {
    if def.columns.iter().any(|c| c == header) {
        return true;
    }
    !def.columns_required.is_empty()
        && def
            .columns_required
            .iter()
            .all(|r| header.iter().any(|h| h == r))
}

/// Compare one artifact's profile against every entry `layouts.yaml` has for it. Shapes that
/// share an artifact id (`hawk.user.raw_ual`) are separate entries; a header counts when any
/// entry accepts it, and encodings/formats/keys/dates are unioned.
fn check_artifact(
    artifact: &str,
    ap: &ArtifactProfile,
    defs: &[&LayoutDef],
    culture: Option<Culture>,
    findings: &mut Vec<String>,
) {
    let formats: BTreeSet<&str> = defs
        .iter()
        .flat_map(|d| d.formats.iter().map(String::as_str))
        .collect();
    if !formats.is_empty() {
        for fmt in ap.formats.keys() {
            if !formats.contains(fmt.as_str()) {
                findings.push(format!(
                    "{artifact}: format {fmt} is not one of {:?}",
                    formats
                ));
            }
        }
    }
    let allowed: BTreeSet<&str> = defs
        .iter()
        .flat_map(|d| d.encodings.values())
        .flatten()
        .map(String::as_str)
        .collect();
    if !allowed.is_empty() {
        for enc in ap.encodings.keys() {
            if !allowed.contains(enc.as_str()) {
                findings.push(format!(
                    "{artifact}: encoding {enc} is not one of {:?}",
                    allowed
                ));
            }
        }
    }
    let line_ends: BTreeSet<&str> = defs.iter().filter_map(|d| d.line_ends.as_deref()).collect();
    for found in ap.line_ends.keys() {
        if !line_ends.is_empty() && !line_ends.contains(found.as_str()) {
            findings.push(format!(
                "{artifact}: line ends {found}, recorded {:?}",
                line_ends
            ));
        }
    }
    let column_defs: Vec<&&LayoutDef> = defs
        .iter()
        .filter(|d| !d.columns.is_empty() || !d.columns_required.is_empty())
        .collect();
    for header in ap.headers.keys() {
        if !column_defs.is_empty() && !column_defs.iter().any(|d| header_matches(d, header)) {
            findings.push(format!(
                "{artifact}: header {:?} matches no recorded variant",
                header
            ));
        }
    }
    let allowed_shapes: BTreeSet<&str> = defs
        .iter()
        .flat_map(|d| d.json_shape.iter().map(String::as_str))
        .collect();
    if !allowed_shapes.is_empty() {
        for shape in ap.json_shapes.keys() {
            if !allowed_shapes.contains(shape.as_str()) {
                findings.push(format!(
                    "{artifact}: JSON shape {shape} is not one of {:?}",
                    allowed_shapes
                ));
            }
        }
    }
    let expected_shapes: BTreeSet<&str> = defs
        .iter()
        .flat_map(|d| d.json_shape_expected.iter().map(String::as_str))
        .collect();
    if !expected_shapes.is_empty() {
        for shape in ap.json_shapes.keys() {
            if !expected_shapes.contains(shape.as_str()) {
                findings.push(format!(
                    "{artifact}: JSON shape {shape} is not the generated shape {:?}",
                    expected_shapes
                ));
            }
        }
    }
    let key_defs: Vec<&&LayoutDef> = defs.iter().filter(|d| !d.json_keys.is_empty()).collect();
    if !key_defs.is_empty()
        && !key_defs
            .iter()
            .any(|d| d.json_keys.iter().all(|k| ap.keys.contains(k)))
    {
        findings.push(format!(
            "{artifact}: JSON records lack the recorded keys of every shape"
        ));
    }
    for def in defs {
        for (column, forms) in &def.dates {
            let allowed = forms.for_culture(culture);
            if let Some(found) = ap.dates.get(column) {
                for form in found {
                    if !allowed.iter().any(|f| f == form) {
                        findings.push(format!(
                            "{artifact}: {column} uses the date form {form}, recorded {:?}",
                            allowed
                        ));
                    }
                }
            }
        }
    }
}

/// One combination of the choices the generator makes PER TREE from the seed (the Purview `CreationDate` form, the
/// message-trace Excel re-save, the Hawk UAL `CreationDate` kind). `--real` generates the matrix once per variant, so
/// a form the generator can produce in any variant is never "real only" just because the seed took the other one.
/// A variant forces the choice (`GenerateOptions`' `Option` overrides) instead of hoping enough seeds cover it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    pub label: String,
    pub purview_culture_dates: Option<bool>,
    pub message_trace_excel_resave: Option<bool>,
    pub hawk_ual_creation_utc: Option<bool>,
}

impl Variant {
    /// Force this variant's choices on `o`.
    pub fn apply(&self, o: &mut GenerateOptions) {
        o.purview_culture_dates = self.purview_culture_dates;
        o.message_trace_excel_resave = self.message_trace_excel_resave;
        o.hawk_ual_creation_utc = self.hawk_ual_creation_utc;
    }
}

/// Every variant a tree of `collector` can take. Adding a per-tree seeded choice to a writer means adding it here;
/// `every_seeds_own_pick_is_covered_by_the_variants` fails when a seed's pick is missing.
pub fn variants(collector: Collector) -> Vec<Variant> {
    let none = || Variant {
        label: String::new(),
        purview_culture_dates: None,
        message_trace_excel_resave: None,
        hawk_ual_creation_utc: None,
    };
    match collector {
        // The Hawk writers pick the UAL CreationDate kind of the embedded raw records per tree.
        Collector::Hawk3 | Collector::Hawk4 => [
            (true, "ual-creation=utc"),
            (false, "ual-creation=unspecified"),
        ]
        .into_iter()
        .map(|(utc, label)| Variant {
            label: label.to_string(),
            hawk_ual_creation_utc: Some(utc),
            ..none()
        })
        .collect(),
        // The portal writer picks the Purview CreationDate form and the message-trace re-save per tree.
        Collector::Portal => {
            let mut out = Vec::new();
            for culture in [true, false] {
                for resave in [false, true] {
                    out.push(Variant {
                        label: format!(
                            "purview-dates={},trace={}",
                            if culture { "culture" } else { "iso" },
                            if resave { "excel-resave" } else { "download" }
                        ),
                        purview_culture_dates: Some(culture),
                        message_trace_excel_resave: Some(resave),
                        ..none()
                    });
                }
            }
            out
        }
        // Microsoft-Extractor-Suite trees have no per-tree seeded form.
        Collector::Invictus => vec![Variant {
            label: "single-form".to_string(),
            ..none()
        }],
    }
}

/// Compare a real capture's profile with the profiles of generated trees.
pub fn conform_real(real: &Profile, generated: &[Profile]) -> ConformanceReport {
    let mut report = ConformanceReport {
        ok: true,
        ..ConformanceReport::default()
    };
    for (artifact, r) in &real.artifacts {
        report.checked += 1;
        let gens: Vec<&ArtifactProfile> = generated
            .iter()
            .filter_map(|g| g.artifacts.get(artifact))
            .collect();
        if gens.is_empty() {
            report.findings.push(format!(
                "{artifact}: seen in the real tree, never generated"
            ));
            continue;
        }
        let gen_headers: BTreeSet<&Vec<String>> =
            gens.iter().flat_map(|g| g.headers.keys()).collect();
        let gen_columns: BTreeSet<String> =
            gen_headers.iter().flat_map(|h| h.iter().cloned()).collect();
        let real_columns: BTreeSet<String> = r.headers.keys().flatten().map(|c| mask(c)).collect();
        let missing: Vec<&String> = real_columns.difference(&gen_columns).collect();
        if !missing.is_empty() {
            report.findings.push(format!(
                "{artifact}: real columns never generated: {}",
                missing
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let gen_encodings: BTreeSet<&String> =
            gens.iter().flat_map(|g| g.encodings.keys()).collect();
        for enc in r.encodings.keys() {
            if !gen_encodings.contains(enc) {
                report.findings.push(format!(
                    "{artifact}: encoding {enc} seen in the real tree only"
                ));
            }
        }
        let gen_shapes: BTreeSet<&String> =
            gens.iter().flat_map(|g| g.json_shapes.keys()).collect();
        let allowed = allowed_json_shapes(artifact);
        for shape in r.json_shapes.keys() {
            // A count-dependent shape (regulated by `json_shape:`) is fine even when the
            // generated matrix only exercised the other count; otherwise the real shape must
            // appear somewhere in the generated trees.
            if !gen_shapes.contains(shape) && !allowed.contains(shape.as_str()) {
                report.findings.push(format!(
                    "{artifact}: JSON shape {shape} seen in the real tree only"
                ));
            }
        }
        for (column, forms) in &r.dates {
            let gen_forms: BTreeSet<&String> = gens
                .iter()
                .filter_map(|g| g.dates.get(column))
                .flatten()
                .collect();
            for form in forms {
                if !gen_forms.contains(form) {
                    report.findings.push(format!(
                        "{artifact}: date form {form} on {column} seen in the real tree only"
                    ));
                }
            }
        }
    }
    report.ok = report.findings.is_empty();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with_shape(artifact: &str, shape: &str) -> Profile {
        let mut ap = ArtifactProfile::default();
        ap.json_shapes.insert(shape.to_string(), 1);
        let mut p = Profile::default();
        p.artifacts.insert(artifact.to_string(), ap);
        p
    }

    /// `conform_layouts` rejects a generated JSON shape that the source cannot produce.
    #[test]
    fn conform_layouts_rejects_a_json_shape_the_source_does_not_allow() {
        let p = profile_with_shape("hawk.tenant.remote_domain", "concatenated");
        let r = conform_layouts(&p, Collector::Hawk4, None);
        assert!(!r.ok, "{}", r.to_text());
        assert!(
            r.findings.iter().any(|f| f.contains("concatenated")),
            "{}",
            r.to_text()
        );
    }

    /// The generated trees now hold several records, so their shape must be the array the
    /// count implies (`json_shape_expected`), even though `bare` stays allowed for a real
    /// capture with one record.
    #[test]
    fn conform_layouts_requires_the_array_when_the_count_implies_it() {
        let p = profile_with_shape("hawk.tenant.remote_domain", "array");
        assert!(conform_layouts(&p, Collector::Hawk4, None).ok);
        let p = profile_with_shape("hawk.tenant.remote_domain", "bare");
        let r = conform_layouts(&p, Collector::Hawk4, None);
        assert!(!r.ok, "{}", r.to_text());
        assert!(
            r.findings.iter().any(|f| f.contains("bare")),
            "{}",
            r.to_text()
        );
    }

    /// A real shape the source allows is fine even when the generated trees only saw the other
    /// count-dependent shape.
    #[test]
    fn conform_real_accepts_a_source_allowed_json_shape_that_was_not_generated() {
        let real = profile_with_shape("hawk.tenant.remote_domain", "array");
        let generated = vec![profile_with_shape("hawk.tenant.remote_domain", "bare")];
        let r = conform_real(&real, &generated);
        assert!(r.ok, "{}", r.to_text());
    }

    /// A shape neither generated nor source-allowed is still a finding.
    #[test]
    fn conform_real_rejects_a_json_shape_the_source_does_not_allow() {
        let real = profile_with_shape("hawk.tenant.remote_domain", "concatenated");
        let generated = vec![profile_with_shape("hawk.tenant.remote_domain", "bare")];
        let r = conform_real(&real, &generated);
        assert!(!r.ok, "{}", r.to_text());
    }

    fn csv(header: &str, row: &str) -> ArtifactProfile {
        let mut p = ArtifactProfile::default();
        p.observe_csv(&format!("{header}\r\n{row}\r\n"));
        p
    }

    fn json(text: &str) -> ArtifactProfile {
        let mut p = ArtifactProfile::default();
        p.observe_json(text);
        p
    }

    /// de-DE renders a CSV `DateTime` day-first with dots (`dd.MM.yyyy HH:mm:ss`), which is its
    /// own class; an en-GB day-first rendering is slash-separated.
    #[test]
    fn the_german_dotted_date_form_is_its_own_class() {
        assert_eq!(classify_date("06.09.2026 12:00:00"), Some("culture_dmy_de"));
        assert_eq!(
            classify_date("06.09.2026 12:00:00 PM"),
            Some("culture_dmy_de")
        );
        assert_eq!(classify_date("06/09/2026 12:00:00"), Some("culture_dmy"));
        assert_eq!(classify_date("9/6/2026 12:00:00 PM"), Some("culture_mdy"));
        // A `1.2.3`-style version is not a date in either culture.
        assert_eq!(classify_date("1.2.3"), None);
    }

    /// Free-text columns whose values merely contain a slash/dot and one colon must not be
    /// guessed to be dates (`userAgent`, `resourceDisplayName`, arbitrary `Param_*`).
    #[test]
    fn free_text_columns_are_never_classified_as_dates() {
        let p = csv(
            "userAgent,resourceDisplayName,Param_Foo,CreationDate",
            "\"Mozilla/5.0 (rv:109.0)\",\"Contoso: 1.2.3\",\"4/5 1:23\",\"4/5/2024 1:23 PM\"",
        );
        assert!(!p.dates.contains_key("userAgent"), "{:?}", p.dates);
        assert!(
            !p.dates.contains_key("resourceDisplayName"),
            "{:?}",
            p.dates
        );
        assert!(!p.dates.contains_key("Param_Foo"), "{:?}", p.dates);
        assert_eq!(
            p.dates.get("CreationDate").map(|s| s.contains("short_g")),
            Some(true),
            "{:?}",
            p.dates
        );
    }

    /// The same rule for JSON keys: only known date keys get a date form.
    #[test]
    fn free_text_json_keys_are_never_classified_as_dates() {
        let p = json(
            r#"{"userAgent":"Mozilla/5.0 (rv:109.0)","resourceDisplayName":"Contoso: 1.2.3","createdDateTime":"2024-01-02T03:04:05Z"}"#,
        );
        assert!(!p.dates.contains_key("userAgent"), "{:?}", p.dates);
        assert!(
            !p.dates.contains_key("resourceDisplayName"),
            "{:?}",
            p.dates
        );
        assert_eq!(
            p.dates.get("createdDateTime").map(|s| s.contains("iso_z")),
            Some(true),
            "{:?}",
            p.dates
        );
    }

    /// A real date column still gets its value form classified.
    #[test]
    fn date_columns_still_classify_by_value_form() {
        let p = csv(
            "CreationTime,WhenChanged",
            "\"2024-01-02T03:04:05.0000000Z\",\"4/5/2024 1:23 PM\"",
        );
        assert_eq!(
            p.dates.get("CreationTime").map(|s| s.contains("iso_z")),
            Some(true),
            "{:?}",
            p.dates
        );
        assert_eq!(
            p.dates.get("WhenChanged").map(|s| s.contains("short_g")),
            Some(true),
            "{:?}",
            p.dates
        );
    }
}
