//! The app's local settings: the analyst name and the recently opened case paths, as JSON in the app config
//! directory. Never case data.

use crate::error::{CmdError, CmdResult};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use sparrow_core::case::actor::Reviewer;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;
use std::sync::atomic::{AtomicU64, Ordering};

const FILE: &str = "settings.json";
/// How many recent case paths are kept.
pub const MAX_RECENT: usize = 10;

#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// The analyst's name, without the `analyst:` prefix.
    pub analyst: Option<String>,
    /// Most recent first, no duplicates, at most [`MAX_RECENT`].
    pub recent: Vec<String>,
    /// The folder of the MaxMind GeoLite2 City and ASN `.mmdb` files the profile step reads. `None`: the default
    /// folder ([`default_geoip_dir`]) when it holds both databases.
    pub geoip_dir: Option<String>,
}

impl Settings {
    /// Put `path` first in the recent list.
    pub fn push_recent(&mut self, path: &str) {
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_string());
        self.recent.truncate(MAX_RECENT);
    }
}

/// The settings in `dir`; defaults when the file is missing or unreadable (settings are a convenience, never a
/// reason the app cannot start).
pub fn load(dir: &Path) -> Settings {
    std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Write the settings to `dir` (created if needed) through a temporary file of its own and a rename, so two
/// writers never share a temporary file.
pub fn save(dir: &Path, s: &Settings) -> std::io::Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(dir)?;
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!("{FILE}.{}.{n}.partial", std::process::id()));
    let out = std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(s).map_err(std::io::Error::other)?,
    )
    .and_then(|()| std::fs::rename(&tmp, dir.join(FILE)));
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

/// The settings directory, locked: every load-modify-save runs under this one lock, so concurrent updates of
/// different fields never lose each other. Lock order: the open case first, then the settings.
fn locked(state: &AppState) -> CmdResult<(MutexGuard<'_, Option<PathBuf>>, PathBuf)> {
    let guard = state.settings_dir.lock().unwrap_or_else(|p| p.into_inner());
    let dir = guard
        .clone()
        .ok_or_else(|| CmdError::new("internal", "the settings directory is not set"))?;
    Ok((guard, dir))
}

fn save_or_err(dir: &Path, s: &Settings) -> CmdResult<()> {
    save(dir, s).map_err(|e| CmdError::new("internal", format!("cannot save the settings: {e}")))
}

pub fn settings_get(state: &AppState) -> CmdResult<Settings> {
    let (_guard, dir) = locked(state)?;
    Ok(load(&dir))
}

/// Store the analyst name, validated as core validates an analyst (`Reviewer::analyst`).
pub fn settings_set_analyst(state: &AppState, name: &str) -> CmdResult<Settings> {
    Reviewer::analyst(name)?;
    let (_guard, dir) = locked(state)?;
    let mut s = load(&dir);
    s.analyst = Some(name.trim().to_string());
    save_or_err(&dir, &s)?;
    Ok(s)
}

/// Remember `path` as the most recently opened case. No settings directory (tests) means nothing to remember.
pub fn record_recent(state: &AppState, path: &str) -> CmdResult<()> {
    let guard = state.settings_dir.lock().unwrap_or_else(|p| p.into_inner());
    let Some(dir) = guard.clone() else {
        return Ok(());
    };
    let mut s = load(&dir);
    s.push_recent(path);
    save_or_err(&dir, &s)
}

// ---------------------------------------------------------------- GeoIP

/// The folder looked at when no GeoIP folder is set: `geoip` in the home directory (`~/geoip`). On Windows the
/// profile folder (`USERPROFILE`) comes first: a `HOME` there is often a Unix-style path set by another tool.
pub fn default_geoip_dir() -> Option<PathBuf> {
    let (first, second) = if cfg!(windows) {
        ("USERPROFILE", "HOME")
    } else {
        ("HOME", "USERPROFILE")
    };
    [first, second]
        .into_iter()
        .filter_map(std::env::var_os)
        .find(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join("geoip"))
}

/// The folders a GeoIP lookup chooses from, read from the settings without looking at the disk. Read it before
/// taking the case lock (lock order: the case, then the settings), then [`GeoipSource::resolve`] right before the
/// profile reads the databases, so a drive unplugged during a long import means no GeoIP, not a failed profile.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GeoipSource {
    pub configured: Option<PathBuf>,
    pub default: Option<PathBuf>,
}

impl GeoipSource {
    pub fn resolve(&self) -> GeoipStatus {
        resolve_geoip(self.configured.as_deref(), self.default.as_deref())
    }
}

/// The configured GeoIP folder from the settings, and the default folder.
pub fn geoip_source(state: &AppState) -> GeoipSource {
    let configured = {
        let guard = state.settings_dir.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_deref().and_then(|d| load(d).geoip_dir)
    };
    GeoipSource {
        configured: configured.map(PathBuf::from),
        default: default_geoip_dir(),
    }
}

/// Where the profile step gets country and ASN from, and why.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct GeoipStatus {
    /// The folder set in the settings, if any.
    pub configured: Option<String>,
    /// The folder the profile step will read; `None`: no GeoIP this run.
    pub dir: Option<String>,
    /// Whether that folder (or the configured one, when it is unusable) holds a City / an ASN database.
    pub city: bool,
    pub asn: bool,
    /// Why there is no GeoIP or only part of it, for the import result card; `None` when both databases are there.
    pub problem: Option<String>,
}

/// The configured folder when set (used even with one database missing; unusable when it is gone or holds
/// neither), else `default` when it holds both databases.
pub fn resolve_geoip(configured: Option<&Path>, default: Option<&Path>) -> GeoipStatus {
    let shown = |p: &Path| p.display().to_string();
    if let Some(dir) = configured {
        let configured = Some(shown(dir));
        return match sparrow_core::enrich::ip::geoip_dir_databases(dir) {
            Ok((city, asn)) if city || asn => GeoipStatus {
                configured,
                dir: Some(shown(dir)),
                city,
                asn,
                problem: (!(city && asn)).then(|| {
                    format!(
                        "the GeoIP folder {} has no GeoLite2 {} database",
                        dir.display(),
                        if city { "ASN" } else { "City" }
                    )
                }),
            },
            Ok(_) => GeoipStatus {
                configured,
                dir: None,
                city: false,
                asn: false,
                problem: Some(format!(
                    "the GeoIP folder {} holds no GeoLite2 City or ASN .mmdb file: addresses get no country or ASN",
                    dir.display()
                )),
            },
            Err(e) => GeoipStatus {
                configured,
                dir: None,
                city: false,
                asn: false,
                problem: Some(format!(
                    "the GeoIP folder {} cannot be read ({e}): addresses get no country or ASN",
                    dir.display()
                )),
            },
        };
    }
    if let Some(dir) = default {
        if let Ok((true, true)) = sparrow_core::enrich::ip::geoip_dir_databases(dir) {
            return GeoipStatus {
                configured: None,
                dir: Some(shown(dir)),
                city: true,
                asn: true,
                problem: None,
            };
        }
    }
    GeoipStatus {
        configured: None,
        dir: None,
        city: false,
        asn: false,
        problem: Some(format!(
            "no GeoIP folder is set{}: addresses get no country or ASN. Choose the folder of the MaxMind GeoLite2 \
             City and ASN .mmdb files in the import dialog",
            default
                .map(|d| format!(" and {} does not hold both GeoLite2 databases", d.display()))
                .unwrap_or_default()
        )),
    }
}

/// The GeoIP folder the profile step will use now. No settings directory (tests) means the default folder only.
pub fn geoip_status(state: &AppState) -> GeoipStatus {
    geoip_source(state).resolve()
}

/// Set the GeoIP folder (it must hold both a City and an ASN database), or clear it with `None` (back to the
/// default folder). A blank value clears too; any other value is kept exactly as given (a folder name may end in a
/// space).
pub fn settings_set_geoip_dir(state: &AppState, dir: Option<&str>) -> CmdResult<GeoipStatus> {
    let dir = match dir {
        None => None,
        Some(d) if d.trim().is_empty() => None,
        Some(d) => {
            let path = Path::new(d);
            if !path.is_absolute() {
                return Err(bad(format!(
                    "the GeoIP folder must be an absolute path: {d}"
                )));
            }
            let (city, asn) = sparrow_core::enrich::ip::geoip_dir_databases(path)
                .map_err(|e| bad(format!("cannot read the GeoIP folder {d}: {e}")))?;
            if !(city && asn) {
                let missing = match (city, asn) {
                    (false, false) => "a GeoLite2 City and a GeoLite2 ASN database",
                    (false, true) => "a GeoLite2 City database",
                    _ => "a GeoLite2 ASN database",
                };
                return Err(bad(format!("{d} does not hold {missing} (.mmdb)")));
            }
            Some(d.to_string())
        }
    };
    {
        let (_guard, settings_dir) = locked(state)?;
        let mut s = load(&settings_dir);
        s.geoip_dir = dir;
        save_or_err(&settings_dir, &s)?;
    }
    Ok(geoip_status(state))
}

// ---------------------------------------------------------------- highlights

const HIGHLIGHTS_FILE: &str = "highlights.json";
/// Highlight sets per case, rules per set, bytes per value, cases remembered at all.
pub const MAX_SETS: usize = 50;
pub const MAX_RULES: usize = 100;
pub const MAX_VALUE_BYTES: usize = 1024;
pub const MAX_CASES: usize = 500;
const MAX_NAME_CHARS: usize = 100;
const MAX_COLUMN_CHARS: usize = 128;
const OPS: [&str; 2] = ["eq", "contains"];
const COLOURS: [&str; 5] = ["red", "amber", "green", "blue", "purple"];

/// One highlight: a row whose `column` (any column when `None`) equals / contains `value` is coloured.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HighlightRule {
    pub column: Option<String>,
    pub op: String,
    pub value: String,
    pub colour: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HighlightSet {
    pub name: String,
    pub rules: Vec<HighlightRule>,
}

/// Local highlight sets keyed by case id: case data the analyst chose to keep on this machine, in a file of its own
/// next to the settings. Never written to the case, never audited, never in a bundle.
type HighlightStore = BTreeMap<String, Vec<HighlightSet>>;

/// The stored highlights. Only a missing file means "none yet"; a file that cannot be read or parsed is an error
/// (naming the file) and is left untouched, so a later save never overwrites what the analyst had.
fn load_highlights(dir: &Path) -> CmdResult<HighlightStore> {
    let path = dir.join(HIGHLIGHTS_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HighlightStore::new()),
        Err(e) => {
            return Err(CmdError::new(
                "internal",
                format!("cannot read {}: {e}", path.display()),
            ));
        }
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        CmdError::new(
            "internal",
            format!(
                "{} is damaged ({e}); fix or delete it to use highlights again",
                path.display()
            ),
        )
    })
}

fn save_highlights(dir: &Path, h: &HighlightStore) -> std::io::Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(dir)?;
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(
        "{HIGHLIGHTS_FILE}.{}.{n}.partial",
        std::process::id()
    ));
    let out = std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(h).map_err(std::io::Error::other)?,
    )
    .and_then(|()| std::fs::rename(&tmp, dir.join(HIGHLIGHTS_FILE)));
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

fn bad(msg: String) -> CmdError {
    CmdError::new("invalid", msg)
}

fn plain(what: &str, s: &str, max_chars: usize) -> CmdResult<()> {
    if s.trim().is_empty() {
        return Err(bad(format!("{what} is empty")));
    }
    if s.chars().count() > max_chars {
        return Err(bad(format!("{what} is longer than {max_chars} characters")));
    }
    if s.chars().any(char::is_control) {
        return Err(bad(format!("{what} holds control characters")));
    }
    Ok(())
}

fn check_case_id(case_id: &str) -> CmdResult<()> {
    plain("the case id", case_id, 200)
}

/// The caps and enums of the contract. Names and columns are plain text; a value may hold anything up to 1 KiB (it
/// is shown escaped and matched raw).
pub fn validate_highlights(sets: &[HighlightSet]) -> CmdResult<()> {
    if sets.len() > MAX_SETS {
        return Err(bad(format!(
            "at most {MAX_SETS} highlight sets per case (got {})",
            sets.len()
        )));
    }
    for set in sets {
        plain("a highlight set name", &set.name, MAX_NAME_CHARS)?;
        if set.rules.len() > MAX_RULES {
            return Err(bad(format!(
                "at most {MAX_RULES} rules per highlight set (set has {})",
                set.rules.len()
            )));
        }
        for r in &set.rules {
            if let Some(c) = &r.column {
                plain("a highlight column", c, MAX_COLUMN_CHARS)?;
            }
            if !OPS.contains(&r.op.as_str()) {
                return Err(bad(format!("unknown highlight operator {:?}", r.op)));
            }
            if !COLOURS.contains(&r.colour.as_str()) {
                return Err(bad(format!("unknown highlight colour {:?}", r.colour)));
            }
            if r.value.len() > MAX_VALUE_BYTES {
                return Err(bad(format!(
                    "a highlight value is longer than {MAX_VALUE_BYTES} bytes"
                )));
            }
        }
    }
    Ok(())
}

pub fn highlights_get(state: &AppState, case_id: &str) -> CmdResult<Vec<HighlightSet>> {
    check_case_id(case_id)?;
    let (_guard, dir) = locked(state)?;
    Ok(load_highlights(&dir)?.remove(case_id).unwrap_or_default())
}

/// Replace the case's sets (validated, capped); returns what was stored.
pub fn highlights_set(
    state: &AppState,
    case_id: &str,
    sets: Vec<HighlightSet>,
) -> CmdResult<Vec<HighlightSet>> {
    check_case_id(case_id)?;
    validate_highlights(&sets)?;
    let (_guard, dir) = locked(state)?;
    let mut all = load_highlights(&dir)?;
    if !all.contains_key(case_id) && all.len() >= MAX_CASES {
        return Err(bad(format!(
            "highlights are kept for at most {MAX_CASES} cases; clear the highlights of another case first"
        )));
    }
    all.insert(case_id.to_string(), sets.clone());
    save_highlights(&dir, &all)
        .map_err(|e| CmdError::new("internal", format!("cannot save the highlights: {e}")))?;
    Ok(sets)
}

pub fn highlights_clear(state: &AppState, case_id: &str) -> CmdResult<()> {
    check_case_id(case_id)?;
    let (_guard, dir) = locked(state)?;
    let mut all = load_highlights(&dir)?;
    if all.remove(case_id).is_some() {
        save_highlights(&dir, &all)
            .map_err(|e| CmdError::new("internal", format!("cannot save the highlights: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sparrow_core::enrich::mmdb_writer::{asn, city, write_mmdb};
    use std::net::IpAddr;

    /// A folder holding a synthetic City and/or ASN database (documentation addresses only).
    fn geoip_folder(with_city: bool, with_asn: bool) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let net: IpAddr = "192.0.2.0".parse().unwrap();
        if with_city {
            let v = city("US", "United States", "Example", 0.0, 0.0);
            std::fs::write(
                dir.path().join("City.mmdb"),
                write_mmdb("GeoLite2-City", 1, &[(net, 24, v)]),
            )
            .unwrap();
        }
        if with_asn {
            let v = asn(64500, "Example AS");
            std::fs::write(
                dir.path().join("ASN.mmdb"),
                write_mmdb("GeoLite2-ASN", 1, &[(net, 24, v)]),
            )
            .unwrap();
        }
        dir
    }

    #[test]
    fn the_default_folder_is_used_only_with_both_databases() {
        let both = geoip_folder(true, true);
        let s = resolve_geoip(None, Some(both.path()));
        assert_eq!(s.dir.as_deref(), Some(both.path().to_str().unwrap()));
        assert!(s.city && s.asn && s.problem.is_none());

        let half = geoip_folder(true, false);
        let s = resolve_geoip(None, Some(half.path()));
        assert_eq!(s.dir, None);
        assert!(s.problem.unwrap().contains("no GeoIP folder is set"));

        let s = resolve_geoip(None, Some(&half.path().join("missing")));
        assert_eq!(s.dir, None);
        assert!(s.problem.is_some());
    }

    #[test]
    fn a_configured_folder_wins_and_says_what_it_lacks() {
        let default = geoip_folder(true, true);
        let configured = geoip_folder(false, true);
        let s = resolve_geoip(Some(configured.path()), Some(default.path()));
        assert_eq!(s.dir.as_deref(), Some(configured.path().to_str().unwrap()));
        assert!(!s.city && s.asn);
        assert!(s.problem.unwrap().contains("no GeoLite2 City database"));

        // Gone (an unplugged drive): no GeoIP this run, never a silent switch to the default folder.
        let gone = configured.path().join("gone");
        let s = resolve_geoip(Some(&gone), Some(default.path()));
        assert_eq!(s.dir, None);
        assert_eq!(s.configured.as_deref(), Some(gone.to_str().unwrap()));
        assert!(s.problem.unwrap().contains("cannot be read"));

        let empty = geoip_folder(false, false);
        let s = resolve_geoip(Some(empty.path()), Some(default.path()));
        assert_eq!(s.dir, None);
        assert!(s.problem.unwrap().contains("holds no GeoLite2"));
    }

    #[test]
    fn setting_the_folder_needs_both_databases_and_clearing_restores_the_default() {
        let settings_dir = tempfile::tempdir().unwrap();
        let state = AppState::default();
        *state.settings_dir.lock().unwrap() = Some(settings_dir.path().to_path_buf());

        let half = geoip_folder(true, false);
        let err = settings_set_geoip_dir(&state, Some(half.path().to_str().unwrap())).unwrap_err();
        assert_eq!(err.kind, "invalid");
        assert!(err.message.contains("ASN"));
        assert_eq!(load(settings_dir.path()).geoip_dir, None);
        assert_eq!(
            settings_set_geoip_dir(&state, Some("relative/geoip"))
                .unwrap_err()
                .kind,
            "invalid"
        );

        let both = geoip_folder(true, true);
        let path = both.path().to_str().unwrap();
        let s = settings_set_geoip_dir(&state, Some(path)).unwrap();
        assert_eq!(s.configured.as_deref(), Some(path));
        assert_eq!(s.dir.as_deref(), Some(path));
        assert_eq!(load(settings_dir.path()).geoip_dir.as_deref(), Some(path));

        let s = settings_set_geoip_dir(&state, None).unwrap();
        assert_eq!(s.configured, None);
        assert_eq!(load(settings_dir.path()).geoip_dir, None);
    }

    #[test]
    fn a_source_looks_at_the_disk_when_resolved_not_when_read() {
        let folder = geoip_folder(true, true);
        let path = folder.path().to_path_buf();
        let source = GeoipSource {
            configured: Some(path.clone()),
            default: None,
        };
        assert_eq!(
            source.resolve().dir.as_deref(),
            Some(path.to_str().unwrap())
        );
        // The drive is unplugged between the start of an import and its profile step.
        drop(folder);
        let s = source.resolve();
        assert_eq!(s.dir, None);
        assert!(s.problem.unwrap().contains("cannot be read"));
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_name_ending_in_a_space_is_kept_as_given() {
        let settings_dir = tempfile::tempdir().unwrap();
        let state = AppState::default();
        *state.settings_dir.lock().unwrap() = Some(settings_dir.path().to_path_buf());
        let parent = tempfile::tempdir().unwrap();
        let spaced = parent.path().join("GeoIP ");
        std::fs::create_dir(&spaced).unwrap();
        for f in ["City.mmdb", "ASN.mmdb"] {
            std::fs::copy(geoip_folder(true, true).path().join(f), spaced.join(f)).unwrap();
        }
        let s = settings_set_geoip_dir(&state, Some(spaced.to_str().unwrap())).unwrap();
        assert_eq!(s.configured.as_deref(), Some(spaced.to_str().unwrap()));
        assert_eq!(
            load(settings_dir.path()).geoip_dir.as_deref(),
            Some(spaced.to_str().unwrap())
        );
        // Blank clears.
        assert_eq!(
            settings_set_geoip_dir(&state, Some("  "))
                .unwrap()
                .configured,
            None
        );
    }

    #[test]
    fn settings_written_before_the_geoip_field_still_load() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(FILE),
            br#"{"analyst":"carlos","recent":["/c.duckdb"]}"#,
        )
        .unwrap();
        let s = load(dir.path());
        assert_eq!(s.analyst.as_deref(), Some("carlos"));
        assert_eq!(s.geoip_dir, None);
    }

    #[test]
    fn recent_paths_are_most_recent_first_deduplicated_and_capped() {
        let mut s = Settings::default();
        for i in 0..12 {
            s.push_recent(&format!("/c{i}.duckdb"));
        }
        assert_eq!(s.recent.len(), MAX_RECENT);
        assert_eq!(s.recent[0], "/c11.duckdb");
        assert_eq!(s.recent[MAX_RECENT - 1], "/c2.duckdb");
        s.push_recent("/c5.duckdb");
        assert_eq!(s.recent[0], "/c5.duckdb");
        assert_eq!(s.recent.iter().filter(|p| *p == "/c5.duckdb").count(), 1);
        assert_eq!(s.recent.len(), MAX_RECENT);
    }
}
