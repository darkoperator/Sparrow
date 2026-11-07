//! Microsoft-Extractor-Suite 4.1.0 (Invictus): the world as a `Start-EvidenceCollection
//! -ProjectName <tenant folder name>` run plus the standalone cmdlets an analyst adds in the same
//! PowerShell session (research: 2026-09-26 Invictus event layouts §0-§1, §4, §7, §8, §10-§12;
//! state layouts §0-§1; sample survey §4). Every file goes under `Output/<project>/`, except
//! `Output/LogFile.txt`.
//!
//! Each cmdlet run gets its own `<Component>/<yyyyMMdd-HHmmss>[-<Sub>]` folder stamped with the
//! collecting host's local time (UTC + `host_utc_offset_minutes`): the first run starts at
//! `collected_at`, each later one 7-40 seconds after the previous run finished (`Runs`).
//! The run order is fixed: UnifiedAuditLog, Sign-In logs, Audit logs, MessageTrace (twice),
//! Mailbox Permissions, Audit Status (twice), MailItemsAccessed, Mailbox Audit Log, Licenses,
//! Users, Admins, Roles (AllRoles then PIM), RiskyEvents (two runs), SecurityAlerts, SecureScore,
//! Activity Logs, Directory Activity Logs (three runs), Email Export, Rules.

mod activity;
mod apps;
mod devices_groups;
mod directory;
mod email;
mod entra;
mod exchange;
mod legacy_audit;
mod licences;
mod log;
mod mfa_ca;
mod quickual;
mod risk_alerts;
mod rules;
mod ual;
mod ual_graph;

use crate::Result;
use crate::events::Day;
use crate::options::GenerateOptions;
use crate::ps::{Encoding, Host};
use crate::rng::{Rng, stream};
use crate::tree::{FileSpec, Tree};
use crate::world::World;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, Utc};

/// One cmdlet run's folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDir {
    /// `<Component>/<stamp>[-<label>]`, relative to the project folder.
    pub rel: String,
    /// `yyyyMMdd-HHmmss`, the host's local time.
    pub stamp: String,
    /// When the run started, host local time.
    pub local: NaiveDateTime,
}

/// The run-stamp sequence of one Output folder: the first run starts at `collected_at` (host
/// local time), each later run 7-40 seconds (seeded) after the previous one finished.
#[derive(Debug, Clone)]
pub struct Runs {
    rng: Rng,
    start: NaiveDateTime,
    /// When the last run finished (`None` before the first run).
    clock: Option<NaiveDateTime>,
}

impl Runs {
    pub fn new(world: &World) -> Runs {
        let offset = Duration::minutes(world.scenario.tenant.host_utc_offset_minutes.into());
        Runs {
            rng: stream(world.seed, "invictus/runs"),
            start: (world.collected_at() + offset).naive_utc(),
            clock: None,
        }
    }

    /// The next run of `component` (`label` is Init-OutputDir's `-SubComponent`).
    pub fn next(&mut self, component: &str, label: Option<&str>) -> RunDir {
        let local = match self.clock {
            None => self.start,
            Some(c) => c + Duration::seconds(self.rng.range(7, 40)),
        };
        self.at(local, component, label)
    }

    /// A run that starts `gap` after the previous one finished (an analyst re-running a
    /// cmdlet later).
    pub fn next_after(&mut self, component: &str, label: Option<&str>, gap: Duration) -> RunDir {
        let local = self.clock.unwrap_or(self.start) + gap;
        self.at(local, component, label)
    }

    /// The current run went on until `t` (paged downloads): the next run starts after it.
    pub fn busy_until(&mut self, t: NaiveDateTime) {
        if self.clock.is_none_or(|c| t > c) {
            self.clock = Some(t);
        }
    }

    fn at(&mut self, local: NaiveDateTime, component: &str, label: Option<&str>) -> RunDir {
        self.clock = Some(local);
        let stamp = local.format("%Y%m%d-%H%M%S").to_string();
        let rel = match label {
            Some(l) => format!("{component}/{stamp}-{l}"),
            None => format!("{component}/{stamp}"),
        };
        RunDir { rel, stamp, local }
    }
}

/// The collection root folder: `Output`; with `non_windows`, the project folder itself
/// (`Output/<project>`), because `Output\LogFile.txt` is then a file beside `Output/` and
/// nothing marks `Output` as a collection.
pub fn root(world: &World, opts: &GenerateOptions) -> String {
    if opts.non_windows {
        format!("Output/{}", world.tenant.folder_name)
    } else {
        "Output".to_string()
    }
}

/// What every artifact writer of one tree shares.
pub(crate) struct Ctx<'w> {
    pub world: &'w World,
    pub opts: &'w GenerateOptions,
    pub host: Host,
    /// `<project>/` (paths below the root), or empty when the root is the project folder.
    pub prefix: String,
    pub runs: Runs,
    pub log: log::Log,
    /// Seconds between pages of a paged download.
    pub rng: Rng,
    /// The window's UTC dates (`writers::window_dates`). Days are generated on demand by
    /// [`Ctx::days`] so no writer holds the whole window's events at once.
    pub dates: Vec<NaiveDate>,
}

impl<'w> Ctx<'w> {
    fn new(world: &'w World, opts: &'w GenerateOptions) -> Ctx<'w> {
        let mut host = Host::new(
            opts.ps,
            opts.culture,
            world.scenario.tenant.host_utc_offset_minutes,
        );
        if opts.non_windows {
            host = host.unix();
        }
        Ctx {
            world,
            opts,
            host,
            prefix: if opts.non_windows {
                String::new()
            } else {
                format!("{}/", world.tenant.folder_name)
            },
            runs: Runs::new(world),
            log: log::Log::default(),
            rng: stream(world.seed, "invictus/pages"),
            dates: crate::writers::window_dates(world),
        }
    }

    /// The window's days, oldest first. Each day is generated when yielded and dropped after, so
    /// iterating never holds more than one day's events (the writers that need a cross-day view
    /// stream or keep bounded summaries).
    pub fn days(&self) -> impl Iterator<Item = Day> + '_ {
        self.dates.iter().map(|date| self.day(*date))
    }

    /// One UTC day's events, restricted to `[window_start, window_end)`.
    fn day(&self, date: NaiveDate) -> Day {
        let (start, end) = (self.world.window_start(), self.world.window_end());
        let mut d = self.world.day(date);
        d.ual.retain(|u| u.time >= start && u.time < end);
        d.signins.retain(|s| s.time >= start && s.time < end);
        d.trace.retain(|t| t.received >= start && t.received < end);
        d
    }

    /// A path below the project folder, as a tree path.
    pub fn path(&self, rel: &str) -> String {
        format!("{}{rel}", self.prefix)
    }

    /// A path below the project folder as the collector's log prints it
    /// (`Output\<project>\<rel>`).
    pub fn shown(&self, rel: &str) -> String {
        format!(
            "Output\\{}\\{}",
            self.world.tenant.folder_name,
            rel.replace('/', "\\")
        )
    }

    /// `-Encoding UTF8` (Export-Csv, Out-File, Set-Content).
    pub fn utf8(&self) -> Encoding {
        Encoding::export_csv_utf8(self.opts.ps)
    }

    /// The triage root (`Triage-<tenant folder>`), a sibling of the project folder under
    /// `Output` (Start-MESTriage; Task 21 adds QuickUAL files there too).
    pub fn triage_root(&self) -> String {
        format!("Triage-{}", self.world.tenant.folder_name)
    }

    pub fn nl(&self) -> &'static str {
        self.host.newline
    }
}

/// One unit of a collection manifest: sources over a requested half-open UTC range.
pub(crate) struct ManifestUnit {
    pub sources: &'static [&'static str],
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub records: u64,
    /// Names relative to the run folder.
    pub files: Vec<String>,
}

impl Ctx<'_> {
    /// With `opts.invictus_manifests`, writes the run's `complete` manifest (Save-CollectionManifest's
    /// shape, `user_ids` null, `output_written` true) into the run folder `dir`.
    pub(crate) fn write_manifest(
        &self,
        tree: &mut Tree<'_>,
        run: &RunDir,
        dir: &str,
        cmdlet: &str,
        finished_local: NaiveDateTime,
        units: &[ManifestUnit],
    ) -> Result<()> {
        if !self.opts.invictus_manifests {
            return Ok(());
        }
        let offset = Duration::minutes(self.world.scenario.tenant.host_utc_offset_minutes.into());
        let utc = |t: NaiveDateTime| (t - offset).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let iso = |t: DateTime<Utc>| t.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let guid = stream(self.world.seed, &format!("invictus/manifest/{dir}")).uuid();
        let units: Vec<serde_json::Value> = units
            .iter()
            .enumerate()
            .map(|(i, u)| {
                serde_json::json!({
                    "unit_id": format!("u-{:04}", i + 1),
                    "sources": u.sources,
                    "scope": {
                        "user_ids": null, "operations": null, "record_types": null,
                        "ip_addresses": null, "session_ids": null, "event_type": null,
                        "direction": null, "other_filters": null
                    },
                    "start_utc": iso(u.start),
                    "end_utc": iso(u.end),
                    "state": "complete",
                    "records_written": u.records,
                    "output_written": true,
                    "files": u.files,
                    "gaps": [],
                })
            })
            .collect();
        let doc = serde_json::json!({
            "schema": "mes-collection-manifest/1",
            "run_id": guid.to_string(),
            "tool": "Microsoft-Extractor-Suite",
            "tool_version": "4.1.0.1",
            "fork": "darkoperator/sparrow-gap-fixes",
            "cmdlet": cmdlet,
            "parameters": {},
            "started_utc": utc(run.local),
            "finished_utc": utc(finished_local.max(run.local)),
            "status": "complete",
            "throttle_waits": { "count": 0, "total_seconds": 0.0 },
            "units": units,
        });
        let text = serde_json::to_string_pretty(&doc).expect("manifest json");
        let rel = format!("{dir}/CollectionManifest-{guid}.mesmanifest");
        let spec = FileSpec::new(&rel, Some("inv.collection_manifest"), Encoding::Utf8);
        tree.write(&spec, &text)?;
        Ok(())
    }
}

/// Writes the Microsoft-Extractor-Suite Output folder of `world` into `tree`.
pub fn write(world: &World, opts: &GenerateOptions, tree: &mut Tree<'_>) -> Result<()> {
    let mut c = Ctx::new(world, opts);
    ual::write_get_ual(&mut c, tree)?;
    ual_graph::write(&mut c, tree)?;
    entra::write_signins(&mut c, tree)?;
    entra::write_audits(&mut c, tree)?;
    exchange::write_message_trace(&mut c, tree)?;
    exchange::write_mailbox_permissions(&mut c, tree)?;
    exchange::write_audit_status(&mut c, tree)?;
    exchange::write_mail_items_accessed(&mut c, tree)?;
    ual::write_mailbox_audit_log(&mut c, tree)?;
    licences::write(&mut c, tree)?;
    directory::write(&mut c, tree)?;
    mfa_ca::write(&mut c, tree)?;
    apps::write(&mut c, tree)?;
    quickual::write(&mut c, tree)?;
    devices_groups::write(&mut c, tree)?;
    risk_alerts::write(&mut c, tree)?;
    activity::write(&mut c, tree)?;
    email::write(&mut c, tree)?;
    rules::write(&mut c, tree)?;
    legacy_audit::write(&mut c, tree)?;
    let log = std::mem::take(&mut c.log);
    log.write(&c, tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::load;

    #[test]
    fn runs_start_at_collection_local_time_and_move_forward() {
        let w = World::build(&load("bec-aitm").unwrap(), 1).unwrap();
        let mut runs = Runs::new(&w);
        let a = runs.next("UnifiedAuditLog", None);
        // collected_at 2026-09-10T14:15:00Z on a UTC+2 host.
        assert_eq!(a.rel, "UnifiedAuditLog/20260910-161500");
        let b = runs.next("Sign-In logs/EntraID", Some("SignInLogs"));
        let gap = (b.local - a.local).num_seconds();
        assert!((7..=40).contains(&gap), "{gap}");
        assert_eq!(
            b.rel,
            format!("Sign-In logs/EntraID/{}-SignInLogs", b.stamp)
        );
        runs.busy_until(b.local + Duration::minutes(5));
        let c = runs.next_after("MessageTrace", None, Duration::hours(1));
        assert_eq!(c.local, b.local + Duration::minutes(5) + Duration::hours(1));
    }
}
