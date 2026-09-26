//! Hawk 4.0 (`Collectors/hawk.4.0.0`; research: 2026-09-26 Hawk layouts, all of it; capture
//! survey §1-§2, §5): the world as an analyst's `Start-HawkTenantInvestigation` followed by
//! `Start-HawkUserInvestigation` for the scenario's `hawk_users`, then the on-demand
//! `Search-HawkTenantActivityByIP` for every attacker address in the logged UAL records and
//! `Get-HawkMessageHeader` for every exported e-mail, all in one output folder
//! `Hawk_<tenant folder name>_<yyyyMMdd_HHmmss>` (UTC collection start).
//!
//! The tenant session runs on `opts.ps`; with `hawk_mixed_editions` the tenant session is
//! PowerShell 7 and the user session (and what it writes to `Tenant/`) Windows PowerShell 5.1
//! (survey capture D). Every file goes through `omft` (Out-MultipleFileType) or, for the
//! collectors that write directly, through the same encodings; `Hawk.log` and
//! `_Investigate.txt` are written last.
//!
//! Hawk 3.1 (`write_v3`, module `v3`) renders the same world with the 3.x files, shapes and
//! log dialects (research §7).

pub mod clixml;
pub mod log;
pub mod omft;
pub mod simple;

mod ondemand;
mod tenant;
mod user;
mod v3;

pub use v3::write_v3;

use crate::Result;
use crate::events::{Day, Ual};
use crate::keys;
use crate::options::{GenerateOptions, PsEdition};
use crate::ps::{DateEvidence, DtKind, Encoding, Host, PsDate, Row, Val, export_csv};
use crate::rng::stream;
use crate::story::Evidence;
use crate::tree::Tree;
use crate::world::{User, World};
use chrono::{DateTime, Duration, Utc};
use log::{Dialect, Log};
use omft::{HawkVersion, Omft, Written};
use serde_json::{Map, Value};
use std::cmp::Reverse;

/// Hawk's module version (`Hawk.psd1`).
pub const HAWK_VERSION: &str = "4.0";

/// `Hawk_<TenantName>_<yyyyMMdd_HHmmss>`: the tenant name with spaces as `_`, the UTC time
/// the investigation started (`collected_at`).
pub fn root(world: &World) -> String {
    format!(
        "Hawk_{}_{}",
        world.tenant.folder_name,
        world.collected_at().format("%Y%m%d_%H%M%S")
    )
}

/// The users the analyst investigates: the scenario's `hawk_users`, else every storyline and
/// look-alike actor and target, else user 1.
pub fn hawk_users(world: &World) -> Vec<&User> {
    let numbers: Vec<u32> = if !world.scenario.tenant.hawk_users.is_empty() {
        world.scenario.tenant.hawk_users.clone()
    } else if !world.victims.is_empty() {
        world.victims.iter().copied().collect()
    } else {
        vec![1]
    };
    let mut out: Vec<&User> = Vec::new();
    for n in numbers {
        let u = world.user(n);
        if !out.iter().any(|o| o.upn == u.upn) {
            out.push(u);
        }
    }
    out
}

/// A property.
pub(crate) fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

pub(crate) fn s(v: impl Into<String>) -> Val {
    Val::Str(v.into())
}

pub(crate) fn opt(v: Option<impl Into<String>>) -> Val {
    v.map_or(Val::Null, |x| Val::Str(x.into()))
}

/// A typed .NET `DateTime` of `kind` that Sparrow reads as a time.
pub(crate) fn date(t: DateTime<Utc>, kind: DtKind) -> Val {
    Val::Date(PsDate::dotnet(t, kind))
}

/// A typed .NET `DateTime` Sparrow does not read as a time.
pub(crate) fn date_text(t: DateTime<Utc>, kind: DtKind) -> Val {
    Val::DateText(PsDate::dotnet(t, kind))
}

/// A Graph SDK model object: its .NET type name in CSV, its properties in JSON.
pub(crate) fn model(name: &str, v: Value) -> Val {
    Val::Model(format!("Microsoft.Graph.PowerShell.Models.{name}"), v)
}

/// A Graph SDK `AdditionalProperties` dictionary (empty).
pub(crate) fn additional_properties() -> Val {
    Val::Model(
        "System.Collections.Generic.Dictionary`2[System.String,System.Object]".into(),
        Value::Object(Map::new()),
    )
}

/// A value from the raw record's AuditData as `ConvertFrom-Json` hands it over.
pub(crate) fn json_val(v: &Value) -> Val {
    match v {
        Value::Array(_) | Value::Object(_) => Val::Raw(v.clone()),
        other => simple::json_scalar(other),
    }
}

/// Text of property `key` of `row` (case-insensitive), as PowerShell prints it.
pub(crate) fn text_of(row: &Row, key: &str) -> Option<String> {
    let (_, v) = row.iter().find(|(k, _)| k.eq_ignore_ascii_case(key))?;
    match v {
        Val::Null => None,
        Val::Str(s) => Some(s.clone()),
        Val::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
        Val::Int(i) => Some(i.to_string()),
        Val::Float(f) => Some(f.to_string()),
        Val::Placeholder(s) => Some(s.clone()),
        Val::Model(n, _) => Some(n.clone()),
        Val::Raw(v) => Some(v.to_string()),
        Val::Date(d) | Val::DateText(d) => Some(d.utc.to_rfc3339()),
    }
}

/// What every step of one Hawk run shares.
pub(crate) struct Ctx<'w> {
    pub world: &'w World,
    pub opts: &'w GenerateOptions,
    pub omft: Omft,
    /// The tenant investigation's session.
    pub tenant_host: Host,
    /// The user investigation's session (5.1 with `hawk_mixed_editions`).
    pub user_host: Host,
    /// The window's events per UTC day.
    pub days: Vec<Day>,
    /// Every logged UAL record of the window, oldest first.
    pub ual: Vec<Ual>,
    /// The investigated users, in the order the analyst named them.
    pub users: Vec<&'w User>,
}

impl<'w> Ctx<'w> {
    /// The run of Hawk `version`. `hawk_mixed_editions` applies to Hawk 4 only.
    fn new(world: &'w World, opts: &'w GenerateOptions, version: HawkVersion) -> Ctx<'w> {
        let offset = world.scenario.tenant.host_utc_offset_minutes;
        let host = |edition: PsEdition| {
            let h = Host::new(edition, opts.culture, offset);
            if opts.non_windows { h.unix() } else { h }
        };
        let (tenant_edition, user_edition) =
            if opts.hawk_mixed_editions && version == HawkVersion::V4 {
                (PsEdition::Ps7, PsEdition::Ps51)
            } else {
                (opts.ps, opts.ps)
            };
        let tenant_host = host(tenant_edition);
        let file_path = if opts.non_windows {
            format!("/Users/Shared/Investigations/{}", root(world))
        } else {
            format!("C:\\Investigations\\{}", root(world))
        };
        let dialect = match version {
            HawkVersion::V4 => Dialect::V4,
            HawkVersion::V3 => Dialect::V3(tenant_host),
        };
        let log = Log::with_dialect(
            world.collected_at(),
            stream(world.seed, "hawk/log"),
            dialect,
        );
        let days = crate::writers::window_days(world);
        let mut ual: Vec<Ual> = days.iter().flat_map(|d| d.ual.clone()).collect();
        ual.sort_by_key(|u| (u.time, u.id));
        Ctx {
            world,
            opts,
            omft: Omft::new(version, tenant_host, log, file_path, opts.non_windows),
            tenant_host,
            user_host: host(user_edition),
            days,
            ual,
            users: hawk_users(world),
        }
    }

    pub fn log(&mut self) -> &mut Log {
        &mut self.omft.log
    }

    /// The collecting host's local wall clock now.
    pub fn local_now(&self) -> DateTime<Utc> {
        self.omft.log.now()
            + Duration::minutes(self.world.scenario.tenant.host_utc_offset_minutes.into())
    }

    /// `Get-AllUnifiedAuditLogEntry -UnifiedSearch <command>`: the window's logged records
    /// `keep` selects, in ResultIndex order (newest first), with the search's log lines.
    pub fn search(&mut self, command: &str, keep: impl Fn(&Ual) -> bool) -> Vec<Ual> {
        let (start, end) = (self.world.window_start(), self.world.window_end());
        let session = self.local_now().format("%H%M%S").to_string();
        let log = self.log();
        log.action("Running Unified Audit Log Search");
        log.plain(format!(
            "{command} -StartDate '{}' -EndDate '{}' -SessionCommand ReturnLargeSet -resultsize 5000 -sessionid {session}",
            start.format("%m/%d/%Y"),
            end.format("%m/%d/%Y"),
        ));
        let mut found: Vec<Ual> = self.ual.iter().filter(|u| keep(u)).cloned().collect();
        found.sort_by_key(|u| Reverse((u.time, u.id)));
        let log = self.log();
        log.tick(1, 6);
        if found.is_empty() {
            log.info("Unified Audit log returned no results.");
            return found;
        }
        let n = found.len();
        let mut index = 0;
        while index < n {
            index = (index + 5000).min(n);
            if index == n {
                log.info("Retrieved all results.");
            }
            log.info(format!("Retrieved:{index:<5} Total: {n}"));
            log.tick(1, 4);
        }
        found
    }
}

/// Whether `a` equals one of `list`, ignoring case (PowerShell `-eq` / `-in`).
pub(crate) fn one_of(a: &str, list: &[&str]) -> bool {
    list.iter().any(|b| a.eq_ignore_ascii_case(b))
}

/// A `Search-UnifiedAuditLog` result object (current EXO module), `AuditData` the embedded
/// JSON text in CSV and JSON alike.
pub(crate) fn raw_row(u: &Ual, index: usize, count: usize, nl: &str) -> Row {
    vec![
        r("RecordType", s(u.record_type.name())),
        r("CreationDate", date_text(u.time, DtKind::Unspecified)),
        r("UserIds", s(u.user_id.clone())),
        r("Operations", s(u.operation.clone())),
        r("AuditData", s(u.audit_data_text())),
        r("ResultIndex", Val::Int(index as i64 + 1)),
        r("ResultCount", Val::Int(count as i64)),
        r(
            "AuditSearchRequestMetadata",
            s(format!("{{{nl}  \"moreRecordsAvailable\": false{nl}}}")),
        ),
        r("Identity", s(u.id.to_string())),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ]
}

/// The raw rows of a search result (ResultIndex order).
pub(crate) fn raw_rows(records: &[Ual], nl: &str) -> Vec<Row> {
    let n = records.len();
    records
        .iter()
        .enumerate()
        .map(|(i, u)| raw_row(u, i, n, nl))
        .collect()
}

/// `Select-Object -ExpandProperty AuditData | ConvertFrom-Json`: AuditData's properties at
/// top level (`CreationTime` a date Sparrow reads).
pub(crate) fn expanded_row(u: &Ual) -> Row {
    u.audit
        .iter()
        .map(|(k, v)| {
            let val = if k == "CreationTime" {
                match simple::json_scalar(v) {
                    Val::DateText(d) => Val::Date(d),
                    other => other,
                }
            } else {
                json_val(v)
            };
            (k.clone(), val)
        })
        .collect()
}

/// `Get-SimpleUnifiedAuditLog` of a search result; `label` seeds the file's property order.
pub(crate) fn simple_rows(world: &World, raw: &[Row], records: &[Ual], label: &str) -> Vec<Row> {
    let seed = stream(world.seed, &format!("hawk/simple/{label}")).next_u64();
    raw.iter()
        .zip(records)
        .map(|(row, u)| simple::flatten(row, &u.audit, seed))
        .collect()
}

/// Every written part loads one `table` row per object, keyed `key(i)`, delivering
/// `evidence(i)`.
pub(crate) fn register(
    tree: &mut Tree<'_>,
    w: &Written,
    table: &'static str,
    key: impl Fn(usize) -> Option<String>,
    evidence: impl Fn(usize) -> Option<Evidence>,
) {
    for part in w.parts() {
        for (i, span) in part.spans.iter().enumerate() {
            if let Some(k) = key(i) {
                tree.row(&part.rel, table, k);
            }
            if let Some(e) = evidence(i) {
                tree.deliver(&e, table, &part.rel, *span);
            }
        }
    }
}

/// Every written part loads the UAL records `records` (same order as the rows).
pub(crate) fn register_ual(tree: &mut Tree<'_>, w: &Written, records: &[Ual]) {
    register(
        tree,
        w,
        "ual_events",
        |i| Some(keys::ual(records[i].id)),
        |i| Some(Evidence::Ual(records[i].id)),
    );
}

/// An `_Investigate_*` file: each object is one `collector_flags` row. The count is exact:
/// every flagged object is a different record (a rule, a device, a grant, a UAL record...), and
/// no two investigate files share a flag kind and a record, so no flag rows merge; a
/// byte-identical copy is `duplicate_file` and counts nothing (the tree's replay).
pub(crate) fn register_flags(tree: &mut Tree<'_>, w: &Written) {
    for part in w.parts() {
        tree.rows_counted(&part.rel, "collector_flags", part.spans.len() as u64);
    }
}

/// Writes the Hawk 4.0 output folder of `world` into `tree`.
pub fn write_v4(world: &World, opts: &GenerateOptions, tree: &mut Tree<'_>) -> Result<()> {
    let mut c = Ctx::new(world, opts, HawkVersion::V4);
    tenant::investigate(&mut c, tree)?;
    user::investigate(&mut c, tree)?;
    ondemand::run(&mut c, tree)?;
    let enc = Encoding::out_file_default(c.tenant_host.edition);
    let nl = c.tenant_host.newline;
    c.omft.log.write(tree, enc, nl)?;
    // The licence line of the interactive header.
    let (tier, _) = tenant::licence_tier(world);
    tree.row("Hawk.log", "licenses", keys::licence_tier(tier));
    // The only culture date Sparrow reads from the log: the summary's first `End Date`.
    let mut ev = DateEvidence::default();
    export_csv(
        &c.tenant_host,
        &[vec![r(
            "End Date",
            date(world.window_end(), DtKind::Unspecified),
        )]],
        &mut ev,
    );
    if ev.culture_dates > 0 {
        tree.date_evidence("Hawk.log", ev);
    }
    Ok(())
}
