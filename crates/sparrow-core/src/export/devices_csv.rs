//! The device-containment CSVs: `devices.csv` (one row per suspect device, with its lifecycle and the file and line
//! of each date) and `device-sightings.csv` (one row per sighting, with the source file, lines and file hash).
//! UTF-8 with a BOM like the timeline CSV; times are UTC `yyyy-MM-dd HH:mm:ss`; every text cell goes through
//! [`neutralise`] (display names and users can be attacker-controlled).

use super::timeline_csv::neutralise;
use super::when;
use crate::Result;
use crate::case::devices::DeviceStatus;
use crate::case::devices::{
    LOOKUP_CHUNK, LifecycleMark, OtherIp, SuspectDevice, SuspectReason, ip_intel, suspect_devices,
};
use duckdb::Connection;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;

pub const DEVICE_COLUMNS: [&str; 28] = [
    "status",
    "confidence",
    "tenant_key",
    "device_id",
    "object_id",
    "display_name",
    "os",
    "trust_type",
    "is_compliant",
    "is_managed",
    "registered_utc",
    "registered_source",
    "removed_utc",
    "removed_source",
    "disabled_utc",
    "disabled_source",
    "last_active_utc",
    "last_active_source",
    "users",
    "malicious_ips",
    "other_ips",
    "reasons",
    "note",
    "analyst_status",
    "analyst_note",
    "analyst_by",
    "analyst_decided_utc",
    "analyst_warning",
];

pub const SIGHTING_COLUMNS: [&str; 15] = [
    "device_id",
    "display_name",
    "event_time_utc",
    "user_upn",
    "ip",
    "ip_malicious",
    "ip_asn_org",
    "ip_country",
    "activity",
    "source_table",
    "record_key",
    "source_file",
    "line_start",
    "line_end",
    "source_file_sha256",
];

/// What to do about a device in this status, or empty.
pub fn note(status: DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Unknown | DeviceStatus::NotInLatestInventory => {
            "treat as active — collect Get-Devices to confirm"
        }
        DeviceStatus::ActiveAfterRemoval => "seen after removal — containment did not hold",
        _ => "",
    }
}

/// The analyst's warning on a device they said was removed or disabled and that was active later.
pub const ANALYST_WARNING: &str = "active after the analyst's removal — containment did not hold";

/// The analyst's status of `d` as the last five columns: status, note, by, decided (UTC), warning; empty when none.
pub fn analyst_cells(d: &SuspectDevice) -> [String; 5] {
    match &d.analyst {
        None => Default::default(),
        Some(a) => [
            a.status.as_str().into(),
            a.note.clone().unwrap_or_default(),
            a.decided_by.clone(),
            when(&a.decided_at),
            if d.active_after_analyst_removal {
                ANALYST_WARNING.into()
            } else {
                String::new()
            },
        ],
    }
}

/// `ip (asn_org, CC[, hosting])`.
pub fn other_ip_text(o: &OtherIp) -> String {
    let mut parts = Vec::new();
    if let Some(org) = &o.asn_org {
        parts.push(org.clone());
    }
    if let Some(cc) = &o.country_iso {
        parts.push(cc.clone());
    }
    if o.is_hosting == Some(true) {
        parts.push("hosting".into());
    }
    if parts.is_empty() {
        o.ip.clone()
    } else {
        format!("{} ({})", o.ip, parts.join(", "))
    }
}

pub fn reason_text(r: &SuspectReason) -> String {
    match r {
        SuspectReason::Indicator { ip, verdict } => format!("indicator {ip} ({verdict})"),
        SuspectReason::Finding {
            ip,
            finding_id,
            rule_id,
        } => format!("finding {finding_id} ({rule_id}) on {ip}"),
        SuspectReason::TravelLeg { ip, finding_id } => {
            format!("impossible-travel leg {ip} (finding {finding_id})")
        }
        SuspectReason::SameName { name, of_device_id } => {
            format!("same name \"{name}\" as device {of_device_id}")
        }
    }
}

/// `(table, record key)`.
pub(crate) type Key = (String, String);

/// The first source of each record: `(folder/file, line_start, line_end, file sha256)`, chosen like
/// `record_source_refs` (lowest file id, then record ordinal). Batched: one bound query per [`LOOKUP_CHUNK`] keys,
/// no case data in the SQL text. A key without provenance is absent.
pub(crate) fn first_sources(
    conn: &Connection,
    keys: &BTreeSet<Key>,
) -> Result<HashMap<Key, Source>> {
    let keys: Vec<&Key> = keys.iter().collect();
    let mut out = HashMap::new();
    for chunk in keys.chunks(LOOKUP_CHUNK) {
        let pairs = vec!["(?, ?)"; chunk.len()].join(", ");
        let mut stmt = conn.prepare(&format!(
            "SELECT table_name, record_key, file, line_start, line_end, sha FROM ( \
               SELECT rs.table_name, rs.record_key, \
                      regexp_extract(c.root_path, '[^/\\\\]+$') || '/' || sf.rel_path AS file, \
                      rs.line_start, rs.line_end, sf.sha256 AS sha, \
                      row_number() OVER (PARTITION BY rs.table_name, rs.record_key \
                                         ORDER BY sf.file_id, rs.record_ordinal) AS rn \
               FROM record_sources rs JOIN source_files sf ON sf.file_id = rs.file_id \
               JOIN collections c ON c.collection_id = sf.collection_id \
               WHERE (rs.table_name, rs.record_key) IN ({pairs})) WHERE rn = 1"
        ))?;
        let args: Vec<&dyn duckdb::ToSql> = chunk
            .iter()
            .flat_map(|(t, k)| [t as &dyn duckdb::ToSql, k as &dyn duckdb::ToSql])
            .collect();
        let rows = stmt.query_map(args.as_slice(), |r| {
            Ok((
                (r.get::<_, String>(0)?, r.get::<_, String>(1)?),
                (r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?),
            ))
        })?;
        for row in rows {
            let (k, v) = row?;
            out.insert(k, v);
        }
    }
    Ok(out)
}

/// `<collection folder>/<file>:<line>[-<end>]`, the form of `record_source_refs`.
pub(crate) fn ref_text(s: &Source) -> String {
    if s.2 == s.1 {
        format!("{}:{}", s.0, s.1)
    } else {
        format!("{}:{}-{}", s.0, s.1, s.2)
    }
}

/// The records behind every lifecycle date of `devices`.
pub(crate) fn mark_keys(devices: &[SuspectDevice]) -> BTreeSet<Key> {
    let mut keys = BTreeSet::new();
    for d in devices {
        let lc = &d.lifecycle;
        for m in [&lc.registered, &lc.removed, &lc.disabled, &lc.last_active]
            .into_iter()
            .flatten()
        {
            keys.insert((m.source_table.clone(), m.record_key.clone()));
        }
    }
    keys
}

/// The first source reference of a lifecycle mark, or empty.
pub(crate) fn mark_source(sources: &HashMap<Key, Source>, m: &Option<LifecycleMark>) -> String {
    m.as_ref()
        .and_then(|m| sources.get(&(m.source_table.clone(), m.record_key.clone())))
        .map(ref_text)
        .unwrap_or_default()
}

fn mark_time(m: &Option<LifecycleMark>) -> String {
    m.as_ref().map(|m| when(&m.at)).unwrap_or_default()
}

fn opt_bool(b: Option<bool>) -> String {
    b.map(|b| b.to_string()).unwrap_or_default()
}

fn csv_err(e: csv::Error) -> crate::Error {
    crate::Error::Invalid(format!("csv: {e}"))
}

fn writer<'a>(out: &'a mut dyn Write, columns: &[&str]) -> Result<csv::Writer<&'a mut dyn Write>> {
    out.write_all("\u{feff}".as_bytes())
        .map_err(super::io_err)?;
    let mut w = csv::Writer::from_writer(out);
    w.write_record(columns).map_err(csv_err)?;
    Ok(w)
}

fn put<W: Write>(w: &mut csv::Writer<W>, cells: Vec<String>) -> Result<()> {
    let cells: Vec<String> = cells.iter().map(|c| neutralise(c)).collect();
    w.write_record(&cells).map_err(csv_err)
}

/// `devices.csv`; returns the rows written.
pub fn write_devices(conn: &Connection, out: &mut dyn Write) -> Result<u64> {
    let devices = suspect_devices(conn, None)?;
    let sources = first_sources(conn, &mark_keys(&devices))?;
    let mut w = writer(out, &DEVICE_COLUMNS)?;
    for d in &devices {
        let lc = &d.lifecycle;
        put(
            &mut w,
            vec![
                lc.status.as_str().into(),
                d.confidence.as_str().into(),
                d.tenant_key.clone().unwrap_or_default(),
                d.device_id.clone(),
                d.object_id.clone().unwrap_or_default(),
                d.display_name.clone().unwrap_or_default(),
                d.os.clone().unwrap_or_default(),
                d.trust_type.clone().unwrap_or_default(),
                opt_bool(d.is_compliant),
                opt_bool(d.is_managed),
                mark_time(&lc.registered),
                mark_source(&sources, &lc.registered),
                mark_time(&lc.removed),
                mark_source(&sources, &lc.removed),
                mark_time(&lc.disabled),
                mark_source(&sources, &lc.disabled),
                mark_time(&lc.last_active),
                mark_source(&sources, &lc.last_active),
                d.users.join("; "),
                d.malicious_ips.join("; "),
                d.other_ips
                    .iter()
                    .map(other_ip_text)
                    .collect::<Vec<_>>()
                    .join("; "),
                d.reasons
                    .iter()
                    .map(reason_text)
                    .collect::<Vec<_>>()
                    .join("; "),
                note(lc.status).into(),
            ]
            .into_iter()
            .chain(analyst_cells(d))
            .collect(),
        )?;
    }
    w.flush().map_err(super::io_err)?;
    Ok(devices.len() as u64)
}

/// `(folder/file, line_start, line_end, file sha256)`.
pub(crate) type Source = (String, i64, i64, String);

/// `device-sightings.csv`: every sighting of every suspect device, devices in list order, sightings in time order
/// (untimed last, with an empty time); returns the rows written.
pub fn write_sightings(conn: &Connection, out: &mut dyn Write) -> Result<u64> {
    let devices = suspect_devices(conn, None)?;
    // Two batched, bound lookups for the whole export: first sources of every sighting, ip_intel of every IP.
    let keys: BTreeSet<Key> = devices
        .iter()
        .flat_map(|d| &d.sightings)
        .map(|s| (s.source_table.clone(), s.record_key.clone()))
        .collect();
    let sources = first_sources(conn, &keys)?;
    let ips: BTreeSet<String> = devices
        .iter()
        .flat_map(|d| &d.sightings)
        .filter_map(|s| s.ip.as_deref())
        .map(str::to_lowercase)
        .collect();
    let intel = ip_intel(conn, &ips)?;
    let mut w = writer(out, &SIGHTING_COLUMNS)?;
    let mut n = 0u64;
    for d in &devices {
        for s in &d.sightings {
            let (org, country) =
                s.ip.as_deref()
                    .and_then(|ip| intel.get(&ip.to_lowercase()))
                    .map(|o| {
                        (
                            o.asn_org.clone().unwrap_or_default(),
                            o.country_iso.clone().unwrap_or_default(),
                        )
                    })
                    .unwrap_or_default();
            let malicious =
                s.ip.as_deref()
                    .is_some_and(|ip| d.malicious_ips.iter().any(|m| m.eq_ignore_ascii_case(ip)));
            let (file, start, end, sha) = sources
                .get(&(s.source_table.clone(), s.record_key.clone()))
                .map(|(f, a, b, h)| (f.clone(), a.to_string(), b.to_string(), h.clone()))
                .unwrap_or_default();
            put(
                &mut w,
                vec![
                    d.device_id.clone(),
                    // The name this record carried, not the device's current one.
                    s.display_name.clone().unwrap_or_default(),
                    s.event_time.as_ref().map(when).unwrap_or_default(),
                    s.user_upn.clone().unwrap_or_default(),
                    s.ip.clone().unwrap_or_default(),
                    malicious.to_string(),
                    org,
                    country,
                    s.activity.clone(),
                    s.source_table.clone(),
                    s.record_key.clone(),
                    file,
                    start,
                    end,
                    sha,
                ],
            )?;
            n += 1;
        }
    }
    w.flush().map_err(super::io_err)?;
    Ok(n)
}
