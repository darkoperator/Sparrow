//! IP enrichment (spec §5.3 `ip_intel`, §2 `core::enrich`): one row per distinct IP address
//! sighted in the event tables, carrying whether it is private, a Microsoft 365 service
//! address, its MaxMind City/ASN geolocation, and whether its ASN is a known hosting provider.

use crate::data::DataDirs;
use crate::normalize::net::normalize_ip;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::types::Value as DbValue;
use duckdb::{Connection, appender_params_from_iter};
use ipnet::IpNet;
use maxminddb::{MaxMindDbError, Reader, geoip2};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

/// Whether `ip` is a private/non-routable address (spec §5.3 `ip_intel.is_private`): RFC 1918,
/// loopback, link-local, CGNAT 100.64.0.0/10, unspecified, IPv6 unique-local (fc00::/7) and
/// link-local (fe80::/10). An IPv4-mapped IPv6 address is judged as its IPv4 address.
/// Documentation ranges (203.0.113.0/24, 198.51.100.0/24, 2001:db8::/32) are **not** private.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_private(IpAddr::V4(v4)),
            None => {
                let s = v6.segments();
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (s[0] & 0xfe00) == 0xfc00
                    || (s[0] & 0xffc0) == 0xfe80
            }
        },
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IpIntelReport {
    pub ips: u64,
    pub geolocated: u64,
    pub with_asn: u64,
    pub microsoft: u64,
    pub hosting: u64,
    pub private: u64,
    pub source_db_version: Option<String>,
    pub warnings: Vec<String>,
}

const DISTINCT_IPS_SQL: &str = "
    SELECT DISTINCT ip FROM (
        SELECT client_ip AS ip FROM ual_events
        UNION ALL SELECT ip FROM signins
        UNION ALL SELECT initiated_by_ip AS ip FROM directory_audits
        UNION ALL SELECT from_ip AS ip FROM message_trace
        UNION ALL SELECT to_ip AS ip FROM message_trace
        UNION ALL SELECT client_ip AS ip FROM mailbox_audit_legacy
        UNION ALL SELECT client_ip AS ip FROM admin_audit_events
        UNION ALL SELECT ip FROM risk_detections
        UNION ALL SELECT client_ip AS ip FROM mail_items_accessed
    ) t
    WHERE ip IS NOT NULL AND trim(ip) <> ''
";

fn distinct_ip_texts(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(DISTINCT_IPS_SQL)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Geo/ASN columns already stored, by `ip` text; carried over when the current run has no
/// reader for that part (no `--geoip-dir`, or the directory is missing a City or ASN database).
#[derive(Debug, Clone, Default)]
struct Carry {
    country_iso: Option<String>,
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    asn: Option<i32>,
    asn_org: Option<String>,
}

fn load_carryover(conn: &Connection) -> Result<HashMap<String, Carry>> {
    let mut stmt = conn.prepare(
        "SELECT ip, country_iso, country, city, latitude, longitude, asn, asn_org FROM ip_intel",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            Carry {
                country_iso: r.get(1)?,
                country: r.get(2)?,
                city: r.get(3)?,
                latitude: r.get(4)?,
                longitude: r.get(5)?,
                asn: r.get(6)?,
                asn_org: r.get(7)?,
            },
        ))
    })?;
    let mut map = HashMap::new();
    for row in rows {
        let (ip, carry) = row?;
        map.insert(ip, carry);
    }
    Ok(map)
}

type MmdbReader = Reader<Vec<u8>>;
type OpenReaders = (Option<MmdbReader>, Option<MmdbReader>, Vec<String>);

/// Every `*.mmdb` file in `dir`, classified by `metadata().database_type` containing "City" or
/// "ASN" (the first match of each kind wins). The directory not existing is an error; a file
/// that fails to open is a warning.
fn open_readers(dir: &Path) -> Result<OpenReaders> {
    let mut warnings = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::NotFound(format!("--geoip-dir {}", dir.display()))
        } else {
            Error::io(dir, e)
        }
    })?;
    let mut city = None;
    let mut asn = None;
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(dir, e))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("mmdb") {
            continue;
        }
        let reader = match Reader::open_readfile(&path) {
            Ok(r) => r,
            Err(e) => {
                warnings.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        let is_city = reader.metadata().database_type.contains("City");
        let is_asn = reader.metadata().database_type.contains("ASN");
        if city.is_none() && is_city {
            city = Some(reader);
        } else if asn.is_none() && is_asn {
            asn = Some(reader);
        }
    }
    if city.is_none() {
        warnings.push(
            "--geoip-dir has no MaxMind City database (metadata.database_type must contain \"City\")"
                .to_string(),
        );
    }
    if asn.is_none() {
        warnings.push(
            "--geoip-dir has no MaxMind ASN database (metadata.database_type must contain \"ASN\")"
                .to_string(),
        );
    }
    Ok((city, asn, warnings))
}

struct CityFields {
    country_iso: Option<String>,
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

fn lookup_city(
    reader: &Reader<Vec<u8>>,
    addr: IpAddr,
) -> std::result::Result<Option<CityFields>, MaxMindDbError> {
    let rec: Option<geoip2::City> = reader.lookup(addr)?.decode()?;
    Ok(rec.map(|c| CityFields {
        country_iso: c.country.iso_code.map(str::to_string),
        country: c.country.names.english.map(str::to_string),
        city: c.city.names.english.map(str::to_string),
        latitude: c.location.latitude,
        longitude: c.location.longitude,
    }))
}

fn lookup_asn(
    reader: &Reader<Vec<u8>>,
    addr: IpAddr,
) -> std::result::Result<Option<(i32, Option<String>)>, MaxMindDbError> {
    let rec: Option<geoip2::Asn> = reader.lookup(addr)?.decode()?;
    Ok(rec.and_then(|a| {
        a.autonomous_system_number.map(|n| {
            (
                n as i32,
                a.autonomous_system_organization.map(str::to_string),
            )
        })
    }))
}

fn build_date(epoch: u64) -> Result<String> {
    DateTime::<Utc>::from_timestamp(epoch as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .ok_or_else(|| Error::Invalid(format!("build_epoch {epoch} out of range")))
}

fn opt_text(v: Option<String>) -> DbValue {
    v.map_or(DbValue::Null, DbValue::Text)
}
fn opt_double(v: Option<f64>) -> DbValue {
    v.map_or(DbValue::Null, DbValue::Double)
}
fn opt_int(v: Option<i32>) -> DbValue {
    v.map_or(DbValue::Null, DbValue::Int)
}
fn opt_bool(v: Option<bool>) -> DbValue {
    v.map_or(DbValue::Null, DbValue::Boolean)
}

struct IpRow {
    ip: String,
    country_iso: Option<String>,
    country: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    asn: Option<i32>,
    asn_org: Option<String>,
    is_hosting: Option<bool>,
    hosting_provider: Option<String>,
    is_microsoft: bool,
    microsoft_service_area: Option<String>,
    is_private: bool,
}

/// Re-derive `ip_intel` from every distinct IP address in the event tables.
pub fn refresh_ip_intel(
    conn: &Connection,
    dirs: &DataDirs,
    geoip_dir: Option<&Path>,
) -> Result<IpIntelReport> {
    let mut warnings = Vec::new();

    let ms = crate::data::ms365_ranges(dirs)?;
    let mut ms_ranges: Vec<(IpNet, String)> = Vec::with_capacity(ms.ranges.len());
    for r in &ms.ranges {
        let net: IpNet = r
            .cidr
            .parse()
            .map_err(|e| Error::Invalid(format!("ms365_ip_ranges.json: {:?}: {e}", r.cidr)))?;
        ms_ranges.push((net, r.service_area.clone()));
    }

    let hosting_map: HashMap<u32, String> = crate::data::hosting_asns(dirs)?
        .into_iter()
        .map(|a| (a.asn, a.name))
        .collect();

    let carryover = load_carryover(conn)?;

    let (city_reader, asn_reader) = match geoip_dir {
        Some(dir) => {
            let (city, asn, mut reader_warnings) = open_readers(dir)?;
            warnings.append(&mut reader_warnings);
            (city, asn)
        }
        None => {
            warnings.push(
                "no --geoip-dir: ip_intel has no geolocation or ASN (MaxMind GeoLite2 City and ASN .mmdb files)"
                    .to_string(),
            );
            (None, None)
        }
    };

    let ip_texts = distinct_ip_texts(conn)?;
    let mut rows = Vec::with_capacity(ip_texts.len());
    let mut skipped_non_ip = 0u64;

    for raw in ip_texts {
        let addr = match normalize_ip(&raw).and_then(|s| s.parse::<IpAddr>().ok()) {
            Some(a) => a,
            None => {
                skipped_non_ip += 1;
                continue;
            }
        };

        let is_priv = is_private(addr);
        let (is_microsoft, microsoft_service_area) =
            match ms_ranges.iter().find(|(net, _)| net.contains(&addr)) {
                Some((_, area)) => (true, Some(area.clone())),
                None => (false, None),
            };

        let (mut country_iso, mut country, mut city, mut latitude, mut longitude) =
            (None, None, None, None, None);
        if let Some(reader) = &city_reader {
            match lookup_city(reader, addr) {
                Ok(Some(rec)) => {
                    country_iso = rec.country_iso;
                    country = rec.country;
                    city = rec.city;
                    latitude = rec.latitude;
                    longitude = rec.longitude;
                }
                Ok(None) => {}
                Err(e) => warnings.push(format!("City lookup for {addr}: {e}")),
            }
        } else if let Some(c) = carryover.get(&raw) {
            country_iso = c.country_iso.clone();
            country = c.country.clone();
            city = c.city.clone();
            latitude = c.latitude;
            longitude = c.longitude;
        }

        let (mut asn, mut asn_org) = (None, None);
        if let Some(reader) = &asn_reader {
            match lookup_asn(reader, addr) {
                Ok(Some((n, org))) => {
                    asn = Some(n);
                    asn_org = org;
                }
                Ok(None) => {}
                Err(e) => warnings.push(format!("ASN lookup for {addr}: {e}")),
            }
        } else if let Some(c) = carryover.get(&raw) {
            asn = c.asn;
            asn_org = c.asn_org.clone();
        }

        let (is_hosting, hosting_provider) = match asn {
            Some(n) => match hosting_map.get(&(n as u32)) {
                Some(name) => (Some(true), Some(name.clone())),
                None => (Some(false), None),
            },
            None => (None, None),
        };

        rows.push(IpRow {
            ip: raw,
            country_iso,
            country,
            city,
            latitude,
            longitude,
            asn,
            asn_org,
            is_hosting,
            hosting_provider,
            is_microsoft,
            microsoft_service_area,
            is_private: is_priv,
        });
    }

    if skipped_non_ip > 0 {
        warnings.push(format!(
            "{skipped_non_ip} value(s) in IP columns are not IP addresses (skipped)"
        ));
    }

    let ips = rows.len() as u64;
    let geolocated = rows.iter().filter(|r| r.country_iso.is_some()).count() as u64;
    let with_asn = rows.iter().filter(|r| r.asn.is_some()).count() as u64;
    let microsoft = rows.iter().filter(|r| r.is_microsoft).count() as u64;
    let hosting = rows.iter().filter(|r| r.is_hosting == Some(true)).count() as u64;
    let private = rows.iter().filter(|r| r.is_private).count() as u64;

    let mut version_parts = Vec::new();
    if let Some(reader) = &city_reader {
        version_parts.push(format!(
            "GeoLite2-City {}",
            build_date(reader.metadata().build_epoch)?
        ));
    }
    if let Some(reader) = &asn_reader {
        version_parts.push(format!(
            "GeoLite2-ASN {}",
            build_date(reader.metadata().build_epoch)?
        ));
    }
    version_parts.push(format!("ms365-endpoints {}", ms.version));
    let source_db_version = Some(version_parts.join("; "));

    conn.execute("DELETE FROM ip_intel", [])?;
    {
        let mut app = conn.appender("ip_intel")?;
        for r in rows {
            app.append_row(appender_params_from_iter([
                DbValue::Text(r.ip),
                opt_text(r.country_iso),
                opt_text(r.country),
                opt_text(r.city),
                opt_double(r.latitude),
                opt_double(r.longitude),
                opt_int(r.asn),
                opt_text(r.asn_org),
                opt_bool(r.is_hosting),
                opt_text(r.hosting_provider),
                DbValue::Boolean(r.is_microsoft),
                opt_text(r.microsoft_service_area),
                DbValue::Boolean(r.is_private),
                opt_text(source_db_version.clone()),
            ]))?;
        }
        app.flush()?;
    }

    Ok(IpIntelReport {
        ips,
        geolocated,
        with_asn,
        microsoft,
        hosting,
        private,
        source_db_version,
        warnings,
    })
}
