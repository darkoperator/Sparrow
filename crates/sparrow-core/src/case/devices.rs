//! Device containment: the devices tied to the case's malicious IPs. Everything here is computed from the case
//! tables on each call — nothing is stored — so indicator verdicts, finding statuses and new ingests are always
//! reflected. UAL device fields are read from `ual_events.audit_data` at read time, so cases ingested before this
//! module existed need no re-ingest.

use crate::Result;
use crate::case::audit;
use crate::detect::enrich::at_us;
use chrono::{DateTime, Utc};
use duckdb::Connection;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Findings of these rules put the IPs of their evidence rows in the malicious set.
pub const ATTACKER_IP_RULES: &[&str] = &["SPW-ID-002", "SPW-ID-004", "SPW-ID-007"];
/// Impossible travel: both legs count, but only as weak evidence (`TravelLeg`).
pub const TRAVEL_RULE: &str = "SPW-ID-003";

const ZERO_GUID: &str = "00000000-0000-0000-0000-000000000000";

fn ts<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&audit::ts_text(t))
}

/// Why an IP is malicious, or why a device is suspect.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuspectReason {
    Indicator {
        ip: String,
        verdict: String,
    },
    Finding {
        ip: String,
        finding_id: String,
        rule_id: String,
    },
    TravelLeg {
        ip: String,
        finding_id: String,
    },
    SameName {
        name: String,
        of_device_id: String,
    },
}

fn sql_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Reasons an IP is malicious, keyed by `(tenant_key, lower-cased ip)`. A tenantless indicator has tenant `None`
/// and applies to every tenant (the readers look it up explicitly).
type TenantIp = (Option<String>, String);

fn malicious_by_tenant(
    conn: &Connection,
    tenant: Option<&str>,
) -> Result<BTreeMap<TenantIp, Vec<SuspectReason>>> {
    let mut map: BTreeMap<TenantIp, Vec<SuspectReason>> = BTreeMap::new();
    let mut st = conn.prepare(
        "SELECT tenant_key, value, CAST(verdict AS VARCHAR) FROM case_indicators \
         WHERE type = 'ip' AND removed_at IS NULL AND verdict IN ('malicious', 'suspicious') \
           AND (CAST(? AS VARCHAR) IS NULL OR tenant_key IS NULL OR tenant_key = ?)",
    )?;
    let rows = st.query_map(duckdb::params![tenant, tenant], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (t, ip, verdict) = row?;
        map.entry((t, ip.to_lowercase()))
            .or_default()
            .push(SuspectReason::Indicator { ip, verdict });
    }
    let rules = sql_list(
        &ATTACKER_IP_RULES
            .iter()
            .copied()
            .chain([TRAVEL_RULE])
            .collect::<Vec<_>>(),
    );
    let mut st = conn.prepare(&format!(
        "SELECT DISTINCT f.tenant_key, x.ip, f.finding_id, f.rule_id FROM findings f \
         JOIN (SELECT e.finding_id, s.ip AS ip, c.tenant_key FROM finding_evidence e \
                 JOIN signins s ON e.source_table = 'signins' AND s.record_key = e.record_key \
                 JOIN collections c ON c.collection_id = s.collection_id \
               UNION ALL \
               SELECT e.finding_id, u.client_ip, c.tenant_key FROM finding_evidence e \
                 JOIN ual_events u ON e.source_table = 'ual_events' AND CAST(u.record_id AS VARCHAR) = e.record_key \
                 JOIN collections c ON c.collection_id = u.collection_id) x \
           ON x.finding_id = f.finding_id AND x.tenant_key IS NOT DISTINCT FROM f.tenant_key \
         WHERE f.rule_id IN ({rules}) AND f.status <> 'false_positive' \
           AND x.ip IS NOT NULL AND x.ip <> '' \
           AND (CAST(? AS VARCHAR) IS NULL OR f.tenant_key = ?) \
         ORDER BY f.finding_id, x.ip"
    ))?;
    let rows = st.query_map(duckdb::params![tenant, tenant], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (t, ip, finding_id, rule_id) = row?;
        let key = (Some(t), ip.to_lowercase());
        let reason = if rule_id == TRAVEL_RULE {
            SuspectReason::TravelLeg { ip, finding_id }
        } else {
            SuspectReason::Finding {
                ip,
                finding_id,
                rule_id,
            }
        };
        map.entry(key).or_default().push(reason);
    }
    for reasons in map.values_mut() {
        reasons.sort();
        reasons.dedup();
    }
    Ok(map)
}

/// Malicious IP → why, across tenants (a view for readers that do not need the tenant; devices use the
/// tenant-keyed set). Keys are IPs lower-cased; a reason carries the IP as stored. The set is the active
/// `malicious`/`suspicious` IP indicators plus the evidence IPs (`signins.ip`, `ual_events.client_ip`) of findings
/// of [`ATTACKER_IP_RULES`] (`Finding`) and [`TRAVEL_RULE`] (`TravelLeg`) whose status is not `false_positive`.
/// With a tenant, only that tenant's findings and indicators (an indicator without a tenant applies to all).
pub fn malicious_ips(
    conn: &Connection,
    tenant: Option<&str>,
) -> Result<BTreeMap<String, Vec<SuspectReason>>> {
    let mut map: BTreeMap<String, Vec<SuspectReason>> = BTreeMap::new();
    for ((_, ip), reasons) in malicious_by_tenant(conn, tenant)? {
        map.entry(ip).or_default().extend(reasons);
    }
    for reasons in map.values_mut() {
        reasons.sort();
        reasons.dedup();
    }
    Ok(map)
}

/// One time a device was seen: a sign-in or a UAL record carrying `DeviceProperties`.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceSighting {
    pub tenant_key: Option<String>,
    /// Lower-cased.
    pub device_id: String,
    pub display_name: Option<String>,
    pub os: Option<String>,
    pub trust_type: Option<String>,
    pub user_upn: Option<String>,
    pub ip: Option<String>,
    /// `None` for a stored row without a time: it still ties the device to its IP and user, but never sets
    /// `last_active`.
    #[serde(serialize_with = "ts_opt")]
    pub event_time: Option<DateTime<Utc>>,
    /// The sign-in app (resource), or the UAL operation.
    pub activity: String,
    /// `signins` or `ual_events`.
    pub source_table: String,
    pub record_key: String,
}

/// A device id worth keeping: lower-cased, not empty, not the all-zero GUID.
fn clean_device_id(id: &str) -> Option<String> {
    let id = id.trim().to_lowercase();
    (!id.is_empty() && id != ZERO_GUID).then_some(id)
}

fn non_empty(s: Option<String>) -> Option<String> {
    s.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// The value of the `Name`d entry of a `DeviceProperties` Name/Value array, as text. Entries that are not
/// objects, and values that are not scalars, are skipped.
fn property(props: &[Value], name: &str) -> Option<String> {
    props.iter().find_map(|p| {
        let o = p.as_object()?;
        let n = o.iter().find(|(k, _)| k.eq_ignore_ascii_case("name"))?.1;
        if !n.as_str()?.eq_ignore_ascii_case(name) {
            return None;
        }
        match o.iter().find(|(k, _)| k.eq_ignore_ascii_case("value"))?.1 {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    })
}

/// Every device sighting in the case (one tenant when asked): `signins.device` (Graph and portal exports) and the
/// `DeviceProperties` of `AzureActiveDirectory` UAL records. Time order, untimed sightings last.
pub fn device_sightings(conn: &Connection, tenant: Option<&str>) -> Result<Vec<DeviceSighting>> {
    sightings(conn, tenant, None)
}

/// The sightings from one IP (case-insensitive), in the order of [`device_sightings`].
pub fn device_sightings_on_ip(conn: &Connection, ip: &str) -> Result<Vec<DeviceSighting>> {
    sightings(conn, None, Some(ip))
}

fn sightings(
    conn: &Connection,
    tenant: Option<&str>,
    ip: Option<&str>,
) -> Result<Vec<DeviceSighting>> {
    let mut out = Vec::new();
    let mut st = conn.prepare(
        "SELECT c.tenant_key, s.device.device_id, s.device.display_name, s.device.os, s.device.trust_type, \
                s.user_upn, s.ip, epoch_us(s.event_time), coalesce(s.app_name, s.resource_name, ''), s.record_key \
         FROM signins s JOIN collections c ON c.collection_id = s.collection_id \
         WHERE s.device.device_id IS NOT NULL \
           AND (CAST(? AS VARCHAR) IS NULL OR c.tenant_key = ?) \
           AND (CAST(? AS VARCHAR) IS NULL OR lower(s.ip) = lower(?))",
    )?;
    let rows = st.query_map(duckdb::params![tenant, tenant, ip, ip], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, Option<i64>>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
        ))
    })?;
    for row in rows {
        let (tenant_key, id, name, os, trust, upn, ip, us, activity, record_key) = row?;
        let Some(device_id) = clean_device_id(&id) else {
            continue;
        };
        out.push(DeviceSighting {
            tenant_key,
            device_id,
            display_name: non_empty(name),
            os: non_empty(os),
            trust_type: non_empty(trust),
            user_upn: non_empty(upn),
            ip: non_empty(ip),
            event_time: at_us(us),
            activity,
            source_table: "signins".into(),
            record_key,
        });
    }
    // Only AzureActiveDirectory records are touched. The `DeviceProperties` key is found case-insensitively; a
    // candidate is an array or a string (a JSON Name/Value array as text) that mentions an id. Rust does the exact parse.
    let mut st = conn.prepare(
        "WITH a AS (SELECT u.audit_data, u.user_upn, u.client_ip, u.event_time, u.operation, u.record_id, c.tenant_key, \
                    CASE WHEN json_type(u.audit_data) = 'OBJECT' THEN \
                         list_filter(json_keys(u.audit_data), lambda k: lower(k) = 'deviceproperties')[1] END AS dk \
                    FROM ual_events u JOIN collections c ON c.collection_id = u.collection_id \
                    WHERE u.workload = 'AzureActiveDirectory' AND (CAST(? AS VARCHAR) IS NULL OR c.tenant_key = ?) \
                      AND (CAST(? AS VARCHAR) IS NULL OR lower(u.client_ip) = lower(?))), \
              b AS (SELECT *, json_extract(audit_data, '$.\"' || dk || '\"') AS dp FROM a WHERE dk IS NOT NULL) \
         SELECT tenant_key, CAST(dp AS VARCHAR), user_upn, client_ip, epoch_us(event_time), coalesce(operation, ''), \
                CAST(record_id AS VARCHAR) \
         FROM b WHERE json_type(dp) IN ('ARRAY', 'VARCHAR') AND contains(lower(CAST(dp AS VARCHAR)), 'id')",
    )?;
    let rows = st.query_map(duckdb::params![tenant, tenant, ip, ip], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (tenant_key, props, upn, ip, us, activity, record_key) = row?;
        let props = match serde_json::from_str::<Value>(&props) {
            Ok(Value::Array(a)) => a,
            // A string holding the Name/Value array, as the UAL normaliser also accepts.
            Ok(Value::String(t)) if t.trim_start().starts_with('[') => {
                match serde_json::from_str::<Value>(&t) {
                    Ok(Value::Array(a)) => a,
                    _ => continue,
                }
            }
            _ => continue,
        };
        let Some(device_id) = property(&props, "Id").and_then(|id| clean_device_id(&id)) else {
            continue;
        };
        out.push(DeviceSighting {
            tenant_key,
            device_id,
            display_name: non_empty(property(&props, "DisplayName")),
            os: non_empty(property(&props, "OS")),
            trust_type: non_empty(property(&props, "TrustType")),
            user_upn: non_empty(upn),
            ip: non_empty(ip),
            event_time: at_us(us),
            activity,
            source_table: "ual_events".into(),
            record_key,
        });
    }
    out.sort_by(|a, b| {
        (
            a.event_time.is_none(),
            a.event_time,
            &a.source_table,
            &a.record_key,
        )
            .cmp(&(
                b.event_time.is_none(),
                b.event_time,
                &b.source_table,
                &b.record_key,
            ))
    });
    Ok(out)
}

/// A display name links devices across users only when at most this many distinct device ids in the tenant carry it.
pub const SAME_NAME_TENANT_MAX: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Low,
}

impl Confidence {
    /// The serde name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Low => "low",
        }
    }
}

impl DeviceStatus {
    /// The serde name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActiveAfterRemoval => "active_after_removal",
            Self::Active => "active",
            Self::Unknown => "unknown",
            Self::NotInLatestInventory => "not_in_latest_inventory",
            Self::Disabled => "disabled",
            Self::Removed => "removed",
        }
    }
}

/// An address a suspect device used that is not (yet) malicious, with what `ip_intel` knows of it.
#[derive(Debug, Clone, Serialize)]
pub struct OtherIp {
    pub ip: String,
    pub asn: Option<i32>,
    pub asn_org: Option<String>,
    pub country_iso: Option<String>,
    pub is_hosting: Option<bool>,
}

/// Where the device is in its life: filled by the lifecycle pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    ActiveAfterRemoval,
    Active,
    #[default]
    Unknown,
    NotInLatestInventory,
    Disabled,
    Removed,
}

/// The record that sets a lifecycle date.
#[derive(Debug, Clone, Serialize)]
pub struct LifecycleMark {
    #[serde(serialize_with = "ts")]
    pub at: DateTime<Utc>,
    pub source_table: String,
    pub record_key: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Lifecycle {
    pub status: DeviceStatus,
    pub registered: Option<LifecycleMark>,
    pub removed: Option<LifecycleMark>,
    pub disabled: Option<LifecycleMark>,
    pub last_active: Option<LifecycleMark>,
    /// `collected_at` of the newest `devices` collection of the tenant.
    #[serde(serialize_with = "ts_opt")]
    pub latest_inventory_at: Option<DateTime<Utc>>,
}

fn ts_opt<S: Serializer>(t: &Option<DateTime<Utc>>, s: S) -> std::result::Result<S::Ok, S::Error> {
    match t {
        Some(t) => ts(t, s),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspectDevice {
    pub tenant_key: Option<String>,
    pub device_id: String,
    pub object_id: Option<String>,
    pub display_name: Option<String>,
    pub os: Option<String>,
    pub trust_type: Option<String>,
    pub is_compliant: Option<bool>,
    pub is_managed: Option<bool>,
    pub confidence: Confidence,
    pub reasons: Vec<SuspectReason>,
    pub users: Vec<String>,
    pub malicious_ips: Vec<String>,
    pub other_ips: Vec<OtherIp>,
    /// Time order.
    pub sightings: Vec<DeviceSighting>,
    pub lifecycle: Lifecycle,
}

/// A row of the `devices` inventory (Invictus `Get-Devices`), keyed by tenant and lower-cased device id.
#[derive(Debug, Clone, Default)]
struct InventoryRow {
    record_key: String,
    collection_id: i64,
    collected_at: Option<DateTime<Utc>>,
    enabled: Option<bool>,
    created: Option<DateTime<Utc>>,
    last_signin: Option<DateTime<Utc>>,
    object_id: Option<String>,
    display_name: Option<String>,
    os: Option<String>,
    trust_type: Option<String>,
    is_compliant: Option<bool>,
    is_managed: Option<bool>,
}

type DeviceKey = (Option<String>, String);

fn inventory(conn: &Connection, tenant: Option<&str>) -> Result<BTreeMap<DeviceKey, InventoryRow>> {
    let mut st = conn.prepare(
        "SELECT c.tenant_key, d.device_id, d.object_id, d.display_name, d.os, d.trust_type, d.is_compliant, d.is_managed, \
                d.record_key, d.collection_id, epoch_us(coalesce(d.collected_at, c.collected_at)), d.enabled, \
                epoch_us(d.created), epoch_us(d.last_signin) \
         FROM devices d JOIN collections c ON c.collection_id = d.collection_id \
         WHERE d.device_id IS NOT NULL AND (CAST(? AS VARCHAR) IS NULL OR c.tenant_key = ?) \
         ORDER BY d.record_key",
    )?;
    let rows = st.query_map(duckdb::params![tenant, tenant], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, String>(1)?,
            InventoryRow {
                object_id: non_empty(r.get(2)?).map(|o| o.to_lowercase()),
                display_name: non_empty(r.get(3)?),
                os: non_empty(r.get(4)?),
                trust_type: non_empty(r.get(5)?),
                is_compliant: r.get(6)?,
                is_managed: r.get(7)?,
                record_key: r.get(8)?,
                collection_id: r.get(9)?,
                collected_at: at_us(r.get(10)?),
                enabled: r.get(11)?,
                created: at_us(r.get(12)?),
                last_signin: at_us(r.get(13)?),
            },
        ))
    })?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (tenant_key, id, inv) = row?;
        if let Some(id) = clean_device_id(&id) {
            out.insert((tenant_key, id), inv);
        }
    }
    Ok(out)
}

/// Records (or IPs) per batched, bound lookup: shared by the provenance and `ip_intel` lookups.
pub(crate) const LOOKUP_CHUNK: usize = 400;

/// `ip_intel` of every given (lower-cased) IP, in bound queries of at most [`LOOKUP_CHUNK`] IPs.
pub(crate) fn ip_intel(
    conn: &Connection,
    ips: &BTreeSet<String>,
) -> Result<HashMap<String, OtherIp>> {
    let mut out = HashMap::new();
    let ips: Vec<&String> = ips.iter().collect();
    for chunk in ips.chunks(LOOKUP_CHUNK) {
        // The IPs are bound values: the SQL text holds only `?` markers, never case data.
        let markers = vec!["?"; chunk.len()].join(", ");
        let mut st = conn.prepare(&format!(
            "SELECT lower(ip), asn, asn_org, country_iso, is_hosting FROM ip_intel WHERE lower(ip) IN ({markers})"
        ))?;
        let rows = st.query_map(duckdb::params_from_iter(chunk.iter()), |r| {
            let key: String = r.get(0)?;
            Ok((
                key.clone(),
                OtherIp {
                    ip: key,
                    asn: r.get(1)?,
                    asn_org: r.get(2)?,
                    country_iso: r.get(3)?,
                    is_hosting: r.get(4)?,
                },
            ))
        })?;
        for row in rows {
            let (k, v) = row?;
            out.insert(k, v);
        }
    }
    Ok(out)
}

/// Case-insensitive, de-duplicated, in first-seen order.
fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|v| v.eq_ignore_ascii_case(value)) {
        list.push(value.to_string());
    }
}

/// The latest non-null value of a sighting field (sightings are in time order).
fn latest<F: Fn(&DeviceSighting) -> Option<&String>>(
    sightings: &[DeviceSighting],
    f: F,
) -> Option<String> {
    sightings.iter().rev().find_map(|s| f(s).cloned())
}

/// The devices to contain: every device with a sighting on a malicious IP (with all its sightings), and the devices
/// that share a display name with one (same user, or a name few devices in the tenant carry). Identity is
/// `(tenant, device id)`. One pass: the other IPs and namesakes of a suspect device pull in nothing further. Ordered
/// by lifecycle status, confidence, then most recently active.
pub fn suspect_devices(conn: &Connection, tenant: Option<&str>) -> Result<Vec<SuspectDevice>> {
    let mal = malicious_by_tenant(conn, tenant)?;
    // Why `ip` is malicious in `tenant`: that tenant's reasons plus those of tenantless indicators.
    let reasons_for = |tenant: &Option<String>, ip: &str| -> Vec<SuspectReason> {
        let ip = ip.to_lowercase();
        let mut v = mal
            .get(&(tenant.clone(), ip.clone()))
            .cloned()
            .unwrap_or_default();
        if tenant.is_some() {
            v.extend(mal.get(&(None, ip)).cloned().unwrap_or_default());
        }
        v
    };
    let sightings = device_sightings(conn, tenant)?;
    let inventory = inventory(conn, tenant)?;
    let mut groups: BTreeMap<DeviceKey, Vec<DeviceSighting>> = BTreeMap::new();
    for s in sightings {
        groups
            .entry((s.tenant_key.clone(), s.device_id.clone()))
            .or_default()
            .push(s);
    }
    // Each device's name: the inventory's, else the latest named sighting.
    let name_of = |key: &DeviceKey, ss: &[DeviceSighting]| -> Option<String> {
        inventory
            .get(key)
            .and_then(|i| i.display_name.clone())
            .or_else(|| latest(ss, |s| s.display_name.as_ref()))
    };
    let mut names: BTreeMap<DeviceKey, String> = BTreeMap::new();
    for (key, ss) in &groups {
        if let Some(n) = name_of(key, ss) {
            names.insert(key.clone(), n);
        }
    }
    for (key, inv) in &inventory {
        if let (Some(n), false) = (&inv.display_name, names.contains_key(key)) {
            names.insert(key.clone(), n.clone());
        }
    }
    // Pass 1: devices seen on a malicious IP.
    let mut reasons: BTreeMap<DeviceKey, Vec<SuspectReason>> = BTreeMap::new();
    for (key, ss) in &groups {
        let mut why = Vec::new();
        for ip in ss.iter().filter_map(|s| s.ip.as_deref()) {
            why.extend(reasons_for(&key.0, ip));
        }
        if !why.is_empty() {
            why.sort();
            why.dedup();
            reasons.insert(key.clone(), why);
        }
    }
    let ip_suspects: Vec<DeviceKey> = reasons.keys().cloned().collect();
    let low = |why: &[SuspectReason]| {
        why.iter()
            .all(|r| matches!(r, SuspectReason::TravelLeg { .. }))
    };
    let users_of = |ss: &[DeviceSighting]| -> BTreeSet<String> {
        ss.iter()
            .filter_map(|s| s.user_upn.as_deref())
            .map(str::to_lowercase)
            .collect()
    };
    // Pass 2: namesakes of those devices.
    let mut carriers: HashMap<(Option<String>, String), BTreeSet<String>> = HashMap::new();
    for ((t, id), n) in &names {
        carriers
            .entry((t.clone(), n.to_lowercase()))
            .or_default()
            .insert(id.clone());
    }
    let mut same_name: BTreeMap<DeviceKey, Vec<(SuspectReason, bool)>> = BTreeMap::new();
    for (key, ss) in &groups {
        if reasons.contains_key(key) {
            continue;
        }
        let Some(name) = names.get(key) else { continue };
        let lname = name.to_lowercase();
        let common = carriers
            .get(&(key.0.clone(), lname.clone()))
            .map_or(0, BTreeSet::len)
            <= SAME_NAME_TENANT_MAX;
        let users = users_of(ss);
        for sus in &ip_suspects {
            if sus.0 != key.0
                || names.get(sus).map(|n| n.to_lowercase()).as_deref() != Some(lname.as_str())
            {
                continue;
            }
            if common || !users.is_disjoint(&users_of(&groups[sus])) {
                let sus_low = low(&reasons[sus]);
                same_name.entry(key.clone()).or_default().push((
                    SuspectReason::SameName {
                        name: names[sus].clone(),
                        of_device_id: sus.1.clone(),
                    },
                    sus_low,
                ));
            }
        }
    }
    let mut suspect_keys: Vec<(DeviceKey, Vec<SuspectReason>, Confidence)> = Vec::new();
    for (key, why) in &reasons {
        let conf = if low(why) {
            Confidence::Low
        } else {
            Confidence::High
        };
        suspect_keys.push((key.clone(), why.clone(), conf));
    }
    for (key, links) in &same_name {
        let conf = if links.iter().all(|(_, l)| *l) {
            Confidence::Low
        } else {
            Confidence::High
        };
        suspect_keys.push((
            key.clone(),
            links.iter().map(|(r, _)| r.clone()).collect(),
            conf,
        ));
    }
    let mut other: BTreeSet<String> = BTreeSet::new();
    for (key, ..) in &suspect_keys {
        for ip in groups[key].iter().filter_map(|s| s.ip.as_deref()) {
            if reasons_for(&key.0, ip).is_empty() {
                other.insert(ip.to_lowercase());
            }
        }
    }
    let intel = ip_intel(conn, &other)?;
    let mut out = Vec::new();
    for (key, why, confidence) in suspect_keys {
        let ss = groups[&key].clone();
        let inv = inventory.get(&key).cloned().unwrap_or_default();
        let mut users = Vec::new();
        let mut malicious = Vec::new();
        let mut others: Vec<OtherIp> = Vec::new();
        for s in &ss {
            if let Some(u) = &s.user_upn {
                push_unique(&mut users, u);
            }
            if let Some(ip) = &s.ip {
                if !reasons_for(&key.0, ip).is_empty() {
                    push_unique(&mut malicious, ip);
                } else if !others.iter().any(|o| o.ip.eq_ignore_ascii_case(ip)) {
                    others.push(intel.get(&ip.to_lowercase()).cloned().map_or_else(
                        || OtherIp {
                            ip: ip.clone(),
                            asn: None,
                            asn_org: None,
                            country_iso: None,
                            is_hosting: None,
                        },
                        |mut o| {
                            o.ip = ip.clone();
                            o
                        },
                    ));
                }
            }
        }
        users.sort_by_key(|u| u.to_lowercase());
        out.push(SuspectDevice {
            tenant_key: key.0.clone(),
            device_id: key.1.clone(),
            object_id: inv.object_id,
            display_name: inv
                .display_name
                .or_else(|| latest(&ss, |s| s.display_name.as_ref())),
            os: inv.os.or_else(|| latest(&ss, |s| s.os.as_ref())),
            trust_type: inv
                .trust_type
                .or_else(|| latest(&ss, |s| s.trust_type.as_ref())),
            is_compliant: inv.is_compliant,
            is_managed: inv.is_managed,
            confidence,
            reasons: why,
            users,
            malicious_ips: malicious,
            other_ips: others,
            sightings: ss,
            lifecycle: Lifecycle::default(),
        });
    }
    apply_lifecycle(conn, tenant, &inventory, &mut out)?;
    sort_devices(&mut out);
    Ok(out)
}

fn sort_devices(list: &mut [SuspectDevice]) {
    list.sort_by(|a, b| {
        let last = |d: &SuspectDevice| d.lifecycle.last_active.as_ref().map(|m| m.at);
        (
            a.lifecycle.status,
            a.confidence,
            Reverse(last(a)),
            &a.tenant_key,
            &a.device_id,
        )
            .cmp(&(
                b.lifecycle.status,
                b.confidence,
                Reverse(last(b)),
                &b.tenant_key,
                &b.device_id,
            ))
    });
}

// ---- lifecycle ---------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    Register,
    Remove,
    /// An `Update device` that sets `AccountEnabled`.
    SetEnabled(bool),
    /// Carries a device id (so it teaches the object-id map) but changes no lifecycle field.
    Other,
}

/// A device-management audit record (UAL or `directory_audits`).
#[derive(Debug, Clone)]
struct DeviceEvent {
    tenant_key: Option<String>,
    mark: LifecycleMark,
    kind: EventKind,
    device_id: Option<String>,
    /// Lower-cased object ids named by the record's targets, for looking an event up.
    oids: Vec<String>,
    /// The one object id this record verifiably belongs to the device it names (`Device_<oid>` target), if any.
    bound_oid: Option<String>,
}

fn event_kind(operation: &str) -> Option<EventKind> {
    let op = operation.trim().trim_end_matches('.').trim().to_lowercase();
    Some(match op.as_str() {
        "add device" | "register device" => EventKind::Register,
        "delete device" | "unregister device" => EventKind::Remove,
        // Whether it sets AccountEnabled is decided by its properties.
        "update device" => EventKind::Other,
        _ => return None,
    })
}

/// The scalar inside an audit-log property value: `["abc"]` with any CR/LF and spacing, `"abc"`, `abc`.
fn scalar(v: &str) -> Option<String> {
    let t: String = v
        .chars()
        .filter(|c| !matches!(c, '[' | ']' | '"' | '\r' | '\n' | '\t'))
        .collect();
    let first = t.split(',').next().unwrap_or("").trim().to_string();
    (!first.is_empty()).then_some(first)
}

fn get_ci<'a>(o: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a Value> {
    o.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

fn text_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// `(name, value)` of a modified property: the new value, else the old one.
type Prop = (String, Option<String>);

fn prop(name: Option<String>, new: Option<String>, old: Option<String>) -> Option<Prop> {
    let value = new.filter(|v| scalar(v).is_some());
    Some((name?, value.or(old)))
}

fn device_id_of(props: &[Prop]) -> Option<String> {
    props
        .iter()
        .filter(|(n, _)| {
            n.eq_ignore_ascii_case("DeviceId") || n.eq_ignore_ascii_case("TargetId.DeviceId")
        })
        .find_map(|(_, v)| clean_device_id(&scalar(v.as_deref()?)?))
}

fn enabled_of(props: &[Prop]) -> Option<bool> {
    props
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("AccountEnabled"))
        .find_map(
            |(_, v)| match scalar(v.as_deref()?)?.to_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
        )
}

fn is_guid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Object ids from target ids: `Device_<oid>` or a bare `<oid>`. The second value is the object id an event may be
/// bound to its device id with: the single distinct `Device_<oid>` id (a bare twin equal to it adds nothing). An event
/// with several different `Device_` targets is ambiguous and binds nothing.
fn oids_of(ids: Vec<String>) -> (Vec<String>, Option<String>) {
    let mut all = Vec::new();
    let mut prefixed: Vec<String> = Vec::new();
    for id in ids {
        let id = id.trim().to_lowercase();
        // Only GUID-shaped ids are object ids: real events also list "Device" and the display name as targets.
        match id.strip_prefix("device_") {
            Some(o) if is_guid(o) => {
                prefixed.push(o.to_string());
                all.push(o.to_string());
            }
            _ if is_guid(&id) => all.push(id),
            _ => {}
        }
    }
    prefixed.sort();
    prefixed.dedup();
    let bound = if prefixed.len() == 1 {
        prefixed.pop()
    } else {
        None
    };
    (all, bound)
}

#[allow(clippy::too_many_arguments)]
fn make_event(
    tenant_key: Option<String>,
    at: DateTime<Utc>,
    source_table: &str,
    record_key: String,
    operation: &str,
    props: &[Prop],
    oids: Vec<String>,
    bound_oid: Option<String>,
) -> Option<DeviceEvent> {
    let mut kind = event_kind(operation)?;
    if let (EventKind::Other, Some(on)) = (kind, enabled_of(props)) {
        kind = EventKind::SetEnabled(on);
    }
    Some(DeviceEvent {
        tenant_key,
        mark: LifecycleMark {
            at,
            source_table: source_table.into(),
            record_key,
        },
        kind,
        device_id: device_id_of(props),
        oids,
        bound_oid,
    })
}

const DEVICE_OPS: &str =
    "'add device', 'register device', 'delete device', 'unregister device', 'update device'";

type EventRow = (
    Option<String>,
    Option<i64>,
    String,
    String,
    Option<String>,
    Option<String>,
);

fn event_rows(conn: &Connection, sql: &str, tenant: Option<&str>) -> Result<Vec<EventRow>> {
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map(duckdb::params![tenant, tenant], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
        ))
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

fn parse_array(text: Option<String>) -> Vec<Value> {
    match text.and_then(|t| serde_json::from_str(&t).ok()) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    }
}

fn device_events(conn: &Connection, tenant: Option<&str>) -> Result<Vec<DeviceEvent>> {
    let mut out = Vec::new();
    let ual_sql = format!(
        "SELECT c.tenant_key, epoch_us(u.event_time), CAST(u.record_id AS VARCHAR), u.operation, \
                CAST(u.audit_data->'ModifiedProperties' AS VARCHAR), CAST(u.audit_data->'Target' AS VARCHAR) \
         FROM ual_events u JOIN collections c ON c.collection_id = u.collection_id \
         WHERE u.workload = 'AzureActiveDirectory' AND lower(rtrim(trim(u.operation), '.')) IN ({DEVICE_OPS}) \
           AND (CAST(? AS VARCHAR) IS NULL OR c.tenant_key = ?)"
    );
    for (tenant_key, us, key, op, props, targets) in event_rows(conn, &ual_sql, tenant)? {
        let Some(at) = at_us(us) else { continue };
        let plist: Vec<Prop> = parse_array(props)
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|p| {
                prop(
                    text_of(get_ci(p, "Name")),
                    text_of(get_ci(p, "NewValue")),
                    text_of(get_ci(p, "OldValue")),
                )
            })
            .collect();
        let ids = parse_array(targets)
            .iter()
            .filter_map(|t| match t {
                Value::String(s) => Some(s.clone()),
                Value::Object(o) => text_of(get_ci(o, "ID")),
                _ => None,
            })
            .collect();
        let (oids, bound) = oids_of(ids);
        out.extend(make_event(
            tenant_key,
            at,
            "ual_events",
            key,
            &op,
            &plist,
            oids,
            bound,
        ));
    }
    let da_sql = format!(
        "SELECT c.tenant_key, epoch_us(a.event_time), a.record_key, a.activity, \
                CAST(a.modified_properties AS VARCHAR), CAST(a.targets AS VARCHAR) \
         FROM directory_audits a JOIN collections c ON c.collection_id = a.collection_id \
         WHERE lower(rtrim(trim(a.activity), '.')) IN ({DEVICE_OPS}) \
           AND (CAST(? AS VARCHAR) IS NULL OR c.tenant_key = ?)"
    );
    for (tenant_key, us, key, op, props, targets) in event_rows(conn, &da_sql, tenant)? {
        let Some(at) = at_us(us) else { continue };
        // The parser's [{target, property, old, new}].
        let mut plist: Vec<Prop> = parse_array(props)
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|p| {
                prop(
                    text_of(get_ci(p, "property")),
                    text_of(get_ci(p, "new")),
                    text_of(get_ci(p, "old")),
                )
            })
            .collect();
        let mut ids = Vec::new();
        let mut device_targets: Vec<String> = Vec::new();
        for t in parse_array(targets).iter().filter_map(Value::as_object) {
            ids.extend(text_of(get_ci(t, "Id")));
            if text_of(get_ci(t, "Type")).is_some_and(|ty| ty.eq_ignore_ascii_case("device")) {
                device_targets.extend(text_of(get_ci(t, "Id")));
            }
            // Properties kept on the raw target when the flattened list lacks them.
            if let Some(Value::Array(ps)) = get_ci(t, "ModifiedProperties") {
                plist.extend(ps.iter().filter_map(Value::as_object).filter_map(|p| {
                    prop(
                        text_of(get_ci(p, "DisplayName")),
                        text_of(get_ci(p, "NewValue")),
                        text_of(get_ci(p, "OldValue")),
                    )
                }));
            }
        }
        // Graph targets carry no `Device_` prefix: the single target of type Device is the verified one.
        device_targets.sort();
        device_targets.dedup();
        let bound = if device_targets.len() == 1 {
            device_targets.pop().map(|o| o.trim().to_lowercase())
        } else {
            None
        };
        out.extend(make_event(
            tenant_key,
            at,
            "directory_audits",
            key,
            &op,
            &plist,
            oids_of(ids).0,
            bound,
        ));
    }
    out.sort_by(|a, b| {
        (a.mark.at, &a.mark.source_table, &a.mark.record_key).cmp(&(
            b.mark.at,
            &b.mark.source_table,
            &b.mark.record_key,
        ))
    });
    Ok(out)
}

/// Fill `lifecycle` (and a missing `object_id`) of every device. Events are matched to a device only by device id,
/// or by an object id resolved to a device id through the ids the add/update/delete records themselves carry and
/// `devices.object_id` — never by name or time.
fn apply_lifecycle(
    conn: &Connection,
    tenant: Option<&str>,
    inventory: &BTreeMap<DeviceKey, InventoryRow>,
    list: &mut [SuspectDevice],
) -> Result<()> {
    let events = device_events(conn, tenant)?;
    // object id → device ids it was bound to; an id bound to two different devices is dropped (never guessed).
    let mut bound: HashMap<(Option<String>, String), BTreeSet<String>> = HashMap::new();
    for ((t, id), inv) in inventory {
        if let Some(o) = &inv.object_id {
            bound
                .entry((t.clone(), o.clone()))
                .or_default()
                .insert(id.clone());
        }
    }
    for e in &events {
        if let (Some(id), Some(o)) = (&e.device_id, &e.bound_oid) {
            bound
                .entry((e.tenant_key.clone(), o.clone()))
                .or_default()
                .insert(id.clone());
        }
    }
    let oid_map: HashMap<(Option<String>, String), String> = bound
        .into_iter()
        .filter(|(_, ids)| ids.len() == 1)
        .map(|(k, ids)| (k, ids.into_iter().next().expect("one id")))
        .collect();
    // An event with no device id resolves only when every target that maps names the same device; targets that
    // map to different devices, or are unmapped, make it ambiguous, and it is ignored.
    let resolved = |e: &DeviceEvent| -> Option<String> {
        if let Some(id) = &e.device_id {
            return Some(id.clone());
        }
        // Every distinct target (a bare id equal to a `Device_` twin is the same target) must map, to one device.
        let distinct: BTreeSet<&String> = e.oids.iter().collect();
        let mut mapped: BTreeSet<&String> = BTreeSet::new();
        for o in distinct {
            mapped.insert(oid_map.get(&(e.tenant_key.clone(), o.clone()))?);
        }
        match mapped.len() {
            1 => mapped.into_iter().next().cloned(),
            _ => None,
        }
    };
    let mut by_device: HashMap<DeviceKey, Vec<&DeviceEvent>> = HashMap::new();
    for e in &events {
        if let Some(id) = resolved(e) {
            by_device
                .entry((e.tenant_key.clone(), id))
                .or_default()
                .push(e);
        }
    }
    // The newest inventory collection of each tenant: the one with the latest collected_at.
    let mut newest: HashMap<Option<String>, (DateTime<Utc>, i64)> = HashMap::new();
    for ((t, _), inv) in inventory {
        if let Some(at) = inv.collected_at {
            let cur = newest.entry(t.clone()).or_insert((at, inv.collection_id));
            if (at, inv.collection_id) > *cur {
                *cur = (at, inv.collection_id);
            }
        }
    }
    for d in list.iter_mut() {
        let key = (d.tenant_key.clone(), d.device_id.clone());
        let inv = inventory.get(&key);
        let events: &[&DeviceEvent] = by_device.get(&key).map_or(&[], Vec::as_slice);
        let earliest = |kind: EventKind| {
            events
                .iter()
                .find(|e| e.kind == kind)
                .map(|e| e.mark.clone())
        };
        let latest_of = |kind: EventKind| {
            events
                .iter()
                .rev()
                .find(|e| e.kind == kind)
                .map(|e| e.mark.clone())
        };
        let inv_mark = |at: Option<DateTime<Utc>>| {
            let (inv, at) = (inv?, at?);
            Some(LifecycleMark {
                at,
                source_table: "devices".into(),
                record_key: inv.record_key.clone(),
            })
        };
        let registered =
            earliest(EventKind::Register).or_else(|| inv_mark(inv.and_then(|i| i.created)));
        let removed = latest_of(EventKind::Remove);
        // last_active: the newest sighting, or devices.last_signin.
        let mut last_active = d.sightings.iter().rev().find_map(|s| {
            Some(LifecycleMark {
                at: s.event_time?,
                source_table: s.source_table.clone(),
                record_key: s.record_key.clone(),
            })
        });
        if let Some(m) = inv_mark(inv.and_then(|i| i.last_signin)) {
            if last_active.as_ref().is_none_or(|l| m.at > l.at) {
                last_active = Some(m);
            }
        }
        // AccountEnabled: the latest evidence wins; an inventory row speaks at its collection time.
        let mut enabled_states: Vec<(DateTime<Utc>, bool, LifecycleMark)> = Vec::new();
        if let Some(i) = inv {
            if let (Some(on), Some(at)) = (i.enabled, i.collected_at) {
                enabled_states.push((at, on, inv_mark(Some(at)).expect("inventory row")));
            }
        }
        for e in events {
            if let EventKind::SetEnabled(on) = e.kind {
                enabled_states.push((e.mark.at, on, e.mark.clone()));
            }
        }
        enabled_states.sort_by_key(|(at, ..)| *at);
        let disabled = match enabled_states.last() {
            Some((_, false, m)) => Some(m.clone()),
            _ => None,
        };
        let seen_after = |t: DateTime<Utc>| {
            d.sightings
                .iter()
                .any(|s| s.event_time.is_some_and(|e| e > t))
        };
        let newest_inv = newest.get(&d.tenant_key).copied();
        let in_newest =
            inv.is_some_and(|i| newest_inv.is_some_and(|(_, cid)| i.collection_id == cid));
        let last_at = last_active.as_ref().map(|l| l.at);
        // Anything later than the latest removal says the device is back: a sighting, a registration, an enable,
        // or an inventory collected after it that lists the device.
        let status = if removed.as_ref().is_some_and(|r| {
            seen_after(r.at)
                || events.iter().any(|e| {
                    e.mark.at > r.at
                        && matches!(e.kind, EventKind::Register | EventKind::SetEnabled(true))
                })
                || inv.is_some_and(|i| i.collected_at.is_some_and(|c| c > r.at))
        }) {
            DeviceStatus::ActiveAfterRemoval
        } else if removed.is_some() {
            DeviceStatus::Removed
        } else if disabled.as_ref().is_some_and(|m| !seen_after(m.at)) {
            DeviceStatus::Disabled
        } else if newest_inv.is_some_and(|(at, _)| last_at.is_some_and(|l| at > l)) && !in_newest {
            DeviceStatus::NotInLatestInventory
        } else if inv.is_some() || events.iter().any(|e| e.kind == EventKind::Register) {
            DeviceStatus::Active
        } else {
            DeviceStatus::Unknown
        };
        if d.object_id.is_none() {
            d.object_id = oid_map
                .iter()
                .filter(|((t, _), id)| *t == d.tenant_key && **id == d.device_id)
                .map(|((_, o), _)| o.clone())
                .min();
        }
        d.lifecycle = Lifecycle {
            status,
            registered,
            removed,
            disabled,
            last_active,
            latest_inventory_at: newest_inv.map(|(at, _)| at),
        };
    }
    Ok(())
}
