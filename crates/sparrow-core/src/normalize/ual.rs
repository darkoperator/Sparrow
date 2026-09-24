//! Normalize one AuditData object into typed `ual_events` columns and child rows (spec §5.1).
//! Property names follow the Microsoft Management Activity API schema
//! (docs/superpowers/research/2026-09-24-ual-audit-facts.md).

use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::record_types::{record_type_name, record_type_value};
use crate::normalize::ual_shape::{AuditInput, Completeness, get_ci, value_text};
use crate::readers::time::{DateOrder, Precision, parse_timestamp};
use serde_json::{Map, Value};
use uuid::Uuid;

/// Namespace of content-derived record ids (UUIDv5 of the canonical AuditData JSON).
pub const SPARROW_UAL_NAMESPACE: Uuid = Uuid::from_u128(0x5f1c_2a3e_8b4d_4c6f_9a7e_1d2b_3c4d_5e6f);

#[derive(Debug, Clone, PartialEq)]
pub struct MailItemRow {
    pub item_ordinal: i32,
    pub access_type: Option<&'static str>,
    pub folder_path: Option<String>,
    pub internet_message_id: Option<String>,
    pub size_bytes: Option<i64>,
    pub is_throttled: Option<bool>,
    pub operation_count: Option<i32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileEventRow {
    pub workload: Option<String>,
    pub site_url: Option<String>,
    pub relative_url: Option<String>,
    pub file_name: Option<String>,
    pub file_ext: Option<String>,
    pub item_type: &'static str,
    pub is_onenote: bool,
    pub application_name: Option<String>,
    pub platform: Option<String>,
    pub device_name: Option<String>,
    pub list_id: Option<String>,
    pub list_item_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SharingRow {
    pub link_type: &'static str,
    pub target_user: Option<String>,
    pub target_email: Option<String>,
    pub permission: Option<&'static str>,
    pub is_external: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchRow {
    pub workload: &'static str,
    pub query_text: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UalRecord {
    /// Lower-case hyphenated UUID.
    pub record_id: String,
    pub synthetic_id: bool,
    /// RFC 3339 UTC.
    pub event_time: String,
    pub time_tz_assumed: bool,
    pub time_precision: Precision,
    pub record_type: Option<i16>,
    pub record_type_name: Option<String>,
    pub workload: Option<String>,
    pub operation: Option<String>,
    pub result_status: Option<String>,
    pub user_upn: Option<String>,
    pub user_type: Option<i16>,
    pub user_key: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub app_id: Option<String>,
    pub client_app_id: Option<String>,
    pub object_id: Option<String>,
    pub organization_id: Option<String>,
    pub mailbox_upn: Option<String>,
    pub parameters: Vec<(String, String)>,
    /// AuditData as JSON text.
    pub audit_data: String,
    pub completeness: Completeness,
    pub mail_items: Vec<MailItemRow>,
    pub file_event: Option<FileEventRow>,
    pub sharing: Option<SharingRow>,
    pub search: Option<SearchRow>,
}

/// Text used as the event time: AuditData CreationTime, else the outer CreationDate.
pub fn event_time_text(input: &AuditInput) -> Option<String> {
    text(&input.audit, "CreationTime").or_else(|| input.outer_time.clone())
}

/// PowerShell's Export-Csv rendering of objects it could not flatten.
fn is_ps_placeholder(v: &str) -> bool {
    v == "System.Object[]" || (v.starts_with("@{") && v.ends_with('}'))
}

/// Trimmed scalar text of `key`; `None` when missing, blank or a PowerShell placeholder.
fn text(m: &Map<String, Value>, key: &str) -> Option<String> {
    let v = value_text(get_ci(m, key)?)?;
    let t = v.trim();
    if t.is_empty() || is_ps_placeholder(t) {
        None
    } else {
        Some(t.to_string())
    }
}

fn first_text(m: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| text(m, k))
}

fn int(m: &Map<String, Value>, key: &str) -> Option<i64> {
    match get_ci(m, key)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn nested_text(m: &Map<String, Value>, outer: &str, key: &str) -> Option<String> {
    match get_ci(m, outer)? {
        Value::Object(o) => text(o, key),
        _ => None,
    }
}

/// `[{Name, Value}]` arrays (Parameters, OperationProperties, ExtendedProperties), also
/// when stored as an embedded JSON string.
fn name_values(v: Option<&Value>) -> Vec<(String, String)> {
    let parsed: Vec<Value>;
    let arr: &Vec<Value> = match v {
        Some(Value::Array(a)) => a,
        Some(Value::String(s)) if s.trim_start().starts_with('[') => {
            match serde_json::from_str::<Value>(s) {
                Ok(Value::Array(a)) => {
                    parsed = a;
                    &parsed
                }
                _ => return Vec::new(),
            }
        }
        _ => return Vec::new(),
    };
    arr.iter()
        .filter_map(|item| {
            let o = item.as_object()?;
            let name = value_text(get_ci(o, "Name")?)?;
            let value = get_ci(o, "Value").and_then(value_text).unwrap_or_default();
            Some((name, value))
        })
        .collect()
}

/// JSON with object keys sorted recursively (stable input for content-derived ids).
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn parse_record_type(s: &str) -> Option<i16> {
    let s = s.trim();
    s.parse::<i16>().ok().or_else(|| record_type_value(s))
}

pub fn normalize_audit(input: &AuditInput, order: Option<DateOrder>) -> Result<UalRecord, String> {
    let a = &input.audit;
    let time_text = event_time_text(input).ok_or("record has no CreationTime")?;
    let t = parse_timestamp(&time_text, order).map_err(|e| format!("CreationTime: {e}"))?;
    let (record_id, synthetic_id) = match text(a, "Id").and_then(|s| Uuid::parse_str(&s).ok()) {
        Some(u) => (u.hyphenated().to_string(), false),
        None => {
            let canon = serde_json::to_string(&canonical(&Value::Object(a.clone())))
                .expect("JSON values serialize");
            (
                Uuid::new_v5(&SPARROW_UAL_NAMESPACE, canon.as_bytes())
                    .hyphenated()
                    .to_string(),
                true,
            )
        }
    };
    let record_type = match get_ci(a, "RecordType") {
        Some(Value::Number(n)) => n.as_i64().and_then(|v| i16::try_from(v).ok()),
        Some(Value::String(s)) => parse_record_type(s),
        _ => None,
    }
    .or_else(|| {
        input
            .outer_record_type
            .as_deref()
            .and_then(parse_record_type)
    });
    let record_type_name = record_type
        .and_then(record_type_name)
        .map(str::to_string)
        .or_else(|| {
            input
                .outer_record_type
                .clone()
                .filter(|s| s.trim().parse::<i16>().is_err())
        });
    let operation = text(a, "Operation");
    let workload = text(a, "Workload");
    let extended = name_values(get_ci(a, "ExtendedProperties"));
    let user_agent = text(a, "UserAgent")
        .or_else(|| {
            extended
                .iter()
                .find(|(n, v)| n.eq_ignore_ascii_case("UserAgent") && !v.is_empty())
                .map(|(_, v)| v.clone())
        })
        .or_else(|| text(a, "ClientInfoString"));
    let mut parameters: Vec<(String, String)> = Vec::new();
    for (k, v) in name_values(get_ci(a, "Parameters"))
        .into_iter()
        .chain(name_values(get_ci(a, "OperationProperties")))
        .chain(input.flat_params.iter().cloned())
    {
        if !parameters.iter().any(|(n, _)| *n == k) {
            parameters.push((k, v));
        }
    }
    let op = operation.clone().unwrap_or_default();
    Ok(UalRecord {
        record_id,
        synthetic_id,
        event_time: t.rfc3339(),
        time_tz_assumed: t.tz_assumed,
        time_precision: t.precision,
        record_type,
        record_type_name,
        workload: workload.clone(),
        operation,
        result_status: text(a, "ResultStatus"),
        user_upn: text(a, "UserId").and_then(|u| normalize_upn(&u)),
        user_type: int(a, "UserType").and_then(|v| i16::try_from(v).ok()),
        user_key: text(a, "UserKey"),
        client_ip: first_text(a, &["ClientIP", "ClientIPAddress", "ActorIpAddress"])
            .and_then(|ip| normalize_ip(&ip)),
        user_agent,
        session_id: text(a, "SessionId")
            .or_else(|| nested_text(a, "AppAccessContext", "AADSessionId")),
        app_id: first_text(a, &["AppId", "ApplicationId"]),
        client_app_id: text(a, "ClientAppId")
            .or_else(|| nested_text(a, "AppAccessContext", "ClientAppId")),
        object_id: text(a, "ObjectId"),
        organization_id: text(a, "OrganizationId")
            .and_then(|s| Uuid::parse_str(&s).ok())
            .map(|u| u.hyphenated().to_string()),
        mailbox_upn: text(a, "MailboxOwnerUPN").and_then(|u| normalize_upn(&u)),
        parameters,
        audit_data: serde_json::to_string(&Value::Object(a.clone()))
            .expect("JSON values serialize"),
        completeness: input.completeness,
        mail_items: if op.eq_ignore_ascii_case("MailItemsAccessed") {
            mail_items(a)
        } else {
            Vec::new()
        },
        file_event: file_event(a, workload.as_deref()),
        sharing: sharing(a, &op),
        search: search(a, &op),
    })
}

fn mail_items(a: &Map<String, Value>) -> Vec<MailItemRow> {
    let props = name_values(get_ci(a, "OperationProperties"));
    let prop = |name: &str| {
        props
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.to_ascii_lowercase())
    };
    let access_type = match prop("MailAccessType").as_deref() {
        Some("bind") => Some("bind"),
        Some("sync") => Some("sync"),
        _ => None,
    };
    let is_throttled = match prop("IsThrottled").as_deref() {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    let operation_count = int(a, "OperationCount").and_then(|v| i32::try_from(v).ok());
    let row = |folder_path: Option<String>, item: Option<&Map<String, Value>>| MailItemRow {
        item_ordinal: 0,
        access_type,
        folder_path,
        internet_message_id: item.and_then(|i| text(i, "InternetMessageId")),
        size_bytes: item.and_then(|i| int(i, "SizeInBytes")),
        is_throttled,
        operation_count,
    };
    let mut rows = Vec::new();
    if let Some(Value::Array(folders)) = get_ci(a, "Folders") {
        for folder in folders.iter().filter_map(Value::as_object) {
            let path = text(folder, "Path");
            match get_ci(folder, "FolderItems") {
                Some(Value::Array(items)) if !items.is_empty() => {
                    for item in items.iter().filter_map(Value::as_object) {
                        rows.push(row(path.clone(), Some(item)));
                    }
                }
                _ => rows.push(row(path, None)),
            }
        }
    }
    if rows.is_empty() {
        rows.push(row(None, None));
    }
    for (i, r) in rows.iter_mut().enumerate() {
        r.item_ordinal = i as i32;
    }
    rows
}

fn file_event(a: &Map<String, Value>, workload: Option<&str>) -> Option<FileEventRow> {
    let w = workload?;
    if !(w.eq_ignore_ascii_case("SharePoint") || w.eq_ignore_ascii_case("OneDrive")) {
        return None;
    }
    let file_name = text(a, "SourceFileName");
    let site_url = text(a, "SiteUrl");
    if file_name.is_none() && site_url.is_none() && get_ci(a, "ItemType").is_none() {
        return None;
    }
    let file_ext = text(a, "SourceFileExtension")
        .or_else(|| {
            file_name
                .as_deref()
                .and_then(|n| n.rsplit_once('.'))
                .map(|(_, e)| e.to_string())
        })
        .map(|e| e.to_ascii_lowercase());
    let item_type = match get_ci(a, "ItemType")
        .and_then(value_text)
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("file" | "1") => "file",
        Some("folder" | "5") => "folder",
        Some("page" | "11") => "page",
        Some("list" | "documentlibrary" | "9") => "list",
        _ => "other",
    };
    let application_name = text(a, "ApplicationDisplayName");
    let user_agent = text(a, "UserAgent");
    let is_onenote = matches!(file_ext.as_deref(), Some("one" | "onetoc2" | "onepkg"))
        || [&application_name, &user_agent].iter().any(|s| {
            s.as_deref()
                .is_some_and(|s| s.to_ascii_lowercase().contains("onenote"))
        });
    Some(FileEventRow {
        workload: Some(w.to_string()),
        site_url,
        relative_url: text(a, "SourceRelativeUrl"),
        file_name,
        file_ext,
        item_type,
        is_onenote,
        application_name,
        platform: text(a, "Platform"),
        device_name: text(a, "DeviceDisplayName"),
        list_id: text(a, "ListId"),
        list_item_id: text(a, "ListItemUniqueId"),
    })
}

/// Sharing operations (Microsoft Learn "Use sharing auditing in the audit log").
fn link_type(op: &str) -> Option<&'static str> {
    let o = op.to_ascii_lowercase();
    if o.starts_with("anonymouslink") {
        Some("anonymous")
    } else if o.starts_with("companylink") {
        Some("company")
    } else if o.starts_with("securelink")
        || o == "addedtosecurelink"
        || o == "removedfromsecurelink"
    {
        Some("specific_people")
    } else if o.starts_with("sharinginvitation") || o == "sharingset" || o == "sharingrevoked" {
        Some("direct")
    } else if o.starts_with("accessrequest") || o == "sharinginheritancebroken" {
        Some("other")
    } else {
        None
    }
}

fn sharing(a: &Map<String, Value>, op: &str) -> Option<SharingRow> {
    let link_type = link_type(op)?;
    let target_user = text(a, "TargetUserOrGroupName");
    let target_email = target_user
        .as_deref()
        .filter(|t| t.contains('@'))
        .map(str::to_ascii_lowercase);
    let perm_text = [text(a, "EventData"), text(a, "SharingType")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let permission = if perm_text.is_empty() {
        None
    } else if ["edit", "contribute", "write", "fullcontrol"]
        .iter()
        .any(|k| perm_text.contains(k))
    {
        Some("edit")
    } else if ["view", "read"].iter().any(|k| perm_text.contains(k)) {
        Some("view")
    } else {
        Some("other")
    };
    let is_external = match text(a, "TargetUserOrGroupType")
        .map(|t| t.to_ascii_lowercase())
        .as_deref()
    {
        Some("guest") => Some(true),
        Some("member") => Some(false),
        _ => None,
    };
    Some(SharingRow {
        link_type,
        target_user,
        target_email,
        permission,
        is_external,
    })
}

/// Search events: `SearchQueryInitiated` (Exchange) and `SharepointSearchQueryInitiated`.
/// Microsoft does not document the query properties; the common names are tried.
fn search(a: &Map<String, Value>, op: &str) -> Option<SearchRow> {
    let workload = match op.to_ascii_lowercase().as_str() {
        "searchqueryinitiated" | "searchqueryinitiatedexchange" => "exchange",
        "sharepointsearchqueryinitiated" | "searchqueryinitiatedsharepoint" => "sharepoint",
        _ => return None,
    };
    Some(SearchRow {
        workload,
        query_text: first_text(a, &["QueryText", "SearchQuery", "Query"]),
        scope: first_text(a, &["QuerySource", "Scope", "SearchScope"]),
    })
}
