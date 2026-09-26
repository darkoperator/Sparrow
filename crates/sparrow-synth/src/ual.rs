//! Unified audit log record builders: one per record type the generator emits, each returning
//! a complete `AuditData` object in Microsoft's key order. Every record starts with the common
//! keys `CreationTime, Id, Operation, OrganizationId, RecordType, ResultStatus, UserKey,
//! UserType, Version, Workload, ClientIP, ObjectId, UserId` (a key Microsoft leaves out for a
//! record type is left out, never reordered), then the type-specific keys. Property names
//! follow the Management Activity API schema (docs/superpowers/research/2026-09-24-ual-audit-facts.md).
//!
//! The builders record what happened; whether Microsoft 365 logged it (audit settings) is
//! decided by the caller.

use crate::events::{RecordType, Ual};
use crate::reserved::WELL_KNOWN_GUIDS;
use crate::rng::{Rng, stream};
use crate::world::{User, World};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::net::IpAddr;
use uuid::Uuid;

/// `CreationTime`: `yyyy-MM-ddTHH:mm:ss`, UTC without a zone, whole seconds.
pub fn creation_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S").to_string()
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn chars(rng: &mut Rng, alphabet: &[u8], n: usize) -> String {
    (0..n)
        .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize] as char)
        .collect()
}

fn upper(rng: &mut Rng, n: usize) -> String {
    chars(rng, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", n)
}

/// An Exchange Online mailbox server name (`AB1PR01MB0001`). Exchange appends a build number
/// `(15.20.x.y)` to `OriginatingServer`; it is left out because the hygiene scanner would read
/// it as an IPv4 address.
pub fn server_name(rng: &mut Rng) -> String {
    format!(
        "{}{}PR{}MB{}",
        upper(rng, 3),
        rng.digits(1),
        rng.digits(2),
        rng.digits(4)
    )
}

const REGIONS: &[&str] = &["namprd04", "namprd12", "eurprd07", "apcprd06"];

/// An Exchange Online Internet message id with the reserved `outlook.example` domain:
/// `<{32 hex}@{server}.{region}.prod.outlook.example>`.
pub fn internet_message_id(rng: &mut Rng) -> String {
    let local = rng.hex(32).to_ascii_uppercase();
    let server = server_name(rng);
    let region = rng.pick(REGIONS);
    format!("<{local}@{server}.{region}.prod.outlook.example>")
}

/// A token's `uti` claim: 22 base64url characters.
pub fn unique_token_id(rng: &mut Rng) -> String {
    chars(rng, B64URL, 22)
}

/// A mailbox folder's opaque id, stable per mailbox and folder path.
pub fn folder_id(w: &World, owner: &str, path: &str) -> String {
    let mut r = stream(w.seed, &format!("folder/{owner}/{path}"));
    format!("LgAAAAA{}AQ", chars(&mut r, B64, 80))
}

/// A mailbox item's opaque id, stable per mailbox and Internet message id.
pub fn item_id(w: &World, owner: &str, internet_message_id: &str) -> String {
    let mut r = stream(w.seed, &format!("item/{owner}/{internet_message_id}"));
    format!("RgAAAAA{}AAAJ", chars(&mut r, B64, 100))
}

/// The display name of application `id`: a tenant app, else a well-known Microsoft app, else
/// empty.
pub fn app_name(w: &World, id: Uuid) -> String {
    if let Some(app) = w.apps.iter().find(|a| a.app_id == id) {
        return app.display_name.clone();
    }
    let text = id.to_string();
    WELL_KNOWN_GUIDS
        .iter()
        .find(|(g, _)| *g == text)
        .map(|(_, d)| d.to_string())
        .unwrap_or_default()
}

/// A mailbox item a record refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub id: String,
    pub internet_message_id: String,
    pub folder_id: String,
    pub folder_path: String,
    pub subject: String,
    pub size: u64,
}

impl ItemRef {
    /// The item for message `internet_message_id` in `owner`'s folder `folder_path`
    /// (`\Inbox`, `\Sent Items`, ...), with ids stable per mailbox.
    pub fn new(
        w: &World,
        owner: &str,
        folder_path: &str,
        internet_message_id: &str,
        subject: &str,
        size: u64,
    ) -> ItemRef {
        ItemRef {
            id: item_id(w, owner, internet_message_id),
            internet_message_id: internet_message_id.to_string(),
            folder_id: folder_id(w, owner, folder_path),
            folder_path: folder_path.to_string(),
            subject: subject.to_string(),
            size,
        }
    }
}

/// The common keys of every record.
struct Head<'a> {
    record_type: RecordType,
    operation: &'a str,
    result_status: Option<&'a str>,
    user_key: String,
    user_type: i64,
    workload: &'a str,
    client_ip: Option<IpAddr>,
    object_id: Option<String>,
    user_id: &'a str,
}

fn head(w: &World, rng: &mut Rng, time: DateTime<Utc>, h: Head) -> Ual {
    let id = rng.uuid();
    let mut m = Map::new();
    m.insert("CreationTime".into(), json!(creation_time(time)));
    m.insert("Id".into(), json!(id.to_string()));
    m.insert("Operation".into(), json!(h.operation));
    m.insert("OrganizationId".into(), json!(w.org_id().to_string()));
    m.insert("RecordType".into(), json!(h.record_type.number()));
    if let Some(s) = h.result_status {
        m.insert("ResultStatus".into(), json!(s));
    }
    m.insert("UserKey".into(), json!(h.user_key));
    m.insert("UserType".into(), json!(h.user_type));
    m.insert("Version".into(), json!(1));
    m.insert("Workload".into(), json!(h.workload));
    if let Some(ip) = h.client_ip {
        m.insert("ClientIP".into(), json!(ip.to_string()));
    }
    if let Some(o) = h.object_id {
        m.insert("ObjectId".into(), json!(o));
    }
    m.insert("UserId".into(), json!(h.user_id));
    Ual {
        id,
        time,
        record_type: h.record_type,
        operation: h.operation.to_string(),
        user_id: h.user_id.to_string(),
        audit: m,
    }
}

fn put(u: &mut Ual, key: &str, v: Value) {
    u.audit.insert(key.to_string(), v);
}

fn name_value(pairs: &[(&str, &str)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(n, v)| json!({"Name": n, "Value": v}))
            .collect(),
    )
}

/// An Exchange admin cmdlet (`Set-Mailbox`, `New-InboxRule`, ...).
#[allow(clippy::too_many_arguments)]
pub fn exchange_admin(
    w: &World,
    rng: &mut Rng,
    actor: &User,
    time: DateTime<Utc>,
    cmdlet: &str,
    object_id: &str,
    params: &[(&str, &str)],
    ip: IpAddr,
    session: Uuid,
) -> Ual {
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: RecordType::ExchangeAdmin,
            operation: cmdlet,
            result_status: Some("True"),
            user_key: actor.puid.clone(),
            user_type: if actor.is_admin { 2 } else { 0 },
            workload: "Exchange",
            client_ip: Some(ip),
            object_id: Some(object_id.to_string()),
            user_id: &actor.upn,
        },
    );
    put(&mut u, "AppId", json!(""));
    put(&mut u, "ClientAppId", json!(""));
    put(&mut u, "ExternalAccess", json!(false));
    put(
        &mut u,
        "OrganizationName",
        json!(w.tenant.initial_domain.clone()),
    );
    put(&mut u, "OriginatingServer", json!(server_name(rng)));
    put(&mut u, "Parameters", name_value(params));
    put(&mut u, "SessionId", json!(session.to_string()));
    u
}

/// Operations Exchange records as `ExchangeItemGroup` (several items per record).
fn is_group_op(op: &str) -> bool {
    matches!(
        op,
        "MoveToDeletedItems" | "SoftDelete" | "HardDelete" | "Move"
    )
}

/// The mailbox-audit `LogonType`: 0 owner, 1 admin, 2 delegate.
pub fn logon_type(owner: &User, logon: &User) -> i64 {
    if owner.upn == logon.upn {
        0
    } else if logon.is_admin {
        1
    } else {
        2
    }
}

fn mailbox_keys(
    w: &World,
    rng: &mut Rng,
    u: &mut Ual,
    owner: &User,
    logon: &User,
    ip: IpAddr,
    client_info: &str,
) {
    put(u, "ClientIPAddress", json!(ip.to_string()));
    put(u, "ClientInfoString", json!(client_info));
    put(u, "ExternalAccess", json!(false));
    put(u, "InternalLogonType", json!(0));
    put(u, "LogonType", json!(logon_type(owner, logon)));
    put(u, "LogonUserSid", json!(logon.sid.clone()));
    put(u, "MailboxGuid", json!(owner.mailbox_guid.to_string()));
    put(u, "MailboxOwnerSid", json!(owner.sid.clone()));
    put(u, "MailboxOwnerUPN", json!(owner.upn.clone()));
    put(
        u,
        "OrganizationName",
        json!(w.tenant.initial_domain.clone()),
    );
    put(u, "OriginatingServer", json!(server_name(rng)));
}

/// A mailbox item operation: `ExchangeItem` for Create / Update / Send / SendAs / SendOnBehalf /
/// UpdateInboxRules / MailboxLogin, `ExchangeItemGroup` for MoveToDeletedItems / SoftDelete /
/// HardDelete / Move.
#[allow(clippy::too_many_arguments)]
pub fn mailbox_item(
    w: &World,
    rng: &mut Rng,
    owner: &User,
    logon: &User,
    time: DateTime<Utc>,
    op: &str,
    item: Option<ItemRef>,
    ip: IpAddr,
    client_info: &str,
    session: Uuid,
) -> Ual {
    let group = is_group_op(op);
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: if group {
                RecordType::ExchangeItemGroup
            } else {
                RecordType::ExchangeItem
            },
            operation: op,
            result_status: Some("Succeeded"),
            user_key: logon.puid.clone(),
            user_type: if logon_type(owner, logon) == 1 { 2 } else { 0 },
            workload: "Exchange",
            client_ip: Some(ip),
            object_id: (!group)
                .then(|| item.as_ref().map(|i| i.id.clone()))
                .flatten(),
            user_id: &logon.upn,
        },
    );
    mailbox_keys(w, rng, &mut u, owner, logon, ip, client_info);
    put(&mut u, "SessionId", json!(session.to_string()));
    if let Some(i) = item {
        let parent = json!({"Id": i.folder_id, "Path": i.folder_path});
        if group {
            put(&mut u, "Folder", parent.clone());
            if op == "MoveToDeletedItems" || op == "Move" {
                let dest = "\\Deleted Items";
                put(
                    &mut u,
                    "DestFolder",
                    json!({"Id": folder_id(w, &owner.upn, dest), "Path": dest}),
                );
            }
            put(
                &mut u,
                "AffectedItems",
                json!([{
                    "Id": i.id,
                    "InternetMessageId": i.internet_message_id,
                    "ParentFolder": parent,
                    "Subject": i.subject,
                }]),
            );
        } else {
            put(
                &mut u,
                "Item",
                json!({
                    "Id": i.id,
                    "InternetMessageId": i.internet_message_id,
                    "ParentFolder": parent,
                    "Subject": i.subject,
                    "SizeInBytes": i.size,
                }),
            );
        }
    }
    u
}

/// `MailItemsAccessed` (`ExchangeItemAggregated`): `access` is `Bind` (with the items read)
/// or `Sync` (one folder per record, no items). `folders` is (path, [(Internet message id,
/// size)]).
#[allow(clippy::too_many_arguments)]
pub fn mail_items_accessed(
    w: &World,
    rng: &mut Rng,
    owner: &User,
    time: DateTime<Utc>,
    access: &str,
    folders: &[(String, Vec<(String, u64)>)],
    ip: IpAddr,
    client_info: &str,
    app_id: Uuid,
    session: Uuid,
    throttled: bool,
) -> Ual {
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: RecordType::ExchangeItemAggregated,
            operation: "MailItemsAccessed",
            result_status: Some("Succeeded"),
            user_key: owner.puid.clone(),
            user_type: 0,
            workload: "Exchange",
            client_ip: Some(ip),
            object_id: None,
            user_id: &owner.upn,
        },
    );
    let correlation = rng.uuid();
    let token = unique_token_id(rng);
    put(
        &mut u,
        "AppAccessContext",
        json!({
            "AADSessionId": session.to_string(),
            "ClientAppId": app_id.to_string(),
            "ClientAppName": app_name(w, app_id),
            "CorrelationId": correlation.to_string(),
            "UniqueTokenId": token,
        }),
    );
    put(&mut u, "ClientAppId", json!(app_id.to_string()));
    mailbox_keys(w, rng, &mut u, owner, owner, ip, client_info);
    put(
        &mut u,
        "OperationProperties",
        name_value(&[
            ("MailAccessType", access),
            ("IsThrottled", if throttled { "True" } else { "False" }),
        ]),
    );
    put(&mut u, "SessionId", json!(session.to_string()));
    let bind = access.eq_ignore_ascii_case("Bind");
    let mut count = 0usize;
    let folders_json: Vec<Value> = folders
        .iter()
        .map(|(path, items)| {
            let mut f = Map::new();
            f.insert("Id".into(), json!(folder_id(w, &owner.upn, path)));
            f.insert("Path".into(), json!(path));
            if bind {
                count += items.len();
                f.insert(
                    "FolderItems".into(),
                    Value::Array(
                        items
                            .iter()
                            .map(|(imid, size)| {
                                json!({
                                    "Id": item_id(w, &owner.upn, imid),
                                    "InternetMessageId": imid,
                                    "SizeInBytes": size,
                                })
                            })
                            .collect(),
                    ),
                );
            } else {
                count += 1;
            }
            Value::Object(f)
        })
        .collect();
    put(&mut u, "Folders", Value::Array(folders_json));
    put(&mut u, "OperationCount", json!(count.max(1)));
    u
}

/// `LogonError` for an Entra ID sign-in error code.
fn logon_error(error: i64) -> &'static str {
    match error {
        50126 => "InvalidUserNameOrPassword",
        50074 => "UserStrongAuthClientAuthNRequiredInterrupt",
        50053 => "IdsLocked",
        50057 => "UserDisabled",
        53003 => "BlockedByConditionalAccess",
        _ => "UnknownError",
    }
}

/// The IdentityTypeValuePair list Entra ID writes for a user actor.
fn user_actor(user: &User) -> Value {
    json!([
        {"ID": user.object_id.to_string(), "Type": 0},
        {"ID": user.upn, "Type": 5},
    ])
}

/// An Entra ID sign-in as the UAL records it (`UserLoggedIn` / `UserLoginFailed`).
#[allow(clippy::too_many_arguments)]
pub fn sts_logon(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    ok: bool,
    ip: IpAddr,
    user_agent: &str,
    app_id: Uuid,
    request_type: &str,
    error: i64,
) -> Ual {
    let tenant = w.org_id().to_string();
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: RecordType::AzureActiveDirectoryStsLogon,
            operation: if ok {
                "UserLoggedIn"
            } else {
                "UserLoginFailed"
            },
            result_status: Some(if ok { "Success" } else { "Failed" }),
            user_key: user.object_id.to_string(),
            user_type: 0,
            workload: "AzureActiveDirectory",
            client_ip: Some(ip),
            object_id: Some(app_id.to_string()),
            user_id: &user.upn,
        },
    );
    put(&mut u, "Actor", user_actor(user));
    put(&mut u, "ActorContextId", json!(tenant));
    put(&mut u, "ActorIpAddress", json!(ip.to_string()));
    put(&mut u, "ApplicationId", json!(app_id.to_string()));
    put(&mut u, "AzureActiveDirectoryEventType", json!(1));
    put(
        &mut u,
        "DeviceProperties",
        name_value(&[
            ("OS", &user.client.os),
            ("BrowserType", &user.client.browser),
            ("IsCompliantAndManaged", "False"),
        ]),
    );
    put(&mut u, "ErrorNumber", json!(error.to_string()));
    put(
        &mut u,
        "ExtendedProperties",
        name_value(&[
            (
                "ResultStatusDetail",
                if ok { "Success" } else { "UserError" },
            ),
            ("UserAgent", user_agent),
            ("RequestType", request_type),
        ]),
    );
    put(&mut u, "InterSystemsId", json!(rng.uuid().to_string()));
    put(&mut u, "IntraSystemId", json!(rng.uuid().to_string()));
    if !ok {
        put(&mut u, "LogonError", json!(logon_error(error)));
    }
    put(&mut u, "ModifiedProperties", json!([]));
    put(&mut u, "SupportTicketId", json!(""));
    put(
        &mut u,
        "Target",
        json!([{"ID": app_id.to_string(), "Type": 0}]),
    );
    put(&mut u, "TargetContextId", json!(tenant));
    u
}

/// An Entra ID directory change (`Update user.`, `Add member to group.`, ...).
///
/// `target` is the IdentityTypeValuePair list as (ID, Type); a Type that parses as an integer
/// is written as a number. `ObjectId` is the last target ID (Entra ID puts the UPN or display
/// name last). `modified` is (name, old value, new value). `extra` entries are appended to
/// `ExtendedProperties`: string values as they are, other values as JSON text.
#[allow(clippy::too_many_arguments)]
pub fn aad(
    w: &World,
    rng: &mut Rng,
    actor: Option<&User>,
    time: DateTime<Utc>,
    op: &str,
    target: &[(String, String)],
    modified: &[(String, String, String)],
    ip: Option<IpAddr>,
    extra: &[(&str, Value)],
) -> Ual {
    let tenant = w.org_id().to_string();
    let service_principal = format!("ServicePrincipal_{}", rng.uuid());
    let (user_key, user_id) = match actor {
        Some(a) => (a.object_id.to_string(), a.upn.clone()),
        None => ("Not Available".to_string(), service_principal.clone()),
    };
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: RecordType::AzureActiveDirectory,
            operation: op,
            result_status: Some("Success"),
            user_key,
            user_type: match actor {
                Some(a) if a.is_admin => 2,
                Some(_) => 0,
                None => 4,
            },
            workload: "AzureActiveDirectory",
            client_ip: ip,
            object_id: target.last().map(|(id, _)| id.clone()),
            user_id: &user_id,
        },
    );
    let actor_json = match actor {
        Some(a) => json!([
            {"ID": a.upn, "Type": 5},
            {"ID": a.puid, "Type": 3},
            {"ID": format!("User_{}", a.object_id), "Type": 2},
        ]),
        None => json!([{"ID": service_principal, "Type": 2}]),
    };
    put(&mut u, "Actor", actor_json);
    put(&mut u, "ActorContextId", json!(tenant));
    if let Some(ip) = ip {
        put(&mut u, "ActorIpAddress", json!(ip.to_string()));
    }
    put(&mut u, "AzureActiveDirectoryEventType", json!(1));
    let mut ext = vec![
        json!({"Name": "additionalDetails", "Value": "{}"}),
        json!({"Name": "extendedAuditEventCategory", "Value": "User"}),
    ];
    for (name, value) in extra {
        let text = match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        ext.push(json!({"Name": name, "Value": text}));
    }
    put(&mut u, "ExtendedProperties", Value::Array(ext));
    put(
        &mut u,
        "ModifiedProperties",
        Value::Array(
            modified
                .iter()
                .map(|(name, old, new)| json!({"Name": name, "NewValue": new, "OldValue": old}))
                .collect(),
        ),
    );
    put(
        &mut u,
        "Target",
        Value::Array(
            target
                .iter()
                .map(|(id, ty)| match ty.parse::<i64>() {
                    Ok(n) => json!({"ID": id, "Type": n}),
                    Err(_) => json!({"ID": id, "Type": ty}),
                })
                .collect(),
        ),
    );
    put(&mut u, "TargetContextId", json!(tenant));
    u
}

/// Whether a SharePoint URL is a OneDrive (`-my.`) site.
fn is_onedrive(url: &str) -> bool {
    url.contains("-my.sharepoint.")
}

/// Stable (Site, WebId, ListId) GUIDs of a site.
fn site_guids(w: &World, site: &str) -> (Uuid, Uuid, Uuid) {
    let mut r = stream(w.seed, &format!("sp/{site}"));
    (r.uuid(), r.uuid(), r.uuid())
}

fn extension(file: &str) -> String {
    file.rsplit_once('.')
        .map(|(_, e)| e.to_string())
        .unwrap_or_default()
}

/// Splits a document URL into (site URL, folder relative to the site, file name).
fn split_doc_url(url: &str) -> (String, String, String) {
    let (dir, file) = url.rsplit_once('/').unwrap_or((url, ""));
    for marker in ["/sites/", "/personal/", "/teams/"] {
        if let Some(pos) = dir.find(marker) {
            let after = pos + marker.len();
            let end = dir[after..].find('/').map_or(dir.len(), |i| after + i);
            let site = &dir[..end];
            let rel = dir[end..].trim_start_matches('/');
            return (site.to_string(), rel.to_string(), file.to_string());
        }
    }
    (dir.to_string(), String::new(), file.to_string())
}

/// A SharePoint / OneDrive file operation (`FileAccessed`, `FileModified`, `FileDownloaded`,
/// ...). `site` is the site URL without a trailing `/`; `rel_folder` the folder relative to it.
#[allow(clippy::too_many_arguments)]
pub fn sharepoint_file(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    op: &str,
    site: &str,
    rel_folder: &str,
    file: &str,
    ip: IpAddr,
    user_agent: &str,
) -> Ual {
    let onedrive = is_onedrive(site);
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: if onedrive {
                RecordType::OneDrive
            } else {
                RecordType::SharePointFileOperation
            },
            operation: op,
            result_status: None,
            user_key: user.puid.clone(),
            user_type: 0,
            workload: if onedrive { "OneDrive" } else { "SharePoint" },
            client_ip: Some(ip),
            object_id: Some(format!("{site}/{rel_folder}/{file}")),
            user_id: &user.upn,
        },
    );
    let (site_id, web_id, list_id) = site_guids(w, site);
    put(&mut u, "SiteUrl", json!(format!("{site}/")));
    put(&mut u, "SourceRelativeUrl", json!(rel_folder));
    put(&mut u, "SourceFileName", json!(file));
    put(&mut u, "SourceFileExtension", json!(extension(file)));
    put(&mut u, "ItemType", json!("File"));
    put(&mut u, "UserAgent", json!(user_agent));
    put(&mut u, "EventSource", json!("SharePoint"));
    put(&mut u, "ListId", json!(list_id.to_string()));
    put(&mut u, "ListItemUniqueId", json!(rng.uuid().to_string()));
    put(&mut u, "Site", json!(site_id.to_string()));
    put(&mut u, "WebId", json!(web_id.to_string()));
    put(
        &mut u,
        "ApplicationDisplayName",
        json!("SharePoint Online Web Client Extensibility"),
    );
    u
}

/// A sharing operation (`AnonymousLinkCreated`, `CompanyLinkCreated`, `SharingSet`,
/// `SharingInvitationCreated`) on the document at `url`. `target` is (name, type: `Guest` |
/// `Member` | `Anonymous`); `permission` is `View` or `Edit`.
#[allow(clippy::too_many_arguments)]
pub fn sharing(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    op: &str,
    url: &str,
    target: Option<(&str, &str)>,
    permission: &str,
    ip: IpAddr,
) -> Ual {
    let onedrive = is_onedrive(url);
    let (site, rel, file) = split_doc_url(url);
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: RecordType::SharePointSharingOperation,
            operation: op,
            result_status: None,
            user_key: user.puid.clone(),
            user_type: 0,
            workload: if onedrive { "OneDrive" } else { "SharePoint" },
            client_ip: Some(ip),
            object_id: Some(url.to_string()),
            user_id: &user.upn,
        },
    );
    let (site_id, web_id, list_id) = site_guids(w, &site);
    put(
        &mut u,
        "EventData",
        json!(format!(
            "<Type>{permission}</Type><MembersCanShare>Enabled</MembersCanShare>"
        )),
    );
    put(&mut u, "ItemType", json!("File"));
    put(&mut u, "EventSource", json!("SharePoint"));
    put(&mut u, "ListId", json!(list_id.to_string()));
    put(&mut u, "Site", json!(site_id.to_string()));
    put(&mut u, "WebId", json!(web_id.to_string()));
    put(&mut u, "SiteUrl", json!(format!("{site}/")));
    put(&mut u, "SourceRelativeUrl", json!(rel));
    put(&mut u, "SourceFileName", json!(file));
    put(&mut u, "SourceFileExtension", json!(extension(&file)));
    if let Some((name, kind)) = target {
        put(&mut u, "TargetUserOrGroupName", json!(name));
        put(&mut u, "TargetUserOrGroupType", json!(kind));
    }
    put(&mut u, "UniqueSharingId", json!(rng.uuid().to_string()));
    u
}

/// A search query: `workload` `Exchange` gives `SearchQueryInitiatedExchange` (record type
/// ExchangeSearch, 101), `SharePoint` gives `SearchQueryInitiatedSharePoint` (SharePointSearch,
/// 102). Microsoft does not document which record type these operations carry; the search
/// record types of the Learn table are used.
pub fn search_query(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    workload: &str,
    query: &str,
    ip: IpAddr,
) -> Ual {
    let exchange = workload.eq_ignore_ascii_case("Exchange");
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: if exchange {
                RecordType::ExchangeSearch
            } else {
                RecordType::SharePointSearch
            },
            operation: if exchange {
                "SearchQueryInitiatedExchange"
            } else {
                "SearchQueryInitiatedSharePoint"
            },
            result_status: Some("Succeeded"),
            user_key: user.puid.clone(),
            user_type: 0,
            workload: if exchange { "Exchange" } else { "SharePoint" },
            client_ip: Some(ip),
            object_id: None,
            user_id: &user.upn,
        },
    );
    put(&mut u, "QueryText", json!(query));
    put(
        &mut u,
        "QuerySource",
        json!(if exchange { "OWA" } else { "SharePoint" }),
    );
    if exchange {
        put(&mut u, "MailboxGuid", json!(user.mailbox_guid.to_string()));
        put(&mut u, "MailboxOwnerUPN", json!(user.upn.clone()));
    }
    u
}

/// An eDiscovery / content search operation (`SearchCreated`, `SearchStarted`,
/// `SearchExported`, ...) on the search named `case`.
pub fn discovery(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    op: &str,
    case: &str,
    ip: IpAddr,
) -> Ual {
    let mut u = head(
        w,
        rng,
        time,
        Head {
            record_type: RecordType::Discovery,
            operation: op,
            result_status: None,
            user_key: user.puid.clone(),
            user_type: if user.is_admin { 2 } else { 0 },
            workload: "SecurityComplianceCenter",
            client_ip: Some(ip),
            object_id: Some(case.to_string()),
            user_id: &user.upn,
        },
    );
    put(&mut u, "Case", json!(case));
    put(&mut u, "ObjectType", json!("ComplianceSearch"));
    put(&mut u, "Query", json!("kind:email"));
    u
}
