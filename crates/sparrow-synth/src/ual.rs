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
use chrono::{DateTime, Duration, Utc};
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

/// The inferred `UserAuthenticationMethod` codes of a sign-in that went through a credential
/// prompt (see `sts_logon`): the property is undocumented, so these are this generator's own
/// codes, not values read from a capture.
const USER_AUTH_METHOD_CODES: &[i64] = &[1, 2, 3];

/// The share of successful authentications the captures record the "Stay signed in?" flag on
/// (about 1-2% of the records).
const KEEP_ME_SIGNED_IN_SHARE: f64 = 0.02;

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

/// The application id an Exchange client session runs under: a tenant app where the world
/// has one, else a well-known Microsoft client id, else a synthetic uuid. The Management
/// Activity API records it as `ClientAppId` and `HostAppId` (office-365-management-api-schema).
pub fn host_app_id(rng: &mut Rng) -> Uuid {
    if !WELL_KNOWN_GUIDS.is_empty() {
        // The first well-known id, so the value stays stable and reserved.
        if let Ok(id) = WELL_KNOWN_GUIDS[0].0.parse::<Uuid>() {
            return id;
        }
    }
    rng.uuid()
}

/// The Outlook app-access API id an Exchange client calls, recorded as
/// `AppAccessContext.APIId` (office-365-management-api-schema). A fixed reserved id, so the
/// value is stable.
const APP_ACCESS_API_ID: Uuid = Uuid::from_u128(0x9e5f94bc_e2b0_4a3f_9b4a_7c0f1b2a3d4e);

/// A neutral attachment summary for an item. The Management Activity API records
/// `Item.Attachments` as one string listing the attachment names, not an object array
/// (office-365-management-api-schema), so the flattened files carry the bare
/// `Item_Attachments` / `AffectedItems_Attachments` column rather than per-attachment keys
/// (an array of objects would descend to `Item_Attachments_Name`, research §4.2).
fn attachments(rng: &mut Rng) -> String {
    let n = rng.below(2) + 1;
    (0..n)
        .map(|i| format!("attachment-{i}.pdf"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A neutral message subject for a folder item the aggregated record refers to by id alone.
fn subject_for(rng: &mut Rng, imid: &str) -> String {
    const SUBJECTS: &[&str] = &[
        "Weekly report",
        "Invoice",
        "Project update",
        "Re: schedule",
        "Notes",
    ];
    let tail = &imid[imid.len().saturating_sub(8)..];
    format!("{} {}", rng.pick(SUBJECTS), tail)
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
    /// The item's `EID`-style immutable id, which the Management Activity API records beside
    /// `Id` (`office-365-management-api-schema`, `Item.ImmutableId`). Distinct per item, so the
    /// flattened files carry `Item_ImmutableId`.
    pub immutable_id: String,
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
            immutable_id: {
                let mut r = stream(w.seed, &format!("immutable/{owner}/{internet_message_id}"));
                chars(&mut r, B64, 40)
            },
            internet_message_id: internet_message_id.to_string(),
            folder_id: folder_id(w, owner, folder_path),
            folder_path: folder_path.to_string(),
            subject: subject.to_string(),
            size,
        }
    }
}

/// A folder path's display name: `\Sent Items` -> `Sent Items`.
pub fn folder_name(path: &str) -> String {
    path.trim_start_matches('\\').to_string()
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
    put(&mut u, "ExchangeVersion", json!(15));
    let app = host_app_id(rng);
    token_context(&mut u, rng, w, app, session, time, None);
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

/// The token / app-access context an Exchange session runs under, plus the request
/// correlation ids and the token object the Management Activity API records beside it
/// (https://learn.microsoft.com/office/office-365-management-api/office-365-management-api-schema,
/// `AppAccessContext`, `AppPoolName`, `TokenObjectId`, `TokenTenantId`, `TokenType`,
/// `CorrelationID`, `RequestId`). Microsoft emits them on the Exchange workloads; the real
/// Hawk captures' flattened files carry them all.
fn token_context(
    u: &mut Ual,
    rng: &mut Rng,
    w: &World,
    app_id: Uuid,
    session: Uuid,
    issued: DateTime<Utc>,
    api_id: Option<Uuid>,
) {
    let correlation = rng.uuid();
    let request = rng.uuid();
    let mut ctx = Map::new();
    ctx.insert("AADSessionId".into(), json!(session.to_string()));
    ctx.insert("APIId".into(), json!(api_id.map(|a| a.to_string())));
    ctx.insert("ClientAppId".into(), json!(app_id.to_string()));
    ctx.insert("ClientAppName".into(), json!(app_name(w, app_id)));
    ctx.insert("CorrelationId".into(), json!(correlation.to_string()));
    ctx.insert("IssuedAtTime".into(), json!(issued.to_rfc3339()));
    ctx.insert("UniqueTokenId".into(), json!(unique_token_id(rng)));
    put(u, "AppAccessContext", Value::Object(ctx));
    put(u, "AppPoolName", json!(app_name(w, app_id)));
    put(u, "ClientAppId", json!(app_id.to_string()));
    put(u, "CorrelationID", json!(correlation.to_string()));
    put(u, "RequestId", json!(request.to_string()));
    put(u, "TokenObjectId", json!(rng.uuid().to_string()));
    put(u, "TokenTenantId", json!(w.org_id().to_string()));
    put(u, "TokenType", json!("User"));
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
    // The Outlook desktop client detail the Management Activity API records beside
    // `ClientInfoString` for an `ExchangeItem` / `ExchangeItemGroup`
    // (office-365-management-api-schema: `ClientProcessName`, `ClientRequestId`,
    // `ClientVersion`, `HostAppId`, `SaveToSentItems`).
    put(u, "ClientProcessName", json!("OUTLOOK.EXE"));
    put(u, "ClientRequestId", json!(rng.uuid().to_string()));
    put(u, "ClientVersion", json!("16.0.17928.0"));
    put(u, "HostAppId", json!(host_app_id(rng).to_string()));
    put(u, "SaveToSentItems", json!(true));
    put(u, "CrossMailboxOperation", json!(false));
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
    let app = host_app_id(rng);
    token_context(&mut u, rng, w, app, session, time, None);
    put(&mut u, "ActorInfoString", json!(logon.upn.clone()));
    // The property-change list the Management Activity API records on an Exchange operation
    // (office-365-management-api-schema `ModifiedProperties`). The real captures keep it as the
    // embedded JSON text the audit service sent, not as an object (survey §2c, "some
    // `Settings_*` and `DataSources` values are still embedded JSON strings"), so the flattened
    // files carry the bare `ModifiedProperties` column instead of `ModifiedProperties_Name`.
    put(
        &mut u,
        "ModifiedProperties",
        json!(
            json!([{
                "Name": "Item",
                "OldValue": "",
                "NewValue": item.as_ref().map_or("", |i| i.subject.as_str()),
            }])
            .to_string()
        ),
    );
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
                    "Attachments": attachments(rng),
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
                    "Attachments": attachments(rng),
                    "Id": i.id,
                    "ImmutableId": i.immutable_id,
                    "InternetMessageId": i.internet_message_id,
                    "IsRecord": false,
                    "ParentFolder": {
                        "Id": i.folder_id,
                        "Name": folder_name(&i.folder_path),
                        "Path": i.folder_path,
                    },
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
    token_context(
        &mut u,
        rng,
        w,
        app_id,
        session,
        time,
        Some(APP_ACCESS_API_ID),
    );
    mailbox_keys(w, rng, &mut u, owner, owner, ip, client_info);
    // The auth method the aggregated record reports
    // (office-365-management-api-schema, `MailItemsAccessed.AuthType`).
    put(&mut u, "AuthType", json!("OAuth"));
    // The aggregate's own property list. Two entries share a name, so the flattened files
    // carry `ExtendedProperties_Name` and `ExtendedProperties_Name_1` (research §4.2).
    put(
        &mut u,
        "ExtendedProperties",
        json!([
            {"Name": "MailboxOwner", "Value": owner.upn},
            {"Name": "Folder", "Value": "\\Inbox"},
            {"Name": "Folder", "Value": "\\Inbox"},
        ]),
    );
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
                                // The full item detail the Management Activity API records per
                                // folder item (office-365-management-api-schema,
                                // `MailItemsAccessed.Folders.FolderItems`): `CreationTime` and
                                // `ImmutableId` sit beside `Id` / `InternetMessageId` /
                                // `SizeInBytes`, and the flattened files carry
                                // `Folders_FolderItems_*` for each.
                                let mut r = stream(w.seed, &format!("mia/{}/{imid}", owner.upn));
                                json!({
                                    "CreationTime": creation_time(time - Duration::days(r.below(30) as i64)),
                                    "Id": item_id(w, &owner.upn, imid),
                                    "ImmutableId": chars(&mut r, B64, 40),
                                    "InternetMessageId": imid,
                                    "SizeInBytes": size,
                                    "Subject": subject_for(&mut r, imid),
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
/// `authentication_method`: the record carries the sign-in's authentication method. Every
/// failed logon does (the captures: `UserLoginFailed` + `Failed` holds one on ~96% of the
/// rows); a successful one does when it is the user's first sign-in of that day, the
/// fresh-authentication case (the captures hold one on 0-57% of `UserLoggedIn` + `Success`
/// rows, depending on the tenant), and not on the later same-day sign-ins the session it
/// opened let through.
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
    authentication_method: bool,
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
    // The sign-in session properties the Management Activity API records for an StsLogon (they
    // reach the files through `Converted_Authentication_Logs`, which expands the AuditData
    // properties; survey §2e), typed the way the captures hold them:
    // - `UserAuthenticationMethod` is a number on a failed logon and on a user's first
    //   sign-in of the day, and empty on the rest (see `sts_logon`'s `authentication_method`).
    //   The codes are inferred: the property is not documented on Microsoft Learn and no value
    //   was read from a capture, so they are this generator's own small set.
    // - `KeepMeSignedIn` is a boolean only where the "Stay signed in?" prompt was shown, which
    //   the captures record for about 1-2% of the records, and empty otherwise. The prompt
    //   follows a successful authentication -- a failed logon has no session to keep -- and the
    //   user answers it either way, so both boolean values occur.
    // - `ZipCode` is the postal code the geo lookup resolved; the captures hold it empty (and
    //   older ones do not have it at all), and the synthetic world has no postal codes.
    if authentication_method {
        // A stream of its own, keyed by the record: drawing from `rng` would move every value
        // the rest of the record (and the world behind it) uses.
        let mut p = stream(w.seed, &format!("stslogon/{}", u.id));
        put(
            &mut u,
            "UserAuthenticationMethod",
            json!(*p.pick(USER_AUTH_METHOD_CODES)),
        );
        if ok && p.chance(KEEP_ME_SIGNED_IN_SHARE) {
            put(&mut u, "KeepMeSignedIn", json!(*p.pick(&[true, false])));
        } else {
            put(&mut u, "KeepMeSignedIn", json!(""));
        }
    } else {
        put(&mut u, "UserAuthenticationMethod", json!(""));
        put(&mut u, "KeepMeSignedIn", json!(""));
    }
    put(&mut u, "ZipCode", json!(""));
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
    // An interactive sign-in reports the same name twice, so `ConvertTo-FlatObject` suffixes
    // the second with `_1` (research hawk layouts §4.2): the real captures carry
    // `ExtendedProperties_Name` / `ExtendedProperties_Name_1` / `ExtendedProperties_Value_2`.
    if let Some(a) = actor {
        ext.push(json!({"Name": "ClientAppUsed", "Value": a.client.browser.clone()}));
        ext.push(json!({"Name": "ClientAppUsed", "Value": a.client.browser.clone()}));
    }
    for (name, value) in extra {
        let text = match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        ext.push(json!({"Name": name, "Value": text}));
    }
    put(&mut u, "ExtendedProperties", Value::Array(ext));
    // The target's object types and the device the change came from
    // (office-365-management-api-schema, AzureActiveDirectory: `Object1Type`, `Object2Type`,
    // `DeviceId`).
    put(&mut u, "Object1Type", json!("User"));
    put(
        &mut u,
        "Object2Type",
        json!(if actor.is_some() {
            "User"
        } else {
            "ServicePrincipal"
        }),
    );
    put(
        &mut u,
        "DeviceId",
        json!(actor.map(|a| a.object_id.to_string()).unwrap_or_default()),
    );
    put(&mut u, "Scope", json!("Directory.ReadWrite.All"));
    // The workload locations an admin change reports (office-365-management-api-schema,
    // `ExchangeLocations`, `SharepointLocations`, `PublicFolderLocations`).
    put(
        &mut u,
        "ExchangeLocations",
        json!([w.tenant.initial_domain.clone()]),
    );
    put(
        &mut u,
        "SharepointLocations",
        json!([format!(
            "https://{}.sharepoint.example/sites/Finance",
            w.tenant.folder_name.to_lowercase()
        )]),
    );
    put(&mut u, "PublicFolderLocations", json!([""]));
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
            result_status: Some("Success"),
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
            result_status: Some("Success"),
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
            result_status: Some("Success"),
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
    // A content search runs under a token like the other Exchange records, and reports the
    // object types and locations it touched (office-365-management-api-schema, the
    // SecurityComplianceCenter workload: `AppAccessContext`, `ExtendedProperties`,
    // `Object1Type`, `Object2Type`, `DeviceId`, `Scope`, `ExchangeLocations`,
    // `SharepointLocations`, `PublicFolderLocations`). The repeated `ExtendedProperties` name
    // is what gives the flattened files their `_1` / `_2` suffixes (research §4.2).
    let app = host_app_id(rng);
    let aad_session = rng.uuid();
    token_context(
        &mut u,
        rng,
        w,
        app,
        aad_session,
        time,
        Some(APP_ACCESS_API_ID),
    );
    put(
        &mut u,
        "ExtendedProperties",
        json!([
            {"Name": "ListPath", "Value": "/Cases"},
            {"Name": "ListItem", "Value": case},
            {"Name": "ListItem", "Value": case},
        ]),
    );
    put(&mut u, "Object1Type", json!("ComplianceSearch"));
    put(&mut u, "Object2Type", json!("Case"));
    put(&mut u, "DeviceId", json!(user.object_id.to_string()));
    put(&mut u, "Scope", json!("Case"));
    put(
        &mut u,
        "ExchangeLocations",
        json!([w.tenant.initial_domain.clone()]),
    );
    put(
        &mut u,
        "SharepointLocations",
        json!([format!(
            "https://{}.sharepoint.example/sites/Finance",
            w.tenant.folder_name.to_lowercase()
        )]),
    );
    put(&mut u, "PublicFolderLocations", json!([""]));
    u
}
