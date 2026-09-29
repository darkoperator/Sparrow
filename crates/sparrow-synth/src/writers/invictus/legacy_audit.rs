//! Get-MailboxAuditLogLegacy (research event layouts §4): one
//! `Mailbox Audit Log/<ts>-Legacy/<yyyyMMddHHmm>-mailboxAuditLog-<upn>.csv` per mailbox, 0-byte
//! when that mailbox had no hits.

use super::Ctx;
use crate::Result;
use crate::events::RecordType;
use crate::ps::{DateEvidence, DtKind, PsDate, Row, Val, export_csv};
use crate::tree::{FileSpec, Tree};
use serde_json::{Value, json};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn s(v: impl Into<String>) -> Val {
    Val::Str(v.into())
}

fn opt(v: Option<String>) -> Val {
    v.map_or(Val::Null, Val::Str)
}

fn audit_text(u: &crate::events::Ual, key: &str) -> Option<String> {
    u.audit.get(key).and_then(Value::as_str).map(str::to_string)
}

fn logon_type_name(n: i64) -> &'static str {
    match n {
        1 => "Admin",
        2 => "Delegate",
        _ => "Owner",
    }
}

type MailboxAuditId = (i64, String, String, String, String, String, String, String);

fn mailbox_audit_row(world: &crate::world::World, u: &crate::events::Ual) -> (Row, MailboxAuditId) {
    let a = &u.audit;
    let text = |k: &str| audit_text(u, k);
    let sub = |v: Option<&Value>, k: &str| {
        v.and_then(|x| x.get(k))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let item = a.get("Item");
    let folder = a
        .get("Folder")
        .or_else(|| item.and_then(|i| i.get("ParentFolder")));
    let dest = a.get("DestFolder");
    let affected: Vec<&Value> = a
        .get("AffectedItems")
        .and_then(Value::as_array)
        .map(|v| v.iter().collect())
        .unwrap_or_default();
    let list = |k: &str| {
        let v: Vec<String> = affected
            .iter()
            .filter_map(|x| x.get(k).and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        if v.is_empty() {
            None
        } else {
            Some(v.join(", "))
        }
    };
    let source_items: Vec<Value> = affected
        .iter()
        .map(|x| {
            json!({
                "Id": x.get("Id"),
                "Subject": x.get("Subject"),
                "InternetMessageId": x.get("InternetMessageId"),
                "FolderPathName": x.get("ParentFolder").and_then(|p| p.get("Path")),
            })
        })
        .collect();
    let logon = world.user_by_upn(&u.user_id);
    let logon_type = logon_type_name(a.get("LogonType").and_then(Value::as_i64).unwrap_or(0));
    let owner = text("MailboxOwnerUPN").unwrap_or_default();
    let owner_name = world.user_by_upn(&owner).map(|o| o.display_name.clone());
    let ip = text("ClientIPAddress").or_else(|| text("ClientIP"));
    let item_id = sub(item, "Id");
    let folder_id = sub(folder, "Id");
    let session = text("SessionId");
    let guid = text("MailboxGuid");
    let row = vec![
        r("Operation", s(u.operation.clone())),
        r("OperationResult", s("Succeeded")),
        r("LogonType", s(logon_type)),
        r(
            "ExternalAccess",
            Val::Bool(
                a.get("ExternalAccess")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
        r("DestFolderId", opt(sub(dest, "Id"))),
        r("DestFolderPathName", opt(sub(dest, "Path"))),
        r("FolderId", opt(folder_id.clone())),
        r("FolderPathName", opt(sub(folder, "Path"))),
        r("FolderName", Val::Null),
        r("MemberRights", Val::Null),
        r("MemberSid", Val::Null),
        r("MemberUpn", Val::Null),
        r("ClientInfoString", opt(text("ClientInfoString"))),
        r("ClientIPAddress", opt(ip.clone())),
        r("ClientIP", opt(ip.clone())),
        r("ClientMachineName", Val::Null),
        r("ClientProcessName", Val::Null),
        r("ClientVersion", Val::Null),
        r("InternalLogonType", s(logon_type)),
        r("MailboxOwnerUPN", s(owner.clone())),
        r("MailboxOwnerSid", opt(text("MailboxOwnerSid"))),
        r("DestMailboxOwnerUPN", Val::Null),
        r("DestMailboxOwnerSid", Val::Null),
        r("DestMailboxGuid", Val::Null),
        r("CrossMailboxOperation", Val::Null),
        r(
            "LogonUserDisplayName",
            opt(logon.map(|l| l.display_name.clone())),
        ),
        r("LogonUserSid", opt(text("LogonUserSid"))),
        r("SourceItems", Val::Raw(Value::Array(source_items))),
        r("SourceFolders", Val::Raw(json!([]))),
        r("SourceItemIdsList", opt(list("Id"))),
        r("SourceItemSubjectsList", opt(list("Subject"))),
        r("SourceItemAttachmentsList", Val::Null),
        r("SourceItemFolderPathNamesList", Val::Null),
        r("SourceFolderPathNamesList", Val::Null),
        r(
            "SourceItemInternetMessageIdsList",
            opt(list("InternetMessageId")),
        ),
        r("ItemId", opt(item_id.clone())),
        r("ItemSubject", opt(sub(item, "Subject"))),
        r("ItemAttachments", Val::Null),
        r("ItemInternetMessageId", opt(sub(item, "InternetMessageId"))),
        r("DirtyProperties", Val::Null),
        r("OriginatingServer", opt(text("OriginatingServer"))),
        r("SessionId", opt(session.clone())),
        r("OperationProperties", Val::Raw(json!([]))),
        r("AuditOperationsCountInAggregatedRecord", Val::Null),
        r("AggregatedRecordFoldersData", Val::Null),
        r("AppId", opt(text("AppId"))),
        r("ClientAppId", opt(text("ClientAppId"))),
        r("ItemIsRecord", Val::Bool(false)),
        r("ItemComplianceLabel", Val::Null),
        r("MailboxGuid", opt(guid.clone())),
        r("MailboxResolvedOwnerName", opt(owner_name)),
        r(
            "LastAccessed",
            Val::Date(PsDate::dotnet(u.time, DtKind::Local)),
        ),
        r(
            "Identity",
            s(format!(
                "{}\\{}",
                guid.clone().unwrap_or_default(),
                u.id.simple()
            )),
        ),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", s("Unchanged")),
    ];
    let mut ids: Vec<String> = item_id.into_iter().collect();
    for x in &affected {
        if let Some(i) = x.get("Id").and_then(Value::as_str) {
            if !ids.iter().any(|y| y == i) {
                ids.push(i.to_string());
            }
        }
    }
    let lower = |v: Option<String>| v.unwrap_or_default().to_lowercase();
    let id = (
        u.time.timestamp(),
        u.operation.to_lowercase(),
        lower(guid),
        lower(text("LogonUserSid")),
        ip.map(|a| a.parse::<IpAddr>().map_or(a, |p| p.to_string()))
            .unwrap_or_default(),
        ids.join(",").to_lowercase(),
        lower(folder_id),
        lower(session),
    );
    (row, id)
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Mailbox Audit Log", Some("Legacy"));
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let since = c.world.collected_at() - chrono::Duration::days(90);
    // One pass over the days: group the ExchangeItem(Group) records by their owner, so each
    // mailbox is not a separate scan of the window.
    let mut by_owner: BTreeMap<String, Vec<crate::events::Ual>> = BTreeMap::new();
    for d in c.days() {
        for u in d.ual {
            if u.time < since
                || !matches!(
                    u.record_type,
                    RecordType::ExchangeItem | RecordType::ExchangeItemGroup
                )
            {
                continue;
            }
            if let Some(o) = u.audit.get("MailboxOwnerUPN").and_then(Value::as_str) {
                by_owner.entry(o.to_lowercase()).or_default().push(u);
            }
        }
    }
    for mailbox in c.world.mailboxes.values() {
        let mut records: Vec<&crate::events::Ual> = by_owner
            .get(&mailbox.upn.to_lowercase())
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        records.sort_by_key(|u| Reverse((u.time, u.id)));
        let rel = format!(
            "{dir}/{}-mailboxAuditLog-{}.csv",
            run.local.format("%Y%m%d%H%M"),
            mailbox.upn
        );
        if records.is_empty() {
            tree.write(
                &FileSpec::new(&rel, Some("inv.mailbox_audit_legacy"), c.utf8()),
                "",
            )?;
            continue;
        }
        let rows: Vec<(Row, MailboxAuditId)> = records
            .iter()
            .map(|u| mailbox_audit_row(c.world, u))
            .collect();
        let distinct = rows
            .iter()
            .map(|(_, id)| id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let rows: Vec<Row> = rows.into_iter().map(|(row, _)| row).collect();
        let mut ev = DateEvidence::default();
        let rendered = export_csv(&c.host, &rows, &mut ev);
        tree.write(
            &FileSpec::new(&rel, Some("inv.mailbox_audit_legacy"), c.utf8()),
            &rendered.text,
        )?;
        if ev.culture_dates > 0 {
            tree.date_evidence(&rel, ev);
        }
        tree.rows_counted(&rel, "mailbox_audit_legacy", distinct);
    }
    Ok(())
}
