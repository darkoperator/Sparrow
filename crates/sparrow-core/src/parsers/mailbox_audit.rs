//! Legacy mailbox audit log (spec 5.1 `mailbox_audit_legacy`): Search-MailboxAuditLog records
//! from Hawk 3 `Exchange_Mailbox_Audit_<user>`. Records have no id; the key hashes the fields
//! that identify one action, so the same record from JSON and CSV copies deduplicates.

use crate::Result;
use crate::db::state_tables::MAILBOX_AUDIT_LEGACY;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::{normalize_ip, normalize_upn};
use crate::normalize::ual_shape::get_ci;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, file_date_order, key_time, load_tables, lower, read_state_records, reject,
    require_any_key,
};
use crate::readers::time::{DateOrder, zone_assumed};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn register(r: &mut ParserRegistry) {
    for id in ["hawk.user.mailbox_audit_legacy", "inv.mailbox_audit_legacy"] {
        r.register(id, Box::new(MailboxAuditParser));
    }
}

const COLS: &[&str] = &[
    "event_time",
    "time_tz_assumed",
    "mailbox_upn",
    "mailbox_guid",
    "operation",
    "operation_result",
    "logon_type",
    "logon_user",
    "logon_user_sid",
    "client_ip",
    "client_info",
    "client_machine",
    "client_process",
    "external_access",
    "folder_path",
    "dest_folder_path",
    "dest_mailbox_upn",
    "cross_mailbox",
    "subjects",
    "internet_message_ids",
    "session_id",
    "app_id",
    "client_app_id",
];

fn upn(v: Option<String>) -> Option<String> {
    v.and_then(|s| normalize_upn(&s))
}

fn mailbox_upn(rec: &Rec, subject: Option<&str>) -> Option<String> {
    upn(rec.text("MailboxOwnerUPN")).or_else(|| subject.and_then(normalize_upn))
}

fn client_ip(rec: &Rec) -> Option<String> {
    rec.first_text(&["ClientIPAddress", "ClientIP"])
        .and_then(|s| normalize_ip(&s))
}

/// `direct` (the item the action touched), then `field` of every `SourceItems` entry; when the
/// record has neither, the `list` text Search-MailboxAuditLog also writes.
fn item_values(rec: &Rec, direct: &str, field: &str, list: &str) -> Vec<String> {
    let mut out: Vec<String> = rec.text(direct).into_iter().collect();
    if let Some(Value::Array(items)) = get_ci(rec.map(), "SourceItems") {
        for item in items.iter().filter_map(Value::as_object) {
            if let Some(v) = Rec::new(item, false).text(field) {
                if !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    if out.is_empty() {
        out.extend(rec.text(list));
    }
    out
}

/// mailbox_audit_legacy.record_key (see the table COMMENT).
pub fn mailbox_audit_key(
    rec: &Rec,
    subject: Option<&str>,
    order: Option<DateOrder>,
) -> Option<String> {
    let time = rec.text("LastAccessed")?;
    let operation = rec.text("Operation")?;
    let mailbox = lower(rec.text("MailboxGuid"))
        .or_else(|| mailbox_upn(rec, subject))
        .unwrap_or_default();
    let parts = [
        "mailbox_audit".to_string(),
        key_time(&time, order),
        operation.to_lowercase(),
        mailbox,
        lower(rec.text("LogonUserSid")).unwrap_or_default(),
        client_ip(rec).unwrap_or_default(),
        item_values(rec, "ItemId", "Id", "SourceItemIdsList")
            .join(",")
            .to_lowercase(),
        lower(rec.text("FolderId")).unwrap_or_default(),
        lower(rec.text("SessionId")).unwrap_or_default(),
        lower(rec.text("OperationResult")).unwrap_or_default(),
    ];
    Some(hex::encode(Sha256::digest(parts.join("\n").as_bytes())))
}

pub struct MailboxAuditParser;

impl ArtifactParser for MailboxAuditParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let subject = ctx.subject.map(str::to_string);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["LastAccessed"], "Search-MailboxAuditLog")?;
        let times: Vec<String> = records
            .iter()
            .filter_map(|r| Rec::new(&r.map, format.lossy()).text("LastAccessed"))
            .collect();
        let order = file_date_order(ctx, times.iter().map(String::as_str))?;
        let mut rows = TableRows::new(&MAILBOX_AUDIT_LEGACY, COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = mailbox_audit_key(&rec, subject.as_deref(), order) else {
                reject(
                    ctx,
                    r,
                    "mailbox audit record has no LastAccessed or Operation",
                )?;
                continue;
            };
            let time = rec.text("LastAccessed");
            let mut c = CellRow::new(COLS);
            c.set(
                "time_tz_assumed",
                Cell::bool(time.as_deref().map(zone_assumed)),
            )
            .set("event_time", Cell::time(time))
            .set(
                "mailbox_upn",
                Cell::text(mailbox_upn(&rec, subject.as_deref())),
            )
            .set("mailbox_guid", Cell::text(lower(rec.text("MailboxGuid"))))
            .set("operation", Cell::text(rec.text("Operation")))
            .set("operation_result", Cell::text(rec.text("OperationResult")))
            .set("logon_type", Cell::text(rec.text("LogonType")))
            .set("logon_user", Cell::text(rec.text("LogonUserDisplayName")))
            .set("logon_user_sid", Cell::text(rec.text("LogonUserSid")))
            .set("client_ip", Cell::text(client_ip(&rec)))
            .set("client_info", Cell::text(rec.text("ClientInfoString")))
            .set("client_machine", Cell::text(rec.text("ClientMachineName")))
            .set("client_process", Cell::text(rec.text("ClientProcessName")))
            .set("external_access", Cell::bool(rec.bool("ExternalAccess")))
            .set("folder_path", Cell::text(rec.text("FolderPathName")))
            .set(
                "dest_folder_path",
                Cell::text(rec.text("DestFolderPathName")),
            )
            .set(
                "dest_mailbox_upn",
                Cell::text(upn(rec.text("DestMailboxOwnerUPN"))),
            )
            .set(
                "cross_mailbox",
                Cell::bool(rec.bool("CrossMailboxOperation")),
            )
            .set(
                "subjects",
                Cell::list(item_values(
                    &rec,
                    "ItemSubject",
                    "Subject",
                    "SourceItemSubjectsList",
                )),
            )
            .set(
                "internet_message_ids",
                Cell::list(item_values(
                    &rec,
                    "ItemInternetMessageId",
                    "InternetMessageId",
                    "SourceItemInternetMessageIdsList",
                )),
            )
            .set("session_id", Cell::text(rec.text("SessionId")))
            .set("app_id", Cell::text(lower(rec.text("AppId"))))
            .set("client_app_id", Cell::text(lower(rec.text("ClientAppId"))));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
