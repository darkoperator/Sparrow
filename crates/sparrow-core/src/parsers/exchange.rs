//! Exchange state: inbox rules (Get-InboxRule) and sweep rules (Get-SweepRule), mobile
//! devices (Get-MobileDevice), transport rules and remote domains.

use crate::Result;
use crate::db::state_tables::{INBOX_RULES, MOBILE_DEVICES, REMOTE_DOMAINS, TRANSPORT_RULES};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::normalize_upn;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    TableRows, collection_key, load_tables, lower, read_state_records, reject, require_any_key,
};

pub fn register(r: &mut ParserRegistry) {
    r.register(
        "hawk.user.inbox_rules",
        Box::new(RulesParser { kind: "inbox" }),
    );
    r.register(
        "hawk.tenant.all_inbox_rules",
        Box::new(RulesParser { kind: "inbox" }),
    );
    r.register(
        "hawk.user.sweep_rules",
        Box::new(RulesParser { kind: "sweep" }),
    );
    r.register(
        "hawk.tenant.all_sweep_rules",
        Box::new(RulesParser { kind: "sweep" }),
    );
    r.register("hawk.user.mobile_devices", Box::new(MobileDevicesParser));
    r.register(
        "hawk.tenant.transport_rules",
        Box::new(TransportRulesParser),
    );
    r.register("hawk.tenant.remote_domain", Box::new(RemoteDomainsParser));
}

fn folder_upn(subject: Option<&str>) -> Option<String> {
    subject.and_then(normalize_upn)
}

fn rule_mailbox(rec: &Rec, subject: Option<&str>) -> Option<String> {
    lower(rec.text("MailboxOwnerId")).or_else(|| folder_upn(subject))
}

fn rule_identity(rec: &Rec) -> Option<String> {
    rec.first_text(&["RuleIdentity", "RuleId", "Identity", "Name"])
}

/// inbox_rules.record_key: kind|mailbox|rule. MailboxOwnerId is the same in tenant-wide and
/// per-user copies, so both land on one row.
pub fn inbox_rule_key(kind: &str, rec: &Rec, subject: Option<&str>) -> Option<String> {
    let mailbox = rule_mailbox(rec, subject)?;
    let rule = rule_identity(rec)?;
    Some(format!("{kind}|{mailbox}|{rule}"))
}

const INBOX_COLS: &[&str] = &[
    "kind",
    "mailbox",
    "mailbox_upn",
    "rule_identity",
    "name",
    "enabled",
    "in_error",
    "priority",
    "forward_to",
    "forward_as_attachment_to",
    "redirect_to",
    "delete_message",
    "soft_delete",
    "move_to_folder",
    "copy_to_folder",
    "mark_as_read",
    "stop_processing",
    "from_addresses",
    "subject_contains",
    "body_contains",
    "subject_or_body_contains",
    "has_attachment",
    "description",
];
const SWEEP_COLS: &[&str] = &[
    "kind",
    "mailbox",
    "mailbox_upn",
    "rule_identity",
    "name",
    "enabled",
    "move_to_folder",
    "source_folder",
    "from_addresses",
];

pub struct RulesParser {
    pub kind: &'static str,
}

impl ArtifactParser for RulesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let subject = ctx.subject;
        let sweep = self.kind == "sweep";
        let records = read_state_records(ctx, format)?;
        let shape: &[&str] = if sweep {
            &["RuleId", "Identity", "MailboxOwnerId"]
        } else {
            // Rule properties too: Hawk's per-user files may lack every identity column.
            &[
                "RuleIdentity",
                "Identity",
                "MailboxOwnerId",
                "ForwardTo",
                "DeleteMessage",
                "RedirectTo",
            ]
        };
        require_any_key(&records, shape, &format!("{} rule", self.kind))?;
        let mut rows = TableRows::new(&INBOX_RULES, if sweep { SWEEP_COLS } else { INBOX_COLS });
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = inbox_rule_key(self.kind, &rec, subject) else {
                reject(
                    ctx,
                    r,
                    "rule has no mailbox (MailboxOwnerId or user folder) or identity",
                )?;
                continue;
            };
            let mut cells = vec![
                Cell::text(Some(self.kind.into())),
                Cell::text(rule_mailbox(&rec, subject)),
                Cell::text(folder_upn(subject)),
                Cell::text(rule_identity(&rec)),
                Cell::text(rec.text("Name")),
                Cell::bool(rec.bool("Enabled")),
            ];
            if sweep {
                cells.extend([
                    Cell::text(rec.text("DestinationFolder")),
                    Cell::text(rec.text("SourceFolder")),
                    Cell::list(rec.list("Sender")),
                ]);
            } else {
                cells.extend([
                    Cell::bool(rec.bool("InError")),
                    Cell::int(rec.int("Priority")),
                    Cell::list(rec.list("ForwardTo")),
                    Cell::list(rec.list("ForwardAsAttachmentTo")),
                    Cell::list(rec.list("RedirectTo")),
                    Cell::bool(rec.bool("DeleteMessage")),
                    Cell::bool(rec.bool("SoftDeleteMessage")),
                    Cell::text(rec.text("MoveToFolder")),
                    Cell::text(rec.text("CopyToFolder")),
                    Cell::bool(rec.bool("MarkAsRead")),
                    Cell::bool(rec.bool("StopProcessingRules")),
                    Cell::list(rec.list("From")),
                    Cell::list(rec.list("SubjectContainsWords")),
                    Cell::list(rec.list("BodyContainsWords")),
                    Cell::list(rec.list("SubjectOrBodyContainsWords")),
                    Cell::bool(rec.bool("HasAttachment")),
                    Cell::text(rec.text("Description")),
                ]);
            }
            rows.push(r, key, cells);
        }
        load_tables(ctx, vec![rows])
    }
}

/// mobile_devices.record_key: lower folder UPN|lower DeviceId.
pub fn mobile_device_key(rec: &Rec, subject: Option<&str>) -> Option<String> {
    let mailbox = folder_upn(subject)?;
    let id = rec.text("DeviceId")?.to_lowercase();
    Some(format!("{mailbox}|{id}"))
}

const DEVICE_COLS: &[&str] = &[
    "mailbox",
    "device_id",
    "friendly_name",
    "device_type",
    "model",
    "os",
    "user_agent",
    "client_type",
    "first_sync",
    "access_state",
    "access_state_reason",
    "is_managed",
    "is_compliant",
    "is_disabled",
    "when_created",
];

pub struct MobileDevicesParser;

impl ArtifactParser for MobileDevicesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let subject = ctx.subject;
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&MOBILE_DEVICES, DEVICE_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = mobile_device_key(&rec, subject) else {
                reject(ctx, r, "mobile device has no DeviceId or user folder")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(folder_upn(subject)),
                    Cell::text(rec.text("DeviceId")),
                    Cell::text(rec.text("FriendlyName")),
                    Cell::text(rec.text("DeviceType")),
                    Cell::text(rec.text("DeviceModel")),
                    Cell::text(rec.text("DeviceOS")),
                    Cell::text(rec.text("DeviceUserAgent")),
                    Cell::text(rec.text("ClientType")),
                    Cell::time(rec.text("FirstSyncTime")),
                    Cell::text(rec.text("DeviceAccessState")),
                    Cell::text(rec.text("DeviceAccessStateReason")),
                    Cell::bool(rec.bool("IsManaged")),
                    Cell::bool(rec.bool("IsCompliant")),
                    Cell::bool(rec.bool("IsDisabled")),
                    Cell::time(rec.first_text(&["WhenCreatedUTC", "WhenCreated"])),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

const TRANSPORT_COLS: &[&str] = &[
    "name",
    "guid",
    "state",
    "mode",
    "priority",
    "created_by",
    "last_modified_by",
    "when_changed",
    "description",
    "conditions",
    "exceptions",
    "actions",
    "redirect_to",
    "blind_copy_to",
    "copy_to",
    "add_to_recipients",
];

pub struct TransportRulesParser;

impl ArtifactParser for TransportRulesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&TRANSPORT_RULES, TRANSPORT_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = lower(rec.text("Name")).map(|n| collection_key(ctx.collection_id, &n))
            else {
                reject(ctx, r, "transport rule has no Name")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(rec.text("Name")),
                    Cell::text(lower(rec.text("Guid"))),
                    Cell::text(rec.text("State")),
                    Cell::text(rec.text("Mode")),
                    Cell::int(rec.int("Priority")),
                    Cell::text(rec.text("CreatedBy")),
                    Cell::text(rec.text("LastModifiedBy")),
                    Cell::time(rec.first_text(&["WhenChangedUTC", "WhenChanged"])),
                    Cell::text(rec.text("Description")),
                    Cell::json(rec.json("Conditions")),
                    Cell::json(rec.json("Exceptions")),
                    Cell::json(rec.json("Actions")),
                    Cell::list(rec.list("RedirectMessageTo")),
                    Cell::list(rec.list("BlindCopyTo")),
                    Cell::list(rec.list("CopyTo")),
                    Cell::list(rec.list("AddToRecipients")),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

const REMOTE_COLS: &[&str] = &[
    "domain_name",
    "name",
    "auto_forward_enabled",
    "allowed_ooo_type",
    "when_changed",
];

pub struct RemoteDomainsParser;

impl ArtifactParser for RemoteDomainsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&REMOTE_DOMAINS, REMOTE_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) =
                lower(rec.text("DomainName")).map(|d| collection_key(ctx.collection_id, &d))
            else {
                reject(ctx, r, "remote domain has no DomainName")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(rec.text("DomainName")),
                    Cell::text(rec.text("Name")),
                    Cell::bool(rec.bool("AutoForwardEnabled")),
                    Cell::text(rec.text("AllowedOOFType")),
                    Cell::time(rec.first_text(&["WhenChangedUTC", "WhenChanged"])),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}
