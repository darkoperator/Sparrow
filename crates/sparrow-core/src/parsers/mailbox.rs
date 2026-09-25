//! Mailbox settings merged from several Hawk files, each filling its own `mailboxes`
//! columns: forwarding reports (JSON/CSV), and the Format-List TXT files Mailbox_Info
//! (Get-Mailbox identity), CAS_Mailbox_Info (Get-CASMailbox protocols) and AutoReply
//! (Get-MailboxAutoReplyConfiguration).

use crate::Result;
use crate::db::state_tables::MAILBOXES;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::normalize_upn;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    TableRows, load_tables, lower, read_state_records, reject, require_any_key, unsupported,
};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.user.forwarding", Box::new(ForwardingParser));
    r.register(
        "hawk.tenant.user_forwarding_report",
        Box::new(ForwardingParser),
    );
    r.register("hawk.user.mailbox_txt", Box::new(MailboxInfoParser));
    r.register("hawk.user.autoreply", Box::new(AutoReplyParser));
}

/// mailboxes.record_key: the Hawk user folder UPN, else the record's UserPrincipalName.
pub fn mailbox_key(rec: &Rec, subject: Option<&str>) -> Option<String> {
    subject.and_then(normalize_upn).or_else(|| {
        rec.text("UserPrincipalName")
            .and_then(|u| normalize_upn(&u))
    })
}

const FORWARDING_COLS: &[&str] = &[
    "upn",
    "display_name",
    "primary_smtp_address",
    "forwarding_smtp_address",
    "forwarding_address",
    "deliver_and_forward",
    "when_changed",
];

/// ForwardingReport_<user> and Tenant/User_ForwardingReport: `DisplayName,
/// UserPrincipalName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress,
/// DeliverToMailboxAndForward, WhenChangedUTC`.
pub struct ForwardingParser;

impl ArtifactParser for ForwardingParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let subject = ctx.subject;
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &[
                "ForwardingSmtpAddress",
                "ForwardingAddress",
                "DeliverToMailboxAndForward",
            ],
            "forwarding",
        )?;
        let mut rows = TableRows::new(&MAILBOXES, FORWARDING_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = mailbox_key(&rec, subject) else {
                reject(ctx, r, "forwarding record has no UserPrincipalName")?;
                continue;
            };
            rows.push(
                r,
                key.clone(),
                vec![
                    Cell::text(Some(key)),
                    Cell::text(rec.text("DisplayName")),
                    Cell::text(lower(rec.text("PrimarySmtpAddress"))),
                    Cell::text(rec.text("ForwardingSmtpAddress")),
                    Cell::text(rec.text("ForwardingAddress")),
                    Cell::bool(rec.bool("DeliverToMailboxAndForward")),
                    Cell::time(rec.first_text(&["WhenChangedUTC", "WhenChanged"])),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

const MAILBOX_COLS: &[&str] = &[
    "upn",
    "display_name",
    "primary_smtp_address",
    "object_id",
    "mailbox_guid",
    "recipient_type",
];
const CAS_COLS: &[&str] = &[
    "upn",
    "display_name",
    "primary_smtp_address",
    "pop_enabled",
    "imap_enabled",
    "ews_enabled",
    "owa_enabled",
    "activesync_enabled",
    "mapi_enabled",
];

fn is_cas(rec: &Rec) -> bool {
    rec.has("OWAEnabled") || rec.has("PopEnabled") || rec.has("ActiveSyncEnabled")
}

fn is_mailbox(rec: &Rec) -> bool {
    rec.has("RecipientTypeDetails") || rec.has("RecipientType") || rec.has("UserPrincipalName")
}

/// Mailbox_Info_<user>.txt and CAS_Mailbox_Info_<user>.txt (one Format-List object each).
pub struct MailboxInfoParser;

impl ArtifactParser for MailboxInfoParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let subject = ctx.subject;
        let records = read_state_records(ctx, RecordFormat::FormatListObject)?;
        if let Some(first) = records.first() {
            let rec = Rec::new(&first.map, true);
            if !is_cas(&rec) && !is_mailbox(&rec) {
                return Err(unsupported(first, "Get-Mailbox or Get-CASMailbox"));
            }
        }
        let mut mailbox_rows = TableRows::new(&MAILBOXES, MAILBOX_COLS);
        let mut cas_rows = TableRows::new(&MAILBOXES, CAS_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, true);
            let Some(key) = mailbox_key(&rec, subject) else {
                reject(
                    ctx,
                    r,
                    "mailbox record has no user folder or UserPrincipalName",
                )?;
                continue;
            };
            if is_cas(&rec) {
                cas_rows.push(
                    r,
                    key.clone(),
                    vec![
                        Cell::text(Some(key)),
                        Cell::text(rec.text("DisplayName")),
                        Cell::text(lower(rec.text("PrimarySmtpAddress"))),
                        Cell::bool(rec.bool("PopEnabled")),
                        Cell::bool(rec.bool("ImapEnabled")),
                        Cell::bool(rec.bool("EwsEnabled")),
                        Cell::bool(rec.bool("OWAEnabled")),
                        Cell::bool(rec.bool("ActiveSyncEnabled")),
                        Cell::bool(rec.bool("MAPIEnabled")),
                    ],
                );
            } else {
                mailbox_rows.push(
                    r,
                    key.clone(),
                    vec![
                        Cell::text(Some(key)),
                        Cell::text(rec.text("DisplayName")),
                        Cell::text(lower(rec.text("PrimarySmtpAddress"))),
                        Cell::text(lower(rec.text("ExternalDirectoryObjectId"))),
                        Cell::text(lower(rec.text("Guid"))),
                        Cell::text(rec.first_text(&["RecipientTypeDetails", "RecipientType"])),
                    ],
                );
            }
        }
        load_tables(ctx, vec![mailbox_rows, cas_rows])
    }
}

const AUTO_REPLY_COLS: &[&str] = &[
    "upn",
    "auto_reply_state",
    "auto_reply_start",
    "auto_reply_end",
    "auto_reply_external_audience",
    "auto_reply_message",
    "auto_reply_external_message",
];

/// AutoReply_<user>.txt: Format-List of Get-MailboxAutoReplyConfiguration.
pub struct AutoReplyParser;

impl ArtifactParser for AutoReplyParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let subject = ctx.subject;
        let records = read_state_records(ctx, RecordFormat::FormatListObject)?;
        if let Some(first) = records.first() {
            if !Rec::new(&first.map, true).has("AutoReplyState") {
                return Err(unsupported(first, "Get-MailboxAutoReplyConfiguration"));
            }
        }
        let mut rows = TableRows::new(&MAILBOXES, AUTO_REPLY_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, true);
            let Some(key) = mailbox_key(&rec, subject) else {
                reject(ctx, r, "auto-reply record has no user folder")?;
                continue;
            };
            rows.push(
                r,
                key.clone(),
                vec![
                    Cell::text(Some(key)),
                    Cell::text(rec.text("AutoReplyState")),
                    Cell::time(rec.text("StartTime")),
                    Cell::time(rec.text("EndTime")),
                    Cell::text(rec.text("ExternalAudience")),
                    Cell::text(rec.text("InternalMessage")),
                    Cell::text(rec.text("ExternalMessage")),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}
