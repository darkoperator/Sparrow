//! Microsoft-Extractor-Suite rules: Get-MailboxRules / Get-MailboxRulesGraph
//! (`Rules/<ts>/<ts>-MailboxRules*.csv`) into `inbox_rules`, and Get-TransportRules
//! (`Rules/<ts>/<ts>-TransportRules.csv`) into `transport_rules`.

use crate::Result;
use crate::db::state_tables::{INBOX_RULES, TRANSPORT_RULES};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, collection_key, load_tables, lower, read_state_records, reject,
    require_any_key,
};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.mailbox_rules", Box::new(MailboxRulesParser));
    r.register("inv.transport_rules", Box::new(TransportRulesParser));
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
    "source",
];

const TRANSPORT_COLS: &[&str] = &[
    "name",
    "state",
    "mode",
    "priority",
    "created_by",
    "when_changed",
    "description",
];

fn split_joined(value: Option<String>, sep: &str) -> Vec<String> {
    value
        .map(|s| {
            s.split(sep)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Split an EXO-joined list on `, ` only outside double-quoted display names. Exchange renders
/// a recipient as `"Last, First" [SMTP:addr]` and doubles a quote inside the name
/// (`"Doe ""Q"" Smith" [SMTP:addr]`), so a comma between the quotes belongs to the name, not
/// to the list separator.
fn split_exo_list(value: Option<String>) -> Vec<String> {
    let Some(s) = value else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if chars.peek() == Some(&'"') {
                    // A doubled quote is an escaped quote inside the name, not a delimiter.
                    current.push('"');
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                    current.push('"');
                }
            }
            ',' if !in_quotes => {
                let item = current.trim();
                if !item.is_empty() {
                    out.push(item.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let item = current.trim();
    if !item.is_empty() {
        out.push(item.to_string());
    }
    out
}

fn smtp_entry_text(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    match lower.find("[smtp:") {
        Some(start) => {
            let addr_start = start + 6;
            lower[addr_start..]
                .find(']')
                .map(|end| text[addr_start..addr_start + end].trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| text.trim().to_string())
        }
        None => text.trim().to_string(),
    }
}

fn exo_recipients(value: Option<String>) -> Vec<String> {
    split_exo_list(value)
        .into_iter()
        .map(|s| smtp_entry_text(&s))
        .collect()
}

fn exo_folders(value: Option<String>) -> Option<String> {
    let folders: Vec<String> = split_joined(value, ", ")
        .into_iter()
        .map(|s| s.rsplit(":\\").next().unwrap_or(&s).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if folders.is_empty() {
        None
    } else {
        Some(folders.join(", "))
    }
}

fn mailbox_key(value: Option<String>) -> Option<String> {
    lower(value)
}

fn rule_key(mailbox: &str, rule_identity: &str) -> String {
    format!("inbox|{mailbox}|{rule_identity}")
}

pub struct MailboxRulesParser;

impl ArtifactParser for MailboxRulesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let graph = ctx.rel_path.contains("MailboxRulesGraph");
        let records = read_state_records(ctx, format)?;
        if graph {
            require_any_key(&records, &["UserPrincipalName", "RuleId"], "mailbox rule")?;
        } else {
            require_any_key(&records, &["UserName", "RuleIdentity"], "mailbox rule")?;
        }
        let mut rows = TableRows::new(&INBOX_RULES, INBOX_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(mailbox) = mailbox_key(rec.first_text(&["UserName", "UserPrincipalName"]))
            else {
                reject(ctx, r, "mailbox rule has no UserName/UserPrincipalName")?;
                continue;
            };
            let id_col = if graph { "RuleId" } else { "RuleIdentity" };
            let Some(rule_identity) = rec.text(id_col) else {
                reject(ctx, r, &format!("mailbox rule has no {id_col}"))?;
                continue;
            };
            let mut c = CellRow::new(INBOX_COLS);
            c.set("kind", Cell::text(Some("inbox".into())))
                .set("mailbox", Cell::text(Some(mailbox.clone())))
                .set("mailbox_upn", Cell::text(Some(mailbox.clone())))
                .set("rule_identity", Cell::text(Some(rule_identity.clone())))
                .set("name", Cell::text(rec.text("RuleName")))
                .set("enabled", Cell::bool(rec.bool("Enabled")));
            if graph {
                c.set("priority", Cell::int(rec.int("Sequence")))
                    .set(
                        "forward_to",
                        Cell::list(split_joined(rec.text("ForwardTo"), "; ")),
                    )
                    .set(
                        "forward_as_attachment_to",
                        Cell::list(split_joined(rec.text("ForwardAsAttachment"), "; ")),
                    )
                    .set(
                        "redirect_to",
                        Cell::list(split_joined(rec.text("RedirectTo"), "; ")),
                    )
                    .set("delete_message", Cell::bool(rec.bool("Delete")))
                    .set("soft_delete", Cell::bool(rec.bool("PermanentDelete")))
                    .set("move_to_folder", Cell::text(rec.text("MoveToFolder")))
                    .set("mark_as_read", Cell::bool(rec.bool("MarkAsRead")))
                    .set(
                        "stop_processing",
                        Cell::bool(rec.bool("StopProcessingRules")),
                    )
                    .set(
                        "from_addresses",
                        Cell::list(split_joined(rec.text("From"), "; ")),
                    )
                    .set(
                        "subject_contains",
                        Cell::list(split_joined(rec.text("SubjectContains"), "; ")),
                    )
                    .set(
                        "body_contains",
                        Cell::list(split_joined(rec.text("BodyContains"), "; ")),
                    )
                    .set("has_attachment", Cell::bool(rec.bool("HasAttachments")))
                    .set("source", Cell::text(Some("graph".into())));
            } else {
                c.set("in_error", Cell::bool(rec.bool("InError")))
                    .set("priority", Cell::int(rec.int("Priority")))
                    .set(
                        "forward_to",
                        Cell::list(exo_recipients(rec.text("ForwardTo"))),
                    )
                    .set(
                        "forward_as_attachment_to",
                        Cell::list(exo_recipients(rec.text("ForwardAsAttachmentTo"))),
                    )
                    .set(
                        "redirect_to",
                        Cell::list(exo_recipients(rec.text("RedirectTo"))),
                    )
                    .set("delete_message", Cell::bool(rec.bool("DeleteMessage")))
                    .set("soft_delete", Cell::bool(rec.bool("SoftDeleteMessage")))
                    .set(
                        "move_to_folder",
                        Cell::text(exo_folders(rec.text("MoveToFolder"))),
                    )
                    .set(
                        "copy_to_folder",
                        Cell::text(exo_folders(rec.text("CopyToFolder"))),
                    )
                    .set("mark_as_read", Cell::bool(rec.bool("MarkAsRead")))
                    .set(
                        "stop_processing",
                        Cell::bool(rec.bool("StopProcessingRules")),
                    )
                    .set(
                        "from_addresses",
                        Cell::list(exo_recipients(rec.text("From"))),
                    )
                    .set(
                        "subject_contains",
                        Cell::list(split_joined(rec.text("SubjectContainsWords"), ", ")),
                    )
                    .set(
                        "body_contains",
                        Cell::list(split_joined(rec.text("BodyContainsWords"), ", ")),
                    )
                    .set(
                        "subject_or_body_contains",
                        Cell::list(split_joined(rec.text("SubjectOrBodyContainsWords"), ", ")),
                    )
                    .set("has_attachment", Cell::bool(rec.bool("HasAttachment")))
                    .set("description", Cell::text(rec.text("Description")))
                    .set("source", Cell::text(Some("exo".into())));
            }
            rows.push(r, rule_key(&mailbox, &rule_identity), c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

pub struct TransportRulesParser;

impl ArtifactParser for TransportRulesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Name", "WhenChanged"], "transport rule")?;
        let mut rows = TableRows::new(&TRANSPORT_RULES, TRANSPORT_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(name) = rec.text("Name") else {
                reject(ctx, r, "transport rule has no Name")?;
                continue;
            };
            let key = collection_key(ctx.collection_id, &name.to_lowercase());
            let mut c = CellRow::new(TRANSPORT_COLS);
            c.set("name", Cell::text(Some(name)))
                .set("state", Cell::text(rec.text("State")))
                .set("mode", Cell::text(rec.text("Mode")))
                .set("priority", Cell::int(rec.int("Priority")))
                .set("created_by", Cell::text(rec.text("CreatedBy")))
                .set("when_changed", Cell::time(rec.text("WhenChanged")))
                .set("description", Cell::text(rec.text("Description")));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
