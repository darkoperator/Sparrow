//! Microsoft-Extractor-Suite Get-MailboxAuditStatus (`Audit Status/<ts>/<ts>-MailboxAuditStatus.csv`):
//! per-mailbox audit settings into `mailboxes`. The collector's EffectiveAuditState is derived
//! from Get-OrganizationConfig AuditDisabled, so it also fills `audit_config.audit_disabled`.

use crate::Result;
use crate::db::state_tables::{AUDIT_CONFIG, MAILBOXES};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::mailbox::mailbox_key;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{TableRows, load_tables, read_state_records, reject, require_any_key};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.audit_status", Box::new(MailboxAuditStatusParser));
}

const COLS: &[&str] = &[
    "upn",
    "display_name",
    "recipient_type",
    "audit_enabled",
    "audit_bypass_enabled",
    "default_audit_set",
    "audit_owner",
    "audit_delegate",
    "audit_admin",
    "effective_audit_state",
];
const AUDIT_COLS: &[&str] = &["audit_disabled"];

/// An action list the collector sorted and joined with `", "`.
fn actions(rec: &Rec, key: &str) -> Vec<String> {
    rec.text(key)
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// What an EffectiveAuditState says about organization AuditDisabled: "Enabled (Organization
/// Policy)" → false, "Disabled" → true, "Bypassed" → nothing.
fn org_audit_disabled(state: &str) -> Option<bool> {
    let s = state.trim().to_ascii_lowercase();
    if s.starts_with("enabled") {
        Some(false)
    } else if s == "disabled" {
        Some(true)
    } else {
        None
    }
}

pub struct MailboxAuditStatusParser;

impl ArtifactParser for MailboxAuditStatusParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &[
                "EffectiveAuditState",
                "OwnerAuditActions",
                "AuditBypassEnabled",
            ],
            "mailbox audit status",
        )?;
        let mut rows = TableRows::new(&MAILBOXES, COLS);
        let mut audit = TableRows::new(&AUDIT_CONFIG, AUDIT_COLS);
        let mut org: Option<(bool, usize)> = None;
        let mut conflict = false;
        for (i, r) in records.iter().enumerate() {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = mailbox_key(&rec, None) else {
                reject(ctx, r, "mailbox audit status row has no UserPrincipalName")?;
                continue;
            };
            let state = rec.text("EffectiveAuditState");
            if let Some(d) = state.as_deref().and_then(org_audit_disabled) {
                match org {
                    None => org = Some((d, i)),
                    Some((prev, _)) if prev != d => conflict = true,
                    Some(_) => {}
                }
            }
            rows.push(
                r,
                key.clone(),
                vec![
                    Cell::text(Some(key)),
                    Cell::text(rec.text("DisplayName")),
                    Cell::text(rec.text("RecipientTypeDetails")),
                    Cell::bool(rec.bool("AuditEnabled")),
                    Cell::bool(rec.bool("AuditBypassEnabled")),
                    Cell::list(actions(&rec, "DefaultAuditSet")),
                    Cell::list(actions(&rec, "OwnerAuditActions")),
                    Cell::list(actions(&rec, "DelegateAuditActions")),
                    Cell::list(actions(&rec, "AdminAuditActions")),
                    Cell::text(state),
                ],
            );
        }
        if conflict {
            ctx.warn(
                "EffectiveAuditState rows disagree about organization auditing (both \"Enabled (Organization Policy)\" and \"Disabled\"); audit_config.audit_disabled not set",
            );
        } else if let Some((disabled, i)) = org {
            audit.push(
                &records[i],
                "organization".into(),
                vec![Cell::bool(Some(disabled))],
            );
        }
        load_tables(ctx, vec![rows, audit])
    }
}
