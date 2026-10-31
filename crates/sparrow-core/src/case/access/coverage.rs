//! What the capture could see, per category: the status of the category's evidence source for the account's tenant
//! (`evidence_availability`), and the gaps Microsoft never logs, which hold in every case. A category with no items
//! reads "none seen" only when that is a finding: its source was collected, or it is partial but the capture does hold
//! the category's operations for that account.

use super::{Category, CategoryCoverage};
use crate::Result;
use duckdb::{Connection, OptionalExt};
use std::collections::BTreeSet;

/// The gaps Microsoft never logs, whatever the licence or the capture.
pub const NEVER_LOGGED: &[(Category, &str)] = &[
    (
        Category::Teams,
        "Teams chats read in the Teams app are not audited (only Graph reads are)",
    ),
    (
        Category::MailRead,
        "Mail synced by desktop Outlook is logged per folder, not per message; offline reading leaves no trace",
    ),
    (
        Category::Attachment,
        "Attachments opened in Outlook or OWA are not audited",
    ),
    (
        Category::Other,
        "Exchange searches are audited only with Audit Premium and per-mailbox opt-in",
    ),
];

/// The evidence sources a category is judged on: the first collected or partial one, else the first with a status. A
/// category falls back to the generic `ual` row only when the case has no row for its own sources (the profile judges
/// the mail sources with their own licence and mailbox-audit checks).
fn sources(c: Category) -> &'static [&'static str] {
    match c {
        Category::MailRead => &["mail_items_accessed", "mailbox_audit_legacy"],
        Category::MailSent => &["mail_send"],
        _ => &[],
    }
}

/// The categories whose operations the capture holds for this account in this tenant: what makes a partial source
/// count as covered (a partial capture may hold other users only).
pub(crate) fn presence(
    conn: &Connection,
    tenant: &str,
    account: &str,
) -> Result<BTreeSet<Category>> {
    let row: [bool; 7] = conn.query_row(
        "WITH u AS (SELECT u.record_id, u.operation, u.workload FROM ual_events u JOIN collections c USING (collection_id) \
             WHERE c.tenant_key = ?1 AND lower(u.user_upn) = ?2) \
         SELECT coalesce(bool_or(operation = 'MailItemsAccessed'), FALSE) \
                 OR EXISTS (SELECT 1 FROM mailbox_audit_legacy l JOIN collections c USING (collection_id) \
                     WHERE c.tenant_key = ?1 AND lower(l.mailbox_upn) = ?2 \
                     AND l.operation IN ('MailItemsAccessed', 'MessageBind')) \
                 OR EXISTS (SELECT 1 FROM mail_items_accessed m JOIN collections c USING (collection_id) \
                     WHERE m.record_id IS NULL AND c.tenant_key = ?1 AND lower(m.user_upn) = ?2), \
             coalesce(bool_or(operation IN ('Send', 'SendAs', 'SendOnBehalf')), FALSE), \
             coalesce(bool_or(operation = 'AttachmentAccess'), FALSE), \
             coalesce(bool_or(record_id IN (SELECT record_id FROM file_events) \
                 OR record_id IN (SELECT record_id FROM sharing_events)), FALSE), \
             coalesce(bool_or(workload = 'MicrosoftTeams'), FALSE), \
             coalesce(bool_or(operation = 'CopilotInteraction'), FALSE), \
             count(*) > 0 \
         FROM u",
        [tenant, account],
        |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?]),
    )?;
    Ok(Category::ALL
        .into_iter()
        .zip(row)
        .filter(|(_, b)| *b)
        .map(|(c, _)| c)
        .collect())
}

fn status(conn: &Connection, tenant: &str, source: &str) -> Result<Option<CategoryCoverage>> {
    Ok(conn
        .query_row(
            "SELECT CAST(status AS VARCHAR), reason, remediation FROM evidence_availability \
             WHERE tenant_key = ? AND evidence = ? ORDER BY evaluated_at DESC LIMIT 1",
            [tenant, source],
            |r| {
                Ok(CategoryCoverage {
                    status: r.get(0)?,
                    reason: r.get(1)?,
                    remediation: r.get(2)?,
                })
            },
        )
        .optional()?)
}

/// The coverage of category `c` for `tenant`, and whether a zero is "none seen": its source was collected, or is
/// partial and the capture holds the category's operations for the account (`present`).
pub(crate) fn coverage(
    conn: &Connection,
    tenant: Option<&str>,
    c: Category,
    present: &BTreeSet<Category>,
) -> Result<(CategoryCoverage, bool)> {
    let Some(tenant) = tenant else {
        return Ok((none(), false));
    };
    let mut found = Vec::new();
    for source in sources(c) {
        if let Some(cov) = status(conn, tenant, source)? {
            found.push(cov);
        }
    }
    if found.is_empty() {
        found.extend(status(conn, tenant, "ual")?);
    }
    let Some(i) = found
        .iter()
        .position(|f| f.status == "collected")
        .or_else(|| found.iter().position(|f| f.status == "partial"))
        .or(if found.is_empty() { None } else { Some(0) })
    else {
        return Ok((none(), false));
    };
    let mut cov = found.swap_remove(i);
    match cov.status.as_str() {
        "collected" => Ok((cov, true)),
        "partial" if present.contains(&c) => Ok((cov, true)),
        "partial" => {
            cov.reason = format!(
                "{} partial: {} operations of this account may not have been collected",
                if sources(c).is_empty() {
                    "UAL"
                } else {
                    "Source"
                },
                c.title()
            );
            Ok((cov, false))
        }
        _ => Ok((cov, false)),
    }
}

fn none() -> CategoryCoverage {
    CategoryCoverage {
        status: "none".into(),
        reason: "The case has no availability record for this source (run sparrow profile)".into(),
        remediation: None,
    }
}

/// What can make the mail tiles of one account incomplete although their source was collected: MailItemsAccessed
/// throttled for it (Exchange stops listing items once an account passes its limit, exactly when a whole mailbox is
/// read), or its mailbox not auditing the action for its owner (an audit bypass, or a customised owner audit set).
#[derive(Debug, Default)]
pub(crate) struct MailLimits {
    pub throttled: bool,
    pub bypass: bool,
    pub no_read_audit: bool,
    pub no_send_audit: bool,
}

pub(crate) fn mail_limits(
    conn: &Connection,
    account: &str,
    src: &super::ScopeSource,
) -> Result<MailLimits> {
    let (ctes, mut params) = super::scope::ctes(src);
    let sql = format!(
        "WITH {ctes} SELECT coalesce(bool_or(m.is_throttled), FALSE) FROM attributed a JOIN mail_items_accessed m \
         ON a.source_table = 'ual_events' AND m.record_id = TRY_CAST(a.record_key AS UUID) WHERE a.account = ?"
    );
    params.push(duckdb::types::Value::Text(account.to_string()));
    let throttled: bool =
        conn.query_row(&sql, duckdb::params_from_iter(params.iter()), |r| r.get(0))?;
    let mailbox: Option<(bool, bool, bool)> = conn
        .query_row(
            "SELECT coalesce(audit_bypass_enabled, FALSE), \
                 audit_owner IS NOT NULL AND NOT list_contains(list_transform(audit_owner, x -> lower(x)), 'mailitemsaccessed'), \
                 audit_owner IS NOT NULL AND NOT list_contains(list_transform(audit_owner, x -> lower(x)), 'send') \
             FROM mailboxes WHERE lower(upn) = ?1 OR lower(primary_smtp_address) = ?1 \
             ORDER BY collected_at DESC NULLS LAST LIMIT 1",
            [account],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (bypass, no_read_audit, no_send_audit) = mailbox.unwrap_or_default();
    Ok(MailLimits {
        throttled,
        bypass,
        no_read_audit,
        no_send_audit,
    })
}

/// `cov` (and whether its zero is a finding) after the account's mail limits: a collected or covered-partial mail
/// source becomes partial with the reason; a source already worse keeps its own status.
pub(crate) fn limited(
    c: Category,
    limits: &MailLimits,
    cov: CategoryCoverage,
    covered: bool,
) -> (CategoryCoverage, bool) {
    let reason = match c {
        Category::MailRead if limits.throttled => Some(
            "MailItemsAccessed was throttled for this account: the per-message list is incomplete"
                .to_string(),
        ),
        Category::MailRead | Category::MailSent if limits.bypass => {
            Some("the mailbox has an audit bypass: its owner's actions are not audited".to_string())
        }
        Category::MailRead if limits.no_read_audit => {
            Some("the mailbox does not audit MailItemsAccessed for its owner".to_string())
        }
        Category::MailSent if limits.no_send_audit => {
            Some("the mailbox does not audit Send for its owner".to_string())
        }
        _ => None,
    };
    match reason {
        Some(reason) if cov.status == "collected" || cov.status == "partial" => (
            CategoryCoverage {
                status: "partial".into(),
                reason,
                remediation: cov.remediation,
            },
            false,
        ),
        _ => (cov, covered),
    }
}
