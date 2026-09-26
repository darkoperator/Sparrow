//! Exchange Online cmdlets: Get-MessageTraceLog (research event layouts §11, run twice),
//! Get-MailboxPermissions and Get-MailboxAuditStatus (sample survey §4.6-§4.7, §6; the second
//! audit status run is byte-identical), and Get-Sessions / Get-MessageIDs (§10).

use super::Ctx;
use crate::Result;
use crate::events::Ual;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, Origin, PsDate, Rendered, Row, Val, export_csv};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::ual::creation_time;
use crate::world::{Mailbox, World};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::cmp::Reverse;
use uuid::Uuid;

/// `Search-UnifiedAuditLog`'s result cap the MailItemsAccessed cmdlets check first.
const MIA_CAP: usize = 4999;

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn opt(v: Option<String>) -> Val {
    v.map_or(Val::Null, Val::Str)
}

/// One message trace row per recipient: Get-MessageTraceV2 over the 90 days before collection
/// (within the window), newest first.
/// Each row with its message trace id, recipient and received time.
fn trace_rows(c: &Ctx<'_>) -> Vec<(Row, Uuid, String, DateTime<Utc>)> {
    let world = c.world;
    let from = (world.collected_at() - Duration::days(90)).max(world.window_start());
    let mut msgs: Vec<_> = c
        .days
        .iter()
        .flat_map(|d| &d.trace)
        .filter(|t| t.received >= from)
        .collect();
    msgs.sort_by_key(|t| Reverse((t.received, t.trace_id)));
    let mut out = Vec::new();
    for t in msgs {
        for (recipient, status) in &t.recipients {
            let row = vec![
                r("MessageTraceId", Val::Str(t.trace_id.to_string())),
                r("MessageId", Val::Str(t.internet_message_id.clone())),
                r(
                    "Received",
                    Val::Date(PsDate::dotnet(t.received, DtKind::Utc)),
                ),
                r("SenderAddress", Val::Str(t.sender.clone())),
                r("RecipientAddress", Val::Str(recipient.clone())),
                r("FromIP", opt(t.from_ip.map(|ip| ip.to_string()))),
                r("ToIP", opt(t.to_ip.map(|ip| ip.to_string()))),
                r("Subject", Val::Str(t.subject.clone())),
                r("Status", Val::Str(status.clone())),
                r("Size", Val::Int(t.size as i64)),
            ];
            out.push((row, t.trace_id, recipient.clone(), t.received));
        }
    }
    out
}

/// Get-MessageTraceLog for all users, then the same cmdlet an hour later (same window, so a
/// byte-identical file). Nothing matched: an empty run folder.
pub(super) fn write_message_trace(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let rows = trace_rows(c);
    let table: Vec<Row> = rows.iter().map(|(row, ..)| row.clone()).collect();
    let mut dates = DateEvidence::default();
    let rendered = export_csv(&c.host, &table, &mut dates);
    for n in 0..2 {
        let run = if n == 0 {
            c.runs.next("MessageTrace", None)
        } else {
            c.runs.next_after("MessageTrace", None, Duration::hours(1))
        };
        let dir = c.path(&run.rel);
        tree.dir(&dir)?;
        c.log
            .add(run.local, "=== Starting Message Trace Log Collection ===");
        if rows.is_empty() {
            continue;
        }
        let rel = format!("{dir}/{}-MessageTrace.csv", run.stamp);
        tree.write(
            &FileSpec::new(&rel, Some("inv.message_trace"), c.utf8()),
            &rendered.text,
        )?;
        if dates.culture_dates > 0 {
            tree.date_evidence(&rel, dates);
        }
        for ((_, trace_id, recipient, _), span) in rows.iter().zip(&rendered.spans) {
            tree.row(&rel, "message_trace", keys::trace(*trace_id, recipient));
            let e = Evidence::Trace {
                trace_id: *trace_id,
                recipient: recipient.clone(),
            };
            tree.deliver(&e, "message_trace", &rel, *span);
        }
        c.log.add(
            run.local + Duration::seconds(3),
            format!(
                "[INFO] Found {} records between {} and {}",
                rows.len(),
                rows.last().map_or(String::new(), |(.., t)| t
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()),
                rows.first().map_or(String::new(), |(.., t)| t
                    .format("%Y-%m-%dT%H:%M:%S")
                    .to_string()),
            ),
        );
    }
    Ok(())
}

/// Grants of `mailbox` of one kind (`right`), in the world's order.
fn grants<'a>(
    world: &'a World,
    mailbox: &str,
    right: &str,
    folder: Option<&str>,
) -> Vec<&'a crate::world::MailboxPermission> {
    world
        .mailbox_permissions
        .iter()
        .filter(|p| p.mailbox == mailbox && p.right == right && p.folder.as_deref() == folder)
        .collect()
}

/// The 17-column Get-MailboxPermissions row of `mb` and its grants' (key, evidence) pairs.
fn permission_row(world: &World, mb: &Mailbox) -> (Row, Vec<(String, Evidence)>) {
    let mut keyed = Vec::new();
    let mut note = |right: &str, folder: Option<&str>, grantee: &str, text: &str| {
        keyed.push((
            keys::mailbox_permission(&mb.upn, right, folder, text),
            Evidence::MailboxPermission {
                mailbox: mb.upn.clone(),
                grantee: grantee.to_string(),
                right: right.to_string(),
                folder: folder.map(str::to_string),
            },
        ));
    };
    let full = grants(world, &mb.upn, "full_access", None);
    let full_users: Vec<String> = full
        .iter()
        .map(|g| keys::mailbox_grantee(world, &g.grantee))
        .collect();
    let full_perms: Vec<String> = full
        .iter()
        .zip(&full_users)
        .map(|(g, name)| {
            note("full_access", None, &g.grantee, name);
            format!(
                "{name} - Rights: {}, Deny: {}, Inheritance: {}",
                g.access_rights.join(","),
                if g.deny { "True" } else { "False" },
                g.inheritance.as_deref().unwrap_or("All")
            )
        })
        .collect();
    let send_as = grants(world, &mb.upn, "send_as", None);
    let send_as_users: Vec<String> = send_as
        .iter()
        .map(|g| keys::mailbox_grantee(world, &g.grantee))
        .collect();
    let send_as_perms: Vec<String> = send_as
        .iter()
        .zip(&send_as_users)
        .map(|(g, name)| {
            note("send_as", None, &g.grantee, name);
            format!(
                "{name} - Type: {}, Rights: {}, Inheritance: {}",
                if g.deny { "Deny" } else { "Allow" },
                g.access_rights.join(" "),
                g.inheritance.as_deref().unwrap_or("None")
            )
        })
        .collect();
    let behalf: Vec<String> = grants(world, &mb.upn, "send_on_behalf", None)
        .iter()
        .map(|g| {
            let name = keys::mailbox_grantee(world, &g.grantee);
            note("send_on_behalf", None, &g.grantee, &name);
            name
        })
        .collect();
    let mut folder_cols = Vec::new();
    for folder in ["calendar", "inbox"] {
        let gs = grants(world, &mb.upn, "folder", Some(folder));
        let users: Vec<String> = gs
            .iter()
            .map(|g| {
                let name = keys::mailbox_folder_grantee(world, &g.grantee);
                note("folder", Some(folder), &g.grantee, &name);
                format!("{name} - {}", g.access_rights.join(" "))
            })
            .collect();
        let perms: Vec<String> = gs
            .iter()
            .map(|g| {
                let display = world
                    .mailboxes
                    .get(&g.grantee)
                    .map_or(g.grantee.clone(), |m| m.display_name.clone());
                format!("{display}: {}", g.access_rights.join(" "))
            })
            .collect();
        folder_cols.push((users, perms, gs.len()));
    }
    let (cal, inbox) = (&folder_cols[0], &folder_cols[1]);
    let row = vec![
        r("UserPrincipalName", Val::Str(mb.upn.clone())),
        r("DisplayName", Val::Str(mb.display_name.clone())),
        r("RecipientTypeDetails", Val::Str(mb.recipient_type.clone())),
        r("FullAccessUsers", Val::Str(full_users.join("; "))),
        r("FullAccessPermissions", Val::Str(full_perms.join(" | "))),
        r("SendAsUsers", Val::Str(send_as_users.join("; "))),
        r("SendAsPermissions", Val::Str(send_as_perms.join(" | "))),
        r("SendOnBehalfUsers", Val::Str(behalf.join("; "))),
        r("CalendarUsers", Val::Str(cal.0.join("; "))),
        r("CalendarPermissions", Val::Str(cal.1.join(" | "))),
        r("InboxUsers", Val::Str(inbox.0.join("; "))),
        r("InboxPermissions", Val::Str(inbox.1.join(" | "))),
        r("FullAccessCount", Val::Int(full.len() as i64)),
        r("SendAsCount", Val::Int(send_as.len() as i64)),
        r("SendOnBehalfCount", Val::Int(behalf.len() as i64)),
        r("CalendarPermissionCount", Val::Int(cal.2 as i64)),
        r("InboxPermissionCount", Val::Int(inbox.2 as i64)),
    ];
    (row, keyed)
}

/// Get-MailboxPermissions: every mailbox, with or without grants.
pub(super) fn write_mailbox_permissions(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Mailbox Permissions", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(
        run.local,
        format!(
            "[INFO] Found {} mailboxes to process",
            c.world.mailboxes.len()
        ),
    );
    let (rows, keyed): (Vec<Row>, Vec<Vec<(String, Evidence)>>) = c
        .world
        .mailboxes
        .values()
        .map(|mb| permission_row(c.world, mb))
        .unzip();
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, &rows, &mut ev);
    let rel = format!("{dir}/{}-MailboxPermissions.csv", run.stamp);
    tree.write(
        &FileSpec::new(&rel, Some("inv.mailbox_permissions"), c.utf8()),
        &rendered.text,
    )?;
    for ((mb, grants), span) in c.world.mailboxes.values().zip(&keyed).zip(&rendered.spans) {
        tree.row(&rel, "mailboxes", keys::mailbox(&mb.upn));
        tree.deliver(&Evidence::Mailbox(mb.upn.clone()), "mailboxes", &rel, *span);
        for (key, e) in grants {
            tree.row(&rel, "mailbox_permissions", key.clone());
            tree.deliver(e, "mailbox_permissions", &rel, *span);
        }
    }
    Ok(())
}

fn sorted_join(list: &[String]) -> String {
    let mut v = list.to_vec();
    v.sort_by_key(|a| a.to_lowercase());
    v.join(", ")
}

/// The 13-column Get-MailboxAuditStatus row of `mb`: the world's final audit settings.
fn audit_status_row(world: &World, mb: &Mailbox) -> Row {
    let state = if mb.bypass {
        "Bypassed"
    } else if world.audit.org_audit_disabled {
        "Disabled"
    } else {
        "Enabled (Organization Policy)"
    };
    vec![
        r("UserPrincipalName", Val::Str(mb.upn.clone())),
        r("DisplayName", Val::Str(mb.display_name.clone())),
        r("RecipientTypeDetails", Val::Str(mb.recipient_type.clone())),
        r("AuditEnabled", Val::Bool(mb.audit_enabled)),
        r("AuditBypassEnabled", Val::Bool(mb.bypass)),
        r(
            "DefaultAuditSet",
            Val::Str(sorted_join(&mb.default_audit_set)),
        ),
        r("OwnerAuditActions", Val::Str(sorted_join(&mb.audit_owner))),
        r(
            "OwnerAuditActionsCount",
            Val::Int(mb.audit_owner.len() as i64),
        ),
        r(
            "DelegateAuditActions",
            Val::Str(sorted_join(&mb.audit_delegate)),
        ),
        r(
            "DelegateAuditActionsCount",
            Val::Int(mb.audit_delegate.len() as i64),
        ),
        r("AdminAuditActions", Val::Str(sorted_join(&mb.audit_admin))),
        r(
            "AdminAuditActionsCount",
            Val::Int(mb.audit_admin.len() as i64),
        ),
        r("EffectiveAuditState", Val::Str(state.into())),
    ]
}

/// Get-MailboxAuditStatus, twice (the second file is byte-identical).
pub(super) fn write_audit_status(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let mailboxes: Vec<&Mailbox> = c.world.mailboxes.values().collect();
    let rows: Vec<Row> = mailboxes
        .iter()
        .map(|mb| audit_status_row(c.world, mb))
        .collect();
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, &rows, &mut ev);
    for _ in 0..2 {
        let run = c.runs.next("Audit Status", None);
        let dir = c.path(&run.rel);
        tree.dir(&dir)?;
        c.log
            .add(run.local, "[INFO] Retrieving audit bypass associations...");
        let rel = format!("{dir}/{}-MailboxAuditStatus.csv", run.stamp);
        tree.write(
            &FileSpec::new(&rel, Some("inv.audit_status"), c.utf8()),
            &rendered.text,
        )?;
        let mut org_row = false;
        for (mb, span) in mailboxes.iter().zip(&rendered.spans) {
            tree.row(&rel, "mailboxes", keys::mailbox(&mb.upn));
            tree.deliver(&Evidence::Mailbox(mb.upn.clone()), "mailboxes", &rel, *span);
            // The first row whose EffectiveAuditState tells organization auditing apart
            // fills the collection's audit_config row.
            if !org_row && !mb.bypass {
                org_row = true;
                tree.row(&rel, "audit_config", keys::audit_config());
                tree.deliver(&Evidence::AuditConfig, "audit_config", &rel, *span);
            }
        }
    }
    Ok(())
}

/// An AuditData string property.
fn text(u: &Ual, key: &str) -> Option<String> {
    u.audit.get(key).and_then(Value::as_str).map(str::to_string)
}

/// `OperationProperties[Name=name].Value`.
fn op_prop(u: &Ual, name: &str) -> Option<String> {
    u.audit
        .get("OperationProperties")
        .and_then(Value::as_array)?
        .iter()
        .find(|p| p.get("Name").and_then(Value::as_str) == Some(name))
        .and_then(|p| p.get("Value"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// AuditData `CreationTime` after `ConvertFrom-Json` (a DateTime on 7, the text on 5.1).
fn timestamp(u: &Ual) -> Val {
    Val::Date(PsDate {
        utc: u.time,
        origin: Origin::IsoText(creation_time(u.time)),
    })
}

fn session_row(u: &Ual) -> Row {
    vec![
        r("TimeStamp", timestamp(u)),
        r("User", Val::Str(u.user_id.clone())),
        r("Action", Val::Str(u.operation.clone())),
        r("SessionId", opt(text(u, "SessionId"))),
        r("ClientIP", opt(text(u, "ClientIPAddress"))),
        r("MailAccessType", opt(op_prop(u, "MailAccessType"))),
        r("IsThrottled", opt(op_prop(u, "IsThrottled"))),
        r(
            "OperationCount",
            u.audit
                .get("OperationCount")
                .and_then(Value::as_i64)
                .map_or(Val::Null, Val::Int),
        ),
    ]
}

/// Get-MessageIDs' rows for one record: a Sync row per folder; a row per folder item when
/// OperationCount > 1; else one row with `Folders.FolderItems.InternetMessageId` and the
/// (absent) top-level `SizeInBytes`.
fn message_id_rows(u: &Ual) -> Vec<Row> {
    let base = |access: &str, folder: Val, id: Val, size: Val| {
        vec![
            r("Timestamp", timestamp(u)),
            r("User", Val::Str(u.user_id.clone())),
            r("IPaddress", opt(text(u, "ClientIPAddress"))),
            r("SessionID", opt(text(u, "SessionId"))),
            r("MailAccessType", Val::Str(access.into())),
            r("FolderPath", folder),
            r("InternetMessageId", id),
            r("SizeInBytes", size),
        ]
    };
    let folders: Vec<&Value> = u
        .audit
        .get("Folders")
        .and_then(Value::as_array)
        .map(|f| f.iter().collect())
        .unwrap_or_default();
    let items: Vec<&Value> = folders
        .iter()
        .filter_map(|f| f.get("FolderItems").and_then(Value::as_array))
        .flatten()
        .collect();
    let item_id = |i: &Value| {
        opt(i
            .get("InternetMessageId")
            .and_then(Value::as_str)
            .map(str::to_string))
    };
    if op_prop(u, "MailAccessType").as_deref() == Some("Sync") {
        return folders
            .iter()
            .map(|f| {
                base(
                    "Sync",
                    opt(f.get("Path").and_then(Value::as_str).map(str::to_string)),
                    Val::Str("N/A (Sync - entire folder)".into()),
                    Val::Null,
                )
            })
            .collect();
    }
    let count = u
        .audit
        .get("OperationCount")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if count > 1 {
        return items
            .iter()
            .map(|i| {
                let size = i
                    .get("SizeInBytes")
                    .and_then(Value::as_i64)
                    .map_or(Val::Null, Val::Int);
                base("Bind", Val::Null, item_id(i), size)
            })
            .collect();
    }
    let id = match items.as_slice() {
        [one] => item_id(one),
        [] => Val::Null,
        _ => Val::Str("System.Object[]".into()),
    };
    vec![base("Bind", Val::Null, id, Val::Null)]
}

/// Writes `rows` (one group per record) as `rel` and delivers each row as a sighting of its
/// raw record.
fn write_derived(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    groups: &[(&Ual, Vec<Row>)],
) -> Result<()> {
    let rows: Vec<Row> = groups.iter().flat_map(|(_, g)| g.clone()).collect();
    let mut dates = DateEvidence::default();
    let Rendered { text, spans } = export_csv(&c.host, &rows, &mut dates);
    tree.write(&FileSpec::new(rel, Some(artifact), c.utf8()), &text)?;
    if dates.culture_dates > 0 {
        tree.date_evidence(rel, dates);
    }
    let mut spans = spans.into_iter();
    for (u, g) in groups {
        for _ in g {
            if let Some(span) = spans.next() {
                tree.deliver(&Evidence::Ual(u.id), "ual_events", rel, span);
            }
        }
    }
    Ok(())
}

/// Get-Sessions `-UserIds <user>` for every storyline user with MailItemsAccessed records in the
/// window, once more for a user without any (an empty run folder), then Get-MessageIDs over the
/// window (no filter: the cmdlet has no `-UserIds`). Both give up above 4999 records.
pub(super) fn write_mail_items_accessed(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let mut records: Vec<Ual> = c
        .days
        .iter()
        .flat_map(|d| &d.ual)
        .filter(|u| u.operation == "MailItemsAccessed")
        .cloned()
        .collect();
    records.sort_by_key(|u| Reverse((u.time, u.id)));
    let of = |upn: &str| -> Vec<&Ual> { records.iter().filter(|u| u.user_id == upn).collect() };
    let victims: Vec<String> = c
        .world
        .victims
        .iter()
        .map(|n| c.world.user(*n).upn.clone())
        .collect();
    for upn in &victims {
        let hits = of(upn);
        if hits.is_empty() {
            continue;
        }
        let run = c.runs.next("MailItemsAccessed", None);
        let dir = c.path(&run.rel);
        tree.dir(&dir)?;
        c.log.add(run.local, "=== Starting Session Collection ===");
        if hits.len() > MIA_CAP {
            continue;
        }
        let groups: Vec<(&Ual, Vec<Row>)> =
            hits.iter().map(|u| (*u, vec![session_row(u)])).collect();
        let rel = format!("{dir}/{}-Sessions-{upn}.csv", run.stamp);
        write_derived(c, tree, &rel, "inv.mia.sessions", &groups)?;
    }
    // A mailbox nobody signs in to (the shared or discovery mailbox) has no hits.
    if let Some(quiet) = c.world.mailboxes.keys().find(|upn| of(upn).is_empty()) {
        let run = c.runs.next("MailItemsAccessed", None);
        tree.dir(&c.path(&run.rel))?;
        c.log.add(run.local, "=== Starting Session Collection ===");
        c.log.add(
            run.local + Duration::seconds(1),
            format!("[INFO] No MailItemsAccessed events found for {quiet}"),
        );
    }
    let run = c.runs.next("MailItemsAccessed", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Message IDs Collection ===");
    if !records.is_empty() && records.len() <= MIA_CAP {
        let groups: Vec<(&Ual, Vec<Row>)> =
            records.iter().map(|u| (u, message_id_rows(u))).collect();
        let rel = format!("{dir}/{}-MessageIDs.csv", run.stamp);
        write_derived(c, tree, &rel, "inv.mia.message_ids", &groups)?;
    } else if records.len() > MIA_CAP {
        c.log.add(
            run.local,
            format!(
                "[WARNING] A total of {} events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window.",
                records.len()
            ),
        );
    }
    Ok(())
}
