//! Get-MailboxRules / Get-MailboxRulesGraph / Get-TransportRules (research state layouts §12):
//! three `Rules/<ts>/...` run folders, each count-guarded.

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Rendered, Row, Val, export_csv};
use crate::rng::stream;
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::world::{InboxRule, TransportRule, World};

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn write_rows(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    rows: &[Row],
) -> Result<Rendered> {
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, rows, &mut ev);
    tree.write(
        &FileSpec::new(rel, Some(artifact), c.utf8()),
        &rendered.text,
    )?;
    if ev.culture_dates > 0 {
        tree.date_evidence(rel, ev);
    }
    Ok(rendered)
}

fn recipient_display(world: &World, addr: &str) -> String {
    world
        .mailboxes
        .get(addr)
        .map(|m| m.display_name.clone())
        .or_else(|| world.user_by_upn(addr).map(|u| u.display_name.clone()))
        .unwrap_or_else(|| addr.to_string())
}

fn exo_recipient(world: &World, addr: &str) -> String {
    format!("\"{}\" [SMTP:{addr}]", recipient_display(world, addr))
}

fn exo_join(world: &World, addrs: &[String]) -> String {
    addrs
        .iter()
        .map(|a| exo_recipient(world, a))
        .collect::<Vec<_>>()
        .join(", ")
}

fn folder_path(mailbox: &str, folder: &Option<String>) -> String {
    folder
        .as_ref()
        .map(|f| format!("{mailbox}:\\{f}"))
        .unwrap_or_default()
}

fn exo_row(world: &World, rule: &InboxRule) -> Row {
    vec![
        r("UserName", Val::Str(rule.mailbox.clone())),
        r("RuleName", Val::Str(rule.name.clone())),
        r("Enabled", Val::Bool(rule.enabled)),
        r("Priority", Val::Int(rule.priority.into())),
        r("RuleIdentity", Val::Str(rule.identity.to_string())),
        r("StopProcessingRules", Val::Bool(rule.stop_processing)),
        r(
            "CopyToFolder",
            Val::Str(folder_path(&rule.mailbox, &rule.copy_to_folder)),
        ),
        r(
            "MoveToFolder",
            Val::Str(folder_path(&rule.mailbox, &rule.move_to_folder)),
        ),
        r("RedirectTo", Val::Str(exo_join(world, &rule.redirect_to))),
        r("ForwardTo", Val::Str(exo_join(world, &rule.forward_to))),
        r(
            "ForwardAsAttachmentTo",
            Val::Str(exo_join(world, &rule.forward_as_attachment_to)),
        ),
        r("ApplyCategory", Val::Str(String::new())),
        r("MarkImportance", Val::Null),
        r("MarkAsRead", Val::Bool(rule.mark_as_read)),
        r("DeleteMessage", Val::Bool(rule.delete_message)),
        r("SoftDeleteMessage", Val::Bool(rule.soft_delete)),
        r("From", Val::Str(exo_join(world, &rule.from))),
        r(
            "SubjectContainsWords",
            Val::Str(rule.subject_contains.join(", ")),
        ),
        r(
            "SubjectOrBodyContainsWords",
            Val::Str(rule.subject_or_body_contains.join(", ")),
        ),
        r("BodyContainsWords", Val::Str(rule.body_contains.join(", "))),
        r("HasAttachment", Val::Bool(rule.has_attachment)),
        r("Description", Val::Str(rule.description())),
        r("InError", Val::Bool(false)),
        r("ErrorType", Val::Str("None".into())),
    ]
}

fn graph_join(values: &[String]) -> Val {
    if values.is_empty() {
        Val::Null
    } else {
        Val::Str(values.join("; "))
    }
}

fn graph_bool(value: bool) -> Val {
    if value { Val::Bool(true) } else { Val::Null }
}

/// The Graph `MoveToFolder` value: a folder id stable per `(mailbox, folder)`, so two rules that
/// move to the same folder report the same id (the id is not the rule's, unlike EXO's).
fn graph_folder(world: &World, rule: &InboxRule) -> Val {
    let Some(folder) = &rule.move_to_folder else {
        return Val::Null;
    };
    let label = format!(
        "invictus/graph_folder/{}/{}",
        rule.mailbox.to_lowercase(),
        folder.to_lowercase()
    );
    let id = stream(world.seed, &label).uuid();
    Val::Str(format!("FolderID: {id}"))
}

fn graph_row(world: &World, rule: &InboxRule) -> Row {
    vec![
        r("UserPrincipalName", Val::Str(rule.mailbox.clone())),
        r("RuleName", Val::Str(rule.name.clone())),
        r("Sequence", Val::Int(rule.priority.into())),
        r("Enabled", Val::Bool(rule.enabled)),
        r("ForwardTo", graph_join(&rule.forward_to)),
        r("RedirectTo", graph_join(&rule.redirect_to)),
        r(
            "ForwardAsAttachment",
            graph_join(&rule.forward_as_attachment_to),
        ),
        r("Delete", graph_bool(rule.delete_message)),
        r("PermanentDelete", graph_bool(rule.soft_delete)),
        r("MoveToFolder", graph_folder(world, rule)),
        r("StopProcessingRules", graph_bool(rule.stop_processing)),
        r("MarkAsRead", graph_bool(rule.mark_as_read)),
        r("From", graph_join(&rule.from)),
        r("SubjectContains", graph_join(&rule.subject_contains)),
        r("BodyContains", graph_join(&rule.body_contains)),
        r("HasAttachments", graph_bool(rule.has_attachment)),
        r("IsImportant", Val::Null),
        r("RuleId", Val::Str(rule.graph_id.clone())),
    ]
}

fn inbox_evidence(rule: &InboxRule) -> Evidence {
    Evidence::InboxRule {
        mailbox: rule.mailbox.clone(),
        identity: rule.identity.to_string(),
        graph_id: rule.graph_id.clone(),
    }
}

fn write_mailbox_rules(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let rules = &c.world.inbox_rules;

    let run = c.runs.next("Rules", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Mailbox Rules Collection ===");
    if !rules.is_empty() {
        let rows: Vec<Row> = rules.iter().map(|r| exo_row(c.world, r)).collect();
        let rel = format!("{dir}/{}-MailboxRules.csv", run.stamp);
        let rendered = write_rows(c, tree, &rel, "inv.mailbox_rules", &rows)?;
        for (rule, span) in rules.iter().zip(&rendered.spans) {
            tree.row(
                &rel,
                "inbox_rules",
                keys::inbox_rule("inbox", &rule.mailbox, &rule.identity.to_string()),
            );
            tree.deliver(&inbox_evidence(rule), "inbox_rules", &rel, *span);
        }
    }

    let run = c.runs.next("Rules", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(
        run.local,
        "=== Starting Mailbox Rules Collection (Graph API) ===",
    );
    if !rules.is_empty() {
        let rows: Vec<Row> = rules.iter().map(|r| graph_row(c.world, r)).collect();
        let rel = format!("{dir}/{}-MailboxRulesGraph.csv", run.stamp);
        let rendered = write_rows(c, tree, &rel, "inv.mailbox_rules", &rows)?;
        for (rule, span) in rules.iter().zip(&rendered.spans) {
            tree.row(
                &rel,
                "inbox_rules",
                keys::inbox_rule("inbox", &rule.mailbox, &rule.graph_id),
            );
            tree.deliver(&inbox_evidence(rule), "inbox_rules", &rel, *span);
        }
    }

    Ok(())
}

fn transport_row(rule: &TransportRule) -> Row {
    vec![
        r("Name", Val::Str(rule.name.clone())),
        r("Description", Val::Str(rule.description.clone())),
        r("CreatedBy", Val::Str(rule.created_by.clone())),
        r(
            "WhenChanged",
            Val::Date(PsDate::dotnet(rule.when_changed, DtKind::Utc)),
        ),
        r("State", Val::Str(rule.state.clone())),
        r("Priority", Val::Int(rule.priority.into())),
        r("Mode", Val::Str(rule.mode.clone())),
    ]
}

fn write_transport_rules(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Rules", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Transport Rules Collection ===");
    let rules = &c.world.transport_rules;
    if rules.is_empty() {
        return Ok(());
    }
    let rows: Vec<Row> = rules.iter().map(transport_row).collect();
    let rel = format!("{dir}/{}-TransportRules.csv", run.stamp);
    let rendered = write_rows(c, tree, &rel, "inv.transport_rules", &rows)?;
    for (rule, span) in rules.iter().zip(&rendered.spans) {
        tree.row(&rel, "transport_rules", keys::transport_rule(&rule.name));
        tree.deliver(
            &Evidence::TransportRule(rule.name.clone()),
            "transport_rules",
            &rel,
            *span,
        );
    }
    Ok(())
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_mailbox_rules(c, tree)?;
    write_transport_rules(c, tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::load;

    fn folder_of(w: &World, rule: &InboxRule) -> Val {
        graph_row(w, rule)
            .into_iter()
            .find(|(k, _)| k == "MoveToFolder")
            .map(|(_, v)| v)
            .unwrap()
    }

    #[test]
    fn graph_folder_id_is_stable_per_mailbox_and_folder() {
        let w = World::build(&load("bec-aitm").unwrap(), 1).unwrap();
        let original = w
            .inbox_rules
            .iter()
            .find(|r| r.move_to_folder.is_some())
            .expect("a baseline rule moves to a folder")
            .clone();
        // A different rule on the same mailbox, moving to the same folder, reports the same id.
        let mut other = original.clone();
        other.identity += 1;
        other.graph_id = format!("{}-other", original.graph_id);
        assert_eq!(folder_of(&w, &original), folder_of(&w, &other));
        // A different folder is a different id.
        let mut elsewhere = original.clone();
        elsewhere.move_to_folder = Some("Archive".to_string());
        assert_ne!(folder_of(&w, &original), folder_of(&w, &elsewhere));
        // A rule without a folder has no id.
        let mut no_folder = original.clone();
        no_folder.move_to_folder = None;
        assert_eq!(folder_of(&w, &no_folder), Val::Null);
    }
}
