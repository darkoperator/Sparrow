//! Configuration storylines: an eDiscovery search and export, audit tampering (which changes
//! what Microsoft 365 logs from its time on, through `AuditState` and the mailbox's audit
//! fields that `baseline::ual_logged` / `baseline::mailbox_logged` read), and their
//! look-alikes.

use super::{Ctx, Evidence, first_admin, push_cmdlet, push_ual};
use crate::Result;
use crate::scenario::StoryKind;
use crate::ual;
use crate::world::World;
use chrono::Duration;

/// Applies `ctx`'s storyline if it is a configuration kind; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        StoryKind::EdiscoverySearch => ediscovery_search(w, ctx)?,
        StoryKind::EdiscoveryViewOnly => {
            let admin = first_admin(w)?;
            let u = ual::discovery(
                w,
                &mut ctx.rng,
                &admin,
                ctx.t,
                "SearchViewed",
                "Contract review 2026",
                admin.office_ip,
            );
            push_ual(w, ctx, u);
        }
        StoryKind::AuditTamper => audit_tamper(w, ctx)?,
        StoryKind::AuditConfigBenign => audit_config_benign(w, ctx)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// An admin account creates, runs and exports a content search from the attacker's address.
fn ediscovery_search(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let ip = w.attacker.replay_ip;
    for (minutes, op) in [
        (0, "SearchCreated"),
        (1, "SearchStarted"),
        (30, "SearchExported"),
    ] {
        let u = ual::discovery(
            w,
            &mut ctx.rng,
            &admin,
            ctx.t + Duration::minutes(minutes),
            op,
            "Legal hold 7",
            ip,
        );
        push_ual(w, ctx, u);
    }
    Ok(())
}

/// An admin account turns auditing off step by step from the attacker's address: the user's
/// mailbox auditing, a bypass association, organization mailbox auditing, and finally UAL
/// ingestion. Each cmdlet's own record is logged; its effect starts at the cmdlet's time (UAL
/// ingestion one second after, so the cmdlet that disables it is still ingested).
fn audit_tamper(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let a = ctx.a.clone();
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let session = ctx.rng.uuid();

    push_cmdlet(
        w,
        ctx,
        &admin,
        t,
        "Set-Mailbox",
        &a.upn,
        &[("Identity", a.upn.as_str()), ("AuditEnabled", "False")],
        ip,
        session,
    );
    let bypass_at = t + Duration::minutes(5);
    push_cmdlet(
        w,
        ctx,
        &admin,
        bypass_at,
        "Set-MailboxAuditBypassAssociation",
        &a.upn,
        &[("Identity", a.upn.as_str()), ("AuditBypassEnabled", "True")],
        ip,
        session,
    );
    if let Some(mb) = w.mailboxes.get_mut(&a.upn) {
        mb.audit_enabled = false;
        mb.audit_disabled_since = Some(t);
        mb.bypass = true;
        mb.bypass_since = Some(bypass_at);
        mb.when_changed = bypass_at;
    }
    ctx.ev.push(Evidence::Mailbox(a.upn.clone()));

    let org_at = t + Duration::minutes(10);
    let org = w.tenant.initial_domain.clone();
    push_cmdlet(
        w,
        ctx,
        &admin,
        org_at,
        "Set-OrganizationConfig",
        &org,
        &[("AuditDisabled", "True")],
        ip,
        session,
    );
    w.audit.org_audit_disabled = true;
    w.audit.org_audit_disabled_at = Some(org_at);

    let ual_at = t + Duration::minutes(15);
    push_cmdlet(
        w,
        ctx,
        &admin,
        ual_at,
        "Set-AdminAuditLogConfig",
        "Admin Audit Log Settings",
        &[("UnifiedAuditLogIngestionEnabled", "False")],
        ip,
        session,
    );
    w.audit.ual_ingestion_enabled = false;
    w.audit.ual_disabled_at = Some(ual_at + Duration::seconds(1));
    ctx.ev.push(Evidence::AuditConfig);
    Ok(())
}

/// The admin lengthens the audit retention and adds an audited owner action, from the office.
fn audit_config_benign(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let a = ctx.a.clone();
    let t = ctx.t;
    let session = ctx.rng.uuid();
    push_cmdlet(
        w,
        ctx,
        &admin,
        t,
        "Set-AdminAuditLogConfig",
        "Admin Audit Log Settings",
        &[("AdminAuditLogAgeLimit", "180.00:00:00")],
        admin.office_ip,
        session,
    );
    w.audit.admin_audit_log_age_limit = "180.00:00:00".to_string();
    // No `Evidence::AuditConfig`: the organization-level state row is one row for the whole
    // tenant, and what it shows to SPW-CFG-001 (ingestion, auditing on or off) is set by the
    // tamper, not by this change. A shared state row cannot identify a storyline; the cmdlet's
    // own UAL record is this look-alike's evidence.

    let at = t + Duration::minutes(2);
    push_cmdlet(
        w,
        ctx,
        &admin,
        at,
        "Set-Mailbox",
        &a.upn,
        &[
            ("Identity", a.upn.as_str()),
            ("AuditOwner", "SearchQueryInitiated"),
        ],
        admin.office_ip,
        session,
    );
    if let Some(mb) = w.mailboxes.get_mut(&a.upn) {
        if !mb.audit_owner.iter().any(|x| x == "SearchQueryInitiated") {
            mb.audit_owner.push("SearchQueryInitiated".to_string());
        }
        mb.when_changed = at;
    }
    ctx.ev.push(Evidence::Mailbox(a.upn));
    Ok(())
}
