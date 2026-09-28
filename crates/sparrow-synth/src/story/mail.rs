//! Mail storylines: inbox rules that hide or forward mail, mailbox and transport-rule
//! forwarding, mailbox permissions, a `MailItemsAccessed` burst, mail sent from a new address,
//! finance searches, an automatic reply, a spoofed message, and their look-alikes.

use super::{
    Ctx, Evidence, attacker_session, first_admin, push_cmdlet, push_trace, push_ual, target,
};
use crate::events::TraceMsg;
use crate::scenario::StoryKind;
use crate::ual::{self, ItemRef};
use crate::world::{Email, InboxRule, MailboxPermission, TransportRule, User, World};
use crate::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use std::net::IpAddr;
use uuid::Uuid;

/// Outlook on the web, as mailbox audit records name it.
const OWA: &str = "Client=OWA;Action=ViaProxy";
/// Outlook desktop.
const OUTLOOK_DESKTOP: &str = "Client=MSExchangeRPC";
/// An app reading mail through Microsoft Graph.
const GRAPH_CLIENT: &str = "Client=REST;Client=RESTSystem;;";

/// A vendor whose mail the look-alikes file or receive. No baseline sender uses this domain, so
/// a rule on it never changes where the baseline's earlier mail was delivered.
const VENDOR_DOMAIN: &str = "tailwind-supplies.example";
const PARTNER_PAYMENTS: &str = "accounts@partner-payments.example";
const SYSTEM_ACTOR: &str = "NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)";

/// Applies `ctx`'s storyline if it is a mail kind; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        StoryKind::InboxRuleFinance => inbox_rule_finance(w, ctx),
        StoryKind::AdminInboxRule => admin_inbox_rule(w, ctx)?,
        StoryKind::ForwardingMailbox => {
            let (ip, fwd) = (w.attacker.replay_ip, w.attacker.forward_address.clone());
            let a = ctx.a.clone();
            set_forwarding(w, ctx, &a, ctx.t, &fwd, ip, true);
        }
        StoryKind::ForwardingInboxRule => forwarding_inbox_rule(w, ctx),
        StoryKind::ForwardingTransportRule => forwarding_transport_rule(w, ctx)?,
        StoryKind::MailboxPermissionGrant => mailbox_permission_grant(w, ctx)?,
        StoryKind::MiaBurst => mia_burst(w, ctx)?,
        StoryKind::SendNewIp => {
            let ip = w.attacker.send_ip;
            let a = ctx.a.clone();
            let session = attacker_session(w, ctx, &a, ctx.t);
            send(
                w,
                ctx,
                ip,
                OWA,
                session,
                PARTNER_PAYMENTS,
                "Updated bank details for invoice 4471",
            );
        }
        StoryKind::SearchFinance => {
            let ip = w.attacker.replay_ip;
            let a = ctx.a.clone();
            let t = ctx.t;
            let u = ual::search_query(
                w,
                &mut ctx.rng,
                &a,
                t,
                "Exchange",
                "invoice payment wire transfer",
                ip,
            );
            push_ual(w, ctx, u);
            let u = ual::search_query(
                w,
                &mut ctx.rng,
                &a,
                t + Duration::minutes(2),
                "SharePoint",
                "bank details",
                ip,
            );
            push_ual(w, ctx, u);
        }
        StoryKind::AutoreplyEnabled => {
            let ip = w.attacker.replay_ip;
            auto_reply(
                w,
                ctx,
                ip,
                "Enabled",
                &format!(
                    "Thank you for your message. Our banking details have changed; please send \
                     remittance to {PARTNER_PAYMENTS}."
                ),
            );
        }
        StoryKind::HeaderSpoof => header_spoof(w, ctx)?,
        StoryKind::VendorFilingRule => vendor_filing_rule(w, ctx),
        StoryKind::AdminBenignRule => admin_benign_rule(w, ctx)?,
        StoryKind::InternalForwarding => {
            let g = target(w, ctx, 2);
            let a = ctx.a.clone();
            let ip = a.office_ip;
            set_forwarding(w, ctx, &a, ctx.t, &g.upn, ip, true);
        }
        StoryKind::ForwardingRemoved => {
            let g = target(w, ctx, 2);
            let a = ctx.a.clone();
            let ip = a.office_ip;
            set_forwarding(w, ctx, &a, ctx.t, &g.upn, ip, false);
            set_forwarding(w, ctx, &a, ctx.t + Duration::days(2), "", ip, false);
        }
        StoryKind::SetMailboxOtherParam => {
            let admin = first_admin(w)?;
            let a = ctx.a.clone();
            let session = ctx.rng.uuid();
            push_cmdlet(
                w,
                ctx,
                &admin,
                ctx.t,
                "Set-Mailbox",
                &a.upn,
                &[
                    ("Identity", a.upn.as_str()),
                    ("RetainDeletedItemsFor", "30.00:00:00"),
                ],
                admin.office_ip,
                session,
            );
        }
        StoryKind::PermissionSystemDiscovery => permission_system_discovery(w, ctx)?,
        StoryKind::MiaSync => mia_sync(w, ctx),
        StoryKind::SendKnownIp => {
            let a = ctx.a.clone();
            let session = ctx.rng.uuid();
            send(
                w,
                ctx,
                a.office_ip,
                OUTLOOK_DESKTOP,
                session,
                "projects@partner.example",
                "Re: Project timeline",
            );
        }
        StoryKind::SearchBenign => {
            let a = ctx.a.clone();
            let u = ual::search_query(
                w,
                &mut ctx.rng,
                &a,
                ctx.t,
                "Exchange",
                "team offsite agenda",
                a.office_ip,
            );
            push_ual(w, ctx, u);
        }
        StoryKind::AutoreplyDisabled => {
            let ip = ctx.a.office_ip;
            auto_reply(w, ctx, ip, "Disabled", "");
        }
        StoryKind::HeaderClean => header_clean(w, ctx),
        _ => return Ok(false),
    }
    Ok(true)
}

/// An Exchange Graph-style opaque rule id (`AAMk...==`).
fn graph_id(ctx: &mut Ctx) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::from("AAMk");
    for _ in 0..40 {
        s.push(ALPHABET[ctx.rng.below(ALPHABET.len() as u64) as usize] as char);
    }
    s.push_str("==");
    s
}

/// An enabled, empty inbox rule `name` on `mailbox` created at `t` (priority 0, identity from
/// the storyline's stream); callers fill its conditions and actions.
fn new_rule(ctx: &mut Ctx, mailbox: &str, name: &str, t: DateTime<Utc>) -> InboxRule {
    InboxRule {
        mailbox: mailbox.to_string(),
        name: name.to_string(),
        identity: 1_000_000_000_000_000_000 + ctx.rng.below(1_000_000_000_000_000_000),
        priority: 0,
        enabled: true,
        from: Vec::new(),
        subject_contains: Vec::new(),
        body_contains: Vec::new(),
        subject_or_body_contains: Vec::new(),
        has_attachment: false,
        move_to_folder: None,
        copy_to_folder: None,
        delete_message: false,
        soft_delete: false,
        forward_to: Vec::new(),
        forward_as_attachment_to: Vec::new(),
        redirect_to: Vec::new(),
        mark_as_read: false,
        stop_processing: false,
        created: t,
        graph_id: graph_id(ctx),
    }
}

fn add_rule(w: &mut World, ctx: &mut Ctx, rule: InboxRule) {
    ctx.ev.push(Evidence::InboxRule {
        mailbox: rule.mailbox.clone(),
        identity: rule.identity,
    });
    w.inbox_rules.push(rule);
}

/// The rule identity Exchange logs: `<mailbox>\<rule name>`.
fn rule_object(mailbox: &str, name: &str) -> String {
    format!("{mailbox}\\{name}")
}

/// The victim's own finance-keyword rule, from the attacker's session: finance mail is marked
/// read and hidden in RSS Feeds.
fn inbox_rule_finance(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let session = attacker_session(w, ctx, &a, t);
    push_cmdlet(
        w,
        ctx,
        &a,
        t,
        "New-InboxRule",
        &rule_object(&a.upn, "."),
        &[
            ("Name", "."),
            ("SubjectOrBodyContainsWords", "invoice;payment;wire"),
            ("MoveToFolder", "RSS Feeds"),
            ("MarkAsRead", "True"),
            ("StopProcessingRules", "True"),
        ],
        ip,
        session,
    );
    let mut rule = new_rule(ctx, &a.upn, ".", t);
    rule.subject_or_body_contains = vec![
        "invoice".to_string(),
        "payment".to_string(),
        "wire".to_string(),
    ];
    rule.move_to_folder = Some("RSS Feeds".to_string());
    rule.mark_as_read = true;
    rule.stop_processing = true;
    add_rule(w, ctx, rule);
}

/// An admin account creates a forwarding and deleting rule on `g`'s mailbox, changes it to
/// redirect too, and creates and removes a throw-away rule.
fn admin_inbox_rule(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let g = target(w, ctx, 2);
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let fwd = w.attacker.forward_address.clone();
    let session = ctx.rng.uuid();
    let sync = rule_object(&g.upn, "Sync");
    let tmp = rule_object(&g.upn, "tmp");
    push_cmdlet(
        w,
        ctx,
        &admin,
        t,
        "New-InboxRule",
        &sync,
        &[
            ("Mailbox", g.upn.as_str()),
            ("Name", "Sync"),
            ("ForwardTo", fwd.as_str()),
            ("DeleteMessage", "True"),
        ],
        ip,
        session,
    );
    push_cmdlet(
        w,
        ctx,
        &admin,
        t + Duration::minutes(10),
        "Set-InboxRule",
        &sync,
        &[("Identity", sync.as_str()), ("RedirectTo", fwd.as_str())],
        ip,
        session,
    );
    push_cmdlet(
        w,
        ctx,
        &admin,
        t + Duration::minutes(30),
        "New-InboxRule",
        &tmp,
        &[
            ("Mailbox", g.upn.as_str()),
            ("Name", "tmp"),
            ("MoveToFolder", "Deleted Items"),
        ],
        ip,
        session,
    );
    push_cmdlet(
        w,
        ctx,
        &admin,
        t + Duration::minutes(40),
        "Remove-InboxRule",
        &tmp,
        &[("Identity", tmp.as_str())],
        ip,
        session,
    );
    let mut rule = new_rule(ctx, &g.upn, "Sync", t);
    rule.forward_to = vec![fwd.clone()];
    rule.redirect_to = vec![fwd];
    rule.delete_message = true;
    add_rule(w, ctx, rule);
    Ok(())
}

/// `Set-Mailbox -ForwardingSmtpAddress` by `actor` on its own mailbox at `t`; an empty
/// `address` clears forwarding (logged as the empty string). `with_deliver` also logs
/// `DeliverToMailboxAndForward False`.
fn set_forwarding(
    w: &mut World,
    ctx: &mut Ctx,
    actor: &User,
    t: DateTime<Utc>,
    address: &str,
    ip: IpAddr,
    with_deliver: bool,
) {
    let value = if address.is_empty() {
        String::new()
    } else {
        format!("smtp:{address}")
    };
    let mut params = vec![
        ("Identity", actor.upn.as_str()),
        ("ForwardingSmtpAddress", value.as_str()),
    ];
    if with_deliver && !address.is_empty() {
        params.push(("DeliverToMailboxAndForward", "False"));
    }
    let session = ctx.rng.uuid();
    push_cmdlet(
        w,
        ctx,
        actor,
        t,
        "Set-Mailbox",
        &actor.upn,
        &params,
        ip,
        session,
    );
    if let Some(mb) = w.mailboxes.get_mut(&actor.upn) {
        mb.forwarding_smtp = (!value.is_empty()).then_some(value);
        mb.deliver_and_forward = false;
        mb.when_changed = t;
    }
    if !ctx.ev.contains(&Evidence::Mailbox(actor.upn.clone())) {
        ctx.ev.push(Evidence::Mailbox(actor.upn.clone()));
    }
}

/// The victim's rule forwarding a vendor's invoices to the attacker.
fn forwarding_inbox_rule(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let fwd = w.attacker.forward_address.clone();
    let session = attacker_session(w, ctx, &a, t);
    let from = "billing@vendor-invoices.example";
    push_cmdlet(
        w,
        ctx,
        &a,
        t,
        "New-InboxRule",
        &rule_object(&a.upn, "AP"),
        &[("Name", "AP"), ("From", from), ("ForwardTo", fwd.as_str())],
        ip,
        session,
    );
    let mut rule = new_rule(ctx, &a.upn, "AP", t);
    rule.from = vec![from.to_string()];
    rule.forward_to = vec![fwd];
    add_rule(w, ctx, rule);
}

/// An admin account adds a transport rule that blind-copies all outbound mail to the attacker.
fn forwarding_transport_rule(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let fwd = w.attacker.forward_address.clone();
    let name = "Journal copy";
    let session = ctx.rng.uuid();
    push_cmdlet(
        w,
        ctx,
        &admin,
        t,
        "New-TransportRule",
        name,
        &[
            ("Name", name),
            ("SentToScope", "NotInOrganization"),
            ("BlindCopyTo", fwd.as_str()),
        ],
        ip,
        session,
    );
    let priority = w.transport_rules.len() as u32;
    w.transport_rules.push(TransportRule {
        name: name.to_string(),
        guid: ctx.rng.uuid(),
        state: "Enabled".to_string(),
        mode: "Enforce".to_string(),
        priority,
        created_by: admin.display_name.clone(),
        when_changed: t,
        description: format!(
            "If the message:\r\n\tIs sent to 'Outside the organization'\r\nTake the following \
             actions:\r\n\tBlind carbon copy (Bcc) the message to '{fwd}'\r\n"
        ),
        blind_copy_to: vec![fwd],
        redirect_to: Vec::new(),
        copy_to: Vec::new(),
        add_to_recipients: Vec::new(),
    });
    ctx.ev.push(Evidence::TransportRule(name.to_string()));
    Ok(())
}

fn add_permission(w: &mut World, ctx: &mut Ctx, p: MailboxPermission) {
    ctx.ev.push(Evidence::MailboxPermission {
        mailbox: p.mailbox.clone(),
        grantee: p.grantee.clone(),
        right: p.right.clone(),
        folder: p.folder.clone(),
    });
    w.mailbox_permissions.push(p);
}

/// An admin account grants the storyline's user (`a`) FullAccess and SendAs on `g`'s mailbox.
fn mailbox_permission_grant(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let a = ctx.a.clone();
    let g = target(w, ctx, 2);
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let session = ctx.rng.uuid();
    push_cmdlet(
        w,
        ctx,
        &admin,
        t,
        "Add-MailboxPermission",
        &g.upn,
        &[
            ("Identity", g.upn.as_str()),
            ("User", a.upn.as_str()),
            ("AccessRights", "FullAccess"),
            ("InheritanceType", "All"),
        ],
        ip,
        session,
    );
    push_cmdlet(
        w,
        ctx,
        &admin,
        t + Duration::minutes(2),
        "Add-RecipientPermission",
        &g.upn,
        &[
            ("Identity", g.upn.as_str()),
            ("Trustee", a.upn.as_str()),
            ("AccessRights", "SendAs"),
        ],
        ip,
        session,
    );
    add_permission(
        w,
        ctx,
        MailboxPermission {
            mailbox: g.upn.clone(),
            grantee: a.upn.clone(),
            right: "full_access".to_string(),
            folder: None,
            access_rights: vec!["FullAccess".to_string()],
            deny: false,
            inheritance: Some("All".to_string()),
        },
    );
    add_permission(
        w,
        ctx,
        MailboxPermission {
            mailbox: g.upn,
            grantee: a.upn,
            right: "send_as".to_string(),
            folder: None,
            access_rights: vec!["SendAs".to_string()],
            deny: false,
            inheritance: None,
        },
    );
    Ok(())
}

/// Exchange's own FullAccess grant on the discovery mailbox for Discovery Management.
fn permission_system_discovery(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let discovery = w
        .mailboxes
        .values()
        .find(|m| m.recipient_type == "DiscoveryMailbox")
        .map(|m| m.upn.clone())
        .ok_or_else(|| Error::Scenario("the tenant has no discovery mailbox".into()))?;
    let session = ctx.rng.uuid();
    let mut u = ual::exchange_admin(
        w,
        &mut ctx.rng,
        &admin,
        ctx.t,
        "Add-MailboxPermission",
        &discovery,
        &[
            ("Identity", discovery.as_str()),
            ("User", "Discovery Management"),
            ("AccessRights", "FullAccess"),
            ("InheritanceType", "All"),
        ],
        admin.office_ip,
        session,
    );
    // Exchange itself performs the grant: a system identity, no client address.
    u.audit.shift_remove("ClientIP");
    u.audit
        .insert("UserKey".into(), serde_json::json!(SYSTEM_ACTOR));
    u.audit.insert("UserType".into(), serde_json::json!(3));
    u.audit
        .insert("UserId".into(), serde_json::json!(SYSTEM_ACTOR));
    u.user_id = SYSTEM_ACTOR.to_string();
    push_ual(w, ctx, u);
    ctx.ev.push(Evidence::MailboxPermission {
        mailbox: discovery,
        grantee: "Discovery Management".to_string(),
        right: "full_access".to_string(),
        folder: None,
    });
    Ok(())
}

/// Messages `user` received in the 14 days before `t` (baseline and storyline trace rows
/// delivered to them), oldest first: (Internet message id, size).
fn received_mail(w: &World, user: &User, t: DateTime<Utc>) -> Vec<(String, u64)> {
    let first = (t - Duration::days(14)).max(w.window_start()).date_naive();
    let mut out = Vec::new();
    let mut date = first;
    while date <= t.date_naive() {
        for m in w.day(date).trace {
            let delivered = m
                .recipients
                .iter()
                .any(|(r, s)| r == &user.upn && s == "Delivered");
            if delivered && m.received < t {
                out.push((m.internet_message_id, m.size));
            }
        }
        date = date.succ_opt().expect("date in range");
    }
    out
}

/// The attacker reads the victim's mail through the consented app (or Outlook's client id) from
/// its mailbox-access address: 12 `Bind` records over ten minutes, each over one or two
/// folders of 8-20 messages the victim received.
fn mia_burst(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a = ctx.a.clone();
    let t = ctx.t;
    let ip = w.attacker.mailbox_ip;
    let consented = w.apps.iter().find(|app| {
        app.display_name == "Mail Organizer Plus"
            && w.grants
                .iter()
                .any(|g| g.client_app_id == app.app_id && g.principal.as_deref() == Some(&a.upn))
    });
    let (app_id, client_info) = match consented {
        Some(app) => (app.app_id, GRAPH_CLIENT),
        None => (super::well_known("Microsoft Office"), OWA),
    };
    let session = attacker_session(w, ctx, &a, t);
    let pool = received_mail(w, &a, t);
    if pool.is_empty() {
        return Err(Error::Scenario(format!(
            "{}: {} received no mail before {t} to read",
            ctx.spec.id, a.upn
        )));
    }
    for i in 0..12i64 {
        let time = t + Duration::seconds(i * 50);
        let n_folders = if ctx.rng.chance(0.5) { 2 } else { 1 };
        let mut folders = Vec::new();
        for path in ["\\Inbox", "\\Finance"].iter().take(n_folders) {
            let want = (ctx.rng.range(8, 20) as usize).min(pool.len());
            let start = ctx.rng.below(pool.len() as u64) as usize;
            let items: Vec<(String, u64)> = (0..want)
                .map(|k| pool[(start + k) % pool.len()].clone())
                .collect();
            folders.push((path.to_string(), items));
        }
        let u = ual::mail_items_accessed(
            w,
            &mut ctx.rng,
            &a,
            time,
            "Bind",
            &folders,
            ip,
            client_info,
            app_id,
            session,
            false,
        );
        push_ual(w, ctx, u);
    }
    Ok(())
}

/// Outlook desktop synchronizing twelve folders over ten minutes from the office.
fn mia_sync(w: &mut World, ctx: &mut Ctx) {
    const FOLDERS: [&str; 12] = [
        "\\Inbox",
        "\\Sent Items",
        "\\Drafts",
        "\\Deleted Items",
        "\\Archive",
        "\\Junk Email",
        "\\Outbox",
        "\\Calendar",
        "\\Contacts",
        "\\Tasks",
        "\\Notes",
        "\\Conversation History",
    ];
    let a = ctx.a.clone();
    let office = super::well_known("Microsoft Office");
    let session = ctx.rng.uuid();
    for (i, path) in FOLDERS.iter().enumerate() {
        let time = ctx.t + Duration::seconds(i as i64 * 50);
        let u = ual::mail_items_accessed(
            w,
            &mut ctx.rng,
            &a,
            time,
            "Sync",
            &[(path.to_string(), Vec::new())],
            a.office_ip,
            OUTLOOK_DESKTOP,
            office,
            session,
            false,
        );
        push_ual(w, ctx, u);
    }
}

/// A message from the storyline's user to `to` at its time from `ip`: the outbound trace row
/// and the owner's `Send` record.
fn send(
    w: &mut World,
    ctx: &mut Ctx,
    ip: IpAddr,
    client_info: &str,
    session: Uuid,
    to: &str,
    subject: &str,
) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let imid = ual::internet_message_id(&mut ctx.rng);
    let size = ctx.rng.range(8_000, 60_000) as u64;
    let trace = TraceMsg {
        trace_id: ctx.rng.uuid(),
        internet_message_id: imid.clone(),
        received: t,
        sender: a.upn.clone(),
        recipients: vec![(to.to_string(), "Delivered".to_string())],
        subject: subject.to_string(),
        from_ip: Some(ip),
        to_ip: None,
        size,
        direction: "Outgoing".to_string(),
        connector_id: None,
    };
    push_trace(w, ctx, trace);
    let item = ItemRef::new(w, &a.upn, "\\Sent Items", &imid, subject, size);
    let u = ual::mailbox_item(
        w,
        &mut ctx.rng,
        &a,
        &a,
        t,
        "Send",
        Some(item),
        ip,
        client_info,
        session,
    );
    push_ual(w, ctx, u);
}

/// `Set-MailboxAutoReplyConfiguration` by the user from `ip`, and the mailbox's reply state.
fn auto_reply(w: &mut World, ctx: &mut Ctx, ip: IpAddr, state: &str, message: &str) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let session = ctx.rng.uuid();
    let mut params = vec![("Identity", a.upn.as_str()), ("AutoReplyState", state)];
    if !message.is_empty() {
        params.push(("ExternalMessage", message));
    }
    push_cmdlet(
        w,
        ctx,
        &a,
        t,
        "Set-MailboxAutoReplyConfiguration",
        &a.upn,
        &params,
        ip,
        session,
    );
    if let Some(mb) = w.mailboxes.get_mut(&a.upn) {
        mb.auto_reply.state = state.to_string();
        mb.auto_reply.internal = message.to_string();
        mb.auto_reply.external = message.to_string();
        mb.auto_reply.audience = if message.is_empty() { "None" } else { "All" }.to_string();
        mb.auto_reply.start = t;
        mb.auto_reply.end = t + Duration::days(30);
        mb.when_changed = t;
    }
    ctx.ev.push(Evidence::Mailbox(a.upn));
}

/// Records an inbound message and its trace row.
fn deliver(w: &mut World, ctx: &mut Ctx, email: Email, envelope_from: &str) {
    let size = (email.body.len() as u64) + 4_000;
    let trace = TraceMsg {
        trace_id: ctx.rng.uuid(),
        internet_message_id: email.message_id.clone(),
        received: email.date,
        sender: envelope_from.to_string(),
        recipients: email
            .to
            .iter()
            .map(|r| (r.clone(), "Delivered".to_string()))
            .collect(),
        subject: email.subject.clone(),
        from_ip: Some(email.originating_ip),
        to_ip: None,
        size,
        direction: "Incoming".to_string(),
        connector_id: None,
    };
    push_trace(w, ctx, trace);
    ctx.ev.push(Evidence::Email(email.message_id.clone()));
    w.emails.push(email);
}

/// Exchange Online front-end and mailbox server names for `Received` headers.
fn exo_hops(ctx: &mut Ctx) -> (String, String) {
    let edge = format!("{}.prod.outlook.example", ual::server_name(&mut ctx.rng));
    let mbx = format!("{}.prod.outlook.example", ual::server_name(&mut ctx.rng));
    (edge, mbx)
}

/// A message to `g` impersonating the first admin from a look-alike sender that fails SPF and
/// DMARC.
fn header_spoof(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let g = target(w, ctx, 1);
    let t = ctx.t;
    let primary = w.primary_domain().to_string();
    let date = t.to_rfc2822();
    let (edge, mbx) = exo_hops(ctx);
    let ip = w.attacker.send_ip;
    let email = Email {
        message_id: format!("<{}@mail.spoof-mail.test>", ctx.rng.hex(24)),
        subject: "Urgent: wire transfer approval needed today".to_string(),
        from_display: admin.display_name.clone(),
        from: format!("admin@{primary}"),
        return_path: "<bounce@spoof-mail.test>".to_string(),
        to: vec![g.upn.clone()],
        date: t,
        received: vec![
            format!("from {edge} by {mbx} with Microsoft SMTP Server; {date}"),
            format!("from relay1.spoof-mail.test by {edge} with Microsoft SMTP Server; {date}"),
            format!("from sender.spoof-mail.test by relay1.spoof-mail.test with ESMTP; {date}"),
        ],
        auth_results: format!(
            "spf=fail smtp.mailfrom=spoof-mail.test; dkim=none; dmarc=fail action=quarantine \
             header.from={primary}"
        ),
        auth_as: "Anonymous".to_string(),
        auth_mechanism: "04".to_string(),
        body: format!(
            "Hi {},\r\n\r\nPlease process the attached wire transfer before 3 PM today. I am in \
             meetings and cannot take calls.\r\n\r\n{}\r\n",
            g.first, admin.display_name
        ),
        originating_ip: ip,
        attachment: None,
    };
    deliver(w, ctx, email, "bounce@spoof-mail.test");
    Ok(())
}

/// A vendor newsletter to `g` that passes SPF, DKIM and DMARC.
fn header_clean(w: &mut World, ctx: &mut Ctx) {
    let g = target(w, ctx, 2);
    let t = ctx.t;
    let date = t.to_rfc2822();
    let (edge, mbx) = exo_hops(ctx);
    let sender = format!("news@{VENDOR_DOMAIN}");
    let ip = ctx.roaming.next();
    let email = Email {
        message_id: format!("<{}@mail.{VENDOR_DOMAIN}>", ctx.rng.hex(24)),
        subject: "Tailwind Supplies: autumn catalogue".to_string(),
        from_display: "Tailwind Supplies".to_string(),
        from: sender.clone(),
        return_path: format!("<{sender}>"),
        to: vec![g.upn.clone()],
        date: t,
        received: vec![
            format!("from {edge} by {mbx} with Microsoft SMTP Server; {date}"),
            format!("from mail.{VENDOR_DOMAIN} by {edge} with Microsoft SMTP Server; {date}"),
            format!("from app.{VENDOR_DOMAIN} by mail.{VENDOR_DOMAIN} with ESMTP; {date}"),
        ],
        auth_results: format!(
            "spf=pass smtp.mailfrom={VENDOR_DOMAIN}; dkim=pass header.d={VENDOR_DOMAIN}; \
             dmarc=pass action=none header.from={VENDOR_DOMAIN}"
        ),
        auth_as: "Anonymous".to_string(),
        auth_mechanism: "04".to_string(),
        body: "Our autumn catalogue is out. Browse the new range on our website.\r\n".to_string(),
        originating_ip: ip,
        attachment: None,
    };
    deliver(w, ctx, email, &sender);
}

/// The user files a vendor's mail into a folder, from the office.
fn vendor_filing_rule(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let from = format!("billing@{VENDOR_DOMAIN}");
    let session = ctx.rng.uuid();
    push_cmdlet(
        w,
        ctx,
        &a,
        t,
        "New-InboxRule",
        &rule_object(&a.upn, "Vendor mail"),
        &[
            ("Name", "Vendor mail"),
            ("From", from.as_str()),
            ("MoveToFolder", "Vendors"),
        ],
        a.office_ip,
        session,
    );
    let mut rule = new_rule(ctx, &a.upn, "Vendor mail", t);
    rule.from = vec![from];
    rule.move_to_folder = Some("Vendors".to_string());
    add_rule(w, ctx, rule);
}

/// The admin files processed mail on the shared accounts-payable mailbox, with
/// `DeleteMessage False` spelled out.
fn admin_benign_rule(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let t = ctx.t;
    let mailbox = format!("accounts-payable@{}", w.primary_domain());
    let session = ctx.rng.uuid();
    push_cmdlet(
        w,
        ctx,
        &admin,
        t,
        "New-InboxRule",
        &rule_object(&mailbox, "Processed"),
        &[
            ("Mailbox", mailbox.as_str()),
            ("Name", "Processed"),
            ("MoveToFolder", "Processed"),
            ("DeleteMessage", "False"),
        ],
        admin.office_ip,
        session,
    );
    let mut rule = new_rule(ctx, &mailbox, "Processed", t);
    rule.move_to_folder = Some("Processed".to_string());
    add_rule(w, ctx, rule);
    Ok(())
}
