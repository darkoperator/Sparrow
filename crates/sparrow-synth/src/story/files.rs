//! File storylines: a scripted mass download, an anonymous link, a OneNote / PDF lure shared
//! inside and outside the tenant, and their look-alikes.

use super::{Ctx, push_trace, push_ual, target};
use crate::Result;
use crate::events::TraceMsg;
use crate::scenario::StoryKind;
use crate::ual;
use crate::world::{User, World};
use chrono::Duration;

/// Applies `ctx`'s storyline if it is a file kind; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        StoryKind::MassDownload => mass_download(w, ctx),
        StoryKind::AnonymousLink => {
            let url = format!("{}/Shared Documents/Q3 invoices.xlsx", site(w, "Finance"));
            let ip = w.attacker.replay_ip;
            anonymous_link(w, ctx, &url, ip);
        }
        StoryKind::LureShare => lure_share(w, ctx),
        StoryKind::NormalDownload => normal_download(w, ctx),
        StoryKind::AnonymousLinkBenign => {
            let url = format!("{}/Shared Documents/Brochure.pdf", site(w, "Marketing"));
            let ip = ctx.a.office_ip;
            anonymous_link(w, ctx, &url, ip);
        }
        StoryKind::InternalDocxShare => internal_docx_share(w, ctx),
        _ => return Ok(false),
    }
    Ok(true)
}

fn tenant_word(w: &World) -> String {
    w.primary_domain()
        .split('.')
        .next()
        .unwrap_or("tenant")
        .to_string()
}

/// A SharePoint team site URL (no trailing `/`), as the baseline names them.
fn site(w: &World, name: &str) -> String {
    format!("https://{}.sharepoint.example/sites/{name}", tenant_word(w))
}

/// `user`'s OneDrive URL (no trailing `/`), as the baseline names it.
fn onedrive(w: &World, user: &User) -> String {
    format!(
        "https://{}-my.sharepoint.example/personal/{}",
        tenant_word(w),
        user.upn.replace(['.', '@', '-'], "_")
    )
}

/// A script downloads 60 invoices from the Finance site in twelve minutes.
fn mass_download(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let finance = site(w, "Finance");
    let (ip, ua) = (w.attacker.replay_ip, w.attacker.user_agent_scripted.clone());
    for i in 0..60i64 {
        let u = ual::sharepoint_file(
            w,
            &mut ctx.rng,
            &a,
            ctx.t + Duration::seconds(i * 12),
            "FileDownloaded",
            &finance,
            "Shared Documents/Invoices",
            &format!("INV-{}.pdf", 10_001 + i),
            ip,
            &ua,
        );
        push_ual(w, ctx, u);
    }
}

/// Five downloads from the Finance site over four hours, from the office.
fn normal_download(w: &mut World, ctx: &mut Ctx) {
    const FILES: [&str; 5] = [
        "Q3 Forecast.xlsx",
        "Budget 2026.xlsx",
        "Vendor List.xlsx",
        "Payment Run.xlsx",
        "Invoice-10231.pdf",
    ];
    let a = ctx.a.clone();
    let finance = site(w, "Finance");
    for (i, file) in FILES.iter().enumerate() {
        let u = ual::sharepoint_file(
            w,
            &mut ctx.rng,
            &a,
            ctx.t + Duration::minutes(i as i64 * 60),
            "FileDownloaded",
            &finance,
            "Shared Documents",
            file,
            a.office_ip,
            &a.client.user_agent,
        );
        push_ual(w, ctx, u);
    }
}

/// An anyone-with-the-link (view) link on the document at `url`.
fn anonymous_link(w: &mut World, ctx: &mut Ctx, url: &str, ip: std::net::IpAddr) {
    let a = ctx.a.clone();
    let u = ual::sharing(
        w,
        &mut ctx.rng,
        &a,
        ctx.t,
        "AnonymousLinkCreated",
        url,
        None,
        "View",
        ip,
    );
    push_ual(w, ctx, u);
}

/// The attacker uploads a OneNote lure and a PDF to the victim's OneDrive, shares them with an
/// external guest and the whole company, and mails the lure link to 15 recipients.
fn lure_share(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let ip = w.attacker.replay_ip;
    let od = onedrive(w, &a);
    let ua = a.client.user_agent.clone();
    for (minutes, file) in [(0, "Secure Document.one"), (1, "Remittance.pdf")] {
        let u = ual::sharepoint_file(
            w,
            &mut ctx.rng,
            &a,
            t + Duration::minutes(minutes),
            "FileUploaded",
            &od,
            "Documents",
            file,
            ip,
            &ua,
        );
        push_ual(w, ctx, u);
    }
    let invite = ual::sharing(
        w,
        &mut ctx.rng,
        &a,
        t + Duration::minutes(5),
        "SharingInvitationCreated",
        &format!("{od}/Documents/Secure Document.one"),
        Some(("accounts@partner-payments.example", "Guest")),
        "View",
        ip,
    );
    push_ual(w, ctx, invite);
    let link = ual::sharing(
        w,
        &mut ctx.rng,
        &a,
        t + Duration::minutes(5),
        "CompanyLinkCreated",
        &format!("{od}/Documents/Remittance.pdf"),
        None,
        "View",
        ip,
    );
    push_ual(w, ctx, link);

    let internal: Vec<String> = w
        .users
        .iter()
        .filter(|u| u.upn != a.upn)
        .map(|u| u.upn.clone())
        .take(8)
        .collect();
    let external = (1..=15 - internal.len()).map(|n| format!("ap@client{n}.example"));
    let recipients: Vec<(String, bool)> = internal
        .into_iter()
        .map(|r| (r, true))
        .chain(external.map(|r| (r, false)))
        .collect();
    for (i, (to, is_internal)) in recipients.into_iter().enumerate() {
        let trace = TraceMsg {
            trace_id: ctx.rng.uuid(),
            internet_message_id: ual::internet_message_id(&mut ctx.rng),
            received: t + Duration::minutes(6 + i as i64),
            sender: a.upn.clone(),
            recipients: vec![(to, "Delivered".to_string())],
            subject: "Secure document shared with you".to_string(),
            from_ip: Some(ip),
            to_ip: None,
            size: ctx.rng.range(20_000, 40_000) as u64,
            direction: if is_internal {
                "Originating"
            } else {
                "Outgoing"
            }
            .to_string(),
            connector_id: None,
        };
        push_trace(w, ctx, trace);
    }
}

/// The user uploads a plan and shares it with a colleague, from the office.
fn internal_docx_share(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let g = target(w, ctx, 2);
    let od = onedrive(w, &a);
    let u = ual::sharepoint_file(
        w,
        &mut ctx.rng,
        &a,
        ctx.t,
        "FileUploaded",
        &od,
        "Documents",
        "Plan.docx",
        a.office_ip,
        &a.client.user_agent,
    );
    push_ual(w, ctx, u);
    let s = ual::sharing(
        w,
        &mut ctx.rng,
        &a,
        ctx.t + Duration::minutes(2),
        "SharingSet",
        &format!("{od}/Documents/Plan.docx"),
        Some((g.upn.as_str(), "Member")),
        "Edit",
        a.office_ip,
    );
    push_ual(w, ctx, s);
}
