//! Correlation negatives: look-alikes for the rules that correlate two kinds of evidence
//! (`evidence_all_of` in `rules/coverage.yaml`). Each carries both evidence halves, so the
//! evidence really lands, but the time or actor condition of the rule fails: the risky sign-in
//! is too old, or the second half is benign. A rule that only checks "both kinds exist" would
//! fire on them; the gate proves the real rule does not.

use super::{Ctx, push_signin, risk_text, signin, unknown_device, well_known};
use crate::Result;
use crate::events::SignInType;
use crate::scenario::StoryKind;
use crate::ual;
use crate::world::World;
use chrono::Duration;

/// Applies `ctx`'s storyline if it is a correlation negative; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        // SPW-ID-010: the risky sign-in is three hours before the (benign) rule.
        StoryKind::InboxRuleAfterStaleRisk => {
            stale_risky_signin(w, ctx, Duration::hours(3));
            super::mail::vendor_filing_rule(w, ctx);
        }
        // SPW-ID-001: the MFA method is registered two days after the risky sign-in.
        StoryKind::MfaAfterStaleRisk => {
            stale_risky_signin(w, ctx, Duration::days(2));
            let (ip, device) = (ctx.a.office_ip, ctx.a.client.device_name.clone());
            super::identity::register_authenticator(w, ctx, ip, &device);
        }
        // SPW-FILE-002: the anonymous link is created 30 hours after the risky sign-in.
        StoryKind::AnonymousLinkAfterStaleRisk => {
            stale_risky_signin(w, ctx, Duration::hours(30));
            let url = format!(
                "{}/Shared Documents/Brochure.pdf",
                super::files::site(w, "Marketing")
            );
            let ip = ctx.a.office_ip;
            super::files::anonymous_link(w, ctx, &url, ip);
        }
        // SPW-FILE-003: the lure is uploaded, and shared with a guest 30 hours later.
        StoryKind::LureSharedLate => lure_shared_late(w, ctx),
        _ => return Ok(false),
    }
    Ok(true)
}

/// The storyline user's proxied (attacker) sign-in with a high risk level `before` the
/// storyline's time: the risky half of a correlated pair, too early to pair with what follows.
fn stale_risky_signin(w: &mut World, ctx: &mut Ctx, before: Duration) {
    let a = ctx.a.clone();
    let att = w.attacker.clone();
    let session = ctx.rng.uuid();
    let mut s = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t - before,
        att.proxy_ip,
        &att.location,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    unknown_device(&mut s);
    s.risk_during = risk_text(w, "high");
    s.risk_aggregated = risk_text(w, "high");
    s.risk_detail = risk_text(w, "none");
    if w.licence.p2() {
        s.risk_state = "atRisk".to_string();
        s.risk_event_types = vec![
            "anomalousToken".to_string(),
            "unfamiliarFeatures".to_string(),
        ];
    }
    push_signin(w, ctx, &a, s, true);
}

/// A OneNote lure uploaded to the user's OneDrive and shared with an external guest a day and
/// a half later, from the office (the upload and the share are both recorded).
fn lure_shared_late(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let (t, ip) = (ctx.t, a.office_ip);
    let od = super::files::onedrive(w, &a);
    let up = ual::sharepoint_file(
        w,
        &mut ctx.rng,
        &a,
        t,
        "FileUploaded",
        &od,
        "Documents",
        "Onboarding.one",
        ip,
        &a.client.user_agent,
    );
    super::push_ual(w, ctx, up);
    let share = ual::sharing(
        w,
        &mut ctx.rng,
        &a,
        t + Duration::hours(30),
        "SharingInvitationCreated",
        &format!("{od}/Documents/Onboarding.one"),
        Some(("hr@partner-payments.example", "Guest")),
        "View",
        ip,
    );
    super::push_ual(w, ctx, share);
}
