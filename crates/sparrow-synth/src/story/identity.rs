//! Identity storylines: the adversary-in-the-middle sign-in and what follows it in Entra ID
//! (risk, confirmed compromise, a new MFA method, a federated domain, a new mobile device), and
//! their look-alikes.

use super::{
    Ctx, Evidence, Modified, dir_audit, first_admin, push_audit, push_audit_and_ual, push_risk,
    push_signin, push_ual, risk_text, signin, unknown_device, user_target, well_known,
};
use crate::events::{RiskDetection, SignInType, Target};
use crate::scenario::StoryKind;
use crate::ual;
use crate::world::{
    LOCATIONS, Location, MICROSOFT_ASN, MfaRegistration, MobileDevice, RiskyUser, User, World,
};
use crate::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use std::net::IpAddr;

/// Applies `ctx`'s storyline if it is an identity kind; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        StoryKind::AitmSignin => aitm_signin(w, ctx),
        StoryKind::ConfirmedCompromised => confirmed_compromised(w, ctx)?,
        StoryKind::MfaMethodAdded => {
            let ip = w.attacker.replay_ip;
            register_authenticator(w, ctx, ip, "Pixel 8");
        }
        StoryKind::MfaNewHire => mfa_new_hire(w, ctx),
        StoryKind::DomainFederation => domain_federation(w, ctx)?,
        StoryKind::DomainPropertyUpdate => domain_property_update(w, ctx)?,
        StoryKind::NewMobileDevice => new_mobile_device(w, ctx),
        StoryKind::OldMobileDevice => old_mobile_device(w, ctx),
        StoryKind::RiskDismissed => risk_dismissed(w, ctx),
        StoryKind::MicrosoftAsnSignin => microsoft_asn_signin(w, ctx),
        StoryKind::PlausibleTravel => plausible_travel(w, ctx)?,
        StoryKind::SameIpTokenUse => same_ip_token_use(w, ctx),
        _ => return Ok(false),
    }
    Ok(true)
}

fn set_risky_user(
    w: &mut World,
    ctx: &mut Ctx,
    level: &str,
    state: &str,
    detail: &str,
    at: DateTime<Utc>,
) {
    let a = &ctx.a;
    w.risky_users.insert(
        a.upn.clone(),
        RiskyUser {
            upn: a.upn.clone(),
            user_id: a.object_id,
            display_name: a.display_name.clone(),
            level: level.to_string(),
            state: state.to_string(),
            detail: detail.to_string(),
            updated: at,
        },
    );
    ctx.ev.push(Evidence::RiskyUser(a.upn.clone()));
}

#[allow(clippy::too_many_arguments)]
fn risk_detection(
    ctx: &mut Ctx,
    activity: &str,
    event_type: &str,
    level: &str,
    state: &str,
    detail: &str,
    timing: &str,
    activity_time: DateTime<Utc>,
    detected: DateTime<Utc>,
) -> RiskDetection {
    let a = &ctx.a;
    RiskDetection {
        id: ctx.rng.hex(64),
        user: a.upn.clone(),
        user_id: a.object_id,
        user_display: a.display_name.clone(),
        activity: activity.to_string(),
        event_type: event_type.to_string(),
        level: level.to_string(),
        state: state.to_string(),
        detail: detail.to_string(),
        timing: timing.to_string(),
        source: "IdentityProtection".to_string(),
        token_issuer_type: "AzureAD".to_string(),
        detected,
        activity_time,
        updated: detected,
        ip: None,
        location: None,
        request_id: None,
        correlation_id: None,
        additional_info: "[]".to_string(),
    }
}

/// A token stolen through an adversary-in-the-middle proxy: the user's own sign-in, the proxied
/// MFA sign-in from a hosting ASN, the token replayed by a script from another hosting ASN, a
/// mailbox logon, and Identity Protection's detection.
fn aitm_signin(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let office = well_known("Microsoft Office");
    let office_home = well_known("OfficeHome");
    let exchange = well_known("Office 365 Exchange Online");
    let p2 = w.licence.p2();
    let att = w.attacker.clone();

    // (1) The user's own sign-in from home.
    let own_session = ctx.rng.uuid();
    let s1 = signin(
        w,
        &mut ctx.rng,
        &a,
        t - Duration::minutes(40),
        a.home_ip,
        &a.home,
        SignInType::Interactive,
        office_home,
        exchange,
        own_session,
    );
    push_signin(w, ctx, &a, s1, true);

    // (2) The proxied sign-in: the user's user agent, MFA satisfied, from the proxy.
    let session = ctx.rng.uuid();
    let mut s2 = signin(
        w,
        &mut ctx.rng,
        &a,
        t,
        att.proxy_ip,
        &att.location,
        SignInType::Interactive,
        office_home,
        exchange,
        session,
    );
    unknown_device(&mut s2);
    s2.risk_during = risk_text(w, "high");
    s2.risk_aggregated = risk_text(w, "high");
    s2.risk_detail = risk_text(w, "none");
    if p2 {
        s2.risk_state = "atRisk".to_string();
        s2.risk_event_types = vec![
            "anomalousToken".to_string(),
            "unfamiliarFeatures".to_string(),
        ];
    }
    // The proxy relays the MFA prompt: the proxied sign-in is an MFA sign-in, so the audit log
    // records the interrupted attempt (`UserLoginFailed` + `ResultStatus` Success) a few seconds
    // before the success it completes. Forced rather than a share, because this sign-in always
    // passes through the prompt -- that is the attack. The record is the same user, address,
    // application and client as `s2`, and carries no session of its own to keep.
    if let Some((error, gap)) = crate::baseline::interrupt_for(w, &s2, true) {
        let at = s2.time - Duration::seconds(gap);
        // A stream keyed by the sign-in, so the storyline's own `ctx.rng` draws are untouched.
        let mut istream = crate::rng::stream(w.seed, &format!("interrupt-record/{}", s2.id));
        let u = crate::baseline::interrupt_record(w, &mut istream, &a, &s2, at, s2.ip, error);
        ctx.ev.push(crate::story::Evidence::Ual(u.id));
        push_ual(w, ctx, u);
    }
    push_signin(w, ctx, &a, s2, true);

    // (3) The replayed token: a script, single factor, same session.
    let mut s3 = signin(
        w,
        &mut ctx.rng,
        &a,
        t + Duration::minutes(3),
        att.replay_ip,
        &att.replay_location,
        SignInType::NonInteractive,
        office,
        exchange,
        session,
    );
    unknown_device(&mut s3);
    s3.user_agent = att.user_agent_axios.clone();
    s3.risk_during = risk_text(w, "medium");
    s3.risk_aggregated = risk_text(w, "high");
    s3.risk_detail = risk_text(w, "none");
    if p2 {
        s3.risk_state = "atRisk".to_string();
    }
    let (s3_request, s3_correlation) = (s3.id, s3.correlation_id);
    push_signin(w, ctx, &a, s3, true);

    // (4) The script opens the mailbox.
    let login = ual::mailbox_item(
        w,
        &mut ctx.rng,
        &a,
        &a,
        t + Duration::minutes(4),
        "MailboxLogin",
        None,
        att.replay_ip,
        &att.user_agent_axios,
        session,
    );
    push_ual(w, ctx, login);

    // (5) Identity Protection flags the replayed token and the user.
    let detected = t + Duration::minutes(5);
    let mut r = risk_detection(
        ctx,
        "signin",
        "anomalousToken",
        "high",
        "atRisk",
        "none",
        "offline",
        t + Duration::minutes(3),
        detected,
    );
    r.ip = Some(att.replay_ip);
    r.location = Some(att.replay_location.clone());
    r.request_id = Some(s3_request);
    r.correlation_id = Some(s3_correlation);
    r.additional_info = json!([{"Key": "userAgent", "Value": att.user_agent_axios}]).to_string();
    push_risk(w, ctx, r);
    set_risky_user(w, ctx, "high", "atRisk", "none", detected);
}

/// An admin confirms the user compromised in Identity Protection.
fn confirmed_compromised(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let a = ctx.a.clone();
    let t = ctx.t;
    let r = risk_detection(
        ctx,
        "user",
        "adminConfirmedUserCompromised",
        "high",
        "confirmedCompromised",
        "adminConfirmedUserCompromised",
        "offline",
        t,
        t,
    );
    push_risk(w, ctx, r);
    set_risky_user(
        w,
        ctx,
        "high",
        "confirmedCompromised",
        "adminConfirmedUserCompromised",
        t,
    );
    let audit = dir_audit(
        &mut ctx.rng,
        t,
        "Confirm user compromised",
        "IdentityProtection",
        "Update",
        "Identity Protection",
        &admin,
        admin.office_ip,
        vec![user_target(&a, Vec::new())],
    );
    push_audit(w, ctx, audit);
    Ok(())
}

/// The Authenticator app on `device_name` registered for the storyline's user, from `ip`:
/// the security-info registration, the `Update user` of the strong-authentication details (and
/// its UAL record), and the MFA registration state. A user who already has the Authenticator
/// app (on their own device) gets a second one.
pub(super) fn register_authenticator(w: &mut World, ctx: &mut Ctx, ip: IpAddr, device_name: &str) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let registered_before = w.mfa.get(&a.upn).map_or(0, |m| {
        m.methods
            .iter()
            .filter(|x| *x == "microsoftAuthenticator")
            .count()
    });
    let mut devices: Vec<serde_json::Value> = Vec::new();
    for _ in 0..registered_before {
        devices.push(json!({
            "DeviceName": a.client.device_name,
            "DeviceToken": "",
            "Id": ctx.rng.uuid().to_string(),
            "AuthenticationType": "Notification, OTP",
        }));
    }
    let old = serde_json::Value::Array(devices.clone());
    devices.push(json!({
        "DeviceName": device_name,
        "DeviceToken": "",
        "Id": ctx.rng.uuid().to_string(),
        "AuthenticationType": "Notification, OTP",
    }));
    let new = serde_json::Value::Array(devices);

    let registered = dir_audit(
        &mut ctx.rng,
        t,
        "User registered security info",
        "UserManagement",
        "Add",
        "Authentication Methods",
        &a,
        ip,
        vec![user_target(&a, Vec::new())],
    );
    push_audit(w, ctx, registered);

    let modified = vec![(
        "StrongAuthenticationPhoneAppDetail".to_string(),
        old.to_string(),
        new.to_string(),
    )];
    let update = dir_audit(
        &mut ctx.rng,
        t,
        "Update user",
        "UserManagement",
        "Update",
        "Core Directory",
        &a,
        ip,
        vec![user_target(&a, modified)],
    );
    push_audit_and_ual(w, ctx, update, Some("Update user."));

    let mfa = w
        .mfa
        .entry(a.upn.clone())
        .or_insert_with(|| MfaRegistration {
            methods: vec!["password".to_string()],
            default_method: None,
            is_admin: a.is_admin,
            is_mfa_registered: false,
            is_mfa_capable: false,
            is_sspr_registered: false,
            last_updated: t,
        });
    mfa.methods.push("microsoftAuthenticator".to_string());
    if mfa.default_method.is_none() {
        mfa.default_method = Some("push".to_string());
    }
    mfa.is_mfa_registered = true;
    mfa.is_mfa_capable = true;
    mfa.last_updated = t;
    ctx.ev.push(Evidence::Mfa(a.upn.clone()));
}

/// A new starter with no second factor yet: a password-only sign-in from the office, then the
/// registration of the Authenticator app on their own phone (their only one).
fn mfa_new_hire(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    if let Some(m) = w.mfa.get_mut(&a.upn) {
        m.methods.retain(|x| x != "microsoftAuthenticator");
        m.default_method = None;
        m.is_mfa_registered = false;
        m.is_mfa_capable = false;
    }
    let session = ctx.rng.uuid();
    let mut s = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t - Duration::minutes(10),
        a.office_ip,
        &a.home,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    // No second factor registered yet: the password alone.
    s.auth_requirement = "singleFactorAuthentication".to_string();
    s.mfa = None;
    s.auth_methods = vec!["Password".to_string()];
    push_signin(w, ctx, &a, s, true);
    register_authenticator(w, ctx, a.office_ip, &a.client.device_name);
}

fn domain_target(domain: &str, modified: Modified) -> Target {
    Target {
        id: domain.to_string(),
        display_name: domain.to_string(),
        kind: "Domain".to_string(),
        upn: None,
        modified,
    }
}

/// An admin session from the attacker's replay address adds, verifies and federates a domain.
fn domain_federation(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let ip = w.attacker.replay_ip;
    let word: String = w
        .tenant
        .name
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    let word = if word.is_empty() {
        "tenant".to_string()
    } else {
        word
    };
    let domain = format!("{word}-sso.test");
    let steps: [(i64, &str, &str, Modified); 3] = [
        (
            0,
            "Add unverified domain",
            "Add domain to company.",
            Vec::new(),
        ),
        (5, "Verify domain", "Verify domain.", Vec::new()),
        (
            10,
            "Set domain authentication",
            "Set domain authentication.",
            vec![(
                "LiveType".to_string(),
                "\"Managed\"".to_string(),
                "\"Federated\"".to_string(),
            )],
        ),
    ];
    for (minutes, activity, op, modified) in steps {
        let audit = dir_audit(
            &mut ctx.rng,
            ctx.t + Duration::minutes(minutes),
            activity,
            "DirectoryManagement",
            if minutes == 0 { "Add" } else { "Update" },
            "Core Directory",
            &admin,
            ip,
            vec![domain_target(&domain, modified)],
        );
        push_audit_and_ual(w, ctx, audit, Some(op));
    }
    Ok(())
}

/// An admin marks the primary domain as the default from the office.
fn domain_property_update(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let admin = first_admin(w)?;
    let domain = w.primary_domain().to_string();
    let audit = dir_audit(
        &mut ctx.rng,
        ctx.t,
        "Update domain",
        "DirectoryManagement",
        "Update",
        "Core Directory",
        &admin,
        admin.office_ip,
        vec![domain_target(
            &domain,
            vec![(
                "IsDefault".to_string(),
                "\"false\"".to_string(),
                "\"true\"".to_string(),
            )],
        )],
    );
    push_audit_and_ual(w, ctx, audit, Some("Update domain."));
    Ok(())
}

/// A new iPhone starts syncing the user's mailbox over ActiveSync.
fn new_mobile_device(w: &mut World, ctx: &mut Ctx) {
    let device = MobileDevice {
        mailbox: ctx.a.upn.clone(),
        device_id: ctx.rng.hex(32).to_ascii_uppercase(),
        friendly_name: "iPhone".to_string(),
        device_type: "iPhone".to_string(),
        model: "iPhone".to_string(),
        os: "iOS 18.2".to_string(),
        user_agent: "Apple-iPhone16C1/2201.102".to_string(),
        client_type: "EAS".to_string(),
        first_sync: ctx.t,
        last_sync: w.collected_at() - Duration::hours(2),
        access_state: "Allowed".to_string(),
        access_reason: "Global".to_string(),
        when_created: ctx.t,
    };
    ctx.ev.push(Evidence::MobileDevice {
        mailbox: device.mailbox.clone(),
        device_id: device.device_id.clone(),
    });
    w.mobile_devices.push(device);
}

/// The user's long-standing phone: first synced 200 days before the window, still syncing.
fn old_mobile_device(w: &mut World, ctx: &mut Ctx) {
    let (ws, we) = (w.window_start(), w.window_end());
    let first_sync = ws - Duration::days(200);
    let upn = ctx.a.upn.clone();
    let i = match w.mobile_devices.iter().position(|d| d.mailbox == upn) {
        Some(i) => i,
        None => {
            w.mobile_devices.push(MobileDevice {
                mailbox: upn.clone(),
                device_id: ctx.rng.hex(32).to_ascii_uppercase(),
                friendly_name: format!("{}'s iPhone", ctx.a.first),
                device_type: "iPhone".to_string(),
                model: "iPhone 14".to_string(),
                os: "iOS 17.5".to_string(),
                user_agent: "Apple-iPhone/1401.28".to_string(),
                client_type: "OutlookMobile".to_string(),
                first_sync,
                last_sync: ctx.t,
                access_state: "Allowed".to_string(),
                access_reason: "Global".to_string(),
                when_created: first_sync,
            });
            w.mobile_devices.len() - 1
        }
    };
    let d = &mut w.mobile_devices[i];
    d.first_sync = first_sync;
    d.when_created = first_sync;
    if d.last_sync < ws || d.last_sync >= we {
        d.last_sync = ctx.t;
    }
    ctx.ev.push(Evidence::MobileDevice {
        mailbox: upn,
        device_id: d.device_id.clone(),
    });
}

/// A low unfamiliar-features detection an admin dismissed.
fn risk_dismissed(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let mut r = risk_detection(
        ctx,
        "signin",
        "unfamiliarFeatures",
        "low",
        "dismissed",
        "adminDismissedAllRiskForUser",
        "realtime",
        t,
        t,
    );
    r.ip = Some(a.home_ip);
    r.location = Some(a.home.clone());
    r.additional_info = json!([{"Key": "userAgent", "Value": a.client.user_agent}]).to_string();
    push_risk(w, ctx, r);
    set_risky_user(
        w,
        ctx,
        "none",
        "dismissed",
        "adminDismissedAllRiskForUser",
        t,
    );
}

/// A sign-in from a Cloud PC: a Microsoft address (not a hosting provider) at the user's home.
fn microsoft_asn_signin(w: &mut World, ctx: &mut Ctx) {
    let a = ctx.a.clone();
    let ip = ctx.shared.next_ip();
    let location = Location {
        asn: MICROSOFT_ASN.0,
        asn_org: MICROSOFT_ASN.1.to_string(),
        ..a.home.clone()
    };
    let session = ctx.rng.uuid();
    let s = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t,
        ip,
        &location,
        SignInType::Interactive,
        well_known("Microsoft Office"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, &a, s, true);
}

/// Great-circle distance in km.
fn distance_km(a: &Location, b: &Location) -> f64 {
    let (la1, lo1, la2, lo2) = (
        a.lat.to_radians(),
        a.lon.to_radians(),
        b.lat.to_radians(),
        b.lon.to_radians(),
    );
    let h = ((la2 - la1) / 2.0).sin().powi(2)
        + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    2.0 * 6371.0 * h.sqrt().asin()
}

/// A flight: home 14 hours before, then a far city a plane could reach in that time.
fn plausible_travel(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a = ctx.a.clone();
    let hours = 14.0;
    // User homes and ordinary destinations; the last two cities are attacker infrastructure.
    let cities = &LOCATIONS[..LOCATIONS.len() - 2];
    let dest = cities
        .iter()
        .filter(|c| {
            let d = distance_km(&a.home, c);
            d >= 500.0 && d / hours < 800.0
        })
        .max_by(|x, y| distance_km(&a.home, x).total_cmp(&distance_km(&a.home, y)))
        .ok_or_else(|| {
            Error::Scenario(format!(
                "{}: no city 500 km or more from {} is reachable in {hours} hours",
                ctx.spec.id, a.home.city
            ))
        })?
        .clone();
    let office_home = well_known("OfficeHome");
    let exchange = well_known("Office 365 Exchange Online");

    let session = ctx.rng.uuid();
    let departure = ctx.t - Duration::hours(14);
    let before = signin(
        w,
        &mut ctx.rng,
        &a,
        departure,
        a.home_ip,
        &a.home,
        SignInType::Interactive,
        office_home,
        exchange,
        session,
    );
    push_signin(w, ctx, &a, before, true);

    let ip = ctx.shared.next_ip();
    // The trip itself, so the baseline keeps this user at the destination from the arrival to
    // the end of the window and out of the air in between: a home sign-in next to the arrival
    // is what a correct impossible-travel rule must not see on its look-alike.
    w.trips.push(crate::world::Trip {
        user: a.upn.clone(),
        departure,
        arrival: ctx.t,
        ip,
        location: dest.clone(),
    });
    let session = ctx.rng.uuid();
    let after = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t,
        ip,
        &dest,
        SignInType::Interactive,
        office_home,
        exchange,
        session,
    );
    push_signin(w, ctx, &a, after, true);
    Ok(())
}

/// An interactive sign-in and the refresh of its token 20 minutes later, same IP and client.
fn same_ip_token_use(w: &mut World, ctx: &mut Ctx) {
    let a: User = ctx.a.clone();
    let session = ctx.rng.uuid();
    let first = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t,
        a.home_ip,
        &a.home,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, &a, first, true);
    let refresh = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t + Duration::minutes(20),
        a.home_ip,
        &a.home,
        SignInType::NonInteractive,
        well_known("Microsoft Office"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, &a, refresh, false);
}
