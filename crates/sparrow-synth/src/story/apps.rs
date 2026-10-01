//! Application storylines: an illicit consent grant, a credential added to a service principal,
//! and their look-alikes (a harmless consent, a sign-in to an app consented long ago, a
//! certificate rotation).

use super::{
    Ctx, Evidence, Modified, app_index, dir_audit, first_admin, push_audit_and_ual, push_signin,
    signin, unknown_device, well_known,
};
use crate::Result;
use crate::events::{SignInType, Target};
use crate::scenario::StoryKind;
use crate::world::{App, CredKind, Credential, Grant, GrantKind, HOSTING_ASNS, User, World};
use chrono::{DateTime, Duration, Utc};
use std::net::IpAddr;

/// Applies `ctx`'s storyline if it is an application kind; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        StoryKind::OauthConsent => oauth_consent(w, ctx),
        StoryKind::LowRiskConsent => low_risk_consent(w, ctx),
        StoryKind::AppSigninExistingConsent => app_signin_existing_consent(w, ctx)?,
        StoryKind::AppCredentialAdded => app_credential_added(w, ctx)?,
        StoryKind::CertRotation => cert_rotation(w, ctx)?,
        StoryKind::CloudConnector => cloud_connector(w, ctx)?,
        StoryKind::CloudConnectorOnboarding => cloud_connector_onboarding(w, ctx)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// A third-party multi-tenant app first seen in this tenant.
fn new_app(
    ctx: &mut Ctx,
    name: &str,
    publisher: &str,
    verified: bool,
    reply_url: &str,
    created: DateTime<Utc>,
) -> App {
    App {
        app_id: ctx.rng.uuid(),
        object_id: ctx.rng.uuid(),
        sp_object_id: ctx.rng.uuid(),
        display_name: name.to_string(),
        publisher: publisher.to_string(),
        verified_publisher: verified.then(|| publisher.to_string()),
        owner_tenant: ctx.rng.uuid(),
        sign_in_audience: "AzureADMultipleOrgs".to_string(),
        reply_urls: vec![reply_url.to_string()],
        created,
        sp_created: created + Duration::days(1),
        first_party: false,
        tags: Vec::new(),
        credentials: Vec::new(),
        owners: Vec::new(),
        assignees: Vec::new(),
    }
}

fn sp_target(app: &App, modified: Modified) -> Target {
    Target {
        id: app.sp_object_id.to_string(),
        display_name: app.display_name.clone(),
        kind: "ServicePrincipal".to_string(),
        upn: None,
        modified,
    }
}

/// The user consents to `app` for Microsoft Graph `scopes` from `ip`: the service principal is
/// created, the delegated grant added (one `Grant` per scope, for this user only), and the
/// consent recorded in the directory audit and the UAL.
fn consent(w: &mut World, ctx: &mut Ctx, app: App, scopes: &[&str], ip: IpAddr) {
    let a = ctx.a.clone();
    let t = ctx.t;
    let graph = well_known("Microsoft Graph");
    let scope_text = scopes.join(" ");
    w.apps.push(app.clone());

    let steps: [(&str, &str, &str, Modified); 3] = [
        (
            "Add service principal",
            "Add service principal.",
            "Add",
            vec![(
                "AppId".to_string(),
                String::new(),
                format!("[\"{}\"]", app.app_id),
            )],
        ),
        (
            "Add delegated permission grant",
            "Add delegated permission grant.",
            "Assign",
            vec![(
                "DelegatedPermissionGrant.Scope".to_string(),
                String::new(),
                format!("\"{scope_text}\""),
            )],
        ),
        (
            "Consent to application",
            "Consent to application.",
            "Assign",
            vec![
                (
                    "ConsentContext.IsAdminConsent".to_string(),
                    String::new(),
                    "\"False\"".to_string(),
                ),
                (
                    "ConsentAction.Permissions".to_string(),
                    String::new(),
                    format!("\"{scope_text}\""),
                ),
            ],
        ),
    ];
    for (activity, op, operation_type, modified) in steps {
        let audit = dir_audit(
            &mut ctx.rng,
            t,
            activity,
            "ApplicationManagement",
            operation_type,
            "Core Directory",
            &a,
            ip,
            vec![sp_target(&app, modified)],
        );
        push_audit_and_ual(w, ctx, audit, Some(op));
    }

    for scope in scopes {
        w.grants.push(Grant {
            kind: GrantKind::Delegated,
            client_app_id: app.app_id,
            resource_app_id: graph,
            scope: scope.to_string(),
            consent_type: "Principal".to_string(),
            principal: Some(a.upn.clone()),
            created: t,
        });
        ctx.ev.push(Evidence::Grant {
            client_app_id: app.app_id,
            scope: scope.to_string(),
            principal: Some(a.upn.clone()),
        });
    }
}

/// An illicit consent: an unverified mail app granted mail, files and offline access from the
/// attacker's replay address, then used a minute later.
fn oauth_consent(w: &mut World, ctx: &mut Ctx) {
    let app = new_app(
        ctx,
        "Mail Organizer Plus",
        "Mail Organizer",
        false,
        "https://app.mailorganizer.example/auth/callback",
        ctx.t - Duration::days(30),
    );
    let ip = w.attacker.replay_ip;
    let location = w.attacker.replay_location.clone();
    consent(
        w,
        ctx,
        app.clone(),
        &[
            "Mail.ReadWrite",
            "Mail.Send",
            "Files.ReadWrite.All",
            "offline_access",
            "User.Read",
        ],
        ip,
    );
    let a = ctx.a.clone();
    let session = ctx.rng.uuid();
    let mut s = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t + Duration::minutes(1),
        ip,
        &location,
        SignInType::Interactive,
        app.app_id,
        well_known("Microsoft Graph"),
        session,
    );
    unknown_device(&mut s);
    push_signin(w, ctx, &a, s, true);
}

/// A verified lunch-poll app granted only sign-in and profile scopes, from the office.
fn low_risk_consent(w: &mut World, ctx: &mut Ctx) {
    let app = new_app(
        ctx,
        "Team Lunch Poll",
        "Poll Vendor Ltd",
        true,
        "https://app.lunchpoll.example/signin",
        ctx.t - Duration::days(120),
    );
    let ip = ctx.a.office_ip;
    consent(
        w,
        ctx,
        app,
        &["openid", "profile", "email", "User.Read"],
        ip,
    );
}

/// A sign-in from the office to `Meeting Notes Pro`, which the user consented to before the
/// window (the grant is added if the world lacks it); no consent event.
fn app_signin_existing_consent(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let app = w.apps[app_index(w, |n| n == "Meeting Notes Pro", "Meeting Notes Pro")?].clone();
    let graph = well_known("Microsoft Graph");
    let granted = app.created + Duration::days(1);
    for scope in ["User.Read", "Calendars.Read"] {
        let exists = w.grants.iter().any(|g| {
            g.client_app_id == app.app_id
                && g.scope == scope
                && g.principal.as_deref() == Some(a.upn.as_str())
        });
        if !exists {
            w.grants.push(Grant {
                kind: GrantKind::Delegated,
                client_app_id: app.app_id,
                resource_app_id: graph,
                scope: scope.to_string(),
                consent_type: "Principal".to_string(),
                principal: Some(a.upn.clone()),
                created: granted,
            });
        }
        ctx.ev.push(Evidence::Grant {
            client_app_id: app.app_id,
            scope: scope.to_string(),
            principal: Some(a.upn.clone()),
        });
    }
    let session = ctx.rng.uuid();
    let s = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t,
        a.office_ip,
        &a.home,
        SignInType::Interactive,
        app.app_id,
        graph,
        session,
    );
    push_signin(w, ctx, &a, s, true);
    Ok(())
}

fn key_description(c: &Credential) -> String {
    let kind = match c.kind {
        CredKind::Password => "Password",
        CredKind::Certificate => "AsymmetricX509Cert",
    };
    format!(
        "\"[KeyIdentifier={},KeyType={kind},KeyUsage=Verify,DisplayName={}]\"",
        c.key_id, c.display_name
    )
}

/// A password credential added to the `Helpdesk Portal` service principal from the attacker's
/// replay address.
fn app_credential_added(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a = ctx.a.clone();
    let t = ctx.t;
    let i = app_index(w, |n| n == "Helpdesk Portal", "Helpdesk Portal")?;
    let cred = Credential {
        key_id: ctx.rng.uuid(),
        kind: CredKind::Password,
        display_name: "sync".to_string(),
        start: t,
        end: t + Duration::days(730),
        on_service_principal: true,
        added_by: Some(a.upn.clone()),
        added: t,
    };
    w.apps[i].credentials.push(cred.clone());
    let app = w.apps[i].clone();
    ctx.ev.push(Evidence::Credential {
        app_object_id: app.object_id,
        key_id: cred.key_id,
        on_service_principal: true,
    });

    let ip = w.attacker.replay_ip;
    let modified = vec![(
        "KeyDescription".to_string(),
        "[]".to_string(),
        format!("[{}]", key_description(&cred)),
    )];
    let added = dir_audit(
        &mut ctx.rng,
        t,
        "Add service principal credentials",
        "ApplicationManagement",
        "Update",
        "Core Directory",
        &a,
        ip,
        vec![sp_target(&app, modified)],
    );
    let update = dir_audit(
        &mut ctx.rng,
        t,
        "Update service principal",
        "ApplicationManagement",
        "Update",
        "Core Directory",
        &a,
        ip,
        vec![sp_target(&app, Vec::new())],
    );
    push_audit_and_ual(w, ctx, added, Some("Add service principal credentials."));
    // The service principal update appears in the UAL only; its directory audit is the
    // credential one above.
    let u = super::aad_for(w, &mut ctx.rng, &update, "Update service principal.");
    super::push_ual(w, ctx, u);
    Ok(())
}

/// An admin, signed in from the office, rotates the payroll app's certificate: the current one
/// expires in 20 days (its end date is moved there, so the state and the audit agree), and a new
/// two-year certificate is added to the application object beside it.
fn cert_rotation(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    const ACTIVITY: &str = "Update application – Certificates and secrets management ";
    let admin = first_admin(w)?;
    let t = ctx.t;
    let session = ctx.rng.uuid();
    let s = signin(
        w,
        &mut ctx.rng,
        &admin,
        t - Duration::minutes(15),
        admin.office_ip,
        &admin.home,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Microsoft Graph"),
        session,
    );
    push_signin(w, ctx, &admin, s, true);

    let i = app_index(w, |n| n.ends_with(" Payroll Sync"), "payroll")?;
    let expiring = t + Duration::days(20);
    for c in w.apps[i]
        .credentials
        .iter_mut()
        .filter(|c| c.kind == CredKind::Certificate && !c.on_service_principal)
    {
        c.end = expiring;
    }
    let before: Vec<String> = w.apps[i].credentials.iter().map(key_description).collect();
    let new = Credential {
        key_id: ctx.rng.uuid(),
        kind: CredKind::Certificate,
        display_name: format!("{} Certificate", w.apps[i].display_name),
        start: t,
        end: t + Duration::days(730),
        on_service_principal: false,
        added_by: Some(admin.upn.clone()),
        added: t,
    };
    w.apps[i].credentials.push(new.clone());
    let app = w.apps[i].clone();
    ctx.ev.push(Evidence::Credential {
        app_object_id: app.object_id,
        key_id: new.key_id,
        on_service_principal: false,
    });

    let after: Vec<String> = app.credentials.iter().map(key_description).collect();
    let modified = vec![(
        "KeyDescription".to_string(),
        format!("[{}]", before.join(",")),
        format!("[{}]", after.join(",")),
    )];
    let audit = dir_audit(
        &mut ctx.rng,
        t,
        ACTIVITY,
        "ApplicationManagement",
        "Update",
        "Core Directory",
        &admin,
        admin.office_ip,
        vec![Target {
            id: app.object_id.to_string(),
            display_name: app.display_name.clone(),
            kind: "Application".to_string(),
            upn: None,
            modified,
        }],
    );
    push_audit_and_ual(w, ctx, audit, Some(ACTIVITY));
    Ok(())
}

/// The connector app of this tenant (created by the onboarding storyline).
const CONNECTOR_APP: &str = "Calendar Sync Cloud";

/// The connector's backend: three addresses of one cloud region (RFC 3849 documentation space, a pool
/// of its own), on a cloud ASN that is NOT the attacker's. Every user of the connector signs in from
/// one of them (shared by all users, not one address per user).
fn connector_backend(
    user_k: usize,
    home: &crate::world::Location,
) -> (IpAddr, crate::world::Location) {
    let ip = IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001,
        0x0db8,
        4,
        0,
        0,
        0,
        0,
        1 + (user_k % 3) as u16,
    ));
    let mut region = home.clone();
    region.asn = HOSTING_ASNS[2].0;
    region.asn_org = HOSTING_ASNS[2].1.to_string();
    (ip, region)
}

/// `days` days of non-interactive token refreshes (python-httpx) by eight users of one city, from the
/// connector's backend, starting `first_day` days after the storyline's time.
fn connector_days(
    w: &mut World,
    ctx: &mut Ctx,
    app: &App,
    first_day: i64,
    days: i64,
) -> Result<()> {
    let a: User = ctx.a.clone();
    let staff: Vec<User> = std::iter::once(a.clone())
        .chain(
            w.users
                .iter()
                .filter(|u| u.home.city == a.home.city && u.upn != a.upn)
                .take(7)
                .cloned(),
        )
        .collect();
    if staff.len() < 6 {
        return Err(crate::Error::Scenario(format!(
            "{}: a cloud connector needs 6 users in {}, the tenant has {}",
            ctx.spec.id,
            a.home.city,
            staff.len()
        )));
    }
    for (k, user) in staff.iter().enumerate() {
        let (ip, region) = connector_backend(k, &a.home);
        for day in first_day..first_day + days {
            let session = ctx.rng.uuid();
            let mut s = signin(
                w,
                &mut ctx.rng,
                user,
                ctx.t + Duration::days(day) + Duration::minutes(k as i64 * 3),
                ip,
                &region,
                SignInType::NonInteractive,
                app.app_id,
                well_known("Microsoft Graph"),
                session,
            );
            s.user_agent = "python-httpx/0.27.0".to_string();
            push_signin(w, ctx, user, s, false);
        }
    }
    Ok(())
}

/// A new third-party SaaS connector onboards: its cloud backend refreshes tokens for the users of one
/// city every day for the first three days. The profile cannot know the connector yet, so a hosting
/// sign-in is a hosting sign-in (SPW-ID-002 hits); the steady state that follows is
/// `cloud_connector`.
fn cloud_connector_onboarding(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let app = new_app(
        ctx,
        CONNECTOR_APP,
        "Sync Vendor Ltd",
        true,
        "https://app.syncvendor.example/signin",
        ctx.t - Duration::days(90),
    );
    w.apps.push(app.clone());
    connector_days(w, ctx, &app, 0, 3)
}

/// The established connector: the same backend refreshes the same users' tokens on the days after its
/// onboarding. A tenant-wide cloud service is not an attacker, and its non-interactive cloud sign-ins
/// form no travel pair either.
fn cloud_connector(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let app = w.apps[app_index(w, |n| n == CONNECTOR_APP, CONNECTOR_APP)?].clone();
    connector_days(w, ctx, &app, 0, 4)
}
