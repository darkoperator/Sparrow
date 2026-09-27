//! Get-OAuthPermissionsGraph (research state layouts §6): `EntraID/<t1>-OAuthPermissions/`,
//! `<t2>-ServicePrincipals/` and `<t3>-AppRegistrations/`, each its own stamp, into
//! `oauth_grants` and `applications`; plus the triage root's
//! `Triage-<tenant folder>/<yyyyMMddHHmm>-UserApplications.csv` (event layouts §3).

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Rendered, Row, Val, export_csv};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::world::{App, CredKind, Grant, GrantKind, User, World};
use std::collections::BTreeSet;
use uuid::Uuid;

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn opt(v: Option<String>) -> Val {
    v.map_or(Val::Null, Val::Str)
}

/// The two Microsoft tenants whose apps are first-party.
const MS_TENANTS: [&str; 2] = [
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
];

/// The collector's `ApplicationType` (Owner rows join all matches with `" & "`; Assignment rows
/// keep the first).
fn application_type(app: &App) -> String {
    if MS_TENANTS.contains(&app.owner_tenant.to_string().as_str()) {
        "Microsoft Application".to_string()
    } else if app
        .tags
        .iter()
        .any(|t| t == "WindowsAzureActiveDirectoryIntegratedApp")
    {
        "Enterprise Application".to_string()
    } else {
        "Internal Application".to_string()
    }
}

/// The SP `PublisherName`: the publisher, else `Microsoft` for a Microsoft-named app, else `""`.
fn publisher_name(app: &App) -> String {
    if !app.publisher.is_empty() {
        app.publisher.clone()
    } else if app.display_name.starts_with("Microsoft") {
        "Microsoft".to_string()
    } else {
        String::new()
    }
}

fn sp_of(world: &World, app_id: Uuid) -> Option<&App> {
    world.apps.iter().find(|a| a.app_id == app_id)
}

fn has_secret(app: &App) -> bool {
    app.credentials
        .iter()
        .any(|c| !c.on_service_principal && c.kind == CredKind::Password)
}

fn has_cert(app: &App) -> bool {
    app.credentials
        .iter()
        .any(|c| !c.on_service_principal && c.kind == CredKind::Certificate)
}

/// One OAuthPermissions.csv row with the `oauth_grants` key and the evidence it delivers.
struct GrantRow {
    row: Row,
    key: String,
    evidence: Evidence,
}

/// A delegated grant scope (25-property row).
fn delegated_row(world: &World, g: &Grant, client: &App, resource: &App, scope: &str) -> GrantRow {
    let principal = g.principal.as_deref().and_then(|p| world.user_by_upn(p));
    let principal_id = principal.map(|u| u.object_id.to_string());
    let row = vec![
        r("PermissionType", Val::Str("Delegated".into())),
        r("AppId", Val::Str(client.app_id.to_string())),
        r("ClientObjectId", Val::Str(client.sp_object_id.to_string())),
        r("AppDisplayName", Val::Str(client.display_name.clone())),
        r(
            "ResourceObjectId",
            Val::Str(resource.sp_object_id.to_string()),
        ),
        r(
            "ResourceDisplayName",
            Val::Str(resource.display_name.clone()),
        ),
        r("Permission", Val::Str(scope.to_string())),
        r("ConsentType", Val::Str(g.consent_type.clone())),
        r("PrincipalObjectId", opt(principal_id.clone())),
        r(
            "PrincipalDisplayName",
            principal.map_or(Val::Str(String::new()), |u| {
                Val::Str(u.display_name.clone())
            }),
        ),
        r("Homepage", Val::Str(String::new())),
        r("PublisherName", Val::Str(publisher_name(client))),
        r("ReplyUrls", Val::Str(client.reply_urls.join(", "))),
        r("ExpiryTime", Val::Null),
        r("CreatedDateTime", Val::Null),
        r(
            "AppOwnerOrganizationId",
            Val::Str(client.owner_tenant.to_string()),
        ),
        r("ApplicationStatus", Val::Str("Enabled".into())),
        r("ApplicationVisibility", Val::Str("Visible".into())),
        r("AssignmentRequired", Val::Str("Yes".into())),
        r("IsAppProxy", Val::Str("No".into())),
        r(
            "PublisherDisplayName",
            opt(client.verified_publisher.clone()),
        ),
        r("VerifiedPublisherId", Val::Null),
        r("AddedDateTime", Val::Null),
        r("SignInAudience", Val::Str(client.sign_in_audience.clone())),
        r("ApplicationType", Val::Str(application_type(client))),
    ];
    let key = keys::oauth_grant(
        &client.sp_object_id.to_string(),
        &resource.sp_object_id.to_string(),
        scope,
        principal_id.as_deref(),
    );
    GrantRow {
        row,
        key,
        evidence: Evidence::Grant {
            client_app_id: g.client_app_id,
            scope: scope.to_string(),
            principal: g.principal.clone(),
        },
    }
}

/// An application grant (27-property row: three extra columns the delegated-first header drops).
fn application_row(g: &Grant, client: &App, resource: &App, scope: &str) -> GrantRow {
    let row = vec![
        r("PermissionType", Val::Str("Application".into())),
        r("AppId", Val::Str(client.app_id.to_string())),
        r("ClientObjectId", Val::Str(client.sp_object_id.to_string())),
        r("AppDisplayName", Val::Str(client.display_name.clone())),
        r(
            "ResourceObjectId",
            Val::Str(resource.sp_object_id.to_string()),
        ),
        r(
            "ResourceDisplayName",
            Val::Str(resource.display_name.clone()),
        ),
        r("Permission", Val::Str(scope.to_string())),
        r("ConsentType", Val::Str("AllPrincipals".into())),
        r("PrincipalObjectId", Val::Null),
        r("PrincipalDisplayName", Val::Str(String::new())),
        r("Homepage", Val::Str(String::new())),
        r("PublisherName", Val::Str(publisher_name(client))),
        r("ReplyUrls", Val::Str(client.reply_urls.join(", "))),
        r("IsEnabled", Val::Bool(true)),
        r("Description", Val::Null),
        r(
            "CreationTimestamp",
            Val::Date(PsDate::dotnet(g.created, DtKind::Utc)),
        ),
        r("CreatedDateTime", Val::Null),
        r(
            "AppOwnerOrganizationId",
            Val::Str(client.owner_tenant.to_string()),
        ),
        r("ApplicationStatus", Val::Str("Enabled".into())),
        r("ApplicationVisibility", Val::Str("Visible".into())),
        r("AssignmentRequired", Val::Str("Yes".into())),
        r("IsAppProxy", Val::Str("No".into())),
        r(
            "PublisherDisplayName",
            opt(client.verified_publisher.clone()),
        ),
        r("VerifiedPublisherId", Val::Null),
        r("AddedDateTime", Val::Null),
        r("SignInAudience", Val::Str(client.sign_in_audience.clone())),
        r("ApplicationType", Val::Str(application_type(client))),
    ];
    let key = keys::oauth_grant(
        &client.sp_object_id.to_string(),
        &resource.sp_object_id.to_string(),
        scope,
        None,
    );
    GrantRow {
        row,
        key,
        evidence: Evidence::Grant {
            client_app_id: g.client_app_id,
            scope: scope.to_string(),
            principal: g.principal.clone(),
        },
    }
}

/// Renders `rows`, records the culture dates and one `record_key` per row.
fn write_rows(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    table: &'static str,
    rows: &[Row],
    keys: &[String],
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
    for key in keys {
        tree.row(rel, table, key.clone());
    }
    Ok(rendered)
}

/// Get-OAuthPermissionsGraph's three run folders, each with its own stamp. Delegated rows come
/// first (the 25-column header the collector produces); the application rows lose
/// `IsEnabled`/`Description`/`CreationTimestamp`.
fn write_oauth_permissions(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("EntraID", Some("OAuthPermissions"));
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting OAuth Permissions Collection ===");
    let mut grants: Vec<GrantRow> = Vec::new();
    for kind in [GrantKind::Delegated, GrantKind::Application] {
        for g in c.world.grants.iter().filter(|g| g.kind == kind) {
            let (Some(client), Some(resource)) = (
                sp_of(c.world, g.client_app_id),
                sp_of(c.world, g.resource_app_id),
            ) else {
                continue;
            };
            for scope in g.scope.split(' ').filter(|s| !s.is_empty()) {
                grants.push(match kind {
                    GrantKind::Delegated => delegated_row(c.world, g, client, resource, scope),
                    GrantKind::Application => application_row(g, client, resource, scope),
                });
            }
        }
    }
    let rows: Vec<Row> = grants.iter().map(|g| g.row.clone()).collect();
    let keys: Vec<String> = grants.iter().map(|g| g.key.clone()).collect();
    let rel = format!("{dir}/{}-OAuthPermissions.csv", run.stamp);
    let rendered = write_rows(c, tree, &rel, "inv.oauth", "oauth_grants", &rows, &keys)?;
    for (grant, span) in grants.iter().zip(&rendered.spans) {
        tree.deliver(&grant.evidence, "oauth_grants", &rel, *span);
    }

    let run = c.runs.next("EntraID", Some("ServicePrincipals"));
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let sps: Vec<&App> = c.world.apps.iter().collect();
    let rows: Vec<Row> = sps
        .iter()
        .map(|a| {
            vec![
                r("AppId", Val::Str(a.app_id.to_string())),
                r("AppDisplayName", Val::Str(a.display_name.clone())),
                r("AppDescription", Val::Null),
                r("AccountEnabled", Val::Bool(true)),
                r(
                    "AppOwnerOrganizationId",
                    Val::Str(a.owner_tenant.to_string()),
                ),
            ]
        })
        .collect();
    let keys: Vec<String> = sps
        .iter()
        .map(|a| keys::application(&a.app_id.to_string()))
        .collect();
    let rel = format!("{dir}/{}-ServicePrincipals.csv", run.stamp);
    write_rows(
        c,
        tree,
        &rel,
        "inv.service_principals",
        "applications",
        &rows,
        &keys,
    )?;

    let run = c.runs.next("EntraID", Some("AppRegistrations"));
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let apps: Vec<&App> = c.world.apps.iter().filter(|a| !a.first_party).collect();
    let rows: Vec<Row> = apps
        .iter()
        .map(|a| {
            vec![
                r("Id", Val::Str(a.object_id.to_string())),
                r("DisplayName", Val::Str(a.display_name.clone())),
                r("AppId", Val::Str(a.app_id.to_string())),
                r(
                    "CreatedDateTime",
                    Val::Date(PsDate::dotnet(a.created, DtKind::Utc)),
                ),
            ]
        })
        .collect();
    let keys: Vec<String> = apps
        .iter()
        .map(|a| keys::application(&a.app_id.to_string()))
        .collect();
    let rel = format!("{dir}/{}-AppRegistrations.csv", run.stamp);
    write_rows(
        c,
        tree,
        &rel,
        "inv.app_registrations",
        "applications",
        &rows,
        &keys,
    )?;
    Ok(())
}

/// One triage UserApplications.csv Owner row.
fn owner_row(app: &App, upn: &str) -> Row {
    vec![
        r("AssociationType", Val::Str("Owner".into())),
        r("AssociatedUser", Val::Str(upn.to_string())),
        r("ApplicationName", Val::Str(app.display_name.clone())),
        r("ApplicationId", Val::Str(app.app_id.to_string())),
        r("ObjectId", Val::Str(app.object_id.to_string())),
        r("PublisherName", Val::Str(app.publisher.clone())),
        r("ApplicationType", Val::Str(application_type(app))),
        r(
            "CreatedDateTime",
            Val::Date(PsDate::dotnet(app.created, DtKind::Utc)),
        ),
        r("ServicePrincipalEnabled", Val::Bool(true)),
        r("HasClientSecrets", Val::Bool(has_secret(app))),
        r("HasCertificates", Val::Bool(has_cert(app))),
        r("RequiredApiPermissionCount", Val::Int(0)),
        r("SignInAudience", Val::Str(app.sign_in_audience.clone())),
        r("Homepage", Val::Str(String::new())),
        r("WebRedirectUris", Val::Str(app.reply_urls.join("; "))),
        r("PublicClientRedirectUris", Val::Str(String::new())),
    ]
}

/// Start-MESTriage's `Get-EntraApplicationsForSpecificUsers`: apps the victims own, written
/// directly in the triage root `Triage-<tenant folder>/`.
fn write_user_applications(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let triage = c.runs.next("Triage", None);
    let dir = c.triage_root();
    tree.dir(&dir)?;
    c.log.add(
        triage.local,
        "=== Starting Entra Applications Collection ===",
    );
    let victims: Vec<&User> = c
        .world
        .victims
        .iter()
        .filter(|n| **n >= 1 && (**n as usize) <= c.world.users.len())
        .map(|n| c.world.user(*n))
        .collect();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::new();
    let mut keys = Vec::new();
    for victim in victims {
        for app in c.world.apps.iter() {
            if !app.owners.iter().any(|o| o == &victim.upn) {
                continue;
            }
            if seen.insert(app.object_id.to_string()) {
                rows.push(owner_row(app, &victim.upn));
                keys.push(keys::application_association(
                    &app.app_id.to_string(),
                    "Owner",
                    &victim.upn,
                ));
            }
        }
    }
    let rel = format!(
        "{dir}/{}-UserApplications.csv",
        triage.local.format("%Y%m%d%H%M")
    );
    write_rows(
        c,
        tree,
        &rel,
        "inv.user_applications",
        "applications",
        &rows,
        &keys,
    )?;
    Ok(())
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_oauth_permissions(c, tree)?;
    write_user_applications(c, tree)
}
