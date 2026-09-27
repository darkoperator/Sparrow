//! Microsoft-Extractor-Suite applications: Get-OAuthPermissionsGraph
//! (`EntraID/<ts>-OAuthPermissions/OAuthPermissions.csv`, `<ts>-ServicePrincipals`, and
//! `<ts>-AppRegistrations`) into `oauth_grants` and `applications`, and the triage
//! `UserApplications.csv` into `applications` associations (research state layouts §6).

use crate::Result;
use crate::db::state_tables::{APPLICATIONS, OAUTH_GRANTS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::apps::{oauth_grant_key, permission_type};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, load_tables, lower, read_state_records, reject, require_any_key,
};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.oauth", Box::new(OAuthPermissionsParser));
    r.register("inv.service_principals", Box::new(ServicePrincipalsParser));
    r.register("inv.app_registrations", Box::new(AppRegistrationsParser));
    r.register("inv.user_applications", Box::new(UserApplicationsParser));
}

/// A `"; "`-joined collector list (`""` gives no items).
fn semi_list(rec: &Rec, key: &str) -> Vec<String> {
    rec.text(key)
        .map(|s| {
            s.split("; ")
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

const GRANT_COLS: &[&str] = &[
    "permission_type",
    "client_id",
    "client_name",
    "resource_id",
    "resource_name",
    "permission",
    "consent_type",
    "principal_id",
    "principal_name",
    "risk_category",
    "publisher",
    "verified_publisher",
    "created",
    "sign_in_audience",
];

/// OAuthPermissions.csv: one row per delegated scope and application app role.
pub struct OAuthPermissionsParser;

impl ArtifactParser for OAuthPermissionsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &["PermissionType", "ClientObjectId"],
            "OAuth permission",
        )?;
        let mut rows = TableRows::new(&OAUTH_GRANTS, GRANT_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = oauth_grant_key(&rec) else {
                reject(
                    ctx,
                    r,
                    "OAuth permission row has no ClientObjectId or Permission",
                )?;
                continue;
            };
            let mut c = CellRow::new(GRANT_COLS);
            c.set(
                "permission_type",
                Cell::text(permission_type(rec.text("PermissionType"))),
            )
            .set("client_id", Cell::text(lower(rec.text("ClientObjectId"))))
            .set("client_name", Cell::text(rec.text("AppDisplayName")))
            .set(
                "resource_id",
                Cell::text(lower(rec.text("ResourceObjectId"))),
            )
            .set("resource_name", Cell::text(rec.text("ResourceDisplayName")))
            .set("permission", Cell::text(rec.text("Permission")))
            .set("consent_type", Cell::text(rec.text("ConsentType")))
            .set(
                "principal_id",
                Cell::text(lower(rec.text("PrincipalObjectId"))),
            )
            .set(
                "principal_name",
                Cell::text(rec.text("PrincipalDisplayName")),
            )
            .set("publisher", Cell::text(rec.text("PublisherName")))
            .set(
                "verified_publisher",
                Cell::text(rec.text("PublisherDisplayName")),
            )
            .set("created", Cell::time(rec.text("CreatedDateTime")))
            .set("sign_in_audience", Cell::text(rec.text("SignInAudience")));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const SP_COLS: &[&str] = &[
    "app_id",
    "display_name",
    "description",
    "enabled",
    "owner_org_id",
];

/// ServicePrincipals.csv: 5 columns, one row per service principal.
pub struct ServicePrincipalsParser;

impl ArtifactParser for ServicePrincipalsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["AppId", "AppDisplayName"], "service principal")?;
        let mut rows = TableRows::new(&APPLICATIONS, SP_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(app_id) = lower(rec.text("AppId")) else {
                reject(ctx, r, "service principal row has no AppId")?;
                continue;
            };
            let mut c = CellRow::new(SP_COLS);
            c.set("app_id", Cell::text(Some(app_id.clone())))
                .set("display_name", Cell::text(rec.text("AppDisplayName")))
                .set("description", Cell::text(rec.text("AppDescription")))
                .set("enabled", Cell::bool(rec.bool("AccountEnabled")))
                .set(
                    "owner_org_id",
                    Cell::text(lower(rec.text("AppOwnerOrganizationId"))),
                );
            rows.push(r, app_id, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const APP_REG_COLS: &[&str] = &["object_id", "display_name", "app_id", "created"];

/// AppRegistrations.csv: 4 columns, tenant app registrations only.
pub struct AppRegistrationsParser;

impl ArtifactParser for AppRegistrationsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["AppId", "DisplayName"], "app registration")?;
        let mut rows = TableRows::new(&APPLICATIONS, APP_REG_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(app_id) = lower(rec.text("AppId")) else {
                reject(ctx, r, "app registration row has no AppId")?;
                continue;
            };
            let mut c = CellRow::new(APP_REG_COLS);
            c.set("object_id", Cell::text(lower(rec.text("Id"))))
                .set("display_name", Cell::text(rec.text("DisplayName")))
                .set("app_id", Cell::text(Some(app_id.clone())))
                .set("created", Cell::time(rec.text("CreatedDateTime")));
            rows.push(r, app_id, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const USER_APP_COLS: &[&str] = &[
    "display_name",
    "app_id",
    "object_id",
    "publisher",
    "application_type",
    "created",
    "enabled",
    "has_secrets",
    "has_certs",
    "required_api_permission_count",
    "sign_in_audience",
    "reply_urls",
    "association_type",
    "associated_user",
];

/// UserApplications.csv (triage root): one row per user–app association. `N/A` cells stay NULL.
pub struct UserApplicationsParser;

impl ArtifactParser for UserApplicationsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &["AssociationType", "ApplicationId"],
            "user application",
        )?;
        let mut rows = TableRows::new(&APPLICATIONS, USER_APP_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let (Some(app_id), Some(association), Some(user)) = (
                lower(rec.text("ApplicationId")),
                lower(rec.text("AssociationType")),
                lower(rec.text("AssociatedUser")),
            ) else {
                reject(
                    ctx,
                    r,
                    "user application row has no ApplicationId, AssociationType or AssociatedUser",
                )?;
                continue;
            };
            let key = format!("{app_id}|{association}|{user}");
            let mut reply = semi_list(&rec, "WebRedirectUris");
            reply.extend(semi_list(&rec, "PublicClientRedirectUris"));
            let mut c = CellRow::new(USER_APP_COLS);
            c.set("display_name", Cell::text(rec.text("ApplicationName")))
                .set("app_id", Cell::text(Some(app_id)))
                .set("object_id", Cell::text(lower(rec.text("ObjectId"))))
                .set("publisher", Cell::text(rec.text("PublisherName")))
                .set("application_type", Cell::text(rec.text("ApplicationType")))
                .set("created", Cell::time(rec.text("CreatedDateTime")))
                .set("enabled", Cell::bool(rec.bool("ServicePrincipalEnabled")))
                .set("has_secrets", Cell::bool(rec.bool("HasClientSecrets")))
                .set("has_certs", Cell::bool(rec.bool("HasCertificates")))
                .set(
                    "required_api_permission_count",
                    Cell::int(rec.int("RequiredApiPermissionCount")),
                )
                .set("sign_in_audience", Cell::text(rec.text("SignInAudience")))
                .set("reply_urls", Cell::list(reply))
                .set("association_type", Cell::text(rec.text("AssociationType")))
                .set("associated_user", Cell::text(Some(user)));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
