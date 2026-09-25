//! OAuth consent grants (Hawk Consent_Grants, from Get-AzureADPSPermissions) and app
//! registration / service principal credentials (ApplicationCertsAndSecrets, SPNCertsAndSecrets).

use crate::Result;
use crate::db::state_tables::{APP_CREDENTIALS, OAUTH_GRANTS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{TableRows, load_tables, lower, read_state_records, reject};

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.tenant.consent_grants", Box::new(ConsentGrantsParser));
    r.register(
        "hawk.tenant.app_credentials",
        Box::new(AppCredentialsParser),
    );
}

/// oauth_grants.record_key: client|resource|lower permission|principal (empty when none).
pub fn oauth_grant_key(rec: &Rec) -> Option<String> {
    let client = lower(rec.first_text(&["ClientObjectId", "ClientId"]))?;
    let permission = rec.first_text(&["Permission", "Scope"])?.to_lowercase();
    let resource = lower(rec.first_text(&["ResourceObjectId", "ResourceId"])).unwrap_or_default();
    let principal = lower(rec.text("PrincipalObjectId")).unwrap_or_default();
    Some(format!("{client}|{resource}|{permission}|{principal}"))
}

fn permission_type(s: Option<String>) -> Option<String> {
    let s = s?.to_ascii_lowercase();
    if s.starts_with("delegated") {
        Some("delegated".into())
    } else if s.starts_with("application") {
        Some("application".into())
    } else {
        None
    }
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
];

pub struct ConsentGrantsParser;

impl ArtifactParser for ConsentGrantsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&OAUTH_GRANTS, GRANT_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = oauth_grant_key(&rec) else {
                reject(ctx, r, "consent grant has no ClientObjectId or Permission")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(permission_type(rec.text("PermissionType"))),
                    Cell::text(lower(rec.first_text(&["ClientObjectId", "ClientId"]))),
                    Cell::text(rec.text("ClientDisplayName")),
                    Cell::text(lower(rec.first_text(&["ResourceObjectId", "ResourceId"]))),
                    Cell::text(rec.text("ResourceDisplayName")),
                    Cell::text(rec.first_text(&["Permission", "Scope"])),
                    Cell::text(rec.text("ConsentType")),
                    Cell::text(lower(rec.text("PrincipalObjectId"))),
                    Cell::text(rec.text("PrincipalDisplayName")),
                    Cell::text(rec.text("ConsentGrantRiskCategory")),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

/// app_credentials.record_key: lower app object id|lower key id.
pub fn app_credential_key(rec: &Rec) -> Option<String> {
    let app = lower(rec.first_text(&["AppObjectID", "AppObjectId"]))?;
    let key = lower(rec.first_text(&["KeyID", "KeyId"]))?;
    Some(format!("{app}|{key}"))
}

fn cred_type(rec: &Rec) -> Option<String> {
    let t = rec
        .first_text(&["CredType", "KeyType"])?
        .to_ascii_lowercase();
    if t.contains("x509") || t.contains("cert") {
        Some("certificate".into())
    } else if t.contains("password") || t.contains("secret") || t == "symmetric" {
        Some("password".into())
    } else {
        None
    }
}

const CRED_COLS: &[&str] = &[
    "app_object_id",
    "app_name",
    "key_id",
    "cred_type",
    "key_type",
    "start_time",
    "end_time",
    "owner",
];

pub struct AppCredentialsParser;

impl ArtifactParser for AppCredentialsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let file = ctx.rel_path.rsplit('/').next().unwrap_or(ctx.rel_path);
        let owner = if file.to_ascii_lowercase().starts_with("spn") {
            "service_principal"
        } else {
            "application"
        };
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&APP_CREDENTIALS, CRED_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = app_credential_key(&rec) else {
                reject(ctx, r, "credential has no AppObjectID or KeyID")?;
                continue;
            };
            rows.push(
                r,
                key,
                vec![
                    Cell::text(lower(rec.first_text(&["AppObjectID", "AppObjectId"]))),
                    Cell::text(rec.text("AppName")),
                    Cell::text(lower(rec.first_text(&["KeyID", "KeyId"]))),
                    Cell::text(cred_type(&rec)),
                    Cell::text(rec.text("KeyType")),
                    Cell::time(rec.first_text(&["StartDate", "StartDateTime"])),
                    Cell::time(rec.first_text(&["EndDate", "EndDateTime"])),
                    Cell::text(Some(owner.into())),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}
