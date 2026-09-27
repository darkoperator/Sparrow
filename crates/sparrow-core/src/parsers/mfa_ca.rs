//! Microsoft-Extractor-Suite MFA and Conditional Access state: Get-MFA
//! (`MFA/<ts1>/<ts1>-AuthenticationMethods.csv` and the second run folder's
//! `<ts2>-UserRegistrationDetails.csv`) and Get-ConditionalAccessPolicies
//! (`ConditionalAccessPolicies/<ts>/<ts>-ConditionalAccessPolicies.csv`) (research state
//! layouts §4, §5).

use crate::Result;
use crate::db::state_tables::{CA_POLICIES, MFA_REGISTRATION};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, load_tables, lower, read_state_records, reject, require_any_key,
};
use serde_json::{Value, json};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.mfa.methods", Box::new(MfaMethodsParser));
    r.register("inv.mfa.registration", Box::new(MfaRegistrationParser));
    r.register("inv.ca", Box::new(CaPoliciesParser));
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

/// A `", "`-joined collector list (`""` gives no items).
fn comma_list(rec: &Rec, key: &str) -> Vec<String> {
    rec.text(key)
        .map(|s| {
            s.split(", ")
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

const METHOD_COLS: &[&str] = &[
    "upn",
    "mfa_status",
    "method_email",
    "method_fido2",
    "method_authenticator_app",
    "method_password",
    "method_phone",
    "method_software_oath",
    "method_hello_business",
    "method_temporary_access_pass",
    "method_qr_code_pin",
];

/// AuthenticationMethods.csv: the per-method flags and MFAstatus for one row per user.
pub struct MfaMethodsParser;

impl ArtifactParser for MfaMethodsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["user", "MFAstatus"], "MFA method")?;
        let mut rows = TableRows::new(&MFA_REGISTRATION, METHOD_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(upn) = lower(rec.text("user")) else {
                reject(ctx, r, "MFA method row has no user")?;
                continue;
            };
            let mut c = CellRow::new(METHOD_COLS);
            c.set("upn", Cell::text(Some(upn.clone())))
                .set("mfa_status", Cell::text(rec.text("MFAstatus")))
                .set("method_email", Cell::bool(rec.bool("email")))
                .set("method_fido2", Cell::bool(rec.bool("fido2")))
                .set("method_authenticator_app", Cell::bool(rec.bool("app")))
                .set("method_password", Cell::bool(rec.bool("password")))
                .set("method_phone", Cell::bool(rec.bool("phone")))
                .set("method_software_oath", Cell::bool(rec.bool("softwareoath")))
                .set(
                    "method_hello_business",
                    Cell::bool(rec.bool("hellobusiness")),
                )
                .set(
                    "method_temporary_access_pass",
                    Cell::bool(rec.bool("temporaryAccessPass")),
                )
                .set("method_qr_code_pin", Cell::bool(rec.bool("qrcodepin")));
            rows.push(r, upn, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const REGISTRATION_COLS: &[&str] = &[
    "user_id",
    "upn",
    "display_name",
    "user_type",
    "is_admin",
    "is_mfa_registered",
    "is_mfa_capable",
    "is_sspr_registered",
    "is_sspr_enabled",
    "is_sspr_capable",
    "is_passwordless_capable",
    "methods",
    "default_method",
    "system_preferred_methods",
    "last_updated",
];

/// UserRegistrationDetails.csv: the reports-API registration and capability flags (the second
/// MFA run folder, written only with Entra ID P1).
pub struct MfaRegistrationParser;

impl ArtifactParser for MfaRegistrationParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &["userPrincipalName", "isMfaRegistered"],
            "MFA registration",
        )?;
        let mut rows = TableRows::new(&MFA_REGISTRATION, REGISTRATION_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(upn) = lower(rec.text("userPrincipalName")) else {
                reject(ctx, r, "MFA registration row has no userPrincipalName")?;
                continue;
            };
            let mut c = CellRow::new(REGISTRATION_COLS);
            c.set("user_id", Cell::text(lower(rec.text("id"))))
                .set("upn", Cell::text(Some(upn.clone())))
                .set("display_name", Cell::text(rec.text("userDisplayName")))
                .set("user_type", Cell::text(rec.text("userType")))
                .set("is_admin", Cell::bool(rec.bool("isAdmin")))
                .set("is_mfa_registered", Cell::bool(rec.bool("isMfaRegistered")))
                .set("is_mfa_capable", Cell::bool(rec.bool("isMfaCapable")))
                .set(
                    "is_sspr_registered",
                    Cell::bool(rec.bool("isSsprRegistered")),
                )
                .set("is_sspr_enabled", Cell::bool(rec.bool("isSsprEnabled")))
                .set("is_sspr_capable", Cell::bool(rec.bool("isSsprCapable")))
                .set(
                    "is_passwordless_capable",
                    Cell::bool(rec.bool("isPasswordlessCapable")),
                )
                .set("methods", Cell::list(comma_list(&rec, "methodsRegistered")))
                .set(
                    "default_method",
                    Cell::text(rec.text("userPreferredMethodForSecondaryAuthentication")),
                )
                .set(
                    "system_preferred_methods",
                    Cell::list(comma_list(&rec, "systemPreferredAuthenticationMethods")),
                )
                .set("last_updated", Cell::time(rec.text("lastUpdatedDateTime")));
            rows.push(r, upn, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

/// The session settings the collector exports, keeping only configured keys.
fn session_controls(rec: &Rec) -> Value {
    let mut m = serde_json::Map::new();
    for (key, column) in [
        (
            "application_enforced_restrictions",
            "ApplicationEnforcedRestrictions",
        ),
        ("cloud_app_security", "CloudAppSecurity"),
        ("disable_resilience_defaults", "DisableResilienceDefaults"),
    ] {
        if let Some(b) = rec.bool(column) {
            m.insert(key.to_string(), json!(b));
        }
    }
    if let Some(v) = rec.text("PersistentBrowser") {
        m.insert("persistent_browser".to_string(), json!(v));
    }
    // A single space means "not configured" and `Rec::text` already trims it to nothing.
    if let Some(v) = rec.text("SignInFrequency") {
        m.insert("sign_in_frequency".to_string(), json!(v));
    }
    Value::Object(m)
}

const CA_COLS: &[&str] = &[
    "policy_id",
    "display_name",
    "state",
    "created",
    "modified",
    "description",
    "include_users",
    "exclude_users",
    "include_groups",
    "exclude_groups",
    "include_roles",
    "exclude_roles",
    "include_applications",
    "exclude_applications",
    "client_app_types",
    "include_platforms",
    "exclude_platforms",
    "include_locations",
    "exclude_locations",
    "user_risk_levels",
    "sign_in_risk_levels",
    "service_principal_risk_levels",
    "user_actions",
    "built_in_controls",
    "grant_operator",
    "device_filter_mode",
    "device_filter_rule",
    "session_controls",
];

/// ConditionalAccessPolicies.csv: one row per policy.
pub struct CaPoliciesParser;

impl ArtifactParser for CaPoliciesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &["Id", "DisplayName"],
            "conditional access policy",
        )?;
        let mut rows = TableRows::new(&CA_POLICIES, CA_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(id) = lower(rec.text("Id")) else {
                reject(ctx, r, "conditional access policy row has no Id")?;
                continue;
            };
            let mut c = CellRow::new(CA_COLS);
            c.set("policy_id", Cell::text(Some(id.clone())))
                .set("display_name", Cell::text(rec.text("DisplayName")))
                .set("state", Cell::text(rec.text("State")))
                .set("created", Cell::time(rec.text("CreatedDateTime")))
                .set("modified", Cell::time(rec.text("ModifiedDateTime")))
                .set("description", Cell::text(rec.text("Description")))
                .set("include_users", Cell::list(semi_list(&rec, "IncludeUsers")))
                .set("exclude_users", Cell::list(semi_list(&rec, "ExcludeUsers")))
                .set(
                    "include_groups",
                    Cell::list(semi_list(&rec, "IncludeGroups")),
                )
                .set(
                    "exclude_groups",
                    Cell::list(semi_list(&rec, "ExcludeGroups")),
                )
                .set("include_roles", Cell::list(semi_list(&rec, "IncludeRoles")))
                .set("exclude_roles", Cell::list(semi_list(&rec, "ExcludeRoles")))
                .set(
                    "include_applications",
                    Cell::list(semi_list(&rec, "IncludeApplications")),
                )
                .set(
                    "exclude_applications",
                    Cell::list(semi_list(&rec, "ExcludeApplications")),
                )
                .set(
                    "client_app_types",
                    Cell::list(semi_list(&rec, "ClientAppTypes")),
                )
                .set(
                    "include_platforms",
                    Cell::list(semi_list(&rec, "IncludePlatforms")),
                )
                .set(
                    "exclude_platforms",
                    Cell::list(semi_list(&rec, "ExcludePlatforms")),
                )
                .set(
                    "include_locations",
                    Cell::list(semi_list(&rec, "IncludeLocations")),
                )
                .set(
                    "exclude_locations",
                    Cell::list(semi_list(&rec, "ExcludeLocations")),
                )
                .set(
                    "user_risk_levels",
                    Cell::list(semi_list(&rec, "UserRiskLevels")),
                )
                .set(
                    "sign_in_risk_levels",
                    Cell::list(semi_list(&rec, "SignInRiskLevels")),
                )
                .set(
                    "service_principal_risk_levels",
                    Cell::list(semi_list(&rec, "ServicePrincipalRiskLevels")),
                )
                .set("user_actions", Cell::list(semi_list(&rec, "UserActions")))
                .set(
                    "built_in_controls",
                    Cell::list(semi_list(&rec, "BuiltInControls")),
                )
                .set("grant_operator", Cell::text(rec.text("GrantOperator")))
                .set(
                    "device_filter_mode",
                    Cell::text(rec.text("DeviceFilterMode")),
                )
                .set(
                    "device_filter_rule",
                    Cell::text(rec.text("DeviceFilterRule")),
                )
                .set("session_controls", Cell::json(Some(session_controls(&rec))));
            rows.push(r, id, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
