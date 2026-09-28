//! Get-MFA and Get-ConditionalAccessPolicies (research state layouts §4, §5):
//! `MFA/<ts1>/<ts1>-AuthenticationMethods.csv` (always) plus the second run folder
//! `MFA/<ts2>/<ts2>-UserRegistrationDetails.csv` (only with Entra ID P1), and
//! `ConditionalAccessPolicies/<ts>/<ts>-ConditionalAccessPolicies.csv` (only with P1, else an
//! empty run folder).

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Row, Val, export_csv};
use crate::tree::{FileSpec, Tree};
use crate::world::{CaPolicy, MfaRegistration, User, World};
use chrono::{DateTime, Duration, Timelike, Utc};

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

/// The Graph `methodsRegistered` name of a world method (`Get-MFAStatus.ps1`'s odata types).
fn graph_method(m: &str) -> String {
    match m {
        "microsoftAuthenticator" => "microsoftAuthenticatorPush",
        "fido2" => "fido2SecurityKey",
        "windowsHelloForBusiness" => "windowsHelloForBusiness",
        "phone" => "mobilePhone",
        "softwareOath" => "softwareOneTimePasscode",
        "temporaryAccessPass" => "temporaryAccessPassOneTime",
        other => other,
    }
    .to_string()
}

fn registration<'w>(world: &'w World, u: &User) -> Option<&'w MfaRegistration> {
    world.mfa.get(&u.upn)
}

/// `MFAstatus`: Enabled when any method other than password / qrCodePin exists
/// (`Get-MFAStatus.ps1`: password keeps it Disabled, qrCodePin does not change it, every other
/// method sets Enabled).
fn mfa_status(methods: &[String]) -> &'static str {
    let enabled = methods
        .iter()
        .any(|m| !matches!(m.as_str(), "password" | "qrcodePin" | "qrCodePin"));
    if enabled { "Enabled" } else { "Disabled" }
}

fn methods_row(world: &World, u: &User) -> Row {
    let reg = registration(world, u);
    let methods = reg.map(|m| m.methods.clone()).unwrap_or_default();
    let has = |name: &str| methods.iter().any(|m| m == name);
    vec![
        r("user", Val::Str(u.upn.clone())),
        r("MFAstatus", Val::Str(mfa_status(&methods).into())),
        r("email", Val::Bool(has("email"))),
        r("fido2", Val::Bool(has("fido2"))),
        r("app", Val::Bool(has("microsoftAuthenticator"))),
        r("password", Val::Bool(has("password"))),
        r("phone", Val::Bool(has("phone"))),
        r("softwareoath", Val::Bool(has("softwareOath"))),
        r("hellobusiness", Val::Bool(has("windowsHelloForBusiness"))),
        r("temporaryAccessPass", Val::Bool(has("temporaryAccessPass"))),
        // The odata type is not a real method, so this is always False.
        r("certificateBasedAuthConfiguration", Val::Bool(false)),
        r("qrcodepin", Val::Bool(has("qrCodePin"))),
    ]
}

fn registration_row(world: &World, u: &User) -> Row {
    let reg = registration(world, u);
    let methods = reg.map(|m| m.methods.clone()).unwrap_or_default();
    let registered = reg.is_some_and(|m| m.is_mfa_registered);
    let sspr = reg.is_some_and(|m| m.is_sspr_registered);
    let passwordless = methods
        .iter()
        .any(|m| m == "fido2" || m == "windowsHelloForBusiness");
    let graph: Vec<String> = methods.iter().map(|m| graph_method(m)).collect();
    let system_preferred: Vec<String> = if registered {
        graph.iter().filter(|m| *m != "password").cloned().collect()
    } else {
        Vec::new()
    };
    let last_updated = reg.map(|m| m.last_updated);
    vec![
        r("id", Val::Str(u.object_id.to_string())),
        r("userPrincipalName", Val::Str(u.upn.clone())),
        r("userDisplayName", Val::Str(u.display_name.clone())),
        r("isAdmin", Val::Bool(u.is_admin)),
        r("isSsprRegistered", Val::Bool(sspr)),
        r("isSsprEnabled", Val::Bool(sspr)),
        r("isSsprCapable", Val::Bool(sspr)),
        r("isMfaRegistered", Val::Bool(registered)),
        r(
            "isMfaCapable",
            Val::Bool(reg.is_some_and(|m| m.is_mfa_capable)),
        ),
        r("isPasswordlessCapable", Val::Bool(passwordless)),
        r("lastUpdatedDateTime", rest_date(last_updated)),
        r("methodsRegistered", Val::Str(graph.join(", "))),
        r(
            "isSystemPreferredAuthenticationMethodEnabled",
            Val::Bool(false),
        ),
        r(
            "systemPreferredAuthenticationMethods",
            Val::Str(system_preferred.join(", ")),
        ),
        r(
            "userPreferredMethodForSecondaryAuthentication",
            reg.and_then(|m| m.default_method.clone())
                .map_or(Val::Null, Val::Str),
        ),
        r("userType", Val::Str("Member".into())),
    ]
}

fn dt(v: Option<DateTime<Utc>>) -> Val {
    v.map_or(Val::Null, |t| Val::Date(PsDate::dotnet(t, DtKind::Utc)))
}

/// A REST `Invoke-MgGraphRequest` timestamp: kept ISO text on PS 5.1, culture on PS7.
fn rest_date(v: Option<DateTime<Utc>>) -> Val {
    v.map_or(Val::Null, |t| {
        let digits = if t.nanosecond() == 0 { 0 } else { 7 };
        Val::Date(PsDate::iso(t, digits))
    })
}

fn list(v: &[String]) -> Val {
    Val::Str(v.join("; "))
}

/// The 39 ConditionalAccessPolicies.csv columns.
fn ca_row(p: &CaPolicy) -> Row {
    vec![
        r("DisplayName", Val::Str(p.display_name.clone())),
        r("Id", Val::Str(p.id.to_string())),
        r("State", Val::Str(p.state.clone())),
        r("CreatedDateTime", dt(Some(p.created))),
        r("ModifiedDateTime", dt(p.modified)),
        r("Description", Val::Null),
        r("IncludeUsers", list(&p.include_users)),
        r("ExcludeUsers", list(&p.exclude_users)),
        r("IncludeGroups", Val::Str(String::new())),
        r("ExcludeGroups", Val::Str(String::new())),
        r("IncludeRoles", list(&p.include_roles)),
        r("ExcludeRoles", Val::Str(String::new())),
        r("IncludeApplications", list(&p.include_apps)),
        r("ExcludeApplications", Val::Str(String::new())),
        r("ClientAppTypes", list(&p.client_app_types)),
        r("IncludePlatforms", Val::Str(String::new())),
        r("ExcludePlatforms", Val::Str(String::new())),
        r("IncludeLocations", Val::Str(String::new())),
        r("ExcludeLocations", Val::Str(String::new())),
        r("UserRiskLevels", list(&p.user_risk_levels)),
        r("UserActions", Val::Str(String::new())),
        r("SignInRiskLevels", list(&p.sign_in_risk_levels)),
        r("ServicePrincipalRiskLevels", Val::Str(String::new())),
        // Not on the v1.0 model, so always "".
        r("IncludeDeviceStates", Val::Str(String::new())),
        r("ExcludeDeviceStates", Val::Str(String::new())),
        r("DeviceFilter", Val::Str("Not Configured".into())),
        r("BuiltInControls", list(&p.built_in_controls)),
        r("CustomAuthenticationFactors", Val::Str(String::new())),
        r(
            "GrantOperator",
            p.grant_operator.clone().map_or(Val::Null, Val::Str),
        ),
        r("TermsOfUse", Val::Str(String::new())),
        r("ApplicationEnforcedRestrictions", Val::Null),
        r("CloudAppSecurity", Val::Null),
        r("DisableResilienceDefaults", Val::Null),
        r("PersistentBrowser", Val::Null),
        // Unset is a single space, never an empty string.
        r("SignInFrequency", Val::Str(" ".into())),
        r("DeviceFilterMode", Val::Null),
        r("DeviceFilterRule", Val::Null),
        r("ClientAppsV2", list(&p.client_app_types)),
        r("DeviceStates", Val::Str(String::new())),
    ]
}

/// Renders `rows`, records the culture dates and one record key per row.
fn write_csv(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    table: &'static str,
    rows: &[Row],
    keys: &[String],
) -> Result<()> {
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
    Ok(())
}

/// Get-MFA: AuthenticationMethods.csv always; the UserRegistrationDetails second run folder
/// (4 seconds later) only with Entra ID P1, because the reports API needs it.
fn write_mfa(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("MFA", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting MFA Status Collection ===");
    let people: Vec<&User> = c.world.all_people().collect();
    let rows: Vec<Row> = people.iter().map(|u| methods_row(c.world, u)).collect();
    let row_keys: Vec<String> = people.iter().map(|u| keys::mfa(&u.upn)).collect();
    let rel = format!("{dir}/{}-AuthenticationMethods.csv", run.stamp);
    write_csv(
        c,
        tree,
        &rel,
        "inv.mfa.methods",
        "mfa_registration",
        &rows,
        &row_keys,
    )?;

    if !c.world.licence.p1() {
        return Ok(());
    }
    let run2 = c.runs.next_after("MFA", None, Duration::seconds(4));
    let dir2 = c.path(&run2.rel);
    tree.dir(&dir2)?;
    c.log
        .add(run2.local, "[INFO] Retrieving user registration details");
    let rows: Vec<Row> = people
        .iter()
        .map(|u| registration_row(c.world, u))
        .collect();
    let rel2 = format!("{dir2}/{}-UserRegistrationDetails.csv", run2.stamp);
    write_csv(
        c,
        tree,
        &rel2,
        "inv.mfa.registration",
        "mfa_registration",
        &rows,
        &row_keys,
    )
}

/// Get-ConditionalAccessPolicies: written unconditionally, but without Entra ID P1 the fetch
/// throws and the run folder stays empty.
fn write_ca(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("ConditionalAccessPolicies", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(
        run.local,
        "=== Starting Conditional Access Policy Collection ===",
    );
    if !c.world.licence.p1() {
        return Ok(());
    }
    let rows: Vec<Row> = c.world.ca_policies.iter().map(ca_row).collect();
    let row_keys: Vec<String> = c
        .world
        .ca_policies
        .iter()
        .map(|p| keys::ca_policy(&p.id.to_string()))
        .collect();
    let rel = format!("{dir}/{}-ConditionalAccessPolicies.csv", run.stamp);
    write_csv(c, tree, &rel, "inv.ca", "ca_policies", &rows, &row_keys)
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_mfa(c, tree)?;
    write_ca(c, tree)
}
