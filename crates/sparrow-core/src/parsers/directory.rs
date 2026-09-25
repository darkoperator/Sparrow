//! Directory identity and admin roles: users (Hawk 4 EntraIDUsers, Hawk 3 AzureADUsers),
//! Entra directory role members, Exchange role group members, and Exchange management role
//! assignments / role entries (eDiscovery, ApplicationImpersonation).

use crate::db::state_tables::{ROLE_ASSIGNMENTS, TENANT_SETTINGS, USERS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::normalize_upn;
use crate::parsers::records::{RecordFormat, SourceRecord};
use crate::parsers::stage::{TableRows, load_tables, lower, read_state_records, reject};
use crate::{Error, Result};
use serde_json::json;

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.tenant.entra_users", Box::new(UsersParser));
    r.register("hawk.tenant.azuread_users", Box::new(UsersParser));
    r.register("hawk.tenant.entra_admins", Box::new(EntraAdminsParser));
    r.register("hawk.tenant.azuread_admins", Box::new(EntraAdminsParser));
    r.register("hawk.tenant.exo_admins", Box::new(ExoAdminsParser));
    for (id, source) in [
        ("hawk.tenant.ediscovery_roles", "exchange_ediscovery"),
        (
            "hawk.tenant.ediscovery_role_assignments",
            "exchange_ediscovery",
        ),
        ("hawk.tenant.impersonation", "exchange_rbac"),
    ] {
        r.register(id, Box::new(ExchangeRolesParser { source }));
    }
}

fn upn_of(v: Option<String>) -> Option<String> {
    v.and_then(|u| normalize_upn(&u))
}

/// users.record_key: lower-case object id, else lower-case UPN.
pub fn user_key(rec: &Rec) -> Option<String> {
    lower(rec.first_text(&["Id", "ObjectID"])).or_else(|| upn_of(rec.text("UserPrincipalName")))
}

const GRAPH_USER_COLS: &[&str] = &[
    "user_id",
    "upn",
    "display_name",
    "mail",
    "account_enabled",
    "created",
    "deleted",
    "last_password_change",
];
const AZUREAD_USER_COLS: &[&str] = &[
    "user_id",
    "upn",
    "user_type",
    "created",
    "state_changed",
    "on_prem_sync",
];

pub struct UsersParser;

impl ArtifactParser for UsersParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        // Hawk 3 used the MSOnline/AzureAD modules, Hawk 4 uses Graph: different columns.
        let azuread = records.iter().any(|r| {
            let rec = Rec::new(&r.map, false);
            rec.has("DateCreated") || rec.has("DirSyncEnabled") || rec.has("UserStateChangedOn")
        });
        let cols = if azuread {
            AZUREAD_USER_COLS
        } else {
            GRAPH_USER_COLS
        };
        let mut rows = TableRows::new(&USERS, cols);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(key) = user_key(&rec) else {
                reject(
                    ctx,
                    r,
                    "user record has neither Id/ObjectID nor UserPrincipalName",
                )?;
                continue;
            };
            let id = lower(rec.first_text(&["Id", "ObjectID"]));
            let upn = upn_of(rec.text("UserPrincipalName"));
            let cells = if azuread {
                vec![
                    Cell::text(id),
                    Cell::text(upn),
                    Cell::text(rec.text("UserType")),
                    Cell::time(rec.text("DateCreated")),
                    Cell::time(rec.text("UserStateChangedOn")),
                    Cell::bool(rec.bool("DirSyncEnabled")),
                ]
            } else {
                vec![
                    Cell::text(id),
                    Cell::text(upn),
                    Cell::text(rec.text("DisplayName")),
                    Cell::text(lower(rec.text("Mail"))),
                    Cell::bool(rec.bool("AccountEnabled")),
                    Cell::time(rec.text("CreatedDateTime")),
                    Cell::time(rec.text("DeletedDateTime")),
                    Cell::time(rec.text("LastPasswordChangeDateTime")),
                ]
            };
            rows.push(r, key, cells);
        }
        load_tables(ctx, vec![rows])
    }
}

/// role_assignments.record_key.
pub fn role_key(source: &str, role: &str, principal: &str) -> String {
    format!("{source}|{}|{principal}", role.to_lowercase())
}

fn principal_key(upn: &Option<String>, id: &Option<String>, name: &Option<String>) -> String {
    upn.clone()
        .or_else(|| id.clone())
        .or_else(|| name.as_ref().map(|n| n.to_lowercase()))
        .unwrap_or_default()
}

/// A Hawk `Members` value as (upn, display name); `No Members` gives neither.
fn member(value: Option<String>) -> (Option<String>, Option<String>) {
    match value {
        Some(v) if v.eq_ignore_ascii_case("No Members") => (None, None),
        Some(v) if v.contains('@') => (normalize_upn(&v), None),
        other => (None, other),
    }
}

const ENTRA_ADMIN_COLS: &[&str] = &[
    "source",
    "role_name",
    "principal_upn",
    "principal_id",
    "principal_name",
    "principal_type",
    "assignment_type",
];

/// Hawk 4 EntraIDAdministrators (`AdminGroupName, Members, MemberType, ObjectId`) and
/// Hawk 3 AzureADAdministrators (`AdminGroupName, Members`).
pub struct EntraAdminsParser;

impl ArtifactParser for EntraAdminsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&ROLE_ASSIGNMENTS, ENTRA_ADMIN_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(role) = rec.text("AdminGroupName") else {
                reject(ctx, r, "admin record has no AdminGroupName")?;
                continue;
            };
            let (upn, name) = member(rec.text("Members"));
            let id = lower(rec.text("ObjectId"));
            let principal_type = if upn.is_none() && name.is_none() && id.is_none() {
                Some("none".to_string())
            } else {
                rec.text("MemberType")
                    .or_else(|| upn.as_ref().map(|_| "User".to_string()))
            };
            let key = role_key("entra_directory", &role, &principal_key(&upn, &id, &name));
            rows.push(
                r,
                key,
                vec![
                    Cell::text(Some("entra_directory".into())),
                    Cell::text(Some(role)),
                    Cell::text(upn),
                    Cell::text(id),
                    Cell::text(name),
                    Cell::text(principal_type),
                    Cell::text(Some("active".into())),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

const EXO_ADMIN_COLS: &[&str] = &[
    "source",
    "role_name",
    "principal_upn",
    "principal_name",
    "principal_type",
    "assignment_type",
];

/// ExchangeOnlineAdministrators: `ExchangeAdminGroup, Members, RecipientType`.
pub struct ExoAdminsParser;

impl ArtifactParser for ExoAdminsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&ROLE_ASSIGNMENTS, EXO_ADMIN_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(role) = rec.text("ExchangeAdminGroup") else {
                reject(ctx, r, "admin record has no ExchangeAdminGroup")?;
                continue;
            };
            let (upn, name) = member(rec.text("Members"));
            let key = role_key("exchange_rbac", &role, &principal_key(&upn, &None, &name));
            rows.push(
                r,
                key,
                vec![
                    Cell::text(Some("exchange_rbac".into())),
                    Cell::text(Some(role)),
                    Cell::text(upn),
                    Cell::text(name),
                    Cell::text(rec.text("RecipientType")),
                    Cell::text(Some("active".into())),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

/// Principal of an Exchange management role assignment as (upn, name).
fn assignee(rec: &Rec) -> (Option<String>, Option<String>) {
    let name = rec.first_text(&["RoleAssigneeName", "RoleAssignee", "User"]);
    let upn = rec
        .first_text(&["EffectiveUserName", "User"])
        .filter(|u| u.contains('@'))
        .and_then(|u| normalize_upn(&u));
    (upn, name)
}

/// role_assignments.record_key of an Exchange management role assignment record.
pub fn exchange_assignment_key(source: &str, rec: &Rec) -> Option<String> {
    let role = rec.text("Role")?;
    let (upn, name) = assignee(rec);
    if upn.is_none() && name.is_none() {
        return None;
    }
    Some(role_key(source, &role, &principal_key(&upn, &None, &name)))
}

fn is_assignment(r: &SourceRecord) -> bool {
    let rec = Rec::new(&r.map, false);
    rec.has("RoleAssignee") || rec.has("RoleAssigneeName")
}

fn is_entry(r: &SourceRecord) -> bool {
    let rec = Rec::new(&r.map, false);
    rec.has("Role") && rec.has("Parameters") && !rec.has("RoleAssignee")
}

const ROLE_ASSIGNMENT_COLS: &[&str] = &[
    "source",
    "role_name",
    "principal_upn",
    "principal_name",
    "principal_type",
    "assignment_type",
    "assignment_name",
    "enabled",
    "start_time",
];
const ROLE_ENTRY_COLS: &[&str] = &["source", "name", "value"];

/// Get-ManagementRoleAssignment (37 columns) and Get-ManagementRoleEntry (22 columns)
/// dumps: EDiscoveryRoles, CustomEDiscoveryRoles, EDiscoveryRoleAssignments,
/// Impersonation_Rights, Impersonation_Roles.
pub struct ExchangeRolesParser {
    pub source: &'static str,
}

impl ArtifactParser for ExchangeRolesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        if let Some(first) = records.first() {
            if !records.iter().any(|r| is_assignment(r) || is_entry(r)) {
                let cols: Vec<&str> = first.map.keys().take(12).map(String::as_str).collect();
                return Err(Error::UnsupportedShape(format!(
                    "no Exchange role assignment or role entry columns in [{}]",
                    cols.join(", ")
                )));
            }
        }
        let mut assignments = TableRows::new(&ROLE_ASSIGNMENTS, ROLE_ASSIGNMENT_COLS);
        let mut entries = TableRows::new(&TENANT_SETTINGS, ROLE_ENTRY_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            if is_assignment(r) {
                let Some(key) = exchange_assignment_key(self.source, &rec) else {
                    reject(ctx, r, "role assignment has no Role or assignee")?;
                    continue;
                };
                let (upn, name) = assignee(&rec);
                let delegating = rec
                    .text("RoleAssignmentDelegationType")
                    .is_some_and(|d| d.starts_with("Delegating"));
                assignments.push(
                    r,
                    key,
                    vec![
                        Cell::text(Some(self.source.into())),
                        Cell::text(rec.text("Role")),
                        Cell::text(upn),
                        Cell::text(name),
                        Cell::text(rec.text("RoleAssigneeType")),
                        Cell::text(Some(
                            if delegating { "delegating" } else { "active" }.into(),
                        )),
                        Cell::text(rec.text("Name")),
                        Cell::bool(rec.bool("Enabled")),
                        Cell::time(rec.first_text(&["WhenCreatedUTC", "WhenCreated"])),
                    ],
                );
            } else if is_entry(r) {
                let role = rec.text("Role").unwrap_or_default();
                let cmdlet = rec.text("Name");
                let name = rec
                    .text("Identity")
                    .or_else(|| cmdlet.as_ref().map(|c| format!("{role}\\{c}")))
                    .unwrap_or_else(|| role.clone());
                let value = json!({
                    "role": role, "cmdlet": cmdlet, "type": rec.text("Type"),
                    "parameters": rec.list("Parameters")
                });
                entries.push(
                    r,
                    format!("exchange_role_entry|{}", name.to_lowercase()),
                    vec![
                        Cell::text(Some("exchange_role_entry".into())),
                        Cell::text(Some(name)),
                        Cell::json(Some(value)),
                    ],
                );
            } else {
                reject(
                    ctx,
                    r,
                    "record is neither a role assignment nor a role entry",
                )?;
            }
        }
        load_tables(ctx, vec![assignments, entries])
    }
}
