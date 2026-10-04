//! Microsoft-Extractor-Suite directory state: Get-Users (`Users/<ts>/<ts>-Users.csv`),
//! Get-AdminUsers (`Admins/<ts>/<date>-<role>.csv` and its `Merged/` re-export) and
//! Get-AllRoleActivity (`Roles/<ts>/<ts>-AllRoles.csv`), plus Get-PIMAssignments
//! (`Roles/<ts>/<ts>-PIM-Assignments.csv`) (research state layouts §2, §3).

use crate::Result;
use crate::db::state_tables::{ROLE_ASSIGNMENTS, USERS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::directory::{role_key, user_key};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, file_date_order, load_tables, lower, read_state_records, reject,
    reject_collector_loss, require_any_key,
};
use crate::readers::time::{DateOrder, parse_timestamp};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.users", Box::new(UsersParser));
    for id in ["inv.admins", "inv.admins.merged", "inv.roles.all"] {
        r.register(id, Box::new(AdminRolesParser));
    }
    r.register("inv.roles.pim", Box::new(PimParser));
}

/// role_assignments principal: the lower UPN, else the object id, else the lower display name.
fn principal_key(upn: &Option<String>, id: &Option<String>, name: &Option<String>) -> String {
    upn.clone()
        .or_else(|| id.clone())
        .or_else(|| name.as_ref().map(|n| n.to_lowercase()))
        .unwrap_or_default()
}

const USER_COLS: &[&str] = &[
    "user_id",
    "upn",
    "display_name",
    "account_enabled",
    "created",
    "last_password_change",
    "user_type",
    "on_prem_sync",
    "last_signin",
    "department",
    "job_title",
];

/// The later of two time cells, chosen with the file's resolved day/month order. The chosen
/// text is staged again by `load_tables` (same order), so only the winner reaches the table.
fn later_time(a: Option<String>, b: Option<String>, order: Option<DateOrder>) -> Option<String> {
    let pa = a
        .as_deref()
        .and_then(|s| parse_timestamp(s, order).ok())
        .map(|t| t.utc);
    let pb = b
        .as_deref()
        .and_then(|s| parse_timestamp(s, order).ok())
        .map(|t| t.utc);
    match (pa, pb) {
        (Some(x), Some(y)) => {
            if y > x {
                b
            } else {
                a
            }
        }
        (Some(_), None) => a,
        (None, Some(_)) => b,
        (None, None) => a.or(b),
    }
}

/// Get-Users: one `users` row per Graph user, keyed by the lower object id.
pub struct UsersParser;

impl ArtifactParser for UsersParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["UserPrincipalName"], "user")?;
        let dates: Vec<String> = records
            .iter()
            .flat_map(|r| {
                let rec = Rec::new(&r.map, format.lossy());
                [
                    rec.text("CreatedDateTime"),
                    rec.text("LastPasswordChangeDateTime"),
                    rec.text("LastSignInDateTime"),
                    rec.text("LastNonInteractiveSignInDateTime"),
                ]
            })
            .flatten()
            .collect();
        let order = file_date_order(ctx, dates.iter().map(String::as_str))?;
        let mut rows = TableRows::new(&USERS, USER_COLS);
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
            let last_signin = later_time(
                rec.text("LastSignInDateTime"),
                rec.text("LastNonInteractiveSignInDateTime"),
                order,
            );
            let mut c = CellRow::new(USER_COLS);
            c.set("user_id", Cell::text(lower(rec.text("Id"))))
                .set("upn", Cell::text(lower(rec.text("UserPrincipalName"))))
                .set("display_name", Cell::text(rec.text("DisplayName")))
                .set("account_enabled", Cell::bool(rec.bool("AccountEnabled")))
                .set("created", Cell::time(rec.text("CreatedDateTime")))
                .set(
                    "last_password_change",
                    Cell::time(rec.text("LastPasswordChangeDateTime")),
                )
                .set("user_type", Cell::text(rec.text("UserType")))
                .set(
                    "on_prem_sync",
                    Cell::bool(rec.bool("OnPremisesSyncEnabled")),
                )
                .set("last_signin", Cell::time(last_signin))
                .set("department", Cell::text(rec.text("Department")))
                .set("job_title", Cell::text(rec.text("JobTitle")));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const ADMIN_COLS: &[&str] = &[
    "source",
    "role_name",
    "principal_upn",
    "principal_id",
    "principal_name",
    "principal_type",
    "assignment_type",
    "enabled",
];

/// The collector's failed `Get-MgUser` lookup: every one of the seven data columns is exactly
/// `Error retrieving data` (a real user may legitimately have that phrase inside a column).
fn is_lookup_error(rec: &Rec) -> bool {
    [
        "Department",
        "JobTitle",
        "AccountEnabled",
        "CreatedDateTime",
        "LastInteractiveSignIn",
        "LastNonInteractiveSignIn",
        "DaysSinceLastSignIn",
    ]
    .iter()
    .all(|k| rec.text(k).as_deref() == Some("Error retrieving data"))
}

/// Get-AdminUsers per-role files and its Merged re-export, and Get-AllRoleActivity's
/// AllRoles.csv: every active (non-PIM-eligible) directory-role member as an `entra_directory`
/// permanent assignment.
pub struct AdminRolesParser;

impl ArtifactParser for AdminRolesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Role", "UserName"], "admin role")?;
        let mut rows = TableRows::new(&ROLE_ASSIGNMENTS, ADMIN_COLS);
        let mut lost_role = 0usize;
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            if is_lookup_error(&rec) {
                reject_collector_loss(
                    ctx,
                    r,
                    "Get-MgUser failed for this role member (the collector wrote 'Error retrieving data')",
                )?;
                continue;
            }
            // A null Role is the collector's carry-over after a failed group lookup
            // (Get-Roles.ps1:146-152): the row still loads, with role_name NULL.
            let role = rec.text("Role");
            lost_role += usize::from(role.is_none());
            let upn = lower(rec.text("UserName"));
            let id = lower(rec.text("UserId"));
            let name = rec.text("DisplayName");
            let key = role_key(
                "entra_directory",
                role.as_deref().unwrap_or(""),
                &principal_key(&upn, &id, &name),
            );
            let mut c = CellRow::new(ADMIN_COLS);
            c.set("source", Cell::text(Some("entra_directory".into())))
                .set("role_name", Cell::text(role))
                .set("principal_upn", Cell::text(upn))
                .set("principal_id", Cell::text(id))
                .set("principal_name", Cell::text(name))
                .set("principal_type", Cell::text(Some("User".into())))
                .set("assignment_type", Cell::text(Some("Permanent".into())))
                .set("enabled", Cell::bool(rec.bool("AccountEnabled")));
            rows.push(r, key, c.into_cells());
        }
        if lost_role > 0 {
            ctx.warn(format!(
                "{lost_role} rows {}",
                crate::ingest::ROLE_CARRY_OVER_WARNING
            ));
        }
        load_tables(ctx, vec![rows])
    }
}

const PIM_COLS: &[&str] = &[
    "source",
    "role_name",
    "principal_upn",
    "principal_name",
    "assignment_type",
    "assignment_name",
    "start_time",
    "end_time",
];

/// Get-PIMAssignments: one `entra_pim` row per active/eligible schedule.
pub struct PimParser;

impl ArtifactParser for PimParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["RoleName", "AssignmentType"], "PIM assignment")?;
        let mut rows = TableRows::new(&ROLE_ASSIGNMENTS, PIM_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(role) = rec.text("RoleName") else {
                reject(ctx, r, "PIM row has no RoleName")?;
                continue;
            };
            let Some(assignment_type) = rec.text("AssignmentType") else {
                reject(ctx, r, "PIM row has no AssignmentType")?;
                continue;
            };
            let upn = lower(rec.text("UserPrincipalName"));
            let name = rec.text("DisplayName");
            let key = role_key("entra_pim", &role, &principal_key(&upn, &None, &name));
            // `SourceType = Group` names the group through which the user holds the role.
            let assignment_name = rec
                .text("SourceType")
                .filter(|s| s.eq_ignore_ascii_case("Group"))
                .and_then(|_| rec.text("SourceName"));
            // The literal `Permanent` means no expiration, so no end time.
            let end = rec
                .text("EndDateTime")
                .filter(|s| !s.eq_ignore_ascii_case("Permanent"));
            let mut c = CellRow::new(PIM_COLS);
            c.set("source", Cell::text(Some("entra_pim".into())))
                .set("role_name", Cell::text(Some(role)))
                .set("principal_upn", Cell::text(upn))
                .set("principal_name", Cell::text(name))
                .set("assignment_type", Cell::text(Some(assignment_type)))
                .set("assignment_name", Cell::text(assignment_name))
                .set("start_time", Cell::time(rec.text("StartDateTime")))
                .set("end_time", Cell::time(end));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
