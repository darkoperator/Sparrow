//! Get-Users, Get-AdminUsers and Get-AllRoleActivity plus Get-PIMAssignments (research state
//! layouts §2, §3): `Users/<ts>/<ts>-Users.csv`, `Admins/<ts>/<date>-<role>.csv` with its
//! `Merged/<date>-All-Administrators.csv`, `Roles/<ts>/<ts>-AllRoles.csv` and
//! `Roles/<ts>/<ts>-PIM-Assignments.csv`. Without Entra ID P1 the Users request (it selects
//! SignInActivity) is refused and the run folder stays empty; without P2 the PIM request is.

use super::Ctx;
use crate::Result;
use crate::events::SignInType;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Row, Val, csv_imported, export_csv};
use crate::tree::{FileSpec, Tree};
use crate::world::{RoleAssignment, User, World};
use chrono::{DateTime, NaiveDateTime, Utc};
use std::collections::BTreeMap;

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

/// A typed Graph SDK `DateTime` (host culture, UTC wall clock).
fn date(v: Option<DateTime<Utc>>) -> Val {
    v.map_or(Val::Null, |t| Val::Date(PsDate::dotnet(t, DtKind::Utc)))
}

/// A REST ISO timestamp (`Invoke-MgGraphRequest`; kept ISO on PS 5.1).
fn rest_date(v: Option<DateTime<Utc>>) -> Val {
    v.map_or(Val::Null, |t| Val::Date(PsDate::iso(t, 7)))
}

type LastSignins = BTreeMap<String, (Option<DateTime<Utc>>, Option<DateTime<Utc>>)>;

/// Every person's last interactive and last non-interactive sign-in of the window.
fn last_signins(c: &Ctx<'_>) -> LastSignins {
    let mut map: LastSignins = BTreeMap::new();
    for s in c.days.iter().flat_map(|d| &d.signins) {
        if s.user.is_empty() {
            continue;
        }
        let e = map.entry(s.user.to_lowercase()).or_default();
        let slot = match s.event_type {
            SignInType::Interactive => &mut e.0,
            SignInType::NonInteractive => &mut e.1,
            SignInType::ServicePrincipal => continue,
        };
        if slot.is_none_or(|t| s.time > t) {
            *slot = Some(s.time);
        }
    }
    map
}

fn signins(map: &LastSignins, upn: &str) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    map.get(&upn.to_lowercase()).copied().unwrap_or_default()
}

/// Every role name in `world.roles`, first appearance order.
fn role_names(world: &World) -> Vec<String> {
    let mut out = Vec::new();
    for a in &world.roles {
        if !out.contains(&a.role) {
            out.push(a.role.clone());
        }
    }
    out
}

/// The `*Admin*` roles (Get-AdminUsers' `-like "*Admin*"`).
fn admin_roles(world: &World) -> Vec<String> {
    role_names(world)
        .into_iter()
        .filter(|r| r.to_ascii_lowercase().contains("admin"))
        .collect()
}

/// Active members of `role`: not a PIM-eligible schedule, and started, not ended. Service
/// principals and groups resolve to nothing (the world holds users only).
fn active_members<'w>(world: &'w World, role: &str) -> Vec<&'w User> {
    let now = world.collected_at();
    world
        .roles
        .iter()
        .filter(|a| a.role == role && a.kind != "PIM Eligible")
        .filter(|a| a.start.is_none_or(|t| t <= now) && a.end.is_none_or(|t| t > now))
        .filter_map(|a| world.user_by_upn(&a.principal))
        .collect()
}

/// `RoleName -replace '[^\w\-_\.]', '_'`.
fn safe_name(role: &str) -> String {
    role.chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn user_row(u: &User, last: (Option<DateTime<Utc>>, Option<DateTime<Utc>>)) -> Row {
    vec![
        r("UserPrincipalName", Val::Str(u.upn.clone())),
        r("DisplayName", Val::Str(u.display_name.clone())),
        r("Id", Val::Str(u.object_id.to_string())),
        r("Department", Val::Str(u.department.clone())),
        r("JobTitle", Val::Str(u.job_title.clone())),
        r("AccountEnabled", Val::Bool(true)),
        r("CreatedDateTime", date(Some(u.created))),
        r(
            "LastPasswordChangeDateTime",
            date(Some(u.last_password_change)),
        ),
        r("UserType", Val::Str("Member".into())),
        r(
            "OnPremisesSyncEnabled",
            if u.on_prem_sync {
                Val::Bool(true)
            } else {
                Val::Null
            },
        ),
        r("Mail", Val::Null),
        r("LastSignInDateTime", date(last.0)),
        r("LastNonInteractiveSignInDateTime", date(last.1)),
        r("IdentityProvider", Val::Null),
        r("City", Val::Str(u.home.city.clone())),
        r("Country", Val::Str(u.home.country_iso.clone())),
        r("UsageLocation", Val::Null),
    ]
}

/// One Admins / AllRoles row. `role_first` is AllRoles' column order (`Role` before `UserName`).
fn role_row(
    role: &str,
    u: &User,
    run_local: NaiveDateTime,
    last: (Option<DateTime<Utc>>, Option<DateTime<Utc>>),
    role_first: bool,
) -> Row {
    let days = match last.0 {
        // `New-TimeSpan -Start <sign-in> -End (Get-Date)`: local wall-clock now minus the SDK
        // DateTime's UTC wall clock, whole days truncated toward zero (Get-UsersInfo.ps1:297).
        Some(t) => Val::Int((run_local - t.naive_utc()).num_days()),
        None => Val::Str("No sign-in data".into()),
    };
    let mut row = vec![
        r("Role", Val::Str(role.to_string())),
        r("UserName", Val::Str(u.upn.clone())),
        r("UserId", Val::Str(u.object_id.to_string())),
        r("DisplayName", Val::Str(u.display_name.clone())),
        r("Department", Val::Str(u.department.clone())),
        r("JobTitle", Val::Str(u.job_title.clone())),
        r("AccountEnabled", Val::Bool(true)),
        r("CreatedDateTime", date(Some(u.created))),
        r("LastInteractiveSignIn", date(last.0)),
        r("LastNonInteractiveSignIn", date(last.1)),
        r("DaysSinceLastSignIn", days),
    ];
    if !role_first {
        let role = row.remove(0);
        row.insert(2, role);
    }
    row
}

/// One Get-Roles.ps1 failed-lookup row (Get-Roles.ps1:146-165): the seven data columns are the
/// literal phrase, UserName comes from the fallback `Get-MgUser`, and Role carries the buggy
/// `$displayName`.
fn error_role_row(role_label: &str, u: &User) -> Row {
    let error = || Val::Str("Error retrieving data".into());
    vec![
        r("Role", Val::Str(role_label.to_string())),
        r("UserName", Val::Str(u.upn.clone())),
        r("UserId", Val::Str(u.object_id.to_string())),
        r("DisplayName", Val::Str(u.display_name.clone())),
        r("Department", error()),
        r("JobTitle", error()),
        r("AccountEnabled", error()),
        r("CreatedDateTime", error()),
        r("LastInteractiveSignIn", error()),
        r("LastNonInteractiveSignIn", error()),
        r("DaysSinceLastSignIn", error()),
    ]
}

/// Renders `rows` and records one `role_assignments` key per row.
fn write_roles_csv(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
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
        tree.row(rel, "role_assignments", key.clone());
    }
    Ok(())
}

/// Get-Users: one row per Graph user. Without Entra ID P1 the run folder stays empty.
fn write_users(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Users", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting User Information Collection ===");
    if !c.world.licence.p1() {
        return Ok(());
    }
    let by_upn = last_signins(c);
    let people: Vec<&User> = c.world.all_people().collect();
    let rows: Vec<Row> = people
        .iter()
        .map(|u| user_row(u, signins(&by_upn, &u.upn)))
        .collect();
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, &rows, &mut ev);
    let rel = format!("{dir}/{}-Users.csv", run.stamp);
    tree.write(
        &FileSpec::new(&rel, Some("inv.users"), c.utf8()),
        &rendered.text,
    )?;
    if ev.culture_dates > 0 {
        tree.date_evidence(&rel, ev);
    }
    for u in &people {
        tree.row(&rel, "users", keys::user(u.object_id));
    }
    Ok(())
}

/// Get-AdminUsers: one file per `*Admin*` role with users, then the Merged re-export.
fn write_admins(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Admins", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Admin Users Collection ===");
    // The Merged folder is always created; the file exists only when a role file does.
    let merged_dir = format!("{dir}/Merged");
    tree.dir(&merged_dir)?;
    // Get-MgUser requests SignInActivity, which needs Entra ID P1: without it every bulk fetch
    // throws, the catch only logs a warning, and no per-role file is written.
    if !c.world.licence.p1() {
        return Ok(());
    }
    let by_upn = last_signins(c);
    let date = run.local.format("%Y%m%d").to_string();
    let mut files: Vec<(String, Vec<Row>)> = Vec::new();
    for role in admin_roles(c.world) {
        let members = active_members(c.world, &role);
        if members.is_empty() {
            continue;
        }
        let name = format!("{date}-{}.csv", safe_name(&role));
        let rel = format!("{dir}/{name}");
        let rows: Vec<Row> = members
            .iter()
            .map(|u| role_row(&role, u, run.local, signins(&by_upn, &u.upn), false))
            .collect();
        let row_keys: Vec<String> = members
            .iter()
            .map(|u| keys::role("entra_directory", &role, &u.upn))
            .collect();
        write_roles_csv(c, tree, &rel, "inv.admins", &rows, &row_keys)?;
        files.push((name, rows));
    }
    if files.is_empty() {
        return Ok(());
    }
    // Import-Csv then Export-Csv: every value becomes a quoted string, header from the
    // alphabetically first file.
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let merged: Vec<Row> = files
        .iter()
        .flat_map(|(_, rows)| rows.iter().map(|row| csv_imported(&c.host, row)))
        .collect();
    let rel = format!("{merged_dir}/{date}-All-Administrators.csv");
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, &merged, &mut ev);
    let spec = FileSpec::new(&rel, Some("inv.admins.merged"), c.utf8())
        .derived()
        .source_derived();
    tree.write(&spec, &rendered.text)?;
    if ev.culture_dates > 0 {
        tree.date_evidence(&rel, ev);
    }
    Ok(())
}

/// Get-AllRoleActivity: every activated role's active members, written unconditionally. Without
/// Entra ID P1 every `Get-MgUser` fails and each member becomes a rejected failure row.
fn write_all_roles(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Roles", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting All Roles Collection ===");
    let by_upn = last_signins(c);
    let p1 = c.world.licence.p1();
    let mut rows = Vec::new();
    let mut row_keys = Vec::new();
    for role in role_names(c.world) {
        // Get-Roles.ps1's `$displayName` bug: the failed-lookup fallback overwrites the per-role
        // label with the user's display name, and every later row of the role writes it as Role
        // (Get-Roles.ps1:134-165; the label is reset per role at :78).
        let mut role_label = role.clone();
        for u in active_members(c.world, &role) {
            if p1 {
                rows.push(role_row(
                    &role_label,
                    u,
                    run.local,
                    signins(&by_upn, &u.upn),
                    true,
                ));
                row_keys.push(keys::role("entra_directory", &role, &u.upn));
            } else {
                // Get-MgUser with SignInActivity throws; the fallback `Get-MgUser -Select
                // "DisplayName,UserPrincipalName"` succeeds, so the catch writes a row whose
                // seven data columns are the phrase.
                role_label = u.display_name.clone();
                rows.push(error_role_row(&role_label, u));
            }
        }
    }
    let rel = format!("{dir}/{}-AllRoles.csv", run.stamp);
    write_roles_csv(c, tree, &rel, "inv.roles.all", &rows, &row_keys)
}

fn pim_row(a: &RoleAssignment, u: &User) -> Row {
    let (assignment_type, status) = if a.kind == "PIM Active" {
        ("PIM Active", "Active")
    } else {
        ("PIM Eligible", "Eligible")
    };
    vec![
        r("RoleName", Val::Str(a.role.clone())),
        r("UserPrincipalName", Val::Str(u.upn.clone())),
        r("DisplayName", Val::Str(u.display_name.clone())),
        r("AssignmentType", Val::Str(assignment_type.into())),
        r("SourceType", Val::Str("Direct".into())),
        r("SourceName", Val::Str("N/A".into())),
        r("OnPremisesSynced", Val::Bool(false)),
        r("AssignmentStatus", Val::Str(status.into())),
        r("StartDateTime", rest_date(a.start)),
        r("EndDateTime", rest_date(a.end)),
        r("DirectoryScopeId", Val::Str("/".into())),
    ]
}

/// Get-PIMAssignments: active schedules first, then eligible. Without Entra ID P2 the beta
/// roleManagement call throws and the run folder stays empty.
fn write_pim(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Roles", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting PIM Assignments Collection ===");
    if !c.world.licence.p2() {
        return Ok(());
    }
    let mut rows = Vec::new();
    let mut row_keys = Vec::new();
    for kind in ["PIM Active", "PIM Eligible"] {
        for a in c.world.roles.iter().filter(|a| a.kind == kind) {
            let Some(u) = c.world.user_by_upn(&a.principal) else {
                continue;
            };
            rows.push(pim_row(a, u));
            row_keys.push(keys::role("entra_pim", &a.role, &u.upn));
        }
    }
    let rel = format!("{dir}/{}-PIM-Assignments.csv", run.stamp);
    write_roles_csv(c, tree, &rel, "inv.roles.pim", &rows, &row_keys)
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_users(c, tree)?;
    write_admins(c, tree)?;
    write_all_roles(c, tree)?;
    write_pim(c, tree)
}
