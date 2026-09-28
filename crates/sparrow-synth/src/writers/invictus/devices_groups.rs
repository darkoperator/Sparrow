//! Get-Devices (research state layouts §8) and Get-Groups / Get-GroupMembers /
//! Get-DynamicGroups (§7): `Device Information/<ts>/<ts>-Devices.csv` (CSV or, with
//! `invictus_devices_json`, `ConvertTo-Json` in the same `.csv` path) and the three
//! `Groups/<ts>/...` run folders.

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Rendered, Row, Val, convert_to_json, export_csv};
use crate::tree::{FileSpec, Tree};
use crate::world::{Device, Group};

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn opt(v: Option<String>) -> Val {
    v.map_or(Val::Null, Val::Str)
}

/// One Devices.csv (or JSON) row: `CreatedDateTime` and `SecurityIdentifier` are empty strings,
/// `LastSignInDateTime` is `yyyy-MM-dd HH:mm:ss` (UTC by inference).
fn device_row(d: &Device) -> Row {
    vec![
        r("CreatedDateTime", Val::Str(String::new())),
        r("DeviceId", Val::Str(d.device_id.to_string())),
        r("ObjectId", Val::Str(d.object_id.to_string())),
        r("AccountEnabled", Val::Bool(d.enabled)),
        r("DeviceOwnership", Val::Str(String::new())),
        r("DisplayName", Val::Str(d.display_name.clone())),
        r("EnrollmentType", Val::Str(String::new())),
        r("IsCompliant", d.is_compliant.map_or(Val::Null, Val::Bool)),
        r("IsManaged", d.is_managed.map_or(Val::Null, Val::Bool)),
        r("IsRooted", Val::Str(String::new())),
        r("ManagementType", Val::Str(String::new())),
        r("DeviceCategory", Val::Str(String::new())),
        r("OperatingSystem", Val::Str(d.os.clone())),
        r("OperatingSystemVersion", Val::Str(d.os_version.clone())),
        r("Manufacturer", Val::Str(d.manufacturer.clone())),
        r("Model", Val::Str(d.model.clone())),
        r(
            "LastSignInDateTime",
            Val::Str(d.last_signin.format("%Y-%m-%d %H:%M:%S").to_string()),
        ),
        r("TrustType", Val::Str(d.trust_type.clone())),
        r("RegisteredOwners", Val::Str(String::new())),
        r("RegisteredUsers", Val::Str(String::new())),
        r("MDMAppId", Val::Str(String::new())),
        r("OnPremisesSyncEnabled", Val::Null),
        r("ProfileType", Val::Null),
        r("SecurityIdentifier", Val::Str(String::new())),
    ]
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

/// Get-Devices. The JSON variant goes into the same `.csv` path (`Out-File` adds one newline).
fn write_devices(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Device Information", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(run.local, "=== Starting Device Collection ===");
    let rows: Vec<Row> = c.world.devices.iter().map(device_row).collect();
    let keys: Vec<String> = c
        .world
        .devices
        .iter()
        .map(|d| keys::device(&d.device_id.to_string()))
        .collect();
    let rel = format!("{dir}/{}-Devices.csv", run.stamp);
    if c.opts.invictus_devices_json {
        let mut text = convert_to_json(&c.host, &rows, false).text;
        text.push_str(c.nl());
        tree.write(&FileSpec::new(&rel, Some("inv.devices"), c.utf8()), &text)?;
        for key in &keys {
            tree.row(&rel, "devices", key.clone());
        }
        return Ok(());
    }
    write_rows(c, tree, &rel, "inv.devices", "devices", &rows, &keys)?;
    Ok(())
}

/// One Groups.csv / DynamicGroups.csv row.
fn group_row(g: &Group) -> Row {
    vec![
        r("GroupId", Val::Str(g.id.to_string())),
        r("DisplayName", Val::Str(g.display_name.clone())),
        r("Description", Val::Null),
        r("Mail", opt(g.mail.clone())),
        r("MailEnabled", Val::Bool(g.mail_enabled)),
        r("MailNickname", Val::Null),
        r("SecurityEnabled", Val::Bool(g.security_enabled)),
        r("GroupTypes", Val::Str(g.group_types.join(","))),
        r(
            "CreatedDateTime",
            Val::Date(PsDate::dotnet(g.created, DtKind::Utc)),
        ),
        r("RenewedDateTime", Val::Null),
        r("ExpirationDateTime", Val::Null),
        r("Visibility", opt(g.visibility.clone())),
        r("OnPremisesSyncEnabled", Val::Null),
        r("OnPremisesLastSyncDateTime", Val::Null),
        r("SecurityIdentifier", Val::Null),
        r("IsManagementRestricted", Val::Null),
        r("MembershipRule", opt(g.membership_rule.clone())),
        r(
            "MembershipRuleProcessingState",
            if g.membership_rule.is_some() {
                Val::Str("On".into())
            } else {
                Val::Null
            },
        ),
        r("Classification", Val::Null),
        r("HideFromAddressLists", Val::Null),
        r("HideFromOutlookClients", Val::Null),
        r("IsAssignableToRole", Val::Bool(g.is_assignable_to_role)),
        r("PreferredDataLocation", Val::Null),
        r("ProxyAddresses", Val::Str(String::new())),
    ]
}

/// Get-Groups: 24 columns.
fn write_groups(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Groups", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(run.local, "=== Starting Groups Collection ===");
    let rows: Vec<Row> = c.world.groups.iter().map(group_row).collect();
    let keys: Vec<String> = c
        .world
        .groups
        .iter()
        .map(|g| keys::group(&g.id.to_string()))
        .collect();
    let rel = format!("{dir}/{}-Groups.csv", run.stamp);
    write_rows(c, tree, &rel, "inv.groups", "groups", &rows, &keys)?;
    Ok(())
}

/// Get-GroupMembers: 7 columns, one row per direct member. `GroupCreated` is always null.
fn write_group_members(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Groups", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let mut rows = Vec::new();
    let mut keys_out = Vec::new();
    for g in &c.world.groups {
        for upn in &g.members {
            let Some(u) = c.world.user_by_upn(upn) else {
                continue;
            };
            rows.push(vec![
                r("GroupName", Val::Str(g.display_name.clone())),
                r("GroupId", Val::Str(g.id.to_string())),
                r("MemberId", Val::Str(u.object_id.to_string())),
                r("DisplayName", Val::Str(u.display_name.clone())),
                r("Email", Val::Null),
                r("UserPrincipalName", Val::Str(u.upn.clone())),
                r("GroupCreated", Val::Null),
            ]);
            keys_out.push(keys::group_member(g.id, u.object_id));
        }
    }
    let rel = format!("{dir}/{}-GroupMembers.csv", run.stamp);
    write_rows(
        c,
        tree,
        &rel,
        "inv.group_members",
        "group_members",
        &rows,
        &keys_out,
    )?;
    Ok(())
}

/// Get-DynamicGroups: 16 columns, only groups with a membership rule.
fn write_dynamic_groups(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Groups", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let groups: Vec<&Group> = c
        .world
        .groups
        .iter()
        .filter(|g| g.membership_rule.is_some())
        .collect();
    let rows: Vec<Row> = groups
        .iter()
        .map(|g| {
            let full = group_row(g);
            // The 16 dynamic-group columns keep the same order minus the ones the cmdlet omits.
            [
                "GroupId",
                "DisplayName",
                "Description",
                "Mail",
                "MailEnabled",
                "MailNickname",
                "SecurityEnabled",
                "GroupTypes",
                "CreatedDateTime",
                "RenewedDateTime",
                "MembershipRule",
                "MembershipRuleProcessingState",
                "OnPremisesSyncEnabled",
                "SecurityIdentifier",
                "Classification",
                "Visibility",
            ]
            .iter()
            .map(|k| {
                full.iter()
                    .find(|(n, _)| n == k)
                    .cloned()
                    .unwrap_or_else(|| ((*k).to_string(), Val::Null))
            })
            .collect()
        })
        .collect();
    let keys_out: Vec<String> = groups
        .iter()
        .map(|g| keys::group(&g.id.to_string()))
        .collect();
    let rel = format!("{dir}/{}-DynamicGroups.csv", run.stamp);
    write_rows(
        c,
        tree,
        &rel,
        "inv.dynamic_groups",
        "groups",
        &rows,
        &keys_out,
    )?;
    Ok(())
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_devices(c, tree)?;
    write_groups(c, tree)?;
    write_group_members(c, tree)?;
    write_dynamic_groups(c, tree)
}
