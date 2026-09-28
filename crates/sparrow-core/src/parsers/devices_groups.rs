//! Microsoft-Extractor-Suite Get-Devices (`Device Information/<ts>/<ts>-Devices.csv`, or the
//! same objects as JSON in the `.csv` path) and Get-Groups / Get-GroupMembers /
//! Get-DynamicGroups (`Groups/<ts>/...`) (research state layouts §7, §8).

use crate::Result;
use crate::db::state_tables::{DEVICES, GROUP_MEMBERS, GROUPS};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, load_tables, lower, read_state_records, reject, require_any_key,
};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.devices", Box::new(DevicesParser));
    r.register("inv.groups", Box::new(GroupsParser));
    r.register("inv.group_members", Box::new(GroupMembersParser));
    r.register("inv.dynamic_groups", Box::new(DynamicGroupsParser));
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

/// A list joined with `sep` and no spaces around it (GroupTypes `,`, ProxyAddresses `;`).
fn joined_list(rec: &Rec, key: &str, sep: char) -> Vec<String> {
    rec.text(key)
        .map(|s| {
            s.split(sep)
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

const DEVICE_COLS: &[&str] = &[
    "device_id",
    "object_id",
    "display_name",
    "os",
    "os_version",
    "trust_type",
    "is_compliant",
    "is_managed",
    "is_rooted",
    "enabled",
    "ownership",
    "enrollment_type",
    "management_type",
    "manufacturer",
    "model",
    "profile_type",
    "on_prem_sync",
    "created",
    "last_signin",
    "owners",
    "users",
];

/// Devices.csv, or the `-Output JSON` variant written into the same `.csv` path.
pub struct DevicesParser;

impl ArtifactParser for DevicesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let mut format = RecordFormat::of(ctx.rel_path);
        if format == RecordFormat::Csv && RecordFormat::json_content(ctx.text.text.as_str()) {
            format = RecordFormat::Json;
        }
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["DeviceId", "DisplayName"], "device")?;
        let mut rows = TableRows::new(&DEVICES, DEVICE_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(device_id) = lower(rec.text("DeviceId")) else {
                reject(ctx, r, "device row has no DeviceId")?;
                continue;
            };
            let mut c = CellRow::new(DEVICE_COLS);
            c.set("device_id", Cell::text(Some(device_id.clone())))
                .set("object_id", Cell::text(lower(rec.text("ObjectId"))))
                .set("display_name", Cell::text(rec.text("DisplayName")))
                .set("os", Cell::text(rec.text("OperatingSystem")))
                .set("os_version", Cell::text(rec.text("OperatingSystemVersion")))
                .set("trust_type", Cell::text(rec.text("TrustType")))
                .set("is_compliant", Cell::bool(rec.bool("IsCompliant")))
                .set("is_managed", Cell::bool(rec.bool("IsManaged")))
                .set("is_rooted", Cell::bool(rec.bool("IsRooted")))
                .set("enabled", Cell::bool(rec.bool("AccountEnabled")))
                .set("ownership", Cell::text(rec.text("DeviceOwnership")))
                .set("enrollment_type", Cell::text(rec.text("EnrollmentType")))
                .set("management_type", Cell::text(rec.text("ManagementType")))
                .set("manufacturer", Cell::text(rec.text("Manufacturer")))
                .set("model", Cell::text(rec.text("Model")))
                .set("profile_type", Cell::text(rec.text("ProfileType")))
                .set(
                    "on_prem_sync",
                    Cell::bool(rec.bool("OnPremisesSyncEnabled")),
                )
                .set("created", Cell::time(rec.text("CreatedDateTime")))
                .set("last_signin", Cell::time(rec.text("LastSignInDateTime")))
                .set("owners", Cell::list(semi_list(&rec, "RegisteredOwners")))
                .set("users", Cell::list(semi_list(&rec, "RegisteredUsers")));
            rows.push(r, device_id, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

const GROUP_COLS: &[&str] = &[
    "group_id",
    "display_name",
    "description",
    "mail",
    "mail_enabled",
    "mail_nickname",
    "security_enabled",
    "group_types",
    "is_dynamic",
    "membership_rule",
    "membership_rule_state",
    "created",
    "renewed",
    "expiration",
    "visibility",
    "on_prem_sync",
    "is_assignable_to_role",
    "classification",
    "proxy_addresses",
];

/// A `groups` row from a Get-Groups or Get-DynamicGroups record.
fn group_cells(rec: &Rec) -> (Option<String>, Vec<Cell>) {
    let group_id = lower(rec.text("GroupId"));
    let group_types = joined_list(rec, "GroupTypes", ',');
    let membership_rule = rec.text("MembershipRule");
    let is_dynamic =
        group_types.iter().any(|t| t == "DynamicMembership") || membership_rule.is_some();
    let mut c = CellRow::new(GROUP_COLS);
    c.set("group_id", Cell::text(group_id.clone()))
        .set("display_name", Cell::text(rec.text("DisplayName")))
        .set("description", Cell::text(rec.text("Description")))
        .set("mail", Cell::text(rec.text("Mail")))
        .set("mail_enabled", Cell::bool(rec.bool("MailEnabled")))
        .set("mail_nickname", Cell::text(rec.text("MailNickname")))
        .set("security_enabled", Cell::bool(rec.bool("SecurityEnabled")))
        .set("group_types", Cell::list(group_types))
        .set("is_dynamic", Cell::bool(Some(is_dynamic)))
        .set("membership_rule", Cell::text(membership_rule))
        .set(
            "membership_rule_state",
            Cell::text(rec.text("MembershipRuleProcessingState")),
        )
        .set("created", Cell::time(rec.text("CreatedDateTime")))
        .set("renewed", Cell::time(rec.text("RenewedDateTime")))
        .set("expiration", Cell::time(rec.text("ExpirationDateTime")))
        .set("visibility", Cell::text(rec.text("Visibility")))
        .set(
            "on_prem_sync",
            Cell::bool(rec.bool("OnPremisesSyncEnabled")),
        )
        .set(
            "is_assignable_to_role",
            Cell::bool(rec.bool("IsAssignableToRole")),
        )
        .set("classification", Cell::text(rec.text("Classification")))
        .set(
            "proxy_addresses",
            Cell::list(joined_list(rec, "ProxyAddresses", ';')),
        );
    (group_id, c.into_cells())
}

/// Groups.csv: 24 columns, one row per group.
pub struct GroupsParser;

impl ArtifactParser for GroupsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["GroupId", "DisplayName"], "group")?;
        let mut rows = TableRows::new(&GROUPS, GROUP_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let (Some(group_id), cells) = group_cells(&rec) else {
                reject(ctx, r, "group row has no GroupId")?;
                continue;
            };
            rows.push(r, group_id, cells);
        }
        load_tables(ctx, vec![rows])
    }
}

/// DynamicGroups.csv: 16 columns, filling the same `groups` rows.
pub struct DynamicGroupsParser;

impl ArtifactParser for DynamicGroupsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["GroupId", "MembershipRule"], "dynamic group")?;
        let mut rows = TableRows::new(&GROUPS, GROUP_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let (Some(group_id), cells) = group_cells(&rec) else {
                reject(ctx, r, "dynamic group row has no GroupId")?;
                continue;
            };
            rows.push(r, group_id, cells);
        }
        load_tables(ctx, vec![rows])
    }
}

const MEMBER_COLS: &[&str] = &[
    "group_id",
    "group_name",
    "member_id",
    "member_display_name",
    "member_mail",
    "member_upn",
];

/// GroupMembers.csv: 7 columns, one row per direct member.
pub struct GroupMembersParser;

impl ArtifactParser for GroupMembersParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["GroupId", "MemberId"], "group member")?;
        let mut rows = TableRows::new(&GROUP_MEMBERS, MEMBER_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let (Some(group_id), Some(member_id)) =
                (lower(rec.text("GroupId")), lower(rec.text("MemberId")))
            else {
                reject(ctx, r, "group member row has no GroupId or MemberId")?;
                continue;
            };
            let key = format!("{group_id}|{member_id}");
            let mut c = CellRow::new(MEMBER_COLS);
            c.set("group_id", Cell::text(Some(group_id)))
                .set("group_name", Cell::text(rec.text("GroupName")))
                .set("member_id", Cell::text(Some(member_id)))
                .set("member_display_name", Cell::text(rec.text("DisplayName")))
                .set("member_mail", Cell::text(rec.text("Email")))
                .set(
                    "member_upn",
                    Cell::text(lower(rec.text("UserPrincipalName"))),
                );
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}
