//! Get-GraphEntraSignInLogs and Get-GraphEntraAuditLogs as Start-EvidenceCollection runs them
//! (research event layouts §7): `Sign-In logs/EntraID/<ts>-SignInLogs/<type>/` and
//! `Audit logs/EntraID/<ts>-AuditLogs/`, one JSON file per Graph page of 1000 (newest first,
//! `ConvertTo-Json | Out-File -Append`), and `-MergeOutput` copies under `Merged/`.

use super::Ctx;
use super::ual::json_inner;
use crate::Result;
use crate::events::{DirAudit, SignIn, SignInType};
use crate::keys;
use crate::ps::{PsDate, Row, Val, convert_to_json};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use crate::world::World;
use chrono::{DateTime, Duration, NaiveDateTime, Timelike, Utc};
use serde_json::{Value, json};
use std::cmp::Reverse;

/// Graph's page size for sign-ins and directory audits.
const PAGE: usize = 1000;

/// A REST timestamp: whole seconds as `...:ssZ`, else with 7 fractional digits.
fn rest_time(t: DateTime<Utc>) -> Val {
    let digits = if t.nanosecond() == 0 { 0 } else { 7 };
    Val::Date(PsDate::iso(t, digits))
}

/// A beta `signIn` REST object with the keys Microsoft-Extractor-Suite's download carries.
fn signin_row(s: &SignIn) -> Row {
    let event_type = match s.event_type {
        SignInType::Interactive => "interactiveUser",
        SignInType::NonInteractive => "nonInteractiveUser",
        SignInType::ServicePrincipal => "servicePrincipal",
    };
    let loc = &s.location;
    let failure = if s.error_code == 0 {
        Value::Null
    } else {
        json!(s.failure_reason)
    };
    let device_id = if s.trust_type.is_some() {
        s.device.device_id.to_string()
    } else {
        String::new()
    };
    let mfa = match &s.mfa {
        Some((method, detail)) => json!({"authMethod": method, "authDetail": detail}),
        None => Value::Null,
    };
    let auth_details: Vec<Value> = s
        .auth_methods
        .iter()
        .map(|m| {
            json!({
                "authenticationMethod": m,
                "succeeded": s.error_code == 0,
                "authenticationStepDateTime": s.time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            })
        })
        .collect();
    let r = |k: &str, v: Val| (k.to_string(), v);
    vec![
        r("id", Val::Str(s.id.to_string())),
        r("createdDateTime", rest_time(s.time)),
        r("userDisplayName", Val::Str(s.user_display.clone())),
        r("userPrincipalName", Val::Str(s.user.clone())),
        r(
            "userId",
            Val::Str(s.user_id.map(|u| u.to_string()).unwrap_or_default()),
        ),
        r("appId", Val::Str(s.app_id.to_string())),
        r("appDisplayName", Val::Str(s.app_name.clone())),
        r("ipAddress", Val::Str(s.ip.to_string())),
        r("clientAppUsed", Val::Str(s.client_app.clone())),
        r("correlationId", Val::Str(s.correlation_id.to_string())),
        r("conditionalAccessStatus", Val::Str(s.ca_status.clone())),
        r(
            "isInteractive",
            Val::Bool(s.event_type == SignInType::Interactive),
        ),
        r("riskDetail", Val::Str(s.risk_detail.clone())),
        r("riskLevelAggregated", Val::Str(s.risk_aggregated.clone())),
        r("riskLevelDuringSignIn", Val::Str(s.risk_during.clone())),
        r("riskState", Val::Str(s.risk_state.clone())),
        r("riskEventTypes", Val::Raw(json!([]))),
        r("riskEventTypes_v2", Val::Raw(json!(s.risk_event_types))),
        r("resourceDisplayName", Val::Str(s.resource_name.clone())),
        r("resourceId", Val::Str(s.resource_id.to_string())),
        r(
            "status",
            Val::Raw(json!({
                "errorCode": s.error_code,
                "failureReason": failure,
                "additionalDetails": Value::Null,
            })),
        ),
        r(
            "deviceDetail",
            Val::Raw(json!({
                "deviceId": device_id,
                "displayName": if s.trust_type.is_some() { s.device.device_name.clone() } else { String::new() },
                "operatingSystem": s.device.os,
                "browser": s.device.browser,
                "isCompliant": s.device_compliant.unwrap_or(false),
                "isManaged": s.device_managed.unwrap_or(false),
                "trustType": s.trust_type.clone().unwrap_or_default(),
            })),
        ),
        r(
            "location",
            Val::Raw(json!({
                "city": loc.city,
                "state": loc.state,
                "countryOrRegion": loc.country_iso,
                "geoCoordinates": {"latitude": loc.lat, "longitude": loc.lon},
            })),
        ),
        r("appliedConditionalAccessPolicies", Val::Raw(json!([]))),
        r(
            "authenticationRequirement",
            Val::Str(s.auth_requirement.clone()),
        ),
        r("signInEventTypes", Val::Raw(json!([event_type]))),
        r("mfaDetail", Val::Raw(mfa)),
        r(
            "authenticationDetails",
            Val::Raw(Value::Array(auth_details)),
        ),
        r("sessionId", Val::Str(s.session_text())),
        r("uniqueTokenIdentifier", Val::Str(s.unique_token_id.clone())),
        r("incomingTokenType", Val::Str(s.incoming_token_type.clone())),
        r("homeTenantId", Val::Str(s.home_tenant_id.to_string())),
        r(
            "resourceTenantId",
            Val::Str(s.resource_tenant_id.to_string()),
        ),
        r("autonomousSystemNumber", Val::Int(s.asn.into())),
        r("userAgent", Val::Str(s.user_agent.clone())),
        r("tokenIssuerType", Val::Str(s.token_issuer.clone())),
        r("crossTenantAccessType", Val::Str("none".into())),
    ]
}

/// Called per written item: (tree, file, item index, line span).
type PerItem<'a> = dyn FnMut(&mut Tree<'_>, &str, usize, (u32, u32)) + 'a;

/// Writes `items` (newest first) as pages of 1000 into `dir`, file `<stamp14>-<suffix>.json`;
/// the page clock starts after `clock` and moves 1-3 seconds per page, except that page 3
/// is fetched in page 2's second when `same_second_third` (its document is appended to page
/// 2's file). Calls `each(tree, rel, item index, line span)` per item. Returns the files' texts
/// in name order (for the merge).
#[allow(clippy::too_many_arguments)]
/// A `Merged/<name>` JSON file written incrementally: `[`, each page entry's inner part joined
/// by `,`, `]`, using the collector's newline. Byte-identical to `merge_json` over all entries.
struct JsonMerge {
    rel: String,
    artifact: &'static str,
    started: bool,
    any: bool,
}

impl JsonMerge {
    fn new(rel: String, artifact: &'static str) -> JsonMerge {
        JsonMerge {
            rel,
            artifact,
            started: false,
            any: false,
        }
    }

    fn spec(&self, c: &Ctx<'_>) -> FileSpec {
        FileSpec::new(&self.rel, Some(self.artifact), c.utf8())
            .derived()
            .source_derived()
    }

    /// Appends one page entry (one `files` element of the old merge), filtering an empty one.
    fn push(&mut self, c: &Ctx<'_>, tree: &mut Tree<'_>, entry: &str) -> Result<()> {
        let spec = self.spec(c);
        if !self.started {
            let mut open = String::new();
            open.push('[');
            open.push_str(c.nl());
            tree.write(&spec, &open)?;
            self.started = true;
        }
        let inner = json_inner(entry);
        if !inner.is_empty() {
            let mut text = String::new();
            if self.any {
                text.push(',');
            }
            text.push_str(inner);
            tree.write(&spec, &text)?;
            self.any = true;
        }
        Ok(())
    }

    fn finish(&mut self, c: &Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
        let spec = self.spec(c);
        let mut text = String::new();
        if !self.started {
            text.push('[');
            text.push_str(c.nl());
        }
        text.push(']');
        text.push_str(c.nl());
        tree.write(&spec, &text)?;
        Ok(())
    }
}

/// Writes the page files of `records` (one per Graph `PAGE`) and streams their merge entries
/// into `merge`. Returns the number of merge entries (the old `files.len()`).
#[allow(clippy::too_many_arguments)]
fn write_pages<T>(
    c: &mut Ctx<'_>,
    tree: &mut Tree<'_>,
    dir: &str,
    suffix: &str,
    artifact: &'static str,
    records: &[T],
    row: impl Fn(&T) -> Row,
    clock: &mut NaiveDateTime,
    same_second_third: bool,
    each: &mut PerItem<'_>,
    merge: &mut JsonMerge,
) -> Result<usize> {
    let mut entries = 0usize;
    let mut last_stamp = String::new();
    let mut current = String::new();
    for (p, chunk) in records.chunks(PAGE).enumerate() {
        if !(p == 2 && same_second_third) {
            *clock += Duration::seconds(c.rng.range(1, 3));
        }
        let stamp = clock.format("%Y%m%d%H%M%S").to_string();
        let rel = format!("{dir}/{stamp}-{suffix}.json");
        let spec = FileSpec::new(&rel, Some(artifact), c.utf8());
        let rows: Vec<Row> = chunk.iter().map(&row).collect();
        let r = convert_to_json(&c.host, &rows, false);
        let text = format!("{}{}", r.text, c.nl());
        let before = tree.write(&spec, &text)?;
        for (i, (a, b)) in r.spans.iter().enumerate() {
            each(tree, &rel, p * PAGE + i, (a + before, b + before));
        }
        if stamp == last_stamp {
            current.push_str(&text);
        } else {
            if !current.is_empty() {
                merge.push(c, tree, &current)?;
                entries += 1;
            }
            current = text;
        }
        last_stamp = stamp;
        c.log
            .add(*clock, format!("[INFO] Retrieved {} records", chunk.len()));
    }
    if !current.is_empty() {
        merge.push(c, tree, &current)?;
        entries += 1;
    }
    Ok(entries)
}

/// Start-EvidenceCollection passes no dates: both cmdlets use their default start, 30 days
/// before the run (`StartDateAz`), which is also Entra ID P1's log retention.
fn graph_start(world: &World) -> DateTime<Utc> {
    (world.collected_at() - Duration::days(30)).max(world.window_start())
}

/// The window's sign-ins of `types` since `graph_start`, newest first.
fn signins_of(c: &Ctx<'_>, types: &[SignInType]) -> Vec<SignIn> {
    let from = graph_start(c.world);
    let mut v: Vec<SignIn> = c
        .days()
        .flat_map(|d| d.signins)
        .filter(|s| types.contains(&s.event_type) && s.time >= from)
        .collect();
    v.sort_by_key(|s| Reverse((s.time, s.id)));
    v
}

/// Get-GraphEntraSignInLogs `-EventTypes All -MergeOutput` since `graph_start`. Without Entra
/// ID P1 Graph refuses
/// the first query: every type folder is created and left empty.
pub(super) fn write_signins(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Sign-In logs/EntraID", Some("SignInLogs"));
    let dir = c.path(&run.rel);
    let mut clock = run.local;
    let types: [(&str, &str, &[SignInType]); 3] = [
        (
            "interactiveUser & nonInteractiveUser",
            "interactiveUser-nonInteractiveUser",
            &[SignInType::Interactive, SignInType::NonInteractive],
        ),
        (
            "servicePrincipal",
            "servicePrincipal",
            &[SignInType::ServicePrincipal],
        ),
        ("managedIdentity", "managedIdentity", &[]),
    ];
    for (folder, _, _) in &types {
        tree.dir(&format!("{dir}/{folder}"))?;
    }
    if !c.world.licence.p1() {
        c.log.add(
            clock,
            "[INFO] Acquiring the interactiveUser & nonInteractiveUser sign-in logs",
        );
        c.log.add(
            clock + Duration::seconds(1),
            "[ERROR] An error occured: Response status code does not indicate success: Forbidden (Forbidden).",
        );
        c.runs.busy_until(clock + Duration::seconds(1));
        return Ok(());
    }
    let mut manifest_units: Vec<(&'static [&'static str], u64, &str)> = Vec::new();
    for (i, (folder, file_name, kinds)) in types.iter().enumerate() {
        c.log
            .add(clock, format!("[INFO] Acquiring the {folder} sign-in logs"));
        let signins = signins_of(c, kinds);
        let type_dir = format!("{dir}/{folder}");
        let mut each = |tree: &mut Tree<'_>, rel: &str, k: usize, span: (u32, u32)| {
            let s = &signins[k];
            tree.row(rel, "signins", keys::signin(s.id));
            tree.deliver(&Evidence::SignIn(s.id), "signins", rel, span);
        };
        let merged_rel = format!("{type_dir}/Merged/SignInLogs-{file_name}-Combined.json");
        tree.dir(&format!("{type_dir}/Merged"))?;
        let mut merge = JsonMerge::new(merged_rel.clone(), "inv.signins.merged");
        let entries = write_pages(
            c,
            tree,
            &type_dir,
            &format!("{file_name}-SignInLogs"),
            "inv.signins",
            &signins,
            signin_row,
            &mut clock,
            i == 0,
            &mut each,
            &mut merge,
        )?;
        merge.finish(c, tree)?;
        let sources: &'static [&'static str] = match i {
            0 => &["signins_interactive", "signins_noninteractive"],
            1 => &["signins_service_principal"],
            _ => &["signins_managed_identity"],
        };
        manifest_units.push((sources, signins.len() as u64, folder));
        c.log.add(clock, format!("\nSummary for {folder}:"));
        c.log.add(clock, format!("  Records: {}", signins.len()));
        c.log.add(clock, format!("  Files: {entries}\n"));
        for s in &signins {
            tree.row(&merged_rel, "signins", keys::signin(s.id));
        }
    }
    let (start, end) = (graph_start(c.world), c.world.window_end());
    let units: Vec<super::ManifestUnit> = manifest_units
        .into_iter()
        .map(|(sources, records, folder)| super::ManifestUnit {
            sources,
            start,
            end,
            records,
            files: if c.opts.invictus_manifests {
                tree.files_in(&format!("{dir}/{folder}"))
                    .into_iter()
                    .map(|f| format!("{folder}/{f}"))
                    .collect()
            } else {
                Vec::new()
            },
        })
        .collect();
    c.write_manifest(tree, &run, &dir, "Get-GraphEntraSignInLogs", clock, &units)?;
    c.runs.busy_until(clock);
    Ok(())
}

/// A v1.0 `directoryAudit` REST object.
fn audit_row(world: &World, a: &DirAudit) -> Row {
    let by = &a.initiated_by;
    let user = match &by.upn {
        Some(upn) => json!({
            "id": by.user_id.map(|u| u.to_string()),
            "displayName": world.user_by_upn(upn).map(|u| u.display_name.clone()),
            "userPrincipalName": upn,
            "ipAddress": by.ip.map(|ip| ip.to_string()).unwrap_or_default(),
            "userType": null,
            "homeTenantId": world.tenant.tenant_id.to_string(),
            "homeTenantName": null,
        }),
        None => Value::Null,
    };
    let app = match (&by.app_id, &by.app_name) {
        (None, None) => Value::Null,
        (id, name) => json!({
            "appId": id.map(|u| u.to_string()),
            "displayName": name,
            "servicePrincipalId": null,
            "servicePrincipalName": null,
        }),
    };
    let targets: Vec<Value> = a
        .targets
        .iter()
        .map(|t| {
            json!({
                "id": t.id,
                "displayName": t.display_name,
                "type": t.kind,
                "userPrincipalName": t.upn,
                "groupType": null,
                "modifiedProperties": t.modified.iter().map(|(name, old, new)| json!({
                    "displayName": name, "oldValue": old, "newValue": new,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let details: Vec<Value> = a
        .additional_details
        .iter()
        .map(|(k, v)| json!({"key": k, "value": v}))
        .collect();
    let r = |k: &str, v: Val| (k.to_string(), v);
    vec![
        r("id", Val::Str(a.id.clone())),
        r("category", Val::Str(a.category.clone())),
        r("correlationId", Val::Str(a.correlation_id.to_string())),
        r("result", Val::Str(a.result.clone())),
        r("resultReason", Val::Str(a.result_reason.clone())),
        r("activityDisplayName", Val::Str(a.activity.clone())),
        r("activityDateTime", rest_time(a.time)),
        r("loggedByService", Val::Str(a.logged_by_service.clone())),
        r("operationType", Val::Str(a.operation_type.clone())),
        r("initiatedBy", Val::Raw(json!({"app": app, "user": user}))),
        r("targetResources", Val::Raw(Value::Array(targets))),
        r("additionalDetails", Val::Raw(Value::Array(details))),
    ]
}

/// Get-GraphEntraAuditLogs `-MergeOutput` since `graph_start`.
pub(super) fn write_audits(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Audit logs/EntraID", Some("AuditLogs"));
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let mut clock = run.local;
    let (start, end) = (graph_start(c.world), c.world.window_end());
    let mut audits: Vec<DirAudit> = c
        .world
        .directory_audits()
        .into_iter()
        .filter(|a| a.time >= start && a.time < end)
        .collect();
    audits.sort_by(|a, b| (b.time, &b.id).cmp(&(a.time, &a.id)));
    c.log.add(clock, "=== Starting Audit Log Collection ===");
    let mut each = |tree: &mut Tree<'_>, rel: &str, k: usize, span: (u32, u32)| {
        let a = &audits[k];
        tree.row(rel, "directory_audits", keys::dir_audit(&a.id));
        tree.deliver(
            &Evidence::DirAudit(a.id.clone()),
            "directory_audits",
            rel,
            span,
        );
    };
    let world = c.world;
    let merged_rel = format!("{dir}/Merged/AuditLogs-Combined.json");
    tree.dir(&format!("{dir}/Merged"))?;
    let mut merge = JsonMerge::new(merged_rel.clone(), "inv.entra_audit.merged");
    write_pages(
        c,
        tree,
        &dir,
        "AuditLogs",
        "inv.entra_audit",
        &audits,
        |a| audit_row(world, a),
        &mut clock,
        false,
        &mut each,
        &mut merge,
    )?;
    merge.finish(c, tree)?;
    for a in &audits {
        tree.row(&merged_rel, "directory_audits", keys::dir_audit(&a.id));
    }
    let unit = super::ManifestUnit {
        sources: &["entra_audit"],
        start,
        end,
        records: audits.len() as u64,
        files: tree.files_in(&dir),
    };
    c.write_manifest(tree, &run, &dir, "Get-GraphEntraAuditLogs", clock, &[unit])?;
    c.runs.busy_until(clock);
    Ok(())
}
