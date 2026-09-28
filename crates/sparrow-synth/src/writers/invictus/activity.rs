//! Get-ActivityLogs and Get-DirectoryActivityLogs (research event layouts §5, §6): the ARM
//! `EventData` objects as `Activity Logs/<ts>/<stamp14>-<subscriptionId>-ActivityLog.json`
//! (`ConvertTo-Json`, `Set-Content -Encoding UTF8`) and the same events through
//! `Directory Activity Logs/<ts>/DirectoryActivityLogs.csv`, `DirectoryActivityLogs.JSON`
//! (upper-case extension; PS7 UTF-8, 5.1 Windows-1252) and
//! `<stamp14>-DirectoryActivityLogs.jsonl` (a pretty array in a `.jsonl` file).

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::options::PsEdition;
use crate::ps::{DateEvidence, Encoding, PsDate, Row, Val, convert_to_json, export_csv};
use crate::rng::stream;
use crate::tree::{FileSpec, Tree};
use crate::world::AzureEvent;
use serde_json::{Value, json};

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

/// The ARM `EventData` top-level keys in the response order (research §5), minus the optional
/// `channels`.
const ARM_KEYS: &[&str] = &[
    "authorization",
    "caller",
    "claims",
    "correlationId",
    "description",
    "eventDataId",
    "eventName",
    "category",
    "eventTimestamp",
    "httpRequest",
    "id",
    "level",
    "operationId",
    "operationName",
    "properties",
    "resourceGroupName",
    "resourceProviderName",
    "resourceId",
    "resourceType",
    "status",
    "subStatus",
    "submissionTimestamp",
    "subscriptionId",
    "tenantId",
];

/// The claim-type URI keys the Azure Activity Log `claims` map uses.
const CLAIM_UPN: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
const CLAIM_NAME: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";

/// `resourceType.value`: the `provider/type` prefix of a resource id.
fn resource_type(resource_id: &str) -> String {
    let after = resource_id
        .split("/providers/")
        .nth(1)
        .unwrap_or(resource_id);
    let mut parts = after.split('/');
    let provider = parts.next().unwrap_or("");
    let kind = parts.next().unwrap_or("");
    if provider.is_empty() {
        provider.to_string()
    } else {
        format!("{provider}/{kind}")
    }
}

/// An ARM `{value, localizedValue}` object.
fn arm_object(value: &str) -> Val {
    Val::Raw(json!({"value": value, "localizedValue": value}))
}

/// The `claims` map: the caller's UPN and display name under the WS-Identity claim-type URIs.
fn claims_json(c: &Ctx<'_>, e: &AzureEvent) -> Value {
    let display = c
        .world
        .user_by_upn(&e.caller)
        .map(|u| u.display_name.clone())
        .unwrap_or_else(|| e.caller.clone());
    json!({CLAIM_UPN: e.caller, CLAIM_NAME: display})
}

/// One EventData object as a `Row`, in the ARM response key order.
fn event_row(c: &Ctx<'_>, e: &AzureEvent) -> Row {
    let operation = &e.operation;
    vec![
        r(
            "authorization",
            Val::Raw(json!({"action": operation, "role": "Contributor", "scope": e.resource_id})),
        ),
        r("caller", Val::Str(e.caller.clone())),
        r("claims", Val::Raw(claims_json(c, e))),
        r("correlationId", Val::Str(e.correlation_id.to_string())),
        r("description", Val::Str(String::new())),
        r("eventDataId", Val::Str(e.event_data_id.to_string())),
        r("eventName", arm_object(operation)),
        r("category", arm_object(&e.category)),
        r("eventTimestamp", Val::Date(PsDate::iso(e.time, 7))),
        r(
            "httpRequest",
            Val::Raw(json!({
                "clientRequestId": e.correlation_id.to_string(),
                "clientIpAddress": e.ip.to_string(),
                "method": "POST"
            })),
        ),
        r(
            "id",
            Val::Str(format!(
                "/subscriptions/{}/providers/Microsoft.Insights/eventtypes/management/values/{}",
                e.subscription_id, e.event_data_id
            )),
        ),
        r("level", Val::Str(e.level.clone())),
        r("operationId", Val::Str(operation.clone())),
        r("operationName", arm_object(operation)),
        r("properties", Val::Raw(json!({"eventCategory": e.category}))),
        r("resourceGroupName", Val::Str(e.resource_group.clone())),
        r("resourceProviderName", arm_object(&e.provider)),
        r("resourceId", Val::Str(e.resource_id.clone())),
        r("resourceType", arm_object(&resource_type(&e.resource_id))),
        r("status", arm_object(&e.status)),
        r("subStatus", arm_object(&e.sub_status)),
        r("submissionTimestamp", Val::Date(PsDate::iso(e.time, 7))),
        r("subscriptionId", Val::Str(e.subscription_id.to_string())),
        r("tenantId", Val::Str(e.tenant_id.to_string())),
    ]
}

/// A seeded permutation of the ARM keys, the hashtable enumeration order the collector copies
/// every event of one run through. Each run gets its own order (three separate processes), so
/// the CSV, JSON and jsonl renderings never collapse into one byte-identical duplicate.
fn reorder(row: &Row, order: &[usize]) -> Row {
    order.iter().map(|&i| row[i].clone()).collect()
}

fn keys_of(c: &Ctx<'_>) -> Vec<String> {
    c.world
        .azure
        .iter()
        .map(|e| keys::azure_activity(&e.event_data_id.to_string()))
        .collect()
}

/// Get-ActivityLogs: one `ActivityLog.json` per subscription with events (the world has one).
fn write_activity_logs(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Activity Logs", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Azure Activity Log Collection ===");
    if c.world.azure.is_empty() {
        return Ok(());
    }
    let rows: Vec<Row> = c.world.azure.iter().map(|e| event_row(c, e)).collect();
    let subscription = c.world.azure[0].subscription_id.to_string();
    let stamp = run.local.format("%Y%m%d%H%M%S").to_string();
    let rel = format!("{dir}/{stamp}-{subscription}-ActivityLog.json");
    let mut text = convert_to_json(&c.host, &rows, false).text;
    text.push_str(c.nl());
    tree.write(&FileSpec::new(&rel, Some("inv.activity"), c.utf8()), &text)?;
    for key in keys_of(c) {
        tree.row(&rel, "azure_activity", key);
    }
    Ok(())
}

/// One DirectoryActivityLogs run: write `rel` with `encoding` and record the rows.
fn write_form(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    encoding: Encoding,
    rows: &[Row],
    keys: &[String],
) -> Result<()> {
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, rows, &mut ev);
    tree.write(
        &FileSpec::new(rel, Some("inv.directory_activity"), encoding),
        &rendered.text,
    )?;
    if ev.culture_dates > 0 {
        tree.date_evidence(rel, ev);
    }
    for key in keys {
        tree.row(rel, "azure_activity", key.clone());
    }
    Ok(())
}

/// The three Get-DirectoryActivityLogs renderings, each its own run folder and its own seeded
/// hashtable key order.
fn write_directory_activity_logs(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let mut rng = stream(c.world.seed, "invictus/directory_activity_keys");
    let base: Vec<Row> = c.world.azure.iter().map(|e| event_row(c, e)).collect();
    let keys = keys_of(c);
    let mut order: Vec<usize> = (0..ARM_KEYS.len()).collect();

    // CSV: Export-Csv -Encoding UTF8.
    rng.shuffle(&mut order);
    let rows: Vec<Row> = base.iter().map(|r| reorder(r, &order)).collect();
    let run = c.runs.next("Directory Activity Logs", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(
        run.local,
        "=== Starting Azure Directory Activity Log Collection ===",
    );
    let rel = format!("{dir}/DirectoryActivityLogs.csv");
    write_form(c, tree, &rel, c.utf8(), &rows, &keys)?;

    // JSON: Set-Content with no -Encoding (PS7 UTF-8, 5.1 Windows-1252).
    rng.shuffle(&mut order);
    let rows: Vec<Row> = base.iter().map(|r| reorder(r, &order)).collect();
    let run = c.runs.next("Directory Activity Logs", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let rel = format!("{dir}/DirectoryActivityLogs.JSON");
    let encoding = match c.opts.ps {
        PsEdition::Ps51 => Encoding::Cp1252,
        PsEdition::Ps7 => Encoding::Utf8,
    };
    let mut text = convert_to_json(&c.host, &rows, false).text;
    text.push_str(c.nl());
    tree.write(
        &FileSpec::new(&rel, Some("inv.directory_activity"), encoding),
        &text,
    )?;
    for key in &keys {
        tree.row(&rel, "azure_activity", key.clone());
    }

    // jsonl: Out-File -Encoding UTF8 of a pretty array (not JSON lines).
    rng.shuffle(&mut order);
    let rows: Vec<Row> = base.iter().map(|r| reorder(r, &order)).collect();
    let run = c.runs.next("Directory Activity Logs", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let stamp = run.local.format("%Y%m%d%H%M%S").to_string();
    let rel = format!("{dir}/{stamp}-DirectoryActivityLogs.jsonl");
    let mut text = convert_to_json(&c.host, &rows, false).text;
    text.push_str(c.nl());
    tree.write(
        &FileSpec::new(&rel, Some("inv.directory_activity"), c.utf8()),
        &text,
    )?;
    for key in &keys {
        tree.row(&rel, "azure_activity", key.clone());
    }
    Ok(())
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    write_activity_logs(c, tree)?;
    write_directory_activity_logs(c, tree)
}
