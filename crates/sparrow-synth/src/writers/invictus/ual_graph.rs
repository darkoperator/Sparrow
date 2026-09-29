//! Get-UALGraph (research event layouts §2): three victim-result runs in
//! `UnifiedAuditLog/<ts>/` (JSON, CSV, JSONL) plus one empty JSON run whose file is the lone
//! `[` the cmdlet leaves behind.

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::ps::{DateEvidence, DtKind, PsDate, Row, Val, export_csv, json_text, json_value};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn victims(c: &Ctx<'_>) -> BTreeSet<String> {
    c.world
        .victims
        .iter()
        .map(|n| c.world.user(*n).upn.to_lowercase())
        .collect()
}

/// The records this writer emits from the full AuditData (the victims' records). `ual::
/// write_get_ual` reads the same set to predict which `-AuditDataOnly` windows are upgraded.
pub(super) fn full_records(c: &Ctx<'_>) -> Vec<crate::events::Ual> {
    let victims = victims(c);
    c.days()
        .flat_map(|d| d.ual)
        .filter(|u| victims.contains(&u.user_id.to_lowercase()))
        .collect()
}

fn graph_row(u: &crate::events::Ual) -> Row {
    vec![
        r("id", Val::Str(u.id.to_string())),
        r(
            "createdDateTime",
            Val::Date(PsDate::dotnet(u.time, DtKind::Utc)),
        ),
        r(
            "auditLogRecordType",
            Val::Int(i64::from(u.record_type.number())),
        ),
        r("operation", Val::Str(u.operation.clone())),
        r(
            "organizationId",
            u.audit
                .get("OrganizationId")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r(
            "userType",
            u.audit
                .get("UserType")
                .and_then(Value::as_i64)
                .map_or(Val::Null, Val::Int),
        ),
        r("userId", Val::Str(u.user_id.clone())),
        r(
            "service",
            u.audit
                .get("Workload")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r(
            "objectId",
            u.audit
                .get("ObjectId")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r("userPrincipalName", Val::Str(u.user_id.clone())),
        r(
            "clientIp",
            u.client_ip().map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r("administrativeUnits", Val::Str(String::new())),
        r("auditData", Val::Raw(Value::Object(u.audit.clone()))),
    ]
}

fn row_object(c: &Ctx<'_>, row: &Row) -> Value {
    let mut map = Map::with_capacity(row.len());
    for (k, v) in row {
        map.insert(k.clone(), json_value(&c.host, v));
    }
    Value::Object(map)
}

fn write_json(c: &Ctx<'_>, rows: &[Row]) -> (String, Vec<(u32, u32)>) {
    let nl = c.nl();
    let mut text = String::from("[");
    text.push_str(nl);
    let mut spans = Vec::with_capacity(rows.len());
    let mut line = 2u32;
    for (i, row) in rows.iter().enumerate() {
        if i == 0 {
            text.push_str(nl);
            line += 1;
        } else {
            text.push(',');
            text.push_str(nl);
            line += 1;
        }
        let obj = json_text(&c.host, &row_object(c, row), false);
        let start = line;
        let end = start + obj.matches('\n').count() as u32;
        spans.push((start, end));
        text.push_str(&obj);
        line = end;
    }
    text.push(']');
    text.push_str(nl);
    (text, spans)
}

fn write_rows(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    rows: &[Row],
    records: &[crate::events::Ual],
) -> Result<()> {
    let (text, spans) = write_json(c, rows);
    tree.write(&FileSpec::new(rel, Some("inv.ual.graph"), c.utf8()), &text)?;
    for (u, span) in records.iter().zip(&spans) {
        tree.row(rel, "ual_events", keys::ual(u.id));
        tree.deliver(&Evidence::Ual(u.id), "ual_events", rel, *span);
    }
    Ok(())
}

fn write_csv(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    rows: &[Row],
    records: &[crate::events::Ual],
) -> Result<()> {
    let rows: Vec<Row> = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|(k, v)| {
                    if k == "auditData" {
                        match v {
                            Val::Raw(Value::Object(m)) => (
                                k.clone(),
                                Val::Str(json_text(&c.host, &Value::Object(m.clone()), false)),
                            ),
                            _ => (k.clone(), v.clone()),
                        }
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect()
        })
        .collect();
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, &rows, &mut ev);
    tree.write(
        &FileSpec::new(rel, Some("inv.ual.graph"), c.utf8()),
        &rendered.text,
    )?;
    if ev.culture_dates > 0 {
        tree.date_evidence(rel, ev);
    }
    for (u, span) in records.iter().zip(&rendered.spans) {
        tree.row(rel, "ual_events", keys::ual(u.id));
        tree.deliver(&Evidence::Ual(u.id), "ual_events", rel, *span);
    }
    Ok(())
}

fn write_jsonl(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    records: &[crate::events::Ual],
) -> Result<()> {
    let mut text = String::new();
    for u in records {
        text.push_str(&json_text(&c.host, &Value::Object(u.audit.clone()), true));
        text.push_str(c.nl());
    }
    tree.write(&FileSpec::new(rel, Some("inv.ual.graph"), c.utf8()), &text)?;
    for (i, u) in records.iter().enumerate() {
        let line = i as u32 + 1;
        tree.row(rel, "ual_events", keys::ual(u.id));
        tree.deliver(&Evidence::Ual(u.id), "ual_events", rel, (line, line));
    }
    Ok(())
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let records = full_records(c);
    let rows: Vec<Row> = records.iter().map(graph_row).collect();

    let run = c.runs.next("UnifiedAuditLog", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let stamp = run.local.format("%Y%m%d%H%M%S").to_string();
    let rel = format!("{dir}/{stamp}-victims-UnifiedAuditLog.json");
    write_rows(c, tree, &rel, &rows, &records)?;

    let run = c.runs.next("UnifiedAuditLog", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let stamp = run.local.format("%Y%m%d%H%M%S").to_string();
    let rel = format!("{dir}/{stamp}-victims-UnifiedAuditLog.csv");
    write_csv(c, tree, &rel, &rows, &records)?;

    let run = c.runs.next("UnifiedAuditLog", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let stamp = run.local.format("%Y%m%d%H%M%S").to_string();
    let rel = format!("{dir}/{stamp}-victims-UnifiedAuditLog.jsonl");
    write_jsonl(c, tree, &rel, &records)?;

    let run = c.runs.next("UnifiedAuditLog", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    let stamp = run.local.format("%Y%m%d%H%M%S").to_string();
    let rel = format!("{dir}/{stamp}-empty-UnifiedAuditLog.json");
    tree.write(
        &FileSpec::new(&rel, Some("inv.ual.graph"), c.utf8()),
        &format!("[{}", c.nl()),
    )?;
    Ok(())
}
