//! Quick UAL / triage (research event layouts §3): per-operation JSON and CSV files in the
//! triage root, plus the derived `UAL-Operations-Combined.csv`.

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::ps::{
    DateEvidence, DtKind, Host, PsDate, Rendered, Row, Val, convert_to_json, export_csv, json_text,
};
use crate::story::Evidence;
use crate::tree::{FileSpec, Tree};
use serde_json::Value;
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

fn file_name(op: &str) -> String {
    let mut out = op
        .chars()
        .map(|ch| match ch {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => ch,
        })
        .collect::<String>();
    if out.ends_with('.') {
        out.pop();
        out.push('_');
    }
    out
}

fn base_row(u: &crate::events::Ual, queried: &str) -> Row {
    vec![
        r("RecordType", Val::Str(u.record_type.name().into())),
        r(
            "CreationDate",
            Val::DateText(PsDate::dotnet(u.time, DtKind::Utc)),
        ),
        r("UserIds", Val::Str(u.user_id.clone())),
        r("Operations", Val::Str(u.operation.clone())),
        r("AuditData", Val::Raw(Value::Object(u.audit.clone()))),
        r("ResultIndex", Val::Int(1)),
        r("ResultCount", Val::Int(1)),
        r(
            "AuditSearchRequestMetadata",
            Val::Str("{\r\n  \"moreRecordsAvailable\": false\r\n}".into()),
        ),
        r("Identity", Val::Str(u.id.to_string())),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", Val::Str("Unchanged".into())),
        r("OperationQueried", Val::Str(queried.to_string())),
    ]
}

fn json_row(u: &crate::events::Ual, queried: &str) -> Row {
    base_row(u, queried)
}

fn csv_row(host: &Host, u: &crate::events::Ual, queried: &str) -> Row {
    vec![
        r("RecordType", Val::Str(u.record_type.name().into())),
        r(
            "CreationDate",
            Val::DateText(PsDate::dotnet(u.time, DtKind::Utc)),
        ),
        r("UserIds", Val::Str(u.user_id.clone())),
        r("Operations", Val::Str(u.operation.clone())),
        r("ResultIndex", Val::Int(1)),
        r("ResultCount", Val::Int(1)),
        r(
            "AuditSearchRequestMetadata",
            Val::Str("{\r\n  \"moreRecordsAvailable\": false\r\n}".into()),
        ),
        r("Identity", Val::Str(u.id.to_string())),
        r("IsValid", Val::Bool(true)),
        r("ObjectState", Val::Str("Unchanged".into())),
        r("OperationQueried", Val::Str(queried.to_string())),
        r(
            "AuditData_UserId",
            u.audit
                .get("UserId")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r(
            "AuditData_ClientIP",
            u.audit
                .get("ClientIP")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r(
            "AuditData_UserAgent",
            u.audit
                .get("UserAgent")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r(
            "AuditData_ObjectId",
            u.audit
                .get("ObjectId")
                .and_then(Value::as_str)
                .map_or(Val::Null, |s| Val::Str(s.to_string())),
        ),
        r(
            "AuditData_Raw",
            Val::Str(json_text(host, &Value::Object(u.audit.clone()), true)),
        ),
    ]
}

/// The operations this writer queries (research event layouts §3).
const FULL_OPERATIONS: [&str; 4] = [
    "New-InboxRule",
    "Set-Mailbox",
    "MailItemsAccessed",
    "Consent to application.",
];

fn op_records(c: &Ctx<'_>, op: &str) -> Vec<crate::events::Ual> {
    let victims = victims(c);
    c.days()
        .flat_map(|d| d.ual)
        .filter(|u| victims.contains(&u.user_id.to_lowercase()) && u.operation == op)
        .collect()
}

/// The records this writer emits from the full AuditData. `ual::write_get_ual` reads the same
/// set to predict which `-AuditDataOnly` windows are upgraded.
pub(super) fn full_records(c: &Ctx<'_>) -> Vec<crate::events::Ual> {
    FULL_OPERATIONS
        .iter()
        .flat_map(|op| op_records(c, op))
        .collect()
}

fn write_json(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    rows: &[Row],
    records: &[crate::events::Ual],
) -> Result<()> {
    let rendered = convert_to_json(&c.host, rows, false);
    if c.opts.non_windows {
        let enc = c.utf8();
        tree.write_unlisted(&format!("Output\\{rel}"), &enc.encode(&rendered.text))?;
        return Ok(());
    }
    tree.write(
        &FileSpec::new(rel, Some(artifact), c.utf8()),
        &rendered.text,
    )?;
    for (u, span) in records.iter().zip(&rendered.spans) {
        tree.row(rel, "ual_events", keys::ual(u.id));
        tree.deliver(&Evidence::Ual(u.id), "ual_events", rel, *span);
    }
    Ok(())
}

fn write_csv(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    derived: bool,
    rows: &[Row],
    records: &[crate::events::Ual],
) -> Result<Rendered> {
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, rows, &mut ev);
    if c.opts.non_windows {
        let enc = c.utf8();
        tree.write_unlisted(&format!("Output\\{rel}"), &enc.encode(&rendered.text))?;
        return Ok(rendered);
    }
    let spec = if derived {
        FileSpec::new(rel, Some(artifact), c.utf8()).derived()
    } else {
        FileSpec::new(rel, Some(artifact), c.utf8())
    };
    tree.write(&spec, &rendered.text)?;
    if ev.culture_dates > 0 {
        tree.date_evidence(rel, ev);
    }
    for (u, span) in records.iter().zip(&rendered.spans) {
        tree.row(rel, "ual_events", keys::ual(u.id));
        tree.deliver(&Evidence::Ual(u.id), "ual_events", rel, *span);
    }
    Ok(rendered)
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let ops = FULL_OPERATIONS;
    let dir = c.triage_root();
    if !c.opts.non_windows {
        tree.dir(&dir)?;
    }
    let mut combined_rows = Vec::new();
    let mut combined_records = Vec::new();
    for op in ops {
        let records = op_records(c, op);
        if records.is_empty() {
            continue;
        }
        let safe = file_name(op);
        let json_rows: Vec<Row> = records.iter().map(|u| json_row(u, op)).collect();
        let csv_rows: Vec<Row> = records.iter().map(|u| csv_row(&c.host, u, op)).collect();
        write_json(
            c,
            tree,
            &format!("{dir}/{safe}.json"),
            "inv.quickual.operation",
            &json_rows,
            &records,
        )?;
        write_csv(
            c,
            tree,
            &format!("{dir}/{safe}.csv"),
            "inv.quickual.operation",
            false,
            &csv_rows,
            &records,
        )?;
        combined_rows.extend(csv_rows);
        combined_records.extend(records);
    }
    if combined_rows.is_empty() {
        return Ok(());
    }
    write_csv(
        c,
        tree,
        &format!("{dir}/UAL-Operations-Combined.csv"),
        "inv.quickual.combined",
        true,
        &combined_rows,
        &combined_records,
    )?;
    Ok(())
}
