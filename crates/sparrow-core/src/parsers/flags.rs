//! Hawk's own flags (spec 5.3 collector_flags): the records of `_Investigate_*` files and
//! the lines of `_Investigate.txt`. A flag's linked_key comes from the key function of the
//! flagged table's parser, so flags join directly to their rows.

use crate::Result;
use crate::db::state_tables::COLLECTOR_FLAGS;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::normalize::net::normalize_upn;
use crate::normalize::ual_shape::{detect_shape, to_audit};
use crate::parsers::apps::oauth_grant_key;
use crate::parsers::directory::exchange_assignment_key;
use crate::parsers::exchange::{inbox_rule_key, mobile_device_key};
use crate::parsers::records::RecordFormat;
use crate::parsers::risk::{risk_detection_key, risky_user_key};
use crate::parsers::stage::{RowDraft, TableRows, load_tables, lower, read_state_records};
use crate::readers::text::{Span, line_spans};
use crate::readers::time::{DateOrderDetector, parse_timestamp};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub fn register(r: &mut ParserRegistry) {
    r.register("hawk.investigate_file", Box::new(InvestigateFileParser));
    r.register("hawk.investigate_txt", Box::new(InvestigateTxtParser));
}

struct FlagKind {
    prefix: &'static str,
    flag_type: &'static str,
    linked_table: Option<&'static str>,
    description: &'static str,
}

const fn kind(
    prefix: &'static str,
    flag_type: &'static str,
    linked_table: Option<&'static str>,
    description: &'static str,
) -> FlagKind {
    FlagKind {
        prefix,
        flag_type,
        linked_table,
        description,
    }
}

static FLAG_KINDS: &[FlagKind] = &[
    kind(
        "Confirmed_Compromised_Risk_Detection",
        "confirmed_compromised_risk_detection",
        Some("risk_detections"),
        "Hawk: risk detection in state confirmedCompromised",
    ),
    kind(
        "Risk_Detection",
        "risk_detection",
        Some("risk_detections"),
        "Hawk: high, medium or low risk detection",
    ),
    kind(
        "Compromised_Users",
        "compromised_user",
        Some("risky_users"),
        "Hawk: user confirmed compromised by Entra ID Protection",
    ),
    kind(
        "Risky_Users",
        "risky_user",
        Some("risky_users"),
        "Hawk: user at high, medium or low risk",
    ),
    kind(
        "Consent_Grants",
        "risky_consent_grant",
        Some("oauth_grants"),
        "Hawk: consent grant in a risk category (broad-scope, extremely dangerous or high risk)",
    ),
    kind(
        "Impersonation_Rights",
        "impersonation_rights",
        Some("role_assignments"),
        "Hawk: ApplicationImpersonation role assignment",
    ),
    kind(
        "InboxRules",
        "inbox_rule",
        Some("inbox_rules"),
        "Hawk: inbox rule deletes, forwards or redirects mail",
    ),
    kind(
        "MobileDevice",
        "new_mobile_device",
        Some("mobile_devices"),
        "Hawk: mobile device first synced inside the investigation window",
    ),
    kind(
        "Admin_Inbox_Rules",
        "admin_inbox_rule_change",
        Some("ual_events"),
        "Hawk: an administrator created, modified or removed an inbox rule",
    ),
    kind(
        "Mailbox_Permission_Change",
        "mailbox_permission_change",
        Some("ual_events"),
        "Hawk: mailbox or recipient permission granted",
    ),
    kind(
        "Entra_Sign_In_Log",
        "risky_signin",
        Some("signins"),
        "Hawk: risky Entra ID sign-in",
    ),
    kind(
        "Simple_New_InboxRule",
        "admin_inbox_rule_change",
        Some("admin_audit_events"),
        "Hawk: an administrator created an inbox rule (Hawk 3 admin audit log)",
    ),
    kind(
        "New_InboxRules",
        "admin_inbox_rule_change",
        Some("admin_audit_events"),
        "Hawk: an administrator created an inbox rule (Hawk 3 admin audit log)",
    ),
];

const OTHER_DESCRIPTION: &str = "Hawk flagged this record for investigation";

fn flag_kind(file_name: &str) -> Option<&'static FlagKind> {
    let lower = file_name.to_ascii_lowercase();
    let rest = lower.strip_prefix("_investigate_")?;
    FLAG_KINDS
        .iter()
        .find(|k| rest.starts_with(&k.prefix.to_ascii_lowercase()))
}

/// AuditData Id of a UAL-shaped record (raw, expanded or flattened), as ual_events keys it.
fn ual_record_id(map: &Map<String, Value>, lossy: bool) -> Option<String> {
    let shape = detect_shape(map.keys().map(String::as_str), false);
    let input = to_audit(shape, map, lossy).ok()?;
    let id = Rec::new(&input.audit, false).text("Id")?;
    uuid::Uuid::parse_str(&id)
        .ok()
        .map(|u| u.hyphenated().to_string())
}

fn linked_key(
    table: &str,
    map: &Map<String, Value>,
    lossy: bool,
    subject: Option<&str>,
) -> Option<String> {
    let rec = Rec::new(map, lossy);
    match table {
        "inbox_rules" => inbox_rule_key("inbox", &rec, subject),
        "oauth_grants" => oauth_grant_key(&rec),
        "role_assignments" => exchange_assignment_key("exchange_rbac", &rec),
        "risky_users" => risky_user_key(&rec),
        "risk_detections" => risk_detection_key(&rec),
        "mobile_devices" => mobile_device_key(&rec, subject),
        "signins" => lower(rec.text("Id")),
        "ual_events" => ual_record_id(map, lossy),
        _ => None,
    }
}

/// JSON with object keys sorted recursively (stable basis for flag keys).
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|k| (k.clone(), canonical(&m[k])))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn flag_key(parts: &[&str]) -> String {
    hex::encode(Sha256::digest(parts.join("\n").as_bytes()))
}

const FLAG_COLS: &[&str] = &[
    "file_id",
    "flag_type",
    "category",
    "flag_time",
    "subject",
    "description",
    "linked_table",
    "linked_key",
];

/// `_Investigate_*.{json,csv,txt}`: copies of records Hawk flagged.
pub struct InvestigateFileParser;

impl ArtifactParser for InvestigateFileParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let rel = ctx.rel_path;
        let file = rel.rsplit('/').next().unwrap_or(rel);
        let (flag_type, table, description) = flag_kind(file)
            .map_or(("other", None, OTHER_DESCRIPTION), |k| {
                (k.flag_type, k.linked_table, k.description)
            });
        let subject = ctx.subject.and_then(normalize_upn);
        let format = RecordFormat::of(rel);
        let file_id = ctx.file_id;
        let records = read_state_records(ctx, format)?;
        let mut rows = TableRows::new(&COLLECTOR_FLAGS, FLAG_COLS);
        for r in &records {
            let linked =
                table.and_then(|t| linked_key(t, &r.map, format.lossy(), subject.as_deref()));
            let basis = linked
                .clone()
                .unwrap_or_else(|| canonical(&Value::Object(r.map.clone())).to_string());
            let key = flag_key(&[flag_type, table.unwrap_or(""), &basis]);
            rows.push(
                r,
                key,
                vec![
                    Cell::int(Some(file_id)),
                    Cell::text(Some(flag_type.into())),
                    Cell::Null,
                    Cell::Null,
                    Cell::text(subject.clone()),
                    Cell::text(Some(description.into())),
                    Cell::text(table.map(Into::into)),
                    Cell::text(linked),
                ],
            );
        }
        load_tables(ctx, vec![rows])
    }
}

fn re_line() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\[([^\]]+)\]\s+-\s+(?:\[(\w+)\]\s+-\s+|##\s*(.*?)\s*##\s+-\s+)?(.*)$")
            .expect("valid regex")
    })
}

const ADDITIONAL: &str = "Additional Information:";

struct Entry {
    span: Span,
    ts: Option<String>,
    tag: Option<String>,
    message: String,
}

/// Hawk 4 `[yyyy-MM-dd HH:mm:ssZ] - [INVESTIGATE] - msg` lines and Hawk 3
/// `[M/d/yyyy h:mm:ss tt] - ## Tag ## - msg` lines followed by `Additional Information: <path>`.
fn entries(text: &str) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for span in line_spans(text) {
        let line = &text[span.start..span.end];
        if line.trim().is_empty() {
            continue;
        }
        if let Some(c) = re_line().captures(line) {
            out.push(Entry {
                span,
                ts: Some(c[1].trim().to_string()),
                tag: c.get(3).map(|m| m.as_str().to_string()),
                message: c[4].trim().to_string(),
            });
        } else if line.trim_start().starts_with(ADDITIONAL) || out.is_empty() {
            let prev = out.last();
            let (ts, tag) = (
                prev.and_then(|p| p.ts.clone()),
                prev.and_then(|p| p.tag.clone()),
            );
            out.push(Entry {
                span,
                ts,
                tag,
                message: line.trim().to_string(),
            });
        } else if let Some(last) = out.last_mut() {
            last.message.push('\n');
            last.message.push_str(line.trim());
            last.span.end = span.end;
        }
    }
    out
}

/// Collection-relative path of a file Hawk named with its absolute (Windows or Unix) path:
/// `Tenant/<file>` or `<user>/<file>`, else just the file name. `None` when not a path.
fn rel_guess(path: &str) -> Option<String> {
    if !path.contains(['\\', '/']) {
        return None;
    }
    let parts: Vec<&str> = path.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
    let file = *parts.last()?;
    match parts.len().checked_sub(2).map(|i| parts[i]) {
        Some(dir) if dir.eq_ignore_ascii_case("Tenant") || dir.contains('@') => {
            Some(format!("{dir}/{file}"))
        }
        _ => Some(file.to_string()),
    }
}

/// `_Investigate.txt`: Hawk's investigation log.
pub struct InvestigateTxtParser;

impl ArtifactParser for InvestigateTxtParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text;
        let list = entries(&text.text);
        let mut detector = DateOrderDetector::default();
        for ts in list.iter().filter_map(|e| e.ts.as_deref()) {
            detector.observe(ts);
        }
        let resolved = match detector.resolve(ctx.options.date_order) {
            Ok(order) => Some(order),
            Err(reason) => {
                ctx.warn(format!(
                    "_Investigate.txt times not parsed (flag_time is NULL): {reason}"
                ));
                None
            }
        };
        let file_id = ctx.file_id;
        let mut unparsed = 0u64;
        let mut rows = TableRows::new(&COLLECTOR_FLAGS, FLAG_COLS);
        for (i, e) in list.iter().enumerate() {
            let time = match (&e.ts, resolved) {
                (Some(ts), Some(order)) if parse_timestamp(ts, order).is_ok() => {
                    Cell::Time(ts.clone())
                }
                (Some(_), Some(_)) => {
                    unparsed += 1;
                    Cell::Null
                }
                _ => Cell::Null,
            };
            let reference = e
                .message
                .strip_prefix(ADDITIONAL)
                .and_then(|p| rel_guess(p.trim()));
            let (flag_type, table) = if reference.is_some() {
                ("investigate_file_reference", Some("source_files"))
            } else {
                ("investigate_note", None)
            };
            let key = flag_key(&[flag_type, e.ts.as_deref().unwrap_or(""), &e.message]);
            rows.push_draft(RowDraft {
                ordinal: i as u64,
                span: e.span,
                record_key: key,
                cells: vec![
                    Cell::int(Some(file_id)),
                    Cell::text(Some(flag_type.into())),
                    Cell::text(e.tag.clone()),
                    time,
                    Cell::Null,
                    Cell::text(Some(e.message.clone())),
                    Cell::text(table.map(Into::into)),
                    Cell::text(reference),
                ],
                raw: Some(json!({ "line": &text.text[e.span.start..e.span.end] })),
            });
        }
        if unparsed > 0 {
            ctx.warn(format!(
                "{unparsed} _Investigate.txt timestamps could not be parsed (flag_time is NULL)"
            ));
        }
        load_tables(ctx, vec![rows])
    }
}
