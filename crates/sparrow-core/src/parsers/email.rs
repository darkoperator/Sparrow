//! Exported e-mail: Microsoft-Extractor-Suite Get-Email `.eml`/`.txt` MIME and Hawk
//! Get-HawkMessageHeader `Message_Header[_Findings]_<file>.csv` exports into `email_artifacts`
//! (research event layouts §9; hawk layouts §1.4). A message's `.eml` and its Hawk header
//! export share one row keyed by the Message-ID.

use crate::Result;
use crate::db::state_tables::EMAIL_ARTIFACTS;
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::Cell;
use crate::normalize::net::normalize_ip;
use crate::parsers::stage::{CellRow, RowDraft, TableRows, load_tables};
use crate::readers::csv_scan::read_csv;
use crate::readers::text::Span;
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::OnceLock;

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.email", Box::new(EmailParser));
    r.register("hawk.message.header", Box::new(HawkHeaderParser));
}

// ---------------------------------------------------------------------------------------------
// MIME header helpers
// ---------------------------------------------------------------------------------------------

/// One unfolded header.
type Header = (String, String);

/// Split a MIME header block into unfolded headers, stopping at the first blank line. Returns
/// the headers and the decoded-text offset where the blank line starts (the record span).
fn parse_header_block(text: &str) -> (Vec<Header>, usize) {
    let mut headers: Vec<Header> = Vec::new();
    let mut pending: Option<Header> = None;
    let mut offset = 0usize;
    let mut end = text.len();
    for segment in text.split_inclusive('\n') {
        let bare = segment.trim_end_matches(['\r', '\n']);
        if bare.trim().is_empty() {
            end = offset;
            break;
        }
        offset += segment.len();
        if bare.starts_with([' ', '\t']) {
            if let Some(h) = pending.as_mut() {
                h.1.push(' ');
                h.1.push_str(bare.trim());
            }
        } else {
            if let Some(h) = pending.take() {
                headers.push(h);
            }
            let (name, value) = match bare.split_once(':') {
                Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
                None => (bare.trim().to_string(), String::new()),
            };
            pending = Some((name, value));
        }
    }
    if let Some(h) = pending.take() {
        headers.push(h);
    }
    (headers, end)
}

/// A case-insensitive view of a header list.
struct HeaderSet<'a> {
    headers: &'a [Header],
}

impl<'a> HeaderSet<'a> {
    fn new(headers: &'a [Header]) -> HeaderSet<'a> {
        HeaderSet { headers }
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> impl Iterator<Item = &'a str> {
        let name = name.to_string();
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(&name))
            .map(|(_, v)| v.as_str())
    }
}

fn encoded_word_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"=\?([^?]+)\?([BbQq])\?([^?]*)\?=").expect("valid regex"))
}

/// Decode RFC 2047 `=?utf-8?B|Q?...?=` encoded words (other charsets are left as written);
/// folding whitespace between two adjacent encoded words is dropped.
fn decode_encoded_words(value: &str) -> String {
    if !value.contains("=?") {
        return value.to_string();
    }
    let re = encoded_word_re();
    let mut out = String::new();
    let mut last_end = 0usize;
    let mut last_was_encoded = false;
    for m in re.find_iter(value) {
        let between = &value[last_end..m.start()];
        if last_was_encoded && between.trim().is_empty() {
            // Fold whitespace between encoded words away.
        } else {
            out.push_str(between);
            last_was_encoded = false;
        }
        let Some(caps) = re.captures(m.as_str()) else {
            continue;
        };
        let charset = caps[1].to_ascii_lowercase();
        let decoded = match (charset.as_str(), caps[2].to_ascii_uppercase().as_str()) {
            ("utf-8" | "us-ascii", "B") => base64_decode(&caps[3]),
            ("utf-8" | "us-ascii", "Q") => Some(q_decode(&caps[3])),
            _ => None,
        };
        match decoded {
            Some(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
            None => out.push_str(m.as_str()),
        }
        last_end = m.end();
        last_was_encoded = true;
    }
    out.push_str(&value[last_end..]);
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// RFC 2047 `Q` decoding: `_` is a space and `=XX` a byte.
fn q_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_' {
            out.push(b' ');
            i += 1;
        } else if b[i] == b'=' && i + 2 < b.len() {
            match (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                }
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Standard base64 (`=` padding and whitespace ignored); `None` on a stray character.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Split an address list on commas that are not inside a quoted display name or angle brackets.
fn split_addresses(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_quotes, mut in_angle, mut escaped) = (false, false, false);
    for c in value.chars() {
        match c {
            '"' if !escaped => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            '<' if !in_quotes => {
                in_angle = true;
                cur.push(c);
            }
            '>' if !in_quotes => {
                in_angle = false;
                cur.push(c);
            }
            ',' if !in_quotes && !in_angle => {
                let t = cur.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
                cur.clear();
            }
            '\\' if in_quotes => {
                escaped = true;
                cur.push(c);
                continue;
            }
            _ => cur.push(c),
        }
        escaped = false;
    }
    let t = cur.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
    out
}

/// `(display name, address)` of one address-list entry; the address is the part inside `<>`.
fn extract_address(entry: &str) -> (Option<String>, Option<String>) {
    let entry = entry.trim();
    if let Some(start) = entry.rfind('<')
        && let Some(rel) = entry[start..].find('>')
    {
        let addr = entry[start + 1..start + rel].trim().to_string();
        let display = entry[..start].trim().trim_matches('"').trim().to_string();
        return (
            (!display.is_empty()).then_some(display),
            (!addr.is_empty()).then_some(addr),
        );
    }
    let addr = entry.trim_matches('"').trim().to_string();
    (None, (!addr.is_empty()).then_some(addr))
}

/// Angle brackets trimmed and trimmed; the `email_artifacts` key form.
fn clean_message_id(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_string()
}

/// The `spf`/`dkim`/`dmarc` result word from an `Authentication-Results` header.
fn auth_result(value: &str, key: &str) -> Option<String> {
    value.split_whitespace().find_map(|tok| {
        let (k, v) = tok.split_once('=')?;
        (k == key).then(|| v.trim_end_matches([';', ',']).to_string())
    })
}

/// An RFC 5322 `Date` value as RFC 3339 text (`Cell::time` parses that).
fn parse_sent(value: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc2822(value.trim())
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc).to_rfc3339())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `Content-Disposition: attachment; filename=` (and `filename*=` RFC 2231) values.
fn attachment_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let bare = line.trim();
        let lower = bare.to_ascii_lowercase();
        if !lower.starts_with("content-disposition:") || !lower.contains("attachment") {
            continue;
        }
        if let Some(idx) = lower.find("filename*=") {
            let v = bare[idx + "filename*=".len()..].trim().trim_matches('"');
            let value = v.splitn(3, '\'').nth(2).unwrap_or(v);
            out.push(percent_decode(value));
        } else if let Some(idx) = lower.find("filename=") {
            let v = bare[idx + "filename=".len()..].trim();
            let v = v.strip_prefix('"').unwrap_or(v);
            let v = v.split('"').next().unwrap_or(v);
            let v = v.split(';').next().unwrap_or(v).trim();
            out.push(v.to_string());
        }
    }
    out
}

/// Every header as `[{"header", "value"}]`.
fn headers_json(headers: &[Header]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(n, v)| json!({"header": n, "value": v}))
            .collect(),
    )
}

fn json_list(items: &[String]) -> Option<Value> {
    (!items.is_empty()).then(|| Value::Array(items.iter().map(|s| json!(s)).collect()))
}

/// A `Cell` from an optional raw header value (`Cell::text` needs an owned `String`).
fn opt(v: Option<&str>) -> Cell {
    v.map(str::to_string).map_or(Cell::Null, Cell::Text)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Compare the From address (inside `<>`) with Return-Path, case-insensitively, trimmed.
fn from_return_match(from: Option<&str>, return_path: Option<&str>) -> Option<bool> {
    let (Some(f), Some(r)) = (from, return_path) else {
        return None;
    };
    Some(f.trim().eq_ignore_ascii_case(r.trim()))
}

// ---------------------------------------------------------------------------------------------
// inv.email (.eml / .txt MIME)
// ---------------------------------------------------------------------------------------------

const EMAIL_COLS: &[&str] = &[
    "source",
    "message_id",
    "subject",
    "from_address",
    "from_display",
    "return_path",
    "to_addresses",
    "cc_addresses",
    "sent",
    "received_hops",
    "auth_results",
    "spf",
    "dkim",
    "dmarc",
    "auth_as",
    "auth_mechanism",
    "originating_ip",
    "p1_p2_match",
    "attachment_names",
    "headers",
];

/// One `email_artifacts` row from a raw MIME file.
pub struct EmailParser;

impl ArtifactParser for EmailParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text.text.as_str();
        let (headers, header_end) = parse_header_block(text);
        if headers.is_empty() {
            return Ok(());
        }
        let set = HeaderSet::new(&headers);
        let message_id = set.get("Message-ID").map(clean_message_id);
        let key = message_id.clone().unwrap_or_else(|| sha256_hex(ctx.raw));
        let from = set.get("From").map(decode_encoded_words);
        let (from_display, from_address) =
            from.as_deref().map(extract_address).unwrap_or((None, None));
        let return_path = set
            .get("Return-Path")
            .map(|v| clean_message_id(&decode_encoded_words(v)));
        let subject = set.get("Subject").map(decode_encoded_words);
        let to_addresses: Vec<String> = set
            .get("To")
            .map(|v| {
                split_addresses(v)
                    .iter()
                    .filter_map(|e| extract_address(e).1)
                    .collect()
            })
            .unwrap_or_default();
        let cc_addresses: Vec<String> = set
            .get("Cc")
            .map(|v| {
                split_addresses(v)
                    .iter()
                    .filter_map(|e| extract_address(e).1)
                    .collect()
            })
            .unwrap_or_default();
        let sent = set.get("Date").and_then(parse_sent);
        let received: Vec<String> = set.all("Received").map(str::to_string).collect();
        let auth_results = set.get("Authentication-Results").map(str::to_string);
        let auth = auth_results.as_deref().unwrap_or_default();
        let (spf, dkim, dmarc) = (
            auth_result(auth, "spf"),
            auth_result(auth, "dkim"),
            auth_result(auth, "dmarc"),
        );
        let originating_ip = set
            .get("X-Originating-IP")
            .map(|v| {
                v.trim()
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            })
            .and_then(|s| normalize_ip(&s));
        let match_ = from_return_match(from_address.as_deref(), return_path.as_deref());

        let mut c = CellRow::new(EMAIL_COLS);
        c.set("source", Cell::text(Some("eml".into())))
            .set("message_id", Cell::text(message_id))
            .set("subject", Cell::text(subject))
            .set("from_address", Cell::text(from_address))
            .set("from_display", Cell::text(from_display))
            .set("return_path", Cell::text(return_path))
            .set("to_addresses", Cell::list(to_addresses))
            .set("cc_addresses", Cell::list(cc_addresses))
            .set("sent", Cell::time(sent))
            .set("received_hops", Cell::json(json_list(&received)))
            .set("auth_results", Cell::text(auth_results))
            .set("spf", Cell::text(spf))
            .set("dkim", Cell::text(dkim))
            .set("dmarc", Cell::text(dmarc))
            .set("auth_as", opt(set.get("X-MS-Exchange-Organization-AuthAs")))
            .set(
                "auth_mechanism",
                opt(set.get("X-MS-Exchange-Organization-AuthMechanism")),
            )
            .set("originating_ip", Cell::text(originating_ip))
            .set("p1_p2_match", Cell::bool(match_))
            .set("attachment_names", Cell::list(attachment_names(text)))
            .set("headers", Cell::json(Some(headers_json(&headers))));

        let mut rows = TableRows::new(&EMAIL_ARTIFACTS, EMAIL_COLS);
        rows.push_draft(RowDraft {
            ordinal: 0,
            span: Span {
                start: 0,
                end: header_end,
            },
            record_key: key,
            cells: c.into_cells(),
            raw: Some(json!({"headers": headers_json(&headers)})),
            sheet_row: None,
        });
        load_tables(ctx, vec![rows])
    }
}

// ---------------------------------------------------------------------------------------------
// hawk.message.header (Message_Header_<f>.csv and Message_Header_Findings_<f>.csv)
// ---------------------------------------------------------------------------------------------

const HAWK_HEADER_COLS: &[&str] = &[
    "source",
    "message_id",
    "subject",
    "from_address",
    "from_display",
    "return_path",
    "to_addresses",
    "sent",
    "received_hops",
    "auth_results",
    "spf",
    "dkim",
    "dmarc",
    "auth_as",
    "auth_mechanism",
    "p1_p2_match",
    "headers",
];

const HAWK_FINDINGS_COLS: &[&str] = &["source", "message_id", "subject", "p1_p2_match", "findings"];

/// The `Header, Value` rows of a Hawk `Message_Header_<f>.csv` as unfolded headers.
fn csv_headers(text: &str) -> Vec<Header> {
    let table = read_csv(text);
    table
        .rows
        .iter()
        .filter_map(|r| {
            let name = r.fields.first()?.trim().to_string();
            let value = r
                .fields
                .get(1)
                .map(|v| v.trim().to_string())
                .unwrap_or_default();
            (!name.is_empty()).then_some((name, value))
        })
        .collect()
}

/// The Message-ID in the sibling `Message_Header_<f>.csv` of a findings file in the same
/// folder, reading the file from the collection root when it exists.
fn sibling_message_id(ctx: &ParseContext<'_>) -> Option<String> {
    let (dir, file) = ctx.rel_path.rsplit_once('/')?;
    let header_file = file.replacen("Message_Header_Findings_", "Message_Header_", 1);
    if header_file == file {
        return None;
    }
    let root: String = ctx
        .conn
        .query_row(
            "SELECT root_path FROM collections WHERE collection_id = ?",
            [ctx.collection_id],
            |r| r.get(0),
        )
        .ok()?;
    let path = Path::new(&root).join(dir).join(header_file);
    let bytes = std::fs::read(path).ok()?;
    let text = crate::readers::text::decode(&bytes).text;
    let headers = csv_headers(&text);
    let set = HeaderSet::new(&headers);
    set.get("Message-ID").map(clean_message_id)
}

/// `Message_Header_<f>.csv` (one `email_artifacts` row) and `Message_Header_Findings_<f>.csv`
/// (the findings of the row with the same folder).
pub struct HawkHeaderParser;

impl ArtifactParser for HawkHeaderParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text.text.as_str();
        let subject = ctx.subject.unwrap_or_default().to_string();
        let is_findings = ctx
            .rel_path
            .rsplit_once('/')
            .is_some_and(|(_, f)| f.starts_with("Message_Header_Findings_"));
        if is_findings {
            let findings = parse_findings(text);
            let sibling = sibling_message_id(ctx);
            let key = sibling
                .clone()
                .unwrap_or_else(|| format!("hawk|{}", subject.to_lowercase()));
            let p1_p2 = findings_p1_p2(&findings);
            let mut c = CellRow::new(HAWK_FINDINGS_COLS);
            c.set("source", Cell::text(Some("hawk_message_header".into())))
                .set("message_id", Cell::text(sibling))
                .set("subject", Cell::text(Some(subject)))
                .set("p1_p2_match", Cell::bool(p1_p2))
                .set(
                    "findings",
                    Cell::json((!findings.is_empty()).then(|| Value::Array(findings.clone()))),
                );
            let mut rows = TableRows::new(&EMAIL_ARTIFACTS, HAWK_FINDINGS_COLS);
            rows.push_draft(RowDraft {
                ordinal: 0,
                span: Span {
                    start: 0,
                    end: text.len(),
                },
                record_key: key,
                cells: c.into_cells(),
                raw: Some(json!({"findings": findings})),
                sheet_row: None,
            });
            return load_tables(ctx, vec![rows]);
        }

        // The header file: one record built from all `Header, Value` rows.
        let headers = csv_headers(text);
        if headers.is_empty() {
            return Ok(());
        }
        let set = HeaderSet::new(&headers);
        let message_id = set.get("Message-ID").map(clean_message_id);
        let key = message_id.clone().unwrap_or_else(|| sha256_hex(ctx.raw));
        let from = set.get("From").map(decode_encoded_words);
        let (from_display, from_address) =
            from.as_deref().map(extract_address).unwrap_or((None, None));
        let return_path = set
            .get("Return-Path")
            .map(|v| clean_message_id(&decode_encoded_words(v)));
        let to_addresses: Vec<String> = set
            .get("To")
            .map(|v| {
                split_addresses(v)
                    .iter()
                    .filter_map(|e| extract_address(e).1)
                    .collect()
            })
            .unwrap_or_default();
        let sent = set.get("Date").and_then(parse_sent);
        let received: Vec<String> = set.all("Received").map(str::to_string).collect();
        let auth_results = set.get("Authentication-Results").map(str::to_string);
        let auth = auth_results.as_deref().unwrap_or_default();
        let (spf, dkim, dmarc) = (
            auth_result(auth, "spf"),
            auth_result(auth, "dkim"),
            auth_result(auth, "dmarc"),
        );
        let match_ = from_return_match(from_address.as_deref(), return_path.as_deref());

        let mut c = CellRow::new(HAWK_HEADER_COLS);
        c.set("source", Cell::text(Some("hawk_message_header".into())))
            .set("message_id", Cell::text(message_id))
            .set("subject", Cell::text(Some(subject)))
            .set("from_address", Cell::text(from_address))
            .set("from_display", Cell::text(from_display))
            .set("return_path", Cell::text(return_path))
            .set("to_addresses", Cell::list(to_addresses))
            .set("sent", Cell::time(sent))
            .set("received_hops", Cell::json(json_list(&received)))
            .set("auth_results", Cell::text(auth_results))
            .set("spf", Cell::text(spf))
            .set("dkim", Cell::text(dkim))
            .set("dmarc", Cell::text(dmarc))
            .set("auth_as", opt(set.get("X-MS-Exchange-Organization-AuthAs")))
            .set(
                "auth_mechanism",
                opt(set.get("X-MS-Exchange-Organization-AuthMechanism")),
            )
            .set("p1_p2_match", Cell::bool(match_))
            .set("headers", Cell::json(Some(headers_json(&headers))));

        let mut rows = TableRows::new(&EMAIL_ARTIFACTS, HAWK_HEADER_COLS);
        rows.push_draft(RowDraft {
            ordinal: 0,
            span: Span {
                start: 0,
                end: text.len(),
            },
            record_key: key,
            cells: c.into_cells(),
            raw: Some(json!({"headers": headers_json(&headers)})),
            sheet_row: None,
        });
        load_tables(ctx, vec![rows])
    }
}

/// The findings rows as `[{"rule", "value", "conclusion", "more_information"}]`.
fn parse_findings(text: &str) -> Vec<Value> {
    let table = read_csv(text);
    table
        .rows
        .iter()
        .filter_map(|r| {
            let rule = r.fields.first()?.trim();
            (!rule.is_empty()).then(|| {
                json!({
                    "rule": rule,
                    "value": r.fields.get(1).map(|v| v.as_str()).unwrap_or(""),
                    "conclusion": r.fields.get(2).map(|v| v.as_str()).unwrap_or(""),
                    "more_information": r.fields.get(3).map(|v| v.as_str()).unwrap_or(""),
                })
            })
        })
        .collect()
}

/// `p1_p2_match` from the findings file's `P1 P2 Match` conclusion.
fn findings_p1_p2(findings: &[Value]) -> Option<bool> {
    findings.iter().find_map(|f| {
        (f.get("rule")?.as_str()? == "P1 P2 Match").then(|| {
            f.get("conclusion")
                .and_then(Value::as_str)
                .is_some_and(|c| c == "P1 and P2 Header match")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_block_unfolds_and_decodes() {
        let text = "Received: from a.example by b.example with ESMTP;\r\n\tWed, 10 Sep 2026 10:00:00 +0000\r\nSubject: =?utf-8?B?SGVsbG8=?= =?utf-8?Q?_world?=\r\nFrom: \"Doe, John\" <john@contoso.example>\r\n\r\nbody\r\n";
        let (headers, end) = parse_header_block(text);
        assert!(end < text.len());
        let set = HeaderSet::new(&headers);
        assert_eq!(set.all("Received").count(), 1);
        assert_eq!(
            decode_encoded_words(set.get("Subject").unwrap()),
            "Hello world"
        );
        let (display, addr) = extract_address(set.get("From").unwrap());
        assert_eq!(display.as_deref(), Some("Doe, John"));
        assert_eq!(addr.as_deref(), Some("john@contoso.example"));
        let to = split_addresses("\"Doe, John\" <john@contoso.example>, jane@contoso.example");
        assert_eq!(to.len(), 2);
    }

    #[test]
    fn auth_results_and_attachments() {
        let auth = "spf=fail smtp.mailfrom=x.test; dkim=none; dmarc=fail action=quarantine";
        assert_eq!(auth_result(auth, "spf").as_deref(), Some("fail"));
        assert_eq!(auth_result(auth, "dkim").as_deref(), Some("none"));
        assert_eq!(auth_result(auth, "dmarc").as_deref(), Some("fail"));
        let mime = "Content-Type: multipart/mixed; boundary=\"x\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\n";
        assert_eq!(attachment_names(mime), vec!["report.pdf".to_string()]);
        let rfc2231 = "Content-Disposition: attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf\r\n";
        assert_eq!(attachment_names(rfc2231), vec!["résumé.pdf".to_string()]);
    }

    #[test]
    fn message_id_key_trims_brackets() {
        assert_eq!(clean_message_id(" <AbC@x.test> "), "AbC@x.test");
    }
}
