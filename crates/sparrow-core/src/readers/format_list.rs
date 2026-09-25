//! Best-effort parser for PowerShell `Format-List` text output (Hawk TXT artifacts).

use crate::readers::text::Span;
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct FlBlock {
    pub span: Span,
    pub fields: Vec<(String, String)>,
    /// Source span of each field (its line plus continuation lines), parallel to `fields`.
    pub field_spans: Vec<Span>,
}

impl FlBlock {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Fields as a JSON object of strings; the first of repeated names wins.
    pub fn to_map(&self) -> Map<String, Value> {
        let mut map = Map::new();
        for (k, v) in &self.fields {
            if !map.contains_key(k) {
                map.insert(k.clone(), Value::String(v.clone()));
            }
        }
        map
    }
}

fn re_field() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^([A-Za-z_][A-Za-z0-9_.\- ]*?)\s*: ?(.*)$").expect("valid regex"))
}

/// Blocks separated by blank lines (`Format-List` of several objects).
pub fn parse_format_list(text: &str) -> Vec<FlBlock> {
    parse(text, false)
}

/// The whole file as one object (`Format-List` of a single object): blank lines inside or
/// between multi-line values do not split it. `None` when the text has no field.
pub fn parse_format_list_object(text: &str) -> Option<FlBlock> {
    parse(text, true).into_iter().next()
}

fn parse(text: &str, single: bool) -> Vec<FlBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<FlBlock> = None;
    let mut offset = 0usize;
    for raw_line in text.split_inclusive('\n') {
        let line_start = offset;
        offset += raw_line.len();
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let line_end = line_start + line.len();
        if line.trim().is_empty() {
            if !single {
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
            }
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            if let Some(c) = re_field().captures(line) {
                let span = Span {
                    start: line_start,
                    end: line_end,
                };
                let block = current.get_or_insert_with(|| FlBlock {
                    span,
                    fields: Vec::new(),
                    field_spans: Vec::new(),
                });
                block
                    .fields
                    .push((c[1].trim().to_string(), c[2].trim().to_string()));
                block.field_spans.push(span);
                block.span.end = line_end;
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            if let (Some(last), Some(last_span)) =
                (block.fields.last_mut(), block.field_spans.last_mut())
            {
                if !last.1.is_empty() {
                    last.1.push(' ');
                }
                last.1.push_str(line.trim());
                last_span.end = line_end;
                block.span.end = line_end;
            }
        }
    }
    if let Some(b) = current {
        blocks.push(b);
    }
    blocks
}
