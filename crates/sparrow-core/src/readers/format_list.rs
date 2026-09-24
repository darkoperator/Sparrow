//! Best-effort parser for PowerShell `Format-List` text output (Hawk TXT artifacts).

use crate::readers::text::Span;
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct FlBlock {
    pub span: Span,
    pub fields: Vec<(String, String)>,
}

impl FlBlock {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn re_field() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^([A-Za-z_][A-Za-z0-9_.\- ]*?)\s*: ?(.*)$").expect("valid regex"))
}

pub fn parse_format_list(text: &str) -> Vec<FlBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<FlBlock> = None;
    let mut offset = 0usize;
    for raw_line in text.split_inclusive('\n') {
        let line_start = offset;
        offset += raw_line.len();
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let line_end = line_start + line.len();
        if line.trim().is_empty() {
            if let Some(b) = current.take() {
                blocks.push(b);
            }
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            if let Some(c) = re_field().captures(line) {
                let block = current.get_or_insert_with(|| FlBlock {
                    span: Span {
                        start: line_start,
                        end: line_end,
                    },
                    fields: Vec::new(),
                });
                block
                    .fields
                    .push((c[1].trim().to_string(), c[2].trim().to_string()));
                block.span.end = line_end;
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            if let Some(last) = block.fields.last_mut() {
                if !last.1.is_empty() {
                    last.1.push(' ');
                }
                last.1.push_str(line.trim());
                block.span.end = line_end;
            }
        }
    }
    if let Some(b) = current {
        blocks.push(b);
    }
    blocks
}
