//! Rendering values exactly as PowerShell 5.1 / 7 would: host-culture dates, `Export-Csv`,
//! `ConvertTo-Json` (Newtonsoft on 7, JavaScriptSerializer-style on 5.1), `Format-List` and the
//! file encodings collectors write with. Every writer in this crate goes through this module so
//! a byte in a generated file always has one place that decided its shape.

use crate::options::{Culture, PsEdition};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Timelike, Utc};

/// A PowerShell host: the edition and culture that wrote a file, the UTC offset used for
/// `DtKind::Local` values (there is no real local clock; the scenario supplies the offset), and
/// the line ending to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub edition: PsEdition,
    pub culture: Culture,
    pub utc_offset_minutes: i32,
    pub newline: &'static str,
}

impl Host {
    /// A Windows host: CRLF line endings.
    pub fn new(edition: PsEdition, culture: Culture, utc_offset_minutes: i32) -> Host {
        Host {
            edition,
            culture,
            utc_offset_minutes,
            newline: "\r\n",
        }
    }

    /// PowerShell 7 on macOS/Linux: LF line endings.
    pub fn unix(mut self) -> Host {
        self.newline = "\n";
        self
    }

    /// The wall-clock naive time a value of `kind` renders as on this host.
    fn wall(&self, t: DateTime<Utc>, kind: DtKind) -> NaiveDateTime {
        match kind {
            DtKind::Local => (t + Duration::minutes(self.utc_offset_minutes.into())).naive_utc(),
            DtKind::Utc | DtKind::Unspecified => t.naive_utc(),
        }
    }

    /// The host culture's long `G`-equivalent rendering (`Export-Csv` / `Format-List`).
    pub fn culture_date(&self, t: DateTime<Utc>, kind: DtKind) -> String {
        let w = self.wall(t, kind);
        match self.culture {
            Culture::EnUs => {
                let (pm, h12) = w.hour12();
                format!(
                    "{}/{}/{} {}:{:02}:{:02} {}",
                    w.month(),
                    w.day(),
                    w.year(),
                    h12,
                    w.minute(),
                    w.second(),
                    if pm { "PM" } else { "AM" }
                )
            }
            Culture::EnGb => w.format("%d/%m/%Y %H:%M:%S").to_string(),
            Culture::DeDe => w.format("%d.%m.%Y %H:%M:%S").to_string(),
            Culture::JaJp => format!(
                "{} {}:{:02}:{:02}",
                w.format("%Y/%m/%d"),
                w.hour(),
                w.minute(),
                w.second()
            ),
        }
    }

    /// The short `g`-equivalent rendering (seconds dropped; Hawk's `Converted_Authentication_Logs`).
    pub fn culture_date_short(&self, t: DateTime<Utc>, kind: DtKind) -> String {
        let w = self.wall(t, kind);
        match self.culture {
            Culture::EnUs => {
                let (pm, h12) = w.hour12();
                format!(
                    "{}/{}/{} {}:{:02} {}",
                    w.month(),
                    w.day(),
                    w.year(),
                    h12,
                    w.minute(),
                    if pm { "PM" } else { "AM" }
                )
            }
            Culture::EnGb => w.format("%d/%m/%Y %H:%M").to_string(),
            Culture::DeDe => w.format("%d.%m.%Y %H:%M").to_string(),
            Culture::JaJp => format!("{} {}:{:02}", w.format("%Y/%m/%d"), w.hour(), w.minute()),
        }
    }

    /// `Export-Csv` / `Format-List` rendering of a date, by its origin and this host's edition.
    pub fn csv_date(&self, d: &PsDate) -> String {
        match &d.origin {
            Origin::DotNet(kind) => self.culture_date(d.utc, *kind),
            Origin::IsoText(text) => {
                if self.edition == PsEdition::Ps7 {
                    self.culture_date(d.utc, DtKind::Utc)
                } else {
                    text.clone()
                }
            }
        }
    }

    /// `ConvertTo-Json` rendering of a date, by its origin and this host's edition.
    pub fn json_date(&self, d: &PsDate) -> String {
        match &d.origin {
            Origin::DotNet(kind) => match self.edition {
                PsEdition::Ps51 => format!("/Date({})/", d.utc.timestamp_millis()),
                PsEdition::Ps7 => newtonsoft_iso(self, d.utc, *kind),
            },
            Origin::IsoText(text) => match self.edition {
                PsEdition::Ps51 => text.clone(),
                PsEdition::Ps7 => newtonsoft_iso(self, d.utc, DtKind::Utc),
            },
        }
    }
}

/// The .NET `DateTimeKind` a typed date carries (or the kind a REST timestamp is re-rendered
/// as).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtKind {
    Utc,
    Local,
    Unspecified,
}

/// Where a date value came from: a typed .NET `DateTime` (Exchange cmdlets, Graph SDK models)
/// or ISO text from REST JSON, kept verbatim until an edition decides to re-render it.
#[derive(Debug, Clone, PartialEq)]
pub enum Origin {
    DotNet(DtKind),
    /// The REST text exactly as the collector received it, e.g. `2026-09-25T00:53:52.035213Z`.
    IsoText(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PsDate {
    pub utc: DateTime<Utc>,
    pub origin: Origin,
}

impl PsDate {
    pub fn dotnet(utc: DateTime<Utc>, kind: DtKind) -> PsDate {
        PsDate {
            utc,
            origin: Origin::DotNet(kind),
        }
    }

    /// The REST text with exactly `frac_digits` fractional digits and a trailing `Z`.
    pub fn iso(utc: DateTime<Utc>, frac_digits: u8) -> PsDate {
        PsDate {
            utc,
            origin: Origin::IsoText(iso_rest_text(utc, frac_digits)),
        }
    }
}

fn iso_rest_text(utc: DateTime<Utc>, frac_digits: u8) -> String {
    let base = utc.format("%Y-%m-%dT%H:%M:%S").to_string();
    if frac_digits == 0 {
        return format!("{base}Z");
    }
    let digits = format!("{:09}", utc.timestamp_subsec_nanos());
    let n = (frac_digits as usize).min(digits.len());
    format!("{base}.{}Z", &digits[..n])
}

/// Newtonsoft-style ISO 8601: `yyyy-MM-ddTHH:mm:ss[.FFFFFFF]` then `Z` / `±hh:mm` / nothing by
/// `kind`, the fractional part trimmed of trailing zeros (omitted entirely when all zero).
fn newtonsoft_iso(host: &Host, utc: DateTime<Utc>, kind: DtKind) -> String {
    let w = host.wall(utc, kind);
    let base = w.format("%Y-%m-%dT%H:%M:%S").to_string();
    let frac = frac7(w.nanosecond());
    let suffix = match kind {
        DtKind::Utc => "Z".to_string(),
        DtKind::Local => offset_suffix(host.utc_offset_minutes),
        DtKind::Unspecified => String::new(),
    };
    format!("{base}{frac}{suffix}")
}

/// Up to 7 fractional-second digits (.NET's 100ns ticks), trailing zeros trimmed; empty
/// (dot omitted) when all zero.
fn frac7(nanos: u32) -> String {
    let digits = format!("{:09}", nanos);
    let seven = &digits[..7];
    let trimmed = seven.trim_end_matches('0');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(".{trimmed}")
    }
}

fn offset_suffix(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let abs = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", abs / 60, abs % 60)
}

/// Culture dates seen so far, so the manifest can predict whether a file's day/month order is
/// resolvable. `decisive` counts renderings whose day is unambiguously > 12 in a day/month-order
/// culture; year-first (ja-JP) and ISO text are never counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DateEvidence {
    pub culture_dates: u32,
    pub decisive: u32,
}

impl DateEvidence {
    pub fn merge(&mut self, other: &DateEvidence) {
        self.culture_dates += other.culture_dates;
        self.decisive += other.decisive;
    }

    /// True when there is culture-date evidence and none of it is decisive: the file's
    /// day/month order cannot be resolved from its dates alone.
    pub fn all_ambiguous(&self) -> bool {
        self.culture_dates > 0 && self.decisive == 0
    }
}

/// Records one culture-rendered date (a day/month-order culture only; ja-JP is year-first and
/// records nothing).
fn note_evidence(host: &Host, ev: &mut DateEvidence, d: &PsDate) {
    if host.culture == Culture::JaJp {
        return;
    }
    let day = match &d.origin {
        Origin::DotNet(kind) => host.wall(d.utc, *kind).day(),
        Origin::IsoText(_) => {
            if host.edition != PsEdition::Ps7 {
                return;
            }
            host.wall(d.utc, DtKind::Utc).day()
        }
    };
    ev.culture_dates += 1;
    if day > 12 {
        ev.decisive += 1;
    }
}

/// A cell/JSON value: one property of a `PSObject`.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Str(String),
    Bool(bool),
    Int(i64),
    Float(f64),
    Date(PsDate),
    /// Renders exactly like `Date` but is not counted in `DateEvidence`: for date columns the
    /// artifact's Sparrow parser does not read as times (e.g. the outer UAL `CreationDate`,
    /// message-trace `StartDate`/`EndDate`).
    DateText(PsDate),
    /// Nested JSON (arrays/objects) as PowerShell would carry them.
    Raw(serde_json::Value),
    /// Text PowerShell prints for a nested value in CSV, e.g. `System.Object[]`, `@{a=1; b=2}`.
    Placeholder(String),
}

/// The ordered properties of one `PSObject`.
pub type Row = Vec<(String, Val)>;

/// Rendered text plus, per item (a CSV data row, a JSON object, a Format-List block), its
/// 1-based first and last physical line in `text` (what `record_sources.line_start/line_end`
/// will say).
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub text: String,
    pub spans: Vec<(u32, u32)>,
}

fn format_float(host: &Host, f: f64) -> String {
    let s = f.to_string();
    if host.culture == Culture::DeDe {
        s.replace('.', ",")
    } else {
        s
    }
}

/// `True` / `False`, PowerShell's rendering of a boolean everywhere it appears as text.
fn ps_bool(b: bool) -> String {
    if b {
        "True".to_string()
    } else {
        "False".to_string()
    }
}

fn raw_scalar_to_ps_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => ps_bool(*b),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => raw_to_csv_string(v),
    }
}

/// PowerShell's `ToString()` of a nested value in a CSV cell.
fn raw_to_csv_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Array(_) => "System.Object[]".to_string(),
        serde_json::Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, val)| format!("{k}={}", raw_scalar_to_ps_string(val)))
                .collect();
            format!("@{{{}}}", inner.join("; "))
        }
        other => raw_scalar_to_ps_string(other),
    }
}

/// How Format-List renders a nested value: arrays of scalars as `{a, b, c}`.
fn raw_to_fl_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(raw_scalar_to_ps_string).collect();
            format!("{{{}}}", inner.join(", "))
        }
        other => raw_scalar_to_ps_string(other),
    }
}

/// Scalar rendering shared by `Export-Csv` and `Format-List`: everything but how a nested
/// `Val::Raw` value prints (`raw`) is identical between the two.
fn scalar_text(
    host: &Host,
    v: &Val,
    ev: &mut DateEvidence,
    raw: fn(&serde_json::Value) -> String,
) -> String {
    match v {
        Val::Null => String::new(),
        Val::Str(s) => s.clone(),
        Val::Bool(b) => ps_bool(*b),
        Val::Int(i) => i.to_string(),
        Val::Float(f) => format_float(host, *f),
        Val::Date(d) => {
            note_evidence(host, ev, d);
            host.csv_date(d)
        }
        Val::DateText(d) => host.csv_date(d),
        Val::Raw(v) => raw(v),
        Val::Placeholder(s) => s.clone(),
    }
}

/// Cell text for `Export-Csv` (never called for `Val::Null`; the caller handles nulls itself).
fn csv_text(host: &Host, v: &Val, ev: &mut DateEvidence) -> String {
    scalar_text(host, v, ev, raw_to_csv_string)
}

fn quote_csv(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn csv_null_field(host: &Host) -> String {
    match host.edition {
        PsEdition::Ps7 => String::new(),
        PsEdition::Ps51 => "\"\"".to_string(),
    }
}

fn csv_field(host: &Host, v: &Val, ev: &mut DateEvidence) -> String {
    match v {
        Val::Null => csv_null_field(host),
        other => quote_csv(&csv_text(host, other, ev)),
    }
}

fn render_csv_rows(
    host: &Host,
    header: &[String],
    rows: &[Row],
    start_line: u32,
    ev: &mut DateEvidence,
) -> Rendered {
    let mut text = String::new();
    let mut spans = Vec::with_capacity(rows.len());
    let mut line = start_line;
    for row in rows {
        let row_line = header
            .iter()
            .map(|h| match row.iter().find(|(k, _)| k == h) {
                Some((_, v)) => csv_field(host, v, ev),
                None => csv_null_field(host),
            })
            .collect::<Vec<_>>()
            .join(",");
        let extra_lines = row_line.matches('\n').count() as u32;
        let end = line + extra_lines;
        spans.push((line, end));
        text.push_str(&row_line);
        text.push_str(host.newline);
        line = end + 1;
    }
    Rendered { text, spans }
}

/// `Export-Csv`: header from the first row's property names; later rows mapped by name
/// (missing -> null, extra dropped); empty `rows` -> empty text, no spans.
pub fn export_csv(host: &Host, rows: &[Row], ev: &mut DateEvidence) -> Rendered {
    if rows.is_empty() {
        return Rendered {
            text: String::new(),
            spans: Vec::new(),
        };
    }
    let header: Vec<String> = rows[0].iter().map(|(k, _)| k.clone()).collect();
    let header_line = header
        .iter()
        .map(|h| quote_csv(h))
        .collect::<Vec<_>>()
        .join(",");
    let mut text = header_line;
    text.push_str(host.newline);
    let body = render_csv_rows(host, &header, rows, 2, ev);
    text.push_str(&body.text);
    Rendered {
        text,
        spans: body.spans,
    }
}

/// `Export-Csv -Append`: rows only (no header line); spans start at line 1 of the appended text.
pub fn export_csv_append(
    host: &Host,
    header: &[String],
    rows: &[Row],
    ev: &mut DateEvidence,
) -> Rendered {
    render_csv_rows(host, header, rows, 1, ev)
}

fn indent(host: &Host, level: usize) -> String {
    let unit = match host.edition {
        PsEdition::Ps7 => 2,
        PsEdition::Ps51 => 4,
    };
    " ".repeat(unit * level)
}

fn kv_colon(host: &Host, compress: bool) -> &'static str {
    if compress {
        return ":";
    }
    match host.edition {
        PsEdition::Ps7 => ": ",
        PsEdition::Ps51 => ":  ",
    }
}

fn write_json_string(host: &Host, s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' if host.edition == PsEdition::Ps51 => out.push_str("\\u003c"),
            '>' if host.edition == PsEdition::Ps51 => out.push_str("\\u003e"),
            '&' if host.edition == PsEdition::Ps51 => out.push_str("\\u0026"),
            '\'' if host.edition == PsEdition::Ps51 => out.push_str("\\u0027"),
            '/' if host.edition == PsEdition::Ps51 => out.push_str("\\/"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_empty_container(
    host: &Host,
    compress: bool,
    level: usize,
    open: char,
    close: char,
    out: &mut String,
) {
    if compress || host.edition == PsEdition::Ps7 {
        out.push(open);
        out.push(close);
        return;
    }
    out.push(open);
    out.push_str(host.newline);
    out.push_str(host.newline);
    out.push_str(&indent(host, level));
    out.push(close);
}

/// A `serde_json::Value` written the way `ConvertTo-Json` would: 7 -> Newtonsoft style
/// (2-space indent, `"k": v`); 5.1 -> 4-space indent, `"k":  v`, `<>&'` and `/` escaped.
/// `compress` drops all whitespace on both editions (5.1 keeps its escapes).
fn write_json_value(
    host: &Host,
    v: &serde_json::Value,
    compress: bool,
    level: usize,
    out: &mut String,
) {
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
        serde_json::Value::String(s) => write_json_string(host, s, out),
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                write_empty_container(host, compress, level, '[', ']', out);
                return;
            }
            out.push('[');
            if !compress {
                out.push_str(host.newline);
            }
            let n = items.len();
            for (i, item) in items.iter().enumerate() {
                if !compress {
                    out.push_str(&indent(host, level + 1));
                }
                write_json_value(host, item, compress, level + 1, out);
                if i + 1 < n {
                    out.push(',');
                }
                if !compress {
                    out.push_str(host.newline);
                }
            }
            if !compress {
                out.push_str(&indent(host, level));
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            if map.is_empty() {
                write_empty_container(host, compress, level, '{', '}', out);
                return;
            }
            out.push('{');
            if !compress {
                out.push_str(host.newline);
            }
            let n = map.len();
            for (i, (k, val)) in map.iter().enumerate() {
                if !compress {
                    out.push_str(&indent(host, level + 1));
                }
                write_json_string(host, k, out);
                out.push_str(kv_colon(host, compress));
                write_json_value(host, val, compress, level + 1, out);
                if i + 1 < n {
                    out.push(',');
                }
                if !compress {
                    out.push_str(host.newline);
                }
            }
            if !compress {
                out.push_str(&indent(host, level));
            }
            out.push('}');
        }
    }
}

/// `json_text` written by hand (not post-processed `serde_json` pretty output): see module docs.
pub fn json_text(host: &Host, v: &serde_json::Value, compress: bool) -> String {
    let mut out = String::new();
    write_json_value(host, v, compress, 0, &mut out);
    out
}

/// A `Val` as the JSON it would be inside `ConvertTo-Json`'s input object.
pub fn json_value(host: &Host, v: &Val) -> serde_json::Value {
    match v {
        Val::Null => serde_json::Value::Null,
        Val::Str(s) => serde_json::Value::String(s.clone()),
        Val::Bool(b) => serde_json::Value::Bool(*b),
        Val::Int(i) => serde_json::Value::Number((*i).into()),
        Val::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Val::Date(d) => serde_json::Value::String(host.json_date(d)),
        Val::DateText(d) => serde_json::Value::String(host.json_date(d)),
        Val::Raw(v) => v.clone(),
        Val::Placeholder(s) => serde_json::Value::String(s.clone()),
    }
}

fn row_to_object(host: &Host, row: &Row) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(row.len());
    for (k, v) in row {
        map.insert(k.clone(), json_value(host, v));
    }
    serde_json::Value::Object(map)
}

fn count_lines(text: &str) -> u32 {
    1 + text.matches('\n').count() as u32
}

/// `ConvertTo-Json`: no items -> `""`; one -> a bare object; several -> an array. No trailing
/// newline. `spans` gives each object's physical line range.
pub fn convert_to_json(host: &Host, items: &[Row], compress: bool) -> Rendered {
    if items.is_empty() {
        return Rendered {
            text: String::new(),
            spans: Vec::new(),
        };
    }
    if items.len() == 1 {
        let text = json_text(host, &row_to_object(host, &items[0]), compress);
        let lines = count_lines(&text);
        return Rendered {
            text,
            spans: vec![(1, lines)],
        };
    }
    let mut text = String::from("[");
    let mut line = 1u32;
    if !compress {
        text.push_str(host.newline);
        line += 1;
    }
    let mut spans = Vec::with_capacity(items.len());
    let n = items.len();
    for (i, row) in items.iter().enumerate() {
        let mut obj_text = String::new();
        if !compress {
            obj_text.push_str(&indent(host, 1));
        }
        write_json_value(host, &row_to_object(host, row), compress, 1, &mut obj_text);
        let obj_lines = count_lines(&obj_text);
        let start = line;
        let end = start + obj_lines - 1;
        spans.push((start, end));
        text.push_str(&obj_text);
        if i + 1 < n {
            text.push(',');
        }
        if !compress {
            text.push_str(host.newline);
        }
        line = end + 1;
    }
    if !compress {
        text.push_str(&indent(host, 0));
    }
    text.push(']');
    Rendered { text, spans }
}

/// Value text for `Format-List` (nulls render empty; nested arrays render as `{a, b, c}`).
fn fl_text(host: &Host, v: &Val, ev: &mut DateEvidence) -> String {
    scalar_text(host, v, ev, raw_to_fl_string)
}

/// `Format-List`: `Name : Value` with names padded to the longest name in the block; blocks
/// separated by one blank line; the output starts with two blank lines and ends with two
/// (`Out-File` of `Format-List`); on 5.1 long values wrap at 120 columns onto continuation
/// lines indented to the value column.
pub fn format_list(host: &Host, blocks: &[Row], ev: &mut DateEvidence) -> Rendered {
    let mut text = String::new();
    text.push_str(host.newline);
    text.push_str(host.newline);
    let mut spans = Vec::with_capacity(blocks.len());
    let mut line = 3u32;
    for block in blocks {
        let pad = block
            .iter()
            .map(|(k, _)| k.chars().count())
            .max()
            .unwrap_or(0);
        let mut block_lines: Vec<String> = Vec::new();
        for (k, v) in block {
            let value = fl_text(host, v, ev);
            let prefix = format!("{k:<pad$} : ");
            if host.edition == PsEdition::Ps51 {
                let limit = 120usize.saturating_sub(pad + 3);
                if limit > 0 && value.chars().count() > limit {
                    let chars: Vec<char> = value.chars().collect();
                    let mut idx = 0;
                    let mut first = true;
                    while idx < chars.len() {
                        let end = (idx + limit).min(chars.len());
                        let chunk: String = chars[idx..end].iter().collect();
                        if first {
                            block_lines.push(format!("{prefix}{chunk}"));
                            first = false;
                        } else {
                            block_lines.push(format!("{}{}", " ".repeat(pad + 3), chunk));
                        }
                        idx = end;
                    }
                    continue;
                }
            }
            block_lines.push(format!("{prefix}{value}"));
        }
        let start = line;
        let end = line + block_lines.len() as u32 - 1;
        spans.push((start, end));
        for l in &block_lines {
            text.push_str(l);
            text.push_str(host.newline);
        }
        text.push_str(host.newline);
        line = end + 2;
    }
    text.push_str(host.newline);
    text.push_str(host.newline);
    Rendered { text, spans }
}

/// A file encoding a collector writes with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf8Bom,
    Utf16LeBom,
    /// PowerShell 7 on macOS/Linux and the analyst portal's `MTSummary` export: UTF-16LE with
    /// no byte-order mark.
    Utf16LeNoBom,
    Ascii,
    Cp1252,
}

impl Encoding {
    pub fn encode(&self, text: &str) -> Vec<u8> {
        match self {
            Encoding::Utf8 => text.as_bytes().to_vec(),
            Encoding::Utf8Bom => {
                let mut v = vec![0xEF, 0xBB, 0xBF];
                v.extend_from_slice(text.as_bytes());
                v
            }
            Encoding::Utf16LeBom => {
                let mut v = vec![0xFF, 0xFE];
                for u in text.encode_utf16() {
                    v.extend_from_slice(&u.to_le_bytes());
                }
                v
            }
            Encoding::Utf16LeNoBom => {
                let mut v = Vec::with_capacity(text.len() * 2);
                for u in text.encode_utf16() {
                    v.extend_from_slice(&u.to_le_bytes());
                }
                v
            }
            Encoding::Ascii => text
                .chars()
                .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
                .collect(),
            Encoding::Cp1252 => text
                .chars()
                .map(|c| {
                    let u = c as u32;
                    if u < 0x80 || (0xA0..=0xFF).contains(&u) {
                        u as u8
                    } else {
                        b'?'
                    }
                })
                .collect(),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Encoding::Utf8 => "utf-8",
            Encoding::Utf8Bom => "utf-8-bom",
            Encoding::Utf16LeBom => "utf-16le-bom",
            Encoding::Utf16LeNoBom => "utf-16le",
            Encoding::Ascii => "ascii",
            Encoding::Cp1252 => "windows-1252",
        }
    }

    /// `-Encoding UTF8`: 5.1 writes a BOM, 7 does not.
    pub fn export_csv_utf8(edition: PsEdition) -> Encoding {
        match edition {
            PsEdition::Ps51 => Encoding::Utf8Bom,
            PsEdition::Ps7 => Encoding::Utf8,
        }
    }

    /// `Out-File`'s default encoding.
    pub fn out_file_default(edition: PsEdition) -> Encoding {
        match edition {
            PsEdition::Ps51 => Encoding::Utf16LeBom,
            PsEdition::Ps7 => Encoding::Utf8,
        }
    }

    /// `Export-Csv`'s default encoding (no `-Encoding` given).
    pub fn export_csv_default(edition: PsEdition) -> Encoding {
        match edition {
            PsEdition::Ps51 => Encoding::Ascii,
            PsEdition::Ps7 => Encoding::Utf8,
        }
    }
}
