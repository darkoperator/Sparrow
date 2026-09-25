//! Timestamp parsing for collector output: ISO/RFC 3339, .NET `\/Date(ms)\/`, compact
//! folder stamps, and culture-formatted PowerShell `DateTime.ToString()` values.
//! Ambiguous day/month values are never guessed.

use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use regex::{Captures, Regex};
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DateOrder {
    MonthFirst,
    DayFirst,
}

impl DateOrder {
    /// How warnings name the order.
    pub fn describe(self) -> &'static str {
        match self {
            DateOrder::MonthFirst => "month-first (e.g. 9/24/2026)",
            DateOrder::DayFirst => "day-first (e.g. 24/9/2026)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Precision {
    Second,
    Minute,
}

impl Precision {
    pub fn as_str(self) -> &'static str {
        match self {
            Precision::Second => "second",
            Precision::Minute => "minute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedTime {
    pub utc: DateTime<Utc>,
    pub precision: Precision,
    /// True when the text carried no zone or offset and UTC was assumed.
    pub tz_assumed: bool,
}

impl ParsedTime {
    pub fn rfc3339(&self) -> String {
        self.utc.to_rfc3339_opts(SecondsFormat::AutoSi, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    #[error("empty timestamp")]
    Empty,
    #[error("ambiguous day/month order in '{0}'; pass --culture (e.g. en-US or en-GB)")]
    Ambiguous(String),
    #[error("unrecognized timestamp '{0}'")]
    Unrecognized(String),
    #[error("'{0}' contradicts the day/month order given by --culture")]
    Contradicts(String),
}

pub fn parse_culture(s: &str) -> Result<DateOrder, String> {
    match s.to_ascii_lowercase().as_str() {
        "mdy" | "en-us" | "en-ph" | "es-us" => Ok(DateOrder::MonthFirst),
        "dmy" | "en-gb" | "en-au" | "en-nz" | "en-ie" | "en-in" | "es-es" | "es-mx" | "fr-fr"
        | "de-de" | "it-it" | "nl-nl" | "pt-br" | "pt-pt" => Ok(DateOrder::DayFirst),
        other => Err(format!(
            "unsupported culture '{other}'; use mdy, dmy, en-US, en-GB, en-AU, de-DE, fr-FR, es-ES, es-MX, it-IT, nl-NL, pt-BR"
        )),
    }
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

fn re_msdate() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^\\?/Date\((-?\d+)(?:[+-]\d{4})?\)\\?/$")
}

fn re_compact() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^(\d{4})(\d{2})(\d{2})[-_]?(\d{2})(\d{2})(\d{2})$")
}

fn re_culture() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(
        &R,
        r"^(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})[ T]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,7}))?)?\s*([AaPp]\.?[Mm]\.?)?$",
    )
}

fn unrec(s: &str) -> TimeError {
    TimeError::Unrecognized(s.to_string())
}

fn num<T: std::str::FromStr>(c: &Captures, i: usize, s: &str) -> Result<T, TimeError> {
    c[i].parse().map_err(|_| unrec(s))
}

pub fn parse_timestamp(input: &str, order: Option<DateOrder>) -> Result<ParsedTime, TimeError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(TimeError::Empty);
    }
    if let Some(c) = re_msdate().captures(s) {
        let ms: i64 = num(&c, 1, s)?;
        let utc = Utc
            .timestamp_millis_opt(ms)
            .single()
            .ok_or_else(|| unrec(s))?;
        return Ok(ParsedTime {
            utc,
            precision: Precision::Second,
            tz_assumed: false,
        });
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(ParsedTime {
            utc: dt.with_timezone(&Utc),
            precision: Precision::Second,
            tz_assumed: false,
        });
    }
    let mut iso = s.trim_end_matches(['Z', 'z']).replacen(' ', "T", 1);
    // Year-first culture dates (ja-JP, zh-CN `G`: yyyy/MM/dd HH:mm:ss) read like ISO.
    if s.get(..5)
        .is_some_and(|p| p.ends_with('/') && p[..4].bytes().all(|b| b.is_ascii_digit()))
    {
        iso = iso.replace('/', "-");
    }
    for (fmt, precision) in [
        ("%Y-%m-%dT%H:%M:%S%.f", Precision::Second),
        ("%Y-%m-%dT%H:%M:%S", Precision::Second),
        ("%Y-%m-%dT%H:%M", Precision::Minute),
    ] {
        if let Ok(n) = NaiveDateTime::parse_from_str(&iso, fmt) {
            return Ok(ParsedTime {
                utc: Utc.from_utc_datetime(&n),
                precision,
                tz_assumed: !s.ends_with(['Z', 'z']),
            });
        }
    }
    if let Some(c) = re_compact().captures(s) {
        let date = NaiveDate::from_ymd_opt(num(&c, 1, s)?, num(&c, 2, s)?, num(&c, 3, s)?)
            .ok_or_else(|| unrec(s))?;
        let n = date
            .and_hms_opt(num(&c, 4, s)?, num(&c, 5, s)?, num(&c, 6, s)?)
            .ok_or_else(|| unrec(s))?;
        return Ok(ParsedTime {
            utc: Utc.from_utc_datetime(&n),
            precision: Precision::Second,
            tz_assumed: true,
        });
    }
    if let Some(c) = re_culture().captures(s) {
        return parse_culture_match(&c, s, order);
    }
    Err(unrec(s))
}

fn parse_culture_match(
    c: &Captures,
    s: &str,
    order: Option<DateOrder>,
) -> Result<ParsedTime, TimeError> {
    let a: u32 = num(c, 1, s)?;
    let b: u32 = num(c, 2, s)?;
    let year: i32 = num(c, 3, s)?;
    let (month, day) = match (a > 12, b > 12, order) {
        (true, true, _) => return Err(unrec(s)),
        (true, false, Some(DateOrder::MonthFirst)) | (false, true, Some(DateOrder::DayFirst)) => {
            return Err(TimeError::Contradicts(s.to_string()));
        }
        (true, false, _) => (b, a),
        (false, true, _) => (a, b),
        (false, false, Some(DateOrder::MonthFirst)) => (a, b),
        (false, false, Some(DateOrder::DayFirst)) => (b, a),
        (false, false, None) if a == b => (a, b),
        (false, false, None) => return Err(TimeError::Ambiguous(s.to_string())),
    };
    let mut hour: u32 = num(c, 4, s)?;
    let minute: u32 = num(c, 5, s)?;
    let second: Option<u32> = match c.get(6) {
        Some(m) => Some(m.as_str().parse().map_err(|_| unrec(s))?),
        None => None,
    };
    let nanos: u32 = match c.get(7) {
        Some(m) => {
            let digits = m.as_str();
            let v: u32 = digits.parse().map_err(|_| unrec(s))?;
            v * 10u32.pow(9 - digits.len() as u32)
        }
        None => 0,
    };
    if let Some(ampm) = c.get(8) {
        let pm = ampm.as_str().to_ascii_lowercase().starts_with('p');
        if hour == 0 || hour > 12 {
            return Err(unrec(s));
        }
        if pm && hour < 12 {
            hour += 12;
        }
        if !pm && hour == 12 {
            hour = 0;
        }
    }
    let date = NaiveDate::from_ymd_opt(year, month, day).ok_or_else(|| unrec(s))?;
    let n = date
        .and_hms_nano_opt(hour, minute, second.unwrap_or(0), nanos)
        .ok_or_else(|| unrec(s))?;
    let precision = if second.is_some() {
        Precision::Second
    } else {
        Precision::Minute
    };
    Ok(ParsedTime {
        utc: Utc.from_utc_datetime(&n),
        precision,
        tz_assumed: true,
    })
}

/// True when `s` carries no zone or offset (UTC is assumed), whatever its day/month order;
/// also true for text that is not a timestamp.
pub fn zone_assumed(s: &str) -> bool {
    [None, Some(DateOrder::MonthFirst), Some(DateOrder::DayFirst)]
        .into_iter()
        .find_map(|o| parse_timestamp(s, o).ok())
        .is_none_or(|t| t.tz_assumed)
}

/// Collects evidence about day/month order across a file's culture-formatted values.
#[derive(Debug, Clone, Default)]
pub struct DateOrderDetector {
    month_first: bool,
    day_first: bool,
    /// Saw a value whose day and month are both <= 12 and differ (e.g. 6/12).
    ambiguous: bool,
}

impl DateOrderDetector {
    pub fn observe(&mut self, s: &str) {
        if let Some(c) = re_culture().captures(s.trim()) {
            let a: u32 = c[1].parse().unwrap_or(0);
            let b: u32 = c[2].parse().unwrap_or(0);
            if a > 12 {
                self.day_first = true;
            }
            if b > 12 {
                self.month_first = true;
            }
            if a <= 12 && b <= 12 && a != b {
                self.ambiguous = true;
            }
        }
    }

    /// The order the observed values prove on their own (a month or day above 12); `None`
    /// when they prove none or both.
    pub fn evidence(&self) -> Option<DateOrder> {
        match (self.month_first, self.day_first) {
            (true, false) => Some(DateOrder::MonthFirst),
            (false, true) => Some(DateOrder::DayFirst),
            _ => None,
        }
    }

    /// Culture dates were seen, but none of them shows the order.
    pub fn only_ambiguous(&self) -> bool {
        self.ambiguous && !self.month_first && !self.day_first
    }

    pub fn resolve(&self, override_order: Option<DateOrder>) -> Result<Option<DateOrder>, String> {
        if let Some(o) = override_order {
            return match (o, self.month_first, self.day_first) {
                (_, true, true) => {
                    Err("conflicting day/month orders in the same file; pass --culture".into())
                }
                (DateOrder::MonthFirst, false, true) => Err(
                    "file shows day-first dates (e.g. 24/9) but --culture says month-first; \
                     remove --culture or ingest this collection separately"
                        .into(),
                ),
                (DateOrder::DayFirst, true, false) => Err(
                    "file shows month-first dates (e.g. 9/24) but --culture says day-first; \
                     remove --culture or ingest this collection separately"
                        .into(),
                ),
                _ => Ok(Some(o)),
            };
        }
        match (self.month_first, self.day_first) {
            (true, true) => {
                Err("conflicting day/month orders in the same file; pass --culture".into())
            }
            (true, false) => Ok(Some(DateOrder::MonthFirst)),
            (false, true) => Ok(Some(DateOrder::DayFirst)),
            (false, false) if self.ambiguous => {
                Err("ambiguous day/month order; pass --culture (e.g. en-US or en-GB)".into())
            }
            (false, false) => Ok(None),
        }
    }
}
