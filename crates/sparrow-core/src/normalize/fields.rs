//! Typed, case-insensitive access to collector records for the state-table parsers, and the
//! cells they stage for the loader.

use crate::normalize::ual_shape::get_ci;
use crate::readers::time::{DateOrder, parse_timestamp};
use serde_json::{Map, Value};

/// Text PowerShell writes for values Export-Csv / Format-List could not render:
/// `System.Object[]`, `@{...}`, and bare .NET type names (`Microsoft.Graph....Model`).
pub fn is_placeholder(s: &str) -> bool {
    let s = s.trim();
    s == "System.Object[]"
        || (s.starts_with("@{") && s.ends_with('}'))
        || ((s.starts_with("System.") || s.starts_with("Microsoft."))
            && !s.contains(char::is_whitespace)
            && s.matches('.').count() >= 2)
}

/// One record (JSON object, CSV row or Format-List block). `lossy` records (CSV rows,
/// Format-List text) have PowerShell placeholders filtered out.
#[derive(Debug, Clone, Copy)]
pub struct Rec<'a> {
    map: &'a Map<String, Value>,
    lossy: bool,
}

impl<'a> Rec<'a> {
    pub fn new(map: &'a Map<String, Value>, lossy: bool) -> Self {
        Rec { map, lossy }
    }

    pub fn map(&self) -> &'a Map<String, Value> {
        self.map
    }

    pub fn has(&self, key: &str) -> bool {
        get_ci(self.map, key).is_some()
    }

    /// Nested object `key` as a record with the same lossiness; `None` when missing or not
    /// an object (CSV cells holding a .NET type name are not objects).
    pub fn object(&self, key: &str) -> Option<Rec<'a>> {
        match get_ci(self.map, key)? {
            Value::Object(m) => Some(Rec {
                map: m,
                lossy: self.lossy,
            }),
            _ => None,
        }
    }

    fn scalar(&self, v: &Value) -> Option<String> {
        let s = match v {
            Value::String(s) => s.trim().to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            _ => return None,
        };
        if s.is_empty() || (self.lossy && is_placeholder(&s)) {
            None
        } else {
            Some(s)
        }
    }

    /// Trimmed scalar text; `None` when missing, null, blank, an array/object or a placeholder.
    pub fn text(&self, key: &str) -> Option<String> {
        self.scalar(get_ci(self.map, key)?)
    }

    pub fn first_text(&self, keys: &[&str]) -> Option<String> {
        keys.iter().find_map(|k| self.text(k))
    }

    /// JSON booleans or `True` / `False` text.
    pub fn bool(&self, key: &str) -> Option<bool> {
        match get_ci(self.map, key)? {
            Value::Bool(b) => Some(*b),
            Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn int(&self, key: &str) -> Option<i64> {
        match get_ci(self.map, key)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    /// Multi-valued property. A JSON array gives its non-blank items; a text value gives one
    /// item (Export-Csv joins items with spaces, which cannot be split back reliably).
    pub fn list(&self, key: &str) -> Vec<String> {
        match get_ci(self.map, key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    Value::Object(_) | Value::Array(_) => Some(v.to_string()),
                    other => self.scalar(other),
                })
                .collect(),
            Some(v) => self.scalar(v).into_iter().collect(),
            None => Vec::new(),
        }
    }

    /// Nested value as JSON: objects and arrays as they are, text holding embedded JSON
    /// parsed, other scalars as JSON scalars. `None` for null, blank and placeholders.
    pub fn json(&self, key: &str) -> Option<Value> {
        match get_ci(self.map, key)? {
            Value::Null => None,
            v @ (Value::Object(_) | Value::Array(_)) => Some(v.clone()),
            v @ Value::String(_) => {
                let s = self.scalar(v)?;
                if s.starts_with('{') || s.starts_with('[') {
                    Some(serde_json::from_str(&s).unwrap_or(Value::String(s)))
                } else {
                    Some(Value::String(s))
                }
            }
            v => Some(v.clone()),
        }
    }
}

/// A value on its way to a state table.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Text(String),
    Bool(bool),
    Int(i64),
    /// Timestamp text (ISO, `/Date(ms)/` or culture-formatted), parsed when staged.
    Time(String),
    List(Vec<String>),
    Json(Value),
}

impl Cell {
    pub fn text(v: Option<String>) -> Cell {
        v.map_or(Cell::Null, Cell::Text)
    }

    pub fn bool(v: Option<bool>) -> Cell {
        v.map_or(Cell::Null, Cell::Bool)
    }

    pub fn int(v: Option<i64>) -> Cell {
        v.map_or(Cell::Null, Cell::Int)
    }

    pub fn time(v: Option<String>) -> Cell {
        v.map_or(Cell::Null, Cell::Time)
    }

    /// An empty list is stored as NULL.
    pub fn list(v: Vec<String>) -> Cell {
        if v.is_empty() {
            Cell::Null
        } else {
            Cell::List(v)
        }
    }

    pub fn json(v: Option<Value>) -> Cell {
        v.map_or(Cell::Null, Cell::Json)
    }

    /// Text handed to the loader: RFC 3339 for times, JSON for lists and JSON values.
    pub fn stage(&self, order: Option<DateOrder>) -> Result<Option<String>, String> {
        Ok(match self {
            Cell::Null => None,
            Cell::Text(s) => Some(s.clone()),
            Cell::Bool(b) => Some(b.to_string()),
            Cell::Int(i) => Some(i.to_string()),
            Cell::Time(s) => Some(
                parse_timestamp(s, order)
                    .map_err(|e| e.to_string())?
                    .rfc3339(),
            ),
            Cell::List(v) => Some(Value::from(v.clone()).to_string()),
            Cell::Json(v) => Some(v.to_string()),
        })
    }
}
