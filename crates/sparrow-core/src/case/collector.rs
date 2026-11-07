//! What the collector's own manifests say was collected (`manifest_runs`, `manifest_units`, `manifest_gaps`), as
//! interval sets per tenant x account x source. Read-only; everything is loaded in three queries by [`load`].
//!
//! - **Counted units**: units of runs with `supported = true` whose collection has a tenant (R8), and that wrote
//!   output (`output_written = true`, R2). Every other unit is ignored here.
//! - **Vouching** (R2, R3): a `complete` or `partial` unit with a valid range vouches its range minus its own gaps,
//!   for each of its sources, for the accounts in `user_ids` (trimmed, lower-cased; NULL = every account; `[]` =
//!   nobody), unless it is narrowed. A MailItemsAccessed-only unit (`mia_only`) vouches `mail_items_accessed` only
//!   (when its sources name `ual` or `mail_items_accessed`), never `ual`. `message_trace` is vouched where a unit
//!   without `direction` vouches, or where both a `sender` and a `recipient` unit vouch.
//! - **Gaps** (R2): a unit's listed gaps; a `failed`, `search_only` or unknown-state unit with none listed is one gap
//!   over its whole range (reason `failed` / `search_only`); a `not_started` unit with none listed likewise (reason
//!   `not_started`). A unit without a valid range (R6) that lists no gap, whatever its state, is one undated gap
//!   with reason `invalid_range`. A gap without a valid range is *undated*: it never shows in the per-account spans, and
//!   it is always listed by [`ManifestIndex::open_gaps`].
//! - **Open gaps** (R4, R5): a gap is open over the part not vouched, for every one of its sources, by the scope
//!   it was asked for: tenant-wide vouching for a tenant-wide gap, vouching of every listed user for a per-user gap
//!   (a `[]` gap has no users, so never closes this way), or vouching by a unit whose `scope` JSON is identical.

use crate::Result;
use crate::case::audit::ts_text;
use chrono::DateTime;
use duckdb::Connection;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Half-open [start_us, end_us), epoch microseconds UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Span {
    pub start_us: i64,
    pub end_us: i64,
}

/// Sorted, disjoint, non-empty spans. Adjacent spans are merged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spans(Vec<Span>);

impl FromIterator<Span> for Spans {
    /// Normalises: drops empty or reversed spans, sorts, merges overlapping and adjacent spans.
    fn from_iter<I: IntoIterator<Item = Span>>(it: I) -> Spans {
        let mut v: Vec<Span> = it.into_iter().filter(|s| s.end_us > s.start_us).collect();
        v.sort_unstable();
        let mut out: Vec<Span> = Vec::with_capacity(v.len());
        for s in v {
            match out.last_mut() {
                Some(last) if s.start_us <= last.end_us => last.end_us = last.end_us.max(s.end_us),
                _ => out.push(s),
            }
        }
        Spans(out)
    }
}

impl Spans {
    pub fn union(&self, o: &Spans) -> Spans {
        self.0.iter().chain(o.0.iter()).copied().collect()
    }

    pub fn minus(&self, o: &Spans) -> Spans {
        let mut out = Vec::new();
        let mut j = 0;
        for s in &self.0 {
            while j < o.0.len() && o.0[j].end_us <= s.start_us {
                j += 1;
            }
            let mut cur = s.start_us;
            for b in &o.0[j..] {
                if b.start_us >= s.end_us {
                    break;
                }
                if b.start_us > cur {
                    out.push(Span {
                        start_us: cur,
                        end_us: b.start_us,
                    });
                }
                cur = cur.max(b.end_us);
                if cur >= s.end_us {
                    break;
                }
            }
            if cur < s.end_us {
                out.push(Span {
                    start_us: cur,
                    end_us: s.end_us,
                });
            }
        }
        Spans(out)
    }

    pub fn intersect(&self, o: &Spans) -> Spans {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        while i < self.0.len() && j < o.0.len() {
            let (a, b) = (self.0[i], o.0[j]);
            let lo = a.start_us.max(b.start_us);
            let hi = a.end_us.min(b.end_us);
            if lo < hi {
                out.push(Span {
                    start_us: lo,
                    end_us: hi,
                });
            }
            if a.end_us <= b.end_us {
                i += 1;
            } else {
                j += 1;
            }
        }
        Spans(out)
    }

    pub fn total_us(&self) -> i64 {
        self.0.iter().map(|s| s.end_us - s.start_us).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Span> {
        self.0.iter()
    }
}

fn us_text(us: i64) -> String {
    ts_text(&DateTime::from_timestamp_micros(us).unwrap_or_default())
}

impl Serialize for Spans {
    /// A JSON array of `{start, end}` ISO 8601 UTC strings.
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Text {
            start: String,
            end: String,
        }
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for sp in &self.0 {
            seq.serialize_element(&Text {
                start: us_text(sp.start_us),
                end: us_text(sp.end_us),
            })?;
        }
        seq.end()
    }
}

/// A collector gap that is still open (R4, R5).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OpenGap {
    pub tenant_key: String,
    pub run_id: String,
    pub unit_id: String,
    pub cmdlet: Option<String>,
    /// The sources the gap is in (for a MailItemsAccessed-only unit, `mail_items_accessed`).
    pub sources: Vec<String>,
    /// The unit's accounts (trimmed, lower-cased); `None` = tenant-wide.
    pub user_ids: Option<Vec<String>>,
    pub narrowed: bool,
    pub reason: String,
    pub detail: Option<String>,
    pub search_id: Option<String>,
    /// What is still open; empty `spans` with `undated = true` is R6's gap without a range.
    pub spans: Spans,
    pub undated: bool,
    pub parameters: Value,
}

/// A gap of a counted unit (R2): listed by the collector, or the unit's whole range.
#[derive(Debug, Clone)]
struct UnitGap {
    span: Option<Span>,
    reason: String,
    detail: Option<String>,
    search_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Any,
    Sender,
    Recipient,
    Other,
}

#[derive(Debug, Clone)]
struct Unit {
    run_id: String,
    unit_id: String,
    cmdlet: Option<String>,
    parameters: Value,
    /// Sources it vouches and gaps for (a MailItemsAccessed-only unit: `mail_items_accessed` only).
    sources: Vec<String>,
    user_ids: Option<Vec<String>>,
    scope: Option<Value>,
    narrowed: bool,
    direction: Direction,
    /// Range minus own gaps for a complete or partial unit with a valid range; empty otherwise.
    vouch: Spans,
    gaps: Vec<UnitGap>,
}

impl Unit {
    fn has_source(&self, source: &str) -> bool {
        self.sources.iter().any(|s| s == source)
    }

    fn covers_account(&self, account: &str) -> bool {
        self.user_ids
            .as_ref()
            .is_none_or(|u| u.iter().any(|x| x == account))
    }
}

/// Units and gaps of runs with `supported = true`, per tenant (R8).
#[derive(Debug, Clone, Default)]
pub struct ManifestIndex {
    by_tenant: BTreeMap<String, Vec<Unit>>,
}

fn span_of(start: Option<i64>, end: Option<i64>) -> Option<Span> {
    match (start, end) {
        (Some(s), Some(e)) if e > s => Some(Span {
            start_us: s,
            end_us: e,
        }),
        _ => None,
    }
}

fn parse_json(text: Option<String>) -> Option<Value> {
    text.and_then(|t| serde_json::from_str(&t).ok())
}

struct GapRow {
    span: Option<Span>,
    reason: Option<String>,
    detail: Option<String>,
    search_id: Option<String>,
}

/// Load the index: runs (with their collection's tenant), units and gaps, in three queries.
pub fn load(conn: &Connection) -> Result<ManifestIndex> {
    // Run id -> (tenant, cmdlet, parameters).
    let mut runs: HashMap<String, (String, Option<String>, Value)> = HashMap::new();
    {
        let mut st = conn.prepare(
            "SELECT r.run_id, c.tenant_key, r.cmdlet, CAST(r.parameters AS VARCHAR) \
             FROM manifest_runs r JOIN collections c ON c.collection_id = r.collection_id \
             WHERE r.supported AND c.tenant_key IS NOT NULL",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (run_id, tenant, cmdlet, params) = row?;
            runs.insert(
                run_id,
                (tenant, cmdlet, parse_json(params).unwrap_or(Value::Null)),
            );
        }
    }
    if runs.is_empty() {
        return Ok(ManifestIndex::default());
    }

    let mut gaps: HashMap<String, Vec<GapRow>> = HashMap::new();
    {
        let mut st = conn.prepare(
            "SELECT unit_key, epoch_us(start_at), epoch_us(end_at), reason, detail, search_id \
             FROM manifest_gaps ORDER BY unit_key, ordinal",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                GapRow {
                    span: span_of(r.get(1)?, r.get(2)?),
                    reason: r.get(3)?,
                    detail: r.get(4)?,
                    search_id: r.get(5)?,
                },
            ))
        })?;
        for row in rows {
            let (key, g) = row?;
            gaps.entry(key).or_default().push(g);
        }
    }

    let mut by_tenant: BTreeMap<String, Vec<Unit>> = BTreeMap::new();
    let mut st = conn.prepare(
        "SELECT unit_key, run_id, unit_id, CAST(sources AS VARCHAR), CAST(scope AS VARCHAR), \
             CAST(user_ids AS VARCHAR), narrowed, mia_only, direction, epoch_us(start_at), epoch_us(end_at), state \
         FROM manifest_units WHERE output_written ORDER BY run_id, unit_id",
    )?;
    let rows = st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, bool>(6)?,
            r.get::<_, bool>(7)?,
            r.get::<_, Option<String>>(8)?,
            span_of(r.get(9)?, r.get(10)?),
            r.get::<_, Option<String>>(11)?,
        ))
    })?;
    for row in rows {
        let (
            unit_key,
            run_id,
            unit_id,
            sources,
            scope,
            user_ids,
            narrowed,
            mia_only,
            direction,
            range,
            state,
        ) = row?;
        let Some((tenant, cmdlet, parameters)) = runs.get(&run_id) else {
            continue;
        };
        let written: Vec<String> = parse_json(sources)
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let sources = if mia_only {
            if written
                .iter()
                .any(|s| s == "ual" || s == "mail_items_accessed")
            {
                vec!["mail_items_accessed".to_string()]
            } else {
                Vec::new()
            }
        } else {
            written
        };
        // NULL = every account. Anything stored that is not a text list vouches nobody.
        let user_ids: Option<Vec<String>> = user_ids.map(|t| {
            serde_json::from_str::<Vec<String>>(&t)
                .unwrap_or_default()
                .into_iter()
                .map(|s| s.trim().to_lowercase())
                .collect()
        });
        let direction = match direction.as_deref().map(|d| d.trim().to_ascii_lowercase()) {
            None => Direction::Any,
            Some(d) if d.is_empty() => Direction::Any,
            Some(d) if d == "sender" => Direction::Sender,
            Some(d) if d == "recipient" => Direction::Recipient,
            Some(_) => Direction::Other,
        };
        let listed = gaps.remove(&unit_key).unwrap_or_default();
        let state = state.unwrap_or_default();
        let vouches = matches!(state.as_str(), "complete" | "partial");
        let vouch = match range {
            Some(r) if vouches && listed.iter().all(|g| g.span.is_some()) => {
                Spans(vec![r]).minus(&listed.iter().filter_map(|g| g.span).collect())
            }
            _ => Spans::default(),
        };
        let unit_gaps: Vec<UnitGap> = if !listed.is_empty() {
            listed
                .into_iter()
                .map(|g| UnitGap {
                    span: g.span,
                    reason: g.reason.unwrap_or_else(|| "failed".to_string()),
                    detail: g.detail,
                    search_id: g.search_id,
                })
                .collect()
        } else if range.is_none() {
            // No valid range and no listed gap, whatever the state: what it collected is unknown (R6).
            vec![UnitGap {
                span: None,
                reason: "invalid_range".to_string(),
                detail: None,
                search_id: None,
            }]
        } else if vouches {
            Vec::new()
        } else {
            let reason = match state.as_str() {
                "search_only" | "not_started" => state.clone(),
                _ => "failed".to_string(),
            };
            vec![UnitGap {
                span: range,
                reason,
                detail: None,
                search_id: None,
            }]
        };
        by_tenant.entry(tenant.clone()).or_default().push(Unit {
            run_id,
            unit_id,
            cmdlet: cmdlet.clone(),
            parameters: parameters.clone(),
            sources,
            user_ids,
            scope: parse_json(scope),
            narrowed,
            direction,
            vouch,
            gaps: unit_gaps,
        });
    }
    Ok(ManifestIndex { by_tenant })
}

fn norm_account(a: &str) -> String {
    a.trim().to_lowercase()
}

impl ManifestIndex {
    /// True when no counted unit (supported run, collection with a tenant, output written) was loaded.
    pub fn is_empty(&self) -> bool {
        self.by_tenant.values().all(Vec::is_empty)
    }

    /// True when a counted unit of `tenant` was loaded.
    pub fn has_tenant(&self, tenant: &str) -> bool {
        !self.units(tenant).is_empty()
    }

    fn units(&self, tenant: &str) -> &[Unit] {
        self.by_tenant.get(tenant).map_or(&[], Vec::as_slice)
    }

    /// Vouching for `source` by the not-narrowed units `keep` selects, with R3's message trace rule.
    fn vouch_where(&self, tenant: &str, source: &str, keep: impl Fn(&Unit) -> bool) -> Spans {
        let units = self
            .units(tenant)
            .iter()
            .filter(|u| !u.narrowed && u.has_source(source) && keep(u));
        if source != "message_trace" {
            return units.flat_map(|u| u.vouch.iter().copied()).collect();
        }
        let (mut any, mut sender, mut recipient) = (Vec::new(), Vec::new(), Vec::new());
        for u in units {
            match u.direction {
                Direction::Any => any.extend(u.vouch.iter().copied()),
                Direction::Sender => sender.extend(u.vouch.iter().copied()),
                Direction::Recipient => recipient.extend(u.vouch.iter().copied()),
                Direction::Other => {}
            }
        }
        let both = Spans::from_iter(sender).intersect(&Spans::from_iter(recipient));
        Spans::from_iter(any).union(&both)
    }

    /// Dated gaps for `source` of the not-narrowed units `keep` selects.
    fn gaps_where(&self, tenant: &str, source: &str, keep: impl Fn(&Unit) -> bool) -> Spans {
        self.units(tenant)
            .iter()
            .filter(|u| !u.narrowed && u.has_source(source) && keep(u))
            .flat_map(|u| u.gaps.iter().filter_map(|g| g.span))
            .collect()
    }

    /// R2 + R3 for one account (lower-cased) and one SOURCES id.
    pub fn vouched(&self, tenant: &str, account: &str, source: &str) -> Spans {
        let account = norm_account(account);
        self.vouch_where(tenant, source, |u| u.covers_account(&account))
    }

    /// Gaps of non-narrowed units in scope for the account and source, minus `vouched` (R2, R4).
    pub fn account_gaps(&self, tenant: &str, account: &str, source: &str) -> Spans {
        let account = norm_account(account);
        self.gaps_where(tenant, source, |u| u.covers_account(&account))
            .minus(&self.vouched(tenant, &account, source))
    }

    /// `vouched` restricted to tenant-wide units (`user_ids` NULL).
    pub fn vouched_tenant_wide(&self, tenant: &str, source: &str) -> Spans {
        self.vouch_where(tenant, source, |u| u.user_ids.is_none())
    }

    /// `account_gaps` restricted to tenant-wide units: their gaps minus `vouched_tenant_wide`.
    pub fn tenant_wide_gaps(&self, tenant: &str, source: &str) -> Spans {
        self.gaps_where(tenant, source, |u| u.user_ids.is_none())
            .minus(&self.vouched_tenant_wide(tenant, source))
    }

    /// What closes a gap of `unit` in `source` (R4, R5): vouching for the unit's accounts (tenant-wide for a
    /// tenant-wide unit), or by any unit with an identical scope.
    fn closing(&self, tenant: &str, unit: &Unit, source: &str) -> Spans {
        let by_scope = match &unit.user_ids {
            None => self.vouched_tenant_wide(tenant, source),
            Some(users) if users.is_empty() => Spans::default(),
            Some(users) => {
                let mut it = users.iter().map(|a| self.vouched(tenant, a, source));
                let first = it.next().unwrap_or_default();
                it.fold(first, |acc, v| acc.intersect(&v))
            }
        };
        let identical: Spans = self
            .units(tenant)
            .iter()
            .filter(|v| v.scope == unit.scope && v.has_source(source))
            .flat_map(|v| v.vouch.iter().copied())
            .collect();
        by_scope.union(&identical)
    }

    /// Every open gap of the case (R4, R5), tenant filter optional; ordered by tenant, start, run_id, unit_id.
    pub fn open_gaps(&self, tenant: Option<&str>) -> Vec<OpenGap> {
        let mut out = Vec::new();
        for (t, units) in &self.by_tenant {
            if tenant.is_some_and(|f| f != t) {
                continue;
            }
            for u in units {
                if u.gaps.is_empty() {
                    continue;
                }
                // Closed where every source of the gap is closed.
                let closed = if u.sources.is_empty() {
                    Spans::default()
                } else {
                    let mut it = u.sources.iter().map(|s| self.closing(t, u, s));
                    let first = it.next().unwrap_or_default();
                    it.fold(first, |acc, c| acc.intersect(&c))
                };
                for g in &u.gaps {
                    let (spans, undated) = match g.span {
                        Some(s) => (Spans(vec![s]).minus(&closed), false),
                        None => (Spans::default(), true),
                    };
                    if !undated && spans.is_empty() {
                        continue;
                    }
                    out.push(OpenGap {
                        tenant_key: t.clone(),
                        run_id: u.run_id.clone(),
                        unit_id: u.unit_id.clone(),
                        cmdlet: u.cmdlet.clone(),
                        sources: u.sources.clone(),
                        user_ids: u.user_ids.clone(),
                        narrowed: u.narrowed,
                        reason: g.reason.clone(),
                        detail: g.detail.clone(),
                        search_id: g.search_id.clone(),
                        spans,
                        undated,
                        parameters: u.parameters.clone(),
                    });
                }
            }
        }
        // Stable: gaps of one unit keep their ordinal order. Undated gaps last within their tenant.
        out.sort_by(|a, b| {
            let start = |g: &OpenGap| g.spans.iter().next().map_or(i64::MAX, |s| s.start_us);
            (&a.tenant_key, start(a), &a.run_id, &a.unit_id).cmp(&(
                &b.tenant_key,
                start(b),
                &b.run_id,
                &b.unit_id,
            ))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(a: i64, b: i64) -> Span {
        Span {
            start_us: a,
            end_us: b,
        }
    }

    fn ss(v: &[(i64, i64)]) -> Spans {
        v.iter().map(|&(a, b)| s(a, b)).collect()
    }

    #[test]
    fn from_iter_sorts_merges_overlap_and_adjacency_and_drops_empty() {
        let x = ss(&[(10, 20), (0, 5), (5, 8), (15, 25), (30, 30), (40, 35)]);
        assert_eq!(x.0, vec![s(0, 8), s(10, 25)]);
        assert_eq!(x.total_us(), 23);
    }

    #[test]
    fn union_merges_adjacent_spans() {
        assert_eq!(ss(&[(0, 5)]).union(&ss(&[(5, 10)])).0, vec![s(0, 10)]);
        assert_eq!(
            ss(&[(0, 5)]).union(&ss(&[(6, 10)])).0,
            vec![s(0, 5), s(6, 10)]
        );
    }

    #[test]
    fn minus_produces_an_interior_hole() {
        let x = ss(&[(0, 100)]).minus(&ss(&[(40, 60)]));
        assert_eq!(x.0, vec![s(0, 40), s(60, 100)]);
        let y = ss(&[(0, 10), (20, 30)]).minus(&ss(&[(5, 25), (28, 40)]));
        assert_eq!(y.0, vec![s(0, 5), s(25, 28)]);
        assert!(ss(&[(0, 10)]).minus(&ss(&[(0, 10)])).is_empty());
        assert_eq!(
            ss(&[(0, 10)]).minus(&ss(&[(-5, 0), (10, 20)])).0,
            vec![s(0, 10)]
        );
    }

    #[test]
    fn intersect_keeps_the_common_part() {
        let x = ss(&[(0, 10), (20, 30)]).intersect(&ss(&[(5, 25)]));
        assert_eq!(x.0, vec![s(5, 10), s(20, 25)]);
        assert!(ss(&[(0, 5)]).intersect(&ss(&[(5, 10)])).is_empty());
    }

    #[test]
    fn empty_inputs() {
        let e = Spans::default();
        let x = ss(&[(0, 10)]);
        assert!(Spans::from_iter(Vec::new()).is_empty());
        assert_eq!(e.union(&e), e);
        assert_eq!(e.union(&x), x);
        assert_eq!(x.minus(&e), x);
        assert!(e.minus(&x).is_empty());
        assert!(e.intersect(&x).is_empty());
        assert!(x.intersect(&e).is_empty());
        assert_eq!(e.total_us(), 0);
        assert_eq!(e.iter().count(), 0);
    }

    #[test]
    fn serializes_as_iso_8601_start_end_pairs() {
        let x = ss(&[(0, 1_500_000)]);
        assert_eq!(
            serde_json::to_string(&x).unwrap(),
            r#"[{"start":"1970-01-01T00:00:00.000000Z","end":"1970-01-01T00:00:01.500000Z"}]"#
        );
        assert_eq!(serde_json::to_string(&Spans::default()).unwrap(), "[]");
    }
}
