//! The access report: what the attacker reached through a compromised account. The records the analyst's accepted
//! malicious flags tie to the attacker (`scope`) are turned into items per category (mail read and sent, attachments,
//! SharePoint/OneDrive, Teams, Copilot, other apps), with how each is tied to the attacker and what the capture could not
//! see. Read-only: nothing is written and no audit entry is added. [`report_with`] previews the report with pending flags
//! or ad-hoc values in scope ([`ScopeSource`]), each item and scope value labelled with its [`Basis`].

mod coverage;
mod items;
mod scope;

pub use coverage::NEVER_LOGGED;
pub use items::{Item, items, items_with};
pub use scope::{
    Attributed, ScopeValue, Window, attributed, attributed_with, pending_flags, scope, scope_with,
};

use crate::case::marks::ValueKind;
use crate::{Error, Result};
use duckdb::Connection;
use duckdb::types::Value;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// How a record is tied to the attacker. Every value but `Time` is direct evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// A flagged Entra session, or an Exchange session shared with a directly attributed record of the account.
    Session,
    /// The record itself was flagged malicious.
    Row,
    /// A flagged device.
    Device,
    /// A flagged IP or prefix, or an ASN flagged for the account.
    Ip,
    /// No session and no IP of its own, inside a window of the account's malicious activity.
    Time,
}

impl Attribution {
    pub fn as_str(self) -> &'static str {
        match self {
            Attribution::Session => "session",
            Attribution::Row => "row",
            Attribution::Device => "device",
            Attribution::Ip => "ip",
            Attribution::Time => "time",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Attribution> {
        [Self::Session, Self::Row, Self::Device, Self::Ip, Self::Time]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

/// What puts a record (or scope value) in the report, strongest first: an accepted flag, a pending agent flag
/// (`--include-pending`), or an ad-hoc value of the request, treated as flagged malicious and accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Accepted,
    Pending,
    Adhoc,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Accepted => "accepted",
            Basis::Pending => "pending",
            Basis::Adhoc => "adhoc",
        }
    }

    /// The SQL rank (1 accepted, 2 pending, 3 ad-hoc).
    pub(crate) fn from_rank(r: i64) -> Basis {
        match r {
            1 => Basis::Accepted,
            2 => Basis::Pending,
            _ => Basis::Adhoc,
        }
    }
}

/// Which malicious flags the report counts: accepted ones always; pending ones too with `include_pending`; and
/// ad-hoc values (ip, ip_prefix, session, device), case-wide, as if flagged and accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSource {
    pub include_pending: bool,
    pub adhoc: Vec<(ValueKind, String)>,
}

impl ScopeSource {
    /// The reviewed report: accepted flags only.
    pub fn accepted() -> ScopeSource {
        ScopeSource::default()
    }

    fn check(&self) -> Result<()> {
        for (k, v) in &self.adhoc {
            if !matches!(
                k,
                ValueKind::Ip | ValueKind::IpPrefix | ValueKind::Session | ValueKind::Device
            ) {
                return Err(Error::Invalid(format!(
                    "an ad-hoc scope value is an ip, ip_prefix, session or device, not {} {v:?}",
                    k.as_str()
                )));
            }
        }
        Ok(())
    }
}

/// What an item is, in tile order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    MailRead,
    MailSent,
    Attachment,
    File,
    Teams,
    Copilot,
    Other,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::MailRead,
        Category::MailSent,
        Category::Attachment,
        Category::File,
        Category::Teams,
        Category::Copilot,
        Category::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::MailRead => "mail_read",
            Category::MailSent => "mail_sent",
            Category::Attachment => "attachment",
            Category::File => "file",
            Category::Teams => "teams",
            Category::Copilot => "copilot",
            Category::Other => "other",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Category::MailRead => "Emails read",
            Category::MailSent => "Emails sent",
            Category::Attachment => "Attachments",
            Category::File => "SharePoint / OneDrive",
            Category::Teams => "Teams",
            Category::Copilot => "Copilot",
            Category::Other => "Other apps",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Category> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// The status of a category's evidence source: an `evidence_availability.status`, or `none` when the case has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategoryCoverage {
    pub status: String,
    pub reason: String,
    pub remediation: Option<String>,
}

/// One category of an account: counts (direct and by time), a one-line qualifier, its coverage, and whether its zero
/// is a finding ("none seen").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tile {
    pub category: Category,
    pub direct: u64,
    pub by_time: u64,
    pub qualifier: Option<String>,
    pub coverage: CategoryCoverage,
    pub none_seen: bool,
    /// Of the counts (`direct` + `by_time`), how many come from pending flags and from ad-hoc values (a preview); 0
    /// in the reviewed report.
    pub pending: u64,
    pub adhoc: u64,
}

/// What the attacker reached through one account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountAccess {
    pub account: String,
    pub tenant_key: Option<String>,
    pub scope: Vec<ScopeValue>,
    /// One per category, in [`Category::ALL`] order.
    pub tiles: Vec<Tile>,
    pub items: Vec<Item>,
    /// Coverage reasons of the categories whose source was not collected, then [`NEVER_LOGGED`].
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessReport {
    pub accounts: Vec<AccountAccess>,
    /// Malicious flags waiting for review: they attribute nothing yet (unless the report includes pending ones).
    pub pending_flags: u64,
    /// True when an item or scope value comes from a pending flag or an ad-hoc value: not the reviewed report.
    pub preview: bool,
}

/// The accounts on the report: those with a direct attribution or an accepted malicious account flag, sorted.
pub fn flagged_accounts(conn: &Connection) -> Result<Vec<String>> {
    flagged_accounts_with(conn, &ScopeSource::accepted())
}

/// [`flagged_accounts`] with the flags `src` puts in play (a pending account flag too, when it includes them).
fn flagged_accounts_with(conn: &Connection, src: &ScopeSource) -> Result<Vec<String>> {
    let (ctes, params) = scope::ctes(src);
    let sql = format!(
        "WITH {ctes} SELECT account FROM dir UNION SELECT lower(value) FROM flagv WHERE kind = 'account' ORDER BY 1"
    );
    let mut st = conn.prepare(&sql)?;
    let rows = st.query_map(duckdb::params_from_iter(params.iter()), |r| r.get(0))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The tenant of the account's attributed records (the most frequent one), else of all its events.
fn tenant_of(conn: &Connection, account: &str, src: &ScopeSource) -> Result<Option<String>> {
    use duckdb::OptionalExt;
    let (ctes, mut params) = scope::ctes(src);
    let sql = format!(
        "WITH {ctes} SELECT coalesce( \
           (SELECT e.tenant_key FROM attributed a JOIN events e USING (source_table, record_key) \
              WHERE a.account = ? AND e.tenant_key IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 1), \
           (SELECT tenant_key FROM events WHERE lower(actor_upn) = ? AND tenant_key IS NOT NULL \
              GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT 1))"
    );
    params.push(Value::Text(account.to_string()));
    params.push(Value::Text(account.to_string()));
    Ok(conn
        .query_row(&sql, duckdb::params_from_iter(params.iter()), |r| r.get(0))
        .optional()?
        .flatten())
}

fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// Counts and qualifier of one category's items. Mail read counts messages (`read` items: one per message already);
/// files count distinct files, direct winning; the rest count items.
fn counts(c: Category, items: &[&Item]) -> (u64, u64, Option<String>) {
    let split = |it: &mut dyn Iterator<Item = &&Item>| {
        let (mut d, mut t) = (0u64, 0u64);
        for i in it {
            if i.attribution == Attribution::Time {
                t += 1
            } else {
                d += 1
            }
        }
        (d, t)
    };
    match c {
        Category::MailRead => {
            let (d, t) = split(&mut items.iter().filter(|i| i.action == "read"));
            let reads: Vec<_> = items.iter().filter(|i| i.action == "read").collect();
            let folders: BTreeSet<_> = reads.iter().filter_map(|i| i.location.as_deref()).collect();
            let synced: BTreeSet<_> = items
                .iter()
                .filter(|i| i.action == "synced")
                .filter_map(|i| i.location.as_deref())
                .collect();
            let mut q = Vec::new();
            if !reads.is_empty() {
                let bytes: i64 = reads.iter().filter_map(|i| i.size_bytes).sum();
                q.push(plural(folders.len(), "folder"));
                q.push(format!("{:.1} MB", bytes as f64 / 1_048_576.0));
            }
            if !synced.is_empty() {
                q.push(format!("{} synced", plural(synced.len(), "folder")));
            }
            let unnamed = items
                .iter()
                .filter(|i| i.action == "read (no message id)")
                .count();
            if unnamed > 0 {
                q.push(format!("{} without a message id", plural(unnamed, "read")));
            }
            (d, t, (!q.is_empty()).then(|| q.join(" · ")))
        }
        Category::MailSent => {
            let (d, t) = split(&mut items.iter());
            let to: BTreeSet<&str> = items
                .iter()
                .filter_map(|i| i.to.as_deref())
                .flat_map(|s| s.split("; "))
                .collect();
            (
                d,
                t,
                (!to.is_empty()).then(|| format!("to {}", plural(to.len(), "recipient"))),
            )
        }
        Category::File => {
            let key = |i: &Item| {
                i.location
                    .clone()
                    .or(i.item.clone())
                    .unwrap_or(i.record_key.clone())
            };
            let direct: BTreeSet<String> = items
                .iter()
                .filter(|i| i.attribution != Attribution::Time)
                .map(|i| key(i))
                .collect();
            let all: BTreeSet<String> = items.iter().map(|i| key(i)).collect();
            let downloads: BTreeSet<String> = items
                .iter()
                .filter(|i| i.action.to_lowercase().contains("download"))
                .map(|i| key(i))
                .collect();
            let q = (!downloads.is_empty()).then(|| format!("{} downloaded", downloads.len()));
            (direct.len() as u64, (all.len() - direct.len()) as u64, q)
        }
        _ => {
            let (d, t) = split(&mut items.iter());
            (d, t, None)
        }
    }
}

fn account_access(
    conn: &Connection,
    account: String,
    items: Vec<Item>,
    src: &ScopeSource,
) -> Result<AccountAccess> {
    let tenant = tenant_of(conn, &account, src)?;
    let present = match &tenant {
        Some(t) => coverage::presence(conn, t, &account)?,
        None => BTreeSet::new(),
    };
    let limits = coverage::mail_limits(conn, &account, src)?;
    let mut tiles = Vec::new();
    let mut gaps = Vec::new();
    for c in Category::ALL {
        let of: Vec<&Item> = items.iter().filter(|i| i.category == c).collect();
        let (direct, by_time, qualifier) = counts(c, &of);
        let share = |b: Basis| {
            let part: Vec<&Item> = of.iter().copied().filter(|i| i.basis == b).collect();
            let (d, t, _) = counts(c, &part);
            d + t
        };
        let (pending, adhoc) = (share(Basis::Pending), share(Basis::Adhoc));
        let (coverage, covered) = coverage::coverage(conn, tenant.as_deref(), c, &present)?;
        let (coverage, covered) = coverage::limited(c, &limits, coverage, covered);
        if coverage.status != "collected" {
            gaps.push(format!("{}: {}", c.title(), coverage.reason));
        }
        tiles.push(Tile {
            category: c,
            direct,
            by_time,
            qualifier,
            none_seen: of.is_empty() && covered,
            coverage,
            pending,
            adhoc,
        });
    }
    gaps.extend(NEVER_LOGGED.iter().map(|(_, g)| g.to_string()));
    Ok(AccountAccess {
        scope: scope::scope_with(conn, &account, src)?,
        account,
        tenant_key: tenant,
        tiles,
        items,
        gaps,
    })
}

/// The access report of every account on it, or of `account` alone (lower-cased; an account with nothing attributed
/// gets an empty section).
pub fn report(conn: &Connection, account: Option<&str>) -> Result<AccessReport> {
    report_with(conn, account, &ScopeSource::accepted())
}

/// [`report`] with the flags `src` puts in play: a preview when it includes pending flags or ad-hoc values (each item
/// and scope value says which, `preview` says whether any is not accepted).
pub fn report_with(
    conn: &Connection,
    account: Option<&str>,
    src: &ScopeSource,
) -> Result<AccessReport> {
    src.check()?;
    let accounts = match account {
        Some(a) => vec![a.to_lowercase()],
        None => flagged_accounts_with(conn, src)?,
    };
    let mut by: BTreeMap<String, Vec<Item>> = BTreeMap::new();
    for i in items_with(conn, account, src)? {
        by.entry(i.account.clone()).or_default().push(i);
    }
    let mut out = Vec::new();
    for a in accounts {
        let its = by.remove(&a).unwrap_or_default();
        out.push(account_access(conn, a, its, src)?);
    }
    let preview = out.iter().any(|a| {
        a.items.iter().any(|i| i.basis != Basis::Accepted)
            || a.scope.iter().any(|s| s.basis != Basis::Accepted)
    });
    Ok(AccessReport {
        accounts: out,
        pending_flags: pending_flags(conn)?,
        preview,
    })
}
