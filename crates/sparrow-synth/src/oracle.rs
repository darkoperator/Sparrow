//! Computed expectations (`computed:` in `rules/coverage.yaml`). Some storyline kinds trigger a rule
//! only under facts the generator draws per seed and scenario: the user's seeded home against the
//! attacker's location (impossible travel), the session ids a collector delivers and whether the
//! creating MFA sign-in is in the tree (a stolen session), the risky sign-in that precedes a rule, a
//! traveller's history before their first send. For those, the generator evaluates the rule's logic
//! itself over the rows THIS tree delivers and writes `hit` or `no_hit` into the manifest, and the
//! detection gate checks it exactly.
//!
//! Every input is the generator's own: the world's events, the record keys the tree's parsed files
//! load (`TreeOutcome::row_keys`), what each collector's rows carry ([`Facts::build`]), the world's
//! GeoIP locations (`geo::locations`, written into the tree's GeoLite2 databases) and the shipped data
//! lists (hosting ASNs, Microsoft ranges, `credential_failure_codes`, `suspicious_user_agents`). No
//! Sparrow query runs. The thresholds are read from the rule files ([`rule_number`]), and the derived
//! relations' constants from `sparrow_core::profile`, so a rule change cannot drift silently from this
//! model: a threshold that moves is read again, and one that cannot be found fails generation.
//!
//! The rows are read as Sparrow sees them, deliberately: a UAL record's fields follow Sparrow's UAL
//! normalizer's field precedence (UserId; ClientIP, then ClientIPAddress, then ActorIpAddress;
//! SessionId, then AppAccessContext.AADSessionId; AppId, then ApplicationId; UserAgent, then the
//! ExtendedProperties UserAgent, then ClientInfoString), so the oracle models the RULE over the record
//! Sparrow's rule reads. A normalizer bug in those fields would be mirrored here, not caught: the
//! parsers' own tests and `synth check`'s table expectations guard the normalizer.

use crate::events::{SignIn, SignInType, Ual};
use crate::options::Collector;
use crate::tree::TreeOutcome;
use crate::world::World;
use crate::{Error, Result};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// A computed condition, named after the rule logic it models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Condition {
    /// SPW-ID-003: two consecutive successful sign-ins of a user too far apart for the time between.
    ImpossibleTravel,
    /// SPW-ID-004: a session used from another network within the hour after its MFA sign-in, or a
    /// scripted user agent.
    AitmIndicators,
    /// SPW-MAIL-006: a send from a network (or hosting address) the user had not used on an earlier day.
    NewNetworkSend,
    /// SPW-ID-010: an inbox rule within the hour after a risky or hosting sign-in of its actor.
    RiskyRuleCorrelation,
}

impl Condition {
    pub const ALL: [Condition; 4] = [
        Condition::ImpossibleTravel,
        Condition::AitmIndicators,
        Condition::NewNetworkSend,
        Condition::RiskyRuleCorrelation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Condition::ImpossibleTravel => "impossible_travel",
            Condition::AitmIndicators => "aitm_indicators",
            Condition::NewNetworkSend => "new_network_send",
            Condition::RiskyRuleCorrelation => "risky_rule_correlation",
        }
    }

    pub fn parse(s: &str) -> Option<Condition> {
        Condition::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// The rule whose logic the condition models.
    pub fn rule_id(self) -> &'static str {
        match self {
            Condition::ImpossibleTravel => "SPW-ID-003",
            Condition::AitmIndicators => "SPW-ID-004",
            Condition::NewNetworkSend => "SPW-MAIL-006",
            Condition::RiskyRuleCorrelation => "SPW-ID-010",
        }
    }
}

/// A record a rule can cite: (table, record key).
pub type Record = (String, String);

/// A delivered `signins` row, as Sparrow reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct SignInRow {
    pub key: String,
    /// Epoch milliseconds.
    pub t: i64,
    /// Lower case; `None` for a service principal.
    pub upn: Option<String>,
    pub ip: IpAddr,
    pub error: i64,
    pub interactive: bool,
    pub session: Option<String>,
    /// Satisfied MFA: an auth requirement starting `multifactor`, or an MFA result
    /// "MFA successfully completed".
    pub mfa: bool,
    /// Risk level during sign-in medium or high.
    pub risky: bool,
    /// Lower case.
    pub app: String,
    pub user_agent: String,
}

/// A delivered `ual_events` row, as Sparrow reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct UalRow {
    pub key: String,
    pub t: i64,
    pub upn: Option<String>,
    pub ip: Option<IpAddr>,
    /// Lower case.
    pub op: String,
    pub session: Option<String>,
    /// Lower case.
    pub app: Option<String>,
    pub user_agent: Option<String>,
    /// The record's ResultStatus is `Failed`.
    pub failed: bool,
}

/// A delivered `admin_audit_events` row (Hawk 3's rendering of an Exchange admin cmdlet).
#[derive(Debug, Clone, PartialEq)]
pub struct AdminRow {
    pub key: String,
    pub t: i64,
    pub caller: Option<String>,
    /// Lower case.
    pub cmdlet: String,
}

/// What `ip_intel` holds for an address the tree's GeoLite2 databases locate (or not).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IpFacts {
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub hosting: bool,
    pub microsoft: bool,
}

/// One (application, hosting ASN) pair's known successes: the users, the UTC days and the count.
type PairUse<'a> = (BTreeSet<&'a str>, BTreeSet<i64>, i64);

/// One preceding sign-in of SPW-ID-010's actor: its time and, for a hosting-arm entry, its address's
/// ASN (`Some(None)`: unknown); `None` is a risk-arm entry, which has no tie.
type Preceding = (i64, Option<Option<u32>>);

/// The facts the computed conditions read, for one tree.
#[derive(Debug, Clone)]
pub struct Facts {
    pub collector: Collector,
    pub signins: Vec<SignInRow>,
    pub ual: Vec<UalRow>,
    pub admin: Vec<AdminRow>,
    ips: BTreeMap<IpAddr, IpFacts>,
    /// `spray_sources` addresses.
    pub spray: BTreeSet<IpAddr>,
    /// `cloud_services` (application, ASN) pairs.
    pub cloud: BTreeSet<(String, u32)>,
    /// Lower-case Microsoft first-party application ids (the `microsoft_first_party_apps` list).
    first_party: BTreeSet<String>,
    codes: BTreeSet<i64>,
    agents: Vec<String>,
}

fn core(e: sparrow_core::Error) -> Error {
    Error::Core(e.to_string())
}

/// `key`'s value in `m`, any case (as Sparrow's UAL normalizer looks it up).
fn get_ci<'a>(m: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    m.get(key).or_else(|| {
        m.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })
}

/// Trimmed scalar text; `None` when missing, blank or a PowerShell placeholder.
fn text(m: &Map<String, Value>, key: &str) -> Option<String> {
    let v = match get_ci(m, key)? {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    let t = v.trim();
    (!t.is_empty() && t != "System.Object[]" && !(t.starts_with("@{") && t.ends_with('}')))
        .then(|| t.to_string())
}

/// `[{Name, Value}]` pairs (ExtendedProperties), also when stored as a JSON string.
fn name_values(v: Option<&Value>) -> Vec<(String, String)> {
    let parsed;
    let arr = match v {
        Some(Value::Array(a)) => a,
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Array(a)) => {
                parsed = a;
                &parsed
            }
            _ => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    arr.iter()
        .filter_map(|e| {
            let o = e.as_object()?;
            Some((text(o, "Name")?, text(o, "Value").unwrap_or_default()))
        })
        .collect()
}

/// Keeps the earliest day `d` of `k` in `m`.
fn first<K: Ord>(m: &mut BTreeMap<K, i64>, k: K, d: i64) {
    let e = m.entry(k).or_insert(d);
    *e = (*e).min(d);
}

fn upn(raw: &str) -> Option<String> {
    let t = raw.trim();
    (!t.is_empty()).then(|| t.to_lowercase())
}

/// Whether `ip` is in `cidr` (`a.b.c.d/n` or an IPv6 prefix).
fn in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let Some((net, len)) = cidr.split_once('/') else {
        return net_eq(ip, cidr, 128);
    };
    let Ok(len) = len.parse::<u32>() else {
        return false;
    };
    net_eq(ip, net, len)
}

fn net_eq(ip: IpAddr, net: &str, len: u32) -> bool {
    match (ip, net.parse::<IpAddr>()) {
        (IpAddr::V4(a), Ok(IpAddr::V4(b))) => {
            let len = len.min(32);
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), Ok(IpAddr::V6(b))) => {
            let len = len.min(128);
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// The built-in rule pack, loaded once.
fn pack() -> Result<&'static sparrow_core::detect::load::RuleSet> {
    static SET: std::sync::OnceLock<
        std::result::Result<sparrow_core::detect::load::RuleSet, String>,
    > = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        sparrow_core::detect::load::load_rules(&sparrow_core::data::DataDirs::default())
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| Error::Core(e.clone()))
}

/// The SQL of rule `rule_id` (built-in pack), and where `fragment` occurs in it: exactly once, so a
/// rewritten rule fails here instead of drifting from the model.
fn locate(rule_id: &str, fragment: &str) -> Result<(&'static str, usize)> {
    let rule = pack()?
        .rules
        .iter()
        .find(|r| r.rule.id == rule_id)
        .ok_or_else(|| Error::Invalid(format!("{rule_id}: no rule file")))?;
    let sparrow_core::detect::rule::RuleBody::Sql { sql } = &rule.rule.body else {
        return Err(Error::Invalid(format!("{rule_id}: not a sql rule")));
    };
    let found: Vec<usize> = sql.match_indices(fragment).map(|(i, _)| i).collect();
    let [at] = found.as_slice() else {
        return Err(Error::Invalid(format!(
            "{rule_id}: {fragment:?} occurs {} times in the rule's SQL, expected once (the computed expectations read the threshold there)",
            found.len()
        )));
    };
    Ok((sql.as_str(), *at))
}

fn number(rule_id: &str, fragment: &str, text: &str) -> Result<f64> {
    text.parse::<f64>().map_err(|_| {
        Error::Invalid(format!(
            "{rule_id}: no number next to {fragment:?} in the rule's SQL"
        ))
    })
}

fn is_number_char(c: char) -> bool {
    c.is_ascii_digit() || c == '.'
}

/// The one number that follows `before` in the SQL of rule `rule_id` (built-in pack).
pub fn rule_number(rule_id: &str, before: &str) -> Result<f64> {
    let (sql, at) = locate(rule_id, before)?;
    let rest = &sql[at + before.len()..];
    let end = rest.find(|c| !is_number_char(c)).unwrap_or(rest.len());
    number(rule_id, before, &rest[..end])
}

/// The one number that precedes `after` in the SQL of rule `rule_id` (built-in pack), for a
/// constant whose distinctive context follows it (the Earth radius before `* asin(`).
pub fn rule_number_before(rule_id: &str, after: &str) -> Result<f64> {
    let (sql, at) = locate(rule_id, after)?;
    let head = &sql[..at];
    let start = head.rfind(|c| !is_number_char(c)).map_or(0, |i| i + 1);
    number(rule_id, after, &head[start..])
}

/// The values of a list of the built-in pack.
fn pack_list(name: &str) -> Result<Vec<String>> {
    pack()?
        .lists
        .get(name)
        .cloned()
        .ok_or_else(|| Error::Invalid(format!("list {name} not found")))
}

impl Facts {
    /// The facts of the tree `out` that `collector` wrote from `world`. What each collector's rows
    /// carry (checked against ingested cases by `tests/oracle.rs`):
    /// - sign-ins: Hawk 4 writes the Graph v1.0 schema, which has no session id, user agent, auth
    ///   requirement or MFA detail; the portal export has no risk column; the others carry the event.
    /// - UAL records: the record's own AuditData (Hawk 3's eDiscovery log keeps eight of its columns),
    ///   read as Sparrow's normalizer reads it (UserId,
    ///   ClientIP / ClientIPAddress / ActorIpAddress, SessionId else AppAccessContext.AADSessionId,
    ///   AppId / ApplicationId, UserAgent else ExtendedProperties UserAgent else ClientInfoString).
    /// - admin audit rows (Hawk 3's Exchange admin cmdlets): the cmdlet, its caller and run time.
    pub fn build(world: &World, collector: Collector, out: &TreeOutcome) -> Result<Facts> {
        let none = BTreeSet::new();
        let keys = |t: &str| out.row_keys.get(t).unwrap_or(&none);
        let (sk, uk, ak) = (
            keys("signins"),
            keys("ual_events"),
            keys("admin_audit_events"),
        );
        let mut signins = Vec::new();
        let mut ual = Vec::new();
        let mut admin = Vec::new();
        for day in crate::writers::window_days(world) {
            for s in &day.signins {
                let key = crate::keys::signin(s.id);
                if sk.contains(&key) {
                    signins.push(signin_row(collector, s, key));
                }
            }
            for u in &day.ual {
                let key = crate::keys::ual(u.id);
                if uk.contains(&key) {
                    ual.push(ual_row(collector, u, key));
                }
                let akey = crate::keys::admin_audit_of(u);
                if ak.contains(&akey) {
                    admin.push(AdminRow {
                        key: akey,
                        t: u.time.timestamp_millis(),
                        caller: upn(&u.user_id),
                        cmdlet: u.operation.trim().to_lowercase(),
                    });
                }
            }
        }
        let dirs = sparrow_core::data::DataDirs::default();
        let hosting: BTreeSet<u32> = sparrow_core::data::hosting_asns(&dirs)
            .map_err(core)?
            .into_iter()
            .map(|a| a.asn)
            .collect();
        let ms: Vec<String> = sparrow_core::data::ms365_ranges(&dirs)
            .map_err(core)?
            .ranges
            .into_iter()
            .map(|r| r.cidr)
            .collect();
        let located = crate::geo::locations(world);
        let mut ips = BTreeMap::new();
        let addresses = signins
            .iter()
            .map(|s| s.ip)
            .chain(ual.iter().filter_map(|u| u.ip))
            .collect::<BTreeSet<_>>();
        for ip in addresses {
            let mut f = IpFacts {
                microsoft: ms.iter().any(|c| in_cidr(ip, c)),
                ..IpFacts::default()
            };
            if let Some(l) = located.get(&ip) {
                f.lat = Some(l.lat);
                f.lon = Some(l.lon);
                f.country = (!l.country_iso.is_empty()).then(|| l.country_iso.clone());
                f.asn = Some(l.asn);
                f.hosting = hosting.contains(&l.asn);
            }
            ips.insert(ip, f);
        }
        let codes = sparrow_core::profile::spray::credential_failure_codes(&dirs)
            .map_err(core)?
            .into_iter()
            .collect();
        let agents = pack_list("suspicious_user_agents")?
            .into_iter()
            .filter(|a| !a.is_empty())
            .map(|a| a.to_lowercase())
            .collect();
        let mut f = Facts {
            collector,
            signins,
            ual,
            admin,
            ips,
            spray: BTreeSet::new(),
            cloud: BTreeSet::new(),
            first_party: pack_list(sparrow_core::profile::cloud_services::FIRST_PARTY_LIST)?
                .into_iter()
                .map(|a| a.trim().to_lowercase())
                .collect(),
            codes,
            agents,
        };
        f.spray = f.spray_sources();
        f.cloud = f.cloud_services();
        Ok(f)
    }

    /// What `ip_intel` holds for each address of the delivered sign-ins and UAL records.
    pub fn ip_facts(&self) -> &BTreeMap<IpAddr, IpFacts> {
        &self.ips
    }

    fn ip(&self, ip: IpAddr) -> IpFacts {
        self.ips.get(&ip).cloned().unwrap_or_default()
    }

    fn credential_failure(&self, s: &SignInRow) -> bool {
        s.interactive && self.codes.contains(&s.error)
    }

    /// `spray_sources` (`sparrow_core::profile::spray`): per address, the users with an interactive
    /// credential failure there; a user is excused by a success there before their first failure, or
    /// within the typo window after one of their failures; the address is a source when the sprayed
    /// (not excused) users reach the minimum and outnumber the successful users less the takeovers.
    fn spray_sources(&self) -> BTreeSet<IpAddr> {
        use sparrow_core::profile::spray::{MIN_USERS, TYPO_MINUTES};
        let typo = TYPO_MINUTES * 60_000;
        let rows: Vec<&SignInRow> = self.signins.iter().filter(|s| s.upn.is_some()).collect();
        let mut fails: BTreeMap<(IpAddr, &str), Vec<i64>> = BTreeMap::new();
        let mut oks: BTreeMap<(IpAddr, &str), Vec<i64>> = BTreeMap::new();
        for s in &rows {
            let u = s.upn.as_deref().unwrap_or_default();
            if self.credential_failure(s) {
                fails.entry((s.ip, u)).or_default().push(s.t);
            }
            if s.error == 0 {
                oks.entry((s.ip, u)).or_default().push(s.t);
            }
        }
        let mut sprayed: BTreeMap<IpAddr, (i64, i64)> = BTreeMap::new();
        for ((ip, u), ft) in &fails {
            let first = ft.iter().copied().min().unwrap_or_default();
            let ok = oks.get(&(*ip, *u));
            let excused = ok.is_some_and(|ot| {
                ot.iter()
                    .any(|o| *o < first || ft.iter().any(|x| *x < *o && *o <= *x + typo))
            });
            if !excused {
                let e = sprayed.entry(*ip).or_default();
                e.0 += 1;
                if ok.is_some() {
                    e.1 += 1;
                }
            }
        }
        let mut success_users: BTreeMap<IpAddr, i64> = BTreeMap::new();
        for (ip, _) in oks.keys() {
            *success_users.entry(*ip).or_default() += 1;
        }
        sprayed
            .into_iter()
            .filter(|(ip, (n, takeover))| {
                *n >= MIN_USERS && *n > success_users.get(ip).copied().unwrap_or(0) - takeover
            })
            .map(|(ip, _)| ip)
            .collect()
    }

    /// `cloud_services` (`sparrow_core::profile::cloud_services`): an (application, hosting ASN)
    /// with known successes of enough users on enough days that are most of the application's
    /// successes, unless enough of its users are sprayed or enough users failed from the ASN.
    fn cloud_services(&self) -> BTreeSet<(String, u32)> {
        use sparrow_core::profile::cloud_services::{
            FAILING_USERS, MIN_DAYS, MIN_USERS, SHARE_PERCENT, SPRAYED_PERCENT, SPRAYED_USERS,
        };
        let mut totals: BTreeMap<&str, i64> = BTreeMap::new();
        let mut by_asn: BTreeMap<(&str, u32), PairUse> = BTreeMap::new();
        let mut sprayed: BTreeSet<&str> = BTreeSet::new();
        let mut failed_from: BTreeMap<(&str, u32), BTreeSet<&str>> = BTreeMap::new();
        for s in &self.signins {
            let Some(u) = s.upn.as_deref() else { continue };
            let f = self.ip(s.ip);
            if self.credential_failure(s) {
                if self.spray.contains(&s.ip) {
                    sprayed.insert(u);
                }
                if let (Some(asn), false) = (f.asn, s.app.is_empty()) {
                    failed_from
                        .entry((s.app.as_str(), asn))
                        .or_default()
                        .insert(u);
                }
            }
            if s.error != 0 || s.app.is_empty() {
                continue;
            }
            *totals.entry(s.app.as_str()).or_default() += 1;
            if let (Some(asn), true) = (f.asn, f.hosting) {
                let e = by_asn.entry((s.app.as_str(), asn)).or_default();
                e.0.insert(u);
                e.1.insert(s.t.div_euclid(86_400_000));
                e.2 += 1;
            }
        }
        let mut out = BTreeSet::new();
        for ((app, asn), (users, days, hosting)) in by_asn {
            let n_sprayed = users.iter().filter(|u| sprayed.contains(*u)).count();
            let n_failing = failed_from.get(&(app, asn)).map_or(0, BTreeSet::len);
            let disqualified = self.first_party.contains(app)
                || (n_sprayed > 0 && n_sprayed * 100 >= users.len() * SPRAYED_PERCENT)
                || n_sprayed >= SPRAYED_USERS
                || n_failing >= FAILING_USERS;
            if !disqualified
                && users.len() >= MIN_USERS
                && days.len() >= MIN_DAYS
                && hosting * 100 >= totals[app] * SHARE_PERCENT
            {
                out.insert((app.to_string(), asn));
            }
        }
        out
    }

    /// The records a rule modelled by `cond` triggers on, in this tree.
    pub fn triggers(&self, cond: Condition) -> Result<BTreeSet<Record>> {
        match cond {
            Condition::ImpossibleTravel => self.impossible_travel(),
            Condition::AitmIndicators => self.aitm_indicators(),
            Condition::NewNetworkSend => self.new_network_send(),
            Condition::RiskyRuleCorrelation => self.risky_rule_correlation(),
        }
    }

    /// SPW-ID-003. Events: successful sign-ins and UAL UserLoggedIn of a user, located, not a
    /// Microsoft address, not a cloud service's sign-in to its application from its ASN (unless the
    /// address is a spray source). Per user in time order (ties by table, then key), each event with
    /// the one before it when the address changed: a pair at least the minimum distance apart whose
    /// implied speed is above the maximum (time floored), and, when both ends are in one country, an
    /// end that is hosting or a spray source. The trigger is the later event, or the earlier one
    /// when only it is hosting.
    fn impossible_travel(&self) -> Result<BTreeSet<Record>> {
        const R: &str = "SPW-ID-003";
        let min_km = rule_number(R, "WHERE km >= ")?;
        let max_kmh = rule_number(R, "AND km / hours > ")?;
        let floor_s = rule_number(R, "/ 1000.0, ")?;
        let radius = rule_number_before(R, " * asin(sqrt(least(1.0,")?;
        struct Ev<'a> {
            t: i64,
            src: &'static str,
            key: &'a str,
            ip: IpAddr,
            f: IpFacts,
            spray: bool,
        }
        let excused = |app: Option<&str>, f: &IpFacts, ip: IpAddr| {
            f.asn.is_some_and(|asn| {
                self.cloud.contains(&(app.unwrap_or("").to_string(), asn))
                    && !self.spray.contains(&ip)
            })
        };
        let mut by_user: BTreeMap<&str, Vec<Ev>> = BTreeMap::new();
        let usable = |f: &IpFacts| f.lat.is_some() && f.lon.is_some() && !f.microsoft;
        for s in &self.signins {
            let (Some(u), f) = (s.upn.as_deref(), self.ip(s.ip)) else {
                continue;
            };
            if s.error != 0 || !usable(&f) || excused(Some(&s.app), &f, s.ip) {
                continue;
            }
            by_user.entry(u).or_default().push(Ev {
                t: s.t,
                src: "signins",
                key: &s.key,
                ip: s.ip,
                spray: self.spray.contains(&s.ip),
                f,
            });
        }
        for x in &self.ual {
            let (Some(u), Some(ip)) = (x.upn.as_deref(), x.ip) else {
                continue;
            };
            let f = self.ip(ip);
            if x.op != "userloggedin" || !usable(&f) || excused(x.app.as_deref(), &f, ip) {
                continue;
            }
            by_user.entry(u).or_default().push(Ev {
                t: x.t,
                src: "ual_events",
                key: &x.key,
                ip,
                spray: self.spray.contains(&ip),
                f,
            });
        }
        let mut out = BTreeSet::new();
        for evs in by_user.values_mut() {
            evs.sort_by(|a, b| (a.t, a.src, a.key).cmp(&(b.t, b.src, b.key)));
            for w in evs.windows(2) {
                let (p, e) = (&w[0], &w[1]);
                if p.ip == e.ip {
                    continue;
                }
                let (plat, plon, lat, lon) = (
                    p.f.lat.unwrap_or_default(),
                    p.f.lon.unwrap_or_default(),
                    e.f.lat.unwrap_or_default(),
                    e.f.lon.unwrap_or_default(),
                );
                let h = ((lat - plat).to_radians() / 2.0).sin().powi(2)
                    + plat.to_radians().cos()
                        * lat.to_radians().cos()
                        * ((lon - plon).to_radians() / 2.0).sin().powi(2);
                let km = 2.0 * radius * h.min(1.0).sqrt().asin();
                let hours = ((e.t - p.t) as f64 / 1000.0).max(floor_s) / 3600.0;
                let same_country =
                    matches!((&e.f.country, &p.f.country), (Some(a), Some(b)) if a == b);
                let infra = e.f.hosting || p.f.hosting || e.spray || p.spray;
                if km >= min_km && km / hours > max_kmh && (infra || !same_country) {
                    let t = if p.f.hosting && !e.f.hosting { p } else { e };
                    out.insert((t.src.to_string(), t.key.to_string()));
                }
            }
        }
        Ok(out)
    }

    /// SPW-ID-004. session_moved: a sign-in or UAL record carrying the session of an interactive,
    /// successful MFA sign-in, after it and within the window, from another address on another
    /// network (the country differs; or the ASN differs and an end is hosting or a spray source, or
    /// the use is a risky sign-in; or an ASN is unknown and the countries are not known to differ);
    /// never a Microsoft address. suspicious_user_agent: a successful sign-in, or a UAL UserLoggedIn,
    /// MailboxLogin or MailItemsAccessed, whose user agent contains a listed agent.
    fn aitm_indicators(&self) -> Result<BTreeSet<Record>> {
        let window = rule_number("SPW-ID-004", "epoch_ms(c.t) + ")? as i64;
        let mut out = BTreeSet::new();
        let creators: Vec<&SignInRow> = self
            .signins
            .iter()
            .filter(|s| s.session.is_some() && s.error == 0 && s.interactive && s.mfa)
            .collect();
        struct Use<'a> {
            src: &'static str,
            key: &'a str,
            t: i64,
            ip: Option<IpAddr>,
            session: &'a str,
            risky: bool,
        }
        let uses = self
            .signins
            .iter()
            .filter_map(|s| {
                Some(Use {
                    src: "signins",
                    key: &s.key,
                    t: s.t,
                    ip: Some(s.ip),
                    session: s.session.as_deref()?,
                    risky: s.risky,
                })
            })
            .chain(self.ual.iter().filter_map(|u| {
                Some(Use {
                    src: "ual_events",
                    key: &u.key,
                    t: u.t,
                    ip: u.ip,
                    session: u.session.as_deref()?,
                    risky: false,
                })
            }));
        for x in uses {
            let Some(xip) = x.ip else { continue };
            for c in creators
                .iter()
                .filter(|c| c.session.as_deref() == Some(x.session))
            {
                if x.key == c.key || xip == c.ip || x.t <= c.t || x.t > c.t + window {
                    continue;
                }
                let (fx, fc) = (self.ip(xip), self.ip(c.ip));
                if fx.microsoft || fc.microsoft {
                    continue;
                }
                let asn_changed = matches!((fx.asn, fc.asn), (Some(a), Some(b)) if a != b);
                let country_changed =
                    matches!((&fx.country, &fc.country), (Some(a), Some(b)) if a != b);
                let unknown = (fx.asn.is_none() || fc.asn.is_none()) && !country_changed;
                let infra = fx.hosting
                    || fc.hosting
                    || self.spray.contains(&xip)
                    || self.spray.contains(&c.ip);
                if unknown || country_changed || (asn_changed && (infra || x.risky)) {
                    out.insert((x.src.to_string(), x.key.to_string()));
                }
            }
        }
        let scripted = |ua: &str| {
            let ua = ua.to_lowercase();
            self.agents.iter().any(|a| ua.contains(a.as_str()))
        };
        for s in &self.signins {
            if s.error == 0 && scripted(&s.user_agent) {
                out.insert(("signins".to_string(), s.key.clone()));
            }
        }
        for u in &self.ual {
            if matches!(
                u.op.as_str(),
                "userloggedin" | "mailboxlogin" | "mailitemsaccessed"
            ) && u.user_agent.as_deref().is_some_and(scripted)
            {
                out.insert(("ual_events".to_string(), u.key.clone()));
            }
        }
        Ok(out)
    }

    /// SPW-MAIL-006. A UAL Send / SendAs / SendOnBehalf, not from a Microsoft address, from an
    /// address the user never used on an earlier day, that is hosting or a spray source (whatever the
    /// user's history, a brand-new account's first send included); or, by a user with activity (any UAL
    /// record or sign-in with an address) on enough earlier UTC days, from a network (ASN, else the
    /// address) never used on an earlier day that also has no country, a country never seen on an
    /// earlier day, or follows a risky sign-in of the user within the look-back.
    fn new_network_send(&self) -> Result<BTreeSet<Record>> {
        const R: &str = "SPW-MAIL-006";
        let min_days = rule_number(R, "epoch_ms(s.event_time) // 86400000) >= ")? as usize;
        let lookback = rule_number(R, "epoch_ms(s.event_time) - ")? as i64;
        let day = |t: i64| t.div_euclid(86_400_000);
        let net = |ip: IpAddr, f: &IpFacts| match f.asn {
            Some(a) => a.to_string(),
            None => ip.to_string(),
        };
        // Per user: the first day of each address, network and country, and the active days.
        #[derive(Default)]
        struct Hist {
            ip: BTreeMap<IpAddr, i64>,
            net: BTreeMap<String, i64>,
            cc: BTreeMap<String, i64>,
            days: BTreeSet<i64>,
        }
        let mut hist: BTreeMap<&str, Hist> = BTreeMap::new();
        let acts = self
            .ual
            .iter()
            .filter_map(|u| Some((u.upn.as_deref()?, u.t, u.ip?)))
            .chain(
                self.signins
                    .iter()
                    .filter_map(|s| Some((s.upn.as_deref()?, s.t, s.ip))),
            );
        for (u, t, ip) in acts {
            let d = day(t);
            let f = self.ip(ip);
            let h = hist.entry(u).or_default();
            first(&mut h.ip, ip, d);
            first(&mut h.net, net(ip, &f), d);
            if let Some(cc) = f.country.clone() {
                first(&mut h.cc, cc, d);
            }
            h.days.insert(d);
        }
        let mut out = BTreeSet::new();
        for s in &self.ual {
            if !matches!(s.op.as_str(), "send" | "sendas" | "sendonbehalf") {
                continue;
            }
            let (Some(u), Some(ip)) = (s.upn.as_deref(), s.ip) else {
                continue;
            };
            let f = self.ip(ip);
            if f.microsoft {
                continue;
            }
            let Some(h) = hist.get(u) else { continue };
            let d = day(s.t);
            let earlier = |first: Option<&i64>| first.is_some_and(|f| *f < d);
            if earlier(h.ip.get(&ip)) {
                continue;
            }
            // Hosting and spray-source sends are judged whatever the history (a brand-new account's
            // first send); the new-network path needs `min_days` earlier active days.
            let history = h.days.iter().filter(|x| **x < d).count() >= min_days;
            let qualifies = f.hosting
                || self.spray.contains(&ip)
                || (history
                    && !earlier(h.net.get(&net(ip, &f)))
                    && (f.country.as_ref().is_none_or(|cc| !earlier(h.cc.get(cc)))
                        || self.signins.iter().any(|r| {
                            r.upn.as_deref() == Some(u)
                                && r.risky
                                && r.t <= s.t
                                && r.t >= s.t - lookback
                        })));
            if qualifies {
                out.insert(("ual_events".to_string(), s.key.clone()));
            }
        }
        Ok(out)
    }

    /// SPW-ID-010. A UAL New-InboxRule / Set-InboxRule / UpdateInboxRules, or an admin audit
    /// New-InboxRule / Set-InboxRule, whose actor had within the window before it a sign-in rated
    /// medium/high risk or from a hosting address, or a UAL UserLoggedIn from a hosting address. A
    /// hosting sign-in or logon of a cloud service's application from its ASN does not count unless
    /// the address is a spray source (the rule header names this exclusion), and the hosting arm
    /// counts only a successful sign-in (error 0) or a logon whose result is not Failed; the risk
    /// arm has neither condition. The hosting arm also ties the rule record's own client address to the
    /// infrastructure (see the rule header); the synthetic admin audit rows (Hawk 3 `Search-AdminAuditLog`
    /// summaries) carry no address, so they are never excluded by it.
    fn risky_rule_correlation(&self) -> Result<BTreeSet<Record>> {
        let window = rule_number("SPW-ID-010", "epoch_ms(r.event_time) - ")? as i64;
        // A hosting address that is not a cloud service's own sign-in to `app` from its ASN.
        let hosting = |ip: IpAddr, app: &str| {
            let f = self.ip(ip);
            f.hosting
                && !(f
                    .asn
                    .is_some_and(|asn| self.cloud.contains(&(app.to_string(), asn)))
                    && !self.spray.contains(&ip))
        };
        // Per actor: (time, the hosting sign-in's ASN when it is a hosting-arm entry). The risk arm
        // has no ASN and no tie.
        let mut risky: BTreeMap<&str, Vec<Preceding>> = BTreeMap::new();
        for s in &self.signins {
            if let Some(u) = s.upn.as_deref() {
                if s.risky {
                    risky.entry(u).or_default().push((s.t, None));
                }
                if s.error == 0 && hosting(s.ip, &s.app) {
                    risky
                        .entry(u)
                        .or_default()
                        .push((s.t, Some(self.ip(s.ip).asn)));
                }
            }
        }
        for x in &self.ual {
            if let (Some(u), Some(ip), "userloggedin") = (x.upn.as_deref(), x.ip, x.op.as_str()) {
                if !x.failed && hosting(ip, x.app.as_deref().unwrap_or("")) {
                    risky
                        .entry(u)
                        .or_default()
                        .push((x.t, Some(self.ip(ip).asn)));
                }
            }
        }
        // The hosting arm's tie to the rule record's own address: no address, an address of unknown
        // ASN or a Microsoft one is not compared; otherwise the hosting sign-in's ASN, any hosting
        // ASN, or a spray source.
        let tied = |ip: Option<IpAddr>, arm: Option<Option<u32>>| {
            let (Some(ip), Some(asn)) = (ip, arm) else {
                return true;
            };
            let f = self.ip(ip);
            f.asn.is_none() || f.microsoft || f.asn == asn || f.hosting || self.spray.contains(&ip)
        };
        let preceded = |actor: Option<&str>, t: i64, ip: Option<IpAddr>| {
            actor.and_then(|a| risky.get(a)).is_some_and(|ts| {
                ts.iter()
                    .any(|(s, arm)| *s <= t && *s >= t - window && tied(ip, *arm))
            })
        };
        let mut out = BTreeSet::new();
        for u in &self.ual {
            if matches!(
                u.op.as_str(),
                "new-inboxrule" | "set-inboxrule" | "updateinboxrules"
            ) && preceded(u.upn.as_deref(), u.t, u.ip)
            {
                out.insert(("ual_events".to_string(), u.key.clone()));
            }
        }
        for a in &self.admin {
            if matches!(a.cmdlet.as_str(), "new-inboxrule" | "set-inboxrule")
                && preceded(a.caller.as_deref(), a.t, None)
            {
                out.insert(("admin_audit_events".to_string(), a.key.clone()));
            }
        }
        Ok(out)
    }
}

fn signin_row(collector: Collector, s: &SignIn, key: String) -> SignInRow {
    let hawk4 = collector == Collector::Hawk4;
    let mfa = s.auth_requirement.to_lowercase().starts_with("multifactor")
        || s.mfa
            .as_ref()
            .is_some_and(|m| m.1.to_lowercase().contains("mfa successfully completed"));
    SignInRow {
        key,
        t: s.time.timestamp_millis(),
        upn: upn(&s.user),
        ip: s.ip,
        error: s.error_code,
        interactive: s.event_type == SignInType::Interactive,
        session: (!hawk4 && !s.session_id.is_nil()).then(|| s.session_id.to_string()),
        mfa: !hawk4 && mfa,
        risky: collector != Collector::Portal
            && matches!(s.risk_during.to_lowercase().as_str(), "medium" | "high"),
        app: s.app_id.to_string().to_lowercase(),
        user_agent: if hawk4 {
            String::new()
        } else {
            s.user_agent.clone()
        },
    }
}

fn ual_row(collector: Collector, u: &Ual, key: String) -> UalRow {
    // Hawk 3 delivers Discovery records only in eDiscoveryLogs.csv, whose eight columns carry no
    // address, session, application or client (`writers::hawk::v3::ediscovery_logs`).
    let kept: Map<String, Value>;
    let a =
        if collector == Collector::Hawk3 && u.record_type == crate::events::RecordType::Discovery {
            kept = [
                "CreationTime",
                "Id",
                "Operation",
                "Workload",
                "UserId",
                "Case",
                "CaseID",
                "Cmdlet",
            ]
            .iter()
            .filter_map(|k| u.audit.get(*k).map(|v| (k.to_string(), v.clone())))
            .collect();
            &kept
        } else {
            &u.audit
        };
    let user_agent = text(a, "UserAgent")
        .or_else(|| {
            name_values(get_ci(a, "ExtendedProperties"))
                .into_iter()
                .find(|(n, v)| n.eq_ignore_ascii_case("UserAgent") && !v.is_empty())
                .map(|(_, v)| v)
        })
        .or_else(|| text(a, "ClientInfoString"));
    UalRow {
        key,
        t: u.time.timestamp_millis(),
        upn: text(a, "UserId").and_then(|s| upn(&s)),
        ip: ["ClientIP", "ClientIPAddress", "ActorIpAddress"]
            .iter()
            .find_map(|k| text(a, k))
            .and_then(|s| s.parse().ok()),
        op: text(a, "Operation").unwrap_or_default().to_lowercase(),
        session: text(a, "SessionId").or_else(|| match get_ci(a, "AppAccessContext") {
            Some(Value::Object(o)) => text(o, "AADSessionId"),
            _ => None,
        }),
        app: ["AppId", "ApplicationId"]
            .iter()
            .find_map(|k| text(a, k))
            .map(|s| s.to_lowercase()),
        user_agent,
        failed: text(a, "ResultStatus").is_some_and(|r| r.eq_ignore_ascii_case("failed")),
    }
}
