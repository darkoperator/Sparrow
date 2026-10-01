//! The storyline engine: applies a scenario's storylines and look-alikes to the world in time
//! order. Each one changes the world at its time (a consent grant, an MFA method, a mobile
//! device...), appends the events Microsoft 365 would have recorded to `world.story`, and returns
//! its ground truth: every evidence item it produced, including records Microsoft 365 does not
//! log under the tenant's audit settings (`World::logged`); the manifest decides per tree
//! whether each was delivered. Which rules a kind must or must not trigger comes from
//! `rules/coverage.yaml` (`coverage`).
//!
//! Every storyline draws from its own stream `story/<id>`, so adding one never changes another.

mod apps;
mod config;
mod files;
mod identity;
mod mail;
mod negatives;
mod spray;

use crate::events::{
    Actor, DirAudit, RecordType, RiskDetection, SignIn, SignInType, Target, TraceMsg, Ual,
};
use crate::reserved::{IpAllocator, Net, WELL_KNOWN_GUIDS};
use crate::rng::{Rng, stream};
use crate::scenario::{Polarity, StoryKind, StorySpec};
use crate::ual;
use crate::world::{Client, Location, User, World};
use crate::{Error, Result};
use chrono::{DateTime, NaiveDate, Utc};
use std::collections::BTreeSet;
use std::net::IpAddr;
use uuid::Uuid;

/// Modified properties of a directory change: (name, old value, new value), as JSON text.
pub(crate) type Modified = Vec<(String, String, String)>;

/// What a storyline produced, independent of any collector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Evidence {
    Ual(Uuid),
    SignIn(Uuid),
    DirAudit(String),
    Trace {
        trace_id: Uuid,
        recipient: String,
    },
    Risk(String),
    RiskyUser(String),
    InboxRule {
        mailbox: String,
        identity: String,
        graph_id: String,
    },
    Mailbox(String),
    Grant {
        client_app_id: Uuid,
        scope: String,
        principal: Option<String>,
    },
    Credential {
        app_object_id: Uuid,
        key_id: Uuid,
        on_service_principal: bool,
    },
    MobileDevice {
        mailbox: String,
        device_id: String,
    },
    TransportRule(String),
    MailboxPermission {
        mailbox: String,
        grantee: String,
        right: String,
        /// `calendar` / `inbox` for a folder grant.
        folder: Option<String>,
    },
    Email(String),
    AuditConfig,
    Mfa(String),
}

/// The ground truth of one applied storyline or look-alike.
#[derive(Debug, Clone)]
pub struct StoryRecord {
    pub id: String,
    pub kind: StoryKind,
    pub polarity: Polarity,
    /// The UPN of the storyline's user (for admin-performed kinds, the affected user).
    pub actor: String,
    pub time: DateTime<Utc>,
    pub evidence: Vec<Evidence>,
    /// The storyline this one is anchored `after` in the scenario (`at: {after: ..}`): the
    /// explicit correlated source of a half its own evidence does not carry.
    pub after: Option<String>,
}

/// One storyline being applied: its spec, resolved time, the affected user and the evidence
/// collected so far.
pub(crate) struct Ctx<'a> {
    pub spec: &'a StorySpec,
    pub t: DateTime<Utc>,
    /// The storyline's user (`actor`, default user 1).
    pub a: User,
    pub rng: Rng,
    pub ev: Vec<Evidence>,
    /// Roaming addresses already handed out and the sign-ins of the day, shared by every
    /// storyline of the world.
    pub shared: &'a mut Shared,
}

/// What every storyline of a world shares: the roaming addresses already handed out, and the
/// users that have already signed in on a day.
#[derive(Default)]
pub(crate) struct Shared {
    alloc: IpAllocator,
    used: u32,
    /// Attacker pool addresses already handed out.
    attacker_used: usize,
    /// Shared office / gateway egress addresses already handed out.
    egress_used: u8,
    /// (UPN, day) of the sign-ins the storylines have already recorded.
    signed_today: BTreeSet<(String, NaiveDate)>,
}

impl Shared {
    /// The next travel / mobile / cloud look-alike address: RFC 5737 TEST-NET-2 hosts for the
    /// first 254, then RFC 3849 addresses of the roaming role, so no address ever carries two
    /// locations.
    pub fn next_ip(&mut self) -> IpAddr {
        self.used += 1;
        if self.used <= 254 {
            IpAddr::V4(self.alloc.v4(Net::Roaming))
        } else {
            IpAddr::V6(self.alloc.v6(Net::Roaming))
        }
    }

    /// The next shared egress address of an office, a secure web gateway or a conference network
    /// (RFC 5737 TEST-NET-1 hosts 200 and up, above every person's office and home address): a
    /// benign pool of its own, apart from the roaming one (a traveller or mobile user) and the
    /// attacker's.
    pub fn next_egress(&mut self) -> IpAddr {
        self.egress_used += 1;
        IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 200 + self.egress_used))
    }

    /// The next attacker-pool address (`Attacker::pool`): attacker infrastructure never uses
    /// `next_ip`, which stands for a benign traveller or mobile user.
    pub fn next_attacker(&mut self, pool: &[IpAddr]) -> Result<IpAddr> {
        let ip = pool
            .get(self.attacker_used)
            .copied()
            .ok_or_else(|| Error::Scenario("the attacker address pool is exhausted".to_string()))?;
        self.attacker_used += 1;
        Ok(ip)
    }

    /// The next RFC 3849 address of the roaming role (a rotating IPv6 privacy address).
    pub fn next_v6(&mut self) -> std::net::Ipv6Addr {
        self.alloc.v6(Net::Roaming)
    }

    /// Records this sign-in and answers whether it is the user's first of that day among the
    /// storylines' sign-ins (the fresh-authentication case a `UserAuthenticationMethod` code
    /// marks). The baseline counts its own sign-ins separately: it is a pure function of the
    /// world, so a user with a storyline sign-in early in a day can hold a first-of-day code
    /// from both.
    pub fn first_sign_in_of_day(&mut self, upn: &str, day: NaiveDate) -> bool {
        self.signed_today.insert((upn.to_string(), day))
    }
}

/// Applies every storyline and look-alike of `world.scenario` in resolved time order (ties by
/// id) and returns their ground truth in that order. Call once per world.
pub fn apply(world: &mut World) -> Result<Vec<StoryRecord>> {
    let scenario = world.scenario.clone();
    let mut out = Vec::new();
    let mut shared = Shared::default();
    for spec in scenario.story_order()? {
        let t = scenario.story_time(&spec.id)?;
        let a = world.user(spec.actor.unwrap_or(1)).clone();
        let mut ctx = Ctx {
            spec,
            t,
            a,
            rng: stream(world.seed, &format!("story/{}", spec.id)),
            ev: Vec::new(),
            shared: &mut shared,
        };
        let handled = identity::apply_one(world, &mut ctx)?
            || apps::apply_one(world, &mut ctx)?
            || spray::apply_one(world, &mut ctx)?
            || mail::apply_one(world, &mut ctx)?
            || files::apply_one(world, &mut ctx)?
            || negatives::apply_one(world, &mut ctx)?
            || config::apply_one(world, &mut ctx)?;
        if !handled {
            return Err(Error::Scenario(format!(
                "kind {} has no storyline handler",
                spec.kind.as_str()
            )));
        }
        out.push(StoryRecord {
            id: spec.id.clone(),
            kind: spec.kind,
            polarity: spec.kind.polarity(),
            actor: ctx.a.upn.clone(),
            time: t,
            evidence: ctx.ev,
            after: match &spec.at {
                crate::scenario::At::After { after, .. } => Some(after.clone()),
                _ => None,
            },
        });
    }
    attribute_trips(world, &mut out);
    Ok(out)
}

/// The baseline keeps a traveller at the destination from the arrival to the end of the window (a
/// `Trip`): the sends and every other event from the trip address on the trip days are part of the
/// `plausible_travel` storyline's trip, not background. They are the storyline's evidence, so the
/// gate sees their kind (a traveller's first send on arrival day in a new country is a new network
/// and a new country by SPW-MAIL-006's logic, a documented limitation).
fn attribute_trips(world: &World, records: &mut [StoryRecord]) {
    for r in records
        .iter_mut()
        .filter(|r| r.kind == StoryKind::PlausibleTravel)
    {
        let Some(trip) = world
            .trips
            .iter()
            .find(|t| t.user == r.actor && t.arrival == r.time)
        else {
            continue;
        };
        let mut date = trip.arrival.date_naive();
        let last = world.window_end().date_naive();
        while date <= last {
            let day = crate::baseline::day(world, date);
            for u in day.ual.iter().filter(|u| world.logged(u)) {
                let ip = u.client_ip().and_then(|t| t.parse::<IpAddr>().ok());
                // Exchange admin cmdlets render as admin-audit rows in Hawk 3, which key them from the
                // cmdlet record the storylines build: the trip's baseline never carries one.
                if u.record_type != RecordType::ExchangeAdmin
                    && u.time >= trip.arrival
                    && ip == Some(trip.ip)
                    && u.user_id.eq_ignore_ascii_case(&trip.user)
                {
                    r.evidence.push(Evidence::Ual(u.id));
                }
            }
            for s in &day.signins {
                if s.time >= trip.arrival && s.ip == trip.ip && s.user == trip.user {
                    r.evidence.push(Evidence::SignIn(s.id));
                }
            }
            date = date.succ_opt().expect("date in range");
        }
    }
}

pub(crate) fn well_known(desc: &str) -> Uuid {
    WELL_KNOWN_GUIDS
        .iter()
        .find(|(_, d)| *d == desc)
        .unwrap_or_else(|| panic!("story: unknown well-known app '{desc}'"))
        .0
        .parse()
        .expect("well-known guid parses")
}

/// The performer of admin kinds: the first admin.
pub(crate) fn first_admin(w: &World) -> Result<User> {
    w.admins
        .first()
        .cloned()
        .ok_or_else(|| Error::Scenario("admin-performed storylines need an admin".into()))
}

/// The world's app named `name` (index into `w.apps`).
pub(crate) fn app_index(w: &World, pred: impl Fn(&str) -> bool, what: &str) -> Result<usize> {
    w.apps
        .iter()
        .position(|a| pred(&a.display_name))
        .ok_or_else(|| Error::Scenario(format!("the tenant has no {what} app")))
}

/// A risk level as Graph shows it: the level with Entra ID P2, `hidden` without.
pub(crate) fn risk_text(w: &World, level: &str) -> String {
    if w.licence.p2() {
        level.to_string()
    } else {
        "hidden".to_string()
    }
}

/// A successful, clean sign-in of `user`: interactive ones satisfy MFA by app notification
/// (admins by FIDO2 key), non-interactive ones reuse the session's earlier authentication; risk
/// `none` (`hidden` without P2). Callers adjust the fields a storyline changes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn signin(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    ip: IpAddr,
    location: &Location,
    event_type: SignInType,
    app: Uuid,
    resource: Uuid,
    session: Uuid,
) -> SignIn {
    let risk = risk_text(w, "none");
    let interactive = event_type == SignInType::Interactive;
    let method = if user.is_admin {
        "FIDO2 security key"
    } else {
        "Mobile app notification"
    };
    let (auth_requirement, mfa, auth_methods) = if interactive {
        (
            "multiFactorAuthentication",
            Some((method.to_string(), String::new())),
            vec!["Password".to_string(), method.to_string()],
        )
    } else {
        (
            "singleFactorAuthentication",
            None,
            vec!["Previously satisfied".to_string()],
        )
    };
    let windows = user.client.os.starts_with("Windows");
    let client_app = if app == well_known("OfficeHome") {
        "Browser"
    } else {
        "Mobile Apps and Desktop clients"
    };
    SignIn {
        id: rng.uuid(),
        time,
        user: user.upn.clone(),
        user_id: Some(user.object_id),
        user_display: user.display_name.clone(),
        app_id: app,
        app_name: ual::app_name(w, app),
        resource_id: resource,
        resource_name: ual::app_name(w, resource),
        ip,
        location: location.clone(),
        user_agent: user.client.user_agent.clone(),
        client_app: client_app.to_string(),
        event_type,
        error_code: 0,
        failure_reason: "Other.".to_string(),
        ca_status: if w.licence.p1() && user.is_admin {
            "success"
        } else {
            "notApplied"
        }
        .to_string(),
        risk_during: risk.clone(),
        risk_aggregated: risk.clone(),
        risk_state: "none".to_string(),
        risk_detail: risk,
        risk_event_types: Vec::new(),
        auth_requirement: auth_requirement.to_string(),
        mfa,
        auth_methods,
        device: user.client.clone(),
        device_compliant: windows.then_some(true),
        device_managed: windows.then_some(true),
        trust_type: windows.then(|| "Azure AD joined".to_string()),
        session_id: session,
        correlation_id: rng.uuid(),
        unique_token_id: ual::unique_token_id(rng),
        token_issuer: "AzureAD".to_string(),
        incoming_token_type: if interactive { "none" } else { "refreshToken" }.to_string(),
        home_tenant_id: w.org_id(),
        resource_tenant_id: w.org_id(),
        asn: location.asn,
    }
}

/// A device the tenant does not know (an attacker's machine behind a proxy): the user's OS and
/// browser as the relayed user agent reports them, no device id, not compliant or managed.
pub(crate) fn unknown_device(sign_in: &mut SignIn) {
    sign_in.device = Client {
        device_id: Uuid::nil(),
        device_name: String::new(),
        ..sign_in.device.clone()
    };
    sign_in.device_compliant = None;
    sign_in.device_managed = None;
    sign_in.trust_type = None;
}

/// The target user `g` of kinds that act on a second user (`target`, default `default`).
pub(crate) fn target(w: &World, ctx: &Ctx, default: u32) -> User {
    w.user(ctx.spec.target.unwrap_or(default)).clone()
}

/// The session of the latest adversary-in-the-middle sign-in of `user` at or before `t` (the
/// proxied sign-in and the replayed token share it), else a new session.
pub(crate) fn attacker_session(w: &World, ctx: &mut Ctx, user: &User, t: DateTime<Utc>) -> Uuid {
    let proxy = w.attacker.proxy_ip;
    w.story
        .signins
        .iter()
        .filter(|s| s.user == user.upn && s.ip == proxy && s.time <= t)
        .max_by_key(|s| s.time)
        .map(|s| s.session_id)
        .unwrap_or_else(|| ctx.rng.uuid())
}

/// Records an Exchange admin cmdlet run by `actor` (`ExchangeAdmin`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn push_cmdlet(
    w: &mut World,
    ctx: &mut Ctx,
    actor: &User,
    time: DateTime<Utc>,
    cmdlet: &str,
    object_id: &str,
    params: &[(&str, &str)],
    ip: IpAddr,
    session: Uuid,
) {
    let u = ual::exchange_admin(
        w,
        &mut ctx.rng,
        actor,
        time,
        cmdlet,
        object_id,
        params,
        ip,
        session,
    );
    push_ual(w, ctx, u);
}

pub(crate) fn push_trace(w: &mut World, ctx: &mut Ctx, t: TraceMsg) {
    for (recipient, _) in &t.recipients {
        ctx.ev.push(Evidence::Trace {
            trace_id: t.trace_id,
            recipient: recipient.clone(),
        });
    }
    w.story.trace.push(t);
}

pub(crate) fn push_ual(w: &mut World, ctx: &mut Ctx, u: Ual) {
    ctx.ev.push(Evidence::Ual(u.id));
    w.story.ual.push(u);
}

/// Adds to `ctx` the evidence of the most recent attacker-proxy sign-in of `user` before `t`:
/// the sign-in and its UAL `UserLoggedIn` record, without recording a new sign-in. A correlated
/// rule's positive storyline carries the preceding risky sign-in it pairs with (SPW-ID-010); the
/// timing/actor correlation itself is Phase 6.
pub(crate) fn push_correlated_signin(w: &World, ctx: &mut Ctx, user: &User, t: DateTime<Utc>) {
    // The baseline sign-ins of the day are deterministic and are what the writers will emit, so
    // pulling the day's sign-ins here gives evidence ids that a delivery can match.
    let day = w.day(t.date_naive());
    let preceding = |s: &SignIn| s.user == user.upn && s.time <= t;
    // Prefer the attacker's proxy sign-in (the risky half of a positive); fall back to any
    // preceding sign-in so a look-alike's benign rule still carries a sign-in to correlate with.
    let Some(s) = day
        .signins
        .iter()
        .filter(|s| preceding(s) && s.ip == w.attacker.proxy_ip)
        .max_by_key(|s| s.time)
        .or_else(|| {
            day.signins
                .iter()
                .filter(|s| preceding(s))
                .max_by_key(|s| s.time)
        })
    else {
        return;
    };
    ctx.ev.push(Evidence::SignIn(s.id));
    if let Some(u) = day.ual.iter().find(|u| {
        u.user_id.eq_ignore_ascii_case(&user.upn)
            && u.time == s.time
            && u.record_type == RecordType::AzureActiveDirectoryStsLogon
    }) {
        ctx.ev.push(Evidence::Ual(u.id));
    }
}

/// Records a sign-in; with `logon`, also its UAL `UserLoggedIn` record (a `UserLoginFailed` one for a
/// failed sign-in; `request_type`
/// `OAuth2:Authorize` for interactive sign-ins, `OAuth2:Token` otherwise).
pub(crate) fn push_signin(w: &mut World, ctx: &mut Ctx, user: &User, s: SignIn, logon: bool) {
    if logon {
        let request_type = if s.event_type == SignInType::Interactive {
            "OAuth2:Authorize"
        } else {
            "OAuth2:Token"
        };
        let u = ual::sts_logon(
            w,
            &mut ctx.rng,
            user,
            s.time,
            if s.error_code == 0 {
                ual::LogonOutcome::Success
            } else {
                ual::LogonOutcome::Failure
            },
            s.ip,
            &s.user_agent,
            s.app_id,
            request_type,
            s.error_code,
            // A successful logon carries the sign-in's authentication method when it is the
            // user's first sign-in of that day; the later same-day ones were let through by
            // the session it opened. Every failed logon carries one.
            s.error_code != 0
                || ctx
                    .shared
                    .first_sign_in_of_day(&s.user, s.time.date_naive()),
        );
        push_ual(w, ctx, u);
    }
    ctx.ev.push(Evidence::SignIn(s.id));
    w.story.signins.push(s);
}

pub(crate) fn push_risk(w: &mut World, ctx: &mut Ctx, r: RiskDetection) {
    ctx.ev.push(Evidence::Risk(r.id.clone()));
    w.story.risk.push(r);
}

/// A directory audit target for `user`.
pub(crate) fn user_target(user: &User, modified: Modified) -> Target {
    Target {
        id: user.object_id.to_string(),
        display_name: user.display_name.clone(),
        kind: "User".to_string(),
        upn: Some(user.upn.clone()),
        modified,
    }
}

/// A directory change `activity` initiated by `actor` from `ip`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dir_audit(
    rng: &mut Rng,
    time: DateTime<Utc>,
    activity: &str,
    category: &str,
    operation_type: &str,
    service: &str,
    actor: &User,
    ip: IpAddr,
    targets: Vec<Target>,
) -> DirAudit {
    let correlation_id = rng.uuid();
    let id = format!(
        "Directory_{}_{}_{}",
        rng.uuid(),
        (0..5)
            .map(|_| (b'A' + rng.below(26) as u8) as char)
            .collect::<String>(),
        rng.range(10_000_000, 99_999_999)
    );
    DirAudit {
        id,
        time,
        activity: activity.to_string(),
        category: category.to_string(),
        operation_type: operation_type.to_string(),
        result: "success".to_string(),
        result_reason: String::new(),
        logged_by_service: service.to_string(),
        initiated_by: Actor {
            upn: Some(actor.upn.clone()),
            user_id: Some(actor.object_id),
            ip: Some(ip),
            app_id: None,
            app_name: None,
        },
        targets,
        additional_details: Vec::new(),
        correlation_id,
    }
}

pub(crate) fn push_audit(w: &mut World, ctx: &mut Ctx, a: DirAudit) {
    ctx.ev.push(Evidence::DirAudit(a.id.clone()));
    w.story.audits.push(a);
}

/// The UAL `AzureActiveDirectory` record of operation `op` for directory audit `a`, with the
/// audit's targets and modified properties (the same mapping the baseline uses).
pub(crate) fn aad_for(w: &World, rng: &mut Rng, a: &DirAudit, op: &str) -> Ual {
    let actor = a
        .initiated_by
        .upn
        .as_deref()
        .and_then(|upn| w.user_by_upn(upn));
    let mut target = Vec::new();
    for t in &a.targets {
        target.push((format!("{}_{}", t.kind, t.id), "2".to_string()));
        target.push((t.id.clone(), "2".to_string()));
        target.push((t.kind.clone(), "2".to_string()));
        match &t.upn {
            Some(upn) => target.push((upn.clone(), "5".to_string())),
            None => target.push((t.display_name.clone(), "1".to_string())),
        }
    }
    let modified: Modified = a.targets.iter().flat_map(|t| t.modified.clone()).collect();
    ual::aad(
        w,
        rng,
        actor,
        a.time,
        op,
        &target,
        &modified,
        a.initiated_by.ip,
        &[],
    )
}

/// Records directory audit `a` and, when `op` is given, its UAL record.
pub(crate) fn push_audit_and_ual(w: &mut World, ctx: &mut Ctx, a: DirAudit, op: Option<&str>) {
    if let Some(op) = op {
        let u = aad_for(w, &mut ctx.rng, &a, op);
        push_ual(w, ctx, u);
    }
    push_audit(w, ctx, a);
}
