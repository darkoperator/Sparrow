//! The benign baseline: ordinary work in the tenant. Sign-ins during working hours from home or
//! office, mailbox activity (Outlook's morning `MailItemsAccessed` sync, binds of received
//! messages, sends, item updates), SharePoint / OneDrive file access, mail sent and received
//! (with matching message trace rows), occasional failed sign-ins and admin configuration
//! changes. Produced per UTC day from per-day streams (`signin/<date>`, `trace/<date>`,
//! `ual/<date>`), so a long window never has to be held in memory at once.
//!
//! What Microsoft 365 logs is applied here, not in the writers: UAL ingestion, organization and
//! per-mailbox audit settings decide which UAL records exist; the licence decides whether
//! sign-in risk levels are visible.

use crate::events::{
    Actor, Day, DirAudit, RiskDetection, SignIn, SignInType, Target, TraceMsg, Ual,
};
use crate::reserved::WELL_KNOWN_GUIDS;
use crate::rng::{Rng, stream};
use crate::ual::{self, ItemRef};
use crate::world::{Location, RiskyUser, User, World};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc, Weekday};
use serde_json::json;
use std::net::{IpAddr, Ipv6Addr};
use uuid::Uuid;

const INTERNAL_SUBJECTS: &[&str] = &[
    "Weekly sync notes",
    "Re: Q3 planning",
    "Project update",
    "Lunch on Friday?",
    "Re: Budget review",
    "Updated slides",
];

const INCOMING: &[(&str, &str)] = &[
    ("orders@northwind.example", "Your order has shipped"),
    ("billing@fabrikam-supplies.example", "Invoice for September"),
    ("news@newsdigest.example", "Newsletter: industry roundup"),
    (
        "support@tailwind-traders.example",
        "Your support case was updated",
    ),
    ("events@litware.example", "Meeting request: product demo"),
];

const PARTNERS: &[(&str, &str)] = &[
    ("accounts@partner.example", "Re: Proposal"),
    ("sales@partner.example", "Contract draft"),
    ("projects@partner.example", "Follow-up from our call"),
];

const ONEDRIVE_FILES: &[&str] = &[
    "Meeting Notes.docx",
    "Status Report.docx",
    "Personal Budget.xlsx",
    "Presentation.pptx",
];

const FINANCE_FILES: &[&str] = &[
    "Q3 Forecast.xlsx",
    "Budget 2026.xlsx",
    "Vendor List.xlsx",
    "Payment Run.xlsx",
    "Invoice-10231.pdf",
];

const OUTLOOK_DESKTOP: &str = "Client=MSExchangeRPC";

fn well_known(desc: &str) -> Uuid {
    WELL_KNOWN_GUIDS
        .iter()
        .find(|(_, d)| *d == desc)
        .unwrap_or_else(|| panic!("baseline: unknown well-known app '{desc}'"))
        .0
        .parse()
        .expect("well-known guid parses")
}

/// Whether the unified audit log ingests a record at `time`. `AuditState::ual_disabled_at`
/// (set by a tamper storyline) takes precedence over the profile flag: records before it are
/// ingested.
pub fn ual_logged(w: &World, time: DateTime<Utc>) -> bool {
    match w.audit.ual_disabled_at {
        Some(t) => time < t,
        None => w.audit.ual_ingestion_enabled,
    }
}

/// Whether mailbox auditing records `action` on `owner`'s mailbox at `time` for a logon of
/// `logon_type` (0 owner, 1 admin, 2 delegate): the UAL ingests, organization auditing is on,
/// the mailbox is audited and not bypassed, and the action is in the logon type's list.
pub fn mailbox_logged(
    w: &World,
    owner: &str,
    logon_type: i64,
    action: &str,
    time: DateTime<Utc>,
) -> bool {
    mailbox_not_logged(w, owner, logon_type, action, time).is_none()
}

/// Why mailbox auditing does not record `action` on `owner`'s mailbox at `time` (the first
/// failing condition of `mailbox_logged`), or `None` when it does. A mailbox the tenant does not
/// have counts as not audited.
pub fn mailbox_not_logged(
    w: &World,
    owner: &str,
    logon_type: i64,
    action: &str,
    time: DateTime<Utc>,
) -> Option<&'static str> {
    if !ual_logged(w, time) {
        return Some(UAL_DISABLED);
    }
    let org_off = match w.audit.org_audit_disabled_at {
        Some(t) => time >= t,
        None => w.audit.org_audit_disabled,
    };
    if org_off {
        return Some("mailbox auditing disabled for the organization");
    }
    let Some(mb) = w.mailboxes.get(owner) else {
        return Some(MAILBOX_AUDIT_OFF);
    };
    // `audit_disabled_since` (set by a tamper storyline) takes precedence over the flag:
    // records before it are audited.
    let audit_off = match mb.audit_disabled_since {
        Some(t) => time >= t,
        None => !mb.audit_enabled,
    };
    if audit_off {
        return Some(MAILBOX_AUDIT_OFF);
    }
    if mb.bypass && mb.bypass_since.is_none_or(|t| time >= t) {
        return Some("mailbox audit bypass");
    }
    let list = match logon_type {
        0 => &mb.audit_owner,
        1 => &mb.audit_admin,
        _ => &mb.audit_delegate,
    };
    if list.iter().any(|a| a == action) {
        None
    } else {
        Some("action not in the mailbox's audit list")
    }
}

/// The reason a record is missing while unified audit log ingestion is off.
pub const UAL_DISABLED: &str = "unified audit log ingestion disabled";
const MAILBOX_AUDIT_OFF: &str = "mailbox auditing disabled for the mailbox";

/// A location's UTC offset in whole hours, from its longitude.
pub fn utc_offset_hours(loc: &Location) -> i64 {
    (loc.lon / 15.0).round() as i64
}

fn day_start(date: NaiveDate) -> DateTime<Utc> {
    date.and_hms_opt(0, 0, 0).expect("midnight").and_utc()
}

/// `user`'s working hours on `date` in UTC, clipped to the UTC day (every event of a day falls
/// on that day). Falls back to the working hours read as UTC if the clip leaves under an hour.
pub fn work_window(w: &World, user: &User, date: NaiveDate) -> (DateTime<Utc>, DateTime<Utc>) {
    let d0 = day_start(date);
    let d1 = d0 + Duration::days(1);
    let (h0, h1) = w.scenario.baseline.work_hours;
    let off = utc_offset_hours(&user.home);
    let s = (d0 + Duration::hours(i64::from(h0) - off)).max(d0);
    let e = (d0 + Duration::hours(i64::from(h1) - off)).min(d1);
    if e - s >= Duration::hours(1) {
        (s, e)
    } else {
        let s = d0 + Duration::hours(i64::from(h0.min(23)));
        let e = (d0 + Duration::hours(i64::from(h1.max(h0 + 1)))).min(d1);
        (s, e)
    }
}

/// A whole-second time in `[a, b)` (`a` when the range is empty).
fn rand_time(rng: &mut Rng, a: DateTime<Utc>, b: DateTime<Utc>) -> DateTime<Utc> {
    let span = (b - a).num_seconds();
    if span <= 0 {
        return a;
    }
    a + Duration::seconds(rng.below(span as u64) as i64)
}

fn is_weekend(date: NaiveDate) -> bool {
    matches!(date.weekday(), Weekday::Sat | Weekday::Sun)
}

/// One person's day.
struct Plan<'a> {
    user: &'a User,
    ip: IpAddr,
    session: Uuid,
    login: DateTime<Utc>,
    end: DateTime<Utc>,
    ual_budget: u64,
    messages: u64,
    /// Indices into the day's sign-ins of this person's interactive sign-ins.
    interactive: Vec<usize>,
    sent: Vec<Msg>,
    received: Vec<Msg>,
}

#[derive(Clone)]
struct Msg {
    imid: String,
    subject: String,
    size: u64,
    time: DateTime<Utc>,
    folder: String,
}

struct Apps {
    office: Uuid,
    office_home: Uuid,
    exchange: Uuid,
    sharepoint: Uuid,
    graph: Uuid,
}

impl Apps {
    fn new() -> Apps {
        Apps {
            office: well_known("Microsoft Office"),
            office_home: well_known("OfficeHome"),
            exchange: well_known("Office 365 Exchange Online"),
            sharepoint: well_known("Office 365 SharePoint Online"),
            graph: well_known("Microsoft Graph"),
        }
    }
}

/// How a sign-in went.
#[derive(Clone, Copy)]
enum Outcome {
    Ok,
    Failed(i64),
}

#[allow(clippy::too_many_arguments)]
fn signin(
    w: &World,
    rng: &mut Rng,
    user: &User,
    time: DateTime<Utc>,
    ip: IpAddr,
    event_type: SignInType,
    app: Uuid,
    resource: Uuid,
    outcome: Outcome,
    session: Uuid,
) -> SignIn {
    let p2 = w.licence.p2();
    let (error_code, failure_reason) = match outcome {
        Outcome::Ok => (0, "Other."),
        Outcome::Failed(50074) => (50074, "Strong Authentication is required."),
        Outcome::Failed(code) => (code, "Invalid username or password"),
    };
    let ok = error_code == 0;
    let ca_status = if ok && w.licence.p1() && user.is_admin {
        "success"
    } else {
        "notApplied"
    };
    let mfa_user = user.is_admin || error_code == 50074;
    let (auth_requirement, mfa, auth_methods) = match (event_type, ok) {
        (SignInType::NonInteractive, _) => (
            if user.is_admin {
                "multiFactorAuthentication"
            } else {
                "singleFactorAuthentication"
            },
            None,
            vec!["Previously satisfied".to_string()],
        ),
        (_, true) if user.is_admin => (
            "multiFactorAuthentication",
            Some(("FIDO2 security key".to_string(), String::new())),
            vec!["FIDO2 security key".to_string()],
        ),
        _ => (
            if mfa_user {
                "multiFactorAuthentication"
            } else {
                "singleFactorAuthentication"
            },
            None,
            vec!["Password".to_string()],
        ),
    };
    let windows = user.client.os.starts_with("Windows");
    let risk = if p2 { "none" } else { "hidden" };
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
        location: user.home.clone(),
        user_agent: user.client.user_agent.clone(),
        client_app: client_app.to_string(),
        event_type,
        error_code,
        failure_reason: failure_reason.to_string(),
        ca_status: ca_status.to_string(),
        risk_during: risk.to_string(),
        risk_aggregated: risk.to_string(),
        risk_state: "none".to_string(),
        risk_detail: risk.to_string(),
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
        incoming_token_type: "none".to_string(),
        home_tenant_id: w.org_id(),
        resource_tenant_id: w.org_id(),
        asn: user.home.asn,
    }
}

fn external_ip(rng: &mut Rng, block: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        0x2001,
        0x0db8,
        block,
        0,
        0,
        0,
        0,
        rng.range(1, 250) as u16,
    ))
}

/// The folder a delivered message lands in: a `Move to folder` inbox rule on the sender wins.
fn delivery_folder(w: &World, mailbox: &str, sender: &str) -> String {
    w.inbox_rules
        .iter()
        .find(|r| r.mailbox == mailbox && r.enabled && r.from.iter().any(|f| f == sender))
        .and_then(|r| r.move_to_folder.as_ref())
        .map_or_else(|| "\\Inbox".to_string(), |f| format!("\\{f}"))
}

/// The baseline events of UTC day `date` (deterministic per date).
pub fn day(w: &World, date: NaiveDate) -> Day {
    let apps = Apps::new();
    let b = &w.scenario.baseline;
    let factor = if is_weekend(date) {
        b.weekend_factor
    } else {
        1.0
    };
    let label = date.format("%Y-%m-%d").to_string();
    let d_end = day_start(date) + Duration::days(1) - Duration::seconds(1);

    // Sign-ins and each person's plan.
    let mut srng = stream(w.seed, &format!("signin/{label}"));
    let mut signins: Vec<SignIn> = Vec::new();
    let mut plans: Vec<Plan> = Vec::new();
    for user in w.all_people() {
        let n_signins = srng.poisson(b.signins_per_user_day * factor);
        let n_ual = srng.poisson(b.ual_per_user_day * factor);
        let n_msg = srng.poisson(b.messages_per_user_day * factor);
        if n_signins + n_ual + n_msg == 0 {
            continue;
        }
        let (start, end) = work_window(w, user, date);
        let ip = if is_weekend(date) || !srng.chance(0.8) {
            user.home_ip
        } else {
            user.office_ip
        };
        let session = srng.uuid();
        let first_hour = (start + Duration::hours(1)).min(end);
        let login = rand_time(&mut srng, start, first_hour);
        let mut plan = Plan {
            user,
            ip,
            session,
            login,
            end,
            ual_budget: n_ual,
            messages: n_msg,
            interactive: Vec::new(),
            sent: Vec::new(),
            received: Vec::new(),
        };
        // The morning sign-in of Outlook desktop starts the day's session.
        plan.interactive.push(signins.len());
        signins.push(signin(
            w,
            &mut srng,
            user,
            login,
            ip,
            SignInType::Interactive,
            apps.office,
            apps.exchange,
            Outcome::Ok,
            session,
        ));
        for _ in 1..n_signins.max(1) {
            let t = rand_time(&mut srng, start, end);
            let roll = srng.unit();
            if roll < 0.05 {
                let code = if srng.chance(0.5) { 50126 } else { 50074 };
                let failed_session = srng.uuid();
                plan.interactive.push(signins.len());
                signins.push(signin(
                    w,
                    &mut srng,
                    user,
                    t,
                    ip,
                    SignInType::Interactive,
                    apps.office_home,
                    apps.sharepoint,
                    Outcome::Failed(code),
                    failed_session,
                ));
            } else if roll < 0.75 {
                let t = t.max(login);
                let resource = *srng.pick(&[apps.exchange, apps.sharepoint, apps.graph]);
                signins.push(signin(
                    w,
                    &mut srng,
                    user,
                    t,
                    ip,
                    SignInType::NonInteractive,
                    apps.office,
                    resource,
                    Outcome::Ok,
                    session,
                ));
            } else {
                let t = t.max(login);
                plan.interactive.push(signins.len());
                signins.push(signin(
                    w,
                    &mut srng,
                    user,
                    t,
                    ip,
                    SignInType::Interactive,
                    apps.office_home,
                    apps.sharepoint,
                    Outcome::Ok,
                    session,
                ));
            }
        }
        plans.push(plan);
    }

    // Mail: each active person's messages, with the trace row and both mailboxes' view.
    let mut trng = stream(w.seed, &format!("trace/{label}"));
    let mut trace: Vec<TraceMsg> = Vec::new();
    let people: Vec<&User> = w.all_people().collect();
    for i in 0..plans.len() {
        for _ in 0..plans[i].messages {
            let (login, end, ip) = (plans[i].login, plans[i].end, plans[i].ip);
            let me = plans[i].user;
            let time = rand_time(&mut trng, login, end);
            let imid = ual::internet_message_id(&mut trng);
            let size = trng.range(4_000, 250_000) as u64;
            let roll = trng.unit();
            let others: Vec<&User> = people.iter().copied().filter(|p| p.upn != me.upn).collect();
            if roll < 0.45 && !others.is_empty() {
                let to = *trng.pick(&others);
                let subject = trng.pick(INTERNAL_SUBJECTS).to_string();
                let msg = Msg {
                    imid: imid.clone(),
                    subject: subject.clone(),
                    size,
                    time,
                    folder: "\\Sent Items".to_string(),
                };
                plans[i].sent.push(msg.clone());
                if let Some(p) = plans.iter_mut().find(|p| p.user.upn == to.upn) {
                    p.received.push(Msg {
                        folder: delivery_folder(w, &to.upn, &me.upn),
                        ..msg
                    });
                }
                trace.push(TraceMsg {
                    trace_id: trng.uuid(),
                    internet_message_id: imid,
                    received: time,
                    sender: me.upn.clone(),
                    recipients: vec![(to.upn.clone(), "Delivered".to_string())],
                    subject,
                    from_ip: Some(ip),
                    to_ip: None,
                    size,
                    direction: "Originating".to_string(),
                    connector_id: None,
                });
            } else if roll < 0.9 || others.is_empty() {
                let (sender, subject) = *trng.pick(INCOMING);
                let spam = trng.chance(0.04);
                let status = if spam { "FilteredAsSpam" } else { "Delivered" };
                let folder = if spam {
                    "\\Junk Email".to_string()
                } else {
                    delivery_folder(w, &me.upn, sender)
                };
                plans[i].received.push(Msg {
                    imid: imid.clone(),
                    subject: subject.to_string(),
                    size,
                    time,
                    folder,
                });
                trace.push(TraceMsg {
                    trace_id: trng.uuid(),
                    internet_message_id: imid,
                    received: time,
                    sender: sender.to_string(),
                    recipients: vec![(me.upn.clone(), status.to_string())],
                    subject: subject.to_string(),
                    from_ip: Some(external_ip(&mut trng, 0xe0)),
                    to_ip: None,
                    size,
                    direction: "Incoming".to_string(),
                    connector_id: None,
                });
            } else {
                let (to, subject) = *trng.pick(PARTNERS);
                plans[i].sent.push(Msg {
                    imid: imid.clone(),
                    subject: subject.to_string(),
                    size,
                    time,
                    folder: "\\Sent Items".to_string(),
                });
                trace.push(TraceMsg {
                    trace_id: trng.uuid(),
                    internet_message_id: imid,
                    received: time,
                    sender: me.upn.clone(),
                    recipients: vec![(to.to_string(), "Delivered".to_string())],
                    subject: subject.to_string(),
                    from_ip: Some(ip),
                    to_ip: Some(external_ip(&mut trng, 0xe1)),
                    size,
                    direction: "Outgoing".to_string(),
                    connector_id: None,
                });
            }
        }
    }

    // Unified audit log.
    let mut urng = stream(w.seed, &format!("ual/{label}"));
    let mut ual_out: Vec<Ual> = Vec::new();
    let tenant_word = w.primary_domain().split('.').next().unwrap_or("tenant");
    let finance_site = format!("https://{tenant_word}.sharepoint.example/sites/Finance");
    for plan in &mut plans {
        let user = plan.user;
        let (ip, session) = (plan.ip, plan.session);
        plan.received.sort_by_key(|m| m.time);

        for &i in &plan.interactive {
            let s = &signins[i];
            if ual_logged(w, s.time) {
                let ok = s.error_code == 0;
                ual_out.push(ual::sts_logon(
                    w,
                    &mut urng,
                    user,
                    s.time,
                    ok,
                    s.ip,
                    &s.user_agent,
                    s.app_id,
                    if ok {
                        "OAuth2:Authorize"
                    } else {
                        "Login:login"
                    },
                    s.error_code,
                ));
            }
        }

        let mut used = 0u64;
        // Outlook desktop syncs the inbox once each morning.
        let sync_time = (plan.login + Duration::seconds(urng.range(30, 300))).min(d_end);
        used += 1;
        if mailbox_logged(w, &user.upn, 0, "MailItemsAccessed", sync_time) {
            ual_out.push(ual::mail_items_accessed(
                w,
                &mut urng,
                user,
                sync_time,
                "Sync",
                &[("\\Inbox".to_string(), Vec::new())],
                ip,
                OUTLOOK_DESKTOP,
                apps.office,
                session,
                false,
            ));
        }

        for m in &plan.sent {
            used += 1;
            if mailbox_logged(w, &user.upn, 0, "Send", m.time) {
                let item = ItemRef::new(w, &user.upn, &m.folder, &m.imid, &m.subject, m.size);
                ual_out.push(ual::mailbox_item(
                    w,
                    &mut urng,
                    user,
                    user,
                    m.time,
                    "Send",
                    Some(item),
                    ip,
                    OUTLOOK_DESKTOP,
                    session,
                ));
            }
        }

        // A few binds of received messages, two at a time.
        let readable: Vec<Msg> = plan
            .received
            .iter()
            .filter(|m| m.folder != "\\Junk Email")
            .take(6)
            .cloned()
            .collect();
        for chunk in readable.chunks(2) {
            let last = chunk.last().expect("non-empty chunk").time.max(plan.login);
            let t = (last + Duration::seconds(urng.range(60, 1800))).min(d_end);
            used += 1;
            if !mailbox_logged(w, &user.upn, 0, "MailItemsAccessed", t) {
                continue;
            }
            let mut folders: Vec<(String, Vec<(String, u64)>)> = Vec::new();
            for m in chunk {
                match folders.iter_mut().find(|(p, _)| *p == m.folder) {
                    Some((_, items)) => items.push((m.imid.clone(), m.size)),
                    None => folders.push((m.folder.clone(), vec![(m.imid.clone(), m.size)])),
                }
            }
            ual_out.push(ual::mail_items_accessed(
                w,
                &mut urng,
                user,
                t,
                "Bind",
                &folders,
                ip,
                OUTLOOK_DESKTOP,
                apps.office,
                session,
                false,
            ));
        }

        // The rest of the day's records: item updates and deletes, file access.
        for _ in used..plan.ual_budget {
            let roll = urng.unit();
            if roll < 0.3 && !readable.is_empty() {
                let m = urng.pick(&readable).clone();
                let op = if roll < 0.2 {
                    "Update"
                } else {
                    "MoveToDeletedItems"
                };
                let t = rand_time(&mut urng, m.time.max(plan.login), plan.end).min(d_end);
                if mailbox_logged(w, &user.upn, 0, op, t) {
                    let item = ItemRef::new(w, &user.upn, &m.folder, &m.imid, &m.subject, m.size);
                    ual_out.push(ual::mailbox_item(
                        w,
                        &mut urng,
                        user,
                        user,
                        t,
                        op,
                        Some(item),
                        ip,
                        OUTLOOK_DESKTOP,
                        session,
                    ));
                }
                continue;
            }
            let t = rand_time(&mut urng, plan.login, plan.end);
            let op_roll = urng.unit();
            let op = if op_roll < 0.6 {
                "FileAccessed"
            } else if op_roll < 0.85 {
                "FileModified"
            } else {
                "FileDownloaded"
            };
            let (site, folder, file) = if urng.chance(0.5) {
                let personal = format!(
                    "https://{tenant_word}-my.sharepoint.example/personal/{}",
                    user.upn.replace(['.', '@', '-'], "_")
                );
                (personal, "Documents", urng.pick(ONEDRIVE_FILES).to_string())
            } else {
                (
                    finance_site.clone(),
                    "Shared Documents",
                    urng.pick(FINANCE_FILES).to_string(),
                )
            };
            if ual_logged(w, t) {
                ual_out.push(ual::sharepoint_file(
                    w,
                    &mut urng,
                    user,
                    t,
                    op,
                    &site,
                    folder,
                    &file,
                    ip,
                    &user.client.user_agent,
                ));
            }
        }

        // Admins make the occasional Exchange configuration change.
        if user.is_admin && !is_weekend(date) && urng.chance(0.3) && !w.users.is_empty() {
            let target = urng.pick(&w.users);
            let t = rand_time(&mut urng, plan.login, plan.end);
            if ual_logged(w, t) && w.audit.admin_audit_log_enabled {
                ual_out.push(ual::exchange_admin(
                    w,
                    &mut urng,
                    user,
                    t,
                    "Set-Mailbox",
                    &target.upn,
                    &[
                        ("Identity", &target.upn),
                        ("RetainDeletedItemsFor", "30.00:00:00"),
                    ],
                    ip,
                    session,
                ));
            }
        }
    }

    // Directory changes of the day, as the UAL records them.
    for a in directory_audits(w)
        .iter()
        .filter(|a| a.time.date_naive() == date)
    {
        if !ual_logged(w, a.time) {
            continue;
        }
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
        let modified: Vec<(String, String, String)> =
            a.targets.iter().flat_map(|t| t.modified.clone()).collect();
        ual_out.push(ual::aad(
            w,
            &mut urng,
            actor,
            a.time,
            &format!("{}.", a.activity),
            &target,
            &modified,
            a.initiated_by.ip,
            &[],
        ));
    }

    ual_out.sort_by_key(|u| (u.time, u.id));
    signins.sort_by_key(|s| (s.time, s.id));
    trace.sort_by_key(|t| (t.received, t.trace_id));
    Day {
        date,
        ual: ual_out,
        signins,
        trace,
    }
}

fn user_target(u: &User, modified: Vec<(String, String, String)>) -> Target {
    Target {
        id: u.object_id.to_string(),
        display_name: u.display_name.clone(),
        kind: "User".to_string(),
        upn: Some(u.upn.clone()),
        modified,
    }
}

/// Benign admin activity in Entra ID over the window (stream `diraudit`): profile updates,
/// group membership changes, password resets and licence changes by the admins, on at least
/// the first weekday.
pub fn directory_audits(w: &World) -> Vec<DirAudit> {
    let mut rng = stream(w.seed, "diraudit");
    let mut out = Vec::new();
    if w.admins.is_empty() || w.users.is_empty() {
        return out;
    }
    let finance = w.groups.iter().find(|g| g.display_name == "Finance");
    let (ws, we) = (w.window_start(), w.window_end());
    let mut date = ws.date_naive();
    while day_start(date) < we {
        let today = date;
        date += Duration::days(1);
        if is_weekend(today) || !(out.is_empty() || rng.chance(0.35)) {
            continue;
        }
        let admin = rng.pick(&w.admins);
        let (s, e) = work_window(w, admin, today);
        let time = rand_time(&mut rng, s, e);
        if time < ws || time >= we {
            continue;
        }
        let user = rng.pick(&w.users);
        let (activity, category, operation_type, targets, details) = match rng.below(4) {
            0 => (
                "Update user",
                "UserManagement",
                "Update",
                vec![user_target(
                    user,
                    vec![(
                        "MobilePhone".to_string(),
                        "[]".to_string(),
                        format!("[\"+1 555 01{}\"]", rng.digits(2)),
                    )],
                )],
                vec![("UserType".to_string(), "Member".to_string())],
            ),
            1 if finance.is_some() => {
                let g = finance.expect("checked");
                (
                    "Add member to group",
                    "GroupManagement",
                    "Assign",
                    vec![
                        user_target(user, Vec::new()),
                        Target {
                            id: g.id.to_string(),
                            display_name: g.display_name.clone(),
                            kind: "Other".to_string(),
                            upn: None,
                            modified: vec![
                                (
                                    "Group.ObjectID".to_string(),
                                    String::new(),
                                    format!("\"{}\"", g.id),
                                ),
                                (
                                    "Group.DisplayName".to_string(),
                                    String::new(),
                                    format!("\"{}\"", g.display_name),
                                ),
                            ],
                        },
                    ],
                    Vec::new(),
                )
            }
            2 => (
                "Reset user password",
                "UserManagement",
                "Update",
                vec![user_target(user, Vec::new())],
                Vec::new(),
            ),
            _ => (
                "Change user license",
                "UserManagement",
                "Update",
                vec![user_target(user, Vec::new())],
                Vec::new(),
            ),
        };
        let correlation_id = rng.uuid();
        let id = format!(
            "Directory_{}_{}_{}",
            rng.uuid(),
            (0..5)
                .map(|_| (b'A' + rng.below(26) as u8) as char)
                .collect::<String>(),
            rng.range(10_000_000, 99_999_999)
        );
        out.push(DirAudit {
            id,
            time,
            activity: activity.to_string(),
            category: category.to_string(),
            operation_type: operation_type.to_string(),
            result: "success".to_string(),
            result_reason: String::new(),
            logged_by_service: "Core Directory".to_string(),
            initiated_by: Actor {
                upn: Some(admin.upn.clone()),
                user_id: Some(admin.object_id),
                ip: Some(admin.office_ip),
                app_id: None,
                app_name: None,
            },
            targets,
            additional_details: details,
            correlation_id,
        });
    }
    out
}

/// Benign Identity Protection data (stream `risk`): one low `unfamiliarFeatures` sign-in
/// detection for user 2, dismissed by an admin, and user 2's risky-user entry. The world holds
/// it regardless of licence; only Entra ID P2 tenants expose it to Graph (the writers decide).
pub fn risk(w: &World) -> (Vec<RiskDetection>, Vec<RiskyUser>) {
    let mut rng = stream(w.seed, "risk");
    let Some(user) = w.users.get(1) else {
        return (Vec::new(), Vec::new());
    };
    let date = w.window_start().date_naive() + Duration::days(3);
    let (s, e) = work_window(w, user, date);
    let activity_time = rand_time(&mut rng, s, e);
    let detected = activity_time + Duration::minutes(rng.range(1, 10));
    let updated = detected + Duration::hours(rng.range(2, 30));
    let detection = RiskDetection {
        id: rng.hex(64),
        user: user.upn.clone(),
        user_id: user.object_id,
        user_display: user.display_name.clone(),
        activity: "signin".to_string(),
        event_type: "unfamiliarFeatures".to_string(),
        level: "low".to_string(),
        state: "dismissed".to_string(),
        detail: "adminDismissedAllRiskForUser".to_string(),
        timing: "realtime".to_string(),
        source: "IdentityProtection".to_string(),
        detected,
        activity_time,
        updated,
        ip: Some(user.home_ip),
        location: Some(user.home.clone()),
        request_id: Some(rng.uuid()),
        correlation_id: Some(rng.uuid()),
        additional_info: json!([
            {"Key": "userAgent", "Value": user.client.user_agent},
        ])
        .to_string(),
    };
    let risky = RiskyUser {
        upn: user.upn.clone(),
        user_id: user.object_id,
        display_name: user.display_name.clone(),
        level: "none".to_string(),
        state: "dismissed".to_string(),
        detail: "adminDismissedAllRiskForUser".to_string(),
        updated,
    };
    (vec![detection], vec![risky])
}
