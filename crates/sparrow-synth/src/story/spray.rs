//! Password-spray storylines, attacker infrastructure outside the hosting providers, and their
//! benign look-alikes.
//!
//! Attackers spray and replay from compromised ISP routers and residential proxies as well as from
//! hosting providers. That infrastructure has its own address pool (`Attacker::pool`) and its own
//! ASNs, separate from the roaming pool (`Shared::next_ip`) that stands for a benign traveller or
//! mobile user, and the addresses are located in the GeoIP databases (`StoryEvents::located`).
//! Credential failures carry no session id (a failure issues no token) and a UAL `UserLoginFailed`
//! record where the collector delivers the UAL.

use super::{Ctx, mail, push_signin, signin, well_known};
use crate::events::{SignIn, SignInType};
use crate::scenario::StoryKind;
use crate::world::{LOCATIONS, Location, User, World};
use crate::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use std::net::IpAddr;

/// A documentation-range residential ISP (RFC 5398 AS number, never a hosting provider) the
/// attacker's compromised routers sit in: the victim's own city, a different ASN.
const RESIDENTIAL_ASN: (u32, &str) = (64509, "Documentation Residential ISP");

/// Applies `ctx`'s storyline if it is a spray kind; `false` otherwise.
pub(crate) fn apply_one(w: &mut World, ctx: &mut Ctx) -> Result<bool> {
    match ctx.spec.kind {
        StoryKind::PasswordSpray => password_spray(w, ctx)?,
        StoryKind::DistributedSpray => distributed_spray(w, ctx)?,
        StoryKind::SpraySuccess => spray_success(w, ctx)?,
        StoryKind::SprayReplay => spray_replay(w, ctx)?,
        StoryKind::ReplayOtherCountry => replay_other_country(w, ctx)?,
        StoryKind::MiaBurstResidential => mail::mia_burst_residential(w, ctx)?,
        StoryKind::SendResidential => mail::send_residential(w, ctx)?,
        StoryKind::OfficeNatMistypes => office_nat_mistypes(w, ctx)?,
        StoryKind::PhoneStalePassword => phone_stale_password(w, ctx),
        _ => return Ok(false),
    }
    Ok(true)
}

/// Takes the next attacker-pool address and tells the GeoIP databases where it is.
pub(super) fn attacker_ip(w: &mut World, ctx: &mut Ctx, location: &Location) -> Result<IpAddr> {
    let ip = ctx.shared.next_attacker(&w.attacker.pool)?;
    w.story.located.push((ip, location.clone()));
    Ok(ip)
}

/// An ordinary-ISP location of another country (never a user's home, never a hosting ASN).
pub(super) fn residential_location(k: usize) -> Location {
    let pool = &LOCATIONS[6..LOCATIONS.len() - 2];
    pool[k % pool.len()].clone()
}

/// The attacker's compromised router in the victim's own city, on another ISP (a different ASN).
fn router_location(victim: &User) -> Location {
    Location {
        asn: RESIDENTIAL_ASN.0,
        asn_org: RESIDENTIAL_ASN.1.to_string(),
        ..victim.home.clone()
    }
}

/// `count` users of the tenant starting at the storyline's user, wrapping around.
fn users_from(w: &World, upn: &str, count: usize) -> Vec<User> {
    let n = w.users.len();
    let first = w.users.iter().position(|u| u.upn == upn).unwrap_or(0);
    (0..count.min(n))
        .map(|k| w.users[(first + k) % n].clone())
        .collect()
}

/// A failed sign-in of `user` from `ip` (error `code`, optional scripted `agent`): no token is
/// issued, so it is recorded in the interactive sign-in report with password only, no Conditional
/// Access and no session id.
#[allow(clippy::too_many_arguments)]
pub(super) fn failed_signin(
    w: &World,
    ctx: &mut Ctx,
    user: &User,
    time: DateTime<Utc>,
    ip: IpAddr,
    location: &Location,
    code: i64,
    agent: Option<&str>,
) -> SignIn {
    let mut s = signin(
        w,
        &mut ctx.rng,
        user,
        time,
        ip,
        location,
        SignInType::Interactive,
        well_known("Microsoft Office"),
        well_known("Office 365 Exchange Online"),
        uuid::Uuid::nil(),
    );
    s.error_code = code;
    s.failure_reason = match code {
        50053 => "The user account is locked out.".to_string(),
        _ => "Invalid username or password or Invalid on-premise username or password.".to_string(),
    };
    if let Some(a) = agent {
        s.user_agent = a.to_string();
        s.client_app = "Other clients".to_string();
    }
    s.auth_requirement = "singleFactorAuthentication".to_string();
    s.mfa = None;
    s.auth_methods = vec!["Password".to_string()];
    s.ca_status = "notApplied".to_string();
    s
}

#[allow(clippy::too_many_arguments)]
fn fail(
    w: &mut World,
    ctx: &mut Ctx,
    user: &User,
    time: DateTime<Utc>,
    ip: IpAddr,
    location: &Location,
    code: i64,
    agent: Option<&str>,
) {
    let s = failed_signin(w, ctx, user, time, ip, location, code, agent);
    push_signin(w, ctx, user, s, true);
}

/// Internet-wide legacy-authentication password spray below the source threshold: one attacker
/// address tries three passwords at each of four users, with the BAV2ROPC (ROPC) client and a
/// scripted one. Every attempt fails (50126 invalid credentials, 50053 once an account locks out):
/// a scripted client that never gets a token is background noise on any tenant that still exposes
/// legacy authentication, not a replayed session, and four users is not a spray source.
fn password_spray(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let victims = users_from(w, &ctx.a.upn, 4);
    let location = residential_location(0);
    let ip = attacker_ip(w, ctx, &location)?;
    for (v, user) in victims.iter().enumerate() {
        let agent = if v % 2 == 0 {
            "BAV2ROPC"
        } else {
            "python-requests/2.31.0"
        };
        for attempt in 0..3i64 {
            let time = ctx.t + Duration::minutes(v as i64 * 7 + attempt * 3);
            let code = if v == 3 && attempt == 2 { 50053 } else { 50126 };
            fail(w, ctx, user, time, ip, &location, code, Some(agent));
        }
    }
    Ok(())
}

/// A distributed, low-and-slow password spray: eight residential-ISP addresses of the attacker's
/// pool in several countries (compromised routers and residential proxies, not hosting
/// providers) each try the same six users once or twice over a few hours with BAV2ROPC and a
/// scripted client, mostly invalid-password (50126) and a smart-lockout (50053) after a second
/// attempt. Every attempt fails.
fn distributed_spray(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let victims = users_from(w, &ctx.a.upn, 6);
    for src in 0..8usize {
        let location = residential_location(src);
        let ip = attacker_ip(w, ctx, &location)?;
        let agent = if src % 2 == 0 {
            "BAV2ROPC"
        } else {
            "python-requests/2.31.0"
        };
        for (v, user) in victims.iter().enumerate() {
            let attempts = if (src + v) % 3 == 0 { 2 } else { 1 };
            for attempt in 0..attempts {
                let time =
                    ctx.t + Duration::minutes(src as i64 * 17 + v as i64 * 2 + attempt as i64 * 31);
                let code = if attempt == 0 { 50126 } else { 50053 };
                fail(w, ctx, user, time, ip, &location, code, Some(agent));
            }
        }
    }
    Ok(())
}

/// The failures of a spray from one address: two attempts at each of `victims`, from `ip`.
fn spray_from(w: &mut World, ctx: &mut Ctx, victims: &[User], ip: IpAddr, location: &Location) {
    for (v, user) in victims.iter().enumerate() {
        for attempt in 0..2i64 {
            let time = ctx.t + Duration::minutes(v as i64 * 3 + attempt);
            fail(w, ctx, user, time, ip, location, 50126, Some("BAV2ROPC"));
        }
    }
}

/// A spray that works, and what the attacker does with the account: a compromised router in the
/// victim's own ISP (the attacker's pool address, the victim's own ASN and city) fails twice
/// against each of six users, signs the first of them in three hours later (password only, no
/// second factor registered), reads the mailbox ten minutes after that and sends a message ten
/// minutes later. The address is a spray source in the user's own network, so only the spray-source
/// path of SPW-MAIL-005 and SPW-MAIL-006 sees it (the network is the user's regular one).
fn spray_success(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let victims = users_from(w, &a.upn, 6);
    let location = a.home.clone();
    let ip = attacker_ip(w, ctx, &location)?;
    spray_from(w, ctx, &victims, ip, &location);
    let session = ctx.rng.uuid();
    let mut ok = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t + Duration::hours(3),
        ip,
        &location,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    ok.auth_requirement = "singleFactorAuthentication".to_string();
    ok.mfa = None;
    ok.auth_methods = vec!["Password".to_string()];
    push_signin(w, ctx, &a, ok, true);
    let start = ctx.t;
    ctx.t = start + Duration::hours(3) + Duration::minutes(10);
    let burst = mail::mia_burst_from(w, ctx, ip, false);
    ctx.t = start + Duration::hours(3) + Duration::minutes(20);
    mail::send_from(w, ctx, ip);
    ctx.t = start;
    burst
}

/// A session replay from a spray source in the victim's country: a compromised router (the
/// attacker's pool address, the victim's city on another ISP and ASN, not a hosting provider)
/// sprays six users, and twenty-five minutes after the victim's interactive MFA sign-in from home
/// it uses the same session. Same country, no scripted agent, no risk rating: only the spray source
/// makes the changed network an attacker's.
fn spray_replay(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let victims = users_from(w, &a.upn, 6);
    let location = router_location(&a);
    let ip = attacker_ip(w, ctx, &location)?;
    spray_from(w, ctx, &victims, ip, &location);
    replay(w, ctx, &a, ip, &location, 25);
    Ok(())
}

/// A token replay from another country: a residential address of the attacker's pool in a country
/// the victim was never in replays the victim's session twenty minutes after their interactive MFA
/// sign-in from home. The replay keeps the user's own browser agent and is not a hosting address,
/// so only the country change makes the session move an attacker's.
fn replay_other_country(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let location = residential_location(1);
    let ip = attacker_ip(w, ctx, &location)?;
    replay(w, ctx, &a, ip, &location, 20);
    Ok(())
}

/// The victim signs in from home with MFA (the session is created) and, `minutes` later, the same
/// session is used from `ip`: an AiTM replay in a browser is an interactive sign-in whose MFA claim
/// comes from the stolen session.
fn replay(w: &mut World, ctx: &mut Ctx, a: &User, ip: IpAddr, location: &Location, minutes: i64) {
    let session = ctx.rng.uuid();
    let first = signin(
        w,
        &mut ctx.rng,
        a,
        ctx.t + Duration::minutes(30),
        a.home_ip,
        &a.home,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, a, first, true);
    let used = signin(
        w,
        &mut ctx.rng,
        a,
        ctx.t + Duration::minutes(30 + minutes),
        ip,
        location,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, a, used, true);
}

/// An office NAT: about ten users of one city share one egress address, sign in from it on the four
/// weekdays before and on the day, and on the last day each mistypes a password once before getting
/// it right. Ordinary days of an ordinary office, so the address is regular tenant egress, not a
/// spray.
fn office_nat_mistypes(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let staff: Vec<User> = w
        .users
        .iter()
        .filter(|u| u.home.city == a.home.city)
        .take(12)
        .cloned()
        .collect();
    if staff.len() < 8 {
        return Err(Error::Scenario(format!(
            "{}: an office NAT needs at least 8 users in one city, {} has {}",
            ctx.spec.id,
            a.home.city,
            staff.len()
        )));
    }
    let nat = ctx.shared.next_ip();
    let location = a.home.clone();
    for (k, user) in staff.iter().enumerate() {
        for day in [4i64, 3, 2, 1] {
            let session = ctx.rng.uuid();
            let s = signin(
                w,
                &mut ctx.rng,
                user,
                ctx.t - Duration::days(day) + Duration::minutes(k as i64 * 7),
                nat,
                &location,
                SignInType::Interactive,
                well_known("OfficeHome"),
                well_known("Office 365 Exchange Online"),
                session,
            );
            push_signin(w, ctx, user, s, true);
        }
        let when = ctx.t + Duration::minutes(k as i64 * 6);
        fail(w, ctx, user, when, nat, &location, 50126, None);
        let session = ctx.rng.uuid();
        let ok = signin(
            w,
            &mut ctx.rng,
            user,
            when + Duration::minutes(1),
            nat,
            &location,
            SignInType::Interactive,
            well_known("OfficeHome"),
            well_known("Office 365 Exchange Online"),
            session,
        );
        push_signin(w, ctx, user, ok, true);
    }
    Ok(())
}

/// One user's phone keeps retrying a stale password: twelve invalid-password failures over an
/// hour from the user's mobile carrier, always the same user.
fn phone_stale_password(w: &mut World, ctx: &mut Ctx) {
    let a: User = ctx.a.clone();
    let ip = ctx.shared.next_ip();
    let location = super::identity::cellular_location(&a.home);
    for i in 0..12i64 {
        fail(
            w,
            ctx,
            &a,
            ctx.t + Duration::minutes(i * 5),
            ip,
            &location,
            50126,
            None,
        );
    }
}
