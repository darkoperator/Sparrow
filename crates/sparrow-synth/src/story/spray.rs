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
        StoryKind::SprayAfterPhish => spray_after_phish(w, ctx)?,
        StoryKind::SpraySuccessForeign => spray_success_foreign(w, ctx)?,
        StoryKind::SprayProxyTakeover => spray_proxy_takeover(w, ctx)?,
        StoryKind::SprayVpsLogin => spray_vps_login(w, ctx)?,
        StoryKind::OfficeNatMistypes => office_nat_mistypes(w, ctx)?,
        StoryKind::OfficeStaleAccounts => office_stale_accounts(w, ctx)?,
        StoryKind::OfficeWindowMistypes => office_window_mistypes(w, ctx)?,
        StoryKind::PhoneStalePassword => phone_stale_password(w, ctx),
        StoryKind::GatewayEgress => gateway_egress(w, ctx)?,
        StoryKind::ConferenceNetwork => conference_network(w, ctx),
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
        50057 => "The user account is disabled.".to_string(),
        50034 => "The user account does not exist in the directory.".to_string(),
        50055 => "The password is expired.".to_string(),
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
/// pool in several countries (compromised routers and residential proxies, not hosting providers),
/// each trying its own rotating subset of 14 users (overlapping, not identical; five to twelve users
/// per source, the median about six) one to three times with BAV2ROPC or a scripted client.
/// Smart lockout is PER ACCOUNT across every source: Microsoft Entra locks an account after 10 failed
/// attempts by default (Azure public cloud; the lockout state is synchronized across data centers),
/// so 50053 appears from an account's cumulative failures, whichever source made them, and every
/// attempt fails (https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout).
fn distributed_spray(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    const SIZES: [usize; 8] = [5, 7, 12, 6, 9, 5, 6, 8];
    const LOCKOUT_THRESHOLD: usize = 10;
    let targets = users_from(w, &ctx.a.upn, 14);
    let mut ips = Vec::new();
    for src in 0..SIZES.len() {
        let location = residential_location(src);
        ips.push((attacker_ip(w, ctx, &location)?, location));
    }
    // Every attempt (source, target, time), in time order across all sources.
    let mut attempts: Vec<(DateTime<Utc>, usize, usize)> = Vec::new();
    for (src, size) in SIZES.iter().enumerate() {
        let start = (src * 5) % targets.len();
        for k in 0..*size {
            let u = (start + k) % targets.len();
            for a in 0..(1 + (src + u) % 3) {
                let time =
                    ctx.t + Duration::minutes(src as i64 * 17 + k as i64 * 2 + a as i64 * 31);
                attempts.push((time, src, u));
            }
        }
    }
    attempts.sort();
    let mut failed = vec![0usize; targets.len()];
    for (time, src, u) in attempts {
        let code = if failed[u] >= LOCKOUT_THRESHOLD {
            50053
        } else {
            50126
        };
        failed[u] += 1;
        let agent = if src % 2 == 0 {
            "BAV2ROPC"
        } else {
            "python-requests/2.31.0"
        };
        let (ip, location) = &ips[src];
        fail(w, ctx, &targets[u], time, *ip, location, code, Some(agent));
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
/// it right. The mistyping users succeed from the address, so none of them is failed-only and the
/// address is not a spray source.
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
    let nat = ctx.shared.next_egress();
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

/// Users of the actor's home city, the actor first (up to `take`): a shared office egress, a
/// connector's cloud region or a compromised router all sit in one city.
fn city_staff(w: &World, actor: &User, take: usize) -> Vec<User> {
    let mut out = vec![actor.clone()];
    out.extend(
        w.users
            .iter()
            .filter(|u| u.home.city == actor.home.city && u.upn != actor.upn)
            .take(take.saturating_sub(1))
            .cloned(),
    );
    out
}

/// A password-only interactive sign-in of `user` from `ip` (no second factor registered).
fn password_signin(
    w: &World,
    ctx: &mut Ctx,
    user: &User,
    time: DateTime<Utc>,
    ip: IpAddr,
    location: &Location,
    app: uuid::Uuid,
) -> SignIn {
    let session = ctx.rng.uuid();
    let mut s = signin(
        w,
        &mut ctx.rng,
        user,
        time,
        ip,
        location,
        SignInType::Interactive,
        app,
        well_known("Office 365 Exchange Online"),
        session,
    );
    s.auth_requirement = "singleFactorAuthentication".to_string();
    s.mfa = None;
    s.auth_methods = vec!["Password".to_string()];
    s
}

/// Phished credentials first, then a spray: a compromised router in the victim's city signs the
/// victim in, and an hour later tries six other users. The success comes BEFORE the source's first
/// failure and the victim was never one of the sprayed users.
fn spray_after_phish(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let location = router_location(&a);
    let ip = attacker_ip(w, ctx, &location)?;
    let ok = password_signin(w, ctx, &a, ctx.t, ip, &location, well_known("OfficeHome"));
    push_signin(w, ctx, &a, ok, true);
    let victims: Vec<User> = users_from(w, &a.upn, 7).into_iter().skip(1).collect();
    let start = ctx.t;
    ctx.t = start + Duration::hours(1);
    spray_from(w, ctx, &victims, ip, &location);
    ctx.t = start;
    Ok(())
}

/// A spray that works from a FOREIGN residential address (another country, not the victim's own
/// carrier): the source fails twice against each of six users, and three hours later the first of
/// them signs in from it, thirty minutes after their own sign-in from home (an impossible-travel pair
/// as well).
fn spray_success_foreign(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let victims = users_from(w, &a.upn, 6);
    let location = residential_location(4);
    let ip = attacker_ip(w, ctx, &location)?;
    spray_from(w, ctx, &victims, ip, &location);
    let session = ctx.rng.uuid();
    let home = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t + Duration::hours(2) + Duration::minutes(30),
        a.home_ip,
        &a.home,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, &a, home, true);
    let ok = password_signin(
        w,
        ctx,
        &a,
        ctx.t + Duration::hours(3),
        ip,
        &location,
        well_known("OfficeHome"),
    );
    push_signin(w, ctx, &a, ok, true);
    Ok(())
}

/// A proxy that sprays many accounts and takes a few: a compromised router in the actor's city fails
/// twice against each of 18 users (five colleagues of the city and 13 others), then signs the five
/// colleagues in on each of the next three days. The 13 failed-only users outnumber the 5 taken
/// accounts, so the address stays a spray source, and every success from it is the takeover.
fn spray_proxy_takeover(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let taken = city_staff(w, &a, 5);
    let others: Vec<User> = w
        .users
        .iter()
        .filter(|u| u.home.city != a.home.city)
        .take(13)
        .cloned()
        .collect();
    if taken.len() < 5 || others.len() < 13 {
        return Err(Error::Scenario(format!(
            "{}: a proxy takeover needs 5 users in {} and 13 others, the tenant has {} and {}",
            ctx.spec.id,
            a.home.city,
            taken.len(),
            others.len()
        )));
    }
    let sprayed: Vec<User> = taken.iter().chain(others.iter()).cloned().collect();
    let location = router_location(&a);
    let ip = attacker_ip(w, ctx, &location)?;
    spray_from(w, ctx, &sprayed, ip, &location);
    for day in 1..=3i64 {
        for (k, user) in taken.iter().enumerate() {
            let time = ctx.t + Duration::days(day) + Duration::minutes(k as i64 * 4);
            let ok = password_signin(w, ctx, user, time, ip, &location, well_known("OfficeHome"));
            push_signin(w, ctx, user, ok, true);
        }
    }
    Ok(())
}

/// Sprayed accounts used interactively from a cloud VPS: a compromised router sprays six colleagues
/// (a spray source), and over the next three days five of the accounts sign in interactively to a
/// low-volume first-party client (Microsoft Teams) from a hosting-ASN VPS in the same city. The VPS is
/// not a spray source, so the hosting sign-ins are SPW-ID-002's alone, and an interactive sign-in
/// always counts.
fn spray_vps_login(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let staff = city_staff(w, &a, 6);
    if staff.len() < 6 {
        return Err(Error::Scenario(format!(
            "{}: a VPS login needs 6 users in {}, the tenant has {}",
            ctx.spec.id,
            a.home.city,
            staff.len()
        )));
    }
    let router = router_location(&a);
    let router_ip = attacker_ip(w, ctx, &router)?;
    spray_from(w, ctx, &staff, router_ip, &router);
    let mut vps = a.home.clone();
    vps.asn = crate::world::HOSTING_ASNS[1].0;
    vps.asn_org = crate::world::HOSTING_ASNS[1].1.to_string();
    let vps_ip = attacker_ip(w, ctx, &vps)?;
    for day in 1..=3i64 {
        for (k, user) in staff.iter().take(5).enumerate() {
            let time = ctx.t + Duration::days(day) + Duration::minutes(k as i64 * 4);
            let ok = password_signin(
                w,
                ctx,
                user,
                time,
                vps_ip,
                &vps,
                well_known("Microsoft Teams"),
            );
            push_signin(w, ctx, user, ok, true);
        }
    }
    Ok(())
}

/// A secure web gateway or VPN egress: eight users of one city share one egress address that blocks
/// their sign-ins by Conditional Access (53003, interactive) and breaks their token refreshes (70043
/// and 50173, non-interactive), with a single success. None of these codes is a rejected credential, so
/// the address is not a spray source.
fn gateway_egress(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let staff = city_staff(w, &a, 8);
    let egress = ctx.shared.next_egress();
    let location = a.home.clone();
    for (k, user) in staff.iter().enumerate() {
        let when = ctx.t + Duration::minutes(k as i64 * 5);
        let s = failed_signin(w, ctx, user, when, egress, &location, 53003, None);
        push_signin(w, ctx, user, s, true);
        for (j, code) in [70043, 50173].into_iter().enumerate() {
            let mut r = failed_signin(
                w,
                ctx,
                user,
                when + Duration::minutes(10 + j as i64),
                egress,
                &location,
                code,
                None,
            );
            r.event_type = SignInType::NonInteractive;
            r.failure_reason = match code {
                70043 => "The refresh token has expired due to inactivity.".to_string(),
                _ => "The user must provide fresh authentication.".to_string(),
            };
            push_signin(w, ctx, user, r, false);
        }
    }
    let session = ctx.rng.uuid();
    let ok = signin(
        w,
        &mut ctx.rng,
        &a,
        ctx.t + Duration::hours(2),
        egress,
        &location,
        SignInType::Interactive,
        well_known("OfficeHome"),
        well_known("Office 365 Exchange Online"),
        session,
    );
    push_signin(w, ctx, &a, ok, true);
    Ok(())
}

/// A conference or hotel network: three attendees of the tenant mistype their password once or twice
/// from the shared venue address (a benign egress-pool address on the attendees' own home ISP network,
/// not the mobile carrier) on the same morning. Three users is far under the five a spray source needs.
fn conference_network(w: &mut World, ctx: &mut Ctx) {
    let a: User = ctx.a.clone();
    let attendees = users_from(w, &a.upn, 3);
    let ip = ctx.shared.next_egress();
    let location = a.home.clone();
    for (k, user) in attendees.iter().enumerate() {
        for attempt in 0..(1 + k % 2) as i64 {
            let when = ctx.t + Duration::minutes(k as i64 * 9 + attempt * 2);
            fail(w, ctx, user, when, ip, &location, 50126, None);
        }
    }
}

/// An office whose mistypes are spread over the whole window, its first day included: the ten users of
/// one city sign in from the office egress address on 20 weekday-spaced days, and eight of them mistype
/// once or twice on various days, then succeed a minute later. Nobody is failed-only, so however the
/// failures are spread (a capture is a window: mistypes start on day one) the address is not a spray
/// source. (A real office is bigger; the tenant has ten users per city.)
fn office_window_mistypes(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    let a: User = ctx.a.clone();
    let staff = city_staff(w, &a, 10);
    if staff.len() < 8 {
        return Err(Error::Scenario(format!(
            "{}: an office needs at least 8 users in {}, the tenant has {}",
            ctx.spec.id,
            a.home.city,
            staff.len()
        )));
    }
    let nat = ctx.shared.next_egress();
    let location = a.home.clone();
    for day in 0..20i64 {
        for (k, user) in staff.iter().enumerate() {
            let when = ctx.t + Duration::days(day) + Duration::minutes(k as i64 * 6);
            let mistypes = k < 8 && (day * 3 + k as i64) % 10 == 0;
            let mut at = when;
            if mistypes || (k < 8 && day == 0) {
                fail(w, ctx, user, at, nat, &location, 50126, None);
                at = when + Duration::minutes(1);
            }
            let ok = password_signin(w, ctx, user, at, nat, &location, well_known("OfficeHome"));
            push_signin(w, ctx, user, ok, true);
        }
    }
    Ok(())
}

/// An office whose departed and disabled accounts keep failing: five users with stale devices (a
/// laptop that still syncs, a phone mail profile) fail with 50057 (disabled), 50034 (no such account) and
/// 50055 (expired password) behind the office egress address that the ten users of the city sign in
/// from successfully. Five failed-only users, but ten users succeed from the address, so it is not a
/// spray source. (A real office is bigger; the tenant has ten users per city, and what counts is
/// that the successes outnumber the failed-only users.)
fn office_stale_accounts(w: &mut World, ctx: &mut Ctx) -> Result<()> {
    const CODES: [i64; 5] = [50057, 50034, 50055, 50057, 50034];
    let a: User = ctx.a.clone();
    let staff = city_staff(w, &a, 10);
    let others: Vec<User> = w
        .users
        .iter()
        .filter(|u| u.home.city != a.home.city)
        .take(CODES.len())
        .cloned()
        .collect();
    if staff.len() < 8 || others.len() < CODES.len() {
        return Err(Error::Scenario(format!(
            "{}: stale accounts behind an office need 8 users in {} and {} others, the tenant has {} and {}",
            ctx.spec.id,
            a.home.city,
            CODES.len(),
            staff.len(),
            others.len()
        )));
    }
    let nat = ctx.shared.next_egress();
    let location = a.home.clone();
    for (k, user) in staff.iter().enumerate() {
        let s = password_signin(
            w,
            ctx,
            user,
            ctx.t + Duration::minutes(k as i64 * 5),
            nat,
            &location,
            well_known("OfficeHome"),
        );
        push_signin(w, ctx, user, s, true);
    }
    for (k, user) in others.iter().enumerate() {
        for attempt in 0..3i64 {
            let when = ctx.t + Duration::minutes(k as i64 * 11 + attempt * 60);
            let s = failed_signin(w, ctx, user, when, nat, &location, CODES[k], None);
            push_signin(w, ctx, user, s, true);
        }
    }
    Ok(())
}
