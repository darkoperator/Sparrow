//! GeoLite2-style City and ASN databases for a generated tree, so Sparrow's `--geoip-dir`
//! enrichment sees the world's ground-truth locations: every person's office and home address
//! (their home location), the attacker's addresses, and every address a storyline used
//! (sign-ins and risk detections carry their location; any other storyline address, such as a
//! mail sender's, gets `OTHER_LOCATION`). Each address is a /32 or /128 network.

use crate::Result;
use crate::tree::Sink;
use crate::world::{LOCATIONS, Location, World};
use sparrow_core::enrich::mmdb_writer::{MmdbValue, asn, city, write_mmdb};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// The `LOCATIONS` entry for storyline addresses no event locates (a documentation-ISP city
/// that is never a user home).
pub const OTHER_LOCATION: usize = 6;

/// Every address of the world with its location; the first source to name an address wins
/// (people, then the attacker, then storyline sign-ins and risk detections, then other
/// storyline addresses).
fn locations(w: &World) -> BTreeMap<IpAddr, Location> {
    let mut m: BTreeMap<IpAddr, Location> = BTreeMap::new();
    for u in w.all_people() {
        m.entry(u.office_ip).or_insert_with(|| u.home.clone());
        m.entry(u.home_ip).or_insert_with(|| u.home.clone());
    }
    let a = &w.attacker;
    m.entry(a.proxy_ip).or_insert_with(|| a.location.clone());
    m.entry(a.replay_ip)
        .or_insert_with(|| a.replay_location.clone());
    m.entry(a.send_ip).or_insert_with(|| a.location.clone());
    m.entry(a.mailbox_ip).or_insert_with(|| a.location.clone());
    for s in &w.story.signins {
        m.entry(s.ip).or_insert_with(|| s.location.clone());
    }
    for (ip, loc) in &w.story.located {
        m.entry(*ip).or_insert_with(|| loc.clone());
    }
    for r in &w.story.risk {
        if let (Some(ip), Some(loc)) = (r.ip, &r.location) {
            m.entry(ip).or_insert_with(|| loc.clone());
        }
    }
    let other = &LOCATIONS[OTHER_LOCATION];
    let mut rest: Vec<IpAddr> = Vec::new();
    rest.extend(
        w.story
            .ual
            .iter()
            .filter_map(|u| u.client_ip().and_then(|t| t.parse::<IpAddr>().ok())),
    );
    rest.extend(
        w.story
            .trace
            .iter()
            .flat_map(|t| [t.from_ip, t.to_ip])
            .flatten(),
    );
    rest.extend(w.story.audits.iter().filter_map(|d| d.initiated_by.ip));
    for ip in rest {
        m.entry(ip).or_insert_with(|| other.clone());
    }
    m
}

/// The City and ASN database entries, one per address, sorted by address.
#[allow(clippy::type_complexity)]
pub fn geo_entries(world: &World) -> (Vec<(IpAddr, u8, MmdbValue)>, Vec<(IpAddr, u8, MmdbValue)>) {
    let mut cities = Vec::new();
    let mut asns = Vec::new();
    for (ip, loc) in locations(world) {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        cities.push((
            ip,
            prefix,
            city(&loc.country_iso, &loc.country, &loc.city, loc.lat, loc.lon),
        ));
        asns.push((ip, prefix, asn(loc.asn, &loc.asn_org)));
    }
    (cities, asns)
}

/// Writes `<dir>/GeoLite2-City.mmdb` and `<dir>/GeoLite2-ASN.mmdb` (`dir` relative to the
/// output directory), built at the collection time.
pub fn write_geoip(world: &World, sink: &mut dyn Sink, dir: &str) -> Result<()> {
    let (cities, asns) = geo_entries(world);
    let epoch = world.collected_at().timestamp().max(0) as u64;
    sink.append(
        &format!("{dir}/GeoLite2-City.mmdb"),
        &write_mmdb("GeoLite2-City", epoch, &cities),
    )?;
    sink.append(
        &format!("{dir}/GeoLite2-ASN.mmdb"),
        &write_mmdb("GeoLite2-ASN", epoch, &asns),
    )
}
