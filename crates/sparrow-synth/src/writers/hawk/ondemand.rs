//! The on-demand cmdlets an analyst runs after the investigations (research hawk layouts
//! §1.4): `Search-HawkTenantActivityByIP` for each attacker address found in the logged UAL
//! records, and `Get-HawkMessageHeader` for each e-mail exported as a `.msg` file.

use super::omft::{Art, Formats};
use super::{Ctx, expanded_row, r, register_ual, s, text_of};
use crate::Result;
use crate::events::Ual;
use crate::ps::{Row, Val};
use crate::tree::Tree;
use crate::world::Email;
use std::collections::BTreeSet;

pub(super) fn run(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    c.log().tick(60, 300);
    let a = &c.world.attacker;
    let mut seen = BTreeSet::new();
    let ips: Vec<String> = [a.proxy_ip, a.replay_ip, a.send_ip, a.mailbox_ip]
        .iter()
        .map(|ip| ip.to_string())
        .filter(|ip| seen.insert(ip.clone()))
        .collect();
    for ip in ips {
        if c.ual.iter().any(|u| u.client_ip() == Some(ip.as_str())) {
            activity_by_ip(c, tree, &ip)?;
            c.log().tick(10, 60);
        }
    }
    let mut names = BTreeSet::new();
    let emails = c.world.emails.clone();
    for e in &emails {
        let name = msg_file_name(e, &mut names);
        message_header(c, tree, e, &name)?;
        c.log().tick(10, 60);
    }
    Ok(())
}

/// Search-HawkTenantActivityByIP: every record from the address (expanded AuditData), the
/// successful ones, and the first record per user (`Unique_Users_Success` is never written:
/// Hawk tests its variable before setting it).
fn activity_by_ip(c: &mut Ctx<'_>, tree: &mut Tree<'_>, ip: &str) -> Result<()> {
    let dir = ip.replace(':', ".");
    c.log()
        .info("Initiating collection of IP-based activity from the UAL.");
    c.log()
        .action(format!("Searching for events related to {ip}"));
    let found = c.search(&format!("Search-UnifiedAuditLog -IPAddresses {ip}"), |u| {
        u.client_ip() == Some(ip)
    });
    if found.is_empty() {
        c.log()
            .info("Get-HawkTenantActivityByIP completed successfully");
        c.log()
            .action(format!("No IP logon events found for IP {ip}"));
    } else {
        let rows: Vec<Row> = found.iter().map(expanded_row).collect();
        c.log()
            .info(format!("Found {} related to provided IP", rows.len()));
        let w = c.omft.write(
            tree,
            "All_Events",
            Some(&dir),
            Art::raw("hawk.ip.events"),
            &rows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register_ual(tree, &w, &found);
        let success: Vec<(Row, Ual)> = rows
            .iter()
            .zip(&found)
            .filter(|(row, _)| {
                text_of(row, "ResultStatus").is_some_and(|v| v.eq_ignore_ascii_case("success"))
            })
            .map(|(row, u)| (row.clone(), u.clone()))
            .collect();
        c.log().info(format!(
            "Found {} Successful logons related to provided IP",
            success.len()
        ));
        let (srows, srecs): (Vec<Row>, Vec<Ual>) = success.into_iter().unzip();
        let w = c.omft.write(
            tree,
            "Success_Events",
            Some(&dir),
            Art::raw("hawk.ip.events"),
            &srows,
            Formats::CSV_JSON,
            false,
            false,
        )?;
        register_ual(tree, &w, &srecs);
        let mut users = BTreeSet::new();
        let unique: Vec<Row> = rows
            .iter()
            .filter(|row| users.insert(text_of(row, "UserId").unwrap_or_default()))
            .cloned()
            .collect();
        c.log().notice(format!(
            "IP {ip} has tried to access {} users",
            unique.len()
        ));
        c.omft.write(
            tree,
            "Unique_Users_Attempted",
            Some(&dir),
            Art::derived("hawk.ip.unique_users").without_parser(),
            &unique,
            Formats::CSV_JSON,
            false,
            true,
        )?;
        c.log().plain(format!(
            "No Successful Logon Events found for this IP: {ip}"
        ));
    }
    c.log()
        .info("Completed collection of IP-based activity from the UAL.");
    Ok(())
}

/// The name an analyst saves a message under: its subject without the characters Windows
/// forbids in file names, `.msg`; a repeated name gets ` (2)`, ` (3)`...
fn msg_file_name(e: &Email, taken: &mut BTreeSet<String>) -> String {
    let stem: String = e
        .subject
        .chars()
        .filter(|c| !"\\/:*?\"<>|".contains(*c))
        .collect();
    let stem = stem.trim().to_string();
    let mut name = format!("{stem}.msg");
    let mut n = 2;
    while !taken.insert(name.to_lowercase()) {
        name = format!("{stem} ({n}).msg");
        n += 1;
    }
    name
}

/// The transport headers Outlook keeps for a received message (property 0x007D), one
/// `Name: value` line each, newest `Received` first.
fn header_lines(e: &Email) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = e
        .received
        .iter()
        .map(|r| ("Received".to_string(), r.clone()))
        .collect();
    v.extend([
        ("Authentication-Results".into(), e.auth_results.clone()),
        ("Return-Path".into(), e.return_path.clone()),
        (
            "From".into(),
            format!("\"{}\" <{}>", e.from_display, e.from),
        ),
        ("To".into(), e.to.join(", ")),
        ("Subject".into(), e.subject.clone()),
        ("Date".into(), e.date.to_rfc2822()),
        ("Message-ID".into(), e.message_id.clone()),
        ("MIME-Version".into(), "1.0".into()),
        (
            "Content-Type".into(),
            "text/plain; charset=\"utf-8\"".into(),
        ),
        (
            "X-MS-Exchange-Organization-AuthAs".into(),
            e.auth_as.clone(),
        ),
        (
            "X-MS-Exchange-Organization-AuthMechanism".into(),
            e.auth_mechanism.clone(),
        ),
    ]);
    v
}

/// `Convert-ReceiveHeader`: (by, with) of a `from X by Y with Z; date` header.
fn received_by_with(h: &str) -> Option<(String, String)> {
    let rest = h.trim_start().strip_prefix("from")?;
    let (_, rest) = rest.split_once("by")?;
    let (by, rest) = rest.split_once("with")?;
    let (with, _) = rest.split_once(';')?;
    let with = with.trim();
    let with = if with.starts_with("SMTP") {
        "SMTP".to_string()
    } else if with.starts_with("ESMTP") {
        "ESMTP".to_string()
    } else {
        with.to_string()
    };
    Some((by.trim().to_string(), with))
}

fn finding(rule: &str, value: &str, conclusion: &str, more: &str) -> Row {
    vec![
        r("Rule", s(rule)),
        r("Value", s(value)),
        r("Conclusion", s(conclusion)),
        r("More Information", s(more)),
    ]
}

/// Get-HawkMessageHeader: the header as `Header, Value` rows, Hawk's findings, and the raw
/// header string (`Format-List *` of a string: its `Length`), in `<root>/<file name>/`.
fn message_header(c: &mut Ctx<'_>, tree: &mut Tree<'_>, e: &Email, name: &str) -> Result<()> {
    let path = if c.opts.non_windows {
        format!("/Users/Shared/Investigations/{name}")
    } else {
        format!("C:\\Investigations\\{name}")
    };
    c.log()
        .action(format!("Reading message header from file {path}"));
    let lines = header_lines(e);
    let raw: String = lines.iter().map(|(k, v)| format!("{k}: {v}\r\n")).collect();
    let output: Vec<Row> = lines
        .iter()
        .map(|(k, v)| vec![r("Header", s(k.clone())), r("Value", s(v.clone()))])
        .collect();
    let docs = "https://docs.microsoft.example/en-us/exchange/header-firewall-exchange-2013-help";
    let mut findings = Vec::new();
    if let Some((by, with)) = e.received.first().and_then(|h| received_by_with(h)) {
        if by.to_lowercase().contains("outlook.com") {
            findings.push(finding(
                "Submitting Host",
                &by,
                "Submitted from Office 365",
                "Warning - This might have originated from one of your clients",
            ));
        } else {
            findings.push(finding(
                "Submitting Host",
                &by,
                "Submitted from Internet",
                "",
            ));
        }
        findings.push(finding("Submitting Client", &with, "None", ""));
    }
    findings.push(finding(
        "Authentication Method",
        &e.auth_as,
        "Method used to authenticate",
        docs,
    ));
    let mechanism = if e.auth_mechanism == "04" || e.auth_mechanism == "06" {
        "04 = Credentials Used; 06 = SMTP Authentication"
    } else {
        "Mechanism used to authenticate"
    };
    findings.push(finding(
        "Authentication Mechanism",
        &e.auth_mechanism,
        mechanism,
        docs,
    ));
    let from = format!("\"{}\" <{}>", e.from_display, e.from);
    let from_address = from
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map_or(from.clone(), |(a, _)| a.to_string());
    let value = format!("From: {from};  Return-Path: {}", e.return_path);
    if from_address
        .trim()
        .eq_ignore_ascii_case(e.return_path.trim())
    {
        findings.push(finding("P1 P2 Match", &value, "P1 and P2 Header match", ""));
    } else {
        findings.push(finding(
            "P1 P2 Match",
            &value,
            "P1 and P2 Header don't Match",
            "WARNING - P1 and P2 Header don't Match",
        ));
    }
    c.omft.write(
        tree,
        "Message_Header_Findings",
        Some(name),
        Art::not_supported("hawk.message.header"),
        &findings,
        Formats::CSV,
        false,
        false,
    )?;
    c.omft.write(
        tree,
        "Message_Header",
        Some(name),
        Art::not_supported("hawk.message.header"),
        &output,
        Formats::CSV,
        false,
        false,
    )?;
    let length = vec![vec![r(
        "Length",
        Val::Int(raw.encode_utf16().count() as i64),
    )]];
    c.omft.write(
        tree,
        "Message_Header_RAW",
        Some(name),
        Art::not_supported("hawk.message.header_raw"),
        &length,
        Formats::TXT,
        false,
        false,
    )?;
    Ok(())
}
