//! Microsoft-Extractor-Suite Get-MailboxPermissions
//! (`Mailbox Permissions/<ts>/<ts>-MailboxPermissions.csv`): one row per mailbox with its
//! grants packed in strings (FullAccess, SendAs, SendOnBehalf, Calendar and Inbox folder
//! permissions). Each grant becomes a `mailbox_permissions` row; the mailbox itself fills
//! `mailboxes` (upn, display name, recipient type).

use crate::Result;
use crate::db::state_tables::{MAILBOX_PERMISSIONS, MAILBOXES};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::mailbox::mailbox_key;
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, load_tables, read_state_records, reject, require_any_key,
};
use regex::Regex;
use std::sync::OnceLock;

pub fn register(r: &mut ParserRegistry) {
    r.register(
        "inv.mailbox_permissions",
        Box::new(MailboxPermissionsParser),
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Grantee as exported: `"<DisplayName> (<smtp>)"` or a raw identity.
    pub grantee: String,
    /// `full_access`, `send_as`, `send_on_behalf` or `folder` (the `mailbox_right` enum).
    pub permission: &'static str,
    /// `calendar` or `inbox` for folder grants.
    pub folder: Option<&'static str>,
    pub access_rights: Vec<String>,
    pub deny: Option<bool>,
    pub inheritance: Option<String>,
    /// The entry did not match the collector's format; `grantee` holds it whole.
    pub unparsed: bool,
}

fn cached(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

fn re_full_access() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(
        &R,
        r"^(?P<user>.+?) - Rights: (?P<rights>.*), Deny: (?P<deny>\w+), Inheritance: (?P<inh>\w+)$",
    )
}

fn re_send_as() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(
        &R,
        r"^(?P<user>.+?) - Type: (?P<type>\w+), Rights: (?P<rights>.*), Inheritance: (?P<inh>\w+)$",
    )
}

/// `"<DisplayName> (<SMTP>) - <rights>"` (CalendarUsers / InboxUsers).
fn re_folder_user() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"^(?P<user>.+) - (?P<rights>[^-]+)$")
}

/// `"<DisplayName>: <rights>"` (CalendarPermissions / InboxPermissions).
fn re_folder_perm() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"^(?P<user>.+): (?P<rights>[^:]+)$")
}

/// `...(<smtp>)` at the end of a grantee.
fn re_smtp() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    cached(&R, r"\(([^()\s]+@[^()\s]+)\)\s*$")
}

/// The SMTP address in a grantee text, lower-case.
pub fn grantee_upn(grantee: &str) -> Option<String> {
    if let Some(c) = re_smtp().captures(grantee) {
        return Some(c[1].to_lowercase());
    }
    let g = grantee.trim();
    (g.contains('@') && !g.contains(char::is_whitespace)).then(|| g.to_lowercase())
}

fn entries(v: Option<String>, sep: &str) -> Vec<String> {
    v.map(|s| {
        s.split(sep)
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(String::from)
            .collect()
    })
    .unwrap_or_default()
}

/// Rights joined with `,` (FullAccess) or spaces (string interpolation of an array).
fn rights(s: &str) -> Vec<String> {
    s.split([',', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

fn bool_text(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn plain(grantee: String, permission: &'static str, folder: Option<&'static str>) -> Grant {
    Grant {
        grantee,
        permission,
        folder,
        access_rights: Vec::new(),
        deny: None,
        inheritance: None,
        unparsed: false,
    }
}

fn unparsed(text: String, permission: &'static str, folder: Option<&'static str>) -> Grant {
    Grant {
        unparsed: true,
        ..plain(text, permission, folder)
    }
}

fn full_access(e: String) -> Grant {
    match re_full_access().captures(&e) {
        Some(c) => Grant {
            grantee: c["user"].trim().to_string(),
            permission: "full_access",
            folder: None,
            access_rights: rights(&c["rights"]),
            deny: bool_text(&c["deny"]),
            inheritance: Some(c["inh"].to_string()),
            unparsed: false,
        },
        None => unparsed(e, "full_access", None),
    }
}

fn send_as(e: String) -> Grant {
    match re_send_as().captures(&e) {
        Some(c) => Grant {
            grantee: c["user"].trim().to_string(),
            permission: "send_as",
            folder: None,
            access_rights: rights(&c["rights"]),
            deny: Some(c["type"].eq_ignore_ascii_case("deny")),
            inheritance: Some(c["inh"].to_string()),
            unparsed: false,
        },
        None => unparsed(e, "send_as", None),
    }
}

fn folder_grant(e: String, re: &Regex, folder: &'static str) -> Grant {
    match re.captures(&e) {
        Some(c) => Grant {
            access_rights: rights(&c["rights"]),
            ..plain(c["user"].trim().to_string(), "folder", Some(folder))
        },
        None => unparsed(e, "folder", Some(folder)),
    }
}

/// Every grant of one mailbox row, in column order.
pub fn grants(rec: &Rec) -> Vec<Grant> {
    let mut out = Vec::new();
    let detailed = entries(rec.text("FullAccessPermissions"), " | ");
    if detailed.is_empty() {
        out.extend(
            entries(rec.text("FullAccessUsers"), "; ")
                .into_iter()
                .map(|u| plain(u, "full_access", None)),
        );
    } else {
        out.extend(detailed.into_iter().map(full_access));
    }
    let detailed = entries(rec.text("SendAsPermissions"), " | ");
    if detailed.is_empty() {
        out.extend(
            entries(rec.text("SendAsUsers"), "; ")
                .into_iter()
                .map(|u| plain(u, "send_as", None)),
        );
    } else {
        out.extend(detailed.into_iter().map(send_as));
    }
    out.extend(
        entries(rec.text("SendOnBehalfUsers"), "; ")
            .into_iter()
            .map(|u| plain(u, "send_on_behalf", None)),
    );
    for (users, perms, folder) in [
        ("CalendarUsers", "CalendarPermissions", "calendar"),
        ("InboxUsers", "InboxPermissions", "inbox"),
    ] {
        let by_user = entries(rec.text(users), "; ");
        if by_user.is_empty() {
            out.extend(
                entries(rec.text(perms), " | ")
                    .into_iter()
                    .map(|e| folder_grant(e, re_folder_perm(), folder)),
            );
        } else {
            out.extend(
                by_user
                    .into_iter()
                    .map(|e| folder_grant(e, re_folder_user(), folder)),
            );
        }
    }
    out
}

const COLS: &[&str] = &[
    "mailbox_upn",
    "mailbox_display_name",
    "recipient_type",
    "grantee",
    "grantee_upn",
    "permission",
    "folder",
    "access_rights",
    "deny",
    "inheritance",
];
const MAILBOX_COLS: &[&str] = &["upn", "display_name", "recipient_type"];

pub struct MailboxPermissionsParser;

impl ArtifactParser for MailboxPermissionsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(
            &records,
            &[
                "FullAccessPermissions",
                "FullAccessUsers",
                "SendAsPermissions",
            ],
            "mailbox permission",
        )?;
        let mut grant_rows = TableRows::new(&MAILBOX_PERMISSIONS, COLS);
        let mut mailbox_rows = TableRows::new(&MAILBOXES, MAILBOX_COLS);
        let mut unmatched = 0usize;
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(mailbox) = mailbox_key(&rec, None) else {
                reject(ctx, r, "mailbox permission row has no UserPrincipalName")?;
                continue;
            };
            let display = rec.text("DisplayName");
            let recipient_type = rec.text("RecipientTypeDetails");
            mailbox_rows.push(
                r,
                mailbox.clone(),
                vec![
                    Cell::text(Some(mailbox.clone())),
                    Cell::text(display.clone()),
                    Cell::text(recipient_type.clone()),
                ],
            );
            for g in grants(&rec) {
                unmatched += usize::from(g.unparsed);
                let key = format!(
                    "{mailbox}|{}|{}|{}",
                    g.permission,
                    g.folder.unwrap_or(""),
                    g.grantee.to_lowercase()
                );
                let mut c = CellRow::new(COLS);
                c.set("mailbox_upn", Cell::text(Some(mailbox.clone())))
                    .set("mailbox_display_name", Cell::text(display.clone()))
                    .set("recipient_type", Cell::text(recipient_type.clone()))
                    .set("grantee_upn", Cell::text(grantee_upn(&g.grantee)))
                    .set("permission", Cell::text(Some(g.permission.into())))
                    .set("folder", Cell::text(g.folder.map(Into::into)))
                    .set("access_rights", Cell::list(g.access_rights))
                    .set("deny", Cell::bool(g.deny))
                    .set("inheritance", Cell::text(g.inheritance))
                    .set("grantee", Cell::text(Some(g.grantee)));
                grant_rows.push(r, key, c.into_cells());
            }
        }
        if unmatched > 0 {
            ctx.warn(format!(
                "{unmatched} permission entries did not match the collector's format; each is stored whole as the grantee"
            ));
        }
        load_tables(ctx, vec![mailbox_rows, grant_rows])
    }
}
