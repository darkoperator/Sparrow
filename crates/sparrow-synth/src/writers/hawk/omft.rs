//! `Out-MultipleFileType` (Hawk `internal/functions/Out-MultipleFileType.ps1`; research hawk
//! layouts §2): collects its pipeline input and writes it as CSV (`Export-Csv -Encoding UTF8`,
//! header = the first object's properties), TXT (`Format-List * | Out-File`, default
//! encoding) and JSON (`ConvertTo-Json -Depth 100 | Out-File -Encoding UTF8`: one object gives
//! a bare object, several an array), in that order, into `<root>\Tenant` or `<root>\<User>`
//! as `<Prefix>[_<part of User before @>].<ext>`. `-Append` adds CSV rows under the existing
//! header and another complete JSON document; no input writes no file (`No Data Found`).
//! `-Notice` logs each written file to `_Investigate.txt`.
//!
//! The Tenant folder is `Join-Path <root> "\Tenant"`: with `non_windows` (PowerShell 7 on
//! macOS/Linux) that is a literal folder named `\Tenant` beside the `Tenant` folder the
//! collectors create themselves (research §1.1).

use super::log::Log;
use crate::Result;
use crate::ps::{
    DateEvidence, Encoding, Host, Row, convert_to_json, export_csv, export_csv_append, format_list,
};
use crate::tree::{FileSpec, Tree};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Which files one call writes (`-csv`, `-json`, `-txt`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Formats {
    pub csv: bool,
    pub json: bool,
    pub txt: bool,
}

impl Formats {
    pub const CSV_JSON: Formats = Formats {
        csv: true,
        json: true,
        txt: false,
    };
    pub const CSV: Formats = Formats {
        csv: true,
        json: false,
        txt: false,
    };
    pub const JSON: Formats = Formats {
        csv: false,
        json: true,
        txt: false,
    };
    pub const TXT: Formats = Formats {
        csv: false,
        json: false,
        txt: true,
    };
}

/// One file a call wrote: its tree path and each object's 1-based line span in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub rel: String,
    pub spans: Vec<(u32, u32)>,
}

/// The files one call wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Written {
    pub csv: Option<Part>,
    pub txt: Option<Part>,
    pub json: Option<Part>,
}

impl Written {
    pub fn parts(&self) -> impl Iterator<Item = &Part> {
        self.csv
            .iter()
            .chain(self.txt.iter())
            .chain(self.json.iter())
    }
}

/// Sparrow's Hawk artifact patterns (`sparrow_core::discovery::registry`, copied by hand, in
/// declaration order): (id, derived, pattern with an optional `subject` group).
const HAWK_ARTIFACTS: &[(&str, bool, &str)] = &[
    ("hawk.log", false, r"Hawk\.log"),
    ("hawk.investigate_txt", false, r"_Investigate\.txt"),
    (
        "hawk.investigate_file",
        false,
        r"(?:(?P<subject>[^/]+@[^/]+)/|[^/]+/)?_Investigate_[^/]+\.(?:csv|json|txt)",
    ),
    (
        "hawk.psframework_log",
        false,
        r"\d{4}-\d{2}-\d{2}_logs\.csv",
    ),
    (
        "hawk.tenant.admin_audit_log_config",
        false,
        r"Tenant/AdminAuditLogConfig\.txt",
    ),
    ("hawk.tenant.org_config", false, r"Tenant/OrgConfig\.txt"),
    (
        "hawk.tenant.remote_domain",
        false,
        r"Tenant/RemoteDomain\.(?:csv|json)",
    ),
    (
        "hawk.tenant.transport_rules",
        false,
        r"Tenant/TransportRules\.(?:csv|json)",
    ),
    (
        "hawk.tenant.transport_config",
        false,
        r"Tenant/TransportConfig\.(?:csv|json)",
    ),
    (
        "hawk.tenant.ediscovery_roles",
        false,
        r"Tenant/(?:Custom)?EDiscoveryRoles\.(?:csv|json)",
    ),
    (
        "hawk.tenant.ediscovery_role_assignments",
        false,
        r"Tenant/EDiscoveryRoleAssignments\.(?:csv|json)",
    ),
    (
        "hawk.tenant.impersonation",
        false,
        r"Tenant/Impersonation_(?:Rights|Roles)\.(?:csv|json)",
    ),
    (
        "hawk.tenant.admin_audit",
        false,
        r"Tenant/(?:New|Set|Remove)_InboxRules\.(?:csv|json)",
    ),
    (
        "hawk.tenant.all_inbox_rules",
        true,
        r"Tenant/All_InboxRules\.(?:csv|json)",
    ),
    (
        "hawk.tenant.azuread_users",
        false,
        r"Tenant/AzureADUsers\.(?:csv|json)",
    ),
    (
        "hawk.tenant.azuread_admins",
        false,
        r"Tenant/AzureADAdministrators\.(?:csv|json)",
    ),
    (
        "hawk.tenant.simple_ual",
        true,
        r"Tenant/Simple_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.tenant.raw_ual",
        false,
        r"Tenant/(?:eDiscoveryLogs|Admin_Inbox_Rules_(?:Creation|Modification|Removal)|Mailbox_Permission_Change|Forwarding_Changes|RBAC_Changes|Domain_Changes_Audit)\.(?:csv|json)",
    ),
    (
        "hawk.tenant.forwarding_recipients",
        true,
        r"Tenant/Forwarding_Recipients\.(?:csv|json)",
    ),
    (
        "hawk.tenant.entra_app_audit",
        false,
        r"Tenant/(?:Entra_ID|Azure)_Application_Audit\.(?:csv|json)",
    ),
    (
        "hawk.tenant.entra_audit",
        false,
        r"Tenant/EntraIDAuditLogs\.(?:csv|json)",
    ),
    (
        "hawk.tenant.exo_admins",
        false,
        r"Tenant/ExchangeOnlineAdministrators\.(?:csv|json)",
    ),
    (
        "hawk.tenant.entra_admins",
        false,
        r"Tenant/EntraIDAdministrators\.(?:csv|json)",
    ),
    (
        "hawk.tenant.consent_grants",
        false,
        r"Tenant/Consent_Grants\.(?:csv|json)",
    ),
    (
        "hawk.tenant.risky_users",
        false,
        r"Tenant/RiskyUsers\.(?:csv|json)",
    ),
    (
        "hawk.tenant.risk_detections",
        false,
        r"Tenant/Risk_Detections\.(?:csv|json)",
    ),
    (
        "hawk.tenant.app_credentials",
        false,
        r"Tenant/(?:SPN|Application)CertsAndSecrets\.(?:csv|json)",
    ),
    (
        "hawk.tenant.entra_users",
        false,
        r"Tenant/EntraIDUsers\.(?:csv|json)",
    ),
    (
        "hawk.tenant.all_sweep_rules",
        true,
        r"Tenant/All_SweepRules\.(?:csv|json)",
    ),
    (
        "hawk.tenant.user_forwarding_report",
        true,
        r"Tenant/User_ForwardingReport\.(?:csv|json)",
    ),
    ("hawk.tenant.help", false, r"Tenant/Hawk_Help\.txt"),
    (
        "hawk.user.mailbox_txt",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:CAS_)?Mailbox_Info_[^/]+\.txt",
    ),
    (
        "hawk.user.mailbox_stats_txt",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Mailbox_(?:Folder_|Archive_)?Statistics_[^/]+\.txt",
    ),
    (
        "hawk.user.inbox_rules",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:All_)?InboxRules_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.sweep_rules",
        false,
        r"(?P<subject>[^/]+@[^/]+)/SweepRules_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.forwarding",
        false,
        r"(?P<subject>[^/]+@[^/]+)/ForwardingReport_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.autoreply",
        false,
        r"(?P<subject>[^/]+@[^/]+)/AutoReply_[^/]+\.txt",
    ),
    (
        "hawk.user.entra_signin",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Entra_Sign_In_Log_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.converted_auth",
        true,
        r"(?P<subject>[^/]+@[^/]+)/Converted_Authentication_Logs_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.raw_auth",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:Raw|Failed_Conversion)_Authentication_Logs_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.simple_ual",
        true,
        r"(?P<subject>[^/]+@[^/]+)/(?:Simple_[^/]+|ExchangeItem(?:Group)?_Simple_[^/]+)\.(?:csv|json)",
    ),
    (
        "hawk.user.raw_ual",
        false,
        r"(?P<subject>[^/]+@[^/]+)/(?:ExchangeItem(?:Group)?_Logs|User_Changes|MailItemsAccessed|ExchangeSearchQueries|SendActivity|SharePointSearches|Exchange_UAL_Audit)_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.message_trace",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Message_Trace_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.mailbox_audit_legacy",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Exchange_Mailbox_Audit_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.mobile_devices",
        false,
        r"(?P<subject>[^/]+@[^/]+)/MobileDevices_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.user.hibp",
        false,
        r"(?P<subject>[^/]+@[^/]+)/Have_I_Been_Pwned_[^/]+\.txt",
    ),
    (
        "hawk.ip.events",
        false,
        r"(?P<subject>[0-9A-Fa-f.]+)/(?:All|Success)_Events_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.ip.unique_users",
        true,
        r"(?P<subject>[0-9A-Fa-f.]+)/Unique_Users_Attempted_[^/]+\.(?:csv|json)",
    ),
    (
        "hawk.message.header_raw",
        false,
        r"(?P<subject>[^/]+)/Message_Header_RAW_[^/]+\.txt",
    ),
    (
        "hawk.message.header",
        false,
        r"(?P<subject>[^/]+)/Message_Header(?:_Findings)?_[^/]+\.csv",
    ),
    ("hawk.xml", false, r"(?:[^/]+/)?XML/[^/]+\.xml"),
];

/// How Sparrow classifies a Hawk file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Class {
    pub artifact: Option<&'static str>,
    pub derived: bool,
    pub subject: Option<String>,
}

/// The classification of Hawk file `rel` (a path below the collection root; a `\` in a folder
/// name reads as `/` and leading separators are dropped, as Sparrow normalizes paths).
pub fn classify(rel: &str) -> Class {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    let res = RES.get_or_init(|| {
        HAWK_ARTIFACTS
            .iter()
            .map(|(_, _, p)| Regex::new(&format!("(?i)^(?:{p})$")).expect("valid pattern"))
            .collect()
    });
    let replaced = rel.replace('\\', "/");
    let mut s = replaced.as_str();
    while let Some(rest) = s.strip_prefix("./").or_else(|| s.strip_prefix('/')) {
        s = rest;
    }
    let mut norm = s.to_string();
    while norm.contains("//") {
        norm = norm.replace("//", "/");
    }
    for ((id, derived, _), re) in HAWK_ARTIFACTS.iter().zip(res) {
        if let Some(c) = re.captures(&norm) {
            return Class {
                artifact: Some(id),
                derived: *derived,
                subject: c.name("subject").map(|m| m.as_str().to_string()),
            };
        }
    }
    Class {
        artifact: None,
        derived: false,
        subject: None,
    }
}

/// The `FileSpec` of Hawk file `rel` written with `encoding`.
pub fn spec(rel: &str, encoding: Encoding) -> FileSpec {
    let c = classify(rel);
    let mut s = FileSpec::new(rel, c.artifact, encoding);
    s.derived = c.derived;
    s.subject = c.subject;
    s
}

/// The Out-MultipleFileType emulation of one Hawk output folder, with its log.
#[derive(Debug, Clone)]
pub struct Omft {
    /// The session writing (edition, culture, line ends): tenant and user investigations may
    /// run in different sessions.
    pub host: Host,
    pub log: Log,
    /// `$Hawk.FilePath` as the collecting host prints it.
    pub file_path: String,
    /// PowerShell 7 on macOS/Linux: `/` separators and the literal `\Tenant` folder.
    pub non_windows: bool,
    csv_headers: BTreeMap<String, Vec<String>>,
    json_docs: BTreeMap<String, u32>,
    dirs: BTreeSet<String>,
}

impl Omft {
    pub fn new(host: Host, log: Log, file_path: String, non_windows: bool) -> Omft {
        Omft {
            host,
            log,
            file_path,
            non_windows,
            csv_headers: BTreeMap::new(),
            json_docs: BTreeMap::new(),
            dirs: BTreeSet::new(),
        }
    }

    /// The folder (tree path) Out-MultipleFileType writes tenant files to.
    pub fn tenant_dir(&self) -> &'static str {
        if self.non_windows {
            "\\Tenant"
        } else {
            "Tenant"
        }
    }

    /// `Join-Path $Hawk.FilePath <dir> <file>` as the host prints it.
    pub fn shown(&self, dir: &str, file: &str) -> String {
        if self.non_windows {
            format!("{}/{dir}/{file}", self.file_path)
        } else {
            let dir = dir.trim_start_matches('\\');
            format!("{}\\{dir}\\{file}", self.file_path)
        }
    }

    /// Records that a collector created folder `dir` itself (`New-Item`, no log line).
    pub fn created(&mut self, dir: &str) {
        self.dirs.insert(dir.to_string());
    }

    /// The tree path of a file Out-MultipleFileType would write for `prefix`, `user` and
    /// extension `ext`.
    pub fn rel(&self, prefix: &str, user: Option<&str>, ext: &str) -> String {
        match user {
            Some(u) => {
                let short = u.split('@').next().unwrap_or(u);
                format!("{u}/{prefix}_{short}.{ext}")
            }
            None => format!("{}/{prefix}.{ext}", self.tenant_dir()),
        }
    }

    /// Writes `rows` like `rows | Out-MultipleFileType -FilePrefix <prefix> [-User <user>]
    /// <formats> [-Append] [-Notice]`. `user` is the `-User` string (a UPN, an IP folder, a
    /// message file name). No rows: logs `No Data Found` and writes nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn write(
        &mut self,
        tree: &mut Tree<'_>,
        prefix: &str,
        user: Option<&str>,
        rows: &[Row],
        formats: Formats,
        append: bool,
        notice: bool,
    ) -> Result<Written> {
        let dir = match user {
            Some(u) => u.to_string(),
            None => self.tenant_dir().to_string(),
        };
        if !self.dirs.contains(&dir) {
            let (what, shown) = match user {
                Some(_) => ("user", self.shown_dir(&dir)),
                None => ("Tenant", self.shown_dir(&dir)),
            };
            self.log
                .action(format!("Making output directory for {what} {shown}"));
            self.dirs.insert(dir.clone());
        }
        let mut out = Written::default();
        if rows.is_empty() {
            self.log.action("No Data Found");
            return Ok(out);
        }
        let host = self.host;
        let utf8 = Encoding::export_csv_utf8(host.edition);
        if formats.csv {
            let rel = self.rel(prefix, user, "csv");
            let mut ev = DateEvidence::default();
            let (text, spans) = match self.csv_headers.get(&rel) {
                Some(header) if append => {
                    let r = export_csv_append(&host, header, rows, &mut ev);
                    (r.text, r.spans)
                }
                _ => {
                    let header: Vec<String> = rows[0].iter().map(|(k, _)| k.clone()).collect();
                    self.csv_headers.insert(rel.clone(), header);
                    let r = export_csv(&host, rows, &mut ev);
                    (r.text, r.spans)
                }
            };
            out.csv = Some(self.put(tree, &rel, utf8, &text, spans, append, notice)?);
            if ev.culture_dates > 0 {
                tree.date_evidence(&rel, ev);
            }
        }
        if formats.txt {
            let rel = self.rel(prefix, user, "txt");
            let mut ev = DateEvidence::default();
            let r = format_list(&host, rows, &mut ev);
            let enc = Encoding::out_file_default(host.edition);
            out.txt = Some(self.put(tree, &rel, enc, &r.text, r.spans, append, notice)?);
            if ev.culture_dates > 0 {
                tree.date_evidence(&rel, ev);
            }
        }
        if formats.json {
            let rel = self.rel(prefix, user, "json");
            let r = convert_to_json(&host, rows, false);
            let text = format!("{}{}", r.text, host.newline);
            *self.json_docs.entry(rel.clone()).or_default() += 1;
            out.json = Some(self.put(tree, &rel, utf8, &text, r.spans, append, notice)?);
        }
        Ok(out)
    }

    /// The number of JSON documents written to `rel` so far.
    pub fn json_documents(&self, rel: &str) -> u32 {
        self.json_docs.get(rel).copied().unwrap_or(0)
    }

    fn shown_dir(&self, dir: &str) -> String {
        if self.non_windows {
            format!("{}/{dir}", self.file_path)
        } else {
            format!("{}\\{}", self.file_path, dir.trim_start_matches('\\'))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn put(
        &mut self,
        tree: &mut Tree<'_>,
        rel: &str,
        encoding: Encoding,
        text: &str,
        spans: Vec<(u32, u32)>,
        append: bool,
        notice: bool,
    ) -> Result<Part> {
        let (dir, file) = rel.rsplit_once('/').unwrap_or(("", rel));
        let shown = self.shown(dir, file);
        if append {
            self.log.plain(format!("Appending Data to {shown}"));
        } else {
            self.log.action(format!("Writing Data to {shown}"));
        }
        let before = tree.write(&spec(rel, encoding), text)?;
        if notice {
            self.log.silent_notice(&shown);
        }
        Ok(Part {
            rel: rel.to_string(),
            spans: spans
                .into_iter()
                .map(|(a, b)| (a + before, b + before))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hawk_paths_classify_as_sparrow_classifies_them() {
        let c = classify("\\Tenant/Simple_RBAC_Changes.json");
        assert_eq!(c.artifact, Some("hawk.tenant.simple_ual"));
        assert!(c.derived);
        let c = classify("ann@contoso.example/_Investigate_InboxRules_ann.json");
        assert_eq!(c.artifact, Some("hawk.investigate_file"));
        assert_eq!(c.subject.as_deref(), Some("ann@contoso.example"));
        let c = classify("ann@contoso.example/MailItemsAccessed_ann@contoso.example_ann.json");
        assert_eq!(c.artifact, Some("hawk.user.raw_ual"));
        let c = classify("203.0.113.9/All_Events_203.0.113.9.csv");
        assert_eq!(c.artifact, Some("hawk.ip.events"));
        assert_eq!(c.subject.as_deref(), Some("203.0.113.9"));
        assert_eq!(classify("Tenant/Unknown.json").artifact, None);
    }
}
