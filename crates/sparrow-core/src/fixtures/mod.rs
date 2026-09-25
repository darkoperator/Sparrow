//! Synthetic collector output trees used by tests. Contains no real client data.

pub mod hawk3;
pub mod hawk4;
pub mod portal;
pub mod state;
pub mod ual;

use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().expect("fixture path has a parent"))
        .expect("create fixture dir");
    std::fs::write(path, bytes).expect("write fixture file");
}

pub fn utf16le_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

pub fn utf8_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(s.as_bytes());
    v
}

pub const HAWK_ROOT_NAME: &str = "Hawk_Contoso_Ltd_20260910_141500";

/// 11 physical lines, 10 log entries (line 10 continues entry 9).
pub const HAWK_LOG: &str = concat!(
    "[2026-09-10 14:15:00Z] - [INFO]   - Hawk output directory created at: C:\\Hawk\\Hawk_Contoso_Ltd_20260910_141500\r\n",
    "[2026-09-10 14:15:01Z] - Hawk Version: 4.0.0\r\n",
    "[2026-09-10 14:15:01Z] - File Path    : C:\\Hawk\\Hawk_Contoso_Ltd_20260910_141500\r\n",
    "[2026-09-10 14:15:01Z] - Start Date   : 6/12/2026 12:00:00 AM\r\n",
    "[2026-09-10 14:15:01Z] - End Date     : 9/11/2026 12:00:00 AM\r\n",
    "[2026-09-10 14:15:01Z] - Tenant Name  : Contoso_Ltd\r\n",
    "[2026-09-10 14:15:02Z] - [INFO]   - M365 License type detected: E5\r\n",
    "[2026-09-10 14:15:02Z] - [INFO]   - Max log retention: 365 days\r\n",
    "[2026-09-10 14:20:00Z] - [INVESTIGATE] - Found suspicious inbox rule\r\n",
    "continued detail line\r\n",
    "[2026-09-10 14:30:00Z] - [ACTION] - Tenant Investigation complete for tenant: Contoso_Ltd\r\n",
);

/// Written as UTF-16LE with BOM (Windows PowerShell 5.1 Out-File default). 3 entries.
pub const INVICTUS_LOG: &str = concat!(
    "2026-09-10 10:00:00: Starting evidence collection\r\n",
    "2026-09-10 10:00:05: [WARNING] Mailbox audit bypass lookup failed\r\n",
    "2026-09-10 10:05:00: Collection complete\r\n",
);

/// Hawk layout. Returns the Hawk_<tenant>_<ts> root.
pub fn hawk_tree(base: &Path) -> PathBuf {
    let root = base.join(HAWK_ROOT_NAME);
    write(&root, "Hawk.log", HAWK_LOG.as_bytes());
    write(
        &root,
        "_Investigate.txt",
        b"[2026-09-10 14:20:00Z] - [INVESTIGATE] - Additional Information: InboxRules\r\n",
    );
    write(
        &root,
        "Tenant/EntraIDUsers.json",
        br#"[{"UserPrincipalName":"alice@contoso.example"}]"#,
    );
    write(
        &root,
        "Tenant/Simple_RBAC_Changes.csv",
        b"\"Operation\"\r\n\"New-ManagementRoleAssignment\"\r\n",
    );
    write(
        &root,
        "Tenant/RBAC_Changes.csv",
        concat!(
            "\"RecordType\",\"CreationDate\",\"UserIds\",\"Operations\",\"AuditData\"\r\n",
            "\"ExchangeAdmin\",\"9/1/2026 10:00:00 AM\",\"admin@contoso.example\",\"New-ManagementRoleAssignment\",",
            "\"{\"\"CreationTime\"\":\"\"2026-09-01T10:00:00\"\",\"\"Id\"\":\"\"c0000000-0000-4000-8000-000000000001\"\",",
            "\"\"Operation\"\":\"\"New-ManagementRoleAssignment\"\",\"\"RecordType\"\":1,",
            "\"\"UserId\"\":\"\"admin@contoso.example\"\",\"\"Workload\"\":\"\"Exchange\"\"}\"\r\n",
        )
        .as_bytes(),
    );
    write(
        &root,
        "alice@contoso.example/InboxRules_alice.json",
        br#"{"Name":"x","ForwardTo":null}"#,
    );
    write(
        &root,
        "alice@contoso.example/_Investigate_InboxRules_alice.json",
        br#"{"Name":"x","DeleteMessage":true}"#,
    );
    write(&root, "notes/random.bin", &[0u8, 1, 2, 3, 255]);
    write(&root, ".DS_Store", b"junk");
    root
}

/// Microsoft-Extractor-Suite layout (Start-EvidenceCollection project "Case1"). Returns the Output root.
pub fn invictus_tree(base: &Path) -> PathBuf {
    let root = base.join("Output");
    write(&root, "LogFile.txt", &utf16le_bom(INVICTUS_LOG));
    write(
        &root,
        "Case1/UnifiedAuditLog/20260910-100000/UAL-20260901000000-20260902000000.json",
        b"[]\n",
    );
    write(
        &root,
        "Case1/Users/20260910-100500/20260910-100500-Users.csv",
        &utf8_bom(
            "\"UserPrincipalName\",\"DisplayName\"\r\n\"alice@contoso.example\",\"Alice\"\r\n",
        ),
    );
    write(
        &root,
        "Case1/Licenses/20260910-100600/20260910-100600-TenantLicenses.csv",
        b"\"Sku\",\"Units\"\r\n\"SPE_E5\",\"25\"\r\n",
    );
    write(
        &root,
        "Case1/Rules/20260910-100700/20260910-100700-MailboxRules.csv",
        b"",
    );
    write(
        &root,
        "Case1/Rules/20260910-100700/20260910-100700-TransportRules.csv",
        b"",
    );
    write(&root, "Case1/weird.xyz", b"?");
    root
}

/// One Export-Csv line: every field quoted, quotes doubled, CRLF.
pub fn csv_line(fields: &[&str]) -> String {
    let quoted: Vec<String> = fields
        .iter()
        .map(|f| format!("\"{}\"", f.replace('"', "\"\"")))
        .collect();
    format!("{}\r\n", quoted.join(","))
}

/// UTF-16LE without a byte-order mark (Exchange admin center message trace download).
pub fn utf16le_no_bom(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Pretty JSON with CRLF line ends, like PowerShell's ConvertTo-Json output on Windows.
pub fn ps_json(v: &Value) -> String {
    serde_json::to_string_pretty(v)
        .expect("fixture JSON serializes")
        .replace('\n', "\r\n")
}

/// Windows PowerShell 5.1 writes DateTime values as `"\/Date(ms)\/"`: turn every
/// `"/Date(ms)/"` string in `json` into that form.
pub fn ps51_dates(json: &str) -> String {
    json.replace("\"/Date(", "\"\\/Date(")
        .replace(")/\"", ")\\/\"")
}
