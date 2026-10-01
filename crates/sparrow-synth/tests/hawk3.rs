use sparrow_synth::check::check_without_detection as check;
use sparrow_synth::generate::{generate, generate_to_dir};
use sparrow_synth::options::{Collector, Culture, GenerateOptions, PsEdition};
use sparrow_synth::reserved::scan_text;
use sparrow_synth::scenario::{builtin_names, load};
use sparrow_synth::testing::ingest_generated;
use sparrow_synth::tree::MemSink;

fn opts(seed: u64) -> GenerateOptions {
    GenerateOptions::new(Collector::Hawk3, seed)
}

fn green(name: &str, o: &GenerateOptions) -> sparrow_synth::manifest::Manifest {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load(name).unwrap(), o, dir.path()).unwrap();
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{name} {o:?}: {:#?}", report.problems);
    m
}

/// Every built-in scenario but `volume`.
const MATRIX: &[&str] = &[
    "audit-tamper",
    "bec-aitm",
    "bec-e3-audit-gaps",
    "bec-o365-no-p1",
    "business-basic",
    "hawk-investigate",
    "password-spray",
];

#[test]
fn the_matrix_covers_every_builtin_but_volume() {
    let builtins: Vec<&str> = builtin_names()
        .iter()
        .copied()
        .filter(|n| *n != "volume")
        .collect();
    assert_eq!(builtins, MATRIX);
}

/// One test per scenario × (edition, culture), so the harness runs them in parallel.
macro_rules! green_matrix {
    ($($test:ident: $scenario:literal, $ps:expr, $culture:expr;)+) => {
        $(
            #[test]
            fn $test() {
                let mut o = opts(41);
                o.ps = $ps;
                o.culture = $culture;
                green($scenario, &o);
            }
        )+
    };
}

green_matrix! {
    audit_tamper_ps51_en_us: "audit-tamper", PsEdition::Ps51, Culture::EnUs;
    audit_tamper_ps7_en_us: "audit-tamper", PsEdition::Ps7, Culture::EnUs;
    audit_tamper_ps51_en_gb: "audit-tamper", PsEdition::Ps51, Culture::EnGb;
    bec_aitm_ps51_en_us: "bec-aitm", PsEdition::Ps51, Culture::EnUs;
    bec_aitm_ps7_en_us: "bec-aitm", PsEdition::Ps7, Culture::EnUs;
    bec_aitm_ps51_en_gb: "bec-aitm", PsEdition::Ps51, Culture::EnGb;
    bec_e3_audit_gaps_ps51_en_us: "bec-e3-audit-gaps", PsEdition::Ps51, Culture::EnUs;
    bec_e3_audit_gaps_ps7_en_us: "bec-e3-audit-gaps", PsEdition::Ps7, Culture::EnUs;
    bec_e3_audit_gaps_ps51_en_gb: "bec-e3-audit-gaps", PsEdition::Ps51, Culture::EnGb;
    bec_o365_no_p1_ps51_en_us: "bec-o365-no-p1", PsEdition::Ps51, Culture::EnUs;
    bec_o365_no_p1_ps7_en_us: "bec-o365-no-p1", PsEdition::Ps7, Culture::EnUs;
    bec_o365_no_p1_ps51_en_gb: "bec-o365-no-p1", PsEdition::Ps51, Culture::EnGb;
    business_basic_ps51_en_us: "business-basic", PsEdition::Ps51, Culture::EnUs;
    business_basic_ps7_en_us: "business-basic", PsEdition::Ps7, Culture::EnUs;
    business_basic_ps51_en_gb: "business-basic", PsEdition::Ps51, Culture::EnGb;
    hawk_investigate_ps51_en_us: "hawk-investigate", PsEdition::Ps51, Culture::EnUs;
    hawk_investigate_ps7_en_us: "hawk-investigate", PsEdition::Ps7, Culture::EnUs;
    hawk_investigate_ps51_en_gb: "hawk-investigate", PsEdition::Ps51, Culture::EnGb;
    password_spray_ps51_en_us: "password-spray", PsEdition::Ps51, Culture::EnUs;
    password_spray_ps7_en_us: "password-spray", PsEdition::Ps7, Culture::EnUs;
    password_spray_ps51_en_gb: "password-spray", PsEdition::Ps51, Culture::EnGb;
}

#[test]
fn admin_activity_uses_the_admin_audit_shape() {
    let mut sink = MemSink::default();
    let m = generate(&load("hawk-investigate").unwrap(), &opts(42), &mut sink).unwrap();
    let f = m
        .files
        .iter()
        .find(|f| f.rel_path == "Tenant/New_InboxRules.json")
        .unwrap();
    assert_eq!(f.status, "parsed");
    assert!(m.tables["admin_audit_events"].rows > 0);
    let bytes = &sink
        .files
        .iter()
        .find(|(k, _)| k.ends_with("Tenant/New_InboxRules.json"))
        .unwrap()
        .1;
    let text = sparrow_core::readers::text::decode(bytes).text;
    assert!(text.contains("CmdletParameters") && text.contains("RunDate"));
}

#[test]
fn clixml_and_forwarding_recipients_are_recorded_but_not_loaded() {
    let mut sink = MemSink::default();
    let m = generate(&load("bec-aitm").unwrap(), &opts(43), &mut sink).unwrap();
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.starts_with("Tenant/XML/") && f.status == "not_supported")
    );
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.starts_with("Tenant/Forwarding_Recipients"))
    );
}

#[test]
fn the_log_uses_the_host_culture_and_the_hawk3_dialect() {
    let mut o = opts(44);
    o.ps = PsEdition::Ps51;
    o.culture = Culture::EnGb;
    let mut sink = MemSink::default();
    let m = generate(&load("hawk-investigate").unwrap(), &o, &mut sink).unwrap();
    let log = &sink
        .files
        .iter()
        .find(|(k, _)| k.ends_with("/Hawk.log"))
        .unwrap()
        .1;
    assert_eq!(&log[..2], &[0xFF, 0xFE], "5.1 writes the log UTF-16LE");
    let text = sparrow_core::readers::text::decode(log).text;
    assert!(text.contains("*** Version 3.1.0 ***"));
    // en-GB `G`: dd/MM/yyyy HH:mm:ss (collected 2026-09-04 11:00 UTC, host on UTC).
    assert!(
        text.starts_with("[04/09/2026 11:00:00] - "),
        "{}",
        &text[..80]
    );
    assert!(!text.contains("License type detected"));
    let log_file = m.files.iter().find(|f| f.rel_path == "Hawk.log").unwrap();
    assert!(log_file.date_evidence.is_some_and(|e| e.culture_dates > 0));
    assert!(
        m.files
            .iter()
            .any(|f| f.rel_path.ends_with("_logs.csv") && f.encoding == "utf-8-bom")
    );
}

/// `scan_text` of a decoded file; Windows PowerShell 5.1 wraps long Format-List values onto
/// indented continuation lines, which are joined back first.
fn scan(rel: &str, bytes: &[u8]) -> Vec<String> {
    let text = sparrow_core::readers::text::decode(bytes).text;
    if rel.ends_with(".txt") {
        let re = regex::Regex::new(r"\r?\n +").unwrap();
        scan_text(&re.replace_all(&text, ""))
    } else {
        scan_text(&text)
    }
}

#[test]
fn trees_are_deterministic_and_clean() {
    let s = load("hawk-investigate").unwrap();
    for ps in [PsEdition::Ps51, PsEdition::Ps7] {
        let mut o = opts(45);
        o.ps = ps;
        let (mut a, mut b) = (MemSink::default(), MemSink::default());
        generate(&s, &o, &mut a).unwrap();
        generate(&s, &o, &mut b).unwrap();
        assert_eq!(a.files, b.files);
        let mut utf16 = 0;
        for (rel, bytes) in &a.files {
            if rel.ends_with(".mmdb") {
                continue;
            }
            utf16 += usize::from(bytes.starts_with(&[0xFF, 0xFE]));
            let found = scan(rel, bytes);
            assert!(found.is_empty(), "{ps:?} {rel}: {found:?}");
        }
        assert_eq!(
            utf16 > 0,
            ps == PsEdition::Ps51,
            "{ps:?}: UTF-16LE files scanned"
        );
    }
}

/// For the Format-List `_Investigate_New_InboxRules.txt`: (total collector_flags rows, flags
/// it shares with the summary copy `_Investigate_Simple_New_InboxRule.json`, its flag
/// sightings). Its zone-less `RunDate` links (and merges) with the summary's flags only when
/// the host runs on UTC.
fn investigate_txt_flags(offset: i32) -> (u64, i64, i64) {
    let mut s = load("hawk-investigate").unwrap();
    s.tenant.host_utc_offset_minutes = offset;
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&s, &opts(46), dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    let report = check(&m, &case).unwrap();
    assert!(report.ok, "offset {offset}: {:#?}", report.problems);
    let q = |sql: &str| -> i64 { case.conn().query_row(sql, [], |r| r.get(0)).unwrap() };
    let keys = |file: &str| {
        format!(
            "SELECT r.record_key FROM record_sources r JOIN source_files s ON s.file_id = r.file_id
             WHERE r.table_name = 'collector_flags' AND s.rel_path = 'Tenant/{file}'"
        )
    };
    let txt = keys("_Investigate_New_InboxRules.txt");
    let json = keys("_Investigate_Simple_New_InboxRule.json");
    let shared = q(&format!("SELECT count(*) FROM ({txt} INTERSECT {json})"));
    let sightings = q(&format!("SELECT count(*) FROM ({txt})"));
    (m.tables["collector_flags"].rows, shared, sightings)
}

#[test]
fn format_list_admin_rule_flags_merge_only_on_a_utc_host() {
    let (utc_total, utc_shared, utc_blocks) = investigate_txt_flags(0);
    let (local_total, local_shared, local_blocks) = investigate_txt_flags(120);
    assert!(utc_blocks > 0 && utc_blocks == local_blocks);
    assert_eq!(
        utc_shared, utc_blocks,
        "UTC host: every Format-List flag merges"
    );
    assert_eq!(local_shared, 0, "UTC+2 host: no Format-List flag merges");
    assert_eq!(local_total - utc_total, local_blocks as u64);
}

/// A window ending long before collection is still `available_not_collected`: Hawk 3 logs no
/// window, so Sparrow can only compare `collected_at` with the retention.
#[test]
fn hawk3_signins_are_available_not_collected_without_a_logged_window() {
    let mut s = load("hawk-investigate").unwrap();
    s.window.start -= chrono::Duration::days(20);
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&s, &opts(47), dir.path()).unwrap();
    assert_eq!(m.evidence["signins"].allowed, ["available_not_collected"]);
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}

/// The 17-column Search-AdminAuditLog shape, in the Hawk 3.1 order (capture survey §2b:59).
const ADMIN17: &[&str] = &[
    "ObjectModified",
    "CmdletName",
    "CmdletParameters",
    "ModifiedProperties",
    "Caller",
    "ExternalAccess",
    "Succeeded",
    "Error",
    "RunDate",
    "OriginatingServer",
    "ClientIP",
    "SessionId",
    "AppId",
    "ClientAppId",
    "Identity",
    "IsValid",
    "ObjectState",
];

fn csv_header(dir: &std::path::Path, root: &str, rel: &str) -> Vec<String> {
    let bytes = std::fs::read(dir.join(root).join(rel)).expect(rel);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    sparrow_core::readers::csv_scan::read_csv(&text).headers
}

/// The `CmdletName` of every data row of a CSV file.
fn csv_column(dir: &std::path::Path, root: &str, rel: &str, column: &str) -> Vec<String> {
    let bytes = std::fs::read(dir.join(root).join(rel)).expect(rel);
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let table = sparrow_core::readers::csv_scan::read_csv(&text);
    let i = table
        .headers
        .iter()
        .position(|h| h == column)
        .unwrap_or_else(|| panic!("{rel} has no column {column}: {:?}", table.headers));
    table
        .rows
        .iter()
        .map(|r| r.fields.get(i).cloned().unwrap_or_default())
        .collect()
}

/// Hawk 3.1's `Tenant/RBAC_Changes` is the 17-column Search-AdminAuditLog shape
/// (`Get-HawkTenantRbacChange.ps1:51-68` names the 16 RBAC cmdlets, the survey records
/// `New-ManagementRoleAssignment` in it). The registry classifies it as `hawk.tenant.raw_ual`,
/// so without it that artifact has no 17-column file at all.
#[test]
fn hawk3_writes_the_17_column_rbac_changes() {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(51), dir.path()).unwrap();
    let root = dir.path().join(&m.root);
    assert!(root.join("Tenant/RBAC_Changes.csv").exists());
    assert_eq!(
        csv_header(dir.path(), &m.root, "Tenant/RBAC_Changes.csv"),
        ADMIN17
    );
    let simple = csv_header(dir.path(), &m.root, "Tenant/Simple_RBAC_Changes.csv");
    assert_eq!(
        simple,
        [
            "Caller",
            "Cmdlet",
            "FullCommand",
            "RunDate(UTC)",
            "ObjectModified"
        ]
    );
    // Only RBAC cmdlets, and at least one record.
    let rbac = [
        "New-ManagementRole",
        "Remove-ManagementRole",
        "New-ManagementRoleAssignment",
        "Remove-ManagementRoleAssignment",
        "Set-ManagementRoleAssignment",
        "New-ManagementScope",
        "Remove-ManagementScope",
        "Set-ManagementScope",
        "New-ManagementRoleEntry",
        "Remove-ManagementRoleEntry",
        "Set-ManagementRoleEntry",
        "New-RoleGroup",
        "Remove-RoleGroup",
        "Set-RoleGroup",
        "Add-RoleGroupMember",
        "Remove-RoleGroupMember",
    ];
    let cmdlets = csv_column(dir.path(), &m.root, "Tenant/RBAC_Changes.csv", "CmdletName");
    assert!(!cmdlets.is_empty(), "RBAC_Changes has no records");
    for cmdlet in &cmdlets {
        assert!(
            rbac.iter().any(|r| r.eq_ignore_ascii_case(cmdlet)),
            "unexpected RBAC cmdlet {cmdlet:?}"
        );
    }

    // The `synth check` gate still holds with the extra files.
    let report = check(&m, &ingest_generated(dir.path(), &m)).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}

/// Sparrow parses the 17-column files into `admin_audit_events` (Phase 2c), one row per
/// record, and the manifest's expectation matches.
#[test]
fn sparrow_loads_the_17_column_rbac_files_into_admin_audit_events() {
    let dir = tempfile::tempdir().unwrap();
    let m = generate_to_dir(&load("bec-aitm").unwrap(), &opts(52), dir.path()).unwrap();
    let case = ingest_generated(dir.path(), &m);
    let n: i64 = case
        .conn()
        .query_row("SELECT count(*) FROM admin_audit_events", [], |r| r.get(0))
        .unwrap();
    assert!(n > 0, "no admin_audit_events rows at all");
    // Every RBAC file row is loaded, and the manifest agrees on the count.
    let rbac_rows: i64 = case
        .conn()
        .query_row(
            "SELECT count(*) FROM record_sources r JOIN source_files f ON f.file_id = r.file_id \
             WHERE r.table_name = 'admin_audit_events' \
               AND f.rel_path IN ('Tenant/RBAC_Changes.csv', 'Tenant/RBAC_Changes.json')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        rbac_rows > 0,
        "RBAC_Changes loaded no admin_audit_events rows"
    );
    let report = check(&m, &case).unwrap();
    assert!(report.ok, "{:#?}", report.problems);
}
