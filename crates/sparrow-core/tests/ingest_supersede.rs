use sparrow_core::fixtures;
use sparrow_core::ingest::context::ParseContext;
use sparrow_core::ingest::parser::{ArtifactParser, ParserRegistry};
use sparrow_core::ingest::supersede::{
    Handled, counterpart_stems, processing_key, truncation_warning,
};
use sparrow_core::ingest::{FileReport, FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::readers::text::line_spans;
use sparrow_core::{Case, Error, Result};
use std::path::{Path, PathBuf};

/// Every physical line is a record.
struct LinesParser;
impl ArtifactParser for LinesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let text = ctx.text;
        for (n, span) in line_spans(&text.text).into_iter().enumerate() {
            let key = format!("{}:{}", ctx.file_id, n);
            ctx.record_source("test_lines", &key, n as u64, span)?;
            ctx.stats.read += 1;
            ctx.stats.loaded += 1;
        }
        Ok(())
    }
}

/// Fails on .json files, loads lines otherwise.
struct JsonFailsParser;
impl ArtifactParser for JsonFailsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        if ctx.rel_path.ends_with(".json") {
            return Err(Error::Invalid("broken json".into()));
        }
        LinesParser.parse(ctx)
    }
}

/// On .json files every record is a parse error; loads lines otherwise.
struct JsonRecordsFailParser;
impl ArtifactParser for JsonRecordsFailParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        if ctx.rel_path.ends_with(".json") {
            let span = line_spans(&ctx.text.text)[0];
            ctx.stats.read += 1;
            return ctx.parse_error(1, span, "unreadable record");
        }
        LinesParser.parse(ctx)
    }
}

/// Always reports an unsupported record shape.
struct LegacyShapeParser;
impl ArtifactParser for LegacyShapeParser {
    fn parse(&self, _ctx: &mut ParseContext<'_>) -> Result<()> {
        Err(Error::UnsupportedShape("legacy admin audit records".into()))
    }
}

fn capture(base: &Path) -> PathBuf {
    let root = base.join("cap");
    fixtures::write(&root, "Hawk.log", fixtures::HAWK_LOG.as_bytes());
    root
}

fn registry(ids: &[&'static str], make: fn() -> Box<dyn ArtifactParser>) -> ParserRegistry {
    let mut r = ParserRegistry::empty();
    for id in ids {
        r.register(id, make());
    }
    r
}

fn row<'r>(report: &'r IngestReport, rel: &str) -> &'r FileReport {
    report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == rel)
        .unwrap_or_else(|| panic!("no report row for {rel}"))
}

fn ingest(base: &Path, parsers: &ParserRegistry) -> (Case, IngestReport) {
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, base, parsers, &IngestOptions::default()).unwrap();
    (case, report)
}

#[test]
fn csv_twin_of_parsed_json_is_superseded() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, "Tenant/Consent_Grants.json", b"[{\"a\":1}]\n");
    fixtures::write(&root, "Tenant/Consent_Grants.csv", b"\"a\"\r\n\"1\"\r\n");
    let parsers = registry(&["hawk.tenant.consent_grants"], || Box::new(LinesParser));
    let (case, report) = ingest(dir.path(), &parsers);
    assert_eq!(
        row(&report, "Tenant/Consent_Grants.json").status,
        FileStatus::Parsed
    );
    let csv = row(&report, "Tenant/Consent_Grants.csv");
    assert_eq!(csv.status, FileStatus::SkippedSuperseded);
    assert_eq!(
        csv.warnings,
        vec!["superseded by Tenant/Consent_Grants.json"]
    );
    let sha: String = case
        .conn()
        .query_row(
            "SELECT sha256 FROM source_files WHERE rel_path = 'Tenant/Consent_Grants.csv'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sha.len(), 64);
}

#[test]
fn csv_is_parsed_when_its_json_twin_fails() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, "Tenant/Consent_Grants.json", b"[{\"a\":1}]\n");
    fixtures::write(&root, "Tenant/Consent_Grants.csv", b"\"a\"\r\n\"1\"\r\n");
    let parsers = registry(&["hawk.tenant.consent_grants"], || {
        Box::new(JsonFailsParser)
    });
    let (_case, report) = ingest(dir.path(), &parsers);
    assert_eq!(
        row(&report, "Tenant/Consent_Grants.json").status,
        FileStatus::Error
    );
    assert_eq!(
        row(&report, "Tenant/Consent_Grants.csv").status,
        FileStatus::Parsed
    );
}

#[test]
fn csv_is_parsed_when_every_record_of_its_json_twin_fails() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(&root, "Tenant/Consent_Grants.json", b"[{\"a\":1}]\n");
    fixtures::write(&root, "Tenant/Consent_Grants.csv", b"\"a\"\r\n\"1\"\r\n");
    let parsers = registry(&["hawk.tenant.consent_grants"], || {
        Box::new(JsonRecordsFailParser)
    });
    let (_case, report) = ingest(dir.path(), &parsers);
    let json = row(&report, "Tenant/Consent_Grants.json");
    assert_eq!(
        (json.status, json.records_read, json.records_error),
        (FileStatus::Parsed, 1, 1)
    );
    assert_eq!(
        row(&report, "Tenant/Consent_Grants.csv").status,
        FileStatus::Parsed
    );
}

#[test]
fn derived_file_is_superseded_by_raw_counterpart_whatever_the_name_order() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    // "Converted_..." sorts before "Raw_...": only the processing order makes this work.
    fixtures::write(
        &root,
        "alice@contoso.example/Converted_Authentication_Logs_alice@contoso.example.json",
        b"[{\"a\":1}]\n",
    );
    fixtures::write(
        &root,
        "alice@contoso.example/Raw_Authentication_Logs_alice@contoso.example.json",
        b"[{\"a\":1}]\n",
    );
    let parsers = registry(&["hawk.user.raw_auth", "hawk.user.converted_auth"], || {
        Box::new(LinesParser)
    });
    let (_case, report) = ingest(dir.path(), &parsers);
    let conv = row(
        &report,
        "alice@contoso.example/Converted_Authentication_Logs_alice@contoso.example.json",
    );
    assert_eq!(conv.status, FileStatus::SkippedSuperseded);
    assert_eq!(
        conv.warnings,
        vec![
            "superseded by alice@contoso.example/Raw_Authentication_Logs_alice@contoso.example.json"
        ]
    );
}

#[test]
fn derived_file_without_counterpart_is_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "alice@contoso.example/ExchangeItem_Simple_alice@contoso.example.json",
        b"[{\"a\":1}]\n",
    );
    let parsers = registry(&["hawk.user.simple_ual"], || Box::new(LinesParser));
    let (_case, report) = ingest(dir.path(), &parsers);
    assert_eq!(
        row(
            &report,
            "alice@contoso.example/ExchangeItem_Simple_alice@contoso.example.json"
        )
        .status,
        FileStatus::Parsed
    );
}

#[test]
fn unsupported_shape_is_not_supported_and_retried_later() {
    let dir = tempfile::tempdir().unwrap();
    let root = capture(dir.path());
    fixtures::write(
        &root,
        "Tenant/RBAC_Changes.json",
        b"[{\"CmdletName\":\"x\"}]\n",
    );
    let mut case = Case::in_memory().unwrap();
    let legacy = registry(&["hawk.tenant.raw_ual"], || Box::new(LegacyShapeParser));
    let report = ingest_path(&mut case, dir.path(), &legacy, &IngestOptions::default()).unwrap();
    let f = row(&report, "Tenant/RBAC_Changes.json");
    assert_eq!(f.status, FileStatus::NotSupported);
    assert_eq!(
        f.warnings,
        vec!["hawk.tenant.raw_ual: legacy admin audit records"]
    );
    assert!(!report.has_errors());
    let lines = registry(&["hawk.tenant.raw_ual"], || Box::new(LinesParser));
    let report = ingest_path(&mut case, dir.path(), &lines, &IngestOptions::default()).unwrap();
    assert_eq!(
        row(&report, "Tenant/RBAC_Changes.json").status,
        FileStatus::Parsed
    );
}

#[test]
fn counterparts_of_derived_hawk_files() {
    assert_eq!(
        counterpart_stems("Simple_RBAC_Changes"),
        vec!["RBAC_Changes", "RBAC_Changess"]
    );
    assert_eq!(
        counterpart_stems("Simple_New_InboxRule"),
        vec!["New_InboxRule", "New_InboxRules"]
    );
    assert_eq!(
        counterpart_stems("ExchangeItem_Simple_a@b"),
        vec!["ExchangeItem_Logs_a@b"]
    );
    assert_eq!(
        counterpart_stems("ExchangeItemGroup_Simple_a@b"),
        vec!["ExchangeItemGroup_Logs_a@b"]
    );
    assert_eq!(
        counterpart_stems("Converted_Authentication_Logs_a@b"),
        vec!["Raw_Authentication_Logs_a@b"]
    );
    assert!(counterpart_stems("User_ForwardingReport").is_empty());
}

#[test]
fn handled_lookup_is_case_insensitive_and_scoped_to_the_folder() {
    let mut h = Handled::default();
    h.insert("Tenant/RBAC_Changes.JSON");
    assert_eq!(
        h.superseded_by("Tenant/rbac_changes.csv", false).as_deref(),
        Some("Tenant/RBAC_Changes.JSON")
    );
    assert_eq!(
        h.superseded_by("Tenant/Simple_RBAC_Changes.csv", true)
            .as_deref(),
        Some("Tenant/RBAC_Changes.JSON")
    );
    assert_eq!(
        h.superseded_by("Tenant/Simple_RBAC_Changes.csv", false),
        None
    );
    assert_eq!(h.superseded_by("Other/RBAC_Changes.csv", false), None);
    assert_eq!(h.superseded_by("Tenant/RBAC_Changes.json", false), None);
    assert_eq!(h.superseded_by("noext", true), None);
}

/// A QuickUAL combined export is made redundant only by the `inv.quickual.operation` files in
/// its own triage root, and only when every one of them parsed.
fn quickual_handled(operations: &[(&str, bool)]) -> Handled {
    let mut h = Handled::default();
    h.note_artifact(
        "Triage1/UAL-Operations-Combined.csv",
        "inv.quickual.combined",
    );
    for (rel, ok) in operations {
        h.note_artifact(rel, "inv.quickual.operation");
        if *ok {
            h.insert(rel);
        } else {
            h.insert_failed(rel);
        }
    }
    h
}

#[test]
fn quickual_combined_is_superseded_when_every_operation_file_parsed() {
    let h = quickual_handled(&[
        ("Triage1/New-InboxRule.json", true),
        ("Triage1/Set-Mailbox.csv", true),
    ]);
    assert_eq!(
        h.superseded_by("Triage1/UAL-Operations-Combined.csv", true)
            .as_deref(),
        Some("Triage1/New-InboxRule.json")
    );
}

#[test]
fn quickual_combined_is_parsed_when_an_operation_file_failed() {
    let h = quickual_handled(&[
        ("Triage1/New-InboxRule.json", true),
        ("Triage1/Set-Mailbox.csv", false),
    ]);
    assert_eq!(
        h.superseded_by("Triage1/UAL-Operations-Combined.csv", true),
        None
    );
}

#[test]
fn quickual_combined_is_parsed_when_only_an_unrelated_file_parsed() {
    let mut h = Handled::default();
    h.note_artifact(
        "Triage1/UAL-Operations-Combined.csv",
        "inv.quickual.combined",
    );
    h.note_artifact(
        "Triage1/202609101000-UserApplications.csv",
        "inv.user_applications",
    );
    h.insert("Triage1/202609101000-UserApplications.csv");
    assert_eq!(
        h.superseded_by("Triage1/UAL-Operations-Combined.csv", true),
        None
    );
}

#[test]
fn processing_order_is_raw_then_derived_json_then_csv() {
    let mut v = [
        processing_key("b.csv", true, 0),
        processing_key("a.csv", false, 0),
        processing_key("z.json", true, 0),
        processing_key("c.json", false, 0),
    ];
    v.sort();
    let order: Vec<&str> = v.iter().map(|k| k.3.as_str()).collect();
    assert_eq!(order, vec!["c.json", "a.csv", "z.json", "b.csv"]);
}

#[test]
fn truncation_warnings_at_known_caps() {
    assert!(
        truncation_warning("portal.ual", 50_000)
            .unwrap()
            .contains("known export cap 50000")
    );
    assert_eq!(truncation_warning("portal.ual", 49_999), None);
    // Audit (Premium) exports stop at 1,000,000 rows.
    assert!(
        truncation_warning("portal.ual", 1_000_000)
            .unwrap()
            .contains("known export cap 1000000")
    );
    assert_eq!(truncation_warning("portal.ual", 999_999), None);
    assert!(truncation_warning("portal.entra_signins", 100_000).is_some());
    assert!(
        truncation_warning("hawk.user.raw_ual", 10_000)
            .unwrap()
            .contains("multiple of 5000")
    );
    assert_eq!(truncation_warning("hawk.user.raw_ual", 9_934), None);
    assert_eq!(truncation_warning("hawk.user.raw_ual", 0), None);
    assert_eq!(truncation_warning("hawk.log", 5_000), None);
}

#[test]
fn page_size_warning_only_for_event_artifacts() {
    assert!(truncation_warning("hawk.user.raw_ual", 10_000).is_some());
    assert!(truncation_warning("hawk.tenant.entra_users", 5_000).is_none());
    assert!(truncation_warning("hawk.tenant.org_config", 5_000).is_none());
}
