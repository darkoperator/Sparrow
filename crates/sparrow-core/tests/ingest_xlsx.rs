use serde_json::json;
use sparrow_core::Case;
use sparrow_core::db::state_tables::COLLECTOR_FLAGS;
use sparrow_core::discovery::Tool;
use sparrow_core::ingest::context::ParseContext;
use sparrow_core::ingest::parser::{ArtifactParser, ParserRegistry};
use sparrow_core::ingest::{FileStatus, IngestOptions, IngestReport, ingest_path};
use sparrow_core::normalize::fields::Cell;
use sparrow_core::parsers::stage::{RowDraft, SheetRow, TableRows, load_tables};
use sparrow_core::readers::text::Span;
use sparrow_core::readers::xlsx::read_xlsx;
use sparrow_core::verify::verify_record;
use std::path::Path;

/// Stand-in for the sign-in parser: one collector_flags row per sheet row.
struct SheetRowsParser;

impl ArtifactParser for SheetRowsParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> sparrow_core::Result<()> {
        let table = read_xlsx(ctx.raw).map_err(sparrow_core::Error::Invalid)?;
        let mut rows = TableRows::new(&COLLECTOR_FLAGS, &["flag_type", "description"]);
        for r in &table.rows {
            rows.push_draft(RowDraft {
                ordinal: r.row as u64,
                span: Span { start: 0, end: 0 },
                record_key: format!("row{}", r.row),
                cells: vec![
                    Cell::text(Some("test".into())),
                    Cell::text(r.fields.first().cloned()),
                ],
                raw: Some(json!({ "fields": r.fields })),
                sheet_row: Some(SheetRow {
                    row: r.row,
                    text: r.text(),
                }),
            });
        }
        load_tables(ctx, vec![rows])
    }
}

fn workbook(rows: &[&[&str]]) -> Vec<u8> {
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    for (r, cells) in rows.iter().enumerate() {
        for (c, v) in cells.iter().enumerate() {
            if !v.is_empty() {
                ws.write_string(r as u32, c as u16, *v).unwrap();
            }
        }
    }
    wb.save_to_buffer().unwrap()
}

const HEADER: &[&str] = &["Date (UTC)", "Request ID", "User agent", "Correlation ID"];
const NAME: &str = "InteractiveSignins_2026-09-01_2026-09-10.xlsx";

fn ingest(base: &Path) -> (Case, IngestReport) {
    let mut parsers = ParserRegistry::empty();
    parsers.register("portal.entra_signins", Box::new(SheetRowsParser));
    let mut case = Case::in_memory().unwrap();
    let report = ingest_path(&mut case, base, &parsers, &IngestOptions::default()).unwrap();
    (case, report)
}

#[test]
fn xlsx_rows_carry_sheet_row_provenance_and_verify() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    let bytes = workbook(&[
        HEADER,
        &["2026-09-01T10:00:00Z", "a1", "ua", "c1"],
        &[],
        &["2026-09-02T10:00:00Z", "a2", "ua", "c2"],
    ]);
    sparrow_core::fixtures::write(&root, NAME, &bytes);
    let (case, report) = ingest(dir.path());
    assert_eq!(report.collections.len(), 1);
    assert_eq!(report.collections[0].tool, Tool::PortalExport);
    let f = &report.collections[0].files[0];
    assert_eq!(f.artifact_id.as_deref(), Some("portal.entra_signins"));
    assert_eq!(
        (f.status, f.records_loaded),
        (FileStatus::Parsed, 2),
        "{f:#?}"
    );
    let (format, encoding): (String, Option<String>) = case
        .conn()
        .query_row("SELECT format, encoding FROM source_files", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((format.as_str(), encoding), ("xlsx", None));
    let pos: (i64, i64, i64, i64, i64) = case
        .conn()
        .query_row(
            "SELECT record_ordinal, line_start, line_end, byte_offset, byte_length FROM record_sources WHERE record_key = 'row4'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!(pos, (4, 4, 4, 0, bytes.len() as i64));
    let v = verify_record(&case, "collector_flags", "row4", None).unwrap();
    assert!(v.ok, "{v:#?}");
    let excerpt = v.sightings[0].excerpt.as_deref().unwrap();
    assert!(excerpt.contains("Request ID: a2"), "{excerpt}");
    assert!(v.sightings[0].source_ref.ends_with(&format!("{NAME}:4")));

    let changed = workbook(&[
        HEADER,
        &["2026-09-01T10:00:00Z", "a1", "ua", "c1"],
        &[],
        &["2026-09-02T10:00:00Z", "a2", "ua", "tampered"],
    ]);
    sparrow_core::fixtures::write(&root, NAME, &changed);
    let v = verify_record(&case, "collector_flags", "row4", None).unwrap();
    assert!(!v.ok);
    assert!(!v.sightings[0].file_hash_ok);
    assert!(!v.sightings[0].record_hash_ok);
}

#[test]
fn workbooks_that_are_not_portal_exports_are_unrecognized() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    sparrow_core::fixtures::write(
        &root,
        NAME,
        &workbook(&[HEADER, &["2026-09-01T10:00:00Z", "a1", "ua", "c1"]]),
    );
    sparrow_core::fixtures::write(
        &root,
        "budget.xlsx",
        &workbook(&[&["Item", "Cost"], &["x", "1"]]),
    );
    let (_case, report) = ingest(dir.path());
    let budget = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "budget.xlsx")
        .unwrap();
    assert_eq!(
        (budget.artifact_id.as_deref(), budget.status),
        (None, FileStatus::Unrecognized)
    );
}

#[test]
fn purview_audit_workbooks_are_unrecognized() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("exports");
    // The sign-in workbook makes the folder a portal-export collection.
    sparrow_core::fixtures::write(
        &root,
        NAME,
        &workbook(&[HEADER, &["2026-09-01T10:00:00Z", "a1", "ua", "c1"]]),
    );
    sparrow_core::fixtures::write(
        &root,
        "audit.xlsx",
        &workbook(&[
            &[
                "RecordId",
                "CreationDate",
                "RecordType",
                "Operation",
                "UserId",
                "AuditData",
            ],
            &[
                "11111111-1111-1111-1111-111111111111",
                "2026-09-01T10:00:00Z",
                "ExchangeItem",
                "Send",
                "a@contoso.example",
                "{}",
            ],
        ]),
    );
    let (_case, report) = ingest(dir.path());
    let f = report.collections[0]
        .files
        .iter()
        .find(|f| f.rel_path == "audit.xlsx")
        .unwrap();
    assert_eq!(
        (f.artifact_id.as_deref(), f.status),
        (None, FileStatus::Unrecognized),
        "{f:#?}"
    );
}
