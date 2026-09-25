use sparrow_core::readers::xlsx::{read_xlsx, xlsx_headers};

fn workbook(
    cells: &[(u32, u16, &str)],
    numbers: &[(u32, u16, f64)],
    bools: &[(u32, u16, bool)],
) -> Vec<u8> {
    let mut wb = rust_xlsxwriter::Workbook::new();
    let ws = wb.add_worksheet();
    for (r, c, v) in cells {
        ws.write_string(*r, *c, *v).unwrap();
    }
    for (r, c, v) in numbers {
        ws.write_number(*r, *c, *v).unwrap();
    }
    for (r, c, v) in bools {
        ws.write_boolean(*r, *c, *v).unwrap();
    }
    wb.save_to_buffer().unwrap()
}

#[test]
fn reads_first_sheet_rows_with_sheet_row_numbers() {
    let bytes = workbook(
        &[
            (0, 0, "Date (UTC)"),
            (0, 1, "Request ID"),
            (0, 2, "Compliant"),
            (1, 0, "2026-09-01T10:00:00Z"),
            (3, 0, "2026-09-02T10:00:00Z"),
            (3, 1, "b2"),
        ],
        &[(1, 1, 2048.0), (3, 2, 1.5)],
        &[(1, 2, true)],
    );
    assert_eq!(
        xlsx_headers(&bytes).unwrap(),
        vec!["Date (UTC)", "Request ID", "Compliant"]
    );
    let t = read_xlsx(&bytes).unwrap();
    assert_eq!(t.headers, vec!["Date (UTC)", "Request ID", "Compliant"]);
    assert_eq!(t.rows.len(), 2);
    assert_eq!(t.rows[0].row, 2);
    assert_eq!(
        t.rows[0].fields,
        vec!["2026-09-01T10:00:00Z", "2048", "True"]
    );
    assert_eq!(t.rows[1].row, 4);
    assert_eq!(t.rows[1].text(), "2026-09-02T10:00:00Z\tb2\t1.5");
}

#[test]
fn header_row_may_start_below_row_one() {
    let bytes = workbook(
        &[
            (2, 0, "Date (UTC)"),
            (2, 1, "Request ID"),
            (3, 0, "2026-09-01T10:00:00Z"),
            (3, 1, "a1"),
        ],
        &[],
        &[],
    );
    assert_eq!(
        xlsx_headers(&bytes).unwrap(),
        vec!["Date (UTC)", "Request ID"]
    );
    let t = read_xlsx(&bytes).unwrap();
    assert_eq!(t.headers, vec!["Date (UTC)", "Request ID"]);
    assert_eq!((t.rows.len(), t.rows[0].row), (1, 4));
}

#[test]
fn not_a_workbook_is_an_error() {
    assert!(read_xlsx(b"not a zip").is_err());
    assert!(xlsx_headers(b"PK\x03\x04junk").is_none());
}

#[test]
fn rows_drop_trailing_empty_cells() {
    let bytes = workbook(
        &[
            (0, 0, "Date (UTC)"),
            (0, 1, "Request ID"),
            (1, 0, "2026-09-01T10:00:00Z"),
            (2, 0, "2026-09-02T10:00:00Z"),
            (2, 3, "wide"),
        ],
        &[],
        &[],
    );
    let t = read_xlsx(&bytes).unwrap();
    assert_eq!(t.rows[0].fields, vec!["2026-09-01T10:00:00Z"]);
    assert_eq!(t.rows[0].text(), "2026-09-01T10:00:00Z");
    assert_eq!(t.rows[1].text(), "2026-09-02T10:00:00Z\t\t\twide");
}
