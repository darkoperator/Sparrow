use serde_json::json;
use sparrow_core::readers::csv_scan::*;
use sparrow_core::readers::text::LineIndex;

#[test]
fn reads_header_and_rows_with_spans() {
    let text = "\"Name\",\"Enabled\"\r\n\"Rule A\",\"True\"\r\n\"Rule B\",\"False\"\r\n";
    let t = read_csv(text);
    assert_eq!(t.headers, vec!["Name", "Enabled"]);
    assert_eq!(t.rows.len(), 2);
    assert_eq!(t.rows[1].ordinal, 1);
    assert_eq!(t.rows[1].fields, vec!["Rule B", "False"]);
    assert_eq!(
        &text[t.rows[1].span.start..t.rows[1].span.end],
        "\"Rule B\",\"False\""
    );
}

#[test]
fn multiline_quoted_cell_spans_several_lines() {
    let text = "Id,auditData\n1,\"{\n  \"\"a\"\": 1\n}\"\n2,\"{}\"\n";
    let t = read_csv(text);
    assert_eq!(t.rows.len(), 2);
    assert_eq!(t.rows[0].fields[1], "{\n  \"a\": 1\n}");
    let idx = LineIndex::new(text);
    let r0 = &t.rows[0];
    assert_eq!(idx.line_of(r0.span.start), 2);
    assert_eq!(idx.line_of(r0.span.end - 1), 4);
    assert_eq!(idx.line_of(t.rows[1].span.start), 5);
}

#[test]
fn row_map_handles_short_and_long_rows() {
    let text = "A,B,C\n1,2\n3,4,5,6\n";
    let t = read_csv(text);
    assert_eq!(
        serde_json::Value::Object(t.row_map(&t.rows[0])),
        json!({"A": "1", "B": "2"})
    );
    assert_eq!(
        serde_json::Value::Object(t.row_map(&t.rows[1])),
        json!({"A": "3", "B": "4", "C": "5", "_extra_0": "6"})
    );
}

#[test]
fn empty_input_and_header_only() {
    let t = read_csv("");
    assert!(t.headers.is_empty() && t.rows.is_empty() && t.errors.is_empty());
    let t = read_csv("\u{feff}A,B\r\n");
    assert_eq!(t.headers, vec!["A", "B"]);
    assert!(t.rows.is_empty());
}

#[test]
fn blank_lines_between_rows_do_not_shift_spans() {
    let text = "A\n1\n\n2\n";
    let t = read_csv(text);
    assert_eq!(t.rows.len(), 2);
    assert_eq!(&text[t.rows[1].span.start..t.rows[1].span.end], "2");
}

#[test]
fn type_line_is_skipped_and_portal_headers_are_normalized() {
    let text = "#TYPE System.Management.Automation.PSCustomObject\r\n\
                \"Date (UTC)\",\"Application ID \",\"Autonomous system  number\",\"Incoming token type\",\"Incoming token type\"\r\n\
                \"a\",\"b\",\"c\",\"d\",\"e\"\r\n";
    let t = read_csv(text);
    assert_eq!(
        t.headers,
        vec![
            "Date (UTC)",
            "Application ID",
            "Autonomous system number",
            "Incoming token type",
            "Incoming token type_2"
        ]
    );
    assert_eq!(t.rows.len(), 1);
    assert_eq!(t.rows[0].ordinal, 0);
    assert_eq!(
        &text[t.rows[0].span.start..t.rows[0].span.end],
        "\"a\",\"b\",\"c\",\"d\",\"e\""
    );
}

#[test]
fn normalize_headers_strips_bom_and_numbers_duplicates() {
    assert_eq!(
        normalize_headers(["\u{feff}RecordId", " A  B ", "x", "x", "x"]),
        vec!["RecordId", "A B", "x", "x_2", "x_3"]
    );
}
