use sparrow_core::readers::format_list::{parse_format_list, parse_format_list_object};

const SAMPLE: &str = "\r\n\r\nName                      : Admin Audit Log Settings\r\nUnifiedAuditLogIngestionEnabled : True\r\nAdminAuditLogCmdlets      : {*}\r\nWhenChanged               : 9/10/2026 2:15:00 PM\r\nDescription               : A long value that PowerShell\r\n                            wrapped onto a second line\r\n\r\nName        : Second\r\nAuditDisabled : False\r\n";

#[test]
fn parses_blocks_fields_and_continuations() {
    let blocks = parse_format_list(SAMPLE);
    assert_eq!(blocks.len(), 2);
    let b = &blocks[0];
    assert_eq!(b.get("name"), Some("Admin Audit Log Settings"));
    assert_eq!(b.get("UnifiedAuditLogIngestionEnabled"), Some("True"));
    assert_eq!(b.get("WhenChanged"), Some("9/10/2026 2:15:00 PM"));
    assert_eq!(
        b.get("Description"),
        Some("A long value that PowerShell wrapped onto a second line")
    );
    assert_eq!(blocks[1].get("AuditDisabled"), Some("False"));
    assert_eq!(blocks[1].get("Missing"), None);
}

#[test]
fn block_span_covers_its_lines() {
    let blocks = parse_format_list(SAMPLE);
    let text = &SAMPLE[blocks[1].span.start..blocks[1].span.end];
    assert!(text.starts_with("Name        : Second"));
    assert!(text.ends_with("AuditDisabled : False"));
}

#[test]
fn empty_values_and_empty_input() {
    let blocks =
        parse_format_list("ForwardingAddress :\nForwardingSmtpAddress : smtp:x@evil.example\n");
    assert_eq!(blocks[0].get("ForwardingAddress"), Some(""));
    assert_eq!(
        blocks[0].get("ForwardingSmtpAddress"),
        Some("smtp:x@evil.example")
    );
    assert!(parse_format_list("").is_empty());
}

/// Shape of a Hawk AutoReply_<user>.txt written by Windows PowerShell 5.1: wrapped values on
/// indented continuation lines, and blank lines that split one object.
const AUTO_REPLY: &str = concat!(
    "\r\n\r\n",
    "AutoReplyState  : Enabled\r\n",
    "EndTime         : 9/30/2026 5:00:00 PM\r\n",
    "ExternalMessage : <html><body>Out of office\r\n",
    "                  until October.</body></html>\r\n",
    "\r\n",
    "InternalMessage : <html><body>Away\r\n",
    "\r\n",
    "                  back soon</body></html>\r\n",
    "StartTime       : 9/24/2026 8:00:00 AM\r\n",
    "Identity        : alice\r\n",
    "\r\n",
);

#[test]
fn object_mode_keeps_fields_after_blank_lines() {
    let b = parse_format_list_object(AUTO_REPLY).unwrap();
    assert_eq!(b.get("AutoReplyState"), Some("Enabled"));
    assert_eq!(
        b.get("ExternalMessage"),
        Some("<html><body>Out of office until October.</body></html>")
    );
    assert_eq!(
        b.get("InternalMessage"),
        Some("<html><body>Away back soon</body></html>")
    );
    assert_eq!(b.get("StartTime"), Some("9/24/2026 8:00:00 AM"));
    assert_eq!(b.get("Identity"), Some("alice"));
    assert!(parse_format_list(AUTO_REPLY).len() > 1);
    assert!(parse_format_list_object("\r\n\r\n").is_none());
}

#[test]
fn field_spans_cover_continuation_lines() {
    let b = parse_format_list_object(AUTO_REPLY).unwrap();
    assert_eq!(b.fields.len(), b.field_spans.len());
    let i = b
        .fields
        .iter()
        .position(|(k, _)| k == "ExternalMessage")
        .unwrap();
    let s = b.field_spans[i];
    let text = &AUTO_REPLY[s.start..s.end];
    assert!(text.starts_with("ExternalMessage :"), "{text}");
    assert!(text.ends_with("until October.</body></html>"), "{text}");
    let whole = &AUTO_REPLY[b.span.start..b.span.end];
    assert!(whole.starts_with("AutoReplyState"));
    assert!(whole.ends_with("Identity        : alice"));
}

#[test]
fn unindented_non_field_lines_are_ignored_and_the_first_duplicate_wins() {
    let blocks =
        parse_format_list("Name : a\r\n---- not a field ----\r\nName : b\r\nOther : c\r\n");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].fields.len(), 3);
    assert_eq!(blocks[0].get("Name"), Some("a"));
    let m = blocks[0].to_map();
    assert_eq!(m["Name"], "a");
    assert_eq!(m["Other"], "c");
    assert_eq!(m.len(), 2);
}
