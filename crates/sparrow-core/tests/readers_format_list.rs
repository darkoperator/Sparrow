use sparrow_core::readers::format_list::parse_format_list;

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
