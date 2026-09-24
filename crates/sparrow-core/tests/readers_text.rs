use sparrow_core::readers::text::*;

fn utf16le(s: &str, bom: bool) -> Vec<u8> {
    let mut v = if bom { vec![0xFF, 0xFE] } else { vec![] };
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

#[test]
fn decodes_plain_utf8() {
    let d = decode(b"a,b\n1,2\n");
    assert_eq!(d.encoding, TextEncoding::Utf8);
    assert_eq!(d.bom_len, 0);
    assert_eq!(d.text, "a,b\n1,2\n");
}

#[test]
fn decodes_utf8_with_bom() {
    let d = decode(&[0xEF, 0xBB, 0xBF, b'h', b'i']);
    assert_eq!(d.encoding, TextEncoding::Utf8Bom);
    assert_eq!(d.bom_len, 3);
    assert_eq!(d.text, "hi");
}

#[test]
fn decodes_utf16le_with_bom_including_non_ascii() {
    let d = decode(&utf16le("café\r\nzoë", true));
    assert_eq!(d.encoding, TextEncoding::Utf16Le);
    assert_eq!(d.bom_len, 2);
    assert_eq!(d.text, "café\r\nzoë");
}

#[test]
fn detects_bomless_utf16le() {
    let d = decode(&utf16le("[2026-09-10 14:15:00Z] - hello", false));
    assert_eq!(d.encoding, TextEncoding::Utf16Le);
    assert_eq!(d.bom_len, 0);
    assert_eq!(d.text, "[2026-09-10 14:15:00Z] - hello");
}

#[test]
fn falls_back_to_windows_1252_for_invalid_utf8() {
    let d = decode(&[b'c', b'a', b'f', 0xE9]);
    assert_eq!(d.encoding, TextEncoding::Windows1252);
    assert_eq!(d.text, "café");
    assert!(d.lossy, "windows-1252 fallback must be reported as lossy");
}

#[test]
fn clean_utf8_is_not_lossy() {
    let d = decode("café\n".as_bytes());
    assert_eq!(d.encoding, TextEncoding::Utf8);
    assert!(!d.lossy);
}

#[test]
fn decodes_utf16be_with_bom() {
    let mut raw = vec![0xFE, 0xFF];
    for u in "café\r\nzoë".encode_utf16() {
        raw.extend_from_slice(&u.to_be_bytes());
    }
    let d = decode(&raw);
    assert_eq!(d.encoding, TextEncoding::Utf16Be);
    assert_eq!(d.bom_len, 2);
    assert_eq!(d.text, "café\r\nzoë");
    assert!(!d.lossy);
}

#[test]
fn utf16_with_odd_trailing_byte_maps_end_to_raw_length() {
    let mut raw = utf16le("ab\r\ncd", true);
    raw.push(b'x');
    let d = decode(&raw);
    assert!(d.text.ends_with('\u{FFFD}'));
    assert!(
        d.lossy,
        "a truncated UTF-16 code unit must be reported as lossy"
    );
    let mut m = OffsetMapper::new(&d, raw.len() as u64);
    assert_eq!(m.raw_offset(&d.text, d.text.len()), raw.len() as u64);
    let cd = d.text.find("cd").unwrap();
    assert_eq!(m.raw_offset(&d.text, cd), 2 + 8);
}

#[test]
fn line_index_maps_offsets_to_lines() {
    let text = "ab\r\ncd\nef";
    let idx = LineIndex::new(text);
    assert_eq!(idx.line_count(), 3);
    assert_eq!(idx.line_of(0), 1);
    assert_eq!(idx.line_of(4), 2);
    assert_eq!(idx.line_of(7), 3);
    assert_eq!(idx.line_text(text, 1, 2), "ab\r\ncd");
    assert_eq!(idx.line_text(text, 3, 3), "ef");
}

#[test]
fn locate_utf16_record_gives_raw_byte_offsets() {
    let raw = utf16le("ab\ncd", true);
    let d = decode(&raw);
    let idx = LineIndex::new(&d.text);
    let mut m = OffsetMapper::new(&d, raw.len() as u64);
    let pos = locate(&d.text, &idx, &mut m, Span { start: 3, end: 5 });
    assert_eq!(
        pos,
        SourcePos {
            line_start: 2,
            line_end: 2,
            byte_offset: 8,
            byte_length: 4
        }
    );
    assert_eq!(&raw[8..12], &utf16le("cd", false)[..]);
}

#[test]
fn locate_utf8_bom_multiline_record() {
    let mut raw = vec![0xEF, 0xBB, 0xBF];
    raw.extend_from_slice("x\n{\n \"a\": 1\n}\n".as_bytes());
    let d = decode(&raw);
    let idx = LineIndex::new(&d.text);
    let mut m = OffsetMapper::new(&d, raw.len() as u64);
    let pos = locate(&d.text, &idx, &mut m, Span { start: 2, end: 13 });
    assert_eq!(pos.line_start, 2);
    assert_eq!(pos.line_end, 4);
    assert_eq!(pos.byte_offset, 5);
    assert_eq!(pos.byte_length, 11);
}

#[test]
fn offset_mapper_handles_non_ascii_in_utf16_and_rewinds() {
    let raw = utf16le("é€x", true);
    let d = decode(&raw);
    let mut m = OffsetMapper::new(&d, raw.len() as u64);
    let x = d.text.find('x').unwrap();
    assert_eq!(m.raw_offset(&d.text, x), 2 + 4);
    assert_eq!(m.raw_offset(&d.text, 0), 2);
}

#[test]
fn line_spans_strip_terminators() {
    let text = "a\r\nbc\n\nd";
    let spans: Vec<&str> = line_spans(text)
        .iter()
        .map(|s| &text[s.start..s.end])
        .collect();
    assert_eq!(spans, vec!["a", "bc", "", "d"]);
}

#[test]
fn bomless_utf16le_csv_with_quoted_header_decodes() {
    let s = "\"origin_timestamp_utc\",\"sender_address\"\r\n\"2026-09-01T10:00:00.0000000Z\",\"a@contoso.example\"\r\n";
    let d = decode(&utf16le(s, false));
    assert_eq!(d.encoding, TextEncoding::Utf16Le);
    assert_eq!(d.bom_len, 0);
    assert!(!d.lossy);
    assert_eq!(d.text, s);
}
