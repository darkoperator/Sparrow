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
    let mut m = OffsetMapper::new(&d);
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
    let mut m = OffsetMapper::new(&d);
    let pos = locate(&d.text, &idx, &mut m, Span { start: 2, end: 13 });
    assert_eq!(pos.line_start, 2);
    assert_eq!(pos.line_end, 4);
    assert_eq!(pos.byte_offset, 5);
    assert_eq!(pos.byte_length, 11);
}

#[test]
fn offset_mapper_handles_non_ascii_in_utf16_and_rewinds() {
    let d = decode(&utf16le("é€x", true));
    let mut m = OffsetMapper::new(&d);
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
