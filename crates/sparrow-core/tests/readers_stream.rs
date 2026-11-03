//! `readers::stream` against the whole-file oracle in `readers::text`: admission, windowed decoding and sightings
//! must equal `decode` / `locate` exactly, for every encoding and every chunk size.

use sparrow_core::discovery::SNIFF_BYTES;
use sparrow_core::hash::sha256_hex;
use sparrow_core::readers::stream::*;
use sparrow_core::readers::text::*;
use std::io::ErrorKind;
use std::path::PathBuf;

fn utf16(s: &str, le: bool, bom: bool) -> Vec<u8> {
    let mut v = match (bom, le) {
        (false, _) => vec![],
        (true, true) => vec![0xFF, 0xFE],
        (true, false) => vec![0xFE, 0xFF],
    };
    for u in s.encode_utf16() {
        v.extend_from_slice(&if le { u.to_le_bytes() } else { u.to_be_bytes() });
    }
    v
}

fn bom8(s: &str) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(s.as_bytes());
    v
}

/// ASCII-heavy text (bomless UTF-16LE needs ≥ 90% zero high bytes in its first 256 bytes) with a few accents.
fn ascii_heavy(nl: &str, trailing: bool) -> String {
    let mut s = String::new();
    for i in 0..12 {
        s.push_str(&format!("user{i}@contoso.com,MailItemsAccessed,{i}"));
        if i == 7 {
            s.push_str(",café zoë €");
        }
        s.push_str(nl);
    }
    s.push_str("last,row,ünï 𝄞");
    if trailing {
        s.push_str(nl);
    }
    s
}

fn multibyte(nl: &str, trailing: bool) -> String {
    let mut s = format!("Name,Value{nl}héllo,wörld €{nl}{nl}emoji,😀😀{nl}last 𝄞 line");
    if trailing {
        s.push_str(nl);
    }
    s
}

/// Mostly ASCII bytes, one `é` (0xE9) and one `€` (0x80) near the end: invalid UTF-8, so Windows-1252.
fn cp1252(nl: &[u8], trailing: bool) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..10 {
        v.extend_from_slice(format!("row{i},value{i}").as_bytes());
        v.extend_from_slice(nl);
    }
    v.extend_from_slice(b"caf\xE9,price \x80");
    v.extend_from_slice(nl);
    v.extend_from_slice(b"end");
    if trailing {
        v.extend_from_slice(nl);
    }
    v
}

/// A file above one checkpoint interval (64 KiB of decoded text) and above the sniff head.
fn large(nl: &str) -> String {
    let mut s = String::new();
    let mut i = 0;
    while s.len() < 150 * 1024 {
        s.push_str(&format!(
            "{i},user{i}@contoso.com,Operation{},é€𝄞{nl}",
            i % 7
        ));
        i += 1;
    }
    s
}

fn inputs() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    for (nl, nl_name) in [("\n", "lf"), ("\r\n", "crlf")] {
        for trailing in [false, true] {
            let t = if trailing { "trail" } else { "notrail" };
            let m = multibyte(nl, trailing);
            let a = ascii_heavy(nl, trailing);
            v.push((format!("utf8-{nl_name}-{t}"), m.as_bytes().to_vec()));
            v.push((format!("utf8bom-{nl_name}-{t}"), bom8(&m)));
            v.push((format!("utf16le-{nl_name}-{t}"), utf16(&m, true, true)));
            v.push((format!("utf16be-{nl_name}-{t}"), utf16(&m, false, true)));
            v.push((format!("bomless16-{nl_name}-{t}"), utf16(&a, true, false)));
            v.push((format!("ascii-utf8-{nl_name}-{t}"), a.as_bytes().to_vec()));
            v.push((
                format!("cp1252-{nl_name}-{t}"),
                cp1252(nl.as_bytes(), trailing),
            ));
            let mut b = vec![0xEF, 0xBB, 0xBF];
            b.extend(cp1252(nl.as_bytes(), trailing));
            v.push((format!("bom-cp1252-{nl_name}-{t}"), b));
        }
    }
    // Edge cases.
    v.push(("empty".into(), vec![]));
    v.push(("only-nl".into(), b"\n".to_vec()));
    v.push(("only-crlf".into(), b"\r\n".to_vec()));
    v.push(("ends-cr".into(), b"a\r".to_vec()));
    v.push(("blank-ws".into(), b"  \r\n\t\n".to_vec()));
    v.push(("bom8-only".into(), vec![0xEF, 0xBB, 0xBF]));
    v.push(("bom16le-only".into(), vec![0xFF, 0xFE]));
    v.push(("bom16be-only".into(), vec![0xFE, 0xFF]));
    v.push(("partial-bom".into(), vec![0xEF, 0xBB]));
    v.push(("one-byte".into(), vec![b'x']));
    v.push(("utf16le-odd".into(), {
        let mut b = utf16("ab\ncd", true, true);
        b.push(b'e');
        b
    }));
    v.push(("utf16be-odd".into(), {
        let mut b = utf16("ab\ncd", false, true);
        b.push(0);
        b
    }));
    v.push(("utf16le-lone-surrogate".into(), {
        let mut b = utf16("ab\n", true, true);
        b.extend_from_slice(&[0x00, 0xD8]); // high surrogate, then a plain char
        b.extend(utf16("z\nq", true, false));
        b
    }));
    v.push(("utf16le-trailing-high-surrogate".into(), {
        let mut b = utf16("ab\n", true, true);
        b.extend_from_slice(&[0x3D, 0xD8]);
        b
    }));
    v.push(("bomless16-odd".into(), {
        let mut b = utf16(&ascii_heavy("\n", true), true, false);
        b.push(b'x');
        b
    }));
    v.push(("bomless16-white".into(), utf16("    \n  ", true, false)));
    v.push(("utf8-truncated-tail".into(), b"abc\n\xE2\x82".to_vec()));
    v.push(("utf8-bad-middle".into(), b"abc\n\xC3(\ndef".to_vec()));
    v.push((
        "utf16-nul-blank".into(),
        vec![0xFF, 0xFE, b' ', 0, b'\n', 0],
    ));
    v
}

fn large_inputs() -> Vec<(String, Vec<u8>)> {
    let l = large("\r\n");
    let n = large("\n");
    vec![
        ("large-utf8".into(), n.as_bytes().to_vec()),
        ("large-utf8bom".into(), bom8(&l)),
        ("large-utf16le".into(), utf16(&l, true, true)),
        ("large-utf16be".into(), utf16(&n, false, true)),
        ("large-cp1252".into(), {
            let mut b = l.replace(['é', '€', '𝄞'], "x").into_bytes();
            let at = b.len() - 10;
            b[at] = 0xE9;
            b
        }),
    ]
}

fn chunks() -> Vec<usize> {
    (1..=17).chain([CHUNK_BYTES]).collect()
}

fn ok() -> impl FnMut(u64) -> bool {
    |_| true
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn on_disk(raw: &[u8]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.csv");
    std::fs::write(&path, raw).unwrap();
    Fixture { _dir: dir, path }
}

fn admitted(f: &Fixture, chunk: usize) -> Admitted {
    admit(&f.path, chunk, &mut ok()).unwrap()
}

/// Both stream sources: the file (`open`) and memory (`from_bytes`).
fn streams(a: &Admitted, raw: &[u8], chunk: usize) -> [(&'static str, TextStream); 2] {
    [
        ("file", a.open(chunk).unwrap()),
        ("bytes", TextStream::from_bytes(raw.to_vec(), a, chunk)),
    ]
}

#[test]
fn admit_matches_decode() {
    let mut checked = 0;
    for (name, raw) in inputs().into_iter().chain(large_inputs()) {
        let d = decode(&raw);
        let f = on_disk(&raw);
        for chunk in chunks() {
            let a = admitted(&f, chunk);
            let ctx = format!("{name} chunk {chunk}");
            assert_eq!(a.path, f.path, "{ctx}");
            assert_eq!(a.raw_len, raw.len() as u64, "{ctx}");
            assert_eq!(a.encoding, d.encoding, "{ctx}");
            assert_eq!(a.bom_len, d.bom_len, "{ctx}");
            assert_eq!(a.lossy, d.lossy, "{ctx}");
            assert_eq!(a.sha256, sha256_hex(&raw), "{ctx}");
            assert_eq!(a.blank, is_blank_content(&raw), "{ctx}");
            assert_eq!(a.head, raw[..raw.len().min(SNIFF_BYTES)], "{ctx}");
            assert_eq!(
                a.modified,
                std::fs::metadata(&f.path).unwrap().modified().ok(),
                "{ctx}"
            );
            assert!(a.unchanged().unwrap(), "{ctx}");
            checked += 1;
        }
    }
    assert!(checked > 500, "{checked}");
}

#[test]
fn from_bytes_matches_admit() {
    let mut checked = 0;
    for (name, raw) in inputs().into_iter().chain(large_inputs()) {
        let f = on_disk(&raw);
        let want = admitted(&f, 4096);
        let got = Admitted::from_bytes(&f.path, &raw);
        assert_eq!(format!("{got:?}"), format!("{want:?}"), "{name}");
        checked += 1;
    }
    assert!(checked > 40, "{checked}");
    // A path that does not exist: no modification time, the rest from the bytes.
    let raw = b"a,b\n1,2\n";
    let got = Admitted::from_bytes(std::path::Path::new("/nonexistent/x.csv"), raw);
    assert_eq!(got.modified, None);
    assert_eq!(got.raw_len, raw.len() as u64);
    assert_eq!(got.sha256, sha256_hex(raw));
}

#[test]
fn admitted_encodings_cover_every_kind() {
    // Guards against a vacuous oracle comparison: the inputs exercise every encoding and both lossy states.
    let mut seen = std::collections::HashSet::new();
    for (_, raw) in inputs() {
        let d = decode(&raw);
        seen.insert((d.encoding.as_str(), d.bom_len, d.lossy));
    }
    for want in [
        ("utf-8", 0, false),
        ("utf-8-bom", 3, false),
        ("utf-16le", 2, false),
        ("utf-16le", 2, true),
        ("utf-16be", 2, false),
        ("utf-16be", 2, true),
        ("utf-16le", 0, false),
        ("windows-1252", 0, true),
        ("windows-1252", 3, true),
    ] {
        assert!(seen.contains(&want), "missing {want:?} in {seen:?}");
    }
}

#[test]
fn head_text_decodes_the_head() {
    for (name, raw) in inputs() {
        let f = on_disk(&raw);
        let a = admitted(&f, 4096);
        // Inputs are shorter than the head, so the head text is the whole decoded text.
        assert_eq!(a.head_text(), decode(&raw).text, "{name}");
    }
    // A head cut inside a multi-byte character drops the partial character.
    let mut s = "a".repeat(SNIFF_BYTES - 1);
    s.push('é');
    s.push_str("tail");
    let f = on_disk(s.as_bytes());
    let a = admitted(&f, 4096);
    assert_eq!(a.head_text(), "a".repeat(SNIFF_BYTES - 1));
    // UTF-16 head: decoded with the admitted encoding.
    let u = utf16(&"xy".repeat(SNIFF_BYTES), true, true);
    let f = on_disk(&u);
    let a = admitted(&f, 4096);
    let want = decode(&u[..SNIFF_BYTES]).text.into_owned();
    assert_eq!(a.head_text(), want);
}

#[test]
fn unchanged_detects_size_change() {
    let f = on_disk(b"a,b\n1,2\n");
    let a = admitted(&f, 3);
    assert!(a.unchanged().unwrap());
    std::fs::write(&f.path, b"a,b\n1,2\n3,4\n").unwrap();
    assert!(!a.unchanged().unwrap());
}

#[test]
fn window_text_matches_decode() {
    for (name, raw) in inputs().into_iter().chain(large_inputs()) {
        let want = decode(&raw).text.into_owned();
        let f = on_disk(&raw);
        for chunk in chunks() {
            let a = admitted(&f, chunk);
            for (src, mut s) in streams(&a, &raw, chunk) {
                let ctx = format!("{name} chunk {chunk} {src}");
                let mut got = String::new();
                let mut fills = 0;
                assert_eq!(s.base(), 0, "{ctx}");
                while s.fill(&mut ok()).unwrap() {
                    fills += 1;
                    assert_eq!(s.base(), got.len(), "{ctx}");
                    got.push_str(s.window());
                    let end = s.base() + s.window().len();
                    s.consume(end);
                    assert_eq!(s.window(), "", "{ctx}");
                    assert_eq!(s.base(), end, "{ctx}");
                }
                assert!(s.at_eof(), "{ctx}");
                assert!(!s.fill(&mut ok()).unwrap(), "{ctx}: fill after eof");
                assert_eq!(got, want, "{ctx}");
                if !raw.is_empty() {
                    assert!(fills >= 1, "{ctx}");
                }
                if chunk < CHUNK_BYTES && raw.len() > 2 * chunk {
                    assert!(fills >= raw.len() / chunk, "{ctx}: {fills} fills");
                }
            }
        }
    }
}

#[test]
fn window_keeps_unconsumed_text() {
    // Consuming only part of the window keeps the rest, and the next fill appends after it.
    let raw = utf16(&multibyte("\r\n", true), true, true);
    let want = decode(&raw).text.into_owned();
    for chunk in chunks() {
        let mut s = TextStream::from_bytes(raw.clone(), &admitted(&on_disk(&raw), chunk), chunk);
        let mut kept = 0;
        while s.fill(&mut ok()).unwrap() {
            let end = s.base() + s.window().len();
            assert_eq!(&want[s.base()..end], s.window(), "chunk {chunk}");
            // Keep the last two complete chars in the window.
            let w = s.window();
            let mut cut = w.len();
            for _ in 0..2 {
                if let Some((i, _)) = w[..cut].char_indices().next_back() {
                    cut = i;
                }
            }
            kept = w.len() - cut;
            s.consume(s.base() + cut);
        }
        assert_eq!(s.base() + kept, want.len(), "chunk {chunk}");
        assert_eq!(s.window(), &want[want.len() - kept..], "chunk {chunk}");
    }
}

/// Fill until absolute decoded offset `end` is inside the window.
fn fill_to(s: &mut TextStream, end: usize) {
    while s.base() + s.window().len() < end {
        assert!(s.fill(&mut ok()).unwrap(), "stream ended before {end}");
    }
}

fn want_sight(raw: &[u8], pos: SourcePos) -> String {
    let start = pos.byte_offset as usize;
    sha256_hex(&raw[start..start + pos.byte_length as usize])
}

#[test]
fn sight_matches_locate() {
    let mut checked = 0;
    for (name, raw) in inputs().into_iter().chain(large_inputs()) {
        let d = decode(&raw);
        let text = d.text.clone().into_owned();
        let index = LineIndex::new(&text);
        let mut mapper = OffsetMapper::new(&d, raw.len() as u64);
        let spans = line_spans(&text);
        let f = on_disk(&raw);
        let sizes: Vec<usize> = if raw.len() > 100_000 {
            vec![1, 7, 16, 4096, CHUNK_BYTES]
        } else {
            chunks()
        };
        for chunk in sizes {
            let a = admitted(&f, chunk);
            for (src, mut s) in streams(&a, &raw, chunk) {
                let ctx = format!("{name} chunk {chunk} {src}");
                for (i, &span) in spans.iter().enumerate() {
                    fill_to(&mut s, span.end);
                    let got = s.sight(span);
                    let want = locate(&text, &index, &mut mapper, span);
                    assert_eq!(got.pos, want, "{ctx} span {i} {span:?}");
                    assert_eq!(got.raw_sha256, want_sight(&raw, want), "{ctx} span {i}");
                    let snip: String = text[span.start..span.end].chars().take(500).collect();
                    assert_eq!(s.snippet(span), snip, "{ctx} span {i}");
                    // A query pointing back at an earlier span still in the window.
                    if i >= 2 {
                        let back = spans[i - 2];
                        let got = s.sight(back);
                        let want = locate(&text, &index, &mut mapper, back);
                        assert_eq!(got.pos, want, "{ctx} back span {}", i - 2);
                        assert_eq!(got.raw_sha256, want_sight(&raw, want), "{ctx} back");
                        s.consume(back.start);
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 5000, "{checked}");
}

#[test]
fn sight_multi_line_and_inner_spans() {
    // Spans covering several lines, ending right after a newline, empty spans, and spans inside a line.
    for (name, raw) in inputs().into_iter().chain(large_inputs()) {
        let d = decode(&raw);
        let text = d.text.clone().into_owned();
        let index = LineIndex::new(&text);
        let mut mapper = OffsetMapper::new(&d, raw.len() as u64);
        let bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        let step = (bounds.len() / 40).max(1);
        let mut spans = Vec::new();
        for (k, &b) in bounds.iter().enumerate().step_by(step) {
            for len in [0usize, 1, 3, 17, 300] {
                let e = bounds.get(k + len).copied().unwrap_or(text.len());
                spans.push(Span { start: b, end: e });
            }
        }
        for chunk in [1usize, 5, 13, CHUNK_BYTES] {
            let a = admitted(&on_disk(&raw), chunk);
            let mut s = TextStream::from_bytes(raw.clone(), &a, chunk);
            for &span in &spans {
                fill_to(&mut s, span.end);
                let got = s.sight(span);
                let want = locate(&text, &index, &mut mapper, span);
                assert_eq!(got.pos, want, "{name} chunk {chunk} {span:?}");
                assert_eq!(got.raw_sha256, want_sight(&raw, want), "{name} {span:?}");
            }
            // The empty span at the very end of the text (LineIndex starts no line after a final `\n`).
            while s.fill(&mut ok()).unwrap() {}
            let end = Span {
                start: text.len(),
                end: text.len(),
            };
            let want = locate(&text, &index, &mut mapper, end);
            assert_eq!(s.sight(end).pos, want, "{name} chunk {chunk} end");
        }
    }
}

#[test]
fn sight_backwards_across_checkpoints() {
    // The whole file in the window: spans queried forwards, then backwards, then partly consumed.
    for (name, raw) in large_inputs() {
        let d = decode(&raw);
        let text = d.text.clone().into_owned();
        let index = LineIndex::new(&text);
        let mut mapper = OffsetMapper::new(&d, raw.len() as u64);
        let spans = line_spans(&text);
        assert!(spans.len() > 2000, "{name}");
        let a = admitted(&on_disk(&raw), 64 * 1024);
        let mut s = TextStream::from_bytes(raw.clone(), &a, 64 * 1024);
        while s.fill(&mut ok()).unwrap() {}
        let check = |s: &mut TextStream, m: &mut OffsetMapper, span: Span| {
            let got = s.sight(span);
            let want = locate(&text, &index, m, span);
            assert_eq!(got.pos, want, "{name} {span:?}");
            assert_eq!(got.raw_sha256, want_sight(&raw, want), "{name} {span:?}");
        };
        for &span in &spans {
            check(&mut s, &mut mapper, span);
        }
        for &span in spans.iter().rev() {
            check(&mut s, &mut mapper, span);
        }
        // Scattered order.
        for k in 0..spans.len() {
            check(&mut s, &mut mapper, spans[(k * 7919) % spans.len()]);
        }
        // Consume half, then query the rest backwards from the end.
        let half = spans[spans.len() / 2].start;
        s.consume(half);
        assert_eq!(s.base(), half);
        for &span in spans.iter().rev().take_while(|sp| sp.start >= half) {
            check(&mut s, &mut mapper, span);
        }
    }
}

#[test]
fn snippet_is_capped_at_500_chars() {
    let line = "é".repeat(800);
    let raw = utf16(&format!("{line}\nx"), true, true);
    let a = admitted(&on_disk(&raw), 100);
    let mut s = TextStream::from_bytes(raw.clone(), &a, 100);
    fill_to(&mut s, line.len());
    let snip = s.snippet(Span {
        start: 0,
        end: line.len(),
    });
    assert_eq!(snip.chars().count(), 500);
    assert_eq!(snip, "é".repeat(500));
}

#[test]
fn on_read_reports_every_byte() {
    for (name, raw) in inputs() {
        let f = on_disk(&raw);
        for chunk in [1usize, 4, CHUNK_BYTES] {
            let mut total = 0u64;
            let a = admit(&f.path, chunk, &mut |n| {
                total += n;
                true
            })
            .unwrap();
            assert_eq!(total, raw.len() as u64, "{name} admit chunk {chunk}");
            let mut s = a.open(chunk).unwrap();
            let mut total = 0u64;
            while s
                .fill(&mut |n| {
                    total += n;
                    true
                })
                .unwrap()
            {}
            assert_eq!(total, raw.len() as u64, "{name} fill chunk {chunk}");
        }
    }
}

#[test]
fn on_read_false_interrupts() {
    let raw = utf16(&multibyte("\r\n", true), true, true);
    let f = on_disk(&raw);
    for chunk in [1usize, 7, CHUNK_BYTES] {
        let err = admit(&f.path, chunk, &mut |_| false).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Interrupted, "admit chunk {chunk}");
        // Stopping after some reads, not only the first.
        if chunk * 3 < raw.len() {
            let mut calls = 0;
            let err = admit(&f.path, chunk, &mut |_| {
                calls += 1;
                calls < 3
            })
            .unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Interrupted,
                "admit late, chunk {chunk}"
            );
            assert_eq!(calls, 3, "chunk {chunk}");
        }

        let a = admitted(&f, chunk);
        for (src, mut s) in streams(&a, &raw, chunk) {
            let err = s.fill(&mut |_| false).unwrap_err();
            assert_eq!(
                err.kind(),
                ErrorKind::Interrupted,
                "fill {src} chunk {chunk}"
            );
        }
    }
}
