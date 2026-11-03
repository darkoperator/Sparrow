//! The windowed scanners against the whole-text ones: `read_csv_stream` / `scan_json_stream` over a `TextStream`
//! must give the same events (ordinal, span, fields / value, errors) and the same headers / shape as
//! `read_csv_each` / `scan_json_each` over the decoded text, for every chunk size. The sink sights each event while
//! it is in the window, and the sighting must equal `locate` on the whole text.

use sparrow_core::hash::sha256_hex;
use sparrow_core::readers::csv_scan::*;
use sparrow_core::readers::json_scan::*;
use sparrow_core::readers::stream::*;
use sparrow_core::readers::text::*;
use sparrow_synth::generate::generate_to_dir;
use sparrow_synth::options::{Collector, GenerateOptions, PsEdition, UalFormat};
use sparrow_synth::scenario::load;
use std::io::ErrorKind;
use std::path::Path;

const CHUNKS: [usize; 4] = [1, 7, 64, 4096];

fn ok() -> impl FnMut(u64) -> bool {
    |_| true
}

fn utf16le_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn bom8(s: &str) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(s.as_bytes());
    v
}

fn audit_data(len: usize) -> String {
    let mut s = String::from("{\"\"Operation\"\":\"\"MailItemsAccessed\"\",\"\"Folders\"\":[");
    let mut i = 0;
    while s.len() < len {
        s.push_str(&format!("{{\"\"Path\"\":\"\"\\\\Inbox\\\\é{i}\"\"}},"));
        i += 1;
    }
    s.push_str("{}]}");
    s
}

fn csv_cases() -> Vec<(String, Vec<u8>)> {
    let big = audit_data(40 * 1024);
    let mut v: Vec<(String, Vec<u8>)> = vec![
        (
            "quoted-crlf".into(),
            b"Name,Note\r\nalice,\"line one\r\nline two\"\r\nbob,plain\r\n".to_vec(),
        ),
        (
            "auditdata-40k".into(),
            format!("CreationDate,UserIds,AuditData\r\n2026-01-01,a@x.com,\"{big}\"\r\n2026-01-02,b@x.com,\"{{}}\"\r\n")
                .into_bytes(),
        ),
        (
            "malformed-mid".into(),
            b"A,B,C\n1,2,3\n4,\"un\"closed,5,6\n7,8\n\"x\"\"y\",9,10\n".to_vec(),
        ),
        (
            "type-line".into(),
            b"#TYPE Selected.System.Management.Automation.PSCustomObject\r\n\"A\",\"B\"\r\n\"1\",\"2\"\r\n"
                .to_vec(),
        ),
        (
            "type-line-bom".into(),
            bom8("#TYPE X\n\"A\",\"A\",\" b  c \"\n1,2,3\n"),
        ),
        ("double-bom".into(), bom8("\u{feff}A,B\n1,2\n")),
        ("utf16".into(), utf16le_bom("A,B\r\n1,\"é\r\nz\"\r\n3,4\r\n")),
        ("no-trailing-nl".into(), b"A,B\n1,2\n3,4".to_vec()),
        ("blank-lines".into(), b"\n\nA,B\n\n\n1,2\n\n  \n\n".to_vec()),
        ("cr-only".into(), b"A,B\r1,2\r3,4\r".to_vec()),
        ("header-only".into(), b"A,B\r\n".to_vec()),
        ("empty".into(), vec![]),
        ("whitespace".into(), b" \r\n \n".to_vec()),
        ("unclosed-quote-at-eof".into(), b"A,B\n1,\"open\nstill".to_vec()),
    ];
    let mut long = String::from("Id,Name\n");
    for i in 0..3000 {
        long.push_str(&format!("{i},user{i}@contoso.com é\n"));
    }
    v.push(("many-rows".into(), long.into_bytes()));
    v
}

fn json_cases() -> Vec<(String, Vec<u8>)> {
    let big = "x".repeat(40 * 1024);
    vec![
        (
            "array".into(),
            b"[\r\n  {\"a\": 1, \"s\": \"x]y}\\\"\"},\r\n  {\"a\": [2, {\"b\": null}]}\r\n]\r\n"
                .to_vec(),
        ),
        (
            "bare-object".into(),
            b"{\"a\": 1, \"b\": \"two\"}\n".to_vec(),
        ),
        (
            "concatenated".into(),
            b"[{\"a\":1}]\n[{\"a\":2},{\"a\":3}]\n{\"b\":4}".to_vec(),
        ),
        (
            "jsonl".into(),
            b"{\"a\":1}\n{\"a\":2}\r\n\n{\"a\":3}\n".to_vec(),
        ),
        (
            "truncated-last".into(),
            b"[{\"a\":1},{\"a\":2},{\"a\":".to_vec(),
        ),
        (
            "truncated-string".into(),
            b"{\"a\":1}\n{\"a\":\"open".to_vec(),
        ),
        ("bracket-only".into(), b"[".to_vec()),
        ("bracket-ws".into(), b"[ \n ".to_vec()),
        (
            "bad-separator".into(),
            b"[{\"a\":1} {\"a\":2}, {\"a\":3}]   \n\n".to_vec(),
        ),
        (
            "bad-record".into(),
            b"[{\"a\":1},{\"a\" 2},{\"a\":3}]".to_vec(),
        ),
        ("trailing-comma".into(), b"[{\"a\":1},]\n".to_vec()),
        (
            "scalars".into(),
            b"[1, 23.5e2, true, null, \"s\"]  7 ] }".to_vec(),
        ),
        ("empty".into(), vec![]),
        ("whitespace".into(), b" \r\n\t ,, \n".to_vec()),
        (
            "big-record".into(),
            format!("[{{\"AuditData\": \"{big}\"}}, {{\"n\": 2}}]").into_bytes(),
        ),
        (
            "utf16".into(),
            utf16le_bom("[{\"a\":\"é𝄞\"},\r\n{\"a\":2}]\r\n"),
        ),
        ("bom8".into(), bom8("{\"a\":1}{\"a\":2}")),
    ]
}

/// Every CSV and JSON file of a few generated collector trees (the core tests have no fixture files).
fn synth_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut trees = vec![
        ("hawk4", GenerateOptions::new(Collector::Hawk4, 7)),
        ("portal", GenerateOptions::new(Collector::Portal, 8)),
    ];
    let mut o = GenerateOptions::new(Collector::Hawk3, 9);
    o.ps = PsEdition::Ps51;
    trees.push(("hawk3-ps51", o));
    for f in [UalFormat::Csv, UalFormat::Json, UalFormat::Jsonl] {
        let mut o = GenerateOptions::new(Collector::Invictus, 10);
        o.ual_format = f;
        o.invictus_devices_json = true;
        trees.push((
            match f {
                UalFormat::Csv => "invictus-csv",
                UalFormat::Json => "invictus-json",
                _ => "invictus-jsonl",
            },
            o,
        ));
    }
    let scenario = load("business-basic").unwrap();
    let mut files = Vec::new();
    for (name, o) in trees {
        let root = dir.join(name);
        generate_to_dir(&scenario, &o, &root).unwrap();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase);
                if matches!(ext.as_deref(), Some("csv" | "json" | "jsonl")) {
                    let rel = p.strip_prefix(dir).unwrap().display().to_string();
                    files.push((rel, std::fs::read(&p).unwrap()));
                }
            }
        }
    }
    files.sort();
    files
}

fn is_json(name: &str) -> bool {
    name.ends_with(".json") || name.ends_with(".jsonl")
}

/// An admitted on-disk copy of `raw` (the stream itself reads `raw` from memory).
fn admitted(raw: &[u8]) -> Admitted {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input");
    std::fs::write(&path, raw).unwrap();
    admit(&path, 4096, &mut ok()).unwrap()
}

/// The whole-text side: decoded text, line index and offset mapper, as ingest builds them.
struct Whole<'a> {
    raw: &'a [u8],
    decoded: DecodedText<'a>,
    index: LineIndex,
    mapper: OffsetMapper,
}

impl<'a> Whole<'a> {
    fn new(raw: &'a [u8]) -> Self {
        let decoded = decode(raw);
        let index = LineIndex::new(&decoded.text);
        let mapper = OffsetMapper::new(&decoded, raw.len() as u64);
        Whole {
            raw,
            decoded,
            index,
            mapper,
        }
    }

    /// The sighting and snippet ingest would record for `span`.
    fn seen(&mut self, span: Span) -> String {
        let text = &self.decoded.text;
        let pos = locate(text, &self.index, &mut self.mapper, span);
        let raw = &self.raw[pos.byte_offset as usize..(pos.byte_offset + pos.byte_length) as usize];
        let end = span.end.min(text.len());
        let snippet: String = text[span.start.min(end)..end].chars().take(500).collect();
        format!("{pos:?} {} {snippet:?}", sha256_hex(raw))
    }
}

fn streamed_seen(stream: &mut TextStream, span: Span) -> String {
    // The scanners never hand over a record that touches the window end before the end of the file.
    let window_end = stream.base() + stream.window().len();
    assert!(
        stream.at_eof() || span.end < window_end,
        "span {span:?} touches the window end {window_end} before EOF"
    );
    let sight = stream.sight(span);
    let snippet = stream.snippet(span);
    format!("{:?} {} {snippet:?}", sight.pos, sight.raw_sha256)
}

fn csv_span(e: &CsvEvent) -> Span {
    match e {
        CsvEvent::Row(r) => r.span,
        CsvEvent::Error(e) => e.span,
    }
}

fn json_span(e: &JsonEvent) -> Span {
    match e {
        JsonEvent::Record(r) => r.span,
        JsonEvent::Error(e) => e.span,
    }
}

/// Whole-text CSV events (with their sightings) and headers, stopping after `stop` events.
fn csv_whole(raw: &[u8], stop: usize) -> (Vec<String>, Vec<String>) {
    let mut w = Whole::new(raw);
    let text = w.decoded.text.clone();
    let mut events = Vec::new();
    let headers = read_csv_each(&text, |h, e| {
        events.push(format!("{h:?} {e:?} {}", w.seen(csv_span(&e))));
        events.len() < stop
    });
    (events, headers)
}

fn csv_streamed(raw: &[u8], a: &Admitted, chunk: usize, stop: usize) -> (Vec<String>, Vec<String>) {
    let mut s = TextStream::from_bytes(raw.to_vec(), a, chunk);
    let mut events = Vec::new();
    let headers = read_csv_stream(&mut s, &mut ok(), |h, e, st| {
        events.push(format!("{h:?} {e:?} {}", streamed_seen(st, csv_span(&e))));
        events.len() < stop
    })
    .unwrap();
    (events, headers)
}

fn json_whole(raw: &[u8], stop: usize) -> (Vec<String>, JsonShape) {
    let mut w = Whole::new(raw);
    let text = w.decoded.text.clone();
    let mut events = Vec::new();
    let shape = scan_json_each(&text, |e| {
        events.push(format!("{e:?} {}", w.seen(json_span(&e))));
        events.len() < stop
    });
    (events, shape)
}

fn json_streamed(raw: &[u8], a: &Admitted, chunk: usize, stop: usize) -> (Vec<String>, JsonShape) {
    let mut s = TextStream::from_bytes(raw.to_vec(), a, chunk);
    let mut events = Vec::new();
    let shape = scan_json_stream(&mut s, &mut ok(), |e, st| {
        events.push(format!("{e:?} {}", streamed_seen(st, json_span(&e))));
        events.len() < stop
    })
    .unwrap();
    (events, shape)
}

/// Chunk sizes for a file: all of them, except the per-byte ones on large generated files (they would take minutes
/// in a debug build and add nothing the synthetic cases do not cover).
fn chunks_for(raw: &[u8]) -> Vec<usize> {
    CHUNKS
        .into_iter()
        .filter(|&c| c >= 64 || raw.len() <= 256 * 1024)
        .collect()
}

#[test]
fn csv_stream_matches_whole() {
    let dir = tempfile::tempdir().unwrap();
    let synth: Vec<_> = synth_files(dir.path())
        .into_iter()
        .filter(|(n, _)| !is_json(n))
        .collect();
    assert!(
        synth.len() >= 20,
        "only {} generated CSV files",
        synth.len()
    );
    let mut events = 0;
    let mut errors_seen = false;
    let files = synth.len();
    for (name, raw) in csv_cases().into_iter().chain(synth) {
        let a = admitted(&raw);
        let (want, want_headers) = csv_whole(&raw, usize::MAX);
        errors_seen |= want.iter().any(|e| e.contains("Error("));
        for chunk in chunks_for(&raw) {
            let (got, got_headers) = csv_streamed(&raw, &a, chunk, usize::MAX);
            assert_eq!(got_headers, want_headers, "{name} chunk {chunk}: headers");
            assert_eq!(got.len(), want.len(), "{name} chunk {chunk}: event count");
            for (i, (g, w)) in got.iter().zip(&want).enumerate() {
                assert_eq!(g, w, "{name} chunk {chunk}: event {i}");
            }
            events += got.len();
        }
        // A sink that stops early sees the same prefix.
        if want.len() > 2 {
            for chunk in [7, 4096] {
                let (got, got_headers) = csv_streamed(&raw, &a, chunk, 2);
                let (want2, want_headers2) = csv_whole(&raw, 2);
                assert_eq!(
                    (got, got_headers),
                    (want2, want_headers2),
                    "{name} chunk {chunk}: stop"
                );
            }
        }
    }
    eprintln!(
        "csv: {files} generated files + {} synthetic, {events} events compared",
        csv_cases().len()
    );
    assert!(events > 10_000, "{events} events compared");
    // The csv crate is lenient: a malformed row parses, it does not error.
    assert!(!errors_seen);
}

#[test]
fn json_stream_matches_whole() {
    let dir = tempfile::tempdir().unwrap();
    let synth: Vec<_> = synth_files(dir.path())
        .into_iter()
        .filter(|(n, _)| is_json(n))
        .collect();
    assert!(
        synth.len() >= 5,
        "only {} generated JSON files",
        synth.len()
    );
    let mut events = 0;
    let mut errors = 0;
    let mut shapes = std::collections::HashSet::new();
    let files = synth.len();
    for (name, raw) in json_cases().into_iter().chain(synth) {
        let a = admitted(&raw);
        let (want, want_shape) = json_whole(&raw, usize::MAX);
        errors += want.iter().filter(|e| e.starts_with("Error(")).count();
        shapes.insert(format!("{want_shape:?}"));
        for chunk in chunks_for(&raw) {
            let (got, got_shape) = json_streamed(&raw, &a, chunk, usize::MAX);
            assert_eq!(got_shape, want_shape, "{name} chunk {chunk}: shape");
            assert_eq!(got.len(), want.len(), "{name} chunk {chunk}: event count");
            for (i, (g, w)) in got.iter().zip(&want).enumerate() {
                assert_eq!(g, w, "{name} chunk {chunk}: event {i}");
            }
            events += got.len();
        }
        if want.len() > 1 {
            for chunk in [7, 4096] {
                let (got, got_shape) = json_streamed(&raw, &a, chunk, 1);
                let (want1, want_shape1) = json_whole(&raw, 1);
                assert_eq!(
                    (got, got_shape),
                    (want1, want_shape1),
                    "{name} chunk {chunk}: stop"
                );
            }
        }
    }
    eprintln!(
        "json: {files} generated files + {} synthetic, {events} events, {errors} errors",
        json_cases().len()
    );
    assert!(events > 1_000, "{events} events compared");
    assert!(errors >= 8, "{errors} error events");
    assert_eq!(shapes.len(), 4, "{shapes:?}");
}

#[test]
fn stopped_read_ends_the_scan() {
    let mut csv = String::from("A,B\n");
    let mut json = String::from("[");
    for i in 0..200 {
        csv.push_str(&format!("{i},value{i}\n"));
        json.push_str(&format!("{{\"a\":{i}}},"));
    }
    json.push_str("{}]");
    let stop_after = |limit: u64| {
        let mut read = 0u64;
        move |n: u64| {
            read += n;
            read <= limit
        }
    };
    let (csv, json) = (csv.into_bytes(), json.into_bytes());
    let a = admitted(&csv);
    let mut s = TextStream::from_bytes(csv.clone(), &a, 64);
    let mut rows = 0;
    let err = read_csv_stream(&mut s, &mut stop_after(1000), |_, _, _| {
        rows += 1;
        true
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Interrupted);
    assert!(rows > 0 && rows < 200, "{rows} rows before the stop");

    let a = admitted(&json);
    let mut s = TextStream::from_bytes(json.clone(), &a, 64);
    let mut records = 0;
    let err = scan_json_stream(&mut s, &mut stop_after(1000), |_, _| {
        records += 1;
        true
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Interrupted);
    assert!(
        records > 0 && records < 201,
        "{records} records before the stop"
    );
}
