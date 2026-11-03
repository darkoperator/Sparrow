//! `ParseContext::queue_source` + `flush_sources` (one set-based INSERT) must leave `record_sources` exactly as
//! the per-row `record_source` path does: every column, in physical order, including the rows that conflict on the
//! primary key (the first one wins, as with `ON CONFLICT DO NOTHING` row by row).

use sparrow_core::Case;
use sparrow_core::ingest::IngestOptions;
use sparrow_core::ingest::context::{ParseContext, RecordSource, WholeText};
use sparrow_core::readers::stream::Admitted;
use sparrow_core::readers::text::{LineIndex, Span, decode};

/// 14 lines of different lengths, so every span has its own line and byte numbers.
fn file_text() -> String {
    (1..=14)
        .map(|n| format!("row {n} {}\n", "x".repeat(n * 3)))
        .collect()
}

/// The span of line `n` (1-based) of [`file_text`].
fn line(text: &str, n: usize) -> Span {
    let mut start = 0;
    for (i, l) in text.split_inclusive('\n').enumerate() {
        if i + 1 == n {
            return Span {
                start,
                end: start + l.len() - 1,
            };
        }
        start += l.len();
    }
    panic!("no line {n}");
}

type Input = (&'static str, String, u64, usize);

/// Calls in the order a parser makes them: distinct rows, exact duplicates, a key reused with another span
/// (a conflict, the first span must stay), the same key at another ordinal, another key at the same ordinal,
/// and awkward text in keys.
fn inputs() -> Vec<Input> {
    let k = |s: &str| s.to_string();
    vec![
        ("ual_events", k("aaa"), 1, 1),
        ("ual_events", k("bbb"), 2, 2),
        ("ual_events", k("aaa"), 1, 1),          // exact duplicate
        ("ual_events", k("aaa"), 1, 5), // same key and ordinal, other span: conflict, line 1 stays
        ("ual_events", k("aaa"), 3, 3), // same key, other ordinal: its own row
        ("ual_events", k("ccc"), 3, 4), // other key, same ordinal as above
        ("mail_items_accessed", k("aaa"), 1, 6), // same key and ordinal in another table
        ("ual_events", k("d'q\"é|\u{1F600} \\"), 7, 8),
        ("ual_events", k("bbb"), 2, 9),   // conflict again
        ("collection_log", k(""), 0, 10), // empty key
        ("ual_events", k("eee"), 9, 14),
    ]
}

type Row = (String, String, i64, i64, i32, i32, i64, i64, String, i64);

fn dump(case: &Case) -> Vec<Row> {
    let mut stmt = case
        .conn()
        .prepare(
            "SELECT table_name, record_key, file_id, record_ordinal, line_start, line_end, byte_offset,
                    byte_length, raw_sha256, rowid FROM record_sources ORDER BY rowid",
        )
        .unwrap();
    stmt.query_map([], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
            r.get(7)?,
            r.get(8)?,
            r.get(9)?,
        ))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// Run `calls` (a batch is flushed at each `None`) through the old or the new path on a fresh case.
fn run(batches: &[Vec<Input>], per_row: bool) -> Vec<Row> {
    let dir = tempfile::tempdir().unwrap();
    let case = Case::create_or_open(&dir.path().join("c.duckdb")).unwrap();
    let text = file_text();
    let raw = text.clone().into_bytes();
    let decoded = decode(&raw);
    let index = LineIndex::new(&decoded.text);
    let opts = IngestOptions::default();
    let admitted = Admitted::from_bytes(std::path::Path::new("x.csv"), &raw);
    let mut ctx = ParseContext::new(
        case.conn(),
        1,
        7,
        "x.csv",
        None,
        &admitted,
        RecordSource::Memory(&raw),
        Some(WholeText {
            raw: &raw,
            text: &decoded,
            index: &index,
        }),
        &opts,
    );
    for batch in batches {
        for (table, key, ordinal, ln) in batch {
            let sight = ctx.sighting(line(&text, *ln));
            if per_row {
                ctx.record_source(table, key, *ordinal, &sight).unwrap();
            } else {
                ctx.queue_source(table, key, *ordinal, &sight);
            }
        }
        if !per_row {
            ctx.flush_sources().unwrap();
        }
    }
    dump(&case)
}

#[test]
fn set_based_sightings_equal_the_per_row_path_including_conflicts() {
    let batches = vec![inputs()];
    let old = run(&batches, true);
    let new = run(&batches, false);
    // The batch has 11 calls; the conflicts collapse them to 8 rows, so the comparison is not vacuous.
    assert_eq!(old.len(), 8, "{old:?}");
    assert_eq!(new, old);
    // The first span won each conflict: ("ual_events", "aaa", 1) is line 1, not line 5.
    let aaa = old
        .iter()
        .find(|r| r.0 == "ual_events" && r.1 == "aaa" && r.3 == 1)
        .unwrap();
    assert_eq!(aaa.4, 1);
}

#[test]
fn flushing_in_several_batches_conflicts_with_rows_from_earlier_batches() {
    // Batch two repeats keys of batch one (conflicts with rows already stored) and adds a new one.
    let all = inputs();
    let batches = vec![
        all[..5].to_vec(),
        all[3..].to_vec(),
        vec![("ual_events", "aaa".to_string(), 1, 12)],
    ];
    let old = run(&batches, true);
    let new = run(&batches, false);
    assert_eq!(old.len(), 8, "{old:?}");
    assert_eq!(new, old);
}

#[test]
fn an_empty_flush_is_a_no_op() {
    let new = run(&[Vec::new()], false);
    assert!(new.is_empty());
}

#[test]
fn a_large_batch_dedups_first_wins_like_the_per_row_path() {
    // 2,600 sightings (past a DuckDB vector boundary): every 7th repeats an earlier key with another span, every
    // 11th is an exact duplicate. The surviving rows and spans must equal the per-row path's. The `rowid` order is
    // compared too, but it can only fail if DuckDB reorders this insert; the dedup and first-wins parts are what
    // this test is sure to catch.
    let mut batch: Vec<Input> = Vec::new();
    for i in 0..2600u64 {
        let ln = (i % 14 + 1) as usize;
        let (table, key, ordinal) = match i {
            _ if i % 7 == 0 && i > 0 => ("ual_events", format!("k{}", i - 7), i - 7),
            _ if i % 11 == 0 && i > 0 => ("ual_events", format!("k{}", i - 11), i - 11),
            _ => ("ual_events", format!("k{i}"), i),
        };
        batch.push((table, key, ordinal, ln));
    }
    let old = run(&[batch.clone()], true);
    let new = run(&[batch], false);
    assert!(old.len() > 1800 && old.len() < 2600, "{}", old.len());
    assert_eq!(new, old);
}
