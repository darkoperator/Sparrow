//! The UAL parser loads a file in batches of `IngestOptions::batch_rows` inside its transaction: every batch
//! size must store exactly what one batch stores, with the same per-file counts.

use sparrow_core::Case;
use sparrow_core::fixtures;
use sparrow_core::ingest::parser::ParserRegistry;
use sparrow_core::ingest::{IngestOptions, ingest_path};
use std::path::Path;

/// Every base table as (name, rows, content hash), leaving out what differs between two ingests of the same tree:
/// the random case id and the clock-dependent columns.
fn tables(case: &Case) -> Vec<(String, i64, String)> {
    let sql: String = case
        .conn()
        .query_row(
            "WITH c AS (
                SELECT table_name,
                       string_agg(format('\"{}\"', column_name), ',' ORDER BY ordinal_position) AS cols
                FROM information_schema.columns
                WHERE table_schema = 'main' AND table_name <> 'case_meta'
                  AND table_name IN (SELECT table_name FROM information_schema.tables
                                     WHERE table_type = 'BASE TABLE' AND table_schema = 'main')
                  AND NOT regexp_matches(column_name, '(_at|started|finished|duration|elapsed)$')
                GROUP BY table_name)
             SELECT string_agg(format('SELECT ''{}'' AS t, count(*) AS n, CAST(coalesce(sum(hash({})), 0) AS VARCHAR) AS h FROM \"{}\"',
                                      table_name, cols, table_name), ' UNION ALL ' ORDER BY table_name)
             FROM c",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut stmt = case.conn().prepare(&format!("{sql} ORDER BY t")).unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn ingest(base: &Path, batch: usize) -> (Vec<(String, i64, String)>, Vec<String>) {
    let mut case = Case::in_memory().unwrap();
    let opts = IngestOptions {
        batch_rows: batch,
        ..IngestOptions::default()
    };
    let report = ingest_path(&mut case, base, &ParserRegistry::builtin(), &opts).unwrap();
    let files = report
        .collections
        .iter()
        .flat_map(|c| &c.files)
        .map(|f| {
            format!(
                "{} {:?} {} {} {} {} {:?}",
                f.rel_path,
                f.status,
                f.records_read,
                f.records_loaded,
                f.records_duplicate,
                f.records_error,
                f.warnings
            )
        })
        .collect();
    (tables(&case), files)
}

#[test]
fn every_batch_size_stores_what_one_batch_stores() {
    let dir = tempfile::tempdir().unwrap();
    for (name, build) in [
        ("hawk", fixtures::hawk_tree as fn(&Path) -> std::path::PathBuf),
        ("hawk4", fixtures::hawk4::hawk4_tree),
        ("invictus-output", fixtures::invictus::invictus_output_tree),
        ("portal", fixtures::portal::portal_tree),
    ] {
        let base = dir.path().join(name);
        build(&base);
        if name == "portal" {
            // Several record types, an in-file duplicate (first copy wins, the second is a duplicate sighting) and a
            // row whose AuditData does not parse (a parse error between good rows), so batches of 1-3 cut across
            // all of them.
            let mut csv = fixtures::ual::PURVIEW_HEADER.to_string();
            for (time, audit) in [
                ("2026-09-01T10:00:00.0000000Z", fixtures::ual::rule()),
                ("2026-09-01T10:05:00.0000000Z", fixtures::ual::mail_items_accessed()),
                ("2026-09-01T10:06:00.0000000Z", fixtures::ual::login()),
                ("2026-09-01T10:00:00.0000000Z", fixtures::ual::rule()),
                ("2026-09-01T10:10:00.0000000Z", fixtures::ual::file_download()),
                ("2026-09-01T10:12:00.0000000Z", fixtures::ual::anonymous_link()),
                ("2026-09-01T10:15:00.0000000Z", fixtures::ual::search()),
            ] {
                csv += &fixtures::ual::purview_row(time, &audit);
            }
            let broken = fixtures::ual::purview_row("2026-09-01T10:20:00.0000000Z", &fixtures::ual::login())
                .replacen("{", "{{", 1);
            csv = csv.replacen(&fixtures::ual::purview_row("2026-09-01T10:06:00.0000000Z", &fixtures::ual::login()), &format!("{}{broken}", fixtures::ual::purview_row("2026-09-01T10:06:00.0000000Z", &fixtures::ual::login())), 1);
            fixtures::write(&base, fixtures::portal::PORTAL_PURVIEW, csv.as_bytes());
        }
        let (want_tables, want_files) = ingest(&base, usize::MAX);
        let ual = want_tables
            .iter()
            .find(|(t, ..)| t == "ual_events")
            .map(|(_, n, _)| *n)
            .unwrap();
        assert!(ual >= 1, "{name}: no UAL rows");
        if name == "portal" {
            let purview = want_files.iter().find(|f| f.starts_with(fixtures::portal::PORTAL_PURVIEW)).unwrap();
            // read 8, loaded 6, 1 duplicate, 1 error.
            assert!(purview.contains(" Parsed 8 6 1 1 "), "{purview}");
        }
        for batch in [1, 2, 3] {
            let (tables, files) = ingest(&base, batch);
            assert_eq!(files, want_files, "{name}, batch {batch}: file reports");
            assert_eq!(tables, want_tables, "{name}, batch {batch}: tables");
        }
    }
}
