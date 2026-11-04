//! Writing `record_sources` from a file's staged rows.
//!
//! `record_sources` has no key index (migration 30): DuckDB keeps an index in memory and never spills it, which capped
//! a case at about 12M sightings. Its four key columns `(table_name, record_key, file_id, record_ordinal)` are kept
//! unique by the writers instead, and every writer is in one file's transaction, writing that file's `file_id` only:
//! - a file is ingested in one transaction with a `file_id` of its own (`source_files` row inserted at its start,
//!   from `seq_file_id`); a failed, cancelled or deferred attempt rolls back with its rows, and a retry or a re-import
//!   inserts a new `source_files` row, so committed rows of any other file can never share a key with this file's;
//! - so a writer only has to drop duplicates among the rows it writes (the first one in staging order wins, as the
//!   old `ON CONFLICT DO NOTHING` kept the first inserted) and rows this file already wrote (an earlier flush or
//!   another writer of the same file).

use crate::Result;
use duckdb::Connection;

/// The staging-order values of the rows [`insert_from_stage`] leaves out as repeats; empty almost always.
const LATER: &str = "stage_sightings_later";

/// `INSERT INTO record_sources` of the rows staged in `stage` for file `file_id`, as evidence table `table` (a plain
/// table name). `key` is the stage's record-key column and `order` a column giving the staging order (unique per row);
/// the stage also has `ord`, `line_start`, `line_end`, `byte_offset`, `byte_length` and `raw_sha256`. A `(record key,
/// ord)` staged twice keeps its first row in `order`; a sighting this file already wrote is not written again.
///
/// The two checks run apart from the insert and are left out of it when they find nothing (the usual case): one
/// statement holding the window, the scan of this file's stored rows and the insert together took about 0.8 GB more
/// memory than the insert alone on 5.9M rows. Nothing depends on the order rows are inserted in (readers order
/// explicitly).
pub(crate) fn insert_from_stage(
    conn: &Connection,
    table: &str,
    stage: &str,
    key: &str,
    order: &str,
    file_id: i64,
) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE {LATER} AS
             SELECT {order} AS o FROM {stage}
             QUALIFY row_number() OVER (PARTITION BY {key}, ord ORDER BY {order}) > 1"
    ))?;
    let repeats: bool = conn.query_row(&format!("SELECT count(*) > 0 FROM {LATER}"), [], |r| {
        r.get(0)
    })?;
    // The file id and table name are literals so the scan is pruned to this file's rows (zone maps).
    let stored_sql = format!(
        "SELECT record_key, record_ordinal FROM record_sources WHERE file_id = {file_id} AND table_name = '{table}'"
    );
    let stored: bool =
        conn.query_row(&format!("SELECT EXISTS ({stored_sql})"), [], |r| r.get(0))?;
    let mut filters = Vec::new();
    if repeats {
        filters.push(format!(
            "NOT EXISTS (SELECT 1 FROM {LATER} l WHERE l.o = s.{order})"
        ));
    }
    if stored {
        filters.push(format!(
            "NOT EXISTS (SELECT 1 FROM ({stored_sql}) r WHERE r.record_key = s.{key} AND r.record_ordinal = s.ord)"
        ));
    }
    let filter = if filters.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", filters.join(" AND "))
    };
    conn.execute(
        &format!(
            "INSERT INTO record_sources (table_name, record_key, file_id, record_ordinal, line_start, line_end,
                                         byte_offset, byte_length, raw_sha256)
             SELECT '{table}', s.{key}, {file_id}, s.ord, s.line_start, s.line_end, s.byte_offset, s.byte_length,
                    s.raw_sha256
             FROM {stage} s {filter}"
        ),
        [],
    )?;
    conn.execute_batch(&format!("DROP TABLE {LATER}"))?;
    Ok(())
}
