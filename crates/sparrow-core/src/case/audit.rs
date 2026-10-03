//! The hash-chained audit trail (Addendum D.3): one row per agent decision or review, each linked to the one before
//! by `prev_hash`. `append` must run inside the caller's transaction, together with the change it records.
//!
//! `append` re-verifies the whole chain first (O(n) per append). That is acceptable: agent decisions number in the
//! thousands, not millions.

use crate::case::actor::Actor;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, OptionalExt, params};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The actor of the entry `Case::upgrade` writes when it brings a case to the Phase 7 schema.
pub const SYSTEM_UPGRADE: &str = "system:upgrade";

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub seq: i64,
    #[serde(serialize_with = "ts_serialize")]
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub on_behalf_of: Option<String>,
    pub action: String,
    pub object_type: String,
    pub object_id: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainReport {
    pub ok: bool,
    pub entries: i64,
    pub head_hash: Option<String>,
    /// The seq where the open (unacknowledged) break starts; for a gap, the first missing seq.
    pub first_bad_seq: Option<i64>,
    pub problem: Option<String>,
    /// The first bad seq of every break an `acknowledge_break` entry has recorded.
    pub acknowledged_breaks: Vec<i64>,
}

/// UTC RFC 3339 with microseconds: the timestamp form inside the hashed JSON.
pub fn ts_text(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn ts_serialize<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&ts_text(t))
}

/// Compact JSON with the keys of every object sorted.
pub fn canonical(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                Value::Object(out)
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(v)).expect("a JSON value serializes")
}

/// Every field but `prev_hash` and `hash`.
fn body(e: &AuditEntry) -> Value {
    serde_json::json!({
        "seq": e.seq,
        "ts": ts_text(&e.ts),
        "actor": e.actor,
        "on_behalf_of": e.on_behalf_of,
        "action": e.action,
        "object_type": e.object_type,
        "object_id": e.object_id,
        "before": e.before,
        "after": e.after,
        "reason": e.reason,
    })
}

/// hex SHA-256 of `prev_hash` followed by the canonical JSON of the entry's other fields.
pub fn entry_hash(prev_hash: &str, e: &AuditEntry) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(canonical(&body(e)).as_bytes());
    hex::encode(h.finalize())
}

/// The case's random UUID (`case_meta`), set by the analyst migration.
pub fn case_id(conn: &Connection) -> Result<String> {
    Ok(conn
        .prepare_cached("SELECT value FROM case_meta WHERE key = 'case_id'")?
        .query_row([], |r| r.get(0))?)
}

/// The `prev_hash` of seq 1: hex SHA-256 of "sparrow-audit-genesis" followed by the case id.
pub fn genesis(conn: &Connection) -> Result<String> {
    Ok(hex::encode(Sha256::digest(format!(
        "sparrow-audit-genesis{}",
        case_id(conn)?
    ))))
}

fn read(conn: &Connection, object: Option<(&str, &str)>) -> Result<Vec<AuditEntry>> {
    let (t, i) = object
        .map(|(t, i)| (Some(t), Some(i)))
        .unwrap_or((None, None));
    let mut stmt = conn.prepare(
        "SELECT seq, epoch_us(ts), actor, on_behalf_of, action, object_type, object_id, \
                CAST(before AS VARCHAR), CAST(after AS VARCHAR), reason, prev_hash, hash \
         FROM audit_trail \
         WHERE ?::VARCHAR IS NULL OR (object_type = ?::VARCHAR AND object_id = ?::VARCHAR) \
         ORDER BY seq",
    )?;
    // Stored JSON that does not parse is kept as a string: its hash then fails verification.
    let parse = |s: Option<String>| {
        s.map(|s| serde_json::from_str::<Value>(&s).unwrap_or(Value::String(s)))
    };
    let rows = stmt.query_map(params![t, t, i], |r| {
        Ok(AuditEntry {
            seq: r.get(0)?,
            ts: DateTime::from_timestamp_micros(r.get(1)?).unwrap_or_default(),
            actor: r.get(2)?,
            on_behalf_of: r.get(3)?,
            action: r.get(4)?,
            object_type: r.get(5)?,
            object_id: r.get(6)?,
            before: parse(r.get(7)?),
            after: parse(r.get(8)?),
            reason: r.get(9)?,
            prev_hash: r.get(10)?,
            hash: r.get(11)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// The entries in seq order; only those of `(object_type, object_id)` when given.
pub fn log(conn: &Connection, object: Option<(&str, &str)>) -> Result<Vec<AuditEntry>> {
    read(conn, object)
}

/// One break in the chain: where it is, why, and the row that shows it (as stored now).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Break {
    /// The first bad seq (for a gap: the first missing seq).
    seq: i64,
    problem: String,
    /// The `hash` column of the row where the break shows (for a gap: the row after it).
    stored_hash: String,
    /// `entry_hash` recomputed over that row's current content.
    content_hash: String,
    /// For a break against the recorded head (truncation, or a rewritten newest entry): that head's seq and hash.
    recorded_head: Option<(i64, String)>,
}

impl Break {
    /// The `after` of the `acknowledge_break` entry that records this break.
    fn ack_after(&self) -> Value {
        if let Some((seq, hash)) = &self.recorded_head {
            return serde_json::json!({
                "first_bad_seq": self.seq,
                "problem": self.problem,
                "recorded_head_seq": seq,
                "recorded_head_hash": hash,
            });
        }
        serde_json::json!({
            "first_bad_seq": self.seq,
            "problem": self.problem,
            "acknowledged_hash": self.stored_hash,
            "acknowledged_content_hash": self.content_hash,
        })
    }
}

/// Walk the chain and return every unacknowledged break, in seq order.
/// - each row's seq must be the previous row's seq + 1 (seq 1 first), its prev_hash the previous row's stored hash
///   (genesis for the first row), and its hash `entry_hash(prev_hash, row)`; each row that fails opens a break;
/// - an intact, linked `acknowledge_break` row closes the ONE open break it names: same first bad seq, same problem,
///   and the same stored hash and content of the row that shows it. Any other break stays open, and a break whose
///   row changed again after its acknowledgement is not the acknowledged one.
///
/// Each row is compared with the previous row's stored seq and hash, not with its index, so the rows after a break
/// (and the acknowledgement) still link.
fn breaks(conn: &Connection) -> Result<(Vec<AuditEntry>, Vec<Break>, Vec<i64>)> {
    #[cfg(any(test, feature = "test-fixtures"))]
    test_hooks::FULL_WALKS.with(|n| n.set(n.get() + 1));
    let all = read(conn, None)?;
    let mut prev_hash = genesis(conn)?;
    let mut prev_seq = 0i64;
    let mut open: Vec<Break> = Vec::new();
    let mut acks = Vec::new();
    for e in &all {
        let content_hash = entry_hash(&e.prev_hash, e);
        let self_ok = content_hash == e.hash;
        let linked = e.prev_hash == prev_hash;
        let problem = if e.seq != prev_seq + 1 {
            Some((
                prev_seq + 1,
                format!(
                    "sequence gap: expected seq {}, found {}",
                    prev_seq + 1,
                    e.seq
                ),
            ))
        } else if !linked {
            Some((
                e.seq,
                "prev_hash does not match the previous entry".to_string(),
            ))
        } else if !self_ok {
            Some((e.seq, "hash does not match the entry's content".to_string()))
        } else {
            None
        };
        match problem {
            Some((seq, problem)) => open.push(Break {
                seq,
                problem,
                stored_hash: e.hash.clone(),
                content_hash,
                recorded_head: None,
            }),
            None if e.action == "acknowledge_break" => {
                if let Some(i) = open
                    .iter()
                    .position(|b| e.after.as_ref() == Some(&b.ack_after()))
                {
                    acks.push(open.remove(i).seq);
                } else if let Some(bad) = head_ack(e) {
                    // A break against the recorded head left no row to pin: its acknowledgement is the entry
                    // appended right after the surviving head, which also resets the recorded head.
                    acks.push(bad);
                }
            }
            None => {}
        }
        prev_hash = e.hash.clone();
        prev_seq = e.seq;
    }
    if let Some((seq, hash)) = recorded_head(conn)? {
        match all.iter().find(|e| e.seq == seq) {
            Some(e) if e.hash == hash => {}
            Some(e) => open.push(Break {
                seq,
                problem: format!("the entry at the recorded head (seq {seq}) has a different hash"),
                stored_hash: e.hash.clone(),
                content_hash: entry_hash(&e.prev_hash, e),
                recorded_head: Some((seq, hash)),
            }),
            None if prev_seq < seq => open.push(Break {
                seq: prev_seq + 1,
                problem: format!("chain is shorter than the recorded head (seq {seq})"),
                stored_hash: String::new(),
                content_hash: String::new(),
                recorded_head: Some((seq, hash)),
            }),
            // A missing row below the stored head is a gap, reported by the walk.
            None => {}
        }
        open.sort_by_key(|b| b.seq);
    }
    Ok((all, open, acks))
}

/// The `case_meta` key of the head (seq and hash) the last insert left: a deleted or rewritten newest entry is
/// detected against it.
const HEAD_KEY: &str = "audit_head";

fn recorded_head(conn: &Connection) -> Result<Option<(i64, String)>> {
    let v: Option<String> = conn
        .prepare_cached("SELECT value FROM case_meta WHERE key = ?")?
        .query_row([HEAD_KEY], |r| r.get(0))
        .optional()?;
    Ok(v.and_then(|v| {
        let (seq, hash) = v.split_once(':')?;
        Some((seq.parse().ok()?, hash.to_string()))
    }))
}

/// The first bad seq a head acknowledgement `e` records, when `e` sits where it must: at that seq (the chain was
/// shorter) or right after the recorded head (the head entry was rewritten).
fn head_ack(e: &AuditEntry) -> Option<i64> {
    let after = e.after.as_ref()?;
    let bad = after.get("first_bad_seq")?.as_i64()?;
    let head = after.get("recorded_head_seq")?.as_i64()?;
    (e.seq == bad || e.seq == head + 1).then_some(bad)
}

/// Verify the whole chain. `ok` is true when no break is open; `first_bad_seq` and `problem` describe the first
/// open break.
pub fn verify(conn: &Connection) -> Result<ChainReport> {
    let (all, open, acks) = breaks(conn)?;
    let first = open.into_iter().next();
    Ok(ChainReport {
        ok: first.is_none(),
        entries: all.len() as i64,
        head_hash: all.last().map(|e| e.hash.clone()),
        first_bad_seq: first.as_ref().map(|b| b.seq),
        problem: first.map(|b| b.problem),
        acknowledged_breaks: acks,
    })
}

/// The stored last row's seq and hash.
fn head(conn: &Connection) -> Result<Option<(i64, String)>> {
    // Not cached: DuckDB keeps a cached plan's column statistics, and an ORDER BY or aggregate planned on an
    // empty audit_trail then fails (or misreads) on real rows.
    Ok(conn
        .query_row(
            "SELECT seq, hash FROM audit_trail ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

/// Chain one entry to the stored head and insert it, without checking the chain.
#[allow(clippy::too_many_arguments)]
fn insert(
    conn: &Connection,
    ts: DateTime<Utc>,
    actor: &str,
    on_behalf_of: Option<&str>,
    action: &str,
    object_type: &str,
    object_id: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    reason: Option<&str>,
) -> Result<AuditEntry> {
    let (seq, prev_hash) = match head(conn)? {
        Some((s, h)) => (s + 1, h),
        None => (1, genesis(conn)?),
    };
    let mut e = AuditEntry {
        seq,
        ts,
        actor: actor.into(),
        on_behalf_of: on_behalf_of.map(Into::into),
        action: action.into(),
        object_type: object_type.into(),
        object_id: object_id.into(),
        before: before.cloned(),
        after: after.cloned(),
        reason: reason.map(Into::into),
        prev_hash,
        hash: String::new(),
    };
    e.hash = entry_hash(&e.prev_hash, &e);
    conn.prepare_cached(
        "INSERT INTO audit_trail (seq, ts, actor, on_behalf_of, action, object_type, object_id, before, after, \
                                  reason, prev_hash, hash) \
         VALUES (?, CAST(? AS TIMESTAMPTZ), ?, ?, ?, ?, ?, CAST(? AS JSON), CAST(? AS JSON), ?, ?, ?)",
    )?
    .execute(params![
            e.seq,
            ts_text(&e.ts),
            e.actor,
            e.on_behalf_of,
            e.action,
            e.object_type,
            e.object_id,
            e.before.as_ref().map(canonical),
            e.after.as_ref().map(canonical),
            e.reason,
            e.prev_hash,
            e.hash
        ],
    )?;
    conn.prepare_cached("INSERT OR REPLACE INTO case_meta (key, value) VALUES (?, ?)")?
        .execute(params![HEAD_KEY, format!("{}:{}", e.seq, e.hash)])?;
    Ok(e)
}

/// The current time at microsecond precision (as stored): the `ts` of an entry, and the `decided_at` /
/// `reviewed_at` of the change it records.
pub fn now() -> DateTime<Utc> {
    DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap_or_default()
}

/// The `case_meta` key of the last fully verified chain state.
const VERIFIED_KEY: &str = "audit_verified";

/// DuckDB's `hash()` of every column `verify` reads, for one stored row.
const ROW_HASH: &str = "hash(seq, epoch_us(ts), actor, on_behalf_of, action, object_type, object_id, \
     CAST(before AS VARCHAR), CAST(after AS VARCHAR), reason, prev_hash, hash)";

/// A fingerprint of everything `verify` reads: the case id (the genesis), the row count, the head, and the XOR of
/// every row's hash (each covers the row's seq, so reordering rows changes it). Any change to a row, the row set or
/// the case id changes it. Computed by DuckDB in one scan, without sorting.
///
/// It only decides when `append` may skip the full SHA-256 walk. It is not a cryptographic commitment, and needs
/// not be: whoever can edit audit rows can also rewrite the stored fingerprint (in `case_meta`), whatever hash it
/// used. `verify` (the CLI's `audit verify`, the exports) always walks the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    count: i64,
    head_seq: i64,
    head_hash: String,
    rows: u64,
    case_id: String,
}

impl Fingerprint {
    fn text(&self) -> String {
        format!(
            "{}:{}:{}:{:016x}:{}",
            self.count, self.head_seq, self.head_hash, self.rows, self.case_id
        )
    }
}

fn fingerprint(conn: &Connection) -> Result<Fingerprint> {
    let sql = format!(
        "SELECT count(*), coalesce(max(seq), 0), coalesce(arg_max(hash, seq), ''), \
                coalesce(bit_xor({ROW_HASH}), 0) FROM audit_trail"
    );
    let (count, head_seq, head_hash, rows) = conn.query_row(&sql, [], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })?;
    Ok(Fingerprint {
        count,
        head_seq,
        head_hash,
        rows,
        case_id: case_id(conn)?,
    })
}

/// `fp` extended by the stored row `e` (just appended to the chain `fp` describes): one point lookup, no scan.
fn extended(conn: &Connection, fp: Fingerprint, e: &AuditEntry) -> Result<Fingerprint> {
    let row: u64 = conn
        .prepare_cached(&format!("SELECT {ROW_HASH} FROM audit_trail WHERE seq = ?"))?
        .query_row([e.seq], |r| r.get(0))?;
    Ok(Fingerprint {
        count: fp.count + 1,
        head_seq: e.seq,
        head_hash: e.hash.clone(),
        rows: fp.rows ^ row,
        case_id: fp.case_id,
    })
}

fn verified_fingerprint(conn: &Connection) -> Result<Option<String>> {
    Ok(conn
        .prepare_cached("SELECT value FROM case_meta WHERE key = ?")?
        .query_row([VERIFIED_KEY], |r| r.get(0))
        .optional()?)
}

fn store_verified(conn: &Connection, fp: &Fingerprint) -> Result<()> {
    conn.prepare_cached("INSERT OR REPLACE INTO case_meta (key, value) VALUES (?, ?)")?
        .execute(params![VERIFIED_KEY, fp.text()])?;
    Ok(())
}

/// Fail unless the chain is intact. The full Rust `verify` runs only when the stored head is not the recorded one
/// or the stored rows differ from the last state this check verified (their fingerprint, `VERIFIED_KEY`); any change to any row, the row set or the case id
/// changes the fingerprint and forces it.
fn ensure_intact(conn: &Connection) -> Result<Fingerprint> {
    let fp = fingerprint(conn)?;
    let head_matches = match recorded_head(conn)? {
        Some((seq, hash)) => seq == fp.head_seq && hash == fp.head_hash,
        None => true,
    };
    if head_matches && verified_fingerprint(conn)?.as_deref() == Some(fp.text().as_str()) {
        return Ok(fp);
    }
    let r = verify(conn)?;
    if !r.ok {
        return Err(Error::ChainBroken(format!(
            "the audit chain is broken at seq {} ({}); run `sparrow audit verify --acknowledge` to record the break",
            r.first_bad_seq.unwrap_or(0),
            r.problem.unwrap_or_default()
        )));
    }
    Ok(fp)
}

/// Append one entry at `ts` (use [`now`], and write the same `ts` to the change's `decided_at` / `reviewed_at`).
/// Must run inside the caller's transaction, with the change it records. Refuses when the chain is broken and the
/// break is not acknowledged.
#[allow(clippy::too_many_arguments)]
pub fn append_at(
    conn: &Connection,
    ts: DateTime<Utc>,
    actor: &str,
    on_behalf_of: Option<&str>,
    action: &str,
    object_type: &str,
    object_id: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    reason: Option<&str>,
) -> Result<AuditEntry> {
    let fp = ensure_intact(conn)?;
    let e = insert(
        conn,
        ts,
        actor,
        on_behalf_of,
        action,
        object_type,
        object_id,
        before,
        after,
        reason,
    )?;
    // The chain was intact and the new entry is linked to its head: remember the new state as verified.
    store_verified(conn, &extended(conn, fp, &e)?)?;
    Ok(e)
}

/// [`append_at`] the current time.
#[allow(clippy::too_many_arguments)]
pub fn append(
    conn: &Connection,
    actor: &str,
    on_behalf_of: Option<&str>,
    action: &str,
    object_type: &str,
    object_id: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    reason: Option<&str>,
) -> Result<AuditEntry> {
    append_at(
        conn,
        now(),
        actor,
        on_behalf_of,
        action,
        object_type,
        object_id,
        before,
        after,
        reason,
    )
}

/// A system entry (`Case::upgrade`), appended without an [`Actor`]. Same contract as [`append`].
pub(crate) fn append_system(
    conn: &Connection,
    actor: &str,
    action: &str,
    object_type: &str,
    object_id: &str,
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<AuditEntry> {
    append(
        conn,
        actor,
        None,
        action,
        object_type,
        object_id,
        before,
        after,
        None,
    )
}

/// Record the first open break as its own entry, chained to the stored head. The entry names the break (seq,
/// problem) and pins the row that shows it (its stored hash and current content), so it closes that break only.
/// Several breaks need several acknowledgements. Runs its own transaction. Fails when the chain is intact.
pub fn acknowledge_break(conn: &Connection, actor: &Actor) -> Result<AuditEntry> {
    conn.execute_batch("BEGIN TRANSACTION")?;
    let out = (|| {
        let (_, open, _) = breaks(conn)?;
        let Some(b) = open.into_iter().next() else {
            return Err(Error::Decision("the audit chain is not broken".into()));
        };
        insert(
            conn,
            now(),
            actor.as_str(),
            actor.on_behalf_of(),
            "acknowledge_break",
            "audit_trail",
            &b.seq.to_string(),
            None,
            Some(&b.ack_after()),
            None,
        )
    })();
    match out {
        Ok(e) => {
            conn.execute_batch("COMMIT")?;
            Ok(e)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

/// Test-only instrumentation (never compiled into a normal build).
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub mod test_hooks {
    thread_local! {
        pub(super) static FULL_WALKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// Full walks of the audit chain (`verify`, and every append that could not use the verified fingerprint) on
    /// this thread so far.
    pub fn full_walks() -> usize {
        FULL_WALKS.with(std::cell::Cell::get)
    }
}
