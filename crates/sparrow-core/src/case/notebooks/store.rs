//! Case notebooks in the case file (`notebooks`, `notebook_queries`, migration 29) and the read side that joins them
//! with the built-in notebook. Every write is one transaction with its audit entry. The built-in notebook refuses
//! every write; renaming, reordering and deleting are the analyst's (an agent may create notebooks and add queries).

use super::builtin;
use super::file::{MAX_QUERIES, check_query_sql, title};
use super::placeholder::placeholders;
use crate::case::actor::Actor;
use crate::case::audit::{self, AuditEntry};
use crate::case::write::in_tx;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, OptionalExt, params};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The built-in notebook's id; its queries' ids start `builtin:`.
pub const BUILTIN_ID: &str = "builtin";
/// The built-in notebook's name, reserved: no case notebook may take it.
pub const BUILTIN_NAME: &str = "Built-in";

/// A query as a notebook list shows it.
#[derive(Debug, Clone, Serialize)]
pub struct QuerySummary {
    pub query_id: String,
    pub position: u32,
    pub title: String,
    pub placeholders: Vec<String>,
    /// Who saved it (`agent:<id>` or `analyst:<name>`); `None` for a built-in query.
    pub decided_by: Option<String>,
    pub on_behalf_of: Option<String>,
    /// When it was saved (UTC RFC 3339); `None` for a built-in query.
    pub decided_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotebookSummary {
    pub notebook_id: String,
    pub name: String,
    pub builtin: bool,
    pub queries: Vec<QuerySummary>,
}

/// One query with its text.
#[derive(Debug, Clone, Serialize)]
pub struct SavedQuery {
    #[serde(flatten)]
    pub summary: QuerySummary,
    pub notebook_id: String,
    pub sql: String,
}

fn summary(
    query_id: String,
    position: u32,
    sql: &str,
    who: Option<(String, Option<String>, String)>,
) -> QuerySummary {
    let (decided_by, on_behalf_of, decided_at) = match who {
        Some((by, behalf, at)) => (Some(by), behalf, Some(at)),
        None => (None, None, None),
    };
    QuerySummary {
        query_id,
        position,
        title: title(sql),
        placeholders: placeholders(sql),
        decided_by,
        on_behalf_of,
        decided_at,
    }
}

fn builtin_queries() -> Vec<SavedQuery> {
    builtin::queries()
        .iter()
        .enumerate()
        .map(|(i, q)| SavedQuery {
            summary: summary(q.id.to_string(), i as u32 + 1, q.sql, None),
            notebook_id: BUILTIN_ID.to_string(),
            sql: q.sql.to_string(),
        })
        .collect()
}

/// The case notebook queries of `notebook_id`, in order.
fn case_queries(conn: &Connection, notebook_id: &str) -> Result<Vec<SavedQuery>> {
    let mut stmt = conn.prepare(
        "SELECT query_id, position, sql, decided_by, on_behalf_of, epoch_us(decided_at) FROM notebook_queries \
         WHERE notebook_id = ? ORDER BY position",
    )?;
    let rows = stmt.query_map(params![notebook_id], |r| {
        let sql: String = r.get(2)?;
        let at = DateTime::from_timestamp_micros(r.get(5)?).unwrap_or_default();
        Ok(SavedQuery {
            summary: summary(
                r.get(0)?,
                r.get::<_, i32>(1)? as u32,
                &sql,
                Some((r.get(3)?, r.get(4)?, audit::ts_text(&at))),
            ),
            notebook_id: notebook_id.to_string(),
            sql,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// Every notebook: the built-in one first, then the case's by name (ignoring case).
pub fn list(conn: &Connection) -> Result<Vec<NotebookSummary>> {
    let mut out = vec![NotebookSummary {
        notebook_id: BUILTIN_ID.into(),
        name: BUILTIN_NAME.into(),
        builtin: true,
        queries: builtin_queries().into_iter().map(|q| q.summary).collect(),
    }];
    let mut stmt =
        conn.prepare("SELECT notebook_id, name FROM notebooks ORDER BY lower(name), notebook_id")?;
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    for (id, name) in rows {
        let queries = case_queries(conn, &id)?
            .into_iter()
            .map(|q| q.summary)
            .collect();
        out.push(NotebookSummary {
            notebook_id: id,
            name,
            builtin: false,
            queries,
        });
    }
    Ok(out)
}

/// Whether `name` names the built-in notebook (its name or its id, ignoring case and surrounding space): no case
/// notebook may take it, so a name always means one notebook.
fn reserved(name: &str) -> bool {
    let name = name.trim();
    name.eq_ignore_ascii_case(BUILTIN_NAME) || name.eq_ignore_ascii_case(BUILTIN_ID)
}

/// `(notebook_id, name)` of the notebook named by id or by exact name (ignoring case).
pub(crate) fn resolve_notebook(conn: &Connection, notebook: &str) -> Result<(String, String)> {
    if reserved(notebook) {
        return Ok((BUILTIN_ID.into(), BUILTIN_NAME.into()));
    }
    conn.query_row(
        "SELECT notebook_id, name FROM notebooks WHERE notebook_id = ? OR lower(name) = lower(?) \
         ORDER BY notebook_id = ? DESC LIMIT 1",
        params![notebook, notebook, notebook],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?
    .ok_or_else(|| Error::Decision(format!("unknown notebook {notebook}")))
}

/// The queries of a notebook named by id or name, in order (the built-in one included).
pub fn notebook_queries(
    conn: &Connection,
    notebook: &str,
) -> Result<(String, String, Vec<SavedQuery>)> {
    let (id, name) = resolve_notebook(conn, notebook)?;
    let qs = if id == BUILTIN_ID {
        builtin_queries()
    } else {
        case_queries(conn, &id)?
    };
    Ok((id, name, qs))
}

/// One query: `notebook` is an id or exact name (ignoring case), `query` a query id or a 1-based position.
pub fn find_query(conn: &Connection, notebook: &str, query: &str) -> Result<SavedQuery> {
    let (_, name, qs) = notebook_queries(conn, notebook)?;
    let pos: Option<u32> = query.parse().ok();
    qs.into_iter()
        .find(|q| q.summary.query_id == query || Some(q.summary.position) == pos)
        .ok_or_else(|| Error::Decision(format!("notebook {name} has no query {query}")))
}

fn new_id(parts: &[&str], actor: &Actor, ts: &DateTime<Utc>) -> String {
    let mut h = Sha256::new();
    for p in parts
        .iter()
        .copied()
        .chain([actor.as_str(), &ts.timestamp_micros().to_string()])
    {
        h.update(p.as_bytes());
        h.update([0x1f]);
    }
    hex::encode(h.finalize())[..16].to_string()
}

/// Refuses a write naming the built-in notebook: its id, its name, or a `builtin:` query id.
fn refuse_builtin(notebook_id: &str) -> Result<()> {
    if notebook_id.starts_with("builtin:") || reserved(notebook_id) {
        return Err(Error::Decision(
            "the built-in notebook cannot be changed".into(),
        ));
    }
    Ok(())
}

fn analyst_only(actor: &Actor, verb: &str) -> Result<()> {
    if !actor.is_analyst() {
        return Err(Error::Decision(format!(
            "only the analyst can {verb} a notebook"
        )));
    }
    Ok(())
}

/// Refuses a name that is empty, more than one line or a title too long, that is the built-in's, or that another
/// notebook (other than `except`) already has.
fn check_name(conn: &Connection, name: &str, except: Option<&str>) -> Result<()> {
    if name.trim().is_empty() || name.contains(['\n', '\r']) {
        return Err(Error::Decision(
            "a notebook name must be one line of text".into(),
        ));
    }
    crate::case::text::check_title(name)?;
    if reserved(name) {
        return Err(Error::Decision(format!(
            "the name {} is reserved: the built-in notebook cannot be changed",
            name.trim()
        )));
    }
    if name_taken(conn, name, except)? {
        return Err(Error::Decision(format!(
            "a notebook named {} already exists",
            name.trim()
        )));
    }
    Ok(())
}

pub(crate) fn name_taken(conn: &Connection, name: &str, except: Option<&str>) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM notebooks WHERE lower(name) = lower(?) AND notebook_id IS DISTINCT FROM ?",
        params![name.trim(), except],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

#[allow(clippy::too_many_arguments)]
fn audit_entry(
    conn: &Connection,
    ts: DateTime<Utc>,
    actor: &Actor,
    action: &str,
    object_type: &str,
    object_id: &str,
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<AuditEntry> {
    audit::append_at(
        conn,
        ts,
        actor.as_str(),
        actor.on_behalf_of(),
        action,
        object_type,
        object_id,
        before,
        after,
        None,
    )
}

/// Inserts a notebook row (no audit entry; the caller writes one).
pub(crate) fn insert_notebook(
    conn: &Connection,
    actor: &Actor,
    name: &str,
    ts: DateTime<Utc>,
) -> Result<String> {
    let id = new_id(&["notebook", name], actor, &ts);
    conn.execute(
        "INSERT INTO notebooks VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), ?)",
        params![
            id,
            name.trim(),
            actor.as_str(),
            audit::ts_text(&ts),
            actor.on_behalf_of()
        ],
    )?;
    Ok(id)
}

/// Inserts a query at the end of `notebook_id` (no audit entry); refuses past [`MAX_QUERIES`].
pub(crate) fn insert_query(
    conn: &Connection,
    actor: &Actor,
    notebook_id: &str,
    sql: &str,
    ts: DateTime<Utc>,
) -> Result<(String, u32)> {
    check_query_sql(sql)?;
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM notebook_queries WHERE notebook_id = ?",
        params![notebook_id],
        |r| r.get(0),
    )?;
    if n as usize >= MAX_QUERIES {
        return Err(Error::Decision(format!(
            "a notebook is limited to {MAX_QUERIES} queries"
        )));
    }
    let position = n as u32 + 1;
    let id = new_id(
        &["query", notebook_id, sql, &position.to_string()],
        actor,
        &ts,
    );
    conn.execute(
        "INSERT INTO notebook_queries VALUES (?, ?, ?, ?, ?, CAST(? AS TIMESTAMPTZ), ?)",
        params![
            id,
            notebook_id,
            position as i32,
            sql,
            actor.as_str(),
            audit::ts_text(&ts),
            actor.on_behalf_of()
        ],
    )?;
    Ok((id, position))
}

/// Creates an empty case notebook. Agents may.
pub fn create_notebook(
    conn: &Connection,
    actor: &Actor,
    name: &str,
) -> Result<(String, AuditEntry)> {
    in_tx(conn, |tx| {
        check_name(tx, name, None)?;
        let ts = audit::now();
        let id = insert_notebook(tx, actor, name, ts)?;
        let after = json!({ "name": name.trim() });
        let e = audit_entry(
            tx,
            ts,
            actor,
            "create_notebook",
            "notebook",
            &id,
            None,
            Some(&after),
        )?;
        Ok((id, e))
    })
}

/// Adds `sql` as the last query of a case notebook. Agents may.
pub fn add_query(
    conn: &Connection,
    actor: &Actor,
    notebook_id: &str,
    sql: &str,
) -> Result<(String, AuditEntry)> {
    refuse_builtin(notebook_id)?;
    check_query_sql(sql)?;
    in_tx(conn, |tx| {
        let (notebook_id, _) = resolve_notebook(tx, notebook_id)?;
        refuse_builtin(&notebook_id)?;
        let ts = audit::now();
        let (id, position) = insert_query(tx, actor, &notebook_id, sql, ts)?;
        let after = json!({ "notebook_id": notebook_id, "position": position, "sql": sql });
        let e = audit_entry(
            tx,
            ts,
            actor,
            "add_notebook_query",
            "notebook_query",
            &id,
            None,
            Some(&after),
        )?;
        Ok((id, e))
    })
}

fn notebook_name(conn: &Connection, notebook_id: &str) -> Result<String> {
    conn.query_row(
        "SELECT name FROM notebooks WHERE notebook_id = ?",
        params![notebook_id],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| Error::Decision(format!("unknown notebook {notebook_id}")))
}

/// Renames a case notebook (analyst only).
pub fn rename_notebook(
    conn: &Connection,
    actor: &Actor,
    notebook_id: &str,
    name: &str,
) -> Result<AuditEntry> {
    refuse_builtin(notebook_id)?;
    analyst_only(actor, "rename")?;
    in_tx(conn, |tx| {
        let old = notebook_name(tx, notebook_id)?;
        check_name(tx, name, Some(notebook_id))?;
        tx.execute(
            "UPDATE notebooks SET name = ? WHERE notebook_id = ?",
            params![name.trim(), notebook_id],
        )?;
        audit_entry(
            tx,
            audit::now(),
            actor,
            "rename_notebook",
            "notebook",
            notebook_id,
            Some(&json!({ "name": old })),
            Some(&json!({ "name": name.trim() })),
        )
    })
}

/// Deletes a case notebook and its queries (analyst only).
pub fn delete_notebook(conn: &Connection, actor: &Actor, notebook_id: &str) -> Result<AuditEntry> {
    refuse_builtin(notebook_id)?;
    analyst_only(actor, "delete")?;
    in_tx(conn, |tx| {
        let name = notebook_name(tx, notebook_id)?;
        let sqls: Vec<String> = case_queries(tx, notebook_id)?
            .into_iter()
            .map(|q| q.sql)
            .collect();
        tx.execute(
            "DELETE FROM notebook_queries WHERE notebook_id = ?",
            params![notebook_id],
        )?;
        tx.execute(
            "DELETE FROM notebooks WHERE notebook_id = ?",
            params![notebook_id],
        )?;
        audit_entry(
            tx,
            audit::now(),
            actor,
            "delete_notebook",
            "notebook",
            notebook_id,
            Some(&json!({ "name": name, "queries": sqls })),
            None,
        )
    })
}

/// `(notebook_id, position, sql)` of a case notebook query.
fn query_row(conn: &Connection, query_id: &str) -> Result<(String, u32, String)> {
    conn.query_row(
        "SELECT notebook_id, position, sql FROM notebook_queries WHERE query_id = ?",
        params![query_id],
        |r| Ok((r.get(0)?, r.get::<_, i32>(1)? as u32, r.get(2)?)),
    )
    .optional()?
    .ok_or_else(|| Error::Decision(format!("unknown notebook query {query_id}")))
}

/// Deletes a case notebook query (analyst only); the ones after it move up.
pub fn delete_query(conn: &Connection, actor: &Actor, query_id: &str) -> Result<AuditEntry> {
    refuse_builtin(query_id)?;
    analyst_only(actor, "delete from")?;
    in_tx(conn, |tx| {
        let (notebook_id, position, sql) = query_row(tx, query_id)?;
        tx.execute(
            "DELETE FROM notebook_queries WHERE query_id = ?",
            params![query_id],
        )?;
        tx.execute(
            "UPDATE notebook_queries SET position = position - 1 WHERE notebook_id = ? AND position > ?",
            params![notebook_id, position as i32],
        )?;
        audit_entry(
            tx,
            audit::now(),
            actor,
            "delete_notebook_query",
            "notebook_query",
            query_id,
            Some(&json!({ "notebook_id": notebook_id, "position": position, "sql": sql })),
            None,
        )
    })
}

/// Moves a case notebook query to `position` (1-based, clamped to the notebook; analyst only).
pub fn move_query(
    conn: &Connection,
    actor: &Actor,
    query_id: &str,
    position: u32,
) -> Result<AuditEntry> {
    refuse_builtin(query_id)?;
    analyst_only(actor, "reorder")?;
    in_tx(conn, |tx| {
        let (notebook_id, from, _) = query_row(tx, query_id)?;
        let mut ids: Vec<String> = case_queries(tx, &notebook_id)?
            .into_iter()
            .map(|q| q.summary.query_id)
            .collect();
        let to = position.clamp(1, ids.len() as u32);
        let id = ids.remove(from as usize - 1);
        ids.insert(to as usize - 1, id);
        for (i, id) in ids.iter().enumerate() {
            tx.execute(
                "UPDATE notebook_queries SET position = ? WHERE query_id = ?",
                params![i as i32 + 1, id],
            )?;
        }
        audit_entry(
            tx,
            audit::now(),
            actor,
            "move_notebook_query",
            "notebook_query",
            query_id,
            Some(&json!({ "notebook_id": notebook_id, "position": from })),
            Some(&json!({ "notebook_id": notebook_id, "position": to })),
        )
    })
}

/// The largest notebook file an import reads.
pub const MAX_IMPORT_BYTES: usize = 4 * 1024 * 1024;

/// A notebook (the built-in one included) as an export file's text.
pub fn export_text(conn: &Connection, notebook: &str, version: &str) -> Result<String> {
    let (_, name, qs) = notebook_queries(conn, notebook)?;
    let sqls: Vec<&str> = qs.iter().map(|q| q.sql.as_str()).collect();
    Ok(super::file::write_file(
        &name,
        version,
        &audit::ts_text(&audit::now()),
        &sqls,
    ))
}

/// The name an import takes: the file's, `Built-in (copy)` for the built-in's (`builtin (copy)` for a file named by
/// its id), then ` (2)`, ` (3)`... until free.
fn import_name(conn: &Connection, name: &str) -> Result<String> {
    let base = if name.trim().eq_ignore_ascii_case(BUILTIN_NAME) {
        format!("{BUILTIN_NAME} (copy)")
    } else if reserved(name) {
        format!("{} (copy)", name.trim())
    } else {
        name.trim().to_string()
    };
    // A suffix never pushes the name past the title limit: the base gives way instead.
    let with = |suffix: &str| -> String {
        let room = crate::case::text::MAX_TITLE_CHARS - suffix.chars().count();
        let cut: String = base.chars().take(room).collect();
        format!("{}{suffix}", cut.trim_end())
    };
    let mut candidate = with("");
    let mut n = 2;
    while name_taken(conn, &candidate, None)? {
        candidate = with(&format!(" ({n})"));
        n += 1;
    }
    Ok(candidate)
}

/// Imports a notebook file as a new case notebook (never merged into another), all or nothing. Agents may.
pub fn import_text(conn: &Connection, actor: &Actor, text: &str) -> Result<(String, AuditEntry)> {
    if text.len() > MAX_IMPORT_BYTES {
        return Err(Error::Decision("an import file is limited to 4 MiB".into()));
    }
    let file = super::file::parse_file(text)?;
    in_tx(conn, |tx| {
        let name = import_name(tx, &file.name)?;
        check_name(tx, &name, None)?;
        let ts = audit::now();
        let id = insert_notebook(tx, actor, &name, ts)?;
        for sql in &file.queries {
            insert_query(tx, actor, &id, sql, ts)?;
        }
        let after = json!({ "name": name, "queries": file.queries.len(), "file_name": file.name });
        let e = audit_entry(
            tx,
            ts,
            actor,
            "import_notebook",
            "notebook",
            &id,
            None,
            Some(&after),
        )?;
        Ok((id, e))
    })
}

/// Adds `sql` to the case notebook named `notebook` (id or name), creating it first when `create` and there is none:
/// one transaction, so a refused query leaves no new notebook behind. `(notebook_id, query_id, the query's entry)`.
pub fn add_query_creating(
    conn: &Connection,
    actor: &Actor,
    notebook: &str,
    sql: &str,
    create: bool,
) -> Result<(String, String, AuditEntry)> {
    refuse_builtin(notebook)?;
    check_query_sql(sql)?;
    in_tx(conn, |tx| {
        let ts = audit::now();
        let notebook_id = match resolve_notebook(tx, notebook) {
            Ok((id, _)) => id,
            Err(_) if create => {
                check_name(tx, notebook, None)?;
                let id = insert_notebook(tx, actor, notebook, ts)?;
                let after = json!({ "name": notebook.trim() });
                audit_entry(
                    tx,
                    ts,
                    actor,
                    "create_notebook",
                    "notebook",
                    &id,
                    None,
                    Some(&after),
                )?;
                id
            }
            Err(e) => return Err(e),
        };
        refuse_builtin(&notebook_id)?;
        let (id, position) = insert_query(tx, actor, &notebook_id, sql, ts)?;
        let after = json!({ "notebook_id": notebook_id, "position": position, "sql": sql });
        let e = audit_entry(
            tx,
            ts,
            actor,
            "add_notebook_query",
            "notebook_query",
            &id,
            None,
            Some(&after),
        )?;
        Ok((notebook_id, id, e))
    })
}

/// Creates a case notebook named `name` holding `sql` as its first query, in one transaction: a refused query or name
/// leaves nothing behind. `(notebook_id, query_id, the query's entry)`.
pub fn create_notebook_with_query(
    conn: &Connection,
    actor: &Actor,
    name: &str,
    sql: &str,
) -> Result<(String, String, AuditEntry)> {
    check_query_sql(sql)?;
    in_tx(conn, |tx| {
        check_name(tx, name, None)?;
        let ts = audit::now();
        let notebook_id = insert_notebook(tx, actor, name, ts)?;
        let after = json!({ "name": name.trim() });
        audit_entry(
            tx,
            ts,
            actor,
            "create_notebook",
            "notebook",
            &notebook_id,
            None,
            Some(&after),
        )?;
        let (id, position) = insert_query(tx, actor, &notebook_id, sql, ts)?;
        let after = json!({ "notebook_id": notebook_id, "position": position, "sql": sql });
        let e = audit_entry(
            tx,
            ts,
            actor,
            "add_notebook_query",
            "notebook_query",
            &id,
            None,
            Some(&after),
        )?;
        Ok((notebook_id, id, e))
    })
}
