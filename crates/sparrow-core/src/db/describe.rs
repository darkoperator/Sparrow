//! Self-description of the case database (tables, columns, COMMENT ON text) for agents and UIs.

use crate::{Case, Result};
use duckdb::params;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TableInfo {
    pub table: String,
    pub comment: Option<String>,
    /// "table" or "view".
    pub kind: String,
    pub columns: Vec<ColumnInfo>,
}

pub fn describe(case: &Case, table: Option<&str>) -> Result<Vec<TableInfo>> {
    let mut stmt = case.conn().prepare(
        "WITH objs AS (
             SELECT database_name, schema_name, table_name AS name, comment, 'table' AS kind FROM duckdb_tables()
             UNION ALL
             SELECT database_name, schema_name, view_name, comment, 'view' FROM duckdb_views() WHERE NOT internal
         )
         SELECT o.name, o.comment, o.kind, c.column_name, c.data_type, c.comment
         FROM objs o
         JOIN duckdb_columns() c ON c.database_name = o.database_name AND c.schema_name = o.schema_name
                                AND c.table_name = o.name
         WHERE o.schema_name = 'main' AND o.database_name = current_database()
               AND (CAST(? AS VARCHAR) IS NULL OR o.name = ?)
         ORDER BY o.name, c.column_index",
    )?;
    let rows = stmt.query_map(params![table, table], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<String>>(5)?,
        ))
    })?;
    let mut out: Vec<TableInfo> = Vec::new();
    for row in rows {
        let (t, table_comment, kind, name, data_type, comment) = row?;
        if out.last().is_none_or(|x| x.table != t) {
            out.push(TableInfo {
                table: t,
                comment: table_comment,
                kind,
                columns: Vec::new(),
            });
        }
        out.last_mut()
            .expect("just pushed")
            .columns
            .push(ColumnInfo {
                name,
                data_type,
                comment,
            });
    }
    Ok(out)
}
