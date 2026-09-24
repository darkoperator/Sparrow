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
    pub columns: Vec<ColumnInfo>,
}

pub fn describe(case: &Case, table: Option<&str>) -> Result<Vec<TableInfo>> {
    let mut stmt = case.conn().prepare(
        "SELECT t.table_name, t.comment, c.column_name, c.data_type, c.comment
         FROM duckdb_tables() t
         JOIN duckdb_columns() c ON c.database_name = t.database_name AND c.schema_name = t.schema_name
                                AND c.table_name = t.table_name
         WHERE t.schema_name = 'main' AND t.database_name = current_database()
               AND (CAST(? AS VARCHAR) IS NULL OR t.table_name = ?)
         ORDER BY t.table_name, c.column_index",
    )?;
    let rows = stmt.query_map(params![table, table], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut out: Vec<TableInfo> = Vec::new();
    for row in rows {
        let (t, table_comment, name, data_type, comment) = row?;
        if out.last().is_none_or(|x| x.table != t) {
            out.push(TableInfo {
                table: t,
                comment: table_comment,
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
