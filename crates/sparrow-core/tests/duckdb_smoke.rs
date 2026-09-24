use duckdb::{Connection, params};

#[test]
fn bundled_duckdb_supports_timestamptz_json_and_map() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE t (ts TIMESTAMPTZ, doc JSON, params MAP(VARCHAR, VARCHAR));")
        .unwrap();
    conn.execute(
        "INSERT INTO t VALUES (CAST(? AS TIMESTAMPTZ), CAST(? AS JSON), MAP {'ForwardTo': 'x@evil.example'})",
        params!["2025-01-15T15:04:05+00:00", r#"{"Operation":"New-InboxRule"}"#],
    )
    .unwrap();
    let (ts, op, fwd): (String, String, String) = conn
        .query_row(
            "SELECT CAST(ts AS VARCHAR), doc->>'$.Operation', params['ForwardTo'] FROM t",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(ts, "2025-01-15 15:04:05+00");
    assert_eq!(op, "New-InboxRule");
    assert_eq!(fwd, "x@evil.example");
}
