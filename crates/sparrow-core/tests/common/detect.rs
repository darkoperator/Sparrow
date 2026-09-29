//! Helpers for the detection tests: build a small in-memory case by SQL, and run a compiled
//! rule the way the runner does (named parameters, the tenant bound last).

#![allow(dead_code)]

use serde_json::Value;
use sparrow_core::Case;
use sparrow_core::detect::compile::Compiled;
use sparrow_core::detect::rule_conn::with_rule_conn;
use sparrow_core::detect::test::insert_record;
use std::collections::BTreeMap;

pub use sparrow_core::detect::test::ensure_collection as collection_of_result;

/// The `collection_id` of `tenant`'s (single) test collection, created on first use.
pub fn collection_of(case: &Case, tenant: &str) -> i64 {
    collection_of_result(case, tenant).unwrap()
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Insert one row into `table` for `tenant` through the shared inserter
/// (`sparrow_core::detect::test::insert_record`); generated ids are unique per call.
pub fn insert_row(case: &Case, table: &str, tenant: &str, fields: Value) {
    let seed = format!(
        "row-{}",
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    insert_record(case, tenant, table, &fields, &seed)
        .unwrap_or_else(|e| panic!("insert into {table}: {e}"));
}

pub fn insert_ual(case: &Case, tenant: &str, fields: Value) {
    insert_row(case, "ual_events", tenant, fields);
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    pub record_key: String,
    pub source_table: String,
    pub event_epoch: Option<i64>,
    pub actor_upn: Option<String>,
    pub ip: Option<String>,
}

/// Run a compiled rule for `tenant` through the production path (`with_rule_conn`: a separate,
/// locked, tenant-scoped read-only instance). The case's writer connection is released while it
/// runs and comes back afterwards. `iocs` binds the `ioc_<type>` parameters.
pub fn run(
    case: &mut Case,
    compiled: &Compiled,
    tenant: &str,
    iocs: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<Hit>, sparrow_core::Error> {
    with_rule_conn(case, |rc| {
        rc.scope(tenant)?;
        let hits = rc.run(compiled, iocs)?;
        let mut out: Vec<Hit> = hits
            .into_iter()
            .map(|h| Hit {
                record_key: h.record_key,
                source_table: h.source_table,
                event_epoch: h.event_time.map(|t| t.timestamp()),
                actor_upn: h.actor_upn,
                ip: h.ip,
            })
            .collect();
        out.sort_by(|a, b| {
            (a.event_epoch, &a.record_key, &a.source_table).cmp(&(
                b.event_epoch,
                &b.record_key,
                &b.source_table,
            ))
        });
        Ok(out)
    })
}
