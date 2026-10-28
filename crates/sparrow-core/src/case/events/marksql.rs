//! SQL over `events e` for the marks of `case::marks`: whether a row is flagged (by its own flag or by a standing
//! value flag), by whom, and whether an agent's mark on it is still waiting for review. Only constants are formatted
//! into the SQL; flag values are joined from `value_flags`, never inlined.
//!
//! A value flag matches a row when the row's column equals the flag's value and the flag's scope, if it has one,
//! matches the row under the same entity rule as an entity tab (`filter::entity_predicate`). The match is one
//! `EXISTS` per (kind, column) so each is an equality join the database can hash.

use super::filter::{entity_columns, entity_predicate};

/// The standing-flag kinds, in the order of `flag_value_kind`.
pub(crate) const VALUE_KINDS: [&str; 6] =
    ["ip", "ip_prefix", "account", "asn", "device", "session"];

/// The `events` columns a value flag of `kind` is compared with.
pub(crate) fn value_columns(kind: &str) -> &'static [&'static str] {
    match kind {
        "ip_prefix" => &["e.ip_prefix"],
        "asn" => &["CAST(e.asn AS VARCHAR)"],
        other => entity_columns(other),
    }
}

/// `vf` (a `value_flags` row) covers the entity named by its scope, or has none.
fn scope_sql() -> String {
    let kinds = ["account", "ip", "device", "session"].map(|k| {
        format!(
            "(vf.scope_kind = '{k}' AND {})",
            entity_predicate(k, "vf.scope_value")
        )
    });
    format!("(vf.scope_kind IS NULL OR {})", kinds.join(" OR "))
}

/// The columns of an `events` row that a flag is matched on, for a base relation.
pub(crate) const BASE_COLUMNS: &str = "e.source_table, e.record_key, e.ip, e.ip_prefix, e.actor_upn, e.owner_upn, \
     e.asn, e.device_id, e.device_object_id, e.entra_session_id";

/// A relation `(source_table, record_key, mal, sus, mp, mc, sp, sc, agent_any, agent_pend)` with one row per row of
/// `base` that has a flag: whether its effective flag set holds a malicious / suspicious flag, whether a flag at that
/// level is still pending (`mp`, `sp`) or confirmed (`mc`, `sc`), and whether an agent made one (`agent_any`) that is
/// pending (`agent_pend`). Built once per query: the row's own flags, then each value-flag kind hash-joined to `base`
/// (a relation named `base` with [`BASE_COLUMNS`]) on its column, with the flag's scope. `restrict` limits the row
/// flags to the keys of `base` (leave it off when `base` is every event).
pub(crate) fn flagged(base: &str, restrict: bool) -> String {
    let own = if restrict {
        format!(
            " WHERE (ef.source_table, ef.record_key) IN (SELECT source_table, record_key FROM {base})"
        )
    } else {
        String::new()
    };
    let mut parts = vec![format!(
        "SELECT ef.source_table, ef.record_key, CAST(ef.level AS VARCHAR) AS level, \
         ef.review_state = 'pending_review' AS pend, ef.decided_by LIKE 'agent:%' AS agent FROM event_flags ef{own}"
    )];
    let scope = scope_sql();
    for kind in VALUE_KINDS {
        for col in value_columns(kind) {
            parts.push(format!(
                "SELECT e.source_table, e.record_key, CAST(vf.level AS VARCHAR), \
                 vf.review_state = 'pending_review', vf.decided_by LIKE 'agent:%' \
                 FROM {base} e JOIN value_flags vf ON vf.removed_at IS NULL AND vf.kind = '{kind}' \
                 AND vf.value = {col} AND {scope}"
            ));
        }
    }
    format!(
        "SELECT source_table, record_key, \
         bool_or(level = 'malicious') AS mal, bool_or(level = 'suspicious') AS sus, \
         bool_or(level = 'malicious' AND pend) AS mp, bool_or(level = 'malicious' AND NOT pend) AS mc, \
         bool_or(level = 'suspicious' AND pend) AS sp, bool_or(level = 'suspicious' AND NOT pend) AS sc, \
         bool_or(agent) AS agent_any, bool_or(agent AND pend) AS agent_pend \
         FROM ({}) GROUP BY 1, 2",
        parts.join(" UNION ALL ")
    )
}

/// The filter on the flag toggle or the agent filter as a clause over `events e`, given the clauses of everything else
/// the query selects (`base_where`, with `WHERE` or empty; its parameters are bound again by the caller).
/// `condition` is over the columns of [`flagged`].
pub(crate) fn flagged_clause(base_where: &str, restrict: bool, condition: &str) -> String {
    format!(
        "(e.source_table, e.record_key) IN (WITH base AS (SELECT {BASE_COLUMNS} FROM events e{base_where}) \
         SELECT source_table, record_key FROM ({}) WHERE {condition})",
        flagged("base", restrict)
    )
}

/// Keys of rows tagged by an agent (pending ones only with `pending_only`), as a clause over `events e`.
pub(crate) fn agent_tag_clause(pending_only: bool) -> String {
    format!(
        "(e.source_table, e.record_key) IN (SELECT source_table, record_key FROM event_tags \
         WHERE decided_by LIKE 'agent:%'{})",
        if pending_only {
            " AND review_state = 'pending_review'"
        } else {
            ""
        }
    )
}

/// Select expressions for the effective flag text and whether it is only an unconfirmed agent's, over the alias `fl`
/// of [`flagged`] left-joined to the rows.
pub(crate) const FLAG_COLUMNS: &str = "CASE WHEN fl.mal THEN 'malicious' WHEN fl.sus THEN 'suspicious' END, \
     CASE WHEN fl.mal THEN fl.mp AND NOT fl.mc WHEN fl.sus THEN fl.sp AND NOT fl.sc ELSE false END";

/// Holds when the standing flag `vf` matches row `e`: its value equals the row's column and its scope covers the row.
/// For one row at a time (the detail panel); the page, filter and summary queries use the relation of [`flagged`].
pub(crate) fn value_flag_matches() -> String {
    let mut any = Vec::new();
    for kind in VALUE_KINDS {
        for col in value_columns(kind) {
            any.push(format!("(vf.kind = '{kind}' AND vf.value = {col})"));
        }
    }
    format!("({}) AND {}", any.join(" OR "), scope_sql())
}
