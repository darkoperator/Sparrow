//! Forward-only schema migrations for case databases.

use crate::{Error, Result};
use duckdb::Connection;

pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "core_provenance",
        sql: include_str!("../../migrations/0001_core_provenance.sql"),
    },
    Migration {
        version: 2,
        name: "source_file_subject",
        sql: include_str!("../../migrations/0002_source_file_subject.sql"),
    },
    Migration {
        version: 3,
        name: "ual_evidence",
        sql: include_str!("../../migrations/0003_ual_evidence.sql"),
    },
    Migration {
        version: 4,
        name: "state_tables",
        sql: include_str!("../../migrations/0004_state_tables.sql"),
    },
    Migration {
        version: 5,
        name: "event_tables",
        sql: include_str!("../../migrations/0005_event_tables.sql"),
    },
    Migration {
        version: 6,
        name: "invictus",
        sql: include_str!("../../migrations/0006_invictus.sql"),
    },
    Migration {
        version: 7,
        name: "profile",
        sql: include_str!("../../migrations/0007_profile.sql"),
    },
    Migration {
        version: 8,
        name: "synth_parsers",
        sql: include_str!("../../migrations/0008_synth_parsers.sql"),
    },
    Migration {
        version: 9,
        name: "detection",
        sql: include_str!("../../migrations/0009_detection.sql"),
    },
    Migration {
        version: 10,
        name: "spray_sources",
        sql: include_str!("../../migrations/0010_spray_sources.sql"),
    },
    Migration {
        version: 11,
        name: "cloud_services",
        sql: include_str!("../../migrations/0011_cloud_services.sql"),
    },
    Migration {
        version: 12,
        name: "cloud_services_established",
        sql: include_str!("../../migrations/0012_cloud_services_established.sql"),
    },
    Migration {
        version: 13,
        name: "spray_failed_only_cloud_asn",
        sql: include_str!("../../migrations/0013_spray_failed_only_cloud_asn.sql"),
    },
    Migration {
        version: 14,
        name: "cloud_services_whole_case",
        sql: include_str!("../../migrations/0014_cloud_services_whole_case.sql"),
    },
    Migration {
        version: 15,
        name: "spray_takeover_resistant",
        sql: include_str!("../../migrations/0015_spray_takeover_resistant.sql"),
    },
    Migration {
        version: 16,
        name: "analyst",
        sql: include_str!("../../migrations/0016_analyst.sql"),
    },
    Migration {
        version: 17,
        name: "indicator_decisions",
        sql: include_str!("../../migrations/0017_indicator_decisions.sql"),
    },
    Migration {
        version: 18,
        name: "derived_relation_comments",
        sql: include_str!("../../migrations/0018_derived_relation_comments.sql"),
    },
    Migration {
        version: 19,
        name: "schema_migrations_comments",
        sql: include_str!("../../migrations/0019_schema_migrations_comments.sql"),
    },
    Migration {
        version: 20,
        name: "enrichment",
        sql: include_str!("../../migrations/0020_enrichment.sql"),
    },
    Migration {
        version: 21,
        name: "share",
        sql: include_str!("../../migrations/0021_share.sql"),
    },
    Migration {
        version: 22,
        name: "directory_audits_completeness",
        sql: include_str!("../../migrations/0022_directory_audits_completeness.sql"),
    },
    Migration {
        version: 23,
        name: "account_signin_window",
        sql: include_str!("../../migrations/0023_account_signin_window.sql"),
    },
    Migration {
        version: 24,
        name: "message_trace_events",
        sql: include_str!("../../migrations/0024_message_trace_events.sql"),
    },
    Migration {
        version: 25,
        name: "events",
        sql: include_str!("../../migrations/0025_events.sql"),
    },
    Migration {
        version: 26,
        name: "marks",
        sql: include_str!("../../migrations/0026_marks.sql"),
    },
    Migration {
        version: 27,
        name: "timeline_group",
        sql: include_str!("../../migrations/0027_timeline_group.sql"),
    },
];

/// The migration that adds the Phase 7 analyst tables and the audit trail.
pub const ANALYST_VERSION: u32 = 16;

pub fn latest_version() -> u32 {
    MIGRATIONS.last().map(|m| m.version).unwrap_or(0)
}

pub fn current_version(conn: &Connection) -> Result<u32> {
    let exists: bool = conn.query_row(
        "SELECT count(*) > 0 FROM duckdb_tables() WHERE schema_name = 'main' AND table_name = 'schema_migrations'",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        return Ok(0);
    }
    let v: Option<i64> = conn.query_row(
        "SELECT CAST(max(version) AS BIGINT) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    Ok(v.unwrap_or(0) as u32)
}

/// Apply pending migrations. Fails if the database is newer than this build.
pub fn migrate(conn: &Connection) -> Result<u32> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name VARCHAR NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT current_timestamp
        );",
    )?;
    let current = current_version(conn)?;
    let latest = latest_version();
    if current > latest {
        return Err(Error::SchemaTooNew {
            db: current,
            supported: latest,
        });
    }
    for m in MIGRATIONS.iter().filter(|m| m.version > current) {
        // An existing case owes a post-migration step (`super::POST_MIGRATION_PENDING`): the marker commits with
        // every migration that has `case_meta` (so with the last one), and an older marker is kept, so a run that
        // stopped part-way still names the version the case had before its first migration.
        let marker = if current > 0 && m.version >= ANALYST_VERSION {
            format!(
                "INSERT INTO case_meta (key, value) VALUES ('{}', '{current}') ON CONFLICT DO NOTHING;\n",
                super::POST_MIGRATION_PENDING
            )
        } else {
            String::new()
        };
        let batch = format!(
            "BEGIN TRANSACTION;\n{}\n{marker}INSERT INTO schema_migrations (version, name) VALUES ({}, '{}');\nCOMMIT;",
            m.sql, m.version, m.name
        );
        if let Err(source) = conn.execute_batch(&batch) {
            let _ = conn.execute_batch("ROLLBACK;");
            return Err(Error::Migration {
                version: m.version,
                source,
            });
        }
    }
    Ok(latest)
}

/// Check a database opened read-only is exactly at this build's schema version.
pub fn check_readable(conn: &Connection) -> Result<u32> {
    let current = current_version(conn)?;
    let latest = latest_version();
    if current > latest {
        return Err(Error::SchemaTooNew {
            db: current,
            supported: latest,
        });
    }
    if current < latest {
        return Err(Error::SchemaOutdated {
            db: current,
            supported: latest,
        });
    }
    Ok(current)
}
