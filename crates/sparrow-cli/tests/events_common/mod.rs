//! Shared by the events and mark tests: the binary runner and a small synthetic case.

use assert_cmd::Command;
use serde_json::Value;
use sparrow_core::Case;
use std::path::Path;

pub struct Run {
    pub code: i32,
    pub out: String,
    pub err: String,
}

pub fn run(args: &[&str]) -> Run {
    let out = Command::cargo_bin("sparrow")
        .unwrap()
        .args(args)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

pub const S1: &str = "4f1c8d3e-1111-4222-8333-444455559a2e";
pub const S2: &str = "7a7a7a7a-2222-4333-8444-555566660b0b";
pub const DEVICE: &str = "d3d3d3d3-0000-4000-8000-00000000abcd";

pub fn build(path: &Path) {
    let case = Case::create_or_open(path).unwrap();
    let c = case.conn();
    for (table, key, source, at, op, actor, ip, prefix, device, name, session) in [
        (
            "ual_events",
            "u1",
            "ual",
            "2026-09-01 10:00:00",
            "Send",
            "jdoe@contoso.example",
            "203.0.113.45",
            "203.0.113.0/24",
            None,
            None,
            Some(S1),
        ),
        (
            "ual_events",
            "u2",
            "ual",
            "2026-09-01 10:05:00",
            "MailItemsAccessed",
            "jdoe@contoso.example",
            "203.0.113.45",
            "203.0.113.0/24",
            None,
            None,
            Some(S1),
        ),
        (
            "signins",
            "s1",
            "signin_interactive",
            "2026-09-01 10:10:00",
            "UserLoggedIn",
            "jdoe@contoso.example",
            "198.51.100.7",
            "198.51.100.0/24",
            Some(DEVICE),
            Some("JDOE-LAPTOP"),
            Some(S2),
        ),
        (
            "ual_events",
            "x1",
            "ual",
            "2026-09-01 11:00:00",
            "Send",
            "other@contoso.example",
            "192.0.2.9",
            "192.0.2.0/24",
            None,
            None,
            None,
        ),
    ] {
        c.execute(
            "INSERT INTO events (source_table, record_key, source, event_time, category, tenant_key, actor_upn, \
             operation, ip, ip_prefix, device_id, device_name, entra_session_id) \
             VALUES (?, ?, ?, CAST(? AS TIMESTAMPTZ), 'other', 'contoso', ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                table,
                key,
                source,
                format!("{at}+00"),
                actor,
                op,
                ip,
                prefix,
                device,
                name,
                session
            ],
        )
        .unwrap();
    }
}

pub fn json(args: &[&str]) -> Value {
    let r = run(args);
    assert_eq!(r.code, 0, "{args:?}: {}", r.err);
    serde_json::from_str(&r.out).unwrap_or_else(|e| panic!("{args:?}: {e}\n{}", r.out))
}
