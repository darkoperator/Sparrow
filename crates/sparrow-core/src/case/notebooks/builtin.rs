//! The built-in notebook: triage queries shipped with Sparrow, embedded at build time. Never stored in a case and
//! never written, so every case shows the current release's queries.

/// One built-in query: a stable id (`builtin:<slug>`) and its text.
pub struct BuiltinQuery {
    pub id: &'static str,
    pub sql: &'static str,
}

/// The built-in queries, in notebook order (position = index + 1).
pub fn queries() -> &'static [BuiltinQuery] {
    QUERIES
}

const QUERIES: &[BuiltinQuery] = &[
    BuiltinQuery {
        id: "builtin:signins-by-country",
        sql: include_str!("builtin/01-signins-by-country.sql"),
    },
    BuiltinQuery {
        id: "builtin:ips-shared-by-accounts",
        sql: include_str!("builtin/02-ips-shared-by-accounts.sql"),
    },
    BuiltinQuery {
        id: "builtin:signin-results-per-day",
        sql: include_str!("builtin/03-signin-results-per-day.sql"),
    },
    BuiltinQuery {
        id: "builtin:hosting-signins",
        sql: include_str!("builtin/04-hosting-signins.sql"),
    },
    BuiltinQuery {
        id: "builtin:first-agent-or-device",
        sql: include_str!("builtin/05-first-agent-or-device.sql"),
    },
    BuiltinQuery {
        id: "builtin:mail-read-per-mailbox",
        sql: include_str!("builtin/06-mail-read-per-mailbox.sql"),
    },
    BuiltinQuery {
        id: "builtin:operations-by-workload",
        sql: include_str!("builtin/07-operations-by-workload.sql"),
    },
    BuiltinQuery {
        id: "builtin:forwarding-inbox-rules",
        sql: include_str!("builtin/08-forwarding-inbox-rules.sql"),
    },
    BuiltinQuery {
        id: "builtin:risky-oauth-grants",
        sql: include_str!("builtin/09-risky-oauth-grants.sql"),
    },
    BuiltinQuery {
        id: "builtin:new-mfa-creds-roles",
        sql: include_str!("builtin/10-new-mfa-creds-roles.sql"),
    },
    BuiltinQuery {
        id: "builtin:malicious-values",
        sql: include_str!("builtin/11-malicious-values.sql"),
    },
    BuiltinQuery {
        id: "builtin:what-an-ip-touched",
        sql: include_str!("builtin/12-what-an-ip-touched.sql"),
    },
];
