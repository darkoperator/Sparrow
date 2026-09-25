//! Column specs of the state tables (migration 0004), the Phase 2c event tables (migration
//! 0005) and the Phase 3 tables (migration 0006), used by the staged loader (`ingest::state`).
//! `columns` lists everything between `collected_at` and `raw`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// Latest wins (spec 5.2), per column: a copy writes each column it provides unless a
    /// newer collection already wrote that column (`column_collections`), so the final
    /// values do not depend on the ingest order.
    LatestWins,
    /// The first copy wins; later copies only add sightings.
    InsertOnly,
    /// Evidence tables: the first copy of a record wins; a later copy adds a sighting and fills
    /// only the columns the stored row still has as NULL (never overwrites).
    FillMissing,
}

#[derive(Debug, Clone, Copy)]
pub struct Col {
    pub name: &'static str,
    /// DuckDB type used to cast the staged text (`VARCHAR[]`, `STRUCT(...)`, enum names, ...).
    pub sql_type: &'static str,
    /// Keep the stored value when the incoming one is NULL (identity-like columns that
    /// some sources of the same entity lack).
    pub keep_when_null: bool,
}

pub const fn col(name: &'static str, sql_type: &'static str) -> Col {
    Col {
        name,
        sql_type,
        keep_when_null: false,
    }
}

pub const fn keep(name: &'static str, sql_type: &'static str) -> Col {
    Col {
        name,
        sql_type,
        keep_when_null: true,
    }
}

#[derive(Debug)]
pub struct TableSpec {
    pub table: &'static str,
    pub mode: LoadMode,
    pub columns: &'static [Col],
}

impl TableSpec {
    pub fn col(&self, name: &str) -> Option<&Col> {
        self.columns.iter().find(|c| c.name == name)
    }
}

const V: &str = "VARCHAR";
const B: &str = "BOOLEAN";
const T: &str = "TIMESTAMPTZ";
const L: &str = "VARCHAR[]";
const J: &str = "JSON";
const I: &str = "INTEGER";
const BI: &str = "BIGINT";
const M: &str = "MAP(VARCHAR, VARCHAR)";

pub static USERS: TableSpec = TableSpec {
    table: "users",
    mode: LoadMode::LatestWins,
    columns: &[
        col("user_id", V),
        col("upn", V),
        col("display_name", V),
        col("mail", V),
        col("account_enabled", B),
        col("created", T),
        col("deleted", T),
        col("last_password_change", T),
        col("user_type", V),
        col("on_prem_sync", B),
        col("state_changed", T),
        col("last_signin", T),
        col("department", V),
        col("job_title", V),
    ],
};

pub static ROLE_ASSIGNMENTS: TableSpec = TableSpec {
    table: "role_assignments",
    mode: LoadMode::LatestWins,
    columns: &[
        col("source", "role_source"),
        col("role_name", V),
        col("principal_upn", V),
        col("principal_id", V),
        col("principal_name", V),
        col("principal_type", V),
        col("assignment_type", V),
        col("assignment_name", V),
        col("enabled", B),
        col("start_time", T),
        col("end_time", T),
    ],
};

pub static OAUTH_GRANTS: TableSpec = TableSpec {
    table: "oauth_grants",
    mode: LoadMode::LatestWins,
    columns: &[
        col("permission_type", "permission_type"),
        col("client_id", V),
        col("client_name", V),
        col("resource_id", V),
        col("resource_name", V),
        col("permission", V),
        col("consent_type", V),
        col("principal_id", V),
        col("principal_name", V),
        col("principal_upn", V),
        col("risk_category", V),
        col("publisher", V),
        col("verified_publisher", V),
        col("created", T),
        col("sign_in_audience", V),
    ],
};

pub static APP_CREDENTIALS: TableSpec = TableSpec {
    table: "app_credentials",
    mode: LoadMode::LatestWins,
    columns: &[
        col("app_object_id", V),
        col("app_name", V),
        col("key_id", V),
        col("cred_type", "credential_type"),
        col("key_type", V),
        col("start_time", T),
        col("end_time", T),
        col("owner", "credential_owner"),
    ],
};

pub static INBOX_RULES: TableSpec = TableSpec {
    table: "inbox_rules",
    mode: LoadMode::LatestWins,
    columns: &[
        col("kind", "rule_kind"),
        col("mailbox", V),
        keep("mailbox_upn", V),
        col("rule_identity", V),
        col("name", V),
        col("enabled", B),
        col("in_error", B),
        col("priority", I),
        col("forward_to", L),
        col("forward_as_attachment_to", L),
        col("redirect_to", L),
        col("delete_message", B),
        col("soft_delete", B),
        col("move_to_folder", V),
        col("copy_to_folder", V),
        col("mark_as_read", B),
        col("stop_processing", B),
        col("from_addresses", L),
        col("subject_contains", L),
        col("body_contains", L),
        col("subject_or_body_contains", L),
        col("has_attachment", B),
        col("source_folder", V),
        col("description", V),
    ],
};

pub static MAILBOXES: TableSpec = TableSpec {
    table: "mailboxes",
    mode: LoadMode::LatestWins,
    columns: &[
        col("upn", V),
        keep("display_name", V),
        keep("primary_smtp_address", V),
        keep("object_id", V),
        keep("mailbox_guid", V),
        keep("recipient_type", V),
        col("forwarding_smtp_address", V),
        col("forwarding_address", V),
        col("deliver_and_forward", B),
        col("audit_enabled", B),
        col("audit_owner", L),
        col("audit_delegate", L),
        col("audit_admin", L),
        col("pop_enabled", B),
        col("imap_enabled", B),
        col("ews_enabled", B),
        col("owa_enabled", B),
        col("activesync_enabled", B),
        col("mapi_enabled", B),
        col("auto_reply_state", V),
        col("auto_reply_start", T),
        col("auto_reply_end", T),
        col("auto_reply_external_audience", V),
        col("auto_reply_message", V),
        col("auto_reply_external_message", V),
        col("when_changed", T),
        col("audit_bypass_enabled", B),
        col("default_audit_set", L),
        col("effective_audit_state", V),
    ],
};

pub static AUDIT_CONFIG: TableSpec = TableSpec {
    table: "audit_config",
    mode: LoadMode::LatestWins,
    columns: &[
        col("admin_audit_log_enabled", B),
        col("unified_audit_log_ingestion_enabled", B),
        col("admin_audit_log_age_limit", V),
        col("log_level", V),
        col("audit_disabled", B),
        col("security_defaults_enabled", B),
    ],
};

pub static TENANT_SETTINGS: TableSpec = TableSpec {
    table: "tenant_settings",
    mode: LoadMode::LatestWins,
    columns: &[col("source", V), col("name", V), col("value", J)],
};

pub static TRANSPORT_RULES: TableSpec = TableSpec {
    table: "transport_rules",
    mode: LoadMode::LatestWins,
    columns: &[
        col("name", V),
        col("guid", V),
        col("state", V),
        col("mode", V),
        col("priority", I),
        col("created_by", V),
        col("last_modified_by", V),
        col("when_changed", T),
        col("description", V),
        col("conditions", J),
        col("exceptions", J),
        col("actions", J),
        col("redirect_to", L),
        col("blind_copy_to", L),
        col("copy_to", L),
        col("add_to_recipients", L),
    ],
};

pub static REMOTE_DOMAINS: TableSpec = TableSpec {
    table: "remote_domains",
    mode: LoadMode::LatestWins,
    columns: &[
        col("domain_name", V),
        col("name", V),
        col("auto_forward_enabled", B),
        col("allowed_ooo_type", V),
        col("when_changed", T),
    ],
};

pub static MOBILE_DEVICES: TableSpec = TableSpec {
    table: "mobile_devices",
    mode: LoadMode::LatestWins,
    columns: &[
        col("mailbox", V),
        col("device_id", V),
        col("friendly_name", V),
        col("device_type", V),
        col("model", V),
        col("os", V),
        col("user_agent", V),
        col("client_type", V),
        col("first_sync", T),
        col("last_sync", T),
        col("access_state", V),
        col("access_state_reason", V),
        col("is_managed", B),
        col("is_compliant", B),
        col("is_disabled", B),
        col("when_created", T),
    ],
};

pub static RISKY_USERS: TableSpec = TableSpec {
    table: "risky_users",
    mode: LoadMode::LatestWins,
    columns: &[
        col("user_id", V),
        col("upn", V),
        col("display_name", V),
        col("risk_level", V),
        col("risk_state", V),
        col("risk_detail", V),
        col("risk_last_updated", T),
        col("is_deleted", B),
        col("is_processing", B),
    ],
};

pub const LOCATION_TYPE: &str =
    "STRUCT(city VARCHAR, state VARCHAR, country VARCHAR, latitude DOUBLE, longitude DOUBLE)";

pub static RISK_DETECTIONS: TableSpec = TableSpec {
    table: "risk_detections",
    mode: LoadMode::LatestWins,
    columns: &[
        col("detection_id", V),
        col("detected_time", T),
        col("activity_time", T),
        col("last_updated_time", T),
        col("activity", V),
        col("risk_event_type", V),
        col("risk_level", V),
        col("risk_state", V),
        col("risk_detail", V),
        col("detection_timing", V),
        col("source", V),
        col("token_issuer_type", V),
        col("ip", V),
        col("user_upn", V),
        col("user_id", V),
        col("user_display_name", V),
        col("correlation_id", V),
        col("request_id", V),
        col("location", LOCATION_TYPE),
        col("additional_info", J),
    ],
};

pub static COLLECTOR_FLAGS: TableSpec = TableSpec {
    table: "collector_flags",
    mode: LoadMode::InsertOnly,
    columns: &[
        col("file_id", "BIGINT"),
        col("flag_type", V),
        col("category", V),
        col("flag_time", T),
        col("subject", V),
        col("description", V),
        col("linked_table", V),
        col("linked_key", V),
    ],
};

pub const DEVICE_TYPE: &str = "STRUCT(device_id VARCHAR, display_name VARCHAR, os VARCHAR, browser VARCHAR, is_compliant BOOLEAN, is_managed BOOLEAN, trust_type VARCHAR)";

pub static SIGNINS: TableSpec = TableSpec {
    table: "signins",
    mode: LoadMode::FillMissing,
    columns: &[
        col("signin_id", V),
        col("event_time", T),
        col("time_tz_assumed", B),
        col("event_type", "signin_event_type"),
        col("user_upn", V),
        col("user_id", V),
        col("user_display_name", V),
        col("app_id", V),
        col("app_name", V),
        col("resource_id", V),
        col("resource_name", V),
        col("ip", V),
        col("user_agent", V),
        col("client_app", V),
        col("is_interactive", B),
        col("status", V),
        col("error_code", I),
        col("failure_reason", V),
        col("ca_status", V),
        col("ca_policies", J),
        col("risk_level_during", V),
        col("risk_level_aggregated", V),
        col("risk_state", V),
        col("risk_detail", V),
        col("risk_event_types", L),
        col("auth_requirement", V),
        col("mfa_result", V),
        col("mfa_detail", V),
        col("auth_methods", L),
        col("device", DEVICE_TYPE),
        col("location", LOCATION_TYPE),
        col("asn", I),
        col("session_id", V),
        col("correlation_id", V),
        col("unique_token_id", V),
        col("token_issuer_type", V),
        col("incoming_token_type", V),
        col("cross_tenant_access_type", V),
        col("home_tenant_id", V),
        col("resource_tenant_id", V),
    ],
};

pub static DIRECTORY_AUDITS: TableSpec = TableSpec {
    table: "directory_audits",
    mode: LoadMode::FillMissing,
    columns: &[
        col("audit_id", V),
        col("event_time", T),
        col("time_tz_assumed", B),
        col("activity", V),
        col("category", V),
        col("operation_type", V),
        col("result", V),
        col("result_reason", V),
        col("logged_by_service", V),
        col("initiated_by_upn", V),
        col("initiated_by_user_id", V),
        col("initiated_by_app_id", V),
        col("initiated_by_app_name", V),
        col("initiated_by_ip", V),
        col("targets", J),
        col("modified_properties", J),
        col("additional_details", J),
        col("correlation_id", V),
    ],
};

pub static MESSAGE_TRACE: TableSpec = TableSpec {
    table: "message_trace",
    mode: LoadMode::FillMissing,
    columns: &[
        col("message_trace_id", V),
        col("received", T),
        col("time_tz_assumed", B),
        col("sender", V),
        col("recipient", V),
        col("subject", V),
        col("status", V),
        col("from_ip", V),
        col("to_ip", V),
        col("size_bytes", BI),
        col("internet_message_id", V),
        col("organization", V),
        col("direction", V),
        col("connector_id", V),
    ],
};

pub static MAILBOX_AUDIT_LEGACY: TableSpec = TableSpec {
    table: "mailbox_audit_legacy",
    mode: LoadMode::FillMissing,
    columns: &[
        col("event_time", T),
        col("time_tz_assumed", B),
        col("mailbox_upn", V),
        col("mailbox_guid", V),
        col("operation", V),
        col("operation_result", V),
        col("logon_type", V),
        col("logon_user", V),
        col("logon_user_sid", V),
        col("client_ip", V),
        col("client_info", V),
        col("client_machine", V),
        col("client_process", V),
        col("external_access", B),
        col("folder_path", V),
        col("dest_folder_path", V),
        col("dest_mailbox_upn", V),
        col("cross_mailbox", B),
        col("subjects", L),
        col("internet_message_ids", L),
        col("session_id", V),
        col("app_id", V),
        col("client_app_id", V),
    ],
};

pub static ADMIN_AUDIT_EVENTS: TableSpec = TableSpec {
    table: "admin_audit_events",
    mode: LoadMode::FillMissing,
    columns: &[
        col("run_time", T),
        col("time_tz_assumed", B),
        col("caller", V),
        col("cmdlet", V),
        col("object_modified", V),
        col("parameters", M),
        col("modified_properties", J),
        col("succeeded", B),
        col("error", V),
        col("external_access", B),
        col("client_ip", V),
        col("session_id", V),
        col("app_id", V),
        col("client_app_id", V),
        col("originating_server", V),
        col("full_command", V),
        col("data_completeness", "data_completeness"),
    ],
};

pub static MAILBOX_PERMISSIONS: TableSpec = TableSpec {
    table: "mailbox_permissions",
    mode: LoadMode::LatestWins,
    columns: &[
        col("mailbox_upn", V),
        keep("mailbox_display_name", V),
        keep("recipient_type", V),
        col("grantee", V),
        keep("grantee_upn", V),
        col("permission", "mailbox_right"),
        col("folder", V),
        col("access_rights", L),
        col("deny", B),
        col("inheritance", V),
    ],
};

pub static ALL: &[&TableSpec] = &[
    &USERS,
    &ROLE_ASSIGNMENTS,
    &OAUTH_GRANTS,
    &APP_CREDENTIALS,
    &INBOX_RULES,
    &MAILBOXES,
    &AUDIT_CONFIG,
    &TENANT_SETTINGS,
    &TRANSPORT_RULES,
    &REMOTE_DOMAINS,
    &MOBILE_DEVICES,
    &RISKY_USERS,
    &RISK_DETECTIONS,
    &COLLECTOR_FLAGS,
    &SIGNINS,
    &DIRECTORY_AUDITS,
    &MESSAGE_TRACE,
    &MAILBOX_AUDIT_LEGACY,
    &ADMIN_AUDIT_EVENTS,
    &MAILBOX_PERMISSIONS,
];
