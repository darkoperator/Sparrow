//! Canonical events: what Microsoft 365 recorded, before any collector renders it. Unified audit
//! log records (complete `AuditData` objects in Microsoft's key order), Graph sign-ins, Entra
//! directory audits, message trace rows and Identity Protection risk detections. The baseline
//! (`baseline`) and the storylines produce these; the writers render them per collector.
//! Whether Microsoft 365 logged an event at all (audit settings, licences) is decided by the
//! producer, not the writers.

use crate::world::{Client, Location};
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{Map, Value};
use std::net::IpAddr;
use uuid::Uuid;

/// The Office 365 Management Activity API `AuditLogRecordType` values the generator emits
/// (numbers and names from the Microsoft Learn table, as copied into
/// `sparrow_core::normalize::record_types::RECORD_TYPES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordType {
    ExchangeAdmin,
    ExchangeItem,
    ExchangeItemGroup,
    SharePoint,
    SharePointFileOperation,
    OneDrive,
    AzureActiveDirectory,
    AzureActiveDirectoryAccountLogon,
    SharePointSharingOperation,
    AzureActiveDirectoryStsLogon,
    Discovery,
    SecurityComplianceAlerts,
    ExchangeItemAggregated,
    ExchangeSearch,
    SharePointSearch,
}

impl RecordType {
    /// Every variant, in number order.
    pub const ALL: &'static [RecordType] = &[
        RecordType::ExchangeAdmin,
        RecordType::ExchangeItem,
        RecordType::ExchangeItemGroup,
        RecordType::SharePoint,
        RecordType::SharePointFileOperation,
        RecordType::OneDrive,
        RecordType::AzureActiveDirectory,
        RecordType::AzureActiveDirectoryAccountLogon,
        RecordType::SharePointSharingOperation,
        RecordType::AzureActiveDirectoryStsLogon,
        RecordType::Discovery,
        RecordType::SecurityComplianceAlerts,
        RecordType::ExchangeItemAggregated,
        RecordType::ExchangeSearch,
        RecordType::SharePointSearch,
    ];

    pub fn number(self) -> i16 {
        match self {
            RecordType::ExchangeAdmin => 1,
            RecordType::ExchangeItem => 2,
            RecordType::ExchangeItemGroup => 3,
            RecordType::SharePoint => 4,
            RecordType::SharePointFileOperation => 6,
            RecordType::OneDrive => 7,
            RecordType::AzureActiveDirectory => 8,
            RecordType::AzureActiveDirectoryAccountLogon => 9,
            RecordType::SharePointSharingOperation => 14,
            RecordType::AzureActiveDirectoryStsLogon => 15,
            RecordType::Discovery => 24,
            RecordType::SecurityComplianceAlerts => 40,
            RecordType::ExchangeItemAggregated => 50,
            RecordType::ExchangeSearch => 101,
            RecordType::SharePointSearch => 102,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RecordType::ExchangeAdmin => "ExchangeAdmin",
            RecordType::ExchangeItem => "ExchangeItem",
            RecordType::ExchangeItemGroup => "ExchangeItemGroup",
            RecordType::SharePoint => "SharePoint",
            RecordType::SharePointFileOperation => "SharePointFileOperation",
            RecordType::OneDrive => "OneDrive",
            RecordType::AzureActiveDirectory => "AzureActiveDirectory",
            RecordType::AzureActiveDirectoryAccountLogon => "AzureActiveDirectoryAccountLogon",
            RecordType::SharePointSharingOperation => "SharePointSharingOperation",
            RecordType::AzureActiveDirectoryStsLogon => "AzureActiveDirectoryStsLogon",
            RecordType::Discovery => "Discovery",
            RecordType::SecurityComplianceAlerts => "SecurityComplianceAlerts",
            RecordType::ExchangeItemAggregated => "ExchangeItemAggregated",
            RecordType::ExchangeSearch => "ExchangeSearch",
            RecordType::SharePointSearch => "SharePointSearch",
        }
    }
}

/// One unified audit log record. `audit` is the complete `AuditData` object; the other fields
/// are the outer columns `Search-UnifiedAuditLog` returns alongside it.
#[derive(Debug, Clone)]
pub struct Ual {
    pub id: Uuid,
    pub time: DateTime<Utc>,
    pub record_type: RecordType,
    pub operation: String,
    /// The outer `UserIds` value (normally the UPN).
    pub user_id: String,
    pub audit: Map<String, Value>,
}

impl Ual {
    /// The embedded `AuditData` string: compact JSON in Microsoft's key order.
    pub fn audit_data_text(&self) -> String {
        serde_json::to_string(&self.audit).expect("JSON values serialize")
    }

    pub fn result_status(&self) -> Option<&str> {
        self.audit.get("ResultStatus").and_then(Value::as_str)
    }

    /// `ClientIP`, else `ClientIPAddress`, else `ActorIpAddress`.
    pub fn client_ip(&self) -> Option<&str> {
        ["ClientIP", "ClientIPAddress", "ActorIpAddress"]
            .iter()
            .find_map(|k| self.audit.get(*k).and_then(Value::as_str))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignInType {
    Interactive,
    NonInteractive,
    ServicePrincipal,
}

/// One Microsoft Graph `signIn` (beta shape, which carries all three event types).
#[derive(Debug, Clone)]
pub struct SignIn {
    pub id: Uuid,
    pub time: DateTime<Utc>,
    /// UPN; empty for service principals.
    pub user: String,
    pub user_id: Option<Uuid>,
    pub user_display: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub resource_id: Uuid,
    pub resource_name: String,
    pub ip: IpAddr,
    pub location: Location,
    pub user_agent: String,
    pub client_app: String,
    pub event_type: SignInType,
    pub error_code: i64,
    pub failure_reason: String,
    pub ca_status: String,
    pub risk_during: String,
    pub risk_aggregated: String,
    pub risk_state: String,
    pub risk_detail: String,
    pub risk_event_types: Vec<String>,
    pub auth_requirement: String,
    /// (method, detail).
    pub mfa: Option<(String, String)>,
    pub auth_methods: Vec<String>,
    pub device: Client,
    pub device_compliant: Option<bool>,
    pub device_managed: Option<bool>,
    pub trust_type: Option<String>,
    pub session_id: Uuid,
    pub correlation_id: Uuid,
    pub unique_token_id: String,
    pub token_issuer: String,
    pub incoming_token_type: String,
    pub home_tenant_id: Uuid,
    pub resource_tenant_id: Uuid,
    pub asn: u32,
}

/// Who performed a directory change.
#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub upn: Option<String>,
    pub user_id: Option<Uuid>,
    pub ip: Option<IpAddr>,
    pub app_id: Option<Uuid>,
    pub app_name: Option<String>,
}

/// A directory audit target.
#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub display_name: String,
    /// `User` | `ServicePrincipal` | `Application` | `Domain` | `Other`.
    pub kind: String,
    pub upn: Option<String>,
    /// (property, old value as JSON text, new value as JSON text).
    pub modified: Vec<(String, String, String)>,
}

/// One Microsoft Graph `directoryAudit`.
#[derive(Debug, Clone)]
pub struct DirAudit {
    /// `Directory_<uuid>_<5 upper letters>_<n>`.
    pub id: String,
    pub time: DateTime<Utc>,
    pub activity: String,
    pub category: String,
    pub operation_type: String,
    pub result: String,
    pub result_reason: String,
    pub logged_by_service: String,
    pub initiated_by: Actor,
    pub targets: Vec<Target>,
    pub additional_details: Vec<(String, String)>,
    pub correlation_id: Uuid,
}

/// One message trace row (one message, all its recipients).
#[derive(Debug, Clone)]
pub struct TraceMsg {
    /// MessageTraceId (the network message id).
    pub trace_id: Uuid,
    /// `<...@...prod.outlook.example>`.
    pub internet_message_id: String,
    pub received: DateTime<Utc>,
    pub sender: String,
    /// (recipient, status: `Delivered` | `Failed` | `Quarantined` | `FilteredAsSpam`).
    pub recipients: Vec<(String, String)>,
    pub subject: String,
    pub from_ip: Option<IpAddr>,
    pub to_ip: Option<IpAddr>,
    pub size: u64,
    /// `Originating` | `Incoming` | `Outgoing`.
    pub direction: String,
    pub connector_id: Option<String>,
}

/// One Identity Protection `riskDetection`.
#[derive(Debug, Clone)]
pub struct RiskDetection {
    pub id: String,
    pub user: String,
    pub user_id: Uuid,
    pub user_display: String,
    /// `signin` | `user`.
    pub activity: String,
    pub event_type: String,
    pub level: String,
    pub state: String,
    pub detail: String,
    pub timing: String,
    pub source: String,
    pub detected: DateTime<Utc>,
    pub activity_time: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub ip: Option<IpAddr>,
    pub location: Option<Location>,
    pub request_id: Option<Uuid>,
    pub correlation_id: Option<Uuid>,
    /// JSON text.
    pub additional_info: String,
}

/// One UTC day of events; each vector sorted by `(time, id)`.
#[derive(Debug, Clone)]
pub struct Day {
    pub date: NaiveDate,
    pub ual: Vec<Ual>,
    pub signins: Vec<SignIn>,
    pub trace: Vec<TraceMsg>,
}
