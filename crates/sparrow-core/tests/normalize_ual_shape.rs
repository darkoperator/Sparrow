use serde_json::{Map, Value, json};
use sparrow_core::normalize::ual_shape::*;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn detects_every_shape_from_keys() {
    use UalShape::*;
    assert_eq!(
        detect_shape(
            [
                "RecordType",
                "CreationDate",
                "UserIds",
                "Operations",
                "AuditData",
                "ResultIndex"
            ],
            false
        ),
        Raw
    );
    assert_eq!(
        detect_shape(
            [
                "RecordId",
                "CreationDate",
                "RecordType",
                "Operation",
                "UserId",
                "AuditData"
            ],
            false
        ),
        Purview
    );
    assert_eq!(
        detect_shape(["CreationTime", "Id", "Operation", "RecordType"], false),
        Record
    );
    assert_eq!(
        detect_shape(["CreationTime", "Id", "Operation", "Param_ForwardTo"], true),
        Flattened
    );
    assert_eq!(
        detect_shape(["Id", "Operation", "ResultStatus", "env_time"], false),
        AppAudit
    );
    assert_eq!(
        detect_shape(
            [
                "ObjectModified",
                "CmdletName",
                "CmdletParameters",
                "Caller",
                "RunDate"
            ],
            false
        ),
        AdminAudit
    );
    assert_eq!(
        detect_shape(
            [
                "Caller",
                "Cmdlet",
                "FullCommand",
                "RunDate(UTC)",
                "ObjectModified"
            ],
            true
        ),
        AdminAuditSimple
    );
    assert_eq!(detect_shape(["Operation"], true), Unknown);
    assert_eq!(detect_shape(["auditdata", "creationdate"], false), Raw);
}

#[test]
fn raw_audit_data_string_is_parsed() {
    let rec = obj(json!({
        "RecordType": "ExchangeAdmin",
        "CreationDate": "9/1/2026 10:00:05 AM",
        "AuditData": "{\"Id\":\"x\",\"CreationTime\":\"2026-09-01T10:00:00\"}"
    }));
    let a = to_audit(UalShape::Raw, &rec, true).unwrap();
    assert_eq!(a.audit["Id"], "x");
    assert_eq!(a.completeness, Completeness::Full);
    assert_eq!(a.outer_record_type.as_deref(), Some("ExchangeAdmin"));
    assert_eq!(a.outer_time.as_deref(), Some("9/1/2026 10:00:05 AM"));
    assert!(a.flat_params.is_empty());
}

#[test]
fn audit_data_object_is_accepted_and_bad_audit_data_is_an_error() {
    let ok = obj(json!({"AuditData": {"Id": "y"}, "RecordId": "r"}));
    assert_eq!(
        to_audit(UalShape::Purview, &ok, true).unwrap().audit["Id"],
        "y"
    );
    let truncated = obj(json!({"AuditData": "{\"Id\":"}));
    assert!(
        to_audit(UalShape::Raw, &truncated, false)
            .unwrap_err()
            .contains("not valid JSON")
    );
    let array = obj(json!({"AuditData": "[1]"}));
    assert!(
        to_audit(UalShape::Raw, &array, false)
            .unwrap_err()
            .contains("not a JSON object")
    );
    let missing = obj(json!({"AuditData": null}));
    assert!(
        to_audit(UalShape::Raw, &missing, false)
            .unwrap_err()
            .contains("no AuditData")
    );
}

#[test]
fn record_completeness_depends_on_lossiness() {
    let rec = obj(json!({"Id": "x", "CreationTime": "2026-09-01T10:00:00", "Operation": "Send"}));
    assert_eq!(
        to_audit(UalShape::Record, &rec, false)
            .unwrap()
            .completeness,
        Completeness::Full
    );
    assert_eq!(
        to_audit(UalShape::Record, &rec, true).unwrap().completeness,
        Completeness::Partial
    );
}

#[test]
fn flattened_collects_param_columns() {
    let rec = obj(json!({
        "Id": "x", "CreationTime": "2026-09-01T10:00:00", "Operation": "Set-Mailbox",
        "Param_ForwardingSmtpAddress": "smtp:x@fabrikam.example", "Param_Identity": "alice", "Param_Empty": ""
    }));
    let a = to_audit(UalShape::Flattened, &rec, false).unwrap();
    assert_eq!(a.completeness, Completeness::Partial);
    assert_eq!(
        a.flat_params,
        vec![
            (
                "ForwardingSmtpAddress".to_string(),
                "smtp:x@fabrikam.example".to_string()
            ),
            ("Identity".to_string(), "alice".to_string())
        ]
    );
}

#[test]
fn app_audit_uses_env_time_as_creation_time() {
    let rec = obj(
        json!({"Id": "x", "Operation": "Consent to application.", "env_time": "2026-09-02T09:00:00Z"}),
    );
    let a = to_audit(UalShape::AppAudit, &rec, false).unwrap();
    assert_eq!(a.audit["CreationTime"], "2026-09-02T09:00:00Z");
    assert_eq!(a.completeness, Completeness::Partial);
}

#[test]
fn admin_audit_and_unknown_shapes_are_rejected() {
    let rec = obj(json!({"CmdletName": "Set-Mailbox"}));
    assert!(to_audit(UalShape::AdminAudit, &rec, false).is_err());
    assert!(to_audit(UalShape::AdminAuditSimple, &rec, false).is_err());
    assert!(to_audit(UalShape::Unknown, &rec, false).is_err());
}

#[test]
fn helpers() {
    let m = obj(json!({"UserId": "a", "Empty": "  ", "N": 5, "B": true, "Nul": null}));
    assert_eq!(get_ci(&m, "userid"), Some(&json!("a")));
    assert_eq!(value_text(&m["Empty"]), None);
    assert_eq!(value_text(&m["N"]).as_deref(), Some("5"));
    assert_eq!(value_text(&m["B"]).as_deref(), Some("true"));
    assert_eq!(value_text(&m["Nul"]), None);
}
