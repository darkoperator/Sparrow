use serde_json::{Map, Value, json};
use sparrow_core::normalize::fields::{Cell, Rec, is_placeholder};
use sparrow_core::readers::time::DateOrder;

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn json_records_keep_types_and_match_keys_case_insensitively() {
    let m = obj(json!({
        "UserPrincipalName": " Alice@Contoso.example ", "AccountEnabled": true, "Priority": 2,
        "ForwardTo": ["\"x\" [SMTP:x@fabrikam.example]", ""],
        "Conditions": ["Microsoft.Exchange.MessagingPolicies.Rules.Tasks.SentToPredicate"],
        "Location": {"City": "Lisbon"}, "Blank": "  ", "Null": null,
        "AdditionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"x\"}]"
    }));
    let r = Rec::new(&m, false);
    assert_eq!(
        r.text("userprincipalname").as_deref(),
        Some("Alice@Contoso.example")
    );
    assert_eq!(r.bool("accountenabled"), Some(true));
    assert_eq!(r.int("Priority"), Some(2));
    assert_eq!(r.list("ForwardTo"), vec!["\"x\" [SMTP:x@fabrikam.example]"]);
    assert_eq!(r.list("Conditions").len(), 1);
    assert_eq!(r.list("Missing"), Vec::<String>::new());
    assert_eq!(r.text("Blank"), None);
    assert_eq!(r.text("Null"), None);
    assert_eq!(r.text("Location"), None);
    assert_eq!(r.json("Location"), Some(json!({"City": "Lisbon"})));
    assert_eq!(
        r.json("AdditionalInfo"),
        Some(json!([{"Key": "userAgent", "Value": "x"}]))
    );
    assert_eq!(r.first_text(&["Missing", "Priority"]).as_deref(), Some("2"));
    assert!(r.has("LOCATION"));
}

#[test]
fn csv_records_drop_powershell_placeholders() {
    let m = obj(json!({
        "Enabled": "True", "InError": "false", "Priority": "3", "Folders": "System.Object[]",
        "Item": "@{Id=1; Subject=x}",
        "Location": "Microsoft.Graph.PowerShell.Models.MicrosoftGraphSignInLocation",
        "From": "\"Bob\" [SMTP:bob@fabrikam.example] \"Eve\" [SMTP:eve@fabrikam.example]",
        "Domain": "Microsoft.com"
    }));
    let r = Rec::new(&m, true);
    assert_eq!(r.bool("Enabled"), Some(true));
    assert_eq!(r.bool("InError"), Some(false));
    assert_eq!(r.int("Priority"), Some(3));
    assert_eq!(r.text("Folders"), None);
    assert_eq!(r.text("Item"), None);
    assert_eq!(r.json("Location"), None);
    assert_eq!(r.list("From").len(), 1);
    assert_eq!(r.text("Domain").as_deref(), Some("Microsoft.com"));
    assert!(is_placeholder(
        "System.Collections.Generic.List`1[System.String]"
    ));
    assert!(!is_placeholder("Microsoft Graph"));
}

#[test]
fn cells_stage_as_text() {
    let md = Some(DateOrder::MonthFirst);
    assert_eq!(Cell::Null.stage(md), Ok(None));
    assert_eq!(Cell::text(Some("a".into())).stage(md), Ok(Some("a".into())));
    assert_eq!(Cell::bool(Some(false)).stage(md), Ok(Some("false".into())));
    assert_eq!(Cell::int(Some(7)).stage(md), Ok(Some("7".into())));
    assert_eq!(Cell::list(vec![]), Cell::Null);
    assert_eq!(
        Cell::list(vec!["a".into(), "b".into()]).stage(md),
        Ok(Some("[\"a\",\"b\"]".into()))
    );
    assert_eq!(
        Cell::json(Some(json!({"k": 1}))).stage(md),
        Ok(Some("{\"k\":1}".into()))
    );
    assert_eq!(
        Cell::time(Some("9/24/2026 8:00:00 AM".into())).stage(md),
        Ok(Some("2026-09-24T08:00:00+00:00".into()))
    );
    assert_eq!(
        Cell::time(Some("/Date(1788256740000)/".into())).stage(None),
        Ok(Some("2026-09-01T09:59:00+00:00".into()))
    );
    let err = Cell::time(Some("6/9/2026 8:00:00 AM".into()))
        .stage(None)
        .unwrap_err();
    assert!(err.contains("--culture"), "{err}");
}
