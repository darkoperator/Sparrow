//! docs/COLLECTION.md (what to collect, by licence) follows data/capabilities.yaml: every capability has a row in
//! its licence table that names the capability's id and states its retention, so a change in the data that the
//! guide does not follow fails here.

use sparrow_core::data::{DataDirs, capabilities};

fn guide() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/COLLECTION.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_capability_has_a_row_with_its_retention() {
    let guide = guide();
    let caps = capabilities(&DataDirs::default()).unwrap();
    assert!(!caps.is_empty());
    for c in caps {
        // The capability's own row starts with its id (other rows may mention it in passing).
        let tag = format!("`{}`", c.id);
        let row = guide
            .lines()
            .find(|l| l.starts_with(&format!("| {tag}")))
            .unwrap_or_else(|| panic!("no table row starts with {tag}"));
        match c.retention_days {
            Some(days) => assert!(
                row.contains(&format!("{days} days")),
                "the row for {tag} does not say {days} days: {row}"
            ),
            None => assert!(row.contains("current state"), "{row}"),
        }
    }
}
