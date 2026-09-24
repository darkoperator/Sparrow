//! A folder of analyst portal exports on their own (becomes a `portal_export` collection).

use crate::fixtures::hawk4::MTSUMMARY_TEXT;
use crate::fixtures::{ual, utf16le_no_bom, write};
use std::path::{Path, PathBuf};

pub const PORTAL_ROOT_NAME: &str = "exports";
pub const PORTAL_PURVIEW: &str = "9b2e6f1a-3c4d-4e5f-8a9b-0c1d2e3f4a5b.csv";
pub const PORTAL_MTSUMMARY: &str = "MTSummary_Message trace report - _2026-09-11T090000.000Z__1b4e28ba-2fa1-41d2-883f-0016d3cca427.csv";

pub fn portal_tree(base: &Path) -> PathBuf {
    let root = base.join(PORTAL_ROOT_NAME);
    let purview = ual::PURVIEW_HEADER.to_string()
        + &ual::purview_row("2026-09-01T10:00:00.0000000Z", &ual::rule());
    write(&root, PORTAL_PURVIEW, purview.as_bytes());
    write(&root, PORTAL_MTSUMMARY, &utf16le_no_bom(MTSUMMARY_TEXT));
    write(&root, "notes.txt", b"exported by the analyst\r\n");
    root
}
