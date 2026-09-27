//! Microsoft-Extractor-Suite licence lists: Get-Licenses
//! (`Licenses/<ts>/<ts>-TenantLicenses.csv`) into `licenses` (high confidence) and
//! Get-LicensesByUser (`Licenses/<ts>/<ts>-UserLicenses.csv`) into `user_licenses`.
//! The collector's own E3/E5/P1/P2/Defender and Retention columns are its outdated
//! interpretation of a SKU name: they stay in `raw` and never feed capabilities.

use crate::Result;
use crate::db::state_tables::{LICENSES, USER_LICENSES};
use crate::ingest::context::ParseContext;
use crate::ingest::parser::{ArtifactParser, ParserRegistry};
use crate::normalize::fields::{Cell, Rec};
use crate::parsers::records::RecordFormat;
use crate::parsers::stage::{
    CellRow, TableRows, load_tables, read_state_records, reject, require_any_key,
};

pub fn register(r: &mut ParserRegistry) {
    r.register("inv.licenses.tenant", Box::new(TenantLicensesParser));
    r.register("inv.licenses.user", Box::new(UserLicensesParser));
}

const TENANT_COLS: &[&str] = &[
    "source",
    "sku_part_number",
    "sku_id",
    "license_tier",
    "capability_status",
    "consumed_units",
    "enabled_units",
    "service_plans",
    "confidence",
];
const USER_COLS: &[&str] = &[
    "source",
    "upn",
    "user_id",
    "sku_part_number",
    "sku_id",
    "service_plans",
];

/// TenantLicenses `ServicePlans` joins the names with `"; "` (and may carry a trailing space
/// on a name or a blank element): split, trim and drop blanks.
fn plans(value: Option<String>) -> Vec<String> {
    value
        .map(|s| {
            s.split(';')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// `licenses.record_key` of a TenantLicenses row.
fn tenant_key(collection_id: i64, sku: &str) -> String {
    format!(
        "{collection_id}|invictus_tenant_licenses|{}",
        sku.to_lowercase()
    )
}

/// `user_licenses.record_key` of a UserLicenses row.
fn user_key(collection_id: i64, upn: &str, sku: &str) -> String {
    format!(
        "{collection_id}|{}|{}",
        upn.to_lowercase(),
        sku.to_lowercase()
    )
}

/// Get-Licenses: one high-confidence `licenses` row per SKU.
pub struct TenantLicensesParser;

impl ArtifactParser for TenantLicensesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["Sku", "ServicePlans"], "tenant licence")?;
        let mut rows = TableRows::new(&LICENSES, TENANT_COLS);
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(sku) = rec.text("Sku") else {
                reject(ctx, r, "tenant licence row has no Sku")?;
                continue;
            };
            let key = tenant_key(ctx.collection_id, &sku);
            let mut c = CellRow::new(TENANT_COLS);
            c.set(
                "source",
                Cell::text(Some("invictus_tenant_licenses".into())),
            )
            .set("sku_part_number", Cell::text(Some(sku)))
            .set("capability_status", Cell::text(rec.text("Status")))
            .set("consumed_units", Cell::int(rec.int("Units")))
            .set("service_plans", Cell::list(plans(rec.text("ServicePlans"))))
            .set("confidence", Cell::text(Some("high".into())));
            rows.push(r, key, c.into_cells());
        }
        load_tables(ctx, vec![rows])
    }
}

/// Get-LicensesByUser: one `user_licenses` row per assigned SKU. The collector's "no licence"
/// row (`SkuPartNumber` None) and a blank SKU are not loaded; each gets one warning.
pub struct UserLicensesParser;

impl ArtifactParser for UserLicensesParser {
    fn parse(&self, ctx: &mut ParseContext<'_>) -> Result<()> {
        let format = RecordFormat::of(ctx.rel_path);
        let records = read_state_records(ctx, format)?;
        require_any_key(&records, &["SkuPartNumber"], "user licence")?;
        let mut rows = TableRows::new(&USER_LICENSES, USER_COLS);
        let mut no_licence = 0usize;
        let mut no_sku = 0usize;
        for r in &records {
            let rec = Rec::new(&r.map, format.lossy());
            let Some(upn) = rec.text("UserPrincipalName") else {
                reject(ctx, r, "user licence row has no UserPrincipalName")?;
                continue;
            };
            let Some(sku) = rec.text("SkuPartNumber") else {
                no_sku += 1;
                continue;
            };
            if sku.eq_ignore_ascii_case("none") {
                no_licence += 1;
                continue;
            }
            let key = user_key(ctx.collection_id, &upn, &sku);
            let mut c = CellRow::new(USER_COLS);
            c.set("source", Cell::text(Some("invictus_user_licenses".into())))
                .set("upn", Cell::text(Some(upn.to_lowercase())))
                .set("sku_part_number", Cell::text(Some(sku)));
            rows.push(r, key, c.into_cells());
        }
        if no_licence > 0 {
            ctx.warn(format!(
                "{no_licence} users have no licence (SkuPartNumber None)"
            ));
        }
        if no_sku > 0 {
            ctx.warn(format!("{no_sku} rows name no SKU"));
        }
        load_tables(ctx, vec![rows])
    }
}
