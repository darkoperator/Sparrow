//! `Licenses/` (research state layouts §1): Get-Licenses (`TenantLicenses.csv`),
//! Get-LicensesByUser (`UserLicenses.csv`), both only with `opts.invictus_licence_list`, and
//! Get-EntraSecurityDefaults (`EntraSecurityDefaults.csv`). Each is its own run folder. The
//! Yes/No and Retention columns and HasPremiumLicense reproduce the collector's own tests
//! (Get-ProductLicenses.ps1), not licensing facts. All three hard-code `-Encoding UTF8`.

use super::Ctx;
use crate::Result;
use crate::keys;
use crate::profiles::SkuSpec;
use crate::ps::{DateEvidence, Row, Val, export_csv};
use crate::tree::{FileSpec, Tree};
use crate::world::World;

fn r(k: &str, v: Val) -> (String, Val) {
    (k.to_string(), v)
}

fn yes_no(b: bool) -> Val {
    Val::Str(if b { "Yes" } else { "No" }.into())
}

/// PowerShell `-contains`: an exact, case-insensitive element match.
fn contains(plans: &[String], name: &str) -> bool {
    plans.iter().any(|p| p.eq_ignore_ascii_case(name))
}

/// PowerShell `-match` of a literal: a case-insensitive substring.
fn matches(sku: &str, pattern: &str) -> bool {
    sku.to_ascii_lowercase()
        .contains(&pattern.to_ascii_lowercase())
}

/// One TenantLicenses.csv row.
fn sku_row(s: &SkuSpec) -> Row {
    let retention = if matches(&s.sku, "E5") {
        "365 days"
    } else if matches(&s.sku, "E3") {
        "180 days"
    } else {
        "90 days"
    };
    let is = |names: &[&str]| names.iter().any(|n| n.eq_ignore_ascii_case(&s.sku));
    vec![
        r("Sku", Val::Str(s.sku.clone())),
        r("Status", Val::Str(s.status.clone())),
        r("Scope", Val::Str(s.scope.clone())),
        r("Units", Val::Int(s.units.into())),
        r("Retention", Val::Str(retention.into())),
        r(
            "E3",
            yes_no(is(&["M365ENTERPRISE", "ENTERPRISEPACK", "STANDARD_EDU"])),
        ),
        r("E5", yes_no(is(&["SPE_E5", "ENTERPRISEPREMIUM"]))),
        r("P1", yes_no(contains(&s.plans, "AAD_PREMIUM"))),
        r("P2", yes_no(contains(&s.plans, "AAD_PREMIUM_P2"))),
        r("DefenderID", yes_no(contains(&s.plans, "MDE_ATP"))),
        r(
            "Defender365P1",
            yes_no(contains(&s.plans, "ATP_ENTERPRISE")),
        ),
        r(
            "Defender365P2",
            yes_no(contains(&s.plans, "ATP_ENTERPRISE_PLUS")),
        ),
        r("ServicePlans", Val::Str(s.plans.join("; "))),
    ]
}

/// Get-EntraSecurityDefaults' premium test: an SKU name matching `E5` or `E3`, or a plan
/// `AAD_PREMIUM` / `AAD_PREMIUM_P2` anywhere.
pub fn has_premium_licence(world: &World) -> bool {
    let skus = &world.licence.skus;
    skus.iter()
        .any(|s| matches(&s.sku, "E5") || matches(&s.sku, "E3"))
        || skus
            .iter()
            .any(|s| contains(&s.plans, "AAD_PREMIUM") || contains(&s.plans, "AAD_PREMIUM_P2"))
}

fn write_csv(
    c: &Ctx<'_>,
    tree: &mut Tree<'_>,
    rel: &str,
    artifact: &'static str,
    rows: &[Row],
) -> Result<Vec<(u32, u32)>> {
    let mut ev = DateEvidence::default();
    let rendered = export_csv(&c.host, rows, &mut ev);
    tree.write(
        &FileSpec::new(rel, Some(artifact), c.utf8()),
        &rendered.text,
    )?;
    Ok(rendered.spans)
}

pub(super) fn write(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    if c.opts.invictus_licence_list {
        write_tenant_licences(c, tree)?;
        write_user_licences(c, tree)?;
    }
    write_security_defaults(c, tree)
}

/// Get-Licenses: one row per SKU, sorted by Units descending; no SKUs leave the run folder
/// empty.
fn write_tenant_licences(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Licenses", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log.add(run.local, "=== Starting License Collection ===");
    let mut skus: Vec<&SkuSpec> = c.world.licence.skus.iter().collect();
    if skus.is_empty() {
        return Ok(());
    }
    skus.sort_by_key(|s| std::cmp::Reverse(s.units));
    let rows: Vec<Row> = skus.iter().map(|s| sku_row(s)).collect();
    let rel = format!("{dir}/{}-TenantLicenses.csv", run.stamp);
    write_csv(c, tree, &rel, "inv.licenses.tenant", &rows)?;
    for s in &skus {
        tree.row(&rel, "licenses", keys::licence(&s.sku));
    }
    Ok(())
}

/// Get-LicensesByUser: one row per user and assigned SKU (`None` for an unlicensed user),
/// sorted by DisplayName.
fn write_user_licences(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Licenses", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting User License Collection ===");
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for u in c.world.all_people() {
        if u.licences.is_empty() {
            rows.push((u.display_name.clone(), u.upn.clone(), "None".into()));
        }
        for sku in &u.licences {
            rows.push((u.display_name.clone(), u.upn.clone(), sku.clone()));
        }
    }
    if rows.is_empty() {
        return Ok(());
    }
    rows.sort_by_key(|(name, ..)| name.to_lowercase());
    let table: Vec<Row> = rows
        .iter()
        .map(|(name, upn, sku)| {
            vec![
                r("DisplayName", Val::Str(name.clone())),
                r("UserPrincipalName", Val::Str(upn.clone())),
                r("SkuPartNumber", Val::Str(sku.clone())),
            ]
        })
        .collect();
    let rel = format!("{dir}/{}-UserLicenses.csv", run.stamp);
    write_csv(c, tree, &rel, "inv.licenses.user", &table)?;
    for (_, upn, sku) in rows.iter().filter(|(_, _, s)| s != "None") {
        tree.row(&rel, "user_licenses", keys::user_licence(upn, sku));
    }
    Ok(())
}

/// The EntraSecurityDefaults.csv columns that become tenant settings (all but `CheckDate`).
const SETTINGS: &[&str] = &[
    "SecurityDefaultsEnabled",
    "HasPremiumLicense",
    "RecommendedState",
    "AlignedWithRecommendations",
];

/// Get-EntraSecurityDefaults: always exactly one row.
fn write_security_defaults(c: &mut Ctx<'_>, tree: &mut Tree<'_>) -> Result<()> {
    let run = c.runs.next("Licenses", None);
    let dir = c.path(&run.rel);
    tree.dir(&dir)?;
    c.log
        .add(run.local, "=== Starting Security Defaults Check ===");
    let enabled = c.world.audit.security_defaults_enabled;
    let premium = has_premium_licence(c.world);
    let row = vec![
        r("SecurityDefaultsEnabled", yes_no(enabled)),
        r("HasPremiumLicense", yes_no(premium)),
        r(
            "RecommendedState",
            Val::Str(if premium { "Disabled" } else { "Enabled" }.into()),
        ),
        r(
            "AlignedWithRecommendations",
            yes_no((premium && !enabled) || (!premium && enabled)),
        ),
        r(
            "CheckDate",
            Val::Str(run.local.format("%Y-%m-%d %H:%M:%S").to_string()),
        ),
    ];
    c.log.add(
        run.local,
        format!(
            "\nSecurity Defaults Status:\nSecurity Defaults: {}",
            if enabled { "Enabled" } else { "Disabled" }
        ),
    );
    let rel = format!("{dir}/{}-EntraSecurityDefaults.csv", run.stamp);
    let spans = write_csv(c, tree, &rel, "inv.licenses.security_defaults", &[row])?;
    for name in SETTINGS {
        tree.row(
            &rel,
            "tenant_settings",
            keys::tenant_setting("entra_security_defaults", name),
        );
    }
    tree.row(&rel, "audit_config", keys::audit_config());
    tree.deliver(
        &crate::story::Evidence::AuditConfig,
        "audit_config",
        &rel,
        spans[0],
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::load;

    fn premium(scenario: &str) -> bool {
        has_premium_licence(&World::build(&load(scenario).unwrap(), 1).unwrap())
    }

    #[test]
    fn premium_test_follows_the_collector() {
        assert!(premium("bec-aitm")); // SPE_E5
        assert!(premium("bec-e3-audit-gaps")); // SPE_E3
        assert!(!premium("bec-o365-no-p1")); // ENTERPRISEPACK: no "E3" in the name
        assert!(!premium("hawk-investigate")); // ENTERPRISEPREMIUM: no "E5" in the name
        assert!(!premium("business-basic"));
    }

    #[test]
    fn tenant_licence_columns_use_the_collector_rules() {
        let w = World::build(&load("bec-o365-no-p1").unwrap(), 1).unwrap();
        let row = sku_row(&w.licence.skus[0]);
        let get = |k: &str| row.iter().find(|(n, _)| n == k).unwrap().1.clone();
        assert_eq!(get("Retention"), Val::Str("90 days".into()));
        assert_eq!(get("E3"), Val::Str("Yes".into()));
        // "ATP_ENTERPRISE " (trailing space) is not an exact element match.
        assert_eq!(get("Defender365P1"), Val::Str("No".into()));
    }
}
