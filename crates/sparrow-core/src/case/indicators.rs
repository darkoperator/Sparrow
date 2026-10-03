//! Case indicators (ip, upn, ...): the analyst's verdicts that detection rules read through
//! `@list:case_iocs.<type>`. All writes go through here and carry an [`Actor`].

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use duckdb::{Connection, params};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

pub use super::actor::Actor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Ip,
    Upn,
    AppId,
    Domain,
    UserAgent,
    RuleName,
    Email,
    Url,
    Hash,
}

impl IndicatorType {
    pub const ALL: [IndicatorType; 9] = [
        IndicatorType::Ip,
        IndicatorType::Upn,
        IndicatorType::AppId,
        IndicatorType::Domain,
        IndicatorType::UserAgent,
        IndicatorType::RuleName,
        IndicatorType::Email,
        IndicatorType::Url,
        IndicatorType::Hash,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            IndicatorType::Ip => "ip",
            IndicatorType::Upn => "upn",
            IndicatorType::AppId => "app_id",
            IndicatorType::Domain => "domain",
            IndicatorType::UserAgent => "user_agent",
            IndicatorType::RuleName => "rule_name",
            IndicatorType::Email => "email",
            IndicatorType::Url => "url",
            IndicatorType::Hash => "hash",
        }
    }

    pub fn parse(s: &str) -> Result<IndicatorType> {
        IndicatorType::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| Error::Invalid(format!("unknown indicator type {s:?}")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    Benign,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Malicious => "malicious",
            Verdict::Suspicious => "suspicious",
            Verdict::Benign => "benign",
        }
    }

    pub fn parse(s: &str) -> Result<Verdict> {
        [Verdict::Malicious, Verdict::Suspicious, Verdict::Benign]
            .into_iter()
            .find(|v| v.as_str() == s)
            .ok_or_else(|| Error::Invalid(format!("unknown indicator verdict {s:?}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Indicator {
    pub indicator_id: String,
    pub tenant_key: Option<String>,
    #[serde(rename = "type")]
    pub ty: IndicatorType,
    pub value: String,
    pub verdict: Verdict,
    pub note: Option<String>,
    pub added_by: String,
    #[serde(serialize_with = "rfc3339")]
    pub added_at: DateTime<Utc>,
}

fn rfc3339<S: Serializer>(t: &DateTime<Utc>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

fn indicator_id(tenant_key: Option<&str>, ty: IndicatorType, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(tenant_key.unwrap_or("").as_bytes());
    h.update([0x1f]);
    h.update(ty.as_str().as_bytes());
    h.update([0x1f]);
    h.update(value.to_lowercase().as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// Add an indicator (or update the verdict and note of the same tenant/type/value). Returns its id.
pub fn add_indicator(
    conn: &Connection,
    actor: &Actor,
    tenant_key: Option<&str>,
    ty: IndicatorType,
    value: &str,
    verdict: Verdict,
    note: Option<&str>,
) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::Invalid(
            "an indicator value must not be empty".into(),
        ));
    }
    let id = indicator_id(tenant_key, ty, value);
    let updated = conn.execute(
        "UPDATE case_indicators SET verdict = CAST(? AS indicator_verdict), note = ?, added_by = ?, \
         added_at = current_timestamp WHERE indicator_id = ?",
        params![verdict.as_str(), note, actor.as_str(), id],
    )?;
    if updated == 0 {
        conn.execute(
            "INSERT INTO case_indicators (indicator_id, tenant_key, type, value, verdict, note, added_by, added_at) \
             VALUES (?, ?, CAST(? AS indicator_type), ?, CAST(? AS indicator_verdict), ?, ?, current_timestamp)",
            params![id, tenant_key, ty.as_str(), value, verdict.as_str(), note, actor.as_str()],
        )?;
    }
    Ok(id)
}

/// Remove an indicator. Returns whether it existed.
pub fn remove_indicator(conn: &Connection, _actor: &Actor, indicator_id: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM case_indicators WHERE indicator_id = ?",
        params![indicator_id],
    )?;
    Ok(n > 0)
}

/// The indicators of `tenant_key` plus the case-wide ones (`tenant_key` NULL); every indicator
/// when `tenant_key` is `None`. Ordered by type, value, id.
pub fn list_indicators(conn: &Connection, tenant_key: Option<&str>) -> Result<Vec<Indicator>> {
    let mut stmt = conn.prepare(
        "SELECT indicator_id, tenant_key, CAST(type AS VARCHAR), value, CAST(verdict AS VARCHAR), note, \
                added_by, epoch_us(added_at) \
         FROM case_indicators WHERE ?::VARCHAR IS NULL OR tenant_key IS NULL OR tenant_key = ?::VARCHAR \
         ORDER BY type, value, indicator_id",
    )?;
    let rows = stmt.query_map(params![tenant_key, tenant_key], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, i64>(7)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (indicator_id, tenant_key, ty, value, verdict, note, added_by, us) = row?;
        out.push(Indicator {
            indicator_id,
            tenant_key,
            ty: IndicatorType::parse(&ty)?,
            value,
            verdict: Verdict::parse(&verdict)?,
            note,
            added_by,
            added_at: DateTime::from_timestamp_micros(us).unwrap_or_default(),
        });
    }
    Ok(out)
}
