//! Who makes a change. Every CLI write is an agent decision; `on_behalf_of` names the analyst who should review it
//! (Addendum D.2). It is not an identity claim. The review app writes analyst decisions (`analyst:<name>`), reviewed
//! when made. `Reviewer` is used only by the core review functions.

use crate::{Error, Result};

/// Trimmed `s`, or an error when it is empty, holds a control character, or holds ':' (the prefix separator).
fn valid(kind: &str, s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() || s.chars().any(char::is_control) || s.contains(':') {
        return Err(Error::Invalid(format!(
            "{kind} must be non-empty text without ':' or control characters"
        )));
    }
    Ok(s.to_string())
}

/// `agent:<id>` (optionally on behalf of `analyst:<name>`) or `analyst:<name>` (a decision reviewed when made).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    who: String,
    on_behalf_of: Option<String>,
}

impl Actor {
    pub fn agent(id: &str, on_behalf_of: Option<&str>) -> Result<Actor> {
        let who = format!("agent:{}", valid("an agent id", id)?);
        let on_behalf_of = match on_behalf_of {
            Some(n) => Some(format!("analyst:{}", valid("an analyst name", n)?)),
            None => None,
        };
        Ok(Actor { who, on_behalf_of })
    }

    /// An analyst's own decision: recorded as `analyst:<name>` and reviewed by that analyst when made.
    pub fn analyst(name: &str) -> Result<Actor> {
        Ok(Actor {
            who: format!("analyst:{}", valid("an analyst name", name)?),
            on_behalf_of: None,
        })
    }

    /// Whether this is an analyst's own decision (not an agent's).
    pub fn is_analyst(&self) -> bool {
        self.who.starts_with("analyst:")
    }

    /// `agent:<id>` or `analyst:<name>`.
    pub fn as_str(&self) -> &str {
        &self.who
    }

    /// `analyst:<name>`, the analyst responsible for reviewing this agent's decisions.
    pub fn on_behalf_of(&self) -> Option<&str> {
        self.on_behalf_of.as_deref()
    }
}

/// `analyst:<name>`: the reviewer of agent decisions (core review functions only; no CLI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewer(String);

impl Reviewer {
    pub fn analyst(name: &str) -> Result<Reviewer> {
        Ok(Reviewer(format!(
            "analyst:{}",
            valid("an analyst name", name)?
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The same analyst as a decision maker.
    pub fn as_actor(&self) -> Actor {
        Actor {
            who: self.0.clone(),
            on_behalf_of: None,
        }
    }
}
