use sparrow_core::case::actor::Actor;

/// Every CLI write is an agent decision (Addendum D.2): `--agent` or $SPARROW_AGENT (default "unnamed"), and
/// optionally on behalf of `--analyst` or $SPARROW_ANALYST. A blank analyst counts as none.
pub fn resolve(agent: Option<String>, analyst: Option<String>) -> anyhow::Result<Actor> {
    let agent = agent
        .or_else(|| crate::cx::env_var("SPARROW_AGENT"))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unnamed".into());
    let analyst = analyst
        .or_else(|| crate::cx::env_var("SPARROW_ANALYST"))
        .filter(|s| !s.trim().is_empty());
    Ok(Actor::agent(&agent, analyst.as_deref())?)
}
