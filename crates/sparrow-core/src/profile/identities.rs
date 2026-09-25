//! Identity resolution (spec §5.3): one `identities` row per actor, however the evidence names
//! it (UPN, Entra object id, UAL UserKey PUID, application id, system account name), and
//! `identity_aliases` mapping every observed identifier to it.
//!
//! Identifiers seen together in one source row are linked by union-find over
//! `(alias_type, value)` nodes. Observations are processed in a fixed order (source order, then
//! by value) so the result is deterministic. Two components are never merged when each already
//! holds a different `object_id` (a UPN reused after the account was deleted and recreated) or
//! a different `app_id`: the identifier stays with the component it joined first and the skipped
//! link is counted as a conflict.

use crate::{Error, Result};
use duckdb::{Connection, params};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IdentityOutcome {
    pub identities: usize,
    pub aliases: usize,
    /// Distinct identifier links skipped because both sides held a different object id / app id.
    pub conflicts: usize,
}

/// Alias types, in identity-id preference order.
const TYPES: [&str; 5] = ["object_id", "app_id", "upn", "puid", "name"];

/// Kind hints, in precedence order (first wins).
const HINTS: [&str; 4] = ["system", "service_principal", "app", "user"];

/// One observation source: `ids` are the alias types of the query's identifier columns.
struct Source {
    label: &'static str,
    table: &'static str,
    hint: &'static str,
    ids: &'static [(&'static str, &'static str)],
    display: &'static str,
    guest: &'static str,
    filter: &'static str,
}

const NO_GUEST: &str = "false";

/// UAL rows whose actor is a system account (UserType 4, NT AUTHORITY\\..., or a SID).
macro_rules! ual_system {
    () => {
        "(coalesce(x.user_type = 4, false) OR trim(x.user_upn) ILIKE 'NT AUTHORITY%' \
         OR trim(x.user_upn) ILIKE 'S-1-5-%')"
    };
}

const SOURCES: &[Source] = &[
    Source {
        label: "users",
        table: "users",
        hint: "'user'",
        ids: &[("object_id", "x.user_id"), ("upn", "x.upn")],
        display: "x.display_name",
        guest: "coalesce(lower(trim(x.user_type)) = 'guest', false)",
        filter: "true",
    },
    Source {
        label: "mailboxes",
        table: "mailboxes",
        hint: "'user'",
        ids: &[("object_id", "x.object_id"), ("upn", "x.upn")],
        display: "x.display_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "signins",
        table: "signins",
        hint: "'user'",
        ids: &[("object_id", "x.user_id"), ("upn", "x.user_upn")],
        display: "x.user_display_name",
        guest: NO_GUEST,
        filter: "(x.event_type IS NULL OR x.event_type IN ('interactive', 'noninteractive'))",
    },
    Source {
        label: "signins",
        table: "signins",
        hint: "'service_principal'",
        ids: &[("app_id", "x.app_id")],
        display: "x.app_name",
        guest: NO_GUEST,
        filter: "x.event_type IN ('service_principal', 'managed_identity')",
    },
    Source {
        label: "ual_events",
        table: "ual_events",
        hint: "'user'",
        ids: &[
            ("upn", "x.user_upn"),
            (
                "puid",
                "CASE WHEN regexp_full_match(trim(x.user_key), '[0-9A-Fa-f]{16}') THEN x.user_key END",
            ),
        ],
        display: "NULL",
        guest: NO_GUEST,
        filter: concat!("x.user_upn LIKE '%@%' AND NOT ", ual_system!()),
    },
    Source {
        label: "ual_events",
        table: "ual_events",
        hint: "'system'",
        ids: &[("name", "x.user_upn")],
        display: "NULL",
        guest: NO_GUEST,
        filter: ual_system!(),
    },
    Source {
        label: "directory_audits",
        table: "directory_audits",
        hint: "'user'",
        ids: &[
            ("object_id", "x.initiated_by_user_id"),
            ("upn", "x.initiated_by_upn"),
        ],
        display: "NULL",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "directory_audits",
        table: "directory_audits",
        hint: "'service_principal'",
        ids: &[("app_id", "x.initiated_by_app_id")],
        display: "x.initiated_by_app_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "risky_users",
        table: "risky_users",
        hint: "'user'",
        ids: &[("object_id", "x.user_id"), ("upn", "x.upn")],
        display: "x.display_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "risk_detections",
        table: "risk_detections",
        hint: "'user'",
        ids: &[("object_id", "x.user_id"), ("upn", "x.user_upn")],
        display: "x.user_display_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "role_assignments",
        table: "role_assignments",
        hint: "CASE WHEN replace(lower(x.principal_type), '_', '') LIKE '%serviceprincipal%'
                    THEN 'service_principal' ELSE 'user' END",
        ids: &[("object_id", "x.principal_id"), ("upn", "x.principal_upn")],
        display: "x.principal_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "oauth_grants",
        table: "oauth_grants",
        hint: "'user'",
        ids: &[("object_id", "x.principal_id"), ("upn", "x.principal_upn")],
        display: "x.principal_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "oauth_grants",
        table: "oauth_grants",
        hint: "'app'",
        ids: &[("app_id", "x.client_id")],
        display: "x.client_name",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "mailbox_permissions",
        table: "mailbox_permissions",
        hint: "'user'",
        ids: &[("upn", "x.grantee_upn")],
        display: "NULL",
        guest: NO_GUEST,
        filter: "true",
    },
    Source {
        label: "admin_audit_events",
        table: "admin_audit_events",
        hint: "'user'",
        ids: &[("upn", "x.caller")],
        display: "NULL",
        guest: NO_GUEST,
        filter: "x.caller LIKE '%@%'",
    },
];

impl Source {
    /// Distinct observations with their row counts:
    /// `tenant_key, hint, id_0, id_1, display_name, guest, n`, ordered by the identifiers.
    fn sql(&self) -> String {
        let ids: Vec<String> = (0..2)
            .map(|i| match self.ids.get(i) {
                Some((_, expr)) => format!("nullif(lower(trim({expr})), '')"),
                None => "CAST(NULL AS VARCHAR)".to_string(),
            })
            .collect();
        format!(
            "SELECT c.tenant_key, {hint} AS hint, {id0} AS id0, {id1} AS id1,
                    nullif(trim({display}), '') AS display_name, {guest} AS guest, count(*) AS n
             FROM {table} x JOIN collections c ON c.collection_id = x.collection_id
             WHERE {filter}
             GROUP BY ALL
             ORDER BY id0, id1, tenant_key, hint, display_name, guest",
            hint = self.hint,
            id0 = ids[0],
            id1 = ids[1],
            display = self.display,
            guest = self.guest,
            table = self.table,
            filter = self.filter,
        )
    }
}

/// Everything recorded about one `(alias_type, value)` node.
#[derive(Default)]
struct NodeInfo {
    sources: BTreeSet<&'static str>,
}

/// Everything recorded about one observation, attached to its first node.
struct Obs {
    node: usize,
    label: &'static str,
    tenant: Option<String>,
    hint: String,
    display: Option<String>,
    guest: bool,
    n: i64,
}

struct Graph {
    keys: Vec<(&'static str, String)>,
    index: HashMap<(&'static str, String), usize>,
    info: Vec<NodeInfo>,
    parent: Vec<usize>,
    /// Per root: the object id / app id the component holds (at most one each: merges that
    /// would bring a second one are refused).
    object_id: Vec<Option<String>>,
    app_id: Vec<Option<String>>,
    conflicts: BTreeSet<(usize, usize)>,
}

impl Graph {
    fn new() -> Self {
        Graph {
            keys: Vec::new(),
            index: HashMap::new(),
            info: Vec::new(),
            parent: Vec::new(),
            object_id: Vec::new(),
            app_id: Vec::new(),
            conflicts: BTreeSet::new(),
        }
    }

    fn node(&mut self, ty: &'static str, value: String) -> usize {
        if let Some(&i) = self.index.get(&(ty, value.clone())) {
            return i;
        }
        let i = self.keys.len();
        self.object_id
            .push((ty == "object_id").then(|| value.clone()));
        self.app_id.push((ty == "app_id").then(|| value.clone()));
        self.keys.push((ty, value.clone()));
        self.index.insert((ty, value), i);
        self.info.push(NodeInfo::default());
        self.parent.push(i);
        i
    }

    fn find(&mut self, mut i: usize) -> usize {
        while self.parent[i] != i {
            self.parent[i] = self.parent[self.parent[i]];
            i = self.parent[i];
        }
        i
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return;
        }
        let clash =
            |x: &Option<String>, y: &Option<String>| matches!((x, y), (Some(x), Some(y)) if x != y);
        if clash(&self.object_id[ra], &self.object_id[rb])
            || clash(&self.app_id[ra], &self.app_id[rb])
        {
            self.conflicts.insert((a.min(b), a.max(b)));
            return;
        }
        // The older root (smaller index) stays the root.
        let (root, child) = if ra < rb { (ra, rb) } else { (rb, ra) };
        self.parent[child] = root;
        if self.object_id[root].is_none() {
            self.object_id[root] = self.object_id[child].take();
        }
        if self.app_id[root].is_none() {
            self.app_id[root] = self.app_id[child].take();
        }
    }
}

#[derive(Serialize)]
struct IdentityRow {
    identity_id: String,
    tenant_key: Option<String>,
    kind: &'static str,
    upn: Option<String>,
    object_id: Option<String>,
    puid: Option<String>,
    app_id: Option<String>,
    display_names: Vec<String>,
    sources: Vec<&'static str>,
    aliases: usize,
}

#[derive(Serialize)]
struct AliasRow {
    alias_type: &'static str,
    alias: String,
    identity_id: String,
    sources: Vec<&'static str>,
}

/// Rebuild `identities` and `identity_aliases` from the evidence tables.
pub fn rebuild(conn: &Connection) -> Result<IdentityOutcome> {
    let mut graph = Graph::new();
    let mut observations = Vec::new();
    for source in SOURCES {
        let mut stmt = conn.prepare(&source.sql())?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let mut nodes = Vec::with_capacity(2);
            for (i, (ty, _)) in source.ids.iter().enumerate() {
                if let Some(v) = r.get::<_, Option<String>>(2 + i)? {
                    let node = graph.node(ty, v);
                    graph.info[node].sources.insert(source.label);
                    nodes.push(node);
                }
            }
            let Some(&first) = nodes.first() else {
                continue;
            };
            for &other in &nodes[1..] {
                graph.union(first, other);
            }
            observations.push(Obs {
                node: first,
                label: source.label,
                tenant: r.get(0)?,
                hint: r.get(1)?,
                display: r.get(4)?,
                guest: r.get(5)?,
                n: r.get(6)?,
            });
        }
    }

    // Components, keyed by root.
    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..graph.keys.len() {
        let root = graph.find(i);
        members.entry(root).or_default().push(i);
    }
    let mut obs_by_root: HashMap<usize, Vec<&Obs>> = HashMap::new();
    for o in &observations {
        let root = graph.find(o.node);
        obs_by_root.entry(root).or_default().push(o);
    }
    let domains = tenant_domains(conn)?;

    let mut identities = Vec::with_capacity(members.len());
    let mut aliases = Vec::with_capacity(graph.keys.len());
    for (root, nodes) in &members {
        let mut by_type: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for &i in nodes {
            let (ty, v) = &graph.keys[i];
            by_type.entry(ty).or_default().insert(v.as_str());
        }
        let smallest = |ty: &str| {
            by_type
                .get(ty)
                .and_then(|s| s.first())
                .map(|v| v.to_string())
        };
        let identity_id = TYPES
            .iter()
            .find_map(|ty| smallest(ty).map(|v| format!("{ty}:{v}")))
            .expect("a component has at least one node");

        let obs = obs_by_root.get(root).map(Vec::as_slice).unwrap_or(&[]);
        let mut tenant_counts: BTreeMap<&str, i64> = BTreeMap::new();
        let mut display_names = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut guest = false;
        let mut hint = HINTS.len() - 1;
        for o in obs {
            if let Some(t) = &o.tenant {
                *tenant_counts.entry(t.as_str()).or_default() += o.n;
            }
            if let Some(d) = &o.display {
                display_names.insert(d.clone());
            }
            sources.insert(o.label);
            guest |= o.guest;
            if let Some(h) = HINTS.iter().position(|h| *h == o.hint) {
                hint = hint.min(h);
            }
        }
        // Most observations; smallest key on a tie (BTreeMap order + strict comparison).
        let tenant_key = tenant_counts
            .iter()
            .fold(None::<(&str, i64)>, |best, (&t, &n)| match best {
                Some((_, bn)) if bn >= n => best,
                _ => Some((t, n)),
            })
            .map(|(t, _)| t.to_string());

        let upns = by_type.get("upn");
        let ext_upn = upns.is_some_and(|s| s.iter().any(|u| u.contains("#ext#")));
        let foreign = match (upns, tenant_key.as_deref().and_then(|t| domains.get(t))) {
            (Some(upns), Some(own)) if !own.is_empty() => !upns
                .iter()
                .any(|u| u.rsplit_once('@').is_some_and(|(_, d)| own.contains(d))),
            _ => false,
        };
        let kind = if ext_upn || guest || foreign {
            "external"
        } else {
            HINTS[hint]
        };

        for &i in nodes {
            let (ty, v) = &graph.keys[i];
            aliases.push(AliasRow {
                alias_type: ty,
                alias: v.clone(),
                identity_id: identity_id.clone(),
                sources: graph.info[i].sources.iter().copied().collect(),
            });
        }
        identities.push(IdentityRow {
            identity_id,
            tenant_key,
            kind,
            upn: smallest("upn"),
            object_id: smallest("object_id"),
            puid: smallest("puid"),
            app_id: smallest("app_id"),
            display_names: display_names.into_iter().collect(),
            sources: sources.into_iter().collect(),
            aliases: nodes.len(),
        });
    }
    identities.sort_by(|a, b| a.identity_id.cmp(&b.identity_id));
    aliases.sort_by(|a, b| (a.alias_type, &a.alias).cmp(&(b.alias_type, &b.alias)));

    conn.execute("DELETE FROM identities", [])?;
    conn.execute("DELETE FROM identity_aliases", [])?;
    conn.execute(
        "INSERT INTO identities (identity_id, tenant_key, kind, upn, object_id, puid, app_id,
             display_names, sources, aliases)
         SELECT identity_id, tenant_key, kind, upn, object_id, puid, app_id, display_names, sources, aliases
         FROM (SELECT unnest(from_json(?, '[{\"identity_id\": \"VARCHAR\", \"tenant_key\": \"VARCHAR\",
                 \"kind\": \"VARCHAR\", \"upn\": \"VARCHAR\", \"object_id\": \"VARCHAR\", \"puid\": \"VARCHAR\",
                 \"app_id\": \"VARCHAR\", \"display_names\": [\"VARCHAR\"], \"sources\": [\"VARCHAR\"],
                 \"aliases\": \"INTEGER\"}]'), recursive := true))",
        params![to_json(&identities)?],
    )?;
    conn.execute(
        "INSERT INTO identity_aliases (alias_type, alias, identity_id, sources)
         SELECT alias_type, alias, identity_id, sources
         FROM (SELECT unnest(from_json(?, '[{\"alias_type\": \"VARCHAR\", \"alias\": \"VARCHAR\",
                 \"identity_id\": \"VARCHAR\", \"sources\": [\"VARCHAR\"]}]'), recursive := true))",
        params![to_json(&aliases)?],
    )?;

    Ok(IdentityOutcome {
        identities: identities.len(),
        aliases: aliases.len(),
        conflicts: graph.conflicts.len(),
    })
}

fn to_json<T: Serialize>(rows: &T) -> Result<String> {
    serde_json::to_string(rows).map_err(|e| Error::Invalid(format!("identity rows: {e}")))
}

/// `tenant_key -> {domain}` from `tenant_domains` (lower-cased).
fn tenant_domains(conn: &Connection) -> Result<HashMap<String, BTreeSet<String>>> {
    let mut stmt = conn.prepare("SELECT tenant_key, lower(trim(domain)) FROM tenant_domains")?;
    let mut rows = stmt.query([])?;
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    while let Some(r) = rows.next()? {
        let (t, d): (String, String) = (r.get(0)?, r.get(1)?);
        out.entry(t).or_default().insert(d);
    }
    Ok(out)
}
