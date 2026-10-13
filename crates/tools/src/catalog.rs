//! Hybrid action catalog: one ranked search surface over every tool the
//! caller may actually invoke, plus the two gateway descriptors that carry
//! it (`search_actions`, `execute_action`).
//!
//! Scope: discovery only. The catalog filters the already-registered
//! descriptors by (a) the registry `enabled` flag, (b) enabled owning
//! connections (MCP rows join their connection; HA-gated names require an
//! enabled `ha_connections` row), and (c) the caller's agent `allowed_tools`
//! grant list when one is supplied. Discovery is never authorization:
//! [`execute_action`] re-enters the normal propose/submit pipeline, so
//! schema, risk, policy, approval, and lease/fence checks all still run.
//! An empty allowlist stays empty — there is no fallback grant.
//!
//! Legacy names (`memory.*`, `shell.*`, `browser.*`, `files.*`, `email.*`,
//! `mcp.*` without the connection segment) never match catalog entries;
//! deliberately migrate allowlists instead (see migration 0041 notes).

use orbit_core::{Error, Result, ToolDescriptor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use uuid::Uuid;

/// One catalog row: the registry name agents execute plus the service that
/// owns it. `service` is the registry-name prefix (`orbit-control`,
/// `orbit-data`, `ha-control`, `mcp`, `memory`, `shell`, `browser`,
/// `files`, `email`) so per-service UIs can group without parsing names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub action_id: String,
    pub service: String,
    pub tool_name: String,
    pub version: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

/// Legacy registry names that no longer resolve. Kept as a deliberate
/// migration list: allowlists carrying these names must be rewritten to the
/// namespaced equivalents, never silently re-admitted.
pub const LEGACY_NAMES: &[&str] = &[
    "memory.search",
    "memory.propose",
    "shell.execute",
    "browser.navigate",
    "browser.fill_submit",
    "browser.session.open",
    "browser.session.snapshot",
    "browser.session.navigate",
    "browser.session.click",
    "browser.session.fill",
    "browser.session.submit",
    "browser.session.download",
    "browser.session.close",
    "files.search",
    "files.read",
    "files.list",
    "files.metadata",
    "files.watch",
    "files.write",
    "files.move",
    "files.copy",
    "email.search",
    "email.read",
    "email.draft",
    "email.send",
    "email.archive",
    "email.label",
];

/// Namespaced replacements for [`LEGACY_NAMES`], applied in order. `mcp.*`
/// entries have no static mapping (the connection segment is per-owner) and
/// stay for the owner to re-grant explicitly.
pub const LEGACY_REPLACEMENTS: &[(&str, &str)] = &[
    ("memory.search", "orbit-data.memory_search"),
    ("memory.propose", "orbit-data.memory_search"),
    ("files.list", "orbit-data.files_list"),
    ("files.search", "orbit-data.workspace_search"),
    ("files.read", "orbit-data.workspace_read"),
    ("files.metadata", "orbit-data.workspace_read"),
    ("files.watch", "orbit-data.workspace_list"),
    ("email.search", "orbit-data.mail_read"),
    ("email.read", "orbit-data.mail_read"),
];

/// Map one legacy name to its replacement, if one exists.
pub fn migrate_name(name: &str) -> Option<&'static str> {
    LEGACY_REPLACEMENTS
        .iter()
        .find(|(legacy, _)| *legacy == name)
        .map(|(_, next)| *next)
}

/// Rewrite an allowlist to namespaced names. Returns the migrated list plus
/// the names that were dropped (unmapped legacy names and anything still
/// unknown). The caller's empty list stays empty: no default grants are
/// ever added.
pub fn migrate_allowlist(allowed: &[String]) -> (Vec<String>, Vec<String>) {
    let mut migrated = Vec::with_capacity(allowed.len());
    let mut dropped = Vec::new();
    for name in allowed {
        if LEGACY_NAMES.contains(&name.as_str()) {
            match migrate_name(name) {
                Some(next) => {
                    if !migrated.iter().any(|n| n == next) {
                        migrated.push(next.to_owned());
                    }
                }
                None => dropped.push(name.clone()),
            }
        } else {
            migrated.push(name.clone());
        }
    }
    (migrated, dropped)
}

fn service_of(name: &str) -> String {
    name.split('.')
        .next()
        .unwrap_or("orbit-control")
        .to_owned()
}

fn describe(name: &str) -> Option<String> {
    let text = match name {
        n if n == "orbit-control.search_actions" => {
            "Ranked search over the caller's executable action catalog."
        }
        n if n == "orbit-control.execute_action" => {
            "Execute one catalog action by id; re-enters propose/submit with full policy checks."
        }
        n if n.starts_with("orbit-control.") => return None,
        n if n.starts_with("orbit-data.") => return None,
        n if n.starts_with("ha-control.") => return None,
        n if n.starts_with("mcp.") => return None,
        _ => return None,
    };
    Some(text.to_owned())
}

fn entry_of(descriptor: &ToolDescriptor) -> CatalogEntry {
    CatalogEntry {
        action_id: descriptor.name.clone(),
        service: service_of(&descriptor.name),
        tool_name: descriptor.name.clone(),
        version: descriptor.version.clone(),
        description: describe(&descriptor.name),
        input_schema: descriptor.input_schema.clone(),
    }
}

/// Build the caller's catalog: registered + enabled descriptors, minus rows
/// whose owning connection is disabled, minus names outside the caller's
/// grant list. `allowed` of `None` means "no agent grant context" (gateway
/// owner surface): every enabled row is discoverable. `Some(list)` filters
/// to exactly that list; an empty list yields an empty catalog.
pub async fn build_catalog(
    pool: &PgPool,
    owner: Uuid,
    allowed: Option<&[String]>,
) -> Result<Vec<CatalogEntry>> {
    let grants: Option<HashSet<&str>> =
        allowed.map(|list| list.iter().map(String::as_str).collect());
    let rows = sqlx::query(
        "SELECT r.descriptor, r.name, COALESCE(c.enabled, true) AS conn_enabled \
         FROM tool_registry r LEFT JOIN mcp_tools t ON t.owner_id=r.owner_id AND t.registry_name=r.name \
         LEFT JOIN mcp_connections c ON c.owner_id=t.owner_id AND c.id=t.connection_id \
         WHERE r.owner_id=$1 AND r.enabled ORDER BY r.name",
    )
    .bind(owner)
    .fetch_all(pool)
    .await?;
    let ha_live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ha_connections WHERE owner_id=$1 AND enabled)",
    )
    .bind(owner)
    .fetch_one(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        if !row.get::<bool, _>("conn_enabled") {
            continue;
        }
        let name: String = row.get("name");
        if name.starts_with("ha-control.") && !ha_live {
            continue;
        }
        if let Some(grants) = &grants {
            if !grants.contains(name.as_str()) {
                continue;
            }
        }
        let descriptor: ToolDescriptor = serde_json::from_value(row.get("descriptor"))?;
        if descriptor.name != name {
            return Err(Error::Forbidden);
        }
        out.push(entry_of(&descriptor));
    }
    // The two gateway tools are catalog-native: they exist exactly when the
    // caller may use them, under the same grant rule as everything else.
    for gateway in gateway_descriptors() {
        if let Some(grants) = &grants {
            if !grants.contains(gateway.name.as_str()) {
                continue;
            }
        }
        out.push(entry_of(&gateway));
    }
    out.sort_by(|a, b| a.action_id.cmp(&b.action_id));
    out.dedup_by(|a, b| a.action_id == b.action_id);
    Ok(out)
}

/// Resolve one action id against an already-built catalog.
pub fn resolve<'a>(catalog: &'a [CatalogEntry], action_id: &str) -> Option<&'a CatalogEntry> {
    catalog.iter().find(|entry| entry.action_id == action_id)
}

/// Ranked search over a built catalog. Token-overlap scoring (query tokens
/// matched against action id + service + description), exact-name hits
/// first, then prefix, then score, then name. `limit` clamps to 1..=10.
pub fn search(catalog: &[CatalogEntry], query: &str, limit: usize) -> Vec<CatalogEntry> {
    let limit = limit.clamp(1, 10);
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return vec![];
    }
    let tokens: Vec<&str> = query.split_whitespace().collect();
    let mut scored: Vec<(u64, &CatalogEntry)> = Vec::new();
    for entry in catalog {
        let hay = format!(
            "{} {} {}",
            entry.action_id.to_lowercase().replace(['.', '_'], " "),
            entry.service.to_lowercase(),
            entry.description.clone().unwrap_or_default().to_lowercase()
        );
        if entry.action_id.eq_ignore_ascii_case(&query) {
            scored.push((u64::MAX, entry));
            continue;
        }
        let mut score = 0u64;
        if entry.action_id.to_lowercase().starts_with(&query) {
            score += 1_000;
        }
        for token in &tokens {
            if hay.contains(token) {
                score += 100;
            } else {
                // Partial credit for a 4+ char prefix hit keeps typo-adjacent
                // queries ("worksapce") from going silently empty.
                let stem = if token.len() > 4 { &token[..4] } else { *token };
                if hay.contains(stem) {
                    score += 10;
                }
            }
        }
        // Promote the two gateway tools plus docs/ask_owner so the
        // always-available helpers surface for vague queries ("help").
        if matches!(
            entry.action_id.as_str(),
            "orbit-control.search_actions"
                | "orbit-control.execute_action"
                | "orbit-control.docs_read"
                | "orbit-control.ask_owner"
        ) {
            score += 5;
        }
        if score > 0 {
            scored.push((score, entry));
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.action_id.cmp(&b.1.action_id)));
    scored
        .into_iter()
        .take(limit)
        .map(|(_, entry)| entry.clone())
        .collect()
}

/// The two gateway tools. Ids 60/61 (SkillsLoad owns 14; agreed split).
/// `execute_action` carries no executor here: the gateway handler resolves
/// the id against [`build_catalog`] output and re-enters propose/submit.
pub fn gateway_descriptors() -> Vec<ToolDescriptor> {
    let effects = orbit_core::ToolEffects {
        external: false,
        modifies_data: true,
        reversible: true,
        credential_access: false,
        affected_party: "OWNER".into(),
        network: false,
    };
    vec![
        ToolDescriptor {
            id: Uuid::from_u128(60),
            name: "orbit-control.search_actions".into(),
            version: "1".into(),
            input_schema: json!({"type":"object","additionalProperties":false,"required":["query"],"properties":{"query":{"type":"string","minLength":1,"maxLength":500},"limit":{"type":"integer","minimum":1,"maximum":10}}}),
            output_schema: json!({"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","items":{"type":"object"}}}}),
            effects: effects.clone(),
            default_risk: orbit_core::RiskLevel::Low,
            permission_keys: vec!["orbit-control.search_actions".into()],
            sandbox_required: false,
        },
        ToolDescriptor {
            id: Uuid::from_u128(61),
            name: "orbit-control.execute_action".into(),
            version: "1".into(),
            input_schema: json!({"type":"object","additionalProperties":false,"required":["action_id","arguments"],"properties":{"action_id":{"type":"string","minLength":1,"maxLength":256},"arguments":{"type":"object"},"task_id":{"type":"string","format":"uuid"},"idempotency_key":{"type":"string","minLength":1,"maxLength":128}}}),
            output_schema: json!({"type":"object","additionalProperties":false,"required":["call_id","state"],"properties":{"call_id":{"type":"string","format":"uuid"},"state":{"type":"string"},"approval_id":{"type":"string","format":"uuid"},"result":{"type":"object"},"error_code":{"type":"string"}}}),
            effects,
            default_risk: orbit_core::RiskLevel::Medium,
            permission_keys: vec!["orbit-control.execute_action".into()],
            sandbox_required: false,
        },
    ]
}

/// Request bodies for the gateway HTTP handlers. `deny_unknown_fields`
/// matches the gateway convention. `ToSchema` keeps the utoipa OpenAPI
/// derive compiling at the gateway call site.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchActionsInput {
    pub query: String,
    pub limit: Option<i64>,
}
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecuteActionInput {
    pub action_id: String,
    pub arguments: Value,
    pub task_id: Option<Uuid>,
    pub idempotency_key: Option<String>,
}
