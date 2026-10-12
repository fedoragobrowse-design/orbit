//! Owner/agent workspace search + entry trust/provenance helpers shared by
//! the `orbit-data.workspace_*` tool arms.
//!
//! Search is a bounded `ILIKE` over entry names (owner-scoped, non-trashed)
//! plus entry/artifacts lookups for read. Provenance is the entry identity
//! plus the sealed head-artifact identity (including node/root mount
//! references from `attachments` source data); trust is `OWNER` for
//! agent-generated content with no external source references and
//! `UNTRUSTED_EXTERNAL` once an entry's head artifact carries node/mount
//! (imported) provenance.

use orbit_core::{OwnerScope, Result};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use orbit_workspace::WorkspaceEntry;

/// Trust label for one entry. Reads/search surface this; mutations record it.
pub fn trust_of_entry(entry: &WorkspaceEntry, source: &Value) -> &'static str {
    if has_external_source(source) {
        "UNTRUSTED_EXTERNAL"
    } else if entry.head_artifact_id.is_some() {
        "OWNER"
    } else {
        "OWNER"
    }
}

/// Structured provenance: entry identity + revision + head artifact +
/// mount/node source references from the sealed store.
pub fn provenance_json(entry: &WorkspaceEntry, source: &Value) -> Value {
    json!({
        "entry_id": entry.id,
        "revision": entry.revision,
        "artifact_id": entry.head_artifact_id,
        "name": entry.name,
        "kind": entry.kind,
        "source_references": source,
    })
}

pub fn has_external_source(source: &Value) -> bool {
    let refs = source
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![source.clone()]);
    refs.iter().any(|r| {
        r.get("node_id").is_some()
            || r.get("root_id").is_some()
            || matches!(
                r.get("kind").and_then(Value::as_str),
                Some("NODE_IMPORT") | Some("BROWSER_DOWNLOAD") | Some("EXTERNAL")
            )
    })
}

/// Fetch the sealed `source_references` for an entry's head artifact.
/// Entries without a head artifact yield `Null` (no external provenance).
pub async fn head_source(
    pool: &PgPool,
    scope: &OwnerScope,
    entry: &WorkspaceEntry,
) -> Result<Value> {
    match entry.head_artifact_id {
        None => Ok(Value::Null),
        Some(aid) => {
            let source: Option<Value> = sqlx::query_scalar(
                "SELECT source_references FROM artifacts WHERE owner_id=$1 AND id=$2",
            )
            .bind(scope.owner_id)
            .bind(aid)
            .fetch_optional(pool)
            .await?;
            Ok(source.unwrap_or(Value::Null))
        }
    }
}

/// Bounded owner-scoped name search over non-trashed entries.
pub async fn search_entries(
    pool: &PgPool,
    scope: &OwnerScope,
    query: &str,
    limit: i64,
) -> Result<Vec<WorkspaceEntry>> {
    let limit = limit.clamp(1, 50);
    let pattern = format!("%{}%", query.replace(['%', '_'], ""));
    Ok(sqlx::query_as::<_, WorkspaceEntry>(
        "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
         FROM workspace_entries
         WHERE owner_id = $1 AND trashed_at IS NULL AND name ILIKE $2
         ORDER BY name ASC LIMIT $3",
    )
    .bind(scope.owner_id)
    .bind(pattern)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

/// Resolve one entry id with owner scoping. Foreign ids are `NotFound` (404).
pub async fn entry_by_id(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
) -> Result<WorkspaceEntry> {
    sqlx::query_as::<_, WorkspaceEntry>(
        "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
         FROM workspace_entries WHERE owner_id = $1 AND id = $2",
    )
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(orbit_core::Error::NotFound)
}
