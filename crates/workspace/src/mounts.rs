//! Mount resolution over `workspace_mounts`.
//!
//! A mount alias resolves to its `(node_id, root_id, mode)` grant. Resolution
//! is fail-closed:
//!
//! - Unknown or foreign alias is `NotFound` (404); aliases are owner-scoped,
//!   so one owner can never resolve another owner's mount.
//! - A mount whose node root is revoked (or whose grant row is gone) is
//!   `Unavailable` with a `MOUNT_REVOKED` marker.
//! - A mount whose node is revoked, missing, or past its heartbeat is
//!   `Unavailable` with a `NODE_OFFLINE` marker. Callers MUST surface the
//!   outage and MUST NOT fall back to cached or direct host writes: an
//!   offline mount has no execution target, so there is nothing to write
//!   through and any locally cached bytes would silently diverge.
//! - Writes additionally pass [`MountTarget::require_write`]: a `READ` mount
//!   rejects mutations, and a `WRITE` mount over a non-`READ_WRITE` root
//!   (e.g. `READ` or per-operation `ASK`) is refused rather than widened.
//!
//! Grant broadening happens only on the node itself (local owner CLI); the
//! node reports its grants and the server records them. There is
//! intentionally no server-side broaden endpoint: the server can only revoke
//! or narrow a reported root, never create or widen one.
//!
//! Files copied from a mount into the workspace MUST carry node/root/path/
//! version provenance in the artifact's `source_references` (see
//! [`MountTarget::copy_provenance`], validated by
//! [`require_mount_provenance`]). The `node_id`/`root_id` keys keep the
//! sealed-store grant check (`validate_file_sources`) enforcing the live
//! root grant on every later read.

use chrono::{DateTime, Utc};
use orbit_core::{Error, OwnerScope, Result};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// A node whose last heartbeat is older than this counts as disconnected,
/// mirroring `computers::OFFLINE_AFTER` (60 s).
const OFFLINE_AFTER_SECONDS: i64 = 60;

/// A workspace mount alias resolved to its live node grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountTarget {
    pub id: Uuid,
    pub alias: String,
    pub node_id: Uuid,
    pub root_id: Uuid,
    /// Mount mode: `READ` or `WRITE` (from `workspace_mounts`).
    pub mode: String,
    pub revision: i64,
    /// Live mode of the underlying node root: `READ`/`READ_WRITE`/`ASK`.
    pub root_mode: String,
    /// Live revision of the underlying node root.
    pub root_revision: i64,
}

impl MountTarget {
    pub fn writable(&self) -> bool {
        self.mode == "WRITE"
    }

    /// Gate a mutation through this mount. A `READ` mount rejects writes
    /// outright, and a `WRITE` mount must not exceed its root grant: only a
    /// `READ_WRITE` root carries standing write authority (`ASK` roots need
    /// the per-operation approval path, not a standing mount).
    pub fn require_write(&self) -> Result<()> {
        if !self.writable() {
            return Err(Error::Forbidden);
        }
        if self.root_mode != "READ_WRITE" {
            return Err(Error::Forbidden);
        }
        Ok(())
    }

    /// Provenance marker to store in the artifact's `source_references` when
    /// bytes are copied from this mount into the workspace. Carries the
    /// node/root/path/version tuple so later reads re-check the live grant.
    pub fn copy_provenance(&self, path: &str, version: &str) -> serde_json::Value {
        serde_json::json!([{
            "kind": "MOUNT_COPY",
            "mount_alias": self.alias,
            "node_id": self.node_id,
            "root_id": self.root_id,
            "path": path,
            "version": version,
        }])
    }
}

/// Resolve `alias` to its `(node_id, root_id, mode)` grant for `scope`.
///
/// Owner-scoped: a foreign alias is `NotFound`. Revoked or missing grants
/// and offline nodes are `Unavailable` (`MOUNT_REVOKED` / `NODE_OFFLINE`),
/// never a degraded cached target.
pub async fn resolve_mount(
    pool: &PgPool,
    scope: &OwnerScope,
    alias: &str,
) -> Result<MountTarget> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Err(Error::Validation("mount alias must not be empty".into()));
    }
    let row: (Uuid, String, Uuid, Uuid, String, i64) = sqlx::query_as(
        "SELECT id, alias, node_id, root_id, mode, revision
         FROM workspace_mounts WHERE owner_id = $1 AND alias = $2",
    )
    .bind(scope.owner_id)
    .bind(alias)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)?;
    let (id, alias, node_id, root_id, mode, revision) = row;
    if mode != "READ" && mode != "WRITE" {
        return Err(Error::Conflict("mount carries an unknown mode".into()));
    }
    // The grant row must still exist and be unrevoked; a mount whose root
    // grant is gone (deleted or revoked) is revoked, not readable.
    let root = sqlx::query(
        "SELECT mode, revision, revoked FROM computer_roots
         WHERE owner_id = $1 AND node_id = $2 AND id = $3",
    )
    .bind(scope.owner_id)
    .bind(node_id)
    .bind(root_id)
    .fetch_optional(pool)
    .await?;
    let root = match root {
        Some(root) if !root.get::<bool, _>("revoked") => root,
        _ => {
            return Err(Error::Unavailable(
                "MOUNT_REVOKED: mount root is revoked or no longer granted".into(),
            ));
        }
    };
    let root_mode: String = root.get("mode");
    let root_revision: i64 = root.get("revision");
    // A revoked or missing node revokes the mount; a node past its heartbeat
    // is offline. Either way there is no execution target to write through.
    let node = sqlx::query(
        "SELECT revoked_at, last_seen FROM computer_nodes
         WHERE owner_id = $1 AND id = $2",
    )
    .bind(scope.owner_id)
    .bind(node_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| Error::Unavailable("MOUNT_REVOKED: mount node is gone".into()))?;
    if node
        .get::<Option<DateTime<Utc>>, _>("revoked_at")
        .is_some()
    {
        return Err(Error::Unavailable(
            "MOUNT_REVOKED: mount node is revoked".into(),
        ));
    }
    let online = node
        .get::<Option<DateTime<Utc>>, _>("last_seen")
        .is_some_and(|seen| (Utc::now() - seen).num_seconds() < OFFLINE_AFTER_SECONDS);
    if !online {
        return Err(Error::Unavailable(
            "NODE_OFFLINE: mount node is not connected; refusing cached host writes".into(),
        ));
    }
    Ok(MountTarget {
        id,
        alias,
        node_id,
        root_id,
        mode,
        revision,
        root_mode,
        root_revision,
    })
}

/// Resolve `alias` and gate it for mutation: revocation/liveness first, then
/// the mount/root write-mode check. Returns the target on success.
pub async fn resolve_mount_for_write(
    pool: &PgPool,
    scope: &OwnerScope,
    alias: &str,
) -> Result<MountTarget> {
    let target = resolve_mount(pool, scope, alias).await?;
    target.require_write()?;
    Ok(target)
}

/// Require node/root/path/version provenance in an artifact's
/// `source_references` before treating it as a mount copy. Every copied file
/// must record where its bytes came from so later reads re-check the live
/// root grant instead of trusting a bare content hash.
pub fn require_mount_provenance(source: &serde_json::Value) -> Result<()> {
    let references = source
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![source.clone()]);
    let ok = references.iter().any(|reference| {
        reference
            .get("node_id")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
            && reference
                .get("root_id")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
            && reference
                .get("path")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
            && reference
                .get("version")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
    });
    if ok {
        Ok(())
    } else {
        Err(Error::Validation(
            "mount copy requires node/root/path/version provenance".into(),
        ))
    }
}
