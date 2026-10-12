//! Persistent workspace metadata over the sealed artifact store.
//!
//! Bytes live only in `artifacts` (via `attachments::upload/read`); this
//! crate resolves paths and versions so user-supplied strings never become
//! server paths. All functions are owner-scoped: foreign IDs are `NotFound`
//! (404), stale revisions and name collisions are `Conflict` (409).
//!
//! Schema: `migrations/0037_os_workspace.sql` (`workspace_entries`,
//! `workspace_versions`, `workspace_mounts`).

use chrono::{DateTime, Utc};
use orbit_core::{Error, OwnerScope, Result};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
pub mod mounts;
pub mod staging;

/// Entry kind: mutable file pointer or directory node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntryKind {
    File,
    Directory,
}

impl EntryKind {
    fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "FILE",
            EntryKind::Directory => "DIRECTORY",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "FILE" => Ok(EntryKind::File),
            "DIRECTORY" => Ok(EntryKind::Directory),
            other => Err(Error::Validation(format!("unknown entry kind {other}"))),
        }
    }
}

/// Metadata row for one workspace entry.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkspaceEntry {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub kind: String,
    pub head_artifact_id: Option<Uuid>,
    pub revision: i64,
    pub trashed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkspaceEntry {
    pub fn entry_kind(&self) -> Result<EntryKind> {
        EntryKind::parse(&self.kind)
    }

    pub fn is_trashed(&self) -> bool {
        self.trashed_at.is_some()
    }
}

/// One immutable content version of a file entry.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkspaceVersion {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub entry_id: Uuid,
    pub revision: i64,
    pub artifact_id: Uuid,
    pub created_by_task_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Reject empty, absolute, traversal, NUL, separator, or overlong names.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::Validation("name must not be empty".into()));
    }
    if name.len() > 255 {
        return Err(Error::Validation("name exceeds 255 bytes".into()));
    }
    if name.contains('\0') {
        return Err(Error::Validation("name must not contain NUL".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(Error::Validation(
            "name must not contain path separators".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(Error::Validation(
            "name must not be a traversal segment".into(),
        ));
    }
    if name.chars().any(|c| c == '\n' || c == '\r') {
        return Err(Error::Validation(
            "name must not contain control characters".into(),
        ));
    }
    Ok(())
}

async fn get_entry(pool: &PgPool, scope: &OwnerScope, id: Uuid) -> Result<WorkspaceEntry> {
    sqlx::query_as::<_, WorkspaceEntry>(
        "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
         FROM workspace_entries WHERE owner_id = $1 AND id = $2",
    )
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

async fn check_artifact_owned(
    pool: &PgPool,
    scope: &OwnerScope,
    artifact_id: Uuid,
) -> Result<()> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM artifacts WHERE owner_id = $1 AND id = $2",
    )
    .bind(scope.owner_id)
    .bind(artifact_id)
    .fetch_optional(pool)
    .await?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

/// Resolve a path (sequence of child names) from the owner root.
pub async fn resolve(
    pool: &PgPool,
    scope: &OwnerScope,
    path_parts: &[String],
) -> Result<WorkspaceEntry> {
    let root = sqlx::query_as::<_, WorkspaceEntry>(
        "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
         FROM workspace_entries WHERE owner_id = $1 AND parent_id IS NULL AND trashed_at IS NULL",
    )
    .bind(scope.owner_id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)?;
    let mut current = root;
    for part in path_parts {
        validate_name(part)?;
        let next = sqlx::query_as::<_, WorkspaceEntry>(
            "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
             FROM workspace_entries
             WHERE owner_id = $1 AND parent_id = $2 AND name = $3 AND trashed_at IS NULL",
        )
        .bind(scope.owner_id)
        .bind(current.id)
        .bind(part)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::NotFound)?;
        current = next;
    }
    Ok(current)
}

/// List non-trashed children of a directory, ordered by name, with id-cursor pagination.
pub async fn children(
    pool: &PgPool,
    scope: &OwnerScope,
    entry: &WorkspaceEntry,
    limit: i64,
    cursor: Option<Uuid>,
) -> Result<Vec<WorkspaceEntry>> {
    let limit = limit.clamp(1, 100);
    let entry = get_entry(pool, scope, entry.id).await?;
    if entry.entry_kind()? != EntryKind::Directory {
        return Err(Error::Validation("entry is not a directory".into()));
    }
    if let Some(cursor_id) = cursor {
        let anchor = get_entry(pool, scope, cursor_id).await?;
        Ok(sqlx::query_as::<_, WorkspaceEntry>(
            "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
             FROM workspace_entries
             WHERE owner_id = $1 AND parent_id = $2 AND trashed_at IS NULL AND name > $3
             ORDER BY name ASC LIMIT $4",
        )
        .bind(scope.owner_id)
        .bind(entry.id)
        .bind(anchor.name)
        .bind(limit)
        .fetch_all(pool)
        .await?)
    } else {
        Ok(sqlx::query_as::<_, WorkspaceEntry>(
            "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
             FROM workspace_entries
             WHERE owner_id = $1 AND parent_id = $2 AND trashed_at IS NULL
             ORDER BY name ASC LIMIT $3",
        )
        .bind(scope.owner_id)
        .bind(entry.id)
        .bind(limit)
        .fetch_all(pool)
        .await?)
    }
}

/// Create a file or directory under `parent_id`.
pub async fn create(
    pool: &PgPool,
    scope: &OwnerScope,
    parent_id: Uuid,
    name: &str,
    kind: EntryKind,
    artifact_id: Option<Uuid>,
) -> Result<WorkspaceEntry> {
    validate_name(name)?;
    let parent = get_entry(pool, scope, parent_id).await?;
    if parent.entry_kind()? != EntryKind::Directory {
        return Err(Error::Validation("parent is not a directory".into()));
    }
    if parent.is_trashed() {
        return Err(Error::Validation("parent is trashed".into()));
    }
    if kind == EntryKind::Directory && artifact_id.is_some() {
        return Err(Error::Validation(
            "directories cannot carry an artifact".into(),
        ));
    }
    if let Some(artifact) = artifact_id {
        check_artifact_owned(pool, scope, artifact).await?;
    }
    let id = Uuid::new_v4();
    let row = sqlx::query_as::<_, WorkspaceEntry>(
        "INSERT INTO workspace_entries (id, owner_id, parent_id, name, kind, head_artifact_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at",
    )
    .bind(id)
    .bind(scope.owner_id)
    .bind(parent_id)
    .bind(name)
    .bind(kind.as_str())
    .bind(artifact_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db) = &e {
            if db.is_unique_violation() {
                return Error::Conflict("name already exists".into());
            }
        }
        Error::from(e)
    })?;
    if kind == EntryKind::File && artifact_id.is_some() {
        record_version(pool, scope, &row, artifact_id.expect("checked"), None).await?;
        return get_entry(pool, scope, row.id).await;
    }
    Ok(row)
}

/// Rename and/or move an entry; `expected_revision` guards against lost updates.
/// Rejects cycles (moving a directory under itself or a descendant).
pub async fn rename_move(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    expected_revision: i64,
    name: Option<&str>,
    parent_id: Option<Uuid>,
) -> Result<WorkspaceEntry> {
    let entry = get_entry(pool, scope, id).await?;
    if entry.parent_id.is_none() {
        return Err(Error::Validation("workspace root cannot be moved".into()));
    }
    let new_name = match name {
        Some(n) => {
            validate_name(n)?;
            n.to_string()
        }
        None => entry.name.clone(),
    };
    let new_parent_id = match parent_id {
        Some(p) => p,
        None => entry
            .parent_id
            .ok_or_else(|| Error::Validation("workspace root cannot be moved".into()))?,
    };
    if Some(new_parent_id) != entry.parent_id || name.is_some() {
        let parent = get_entry(pool, scope, new_parent_id).await?;
        if parent.entry_kind()? != EntryKind::Directory {
            return Err(Error::Validation("parent is not a directory".into()));
        }
        if parent.is_trashed() {
            return Err(Error::Validation("parent is trashed".into()));
        }
        // Cycle check: walk up from the destination; it must never reach `id`.
        let mut cursor = Some(new_parent_id);
        while let Some(current) = cursor {
            if current == id {
                return Err(Error::Validation(
                    "cannot move an entry under itself or a descendant".into(),
                ));
            }
            let row: Option<(Option<Uuid>,)> =
                sqlx::query_as("SELECT parent_id FROM workspace_entries WHERE owner_id = $1 AND id = $2")
                    .bind(scope.owner_id)
                    .bind(current)
                    .fetch_optional(pool)
                    .await?;
            cursor = row.and_then(|r| r.0);
        }
    }
    let updated = sqlx::query_as::<_, WorkspaceEntry>(
        "UPDATE workspace_entries
         SET parent_id = $3, name = $4, revision = revision + 1, updated_at = now()
         WHERE owner_id = $1 AND id = $2 AND revision = $5
         RETURNING id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at",
    )
    .bind(scope.owner_id)
    .bind(id)
    .bind(new_parent_id)
    .bind(&new_name)
    .bind(expected_revision)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db) = &e {
            if db.is_unique_violation() {
                return Error::Conflict("name already exists".into());
            }
        }
        Error::from(e)
    })?;
    match updated {
        Some(row) => Ok(row),
        None => Err(stale_or_missing(pool, scope, id, expected_revision).await),
    }
}
async fn stale_or_missing(pool: &PgPool, scope: &OwnerScope, id: Uuid, expected: i64) -> Error {
    match get_entry(pool, scope, id).await {
        Ok(entry) if entry.revision != expected => {
            Error::Conflict("stale revision: entry changed".into())
        }
        Ok(_) => Error::Conflict("stale revision".into()),
        Err(e) => e,
    }
}

/// Point a file entry at a new head artifact and record a version row.
/// Caller-created versions (initial create / restore) use [`record_version`] directly.
pub async fn set_content(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    expected_revision: i64,
    artifact_id: Uuid,
) -> Result<WorkspaceEntry> {
    check_artifact_owned(pool, scope, artifact_id).await?;
    let mut tx = pool.begin().await?;
    let entry: Option<WorkspaceEntry> = sqlx::query_as::<_, WorkspaceEntry>(
        "SELECT id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at
         FROM workspace_entries WHERE owner_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let entry = entry.ok_or(Error::NotFound)?;
    if entry.entry_kind()? != EntryKind::File {
        return Err(Error::Validation("entry is not a file".into()));
    }
    if entry.is_trashed() {
        return Err(Error::Validation("entry is trashed".into()));
    }
    if entry.revision != expected_revision {
        return Err(Error::Conflict("stale revision: entry changed".into()));
    }
    let new_revision = entry.revision + 1;
    sqlx::query(
        "UPDATE workspace_entries SET head_artifact_id = $3, revision = $4, updated_at = now()
         WHERE owner_id = $1 AND id = $2",
    )
    .bind(scope.owner_id)
    .bind(id)
    .bind(artifact_id)
    .bind(new_revision)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO workspace_versions (id, owner_id, entry_id, revision, artifact_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(scope.owner_id)
    .bind(id)
    .bind(new_revision)
    .bind(artifact_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    get_entry(pool, scope, id).await
}

async fn record_version(
    pool: &PgPool,
    scope: &OwnerScope,
    entry: &WorkspaceEntry,
    artifact_id: Uuid,
    created_by_task_id: Option<Uuid>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO workspace_versions (id, owner_id, entry_id, revision, artifact_id, created_by_task_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (owner_id, entry_id, revision) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(scope.owner_id)
    .bind(entry.id)
    .bind(entry.revision)
    .bind(artifact_id)
    .bind(created_by_task_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Logically delete an entry (reversible via [`restore`]).
pub async fn trash(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    expected_revision: i64,
) -> Result<WorkspaceEntry> {
    let entry = get_entry(pool, scope, id).await?;
    if entry.parent_id.is_none() {
        return Err(Error::Validation("workspace root cannot be trashed".into()));
    }
    if entry.is_trashed() {
        return Err(Error::Validation("entry is already trashed".into()));
    }
    if entry.revision != expected_revision {
        return Err(Error::Conflict("stale revision: entry changed".into()));
    }
    sqlx::query_as::<_, WorkspaceEntry>(
        "UPDATE workspace_entries SET trashed_at = now(), revision = revision + 1, updated_at = now()
         WHERE owner_id = $1 AND id = $2 AND revision = $3
         RETURNING id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at",
    )
    .bind(scope.owner_id)
    .bind(id)
    .bind(expected_revision)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::Conflict("stale revision: entry changed".into()))
}

/// Reverse [`trash`]; fails with 409 if an active sibling reuses the name.
pub async fn restore(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    expected_revision: i64,
) -> Result<WorkspaceEntry> {
    let entry = get_entry(pool, scope, id).await?;
    if !entry.is_trashed() {
        return Err(Error::Validation("entry is not trashed".into()));
    }
    if entry.revision != expected_revision {
        return Err(Error::Conflict("stale revision: entry changed".into()));
    }
    sqlx::query_as::<_, WorkspaceEntry>(
        "UPDATE workspace_entries SET trashed_at = NULL, revision = revision + 1, updated_at = now()
         WHERE owner_id = $1 AND id = $2 AND revision = $3
         RETURNING id, owner_id, parent_id, name, kind, head_artifact_id, revision, trashed_at, created_at, updated_at",
    )
    .bind(scope.owner_id)
    .bind(id)
    .bind(expected_revision)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db) = &e {
            if db.is_unique_violation() {
                return Error::Conflict("name already exists".into());
            }
        }
        Error::from(e)
    })?
    .ok_or(Error::Conflict("stale revision: entry changed".into()))
}

/// List versions of a file entry, newest first.
pub async fn versions(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
) -> Result<Vec<WorkspaceVersion>> {
    let entry = get_entry(pool, scope, id).await?;
    Ok(sqlx::query_as::<_, WorkspaceVersion>(
        "SELECT id, owner_id, entry_id, revision, artifact_id, created_by_task_id, created_at
         FROM workspace_versions WHERE owner_id = $1 AND entry_id = $2 ORDER BY revision DESC",
    )
    .bind(scope.owner_id)
    .bind(entry.id)
    .fetch_all(pool)
    .await?)
}

/// Restore the head pointer to a prior version's artifact (CAS on `expected_revision`).
pub async fn restore_version(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    expected_revision: i64,
    version_id: Uuid,
) -> Result<WorkspaceEntry> {
    let entry = get_entry(pool, scope, id).await?;
    if entry.entry_kind()? != EntryKind::File {
        return Err(Error::Validation("entry is not a file".into()));
    }
    let version = sqlx::query_as::<_, WorkspaceVersion>(
        "SELECT id, owner_id, entry_id, revision, artifact_id, created_by_task_id, created_at
         FROM workspace_versions WHERE owner_id = $1 AND id = $2 AND entry_id = $3",
    )
    .bind(scope.owner_id)
    .bind(version_id)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)?;
    set_content(pool, scope, id, expected_revision, version.artifact_id).await
}
