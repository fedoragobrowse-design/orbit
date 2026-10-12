//! Persistent workspace metadata over the sealed artifact store.
//!
//! Bytes live only in `artifacts` (sealed, immutable, owner-scoped); this
//! module owns the mutable namespace: `workspace_entries` (FILE|DIRECTORY
//! tree with per-entry revision pins), `workspace_versions` (FILE content
//! history pointing at artifact rows), and `workspace_mounts` (explicit
//! aliases onto computer-node roots). User-supplied strings never become
//! server paths — every lookup is by UUID under owner scope.
//!
//! Scope note: the lazy seed creates `/workspace` plus Inbox/Projects/
//! Outputs/Trash; Inbox starts empty and imports land here going forward
//! (existing artifacts are not relinked).
use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, patch, post, put},
};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

const MAX_NAME_LEN: usize = 255;
const MAX_LIST: i64 = 200;
const SEED_CHILDREN: [&str; 4] = ["Inbox", "Projects", "Outputs", "Trash"];

fn check_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::Validation(
            "entry name must be 1-255 bytes".into(),
        ));
    }
    if name.contains('\0')
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
        || name.chars().any(char::is_control)
    {
        return Err(Error::Validation("invalid entry name".into()));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct TreeQuery {
    pub parent_id: Option<Uuid>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntryCreate {
    pub parent_id: Uuid,
    pub name: String,
    pub kind: String,
    pub artifact_id: Option<Uuid>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct EntryPatch {
    pub expected_revision: i64,
    pub name: Option<String>,
    pub parent_id: Option<Uuid>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentPut {
    pub expected_revision: i64,
    pub artifact_id: Uuid,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionPin {
    pub expected_revision: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionRestore {
    pub expected_revision: i64,
    pub version_id: Uuid,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MountCreate {
    pub alias: String,
    pub node_id: Uuid,
    pub root_id: Uuid,
    pub mode: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MountPatch {
    pub expected_revision: i64,
    pub alias: Option<String>,
    pub mode: Option<String>,
}

/// Ensure the owner's private tree (`/workspace` + four fixed children).
/// Idempotent: concurrent first calls converge on the same rows via
/// `ON CONFLICT DO NOTHING` over advisory-free unique guards.
async fn ensure_seed(
    tx: &mut Transaction<'_, Postgres>,
    owner: Uuid,
) -> Result<Uuid, Error> {
    let root: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM workspace_entries WHERE owner_id=$1 AND parent_id IS NULL AND trashed_at IS NULL LIMIT 1",
    )
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await?;
    let root_id = match root {
        Some(id) => id,
        None => {
            let id = Uuid::new_v4();
            // Owner root row (name ''), guarded by the partial unique index.
            sqlx::query(
                "INSERT INTO workspace_entries(id,owner_id,parent_id,name,kind) VALUES($1,$2,NULL,'','DIRECTORY') ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(owner)
            .execute(&mut **tx)
            .await?;
            sqlx::query_scalar(
                "SELECT id FROM workspace_entries WHERE owner_id=$1 AND parent_id IS NULL AND trashed_at IS NULL LIMIT 1",
            )
            .bind(owner)
            .fetch_one(&mut **tx)
            .await?
        }
    };
    for child in SEED_CHILDREN {
        let child_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO workspace_entries(id,owner_id,parent_id,name,kind) VALUES($1,$2,$3,$4,'DIRECTORY') ON CONFLICT DO NOTHING",
        )
        .bind(child_id)
        .bind(owner)
        .bind(root_id)
        .bind(child)
        .execute(&mut **tx)
        .await?;
    }
    Ok(root_id)
}

fn entry_view(
    id: Uuid,
    parent_id: Option<Uuid>,
    name: &str,
    kind: &str,
    head: Option<Uuid>,
    revision: i64,
    trashed: bool,
) -> Value {
    json!({
        "id": id, "parent_id": parent_id, "name": name, "kind": kind,
        "head_artifact_id": head, "revision": revision, "trashed": trashed,
    })
}

fn row_view(r: &sqlx::postgres::PgRow) -> Result<Value, Error> {
    Ok(entry_view(
        r.try_get::<Uuid, _>("id")?,
        r.try_get::<Option<Uuid>, _>("parent_id")?,
        &r.try_get::<String, _>("name").unwrap_or_default(),
        &r.try_get::<String, _>("kind").unwrap_or_default(),
        r.try_get::<Option<Uuid>, _>("head_artifact_id")?,
        r.try_get::<i64, _>("revision").unwrap_or(1),
        r.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
            .is_some(),
    ))
}

const ENTRY_COLS: &str =
    "id,parent_id,name,kind,head_artifact_id,revision,trashed_at";

async fn load_entry(
    pool: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
) -> Result<sqlx::postgres::PgRow, Error> {
    sqlx::query(&format!(
        "SELECT {ENTRY_COLS} FROM workspace_entries WHERE owner_id=$1 AND id=$2"
    ))
    .bind(owner)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

async fn check_artifact(pool: &sqlx::PgPool, owner: Uuid, id: Uuid) -> Result<(), Error> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*)::int8 FROM artifacts WHERE owner_id=$1 AND id=$2")
        .bind(owner)
        .bind(id)
        .fetch_one(pool)
        .await?;
    if n == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Reject cycles: `candidate` must not equal `entry` nor descend from it.
async fn check_no_cycle(
    pool: &sqlx::PgPool,
    owner: Uuid,
    entry: Uuid,
    candidate_parent: Uuid,
) -> Result<(), Error> {
    if candidate_parent == entry {
        return Err(Error::Validation("cannot move an entry into itself".into()));
    }
    let hit: Option<Uuid> = sqlx::query_scalar(
        "WITH RECURSIVE down(id) AS (SELECT $2::uuid UNION ALL SELECT e.id FROM workspace_entries e JOIN down d ON e.parent_id=d.id WHERE e.owner_id=$1) SELECT id FROM down WHERE id=$3 LIMIT 1",
    )
    .bind(owner)
    .bind(entry)
    .bind(candidate_parent)
    .fetch_optional(pool)
    .await?;
    if hit.is_some() {
        return Err(Error::Validation("cannot move an entry under its own child".into()));
    }
    Ok(())
}

fn as_conflict(e: sqlx::Error) -> Error {
    if let sqlx::Error::Database(d) = &e {
        if d.code().as_deref() == Some("23505") {
            return Error::Conflict("name already exists in this folder".into());
        }
    }
    Error::Database(e)
}

#[utoipa::path(get, path = "/api/v1/workspace/tree", responses((status = 200, body = Value)))]
pub async fn tree(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<TreeQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = q.limit.unwrap_or(100).clamp(1, MAX_LIST);
    let mut tx = state.pool.begin().await?;
    let root_id = ensure_seed(&mut tx, a.scope.owner_id).await?;
    let parent = q.parent_id.unwrap_or(root_id);
    // Foreign IDs are 404 (never leak cross-owner rows).
    let prow = sqlx::query(&format!(
        "SELECT {ENTRY_COLS} FROM workspace_entries WHERE owner_id=$1 AND id=$2"
    ))
    .bind(a.scope.owner_id)
    .bind(parent)
    .fetch_optional(&mut *tx)
    .await?;
    let prow = prow.ok_or(Error::NotFound)?;
    if prow.try_get::<String, _>("kind").unwrap_or_default() != "DIRECTORY" {
        return Err(Error::Validation("parent is not a directory".into()).into());
    }
    let rows = if let Some(cursor) = q.cursor {
        sqlx::query(&format!(
            "SELECT {ENTRY_COLS} FROM workspace_entries WHERE owner_id=$1 AND parent_id=$2 AND trashed_at IS NULL AND (name,id)>(SELECT name,id FROM workspace_entries WHERE owner_id=$1 AND id=$4) ORDER BY name,id LIMIT $3"
        ))
        .bind(a.scope.owner_id)
        .bind(parent)
        .bind(limit)
        .bind(cursor)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(&format!(
            "SELECT {ENTRY_COLS} FROM workspace_entries WHERE owner_id=$1 AND parent_id=$2 AND trashed_at IS NULL ORDER BY name,id LIMIT $3"
        ))
        .bind(a.scope.owner_id)
        .bind(parent)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?
    };
    let mut items = Vec::with_capacity(rows.len());
    for r in &rows {
        items.push(row_view(r)?);
    }
    let next_cursor = rows.last().and_then(|r| r.try_get::<Uuid, _>("id").ok());
    tx.commit().await?;
    Ok(Json(json!({"parent_id": parent, "items": items, "next_cursor": next_cursor})))
}

#[utoipa::path(post, path = "/api/v1/workspace/entries", request_body = EntryCreate, responses((status = 200, body = Value)))]
pub async fn create_entry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<EntryCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    check_name(&input.name)?;
    if input.kind != "FILE" && input.kind != "DIRECTORY" {
        return Err(Error::Validation("kind must be FILE or DIRECTORY".into()).into());
    }
    if input.kind == "DIRECTORY" && input.artifact_id.is_some() {
        return Err(Error::Validation("directories take no artifact".into()).into());
    }
    let parent = load_entry(&state.pool, a.scope.owner_id, input.parent_id).await?;
    if parent.try_get::<String, _>("kind").unwrap_or_default() != "DIRECTORY" {
        return Err(Error::Validation("parent is not a directory".into()).into());
    }
    if parent
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
        .is_some()
    {
        return Err(Error::Validation("parent is trashed".into()).into());
    }
    if let Some(art) = input.artifact_id {
        check_artifact(&state.pool, a.scope.owner_id, art).await?;
    }
    let id = Uuid::new_v4();
    let row = sqlx::query(&format!(
        "INSERT INTO workspace_entries(id,owner_id,parent_id,name,kind,head_artifact_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING {ENTRY_COLS}"
    ))
    .bind(id)
    .bind(a.scope.owner_id)
    .bind(input.parent_id)
    .bind(&input.name)
    .bind(&input.kind)
    .bind(input.artifact_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(as_conflict)?;
    let row = row.ok_or(Error::Conflict("name already exists in this folder".into()))?;
    if input.kind == "FILE" {
        if let Some(art) = input.artifact_id {
            sqlx::query(
                "INSERT INTO workspace_versions(id,owner_id,entry_id,revision,artifact_id) VALUES($1,$2,$3,1,$4)",
            )
            .bind(Uuid::new_v4())
            .bind(a.scope.owner_id)
            .bind(id)
            .bind(art)
            .execute(&state.pool)
            .await?;
        }
    }
    Ok(Json(row_view(&row)?))
}

#[utoipa::path(patch, path = "/api/v1/workspace/entries/{id}", request_body = EntryPatch, responses((status = 200, body = Value)))]
pub async fn patch_entry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<EntryPatch>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if input.name.is_none() && input.parent_id.is_none() {
        return Err(Error::Validation("patch needs name and/or parent_id".into()).into());
    }
    if let Some(name) = &input.name {
        check_name(name)?;
    }
    let cur = load_entry(&state.pool, a.scope.owner_id, id).await?;
    if cur.try_get::<i64, _>("revision").unwrap_or(0) != input.expected_revision {
        return Err(Error::Conflict("stale revision".into()).into());
    }
    if cur
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
        .is_some()
    {
        return Err(Error::Validation("entry is trashed".into()).into());
    }
    if cur.try_get::<Option<Uuid>, _>("parent_id")?.is_none() {
        return Err(Error::Validation("cannot rename or move the workspace root".into()).into());
    }
    let new_parent = match input.parent_id {
        Some(p) => {
            let prow = load_entry(&state.pool, a.scope.owner_id, p).await?;
            if prow.try_get::<String, _>("kind").unwrap_or_default() != "DIRECTORY" {
                return Err(Error::Validation("parent is not a directory".into()).into());
            }
            if prow
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
                .is_some()
            {
                return Err(Error::Validation("parent is trashed".into()).into());
            }
            check_no_cycle(&state.pool, a.scope.owner_id, id, p).await?;
            Some(p)
        }
        None => None,
    };
    let new_name = input.name.clone().unwrap_or_else(|| {
        cur.try_get::<String, _>("name").unwrap_or_default()
    });
    let row = sqlx::query(&format!(
        "UPDATE workspace_entries SET name=$3,parent_id=COALESCE($4,parent_id),revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5 RETURNING {ENTRY_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(&new_name)
    .bind(new_parent)
    .bind(input.expected_revision)
    .fetch_optional(&state.pool)
    .await
    .map_err(as_conflict)?;
    let row = row.ok_or(Error::Conflict("stale revision or name collision".into()))?;
    Ok(Json(row_view(&row)?))
}

#[utoipa::path(put, path = "/api/v1/workspace/entries/{id}/content", request_body = ContentPut, responses((status = 200, body = Value)))]
pub async fn put_content(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ContentPut>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    check_artifact(&state.pool, a.scope.owner_id, input.artifact_id).await?;
    let size: i64 = sqlx::query_scalar("SELECT size FROM artifacts WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(input.artifact_id)
        .fetch_one(&state.pool)
        .await?;
    if size > 10 * 1024 * 1024 {
        return Err(Error::Validation("artifact too large (10 MiB max)".into()).into());
    }
    let cur = load_entry(&state.pool, a.scope.owner_id, id).await?;
    if cur.try_get::<String, _>("kind").unwrap_or_default() != "FILE" {
        return Err(Error::Validation("only files take content".into()).into());
    }
    if cur
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
        .is_some()
    {
        return Err(Error::Validation("entry is trashed".into()).into());
    }
    let row = sqlx::query(&format!(
        "UPDATE workspace_entries SET head_artifact_id=$3,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$4 RETURNING {ENTRY_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.artifact_id)
    .bind(input.expected_revision)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or(Error::Conflict("stale revision".into()))?;
    let revision = row.try_get::<i64, _>("revision").unwrap_or(input.expected_revision + 1);
    sqlx::query(
        "INSERT INTO workspace_versions(id,owner_id,entry_id,revision,artifact_id) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(revision)
    .bind(input.artifact_id)
    .execute(&state.pool)
    .await?;
    Ok(Json(row_view(&row)?))
}

#[utoipa::path(post, path = "/api/v1/workspace/entries/{id}/trash", request_body = RevisionPin, responses((status = 200, body = Value)))]
pub async fn trash_entry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionPin>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let cur = load_entry(&state.pool, a.scope.owner_id, id).await?;
    if cur.try_get::<Option<Uuid>, _>("parent_id")?.is_none() {
        return Err(Error::Validation("cannot trash the workspace root".into()).into());
    }
    let row = sqlx::query(&format!(
        "UPDATE workspace_entries SET trashed_at=now(),revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$3 AND trashed_at IS NULL RETURNING {ENTRY_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or(Error::Conflict("stale revision".into()))?;
    Ok(Json(row_view(&row)?))
}

#[utoipa::path(post, path = "/api/v1/workspace/entries/{id}/restore", request_body = RevisionPin, responses((status = 200, body = Value)))]
pub async fn restore_entry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionPin>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let cur = load_entry(&state.pool, a.scope.owner_id, id).await?;
    if cur
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
        .is_none()
    {
        return Err(Error::Validation("entry is not trashed".into()).into());
    }
    let row = sqlx::query(&format!(
        "UPDATE workspace_entries SET trashed_at=NULL,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$3 RETURNING {ENTRY_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .fetch_optional(&state.pool)
    .await
    .map_err(as_conflict)?;
    let row = row.ok_or(Error::Conflict(
        "stale revision or name collision on restore".into(),
    ))?;
    Ok(Json(row_view(&row)?))
}

#[utoipa::path(get, path = "/api/v1/workspace/entries/{id}/versions", responses((status = 200, body = Value)))]
pub async fn list_versions(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    load_entry(&state.pool, a.scope.owner_id, id).await?;
    let rows = sqlx::query(
        "SELECT id,revision,artifact_id,created_by_task_id,created_at FROM workspace_versions WHERE owner_id=$1 AND entry_id=$2 ORDER BY revision DESC,id DESC LIMIT 200",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for r in &rows {
        items.push(json!({
            "id": r.try_get::<Uuid, _>("id")?,
            "revision": r.try_get::<i64, _>("revision").unwrap_or(0),
            "artifact_id": r.try_get::<Uuid, _>("artifact_id")?,
            "created_by_task_id": r.try_get::<Option<Uuid>, _>("created_by_task_id")?,
            "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok(),
        }));
    }
    Ok(Json(json!({"entry_id": id, "items": items})))
}

#[utoipa::path(post, path = "/api/v1/workspace/entries/{id}/restore-version", request_body = VersionRestore, responses((status = 200, body = Value)))]
pub async fn restore_version(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<VersionRestore>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let cur = load_entry(&state.pool, a.scope.owner_id, id).await?;
    if cur.try_get::<String, _>("kind").unwrap_or_default() != "FILE" {
        return Err(Error::Validation("only files have versions".into()).into());
    }
    if cur
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("trashed_at")?
        .is_some()
    {
        return Err(Error::Validation("entry is trashed".into()).into());
    }
    let art: Option<Uuid> = sqlx::query_scalar(
        "SELECT artifact_id FROM workspace_versions WHERE owner_id=$1 AND entry_id=$2 AND id=$3",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.version_id)
    .fetch_optional(&state.pool)
    .await?;
    let art = art.ok_or(Error::NotFound)?;
    let row = sqlx::query(&format!(
        "UPDATE workspace_entries SET head_artifact_id=$3,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$4 RETURNING {ENTRY_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(art)
    .bind(input.expected_revision)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or(Error::Conflict("stale revision".into()))?;
    let revision = row.try_get::<i64, _>("revision").unwrap_or(input.expected_revision + 1);
    sqlx::query(
        "INSERT INTO workspace_versions(id,owner_id,entry_id,revision,artifact_id) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(revision)
    .bind(art)
    .execute(&state.pool)
    .await?;
    Ok(Json(row_view(&row)?))
}

fn check_alias(alias: &str) -> Result<(), Error> {
    if alias.is_empty() || alias.len() > 64 {
        return Err(Error::Validation("mount alias must be 1-64 bytes".into()));
    }
    if alias.contains('\0')
        || alias.contains('/')
        || alias.contains('\\')
        || alias == "."
        || alias == ".."
        || alias.chars().any(char::is_control)
    {
        return Err(Error::Validation("invalid mount alias".into()));
    }
    Ok(())
}

fn mount_view(
    id: Uuid,
    alias: &str,
    node: Uuid,
    root: Uuid,
    mode: &str,
    revision: i64,
) -> Value {
    json!({"id": id, "alias": alias, "node_id": node, "root_id": root, "mode": mode, "revision": revision})
}

#[utoipa::path(get, path = "/api/v1/workspace/mounts", responses((status = 200, body = Value)))]
pub async fn list_mounts(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query(
        "SELECT id,alias,node_id,root_id,mode,revision FROM workspace_mounts WHERE owner_id=$1 ORDER BY alias,id LIMIT 200",
    )
    .bind(a.scope.owner_id)
    .fetch_all(&state.pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for r in &rows {
        items.push(mount_view(
            r.try_get::<Uuid, _>("id")?,
            &r.try_get::<String, _>("alias").unwrap_or_default(),
            r.try_get::<Uuid, _>("node_id")?,
            r.try_get::<Uuid, _>("root_id")?,
            &r.try_get::<String, _>("mode").unwrap_or_default(),
            r.try_get::<i64, _>("revision").unwrap_or(1),
        ));
    }
    Ok(Json(json!({"items": items})))
}

#[utoipa::path(post, path = "/api/v1/workspace/mounts", request_body = MountCreate, responses((status = 200, body = Value)))]
pub async fn create_mount(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<MountCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    check_alias(&input.alias)?;
    if input.mode != "READ" && input.mode != "WRITE" {
        return Err(Error::Validation("mode must be READ or WRITE".into()).into());
    }
    // Mounts resolve through computer-node root grants; a missing or revoked
    // root is 404/validation rather than a cached host write.
    let root: Option<(bool,)> = sqlx::query_as(
        "SELECT (revoked) FROM computer_roots WHERE owner_id=$1 AND node_id=$2 AND id=$3",
    )
    .bind(a.scope.owner_id)
    .bind(input.node_id)
    .bind(input.root_id)
    .fetch_optional(&state.pool)
    .await?;
    let (revoked,) = root.ok_or(Error::NotFound)?;
    if revoked {
        return Err(Error::Validation("node root is revoked".into()).into());
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workspace_mounts(id,owner_id,alias,node_id,root_id,mode) VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(a.scope.owner_id)
    .bind(&input.alias)
    .bind(input.node_id)
    .bind(input.root_id)
    .bind(&input.mode)
    .execute(&state.pool)
    .await
    .map_err(as_conflict)?;
    Ok(Json(mount_view(
        id,
        &input.alias,
        input.node_id,
        input.root_id,
        &input.mode,
        1,
    )))
}

#[utoipa::path(patch, path = "/api/v1/workspace/mounts/{id}", request_body = MountPatch, responses((status = 200, body = Value)))]
pub async fn patch_mount(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<MountPatch>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if input.alias.is_none() && input.mode.is_none() {
        return Err(Error::Validation("patch needs alias and/or mode".into()).into());
    }
    if let Some(alias) = &input.alias {
        check_alias(alias)?;
    }
    if let Some(mode) = &input.mode {
        if mode != "READ" && mode != "WRITE" {
            return Err(Error::Validation("mode must be READ or WRITE".into()).into());
        }
    }
    let row = sqlx::query(
        "UPDATE workspace_mounts SET alias=COALESCE($3,alias),mode=COALESCE($4,mode),revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5 RETURNING id,alias,node_id,root_id,mode,revision",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.alias.as_deref())
    .bind(input.mode.as_deref())
    .bind(input.expected_revision)
    .fetch_optional(&state.pool)
    .await
    .map_err(as_conflict)?;
    let Some(row) = row else {
        // Distinguish foreign IDs (404) from stale revisions (409); a name
        // collision already surfaced as 409 above via `as_conflict`.
        let exists: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::int8 FROM workspace_mounts WHERE owner_id=$1 AND id=$2")
                .bind(a.scope.owner_id)
                .bind(id)
                .fetch_one(&state.pool)
                .await?;
        if exists == 0 {
            return Err(Error::NotFound.into());
        }
        return Err(Error::Conflict("stale revision".into()).into());
    };
    Ok(Json(mount_view(
        row.try_get::<Uuid, _>("id")?,
        &row.try_get::<String, _>("alias").unwrap_or_default(),
        row.try_get::<Uuid, _>("node_id")?,
        row.try_get::<Uuid, _>("root_id")?,
        &row.try_get::<String, _>("mode").unwrap_or_default(),
        row.try_get::<i64, _>("revision").unwrap_or(1),
    )))
}

#[utoipa::path(delete, path = "/api/v1/workspace/mounts/{id}", responses((status = 200, body = Value)))]
pub async fn delete_mount(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let done = sqlx::query("DELETE FROM workspace_mounts WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if done == 0 {
        return Err(Error::NotFound.into());
    }
    Ok(Json(json!({"removed": id})))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    tree,
    create_entry,
    patch_entry,
    put_content,
    trash_entry,
    restore_entry,
    list_versions,
    restore_version,
    list_mounts,
    create_mount,
    patch_mount,
    delete_mount
))]
pub struct WorkspaceApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/workspace/tree", get(tree))
        .route("/api/v1/workspace/entries", post(create_entry))
        .route("/api/v1/workspace/entries/{id}", patch(patch_entry))
        .route("/api/v1/workspace/entries/{id}/content", put(put_content))
        .route("/api/v1/workspace/entries/{id}/trash", post(trash_entry))
        .route("/api/v1/workspace/entries/{id}/restore", post(restore_entry))
        .route("/api/v1/workspace/entries/{id}/versions", get(list_versions))
        .route(
            "/api/v1/workspace/entries/{id}/restore-version",
            post(restore_version),
        )
        .route("/api/v1/workspace/mounts", get(list_mounts).post(create_mount))
        .route("/api/v1/workspace/mounts/{id}", patch(patch_mount).delete(delete_mount))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn workspace_names_reject_traversal_and_separators() {
        for bad in ["", ".", "..", "a/b", "a\\b", "a\0b", "a\nb", "a/b/../c"] {
            assert!(check_name(bad).is_err(), "accepts {bad:?}");
        }
        assert!(check_name("notes.txt").is_ok());
        assert!(check_name(&"x".repeat(256)).is_err());
    }
    #[test]
    fn mount_alias_and_mode_bounds() {
        assert!(check_alias("").is_err());
        assert!(check_alias("../x").is_err());
        assert!(check_alias("photos").is_ok());
    }
}
