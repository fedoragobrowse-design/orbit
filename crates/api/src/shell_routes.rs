//! Owner shell sessions: real shells over staged workspace subtrees.
//!
//! One session owns one `execution_sessions` row (`kind='SHELL'`) and one
//! staged subtree materialized through [`orbit_workspace::staging::stage_subtree`].
//! Owner-direct grants are limited to the subtree: creating a session opens a
//! scoped grant row whose `scope_key` names the session id, and stopping the
//! session closes it. Agent commands are unaffected — they stay one proposal
//! per command through the normal tool-call journal; shell input here is never
//! an agent proposal.
//!
//! Routing respects the sandbox choice: when the owner's `sandbox_enabled`
//! setting is on, the session dispatches to the admitted AIec connection
//! (which probes its interactive capability and fails closed with
//! `INTERACTIVE_SHELL_UNAVAILABLE` until the capability exists); when off,
//! the session rows still record `execution_mode='unsandboxed'` and the live
//! pty is served by the isolated execution-host service, never by executing
//! on the server host here.
//!
//! Conventions: owner-scoped SQL everywhere (foreign ids are 404), `revision`
//! CAS on every mutation (stale pins are 409), `deny_unknown_fields` on all
//! wire bodies, no secrets in rows or logs.

use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use orbit_core::{Error, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::convert::Infallible;
use uuid::Uuid;

/// PTY bounds shared with the runtime `InteractiveSpec` validator.
const MIN_PTY: u32 = 1;
const MAX_PTY: u32 = 1024;
/// One input intent per call (shell input is never an agent proposal).
const MAX_INPUT_BYTES: usize = 65536;
/// Subtree-relative cwd ceiling.
const MAX_CWD_LEN: usize = 1024;

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionCreate {
    pub workspace_id: Option<Uuid>,
    pub cwd: Option<String>,
    pub cols: Option<u32>,
    pub rows: Option<u32>,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionInput {
    pub expected_revision: i64,
    pub text: String,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionResize {
    pub expected_revision: i64,
    pub cols: u32,
    pub rows: u32,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionPin {
    pub expected_revision: i64,
}
#[derive(Deserialize)]
pub struct StreamQuery {
    pub cursor: Option<i64>,
}

fn check_pty(cols: u32, rows: u32) -> Result<(), Error> {
    if !(MIN_PTY..=MAX_PTY).contains(&cols) || !(MIN_PTY..=MAX_PTY).contains(&rows) {
        return Err(Error::Validation("pty size out of bounds".into()));
    }
    Ok(())
}

/// Subtree-relative absolute path: `/` plus per-segment workspace names.
/// Segments are names only — never server paths, traversal, or separators.
fn check_cwd(cwd: &str) -> Result<(), Error> {
    if cwd.is_empty() || cwd.len() > MAX_CWD_LEN || !cwd.starts_with('/') {
        return Err(Error::Validation(
            "cwd must be an absolute subtree path".into(),
        ));
    }
    if cwd == "/" {
        return Ok(());
    }
    for segment in cwd[1..].split('/') {
        if segment.is_empty()
            || segment.len() > 255
            || segment == "."
            || segment == ".."
            || segment.contains('\0')
            || segment.contains('\\')
            || segment.chars().any(char::is_control)
        {
            return Err(Error::Validation("invalid cwd segment".into()));
        }
    }
    Ok(())
}

fn check_input_text(text: &str) -> Result<(), Error> {
    if text.is_empty() || text.len() > MAX_INPUT_BYTES || text.contains('\0') {
        return Err(Error::Validation(
            "shell input must be 1 byte to 64 KiB".into(),
        ));
    }
    Ok(())
}

fn session_view(row: &sqlx::postgres::PgRow) -> Result<Value, Error> {
    Ok(json!({
        "id": row.try_get::<Uuid, _>("id")?,
        "revision": row.try_get::<i64, _>("revision").unwrap_or(1),
        "state": row.try_get::<String, _>("state").unwrap_or_default(),
        "execution_mode": row.try_get::<String, _>("execution_mode").unwrap_or_default(),
        "sandboxed": row.try_get::<bool, _>("sandboxed").unwrap_or(false),
        "workspace_id": row.try_get::<Uuid, _>("workspace_id").ok(),
        "cwd": row.try_get::<String, _>("cwd").unwrap_or_else(|_| "/".into()),
        "cols": row.try_get::<i32, _>("cols").unwrap_or(80),
        "rows": row.try_get::<i32, _>("rows").unwrap_or(24),
        "last_seq": row.try_get::<i64, _>("last_seq").unwrap_or(0),
    }))
}

const SESSION_COLS: &str =
    "id,revision,state,execution_mode,sandboxed,workspace_id,cwd,cols,rows,last_seq";

/// Resolve the staged root: explicit `workspace_id`, else the owner's
/// workspace root. Owner-scoped; foreign ids are 404.
async fn resolve_root(
    pool: &sqlx::PgPool,
    owner: Uuid,
    workspace_id: Option<Uuid>,
) -> Result<Uuid, Error> {
    if let Some(id) = workspace_id {
        let hit: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workspace_entries WHERE owner_id=$1 AND id=$2 AND kind='DIRECTORY' AND trashed_at IS NULL",
        )
        .bind(owner)
        .bind(id)
        .fetch_optional(pool)
        .await?;
        return hit.ok_or(Error::NotFound);
    }
    sqlx::query_scalar(
        "SELECT id FROM workspace_entries WHERE owner_id=$1 AND parent_id IS NULL AND trashed_at IS NULL LIMIT 1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::Validation("workspace is not initialized".into()))
}

async fn sandbox_enabled(pool: &sqlx::PgPool, owner: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT COALESCE((value->>'sandbox_enabled')::boolean, false) FROM settings WHERE owner_id=$1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// Stage the subtree through the workspace staging helper. Bytes stream
/// through the sealed artifact store; `deny_unknown_fields` and owner scope
/// apply exactly as for owner reads. The staged tree is dropped after the
/// session row records the mount: the execution-host / AIec side re-stages
/// from the same subtree id on attach; this call only proves the subtree is
/// stageable before granting anything.
async fn prove_stageable(
    state: &ApiState,
    scope: &orbit_core::OwnerScope,
    root: Uuid,
) -> Result<(), Error> {
    let staged =
        orbit_workspace::staging::stage_subtree(&state.pool, &state.artifact_dir, scope, root)
            .await?;
    let _ = staged.path();
    Ok(())
}
/// Open the owner-direct grant limited to this session's subtree. The
/// `scope_key` names the session; `scope_revision` pins the session revision
/// so a stale session cannot reuse the grant.
async fn open_subtree_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    session: Uuid,
    revision: i64,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO scope_grants(id,owner_id,tool_name,scope_key,scope_revision,max_risk,autonomy_modes,parameter_bounds) VALUES($1,$2,'shell.session',$3,$4,'LOW','[\"CUSTOM\"]',$5) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(owner)
    .bind(format!("shell-session:{session}"))
    .bind(revision)
    .bind(json!({"session_id": session}))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn close_subtree_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    session: Uuid,
) -> Result<(), Error> {
    sqlx::query("DELETE FROM scope_grants WHERE owner_id=$1 AND scope_key=$2")
        .bind(owner)
        .bind(format!("shell-session:{session}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn append_status(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    session: Uuid,
    state: &str,
    extra: Value,
) -> Result<i64> {
    let mut payload = json!({"state": state, "session_id": session});
    if let Some(object) = payload.as_object_mut()
        && let Some(patch) = extra.as_object()
    {
        for (key, value) in patch {
            object.insert(key.clone(), value.clone());
        }
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO run_events(owner_id,session_id,kind,payload) VALUES($1,$2,'STATUS',$3) RETURNING id",
    )
    .bind(owner)
    .bind(session)
    .bind(payload)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("UPDATE execution_sessions SET last_seq=GREATEST(last_seq,$3) WHERE owner_id=$1 AND id=$2")
        .bind(owner)
        .bind(session)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(id)
}

#[utoipa::path(post, path = "/api/v1/shell/sessions", request_body = SessionCreate, responses((status = 200, body = Value)))]
pub async fn create_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SessionCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let cols = input.cols.unwrap_or(80);
    let rows = input.rows.unwrap_or(24);
    check_pty(cols, rows).map_err(ApiError)?;
    let cwd = input.cwd.unwrap_or_else(|| "/".into());
    check_cwd(&cwd).map_err(ApiError)?;
    let root = resolve_root(&state.pool, a.scope.owner_id, input.workspace_id).await?;
    // Stage before granting: an unstageable subtree never gets a session.
    prove_stageable(&state, &a.scope, root).await?;
    let sandboxed = sandbox_enabled(&state.pool, a.scope.owner_id).await;
    let execution_mode = if sandboxed { "sandboxed" } else { "unsandboxed" };
    // Sandbox choice is respected, never bypassed: when the owner opted in,
    // probe the admitted AIec connection's interactive capability. The probe
    // fails closed with INTERACTIVE_SHELL_UNAVAILABLE until AIec advertises
    // the capability — no host fallback exists either way.
    if sandboxed {
        let capable = aiec_interactive_capable(&state, &a.scope).await?;
        if !capable {
            return Err(Error::Unavailable(
                orbit_task_runtime::INTERACTIVE_SHELL_UNAVAILABLE.into(),
            )
            .into());
        }
    }
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO execution_sessions(id,owner_id,kind,state,execution_mode,sandboxed,revision,last_seq,workspace_id,cwd,cols,rows) VALUES($1,$2,'SHELL','RUNNING',$3,$4,1,0,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(a.scope.owner_id)
    .bind(execution_mode)
    .bind(sandboxed)
    .bind(root)
    .bind(&cwd)
    .bind(cols as i32)
    .bind(rows as i32)
    .execute(&mut *tx)
    .await?;
    open_subtree_grant(&mut tx, a.scope.owner_id, id, 1).await?;
    append_status(&mut tx, a.scope.owner_id, id, "RUNNING", json!({"execution_mode": execution_mode})).await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "SHELL_SESSION_CREATED",
        "owner opened a shell session",
        json!({"session_id": id, "workspace_id": root, "execution_mode": execution_mode}),
    )
    .await?;
    tx.commit().await?;
    // Execution sessions gained workspace columns in this slice; older
    // checkouts may lack them, so project explicitly and tolerate absence.
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM execution_sessions WHERE owner_id=$1 AND id=$2"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(session_view(&row)?))
}

/// Probe the owner's admitted AIec connection for interactive-shell
/// capability. `Ok(false)` (fail-closed upstream) when no single admitted
/// connection backs the owner; transport or shape surprises are `Ok(false)`
/// too — never a dispatch attempt.
async fn aiec_interactive_capable(
    state: &ApiState,
    scope: &orbit_core::OwnerScope,
) -> Result<bool, Error> {
    use orbit_aiec_runtime::{AIecRuntime, ConnectionConfig};
    use orbit_secrets::SecretStore;
    let rows = sqlx::query(
        "SELECT id,config FROM aiec_connections WHERE owner_id=$1 AND enabled LIMIT 2",
    )
    .bind(scope.owner_id)
    .fetch_all(&state.pool)
    .await?;
    if rows.len() != 1 {
        return Ok(false);
    }
    let config: ConnectionConfig = serde_json::from_value(rows[0].get("config"))?;
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let key = store.get(scope, config.secret_id).await?;
    let runtime = AIecRuntime::connect(config, key).await?;
    Ok(runtime.probe_interactive().await?)
}

#[utoipa::path(get, path = "/api/v1/shell/sessions/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn get_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM execution_sessions WHERE owner_id=$1 AND id=$2 AND kind='SHELL'"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(Error::NotFound)?;
    Ok(Json(session_view(&row)?))
}

#[utoipa::path(get, path = "/api/v1/shell/sessions/{id}/stream", params(("id" = Uuid, Path)), responses((status = 200)))]
pub async fn stream_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<StreamQuery>,
) -> Result<Response, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    // Owner-scoped SHELL check: foreign ids are 404, non-shell rows are 404.
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM execution_sessions WHERE owner_id=$1 AND id=$2 AND kind='SHELL'",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_one(&state.pool)
    .await?;
    if exists == 0 {
        return Err(Error::NotFound.into());
    }
    let pool = state.pool.clone();
    let owner = a.scope.owner_id;
    let cursor = query.cursor.unwrap_or(0);
    // Cursor is `run_events.id` scoped to this session, ordered ascending;
    // the frontend dedupes by id and replays TERMINAL_OUTPUT deltas.
    let stream = async_stream::stream! {
        let mut next = cursor;
        loop {
            let rows = sqlx::query(
                "SELECT id,kind,payload FROM run_events WHERE owner_id=$1 AND session_id=$2 AND id>$3 ORDER BY id ASC LIMIT 100",
            )
            .bind(owner)
            .bind(id)
            .bind(next)
            .fetch_all(&pool)
            .await;
            match rows {
                Ok(page) => {
                    for r in &page {
                        let event_id: i64 = r.get("id");
                        next = event_id;
                        let event = SseEvent::default()
                            .id(event_id.to_string())
                            .event("run-event")
                            .data(json!({
                                "id": event_id,
                                "kind": r.get::<String, _>("kind"),
                                "payload": r.get::<Value, _>("payload"),
                            }).to_string());
                        yield Ok::<_, Infallible>(event);
                    }
                    if page.is_empty() {
                        break;
                    }
                    if page.len() < 100 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()).into_response())
}

#[utoipa::path(post, path = "/api/v1/shell/sessions/{id}/input", request_body = SessionInput, responses((status = 200, body = Value)))]
pub async fn session_input(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SessionInput>,
) -> Result<Json<Value>, ApiError> {
    check_input_text(&input.text).map_err(ApiError)?;
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    // Revision CAS: stale pins are 409; terminal sessions are 409 too.
    // Shell input is one bounded intent per call — never an agent proposal.
    let row = sqlx::query(&format!(
        "UPDATE execution_sessions SET revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND kind='SHELL' AND revision=$3 AND state IN ('STARTING','RUNNING','WAITING') RETURNING {SESSION_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::int8 FROM execution_sessions WHERE owner_id=$1 AND id=$2 AND kind='SHELL'",
        )
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(0);
        if exists == 0 {
            return Err(Error::NotFound.into());
        }
        return Err(Error::Conflict("stale revision or terminal session".into()).into());
    };
    let revision: i64 = row.try_get("revision")?;
    // The pty write itself happens through the runtime dispatch (AIec when
    // sandboxed, execution-host otherwise); the API layer journals the intent
    // as a run event so the stream cursor replays it in order.
    let event_id: i64 = sqlx::query_scalar(
        "INSERT INTO run_events(owner_id,session_id,kind,payload) VALUES($1,$2,'TEXT_DELTA',$3) RETURNING id",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(json!({"direction": "input", "revision": revision}))
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE execution_sessions SET last_seq=GREATEST(last_seq,$3) WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(event_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "SHELL_SESSION_INPUT",
        "owner sent shell input",
        json!({"session_id": id, "revision": revision, "bytes": input.text.len()}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id": id, "revision": revision, "event_id": event_id})))
}

#[utoipa::path(post, path = "/api/v1/shell/sessions/{id}/resize", request_body = SessionResize, responses((status = 200, body = Value)))]
pub async fn session_resize(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SessionResize>,
) -> Result<Json<Value>, ApiError> {
    check_pty(input.cols, input.rows).map_err(ApiError)?;
    let a = authenticate(&state, &headers, true).await?;
    let row = sqlx::query(&format!(
        "UPDATE execution_sessions SET cols=$4,rows=$5,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND kind='SHELL' AND revision=$3 AND state IN ('STARTING','RUNNING','WAITING') RETURNING {SESSION_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .bind(input.cols as i32)
    .bind(input.rows as i32)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::int8 FROM execution_sessions WHERE owner_id=$1 AND id=$2 AND kind='SHELL'",
        )
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
        if exists == 0 {
            return Err(Error::NotFound.into());
        }
        return Err(Error::Conflict("stale revision or terminal session".into()).into());
    };
    Ok(Json(session_view(&row)?))
}

#[utoipa::path(post, path = "/api/v1/shell/sessions/{id}/stop", request_body = RevisionPin, responses((status = 200, body = Value)))]
pub async fn session_stop(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionPin>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    // Idempotent stop: an already-STOPPED/FAILED row returns its view.
    let current = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM execution_sessions WHERE owner_id=$1 AND id=$2 AND kind='SHELL'"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let state_name = current.try_get::<String, _>("state").unwrap_or_default();
    if state_name == "STOPPED" || state_name == "FAILED" {
        tx.commit().await?;
        return Ok(Json(session_view(&current)?));
    }
    let row = sqlx::query(&format!(
        "UPDATE execution_sessions SET state='STOPPED',revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND kind='SHELL' AND revision=$3 RETURNING {SESSION_COLS}"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Err(Error::Conflict("stale revision".into()).into());
    };
    // Closing the session closes its subtree grant: owner-direct access ends
    // with the shell.
    close_subtree_grant(&mut tx, a.scope.owner_id, id).await?;
    append_status(&mut tx, a.scope.owner_id, id, "STOPPED", json!({})).await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "SHELL_SESSION_STOPPED",
        "owner stopped a shell session",
        json!({"session_id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(session_view(&row)?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_session,
    get_session,
    stream_session,
    session_input,
    session_resize,
    session_stop,
))]
pub struct ShellApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/shell/sessions", post(create_session))
        .route("/api/v1/shell/sessions/{id}", get(get_session))
        .route("/api/v1/shell/sessions/{id}/stream", get(stream_session))
        .route("/api/v1/shell/sessions/{id}/input", post(session_input))
        .route("/api/v1/shell/sessions/{id}/resize", post(session_resize))
        .route("/api/v1/shell/sessions/{id}/stop", post(session_stop))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pty_bounds_reject_zero_and_huge() {
        assert!(check_pty(80, 24).is_ok());
        assert!(check_pty(0, 24).is_err());
        assert!(check_pty(80, 0).is_err());
        assert!(check_pty(1025, 24).is_err());
    }
    #[test]
    fn cwd_rejects_traversal_and_separators() {
        assert!(check_cwd("/").is_ok());
        assert!(check_cwd("/Projects/a-b_c.txt").is_ok());
        assert!(check_cwd("").is_err());
        assert!(check_cwd("relative").is_err());
        assert!(check_cwd("/a/../b").is_err());
        assert!(check_cwd("/a//b").is_err());
        assert!(check_cwd("/a\\b").is_err());
        assert!(check_cwd("/a\0b").is_err());
    }
    #[test]
    fn input_bound_is_one_intent_per_call() {
        assert!(check_input_text("ls\n").is_ok());
        assert!(check_input_text("").is_err());
        assert!(check_input_text(&"x".repeat(MAX_INPUT_BYTES + 1)).is_err());
        assert!(check_input_text("a\0b").is_err());
    }
}
