//! Managed browser sessions: owner CRUD over `browser_sessions` rows plus the
//! live-view stream, with dispatch to the private browser-host socket service.
//!
//! One session owns one `browser_sessions` row and one browser context in the
//! host. Owner-direct mutations (takeover/return, close) use `revision` CAS;
//! agent mutations route through the normal tool-call journal (`propose` /
//! `submit` / `approve`) on the `browser.session.*` descriptors (see
//! [`execute_session_tool`]), and an active owner takeover pauses them: the
//! executor re-checks `takeover` under lock at settle time and refuses with a
//! conflict instead of dispatching.
//!
//! Broker validation runs twice: the API-layer [`screen_browser_url`]
//! pre-screen here (strict parse, numeric-host denial, literal-IP deny set
//! shared with `AdmittedEndpoint`, `lookup_host` on every hostname,
//! fail-closed on unresolvable names) and the host re-screen at dispatch +
//! redirect as the second backstop. Missing broker capability fails closed
//! with UNAVAILABLE; there is no raw-guest-network fallback and no
//! server-host execution.
//!
//! Stale DOM protection: actuating tools (`click`/`fill`/`submit`/`download`)
//! pin `expected_dom_revision`. A mismatch never dispatches stale coordinates;
//! the executor returns a conflict naming the live revision so the caller
//! takes a fresh snapshot instead. Downloads land in the workspace Inbox as
//! `UNTRUSTED_EXTERNAL` through the quarantine gates (path-traversal +
//! archive-bomb screens). Uploads are not dispatched from page bytes: they
//! need a path-pinned export approval first. Password inputs are never echoed
//! in frames, events, or logs (the host masks them); cookie/profile snapshots
//! are caller-sealed artifacts — sealed bytes live in the artifact store, the
//! row only names the artifact id.
//!
//! Conventions: owner-scoped SQL everywhere (foreign ids are 404), `revision`
//! CAS on every mutation (stale pins are 409), `deny_unknown_fields` on all
//! wire bodies, no secrets in rows or logs.

use crate::{ApiError, ApiState, authenticate, computers::screen_browser_url};
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::{
        IntoResponse, Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::StreamExt;
use orbit_core::{Error, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::convert::Infallible;
use std::path::PathBuf;
use uuid::Uuid;

/// Socket path for the private browser-host service. The host owns the only
/// real browser; this API layer never fetches page bytes itself.
fn browser_socket_path() -> String {
    std::env::var("ORBIT_BROWSER_HOST_SOCK")
        .unwrap_or_else(|_| "/run/orbit/browser-host.sock".into())
}

/// Bearer for the browser-host socket (EXEC_HOST-style token). Absent token
/// fails closed with UNAVAILABLE, never an unauthenticated dispatch.
fn browser_socket_token() -> Option<String> {
    std::env::var("ORBIT_BROWSER_HOST_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
}

/// One NDJSON-framed host call: `{op, token, payload}` per line, first
/// response line is the result envelope. Timeouts bound every dispatch so a
/// wedged daemon cannot hang the API worker.
async fn host_call(op: &str, payload: Value) -> Result<Value> {
    let token = browser_socket_token()
        .ok_or_else(|| Error::Unavailable("browser host is not configured".into()))?;
    let path = browser_socket_path();
    let request = json!({"op": op, "token": token, "payload": payload});
    let mut line = serde_json::to_vec(&request).map_err(Error::from)?;
    line.push(b'\n');
    let raw = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        #[cfg(unix)]
        {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .map_err(|_| Error::Unavailable("browser host is unreachable".into()))?;
            stream
                .write_all(&line)
                .await
                .map_err(|_| Error::Unavailable("browser host is unreachable".into()))?;
            let mut reader = tokio::io::BufReader::new(stream);
            let mut out = String::new();
            reader
                .read_line(&mut out)
                .await
                .map_err(|_| Error::Unavailable("browser host gave no response".into()))?;
            Ok::<String, Error>(out)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err::<String, Error>(Error::Unavailable("browser host needs a unix socket".into()))
        }
    })
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|e| match e {
        Error::Unavailable(_) => Error::Unavailable("browser host is unreachable".into()),
        other => other,
    })?;
    if raw.trim().is_empty() {
        return Err(Error::Unavailable("browser host gave no response".into()));
    }
    let envelope: Value = serde_json::from_str(raw.trim())
        .map_err(|_| Error::Unavailable("browser host gave no response".into()))?;
    if envelope.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(envelope.get("result").cloned().unwrap_or(Value::Null));
    }
    let code = envelope
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("browser host failed");
    // Host-side failures stay host-side errors: unavailable broker caps and
    // redirects-denied surface as UNAVAILABLE, never raw guest net.
    Err(Error::Unavailable(code.into()))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionCreate {
    pub task_id: Option<Uuid>,
    pub url: Option<String>,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionPin {
    pub expected_revision: i64,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserNavigate {
    pub expected_revision: i64,
    pub url: String,
}
#[derive(Deserialize)]
pub struct StreamQuery {
    pub cursor: Option<i64>,
}

/// Max 2fps viewer cadence for live frames (host enforces the same ceiling;
/// frames flow only while a viewer or snapshot is active).
const LIVE_FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

const SESSION_COLS: &str =
    "id,revision,state,takeover,url,dom_revision,task_id,last_seq,created_at,updated_at";

fn session_view(row: &sqlx::postgres::PgRow) -> Result<Value, Error> {
    Ok(json!({
        "id": row.try_get::<Uuid, _>("id")?,
        "revision": row.try_get::<i64, _>("revision").unwrap_or(1),
        "state": row.try_get::<String, _>("state").unwrap_or_default(),
        "takeover": row.try_get::<bool, _>("takeover").unwrap_or(false),
        "url": row.try_get::<String, _>("url").unwrap_or_default(),
        "title": null,
        "dom_revision": row.try_get::<i64, _>("dom_revision").unwrap_or(0),
        "task_id": row.try_get::<Uuid, _>("task_id").ok(),
        "last_seq": row.try_get::<i64, _>("last_seq").unwrap_or(0),
    }))
}

async fn session_row(
    pool: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
) -> Result<sqlx::postgres::PgRow, Error> {
    sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 AND id=$2"
    ))
    .bind(owner)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

/// Owner-scoped task check: a linked task must belong to the owner, else 404.
async fn check_task(pool: &sqlx::PgPool, owner: Uuid, task: Uuid) -> Result<(), Error> {
    let hit: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM tasks WHERE owner_id=$1 AND id=$2")
            .bind(owner)
            .bind(task)
            .fetch_optional(pool)
            .await?;
    hit.map(|_| ()).ok_or(Error::NotFound)
}

/// Browser run events live in their own nullable column: `run_events.
/// session_id` stays FK'd to `execution_sessions`, so session `nav`/`loading`/
/// `title`/`status` events use `browser_session_id`. `kind` is the SSE event
/// name the viewer subscribes to.
async fn append_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    session: Uuid,
    task: Option<Uuid>,
    kind: &str,
    payload: Value,
) -> Result<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO run_events(owner_id,task_id,browser_session_id,kind,payload) VALUES($1,$2,$3,$4,$5) RETURNING id",
    )
    .bind(owner)
    .bind(task)
    .bind(session)
    .bind(kind)
    .bind(payload)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("UPDATE browser_sessions SET last_seq=GREATEST(last_seq,$3),updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(owner)
        .bind(session)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(id)
}

/// Open the owner-direct grant limited to this session. `scope_key` names the
/// session; `scope_revision` pins the session revision so a stale session
/// cannot reuse the grant. Actuating tools (`click`/`fill`/`submit`/
/// `download`) stay grantless here: they are High-risk, so the
/// HIGH_RISK_CONSENT_CEILING always parks them for approval — a narrow
/// session grant only satisfies the explicit-scope requirement at approve
/// time, never the consent itself.
async fn open_session_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    session: Uuid,
    revision: i64,
) -> Result<(), Error> {
    for tool in [
        "browser.session.open",
        "browser.session.snapshot",
        "browser.session.navigate",
        "browser.session.close",
    ] {
        sqlx::query(
            "INSERT INTO scope_grants(id,owner_id,tool_name,scope_key,scope_revision,max_risk,autonomy_modes,parameter_bounds) VALUES($1,$2,$3,$4,$5,'LOW','[\"CUSTOM\"]',$6) ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(owner)
        .bind(tool)
        .bind(format!("browser-session:{session}"))
        .bind(revision)
        .bind(json!({"session_id": session}))
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn close_session_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    session: Uuid,
) -> Result<(), Error> {
    sqlx::query("DELETE FROM scope_grants WHERE owner_id=$1 AND scope_key=$2")
        .bind(owner)
        .bind(format!("browser-session:{session}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Settle-time gate shared by every agent-actuated browser dispatch: the
/// session must be RUNNING, takeover must be off, and the caller's DOM pin
/// must match the live `dom_revision`. Stale pins return a conflict naming
/// the live revision so the caller takes a fresh snapshot; stale coordinates
/// are never dispatched.
pub async fn settle_actuation(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
    session: Uuid,
    expected_dom_revision: i64,
) -> Result<sqlx::postgres::PgRow, Error> {
    let row = session_row(pool, scope.owner_id, session).await?;
    if row.try_get::<bool, _>("takeover").unwrap_or(false) {
        return Err(Error::Conflict("owner takeover is active".into()));
    }
    if row.try_get::<String, _>("state").unwrap_or_default() != "RUNNING" {
        return Err(Error::Conflict("browser session is not running".into()));
    }
    let live = row.try_get::<i64, _>("dom_revision").unwrap_or(0);
    if live != expected_dom_revision {
        return Err(Error::Conflict(format!(
            "stale DOM revision: expected {expected_dom_revision}, live is {live}; take a fresh snapshot"
        )));
    }
    Ok(row)
}

async fn insert_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    task: Option<Uuid>,
    url: &str,
) -> Result<Uuid, Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO browser_sessions(id,owner_id,task_id,url,state,takeover,dom_revision,revision,last_seq) VALUES($1,$2,$3,$4,'RUNNING',false,0,1,0)",
    )
    .bind(id)
    .bind(owner)
    .bind(task)
    .bind(url)
    .execute(&mut **tx)
    .await?;
    open_session_grant(tx, owner, id, 1).await?;
    append_event(
        tx,
        owner,
        id,
        task,
        "nav",
        json!({"state": "RUNNING", "session_id": id, "url": url}),
    )
    .await?;
    Ok(id)
}

#[utoipa::path(post, path = "/api/v1/browser/sessions", request_body = BrowserSessionCreate, responses((status = 200, body = Value)))]
pub async fn create_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<BrowserSessionCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if let Some(task) = input.task_id {
        check_task(&state.pool, a.scope.owner_id, task).await?;
    }
    let url = input.url.unwrap_or_default();
    // Pre-screen before any host dispatch (second backstop lives in the host).
    if !url.is_empty() {
        screen_browser_url(&url).await?;
    }
    let mut tx = state.pool.begin().await?;
    let id = insert_session(&mut tx, a.scope.owner_id, input.task_id, &url).await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        input.task_id,
        "BROWSER_SESSION_CREATED",
        "owner opened a browser session",
        json!({"session_id": id, "task_id": input.task_id, "url": url}),
    )
    .await?;
    tx.commit().await?;
    if !url.is_empty() {
        // Best-effort initial navigation; a denied/unreachable host surfaces
        // on the navigate call itself, never as a failed create.
        let _ = host_call("navigate", json!({"session_id": id, "url": &url})).await;
    }
    let row = session_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(Json(session_view(&row)?))
}

#[utoipa::path(get, path = "/api/v1/browser/sessions", responses((status = 200, body = Value)))]
pub async fn list_sessions(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 200"
    ))
    .bind(a.scope.owner_id)
    .fetch_all(&state.pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(session_view(row)?);
    }
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

#[utoipa::path(get, path = "/api/v1/browser/sessions/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn get_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = session_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(Json(session_view(&row)?))
}

/// Metadata-only snapshot: url/title/dom_revision/takeover. Frame bytes flow
/// over the `live` websocket (2fps, viewer-attached only), never here.
#[utoipa::path(get, path = "/api/v1/browser/sessions/{id}/snapshot", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn snapshot_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let view = tool_snapshot_session(&state.pool, &a.scope, id).await?;
    Ok(Json(view))
}

async fn tool_snapshot_session(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
    id: Uuid,
) -> Result<Value, Error> {
    let row = session_row(pool, scope.owner_id, id).await?;
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    let result = host_call("snapshot", json!({"session_id": id})).await?;
    let dom_revision = result
        .get("dom_revision")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| row.try_get::<i64, _>("dom_revision").unwrap_or(0));
    let url = result
        .get("url")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| row.try_get::<String, _>("url").unwrap_or_default());
    let title = result.get("title").cloned().unwrap_or(Value::Null);
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE browser_sessions SET url=$3,dom_revision=$4,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(id)
        .bind(&url)
        .bind(dom_revision)
        .execute(&mut *tx)
        .await?;
    append_event(
        &mut tx,
        scope.owner_id,
        id,
        task,
        "title",
        json!({"snapshot": true, "session_id": id, "url": url, "title": title, "dom_revision": dom_revision}),
    )
    .await?;
    tx.commit().await?;
    let row = session_row(pool, scope.owner_id, id).await?;
    let mut view = session_view(&row)?;
    view["title"] = title;
    Ok(view)
}

#[utoipa::path(post, path = "/api/v1/browser/sessions/{id}/navigate", params(("id" = Uuid, Path)), request_body = BrowserNavigate, responses((status = 200, body = Value)))]
pub async fn navigate_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<BrowserNavigate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Owner actuation pins the live revision: while the owner holds the page,
    // even owner API calls CAS on `revision` to avoid racing the viewer.
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 AND id=$2 FOR UPDATE"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    if row.try_get::<i64, _>("revision").unwrap_or(1) != input.expected_revision {
        return Err(Error::Conflict("browser session changed".into()).into());
    }
    tx.commit().await?;
    let view = tool_navigate_session(&state.pool, &a.scope, id, &input.url).await?;
    Ok(Json(view))
}

async fn tool_navigate_session(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
    id: Uuid,
    url: &str,
) -> Result<Value, Error> {
    session_row(pool, scope.owner_id, id).await?;
    screen_browser_url(url).await?;
    let result = host_call("navigate", json!({"session_id": id, "url": url})).await?;
    let dom_revision = result
        .get("dom_revision")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    // The host reports the final URL after redirects (second backstop); the
    // row records where the page actually landed, not where we asked to go.
    let final_url: String = result
        .get("url")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| url.to_owned());
    let mut tx = pool.begin().await?;
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 AND id=$2"
    ))
    .bind(scope.owner_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    sqlx::query("UPDATE browser_sessions SET url=$3,dom_revision=$4,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(id)
        .bind(&final_url)
        .bind(dom_revision)
        .execute(&mut *tx)
        .await?;
    append_event(
        &mut tx,
        scope.owner_id,
        id,
        task,
        "nav",
        json!({"nav": true, "session_id": id, "url": final_url, "dom_revision": dom_revision}),
    )
    .await?;
    tx.commit().await?;
    let row = session_row(pool, scope.owner_id, id).await?;
    session_view(&row)
}

/// Owner takeover: pauses agent mutations at settle time until `return`.
/// CAS on the session revision so a stale owner view cannot seize control.
#[utoipa::path(post, path = "/api/v1/browser/sessions/{id}/takeover", params(("id" = Uuid, Path)), request_body = RevisionPin, responses((status = 200, body = Value)))]
pub async fn takeover_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionPin>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    let affected = sqlx::query(
        "UPDATE browser_sessions SET takeover=true,state=CASE WHEN state='RUNNING' THEN 'PAUSED' ELSE state END,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$3 AND state IN ('RUNNING','PAUSED')",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected != 1 {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::int8 FROM browser_sessions WHERE owner_id=$1 AND id=$2",
        )
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        if exists == 0 {
            return Err(Error::NotFound.into());
        }
        return Err(Error::Conflict("browser session changed".into()).into());
    }
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 AND id=$2"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    append_event(
        &mut tx,
        a.scope.owner_id,
        id,
        task,
        "status",
        json!({"takeover": true, "session_id": id}),
    )
    .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        task,
        "BROWSER_TAKEOVER",
        "owner took over the browser session; agent mutations paused",
        json!({"session_id": id}),
    )
    .await?;
    tx.commit().await?;
    let row = session_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(Json(session_view(&row)?))
}

/// Owner return: resumes agent mutations. Same CAS discipline as takeover.
#[utoipa::path(post, path = "/api/v1/browser/sessions/{id}/return", params(("id" = Uuid, Path)), request_body = RevisionPin, responses((status = 200, body = Value)))]
pub async fn return_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionPin>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    let affected = sqlx::query(
        "UPDATE browser_sessions SET takeover=false,state=CASE WHEN state='PAUSED' THEN 'RUNNING' ELSE state END,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$3 AND state IN ('RUNNING','PAUSED')",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected != 1 {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::int8 FROM browser_sessions WHERE owner_id=$1 AND id=$2",
        )
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        if exists == 0 {
            return Err(Error::NotFound.into());
        }
        return Err(Error::Conflict("browser session changed".into()).into());
    }
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 AND id=$2"
    ))
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    append_event(
        &mut tx,
        a.scope.owner_id,
        id,
        task,
        "status",
        json!({"takeover": false, "session_id": id}),
    )
    .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        task,
        "BROWSER_RETURNED",
        "owner returned the browser session; agent mutations resumed",
        json!({"session_id": id}),
    )
    .await?;
    tx.commit().await?;
    let row = session_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(Json(session_view(&row)?))
}

/// Agent actuation entrypoint shared by the `browser.session.*` executors:
/// click / fill / submit / download. Settle-time gates (takeover, RUNNING,
/// fresh DOM pin) run first; mutating clicks and all submits/downloads park
/// for approval upstream via the High-risk consent ceiling — this function
/// only dispatches already-authorized calls. Downloads are quarantined into
/// the workspace Inbox; uploads are refused here (path-pinned export approval
/// required).
pub async fn actuate_session(
    pool: &sqlx::PgPool,
    artifact_dir: &PathBuf,
    scope: &orbit_core::OwnerScope,
    session: Uuid,
    op: &str,
    args: &Value,
    expected_dom_revision: i64,
) -> Result<Value, Error> {
    let row = settle_actuation(pool, scope, session, expected_dom_revision).await?;
    let mut payload = json!({"session_id": session});
    for key in ["target", "fields", "submit_selector", "mutating"] {
        if let Some(value) = args.get(key) {
            payload[key] = value.clone();
        }
    }
    // Fill values travel to the host only; they are never written to run
    // events or logs (password inputs stay masked end to end).
    let result = host_call(op, payload).await?;
    let dom_revision = result
        .get("dom_revision")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| row.try_get::<i64, _>("dom_revision").unwrap_or(0));
    let url = result
        .get("url")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| row.try_get::<String, _>("url").unwrap_or_default());
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    if op == "download" {
        return quarantine_download(pool, artifact_dir, scope, session, task, args, &result).await;
    }
    if op == "upload" {
        // Page-driven uploads never dispatch bytes: the owner must approve a
        // path-pinned export first; the approved executor performs the read.
        return Err(Error::Validation(
            "browser uploads need a path-pinned export approval".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE browser_sessions SET url=$3,dom_revision=$4,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(session)
        .bind(&url)
        .bind(dom_revision)
        .execute(&mut *tx)
        .await?;
    append_event(
        &mut tx,
        scope.owner_id,
        session,
        task,
        "nav",
        json!({"op": op, "session_id": session, "url": url, "dom_revision": dom_revision}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"status": "OK", "dom_revision": dom_revision, "url": url}))
}

/// Download settle: host bytes enter through the quarantine gates and land in
/// the workspace Inbox as UNTRUSTED_EXTERNAL. Never executed, never trusted
/// by suffix; archive bombs and traversal names are validation errors.
async fn quarantine_download(
    pool: &sqlx::PgPool,
    artifact_dir: &PathBuf,
    scope: &orbit_core::OwnerScope,
    session: Uuid,
    task: Option<Uuid>,
    args: &Value,
    result: &Value,
) -> Result<Value, Error> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| result.get("name").and_then(Value::as_str))
        .unwrap_or("download.bin");
    let claimed = result
        .get("mime")
        .and_then(Value::as_str)
        .unwrap_or("application/octet-stream");
    let bytes = result
        .get("content_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Unavailable("browser host returned no download bytes".into()))?;
    let bytes = STANDARD
        .decode(bytes)
        .map_err(|_| Error::Validation("download bytes are not valid base64".into()))?;
    // Quarantine gates first: size, traversal, MIME sniff, archive bombs.
    let quarantined = orbit_email::quarantine_store(name, claimed, &bytes)?;
    // Inbox landing: a workspace file row pinned under the owner's Inbox
    // directory, content-addressed through the sealed artifact store.
    let inbox = ensure_inbox(pool, scope).await?;
    let stored = orbit_agent_runtime::attachments::upload(
        pool,
        artifact_dir,
        scope,
        &quarantined.name,
        &quarantined.mime,
        &bytes,
    )
    .await?;
    let artifact_id: Uuid = serde_json::from_value(stored["id"].clone())
        .map_err(|_| Error::Unavailable("download storage failed".into()))?;
    let entry = orbit_workspace::create(
        pool,
        scope,
        inbox,
        &quarantined.name,
        orbit_workspace::EntryKind::File,
        Some(artifact_id),
    )
    .await;
    // Name collisions yield a suffixed retry, never an overwrite.
    let entry = match entry {
        Ok(entry) => entry,
        Err(_) => {
            let retry = format!("{}-{}", &quarantined.sha256[..8], quarantined.name);
            orbit_workspace::create(
                pool,
                scope,
                inbox,
                &retry,
                orbit_workspace::EntryKind::File,
                Some(artifact_id),
            )
            .await?
        }
    };
    let mut tx = pool.begin().await?;
    append_event(
        &mut tx,
        scope.owner_id,
        session,
        task,
        "nav",
        json!({"download": true, "session_id": session, "artifact_id": artifact_id, "entry_id": entry.id, "sha256": quarantined.sha256, "mime": quarantined.mime}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"status": "OK", "artifact_id": artifact_id, "entry_id": entry.id, "sha256": quarantined.sha256, "mime": quarantined.mime}))
}

/// Resolve (creating once) the owner's workspace Inbox directory. Untrusted
/// browser downloads land here, never beside owner files.
async fn ensure_inbox(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
) -> Result<Uuid, Error> {
    if let Ok(entry) = orbit_workspace::resolve(pool, scope, &["Inbox".to_owned()]).await {
        return Ok(entry.id);
    }
    let root: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM workspace_entries WHERE owner_id=$1 AND parent_id IS NULL AND trashed_at IS NULL LIMIT 1",
    )
    .bind(scope.owner_id)
    .fetch_optional(pool)
    .await?;
    let root = root.ok_or(Error::Validation("workspace is not initialized".into()))?;
    let entry = orbit_workspace::create(
        pool,
        scope,
        root,
        "Inbox",
        orbit_workspace::EntryKind::Directory,
        None,
    )
    .await?;
    Ok(entry.id)
}

async fn tool_close_session(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
    id: Uuid,
) -> Result<Value, Error> {
    let mut tx = pool.begin().await?;
    let affected = sqlx::query(
        "UPDATE browser_sessions SET state='STOPPED',takeover=false,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND state IN ('STARTING','RUNNING','PAUSED','FAILED')",
    )
    .bind(scope.owner_id)
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected != 1 {
        let exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::int8 FROM browser_sessions WHERE owner_id=$1 AND id=$2",
        )
        .bind(scope.owner_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        if exists == 0 {
            return Err(Error::NotFound);
        }
        return Err(Error::Conflict("browser session is already closed".into()));
    }
    let row = sqlx::query(&format!(
        "SELECT {SESSION_COLS} FROM browser_sessions WHERE owner_id=$1 AND id=$2"
    ))
    .bind(scope.owner_id)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    // Closing releases the session grant and any takeover hold together.
    close_session_grant(&mut tx, scope.owner_id, id).await?;
    append_event(
        &mut tx,
        scope.owner_id,
        id,
        task,
        "status",
        json!({"state": "STOPPED", "session_id": id}),
    )
    .await?;
    tx.commit().await?;
    // Best-effort host teardown; the row is already closed either way.
    let _ = host_call("close", json!({"session_id": id})).await;
    let row = session_row(pool, scope.owner_id, id).await?;
    session_view(&row)
}

/// Tool-journal entrypoint for the `browser.session.*` descriptors, wired from
/// the executor registry. The journal (`propose`/`submit`/`approve`) already
/// bound the action and enforced policy + approval; this only settles each
/// op: read ops run inline, actuation re-checks takeover + DOM freshness.
pub async fn execute_session_tool(
    pool: &sqlx::PgPool,
    artifact_dir: &PathBuf,
    scope: &orbit_core::OwnerScope,
    name: &str,
    args: &Value,
) -> Result<Value, Error> {
    let session: Uuid = args
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Validation("browser tool needs session_id".into()))?;
    match name {
        "browser.session.open" => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let task = args
                .get("task_id")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok());
            if let Some(task) = task {
                check_task(pool, scope.owner_id, task).await?;
            }
            if !url.is_empty() {
                screen_browser_url(&url).await?;
            }
            let mut tx = pool.begin().await?;
            let id = insert_session(&mut tx, scope.owner_id, task, &url).await?;
            tx.commit().await?;
            if !url.is_empty() {
                let _ =
                    host_call("navigate", json!({"session_id": id, "url": &url})).await;
            }
            let row = session_row(pool, scope.owner_id, id).await?;
            session_view(&row)
        }
        "browser.session.snapshot" => tool_snapshot_session(pool, scope, session).await,
        "browser.session.navigate" => {
            let url = args
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Validation("browser navigate needs url".into()))?;
            tool_navigate_session(pool, scope, session, url).await
        }
        "browser.session.close" => tool_close_session(pool, scope, session).await,
        "browser.session.click" | "browser.session.fill" | "browser.session.submit"
        | "browser.session.download" => {
            let expected_dom_revision = args
                .get("expected_dom_revision")
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    Error::Validation("browser actuation needs expected_dom_revision".into())
                })?;
            let op = name
                .strip_prefix("browser.session.")
                .ok_or(Error::Forbidden)?;
            actuate_session(pool, artifact_dir, scope, session, op, args, expected_dom_revision)
                .await
        }
        _ => Err(Error::Forbidden),
    }
}

#[utoipa::path(post, path = "/api/v1/browser/sessions/{id}/close", params(("id" = Uuid, Path)), request_body = RevisionPin, responses((status = 200, body = Value)))]
pub async fn close_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionPin>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Owner close pins `revision` like every other owner mutation; the tool
    // path instead relies on the journal binding. Both funnel to the row
    // update below, which is the single close gate.
    let row = session_row(&state.pool, a.scope.owner_id, id).await?;
    if row.try_get::<i64, _>("revision").unwrap_or(1) != input.expected_revision {
        return Err(Error::Conflict("browser session changed".into()).into());
    }
    let mut tx = state.pool.begin().await?;
    let task: Option<Uuid> = row.try_get::<Uuid, _>("task_id").ok();
    let affected = sqlx::query(
        "UPDATE browser_sessions SET state='STOPPED',takeover=false,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$3 AND state IN ('STARTING','RUNNING','PAUSED','FAILED')",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(input.expected_revision)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected != 1 {
        tx.rollback().await?;
        return Err(Error::Conflict("browser session changed".into()).into());
    }
    // Closing releases the session grant and any takeover hold together.
    close_session_grant(&mut tx, a.scope.owner_id, id).await?;
    append_event(
        &mut tx,
        a.scope.owner_id,
        id,
        task,
        "status",
        json!({"state": "STOPPED", "session_id": id}),
    )
    .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        task,
        "BROWSER_SESSION_CLOSED",
        "owner closed a browser session",
        json!({"session_id": id}),
    )
    .await?;
    tx.commit().await?;
    // Best-effort host teardown; the row is already closed either way.
    let _ = host_call("close", json!({"session_id": id})).await;
    let row = session_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(Json(session_view(&row)?))
}

/// Run-event SSE over the session: `nav`, `title`, `status` events as
/// `{id, kind, payload}`. Cursor is `run_events.id` scoped to this session
/// via `browser_session_id`, ordered ascending; the viewer dedupes by id and
/// replays from the cursor.
#[utoipa::path(get, path = "/api/v1/browser/sessions/{id}/stream", params(("id" = Uuid, Path)), responses((status = 200)))]
pub async fn stream_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<StreamQuery>,
) -> Result<Response, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::int8 FROM browser_sessions WHERE owner_id=$1 AND id=$2",
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
    // the frontend dedupes by id and replays from the cursor.
    let stream = async_stream::stream! {
        let mut next = cursor;
        loop {
            let rows = sqlx::query(
                "SELECT id,kind,payload FROM run_events WHERE owner_id=$1 AND browser_session_id=$2 AND id>$3 ORDER BY id ASC LIMIT 100",
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
                        let kind: String = r.get("kind");
                        let event = SseEvent::default()
                            .id(event_id.to_string())
                            .event(kind.clone())
                            .data(json!({
                                "id": event_id,
                                "kind": kind,
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

/// Live viewer websocket: owner-authenticated, binary JPEG frames at max 2fps
/// while attached, text messages for `loading`/`title` status. Task work
/// continues after the viewer disconnects — viewing never owns the task.
pub async fn live_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    // 404 on foreign ids before the upgrade; the socket never learns whether
    // other owners' sessions exist.
    session_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(upgrade.on_upgrade(move |socket| serve_live(state, a.scope.owner_id, id, socket)))
}

async fn serve_live(state: ApiState, owner: Uuid, id: Uuid, mut socket: WebSocket) {
    let mut tick = tokio::time::interval(LIVE_FRAME_INTERVAL);
    // Frames-subscribe: one host snapshot per tick, forwarded as binary.
    // Password-masked by the host; this layer never inspects frame bytes.
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let alive: i64 = sqlx::query_scalar("SELECT COUNT(*)::int8 FROM browser_sessions WHERE owner_id=$1 AND id=$2 AND state IN ('RUNNING','PAUSED')")
                    .bind(owner).bind(id).fetch_one(&state.pool).await.unwrap_or(0);
                if alive == 0 { break; }
                match host_call("frame", json!({"session_id": id})).await {
                    Ok(frame) => {
                        let Some(b64) = frame.get("jpeg_base64").and_then(Value::as_str) else { continue };
                        use base64::{Engine, engine::general_purpose::STANDARD};
                        let Ok(bytes) = STANDARD.decode(b64) else { continue };
                        if socket.send(Message::Binary(bytes.into())).await.is_err() { break; }
                    }
                    Err(_) => {
                        // Host unavailable mid-view: tell the viewer once, keep
                        // the socket until the session closes or it goes away.
                        let status: String = json!({"kind": "loading", "loading": false, "unavailable": true}).to_string();
                        if socket.send(Message::Text(status.into())).await.is_err() { break; }
                    }
                }
            }
            incoming = socket.next() => {
                let Some(incoming) = incoming else { break };
                if incoming.is_err() { break; }
                // Viewer-to-server messages are ignored: the viewer never
                // drives the page; control flows through takeover + tools.
            }
        }
    }
}

pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/browser/sessions",
            post(create_session).get(list_sessions),
        )
        .route("/api/v1/browser/sessions/{id}", get(get_session))
        .route(
            "/api/v1/browser/sessions/{id}/snapshot",
            get(snapshot_session),
        )
        .route(
            "/api/v1/browser/sessions/{id}/navigate",
            post(navigate_session),
        )
        .route(
            "/api/v1/browser/sessions/{id}/takeover",
            post(takeover_session),
        )
        .route(
            "/api/v1/browser/sessions/{id}/return",
            post(return_session),
        )
        .route("/api/v1/browser/sessions/{id}/stream", get(stream_session))
        .route("/api/v1/browser/sessions/{id}/live", get(live_session))
        .route("/api/v1/browser/sessions/{id}/close", post(close_session))
}
