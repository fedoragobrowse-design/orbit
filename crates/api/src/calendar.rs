//! Owner-scoped calendar API: ICS/CalDAV sources, polled events, today view.
//! No OAuth: Google/Graph stay unavailable by design; public ICS feeds and
//! CalDAV basic-auth only. Feed bytes are untrusted (bounded UID/title,
//! strict timestamps, raw truncated) — see orbit-calendar docs.
use crate::{ApiError, ApiState, authenticate};
use axum::{Json, Router, extract::{Path, Query, State}, http::HeaderMap, routing::{delete, get, post}};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceCreate { pub name: String, pub kind: String, pub url: String, pub username: Option<String>, pub password: Option<String>, #[serde(default = "yes")] pub enabled: bool }
fn yes() -> bool { true }
fn config_of(input: &SourceCreate) -> Result<orbit_calendar::CalendarSource, ApiError> {
    let src = orbit_calendar::CalendarSource { kind: input.kind.clone(), url: input.url.clone(), username: input.username.clone(), password: input.password.clone() };
    src.validate().map_err(ApiError::from)?;
    if input.name.is_empty() || input.name.len() > 64 || input.name.chars().any(char::is_control) {
        return Err(Error::Validation("invalid calendar source name".into()).into());
    }
    Ok(src)
}
#[utoipa::path(get, path = "/api/v1/calendar/sources", responses((status = 200, body = Value)))]
pub async fn list_sources(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'configuration',configuration - 'password','enabled',enabled,'last_sync',last_sync) FROM calendar_sources WHERE owner_id=$1 ORDER BY name").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
    Ok(Json(json!({"items": rows})))
}
#[utoipa::path(post, path = "/api/v1/calendar/sources", request_body = SourceCreate, responses((status = 200, body = Value)))]
pub async fn create_source(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<SourceCreate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let src = config_of(&input)?;
    let id = Uuid::new_v4();
    let cfg = json!({"kind": src.kind, "url": src.url, "username": src.username, "password": src.password});
    sqlx::query("INSERT INTO calendar_sources(id,owner_id,name,configuration,enabled) VALUES($1,$2,$3,$4,$5)").bind(id).bind(a.scope.owner_id).bind(&input.name).bind(&cfg).bind(input.enabled).execute(&state.pool).await?;
    Ok(Json(json!({"id": id, "name": input.name, "kind": src.kind, "enabled": input.enabled})))
}
#[utoipa::path(delete, path = "/api/v1/calendar/sources/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn remove_source(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let done = sqlx::query("DELETE FROM calendar_sources WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&state.pool).await?.rows_affected();
    if done == 0 {
        return Err(Error::NotFound.into());
    }
    Ok(Json(json!({"removed": id})))
}
#[utoipa::path(post, path = "/api/v1/calendar/sources/{id}/sync", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn sync_source(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row: Option<(String, Value)> = sqlx::query_as("SELECT name,configuration FROM calendar_sources WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?;
    let (name, cfg) = row.ok_or(Error::NotFound)?;
    let src = orbit_calendar::CalendarSource { kind: cfg.get("kind").and_then(Value::as_str).unwrap_or("").into(), url: cfg.get("url").and_then(Value::as_str).unwrap_or("").into(), username: cfg.get("username").and_then(Value::as_str).map(str::to_owned), password: cfg.get("password").and_then(Value::as_str).map(str::to_owned) };
    let out = orbit_calendar::sync_source(&state.pool, &a.scope, &name, &src).await?;
    sqlx::query("UPDATE calendar_sources SET last_sync=now(),updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&state.pool).await?;
    Ok(Json(out))
}
#[derive(Deserialize, utoipa::ToSchema)]
pub struct EventsQuery { pub from: Option<String>, pub to: Option<String>, pub limit: Option<i64> }
#[utoipa::path(get, path = "/api/v1/calendar/events", responses((status = 200, body = Value)))]
pub async fn list_events(State(state): State<ApiState>, headers: HeaderMap, Query(q): Query<EventsQuery>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<Value> = if q.from.is_some() || q.to.is_some() {
        sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id'-'raw' FROM calendar_events t WHERE owner_id=$1 AND ($2::timestamptz IS NULL OR starts_at>=$2) AND ($3::timestamptz IS NULL OR starts_at<$3) ORDER BY starts_at NULLS LAST,id LIMIT $4").bind(a.scope.owner_id).bind(q.from.as_deref()).bind(q.to.as_deref()).bind(limit).fetch_all(&state.pool).await?
    } else {
        sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id'-'raw' FROM calendar_events t WHERE owner_id=$1 ORDER BY starts_at NULLS LAST,id LIMIT $2").bind(a.scope.owner_id).bind(limit).fetch_all(&state.pool).await?
    };
    Ok(Json(json!({"items": rows})))
}
#[utoipa::path(get, path = "/api/v1/calendar/today", responses((status = 200, body = Value)))]
pub async fn today(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id'-'raw' FROM calendar_events t WHERE owner_id=$1 AND starts_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AND starts_at<date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'+interval '1 day' ORDER BY starts_at NULLS LAST,id LIMIT 100").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
    Ok(Json(json!({"items": rows})))
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_sources, create_source, remove_source, sync_source, list_events, today))]
pub struct CalendarApi;
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/calendar/sources", get(list_sources).post(create_source))
        .route("/api/v1/calendar/sources/{id}", delete(remove_source))
        .route("/api/v1/calendar/sources/{id}/sync", post(sync_source))
        .route("/api/v1/calendar/events", get(list_events))
        .route("/api/v1/calendar/today", get(today))
}
