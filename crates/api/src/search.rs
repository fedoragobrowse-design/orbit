use crate::{ApiError, ApiState, authenticate};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
/// Global search: one read-scoped POST over the rows the owner already has.
/// Memory, tasks, events, notifications, mail (metadata + body). Files live on
/// nodes, not in Postgres, so the envelope carries a note instead of file hits.
/// Every query is owner-scoped, ILIKE-bounded, capped — the same shape as the
/// brief aggregation, no new tables, no writes, no model calls.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    pub query: String,
    pub limit: Option<i64>,
}
#[utoipa::path(post, path = "/api/v1/search", request_body = SearchQuery, responses((status = 200, body = Value)))]
pub async fn search(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SearchQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let q = input.query.trim();
    if q.is_empty() || q.len() > 256 {
        return Err(Error::Validation("search query required, maximum 256 characters".into()).into());
    }
    let limit = input.limit.unwrap_or(12).clamp(1, 12);
    let like = format!("%{}%", q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let o = a.scope.owner_id;
    let memory: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM memory_records t WHERE owner_id=$1 AND privacy_class != 'SECRET' AND (subject ILIKE $2 ESCAPE '\\' OR value::text ILIKE $2 ESCAPE '\\') ORDER BY updated_at DESC,id DESC LIMIT $3").bind(o).bind(&like).bind(limit).fetch_all(&state.pool).await?;
    let tasks: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM tasks t WHERE owner_id=$1 AND title ILIKE $2 ESCAPE '\\' ORDER BY created_at DESC,id DESC LIMIT $3").bind(o).bind(&like).bind(limit).fetch_all(&state.pool).await?;
    let events: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM events t WHERE owner_id=$1 AND (event_type ILIKE $2 ESCAPE '\\' OR payload::text ILIKE $2 ESCAPE '\\') ORDER BY timestamp DESC,id DESC LIMIT $3").bind(o).bind(&like).bind(limit).fetch_all(&state.pool).await?;
    let notifications: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM notifications t WHERE owner_id=$1 AND (title ILIKE $2 ESCAPE '\\' OR body ILIKE $2 ESCAPE '\\') ORDER BY created_at DESC,id DESC LIMIT $3").bind(o).bind(&like).bind(limit).fetch_all(&state.pool).await?;
    let mail: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'account_id',account_id,'metadata',metadata,'received_at',received_at) FROM email_messages WHERE owner_id=$1 AND (metadata::text ILIKE $2 ESCAPE '\\' OR body_text ILIKE $2 ESCAPE '\\') ORDER BY received_at DESC,id DESC LIMIT $3").bind(o).bind(&like).bind(limit).fetch_all(&state.pool).await?;
    Ok(Json(json!({"query": q, "memory": memory, "tasks": tasks, "events": events, "notifications": notifications, "mail": mail, "files_note": "Files live on your computers, not in search. Open Files on a computer to search them."})))
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(search), components(schemas(SearchQuery)))]
pub struct SearchApi;
pub fn router() -> Router<ApiState> {
    Router::new().route("/api/v1/search", post(search))
}
