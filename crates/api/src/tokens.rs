//! API tokens (growth D15): owner-minted `orb_` bearer tokens with the
//! same `OwnerScope` as a session. Plaintext is returned ONCE at create;
//! only the SHA256 hash is stored. Revoked tokens fail closed.
use axum::{Json, Router, extract::{Path, State}, http::HeaderMap, routing::{get, post}};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
use crate::{ApiError, ApiState, authenticate};
pub const PREFIX: &str = "orb_";
fn name_ok(v: &str) -> Result<String, Error> {
    let v = v.trim();
    if v.is_empty() || v.len() > 64 || v.chars().any(char::is_control) { return Err(Error::Validation("invalid token name".into())); }
    Ok(v.to_owned())
}
pub fn mint() -> String { format!("{PREFIX}{}", crate::auth::random()) }
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenCreate { pub name: String }
#[utoipa::path(post, path = "/api/v1/tokens", request_body = TokenCreate, responses((status = 200, body = Value)))]
pub async fn create_token(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<TokenCreate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Session-cookie auth only: a stolen bearer must not mint persistence.
    if a.session_id == Uuid::nil() { return Err(Error::Forbidden.into()); }
    let name = name_ok(&input.name).map_err(ApiError::from)?;
    let plain = mint();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO api_tokens(id,owner_id,name,token_hash) VALUES($1,$2,$3,$4)").bind(id).bind(a.scope.owner_id).bind(&name).bind(crate::auth::hash(&plain)).execute(&state.pool).await?;
    Ok(Json(json!({"id": id, "name": name, "token": plain, "warning": "Copy this token now — Orbit never shows it again."})))
}
#[utoipa::path(get, path = "/api/v1/tokens", responses((status = 200, body = Value)))]
pub async fn list_tokens(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id,name,scopes,last_used,revoked,created_at FROM api_tokens WHERE owner_id=$1 AND revoked=false ORDER BY created_at").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id": r.try_get::<Uuid,_>("id").ok(), "name": r.try_get::<String,_>("name").unwrap_or_default(), "scopes": r.try_get::<Value,_>("scopes").unwrap_or(json!([])), "last_used": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_used").unwrap_or(None), "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok()})).collect();
    Ok(Json(json!({"items": items})))
}
#[utoipa::path(post, path = "/api/v1/tokens/{id}/revoke", params(("id" = String, Path)), responses((status = 200, body = Value)))]
pub async fn revoke_token(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Session-cookie auth only: revocation is a credential lifecycle change.
    if a.session_id == Uuid::nil() { return Err(Error::Forbidden.into()); }
    let n = sqlx::query("UPDATE api_tokens SET revoked=true WHERE owner_id=$1 AND id=$2 AND revoked=false").bind(a.scope.owner_id).bind(id).execute(&state.pool).await?.rows_affected();
    if n == 0 { return Err(Error::NotFound.into()); }
    Ok(Json(json!({"revoked": id.to_string()})))
}
pub fn bearer(headers: &HeaderMap) -> Option<String> {
    headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?.strip_prefix(PREFIX).map(str::to_owned)
}
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/tokens/{id}/revoke", post(revoke_token))
}
