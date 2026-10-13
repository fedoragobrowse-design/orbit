//! API tokens (growth D15): owner-minted `orb_` bearer tokens with the
//! same `OwnerScope` as a session. Plaintext is returned ONCE at create;
//! only the SHA256 hash is stored. Revoked tokens fail closed.
use axum::{Json, Router, extract::{Path, State}, http::HeaderMap, routing::post};
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
pub struct TokenCreate { pub name: String, #[serde(default)] pub grants: Vec<TokenGrantInput> }
/// Explicit service/tool grant attached to a token at mint or update time.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenGrantInput { pub service: String, pub tool_name: String }
/// Services that may appear in grants.
pub const GRANT_SERVICES: [&str; 3] = ["orbit-control", "orbit-data", "ha-control"];
/// Validate a grant against the service allow-list and the live tool
/// descriptors; unknown services or tools fail closed.
pub fn grant_ok(service: &str, tool_name: &str) -> Result<(String, String), Error> {
    let service = service.trim();
    let tool_name = tool_name.trim();
    if !GRANT_SERVICES.contains(&service) {
        return Err(Error::Validation("unknown grant service".into()));
    }
    let prefix = format!("{service}.");
    if !tool_name.starts_with(&prefix)
        || !orbit_tools::descriptors().iter().any(|d| d.name == tool_name)
    {
        return Err(Error::Validation("unknown grant tool".into()));
    }
    Ok((service.to_owned(), tool_name.to_owned()))
}
#[utoipa::path(post, path = "/api/v1/tokens", request_body = TokenCreate, responses((status = 200, body = Value)))]
pub async fn create_token(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<TokenCreate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Session-cookie auth only: a stolen bearer must not mint persistence.
    if a.session_id == Uuid::nil() { return Err(Error::Forbidden.into()); }
    let name = name_ok(&input.name).map_err(ApiError::from)?;
    let mut checked: Vec<(String, String)> = Vec::with_capacity(input.grants.len());
    for grant in &input.grants {
        checked.push(grant_ok(&grant.service, &grant.tool_name).map_err(ApiError::from)?);
    }
    let plain = mint();
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await.map_err(ApiError::from)?;
    sqlx::query("INSERT INTO api_tokens(id,owner_id,name,token_hash) VALUES($1,$2,$3,$4)").bind(id).bind(a.scope.owner_id).bind(&name).bind(crate::auth::hash(&plain)).execute(&mut *tx).await.map_err(ApiError::from)?;
    for (service, tool_name) in &checked {
        sqlx::query("INSERT INTO api_token_grants(token_id,owner_id,service,tool_name) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(id).bind(a.scope.owner_id).bind(service).bind(tool_name).execute(&mut *tx).await.map_err(ApiError::from)?;
    }
    tx.commit().await.map_err(ApiError::from)?;
    Ok(Json(json!({"id": id, "name": name, "token": plain, "grants": checked.iter().map(|(service, tool_name)| json!({"service": service, "tool_name": tool_name})).collect::<Vec<_>>(), "warning": "Copy this token now — Orbit never shows it again."})))
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
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenGrantsUpdate { pub grants: Vec<TokenGrantInput> }
#[utoipa::path(post, path = "/api/v1/tokens/{id}/grants", params(("id" = String, Path)), request_body = TokenGrantsUpdate, responses((status = 200, body = Value)))]
pub async fn set_token_grants(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<TokenGrantsUpdate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Session-cookie auth only: grants are credential lifecycle changes.
    if a.session_id == Uuid::nil() { return Err(Error::Forbidden.into()); }
    let mut checked: Vec<(String, String)> = Vec::with_capacity(input.grants.len());
    for grant in &input.grants {
        checked.push(grant_ok(&grant.service, &grant.tool_name).map_err(ApiError::from)?);
    }
    let mut tx = state.pool.begin().await.map_err(ApiError::from)?;
    let owned: Option<Uuid> = sqlx::query_scalar("SELECT id FROM api_tokens WHERE owner_id=$1 AND id=$2 AND revoked=false").bind(a.scope.owner_id).bind(id).fetch_optional(&mut *tx).await.map_err(ApiError::from)?;
    if owned.is_none() { return Err(Error::NotFound.into()); }
    sqlx::query("DELETE FROM api_token_grants WHERE owner_id=$1 AND token_id=$2").bind(a.scope.owner_id).bind(id).execute(&mut *tx).await.map_err(ApiError::from)?;
    for (service, tool_name) in &checked {
        sqlx::query("INSERT INTO api_token_grants(token_id,owner_id,service,tool_name) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(id).bind(a.scope.owner_id).bind(service).bind(tool_name).execute(&mut *tx).await.map_err(ApiError::from)?;
    }
    tx.commit().await.map_err(ApiError::from)?;
    Ok(Json(json!({"id": id, "grants": checked.iter().map(|(service, tool_name)| json!({"service": service, "tool_name": tool_name})).collect::<Vec<_>>()})))
}
pub async fn token_grants(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT service,tool_name FROM api_token_grants WHERE owner_id=$1 AND token_id=$2 ORDER BY service,tool_name").bind(a.scope.owner_id).bind(id).fetch_all(&state.pool).await.map_err(ApiError::from)?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"service": r.try_get::<String,_>("service").unwrap_or_default(), "tool_name": r.try_get::<String,_>("tool_name").unwrap_or_default()})).collect();
    Ok(Json(json!({"id": id, "grants": items})))
}
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/tokens/{id}/revoke", post(revoke_token))
        .route("/api/v1/tokens/{id}/grants", post(set_token_grants).get(token_grants))
 }
