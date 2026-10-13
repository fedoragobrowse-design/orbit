//! Home Assistant + GitHub connectors (growth C13).
//!
//! Both follow the email-account pattern: a row names the connection, the
//! token lives write-only in the sealed `SecretStore`, and polling stores
//! third-party bytes as untrusted data (bounded, control-char rejected).
//! GitHub PAT keeps `oauth_clients(connector=github)` at `usable:false` —
//! the PAT is the supported path; OAuth client storage is unchanged.
use axum::{Json, Router, extract::{Path, Query, State}, http::HeaderMap, routing::{get, post}};
use orbit_core::{Error, OwnerScope};
use orbit_secrets::SecretStore;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
use crate::{ApiError, ApiState, authenticate};
/// One `CONNECTOR_*_RECEIVED` receipt per successful sync (email `sync_batch`
/// gate, adapted): writes when — and only when — at least one row was
/// inserted/updated, reusing the existing `events` + `event_deliveries`
/// tables with a `foundation` delivery. No-op syncs write nothing.
pub(crate) async fn emit_connector_receipt(pool: &sqlx::PgPool, scope: &OwnerScope, kind: &str, source: &str, source_key: &str, payload: Value) -> Result<(), Error> {
    let event = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,$3,$4,$5,$6,'UNTRUSTED_EXTERNAL','PRIVATE',$7,$8) ON CONFLICT(owner_id,source,source_event_key) DO NOTHING RETURNING id")
        .bind(event).bind(scope.owner_id).bind(kind).bind(source).bind(scope.principal_id).bind(&payload).bind(event).bind(source_key)
        .fetch_optional(&mut *tx).await?.is_some();
    if inserted {
        sqlx::query("INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING")
            .bind(Uuid::new_v4()).bind(scope.owner_id).bind(event).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(())
}
/// Connector manifest schema: id + description-from-file metadata, the tool
/// actions the connector exposes, its input/output schemas, required scopes,
/// the sealed-store credential type, and the `CONNECTOR_*_RECEIVED` event the
/// sync path emits. New (uninstalled) connectors start
/// disabled/untrusted: `enabled=false`, `trusted=false`, with a permission
/// preview naming the scopes the owner must approve before first sync.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    pub id: String,
    pub description: String,
    pub actions: Vec<String>,
    pub input_schema: Value,
    pub output_schema: Value,
    pub scopes: Vec<String>,
    pub credential: String,
    pub event: String,
    pub cursor: String,
    pub enabled: bool,
    pub trusted: bool,
    pub permission_preview: Vec<String>,
}
fn manifest(id: &str, description: &str, actions: &[&str], scopes: &[&str], credential: &str, event: &str, cursor: &str) -> ConnectorManifest {
    ConnectorManifest {
        id: id.into(),
        description: description.into(),
        actions: actions.iter().map(|s| s.to_string()).collect(),
        input_schema: json!({"type": "object"}),
        output_schema: json!({"type": "object", "properties": {"synced": {"type": "boolean"}, "stored": {"type": "integer"}}}),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        credential: credential.into(),
        event: event.into(),
        cursor: cursor.into(),
        enabled: false,
        trusted: false,
        permission_preview: scopes.iter().map(|s| s.to_string()).collect(),
    }
}
/// Built-in connector manifests keyed by `manifest.id`. New sources start
/// disabled/untrusted with a permission preview; the owner flips `enabled`
/// by approving the manifest's scopes (marketplace install gate).
pub fn manifests() -> Vec<ConnectorManifest> {
    vec![
        manifest("ha", "Home Assistant states connector (crates/api/src/connectors.rs)", &["sync", "list_states", "list_entities"], &["ha:read"], "ha-token", "CONNECTOR_HA_RECEIVED", "last_sync"),
        manifest("github", "GitHub notifications connector (crates/api/src/connectors.rs)", &["sync", "list"], &["github:notifications"], "github-token", "CONNECTOR_GITHUB_RECEIVED", "last_sync"),
        manifest("calendar", "Calendar ICS/CalDAV connector (crates/api/src/calendar.rs)", &["sync", "list_events", "today"], &["calendar:read"], "calendar-basic", "CONNECTOR_CALENDAR_RECEIVED", "last_sync"),
        manifest("inbox", "AI inbox import connector (crates/api/src/inbox.rs)", &["import", "list"], &["inbox:write"], "none", "CONNECTOR_INBOX_RECEIVED", "received_at"),
    ]
}
const MAX_TOKEN_BYTES: usize = 8192;
const MAX_URL_LEN: usize = 2048;
const MAX_NAME_LEN: usize = 64;
const MAX_ROWS: i64 = 200;
fn name_ok(v: &str) -> Result<String, Error> {
    let v = v.trim();
    if v.is_empty() || v.len() > MAX_NAME_LEN || v.chars().any(char::is_control) { return Err(Error::Validation("invalid connection name".into())); }
    Ok(v.to_owned())
}
fn url_ok(v: &str) -> Result<String, Error> {
    let v = v.trim();
    if v.is_empty() || v.len() > MAX_URL_LEN || v.chars().any(char::is_control) { return Err(Error::Validation("invalid base url".into())); }
    let lower = v.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") { return Err(Error::Validation("base url must be http(s)".into())); }
    Ok(v.to_owned())
}
fn ha_endpoint(base: &str) -> Result<orbit_model_router::endpoint::AdmittedEndpoint, Error> {
    let base = url_ok(base)?;
    Ok(orbit_model_router::endpoint::AdmittedEndpoint { origin: base, local: false, admitted_addresses: vec![] })
}
fn token_ok(v: &str) -> Result<(), Error> {
    if v.is_empty() || v.len() > MAX_TOKEN_BYTES { return Err(Error::Validation("invalid token size".into())); }
    Ok(())
}
fn entity_ok(v: &str) -> bool { !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control) }
fn text_ok(v: &str, cap: usize) -> bool { v.len() <= cap && !v.chars().any(char::is_control) }
async fn revoke_quiet(state: &ApiState, scope: &OwnerScope, id: Uuid) {
    if let Ok(store) = SecretStore::open(state.pool.clone(), &state.key_dir).await { let _ = store.revoke(scope, id).await; }
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HaCreate { pub name: String, pub base_url: String, pub token: String }
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GithubCreate { pub name: String, pub token: String }
#[derive(Deserialize)]
pub struct Page { pub limit: Option<i64> }
#[utoipa::path(post, path = "/api/v1/ha/connections", request_body = HaCreate, responses((status = 200, body = Value)))]
pub async fn create_ha(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<HaCreate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let name = name_ok(&input.name).map_err(ApiError::from)?;
    let base = url_ok(&input.base_url).map_err(ApiError::from)?;
    ha_endpoint(&base).map_err(ApiError::from)?.client().await.map_err(ApiError::from)?;
    token_ok(&input.token).map_err(ApiError::from)?;
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let fresh = store.put(&a.scope, "ha-token", input.token.as_bytes()).await?;
    let row = sqlx::query("INSERT INTO ha_connections(id,owner_id,name,base_url,credential_id) VALUES($1,$2,$3,$4,$5) RETURNING id,created_at,updated_at")
        .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(&name).bind(&base).bind(fresh)
        .fetch_one(&state.pool).await.map_err(|e| match e { sqlx::Error::Database(d) if d.constraint() == Some("ha_connections_owner_id_name_key") => ApiError(Error::Conflict("calendar connection name taken".into())), _ => ApiError::from(e) })?;
    Ok(Json(json!({"id": row.try_get::<Uuid,_>("id")?, "name": name, "base_url": base, "enabled": true, "configured": true, "created_at": row.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at")?, "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>,_>("updated_at")?})))
}
#[utoipa::path(get, path = "/api/v1/ha/connections", responses((status = 200, body = Value)))]
pub async fn list_ha(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id,name,base_url,credential_id IS NOT NULL AS configured,enabled,last_sync,created_at,updated_at FROM ha_connections WHERE owner_id=$1 ORDER BY created_at").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id": r.try_get::<Uuid,_>("id").ok(), "name": r.try_get::<String,_>("name").unwrap_or_default(), "base_url": r.try_get::<String,_>("base_url").unwrap_or_default(), "configured": r.try_get::<bool,_>("configured").unwrap_or(false), "enabled": r.try_get::<bool,_>("enabled").unwrap_or(false), "last_sync": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_sync").unwrap_or(None), "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(), "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("updated_at").ok()})).collect();
    Ok(Json(json!({"items": items})))
}
#[utoipa::path(post, path = "/api/v1/ha/connections/{id}/sync", params(("id" = String, Path)), responses((status = 200, body = Value)))]
pub async fn sync_ha(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = sqlx::query("SELECT base_url,credential_id FROM ha_connections WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;
    let base: String = row.try_get("base_url")?;
    let cred: Option<Uuid> = row.try_get("credential_id")?;
    let Some(cred) = cred else { return Err(Error::Validation("connection has no stored token".into()).into()); };
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let token = String::from_utf8(store.get(&a.scope, cred).await?.to_vec()).map_err(|_| Error::Validation("stored token unreadable".to_string()))?;
    let ep = ha_endpoint(&base).map_err(ApiError::from)?;
    let url = ep.url("api/states").map_err(ApiError::from)?;
    let req = ep.client().await.map_err(ApiError::from)?.get(url).bearer_auth(&token);
    let sent = tokio::time::timeout(std::time::Duration::from_secs(20), req.send()).await.map_err(|_| Error::Unavailable("home assistant unreachable (timeout)".to_string()))?;
    let resp = sent.map_err(|_| ApiError(Error::Unavailable("home assistant unreachable".to_string())))?;
    if resp.status().is_redirection() { return Err(ApiError(Error::Unavailable("home assistant rejected the request (redirect refused)".to_string()))); }
    let states: Vec<Value> = resp.error_for_status().map_err(|_| ApiError(Error::Unavailable("home assistant rejected the request".to_string())))?.json().await.map_err(|_| ApiError(Error::Validation("home assistant returned invalid states".to_string())))?;
    let mut stored = 0i64;
    for s in states.iter().take(MAX_ROWS as usize) {
        let entity = s.get("entity_id").and_then(Value::as_str).unwrap_or("");
        let st = s.get("state").and_then(Value::as_str).unwrap_or("");
        if !entity_ok(entity) || !text_ok(st, 1024) { continue; }
        let attrs = s.get("attributes").cloned().unwrap_or(json!({}));
        let observed: Option<chrono::DateTime<chrono::Utc>> = s.get("last_updated").and_then(Value::as_str).and_then(|v| v.parse().ok());
        sqlx::query("INSERT INTO ha_states(id,owner_id,connection_id,entity_id,state,attributes,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (owner_id,connection_id,entity_id) DO UPDATE SET state=EXCLUDED.state,attributes=EXCLUDED.attributes,observed_at=EXCLUDED.observed_at")
            .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(id).bind(entity).bind(st).bind(attrs).bind(observed).execute(&state.pool).await?;
        stored += 1;
    }
    sqlx::query("UPDATE ha_connections SET last_sync=now(),updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&state.pool).await?;
    if stored > 0 {
        emit_connector_receipt(&state.pool, &a.scope, "CONNECTOR_HA_RECEIVED", &format!("ha:{id}"), &format!("ha-sync:{id}:{}", Uuid::new_v4()), json!({"connection_id": id, "stored": stored, "source_reference": format!("ha:{id}")})).await?;
    }
    Ok(Json(json!({"synced": true, "stored": stored})))
}
#[utoipa::path(post, path = "/api/v1/ha/connections/{id}/remove", params(("id" = String, Path)), responses((status = 200, body = Value)))]
pub async fn remove_ha(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let cred: Option<Option<Uuid>> = sqlx::query_scalar("DELETE FROM ha_connections WHERE owner_id=$1 AND id=$2 RETURNING credential_id").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?;
    let Some(cred) = cred.flatten() else { return Err(Error::NotFound.into()); };
    revoke_quiet(&state, &a.scope, cred).await;
    Ok(Json(json!({"removed": id.to_string()})))
}
#[utoipa::path(post, path = "/api/v1/github/connections", request_body = GithubCreate, responses((status = 200, body = Value)))]
pub async fn create_github(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<GithubCreate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let name = name_ok(&input.name).map_err(ApiError::from)?;
    token_ok(&input.token).map_err(ApiError::from)?;
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let fresh = store.put(&a.scope, "github-token", input.token.as_bytes()).await?;
    let row = sqlx::query("INSERT INTO github_connections(id,owner_id,name,credential_id) VALUES($1,$2,$3,$4) RETURNING id,created_at,updated_at")
        .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(&name).bind(fresh)
        .fetch_one(&state.pool).await.map_err(|e| match e { sqlx::Error::Database(d) if d.constraint() == Some("github_connections_owner_id_name_key") => ApiError(Error::Conflict("github connection name taken".into())), _ => ApiError::from(e) })?;
    Ok(Json(json!({"id": row.try_get::<Uuid,_>("id")?, "name": name, "enabled": true, "configured": true, "created_at": row.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at")?, "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>,_>("updated_at")?})))
}
#[utoipa::path(get, path = "/api/v1/github/connections", responses((status = 200, body = Value)))]
pub async fn list_github(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id,name,credential_id IS NOT NULL AS configured,enabled,last_sync,created_at,updated_at FROM github_connections WHERE owner_id=$1 ORDER BY created_at").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id": r.try_get::<Uuid,_>("id").ok(), "name": r.try_get::<String,_>("name").unwrap_or_default(), "configured": r.try_get::<bool,_>("configured").unwrap_or(false), "enabled": r.try_get::<bool,_>("enabled").unwrap_or(false), "last_sync": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_sync").unwrap_or(None), "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok(), "updated_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("updated_at").ok()})).collect();
    Ok(Json(json!({"items": items})))
}
#[utoipa::path(post, path = "/api/v1/github/connections/{id}/sync", params(("id" = String, Path)), responses((status = 200, body = Value)))]
pub async fn sync_github(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = sqlx::query("SELECT credential_id FROM github_connections WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;
    let cred: Option<Uuid> = row.try_get("credential_id")?;
    let Some(cred) = cred else { return Err(Error::Validation("connection has no stored token".into()).into()); };
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let token = String::from_utf8(store.get(&a.scope, cred).await?.to_vec()).map_err(|_| Error::Validation("stored token unreadable".to_string()))?;
    let client = reqwest::Client::builder().user_agent("orbit-github-connector").timeout(std::time::Duration::from_secs(20)).build().map_err(|_| Error::Unavailable("http client unavailable".to_string()))?;
    let notifs: Vec<Value> = client.get("https://api.github.com/notifications?per_page=50").bearer_auth(&token).header("Accept", "application/vnd.github+json").send().await.map_err(|_| Error::Unavailable("github unreachable".to_string()))?
        .error_for_status().map_err(|_| Error::Unavailable("github rejected the token".to_string()))?
        .json().await.map_err(|_| Error::Validation("github returned invalid notifications".to_string()))?;
    let mut stored = 0i64;
    for (i, n) in notifs.iter().take(50).enumerate() {
        let title = n.get("subject").and_then(|s| s.get("title")).and_then(Value::as_str).unwrap_or("");
        let url = n.get("subject").and_then(|s| s.get("url")).and_then(Value::as_str).unwrap_or("");
        let kind = n.get("subject").and_then(|s| s.get("type")).and_then(Value::as_str).unwrap_or("notification");
        if !text_ok(title, 512) || !text_ok(url, 2048) || !text_ok(kind, 64) { continue; }
        sqlx::query("INSERT INTO github_events_cache(id,owner_id,connection_id,repo,kind,number,title,state,url,observed_at) VALUES($1,$2,$3,'', $4,$5,$6,'', $7,now()) ON CONFLICT (owner_id,connection_id,kind,number) DO UPDATE SET title=EXCLUDED.title,url=EXCLUDED.url,observed_at=now()")
            .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(id).bind(kind).bind(100000 + i as i32).bind(title).bind(url).execute(&state.pool).await?;
        stored += 1;
    }
    sqlx::query("UPDATE github_connections SET last_sync=now(),updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&state.pool).await?;
    if stored > 0 {
        emit_connector_receipt(&state.pool, &a.scope, "CONNECTOR_GITHUB_RECEIVED", &format!("github:{id}"), &format!("github-sync:{id}:{}", Uuid::new_v4()), json!({"connection_id": id, "stored": stored, "source_reference": format!("github:{id}")})).await?;
    }
    Ok(Json(json!({"synced": true, "stored": stored})))
}
#[utoipa::path(post, path = "/api/v1/github/connections/{id}/remove", params(("id" = String, Path)), responses((status = 200, body = Value)))]
pub async fn remove_github(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let cred: Option<Option<Uuid>> = sqlx::query_scalar("DELETE FROM github_connections WHERE owner_id=$1 AND id=$2 RETURNING credential_id").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?;
    let Some(cred) = cred.flatten() else { return Err(Error::NotFound.into()); };
    revoke_quiet(&state, &a.scope, cred).await;
    Ok(Json(json!({"removed": id.to_string()})))
}
#[utoipa::path(get, path = "/api/v1/ha/states", responses((status = 200, body = Value)))]
pub async fn list_states(State(state): State<ApiState>, headers: HeaderMap, Query(p): Query<Page>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = p.limit.unwrap_or(50).clamp(1, MAX_ROWS);
    let rows = sqlx::query("SELECT id,connection_id,entity_id,state,attributes,observed_at FROM ha_states WHERE owner_id=$1 ORDER BY observed_at DESC NULLS LAST LIMIT $2").bind(a.scope.owner_id).bind(limit).fetch_all(&state.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id": r.try_get::<Uuid,_>("id").ok(), "connection_id": r.try_get::<Uuid,_>("connection_id").ok(), "entity_id": r.try_get::<String,_>("entity_id").unwrap_or_default(), "state": r.try_get::<String,_>("state").unwrap_or_default(), "attributes": r.try_get::<Value,_>("attributes").unwrap_or(json!({})), "observed_at": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("observed_at").unwrap_or(None)})).collect();
    Ok(Json(json!({"items": items})))
}
/// P4 Home Assistant tab: entity snapshots from `ha_entities` (0030).
/// Every row returns `tainted:true`: states/attributes are third-party
/// bytes pulled from the operator-configured HA URL, stored only as
/// UntrustedExternal content. There is deliberately no actuation path
/// here — a state change is a Confirm-gated tool proposal, never a write
/// through this route. Owner-scoped; `last_seen` orders newest first.
#[utoipa::path(get, path = "/api/v1/ha/entities", responses((status = 200, body = Value)))]
pub async fn list_entities(State(state): State<ApiState>, headers: HeaderMap, Query(p): Query<Page>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = p.limit.unwrap_or(50).clamp(1, MAX_ROWS);
    let rows = sqlx::query("SELECT id,entity_id,state,attributes,connection_id,tainted,last_seen FROM ha_entities WHERE owner_id=$1 ORDER BY last_seen DESC NULLS LAST LIMIT $2").bind(a.scope.owner_id).bind(limit).fetch_all(&state.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id": r.try_get::<Uuid,_>("id").ok(), "entity_id": r.try_get::<String,_>("entity_id").unwrap_or_default(), "state": r.try_get::<String,_>("state").unwrap_or_default(), "attributes": r.try_get::<Value,_>("attributes").unwrap_or(json!({})), "connection_id": r.try_get::<Option<Uuid>,_>("connection_id").unwrap_or(None), "tainted": r.try_get::<bool,_>("tainted").unwrap_or(true), "trust_level": "UNTRUSTED_EXTERNAL", "last_seen": r.try_get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_seen").unwrap_or(None)})).collect();
    Ok(Json(json!({"items": items})))
}
/// P4 HA sync: pull `/api/states` from the operator-configured HA base URL
/// (the `ha_connections` row names the connection; its token lives
/// write-only in the sealed `SecretStore` and never surfaces) and upsert
/// snapshots into `ha_entities`. Request and storage reuse the 0019 screen:
/// `AdmittedEndpoint` client (SSRF/loopback/metadata refused, no
/// redirects), 20 s timeout, 200-row cap, entity/state bounded with
/// control-char rejection, attributes defaulting to `{}`. Rows land with
/// `tainted=true` — untrusted content taint rides to the classifier and
/// `validate_context` keeps these values out of SystemPolicy/
/// UserInstruction privileged context. Never actuates: states are stored,
/// never sent back as commands.
#[utoipa::path(post, path = "/api/v1/ha/sync", responses((status = 200, body = Value)))]
pub async fn sync_entities(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<HaSync>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = sqlx::query("SELECT base_url,credential_id FROM ha_connections WHERE owner_id=$1 AND id=$2 AND enabled").bind(a.scope.owner_id).bind(input.connection_id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;
    let base: String = row.try_get("base_url")?;
    let cred: Option<Uuid> = row.try_get("credential_id")?;
    let Some(cred) = cred else { return Err(Error::Validation("connection has no stored token".into()).into()); };
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let token = String::from_utf8(store.get(&a.scope, cred).await?.to_vec()).map_err(|_| Error::Validation("stored token unreadable".to_string()))?;
    let ep = ha_endpoint(&base).map_err(ApiError::from)?;
    let url = ep.url("api/states").map_err(ApiError::from)?;
    let req = ep.client().await.map_err(ApiError::from)?.get(url).bearer_auth(&token);
    let sent = tokio::time::timeout(std::time::Duration::from_secs(20), req.send()).await.map_err(|_| Error::Unavailable("home assistant unreachable (timeout)".to_string()))?;
    let resp = sent.map_err(|_| ApiError(Error::Unavailable("home assistant unreachable".to_string())))?;
    if resp.status().is_redirection() { return Err(ApiError(Error::Unavailable("home assistant rejected the request (redirect refused)".to_string()))); }
    let states: Vec<Value> = resp.error_for_status().map_err(|_| ApiError(Error::Unavailable("home assistant rejected the request".to_string())))?.json().await.map_err(|_| ApiError(Error::Validation("home assistant returned invalid states".to_string())))?;
    let mut stored = 0i64;
    for s in states.iter().take(MAX_ROWS as usize) {
        let entity = s.get("entity_id").and_then(Value::as_str).unwrap_or("");
        let st = s.get("state").and_then(Value::as_str).unwrap_or("");
        if !entity_ok(entity) || !text_ok(st, 1024) { continue; }
        let attrs = s.get("attributes").cloned().unwrap_or(json!({}));
        let observed: Option<chrono::DateTime<chrono::Utc>> = s.get("last_updated").and_then(Value::as_str).and_then(|v| v.parse().ok());
        sqlx::query("INSERT INTO ha_entities(id,owner_id,entity_id,state,attributes,connection_id,tainted,last_seen) VALUES($1,$2,$3,$4,$5,$6,true,$7) ON CONFLICT (owner_id,entity_id) DO UPDATE SET state=EXCLUDED.state,attributes=EXCLUDED.attributes,connection_id=EXCLUDED.connection_id,tainted=true,last_seen=EXCLUDED.last_seen,updated_at=now()")
            .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(entity).bind(st).bind(attrs).bind(input.connection_id).bind(observed).execute(&state.pool).await?;
        stored += 1;
    }
    sqlx::query("UPDATE ha_connections SET last_sync=now(),updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(input.connection_id).execute(&state.pool).await?;
    if stored > 0 {
        emit_connector_receipt(&state.pool, &a.scope, "CONNECTOR_HA_RECEIVED", &format!("ha:{}", input.connection_id), &format!("ha-entities-sync:{}:{}", input.connection_id, Uuid::new_v4()), json!({"connection_id": input.connection_id, "stored": stored, "source_reference": format!("ha:{}", input.connection_id)})).await?;
    }
    Ok(Json(json!({"synced": true, "stored": stored})))
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HaSync { pub connection_id: Uuid }
pub struct ConnectorApi;
/// Connector manifests: id, description-from-file, actions, schemas,
/// scopes, sealed-store credential type, emitted event, and cursor.
/// New sources start disabled/untrusted with a permission preview;
/// installing (marketplace gate) or approving scopes flips `enabled`.
#[utoipa::path(get, path = "/api/v1/connectors/manifests", responses((status = 200, body = Value)))]
pub async fn list_manifests(State(_state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let _ = authenticate(&_state, &headers, false).await?;
    Ok(Json(json!({"items": manifests()})))
}
impl ConnectorApi {
    pub fn router() -> Router<ApiState> {
        Router::new()
            .route("/api/v1/connectors/manifests", get(list_manifests))
            .route("/api/v1/ha/connections", post(create_ha).get(list_ha))
            .route("/api/v1/ha/connections/{id}/sync", post(sync_ha))
            .route("/api/v1/ha/connections/{id}/remove", post(remove_ha))
            .route("/api/v1/ha/states", get(list_states))
            .route("/api/v1/ha/entities", get(list_entities))
            .route("/api/v1/ha/sync", post(sync_entities))
            .route("/api/v1/github/connections", post(create_github).get(list_github))
            .route("/api/v1/github/connections/{id}/sync", post(sync_github))
            .route("/api/v1/github/connections/{id}/remove", post(remove_github))
    }
}
pub fn router() -> Router<ApiState> { ConnectorApi::router() }
