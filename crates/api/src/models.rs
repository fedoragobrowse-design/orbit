use crate::{ApiError, ApiState, authenticate};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use orbit_core::{Error, ModelRole, OwnerScope};
use orbit_model_router::{
    endpoint::{local_address, AdmittedEndpoint},
    provider::HttpProvider,
    BudgetLimits, ChatMessage, ChatRequest, CredentialKind, ModelConfig, ModelProvider, ProviderCapabilities,
    ProviderConfig, ProviderKind,
};
use orbit_secrets::SecretStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use std::net::IpAddr;
use utoipa::ToSchema;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Request / query shapes. owner_id is never caller-selectable; credentials are
// write-only and never surface in any response.
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderCreate {
    pub name: String,
    pub kind: String,
    pub origin: String,
    pub local: Option<bool>,
    pub admitted_addresses: Option<Vec<String>>,
    pub credential_kind: Option<String>,
    pub rerank_path: Option<String>,
    pub enabled: Option<bool>,
    pub credential: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderUpdate {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub origin: Option<String>,
    pub local: Option<bool>,
    pub admitted_addresses: Option<Vec<String>>,
    pub credential_kind: Option<String>,
    pub rerank_path: Option<String>,
    pub enabled: Option<bool>,
    pub credential: Option<String>,
    pub expected_revision: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialRotate {
    pub credential: String,
    pub expected_revision: Option<i64>,
}

/// OAuth client registration. The client secret is write-only (sealed into
/// the shared secret store); the client id is configuration and may be
/// shown back with only a short suffix in status responses.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientUpsert {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelCreate {
    pub provider_id: Uuid,
    pub name: String,
    pub model: String,
    pub roles: Vec<String>,
    pub priority: Option<i32>,
    pub context_tokens: u32,
    pub capabilities: Value,
    pub input_usd_per_million: Option<f64>,
    pub output_usd_per_million: Option<f64>,
    pub keep_alive: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelUpdate {
    pub provider_id: Option<Uuid>,
    pub name: Option<String>,
    pub model: Option<String>,
    pub roles: Option<Vec<String>>,
    pub priority: Option<i32>,
    pub context_tokens: Option<u32>,
    pub capabilities: Option<Value>,
    pub input_usd_per_million: Option<Option<f64>>,
    pub output_usd_per_million: Option<Option<f64>>,
    pub keep_alive: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub expected_revision: i64,
}

#[derive(Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetUpdate {
    pub task_usd: f64,
    pub day_usd: f64,
    pub month_usd: f64,
    pub agent_day_usd: f64,
    pub max_model_calls: i32,
    pub max_input_tokens: i64,
    pub max_output_tokens: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListPage {
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelListPage {
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
    pub provider_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCallPage {
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
    pub task_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Validation. Mirrors the router's own admission rules so invalid configs are
// rejected at write time instead of failing at dispatch.
// ---------------------------------------------------------------------------

fn validate_name(name: &str, what: &str) -> Result<String, Error> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(Error::Validation(format!("{what} name must be 1-128 characters")));
    }
    Ok(name.to_owned())
}

fn normalize_enum_token(raw: &str) -> String {
    raw.trim().to_ascii_uppercase().replace(['-', ' ', '.'], "_")
}

fn parse_kind(kind: &str) -> Result<ProviderKind, Error> {
    serde_json::from_value::<ProviderKind>(Value::String(normalize_enum_token(kind))).map_err(
        |_| {
            Error::Validation(
                "unknown provider kind; expected OLLAMA, OPENAI_COMPATIBLE, ANTHROPIC or GEMINI"
                    .into(),
            )
        },
    )
}

fn parse_admitted(raw: Vec<String>) -> Result<Vec<IpAddr>, Error> {
    if raw.len() > 64 {
        return Err(Error::Validation("too many admitted addresses".into()));
    }
    raw.iter()
        .map(|s| {
            s.parse::<IpAddr>()
                .map_err(|_| Error::Validation("invalid admitted address".into()))
        })
        .collect()
}

fn validate_origin(origin: &str, local: bool, admitted: &[IpAddr]) -> Result<(), Error> {
    if origin.is_empty() || origin.len() > 512 {
        return Err(Error::Validation("invalid provider origin".into()));
    }
    // Reuses the router's own origin grammar: HTTP(S) origin, no credentials,
    // query or fragment, no path traversal.
    AdmittedEndpoint {
        origin: origin.to_owned(),
        local,
        admitted_addresses: admitted.to_vec(),
    }
    .url("")
    .map(|_| ())?;
    if !local && !origin.to_ascii_lowercase().starts_with("https://") {
        return Err(Error::Validation("remote provider origin requires HTTPS".into()));
    }
    if local {
        if admitted.is_empty() {
            return Err(Error::Validation(
                "local provider requires at least one admitted address".into(),
            ));
        }
        if !admitted.iter().all(|ip| local_address(*ip)) {
            return Err(Error::Validation(
                "local provider admitted addresses must be loopback or private".into(),
            ));
        }
    }
    Ok(())
}

fn validate_rerank_path(path: Option<String>) -> Result<Option<String>, Error> {
    match path {
        Some(p) => {
            if p.is_empty()
                || p.len() > 256
                || !p.starts_with('/')
                || p.contains("://")
                || p.split('/').any(|s| s == "..")
            {
                return Err(Error::Validation("invalid rerank path".into()));
            }
            Ok(Some(p))
        }
        None => Ok(None),
    }
}

fn validate_credential(secret: &str) -> Result<(), Error> {
    if secret.is_empty() || secret.len() > 65536 {
        return Err(Error::Validation("invalid credential size".into()));
    }
    Ok(())
}
/// Explicit provider credential selection only: API_KEY sends Anthropic as x-api-key, OAUTH sends Bearer + the OAuth beta header. Ambient environment is never consulted.
fn parse_credential_kind(raw: Option<String>) -> Result<CredentialKind, Error> {
    match raw.as_deref().map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("api_key") => Ok(CredentialKind::ApiKey),
        Some("oauth") => Ok(CredentialKind::Oauth),
        Some(_) => Err(Error::Validation("unknown credential kind; expected API_KEY or OAUTH".into())),
    }
}
/// Ollama keep_alive is an explicit duration (e.g. 5m, 1h) or 0 to unload; anything else is rejected so a typo cannot pin VRAM.
fn parse_keep_alive(raw: Option<String>) -> Result<Option<String>, Error> {
    let Some(value) = raw else { return Ok(None) };
    let value = value.trim();
    if value == "0" || value == "-1" {
        return Ok(Some(value.to_owned()));
    }
    let (number, unit) = value.split_at(value.len().saturating_sub(1));
    if value.len() <= 1 || value.len() > 16 || !matches!(unit, "s" | "m" | "h") || number.parse::<f64>().is_err() {
        return Err(Error::Validation("invalid keep_alive; use a duration like 5m or 0".into()));
    }
    Ok(Some(value.to_owned()))
}

/// Supported OAuth connector names. Only connectors with a real (planned)
/// integration surface stay listed; unknown names are rejected so a typo
/// cannot create a silently unused credential row.
fn parse_connector(raw: &str) -> Result<&'static str, Error> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "google" => Ok("google"),
        "outlook" => Ok("outlook"),
        "github" => Ok("github"),
        _ => Err(Error::Validation(
            "unknown OAuth connector; expected google, outlook or github".into(),
        )),
    }
}

fn validate_client_id(id: &str) -> Result<String, Error> {
    let id = id.trim();
    if id.is_empty() || id.len() > 1024 {
        return Err(Error::Validation("invalid OAuth client id".into()));
    }
    Ok(id.to_owned())
}

/// Last-4 suffix of a client id for status display. A client id is
/// non-secret configuration, but even it is only shown truncated.
fn client_id_suffix(id: &str) -> String {
    let tail: String = id.chars().rev().take(4).collect::<String>().chars().rev().collect();
    format!("…{tail}")
}

fn parse_roles(roles: &[String]) -> Result<Vec<ModelRole>, Error> {
    if roles.is_empty() || roles.len() > 16 {
        return Err(Error::Validation("model requires 1-16 roles".into()));
    }
    roles
        .iter()
        .map(|r| {
            serde_json::from_value::<ModelRole>(Value::String(normalize_enum_token(r)))
                .map_err(|_| Error::Validation("unknown model role".into()))
        })
        .collect()
}

fn parse_capabilities(caps: &Value) -> Result<ProviderCapabilities, Error> {
    let caps: ProviderCapabilities = serde_json::from_value(caps.clone())
        .map_err(|_| Error::Validation("invalid model capabilities".into()))?;
    if !(caps.chat || caps.embeddings || caps.rerank) {
        return Err(Error::Validation(
            "model must enable chat, embeddings or rerank".into(),
        ));
    }
    Ok(caps)
}

fn validate_prices(
    input: Option<f64>,
    output: Option<f64>,
) -> Result<(Option<f64>, Option<f64>), Error> {
    match (input, output) {
        (Some(a), Some(b)) => {
            for price in [a, b] {
                if !price.is_finite() || price < 0.0 {
                    return Err(Error::Validation("invalid model price".into()));
                }
            }
            Ok((Some(a), Some(b)))
        }
        (None, None) => Ok((None, None)),
        _ => Err(Error::Validation(
            "model prices must be set together or not at all".into(),
        )),
    }
}

/// The router rejects Anthropic models with embeddings at dispatch; reject the
/// combination at write time instead.
fn check_anthropic(kind: ProviderKind, caps: &ProviderCapabilities) -> Result<(), Error> {
    if kind == ProviderKind::Anthropic && caps.embeddings {
        return Err(Error::UnsupportedCapability);
    }
    Ok(())
}

fn validate_model_name(model: &str) -> Result<String, Error> {
    let model = model.trim();
    if model.is_empty() || model.len() > 256 {
        return Err(Error::Validation(
            "model identifier must be 1-256 characters".into(),
        ));
    }
    Ok(model.to_owned())
}

// ---------------------------------------------------------------------------
// Stored rows. credential_id lives in its column (authoritative for the
// router) and is re-injected into the parsed config; responses only ever
// expose secret_set.
// ---------------------------------------------------------------------------

fn provider_from_row(row: &sqlx::postgres::PgRow) -> Result<(ProviderConfig, i64), Error> {
    let mut raw: Value = row.try_get("configuration")?;
    let credential_id: Option<Uuid> = row.try_get("credential_id")?;
    raw["credential_id"] = json!(credential_id);
    let config: ProviderConfig = serde_json::from_value(raw)
        .map_err(|_| Error::Unavailable("stored provider configuration is invalid".into()))?;
    Ok((config, row.try_get("revision")?))
}

fn model_from_row(row: &sqlx::postgres::PgRow) -> Result<(ModelConfig, i64), Error> {
    let raw: Value = row.try_get("configuration")?;
    let config: ModelConfig = serde_json::from_value(raw)
        .map_err(|_| Error::Unavailable("stored model configuration is invalid".into()))?;
    Ok((config, row.try_get("revision")?))
}

async fn provider_row(
    pool: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
) -> Result<sqlx::postgres::PgRow, Error> {
    sqlx::query(
        "SELECT configuration, credential_id, revision, created_at, updated_at FROM model_providers WHERE owner_id=$1 AND id=$2",
    )
    .bind(owner)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

async fn model_row(
    pool: &sqlx::PgPool,
    owner: Uuid,
    id: Uuid,
) -> Result<sqlx::postgres::PgRow, Error> {
    sqlx::query(
        "SELECT configuration, revision, created_at, updated_at FROM models WHERE owner_id=$1 AND id=$2",
    )
    .bind(owner)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)
}

async fn provider_kind(
    pool: &sqlx::PgPool,
    owner: Uuid,
    provider_id: Uuid,
) -> Result<ProviderKind, Error> {
    let row = provider_row(pool, owner, provider_id).await?;
    Ok(provider_from_row(&row)?.0.kind)
}

async fn provider_has_embedding_models(
    pool: &sqlx::PgPool,
    owner: Uuid,
    provider_id: Uuid,
) -> Result<bool, Error> {
    let rows = sqlx::query("SELECT configuration FROM models WHERE owner_id=$1 AND provider_id=$2")
        .bind(owner)
        .bind(provider_id)
        .fetch_all(pool)
        .await?;
    for row in &rows {
        let raw: Value = row.try_get("configuration")?;
        if let Ok(model) = serde_json::from_value::<ModelConfig>(raw) {
            if model.enabled && model.capabilities.embeddings {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn revoke_quiet(state: &ApiState, scope: &OwnerScope, id: Uuid) {
    if let Ok(store) = SecretStore::open(state.pool.clone(), &state.key_dir).await {
        store.revoke(scope, id).await.ok();
    }
}

fn provider_view(
    config: &ProviderConfig,
    revision: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> Value {
    json!({
        "id": config.id,
        "name": config.name,
        "kind": serde_json::to_value(&config.kind).unwrap_or(Value::String("UNKNOWN".into())),
        "origin": config.origin,
        "local": config.local,
        "admitted_addresses": config.admitted_addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        "credential_kind": serde_json::to_value(&config.credential_kind).unwrap_or(Value::String("API_KEY".into())),
        "rerank_path": config.rerank_path,
        "secret_set": config.credential_id.is_some(),
        "revision": revision,
        "created_at": created_at,
        "updated_at": updated_at,
    })
}

fn model_view(
    config: &ModelConfig,
    revision: i64,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> Value {
    json!({
        "id": config.id,
        "provider_id": config.provider_id,
        "name": config.name,
        "model": config.model,
        "roles": serde_json::to_value(&config.roles).unwrap_or(Value::Null),
        "priority": config.priority,
        "context_tokens": config.context_tokens,
        "capabilities": serde_json::to_value(&config.capabilities).unwrap_or(Value::Null),
        "input_usd_per_million": config.input_usd_per_million,
        "output_usd_per_million": config.output_usd_per_million,
        "keep_alive": config.keep_alive,
        "enabled": config.enabled,
        "revision": revision,
        "created_at": created_at,
        "updated_at": updated_at,
    })
}

fn paging(cursor: Option<i64>, limit: Option<i64>) -> Result<(i64, i64), Error> {
    let limit = limit.unwrap_or(30).clamp(1, 100);
    let offset = cursor.unwrap_or(0);
    if offset < 0 {
        return Err(Error::Validation("invalid cursor".into()));
    }
    Ok((limit, offset))
}

fn next_cursor(offset: i64, limit: i64, len: usize) -> Option<i64> {
    if len as i64 >= limit {
        Some(offset + limit)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/providers", responses((status = 200, body = Value)))]
pub async fn list_providers(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<ListPage>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (limit, offset) = paging(page.cursor, page.limit)?;
    let rows = sqlx::query(
        "SELECT configuration, credential_id, revision, created_at, updated_at FROM model_providers WHERE owner_id=$1 ORDER BY created_at, id LIMIT $2 OFFSET $3",
    )
    .bind(a.scope.owner_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let (config, revision) = provider_from_row(row)?;
        items.push(provider_view(
            &config,
            revision,
            row.try_get("created_at")?,
            row.try_get("updated_at")?,
        ));
    }
    let cursor = next_cursor(offset, limit, items.len());
    Ok(Json(json!({"items": items, "next_cursor": cursor})))
}

#[utoipa::path(post, path = "/api/v1/providers", request_body = ProviderCreate, responses((status = 200, body = Value)))]
pub async fn create_provider(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ProviderCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let id = Uuid::new_v4();
    let name = validate_name(&input.name, "provider")?;
    let kind = parse_kind(&input.kind)?;
    let local = input.local.unwrap_or(false);
    let admitted = parse_admitted(input.admitted_addresses.unwrap_or_default())?;
    validate_origin(&input.origin, local, &admitted)?;
    let credential_kind = parse_credential_kind(input.credential_kind)?;
    let rerank_path = validate_rerank_path(input.rerank_path)?;
    let enabled = input.enabled.unwrap_or(true);
    let credential_id = match input.credential {
        Some(secret) => {
            validate_credential(&secret)?;
            let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
            Some(
                store
                    .put(&a.scope, "model-provider-credential", secret.as_bytes())
                    .await?,
            )
        }
        None => None,
    };
    let config = ProviderConfig {
        id,
        name,
        kind,
        origin: input.origin,
        local,
        admitted_addresses: admitted,
        credential_id,
        credential_kind,
        rerank_path,
        enabled,
    };
    let stored: Value = serde_json::to_value(&config).map_err(Error::from)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    if let Err(error) = sqlx::query(
        "INSERT INTO model_providers(id, owner_id, configuration, credential_id) VALUES($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(a.scope.owner_id)
    .bind(&stored)
    .bind(credential_id)
    .execute(&mut *tx)
    .await
    {
        drop(tx);
        if let Some(cid) = credential_id {
            revoke_quiet(&state, &a.scope, cid).await;
        }
        return Err(error.into());
    }
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "PROVIDER_CREATED",
        "owner created model provider",
        json!({"provider_id": id, "local": config.local}),
    )
    .await?;
    tx.commit().await?;
    let now = chrono::Utc::now();
    Ok(Json(provider_view(&config, 1, now, now)))
}

#[utoipa::path(get, path = "/api/v1/providers/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn provider_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = provider_row(&state.pool, a.scope.owner_id, id).await?;
    let (config, revision) = provider_from_row(&row)?;
    Ok(Json(provider_view(
        &config,
        revision,
        row.try_get("created_at")?,
        row.try_get("updated_at")?,
    )))
}

#[utoipa::path(patch, path = "/api/v1/providers/{id}", params(("id" = Uuid, Path)), request_body = ProviderUpdate, responses((status = 200, body = Value)))]
pub async fn update_provider(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ProviderUpdate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = provider_row(&state.pool, a.scope.owner_id, id).await?;
    let (mut config, _) = provider_from_row(&row)?;
    let previous_credential = config.credential_id;

    if let Some(name) = input.name.as_deref() {
        config.name = validate_name(name, "provider")?;
    }
    if let Some(kind) = input.kind.as_deref() {
        let kind = parse_kind(kind)?;
        if kind == ProviderKind::Anthropic
            && config.kind != ProviderKind::Anthropic
            && provider_has_embedding_models(&state.pool, a.scope.owner_id, id).await?
        {
            return Err(Error::UnsupportedCapability.into());
        }
        config.kind = kind;
    }
    if let Some(local) = input.local {
        config.local = local;
    }
    if input.credential_kind.is_some() {
        config.credential_kind = parse_credential_kind(input.credential_kind)?;
    }
    let admitted_changed = input.admitted_addresses.is_some();
    if let Some(admitted) = input.admitted_addresses {
        config.admitted_addresses = parse_admitted(admitted)?;
    }
    if input.origin.is_some() || input.local.is_some() || admitted_changed {
        let origin = input.origin.clone().unwrap_or_else(|| config.origin.clone());
        validate_origin(&origin, config.local, &config.admitted_addresses)?;
        config.origin = origin;
    }
    if let Some(rerank_path) = input.rerank_path {
        config.rerank_path = validate_rerank_path(Some(rerank_path))?;
    }
    if let Some(enabled) = input.enabled {
        config.enabled = enabled;
    }
    if let Some(secret) = input.credential.as_deref() {
        validate_credential(secret)?;
        let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
        config.credential_id = Some(
            store
                .put(&a.scope, "model-provider-credential", secret.as_bytes())
                .await?,
        );
    }

    let stored: Value = serde_json::to_value(&config).map_err(Error::from)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let updated = sqlx::query(
        "UPDATE model_providers SET configuration=$3, credential_id=$4, revision=revision+1, updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5 RETURNING revision, created_at, updated_at",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(&stored)
    .bind(config.credential_id)
    .bind(input.expected_revision)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(updated) = updated else {
        drop(tx);
        if config.credential_id != previous_credential {
            if let Some(cid) = config.credential_id {
                revoke_quiet(&state, &a.scope, cid).await;
            }
        }
        return Err(Error::Conflict("provider revision changed".into()).into());
    };
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "PROVIDER_UPDATED",
        "owner updated model provider",
        json!({"provider_id": id, "revision": updated.try_get::<i64, _>("revision")?}),
    )
    .await?;
    tx.commit().await?;
    if config.credential_id != previous_credential {
        if let Some(old) = previous_credential {
            revoke_quiet(&state, &a.scope, old).await;
        }
    }
    Ok(Json(provider_view(
        &config,
        updated.try_get("revision")?,
        updated.try_get("created_at")?,
        updated.try_get("updated_at")?,
    )))
}

#[utoipa::path(delete, path = "/api/v1/providers/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn delete_provider(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT configuration, credential_id, revision, created_at, updated_at FROM model_providers WHERE owner_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let dependents: i64 =
        sqlx::query_scalar("SELECT count(*) FROM models WHERE owner_id=$1 AND provider_id=$2")
            .bind(a.scope.owner_id)
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if dependents > 0 {
        return Err(Error::Conflict("provider has models; delete them first".into()).into());
    }
    let (config, revision) = provider_from_row(&row)?;
    let view = provider_view(
        &config,
        revision,
        row.try_get("created_at")?,
        row.try_get("updated_at")?,
    );
    sqlx::query("DELETE FROM model_providers WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "PROVIDER_DELETED",
        "owner deleted model provider",
        json!({"provider_id": id}),
    )
    .await?;
    tx.commit().await?;
    if let Some(cid) = config.credential_id {
        revoke_quiet(&state, &a.scope, cid).await;
    }
    Ok(Json(view))
}

/// Live probe: builds the adapter exactly the way the router does (stored
/// config plus the sealed credential) and performs a real minimal chat
/// completion. Any failure surfaces as its typed error; success is only
/// reported after the provider actually answered.
#[utoipa::path(post, path = "/api/v1/providers/{id}/test", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn test_provider(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = provider_row(&state.pool, a.scope.owner_id, id).await?;
    let (provider, _) = provider_from_row(&row)?;

    let candidates =
        sqlx::query("SELECT configuration FROM models WHERE owner_id=$1 AND provider_id=$2 ORDER BY (configuration->>'priority')::integer, id")
            .bind(a.scope.owner_id)
            .bind(id)
            .fetch_all(&state.pool)
            .await?;
    let mut model: Option<ModelConfig> = None;
    for candidate in &candidates {
        let raw: Value = candidate.try_get("configuration")?;
        if let Ok(parsed) = serde_json::from_value::<ModelConfig>(raw) {
            if parsed.enabled && parsed.capabilities.chat {
                model = Some(parsed);
                break;
            }
        }
    }
    let Some(model) = model else {
        return Err(Error::Unavailable(
            "no enabled chat model configured for provider test".into(),
        )
        .into());
    };

    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let credential = match provider.credential_id {
        Some(cid) => Some(store.get(&a.scope, cid).await?),
        None => None,
    };
    let adapter = HttpProvider::new(provider.clone(), model.clone(), credential).await?;
    let ping = ChatRequest {
        messages: vec![ChatMessage {
            role: "user".into(),
            content: "ping".into(),
            tool_call_id: None,
            tool_calls: vec![],
            images: vec![],
        }],
        tools: vec![],
        output_schema: None,
        max_output_tokens: 16,
        reasoning: false,
    };
    let started = std::time::Instant::now();
    let response = adapter.complete(ping).await?;
    let latency_ms = started.elapsed().as_millis() as i64;

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "PROVIDER_TESTED",
        "owner tested model provider",
        json!({"provider_id": id, "model_id": model.id, "local": provider.local, "ok": true}),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "ok": true,
        "provider_id": id,
        "model_id": model.id,
        "model": model.model,
        "local": provider.local,
        "effective_origin": provider.origin,
        "capabilities": serde_json::to_value(&model.capabilities).unwrap_or(Value::Null),
        "transmitted_content": "static ping without owner data",
        "reply_chars": response.text.len(),
        "finish_reason": response.finish_reason,
        "latency_ms": latency_ms,
    })))
}

/// Dedicated credential rotate: seals the new value into the shared secret
/// store and swaps the provider row to point at it. The old secret is
/// revoked only after the row swap commits, so a failed write can never
/// orphan the live credential. The value never appears in any response.
#[utoipa::path(post, path = "/api/v1/providers/{id}/credential", params(("id" = Uuid, Path)), request_body = CredentialRotate, responses((status = 200, body = Value)))]
pub async fn rotate_credential(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<CredentialRotate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    validate_credential(&input.credential)?;
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let row = provider_row(&state.pool, a.scope.owner_id, id).await?;
    let (mut config, _) = provider_from_row(&row)?;
    let previous = config.credential_id;
    let fresh = store
        .put(
            &a.scope,
            "model-provider-credential",
            input.credential.as_bytes(),
        )
        .await?;
    config.credential_id = Some(fresh);
    let stored: Value = serde_json::to_value(&config).map_err(Error::from)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let expected = input.expected_revision.unwrap_or(i64::MAX);
    let updated = if input.expected_revision.is_some() {
        sqlx::query(
            "UPDATE model_providers SET configuration=$3, credential_id=$4, revision=revision+1, updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5 RETURNING revision, created_at, updated_at",
        )
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(&stored)
        .bind(config.credential_id)
        .bind(expected)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "UPDATE model_providers SET configuration=$3, credential_id=$4, revision=revision+1, updated_at=now() WHERE owner_id=$1 AND id=$2 RETURNING revision, created_at, updated_at",
        )
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(&stored)
        .bind(config.credential_id)
        .fetch_optional(&mut *tx)
        .await?
    };
    let Some(updated) = updated else {
        drop(tx);
        revoke_quiet(&state, &a.scope, fresh).await;
        return Err(Error::Conflict("provider revision changed".into()).into());
    };
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "PROVIDER_CREDENTIAL_ROTATED",
        "owner rotated model provider credential",
        json!({"provider_id": id}),
    )
    .await?;
    tx.commit().await?;
    if let Some(old) = previous {
        if old != fresh {
            revoke_quiet(&state, &a.scope, old).await;
        }
    }
    Ok(Json(provider_view(
        &config,
        updated.try_get("revision")?,
        updated.try_get("created_at")?,
        updated.try_get("updated_at")?,
    )))
}

// ---------------------------------------------------------------------------
// OAuth client credentials. Connectors stay UNAVAILABLE-for-use: no OAuth
// flow, token exchange, or Graph/CalDAV access exists in this slice. These
// endpoints only store the client id/secret so a future flow has sealed
// credentials to use, and report configured/unconfigured per connector.
// ---------------------------------------------------------------------------

const OAUTH_CONNECTORS: [&str; 3] = ["google", "outlook", "github"];

/// Per-connector status: whether a client is stored, a truncated client-id
/// suffix, and when it was last written. The secret is never surfaced.
#[utoipa::path(get, path = "/api/v1/oauth/clients", responses((status = 200, body = Value)))]
pub async fn oauth_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query(
        "SELECT connector, client_id, revision, updated_at FROM oauth_clients WHERE owner_id=$1",
    )
    .bind(a.scope.owner_id)
    .fetch_all(&state.pool)
    .await?;
    let mut by_connector = std::collections::HashMap::<String, (String, i64, chrono::DateTime<chrono::Utc>)>::new();
    for row in &rows {
        let connector: String = row.try_get("connector")?;
        let client_id: String = row.try_get("client_id")?;
        let revision: i64 = row.try_get("revision")?;
        let updated_at: chrono::DateTime<chrono::Utc> = row.try_get("updated_at")?;
        by_connector.insert(connector, (client_id, revision, updated_at));
    }
    let items: Vec<Value> = OAUTH_CONNECTORS
        .iter()
        .map(|connector| match by_connector.get(*connector) {
            Some((client_id, revision, updated_at)) => json!({
                "connector": connector,
                "configured": true,
                "client_id_suffix": client_id_suffix(client_id),
                "revision": revision,
                "updated_at": updated_at,
                "usable": false,
                "note": "Client stored. OAuth sign-in is not available in this build; credentials are pending verification.",
            }),
            None => json!({
                "connector": connector,
                "configured": false,
                "client_id_suffix": Value::Null,
                "revision": Value::Null,
                "updated_at": Value::Null,
                "usable": false,
                "note": "No client stored. OAuth sign-in is not available in this build.",
            }),
        })
        .collect();
    Ok(Json(json!({"items": items})))
}

/// Create or replace one connector's client credentials. The secret goes
/// straight into the shared secret store; only its id lands in the row.
#[utoipa::path(put, path = "/api/v1/oauth/clients/{connector}", params(("connector" = String, Path)), request_body = OAuthClientUpsert, responses((status = 200, body = Value)))]
pub async fn upsert_oauth_client(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(connector): Path<String>,
    Json(input): Json<OAuthClientUpsert>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let connector = parse_connector(&connector)?;
    let client_id = validate_client_id(&input.client_id)?;
    validate_credential(&input.client_secret)?;
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let fresh = store
        .put(&a.scope, "oauth-client-secret", input.client_secret.as_bytes())
        .await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let previous: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT credential_id FROM oauth_clients WHERE owner_id=$1 AND connector=$2",
    )
    .bind(a.scope.owner_id)
    .bind(connector)
    .fetch_optional(&mut *tx)
    .await?;
    let previous: Option<Uuid> = previous.flatten();
    let row = sqlx::query(
        "INSERT INTO oauth_clients(id, owner_id, connector, client_id, credential_id) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT (owner_id, connector) DO UPDATE SET client_id=EXCLUDED.client_id, credential_id=EXCLUDED.credential_id, revision=oauth_clients.revision+1, updated_at=now()
         RETURNING revision, updated_at",
    )
    .bind(Uuid::new_v4())
    .bind(a.scope.owner_id)
    .bind(connector)
    .bind(&client_id)
    .bind(fresh)
    .fetch_one(&mut *tx)
    .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "OAUTH_CLIENT_STORED",
        "owner stored OAuth client credentials",
        json!({"connector": connector}),
    )
    .await?;
    tx.commit().await?;
    if let Some(old) = previous {
        if old != fresh {
            revoke_quiet(&state, &a.scope, old).await;
        }
    }
    let revision: i64 = row.try_get("revision")?;
    let updated_at: chrono::DateTime<chrono::Utc> = row.try_get("updated_at")?;
    Ok(Json(json!({
        "connector": connector,
        "configured": true,
        "client_id_suffix": client_id_suffix(&client_id),
        "revision": revision,
        "updated_at": updated_at,
        "usable": false,
        "note": "Client stored. OAuth sign-in is not available in this build; credentials are pending verification.",
    })))
}

/// Remove one connector's client credentials and revoke the sealed secret.
#[utoipa::path(delete, path = "/api/v1/oauth/clients/{connector}", params(("connector" = String, Path)), responses((status = 200, body = Value)))]
pub async fn delete_oauth_client(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(connector): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let connector = parse_connector(&connector)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let credential_id: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM oauth_clients WHERE owner_id=$1 AND connector=$2 RETURNING credential_id",
    )
    .bind(a.scope.owner_id)
    .bind(connector)
    .fetch_optional(&mut *tx)
    .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "OAUTH_CLIENT_REMOVED",
        "owner removed OAuth client credentials",
        json!({"connector": connector}),
    )
    .await?;
    tx.commit().await?;
    if let Some(old) = credential_id {
        revoke_quiet(&state, &a.scope, old).await;
    }
    Ok(Json(json!({"connector": connector, "configured": false, "usable": false})))
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/models", responses((status = 200, body = Value)))]
pub async fn list_models(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<ModelListPage>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (limit, offset) = paging(page.cursor, page.limit)?;
    let rows = if let Some(provider_id) = page.provider_id {
        sqlx::query(
            "SELECT configuration, revision, created_at, updated_at FROM models WHERE owner_id=$1 AND provider_id=$2 ORDER BY created_at, id LIMIT $3 OFFSET $4",
        )
        .bind(a.scope.owner_id)
        .bind(provider_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT configuration, revision, created_at, updated_at FROM models WHERE owner_id=$1 ORDER BY created_at, id LIMIT $2 OFFSET $3",
        )
        .bind(a.scope.owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?
    };
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let (config, revision) = model_from_row(row)?;
        items.push(model_view(
            &config,
            revision,
            row.try_get("created_at")?,
            row.try_get("updated_at")?,
        ));
    }
    let cursor = next_cursor(offset, limit, items.len());
    Ok(Json(json!({"items": items, "next_cursor": cursor})))
}

#[utoipa::path(post, path = "/api/v1/models", request_body = ModelCreate, responses((status = 200, body = Value)))]
pub async fn create_model(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ModelCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let kind = provider_kind(&state.pool, a.scope.owner_id, input.provider_id).await?;
    let name = validate_name(&input.name, "model")?;
    let model_name = validate_model_name(&input.model)?;
    let roles = parse_roles(&input.roles)?;
    let capabilities = parse_capabilities(&input.capabilities)?;
    check_anthropic(kind, &capabilities)?;
    if input.context_tokens == 0 {
        return Err(Error::Validation("model context tokens must be positive".into()).into());
    }
    let (input_price, output_price) =
        validate_prices(input.input_usd_per_million, input.output_usd_per_million)?;
    let keep_alive = parse_keep_alive(input.keep_alive)?;
    let id = Uuid::new_v4();
    let config = ModelConfig {
        id,
        provider_id: input.provider_id,
        model: model_name,
        name,
        roles,
        priority: input.priority.unwrap_or(100),
        context_tokens: input.context_tokens,
        capabilities,
        input_usd_per_million: input_price,
        output_usd_per_million: output_price,
        keep_alive,
        enabled: input.enabled.unwrap_or(true),
    };
    let stored: Value = serde_json::to_value(&config).map_err(Error::from)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO models(id, owner_id, provider_id, configuration) VALUES($1,$2,$3,$4)")
        .bind(id)
        .bind(a.scope.owner_id)
        .bind(input.provider_id)
        .bind(&stored)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "MODEL_CREATED",
        "owner created model",
        json!({"model_id": id, "provider_id": input.provider_id}),
    )
    .await?;
    tx.commit().await?;
    let now = chrono::Utc::now();
    Ok(Json(model_view(&config, 1, now, now)))
}

#[utoipa::path(get, path = "/api/v1/models/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn model_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = model_row(&state.pool, a.scope.owner_id, id).await?;
    let (config, revision) = model_from_row(&row)?;
    Ok(Json(model_view(
        &config,
        revision,
        row.try_get("created_at")?,
        row.try_get("updated_at")?,
    )))
}

#[utoipa::path(patch, path = "/api/v1/models/{id}", params(("id" = Uuid, Path)), request_body = ModelUpdate, responses((status = 200, body = Value)))]
pub async fn update_model(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ModelUpdate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = model_row(&state.pool, a.scope.owner_id, id).await?;
    let (mut config, _) = model_from_row(&row)?;

    if let Some(provider_id) = input.provider_id {
        provider_row(&state.pool, a.scope.owner_id, provider_id).await?;
        config.provider_id = provider_id;
    }
    if let Some(name) = input.name {
        config.name = validate_name(&name, "model")?;
    }
    if let Some(model) = input.model {
        config.model = validate_model_name(&model)?;
    }
    if let Some(roles) = input.roles {
        config.roles = parse_roles(&roles)?;
    }
    if let Some(priority) = input.priority {
        config.priority = priority;
    }
    if let Some(context_tokens) = input.context_tokens {
        if context_tokens == 0 {
            return Err(Error::Validation("model context tokens must be positive".into()).into());
        }
        config.context_tokens = context_tokens;
    }
    if let Some(caps) = input.capabilities {
        config.capabilities = parse_capabilities(&caps)?;
    }
    if input.input_usd_per_million.is_some() || input.output_usd_per_million.is_some() {
        let next_input = input
            .input_usd_per_million
            .unwrap_or(config.input_usd_per_million);
        let next_output = input
            .output_usd_per_million
            .unwrap_or(config.output_usd_per_million);
        let (next_input, next_output) = validate_prices(next_input, next_output)?;
        config.input_usd_per_million = next_input;
        config.output_usd_per_million = next_output;
    }
    if let Some(keep_alive) = input.keep_alive {
        config.keep_alive = parse_keep_alive(keep_alive)?;
    }
    if let Some(enabled) = input.enabled {
        config.enabled = enabled;
    }
    let kind = provider_kind(&state.pool, a.scope.owner_id, config.provider_id).await?;
    check_anthropic(kind, &config.capabilities)?;
    let stored: Value = serde_json::to_value(&config).map_err(Error::from)?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let updated = sqlx::query(
        "UPDATE models SET provider_id=$3, configuration=$4, revision=revision+1, updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5 RETURNING revision, created_at, updated_at",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(config.provider_id)
    .bind(&stored)
    .bind(input.expected_revision)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::Conflict("model revision changed".into()))?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "MODEL_UPDATED",
        "owner updated model",
        json!({"model_id": id, "revision": updated.try_get::<i64, _>("revision")?}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(model_view(
        &config,
        updated.try_get("revision")?,
        updated.try_get("created_at")?,
        updated.try_get("updated_at")?,
    )))
}

#[utoipa::path(delete, path = "/api/v1/models/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn delete_model(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT configuration, revision, created_at, updated_at FROM models WHERE owner_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let (config, revision) = model_from_row(&row)?;
    let view = model_view(
        &config,
        revision,
        row.try_get("created_at")?,
        row.try_get("updated_at")?,
    );
    sqlx::query("DELETE FROM models WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "MODEL_DELETED",
        "owner deleted model",
        json!({"model_id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view))
}

// ---------------------------------------------------------------------------
// Model calls (read-only ledger) and budgets singleton.
// ---------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/model-calls", responses((status = 200, body = Value)))]
pub async fn list_model_calls(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<ModelCallPage>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (limit, offset) = paging(page.cursor, page.limit)?;
    let rows = if let Some(task_id) = page.task_id {
        sqlx::query(
            "SELECT to_jsonb(t)-'owner_id' AS record FROM model_calls t WHERE owner_id=$1 AND task_id=$2 ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4",
        )
        .bind(a.scope.owner_id)
        .bind(task_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query(
            "SELECT to_jsonb(t)-'owner_id' AS record FROM model_calls t WHERE owner_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3",
        )
        .bind(a.scope.owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?
    };
    let items: Vec<Value> = rows
        .iter()
        .map(|row| row.try_get("record"))
        .collect::<Result<_, _>>()?;
    let cursor = next_cursor(offset, limit, items.len());
    Ok(Json(json!({"items": items, "next_cursor": cursor})))
}

#[utoipa::path(get, path = "/api/v1/budgets", responses((status = 200, body = Value)))]
pub async fn get_budgets(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = sqlx::query(
        "SELECT task_usd, day_usd, month_usd, agent_day_usd, max_model_calls, max_input_tokens, max_output_tokens FROM model_budgets WHERE owner_id=$1",
    )
    .bind(a.scope.owner_id)
    .fetch_optional(&state.pool)
    .await?;
    let limits = match row {
        Some(row) => BudgetLimits {
            task_usd: row.try_get("task_usd")?,
            day_usd: row.try_get("day_usd")?,
            month_usd: row.try_get("month_usd")?,
            agent_day_usd: row.try_get("agent_day_usd")?,
            max_model_calls: row.try_get("max_model_calls")?,
            max_input_tokens: row.try_get("max_input_tokens")?,
            max_output_tokens: row.try_get("max_output_tokens")?,
        },
        None => BudgetLimits::default(),
    };
    Ok(Json(serde_json::to_value(&limits).map_err(Error::from)?))
}

#[utoipa::path(put, path = "/api/v1/budgets", request_body = BudgetUpdate, responses((status = 200, body = Value)))]
pub async fn update_budgets(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<BudgetUpdate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let limits = BudgetLimits {
        task_usd: input.task_usd,
        day_usd: input.day_usd,
        month_usd: input.month_usd,
        agent_day_usd: input.agent_day_usd,
        max_model_calls: input.max_model_calls,
        max_input_tokens: input.max_input_tokens,
        max_output_tokens: input.max_output_tokens,
    };
    limits.validate()?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO model_budgets(owner_id, task_usd, day_usd, month_usd, agent_day_usd, max_model_calls, max_input_tokens, max_output_tokens) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id) DO UPDATE SET task_usd=EXCLUDED.task_usd, day_usd=EXCLUDED.day_usd, month_usd=EXCLUDED.month_usd, agent_day_usd=EXCLUDED.agent_day_usd, max_model_calls=EXCLUDED.max_model_calls, max_input_tokens=EXCLUDED.max_input_tokens, max_output_tokens=EXCLUDED.max_output_tokens",
    )
    .bind(a.scope.owner_id)
    .bind(limits.task_usd)
    .bind(limits.day_usd)
    .bind(limits.month_usd)
    .bind(limits.agent_day_usd)
    .bind(limits.max_model_calls)
    .bind(limits.max_input_tokens)
    .bind(limits.max_output_tokens)
    .execute(&mut *tx)
    .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "BUDGETS_UPDATED",
        "owner updated model budgets",
        serde_json::to_value(&limits).map_err(Error::from)?,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::to_value(&limits).map_err(Error::from)?))
}
/// Per-provider spend caps: same shape as the global budgets, scoped to one
/// provider row. Zero means uncapped (default). The router enforces them in
/// the reserve path with "provider model cost budget exhausted".
#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderBudgetUpdate {
    pub day_usd: f64,
    pub month_usd: f64,
}
#[utoipa::path(get, path = "/api/v1/providers/{id}/budget", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn get_provider_budget(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row: Option<(f64, f64)> = sqlx::query_as("SELECT day_usd::float8,month_usd::float8 FROM provider_budgets WHERE owner_id=$1 AND provider_id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?;
    let (day_usd, month_usd) = row.unwrap_or((0.0, 0.0));
    Ok(Json(json!({"provider_id": id, "day_usd": day_usd, "month_usd": month_usd})))
}
#[utoipa::path(put, path = "/api/v1/providers/{id}/budget", params(("id" = Uuid, Path)), request_body = ProviderBudgetUpdate, responses((status = 200, body = Value)))]
pub async fn update_provider_budget(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<ProviderBudgetUpdate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if !(0.0..=1_000_000.0).contains(&input.day_usd) || !(0.0..=1_000_000.0).contains(&input.month_usd) {
        return Err(Error::Validation("provider caps must be 0..1000000 USD".into()).into());
    }
    sqlx::query("SELECT 1 FROM model_providers WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;
    sqlx::query("INSERT INTO provider_budgets(owner_id,provider_id,day_usd,month_usd) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id,provider_id) DO UPDATE SET day_usd=EXCLUDED.day_usd,month_usd=EXCLUDED.month_usd,updated_at=now()").bind(a.scope.owner_id).bind(id).bind(input.day_usd).bind(input.month_usd).execute(&state.pool).await?;
    Ok(Json(json!({"provider_id": id, "day_usd": input.day_usd, "month_usd": input.month_usd})))
}

// Local model manager (growth D16): proxy the owner's OLLAMA daemon. No new
// tables; installed list + pull status come straight from the daemon, and
// benchmark reports server-measured latency only. Unreachable daemon is 503,
// never a faked empty list.
const MAX_OLLAMA_BYTES: usize = 1024 * 1024;
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalPull { pub name: String }
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalBenchmark { pub model: String }
async fn ollama_origin(pool: &sqlx::PgPool, owner: Uuid, id: Uuid) -> Result<String, Error> {
    let row = provider_row(pool, owner, id).await?;
    let (config, _) = provider_from_row(&row)?;
    if config.kind != ProviderKind::Ollama { return Err(Error::Validation("local model manager needs an OLLAMA provider".into())); }
    if !config.enabled { return Err(Error::Validation("provider is disabled".into())); }
    Ok(config.origin.trim_end_matches('/').to_owned())
}
fn clean_tag_name(raw: &str) -> Result<String, Error> {
    let name = raw.trim();
    if name.is_empty() || name.len() > 256 || name.chars().any(|c| c.is_control() || c == '\n' || c == '\r') { return Err(Error::Validation("model name must be 1-256 characters".into())); }
    Ok(name.to_owned())
}
async fn ollama_get(origin: &str, path: &str) -> Result<Value, Error> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build().map_err(|e| Error::Unavailable(format!("local model client failed: {e}")))?;
    let resp = client.get(format!("{origin}{path}")).send().await.map_err(|_| Error::Unavailable("local model daemon unreachable".into()))?;
    if !resp.status().is_success() { return Err(Error::Unavailable(format!("local model daemon returned HTTP {}", resp.status()))); }
    let bytes = resp.bytes().await.map_err(|_| Error::Unavailable("local model daemon response unreadable".into()))?;
    if bytes.len() > MAX_OLLAMA_BYTES { return Err(Error::Unavailable("local model daemon response too large".into())); }
    serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::Unavailable("local model daemon returned invalid JSON".into()))
}
#[utoipa::path(get, path = "/api/v1/providers/{id}/local/models", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn local_models(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let origin = ollama_origin(&state.pool, a.scope.owner_id, id).await?;
    let value = ollama_get(&origin, "/api/tags").await?;
    let models = value.get("models").and_then(|m| m.as_array()).cloned().unwrap_or_default();
    let names: Vec<Value> = models.iter().filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|n| json!({"name": n, "size": m.get("size"), "modified_at": m.get("modified_at")}))).collect();
    Ok(Json(json!({"provider_id": id, "models": names})))
}
#[utoipa::path(post, path = "/api/v1/providers/{id}/local/pull", params(("id" = Uuid, Path)), request_body = LocalPull, responses((status = 200, body = Value)))]
pub async fn local_pull(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<LocalPull>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let origin = ollama_origin(&state.pool, a.scope.owner_id, id).await?;
    let name = clean_tag_name(&input.name)?;
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().map_err(|e| Error::Unavailable(format!("local model client failed: {e}")))?;
    let resp = client.post(format!("{origin}/api/pull")).json(&json!({"name": name, "stream": false})).send().await.map_err(|_| Error::Unavailable("local model daemon unreachable".into()))?;
    if !resp.status().is_success() { return Err(Error::Unavailable(format!("local model daemon returned HTTP {}", resp.status())).into()); }
    let body: Value = resp.json().await.map_err(|_| Error::Unavailable("local model daemon response unreadable".into()))?;
    Ok(Json(json!({"provider_id": id, "name": name, "status": body.get("status").cloned().unwrap_or(Value::Null)})))
}
#[utoipa::path(post, path = "/api/v1/providers/{id}/local/benchmark", params(("id" = Uuid, Path)), request_body = LocalBenchmark, responses((status = 200, body = Value)))]
pub async fn local_benchmark(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<LocalBenchmark>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let origin = ollama_origin(&state.pool, a.scope.owner_id, id).await?;
    let model = clean_tag_name(&input.model)?;
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build().map_err(|e| Error::Unavailable(format!("local model client failed: {e}")))?;
    let started = std::time::Instant::now();
    let resp = client.post(format!("{origin}/api/generate")).json(&json!({"model": model, "prompt": "Reply with the word ok.", "stream": false, "options": {"num_predict": 1}})).send().await.map_err(|_| Error::Unavailable("local model daemon unreachable".into()))?;
    if !resp.status().is_success() { return Err(Error::Unavailable(format!("local model daemon returned HTTP {}", resp.status())).into()); }
    let body: Value = resp.json().await.map_err(|_| Error::Unavailable("local model daemon response unreadable".into()))?;
    let elapsed_ms = started.elapsed().as_millis() as i64;
    let daemon_ms = body.get("total_duration").and_then(|d| d.as_i64()).map(|ns| ns / 1_000_000);
    Ok(Json(json!({"provider_id": id, "model": model, "elapsed_ms": elapsed_ms, "daemon_total_ms": daemon_ms, "done": body.get("done").cloned().unwrap_or(Value::Null)})))
}
// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_providers,
        create_provider,
        provider_detail,
        update_provider,
        delete_provider,
        test_provider,
        rotate_credential,
        oauth_status,
        upsert_oauth_client,
        delete_oauth_client,
        list_models,
        create_model,
        model_detail,
        update_model,
        delete_model,
        list_model_calls,
        get_budgets,
        update_budgets,
        get_provider_budget,
        update_provider_budget,
        local_models,
        local_pull,
        local_benchmark
    ),
    components(schemas(
        ProviderCreate,
        ProviderUpdate,
        CredentialRotate,
        OAuthClientUpsert,
        ModelCreate,
        ModelUpdate,
        BudgetUpdate,
        ProviderBudgetUpdate,
        LocalPull,
        LocalBenchmark
    ))
)]
pub struct ModelsApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/providers",
            get(list_providers).post(create_provider),
        )
        .route(
            "/api/v1/providers/{id}",
            get(provider_detail)
                .patch(update_provider)
                .delete(delete_provider),
        )
        .route("/api/v1/providers/{id}/test", post(test_provider))
        .route("/api/v1/providers/{id}/credential", post(rotate_credential))
        .route("/api/v1/oauth/clients", get(oauth_status))
        .route(
            "/api/v1/oauth/clients/{connector}",
            axum::routing::put(upsert_oauth_client).delete(delete_oauth_client),
        )
        .route("/api/v1/models", get(list_models).post(create_model))
        .route(
            "/api/v1/models/{id}",
            get(model_detail).patch(update_model).delete(delete_model),
        )
        .route("/api/v1/model-calls", get(list_model_calls))
        .route("/api/v1/providers/{id}/budget", get(get_provider_budget).put(update_provider_budget))
        .route("/api/v1/providers/{id}/local/models", get(local_models))
        .route("/api/v1/providers/{id}/local/pull", post(local_pull))
        .route("/api/v1/providers/{id}/local/benchmark", post(local_benchmark))
        .route(
            "/api/v1/budgets",
            get(get_budgets).put(update_budgets),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_kind_defaults_to_api_key_and_accepts_oauth() {
        assert_eq!(parse_credential_kind(None).unwrap(), CredentialKind::ApiKey);
        assert_eq!(parse_credential_kind(Some("API_KEY".into())).unwrap(), CredentialKind::ApiKey);
        assert_eq!(parse_credential_kind(Some("oauth".into())).unwrap(), CredentialKind::Oauth);
        assert!(parse_credential_kind(Some("bearer".into())).is_err());
    }
    #[test]
    fn keep_alive_accepts_durations_and_zero_but_rejects_bare_numbers() {
        assert_eq!(parse_keep_alive(None).unwrap(), None);
        assert_eq!(parse_keep_alive(Some("5m".into())).unwrap(), Some("5m".into()));
        assert_eq!(parse_keep_alive(Some("0".into())).unwrap(), Some("0".into()));
        assert!(parse_keep_alive(Some("5".into())).is_err());
        assert!(parse_keep_alive(Some("forever".into())).is_err());
        assert!(parse_keep_alive(Some(String::new())).is_err());
    }
    #[test]
    fn stored_configs_without_new_fields_still_parse() {
        // Rows written before credential_kind/keep_alive existed must keep loading: serde defaults fill ApiKey/None.
        let provider: ProviderConfig = serde_json::from_value(json!({"id": Uuid::new_v4(),"name": "p","kind": "ANTHROPIC","origin": "https://api.anthropic.com","local": false,"admitted_addresses": [],"credential_id": null,"rerank_path": null,"enabled": true})).unwrap();
        assert_eq!(provider.credential_kind, CredentialKind::ApiKey);
        let mut model_value = json!({"id": Uuid::new_v4(),"provider_id": provider.id,"model": "m","name": "m","roles": [],"priority": 100,"context_tokens": 8192,"capabilities": {"chat": true,"tools": false,"vision": false,"structured_output": false,"reasoning": false,"embeddings": false,"rerank": false},"input_usd_per_million": null,"output_usd_per_million": null,"enabled": true});
        let model: ModelConfig = serde_json::from_value(model_value.clone()).unwrap();
        assert_eq!(model.keep_alive, None);
        model_value["keep_alive"] = json!("5m");
        let model: ModelConfig = serde_json::from_value(model_value).unwrap();
        assert_eq!(model.keep_alive.as_deref(), Some("5m"));
    }
}
