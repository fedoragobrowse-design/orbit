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
    BudgetLimits, ChatMessage, ChatRequest, ModelConfig, ModelProvider, ProviderCapabilities,
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
    pub rerank_path: Option<String>,
    pub enabled: Option<bool>,
    pub credential: Option<String>,
    pub expected_revision: i64,
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
        "rerank_path": config.rerank_path,
        "enabled": config.enabled,
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
        list_models,
        create_model,
        model_detail,
        update_model,
        delete_model,
        list_model_calls,
        get_budgets,
        update_budgets
    ),
    components(schemas(
        ProviderCreate,
        ProviderUpdate,
        ModelCreate,
        ModelUpdate,
        BudgetUpdate
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
        .route("/api/v1/models", get(list_models).post(create_model))
        .route(
            "/api/v1/models/{id}",
            get(model_detail).patch(update_model).delete(delete_model),
        )
        .route("/api/v1/model-calls", get(list_model_calls))
        .route(
            "/api/v1/budgets",
            get(get_budgets).put(update_budgets),
        )
}
