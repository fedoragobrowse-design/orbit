use crate::{ApiError, ApiState, authenticate};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use orbit_core::{Error, MemoryStatus, MemoryType, PrivacyClass};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPage {
    #[serde(rename = "type")]
    pub kind: Option<MemoryType>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateMemoryRequest {
    #[serde(rename = "type")]
    pub memory_type: MemoryType,
    pub subject: String,
    pub value: Value,
    #[serde(default)]
    pub related_entities: Vec<Uuid>,
    pub privacy_class: Option<PrivacyClass>,
    pub confidence: Option<f64>,
    pub valid_until: Option<DateTime<Utc>>,
    pub entity_id: Option<Uuid>,
}

impl CreateMemoryRequest {
    fn into_candidate(self) -> orbit_memory::Candidate {
        orbit_memory::Candidate {
            memory_type: self.memory_type,
            subject: self.subject,
            value: self.value,
            source_references: Vec::new(),
            related_entities: self.related_entities,
            privacy_class: self.privacy_class.unwrap_or(PrivacyClass::Private),
            confidence: self.confidence.unwrap_or(0.8),
            valid_until: self.valid_until,
            entity_id: self.entity_id,
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchMemoryRequest {
    pub subject: Option<String>,
    pub value: Option<Value>,
    pub confidence: Option<f64>,
    pub privacy_class: Option<PrivacyClass>,
    pub valid_until: Option<DateTime<Utc>>,
    pub related_entities: Option<Vec<Uuid>>,
    pub expected_revision: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SupersedeRequest {
    pub subject: String,
    pub value: Value,
    pub confidence: Option<f64>,
    pub privacy_class: Option<PrivacyClass>,
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub related_entities: Vec<Uuid>,
    pub expected_revision: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub expected_revision: i64,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default)]
    pub types: Vec<MemoryType>,
    pub project_id: Option<Uuid>,
    pub limit: Option<usize>,
}

#[derive(Serialize, ToSchema)]
pub struct RetentionSettingsResponse {
    pub event_body_days: i32,
    pub conversation_body_days: i32,
    pub runtime_artifact_days: i32,
    pub connector_cache_days: i32,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionUpdate {
    pub event_body_days: i32,
    pub conversation_body_days: i32,
    pub runtime_artifact_days: i32,
    pub connector_cache_days: i32,
}

fn owner_scope() -> orbit_memory::RetrievalScope {
    orbit_memory::RetrievalScope {
        types: Vec::new(),
        project_ids: Vec::new(),
        max_privacy: PrivacyClass::HighlyPrivate,
        agent_id: None,
    }
}

async fn apply_supersede(
    state: &ApiState,
    scope: &orbit_core::OwnerScope,
    id: Uuid,
    subject: String,
    value: Value,
    confidence: Option<f64>,
    privacy_class: Option<PrivacyClass>,
    valid_until: Option<DateTime<Utc>>,
    related_entities: Vec<Uuid>,
    expected_revision: i64,
) -> Result<Value, ApiError> {
    let old = orbit_memory::get(&state.pool, scope, id).await?;
    if old.status != MemoryStatus::Active {
        return Err(Error::Conflict("memory is not active".into()).into());
    }
    let candidate = orbit_memory::Candidate {
        memory_type: old.memory_type,
        subject,
        value,
        source_references: Vec::new(),
        related_entities,
        privacy_class: privacy_class.unwrap_or(old.privacy_class),
        confidence: confidence.unwrap_or(old.confidence),
        valid_until: valid_until.or(old.valid_until),
        entity_id: None,
    };
    candidate.validate()?;
    let provenance = orbit_memory::owner_provenance(scope, &candidate);
    let outcome =
        orbit_memory::ingest(&state.pool, scope, candidate, provenance, Some((id, expected_revision)), None)
            .await?;
    match outcome.memory_id {
        Some(memory_id) => Ok(json!({
            "status": outcome.status,
            "candidate_id": outcome.candidate_id,
            "record": orbit_memory::get(&state.pool, scope, memory_id).await?,
        })),
        None => Ok(json!({
            "status": outcome.status,
            "candidate_id": outcome.candidate_id,
            "conflicts_with": outcome.conflicts_with,
        })),
    }
}

#[utoipa::path(get, path = "/api/v1/memory", responses((status = 200, body = Value)))]
pub async fn list_memories(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<MemoryPage>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let limit = page.limit.unwrap_or(20).clamp(1, 50);
    let (records, next) =
        orbit_memory::list(&state.pool, &auth.scope, page.kind, page.cursor, limit).await?;
    Ok(Json(json!({"items": records, "next_cursor": next})))
}

#[utoipa::path(post, path = "/api/v1/memory", request_body = CreateMemoryRequest, responses((status = 200, body = Value)))]
pub async fn create_memory(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CreateMemoryRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let candidate = input.into_candidate();
    candidate.validate()?;
    let provenance = orbit_memory::owner_provenance(&auth.scope, &candidate);
    let outcome =
        orbit_memory::ingest(&state.pool, &auth.scope, candidate, provenance, None, None).await?;
    match outcome.memory_id {
        Some(memory_id) => Ok(Json(json!({
            "status": outcome.status,
            "candidate_id": outcome.candidate_id,
            "record": orbit_memory::get(&state.pool, &auth.scope, memory_id).await?,
        }))),
        None => Ok(Json(json!({
            "status": outcome.status,
            "candidate_id": outcome.candidate_id,
            "conflicts_with": outcome.conflicts_with,
        }))),
    }
}

#[utoipa::path(get, path = "/api/v1/memory/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn get_memory(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(json!(orbit_memory::get(&state.pool, &auth.scope, id).await?)))
}

#[utoipa::path(patch, path = "/api/v1/memory/{id}", params(("id" = Uuid, Path)), request_body = PatchMemoryRequest, responses((status = 200, body = Value)))]
pub async fn patch_memory(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PatchMemoryRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let old = orbit_memory::get(&state.pool, &auth.scope, id).await?;
    Ok(Json(
        apply_supersede(
            &state,
            &auth.scope,
            id,
            input.subject.unwrap_or(old.subject),
            input.value.unwrap_or(old.value),
            input.confidence,
            input.privacy_class,
            input.valid_until,
            input.related_entities.unwrap_or(old.related_entities),
            input.expected_revision,
        )
        .await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/memory/{id}/verify", params(("id" = Uuid, Path)), request_body = VerifyRequest, responses((status = 200, body = Value)))]
pub async fn verify_memory(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<VerifyRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    Ok(Json(json!(
        orbit_memory::verify(&state.pool, &auth.scope, id, input.expected_revision).await?
    )))
}

#[utoipa::path(post, path = "/api/v1/memory/{id}/supersede", params(("id" = Uuid, Path)), request_body = SupersedeRequest, responses((status = 200, body = Value)))]
pub async fn supersede_memory(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SupersedeRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    Ok(Json(
        apply_supersede(
            &state,
            &auth.scope,
            id,
            input.subject,
            input.value,
            input.confidence,
            input.privacy_class,
            input.valid_until,
            input.related_entities,
            input.expected_revision,
        )
        .await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/memory/{id}/forget", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn forget_memory(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    orbit_memory::forget(&state.pool, &auth.scope, id).await?;
    Ok(Json(json!({"status": "FORGOTTEN", "id": id})))
}

#[utoipa::path(get, path = "/api/v1/memory/{id}/history", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn memory_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(orbit_memory::history(&state.pool, &auth.scope, id).await?))
}

#[utoipa::path(post, path = "/api/v1/memory/search", request_body = SearchRequest, responses((status = 200, body = Value)))]
pub async fn search_memories(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SearchRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let request = orbit_memory::SearchRequest {
        query: input.query,
        types: input.types,
        project_id: input.project_id,
        limit: input.limit.unwrap_or(12),
    };
    // Retrieval enforces the 12-record / 6000-character budget and excludes SECRET records.
    let records =
        orbit_memory::search(&state.pool, &auth.scope, &request, &owner_scope(), None).await?;
    Ok(Json(json!({"items": records})))
}

#[utoipa::path(get, path = "/api/v1/projects", responses((status = 200, body = Value)))]
pub async fn list_projects(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<MemoryPage>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let limit = page.limit.unwrap_or(20).clamp(1, 50);
    let (projects, next) =
        orbit_memory::list(&state.pool, &auth.scope, Some(MemoryType::Project), page.cursor, limit)
            .await?;
    let mut items = Vec::with_capacity(projects.len());
    for project in &projects {
        let related: Vec<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(m) - 'owner_id' FROM memory_relations r \
             JOIN memory_records m ON m.owner_id = r.owner_id \
             AND m.id = CASE WHEN r.from_id = $2 THEN r.to_id ELSE r.from_id END \
             WHERE r.owner_id = $1 AND (r.from_id = $2 OR r.to_id = $2) AND m.id <> $2 \
             AND m.type IN ('TASK','DECISION','DOCUMENT') AND m.status = 'ACTIVE' \
             AND m.privacy_class <> 'SECRET' AND (m.valid_until IS NULL OR m.valid_until > now()) \
             ORDER BY m.id",
        )
        .bind(auth.scope.owner_id)
        .bind(project.id)
        .fetch_all(&state.pool)
        .await?;
        items.push(json!({"record": project, "related": related}));
    }
    Ok(Json(json!({"items": items, "next_cursor": next})))
}

#[utoipa::path(get, path = "/api/v1/retention", responses((status = 200, body = RetentionSettingsResponse)))]
pub async fn get_retention(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<RetentionSettingsResponse>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let row = sqlx::query(
        "SELECT event_body_days, conversation_body_days, runtime_artifact_days, connector_cache_days \
         FROM retention_settings WHERE owner_id = $1",
    )
    .bind(auth.scope.owner_id)
    .fetch_optional(&state.pool)
    .await?;
    match row {
        Some(row) => Ok(Json(RetentionSettingsResponse {
            event_body_days: row.get("event_body_days"),
            conversation_body_days: row.get("conversation_body_days"),
            runtime_artifact_days: row.get("runtime_artifact_days"),
            connector_cache_days: row.get("connector_cache_days"),
        })),
        None => Ok(Json(RetentionSettingsResponse {
            event_body_days: 30,
            conversation_body_days: 90,
            runtime_artifact_days: 30,
            connector_cache_days: 30,
        })),
    }
}

#[utoipa::path(put, path = "/api/v1/retention", request_body = RetentionUpdate, responses((status = 200, body = RetentionSettingsResponse)))]
pub async fn update_retention(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<RetentionUpdate>,
) -> Result<Json<RetentionSettingsResponse>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    if input.event_body_days < 1
        || input.conversation_body_days < 1
        || input.runtime_artifact_days < 1
        || input.connector_cache_days < 1
    {
        return Err(Error::Validation("retention windows must be at least 1 day".into()).into());
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id = $1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO retention_settings(owner_id, event_body_days, conversation_body_days, runtime_artifact_days, connector_cache_days) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (owner_id) DO UPDATE SET event_body_days = $2, conversation_body_days = $3, \
         runtime_artifact_days = $4, connector_cache_days = $5",
    )
    .bind(auth.scope.owner_id)
    .bind(input.event_body_days)
    .bind(input.conversation_body_days)
    .bind(input.runtime_artifact_days)
    .bind(input.connector_cache_days)
    .execute(&mut *tx)
    .await?;
    orbit_audit::append(
        &mut tx,
        &auth.scope,
        Uuid::new_v4(),
        None,
        None,
        "RETENTION_UPDATED",
        "owner updated retention settings",
        json!({
            "event_body_days": input.event_body_days,
            "conversation_body_days": input.conversation_body_days,
            "runtime_artifact_days": input.runtime_artifact_days,
            "connector_cache_days": input.connector_cache_days,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(RetentionSettingsResponse {
        event_body_days: input.event_body_days,
        conversation_body_days: input.conversation_body_days,
        runtime_artifact_days: input.runtime_artifact_days,
        connector_cache_days: input.connector_cache_days,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_memories,
        create_memory,
        get_memory,
        patch_memory,
        verify_memory,
        supersede_memory,
        forget_memory,
        memory_history,
        search_memories,
        list_projects,
        get_retention,
        update_retention
    ),
    components(schemas(
        CreateMemoryRequest,
        PatchMemoryRequest,
        SupersedeRequest,
        VerifyRequest,
        SearchRequest,
        RetentionSettingsResponse,
        RetentionUpdate
    ))
)]
pub struct MemoryApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/memory", get(list_memories).post(create_memory))
        .route("/api/v1/memory/search", post(search_memories))
        .route("/api/v1/memory/{id}", get(get_memory).patch(patch_memory))
        .route("/api/v1/memory/{id}/verify", post(verify_memory))
        .route("/api/v1/memory/{id}/supersede", post(supersede_memory))
        .route("/api/v1/memory/{id}/forget", post(forget_memory))
        .route("/api/v1/memory/{id}/history", get(memory_history))
        .route("/api/v1/projects", get(list_projects))
        .route("/api/v1/retention", get(get_retention).put(update_retention))
}
