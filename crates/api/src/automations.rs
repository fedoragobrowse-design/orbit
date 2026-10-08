use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Automation CRUD + lifecycle for durable cron / timer / event triggers.
///
/// Every route is owner-scoped via [`authenticate`]; all scheduler mutations
/// lock the owner's authorization epoch first, so concurrent schedulers and
/// API writers serialize on one owner at a time.
///
/// Trigger shapes:
/// - `{"kind":"cron","expression":"0 9 * * *","timezone":"UTC"}` — standard
///   5-field cron with an explicit fixed `+HH:MM`/`-HH:MM`/`Z`/`UTC` offset.
/// - `{"kind":"timer","run_at":"<rfc3339>"}` — one-shot timer.
/// - `{"kind":"event","event_type":"EMAIL_RECEIVED","filters":[...]}` —
///   durable file/event trigger; the scheduler matches filters at claim time.
///
/// Missed windows coalesce: if the worker was down, a cron/timer automation
/// fires exactly one trigger for the whole backlog and records the rest as
/// `missed_count` on the fire row — never a burst. `preview` reports what
/// would fire without inserting any fire, event, or task rows.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAutomationRequest {
    pub trigger: Value,
    #[serde(default)]
    pub filters: Value,
    pub agent_id: Option<Uuid>,
    pub instructions: String,
    #[serde(default)]
    pub policy_scope: Value,
    #[serde(default = "default_model_role")]
    pub model_role: String,
    #[serde(default = "default_notification_behavior")]
    pub notification_behavior: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_model_role() -> String {
    "FAST".into()
}
fn default_notification_behavior() -> String {
    "NONE".into()
}
fn default_timezone() -> String {
    "UTC".into()
}
fn default_enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationPage {
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchAutomationRequest {
    #[serde(default)]
    pub expected_revision: i64,
    pub trigger: Option<Value>,
    pub filters: Option<Value>,
    pub agent_id: Option<Option<Uuid>>,
    pub instructions: Option<String>,
    pub policy_scope: Option<Value>,
    pub model_role: Option<String>,
    pub notification_behavior: Option<String>,
    pub timezone: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetEnabledRequest {
    pub enabled: bool,
    pub expected_revision: i64,
}

#[utoipa::path(get, path = "/api/v1/automations", responses((status = 200, body = Value)))]
pub async fn list_automations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<AutomationPage>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let limit = page.limit.unwrap_or(20).clamp(1, 50);
    let (items, next) = orbit_scheduler::list(&state.pool, &auth.scope, page.cursor, limit).await?;
    Ok(Json(json!({"items": items, "next_cursor": next})))
}

#[utoipa::path(post, path = "/api/v1/automations", request_body = CreateAutomationRequest, responses((status = 200, body = Value)))]
pub async fn create_automation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<CreateAutomationRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let automation = orbit_scheduler::Automation {
        id: Uuid::new_v4(),
        owner_id: auth.scope.owner_id,
        enabled: input.enabled,
        trigger: input.trigger,
        filters: if input.filters.is_null() {
            Value::Array(vec![])
        } else {
            input.filters
        },
        agent_id: input.agent_id,
        instructions: input.instructions,
        policy_scope: if input.policy_scope.is_null() {
            json!({})
        } else {
            input.policy_scope
        },
        model_role: input.model_role,
        notification_behavior: input.notification_behavior,
        timezone: input.timezone,
        version: 1,
        revision: 1,
        next_run: None,
        last_run: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    Ok(Json(json!(
        orbit_scheduler::create(&state.pool, &auth.scope, automation).await?
    )))
}

#[utoipa::path(get, path = "/api/v1/automations/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn get_automation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(json!(
        orbit_scheduler::get(&state.pool, &auth.scope, id).await?
    )))
}

#[utoipa::path(patch, path = "/api/v1/automations/{id}", params(("id" = Uuid, Path)), request_body = PatchAutomationRequest, responses((status = 200, body = Value)))]
pub async fn patch_automation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<PatchAutomationRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mut patch = json!({});
    if let Some(v) = input.trigger {
        patch["trigger"] = v;
    }
    if let Some(v) = input.filters {
        patch["filters"] = v;
    }
    if let Some(v) = input.instructions {
        patch["instructions"] = Value::String(v);
    }
    if let Some(v) = input.policy_scope {
        patch["policy_scope"] = v;
    }
    if let Some(v) = input.model_role {
        patch["model_role"] = Value::String(v);
    }
    if let Some(v) = input.notification_behavior {
        patch["notification_behavior"] = Value::String(v);
    }
    if let Some(v) = input.timezone {
        patch["timezone"] = Value::String(v);
    }
    if let Some(v) = input.agent_id {
        patch["agent_id"] = v
            .map(|id| Value::from(id.to_string()))
            .unwrap_or(Value::Null);
    }
    Ok(Json(json!(
        orbit_scheduler::update(&state.pool, &auth.scope, id, input.expected_revision, patch)
            .await?
    )))
}

#[utoipa::path(post, path = "/api/v1/automations/{id}/enable", params(("id" = Uuid, Path)), request_body = SetEnabledRequest, responses((status = 200, body = Value)))]
pub async fn set_automation_enabled(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SetEnabledRequest>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    Ok(Json(json!(
        orbit_scheduler::set_enabled(
            &state.pool,
            &auth.scope,
            id,
            input.enabled,
            input.expected_revision
        )
        .await?
    )))
}

#[utoipa::path(delete, path = "/api/v1/automations/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn delete_automation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    orbit_scheduler::remove(&state.pool, &auth.scope, id).await?;
    Ok(Json(json!({"deleted": id})))
}

/// Side-effect-free preview: reports the next scheduled run and how many
/// missed windows would coalesce into a single trigger. Inserts nothing.
#[utoipa::path(get, path = "/api/v1/automations/{id}/preview", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn preview_automation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(
        orbit_scheduler::preview(&state.pool, &auth.scope, id).await?,
    ))
}

/// Correlated fire history for one automation, newest first, each row
/// carrying the event and task the window was dispatched to.
#[utoipa::path(get, path = "/api/v1/automations/{id}/history", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn automation_history(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(page): Query<AutomationPage>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let limit = page.limit.unwrap_or(20).clamp(1, 50);
    let (items, next) =
        orbit_scheduler::history(&state.pool, &auth.scope, id, page.cursor, limit).await?;
    Ok(Json(json!({"items": items, "next_cursor": next})))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_automations,
        create_automation,
        get_automation,
        patch_automation,
        set_automation_enabled,
        delete_automation,
        preview_automation,
        automation_history
    ),
    components(schemas(CreateAutomationRequest, PatchAutomationRequest, SetEnabledRequest))
)]
pub struct AutomationsApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/automations",
            get(list_automations).post(create_automation),
        )
        .route(
            "/api/v1/automations/{id}",
            get(get_automation)
                .patch(patch_automation)
                .delete(delete_automation),
        )
        .route(
            "/api/v1/automations/{id}/enable",
            post(set_automation_enabled),
        )
        .route("/api/v1/automations/{id}/preview", get(preview_automation))
        .route("/api/v1/automations/{id}/history", get(automation_history))
}
