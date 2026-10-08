use crate::{ApiError, ApiState, authenticate};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{delete, get, post},
    Json, Router,
};
use orbit_core::Error;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;
use utoipa::ToSchema;

// Write-transaction lock order (shared convention): authorization_epochs ->
// task -> tool call -> approval. Every mutation below locks in this order.

#[derive(Deserialize)]
pub struct Page {
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct ListResponse {
    pub items: Vec<Value>,
    pub next_cursor: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct PolicyView {
    pub rules: Value,
    pub revision: i64,
    pub max_tool_calls: i32,
    pub max_active_seconds: i32,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyUpdate {
    pub rules: Value,
    pub expected_revision: i64,
}

#[derive(Serialize, ToSchema)]
pub struct GrantView {
    pub id: Uuid,
    pub tool_name: String,
    pub scope_key: String,
    pub scope_revision: i64,
    pub max_risk: String,
    pub autonomy_modes: Value,
    pub parameter_bounds: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantCreate {
    pub tool_name: String,
    pub scope_key: String,
    pub scope_revision: i64,
    pub max_risk: String,
    pub autonomy_modes: Value,
    pub parameter_bounds: Value,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecision {
    pub expected_revision: i64,
}

fn page_args(page: Page) -> Result<(i64, i64), ApiError> {
    let limit = page.limit.unwrap_or(30).clamp(1, 100);
    let offset = page.cursor.unwrap_or(0);
    if offset < 0 {
        return Err(Error::Validation("invalid cursor".into()).into());
    }
    Ok((limit, offset))
}

fn paged(items: Vec<Value>, limit: i64, offset: i64) -> ListResponse {
    let mut items = items;
    let next = if items.len() > limit as usize {
        items.pop();
        Some(offset + limit)
    } else {
        None
    };
    ListResponse {
        items,
        next_cursor: next,
    }
}

#[utoipa::path(get, path = "/api/v1/policy", responses((status = 200, body = PolicyView)))]
pub async fn get_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<PolicyView>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = sqlx::query("SELECT rules,revision,max_tool_calls,max_active_seconds FROM policies WHERE owner_id=$1")
        .bind(a.scope.owner_id)
        .fetch_optional(&state.pool)
        .await?;
    match row {
        Some(r) => Ok(Json(PolicyView {
            rules: r.get("rules"),
            revision: r.get("revision"),
            max_tool_calls: r.get("max_tool_calls"),
            max_active_seconds: r.get("max_active_seconds"),
        })),
        None => Ok(Json(PolicyView {
            rules: json!([]),
            revision: 1,
            max_tool_calls: 24,
            max_active_seconds: 600,
        })),
    }
}

#[utoipa::path(put, path = "/api/v1/policy", request_body = PolicyUpdate, responses((status = 200, body = PolicyView)))]
pub async fn update_policy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<PolicyUpdate>,
) -> Result<Json<PolicyView>, ApiError> {
    if !input.rules.is_array() {
        return Err(Error::Validation("policy rules must be an array".into()).into());
    }
    for rule in input.rules.as_array().expect("array checked") {
        if rule.get("tool_pattern").and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err(Error::Validation("every policy rule needs a tool_pattern".into()).into());
        }
    }
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT revision FROM policies WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_optional(&mut *tx)
        .await?;
    let live = match row {
        Some(r) => r.get::<i64, _>("revision"),
        None => {
            sqlx::query("INSERT INTO policies(owner_id,rules) VALUES($1,'[]')")
                .bind(a.scope.owner_id)
                .execute(&mut *tx)
                .await?;
            1
        }
    };
    if live != input.expected_revision {
        return Err(Error::Conflict("policy revision changed".into()).into());
    }
    let updated = sqlx::query("UPDATE policies SET rules=$2,revision=revision+1 WHERE owner_id=$1 RETURNING revision,max_tool_calls,max_active_seconds")
        .bind(a.scope.owner_id)
        .bind(&input.rules)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(a.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "POLICY_UPDATED",
        "owner updated gateway policy",
        json!({"revision": updated.get::<i64, _>("revision")}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(PolicyView {
        rules: input.rules,
        revision: updated.get("revision"),
        max_tool_calls: updated.get("max_tool_calls"),
        max_active_seconds: updated.get("max_active_seconds"),
    }))
}

#[utoipa::path(get, path = "/api/v1/grants", responses((status = 200, body = ListResponse)))]
pub async fn list_grants(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<ListResponse>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (limit, offset) = page_args(page)?;
    let items: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(g)-'owner_id' FROM scope_grants g WHERE owner_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3")
        .bind(a.scope.owner_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(paged(items, limit, offset)))
}

fn validate_grant(input: &GrantCreate) -> Result<(), Error> {
    if input.tool_name.is_empty()
        || input.tool_name.len() > 256
        || input.scope_key.is_empty()
        || input.scope_key.len() > 256
    {
        return Err(Error::Validation("tool_name and scope_key are required, maximum 256 characters".into()));
    }
    if input.scope_revision < 1 {
        return Err(Error::Validation("scope_revision must be positive".into()));
    }
    if !matches!(input.max_risk.as_str(), "READ_ONLY" | "LOW") {
        return Err(Error::Validation("max_risk must be READ_ONLY or LOW".into()));
    }
    let modes = input.autonomy_modes.as_array().filter(|m| !m.is_empty()).ok_or_else(|| Error::Validation("autonomy_modes must be a non-empty array".into()))?;
    for mode in modes {
        if !matches!(
            mode.as_str(),
            Some("CHAT" | "OBSERVE" | "ASSIST" | "TRUSTED_AUTOMATION" | "CUSTOM")
        ) {
            return Err(Error::Validation("unknown autonomy mode in grant".into()));
        }
    }
    if !input.parameter_bounds.is_object() || input.parameter_bounds.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(Error::Validation("parameter_bounds must be a non-empty object".into()));
    }
    Ok(())
}

#[utoipa::path(post, path = "/api/v1/grants", request_body = GrantCreate, responses((status = 200, body = GrantView)))]
pub async fn create_grant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<GrantCreate>,
) -> Result<Json<Value>, ApiError> {
    validate_grant(&input).map_err(ApiError)?;
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let id = Uuid::new_v4();
    let inserted = sqlx::query("INSERT INTO scope_grants AS sg(id,owner_id,tool_name,scope_key,scope_revision,max_risk,autonomy_modes,parameter_bounds) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING RETURNING to_jsonb(sg)-'owner_id' AS record")
        .bind(id)
        .bind(a.scope.owner_id)
        .bind(&input.tool_name)
        .bind(&input.scope_key)
        .bind(input.scope_revision)
        .bind(&input.max_risk)
        .bind(&input.autonomy_modes)
        .bind(&input.parameter_bounds)
        .fetch_optional(&mut *tx)
        .await?;
    let record: Value = inserted
        .and_then(|r| r.try_get::<Value, _>("record").ok())
        .ok_or(Error::Conflict("duplicate grant for tool and scope".into()))?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(a.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "GRANT_CREATED",
        "owner created scope grant",
        json!({"grant_id": id, "tool_name": input.tool_name, "scope_key": input.scope_key}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(record))
}

#[utoipa::path(delete, path = "/api/v1/grants/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn delete_grant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    // Lock order: authorization_epochs first.
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let grant = sqlx::query("SELECT tool_name,scope_key FROM scope_grants WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let tool_name: String = grant.get("tool_name");
    let scope_key: String = grant.get("scope_key");
    sqlx::query("DELETE FROM scope_grants WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(a.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    // Revocation invalidates queued approvals for that tool+scope so a stale
    // consent can never dispatch after the grant is gone.
    let invalidated: Vec<Uuid> = sqlx::query_scalar("UPDATE tool_calls SET state='INVALIDATED',error_code='GRANT_REVOKED' WHERE owner_id=$1 AND state='WAITING_FOR_APPROVAL' AND snapshot->>'tool_name'=$2 AND (snapshot->'scope_revisions') ? $3 RETURNING id")
        .bind(a.scope.owner_id)
        .bind(&tool_name)
        .bind(&scope_key)
        .fetch_all(&mut *tx)
        .await?;
    for call_id in &invalidated {
        sqlx::query("UPDATE approvals SET state='EXPIRED' WHERE owner_id=$1 AND call_id=$2 AND state='PENDING'")
            .bind(a.scope.owner_id)
            .bind(call_id)
            .execute(&mut *tx)
            .await?;
    }
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "GRANT_REVOKED",
        "owner revoked scope grant",
        json!({"grant_id": id, "tool_name": tool_name, "scope_key": scope_key, "calls_invalidated": invalidated.len() as i64}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"removed": true, "calls_invalidated": invalidated.len() as i64})))
}

#[utoipa::path(get, path = "/api/v1/approvals", responses((status = 200, body = ListResponse)))]
pub async fn list_approvals(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<ListResponse>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (limit, offset) = page_args(page)?;
    let items: Vec<Value> = sqlx::query_scalar("SELECT ((to_jsonb(a) - 'owner_id') || jsonb_build_object('requires_sandbox', COALESCE((a.snapshot->>'requires_sandbox')::boolean, true))) FROM approvals a WHERE owner_id=$1 AND state='PENDING' ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3")
        .bind(a.scope.owner_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(paged(items, limit, offset)))
}

#[utoipa::path(get, path = "/api/v1/approvals/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn approval_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let record: Value = sqlx::query_scalar("SELECT ((to_jsonb(a) - 'owner_id') || jsonb_build_object('requires_sandbox', COALESCE((a.snapshot->>'requires_sandbox')::boolean, true))) FROM approvals a WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(record))
}

struct ApprovalContext {
    task_id: Uuid,
    call_id: Uuid,
    correlation_id: Uuid,
    task_revision: i64,
    task_fence: i64,
    requires_sandbox: bool,
    snapshot: Value,
    action_hash: String,
}

/// Lock order: authorization_epochs -> task -> tool call -> approval. Reads the
/// approval/call binding without locks first so the locking itself follows the
/// order, then re-verifies everything after all locks are held.
async fn locked_approval(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_id: Uuid,
    approval_id: Uuid,
    expected_revision: i64,
) -> Result<ApprovalContext, Error> {
    let live_epoch: i64 = sqlx::query_scalar("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(owner_id)
        .fetch_one(&mut **tx)
        .await?;
    let link = sqlx::query("SELECT task_id,call_id FROM approvals WHERE owner_id=$1 AND id=$2")
        .bind(owner_id)
        .bind(approval_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    let task_id: Uuid = link.get("task_id");
    let call_id: Uuid = link.get("call_id");

    let task = sqlx::query("SELECT *,expires_at>now() AS unexpired,lease_until>now() AS lease_live FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(owner_id)
        .bind(task_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    if task.get::<i64, _>("revision") != expected_revision {
        return Err(Error::Conflict("task revision changed".into()));
    }
    let task_state: String = task.get("state");
    // The gateway only resumes tasks parked in WAITING_FOR_APPROVAL; that is
    // also the single state with a legal trigger transition back to QUEUED.
    if task_state != "WAITING_FOR_APPROVAL" {
        return Err(Error::Conflict("task is not awaiting approval".into()));
    }
    if !task.get::<bool, _>("unexpired") {
        return Err(Error::Conflict("task expired".into()));
    }

    let call = sqlx::query("SELECT * FROM tool_calls WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(owner_id)
        .bind(call_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    if call.get::<Uuid, _>("task_id") != task_id {
        return Err(Error::Conflict("approval binding changed".into()));
    }
    if call.get::<String, _>("state") != "WAITING_FOR_APPROVAL" {
        return Err(Error::Conflict("proposal already settled".into()));
    }
    if call.get::<Option<Uuid>, _>("approval_id") != Some(approval_id) {
        return Err(Error::Conflict("approval binding changed".into()));
    }
    if call.get::<Option<i64>, _>("task_fence").is_some_and(|f| f != task.get::<i64, _>("fence")) {
        return Err(Error::Conflict("task fence changed".into()));
    }

    let approval = sqlx::query("SELECT *,expires_at>now() AS unexpired FROM approvals WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(owner_id)
        .bind(approval_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    if approval.get::<String, _>("state") != "PENDING" {
        return Err(Error::Conflict("approval already decided".into()));
    }
    if !approval.get::<bool, _>("unexpired") {
        return Err(Error::Conflict("approval expired".into()));
    }

    // Digest binding: the approval and the queued call must commit to the same
    // immutable snapshot and action hash; the trigger layer rejects mutation.
    let snapshot: Value = approval.get("snapshot");
    let action_hash: String = approval.get("action_hash");
    if action_hash.len() != 64 || call.get::<Value, _>("snapshot") != snapshot || call.get::<String, _>("action_hash") != action_hash {
        return Err(Error::Conflict("immutable action digest changed".into()));
    }

    // Live authorization recheck: the consent is only valid while the policy
    // revision, authorization epoch, and every scoped grant revision recorded
    // in the snapshot still match the live rows.
    let policy_revision = snapshot.get("policy_revision").and_then(Value::as_i64).unwrap_or(-1);
    let epoch = snapshot.get("authorization_epoch").and_then(Value::as_i64).unwrap_or(-1);
    if epoch != live_epoch {
        return Err(Error::Conflict("authorization changed; re-proposal required".into()));
    }
    let live_policy: Option<i64> = sqlx::query_scalar("SELECT revision FROM policies WHERE owner_id=$1")
        .bind(owner_id)
        .fetch_optional(&mut **tx)
        .await?;
    if live_policy.unwrap_or(1) != policy_revision {
        return Err(Error::Conflict("policy changed; re-proposal required".into()));
    }
    let tool_name = snapshot.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let scopes = snapshot.get("scope_revisions").and_then(Value::as_object).cloned().unwrap_or_default();
    for (scope_key, revision) in &scopes {
        let live_grant: Option<i64> = sqlx::query_scalar("SELECT scope_revision FROM scope_grants WHERE owner_id=$1 AND tool_name=$2 AND scope_key=$3")
            .bind(owner_id)
            .bind(tool_name)
            .bind(scope_key)
            .fetch_optional(&mut **tx)
            .await?;
        if live_grant != revision.as_i64() {
            return Err(Error::Conflict("scope grant changed; re-proposal required".into()));
        }
    }

    Ok(ApprovalContext {
        task_id,
        call_id,
        correlation_id: task.get("correlation_id"),
        task_revision: task.get("revision"),
        task_fence: task.get("fence"),
        requires_sandbox: snapshot.get("requires_sandbox").and_then(Value::as_bool).unwrap_or(true),
        snapshot,
        action_hash,
    })
}

async fn queue_task_wakeup(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_id: Uuid,
    principal_id: Uuid,
    correlation_id: Uuid,
    approval_id: Uuid,
    accepted: bool,
) -> Result<(), Error> {
    let kind = if accepted { "APPROVAL_ACCEPTED" } else { "APPROVAL_DENIED" };
    let event_id: Uuid = sqlx::query_scalar("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,$3,'gateway',$4,$5,'OWNER_AUTHENTICATED','PRIVATE',$6,$7) ON CONFLICT(owner_id,source,source_event_key) DO UPDATE SET source_event_key=EXCLUDED.source_event_key RETURNING id")
        .bind(Uuid::new_v4())
        .bind(owner_id)
        .bind(kind)
        .bind(principal_id)
        .bind(json!({"approval_id": approval_id}))
        .bind(correlation_id)
        .bind(format!("approval:{approval_id}:{kind}"))
        .fetch_one(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING")
        .bind(Uuid::new_v4())
        .bind(owner_id)
        .bind(event_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[utoipa::path(post, path = "/api/v1/approvals/{id}/approve", params(("id" = Uuid, Path)), request_body = ApprovalDecision, responses((status = 200, body = Value)))]
pub async fn approve_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ApprovalDecision>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    let ctx = locked_approval(&mut tx, a.scope.owner_id, id, input.expected_revision).await?;

    // Consume the consent exactly once; the PENDING guard makes a second
    // dispatch conflict instead of double-executing.
    let consumed = sqlx::query("UPDATE approvals SET state='CONSUMED',decided_at=now(),decided_by=$3,consumed_at=now() WHERE owner_id=$1 AND id=$2 AND state='PENDING'")
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(a.scope.principal_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if consumed != 1 {
        return Err(Error::Conflict("approval already decided".into()).into());
    }

    let authorization_id = Uuid::new_v4();
    let dispatched = sqlx::query("UPDATE tool_calls SET state='SUBMITTED',authorization_id=$3,task_fence=$4,submitted_at=now() WHERE owner_id=$1 AND id=$2 AND state='WAITING_FOR_APPROVAL'")
        .bind(a.scope.owner_id)
        .bind(ctx.call_id)
        .bind(authorization_id)
        .bind(ctx.task_fence)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if dispatched != 1 {
        return Err(Error::Conflict("proposal already settled".into()).into());
    }

    let resumed = sqlx::query("UPDATE tasks SET state='QUEUED',revision=revision+1,wait_reason=NULL,checkpoint=checkpoint || jsonb_build_object('phase','DISPATCH','approval_id',$3,'authorization_id',$4),updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5")
        .bind(a.scope.owner_id)
        .bind(ctx.task_id)
        .bind(id)
        .bind(authorization_id)
        .bind(ctx.task_revision)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if resumed != 1 {
        return Err(Error::Conflict("task revision changed".into()).into());
    }
    queue_task_wakeup(&mut tx, a.scope.owner_id, a.scope.principal_id, ctx.correlation_id, id, true).await?;

    orbit_audit::append(
        &mut tx,
        &a.scope,
        ctx.correlation_id,
        None,
        Some(ctx.task_id),
        "APPROVAL_CONSUMED",
        "owner approved tool call",
        json!({"approval_id": id, "call_id": ctx.call_id, "authorization_id": authorization_id, "requires_sandbox": ctx.requires_sandbox}),
    )
    .await?;
    tx.commit().await?;
    // Consent never removes the sandbox requirement recorded in the snapshot.
    Ok(Json(json!({
        "id": id,
        "call_id": ctx.call_id,
        "task_id": ctx.task_id,
        "state": "CONSUMED",
        "authorization_id": authorization_id,
        "task_fence": ctx.task_fence,
        "action_hash": ctx.action_hash,
        "requires_sandbox": ctx.requires_sandbox,
        "preview": ctx.snapshot.get("arguments").cloned().unwrap_or(Value::Null),
    })))
}

#[utoipa::path(post, path = "/api/v1/approvals/{id}/reject", params(("id" = Uuid, Path)), request_body = ApprovalDecision, responses((status = 200, body = Value)))]
pub async fn reject_approval(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ApprovalDecision>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    let ctx = locked_approval(&mut tx, a.scope.owner_id, id, input.expected_revision).await?;

    let decided = sqlx::query("UPDATE approvals SET state='DENIED',decided_at=now(),decided_by=$3 WHERE owner_id=$1 AND id=$2 AND state='PENDING'")
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(a.scope.principal_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if decided != 1 {
        return Err(Error::Conflict("approval already decided".into()).into());
    }
    // Rejection closes the proposal; the denied call never dispatches.
    sqlx::query("UPDATE tool_calls SET state='DENIED',error_code='OWNER_DENIED' WHERE owner_id=$1 AND id=$2 AND state='WAITING_FOR_APPROVAL'")
        .bind(a.scope.owner_id)
        .bind(ctx.call_id)
        .execute(&mut *tx)
        .await?;
    let resumed = sqlx::query("UPDATE tasks SET state='QUEUED',revision=revision+1,wait_reason=NULL,checkpoint=checkpoint || jsonb_build_object('phase','DISPATCH','denied_approval_id',$3),updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$4")
        .bind(a.scope.owner_id)
        .bind(ctx.task_id)
        .bind(id)
        .bind(ctx.task_revision)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if resumed != 1 {
        return Err(Error::Conflict("task revision changed".into()).into());
    }
    queue_task_wakeup(&mut tx, a.scope.owner_id, a.scope.principal_id, ctx.correlation_id, id, false).await?;

    orbit_audit::append(
        &mut tx,
        &a.scope,
        ctx.correlation_id,
        None,
        Some(ctx.task_id),
        "APPROVAL_DENIED",
        "owner rejected tool call",
        json!({"approval_id": id, "call_id": ctx.call_id}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id": id, "call_id": ctx.call_id, "task_id": ctx.task_id, "state": "DENIED"})))
}

#[utoipa::path(get, path = "/api/v1/tool-calls", responses((status = 200, body = ListResponse)))]
pub async fn list_tool_calls(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<ListResponse>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (limit, offset) = page_args(page)?;
    let items: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM tool_calls t WHERE owner_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3")
        .bind(a.scope.owner_id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(paged(items, limit, offset)))
}

#[utoipa::path(get, path = "/api/v1/tool-calls/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn tool_call_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let record: Value = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM tool_calls t WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(record))
}

#[utoipa::path(get, path = "/api/v1/tools", responses((status = 200, body = ListResponse)))]
pub async fn list_tools(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<ListResponse>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let items: Vec<Value> = sqlx::query_scalar("SELECT descriptor FROM tool_registry WHERE owner_id=$1 AND enabled ORDER BY name")
        .bind(a.scope.owner_id)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(ListResponse { items, next_cursor: None }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_policy,
        update_policy,
        list_grants,
        create_grant,
        delete_grant,
        list_approvals,
        approval_detail,
        approve_approval,
        reject_approval,
        list_tool_calls,
        tool_call_detail,
        list_tools,
    ),
    components(schemas(
        ListResponse,
        PolicyView,
        PolicyUpdate,
        GrantView,
        GrantCreate,
        ApprovalDecision,
    ))
)]
pub struct GatewayApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/policy", get(get_policy).put(update_policy))
        .route("/api/v1/grants", get(list_grants).post(create_grant))
        .route("/api/v1/grants/{id}", delete(delete_grant))
        .route("/api/v1/approvals", get(list_approvals))
        .route("/api/v1/approvals/{id}", get(approval_detail))
        .route("/api/v1/approvals/{id}/approve", post(approve_approval))
        .route("/api/v1/approvals/{id}/reject", post(reject_approval))
        .route("/api/v1/tool-calls", get(list_tool_calls))
        .route("/api/v1/tool-calls/{id}", get(tool_call_detail))
        .route("/api/v1/tools", get(list_tools))
}
