//! Owner answers for agent questions plus the agent docs pages.
//! Questions come from the orbit-control.ask_owner tool; the owner answers
//! or cancels them here. Docs are the same pages the agent reads, served
//! as plain text so the web app and the agent see the same words.
use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use orbit_core::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

fn doc_content(page: &str) -> Option<&'static str> {
    Some(match page {
        "overview" => include_str!("../../../docs/orbit-overview.md"),
        "settings" => include_str!("../../../docs/orbit-settings.md"),
        "memory" => include_str!("../../../docs/orbit-memory.md"),
        "tools" => include_str!("../../../docs/orbit-tools.md"),
        _ => return None,
    })
}

#[derive(Serialize)]
pub struct DocResponse {
    page: String,
    content: String,
}

#[utoipa::path(get,path="/api/v1/docs/{page}",params(("page"=String,Path)),responses((status=200,body=Value)))]
pub async fn get_doc(
    State(_state): State<ApiState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<DocResponse>, ApiError> {
    let _a = authenticate(&_state, &headers, false).await?;
    let content = doc_content(page.trim()).ok_or(Error::NotFound)?;
    Ok(Json(DocResponse {
        page: page.trim().to_owned(),
        content: content.to_owned(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionsQuery {
    #[serde(default)]
    pub state: Option<String>,
}

#[utoipa::path(get,path="/api/v1/questions",responses((status=200,body=Value)))]
pub async fn list_questions(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<QuestionsQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let items: Vec<Value> = match q.state.as_deref().map(str::trim) {
        None | Some("") => {
            sqlx::query_scalar("SELECT jsonb_build_object('id',id,'task_id',task_id,'agent_id',agent_id,'question',question,'options',options,'answer',answer,'state',state,'created_at',created_at,'answered_at',answered_at) FROM agent_questions WHERE owner_id=$1 ORDER BY created_at DESC,id DESC LIMIT 100")
                .bind(a.scope.owner_id).fetch_all(&state.pool).await?
        }
        Some(s) => {
            if !matches!(s, "OPEN" | "ANSWERED" | "CANCELLED") {
                return Err(Error::Validation("unknown question state".into()).into());
            }
            sqlx::query_scalar("SELECT jsonb_build_object('id',id,'task_id',task_id,'agent_id',agent_id,'question',question,'options',options,'answer',answer,'state',state,'created_at',created_at,'answered_at',answered_at) FROM agent_questions WHERE owner_id=$1 AND state=$2 ORDER BY created_at DESC,id DESC LIMIT 100")
                .bind(a.scope.owner_id).bind(s).fetch_all(&state.pool).await?
        }
    };
    Ok(Json(json!({"items": items})))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AnswerRequest {
    pub answer: String,
    pub expected_revision: Option<i64>,
}

fn valid_answer(v: &str) -> bool {
    let t = v.trim();
    !t.is_empty() && t.len() <= 2000
}

/// Settle one OPEN question exactly once. Lock order follows the shared
/// convention: authorization_epochs -> task -> tool call -> question. The
/// answer is stored as an owner-authenticated tool result row on the parked
/// call, the call is settled with that result, and the task is re-queued at
/// phase RESULT/CONTEXT so the same run resumes with the answer — never a
/// fabricated one. Re-answer is 409; cancelled/expired resumes with a
/// cancelled result, never a fabricated answer.
async fn settle_question(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
    id: Uuid,
    expected_revision: Option<i64>,
    answer: Option<String>,
    cancelled: bool,
) -> Result<Value, Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let question_head = sqlx::query("SELECT task_id,call_id FROM agent_questions WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let task_id: Uuid = question_head.get("task_id");
    let task = sqlx::query("SELECT revision,fence,state,correlation_id FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(scope.owner_id)
        .bind(task_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let task_revision: i64 = task.get("revision");
    let task_state: String = task.get("state");
    let correlation: Uuid = task.get("correlation_id");
    let call_id: Option<Uuid> = question_head.get("call_id");
    if let Some(cid) = call_id {
        sqlx::query("SELECT id FROM tool_calls WHERE owner_id=$1 AND id=$2 AND task_id=$3 FOR UPDATE")
            .bind(scope.owner_id)
            .bind(cid)
            .bind(task_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::NotFound)?;
    }
    // Question last under the same locks: OPEN + revision match, consumed once.
    let question = sqlx::query("SELECT state,revision,expires_at FROM agent_questions WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let state: String = question.get("state");
    if state != "OPEN" {
        return Err(Error::Conflict("question is no longer open".into()));
    }
    let question_revision: i64 = question.get("revision");
    if let Some(expected) = expected_revision {
        if expected != question_revision {
            return Err(Error::Conflict("question revision changed".into()));
        }
    }
    let expired: bool = question
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at")
        .is_some_and(|exp| exp <= chrono::Utc::now());
    // An expired question can only lapse: answer attempts conflict, cancel lapses it.
    if expired && !cancelled {
        return Err(Error::Conflict("question expired".into()));
    }
    let lapsed = cancelled || expired;
    let result = match (&answer, lapsed) {
        (Some(text), false) => json!({"answer": text, "question_id": id}),
        _ => json!({"cancelled": true, "question_id": id}),
    };
    let answered_state = if lapsed { "CANCELLED" } else { "ANSWERED" };
    // Owner-authenticated tool result: the owner's words become the parked
    // call's result; the model resumes from this row, never from a guess.
    // run_events.id is BIGINT, so answer_event_id stores the real event row.
    let event_id: i64 = sqlx::query_scalar("INSERT INTO run_events(owner_id,task_id,kind,payload) VALUES($1,$2,'TOOL_RESULT',$3) RETURNING id")
        .bind(scope.owner_id)
        .bind(task_id)
        .bind(json!({"call_id": call_id, "question_id": id, "result": result, "trust": "OWNER_AUTHENTICATED"}))
        .fetch_one(&mut *tx)
        .await?;
    if let Some(cid) = call_id {
        let settled = sqlx::query("UPDATE tool_calls SET state=$4,result=$5,completed_at=now() WHERE owner_id=$1 AND id=$2 AND task_id=$3 AND state='SUBMITTED'")
            .bind(scope.owner_id)
            .bind(cid)
            .bind(task_id)
            .bind(if lapsed { "CANCELLED" } else { "COMPLETED" })
            .bind(&result)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if settled != 1 {
            return Err(Error::Conflict("question call already settled".into()));
        }
    }
    let updated: Value = sqlx::query_scalar("UPDATE agent_questions SET answer=$3,state=$4,answered_at=now(),answer_event_id=$5,revision=revision+1 WHERE owner_id=$1 AND id=$2 AND state='OPEN' RETURNING jsonb_build_object('id',id,'task_id',task_id,'agent_id',agent_id,'call_id',call_id,'question',question,'options',options,'answer',answer,'state',state,'created_at',created_at,'answered_at',answered_at)")
        .bind(scope.owner_id).bind(id).bind(answer.as_deref()).bind(answered_state).bind(event_id).fetch_optional(&mut *tx).await?
        .ok_or(Error::Conflict("question is no longer open".into()))?;
    // Re-queue the parked run at RESULT/CONTEXT: RESULT drains the settled
    // call row first, then the loop continues to CONTEXT for the next turn.
    // Only a WAITING_FOR_INPUT task resumes; any other state is a conflict.
    if task_state != "WAITING_FOR_INPUT" {
        return Err(Error::Conflict("task is not waiting for owner input".into()));
    }
    let resumed = sqlx::query("UPDATE tasks SET state='QUEUED',revision=revision+1,wait_reason=NULL,checkpoint=checkpoint || jsonb_build_object('phase','RESULT','question_id',$3,'answer_event_id',$4),updated_at=now() WHERE owner_id=$1 AND id=$2 AND revision=$5 AND state='WAITING_FOR_INPUT'")
        .bind(scope.owner_id)
        .bind(task_id)
        .bind(id)
        .bind(event_id)
        .bind(task_revision)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if resumed != 1 {
        return Err(Error::Conflict("task revision changed".into()));
    }
    // Keep the attention badge honest once the owner has replied.
    sqlx::query("UPDATE notifications SET read_at=COALESCE(read_at,now()),acknowledged_at=COALESCE(acknowledged_at,now()) WHERE owner_id=$1 AND task_id=$2")
        .bind(scope.owner_id).bind(task_id).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx, scope, correlation, None, Some(task_id), if cancelled || expired { "AGENT_QUESTION_CANCELLED" } else { "AGENT_QUESTION_ANSWERED" }, "owner settled an agent question", json!({"question_id": id, "call_id": call_id, "answer_event_id": event_id})).await?;
    tx.commit().await?;
    Ok(updated)
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub expected_revision: Option<i64>,
}
#[utoipa::path(post,path="/api/v1/questions/{id}/answer",params(("id"=Uuid,Path)),request_body=AnswerRequest,responses((status=200,body=Value)))]
pub async fn answer_question(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<AnswerRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if !valid_answer(&input.answer) {
        return Err(Error::Validation("answer must be 1-2000 chars".into()).into());
    }
    let answer = input.answer.trim().to_owned();
    Ok(Json(settle_question(&state.pool, &a.scope, id, input.expected_revision, Some(answer), false).await.map_err(ApiError)?))
}

#[utoipa::path(post,path="/api/v1/questions/{id}/cancel",params(("id"=Uuid,Path)),request_body=CancelRequest,responses((status=200,body=Value)))]
pub async fn cancel_question(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<CancelRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    Ok(Json(settle_question(&state.pool, &a.scope, id, input.expected_revision, None, true).await.map_err(ApiError)?))
}


#[utoipa::path(get,path="/api/v1/skills",responses((status=200,body=Value)))]
pub async fn list_skills(State(state): State<ApiState>,headers: HeaderMap)->Result<Json<Value>,ApiError>{
 let a=authenticate(&state,&headers,false).await?;
 let items: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'description',description,'enabled',enabled) FROM skills WHERE owner_id=$1 ORDER BY name LIMIT 100").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
 Ok(Json(json!({"items":items})))
}
#[derive(Deserialize,utoipa::ToSchema)] #[serde(deny_unknown_fields)] pub struct SkillToggle {pub enabled: bool}
#[utoipa::path(post,path="/api/v1/skills/{name}/enabled",params(("name"=String,Path)),request_body=SkillToggle,responses((status=200,body=Value)))]
pub async fn set_skill_enabled(State(state): State<ApiState>,headers: HeaderMap,Path(name): Path<String>,Json(input): Json<SkillToggle>)->Result<Json<Value>,ApiError>{
 let a=authenticate(&state,&headers,true).await?;
 let name=name.trim().to_owned();
 if name.is_empty()||name.len()>120{return Err(Error::Validation("skill name must be 1-120 chars".into()).into())}
 let row: Option<Value> = sqlx::query_scalar("UPDATE skills SET enabled=$3,updated_at=now() WHERE owner_id=$1 AND name=$2 RETURNING jsonb_build_object('id',id,'name',name,'description',description,'enabled',enabled)").bind(a.scope.owner_id).bind(&name).bind(input.enabled).fetch_optional(&state.pool).await?;
 Ok(Json(row.ok_or(Error::NotFound)?))
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(get_doc, list_questions, answer_question, cancel_question, list_skills, set_skill_enabled))]
pub struct ControlApi;
pub fn router() -> Router<ApiState> {
 Router::new()
  .route("/api/v1/docs/{page}", get(get_doc))
  .route("/api/v1/questions", get(list_questions))
  .route("/api/v1/questions/{id}/answer", post(answer_question))
  .route("/api/v1/questions/{id}/cancel", post(cancel_question))
  .route("/api/v1/skills", get(list_skills))
  .route("/api/v1/skills/{name}/enabled", post(set_skill_enabled))
}
