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
}

fn valid_answer(v: &str) -> bool {
    let t = v.trim();
    !t.is_empty() && t.len() <= 2000
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
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT task_id,state FROM agent_questions WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let cur: String = row.get("state");
    if cur != "OPEN" {
        return Err(Error::Conflict("question is no longer open".into()).into());
    }
    let task_id: Uuid = row.get("task_id");
    let updated: Value = sqlx::query_scalar("UPDATE agent_questions SET answer=$3,state='ANSWERED',answered_at=now() WHERE owner_id=$1 AND id=$2 RETURNING jsonb_build_object('id',id,'task_id',task_id,'agent_id',agent_id,'question',question,'options',options,'answer',answer,'state',state,'created_at',created_at,'answered_at',answered_at)")
        .bind(a.scope.owner_id).bind(id).bind(&answer).fetch_one(&mut *tx).await?;
    sqlx::query("UPDATE notifications SET read_at=COALESCE(read_at,now()),acknowledged_at=COALESCE(acknowledged_at,now()) WHERE owner_id=$1 AND task_id=$2")
        .bind(a.scope.owner_id).bind(task_id).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx, &a.scope, Uuid::new_v4(), None, Some(task_id), "AGENT_QUESTION_ANSWERED", "owner answered an agent question", json!({"question_id": id})).await?;
    tx.commit().await?;
    Ok(Json(updated))
}

#[utoipa::path(post,path="/api/v1/questions/{id}/cancel",params(("id"=Uuid,Path)),responses((status=200,body=Value)))]
pub async fn cancel_question(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT task_id,state FROM agent_questions WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let cur: String = row.get("state");
    if cur != "OPEN" {
        return Err(Error::Conflict("question is no longer open".into()).into());
    }
    let task_id: Uuid = row.get("task_id");
    let updated: Value = sqlx::query_scalar("UPDATE agent_questions SET state='CANCELLED',answered_at=now() WHERE owner_id=$1 AND id=$2 RETURNING jsonb_build_object('id',id,'task_id',task_id,'agent_id',agent_id,'question',question,'options',options,'answer',answer,'state',state,'created_at',created_at,'answered_at',answered_at)")
        .bind(a.scope.owner_id).bind(id).fetch_one(&mut *tx).await?;
    sqlx::query("UPDATE notifications SET read_at=COALESCE(read_at,now()),acknowledged_at=COALESCE(acknowledged_at,now()) WHERE owner_id=$1 AND task_id=$2")
        .bind(a.scope.owner_id).bind(task_id).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx, &a.scope, Uuid::new_v4(), None, Some(task_id), "AGENT_QUESTION_CANCELLED", "owner cancelled an agent question", json!({"question_id": id})).await?;
    tx.commit().await?;
    Ok(Json(updated))
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
