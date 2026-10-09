use crate::{ApiError,ApiState,auth};
use axum::{Json,Router,extract::State,http::HeaderMap,routing::get};
use serde_json::{Value,json};
/// Morning brief: one read-scoped aggregation over tables that already exist.
/// Pending approvals (action needed), unread notifications, open tasks, recent
/// events, due-soon automations, unread mail. No new tables, no writes, no
/// model calls — every section links to the page that owns the action.
#[utoipa::path(get,path="/api/v1/brief",responses((status=200,body=Value)))]
pub async fn brief(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
 let a=auth::authenticate(&state,&headers,false).await?;let o=a.scope.owner_id;
 let approvals:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(a)-'owner_id' FROM approvals a WHERE owner_id=$1 AND state='PENDING' ORDER BY created_at DESC,id DESC LIMIT 10").bind(o).fetch_all(&state.pool).await?;
 let notifications:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM notifications t WHERE owner_id=$1 AND read_at IS NULL AND dismissed_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 10").bind(o).fetch_all(&state.pool).await?;
 let tasks:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM tasks t WHERE owner_id=$1 AND state IN ('QUEUED','RUNNING','WAITING_FOR_APPROVAL','WAITING_FOR_RESOURCE') ORDER BY created_at DESC,id DESC LIMIT 10").bind(o).fetch_all(&state.pool).await?;
 let events:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM events t WHERE owner_id=$1 ORDER BY timestamp DESC,id DESC LIMIT 10").bind(o).fetch_all(&state.pool).await?;
 let automations:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM automations t WHERE owner_id=$1 AND enabled ORDER BY next_run NULLS LAST,id DESC LIMIT 10").bind(o).fetch_all(&state.pool).await?;
 let mail:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'account_id',account_id,'metadata',metadata,'received_at',received_at) FROM email_messages WHERE owner_id=$1 ORDER BY received_at DESC,id DESC LIMIT 5").bind(o).fetch_all(&state.pool).await?;
 Ok(Json(json!({"generated_at":chrono::Utc::now(),"approvals_pending":approvals.len(),"notifications_unread":notifications.len(),"tasks_open":tasks.len(),"approvals":approvals,"notifications":notifications,"tasks":tasks,"recent_events":events,"automations_enabled":automations,"recent_mail":mail})))
}
#[derive(utoipa::OpenApi)] #[openapi(paths(brief))] pub struct BriefApi;
pub fn router()->Router<ApiState>{Router::new().route("/api/v1/brief",get(brief))}
