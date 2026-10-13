use crate::{ApiState,ApiError,authenticate};
use axum::{extract::{State,Path,Query},http::HeaderMap,response::sse::{Sse,Event as SseEvent,KeepAlive},routing::{get,post},Json,Router};
use orbit_core::{Error,Event,EventType,PrivacyClass,TrustLevel,AutonomyMode};
use orbit_event_bus::{EventBus,PostgresEventBus};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use sqlx::Row;
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Deserialize,ToSchema)] #[serde(deny_unknown_fields)]
pub struct PublishRequest {pub event_type:EventType,pub payload:Value,pub source_event_key:String,pub privacy_class:Option<PrivacyClass>}
#[derive(Serialize,ToSchema)] pub struct PublishResponse {pub id:Uuid}
#[derive(Deserialize)] pub struct Page {pub cursor:Option<i64>,pub limit:Option<i64>,pub correlation_id:Option<Uuid>}
#[derive(Serialize,ToSchema)] pub struct ListResponse {pub items:Vec<Value>,pub next_cursor:Option<i64>}
#[derive(Serialize,Deserialize,ToSchema)] #[serde(deny_unknown_fields)] pub struct Settings {pub installation_mode:String,pub autonomy_mode:AutonomyMode,pub allow_private_cloud:bool,pub agent_backend:String,#[serde(default)] pub inbox_enabled:bool,#[serde(default)] pub sandbox_enabled:bool,#[serde(default)] pub agent_may_change_settings:bool,#[serde(default)] pub agent_may_manage_mcp:bool,pub revision:i64}
#[derive(Deserialize,ToSchema)] #[serde(deny_unknown_fields)] pub struct SettingsUpdate {pub installation_mode:String,pub autonomy_mode:AutonomyMode,pub allow_private_cloud:bool,pub agent_backend:String,#[serde(default)] pub inbox_enabled:bool,#[serde(default)] pub sandbox_enabled:bool,#[serde(default)] pub agent_may_change_settings:bool,#[serde(default)] pub agent_may_manage_mcp:bool,pub expected_revision:i64}
#[derive(Deserialize,ToSchema)] #[serde(deny_unknown_fields)] pub struct RecoveryRequest {pub expected_revision:i64}
#[derive(Deserialize,ToSchema)] #[serde(deny_unknown_fields)] pub struct ReconcileRequest {pub call_id:Uuid,pub expected_revision:i64,pub resolution:String,pub evidence_reference:String}
#[derive(Serialize,ToSchema)] pub struct TaskDetail {pub id:Uuid,pub title:String,pub state:String,pub revision:i64,pub fence:i64,pub event_id:Option<Uuid>,pub correlation_id:Uuid,pub checkpoint:Value,pub wait_reason:Option<String>,pub unresolved_call_ids:Value,pub evidence:Value,pub allowed_recovery_actions:Vec<String>,pub retry_of:Option<Uuid>,pub created_at:chrono::DateTime<chrono::Utc>,pub expires_at:chrono::DateTime<chrono::Utc>}
#[utoipa::path(get,path="/health",responses((status=200,body=Value)))]
pub async fn health()->Json<Value>{Json(json!({"status":"ok"}))}
#[utoipa::path(get,path="/ready",responses((status=200,body=Value),(status=503,description="Dependency unavailable")))]
pub async fn ready(State(state):State<ApiState>)->Result<Json<Value>,ApiError>{sqlx::query("SELECT singleton FROM installation WHERE singleton").fetch_one(&state.pool).await.map_err(|_|Error::Unavailable("database unavailable".into()))?;Ok(Json(json!({"status":"ok"})))}
#[utoipa::path(get,path="/api/v1/settings",responses((status=200,body=Settings)))]
pub async fn settings(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Settings>,ApiError>{let a=authenticate(&state,&headers,false).await?;let row=sqlx::query("SELECT value,revision FROM settings WHERE owner_id=$1").bind(a.scope.owner_id).fetch_one(&state.pool).await?;let mut v:Value=row.get("value");v["revision"]=json!(row.get::<i64,_>("revision"));Ok(Json(serde_json::from_value(v).map_err(Error::from)?))}
#[utoipa::path(put,path="/api/v1/settings",request_body=SettingsUpdate,responses((status=200,body=Settings)))]
pub async fn update_settings(State(state):State<ApiState>,headers:HeaderMap,Json(input):Json<SettingsUpdate>)->Result<Json<Settings>,ApiError>{
 let a=authenticate(&state,&headers,true).await?;if !matches!(input.installation_mode.as_str(),"LOCAL_ONLY"|"HYBRID"|"CLOUD_ONLY"){return Err(Error::Validation("unknown installation mode".into()).into())}
 orbit_agent_backend::BackendKind::parse(&input.agent_backend).map_err(|e| -> ApiError { e.into() })?;
 let mut tx=state.pool.begin().await?;sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 let value=json!({"installation_mode":input.installation_mode,"autonomy_mode":input.autonomy_mode,"allow_private_cloud":input.allow_private_cloud,"agent_backend":input.agent_backend,"inbox_enabled":input.inbox_enabled,"sandbox_enabled":input.sandbox_enabled,"agent_may_change_settings":input.agent_may_change_settings,"agent_may_manage_mcp":input.agent_may_manage_mcp});
 let revision:Option<i64>=sqlx::query_scalar("UPDATE settings SET value=$2,revision=revision+1 WHERE owner_id=$1 AND revision=$3 RETURNING revision").bind(a.scope.owner_id).bind(&value).bind(input.expected_revision).fetch_optional(&mut *tx).await?;
 let revision=revision.ok_or(Error::Conflict("settings revision changed".into()))?;
 sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(a.scope.owner_id).execute(&mut *tx).await?;
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"SETTINGS_UPDATED","owner updated settings",json!({"revision":revision})).await?;tx.commit().await?;
 Ok(Json(Settings{installation_mode:input.installation_mode,autonomy_mode:input.autonomy_mode,allow_private_cloud:input.allow_private_cloud,agent_backend:input.agent_backend,inbox_enabled:input.inbox_enabled,sandbox_enabled:input.sandbox_enabled,agent_may_change_settings:input.agent_may_change_settings,agent_may_manage_mcp:input.agent_may_manage_mcp,revision}))
}
#[utoipa::path(post,path="/api/v1/events",request_body=PublishRequest,responses((status=200,body=PublishResponse)))]
pub async fn publish(State(state):State<ApiState>,headers:HeaderMap,Json(input):Json<PublishRequest>)->Result<Json<PublishResponse>,ApiError>{
 let a=authenticate(&state,&headers,true).await?;if input.source_event_key.is_empty()||input.source_event_key.len()>256{return Err(Error::Validation("source event key required, maximum 256 characters".into()).into())}
 // The web transport is owner authenticated; payload never supplies authoritative identity.
 let e=Event{id:Uuid::new_v4(),owner_id:a.scope.owner_id,event_type:input.event_type,source:"web".into(),principal_id:a.scope.principal_id,timestamp:chrono::Utc::now(),payload:input.payload,trust_level:TrustLevel::OwnerAuthenticated,privacy_class:input.privacy_class.unwrap_or(PrivacyClass::Private),correlation_id:Uuid::new_v4(),related_entities:vec![],source_event_key:input.source_event_key};
 let id=PostgresEventBus{pool:state.pool}.publish(&a.scope,e).await?;Ok(Json(PublishResponse{id}))
}
async fn list_table(state:&ApiState,headers:&HeaderMap,page:Page,table:&str,order:&str)->Result<Json<ListResponse>,ApiError>{
 let a=authenticate(state,headers,false).await?;let limit=page.limit.unwrap_or(30).clamp(1,100);let offset=page.cursor.unwrap_or(0);if offset<0{return Err(Error::Validation("invalid cursor".into()).into())}
 let query=format!("SELECT to_jsonb(t)-'owner_id' AS record FROM {table} t WHERE owner_id=$1 AND ($2::uuid IS NULL OR correlation_id=$2) ORDER BY {order} LIMIT $3 OFFSET $4");
 let mut items:Vec<Value>=sqlx::query_scalar(&query).bind(a.scope.owner_id).bind(page.correlation_id).bind(limit+1).bind(offset).fetch_all(&state.pool).await?;let next=if items.len()>limit as usize{items.pop();Some(offset+limit)}else{None};Ok(Json(ListResponse{items,next_cursor:next}))
}
#[utoipa::path(get,path="/api/v1/events",responses((status=200,body=ListResponse)))] pub async fn events(State(s):State<ApiState>,h:HeaderMap,Query(p):Query<Page>)->Result<Json<ListResponse>,ApiError>{list_table(&s,&h,p,"events","timestamp DESC,id DESC").await}
#[utoipa::path(get,path="/api/v1/tasks",responses((status=200,body=ListResponse)))] pub async fn tasks(State(s):State<ApiState>,h:HeaderMap,Query(p):Query<Page>)->Result<Json<ListResponse>,ApiError>{list_table(&s,&h,p,"tasks","created_at DESC,id DESC").await}
#[utoipa::path(get,path="/api/v1/activity",responses((status=200,body=ListResponse)))] pub async fn activity(State(s):State<ApiState>,h:HeaderMap,Query(p):Query<Page>)->Result<Json<ListResponse>,ApiError>{list_table(&s,&h,p,"audit_events","sequence DESC").await}
#[utoipa::path(get,path="/api/v1/notifications",responses((status=200,body=ListResponse)))] pub async fn notifications(State(s):State<ApiState>,h:HeaderMap,Query(p):Query<Page>)->Result<Json<ListResponse>,ApiError>{list_table(&s,&h,p,"notifications","created_at DESC,id DESC").await}
async fn detail(state:ApiState,headers:HeaderMap,id:Uuid,table:&str)->Result<Json<Value>,ApiError>{let a=authenticate(&state,&headers,false).await?;let q=format!("SELECT to_jsonb(t)-'owner_id' FROM {table} t WHERE owner_id=$1 AND id=$2");Ok(Json(sqlx::query_scalar(&q).bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?))}
#[utoipa::path(get,path="/api/v1/events/{id}",params(("id"=Uuid,Path)),responses((status=200,body=Value)))] pub async fn event_detail(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{detail(s,h,id,"events").await}
#[utoipa::path(get,path="/api/v1/activity/{id}",params(("id"=Uuid,Path)),responses((status=200,body=Value)))] pub async fn activity_detail(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{detail(s,h,id,"audit_events").await}
#[utoipa::path(get,path="/api/v1/notifications/{id}",params(("id"=Uuid,Path)),responses((status=200,body=Value)))] pub async fn notification_detail(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{detail(s,h,id,"notifications").await}
#[derive(Serialize, ToSchema)] pub struct TaskRunItem {pub task_id: Uuid,pub phase: String,pub model_calls: i32,pub model_retries: i32,pub turn: i32,pub depth: i32,pub tool_calls: i32,pub tokens: i64,pub sources: Vec<Value>}
#[derive(Serialize, ToSchema)] pub struct TaskRuns {pub items: Vec<TaskRunItem>}
 #[utoipa::path(get,path="/api/v1/tasks/{id}",params(("id"=Uuid,Path)),responses((status=200,body=TaskDetail)))]
 pub async fn task_detail(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{
  let Json(mut v)=detail(s,h,id,"tasks").await?;let state=v["state"].as_str().unwrap_or("");let clear=v["unresolved_call_ids"].as_array().is_some_and(Vec::is_empty);let mut actions=vec![];
  if matches!(state,"QUEUED"|"RUNNING"|"WAITING_FOR_APPROVAL"|"WAITING_FOR_RESOURCE"){actions.push("CANCEL")}
  if !clear {actions.push("RECONCILE")} else if matches!(state,"FAILED"|"TIMED_OUT"|"CANCELLED"){actions.push("RETRY")} else if state=="WAITING_FOR_RESOURCE"&&v["consumer"]=="foundation"{actions.push("RESUME")}
  v["allowed_recovery_actions"]=json!(actions);Ok(Json(v))
 }
/// Live subagent view: the run row for this task plus sibling runs sharing
/// the same correlation id (subagent tasks, when present). Owner-scoped;
/// depth falls back to the task checkpoint JSON when no subagent table row
/// exists. Empty items when no agent run was recorded (foundation tasks).
/// Sources read `model_context_sources` receipts (one row per CONTEXT block
/// per turn), never the live `agent_runs.context` JSON. Labels read
/// "Provided as context" unless the run's assistant text cites the pin.
#[utoipa::path(get,path="/api/v1/tasks/{id}/runs",params(("id"=Uuid,Path)),responses((status=200,body=TaskRuns)))]
pub async fn task_runs(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<TaskRuns>,ApiError>{
 let a=authenticate(&s,&h,false).await?;
 let correlation:Option<Uuid>=sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&s.pool).await?.ok_or(Error::NotFound)?;
 let correlation=correlation.ok_or(Error::NotFound)?;
 let rows=sqlx::query("SELECT r.task_id,r.phase,r.model_calls,r.model_retries,r.turn,r.depth,r.tool_calls,r.tokens,t.checkpoint FROM agent_runs r JOIN tasks t ON t.owner_id=r.owner_id AND t.id=r.task_id WHERE r.owner_id=$1 AND (r.task_id=$2 OR t.correlation_id=$3) ORDER BY r.depth,r.task_id").bind(a.scope.owner_id).bind(id).bind(correlation).fetch_all(&s.pool).await?;
 let mut items=Vec::with_capacity(rows.len());
 for r in &rows{
  let checkpoint:Value=r.get("checkpoint");
  let checkpoint_depth=checkpoint.get("depth").and_then(Value::as_i64).and_then(|d|i32::try_from(d).ok()).unwrap_or_else(||r.get("depth"));
  let task:Uuid=r.get("task_id");
  let receipts=sqlx::query("SELECT source_type,source_id,source_version,locator,trust_level,turn FROM model_context_sources WHERE owner_id=$1 AND task_id=$2 ORDER BY turn,source_type,source_id LIMIT 24").bind(a.scope.owner_id).bind(task).fetch_all(&s.pool).await.unwrap_or_default();
  // Assistant text for this run: a receipt counts as cited when the same-turn
  // reply (turn_key `assistant:{turn}`) names its pin; otherwise the chip
  // reads "Provided as context".
  let replies:Vec<(String,Option<String>)>=sqlx::query("SELECT content,turn_key FROM chat_messages WHERE owner_id=$1 AND task_id=$2 AND role='assistant' ORDER BY sequence LIMIT 24").bind(a.scope.owner_id).bind(task).fetch_all(&s.pool).await.map(|rows|rows.iter().map(|m|(m.get::<String,_>("content"),m.get::<Option<String>,_>("turn_key"))).collect()).unwrap_or_default();
  // Tombstones: deletion never removes receipt rows; the referenced record
  // going missing (or memory FORGOTTEN) surfaces as a deleted pin instead.
  let mem_ids:Vec<Uuid>=receipts.iter().filter(|q|q.get::<String,_>("source_type")=="memory").filter_map(|q|Uuid::parse_str(q.get::<String,_>("source_id").as_str()).ok()).collect();
  let mem_rows=if mem_ids.is_empty(){Vec::new()}else{sqlx::query("SELECT id,version,status FROM memory_records WHERE owner_id=$1 AND id=ANY($2)").bind(a.scope.owner_id).bind(&mem_ids).fetch_all(&s.pool).await.unwrap_or_default()};
  let mut sources=Vec::new();
  for q in receipts.iter().take(12){
   let source_type:String=q.get("source_type");
   let source_id:String=q.get("source_id");
   let source_version:String=q.get("source_version");
   let locator:String=q.get("locator");
   let trust:Value=json!(q.get::<String,_>("trust_level"));
   let cited={
    let pin=format!("assistant:{}",q.get::<i32,_>("turn"));
    replies.iter().any(|(t,k)|k.as_deref()==Some(pin.as_str())&&(t.contains(&source_id)||t.contains(&locator)))
   };
   let tombstone=if source_type=="memory"{
    match mem_rows.iter().find(|m|m.get::<Uuid,_>("id").to_string()==source_id){
     None=>true,
     Some(m)=>m.get::<String,_>("status")=="FORGOTTEN",
    }
   }else{false};
   sources.push(json!({"kind":source_type,"reference":locator,"source_id":source_id,"source_version":source_version,"trust":trust,"turn":q.get::<i32,_>("turn"),"cited":cited,"tombstone":tombstone,"label":if cited {"Cited by model"} else {"Provided as context"}}));
  }
  items.push(TaskRunItem{task_id:task,phase:r.get("phase"),model_calls:r.get("model_calls"),model_retries:r.get("model_retries"),turn:r.get("turn"),depth:checkpoint_depth,tool_calls:r.get("tool_calls"),tokens:r.get("tokens"),sources});
 }
 Ok(Json(TaskRuns{items}))
}
/// Why-timeline: every row sharing one correlation_id — the triggering
/// event, the tasks it spawned, the audit trail, and the notifications the
/// owner saw. One call answers "why did Orbit do that?" without joining
/// four list endpoints. Cap 100 per table; reads are owner-scoped.
#[utoipa::path(get,path="/api/v1/why/{correlation_id}",params(("correlation_id"=Uuid,Path)),responses((status=200,body=Value)))]
pub async fn why_timeline(State(state): State<ApiState>, headers: HeaderMap, Path(correlation): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let events: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM events t WHERE owner_id=$1 AND correlation_id=$2 ORDER BY timestamp,id LIMIT 100").bind(a.scope.owner_id).bind(correlation).fetch_all(&state.pool).await?;
    let tasks: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM tasks t WHERE owner_id=$1 AND correlation_id=$2 ORDER BY created_at,id LIMIT 100").bind(a.scope.owner_id).bind(correlation).fetch_all(&state.pool).await?;
    let activity: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM audit_events t WHERE owner_id=$1 AND correlation_id=$2 ORDER BY sequence LIMIT 100").bind(a.scope.owner_id).bind(correlation).fetch_all(&state.pool).await?;
    let notifications: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM notifications t WHERE owner_id=$1 AND correlation_id=$2 ORDER BY created_at,id LIMIT 100").bind(a.scope.owner_id).bind(correlation).fetch_all(&state.pool).await?;
    if events.is_empty() && tasks.is_empty() && activity.is_empty() && notifications.is_empty() {
        return Err(Error::NotFound.into());
    }
    Ok(Json(json!({"correlation_id": correlation, "events": events, "tasks": tasks, "activity": activity, "notifications": notifications})))
}
async fn notification_mutation(s:ApiState,h:HeaderMap,id:Uuid,column:&str)->Result<Json<Value>,ApiError>{let a=authenticate(&s,&h,true).await?;let q=format!("UPDATE notifications SET {column}=COALESCE({column},now()) WHERE owner_id=$1 AND id=$2 RETURNING to_jsonb(notifications)-'owner_id'");Ok(Json(sqlx::query_scalar(&q).bind(a.scope.owner_id).bind(id).fetch_optional(&s.pool).await?.ok_or(Error::NotFound)?))}
#[utoipa::path(post,path="/api/v1/notifications/{id}/read",params(("id"=Uuid,Path)),responses((status=200,body=Value)))] pub async fn read_notification(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{notification_mutation(s,h,id,"read_at").await}
#[utoipa::path(post,path="/api/v1/notifications/{id}/acknowledge",params(("id"=Uuid,Path)),responses((status=200,body=Value)))] pub async fn acknowledge(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{notification_mutation(s,h,id,"acknowledged_at").await}
#[utoipa::path(post,path="/api/v1/notifications/{id}/dismiss",params(("id"=Uuid,Path)),responses((status=200,body=Value)))] pub async fn dismiss(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>)->Result<Json<Value>,ApiError>{notification_mutation(s,h,id,"dismissed_at").await}
async fn recover(s:ApiState,h:HeaderMap,id:Uuid,input:RecoveryRequest,operation:&str)->Result<Json<Value>,ApiError>{
 let a=authenticate(&s,&h,true).await?;let mut tx=s.pool.begin().await?;sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 let r=sqlx::query("SELECT *,expires_at>now() AS unexpired FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(a.scope.owner_id).bind(id).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
 if r.get::<i64,_>("revision")!=input.expected_revision{return Err(Error::Conflict("task revision changed".into()).into())}let state:String=r.get("state");let unresolved:Value=r.get("unresolved_call_ids");let consumer:String=r.get("consumer");let mut result=id;
 match operation {
 "CANCEL"=>{if matches!(state.as_str(),"COMPLETED"|"FAILED"|"CANCELLED"|"TIMED_OUT"){return Err(Error::Conflict("terminal task cannot cancel".into()).into())}sqlx::query("UPDATE tasks SET state='CANCELLED',revision=revision+1,fence=fence+1,lease_until=NULL,updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&mut *tx).await?;},
 "RESUME"=>{if state!="WAITING_FOR_RESOURCE"||!r.get::<bool,_>("unexpired")||unresolved!=json!([]){return Err(Error::Conflict("task cannot safely resume".into()).into())}if consumer!="foundation"{return Err(Error::Unavailable("dependency/policy recovery requires registered consumer".into()).into())}sqlx::query("UPDATE tasks SET state='QUEUED',revision=revision+1,fence=fence+1,wait_reason=NULL,updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&mut *tx).await?;},
 "RETRY"=>{if !matches!(state.as_str(),"FAILED"|"TIMED_OUT"|"CANCELLED")||unresolved!=json!([]){return Err(Error::Conflict("task cannot retry while effects unresolved".into()).into())}if consumer!="foundation"{return Err(Error::Unavailable("consumer recovery unavailable".into()).into())}result=Uuid::new_v4();sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,title,consumer,retry_of,checkpoint) VALUES($1,$2,$3,$4,$5,'foundation',$6,$7)").bind(result).bind(a.scope.owner_id).bind(a.scope.principal_id).bind(r.get::<Uuid,_>("correlation_id")).bind(r.get::<String,_>("title")).bind(id).bind(json!({"phase":"NOTIFICATION","source_event_id":r.get::<Option<Uuid>,_>("event_id"),"completed_effect_references":[id]})).execute(&mut *tx).await?;},_=>unreachable!()}
 orbit_audit::append(&mut tx,&a.scope,r.get("correlation_id"),r.get("event_id"),Some(id),&format!("TASK_{operation}"),"owner recovery",json!({"linked_task_id":result})).await?;
 if operation=="CANCEL"{orbit_event_bus::terminal_event(&mut tx,&a.scope,id,r.get("correlation_id"),orbit_core::TaskState::Cancelled).await?;}
 tx.commit().await?;Ok(Json(json!({"id":result})))
}
#[utoipa::path(post,path="/api/v1/tasks/{id}/cancel",params(("id"=Uuid,Path)),request_body=RecoveryRequest,responses((status=200,body=Value)))] pub async fn cancel(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>,Json(i):Json<RecoveryRequest>)->Result<Json<Value>,ApiError>{recover(s,h,id,i,"CANCEL").await}
#[utoipa::path(post,path="/api/v1/tasks/{id}/resume",params(("id"=Uuid,Path)),request_body=RecoveryRequest,responses((status=200,body=Value)))] pub async fn resume(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>,Json(i):Json<RecoveryRequest>)->Result<Json<Value>,ApiError>{recover(s,h,id,i,"RESUME").await}
#[utoipa::path(post,path="/api/v1/tasks/{id}/retry",params(("id"=Uuid,Path)),request_body=RecoveryRequest,responses((status=200,body=Value)))] pub async fn retry(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>,Json(i):Json<RecoveryRequest>)->Result<Json<Value>,ApiError>{recover(s,h,id,i,"RETRY").await}
#[utoipa::path(post,path="/api/v1/tasks/{id}/reconcile",params(("id"=Uuid,Path)),request_body=ReconcileRequest,responses((status=200,body=Value)))] pub async fn reconcile(State(s):State<ApiState>,h:HeaderMap,Path(id):Path<Uuid>,Json(_i):Json<ReconcileRequest>)->Result<Json<Value>,ApiError>{let _=detail(s.clone(),h.clone(),id,"tasks").await?;authenticate(&s,&h,true).await?;Err(Error::Conflict("notification tasks have no uncertain external calls".into()).into())}
#[utoipa::path(get,path="/api/v1/stream",responses((status=200,description="Durable SSE activity; Last-Event-ID resumes audit sequence")))]
pub async fn stream(State(state):State<ApiState>,headers:HeaderMap)->Result<Sse<impl futures_util::Stream<Item=Result<SseEvent,std::convert::Infallible>>>,ApiError>{
 let a=authenticate(&state,&headers,false).await?;let mut cursor=match headers.get("last-event-id"){Some(v)=>v.to_str().ok().and_then(|s|s.parse::<i64>().ok()).filter(|n|*n>=0).ok_or(Error::Validation("invalid Last-Event-ID".into()))?,None=>0};
 let stream=async_stream::stream!{loop{
 let valid=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM sessions WHERE owner_id=$1 AND id=$2 AND expires_at>now())").bind(a.scope.owner_id).bind(a.session_id).fetch_one(&state.pool).await;
 if !matches!(valid,Ok(true)){break}
 match sqlx::query("SELECT sequence,to_jsonb(a)-'owner_id' AS record FROM audit_events a WHERE owner_id=$1 AND sequence>$2 ORDER BY sequence LIMIT 100").bind(a.scope.owner_id).bind(cursor).fetch_all(&state.pool).await {Ok(rows)=>{let empty=rows.is_empty();for r in rows{cursor=r.get("sequence");let v:Value=r.get("record");yield Ok(SseEvent::default().id(cursor.to_string()).event("activity").data(v.to_string()));}if !empty{continue}},Err(_)=>break}
 tokio::time::sleep(std::time::Duration::from_millis(500)).await;
 }};Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(health,ready,settings,update_settings,publish,events,tasks,activity,notifications,event_detail,task_detail,task_runs,activity_detail,notification_detail,why_timeline,read_notification,acknowledge,dismiss,cancel,resume,retry,reconcile,stream,crate::auth::setup,crate::auth::login,crate::auth::current,crate::auth::logout),components(schemas(PublishRequest,PublishResponse,Settings,SettingsUpdate,TaskDetail,TaskRunItem,TaskRuns,ListResponse,RecoveryRequest,ReconcileRequest,crate::auth::SetupRequest,crate::auth::LoginRequest,crate::auth::User,crate::auth::SessionResponse,orbit_core::Event,orbit_core::PrivacyClass,orbit_core::EventType,orbit_core::TaskState)))]
pub struct OpenApi;
pub async fn openapi()->Json<Value>{use utoipa::OpenApi as _;Json(serde_json::to_value(OpenApi::openapi()).expect("OpenAPI serializes"))}
pub fn router()->Router<ApiState>{Router::new().route("/health",get(health)).route("/ready",get(ready)).route("/api/v1/openapi.json",get(openapi)).route("/api/v1/settings",get(settings).put(update_settings)).route("/api/v1/events",get(events).post(publish)).route("/api/v1/events/{id}",get(event_detail)).route("/api/v1/tasks",get(tasks)).route("/api/v1/tasks/{id}",get(task_detail)).route("/api/v1/tasks/{id}/runs",get(task_runs)).route("/api/v1/tasks/{id}/cancel",post(cancel)).route("/api/v1/tasks/{id}/resume",post(resume)).route("/api/v1/tasks/{id}/retry",post(retry)).route("/api/v1/tasks/{id}/reconcile",post(reconcile)).route("/api/v1/activity",get(activity)).route("/api/v1/activity/{id}",get(activity_detail)).route("/api/v1/notifications",get(notifications)).route("/api/v1/notifications/{id}",get(notification_detail)).route("/api/v1/notifications/{id}/read",post(read_notification)).route("/api/v1/notifications/{id}/acknowledge",post(acknowledge)).route("/api/v1/notifications/{id}/dismiss",post(dismiss)).route("/api/v1/stream",get(stream)).route("/api/v1/why/{correlation_id}",get(why_timeline))}
