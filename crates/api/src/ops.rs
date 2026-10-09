use crate::{ApiError,ApiState,auth,authenticate};
use axum::{Json,Router,extract::State,http::HeaderMap,routing::{get,post}};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value,json};
use uuid::Uuid;
/// Owner-scoped tables covered by encrypted backup/restore. The audit trail is
/// intentionally excluded: audit_events is append-only evidence, never rewritten.
/// Ephemeral worker state (event_deliveries, leases) is excluded; the worker
/// recreates deliveries for newly published events.
const BACKUP_TABLES:[&str;4]=["events","tasks","automations","memory_records"];
/// Secrets-store plaintext ceiling is 64 KiB; chunks stay under it.
const BACKUP_CHUNK:usize=60_000;
/// Kill-switch flag lives in a per-owner sentinel file under artifact_dir — no
/// schema change. Presence means frozen.
fn frozen_path(state:&ApiState,owner:Uuid)->std::path::PathBuf{state.artifact_dir.join(format!("ops-frozen-{owner}"))}
pub async fn is_frozen(state:&ApiState,owner:Uuid)->bool{tokio::fs::try_exists(frozen_path(state,owner)).await.unwrap_or(false)}
/// Central read-only guard: mutation routes that authenticate through
/// [`authenticate`] reject with 403 while the owner's kill switch is engaged.
/// Ops kill/resume call `auth::authenticate` directly so resume can always lift
/// the freeze; reads (`mutation=false`) never consult the flag, so the approvals
/// inbox stays readable while frozen. Known gap: marketplace/mcp import
/// `auth::authenticate` directly and bypass this guard (documented in docs/OPS.md).
pub async fn guard(state:&ApiState,headers:&HeaderMap,mutation:bool)->Result<crate::AuthSession,ApiError>{
 let session=auth::authenticate(state,headers,mutation).await?;
 if mutation&&is_frozen(state,session.scope.owner_id).await{return Err(Error::Forbidden.into())}
 Ok(session)
}
#[utoipa::path(post,path="/api/v1/ops/kill",responses((status=200,body=Value)))]
pub async fn kill(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
 let a=auth::authenticate(&state,&headers,true).await?;
 let mut tx=state.pool.begin().await?;
 sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"OPS_FROZEN","owner engaged read-only kill switch",json!({})).await?;
 tx.commit().await?;
 tokio::fs::create_dir_all(&state.artifact_dir).await.map_err(|_|Error::Unavailable("artifact directory unavailable".into()))?;
 tokio::fs::write(frozen_path(&state,a.scope.owner_id),b"frozen").await.map_err(|_|Error::Unavailable("kill-switch flag unwritable".into()))?;
 Ok(Json(json!({"frozen":true})))
}
#[utoipa::path(post,path="/api/v1/ops/resume",responses((status=200,body=Value)))]
pub async fn resume(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
 let a=auth::authenticate(&state,&headers,true).await?;
 let mut tx=state.pool.begin().await?;
 sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"OPS_RESUMED","owner lifted read-only kill switch",json!({})).await?;
 tx.commit().await?;
 match tokio::fs::remove_file(frozen_path(&state,a.scope.owner_id)).await{Ok(())|Err(_)=>{}}
 Ok(Json(json!({"frozen":false})))
}
#[utoipa::path(get,path="/api/v1/ops/status",responses((status=200,body=Value)))]
pub async fn status(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
 let a=auth::authenticate(&state,&headers,false).await?;
 Ok(Json(json!({"frozen":is_frozen(&state,a.scope.owner_id).await})))
}
/// Encrypted backup with no schema change: the owner dump is chunked into
/// `ops-backup` secrets and a small `ops-backup-manifest` secret holds the chunk
/// ids. The returned artifact id IS the manifest secret id, so restore needs no
/// registry table — the secrets store already scopes every row by owner.
#[utoipa::path(post,path="/api/v1/ops/backup",responses((status=200,body=Value)))]
pub async fn backup(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
 // Read-scoped auth: backup exports user data without mutating it, so operators
 // can snapshot a frozen installation.
 let a=auth::authenticate(&state,&headers,false).await?;
 let mut dump=serde_json::Map::new();let mut counts=serde_json::Map::new();
 for table in BACKUP_TABLES{
  let rows:Vec<Value>=sqlx::query_scalar(&format!("SELECT to_jsonb(t) FROM {table} t WHERE owner_id=$1 ORDER BY id")).bind(a.scope.owner_id).fetch_all(&state.pool).await?;
  counts.insert(table.into(),json!(rows.len()));dump.insert(table.into(),Value::Array(rows));
 }
 let bytes=serde_json::to_vec(&Value::Object(dump)).map_err(Error::from)?;
 let store=orbit_secrets::SecretStore::open(state.pool.clone(),&state.key_dir).await?;
 let mut chunk_ids=Vec::new();
 for chunk in bytes.chunks(BACKUP_CHUNK){chunk_ids.push(store.put(&a.scope,"ops-backup",chunk).await?)}
 let manifest=json!({"chunks":chunk_ids,"byte_size":bytes.len() as i64,"tables":counts});
 let artifact=store.put(&a.scope,"ops-backup-manifest",&serde_json::to_vec(&manifest).map_err(Error::from)?).await?;
 Ok(Json(json!({"artifact_id":artifact,"byte_size":bytes.len() as i64,"chunks":chunk_ids.len(),"tables":counts})))
}
#[derive(Deserialize,utoipa::ToSchema)] #[serde(deny_unknown_fields)]
pub struct RestoreRequest{pub artifact_id:Uuid}
#[utoipa::path(post,path="/api/v1/ops/restore",request_body=RestoreRequest,responses((status=200,body=Value)))]
pub async fn restore(State(state):State<ApiState>,headers:HeaderMap,Json(input):Json<RestoreRequest>)->Result<Json<Value>,ApiError>{
 // Full mutation auth: restore rewrites user tables, so the kill switch blocks it.
 let a=authenticate(&state,&headers,true).await?;
 let store=orbit_secrets::SecretStore::open(state.pool.clone(),&state.key_dir).await?;
 let manifest_raw=store.get(&a.scope,input.artifact_id).await?;
 let manifest:Value=serde_json::from_slice(&manifest_raw).map_err(|_|Error::Validation("backup artifact unreadable".into()))?;
 let chunk_ids:Vec<Uuid>=serde_json::from_value(manifest.get("chunks").cloned().unwrap_or(Value::Null)).map_err(|_|Error::Validation("backup artifact unreadable".into()))?;
 let mut bytes=Vec::new();
 for cid in &chunk_ids{bytes.extend(store.get(&a.scope,*cid).await?.as_slice())}
 let dump:Value=serde_json::from_slice(&bytes).map_err(|_|Error::Validation("backup artifact unreadable".into()))?;
 let mut tx=state.pool.begin().await?;
 sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 // Dependency order: events before tasks (tasks.event_id references events).
 for table in BACKUP_TABLES{
  let rows=dump.get(table).and_then(Value::as_array).cloned().unwrap_or_default();
  let ids:Vec<Uuid>=rows.iter().filter_map(|r|r.get("id").and_then(Value::as_str)).filter_map(|s|Uuid::parse_str(s).ok()).collect();
  if ids.is_empty(){continue}
  sqlx::query(&format!("INSERT INTO {table} SELECT * FROM jsonb_populate_recordset(NULL::{table},$1) ON CONFLICT DO NOTHING")).bind(Value::Array(rows)).execute(&mut *tx).await?;
  // Owner-scoped apply: every restored row belongs to the caller even if the
  // artifact blob were swapped between owners.
  sqlx::query(&format!("UPDATE {table} SET owner_id=$1 WHERE id=ANY($2)")).bind(a.scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 }
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"OPS_RESTORED","owner restored encrypted backup",json!({"artifact_id":input.artifact_id})).await?;
 tx.commit().await?;Ok(Json(json!({"restored":input.artifact_id})))
}
/// Side-effect-free dry run: the scheduler preview (next run + coalesced
/// missed windows; inserts nothing) plus the trigger/action summary the fired
/// window WOULD dispatch to — consumer, task title and checkpoint — computed
/// with the same rule as dispatch, never executed.
#[utoipa::path(post,path="/api/v1/automations/{id}/dry-run",responses((status=200,body=Value)))]
pub async fn dry_run(State(state):State<ApiState>,headers:HeaderMap,axum::extract::Path(id):axum::extract::Path<Uuid>)->Result<Json<Value>,ApiError>{
 // Direct auth: dry-run changes nothing, so it stays available while frozen.
 let a=auth::authenticate(&state,&headers,true).await?;
 let automation=orbit_scheduler::get(&state.pool,&a.scope,id).await?;
 let preview=orbit_scheduler::preview(&state.pool,&a.scope,id).await?;
 let consumer=if automation.notification_behavior=="IN_APP"&&automation.agent_id.is_none(){"foundation"}else{"agents"};
 Ok(Json(json!({"automation_id":id,"enabled":automation.enabled,"trigger":automation.trigger,"filters":automation.filters,"agent_id":automation.agent_id,"instructions":automation.instructions,"policy_scope":automation.policy_scope,"model_role":automation.model_role,"notification_behavior":automation.notification_behavior,"preview":preview,"would_dispatch":{"consumer":consumer,"task_title":format!("Automation {id}"),"checkpoint_phase":if consumer=="foundation"{"NOTIFICATION"}else{"CONTEXT"}}})))
}
#[derive(utoipa::OpenApi)] #[openapi(paths(kill,resume,status,backup,restore,dry_run),components(schemas(RestoreRequest)))]
pub struct OpsApi;
pub fn router()->Router<ApiState>{Router::new().route("/api/v1/ops/kill",post(kill)).route("/api/v1/ops/resume",post(resume)).route("/api/v1/ops/status",get(status)).route("/api/v1/ops/backup",post(backup)).route("/api/v1/ops/restore",post(restore)).route("/api/v1/automations/{id}/dry-run",post(dry_run))}
