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
/// inbox stays readable while frozen. Every mutation router (marketplace, mcp
/// included) goes through this guard — no documented bypass remains.
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
 // Mutation-scoped guard: backup WRITES secrets (chunks+manifest), so a
 // frozen installation blocks it like every other mutation.
 let a=guard(&state,&headers,true).await?;
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
 let mut tx=state.pool.begin().await?;
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"OPS_BACKUP","owner snapshotted encrypted backup",json!({"artifact_id":artifact})).await?;
 tx.commit().await?;
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
  if rows.is_empty(){continue}
  // Stamp owner pre-insert: rows keep their ids but always belong to the
  // caller, so ON CONFLICT DO NOTHING skips rows owned by others instead of
  // reassigning them.
  let owned:Vec<Value>=rows.into_iter().map(|mut r|{if let Some(o)=r.as_object_mut(){o.insert("owner_id".into(),json!(a.scope.owner_id));}r}).collect();
  sqlx::query(&format!("INSERT INTO {table} SELECT * FROM jsonb_populate_recordset(NULL::{table},$1) ON CONFLICT DO NOTHING")).bind(Value::Array(owned)).execute(&mut *tx).await?;
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
 // Read-scoped guard: the preview inserts nothing, so it stays available
 // while frozen (freeze-transparent by design).
 let a=guard(&state,&headers,false).await?;
 let automation=orbit_scheduler::get(&state.pool,&a.scope,id).await?;
 let preview=orbit_scheduler::preview(&state.pool,&a.scope,id).await?;
 let consumer=if automation.notification_behavior=="IN_APP"&&automation.agent_id.is_none(){"foundation"}else{"agents"};
 Ok(Json(json!({"automation_id":id,"enabled":automation.enabled,"trigger":automation.trigger,"filters":automation.filters,"agent_id":automation.agent_id,"instructions":automation.instructions,"policy_scope":automation.policy_scope,"model_role":automation.model_role,"notification_behavior":automation.notification_behavior,"preview":preview,"would_dispatch":{"consumer":consumer,"task_title":format!("Automation {id}"),"checkpoint_phase":if consumer=="foundation"{"NOTIFICATION"}else{"CONTEXT"}}})))
}
/// Pause everything, nodes included: kill-switch freeze (sentinel file) PLUS
/// revoking every live computer node and its roots. Kill alone stops the hub
/// from dispatching; this also drops node session credentials so a
/// compromised node cannot keep pushing files or tool results until the owner
/// re-enrolls it. Reads stay available; `resume` lifts the freeze but revoked
/// nodes stay revoked until individually re-enrolled.
#[utoipa::path(post,path="/api/v1/ops/revoke-nodes",responses((status=200,body=Value)))]
pub async fn revoke_nodes(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<Value>,ApiError>{
 let a=auth::authenticate(&state,&headers,true).await?;
 let mut tx=state.pool.begin().await?;
 sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 let nodes: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM computer_nodes WHERE owner_id=$1 AND revoked_at IS NULL").bind(a.scope.owner_id).fetch_all(&mut *tx).await?;
 sqlx::query("UPDATE computer_nodes SET revoked_at=now(),revision=revision+1,connection_id=NULL WHERE owner_id=$1 AND revoked_at IS NULL").bind(a.scope.owner_id).execute(&mut *tx).await?;
 sqlx::query("UPDATE computer_roots SET revoked=true,revision=revision+1 WHERE owner_id=$1 AND NOT revoked").bind(a.scope.owner_id).execute(&mut *tx).await?;
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"OPS_NODES_REVOKED","owner revoked all computer nodes alongside kill switch",json!({"revoked": nodes.len()})).await?;
 tx.commit().await?;
 for id in &nodes { state.nodes.evict(*id).await; }
 Ok(Json(json!({"revoked": nodes.len()})))
}
#[derive(utoipa::OpenApi)] #[openapi(paths(kill,resume,status,backup,restore,dry_run,revoke_nodes),components(schemas(RestoreRequest)))]
pub struct OpsApi;
pub fn router()->Router<ApiState>{Router::new().route("/api/v1/ops/kill",post(kill)).route("/api/v1/ops/resume",post(resume)).route("/api/v1/ops/status",get(status)).route("/api/v1/ops/backup",post(backup)).route("/api/v1/ops/restore",post(restore)).route("/api/v1/ops/revoke-nodes",post(revoke_nodes)).route("/api/v1/automations/{id}/dry-run",post(dry_run))}
