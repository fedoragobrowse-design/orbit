use crate::{ApiError, ApiState, authenticate};
use axum::{Json, Router, extract::{Path, Query, State}, http::HeaderMap, routing::{get, post}};
use chrono::{DateTime, Utc};
use orbit_aiec_runtime::{AIecRuntime, ConnectionConfig};
use orbit_core::{Error, OwnerScope, Result, RiskLevel, ToolDescriptor, ToolEffects};
use orbit_secrets::SecretStore;
use orbit_task_runtime::{InputArtifact, RuntimeTask, FILE_LIMIT, TRANSFER_LIMIT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn router() -> Router<ApiState> {
    Router::new().route("/api/v1/runtimes/connections",get(connections).post(create_connection))
        .route("/api/v1/runtimes/connections/{id}",get(connection_detail).patch(update_connection).delete(remove_connection))
        .route("/api/v1/runtimes/connections/{id}/test",post(test_connection))
        .route("/api/v1/runtimes",get(list_runs))
        .route("/api/v1/runtimes/{id}/cleanup",post(request_cleanup))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionWrite {
    name: String, origin: String, admitted_addresses: Vec<std::net::IpAddr>, ca_pem: Option<String>,
    secret_id: Option<Uuid>, credential: Option<String>, image: String, disk_mb: u32, lifetime_seconds: u64,
    enabled: Option<bool>,
}
async fn connection_input(state:&ApiState,scope:&OwnerScope,input:ConnectionWrite,old:Option<Uuid>)->Result<(String,ConnectionConfig,bool)> {
    if input.name.trim().is_empty() || input.name.len()>128 {return Err(Error::Validation("invalid connection name".into()));}
    let store=SecretStore::open(state.pool.clone(),&state.key_dir).await?;
    let secret_id=match(input.credential,input.secret_id.or(old)) {
        (Some(key),_)=>store.put(scope,"aiec-tenant-api-key",key.as_bytes()).await?,
        (None,Some(id))=>{store.get(scope,id).await?;id},
        _=>return Err(Error::Validation("tenant API credential required".into())),
    };
    let config=ConnectionConfig{origin:input.origin,admitted_addresses:input.admitted_addresses,ca_pem:input.ca_pem,secret_id,image:input.image,disk_mb:input.disk_mb,lifetime_seconds:input.lifetime_seconds};config.validate()?;
    // Admission resolves/pins in the server namespace; it does not contact AIec or prove capacity.
    let _=AIecRuntime::connect(config.clone(),store.get(scope,secret_id).await?).await?;
    Ok((input.name,config,input.enabled.unwrap_or(true)))
}
fn connection_view(row:&sqlx::postgres::PgRow)->Value {
    let mut value=row.get::<Value,_>("config");
    if let Some(object)=value.as_object_mut(){object.insert("id".into(),json!(row.get::<Uuid,_>("id")));object.insert("name".into(),json!(row.get::<String,_>("name")));object.insert("revision".into(),json!(row.get::<i64,_>("revision")));object.insert("enabled".into(),json!(row.get::<bool,_>("enabled")));object.insert("status".into(),json!(row.get::<String,_>("status")));object.insert("last_test".into(),json!(row.get::<Option<DateTime<Utc>>,_>("last_test")));} value
}
async fn connections(State(state):State<ApiState>,headers:HeaderMap)->std::result::Result<Json<Value>,ApiError>{
    let auth=authenticate(&state,&headers,false).await?;let rows=sqlx::query("SELECT * FROM aiec_connections WHERE owner_id=$1 ORDER BY created_at,id LIMIT 50").bind(auth.scope.owner_id).fetch_all(&state.pool).await?;
    Ok(Json(json!({"items":rows.iter().map(connection_view).collect::<Vec<_>>(),"next_cursor":null})))
}
async fn connection_detail(State(state):State<ApiState>,headers:HeaderMap,Path(id):Path<Uuid>)->std::result::Result<Json<Value>,ApiError>{let auth=authenticate(&state,&headers,false).await?;let row=sqlx::query("SELECT * FROM aiec_connections WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;Ok(Json(connection_view(&row)))}
async fn create_connection(State(state):State<ApiState>,headers:HeaderMap,Json(input):Json<ConnectionWrite>)->std::result::Result<Json<Value>,ApiError>{
    let auth=authenticate(&state,&headers,true).await?;let(name,config,enabled)=connection_input(&state,&auth.scope,input,None).await?;let id=Uuid::new_v4();let mut tx=state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(auth.scope.owner_id).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO aiec_connections(id,owner_id,name,config,enabled) VALUES($1,$2,$3,$4,$5)").bind(id).bind(auth.scope.owner_id).bind(name).bind(json!(config)).bind(enabled).execute(&mut *tx).await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(auth.scope.owner_id).execute(&mut *tx).await?;tx.commit().await?;
    connection_detail(State(state),headers,Path(id)).await
}
async fn update_connection(State(state):State<ApiState>,headers:HeaderMap,Path(id):Path<Uuid>,Json(input):Json<ConnectionWrite>)->std::result::Result<Json<Value>,ApiError>{
    let auth=authenticate(&state,&headers,true).await?;let old:Value=sqlx::query_scalar("SELECT config FROM aiec_connections WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;let old:ConnectionConfig=serde_json::from_value(old).map_err(Error::from)?;
    let(name,config,enabled)=connection_input(&state,&auth.scope,input,Some(old.secret_id)).await?;let mut tx=state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(auth.scope.owner_id).fetch_one(&mut *tx).await?;
    sqlx::query("UPDATE aiec_connections SET name=$3,config=$4,enabled=$5,revision=revision+1,status='UNTESTED' WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).bind(name).bind(json!(config)).bind(enabled).execute(&mut *tx).await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(auth.scope.owner_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE runtime_runs SET cleanup_requested=true WHERE owner_id=$1 AND connection_id=$2 AND cleanup_required").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?;tx.commit().await?;
    connection_detail(State(state),headers,Path(id)).await
}
async fn remove_connection(State(state):State<ApiState>,headers:HeaderMap,Path(id):Path<Uuid>)->std::result::Result<Json<Value>,ApiError>{
    let auth=authenticate(&state,&headers,true).await?;let mut tx=state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(auth.scope.owner_id).fetch_one(&mut *tx).await?;
    let n=sqlx::query("UPDATE aiec_connections SET enabled=false,revision=revision+1,status='REVOKED' WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?.rows_affected();if n==0{return Err(Error::NotFound.into());}
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(auth.scope.owner_id).execute(&mut *tx).await?;
    // Retain encrypted connector credential for obligatory system cleanup, never for new agent work.
    sqlx::query("UPDATE runtime_runs SET cleanup_requested=true WHERE owner_id=$1 AND connection_id=$2 AND cleanup_required").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?;tx.commit().await?;Ok(Json(json!({"removed":true,"cleanup_credentials_retained":true})))
}
async fn adapter(pool:&PgPool,key_dir:&std::path::Path,scope:&OwnerScope,connection_id:Uuid)->Result<AIecRuntime>{
    let config:Value=sqlx::query_scalar("SELECT config FROM aiec_connections WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(connection_id).fetch_optional(pool).await?.ok_or(Error::NotFound)?;let config:ConnectionConfig=serde_json::from_value(config)?;let store=SecretStore::open(pool.clone(),key_dir).await?;let key=store.get(scope,config.secret_id).await?;AIecRuntime::connect(config,key).await
}
async fn test_connection(State(state):State<ApiState>,headers:HeaderMap,Path(id):Path<Uuid>)->std::result::Result<Json<Value>,ApiError>{let auth=authenticate(&state,&headers,true).await?;let runtime=adapter(&state.pool,&state.key_dir,&auth.scope,id).await?;let result=runtime.readiness().await?;sqlx::query("UPDATE aiec_connections SET status='AUTHENTICATED',last_test=now() WHERE owner_id=$1 AND id=$2 AND enabled").bind(auth.scope.owner_id).bind(id).execute(&state.pool).await?;Ok(Json(result))}
#[derive(Deserialize)]
struct RunQuery { task_id:Option<Uuid>, cursor:Option<Uuid> }
async fn list_runs(State(state):State<ApiState>,headers:HeaderMap,Query(query):Query<RunQuery>)->std::result::Result<Json<Value>,ApiError>{let auth=authenticate(&state,&headers,false).await?;let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(r)-'action_snapshot'-'creator_id' FROM runtime_runs r WHERE owner_id=$1 AND ($2::uuid IS NULL OR task_id=$2) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT 51").bind(auth.scope.owner_id).bind(query.task_id).bind(query.cursor).fetch_all(&state.pool).await?;let next=if rows.len()>50 {rows[49].get("id").cloned()}else{None};Ok(Json(json!({"items":rows.into_iter().take(50).collect::<Vec<_>>(),"next_cursor":next})))}
async fn request_cleanup(State(state):State<ApiState>,headers:HeaderMap,Path(id):Path<Uuid>)->std::result::Result<Json<Value>,ApiError>{let auth=authenticate(&state,&headers,true).await?;let mut tx=state.pool.begin().await?;sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(auth.scope.owner_id).fetch_one(&mut *tx).await?;let task:Uuid=sqlx::query_scalar("SELECT task_id FROM runtime_runs WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;sqlx::query("SELECT id FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(auth.scope.owner_id).bind(task).fetch_one(&mut *tx).await?;sqlx::query("UPDATE runtime_runs SET cleanup_requested=true WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?;tx.commit().await?;Ok(Json(json!({"cleanup_required":true,"resolution":"PENDING_REMOTE_PROOF"})))}

pub fn descriptors()->Vec<ToolDescriptor>{vec![ToolDescriptor{id:Uuid::from_u128(0x65d70d8d_4fe0_40d1_a647_2ff1e8771150),name:"shell.execute".into(),version:"1".into(),input_schema:json!({"type":"object","required":["image","argv","working_directory","timeout_seconds","input_artifact_ids","output_paths"],"properties":{"image":{"type":"string"},"argv":{"type":"array","minItems":1,"maxItems":128,"items":{"type":"string"}},"working_directory":{"type":"string"},"timeout_seconds":{"type":"integer","minimum":1,"maximum":120},"input_artifact_ids":{"type":"array","maxItems":10,"items":{"type":"string","format":"uuid"}},"output_paths":{"type":"array","maxItems":10,"items":{"type":"string"}},"runtime_spec":{"type":"object"}},"additionalProperties":false}),output_schema:json!({"type":"object","required":["runtime_id","result","artifacts","cleanup"],"properties":{"runtime_id":{"type":"string"},"result":{"type":"object"},"artifacts":{"type":"array"},"cleanup":{"type":"string"}},"additionalProperties":false}),effects:ToolEffects{external:true,modifies_data:true,reversible:false,credential_access:false,affected_party:"owner-private isolated workload".into(),network:false},default_risk:RiskLevel::High,permission_keys:vec!["aiec.admitted_image".into()],sandbox_required:true}]}
#[derive(Clone,Serialize,Deserialize)]
struct ConsentSpec {connection_id:Uuid,revision:i64,image:String,cpu:u32,memory_mb:u32,disk_mb:u32,lifetime_seconds:u64,network_enabled:bool,inputs:Vec<InputArtifact>}
/// Materialize all resource and byte bindings before consent, not after approval.
pub async fn materialize(pool:&PgPool,scope:&OwnerScope,mut args:Value)->Result<Value>{
    if args.get("runtime_spec").is_some(){return Err(Error::Validation("runtime_spec is server materialized".into()));}
    let image=args.get("image").and_then(Value::as_str).ok_or_else(||Error::Validation("image required".into()))?;
    let rows=sqlx::query("SELECT id,revision,config FROM aiec_connections WHERE owner_id=$1 AND enabled AND config->>'image'=$2 ORDER BY id LIMIT 2").bind(scope.owner_id).bind(image).fetch_all(pool).await?;
    if rows.len()!=1{return Err(Error::Unavailable("configure one admitted AIec connection for this image".into()));}let row=&rows[0];let config:ConnectionConfig=serde_json::from_value(row.get("config"))?;
    let ids:Vec<Uuid>=serde_json::from_value(args.get("input_artifact_ids").cloned().ok_or_else(||Error::Validation("input artifacts required".into()))?)?;if ids.len()>10{return Err(Error::Validation("too many input artifacts".into()));}
    let mut inputs=Vec::new();let mut total=0usize;let mut seen=std::collections::BTreeSet::new();
    for id in ids{if !seen.insert(id){return Err(Error::Validation("duplicate input artifact".into()));}let artifact=sqlx::query("SELECT sha256,size FROM artifacts WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).fetch_optional(pool).await?.ok_or(Error::NotFound)?;let size:i64=artifact.get("size");if size<0||size as usize>FILE_LIMIT{return Err(Error::Validation("runtime inputs cap at 1 MiB/file".into()));}total+=size as usize;if total>TRANSFER_LIMIT{return Err(Error::Validation("runtime inputs cap at 10 MiB total".into()));}inputs.push(InputArtifact{artifact_id:id,path:format!("/workspace/inputs/{id}"),sha256:artifact.get("sha256"),size:size as u64,bytes:Vec::new()});}
    let consent=ConsentSpec{connection_id:row.get("id"),revision:row.get("revision"),image:config.image,cpu:1,memory_mb:512,disk_mb:config.disk_mb,lifetime_seconds:1680,network_enabled:false,inputs};
    let task=task_from_args(&args)?;task.validate()?;
    args.as_object_mut().ok_or_else(||Error::Validation("shell arguments must be an object".into()))?.insert("runtime_spec".into(),json!(consent));Ok(args)
}
pub async fn materialize_action(state:&ApiState,scope:&OwnerScope,_tool:&str,args:Value)->Result<(Value,BTreeMap<String,i64>,BTreeMap<String,String>)>{let args=materialize(&state.pool,scope,args).await?;let spec:ConsentSpec=serde_json::from_value(args["runtime_spec"].clone())?;let revisions=BTreeMap::from([(format!("aiec:{}",spec.connection_id),spec.revision)]);let digests=spec.inputs.iter().map(|i|(i.artifact_id.to_string(),i.sha256.clone())).collect();Ok((args,revisions,digests))}
fn task_from_args(args:&Value)->Result<RuntimeTask>{Ok(RuntimeTask{argv:serde_json::from_value(args["argv"].clone())?,working_directory:serde_json::from_value(args["working_directory"].clone())?,timeout_seconds:serde_json::from_value(args["timeout_seconds"].clone())?,output_paths:serde_json::from_value(args["output_paths"].clone())?})}
