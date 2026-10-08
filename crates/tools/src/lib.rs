use async_trait::async_trait;
use orbit_core::{AuthorizedAction,Error,OwnerScope,Result,RiskLevel,ToolDescriptor,ToolEffects};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use sqlx::{PgPool,Row};
use std::{collections::BTreeMap,path::PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ToolResult {pub output:Value,pub privacy_class:orbit_core::PrivacyClass,pub trust_level:orbit_core::TrustLevel,pub source_reference:String}
#[async_trait]
pub trait ToolExecutor:Send+Sync {async fn execute(&self,scope:&OwnerScope,action:AuthorizedAction)->Result<ToolResult>;}

pub fn validate_schema(schema:&Value)->Result<()> {
 if serde_json::to_vec(schema)?.len()>65536{return Err(Error::Validation("tool schema exceeds 64 KiB".into()));}
 fn depth(value:&Value,n:usize)->bool{n<=32&&match value{Value::Array(a)=>a.iter().all(|v|depth(v,n+1)),Value::Object(o)=>o.values().all(|v|depth(v,n+1)),_=>true}}
 if !depth(schema,0){return Err(Error::Validation("tool schema depth exceeds 32".into()));}
 // References cannot initiate network/file loads through an untrusted schema.
 fn external_ref(v:&Value)->bool{match v{Value::Object(o)=>o.iter().any(|(k,v)|(k=="$ref"&&v.as_str().is_some_and(|s|!s.starts_with('#')))||external_ref(v)),Value::Array(a)=>a.iter().any(external_ref),_=>false}}
 if external_ref(schema){return Err(Error::Validation("external schema references are forbidden".into()));}
 jsonschema::validator_for(schema).map_err(|_|Error::Validation("invalid tool JSON Schema".into()))?;Ok(())
}
pub fn validate_value(schema:&Value,value:&Value)->Result<()> {validate_schema(schema)?;if !jsonschema::validator_for(schema).map_err(|_|Error::Validation("invalid tool schema".into()))?.is_valid(value){return Err(Error::Validation("tool value does not match its registered schema".into()));}Ok(())}
pub fn provider_name(id:Uuid)->String{format!("t_{}",id.simple())}
#[derive(Default)]pub struct Registry {by_name:BTreeMap<String,ToolDescriptor>,by_provider:BTreeMap<String,String>}
impl Registry {
 pub fn register(&mut self,d:ToolDescriptor)->Result<()>{validate_schema(&d.input_schema)?;validate_schema(&d.output_schema)?;if d.name.is_empty()||d.version.is_empty()||self.by_name.contains_key(&d.name)||self.by_provider.contains_key(&provider_name(d.id)){return Err(Error::Conflict("duplicate tool or provider identity".into()));}self.by_provider.insert(provider_name(d.id),d.name.clone());self.by_name.insert(d.name.clone(),d);Ok(())}
 pub fn resolve(&self,name:&str)->Result<&ToolDescriptor>{self.by_name.get(name).ok_or(Error::Forbidden)}
 pub fn from_provider(&self,name:&str)->Result<&ToolDescriptor>{self.resolve(self.by_provider.get(name).ok_or(Error::Forbidden)?)}
}
pub fn descriptors()->Vec<ToolDescriptor>{
 let effects=ToolEffects{external:false,modifies_data:true,reversible:true,credential_access:false,affected_party:"OWNER".into(),network:false};
 vec![ToolDescriptor{id:Uuid::from_u128(1),name:"notifications.create".into(),version:"1".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["severity","title","body","related_entity_ids"],"properties":{"severity":{"enum":["INFO","ACTION_REQUIRED","IMPORTANT","URGENT"]},"title":{"type":"string","minLength":1,"maxLength":240},"body":{"type":"string","maxLength":32768},"related_entity_ids":{"type":"array","maxItems":50,"items":{"type":"string","format":"uuid"}}}}),output_schema:json!({"type":"object","additionalProperties":false,"required":["notification_id"],"properties":{"notification_id":{"type":"string","format":"uuid"}}}),effects:effects.clone(),default_risk:RiskLevel::Low,permission_keys:vec!["notifications.create".into()],sandbox_required:false},
 ToolDescriptor{id:Uuid::from_u128(2),name:"reports.save".into(),version:"1".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["title","content","source_references"],"properties":{"title":{"type":"string","minLength":1,"maxLength":240},"content":{"type":"string","maxLength":1048576},"source_references":{"type":"array","maxItems":50,"items":{"type":"string","maxLength":2048}}}}),output_schema:json!({"type":"object","additionalProperties":false,"required":["artifact_id","sha256"],"properties":{"artifact_id":{"type":"string","format":"uuid"},"sha256":{"type":"string","pattern":"^[a-f0-9]{64}$"}}}),effects,default_risk:RiskLevel::Low,permission_keys:vec!["reports.save".into()],sandbox_required:false}]
}
/// The execution envelope alone is not authority: callers must match the
/// committed submission journal. A cancelled task may still receive evidence
/// for a request whose submission committed earlier.
pub async fn verify_submission(pool:&PgPool,scope:&OwnerScope,action:&AuthorizedAction)->Result<()> {
 let s=action.snapshot();if s.owner_id!=scope.owner_id||s.principal_id!=scope.principal_id{return Err(Error::Forbidden);}
 let row=sqlx::query("SELECT snapshot,action_hash,task_fence,state FROM tool_calls WHERE owner_id=$1 AND id=$2 AND authorization_id=$3 AND task_id=$4").bind(scope.owner_id).bind(s.action_id).bind(action.authorization_id()).bind(s.task_id).fetch_optional(pool).await?.ok_or(Error::Forbidden)?;
 if !matches!(row.get::<String,_>("state").as_str(),"SUBMITTED"|"COMPLETED")||row.get::<i64,_>("task_fence")!=action.task_fence()||row.get::<Value,_>("snapshot")!=serde_json::to_value(s)?||orbit_approvals::canonical_hash(s)?!=row.get::<String,_>("action_hash"){return Err(Error::Forbidden);}Ok(())
}
pub struct SafeTools {pub pool:PgPool,pub artifact_dir:PathBuf}
#[async_trait]impl ToolExecutor for SafeTools {
 async fn execute(&self,scope:&OwnerScope,action:AuthorizedAction)->Result<ToolResult>{
  verify_submission(&self.pool,scope,&action).await?;
  let s=action.snapshot();let d=descriptors().into_iter().find(|d|d.name==s.tool_name&&d.version==s.tool_version).ok_or(Error::Forbidden)?;validate_value(&d.input_schema,&s.arguments)?;
  let output=match s.tool_name.as_str(){
   "notifications.create"=>{
    let id=s.action_id;
    sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body,authorization_id,related_entity_ids) SELECT $1,$2,id,correlation_id,$4,$5,$6,$7,$8 FROM tasks WHERE owner_id=$2 AND id=$3 ON CONFLICT(authorization_id) DO NOTHING").bind(id).bind(scope.owner_id).bind(s.task_id).bind(s.arguments["severity"].as_str().unwrap()).bind(s.arguments["title"].as_str().unwrap()).bind(s.arguments["body"].as_str().unwrap()).bind(action.authorization_id()).bind(&s.arguments["related_entity_ids"]).execute(&self.pool).await?;
    json!({"notification_id":id})
   },
   "reports.save"=>{
    let id=s.action_id;let content=s.arguments["content"].as_str().unwrap().as_bytes();if content.len()>1048576{return Err(Error::Validation("report exceeds 1 MiB".into()));}
    let digest=hex::encode(Sha256::digest(content));let storage_key=format!("{}/{}",scope.owner_id,id);let parent=self.artifact_dir.join(scope.owner_id.to_string());
    tokio::fs::create_dir_all(&parent).await.map_err(|_|Error::Unavailable("private artifact directory unavailable".into()))?;
    if tokio::fs::symlink_metadata(&parent).await.map_err(|_|Error::Unavailable("artifact storage unavailable".into()))?.file_type().is_symlink(){return Err(Error::Forbidden);}
    #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;tokio::fs::set_permissions(&parent,std::fs::Permissions::from_mode(0o700)).await.map_err(|_|Error::Unavailable("artifact permissions unavailable".into()))?;}
    let path=self.artifact_dir.join(&storage_key);
    match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&path).await{
     Ok(mut file)=>{file.write_all(content).await.map_err(|_|Error::Unavailable("artifact write failed".into()))?;file.sync_all().await.map_err(|_|Error::Unavailable("artifact persistence failed".into()))?;},
     Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>{let meta=tokio::fs::symlink_metadata(&path).await.map_err(|_|Error::Unavailable("artifact unavailable".into()))?;if !meta.is_file()||meta.len()!=content.len() as u64{return Err(Error::Conflict("existing immutable artifact differs".into()));}let prior=tokio::fs::read(&path).await.map_err(|_|Error::Unavailable("artifact unavailable".into()))?;if hex::encode(Sha256::digest(&prior))!=digest{return Err(Error::Conflict("existing immutable artifact differs".into()));}},
     Err(_)=>return Err(Error::Unavailable("artifact storage unavailable".into())),
    }
    sqlx::query("INSERT INTO artifacts(id,owner_id,task_id,authorization_id,title,safe_name,mime_type,size,sha256,source_references,storage_key) VALUES($1,$2,$3,$4,$5,'report.txt','text/plain; charset=utf-8',$6,$7,$8,$9) ON CONFLICT(authorization_id) DO NOTHING").bind(id).bind(scope.owner_id).bind(s.task_id).bind(action.authorization_id()).bind(s.arguments["title"].as_str().unwrap()).bind(content.len() as i64).bind(&digest).bind(&s.arguments["source_references"]).bind(storage_key).execute(&self.pool).await?;
    json!({"artifact_id":id,"sha256":digest})
   },_=>return Err(Error::Forbidden)
  };validate_value(&d.output_schema,&output)?;Ok(ToolResult{output,privacy_class:orbit_core::PrivacyClass::Private,trust_level:orbit_core::TrustLevel::UntrustedExternal,source_reference:format!("tool-call:{}",s.action_id)})
 }
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn provider_mapping_is_exact(){let mut r=Registry::default();for d in descriptors(){let name=provider_name(d.id);assert_eq!(name.len(),34);r.register(d.clone()).unwrap();assert_eq!(r.from_provider(&name).unwrap().name,d.name);}assert!(r.from_provider("notifications_create").is_err());}
 #[test]fn schema_enforces_no_arbitrary_paths(){let d=descriptors().pop().unwrap();assert!(validate_value(&d.input_schema,&json!({"title":"x","content":"ok","source_references":[],"path":"/etc/passwd"})).is_err());assert!(validate_value(&d.output_schema,&json!({"artifact_id":"bad"})).is_err());}
}
