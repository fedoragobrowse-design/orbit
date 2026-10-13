use async_trait::async_trait;
use orbit_core::{AuthorizedAction,Error,OwnerScope,Result,RiskLevel,ToolDescriptor,ToolEffects};
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use sqlx::{PgPool,Row};
use std::{collections::BTreeMap,path::PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub mod catalog;
pub mod workspace;
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
 vec![
  ToolDescriptor {
   id: Uuid::from_u128(10),
   name: "orbit-control.settings_update".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["settings"],"properties":{"settings":{"type":"object","minProperties":1,"maxProperties":16},"expected_revision":{"type":"integer"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["revision"],"properties":{"revision":{"type":"integer"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::High,
   permission_keys: vec!["orbit-control.settings_update".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(11),
   name: "orbit-control.ask_owner".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["question"],"properties":{"question":{"type":"string","minLength":1,"maxLength":2000},"options":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":200}}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["question_id"],"properties":{"question_id":{"type":"string","format":"uuid"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-control.ask_owner".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(12),
   name: "orbit-control.skills_list".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":[],"properties":{}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","items":{"type":"object"}}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-control.skills_list".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(14),
   name: "orbit-control.skill_read".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string","minLength":1,"maxLength":120}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["name","source","state","content_digest"],"properties":{"name":{"type":"string"},"source":{"type":"string"},"state":{"type":"string"},"content_digest":{"type":"string"},"description":{"type":"string"},"instructions":{"type":"string"},"trust_level":{"type":"string"},"requested_actions":{"type":"array","items":{"type":"string"}},"reason":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-control.skill_read".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(13),
   name: "orbit-control.docs_read".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["path"],"properties":{"path":{"type":"string","minLength":1,"maxLength":256}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["content"],"properties":{"content":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-control.docs_read".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(20),
   name: "orbit-data.memory_search".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["query"],"properties":{"query":{"type":"string","minLength":1,"maxLength":500},"limit":{"type":"integer","minimum":1,"maximum":20}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items","trust"],"properties":{"items":{"type":"array","items":{"type":"object"}},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-data.memory_search".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(21),
   name: "orbit-data.mail_read".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["message_id"],"properties":{"message_id":{"type":"string","format":"uuid"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["subject","from","body","trust"],"properties":{"subject":{"type":"string"},"from":{"type":"string"},"body":{"type":"string"},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-data.mail_read".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(22),
   name: "orbit-data.calendar_list".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["from","to"],"properties":{"from":{"type":"string"},"to":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":200}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items","trust"],"properties":{"items":{"type":"array","items":{"type":"object"}},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-data.calendar_list".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(23),
   name: "orbit-data.files_list".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":[],"properties":{"limit":{"type":"integer","minimum":1,"maximum":100}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items","trust"],"properties":{"items":{"type":"array","items":{"type":"object"}},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-data.files_list".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(40),
   name: "orbit-control.workspace_create".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["parent_id","name","kind"],"properties":{"parent_id":{"type":"string","format":"uuid"},"name":{"type":"string","minLength":1,"maxLength":255},"kind":{"enum":["FILE","DIRECTORY"]},"artifact_id":{"type":"string","format":"uuid"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","name","kind","revision","trust"],"properties":{"entry_id":{"type":"string","format":"uuid"},"name":{"type":"string"},"kind":{"type":"string"},"revision":{"type":"integer"},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-control.workspace_create".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(41),
   name: "orbit-control.workspace_write".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","expected_revision","artifact_id"],"properties":{"entry_id":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":1},"artifact_id":{"type":"string","format":"uuid"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","revision","artifact_id","trust"],"properties":{"entry_id":{"type":"string","format":"uuid"},"revision":{"type":"integer"},"artifact_id":{"type":"string","format":"uuid"},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-control.workspace_write".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(42),
   name: "orbit-control.workspace_move".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","expected_revision"],"properties":{"entry_id":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":1},"name":{"type":"string","minLength":1,"maxLength":255},"parent_id":{"type":"string","format":"uuid"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","name","revision","trust"],"properties":{"entry_id":{"type":"string","format":"uuid"},"name":{"type":"string"},"revision":{"type":"integer"},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-control.workspace_move".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(43),
   name: "orbit-control.workspace_trash".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","expected_revision"],"properties":{"entry_id":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":1}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","revision","trashed","trust"],"properties":{"entry_id":{"type":"string","format":"uuid"},"revision":{"type":"integer"},"trashed":{"type":"boolean"},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-control.workspace_trash".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(44),
   name: "orbit-control.workspace_restore".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","expected_revision"],"properties":{"entry_id":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":1},"version_id":{"type":"string","format":"uuid"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","revision","trust"],"properties":{"entry_id":{"type":"string","format":"uuid"},"revision":{"type":"integer"},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Medium,
   permission_keys: vec!["orbit-control.workspace_restore".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(45),
   name: "orbit-data.workspace_list".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["parent_id"],"properties":{"parent_id":{"type":"string","format":"uuid"},"limit":{"type":"integer","minimum":1,"maximum":100},"cursor":{"type":"string","format":"uuid"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items","trust"],"properties":{"items":{"type":"array","items":{"type":"object"}},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-data.workspace_list".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(46),
   name: "orbit-data.workspace_read".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id"],"properties":{"entry_id":{"type":"string","format":"uuid"},"max_bytes":{"type":"integer","minimum":1,"maximum":1048576}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["entry_id","name","kind","revision","artifact_id","trust","provenance"],"properties":{"entry_id":{"type":"string","format":"uuid"},"name":{"type":"string"},"kind":{"type":"string"},"revision":{"type":"integer"},"artifact_id":{"type":["string","null"]},"content":{"type":"string"},"truncated":{"type":"boolean"},"trust":{"type":"string"},"provenance":{"type":"object"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-data.workspace_read".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(47),
   name: "orbit-data.workspace_search".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["query"],"properties":{"query":{"type":"string","minLength":1,"maxLength":200},"limit":{"type":"integer","minimum":1,"maximum":50}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items","trust"],"properties":{"items":{"type":"array","items":{"type":"object"}},"trust":{"type":"string"}}}),
   effects: effects.clone(),
   default_risk: RiskLevel::Low,
   permission_keys: vec!["orbit-data.workspace_search".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(30),
   name: "ha-control.entities_list".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":[],"properties":{"limit":{"type":"integer","minimum":1,"maximum":200}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["items","trust"],"properties":{"items":{"type":"array","items":{"type":"object"}},"trust":{"type":"string"}}}),
   effects: ToolEffects{external:true,modifies_data:false,reversible:true,credential_access:false,affected_party:"OWNER".into(),network:true},
   default_risk: RiskLevel::High,
   permission_keys: vec!["ha-control.entities_list".into()],
   sandbox_required: false,
  },
  ToolDescriptor {
   id: Uuid::from_u128(31),
   name: "ha-control.call_service".into(),
   version: "1".into(),
   input_schema: json!({"type":"object","additionalProperties":false,"required":["domain","service","entity_id"],"properties":{"domain":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z0-9_]+$"},"service":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z0-9_]+$"},"entity_id":{"type":"string","minLength":1,"maxLength":256},"data":{"type":"object"}}}),
   output_schema: json!({"type":"object","additionalProperties":false,"required":["ok","domain","service","entity_id"],"properties":{"ok":{"type":"boolean"},"domain":{"type":"string"},"service":{"type":"string"},"entity_id":{"type":"string"}}}),
   effects: ToolEffects{external:true,modifies_data:true,reversible:false,credential_access:true,affected_party:"OWNER".into(),network:true},
   default_risk: RiskLevel::High,
   permission_keys: vec!["ha-control.call_service".into()],
   sandbox_required: false,
  },
 ToolDescriptor{id:Uuid::from_u128(1),name:"notifications.create".into(),version:"1".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["severity","title","body","related_entity_ids"],"properties":{"severity":{"enum":["INFO","ACTION_REQUIRED","IMPORTANT","URGENT"]},"title":{"type":"string","minLength":1,"maxLength":240},"body":{"type":"string","maxLength":32768},"related_entity_ids":{"type":"array","maxItems":50,"items":{"type":"string","format":"uuid"}}}}),output_schema:json!({"type":"object","additionalProperties":false,"required":["notification_id"],"properties":{"notification_id":{"type":"string","format":"uuid"}}}),effects:effects.clone(),default_risk:RiskLevel::Low,permission_keys:vec!["notifications.create".into()],sandbox_required:false},
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
pub struct SafeTools {pub pool:PgPool,pub artifact_dir:PathBuf,pub key_dir:PathBuf}
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
   },"orbit-control.settings_update"=>{
    // Consent-gated: owner must have flipped agent_may_change_settings, else Forbidden.
    let row: Option<Value> = sqlx::query_scalar("SELECT value FROM settings WHERE owner_id=$1").bind(scope.owner_id).fetch_optional(&self.pool).await?;
    let v = row.unwrap_or(json!({}));
    if v.get("agent_may_change_settings").and_then(Value::as_bool) != Some(true) {return Err(Error::Forbidden);}
    let patch = &s.arguments["settings"];
    if !patch.is_object() {return Err(Error::Validation("settings must be an object".into()));}
    let merged = orbit_tools_merge_settings(v, patch)?;
    let rev: Option<i64> = sqlx::query_scalar("UPDATE settings SET value=$2,revision=revision+1 WHERE owner_id=$1 AND ($3::bigint IS NULL OR revision=$3) RETURNING revision").bind(scope.owner_id).bind(&merged).bind(s.arguments.get("expected_revision").and_then(Value::as_i64)).fetch_optional(&self.pool).await?;
    let rev = rev.ok_or(Error::Conflict("settings revision changed".into()))?;
    json!({"revision":rev})
   },"orbit-control.ask_owner"=>{
    let q = s.arguments["question"].as_str().unwrap_or("").trim();
    if q.is_empty() {return Err(Error::Validation("question required".into()));}
    let opts = s.arguments.get("options").cloned().unwrap_or(json!([]));
    let qid = Uuid::new_v4();
    // Park contract: link the question to the requesting tool call
    // (action.action_id) and give it a 24h lapse. The question is recorded
    // OPEN; the task is parked RUNNING -> WAITING_FOR_INPUT per the legal
    // transition trigger; only the returned question_id is handed back.
    // No completion is recorded here: the call stays SUBMITTED (never
    // COMPLETED) until the owner answers/cancels via control.rs, and the
    // execute path must park on this output rather than settle it.
    let mut tx = self.pool.begin().await?;
    sqlx::query("INSERT INTO agent_questions(id,owner_id,task_id,agent_id,call_id,question,options,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '24 hours')").bind(qid).bind(scope.owner_id).bind(s.task_id).bind(s.agent_id).bind(s.action_id).bind(q).bind(&opts).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body,authorization_id,related_entity_ids) SELECT $1,$2,id,correlation_id,'ACTION_REQUIRED',$4,$5,$6,'[]' FROM tasks WHERE owner_id=$2 AND id=$3 ON CONFLICT(authorization_id) DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(s.task_id).bind("Agent has a question").bind(q).bind(action.authorization_id()).execute(&mut *tx).await?;
    let correlation: Uuid = sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(s.task_id).fetch_optional(&mut *tx).await?.unwrap_or_else(Uuid::new_v4);
    orbit_audit::append(&mut tx, scope, correlation, None, Some(s.task_id), "AGENT_QUESTION_ASKED", "agent asked the owner a question", json!({"question_id": qid, "call_id": s.action_id})).await?;
    // Only a RUNNING row parks; stale/terminal states conflict instead.
    let parked = sqlx::query("UPDATE tasks SET state='WAITING_FOR_INPUT',wait_reason='waiting for owner answer',lease_until=NULL,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND state='RUNNING'").bind(scope.owner_id).bind(s.task_id).execute(&mut *tx).await?.rows_affected();
    if parked != 1 {
        return Err(Error::Conflict("task is not running; cannot park for owner input".into()));
    }
    tx.commit().await?;
    // question_id-only output matches the descriptor output schema exactly,
    // so the shared SETTLE validation below still applies unchanged.
    json!({"question_id":qid})
   },"orbit-control.skills_list"=>{
    let rows = sqlx::query("SELECT name,description,enabled FROM skills WHERE owner_id=$1 ORDER BY name LIMIT 100").bind(scope.owner_id).fetch_all(&self.pool).await?;
    let mut items: Vec<Value> = rows.iter().map(|r|{let enabled=r.get::<bool,_>("enabled");json!({"name":r.get::<String,_>("name"),"source":"local","description":r.get::<String,_>("description"),"enabled":enabled,"state":if enabled{"ok"}else{"off"}})}).collect();
    let installs = sqlx::query("SELECT name,version,kind,content_digest,trust_level,capabilities FROM marketplace_installs WHERE owner_id=$1 ORDER BY name LIMIT 100").bind(scope.owner_id).fetch_all(&self.pool).await.unwrap_or_default();
    for r in &installs{let kind=r.get::<String,_>("kind");let state=if kind=="skill"{"ok".to_owned()}else{format!("not a skill (kind {kind})")};items.push(json!({"name":r.get::<String,_>("name"),"source":"marketplace","version":r.get::<String,_>("version"),"kind":kind,"content_digest":r.get::<String,_>("content_digest"),"trust_level":r.get::<String,_>("trust_level"),"requested_actions":r.get::<Value,_>("capabilities").get("tools").cloned().unwrap_or(json!([])),"state":state}));}
    json!({"items":items})
   },"orbit-control.skill_read"=>{
    let name=s.arguments["name"].as_str().unwrap_or("").trim().to_owned();
    if name.is_empty()||name.len()>120||!name.bytes().all(|c|c.is_ascii_lowercase()||c.is_ascii_digit()||c==b'-'){return Err(Error::Validation("skill name must be lowercase letters, digits, or '-'".into()));}
    if let Some(r)=sqlx::query("SELECT description,entrypoint,enabled FROM skills WHERE owner_id=$1 AND name=$2").bind(scope.owner_id).bind(&name).fetch_optional(&self.pool).await?{if !r.get::<bool,_>("enabled"){json!({"name":name,"source":"local","state":"off","content_digest":"","reason":"skill is switched off; switch it on in Settings to use it"})}else{json!({"name":name,"source":"local","state":"ok","content_digest":"","description":r.get::<String,_>("description"),"entrypoint":r.get::<String,_>("entrypoint"),"trust_level":"owner-curated","requested_actions":[]})}}
    else if let Some(r)=sqlx::query("SELECT version,kind,description,content_digest,publisher_name,trust_level,capabilities FROM marketplace_installs WHERE owner_id=$1 AND name=$2").bind(scope.owner_id).bind(&name).fetch_optional(&self.pool).await?{let kind=r.get::<String,_>("kind");if kind!="skill"{json!({"name":name,"source":"marketplace","state":format!("not a skill (kind {kind})"),"content_digest":r.get::<String,_>("content_digest"),"reason":format!("marketplace package {name:?} is not a skill")})}else{json!({"name":name,"source":"marketplace","state":"ok","content_digest":r.get::<String,_>("content_digest"),"version":r.get::<String,_>("version"),"description":r.get::<String,_>("description"),"publisher_name":r.get::<String,_>("publisher_name"),"trust_level":r.get::<String,_>("trust_level"),"requested_actions":r.get::<Value,_>("capabilities").get("tools").cloned().unwrap_or(json!([])),"capabilities":r.get::<Value,_>("capabilities")})}}
    else{json!({"name":name,"source":"unknown","state":"unknown","content_digest":"","reason":"skill is unknown; install it from the Marketplace or check the name"})}
   },"orbit-control.docs_read"=>{
    let path = s.arguments["path"].as_str().unwrap_or("");
    let content = orbit_tools_doc(path).ok_or(Error::Validation("unknown doc path".into()))?;
    json!({"content":content})
   },"orbit-data.memory_search"=>{
    let q = s.arguments["query"].as_str().unwrap_or("");
    let limit = s.arguments.get("limit").and_then(Value::as_i64).unwrap_or(5).clamp(1,20);
    let rows = sqlx::query("SELECT subject,value FROM memory_records WHERE owner_id=$1 AND (subject ILIKE $2 OR value ILIKE $2) LIMIT $3").bind(scope.owner_id).bind(format!("%{q}%")).bind(limit).fetch_all(&self.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"subject":r.get::<String,_>("subject"),"value":r.get::<String,_>("value")})).collect();
    json!({"items":items,"trust":"UNTRUSTED_EXTERNAL"})
   },"orbit-data.mail_read"=>{
    let mid: Uuid = s.arguments["message_id"].as_str().unwrap_or("").parse().map_err(|_| Error::Validation("invalid message_id".into()))?;
    let row = sqlx::query("SELECT metadata,body_text FROM email_messages WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(mid).fetch_optional(&self.pool).await?.ok_or(Error::Forbidden)?;
    let meta: Value = row.get("metadata");
    json!({"subject":meta.get("subject").cloned().unwrap_or(Value::Null),"from":meta.get("from").cloned().unwrap_or(Value::Null),"body":row.get::<String,_>("body_text"),"trust":"UNTRUSTED_EXTERNAL"})
   },"orbit-data.calendar_list"=>{
    let rows = sqlx::query("SELECT title,starts_at,ends_at,source FROM calendar_events WHERE owner_id=$1 AND starts_at>=$2 AND starts_at<$3 ORDER BY starts_at LIMIT $4").bind(scope.owner_id).bind(s.arguments["from"].as_str().unwrap_or("1970-01-01T00:00:00Z").parse::<chrono::DateTime<chrono::Utc>>().unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)).bind(s.arguments["to"].as_str().unwrap_or("2100-01-01T00:00:00Z").parse::<chrono::DateTime<chrono::Utc>>().unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC)).bind(s.arguments.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1,200)).fetch_all(&self.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"title":r.get::<String,_>("title"),"starts_at":r.get::<chrono::DateTime<chrono::Utc>,_>("starts_at"),"source":r.get::<String,_>("source")})).collect();
    json!({"items":items,"trust":"UNTRUSTED_EXTERNAL"})
   },"ha-control.entities_list"=>{
    let conns: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ha_connections WHERE owner_id=$1").bind(scope.owner_id).fetch_one(&self.pool).await?;
    if conns == 0 {return Err(Error::Validation("connect Home Assistant first under Connections".into()));}
    let limit = s.arguments.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1,200);
    let rows = sqlx::query("SELECT entity_id,state,attributes,connection_id,last_seen FROM ha_entities WHERE owner_id=$1 ORDER BY last_seen DESC NULLS LAST LIMIT $2").bind(scope.owner_id).bind(limit).fetch_all(&self.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"entity_id":r.get::<String,_>("entity_id"),"state":r.get::<String,_>("state"),"attributes":r.get::<Value,_>("attributes"),"connection_id":r.get::<Option<Uuid>,_>("connection_id"),"last_seen":r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("last_seen"),"tainted":true,"trust_level":"UNTRUSTED_EXTERNAL"})).collect();
    json!({"items":items,"trust":"UNTRUSTED_EXTERNAL"})
   },"ha-control.call_service"=>{
    let domain = s.arguments["domain"].as_str().unwrap_or("");
    let service = s.arguments["service"].as_str().unwrap_or("");
    let entity = s.arguments["entity_id"].as_str().unwrap_or("");
    if domain.is_empty() || service.is_empty() || entity.is_empty() {return Err(Error::Validation("domain, service, and entity_id are required".into()));}
    let row = sqlx::query("SELECT base_url,credential_id FROM ha_connections WHERE owner_id=$1 AND enabled ORDER BY created_at LIMIT 1").bind(scope.owner_id).fetch_optional(&self.pool).await?.ok_or(Error::Validation("connect Home Assistant first under Connections".into()))?;
    let base: String = row.try_get("base_url").map_err(|_| Error::Validation("connect Home Assistant first under Connections".into()))?;
    let cred: Option<Uuid> = row.try_get("credential_id").map_err(|_| Error::Validation("connect Home Assistant first under Connections".into()))?;
    let Some(cred) = cred else {return Err(Error::Validation("connect Home Assistant first under Connections".into()));};
    let store = orbit_secrets::SecretStore::open(self.pool.clone(), &self.key_dir).await?;
    let token = String::from_utf8(store.get(scope, cred).await?.to_vec()).map_err(|_| Error::Validation("stored Home Assistant token unreadable".into()))?;
    let ep = orbit_model_router::endpoint::AdmittedEndpoint{origin:base,local:false,admitted_addresses:vec![]};
    let url = ep.url(&format!("api/services/{domain}/{service}")).map_err(|e| match e {orbit_core::Error::Validation(m)=>Error::Validation(m),_=>Error::Forbidden})?;
    let client = ep.client().await.map_err(|e| match e {orbit_core::Error::Validation(m)=>Error::Validation(m),orbit_core::Error::Unavailable(m)=>Error::Unavailable(m),_=>Error::Forbidden})?;
    let mut body = serde_json::Map::new();
    body.insert("entity_id".into(), Value::String(entity.to_owned()));
    if let Some(extra) = s.arguments.get("data").and_then(Value::as_object) {for (k,v) in extra {body.insert(k.clone(), v.clone());}}
    let send = client.post(url).bearer_auth(&token).json(&Value::Object(body));
    let sent = tokio::time::timeout(std::time::Duration::from_secs(20), send.send()).await.map_err(|_| Error::Unavailable("home assistant unreachable (timeout)".into()))?.map_err(|_| Error::Unavailable("home assistant unreachable".into()))?;
    if sent.status().is_redirection() {return Err(Error::Unavailable("home assistant rejected the request (redirect refused)".into()));}
    sent.error_for_status().map_err(|_| Error::Unavailable("home assistant rejected the request".into()))?;
    let output = json!({"ok":true,"domain":domain,"service":service,"entity_id":entity});
    let cid: Uuid = sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(s.task_id).fetch_optional(&self.pool).await?.unwrap_or_else(Uuid::new_v4);
    let mut tx = self.pool.begin().await?;
    sqlx::query("UPDATE tool_calls SET state='COMPLETED',result=$3,completed_at=now() WHERE owner_id=$1 AND id=$2 AND state='SUBMITTED'").bind(scope.owner_id).bind(s.action_id).bind(&output).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx, scope, cid, None, Some(s.task_id), "HA_SERVICE_CALLED", "owner-approved Home Assistant service call", json!({"domain":domain,"service":service,"entity_id":entity,"call_id":s.action_id})).await?;
    tx.commit().await?;
    output
   },"orbit-data.files_list"=>{
    let limit = s.arguments.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1,100);
    let rows = sqlx::query("SELECT id,title,mime_type,size FROM artifacts WHERE owner_id=$1 ORDER BY created_at DESC LIMIT $2").bind(scope.owner_id).bind(limit).fetch_all(&self.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id":r.get::<Uuid,_>("id"),"title":r.get::<String,_>("title"),"mime":r.get::<String,_>("mime_type"),"size":r.get::<i64,_>("size")})).collect();
    json!({"items":items,"trust":"UNTRUSTED_EXTERNAL"})
   },"orbit-control.workspace_create"=>{
    let parent_id: Uuid = s.arguments.get("parent_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid parent_id".into()))?;
    let name = s.arguments.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    let kind = match s.arguments.get("kind").and_then(Value::as_str).unwrap_or("") {
     "FILE" => orbit_workspace::EntryKind::File,
     "DIRECTORY" => orbit_workspace::EntryKind::Directory,
     _ => return Err(Error::Validation("invalid kind".into())),
    };
    let artifact_id: Option<Uuid> = match s.arguments.get("artifact_id").and_then(Value::as_str) {
     None => None,
     Some(raw) => Some(raw.parse().map_err(|_| Error::Validation("invalid artifact_id".into()))?),
    };
    let entry = orbit_workspace::create(&self.pool, scope, parent_id, &name, kind, artifact_id).await?;
    json!({"entry_id":entry.id,"name":entry.name,"kind":entry.kind,"revision":entry.revision,"trust":"OWNER"})
   },"orbit-control.workspace_write"=>{
    let entry_id: Uuid = s.arguments.get("entry_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid entry_id".into()))?;
    let expected_revision = s.arguments.get("expected_revision").and_then(Value::as_i64).unwrap_or(0);
    let artifact_id: Uuid = s.arguments.get("artifact_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid artifact_id".into()))?;
    let entry = orbit_workspace::set_content(&self.pool, scope, entry_id, expected_revision, artifact_id).await?;
    json!({"entry_id":entry.id,"revision":entry.revision,"artifact_id":entry.head_artifact_id,"trust":"OWNER"})
   },"orbit-control.workspace_move"=>{
    let entry_id: Uuid = s.arguments.get("entry_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid entry_id".into()))?;
    let expected_revision = s.arguments.get("expected_revision").and_then(Value::as_i64).unwrap_or(0);
    let name = s.arguments.get("name").and_then(Value::as_str).map(|v| v.to_string());
    let parent_id: Option<Uuid> = match s.arguments.get("parent_id").and_then(Value::as_str) {
     None => None,
     Some(raw) => Some(raw.parse().map_err(|_| Error::Validation("invalid parent_id".into()))?),
    };
    let entry = orbit_workspace::rename_move(&self.pool, scope, entry_id, expected_revision, name.as_deref(), parent_id).await?;
    json!({"entry_id":entry.id,"name":entry.name,"revision":entry.revision,"trust":"OWNER"})
   },"orbit-control.workspace_trash"=>{
    let entry_id: Uuid = s.arguments.get("entry_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid entry_id".into()))?;
    let expected_revision = s.arguments.get("expected_revision").and_then(Value::as_i64).unwrap_or(0);
    let entry = orbit_workspace::trash(&self.pool, scope, entry_id, expected_revision).await?;
    json!({"entry_id":entry.id,"revision":entry.revision,"trashed":entry.trashed_at.is_some(),"trust":"OWNER"})
   },"orbit-control.workspace_restore"=>{
    let entry_id: Uuid = s.arguments.get("entry_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid entry_id".into()))?;
    let expected_revision = s.arguments.get("expected_revision").and_then(Value::as_i64).unwrap_or(0);
    let entry = match s.arguments.get("version_id").and_then(Value::as_str) {
     None => orbit_workspace::restore(&self.pool, scope, entry_id, expected_revision).await?,
     Some(raw) => {
      let version_id: Uuid = raw.parse().map_err(|_| Error::Validation("invalid version_id".into()))?;
      orbit_workspace::restore_version(&self.pool, scope, entry_id, expected_revision, version_id).await?
     }
    };
    json!({"entry_id":entry.id,"revision":entry.revision,"trust":"OWNER"})
   },"orbit-data.workspace_list"=>{
    let parent_id: Uuid = s.arguments.get("parent_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid parent_id".into()))?;
    let parent = workspace::entry_by_id(&self.pool, scope, parent_id).await?;
    let limit = s.arguments.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(1,100);
    let cursor: Option<Uuid> = match s.arguments.get("cursor").and_then(Value::as_str) {
     None => None,
     Some(raw) => Some(raw.parse().map_err(|_| Error::Validation("invalid cursor".into()))?),
    };
    let kids = orbit_workspace::children(&self.pool, scope, &parent, limit, cursor).await?;
    let mut items: Vec<Value> = Vec::with_capacity(kids.len());
    for e in &kids {
     let source = workspace::head_source(&self.pool, scope, e).await?;
     items.push(json!({"entry_id":e.id,"name":e.name,"kind":e.kind,"revision":e.revision,"artifact_id":e.head_artifact_id,"trust":workspace::trust_of_entry(e, &source),"provenance":workspace::provenance_json(e, &source),"trashed":e.trashed_at.is_some()}));
    }
    json!({"items":items,"trust":"OWNER"})
   },"orbit-data.workspace_read"=>{
    let entry_id: Uuid = s.arguments.get("entry_id").and_then(Value::as_str).unwrap_or("").parse().map_err(|_| Error::Validation("invalid entry_id".into()))?;
    let max_bytes = s.arguments.get("max_bytes").and_then(Value::as_i64).unwrap_or(65536).clamp(1,1_048_576) as usize;
    let entry = workspace::entry_by_id(&self.pool, scope, entry_id).await?;
    let source = workspace::head_source(&self.pool, scope, &entry).await?;
    let (content, truncated, artifact_id) = match entry.head_artifact_id {
     None => (None, false, None),
     Some(aid) => {
      let (_name, bytes, _source) = orbit_agent_runtime::attachments::read(&self.pool, &self.artifact_dir, scope, aid).await?;
      let take = bytes.len().min(max_bytes);
      (Some(String::from_utf8_lossy(&bytes[..take]).into_owned()), bytes.len() > max_bytes, Some(aid))
     }
    };
    json!({"entry_id":entry.id,"name":entry.name,"kind":entry.kind,"revision":entry.revision,"artifact_id":artifact_id,"content":content,"truncated":truncated,"trust":workspace::trust_of_entry(&entry, &source),"provenance":workspace::provenance_json(&entry, &source)})
   },"orbit-data.workspace_search"=>{
    let query = s.arguments.get("query").and_then(Value::as_str).unwrap_or("").to_string();
    let limit = s.arguments.get("limit").and_then(Value::as_i64).unwrap_or(20).clamp(1,50);
    let rows = workspace::search_entries(&self.pool, scope, &query, limit).await?;
    let mut items: Vec<Value> = Vec::with_capacity(rows.len());
    for e in &rows {
     let source = workspace::head_source(&self.pool, scope, e).await?;
     items.push(json!({"entry_id":e.id,"name":e.name,"kind":e.kind,"revision":e.revision,"artifact_id":e.head_artifact_id,"trust":workspace::trust_of_entry(e, &source),"provenance":workspace::provenance_json(e, &source)}));
    }
    json!({"items":items,"trust":"MIXED"})
   },_=>return Err(Error::Forbidden)
  };validate_value(&d.output_schema,&output)?;Ok(ToolResult{output,privacy_class:orbit_core::PrivacyClass::Private,trust_level:orbit_core::TrustLevel::UntrustedExternal,source_reference:format!("tool-call:{}",s.action_id)})
 }
}

fn orbit_tools_merge_settings(current: Value, patch: &Value) -> Result<Value> {
    let mut out = current.as_object().cloned().unwrap_or_default();
    // Allowlist: agent may change everyday prefs, never identity/keys/consent itself.
    const ALLOW: &[&str] = &["installation_mode","autonomy_mode","allow_private_cloud","agent_backend","inbox_enabled","sandbox_enabled"];
    for (k, v) in patch.as_object().cloned().unwrap_or_default() {
        if !ALLOW.contains(&k.as_str()) {return Err(Error::Forbidden);}
        if k == "installation_mode" && !matches!(v.as_str(), Some("LOCAL_ONLY")|Some("HYBRID")|Some("CLOUD_ONLY")) {return Err(Error::Validation("unknown installation mode".into()));}
        if k == "agent_backend" && orbit_agent_backend::BackendKind::parse(v.as_str().unwrap_or("")).is_err() {return Err(Error::Validation("unknown agent backend".into()));}
        out.insert(k, v);
    }
    Ok(Value::Object(out))
}
fn orbit_tools_doc(path: &str) -> Option<&'static str> {
    Some(match path {
        "overview" => include_str!("../../../docs/orbit-overview.md"),
        "settings" => include_str!("../../../docs/orbit-settings.md"),
        "memory" => include_str!("../../../docs/orbit-memory.md"),
        "tools" => include_str!("../../../docs/orbit-tools.md"),
        _ => return None,
    })
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn provider_mapping_is_exact(){let mut r=Registry::default();for d in descriptors(){let name=provider_name(d.id);assert_eq!(name.len(),34);r.register(d.clone()).unwrap();assert_eq!(r.from_provider(&name).unwrap().name,d.name);}assert!(r.from_provider("notifications_create").is_err());}
 #[test]fn schema_enforces_no_arbitrary_paths(){let d=descriptors().pop().unwrap();assert!(validate_value(&d.input_schema,&json!({"title":"x","content":"ok","source_references":[],"path":"/etc/passwd"})).is_err());assert!(validate_value(&d.output_schema,&json!({"artifact_id":"bad"})).is_err());}
 #[test]fn ha_control_is_high_risk_and_confirm_gated(){for name in ["ha-control.entities_list","ha-control.call_service"]{let d=descriptors().into_iter().find(|d|d.name==name).unwrap_or_else(||panic!("missing {name}"));assert_eq!(d.default_risk,RiskLevel::High);assert!(!d.sandbox_required);assert!(d.permission_keys.iter().any(|k|k=="ha-control.*")||d.permission_keys.iter().any(|k|k==name));}}
}
