pub mod attachments;
mod runtime;
pub use runtime::*;
use async_trait::async_trait;
use orbit_core::{ContextBlock,Error,ModelRole,OwnerScope,Result,ToolDescriptor};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use uuid::Uuid;
use utoipa::ToSchema;

#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct ContextStrategy {pub include_memory:bool,pub history_messages:u32,pub max_context_characters:u32}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct RunLimits {pub max_model_calls:u32,pub max_tool_calls:u32,pub max_active_seconds:u32,pub max_tokens:u64,pub max_retries:u32,pub max_subagent_depth:u32}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct MemoryPermissions {pub read_types:Vec<String>,pub write_types:Vec<String>,pub project_ids:Vec<Uuid>}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct AgentInput {pub name:String,pub purpose:String,pub instructions:String,pub allowed_tools:Vec<String>,pub model_role:ModelRole,pub context_strategy:ContextStrategy,pub limits:RunLimits,pub autonomy_constraints:Vec<String>,pub memory_permissions:MemoryPermissions,pub sandbox_required:bool}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct AgentDefinition {pub id:Uuid,pub owner_id:Uuid,#[serde(flatten)]pub config:AgentInput,pub revision:i64}
impl AgentInput {
 pub fn validate(&self)->Result<()> {
  if self.name.trim().is_empty() || self.name.len()>120 || self.purpose.len()>2000 || self.instructions.len()>16000 || self.allowed_tools.len()>128 || self.allowed_tools.iter().any(|s|s.is_empty()||s.len()>256) || self.context_strategy.history_messages==0 || self.context_strategy.history_messages>100 || !(1000..=64000).contains(&self.context_strategy.max_context_characters) || self.limits.max_model_calls==0 || self.limits.max_model_calls>100 || self.limits.max_tool_calls==0 || self.limits.max_tool_calls>200 || self.limits.max_active_seconds==0 || self.limits.max_active_seconds>3600 || !(1024..=1000000).contains(&self.limits.max_tokens) || self.limits.max_retries>5 || self.limits.max_subagent_depth>1 || self.memory_permissions.project_ids.len()>100 {return Err(Error::Validation("invalid bounded agent definition".into()));}
  let types=["PROFILE","PREFERENCE","PERSON","PROJECT","TASK","DECISION","EVENT","ROUTINE","DOCUMENT","TEMPORARY_CONTEXT"];
  if self.memory_permissions.read_types.iter().chain(&self.memory_permissions.write_types).any(|t|!types.contains(&t.as_str())) {return Err(Error::Validation("invalid memory type".into()));}
  Ok(())
 }
}
#[async_trait]
pub trait Dispatcher:Send+Sync {
 async fn descriptors(&self,scope:&OwnerScope)->Result<Vec<ToolDescriptor>>;
 async fn context(&self,scope:&OwnerScope,agent:&AgentDefinition,query:&str)->Result<Vec<ContextBlock>>;
 async fn propose(&self,scope:&OwnerScope,task:Uuid,agent:Uuid,name:&str,args:Value,proposal_key:&str)->Result<Value>;
 async fn submit(&self,scope:&OwnerScope,task:Uuid,worker:Uuid,fence:i64)->Result<Vec<Value>>;
}
pub fn safe_filename(input:&str)->String {
 let name:String=input.chars().filter(|c|c.is_ascii_alphanumeric()||matches!(c,'_'|'-'|'.'|' ')).take(120).collect();
 let name=name.trim().trim_matches('.'); if name.is_empty(){"attachment.bin".into()}else{name.into()}
}
/// There is no API for promoting model/external material into privileged context.
pub fn validate_context(block:&ContextBlock)->Result<()> {
 use orbit_core::{ContextKind,TrustLevel,PrivacyClass};
 if block.privacy_class==PrivacyClass::Secret || (matches!(block.kind,ContextKind::SystemPolicy|ContextKind::UserInstruction) && block.trust_level==TrustLevel::UntrustedExternal) || (matches!(block.kind,ContextKind::ToolOutput|ContextKind::UntrustedExternalContent|ContextKind::Memory) && block.trust_level!=TrustLevel::UntrustedExternal) {return Err(Error::Forbidden)}
 Ok(())
}
