pub mod attachments;
mod runtime;
pub use runtime::*;
use async_trait::async_trait;
use orbit_core::{ContextBlock, Error, OwnerScope, Result, ToolDescriptor};
use serde_json::Value;
use uuid::Uuid;

pub use orbit_core::{AgentDefinition, AgentInput, ContextStrategy, MemoryPermissions, RunLimits};
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
