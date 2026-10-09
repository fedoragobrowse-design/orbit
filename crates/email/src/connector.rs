use super::{MailService,MAX_MESSAGE_BYTES};
use orbit_core::{OwnerScope,Result};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use uuid::Uuid;
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum SyncState{NeverSynced,Polling,Synced,Error}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimits{pub batch_limit:usize,pub max_message_bytes:usize,pub min_poll_seconds:u64,pub max_poll_seconds:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct PollHandle{pub owner_id:Uuid,pub account_id:Uuid,pub poll_seconds:u64}
#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest{pub name:String,pub version:String,pub kind:String,pub scopes:Vec<String>,pub sync_state:SyncState}
/// External-source connector boundary. Every implementor ingests third-party bytes, so `untrusted_output()` is always true and all MIME/body parsing stays sandboxed before any trust elevation (see docs/CONNECTORS.md).
#[async_trait::async_trait]
pub trait Connector:Send+Sync{async fn fetch(&self,scope:&OwnerScope,account:Uuid)->Result<Value>;async fn watch(&self,scope:&OwnerScope,account:Uuid)->Result<PollHandle>;fn capabilities(&self)->Vec<String>;fn required_scopes(&self)->Vec<String>;fn rate_limits(&self)->RateLimits;fn untrusted_output(&self)->bool;fn manifest(&self)->ConnectorManifest;}
#[async_trait::async_trait]
impl Connector for MailService{
 async fn fetch(&self,scope:&OwnerScope,account:Uuid)->Result<Value>{self.sync(scope,account).await}
 async fn watch(&self,scope:&OwnerScope,account:Uuid)->Result<PollHandle>{self.test(scope,account).await?;let(c,_,_,_)=self.account(scope,account).await?;Ok(PollHandle{owner_id:scope.owner_id,account_id:account,poll_seconds:c.poll_seconds})}
 fn capabilities(&self)->Vec<String>{["fetch","watch","test","send"].into_iter().map(str::to_owned).collect()}
 fn required_scopes(&self)->Vec<String>{["imap:read","smtp:send"].into_iter().map(str::to_owned).collect()}
 fn rate_limits(&self)->RateLimits{RateLimits{batch_limit:50,max_message_bytes:MAX_MESSAGE_BYTES,min_poll_seconds:15,max_poll_seconds:3600}}
 fn untrusted_output(&self)->bool{true}
 fn manifest(&self)->ConnectorManifest{ConnectorManifest{name:"orbit-mail-imap".into(),version:env!("CARGO_PKG_VERSION").into(),kind:"mail-imap".into(),scopes:self.required_scopes(),sync_state:SyncState::Polling}}
}
