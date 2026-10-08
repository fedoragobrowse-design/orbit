use chrono::{DateTime,Utc};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use uuid::Uuid;
use utoipa::ToSchema;

macro_rules! wire_enum { ($name:ident {$($variant:ident),* $(,)?}) => {#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq,PartialOrd,Ord,ToSchema)] #[serde(rename_all="SCREAMING_SNAKE_CASE")] pub enum $name {$($variant),*}} }
wire_enum!(PrivacyClass {Public,Personal,Private,HighlyPrivate,Secret});
wire_enum!(TrustLevel {OwnerAuthenticated,System,UntrustedExternal});
wire_enum!(PrincipalType {WebUser,MobileUser,ComputerNode,EmailSender,Automation,Webhook,Agent,System,McpServer});
wire_enum!(EventType {EmailReceived,EmailReplied,CalendarChanged,FileCreated,FileModified,FileDeleted,FileShared,ComputerConnected,ComputerDisconnected,DeviceEvent,ScheduleTrigger,TimerTrigger,WebhookReceived,GithubEvent,HomeEvent,TaskCompleted,TaskFailed,UserMessage,ApprovalAccepted,ApprovalDenied});
wire_enum!(ClassificationKind {Ignore,StoreOnly,MemoryCandidate,Notify,CreateTask,Urgent});
wire_enum!(TaskState {Queued,Running,WaitingForApproval,WaitingForResource,Completed,Failed,Cancelled,TimedOut});
wire_enum!(RiskLevel {ReadOnly,Low,Medium,High,Critical,Forbidden});
wire_enum!(AutonomyMode {Chat,Observe,Assist,TrustedAutomation,Custom});
wire_enum!(ModelRole {Fast,Private,Reasoning,Coding,Vision,Embedding});
wire_enum!(MemoryType {Profile,Preference,Person,Project,Task,Decision,Event,Routine,Document,TemporaryContext});
wire_enum!(MemoryStatus {Active,Superseded,Expired,Forgotten});
wire_enum!(NotificationSeverity {Info,ActionRequired,Important,Urgent});
wire_enum!(ContextKind {UserInstruction,SystemPolicy,ToolOutput,UntrustedExternalContent,Memory});
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct Principal {pub id:Uuid,pub owner_id:Uuid,pub principal_type:PrincipalType,pub auth_method:String,pub trust_level:TrustLevel,pub source:String,pub session_id:Option<Uuid>}
#[derive(Debug,Clone)]
pub struct OwnerScope {pub owner_id:Uuid,pub principal_id:Uuid}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct Event {pub id:Uuid,pub owner_id:Uuid,pub event_type:EventType,pub source:String,pub principal_id:Uuid,pub timestamp:DateTime<Utc>,pub payload:Value,pub trust_level:TrustLevel,pub privacy_class:PrivacyClass,pub correlation_id:Uuid,pub related_entities:Vec<Uuid>,pub source_event_key:String}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct ContextBlock {pub kind:ContextKind,pub text_or_reference:String,pub privacy_class:PrivacyClass,pub trust_level:TrustLevel,pub source_reference:String}

#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct ToolEffects {pub external:bool,pub modifies_data:bool,pub reversible:bool,pub credential_access:bool,pub affected_party:String,pub network:bool}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct ToolDescriptor {pub id:Uuid,pub name:String,pub version:String,pub input_schema:Value,pub output_schema:Value,pub effects:ToolEffects,pub default_risk:RiskLevel,pub permission_keys:Vec<String>,pub sandbox_required:bool}
#[derive(Debug,Clone,Serialize,Deserialize,ToSchema)]
pub struct ActionSnapshot {
 pub action_id:Uuid,pub owner_id:Uuid,pub principal_id:Uuid,pub agent_id:Option<Uuid>,pub task_id:Uuid,
 pub tool_name:String,pub tool_version:String,pub arguments:Value,
 pub input_artifact_digests:std::collections::BTreeMap<String,String>,
 pub scope_revisions:std::collections::BTreeMap<String,i64>,pub policy_revision:i64,pub authorization_epoch:i64,
 pub requires_sandbox:bool,pub expires_at:DateTime<Utc>,
}
/// Ephemeral execution envelope. Lease fences intentionally are not immutable consent fields.
#[derive(Debug,Clone)]
pub struct AuthorizedAction {snapshot:ActionSnapshot,authorization_id:Uuid,task_fence:i64}
impl AuthorizedAction {
 /// The dispatcher calls this only after the durable submission transaction commits.
 pub fn from_submission(snapshot:ActionSnapshot,authorization_id:Uuid,task_fence:i64)->Self{Self{snapshot,authorization_id,task_fence}}
 pub fn snapshot(&self)->&ActionSnapshot{&self.snapshot}
 pub fn authorization_id(&self)->Uuid{self.authorization_id}
 pub fn task_fence(&self)->i64{self.task_fence}
}
#[derive(Debug,thiserror::Error)]
pub enum Error {#[error("authentication required")] Unauthorized,#[error("permission denied")] Forbidden,#[error("record not found")] NotFound,#[error("{0}")] Validation(String),#[error("{0}")] Conflict(String),#[error("{0}")] Unavailable(String),#[error("capability unsupported")] UnsupportedCapability,#[error("operation timed out")] Timeout,#[error("effect outcome is unknown")] OutcomeUnknown,#[error("storage operation failed")] Database(#[from] sqlx::Error),#[error("serialization failed")] Serialization(#[from] serde_json::Error)}
pub type Result<T, E = Error> = std::result::Result<T,E>;
pub fn literal<T:Serialize>(value:T)->String {serde_json::to_value(value).expect("enum serializes").as_str().expect("enum string").to_owned()}
pub fn validate_event(kind:EventType,payload:&Value)->Result<()> {
 if !payload.is_object() || serde_json::to_vec(payload)?.len()>65536 {return Err(Error::Validation("event payload must be a bounded object".into()));}
 let required=match kind {EventType::UserMessage=>"text",EventType::FileCreated|EventType::FileModified|EventType::FileDeleted=>"file_id",EventType::EmailReceived|EventType::EmailReplied=>"message_id",EventType::TaskCompleted|EventType::TaskFailed=>"task_id",EventType::ApprovalAccepted|EventType::ApprovalDenied=>"approval_id",EventType::ComputerConnected|EventType::ComputerDisconnected=>"node_id",EventType::ScheduleTrigger|EventType::TimerTrigger=>"automation_id",_=>"source_reference"};
 if payload.get(required).and_then(Value::as_str).filter(|s| !s.is_empty() && s.len()<=32768).is_none(){return Err(Error::Validation(format!("missing event field {required}")));}
 Ok(())
}
