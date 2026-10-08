use chrono::{DateTime,Utc};
use orbit_core::{MemoryType,MemoryStatus,PrivacyClass,TrustLevel,Error,Result};
use serde::{Serialize,Deserialize};
use serde_json::Value;
use uuid::Uuid;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct MemoryRecord {
 pub id:Uuid,pub owner_id:Uuid,#[serde(rename="type")]pub memory_type:MemoryType,pub subject:String,pub value:Value,
 pub source:String,pub source_reference:String,pub source_references:Vec<String>,pub confidence:f64,pub trust_level:TrustLevel,
 pub created_at:DateTime<Utc>,pub updated_at:DateTime<Utc>,pub last_verified_at:Option<DateTime<Utc>>,
 pub valid_from:DateTime<Utc>,pub valid_until:Option<DateTime<Utc>>,pub privacy_class:PrivacyClass,pub status:MemoryStatus,
 pub related_entities:Vec<Uuid>,pub version:i64,pub supersedes_id:Option<Uuid>,pub entity_key:String,
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
 #[serde(rename="type")]pub memory_type:MemoryType,pub subject:String,pub value:Value,
 #[serde(default)]pub source_references:Vec<String>,#[serde(default)]pub related_entities:Vec<Uuid>,
 #[serde(default="private")]pub privacy_class:PrivacyClass,#[serde(default="confidence")]pub confidence:f64,
 pub valid_until:Option<DateTime<Utc>>,pub entity_id:Option<Uuid>,
}
fn private()->PrivacyClass{PrivacyClass::Private} fn confidence()->f64{0.8}
impl Candidate {
 pub fn validate(&self)->Result<()> {
  if self.subject.trim().is_empty()||self.subject.chars().count()>256||serde_json::to_vec(&self.value)?.len()>16000||self.value.is_null()||self.source_references.len()>32||self.related_entities.len()>32||!self.confidence.is_finite()||!(0.0..=1.0).contains(&self.confidence){return Err(Error::Validation("invalid bounded memory candidate".into()))}
  if self.source_references.iter().any(|r|r.is_empty()||r.len()>1024){return Err(Error::Validation("invalid source reference".into()))} Ok(())
 }
 pub fn entity_key(&self)->String {
  if let Some(id)=self.entity_id{return format!("id:{id}")}
  // Same-name people never implicitly merge. Non-person facts have deterministic aliases.
  if self.memory_type==MemoryType::Person{return format!("person:{}",Uuid::new_v4())}
  format!("alias:{}",normalize(&self.subject))
 }
}
pub fn normalize(s:&str)->String {s.nfkc().flat_map(char::to_lowercase).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")}
#[derive(Debug,Clone)]
pub struct Provenance {pub source:String,pub references:Vec<String>,pub privacy:PrivacyClass,pub trust:TrustLevel,pub correlation_id:Uuid,pub task_id:Option<Uuid>}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct CandidateOutcome {pub candidate_id:Uuid,pub status:String,pub memory_id:Option<Uuid>,pub conflicts_with:Option<Uuid>}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {pub query:String,#[serde(default)]pub types:Vec<MemoryType>,pub project_id:Option<Uuid>,#[serde(default="twelve")]pub limit:usize}
fn twelve()->usize{12}
#[derive(Debug,Clone)]
pub struct RetrievalScope {pub types:Vec<MemoryType>,pub project_ids:Vec<Uuid>,pub max_privacy:PrivacyClass,pub agent_id:Option<Uuid>}
impl Default for RetrievalScope {fn default()->Self{Self{types:vec![],project_ids:vec![],max_privacy:PrivacyClass::HighlyPrivate,agent_id:None}}}
#[derive(Debug,Clone)]
pub struct QueryVector {pub provider_id:Uuid,pub model_id:Uuid,pub values:Vec<f32>}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RetentionSettings {pub event_body_days:i32,pub conversation_body_days:i32,pub runtime_artifact_days:i32,pub connector_cache_days:i32}
impl Default for RetentionSettings {fn default()->Self{Self{event_body_days:30,conversation_body_days:90,runtime_artifact_days:30,connector_cache_days:30}}}
