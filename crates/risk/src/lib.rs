use orbit_core::{ClassificationKind,Event,EventType,RiskLevel,ToolDescriptor,ToolEffects};
use serde::{Deserialize,Serialize};
use serde_json::Value;

#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProposedAction { pub tool_name:String,pub arguments:Value }
#[derive(Debug,Clone,Default)]
pub struct ActionContext { pub optional_escalation:Option<RiskLevel> }
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RiskAssessment {pub level:RiskLevel,pub effects:ToolEffects,pub reasons:Vec<String>}
pub struct RiskClassifier;
impl RiskClassifier {
 pub fn classify_action(action:&ProposedAction,descriptor:&ToolDescriptor,context:&ActionContext)->orbit_core::Result<RiskAssessment>{
  let name=action.tool_name.as_str();
  let mut level=descriptor.default_risk;
  let mut reasons=vec!["DESCRIPTOR_FLOOR".into()];
  let deterministic=if name=="files.delete"||name.starts_with("payments.")||name.starts_with("secrets.")||name.starts_with("host.") {RiskLevel::Forbidden}
   else if name=="shell.execute" {RiskLevel::High}
   else if matches!(name,"email.send"|"files.write"|"files.move"|"files.copy") {RiskLevel::High}
   else if descriptor.effects.external&&descriptor.effects.modifies_data {RiskLevel::Medium}
   else if descriptor.effects.modifies_data {RiskLevel::Low}
   else {RiskLevel::ReadOnly};
  level=level.max(deterministic);reasons.push("DETERMINISTIC_EFFECT_FLOOR".into());
  if let Some(escalation)=context.optional_escalation {level=level.max(escalation);reasons.push("CLASSIFIER_ESCALATION_ONLY".into());}
  Ok(RiskAssessment{level,effects:descriptor.effects.clone(),reasons})
 }
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Classification {pub kind:ClassificationKind,pub confidence:f64,pub reason:String,pub recommended_agent:Option<String>,pub recommended_model_class:Option<String>}
pub struct EventClassifier;
impl EventClassifier {
 pub fn classify(event:&Event)->orbit_core::Result<Classification>{
  orbit_core::validate_event(event.event_type,&event.payload)?;
  let(kind,agent,reason)=match event.event_type{
   EventType::UserMessage=>(ClassificationKind::CreateTask,Some("general"),"AUTHENTICATED_CHAT"),
   EventType::FileCreated|EventType::FileModified|EventType::FileDeleted=>(ClassificationKind::StoreOnly,Some("file"),"REQUIRES_MATCHING_ROOT_AUTOMATION"),
   EventType::EmailReceived|EventType::EmailReplied=>(ClassificationKind::StoreOnly,Some("email"),"UNTRUSTED_MAIL_REQUIRES_ACCOUNT_RULE"),
   EventType::ScheduleTrigger|EventType::TimerTrigger=>(ClassificationKind::CreateTask,None,"PERSISTED_TRIGGER"),
   EventType::ApprovalAccepted|EventType::ApprovalDenied=>(ClassificationKind::StoreOnly,None,"DURABLE_APPROVAL_CHECKPOINT"),
   EventType::TaskFailed|EventType::ComputerDisconnected=>(ClassificationKind::Notify,None,"RESOURCE_STATUS"),
   _=>(ClassificationKind::StoreOnly,None,"NO_DEFAULT_PROACTIVE_AUTHORITY")};
  Ok(Classification{kind,confidence:1.0,reason:reason.into(),recommended_agent:agent.map(str::to_owned),recommended_model_class:None})
 }
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn effects_and_escalations_cannot_lower_floors(){
  let d=ToolDescriptor{id:uuid::Uuid::new_v4(),name:"shell.execute".into(),version:"1".into(),input_schema:Value::Bool(true),output_schema:Value::Bool(true),effects:ToolEffects{external:true,modifies_data:true,reversible:false,credential_access:false,affected_party:"owner".into(),network:false},default_risk:RiskLevel::ReadOnly,permission_keys:vec![],sandbox_required:true};
  let p=ProposedAction{tool_name:d.name.clone(),arguments:Value::Null};
  assert_eq!(RiskClassifier::classify_action(&p,&d,&ActionContext{optional_escalation:Some(RiskLevel::Low)}).unwrap().level,RiskLevel::High);
  assert_eq!(RiskClassifier::classify_action(&p,&d,&ActionContext{optional_escalation:Some(RiskLevel::Critical)}).unwrap().level,RiskLevel::Critical);
 }
}
