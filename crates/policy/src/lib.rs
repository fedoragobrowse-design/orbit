use orbit_core::{AutonomyMode,OwnerScope,RiskLevel,ToolDescriptor};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum PolicyLayer {Administrator,Owner,Integration,Tool}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct PolicyRule {pub id:Uuid,pub layer:PolicyLayer,pub tool_pattern:String,pub scope_key:Option<String>,pub deny:bool,pub requires_approval:bool,pub requires_sandbox:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ScopeGrant {pub id:Uuid,pub tool_name:String,pub scope_key:String,pub scope_revision:i64,pub max_risk:RiskLevel,pub autonomy_modes:Vec<AutonomyMode>,pub parameter_bounds:Value}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum PolicyOutcome {Allow,Deny,RequireApproval,SandboxOnly}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct PolicyDecision {pub outcome:PolicyOutcome,pub denied:bool,pub requires_approval:bool,pub requires_sandbox:bool,pub matched_rules:Vec<Uuid>,pub policy_revision:i64,pub scope_revisions:BTreeMap<String,i64>,pub reason_codes:Vec<String>}
pub struct PolicyEngine {pub revision:i64,pub autonomy:AutonomyMode,pub rules:Vec<PolicyRule>,pub grants:Vec<ScopeGrant>}
impl PolicyEngine {
 pub fn evaluate(&self,_scope:&OwnerScope,name:&str,args:&Value,descriptor:&ToolDescriptor,risk:RiskLevel,scopes:&BTreeMap<String,i64>)->PolicyDecision{
  let safe_local=matches!(name,"notifications.create"|"reports.save"|"memory.search"|"memory.propose");
  let scoped_default=matches!(name,"files.search"|"files.read"|"files.list"|"files.metadata"|"files.watch"|"email.read"|"email.search"|"email.draft");
  let modifying=matches!(name,"files.write"|"files.move"|"files.copy"|"email.send"|"email.archive"|"email.label"|"shell.execute");
  let explicitly_forbidden=name=="files.delete"||name.starts_with("payments.")||name.starts_with("secrets.")||name.starts_with("host.")||risk==RiskLevel::Forbidden;
  let mut denied=explicitly_forbidden||(!safe_local&&!scoped_default&&!modifying&&!name.starts_with("mcp."));
  let mut reasons=vec!["SYSTEM_DEFAULTS".into()];
  if (scoped_default||modifying||name.starts_with("mcp."))&&scopes.is_empty(){denied=true;reasons.push("EXPLICIT_RESOURCE_SCOPE_REQUIRED".into());}
  let mut approval=modifying||risk>=RiskLevel::High||args.get("consent_required").and_then(Value::as_bool)==Some(true);
  let mut sandbox=descriptor.sandbox_required||name=="shell.execute";
  let mut matched=Vec::new();
  for rule in &self.rules {
   let matches_name=rule.tool_pattern==name||rule.tool_pattern=="*"||rule.tool_pattern.strip_suffix(".*").is_some_and(|prefix|name.starts_with(&format!("{prefix}.")));
   if matches_name&&rule.scope_key.as_ref().is_none_or(|key|scopes.contains_key(key)) {denied|=rule.deny;approval|=rule.requires_approval;sandbox|=rule.requires_sandbox;matched.push(rule.id);}
  }
  // Node/connector admission is an explicit resource grant. Autonomous modifying
  // effects require an additional bounded tool+resource grant, not merely a mode.
  let automatic_grant=!scopes.is_empty()&&scopes.iter().all(|(key,revision)|self.grants.iter().any(|grant|grant.tool_name==name&&grant.scope_key==*key&&grant.scope_revision==*revision&&risk<=grant.max_risk&&grant.autonomy_modes.contains(&self.autonomy)&&bounds_match(&grant.parameter_bounds,args)));
  if name.starts_with("mcp.")&&!automatic_grant {approval=true;}
  if descriptor.effects.external&&descriptor.effects.modifies_data {
   match self.autonomy{
    AutonomyMode::Chat|AutonomyMode::Observe=>{denied=true;reasons.push("AUTONOMY_EXTERNAL_MUTATION_CEILING".into());},
    AutonomyMode::Assist=>approval=true,
    AutonomyMode::TrustedAutomation|AutonomyMode::Custom=>{if !automatic_grant {approval=true;}},
   }
  }
  // A LOW scoped explicit grant can remove only the default low-effect consent,
  // never a layer requirement, ASK-root consent, or HIGH/CRITICAL consent.
  if automatic_grant&&risk<=RiskLevel::Low&&!modifying&&args.get("consent_required").and_then(Value::as_bool)!=Some(true)&&!self.rules.iter().any(|r|matched.contains(&r.id)&&r.requires_approval){approval=false;}
  if explicitly_forbidden {reasons.push("SYSTEM_FORBIDDEN_CAPABILITY".into());}
  if risk>=RiskLevel::High {approval=true;reasons.push("HIGH_RISK_CONSENT_CEILING".into());}
  let outcome=if denied{PolicyOutcome::Deny}else if approval{PolicyOutcome::RequireApproval}else if sandbox{PolicyOutcome::SandboxOnly}else{PolicyOutcome::Allow};
  PolicyDecision{outcome,denied,requires_approval:approval,requires_sandbox:sandbox,matched_rules:matched,policy_revision:self.revision,scope_revisions:scopes.clone(),reason_codes:reasons}
 }
 pub fn permits_proactive_models(&self)->bool{self.autonomy!=AutonomyMode::Chat}
}
/// Bounds are allowlisted exact values or numeric maxima; unspecified parameters
/// are not granted automatically. Identity fields are already bound by scope.
pub fn bounds_match(bounds:&Value,args:&Value)->bool{
 let (Some(bounds),Some(args))=(bounds.as_object(),args.as_object())else{return false};
 !bounds.is_empty()&&args.iter().all(|(key,value)|bounds.get(key).is_some_and(|bound|{
  if let Some(max)=bound.get("maximum").and_then(Value::as_f64){value.as_f64().is_some_and(|v|v<=max&&v>=0.0)}
  else if let Some(values)=bound.get("enum").and_then(Value::as_array){values.contains(value)}else{bound==value}
 }))
}
#[cfg(test)]mod tests{
 use super::*; use orbit_core::ToolEffects;use serde_json::json;
 fn descriptor()->ToolDescriptor{ToolDescriptor{id:Uuid::new_v4(),name:"shell.execute".into(),version:"1".into(),input_schema:json!({}),output_schema:json!({}),effects:ToolEffects{external:true,modifies_data:true,reversible:false,credential_access:false,affected_party:"owner".into(),network:false},default_risk:RiskLevel::High,permission_keys:vec![],sandbox_required:true}}
 #[test]fn deny_wins_and_sandbox_survives_consent(){let scope=OwnerScope{owner_id:Uuid::new_v4(),principal_id:Uuid::new_v4()};let key="aiec:one".into();let scopes=BTreeMap::from([(key,1)]);let mut e=PolicyEngine{revision:1,autonomy:AutonomyMode::Assist,rules:vec![],grants:vec![]};let d=e.evaluate(&scope,"shell.execute",&json!({}),&descriptor(),RiskLevel::High,&scopes);assert!(!d.denied&&d.requires_approval&&d.requires_sandbox);e.rules.push(PolicyRule{id:Uuid::new_v4(),layer:PolicyLayer::Administrator,tool_pattern:"*".into(),scope_key:None,deny:true,requires_approval:false,requires_sandbox:false});let d=e.evaluate(&scope,"shell.execute",&json!({}),&descriptor(),RiskLevel::High,&scopes);assert!(d.denied&&d.requires_approval&&d.requires_sandbox);}
 #[test]fn mode_is_not_permission(){assert!(!bounds_match(&json!({}),&json!({"amount":100})));assert!(!bounds_match(&json!({"limit":{"maximum":5}}),&json!({"limit":6})));}
}
