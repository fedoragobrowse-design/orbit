use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{
        Response,
        sse::{Event as SseEvent, KeepAlive, Sse},
    },
    routing::{get, post},
};
use orbit_core::Error;
use orbit_tools::ToolExecutor;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
};
use uuid::Uuid;

/// Tools the M4 gateway does not exist for yet, so the agent loop executes
/// them in-app: memory reads and writes, and notification/report artifacts.
/// Every other admitted tool waits for a real gateway approval; unadmitted
/// tools (absent from the registry or outside the agent's allow-list) are
/// denied and recorded, never executed.
const IN_APP_TOOLS: [&str; 4] = [
    "memory.search",
    "memory.propose",
    "notifications.create",
    "reports.save",
];

#[derive(Clone)]
pub struct AgentDispatcher {
    pub pool: sqlx::PgPool,
    pub key_dir: PathBuf,
    pub artifact_dir: PathBuf,
}
impl AgentDispatcher {
    pub fn new(state: &ApiState) -> Self {
        Self {
            pool: state.pool.clone(),
            key_dir: state.key_dir.clone(),
            artifact_dir: state.artifact_dir.clone(),
        }
    }
    async fn descriptors_for(
        &self,
        scope: &orbit_core::OwnerScope,
    ) -> Result<Vec<orbit_core::ToolDescriptor>, Error> {
        Ok(
            sqlx::query_scalar(
                "SELECT descriptor FROM tool_registry WHERE owner_id=$1 AND enabled",
            )
            .bind(scope.owner_id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect(),
        )
    }
    /// Policy stub: admission is registry presence plus the agent allow-list and
    /// schema validity. Unadmitted tools deny; admitted ones get the owner policy
    /// decision with no pre-M4 grants bypass.
    async fn admission(
        &self,
        scope: &orbit_core::OwnerScope,
        agent: Uuid,
        name: &str,
        args: &Value,
    ) -> Result<(orbit_core::ToolDescriptor, Value, orbit_core::RiskLevel), Error> {
        let descriptor = self.admission_in_pool(scope, agent, name, args).await?;
        let risk = orbit_risk::RiskClassifier::classify_action(
            &orbit_risk::ProposedAction {
                tool_name: name.into(),
                arguments: args.clone(),
            },
            &descriptor,
            &orbit_risk::ActionContext {
                optional_escalation: None,
            },
        )?
        .level;
        let settings: Value = sqlx::query_scalar("SELECT value FROM settings WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(json!({}));
        let autonomy: orbit_core::AutonomyMode = serde_json::from_value(
            settings
                .get("autonomy_mode")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .unwrap_or(orbit_core::AutonomyMode::Observe);
        let row = sqlx::query("SELECT revision,rules FROM policies WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&self.pool)
            .await?;
        let (revision, rules) = match &row {
            Some(r) => (
                r.get("revision"),
                serde_json::from_value(r.get::<Value, _>("rules")).unwrap_or_default(),
            ),
            None => (1, vec![]),
        };
        let empty_revisions: BTreeMap<String, i64> = BTreeMap::new();
        let decision = orbit_policy::PolicyEngine {
            revision,
            autonomy,
            rules,
            grants: vec![],
        }
        .evaluate(scope, name, args, &descriptor, risk, &empty_revisions);
        if decision.policy_revision != revision {
            return Err(Error::Conflict("policy changed during evaluation".into()));
        }
        Ok((descriptor, serde_json::to_value(&decision)?, risk))
    }
    async fn admission_in_pool(
        &self,
        scope: &orbit_core::OwnerScope,
        agent: Uuid,
        name: &str,
        args: &Value,
    ) -> Result<orbit_core::ToolDescriptor, Error> {
        let definition: Value = sqlx::query_scalar(
            "SELECT definition FROM agent_definitions WHERE owner_id=$1 AND id=$2",
        )
        .bind(scope.owner_id)
        .bind(agent)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::Forbidden)?;
        let allowed: Vec<String> = serde_json::from_value(
            definition
                .get("allowed_tools")
                .cloned()
                .unwrap_or(json!([])),
        )
        .map_err(|_| Error::Forbidden)?;
        if !allowed.iter().any(|t| t == name) {
            return Err(Error::Forbidden);
        }
        let descriptor: Value = sqlx::query_scalar(
            "SELECT descriptor FROM tool_registry WHERE owner_id=$1 AND name=$2 AND enabled",
        )
        .bind(scope.owner_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::Forbidden)?;
        let descriptor: orbit_core::ToolDescriptor =
            serde_json::from_value(descriptor).map_err(|_| Error::Forbidden)?;
        orbit_tools::validate_value(&descriptor.input_schema, args)?;
        Ok(descriptor)
    }
}
#[async_trait::async_trait]
impl orbit_agent_runtime::Dispatcher for AgentDispatcher {
    async fn descriptors(
        &self,
        scope: &orbit_core::OwnerScope,
    ) -> orbit_core::Result<Vec<orbit_core::ToolDescriptor>> {
        self.descriptors_for(scope).await
    }
    async fn context(
        &self,
        scope: &orbit_core::OwnerScope,
        agent: &orbit_agent_runtime::AgentDefinition,
        query: &str,
    ) -> orbit_core::Result<Vec<orbit_core::ContextBlock>> {
        orbit_memory::search_for_agent(&self.pool, scope, agent.id, query).await
    }
    async fn propose(
        &self,
        scope: &orbit_core::OwnerScope,
        task: Uuid,
        agent: Uuid,
        name: &str,
        args: Value,
        proposal_key: &str,
    ) -> orbit_core::Result<Value> {
        let key = proposal_key.to_owned();
        if orbit_core::ContextBlock::looks_like_injection(&args.to_string()){let call=Uuid::new_v4();let hash=orbit_computer_node_protocol::sha256(format!("{task}:{proposal_key}:{name}").as_bytes());let denied=serde_json::to_value(&orbit_policy::PolicyDecision{outcome:orbit_policy::PolicyOutcome::Deny,denied:true,requires_approval:false,requires_sandbox:false,matched_rules:vec![],policy_revision:1,scope_revisions:BTreeMap::new(),reason_codes:vec!["PROMPT_INJECTION_QUARANTINED".into()]})?;let mut tx=self.pool.begin().await?;sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,agent_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'DENIED')").bind(call).bind(scope.owner_id).bind(task).bind(agent).bind(&key).bind(&hash).bind(json!({"tool_name":name,"arguments":args,"denied":"prompt injection quarantined"})).bind(&hash).bind(json!({"name":name,"admitted":false})).bind(&hash).bind(json!({"level":"FORBIDDEN","reasons":["prompt injection quarantined"]})).bind(&denied).execute(&mut *tx).await?;orbit_audit::append(&mut tx,scope,task,None,Some(task),"PROMPT_INJECTION_QUARANTINED","tainted proposal denied before authorization",json!({"call_id":call,"tool_name":name})).await?;tx.commit().await?;return Ok(json!({"call_id":call,"state":"DENIED","proposal_digest":hash}))}
        if let Some(existing)=sqlx::query("SELECT id,state,proposal_digest FROM tool_calls WHERE owner_id=$1 AND task_id=$2 AND proposal_key=$3").bind(scope.owner_id).bind(task).bind(&key).fetch_optional(&self.pool).await?{return Ok(json!({"call_id":existing.get::<Uuid,_>("id"),"state":existing.get::<String,_>("state"),"proposal_digest":existing.get::<String,_>("proposal_digest"),"replayed":true}))}
        let journal = match self.admission(scope, agent, name, &args).await {
            // Policy DENY never parks for approval: it records DENIED with no consent row.
            Ok((descriptor, decision, risk))
                if decision
                    .get("denied")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true) =>
            {
                Err(decision)
            }
            Ok(admitted) => Ok((admitted, None::<()>)),
            Err(_) => Err(serde_json::to_value(&orbit_policy::PolicyDecision {
                outcome: orbit_policy::PolicyOutcome::Deny,
                denied: true,
                requires_approval: false,
                requires_sandbox: false,
                matched_rules: vec![],
                policy_revision: 1,
                scope_revisions: BTreeMap::new(),
                reason_codes: vec!["TOOL_NOT_ADMITTED".into()],
            })?),
        };
        let call = Uuid::new_v4();
        let (
            snapshot_value,
            hash,
            descriptor_value,
            digest,
            risk_value,
            decision_value,
            state,
            expires_at,
        ) = match journal {
            Ok(((descriptor, decision, _risk_level), _)) => {
                let epoch = sqlx::query_scalar::<_, i64>(
                    "SELECT revision FROM authorization_epochs WHERE owner_id=$1",
                )
                .bind(scope.owner_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(Error::Forbidden)?;
                let revision =
                    sqlx::query_scalar::<_, i64>("SELECT revision FROM policies WHERE owner_id=$1")
                        .bind(scope.owner_id)
                        .fetch_optional(&self.pool)
                        .await?
                        .unwrap_or(1);
                let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
                let snapshot = orbit_core::ActionSnapshot {
                    action_id: call,
                    owner_id: scope.owner_id,
                    principal_id: scope.principal_id,
                    agent_id: Some(agent),
                    task_id: task,
                    tool_name: name.into(),
                    tool_version: descriptor.version.clone(),
                    arguments: args.clone(),
                    input_artifact_digests: BTreeMap::new(),
                    scope_revisions: BTreeMap::new(),
                    policy_revision: revision,
                    authorization_epoch: epoch,
                    requires_sandbox: descriptor.sandbox_required,
                    expires_at,
                };
                let hash = orbit_approvals::canonical_hash(&snapshot)?;
                let descriptor_value = serde_json::to_value(&descriptor)?;
                let digest =
                    orbit_computer_node_protocol::sha256(&serde_json::to_vec(&descriptor)?);
                let risk = orbit_risk::RiskClassifier::classify_action(
                    &orbit_risk::ProposedAction {
                        tool_name: name.into(),
                        arguments: args.clone(),
                    },
                    &descriptor,
                    &orbit_risk::ActionContext {
                        optional_escalation: None,
                    },
                )?;
                let state = if IN_APP_TOOLS.contains(&name) {
                    "PROPOSED"
                } else {
                    "WAITING_FOR_APPROVAL"
                };
                (
                    serde_json::to_value(&snapshot)?,
                    hash,
                    descriptor_value,
                    digest,
                    serde_json::to_value(&risk)?,
                    decision,
                    state,
                    Some(expires_at),
                )
            }
            // Denied tools (unadmitted or policy-denied) record DENIED before any effect exists.
            Err(denied) => {
                let hash =
                    orbit_computer_node_protocol::sha256(format!("{task}:{key}:{name}").as_bytes());
                (
                    json!({"tool_name":name,"arguments":args,"denied":"tool is not admitted for this agent"}),
                    hash.clone(),
                    json!({"name":name,"admitted":false}),
                    hash,
                    json!({"level":"FORBIDDEN","reasons":["tool is not admitted for this agent"]}),
                    denied,
                    "DENIED",
                    None,
                )
            }
        };
        if state == "WAITING_FOR_APPROVAL" {
            // Gateway-owned consent: the approval row and its call binding are created
            // atomically so `approve` can always resolve the snapshot it must verify.
            let approval = Uuid::new_v4();
            let preview = orbit_approvals::preview(&serde_json::from_value::<
                orbit_core::ActionSnapshot,
            >(snapshot_value.clone())?);
            let mut tx = self.pool.begin().await?;
            sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,agent_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state,approval_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
    .bind(call).bind(scope.owner_id).bind(task).bind(agent).bind(&key).bind(&hash).bind(&snapshot_value).bind(&hash).bind(&descriptor_value).bind(&digest).bind(&risk_value).bind(&decision_value).bind(state).bind(approval).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO approvals(id,owner_id,task_id,call_id,snapshot,action_hash,risk,reasons,preview,policy_decision,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
    .bind(approval).bind(scope.owner_id).bind(task).bind(call).bind(&snapshot_value).bind(&hash).bind(&risk_value).bind(json!([risk_value.get("reasons")])).bind(&preview).bind(&decision_value).bind(expires_at).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(
                json!({"call_id":call,"state":state,"proposal_digest":hash,"approval_id":approval}),
            );
        }
        sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,agent_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
   .bind(call).bind(scope.owner_id).bind(task).bind(agent).bind(&key).bind(&hash).bind(&snapshot_value).bind(&hash).bind(&descriptor_value).bind(&digest).bind(&risk_value).bind(&decision_value).bind(state).execute(&self.pool).await?;
        Ok(json!({"call_id":call,"state":state,"proposal_digest":hash}))
    }
    async fn submit(
        &self,
        scope: &orbit_core::OwnerScope,
        task: Uuid,
        worker: Uuid,
        fence: i64,
    ) -> Result<Vec<Value>, Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
            .bind(scope.owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let task_row=sqlx::query("SELECT state,lease_holder,lease_until,fence FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(scope.owner_id).bind(task).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
        let lease_live =
            match task_row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("lease_until") {
                Some(until) => until > chrono::Utc::now(),
                None => false,
            };
        if task_row.get::<String, _>("state") != "RUNNING"
            || task_row.get::<Option<Uuid>, _>("lease_holder") != Some(worker)
            || !lease_live
            || task_row.get::<i64, _>("fence") != fence
        {
            return Err(Error::Conflict("agent lease or fence changed".into()));
        }
        let agent: Uuid =
            sqlx::query_scalar("SELECT agent_id FROM agent_runs WHERE owner_id=$1 AND task_id=$2")
                .bind(scope.owner_id)
                .bind(task)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(Error::NotFound)?;
        // Gateway-approved resume: `approve` parks the task at DISPATCH with a fresh
        // authorization, so SUBMITTED in-app calls execute here under the same lease
        // and fence checks. Consent never removes the sandbox requirement, and only
        // IN_APP_TOOLS run inside the agent worker; anything else stays parked for
        // the out-of-band executor that owns its sandbox or node session.
        let mut resumed = vec![];
        for call in sqlx::query("SELECT id,authorization_id,snapshot->>'tool_name' AS tool,snapshot FROM tool_calls WHERE owner_id=$1 AND task_id=$2 AND state='SUBMITTED' AND authorization_id IS NOT NULL ORDER BY submitted_at FOR UPDATE").bind(scope.owner_id).bind(task).fetch_all(&mut *tx).await?{
   let id:Uuid=call.get("id");let authorization:Uuid=call.get("authorization_id");let name:String=call.get("tool");
   if !IN_APP_TOOLS.contains(&name.as_str()){continue}
   if call.get::<Value,_>("snapshot").get("requires_sandbox").and_then(Value::as_bool).unwrap_or(true){continue}
   tx.commit().await?;
   let outcome=self.execute_call(scope,task,agent,id,authorization,fence).await?;
   resumed.push(outcome);tx=self.pool.begin().await?;
   sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(scope.owner_id).fetch_one(&mut *tx).await?;
  }
        let calls=sqlx::query("SELECT id,snapshot FROM tool_calls WHERE owner_id=$1 AND task_id=$2 AND state='PROPOSED' ORDER BY created_at FOR UPDATE").bind(scope.owner_id).bind(task).fetch_all(&mut *tx).await?;
        if calls.is_empty() && resumed.is_empty() {
            tx.commit().await?;
            return Ok(vec![]);
        }
        let mut queued = vec![];
        for call in &calls {
            let id: Uuid = call.get("id");
            let snapshot: Value = call.get("snapshot");
            let name = snapshot
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let args = snapshot.get("arguments").cloned().unwrap_or(json!({}));
            if !IN_APP_TOOLS.contains(&name.as_str()) {
                sqlx::query("UPDATE tool_calls SET state='WAITING_FOR_APPROVAL' WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).execute(&mut *tx).await?;
                queued.push(json!({"call_id":id,"state":"WAITING_FOR_APPROVAL"}));
                continue;
            }
            // Re-verify admission, schema, and the registry row under the epoch and call locks.
            let descriptor=sqlx::query("SELECT descriptor FROM tool_registry WHERE owner_id=$1 AND name=$2 AND enabled FOR UPDATE").bind(scope.owner_id).bind(&name).fetch_optional(&mut *tx).await?;
            let admitted = match &descriptor {
                Some(d) => {
                    let desc: orbit_core::ToolDescriptor =
                        serde_json::from_value(d.get::<Value, _>("descriptor"))
                            .map_err(|_| Error::Forbidden)?;
                    orbit_tools::validate_value(&desc.input_schema, &args).is_ok()
                }
                None => false,
            };
            let definition: Value = sqlx::query_scalar(
                "SELECT definition FROM agent_definitions WHERE owner_id=$1 AND id=$2",
            )
            .bind(scope.owner_id)
            .bind(agent)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Forbidden)?;
            let allowed: Vec<String> = serde_json::from_value(
                definition
                    .get("allowed_tools")
                    .cloned()
                    .unwrap_or(json!([])),
            )
            .map_err(|_| Error::Forbidden)?;
            if !admitted || !allowed.iter().any(|t| t == &name) {
                sqlx::query("UPDATE tool_calls SET state='DENIED' WHERE owner_id=$1 AND id=$2")
                    .bind(scope.owner_id)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                queued.push(json!({"call_id":id,"state":"DENIED"}));
                continue;
            }
            let authorization = Uuid::new_v4();
            let affected=sqlx::query("UPDATE tool_calls SET state='SUBMITTED',authorization_id=$3,task_fence=$4,submitted_at=now(),dispatch_holder=$5 WHERE owner_id=$1 AND id=$2 AND state='PROPOSED'").bind(scope.owner_id).bind(id).bind(authorization).bind(fence).bind(worker).execute(&mut *tx).await?.rows_affected();
            if affected == 0 {
                continue;
            }
            queued.push(json!({"call_id":id,"state":"SUBMITTED","authorization_id":authorization}));
        }
        tx.commit().await?;
        let mut states = resumed;
        for s in queued {
            if s["state"] != "SUBMITTED" {
                states.push(s);
                continue;
            }
            let id = s["call_id"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(Uuid::nil);
            let authorization = s["authorization_id"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(Uuid::nil);
            states.push(
                self.execute_call(scope, task, agent, id, authorization, fence)
                    .await?,
            );
        }
        Ok(states)
    }
}
impl AgentDispatcher {
    async fn execute_call(
        &self,
        scope: &orbit_core::OwnerScope,
        task: Uuid,
        agent: Uuid,
        id: Uuid,
        authorization: Uuid,
        fence: i64,
    ) -> Result<Value, Error> {
        let outcome = self
            .execute_authorized(scope, task, agent, id, authorization, fence)
            .await;
        let (state, result, code) = match &outcome {
            Ok(value) => ("COMPLETED", value.clone(), None),
            Err(Error::OutcomeUnknown) => (
                "OUTCOME_UNKNOWN",
                json!({"error":"effect outcome is unknown"}),
                Some("OUTCOME_UNKNOWN".to_owned()),
            ),
            Err(error) => (
                "FAILED",
                json!({"error":error.to_string()}),
                Some(
                    match error {
                        Error::Unauthorized => "UNAUTHORIZED",
                        Error::Forbidden => "FORBIDDEN",
                        Error::NotFound => "NOT_FOUND",
                        Error::Validation(_) => "VALIDATION",
                        Error::Conflict(_) => "CONFLICT",
                        Error::Unavailable(_) => "UNAVAILABLE",
                        _ => "INTERNAL",
                    }
                    .to_owned(),
                ),
            ),
        };
        sqlx::query("UPDATE tool_calls SET state=$4,result=$5,error_code=$6,completed_at=now() WHERE owner_id=$1 AND id=$2 AND authorization_id=$3 AND state='SUBMITTED'").bind(scope.owner_id).bind(id).bind(authorization).bind(state).bind(&result).bind(&code).execute(&self.pool).await?;
        Ok(json!({"call_id":id,"state":state}))
    }
    async fn execute_authorized(
        &self,
        scope: &orbit_core::OwnerScope,
        task: Uuid,
        agent: Uuid,
        id: Uuid,
        authorization: Uuid,
        fence: i64,
    ) -> Result<Value, Error> {
        let row=sqlx::query("SELECT snapshot,action_hash,descriptor FROM tool_calls WHERE owner_id=$1 AND id=$2 AND state='SUBMITTED'").bind(scope.owner_id).bind(id).fetch_optional(&self.pool).await?.ok_or(Error::Forbidden)?;
        let snapshot: orbit_core::ActionSnapshot =
            serde_json::from_value(row.get::<Value, _>("snapshot"))
                .map_err(|_| Error::Forbidden)?;
        if snapshot.action_id != id
            || snapshot.task_id != task
            || snapshot.agent_id != Some(agent)
            || orbit_approvals::canonical_hash(&snapshot)? != row.get::<String, _>("action_hash")
        {
            return Err(Error::Forbidden);
        }
        let descriptor: orbit_core::ToolDescriptor =
            serde_json::from_value(row.get::<Value, _>("descriptor"))
                .map_err(|_| Error::Forbidden)?;
        if snapshot.tool_name != descriptor.name || snapshot.tool_version != descriptor.version {
            return Err(Error::Forbidden);
        }
        let action = orbit_core::AuthorizedAction::from_submission(snapshot, authorization, fence);
        match descriptor.name.as_str() {
            "memory.search" | "memory.propose" => {
                orbit_memory::execute_authorized(&self.pool, &self.key_dir, scope, &action).await
            }
            _ => Ok(orbit_tools::SafeTools {
                pool: self.pool.clone(),
                artifact_dir: self.artifact_dir.clone(),
            }
            .execute(scope, action)
            .await?
            .output),
        }
    }
}

/// Register the in-app tools the agent loop may execute directly so admission
/// never denies a seeded agent for a missing registry row. Rows carry the
/// namespaced provider identity the gateway schema requires; reseeding is an
/// idempotent upsert, never a duplicate row.
pub async fn seed_agent_tools(state: &ApiState) -> orbit_core::Result<()> {
    let owners: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM users")
        .fetch_all(&state.pool)
        .await?;
    let catalog: Vec<orbit_core::ToolDescriptor> = orbit_tools::descriptors()
        .into_iter()
        .chain(orbit_memory::descriptors())
        .collect();
    for owner in owners {
        for d in &catalog {
            let digest = orbit_computer_node_protocol::sha256(&serde_json::to_vec(&d)?);
            sqlx::query("INSERT INTO tool_registry(id,owner_id,name,version,descriptor,descriptor_digest,provider_name,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT(owner_id,name) DO UPDATE SET version=EXCLUDED.version,descriptor=EXCLUDED.descriptor,descriptor_digest=EXCLUDED.descriptor_digest,provider_name=EXCLUDED.provider_name,enabled=true")
   .bind(d.id).bind(owner).bind(&d.name).bind(&d.version).bind(serde_json::to_value(&d)?).bind(&digest).bind(orbit_tools::provider_name(d.id)).execute(&state.pool).await?;
        }
    }
    Ok(())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentCreate {
    pub agent: Option<orbit_agent_runtime::AgentInput>,
    pub clone_from: Option<Uuid>,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPatch {
    pub agent: Option<orbit_agent_runtime::AgentInput>,
    pub enabled: Option<bool>,
}
async fn agent_row(
    state: &ApiState,
    scope: &orbit_core::OwnerScope,
    id: Uuid,
) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query(
        "SELECT id,revision,enabled,definition FROM agent_definitions WHERE owner_id=$1 AND id=$2",
    )
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(Error::NotFound)?;
    Ok(Json(
        json!({"id":row.get::<Uuid,_>("id"),"revision":row.get::<i64,_>("revision"),"enabled":row.get::<bool,_>("enabled"),"definition":row.get::<Value,_>("definition")}),
    ))
}
#[utoipa::path(get,path="/api/v1/agents",responses((status=200,body=Value)))]
pub async fn list_agents(State(s): State<ApiState>, h: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, false).await?;
    Ok(Json(
        json!({"items":sqlx::query_scalar::<_,Value>("SELECT definition||jsonb_build_object('id',id,'revision',revision,'enabled',enabled) FROM agent_definitions WHERE owner_id=$1 ORDER BY definition->>'name' LIMIT 200").bind(a.scope.owner_id).fetch_all(&s.pool).await?,"next_cursor":null}),
    ))
}
#[utoipa::path(post,path="/api/v1/agents",responses((status=200,body=Value)))]
pub async fn create_agent(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(input): Json<AgentCreate>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, true).await?;
    let definition = match (input.agent, input.clone_from) {
        (Some(agent), _) => {
            agent.validate()?;
            serde_json::to_value(agent)
                .map_err(|_| Error::Unavailable("agent definition failed to serialize".into()))?
        }
        (None, Some(from)) => sqlx::query_scalar(
            "SELECT definition FROM agent_definitions WHERE owner_id=$1 AND id=$2",
        )
        .bind(a.scope.owner_id)
        .bind(from)
        .fetch_optional(&s.pool)
        .await?
        .ok_or(Error::NotFound)?,
        (None, None) => {
            return Err(Error::Validation("agent definition or clone_from required".into()).into());
        }
    };
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_definitions(id,owner_id,revision,enabled,definition) VALUES($1,$2,1,true,$3)").bind(id).bind(a.scope.owner_id).bind(&definition).execute(&s.pool).await?;
    Ok(Json(json!({"id":id})))
}
#[utoipa::path(get,path="/api/v1/agents/{id}",responses((status=200,body=Value)))]
pub async fn agent_detail(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, false).await?;
    agent_row(&s, &a.scope, id).await
}
#[utoipa::path(put,path="/api/v1/agents/{id}",responses((status=200,body=Value)))]
pub async fn update_agent(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(patch): Json<AgentPatch>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, true).await?;
    sqlx::query("SELECT id FROM agent_definitions WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_one(&s.pool)
        .await?;
    if let Some(enabled) = patch.enabled {
        sqlx::query("UPDATE agent_definitions SET enabled=$3,revision=revision+1 WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).bind(enabled).execute(&s.pool).await?;
        return agent_row(&s, &a.scope, id).await;
    }
    let input = patch
        .agent
        .ok_or(Error::Validation("agent definition required".into()))?;
    input.validate()?;
    sqlx::query("UPDATE agent_definitions SET definition=$3,revision=revision+1 WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).bind(serde_json::to_value(input).map_err(|_|Error::Unavailable("agent definition failed to serialize".into()))?).execute(&s.pool).await?;
    agent_row(&s, &a.scope, id).await
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChatPost {
    pub conversation_id: Option<Uuid>,
    pub agent_id: Option<Uuid>,
    pub message: String,
    pub attachments: Option<Vec<Uuid>>,
}
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ChatPage {
    pub conversation_id: Uuid,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct UploadQuery {
    pub filename: String,
    pub content_type: Option<String>,
}
/// Task-backed chat: the user message is journaled as an event plus a
/// transcript row, and a QUEUED `agents`-consumer task owns the agent run.
/// Without a configured provider the run waits with WAITING_FOR_RESOURCE;
/// this endpoint never fabricates model output.
#[utoipa::path(post,path="/api/v1/chat/messages",responses((status=200,body=Value)))]
pub async fn post_message(
    State(s): State<ApiState>,
    h: HeaderMap,
    Json(input): Json<ChatPost>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, true).await?;
    if input.message.trim().is_empty() || input.message.len() > 32768 {
        return Err(Error::Validation("message must be 1-32768 characters".into()).into());
    }
    let agent=input.agent_id.map(Ok::<_,Error>).transpose()?
  .or(sqlx::query_scalar("SELECT id FROM agent_definitions WHERE owner_id=$1 AND enabled ORDER BY definition->>'name' LIMIT 1").bind(a.scope.owner_id).fetch_optional(&s.pool).await?)
  .ok_or(Error::Unavailable("no enabled agent; configure one before chatting".into()))?;
    let stored: Value = sqlx::query_scalar(
        "SELECT definition FROM agent_definitions WHERE owner_id=$1 AND id=$2 AND enabled",
    )
    .bind(a.scope.owner_id)
    .bind(agent)
    .fetch_optional(&s.pool)
    .await?
    .ok_or(Error::Unavailable("selected agent is not enabled".into()))?;
    let definition = orbit_agent_runtime::AgentDefinition {
        id: agent,
        owner_id: a.scope.owner_id,
        config: serde_json::from_value(stored)
            .map_err(|_| Error::Validation("stored agent definition is invalid".into()))?,
        revision: 1,
    };
    let conversation = input
        .conversation_id
        .map(Ok::<_, Error>)
        .unwrap_or_else(|| Ok(Uuid::new_v4()))?;
    sqlx::query("INSERT INTO conversations(id,owner_id,agent_id,title) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(conversation).bind(a.scope.owner_id).bind(agent).bind(input.message.chars().take(80).collect::<String>()).execute(&s.pool).await?;
    sqlx::query("SELECT id FROM conversations WHERE owner_id=$1 AND id=$2 AND agent_id=$3")
        .bind(a.scope.owner_id)
        .bind(conversation)
        .bind(agent)
        .fetch_one(&s.pool)
        .await?;
    let files = input.attachments.clone().unwrap_or_default();
    for file in &files {
        orbit_agent_runtime::attachments::read(&s.pool, &s.artifact_dir, &a.scope, *file).await?;
    }
    let task = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let event:Uuid=sqlx::query_scalar("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,'USER_MESSAGE','chat',$3,$4,'OWNER_AUTHENTICATED','PRIVATE',$5,$6) ON CONFLICT(owner_id,source,source_event_key) DO UPDATE SET source_event_key=EXCLUDED.source_event_key RETURNING id")
  .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(a.scope.principal_id).bind(json!({"conversation_id":conversation,"agent_id":agent,"text":input.message,"attachments":files})).bind(correlation).bind(format!("chat:{task}")).fetch_one(&s.pool).await?;
    let checkpoint = json!({"phase":"CONTEXT","agent_id":agent,"conversation_id":conversation,"depth":0,"automatic":false,"affected_files":files});
    sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,event_id,title,consumer,checkpoint,state) VALUES($1,$2,$3,$4,$5,$6,'agents',$7,'QUEUED')")
  .bind(task).bind(a.scope.owner_id).bind(a.scope.principal_id).bind(correlation).bind(event).bind(input.message.chars().take(120).collect::<String>()).bind(&checkpoint).execute(&s.pool).await?;
    // The worker bootstraps the same run idempotently; recording it here makes
    // the task-backed run visible the moment the message is accepted.
    sqlx::query("INSERT INTO agent_runs(task_id,owner_id,agent_id,conversation_id,definition,depth,automatic) VALUES($1,$2,$3,$4,$5,0,false) ON CONFLICT DO NOTHING")
  .bind(task).bind(a.scope.owner_id).bind(agent).bind(conversation).bind(json!(definition)).execute(&s.pool).await?;
    sqlx::query("INSERT INTO chat_messages(id,owner_id,task_id,conversation_id,turn_key,role,content,attachments) VALUES($1,$2,$3,$4,$5,'user',$6,$7)")
  .bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(task).bind(conversation).bind(format!("user:{task}")).bind(&input.message).bind(json!(files)).execute(&s.pool).await?;
    Ok(Json(
        json!({"conversation_id":conversation,"task_id":task,"agent_id":agent}),
    ))
}
#[utoipa::path(get,path="/api/v1/chat/messages",responses((status=200,body=Value)))]
pub async fn chat_messages(
    State(s): State<ApiState>,
    h: HeaderMap,
    Query(p): Query<ChatPage>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, false).await?;
    let limit = p.limit.unwrap_or(50).clamp(1, 200);
    let cursor = p.cursor.as_deref().and_then(|c| Uuid::parse_str(c).ok());
    let (since, since_id) = match cursor {
        Some(id) => {
            let r = sqlx::query("SELECT created_at FROM chat_messages WHERE owner_id=$1 AND id=$2")
                .bind(a.scope.owner_id)
                .bind(id)
                .fetch_optional(&s.pool)
                .await?
                .ok_or(Error::Validation("unknown chat cursor".into()))?;
            (r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"), id)
        }
        None => (chrono::DateTime::<chrono::Utc>::MAX_UTC, Uuid::nil()),
    };
    let rows=sqlx::query("SELECT id,task_id,role,content,attachments,created_at FROM chat_messages WHERE owner_id=$1 AND conversation_id=$2 AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT $5").bind(a.scope.owner_id).bind(p.conversation_id).bind(since).bind(since_id).bind(limit+1).fetch_all(&s.pool).await?;
    let mut items:Vec<Value>=rows.iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"task_id":r.get::<Option<Uuid>,_>("task_id"),"role":r.get::<String,_>("role"),"content":r.get::<String,_>("content"),"attachments":r.get::<Value,_>("attachments"),"created_at":r.get::<chrono::DateTime<chrono::Utc>,_>("created_at")})).collect();
    let next = if items.len() as i64 > limit {
        items.pop();
        items
            .last()
            .and_then(|v| v["id"].as_str().map(str::to_owned))
    } else {
        None
    };
    Ok(Json(json!({"items":items,"next_cursor":next})))
}
#[utoipa::path(get,path="/api/v1/chat/stream",responses((status=200)))]
pub async fn chat_stream(
    State(s): State<ApiState>,
    h: HeaderMap,
    Query(p): Query<ChatPage>,
) -> Result<
    Sse<impl futures_util::Stream<Item = Result<SseEvent, std::convert::Infallible>>>,
    ApiError,
> {
    let a = authenticate(&s, &h, false).await?;
    let session = a.session_id;
    let owner = a.scope.owner_id;
    let conversation = p.conversation_id;
    let stream = async_stream::stream! {let mut seen=HashSet::new();loop{
     if !matches!(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM sessions WHERE owner_id=$1 AND id=$2 AND expires_at>now())").bind(owner).bind(session).fetch_one(&s.pool).await,Ok(true)){break}
     match sqlx::query("SELECT id,task_id,role,content,attachments FROM chat_messages WHERE owner_id=$1 AND conversation_id=$2 ORDER BY created_at,id LIMIT 200").bind(owner).bind(conversation).fetch_all(&s.pool).await{
      Ok(rows)=>{let mut fresh=false;for r in &rows{let id:Uuid=r.get("id");if seen.insert(id){fresh=true;yield Ok(SseEvent::default().id(id.to_string()).event("message").data(json!({"id":id,"task_id":r.get::<Option<Uuid>,_>("task_id"),"role":r.get::<String,_>("role"),"content":r.get::<String,_>("content"),"attachments":r.get::<Value,_>("attachments")}).to_string()))}}if fresh{continue}},Err(_)=>break}
     match sqlx::query("SELECT state FROM tasks WHERE owner_id=$1 AND checkpoint->>'conversation_id'=$2 ORDER BY created_at DESC LIMIT 1").bind(owner).bind(conversation.to_string()).fetch_optional(&s.pool).await{Ok(Some(r))=>{let state:String=r.get("state");if matches!(state.as_str(),"COMPLETED"|"FAILED"|"TIMED_OUT"|"CANCELLED"){yield Ok(SseEvent::default().event("done").data(json!({"state":state}).to_string()));break}},Ok(None)=>{},Err(_)=>break}
     tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }};
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
#[utoipa::path(post,path="/api/v1/chat/attachments",responses((status=200,body=Value)))]
pub async fn upload_attachment(
    State(s): State<ApiState>,
    h: HeaderMap,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, true).await?;
    let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024).await.map_err(|_| Error::Validation("attachment body unreadable".into()))?;
    let quarantined = orbit_email::quarantine_store(&q.filename, q.content_type.as_deref().unwrap_or("application/octet-stream"), &bytes)?;
    Ok(Json(orbit_agent_runtime::attachments::upload(&s.pool, &s.artifact_dir, &a.scope, &quarantined.name, &quarantined.mime, &bytes).await?))
}
#[utoipa::path(get,path="/api/v1/chat/attachments/{id}",responses((status=200)))]
pub async fn download_attachment(
    State(s): State<ApiState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let a = authenticate(&s, &h, false).await?;
    let (name, bytes, _) =
        orbit_agent_runtime::attachments::read(&s.pool, &s.artifact_dir, &a.scope, id).await?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        )
        .body(Body::from(bytes))
        .map_err(|_| ApiError(Error::Unavailable("attachment response failed".into())))?)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_agents,
        create_agent,
        agent_detail,
        update_agent,
        post_message,
        chat_messages,
        chat_stream,
        upload_attachment,
        download_attachment
    ),
    components(schemas(orbit_agent_runtime::AgentInput))
)]
pub struct OpenApi;
pub async fn openapi() -> Json<Value> {
    use utoipa::OpenApi as _;
    Json(serde_json::to_value(OpenApi::openapi()).expect("OpenAPI serializes"))
}
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/agents", get(list_agents).post(create_agent))
        .route("/api/v1/agents/{id}", get(agent_detail).put(update_agent))
        .route(
            "/api/v1/chat/messages",
            get(chat_messages).post(post_message),
        )
        .route("/api/v1/chat/stream", get(chat_stream))
        .route("/api/v1/chat/attachments", post(upload_attachment))
        .route("/api/v1/chat/attachments/{id}", get(download_attachment))
}
