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
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::BTreeMap,
    path::PathBuf,
};
use uuid::Uuid;

/// A tool name is registry-routable when the [`ExecutorRegistry`] can dispatch
/// it to a real executor: memory tools, notification/report artifacts,
/// `orbit-control.*`/`orbit-data.*`/`ha-control.*` builtins, external `mcp.*`
/// tools, computer `files.*` tools (which report `TOOL_EXECUTOR_UNAVAILABLE`
/// until the node gateway wires in), and `shell.execute`. Routable tools park
/// in `PROPOSED` for the `submit` loop to execute; anything else admitted but
/// not yet executable waits for a real gateway approval. Unadmitted tools
/// (absent from the registry or outside the agent's allow-list) are denied
/// and recorded, never executed.
fn is_registry_routable(name: &str) -> bool {
    matches!(name, "memory.search" | "memory.propose" | "notifications.create" | "reports.save" | "shell.execute")
        || name.starts_with("orbit-control.")
        || name.starts_with("orbit-data.")
        || name.starts_with("ha-control.")
        || name.starts_with("files.")
        || name.starts_with("mcp.")
}
/// Extract command text from tool args carrying `command` (string or array) or
/// `argv`. Returns `None` when the proposal carries no command text.
fn command_argv(args: &Value) -> Option<Vec<String>> {
    if let Some(argv) = args.get("argv").and_then(Value::as_array) {
        let v: Vec<String> = argv.iter().filter_map(|a| a.as_str().map(str::to_owned)).collect();
        if !v.is_empty() { return Some(v); }
    }
    match args.get("command") {
        Some(Value::String(s)) if !s.is_empty() => Some(vec![s.clone()]),
        Some(Value::Array(a)) => {
            let v: Vec<String> = a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect();
            if v.is_empty() { None } else { Some(v) }
        }
        _ => None,
    }
}

/// Journal-input admission for non-loop callers (gateway `execute_action`):
/// runs the shared registry + schema + risk + policy pipeline with the
/// owner's enabled registry as the grant set, without an agent definition
/// row. Discovery already resolved the id against the live catalog; this
/// re-verifies the registry row and schema here so execute enforces grants
/// even if the catalog changed between search and execute.
pub async fn journal_proposal(
    pool: &sqlx::PgPool,
    scope: &orbit_core::OwnerScope,
    task: uuid::Uuid,
    name: &str,
    args: serde_json::Value,
    proposal_key: &str,
) -> orbit_core::Result<(serde_json::Value, String, serde_json::Value, String, serde_json::Value, serde_json::Value, String)> {
    AgentDispatcher { pool: pool.clone(), key_dir: std::path::PathBuf::new(), artifact_dir: std::path::PathBuf::new(), origin: String::new() }
        .journal_gateway_proposal(scope, task, name, args, proposal_key)
        .await
}
#[derive(Clone)]
pub struct AgentDispatcher {
    pub pool: sqlx::PgPool,
    pub key_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub origin: String,
}
impl AgentDispatcher {
    pub fn new(state: &ApiState) -> Self {
        Self { pool: state.pool.clone(), key_dir: state.key_dir.clone(), artifact_dir: state.artifact_dir.clone(), origin: state.origin.clone() }
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
        // Same Jev destructive-bash verdict the backends run on runner commands:
        // any tool proposal carrying command text is Denied on Block, before policy.
        if let Some(argv) = command_argv(args) {
            if orbit_sandbox_dispatch::decide_with_threshold(&argv, 0.8).verdict == orbit_sandbox_dispatch::Verdict::Block {
                return Err(Error::Forbidden);
            }
        }
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
        // Owner-scoped grants bound this tool: load only this tool's rows so the
        // engine can clear default low-effect consent exactly where the owner
        // granted it, following the computer gateway's scoped admission pattern.
        // Rows omit owner_id; malformed rows are skipped, never granted.
        let grants: Vec<orbit_policy::ScopeGrant> = sqlx::query_scalar(
            "SELECT to_jsonb(g)-'owner_id' FROM scope_grants g WHERE owner_id=$1 AND tool_name=$2",
        )
        .bind(scope.owner_id)
        .bind(name)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect();
        let scope_revisions: BTreeMap<String, i64> = grants
            .iter()
            .map(|grant| (grant.scope_key.clone(), grant.scope_revision))
            .collect();
        let mut decision = orbit_policy::PolicyEngine {
            revision,
            autonomy,
            rules,
            grants,
        }
        .evaluate(scope, name, args, &descriptor, risk, &scope_revisions);
        if decision.policy_revision != revision {
            return Err(Error::Conflict("policy changed during evaluation".into()));
        }
        // Sandbox opt-out (default off): when the owner disabled the sandbox,
        // the journaled decision carries SANDBOX_DISABLED so every admitted
        // interaction records the gate state. Admission itself is unchanged:
        // still Jev-gated on command text plus policy-checked, without AIec.
        if !settings.get("sandbox_enabled").and_then(Value::as_bool).unwrap_or(false) && !decision.reason_codes.iter().any(|c| c == "SANDBOX_DISABLED") {
            decision.reason_codes.push("SANDBOX_DISABLED".into());
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
        {
        let mut blocks = orbit_memory::search_for_agent(&self.pool, scope, agent.id, query).await?;
        let selected: Vec<String> = agent.config.skills.clone();
        if !selected.is_empty() {
            let (resolved, problems) = crate::skills::load_for_agent(&self.pool, scope, &selected).await;
            for s in &resolved {
                let extra: Vec<String> = s.requested_actions.iter().filter(|a| !agent.config.allowed_tools.iter().any(|t| t == *a)).cloned().collect();
                if !extra.is_empty() {
                    blocks.push(orbit_core::ContextBlock {
                        kind: orbit_core::ContextKind::ToolOutput,
                        text_or_reference: format!("Skill {} requests actions outside this agent's tools ({}); those requests are ignored", s.name, extra.join(", ")),
                        privacy_class: orbit_core::PrivacyClass::Private,
                        trust_level: orbit_core::TrustLevel::UntrustedExternal,
                        source_reference: format!("skill:{}", s.name),
                    });
                }
            }
            blocks.extend(crate::skills::context_blocks(&resolved, &problems));
        }
        Ok(blocks)
    }
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
                let state = if is_registry_routable(name) {
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
            let push_state = crate::ApiState { pool: self.pool.clone(), origin: self.origin.clone(), key_dir: self.key_dir.clone(), artifact_dir: self.artifact_dir.clone(), nodes: crate::computers::NodeHub::default() };
            crate::push::enqueue_approval_push(&push_state, scope, approval, &preview).await;
            return Ok(json!({"call_id":call,"state":state,"proposal_digest":hash,"approval_id":approval}));
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
        // Sandbox opt-out (default off): the per-owner sandbox_enabled setting
        // gates AIec use per interaction. When off, admitted tools run direct
        // (still Jev-gated at admission plus policy-checked); when on,
        // requires_sandbox snapshots stay parked for the out-of-band executor
        // Gateway-approved resume: `approve` parks the task at DISPATCH with a fresh
        // authorization, so SUBMITTED calls execute here under the same lease
        // and fence checks. Every SUBMITTED call — immediately permitted or
        // approved — routes through the ExecutorRegistry; registry-routed
        // names without an executor report TOOL_EXECUTOR_UNAVAILABLE, never
        // an invented completion.
        let mut resumed = vec![];
        for call in sqlx::query("SELECT id,authorization_id,snapshot FROM tool_calls WHERE owner_id=$1 AND task_id=$2 AND state='SUBMITTED' AND authorization_id IS NOT NULL ORDER BY submitted_at FOR UPDATE").bind(scope.owner_id).bind(task).fetch_all(&mut *tx).await?{
   let id:Uuid=call.get("id");let authorization:Uuid=call.get("authorization_id");
   if call.get::<Value,_>("snapshot").get("requires_sandbox").and_then(Value::as_bool).unwrap_or(true){continue}
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
            // All admitted PROPOSED names route through the registry at
            // execution; the approval detour is gone. Unadmitted names deny
            // in the re-verification below.
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
        // Park path: the executor already recorded the OPEN question and
        // moved the task RUNNING -> WAITING_FOR_INPUT. Report the parked
        // state and return WITHOUT settling the call — settlement belongs
        // to control.rs answer/cancel, which re-queues the same run.
        if let Err(Error::AskOwnerParked(output)) = &outcome {
            return Ok(json!({"call_id":id,"state":"WAITING_FOR_INPUT","question_id":output.get("question_id")}));
        }
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
        let sandboxed: bool = sqlx::query_scalar("SELECT COALESCE((value->>'sandbox_enabled')::boolean, false) FROM settings WHERE owner_id=$1").bind(scope.owner_id).fetch_optional(&self.pool).await?.unwrap_or(false);
        if !sandboxed {
            let cid: Uuid = sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(task).fetch_one(&self.pool).await?;
            let mut tx = self.pool.begin().await?;
            orbit_audit::append(&mut tx, scope, cid, None, Some(task), "TOOL_EXECUTED", &format!("UNSANDBOXED tool {id} ran without a sandbox (sandbox off); Jev-gated and policy-checked"), serde_json::json!({"call_id": id, "sandboxed": false})).await?;
            tx.commit().await?;
        }
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
        let tool_name = descriptor.name.clone();
        // ask_owner parks instead of completing (sibling ask_owner slice owns
        // this arm): the executor records the OPEN question linked to this
        // call. Return the question_id output WITHOUT settling the call to
        // COMPLETED — settlement happens exactly once in control.rs
        // answer/cancel, which also re-queues the task.
        if tool_name == "orbit-control.ask_owner" {
            use orbit_tools::ToolExecutor;
            let output = orbit_tools::SafeTools {
                pool: self.pool.clone(),
                artifact_dir: self.artifact_dir.clone(),
                key_dir: self.key_dir.clone(),
            }
            .execute(scope, action)
            .await?
            .output;
            debug_assert!(output.get("question_id").is_some());
            return Err(Error::AskOwnerParked(output));
        }
        // All admitted calls — immediately permitted and approved SUBMITTED
        // resumes alike — route through the ExecutorRegistry under the same
        // lease/fence locks and binding checks above. A registered descriptor
        // without an executor reports TOOL_EXECUTOR_UNAVAILABLE, never an
        // invented completion.
        let args = action.snapshot().arguments.clone();
        crate::ExecutorRegistry {
            pool: self.pool.clone(),
            key_dir: self.key_dir.clone(),
            artifact_dir: self.artifact_dir.clone(),
            origin: self.origin.clone(),
        }
        .route(scope, task, agent, &tool_name, &args, action)
        .await
    }
    /// Gateway variant of the propose journal inputs: same registry +
    /// schema + risk + policy checks, but the grant set is the owner's live
    /// enabled catalog (no agent definition row). Returns the same tuple
    /// the loop's propose persists, minus the agent-bound snapshot id.
    async fn journal_gateway_proposal(
        &self,
        scope: &orbit_core::OwnerScope,
        task: Uuid,
        name: &str,
        args: Value,
        proposal_key: &str,
    ) -> Result<(Value, String, Value, String, Value, Value, String), Error> {
        if orbit_core::ContextBlock::looks_like_injection(&args.to_string()) {
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
        orbit_tools::validate_value(&descriptor.input_schema, &args)?;
        let risk = orbit_risk::RiskClassifier::classify_action(
            &orbit_risk::ProposedAction { tool_name: name.into(), arguments: args.clone() },
            &descriptor,
            &orbit_risk::ActionContext { optional_escalation: None },
        )?
        .level;
        if let Some(argv) = command_argv(&args) {
            if orbit_sandbox_dispatch::decide_with_threshold(&argv, 0.8).verdict
                == orbit_sandbox_dispatch::Verdict::Block
            {
                return Err(Error::Forbidden);
            }
        }
        let policy = self.policy_decision(scope, name, &args, &descriptor, risk).await?;
        let denied = policy.get("denied").and_then(Value::as_bool).unwrap_or(true);
        if denied {
            return Err(Error::Forbidden);
        }
        let epoch = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM authorization_epochs WHERE owner_id=$1",
        )
        .bind(scope.owner_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::Forbidden)?;
        let revision = sqlx::query_scalar::<_, i64>("SELECT revision FROM policies WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(1);
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        let snapshot = orbit_core::ActionSnapshot {
            action_id: Uuid::new_v4(),
            owner_id: scope.owner_id,
            principal_id: scope.principal_id,
            // Gateway calls carry no agent row: bind to the nil agent so the
            // ExecutorRegistry binding check (agent_id == Some(agent)) passes
            // exactly for the Uuid::nil() the gateway handler routes with.
            agent_id: Some(Uuid::nil()),
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
        let digest = orbit_computer_node_protocol::sha256(&serde_json::to_vec(&descriptor)?);
        let risk_value = serde_json::to_value(&risk)?;
        let decision_value = policy;
        let state = if is_registry_routable(name) { "PROPOSED" } else { "WAITING_FOR_APPROVAL" }.to_owned();
        let _ = proposal_key;
        Ok((serde_json::to_value(&snapshot)?, hash, descriptor_value, digest, risk_value, decision_value, state))
    }
    /// Shared policy evaluation (grants + engine + sandbox annotation) used
    /// by both the loop admission and the gateway journal path.
    async fn policy_decision(
        &self,
        scope: &orbit_core::OwnerScope,
        name: &str,
        args: &Value,
        descriptor: &orbit_core::ToolDescriptor,
        risk: orbit_core::RiskLevel,
    ) -> Result<Value, Error> {
        let settings: Value = sqlx::query_scalar("SELECT value FROM settings WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(json!({}));
        let autonomy: orbit_core::AutonomyMode = serde_json::from_value(
            settings.get("autonomy_mode").cloned().unwrap_or(Value::Null),
        )
        .unwrap_or(orbit_core::AutonomyMode::Observe);
        let row = sqlx::query("SELECT revision,rules FROM policies WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&self.pool)
            .await?;
        let (revision, rules) = match &row {
            Some(r) => (r.get("revision"), serde_json::from_value(r.get::<Value, _>("rules")).unwrap_or_default()),
            None => (1, vec![]),
        };
        let grants: Vec<orbit_policy::ScopeGrant> = sqlx::query_scalar(
            "SELECT to_jsonb(g)-'owner_id' FROM scope_grants g WHERE owner_id=$1 AND tool_name=$2",
        )
        .bind(scope.owner_id)
        .bind(name)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .filter_map(|value| serde_json::from_value(value).ok())
        .collect();
        let scope_revisions: BTreeMap<String, i64> = grants
            .iter()
            .map(|grant| (grant.scope_key.clone(), grant.scope_revision))
            .collect();
        let mut decision = orbit_policy::PolicyEngine { revision, autonomy, rules, grants }
            .evaluate(scope, name, args, descriptor, risk, &scope_revisions);
        if decision.policy_revision != revision {
            return Err(Error::Conflict("policy changed during evaluation".into()));
        }
        if !settings.get("sandbox_enabled").and_then(Value::as_bool).unwrap_or(false)
            && !decision.reason_codes.iter().any(|c| c == "SANDBOX_DISABLED")
        {
            decision.reason_codes.push("SANDBOX_DISABLED".into());
        }
        Ok(serde_json::to_value(&decision)?)
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
    #[serde(default)]
    pub images: Option<Vec<Uuid>>,
}
#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub struct ChatPage {
    pub conversation_id: Uuid,
    pub after_sequence: Option<i64>,
    pub before_sequence: Option<i64>,
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
    let mut files = input.attachments.clone().unwrap_or_default();
    for image in input.images.clone().unwrap_or_default() {
        if !files.contains(&image) {
            files.push(image);
        }
    }
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
#[utoipa::path(get,path="/api/v1/chat/conversations",responses((status=200,body=Value)))]
pub async fn chat_conversations(
    State(s): State<ApiState>,
    h: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, false).await?;
    let rows: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',c.id,'title',c.title,'agent_id',c.agent_id,'created_at',c.created_at,'last_at',(SELECT max(created_at) FROM chat_messages m WHERE m.owner_id=c.owner_id AND m.conversation_id=c.id)) FROM conversations c WHERE c.owner_id=$1 ORDER BY (SELECT max(created_at) FROM chat_messages m WHERE m.owner_id=c.owner_id AND m.conversation_id=c.id) DESC NULLS LAST,c.created_at DESC LIMIT 50").bind(a.scope.owner_id).fetch_all(&s.pool).await?;
    Ok(Json(json!({"items": rows})))
}
#[utoipa::path(get,path="/api/v1/chat/messages",responses((status=200,body=Value)))]
pub async fn chat_messages(
    State(s): State<ApiState>,
    h: HeaderMap,
    Query(p): Query<ChatPage>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&s, &h, false).await?;
    let limit = p.limit.unwrap_or(50).clamp(1, 100);
    // Ordered conversation timeline: cursor is (conversation_id, sequence).
    // Latest page (no before_sequence) returns the newest `limit` rows
    // ascending; older pages return rows before the cursor, also ascending.
    let rows = if let Some(before) = p.before_sequence {
        sqlx::query("SELECT m.id,m.task_id,m.role,m.content,m.attachments,m.sequence,m.created_at FROM chat_messages m WHERE m.owner_id=$1 AND m.conversation_id=$2 AND m.sequence<$3 ORDER BY m.sequence DESC LIMIT $4").bind(a.scope.owner_id).bind(p.conversation_id).bind(before).bind(limit+1).fetch_all(&s.pool).await?
    } else if let Some(after) = p.after_sequence {
        sqlx::query("SELECT m.id,m.task_id,m.role,m.content,m.attachments,m.sequence,m.created_at FROM chat_messages m WHERE m.owner_id=$1 AND m.conversation_id=$2 AND m.sequence>$3 ORDER BY m.sequence ASC LIMIT $4").bind(a.scope.owner_id).bind(p.conversation_id).bind(after).bind(limit+1).fetch_all(&s.pool).await?
    } else {
        sqlx::query("SELECT m.id,m.task_id,m.role,m.content,m.attachments,m.sequence,m.created_at FROM chat_messages m WHERE m.owner_id=$1 AND m.conversation_id=$2 ORDER BY m.sequence DESC LIMIT $3").bind(a.scope.owner_id).bind(p.conversation_id).bind(limit+1).fetch_all(&s.pool).await?
    };
    let has_more = rows.len() as i64 > limit;
    let mut items: Vec<Value> = rows.iter().take(limit as usize).map(|r| json!({"id": r.get::<Uuid, _>("id"), "task_id": r.get::<Option<Uuid>, _>("task_id"), "role": r.get::<String, _>("role"), "content": r.get::<String, _>("content"), "attachments": r.get::<Value, _>("attachments"), "sequence": r.get::<i64, _>("sequence"), "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at")})).collect();
    // Descending fetches (latest page, older pages) flip to ascending so
    // every page reads oldest-first regardless of direction.
    if p.after_sequence.is_none() {
        items.reverse();
    }
    let (first, last) = (items.first().and_then(|v| v["sequence"].as_i64()), items.last().and_then(|v| v["sequence"].as_i64()));
    Ok(Json(json!({"items": items, "first_sequence": first, "last_sequence": last, "has_more": has_more})))
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
    // Ordered run-event timeline: replay `run_events` for this conversation's
    // tasks from `Last-Event-ID`, then follow new rows in `id` order. A run id
    // stays explicit so an old completed task cannot terminate a new turn.
    let start: i64 = h
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(0);
    let tasks: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT m.task_id FROM chat_messages m WHERE m.owner_id=$1 AND m.conversation_id=$2 AND m.task_id IS NOT NULL").bind(owner).bind(conversation).fetch_all(&s.pool).await?;
    let stream = async_stream::stream! {
        let mut cursor = start;
        // Replay phase: every stored message once, then every stored event
        // after the cursor, each exactly once in (sequence, id) order.
        let rows = sqlx::query("SELECT m.id,m.task_id,m.role,m.content,m.attachments,m.sequence FROM chat_messages m WHERE m.owner_id=$1 AND m.conversation_id=$2 ORDER BY m.sequence ASC LIMIT 500").bind(owner).bind(conversation).fetch_all(&s.pool).await;
        if let Ok(rows) = rows {
            for r in &rows {
                let id: Uuid = r.get("id");
                let seq: i64 = r.get("sequence");
                yield Ok(SseEvent::default().id(seq.to_string()).event("message").data(json!({"id": id, "task_id": r.get::<Option<Uuid>, _>("task_id"), "role": r.get::<String, _>("role"), "content": r.get::<String, _>("content"), "attachments": r.get::<Value, _>("attachments"), "sequence": seq}).to_string()));
            }
        }
        loop {
            if !matches!(sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM sessions WHERE owner_id=$1 AND id=$2 AND expires_at>now())").bind(owner).bind(session).fetch_one(&s.pool).await, Ok(true)) { break; }
            if tasks.is_empty() {
                match sqlx::query("SELECT state,id FROM tasks WHERE owner_id=$1 AND checkpoint->>'conversation_id'=$2 ORDER BY created_at DESC LIMIT 5").bind(owner).bind(conversation.to_string()).fetch_all(&s.pool).await {
                    Ok(latest) => {
                        let terminal = latest.iter().find_map(|r| { let state: String = r.get("state"); matches!(state.as_str(), "COMPLETED" | "FAILED" | "TIMED_OUT" | "CANCELLED").then(|| (state, r.get::<Uuid, _>("id"))) });
                        if let Some((state, id)) = terminal {
                            yield Ok(SseEvent::default().event("done").data(json!({"state": state, "task_id": id}).to_string()));
                            break;
                        }
                    }
                    Err(_) => break,
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
            let events = sqlx::query("SELECT e.id,e.task_id,e.kind,e.payload FROM run_events e WHERE e.owner_id=$1 AND e.task_id = ANY($2) AND e.id>$3 ORDER BY e.id ASC LIMIT 100").bind(owner).bind(&tasks).bind(cursor).fetch_all(&s.pool).await;
            match events {
                Ok(rows) => {
                    for r in &rows {
                        let id: i64 = r.get("id");
                        cursor = id;
                        let kind: String = r.get("kind");
                        let event = match kind.as_str() {
                            "TEXT_DELTA" => "delta",
                            "TOOL_STARTED" => "tool_started",
                            "TOOL_RESULT" => "tool_result",
                            "STATUS" => "status",
                            "USAGE" => "usage",
                            _ => "event",
                        };
                        yield Ok(SseEvent::default().id(id.to_string()).event(event).data(json!({"id": id, "task_id": r.get::<Option<Uuid>, _>("task_id"), "kind": kind, "payload": r.get::<Value, _>("payload")}).to_string()));
                    }
                    if !rows.is_empty() { continue; }
                }
                Err(_) => break,
            }
            // New chat rows after connect stream as messages (deduped by id on
            // the client); terminal task state closes this run only.
            match sqlx::query("SELECT m.id,m.task_id,m.role,m.content,m.attachments,m.sequence FROM chat_messages m WHERE m.owner_id=$1 AND m.conversation_id=$2 AND m.sequence>$3 ORDER BY m.sequence ASC LIMIT 50").bind(owner).bind(conversation).bind(start).fetch_all(&s.pool).await {
                Ok(fresh) => {
                    for r in &fresh {
                        let id: Uuid = r.get("id");
                        let seq: i64 = r.get("sequence");
                        yield Ok(SseEvent::default().id(format!("m{seq}")).event("message").data(json!({"id": id, "task_id": r.get::<Option<Uuid>, _>("task_id"), "role": r.get::<String, _>("role"), "content": r.get::<String, _>("content"), "attachments": r.get::<Value, _>("attachments"), "sequence": seq}).to_string()));
                    }
                    if !fresh.is_empty() { continue; }
                }
                Err(_) => break,
            }
            match sqlx::query("SELECT id,state FROM tasks WHERE owner_id=$1 AND checkpoint->>'conversation_id'=$2 AND id = ANY($3) ORDER BY created_at DESC LIMIT 5").bind(owner).bind(conversation.to_string()).bind(&tasks).fetch_all(&s.pool).await {
                Ok(latest) => {
                    let terminal = latest.iter().find_map(|r| { let state: String = r.get("state"); matches!(state.as_str(), "COMPLETED" | "FAILED" | "TIMED_OUT" | "CANCELLED").then(|| (state, r.get::<Uuid, _>("id"))) });
                    if let Some((state, id)) = terminal {
                        // Drain first: only close once no newer events remain.
                        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM run_events WHERE owner_id=$1 AND task_id = ANY($2) AND id>$3").bind(owner).bind(&tasks).bind(cursor).fetch_optional(&s.pool).await.unwrap_or(Some(0)).unwrap_or(0);
                        if pending == 0 {
                            yield Ok(SseEvent::default().event("done").data(json!({"state": state, "task_id": id}).to_string()));
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    };
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
        chat_conversations,
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
        .route("/api/v1/chat/conversations", get(chat_conversations))
        .route("/api/v1/chat/stream", get(chat_stream))
        .route("/api/v1/chat/attachments", post(upload_attachment))
        .route("/api/v1/chat/attachments/{id}", get(download_attachment))
}
