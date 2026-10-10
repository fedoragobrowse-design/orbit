use crate::{AgentDefinition, AgentInput, Dispatcher, validate_context};
use orbit_core::{ContextBlock, ContextKind, Error, OwnerScope, PrivacyClass, Result, TrustLevel};
use orbit_model_router::{
    ChatMessage, ChatRequest, ChatResponse, ModelRouter, RoutedRequest, ToolSchema,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{path::PathBuf, sync::Arc, time::Instant};
use uuid::Uuid;

pub async fn seed_agents(
    pool: &PgPool,
    scope: &OwnerScope,
    available: &[orbit_core::ToolDescriptor],
) -> Result<()> {
    for (key, body, required) in [
        (
            "general",
            include_str!("../../../agents/general.json"),
            None,
        ),
        (
            "file",
            include_str!("../../../agents/file.json"),
            Some("files.read"),
        ),
        (
            "email",
            include_str!("../../../agents/email.json"),
            Some("email.read"),
        ),
    ] {
        if required.is_some_and(|name| !available.iter().any(|d| d.name == name)) {
            continue;
        }
        let id = Uuid::from_bytes(
            Sha256::digest(format!("{}:builtin:{key}", scope.owner_id)).as_slice()[..16]
                .try_into()
                .expect("digest length"),
        );
        let config: AgentInput = serde_json::from_str(body)?;
        config.validate()?;
        sqlx::query("INSERT INTO agent_definitions(id,owner_id,definition) VALUES($1,$2,$3) ON CONFLICT DO NOTHING").bind(id).bind(scope.owner_id).bind(json!(config)).execute(pool).await?;
    }
    Ok(())
}

pub async fn tick(
    pool: &PgPool,
    key_dir: PathBuf,
    worker: Uuid,
    dispatcher: Arc<dyn Dispatcher>,
) -> Result<()> {
    let candidates=sqlx::query("SELECT owner_id,id FROM tasks WHERE consumer IN ('agents','gateway') AND (state='QUEUED' OR (state='RUNNING' AND lease_until<now())) ORDER BY created_at,id LIMIT 10").fetch_all(pool).await?;
    for row in candidates {
        let owner: Uuid = row.get("owner_id");
        let task: Uuid = row.get("id");
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
            .bind(owner)
            .fetch_one(&mut *tx)
            .await?;
        let r=sqlx::query("SELECT *,lease_until>now() AS lease_active,expires_at<=now() AS expired FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(owner).bind(task).fetch_one(&mut *tx).await?;
        let state: String = r.get("state");
        if !matches!(state.as_str(), "QUEUED" | "RUNNING")
            || (state == "RUNNING" && r.get::<Option<bool>, _>("lease_active") == Some(true))
        {
            continue;
        }
        let scope = OwnerScope {
            owner_id: owner,
            principal_id: r.get("principal_id"),
        };
        if r.get::<bool, _>("expired") {
            sqlx::query("UPDATE tasks SET state='TIMED_OUT',fence=fence+1,revision=revision+1,lease_until=NULL WHERE owner_id=$1 AND id=$2").bind(owner).bind(task).execute(&mut *tx).await?;
            tx.commit().await?;
            continue;
        }
        let fence:i64=sqlx::query_scalar("UPDATE tasks SET state='RUNNING',fence=fence+1,revision=revision+1,lease_holder=$3,lease_until=now()+interval '30 seconds',updated_at=now() WHERE owner_id=$1 AND id=$2 RETURNING fence").bind(owner).bind(task).bind(worker).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        let hb_pool = pool.clone();
        let hb_scope = scope.clone();
        let heartbeat = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let result=sqlx::query("UPDATE tasks SET lease_until=now()+interval '30 seconds' WHERE owner_id=$1 AND id=$2 AND fence=$3 AND lease_holder=$4 AND state='RUNNING' AND lease_until>now()").bind(hb_scope.owner_id).bind(task).bind(fence).bind(worker).execute(&hb_pool).await;
                if !matches!(result,Ok(r) if r.rows_affected()==1) {
                    break;
                }
            }
        });
        let outcome = run(
            pool,
            &key_dir,
            &scope,
            task,
            worker,
            fence,
            dispatcher.as_ref(),
        )
        .await;
        heartbeat.abort();
        if let Err(error) = outcome {
            match error {
                Error::Conflict(_) => {}
                Error::OutcomeUnknown => {
                    wait(pool, &scope, task, fence, "OUTCOME_UNKNOWN").await?;
                }
                Error::Unavailable(reason) => {
                    let code = if reason.starts_with("LOCAL_MODEL_UNAVAILABLE") {
                        "LOCAL_MODEL_UNAVAILABLE"
                    } else if reason.starts_with("MODEL_") {
                        "MODEL_RESOURCE_UNAVAILABLE"
                    } else {
                        "DEPENDENCY_UNAVAILABLE"
                    };
                    wait(pool, &scope, task, fence, code).await?;
                }
                Error::Timeout => {
                    finish(
                        pool,
                        &scope,
                        task,
                        fence,
                        "TIMED_OUT",
                        "ACTIVE_BUDGET_EXHAUSTED",
                    )
                    .await?;
                }
                _ => {
                    finish(pool, &scope, task, fence, "FAILED", "AGENT_RUN_FAILED").await?;
                }
            }
        }
    }
    Ok(())
}

async fn lock<'a>(
    pool: &'a PgPool,
    scope: &OwnerScope,
    task: Uuid,
    fence: i64,
) -> Result<Transaction<'a, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks WHERE owner_id=$1 AND id=$2 AND fence=$3 AND state='RUNNING' AND lease_until>now() AND expires_at>now() FOR UPDATE)").bind(scope.owner_id).bind(task).bind(fence).fetch_one(&mut *tx).await?;
    if !valid {
        return Err(Error::Conflict("task lease or execution fence lost".into()));
    }
    Ok(tx)
}
async fn phase(
    pool: &PgPool,
    scope: &OwnerScope,
    task: Uuid,
    fence: i64,
    next: &str,
) -> Result<()> {
    let mut tx = lock(pool, scope, task, fence).await?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT phase FROM agent_runs WHERE owner_id=$1 AND task_id=$2")
            .bind(scope.owner_id)
            .bind(task)
            .fetch_optional(&mut *tx)
            .await?;
    match &current {
        Some(from) if legal_transition(from, next) => {}
        Some(_) => return Err(Error::Conflict("illegal agent step transition".into())),
        None => return Err(Error::NotFound),
    }
    sqlx::query("UPDATE agent_runs SET phase=$3,updated_at=now() WHERE owner_id=$1 AND task_id=$2")
        .bind(scope.owner_id)
        .bind(task)
        .bind(next)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE tasks SET checkpoint=jsonb_set(checkpoint,'{phase}',to_jsonb($3::text)),revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(task).bind(next).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
/// Durable step journal: the only legal checkpoint transitions. Recovery may
/// re-enter the stored phase or advance along the loop; terminal DONE and
/// unknown phases never transition.
pub fn legal_transition(from: &str, to: &str) -> bool {
    if to == "DONE" {
        return from != "DONE";
    }
    matches!(
        (from, to),
        ("CONTEXT", "MODEL")
            | ("MODEL", "MODEL_INFLIGHT")
            | ("MODEL_INFLIGHT", "MODEL")
            | ("MODEL_INFLIGHT", "RESPONSE")
            | ("RESPONSE", "PROPOSE")
            | ("RESPONSE", "CONTEXT")
            | ("PROPOSE", "PROPOSE")
            | ("PROPOSE", "DISPATCH")
            | ("DISPATCH", "RESULT")
            | ("RESULT", "CONTEXT")
            | ("RESULT", "RESPONSE")
    )
}
/// Phase recovered from a persisted task checkpoint. Unknown or terminal
/// checkpoints cannot resume; the task must retry from CONTEXT instead.
pub fn resume_phase(checkpoint: &serde_json::Value) -> Result<String> {
    let phase = checkpoint
        .get("phase")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::Validation("agent checkpoint missing phase".into()))?;
    match phase {
        "CONTEXT" | "MODEL" | "MODEL_INFLIGHT" | "RESPONSE" | "PROPOSE" | "DISPATCH" | "RESULT" => {
            Ok(phase.into())
        }
        "DONE" => Err(Error::Conflict("agent run already complete".into())),
        _ => Err(Error::Validation("unknown agent checkpoint phase".into())),
    }
}
async fn wait(
    pool: &PgPool,
    scope: &OwnerScope,
    task: Uuid,
    fence: i64,
    reason: &str,
) -> Result<()> {
    let mut tx = match lock(pool, scope, task, fence).await {
        Ok(tx) => tx,
        Err(Error::Conflict(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    sqlx::query("UPDATE tasks SET state='WAITING_FOR_RESOURCE',wait_reason=$4,lease_until=NULL,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND fence=$3").bind(scope.owner_id).bind(task).bind(fence).bind(reason).execute(&mut *tx).await?;
    let c: Uuid =
        sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(task)
            .fetch_one(&mut *tx)
            .await?;
    orbit_audit::append(
        &mut tx,
        scope,
        c,
        None,
        Some(task),
        "TASK_WAITING_FOR_RESOURCE",
        reason,
        json!({}),
    )
    .await?;
    sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body) VALUES($1,$2,$3,$4,'ACTION_REQUIRED','Assistant needs a resource',$5) ON CONFLICT(owner_id,task_id) DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(task).bind(c).bind(reason).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
/// Park for human consent: approval-pending calls freeze the run in
/// WAITING_FOR_APPROVAL so the gateway `approve` path can resume the same
/// checkpoint. The phase stays DISPATCH; no new dispatch happens while parked.
async fn wait_for_approval(
    pool: &PgPool,
    scope: &OwnerScope,
    task: Uuid,
    fence: i64,
    approvals: &[String],
) -> Result<()> {
    let mut tx = match lock(pool, scope, task, fence).await {
        Ok(tx) => tx,
        Err(Error::Conflict(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    let reason = format!("waiting for approval of {}", approvals.join(","));
    sqlx::query("UPDATE tasks SET state='WAITING_FOR_APPROVAL',wait_reason=$4,lease_until=NULL,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND fence=$3").bind(scope.owner_id).bind(task).bind(fence).bind(&reason).execute(&mut *tx).await?;
    let c: Uuid =
        sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(task)
            .fetch_one(&mut *tx)
            .await?;
    orbit_audit::append(
        &mut tx,
        scope,
        c,
        None,
        Some(task),
        "TASK_WAITING_FOR_APPROVAL",
        &reason,
        json!({"approvals":approvals}),
    )
    .await?;
    sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body) VALUES($1,$2,$3,$4,'ACTION_REQUIRED','Assistant needs approval',$5) ON CONFLICT(owner_id,task_id) DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(task).bind(c).bind(&reason).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn finish(
    pool: &PgPool,
    scope: &OwnerScope,
    task: Uuid,
    fence: i64,
    state: &str,
    reason: &str,
) -> Result<()> {
    let mut tx = match lock(pool, scope, task, fence).await {
        Ok(tx) => tx,
        Err(Error::Conflict(_)) => return Ok(()),
        Err(e) => return Err(e),
    };
    let t = sqlx::query("SELECT correlation_id,event_id FROM tasks WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(task)
        .fetch_one(&mut *tx)
        .await?;
    let correlation: Uuid = t.get("correlation_id");
    sqlx::query("UPDATE tasks SET state=$4,wait_reason=NULL,lease_until=NULL,checkpoint=jsonb_set(checkpoint,'{phase}','\"DONE\"'),revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND fence=$3").bind(scope.owner_id).bind(task).bind(fence).bind(state).execute(&mut *tx).await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        t.get("event_id"),
        Some(task),
        &format!("TASK_{state}"),
        reason,
        json!({}),
    )
    .await?;
    sqlx::query("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,$3,'agent-runtime',$4,$5,'SYSTEM','PRIVATE',$6,$7) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(if state=="COMPLETED"{"TASK_COMPLETED"}else{"TASK_FAILED"}).bind(scope.principal_id).bind(json!({"task_id":task,"state":state})).bind(correlation).bind(format!("terminal:{task}")).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn run(
    pool: &PgPool,
    key_dir: &PathBuf,
    scope: &OwnerScope,
    task: Uuid,
    worker: Uuid,
    fence: i64,
    dispatcher: &dyn Dispatcher,
) -> Result<()> {
    let task_row = sqlx::query("SELECT consumer,checkpoint FROM tasks WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(task)
        .fetch_one(pool)
        .await?;
    if task_row.get::<String, _>("consumer") == "gateway" {
        let results = dispatcher.submit(scope, task, worker, fence).await?;
        if results.iter().any(|r| r["state"] == "OUTCOME_UNKNOWN") {
            return Err(Error::OutcomeUnknown);
        }
        if results
            .iter()
            .any(|r| r["state"] == "WAITING_FOR_APPROVAL" || r["state"] == "WAITING_FOR_RESOURCE")
        {
            return Ok(());
        }
        return finish(
            pool,
            scope,
            task,
            fence,
            if results.iter().any(|r| r["state"] == "FAILED") {
                "FAILED"
            } else {
                "COMPLETED"
            },
            "gateway dispatch settled",
        )
        .await;
    }
    let checkpoint: Value = task_row.get("checkpoint");
    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM agent_runs WHERE owner_id=$1 AND task_id=$2)",
    )
    .bind(scope.owner_id)
    .bind(task)
    .fetch_one(pool)
    .await?
    {
        let agent = checkpoint["agent_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| Error::Validation("agent checkpoint missing definition".into()))?;
        let a=sqlx::query("SELECT definition,revision FROM agent_definitions WHERE owner_id=$1 AND id=$2 AND enabled").bind(scope.owner_id).bind(agent).fetch_optional(pool).await?.ok_or(Error::Forbidden)?;
        let definition = AgentDefinition {
            id: agent,
            owner_id: scope.owner_id,
            config: serde_json::from_value(a.get("definition"))?,
            revision: a.get("revision"),
        };
        let mut tx = lock(pool, scope, task, fence).await?;
        let conversation = checkpoint["conversation_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_else(Uuid::new_v4);
        sqlx::query("INSERT INTO conversations(id,owner_id,agent_id,title) VALUES($1,$2,$3,'Automation activity') ON CONFLICT DO NOTHING").bind(conversation).bind(scope.owner_id).bind(agent).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO agent_runs(task_id,owner_id,agent_id,conversation_id,definition,depth,automatic) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING").bind(task).bind(scope.owner_id).bind(agent).bind(conversation).bind(json!(definition)).bind(checkpoint["depth"].as_i64().unwrap_or(0) as i32).bind(checkpoint["automatic"].as_bool().unwrap_or(false)).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    loop {
        let r = sqlx::query("SELECT * FROM agent_runs WHERE owner_id=$1 AND task_id=$2")
            .bind(scope.owner_id)
            .bind(task)
            .fetch_one(pool)
            .await?;
        let agent: AgentDefinition = serde_json::from_value(r.get("definition"))?;
        let limits = &agent.config.limits;
        let turn: i32 = r.get("turn");
        let conversation: Uuid = r.get("conversation_id");
        let current: String = r.get("phase");
        if r.get::<f64, _>("active_seconds") >= f64::from(limits.max_active_seconds)
            || r.get::<i64, _>("tokens") >= limits.max_tokens as i64
            || r.get::<i32, _>("depth") > limits.max_subagent_depth as i32
        {
            return Err(Error::Timeout);
        }
        match current.as_str() {
            "CONTEXT" => {
                let permitted = dispatcher.descriptors(scope).await?;
                let mut tools = Vec::new();
                let mut tx = lock(pool, scope, task, fence).await?;
                for d in permitted
                    .iter()
                    .filter(|d| agent.config.allowed_tools.contains(&d.name))
                {
                    let alias = format!("t_{}", d.id.simple());
                    sqlx::query("INSERT INTO agent_tool_aliases(owner_id,task_id,alias,tool_id,tool_name,tool_version,input_schema) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(owner_id,task_id,alias) DO UPDATE SET tool_name=EXCLUDED.tool_name,tool_version=EXCLUDED.tool_version,input_schema=EXCLUDED.input_schema").bind(scope.owner_id).bind(task).bind(&alias).bind(d.id).bind(&d.name).bind(&d.version).bind(&d.input_schema).execute(&mut *tx).await?;
                    tools.push(ToolSchema {
                        name: alias,
                        description: format!(
                            "Registered tool {} ({}). {}",
                            d.name, d.version, d.effects.affected_party
                        ),
                        input_schema: d.input_schema.clone(),
                    });
                }
                tx.commit().await?;
                let rows=sqlx::query("SELECT role,content,attachments,tool_calls,tool_call_id,id FROM (SELECT * FROM chat_messages WHERE owner_id=$1 AND conversation_id=$2 ORDER BY created_at DESC,id DESC LIMIT $3) m ORDER BY created_at,id").bind(scope.owner_id).bind(conversation).bind(i64::from(agent.config.context_strategy.history_messages)).fetch_all(pool).await?;
                let mut context = vec![ContextBlock {
                    kind: ContextKind::SystemPolicy,
                    text_or_reference: agent.config.instructions.clone(),
                    privacy_class: PrivacyClass::Private,
                    trust_level: TrustLevel::System,
                    source_reference: format!("agent:{}:{}", agent.id, agent.revision),
                }];
                let mut messages = Vec::new();
                let mut query = String::new();
                for message in rows {
                    let role: String = message.get("role");
                    let content: String = message.get("content");
                    if role == "user" {
                        query = content.clone();
                        context.push(ContextBlock {
                            kind: ContextKind::UserInstruction,
                            text_or_reference: content.clone(),
                            privacy_class: PrivacyClass::Private,
                            trust_level: TrustLevel::OwnerAuthenticated,
                            source_reference: format!("message:{}", message.get::<Uuid, _>("id")),
                        });
                    }
                    messages.push(ChatMessage {
                        role,
                        content,
                        tool_call_id: message.get("tool_call_id"),
                        tool_calls: serde_json::from_value(message.get("tool_calls"))?,
                        images: vec![],
                    });
                    let attachments: Vec<Uuid> =
                        serde_json::from_value(message.get("attachments"))?;
                    for id in attachments {
                        let a=sqlx::query("SELECT id,name,sha256,privacy_class,source_reference FROM chat_attachments WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).fetch_optional(pool).await?.ok_or(Error::Forbidden)?;
                        context.push(ContextBlock{kind:ContextKind::UntrustedExternalContent,text_or_reference:json!({"attachment_id":id,"name":a.get::<String,_>("name"),"sha256":a.get::<String,_>("sha256"),"source_reference":a.get::<Option<Value>,_>("source_reference")}).to_string(),privacy_class:serde_json::from_value(json!(a.get::<String,_>("privacy_class")))?,trust_level:TrustLevel::UntrustedExternal,source_reference:format!("attachment:{id}")});
                    }
                }
                if let Some(instructions) = checkpoint["instructions"].as_str() {
                    context.push(ContextBlock {
                        kind: ContextKind::UserInstruction,
                        text_or_reference: instructions.into(),
                        privacy_class: PrivacyClass::Private,
                        trust_level: TrustLevel::OwnerAuthenticated,
                        source_reference: format!("automation-task:{task}"),
                    });
                    query = instructions.into();
                    messages.push(ChatMessage {
                        role: "user".into(),
                        content: instructions.into(),
                        ..Default::default()
                    });
                }
                if checkpoint.get("affected_files").is_some() {
                    context.push(ContextBlock {
                        kind: ContextKind::UntrustedExternalContent,
                        text_or_reference: json!({"affected_files":checkpoint["affected_files"]})
                            .to_string(),
                        privacy_class: PrivacyClass::Private,
                        trust_level: TrustLevel::UntrustedExternal,
                        source_reference: format!("event-task:{task}"),
                    });
                }
                context.extend(dispatcher.context(scope, &agent, &query).await?);
                let mut chars = 0usize;
                context.retain(|block| {
                    chars += block.text_or_reference.chars().count();
                    chars <= agent.config.context_strategy.max_context_characters as usize
                });
                for b in &context {
                    validate_context(b)?
                }
                let input_chars: usize = messages.iter().map(|m| m.content.len()).sum::<usize>()
                    + context
                        .iter()
                        .map(|b| b.text_or_reference.len())
                        .sum::<usize>();
                if input_chars as u64
                    >= limits
                        .max_tokens
                        .saturating_sub(r.get::<i64, _>("tokens") as u64)
                {
                    return Err(Error::Timeout);
                }
                let chat = ChatRequest {
                    messages,
                    tools,
                    output_schema: None,
                    max_output_tokens: 2048.min(
                        limits
                            .max_tokens
                            .saturating_sub(r.get::<i64, _>("tokens") as u64)
                            as u32,
                    ),
                    reasoning: false,
                };
                let mut tx = lock(pool, scope, task, fence).await?;
                sqlx::query("UPDATE agent_runs SET context=$3,chat=$4,model_retries=0 WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).bind(json!(context)).bind(json!(chat)).execute(&mut *tx).await?;
                tx.commit().await?;
                phase(pool, scope, task, fence, "MODEL").await?;
            }
            "MODEL" | "MODEL_INFLIGHT" => {
                if r.get::<i32, _>("model_calls") >= limits.max_model_calls as i32
                    || (current == "MODEL_INFLIGHT"
                        && r.get::<i32, _>("model_retries") >= limits.max_retries as i32)
                {
                    return Err(Error::Validation(
                        "model call or retry budget exhausted".into(),
                    ));
                }
                let context: Vec<ContextBlock> = serde_json::from_value(r.get("context"))?;
                let privacy = context
                    .iter()
                    .map(|c| c.privacy_class)
                    .max()
                    .unwrap_or(PrivacyClass::Private);
                let mut tx = lock(pool, scope, task, fence).await?;
                sqlx::query("UPDATE agent_runs SET phase='MODEL_INFLIGHT',model_calls=model_calls+1,model_retries=model_retries+CASE WHEN phase='MODEL_INFLIGHT' THEN 1 ELSE 0 END WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).execute(&mut *tx).await?;
                tx.commit().await?;
                let started = Instant::now();
                let remaining = (f64::from(limits.max_active_seconds)
                    - r.get::<f64, _>("active_seconds"))
                .max(0.0);
                let answer = tokio::time::timeout(
                    std::time::Duration::from_secs_f64(remaining),
                    ModelRouter::new(pool.clone(), key_dir.clone()).complete(
                        scope,
                        RoutedRequest {
                            role: agent.config.model_role,
                            chat: serde_json::from_value(r.get("chat"))?,
                            context,
                            privacy,
                            task_id: Some(task),
                            task_fence: Some(fence),
                            agent_id: Some(agent.id),
                            automatic: r.get("automatic"),
                            model_id: None,
                        },
                    ),
                )
                .await;
                let mut tx = lock(pool, scope, task, fence).await?;
                sqlx::query("UPDATE agent_runs SET active_seconds=active_seconds+$3 WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).bind(started.elapsed().as_secs_f64()).execute(&mut *tx).await?;
                match answer {
                    Ok(Ok(answer)) => {
                        if answer.response.tool_calls.len() > 24
                            || answer.response.text.len() > 262144
                        {
                            return Err(Error::Validation("model response exceeded bounds".into()));
                        }
                        sqlx::query("UPDATE agent_runs SET phase='RESPONSE',model_response=$3,route=$4,model_call_id=$5,tokens=tokens+$6,proposal_index=0,pending_calls='[]' WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).bind(json!(answer.response)).bind(json!(answer.route)).bind(answer.call_id).bind((answer.response.usage.input_tokens+answer.response.usage.output_tokens) as i64).execute(&mut *tx).await?;
                        tx.commit().await?;
                        phase(pool, scope, task, fence, "RESPONSE").await?;
                    }
                    Ok(Err(e)) => {
                        tx.commit().await?;
                        return Err(e);
                    }
                    Err(_) => {
                        tx.commit().await?;
                        return Err(Error::Timeout);
                    }
                }
            }
            "RESPONSE" => {
                let response: ChatResponse = serde_json::from_value(r.get("model_response"))?;
                let mut tx = lock(pool, scope, task, fence).await?;
                sqlx::query("INSERT INTO chat_messages(id,owner_id,conversation_id,task_id,role,content,route,tool_calls,turn_key) VALUES($1,$2,$3,$4,'assistant',$5,$6,$7,$8) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(conversation).bind(task).bind(&response.text).bind(r.get::<Option<Value>,_>("route")).bind(json!(response.tool_calls)).bind(format!("assistant:{turn}")).execute(&mut *tx).await?;
                sqlx::query(
                    "UPDATE conversations SET updated_at=now() WHERE owner_id=$1 AND id=$2",
                )
                .bind(scope.owner_id)
                .bind(conversation)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                if response.tool_calls.is_empty() {
                    if response.text.trim().is_empty() {
                        return Err(Error::Validation("empty model final response".into()));
                    }
                    return finish(
                        pool,
                        scope,
                        task,
                        fence,
                        "COMPLETED",
                        "model final response persisted",
                    )
                    .await;
                }
                phase(pool, scope, task, fence, "PROPOSE").await?;
            }
            "PROPOSE" => {
                let response: ChatResponse = serde_json::from_value(r.get("model_response"))?;
                let index = r.get::<i32, _>("proposal_index") as usize;
                if index >= response.tool_calls.len() {
                    phase(pool, scope, task, fence, "DISPATCH").await?;
                    continue;
                }
                if r.get::<i32, _>("tool_calls") >= limits.max_tool_calls as i32 {
                    return Err(Error::Validation("tool call budget exhausted".into()));
                }
                let call = &response.tool_calls[index];
                let mapping=sqlx::query("SELECT tool_name,tool_version FROM agent_tool_aliases WHERE owner_id=$1 AND task_id=$2 AND alias=$3").bind(scope.owner_id).bind(task).bind(&call.name).fetch_optional(pool).await?.ok_or(Error::Forbidden)?;
                let name: String = mapping.get("tool_name");
                if !agent.config.allowed_tools.contains(&name) {
                    return Err(Error::Forbidden);
                }
                let current_catalog = dispatcher.descriptors(scope).await?;
                if !current_catalog.iter().any(|d| {
                    d.name == name && d.version == mapping.get::<String, _>("tool_version")
                }) {
                    return Err(Error::Conflict("tool catalog changed".into()));
                }
                let signature = hex::encode(Sha256::digest(
                    json!({"name":name,"arguments":call.arguments}).to_string(),
                ));
                let failures: Value = r.get("failure_counts");
                if failures[&signature].as_u64().unwrap_or(0) > u64::from(limits.max_retries) {
                    return Err(Error::Validation(
                        "repeated identical failing proposal stopped".into(),
                    ));
                }
                // Reserve once before proposing. The gateway's durable proposal key closes the crash gap.
                let mut tx = lock(pool, scope, task, fence).await?;
                sqlx::query("UPDATE agent_runs SET tool_calls=tool_calls+1 WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).execute(&mut *tx).await?;
                tx.commit().await?;
                let proposal = dispatcher
                    .propose(
                        scope,
                        task,
                        agent.id,
                        &name,
                        call.arguments.clone(),
                        &format!("turn:{turn}:call:{index}"),
                    )
                    .await?;
                let mut tx = lock(pool, scope, task, fence).await?;
                let mut pending: Vec<Value> = serde_json::from_value(r.get("pending_calls"))?;
                pending.push(json!({"call_id":proposal["call_id"],"model_call_id":call.id,"signature":signature}));
                sqlx::query("UPDATE agent_runs SET pending_calls=$3,proposal_index=proposal_index+1 WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).bind(json!(pending)).execute(&mut *tx).await?;
                tx.commit().await?;
            }
            "DISPATCH" => {
                let results = dispatcher.submit(scope, task, worker, fence).await?;
                if results.iter().any(|r| r["state"] == "OUTCOME_UNKNOWN") {
                    return Err(Error::OutcomeUnknown);
                }
                let pending_approvals: Vec<String> = results
                    .iter()
                    .filter(|r| r["state"] == "WAITING_FOR_APPROVAL")
                    .filter_map(|r| {
                        r.get("approval_id")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                            .or_else(|| {
                                r.get("call_id").and_then(|v| v.as_str()).map(str::to_owned)
                            })
                    })
                    .collect();
                if !pending_approvals.is_empty() {
                    wait_for_approval(pool, scope, task, fence, &pending_approvals).await?;
                    return Ok(());
                }
                if results.iter().any(|r| r["state"] == "WAITING_FOR_RESOURCE") {
                    return Ok(());
                }
                phase(pool, scope, task, fence, "RESULT").await?;
            }
            "RESULT" => {
                let pending: Vec<Value> = serde_json::from_value(r.get("pending_calls"))?;
                let mut failures: Value = r.get("failure_counts");
                let mut tx = lock(pool, scope, task, fence).await?;
                for item in pending {
                    let id = item["call_id"]
                        .as_str()
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .ok_or_else(|| Error::Validation("invalid proposal checkpoint".into()))?;
                    let result=sqlx::query("SELECT state,result,error_code FROM tool_calls WHERE owner_id=$1 AND task_id=$2 AND id=$3").bind(scope.owner_id).bind(task).bind(id).fetch_one(&mut *tx).await?;
                    let state: String = result.get("state");
                    if state == "OUTCOME_UNKNOWN" || state == "SUBMITTED" {
                        return Err(Error::OutcomeUnknown);
                    }
                    if !matches!(
                        state.as_str(),
                        "COMPLETED"
                            | "FAILED"
                            | "DENIED"
                            | "RECONCILED_APPLIED"
                            | "RECONCILED_NOT_APPLIED"
                    ) {
                        return Err(Error::Unavailable("tool result not settled".into()));
                    }
                    let value: Option<Value> = result.get("result");
                    if state == "RECONCILED_APPLIED" && value.is_none() {
                        return Err(Error::Validation(
                            "applied effect lacks recoverable output; no replay".into(),
                        ));
                    }
                    let signature = item["signature"].as_str().unwrap_or("");
                    if state != "COMPLETED" && state != "RECONCILED_APPLIED" {
                        failures[signature] = json!(failures[signature].as_u64().unwrap_or(0) + 1);
                    }
                    let content=json!({"call_id":id,"state":state,"result":value,"error_code":result.get::<Option<String>,_>("error_code")}).to_string();
                    if content.len() > 1024 * 1024 {
                        return Err(Error::Validation(
                            "tool result exceeds context bound".into(),
                        ));
                    }
                    sqlx::query("INSERT INTO chat_messages(id,owner_id,conversation_id,task_id,role,content,turn_key,tool_call_id) VALUES($1,$2,$3,$4,'tool',$5,$6,$7) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(conversation).bind(task).bind(content).bind(format!("tool:{turn}:{id}")).bind(item["model_call_id"].as_str()).execute(&mut *tx).await?;
                }
                sqlx::query("UPDATE agent_runs SET failure_counts=$3,turn=turn+1,pending_calls='[]' WHERE owner_id=$1 AND task_id=$2").bind(scope.owner_id).bind(task).bind(failures).execute(&mut *tx).await?;
                tx.commit().await?;
                phase(pool, scope, task, fence, "CONTEXT").await?;
            }
            _ => return Err(Error::Validation("unknown durable agent checkpoint".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn step_journal_advances_along_the_loop() {
        for (from, to) in [
            ("CONTEXT", "MODEL"),
            ("MODEL", "MODEL_INFLIGHT"),
            ("MODEL_INFLIGHT", "MODEL"),
            ("MODEL_INFLIGHT", "RESPONSE"),
            ("RESPONSE", "PROPOSE"),
            ("RESPONSE", "CONTEXT"),
            ("PROPOSE", "PROPOSE"),
            ("PROPOSE", "DISPATCH"),
            ("DISPATCH", "RESULT"),
            ("RESULT", "CONTEXT"),
            ("RESULT", "RESPONSE"),
        ] {
            assert!(legal_transition(from, to), "{from} -> {to}")
        }
        for (from, to) in [
            ("CONTEXT", "DISPATCH"),
            ("MODEL", "RESULT"),
            ("PROPOSE", "RESULT"),
            ("DISPATCH", "CONTEXT"),
            ("RESULT", "PROPOSE"),
            ("DONE", "CONTEXT"),
            ("CONTEXT", "DONE-EXTRA"),
        ] {
            assert!(!legal_transition(from, to), "{from} -/-> {to}")
        }
    }
    #[test]
    fn step_journal_completes_from_any_live_phase() {
        for from in [
            "CONTEXT",
            "MODEL",
            "MODEL_INFLIGHT",
            "RESPONSE",
            "PROPOSE",
            "DISPATCH",
            "RESULT",
        ] {
            assert!(legal_transition(from, "DONE"), "{from} -> DONE")
        }
        assert!(!legal_transition("DONE", "DONE"));
    }
    #[test]
    fn checkpoint_recovers_stored_phase_and_rejects_terminal_or_unknown() {
        for phase in [
            "CONTEXT",
            "MODEL",
            "MODEL_INFLIGHT",
            "RESPONSE",
            "PROPOSE",
            "DISPATCH",
            "RESULT",
        ] {
            assert_eq!(resume_phase(&json!({"phase":phase})).unwrap(), phase)
        }
        assert!(resume_phase(&json!({"phase":"DONE"})).is_err());
        assert!(resume_phase(&json!({"phase":"NOTIFICATION"})).is_err());
        assert!(resume_phase(&json!({})).is_err());
    }
}
