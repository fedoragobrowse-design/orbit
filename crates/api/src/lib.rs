pub mod agents;
pub mod auth;
pub mod automations;
pub mod brief;
pub mod calendar;
pub mod computers;
pub mod connectors;
pub mod control;
pub mod email;
pub mod foundation;
pub mod gateway;
pub mod inbox;
pub mod marketplace;
pub mod mcp;
pub mod memory;
pub mod models;
pub mod notes;
pub mod ops;
pub mod push;
pub mod runtimes;
pub mod search;
pub mod updates;
pub mod tokens;
pub mod uploads;
pub mod utility_tabs;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use orbit_core::{Error, OwnerScope};
use serde_json::json;
use sqlx::PgPool;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone)]
pub struct ApiState {
    pub pool: PgPool,
    pub origin: String,
    pub key_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub nodes: computers::NodeHub,
}
pub struct AuthSession {
    pub scope: OwnerScope,
    pub csrf_token: String,
    pub session_id: Uuid,
}
pub struct ApiError(pub Error);
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self(Error::Database(e))
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Error::NotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Error::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION"),
            Error::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Error::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
            Error::UnsupportedCapability => {
                (StatusCode::UNPROCESSABLE_ENTITY, "UNSUPPORTED_CAPABILITY")
            }
            Error::Timeout => (StatusCode::GATEWAY_TIMEOUT, "TIMEOUT"),
            Error::OutcomeUnknown => (StatusCode::CONFLICT, "OUTCOME_UNKNOWN"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL"),
        };
        (status,Json(json!({"error":{"code":code,"message":self.0.to_string(),"request_id":Uuid::new_v4()}}))).into_response()
    }
}
pub async fn authenticate(state: &ApiState, headers: &HeaderMap, mutation: bool) -> Result<AuthSession, ApiError> { ops::guard(state, headers, mutation).await }
pub fn router(state: ApiState) -> Router {
    Router::new()
        .merge(auth::router())
        .merge(foundation::router())
        .merge(models::router())
        .merge(gateway::router())
        .merge(memory::router())
        .merge(automations::router())
        .merge(runtimes::router())
        .merge(email::router())
        .merge(mcp::router())
        .merge(marketplace::router())
        .merge(computers::router())
        .merge(agents::router())
        .merge(push::router())
        .merge(ops::router())
        .merge(updates::router())
        .merge(search::router())
        .merge(brief::router())
        .merge(calendar::router())
        .merge(connectors::router())
        .merge(tokens::router())
        .merge(uploads::router())
        .merge(utility_tabs::router())
        .merge(notes::router())
        .merge(inbox::router())
        .merge(control::router())
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(state)
}
pub async fn initialize(state: &ApiState) -> orbit_core::Result<()> {
    let migration_url = std::env::var("ORBIT_MIGRATION_DATABASE_URL")
        .map_err(|_| Error::Unavailable("migration database identity required".into()))?;
    let migration_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&migration_url)
        .await?;
    let migrator = sqlx::migrate!("../../migrations");
    migrator
        .run(&migration_pool)
        .await
        .map_err(|_| Error::Unavailable("database migrations failed".into()))?;
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&state.pool)
        .await?;
    let quoted = format!("\"{}\"", role.replace('"', "\"\""));
    sqlx::query(&format!(
        "REVOKE UPDATE,DELETE,TRUNCATE ON audit_events FROM {quoted}"
    ))
    .execute(&migration_pool)
    .await?;
    sqlx::query(&format!("GRANT SELECT,INSERT ON audit_events TO {quoted}"))
        .execute(&migration_pool)
        .await?;
    sqlx::query(&format!(
        "GRANT USAGE,SELECT ON SEQUENCE audit_events_sequence_seq TO {quoted}"
    ))
    .execute(&migration_pool)
    .await?;
    let unsafe_role:bool=sqlx::query_scalar("SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR pg_has_role(current_user,c.relowner,'USAGE') OR has_schema_privilege(current_user,'public','CREATE') FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname=current_user AND c.oid='audit_events'::regclass").fetch_one(&state.pool).await?;
    if unsafe_role {
        return Err(Error::Forbidden);
    }
    migration_pool.close().await;
    auth::ensure_setup(state).await?;
    agents::seed_agent_tools(state).await?;
    Ok(())
}
pub async fn worker(state: ApiState) {
    let bus = orbit_event_bus::PostgresEventBus {
        pool: state.pool.clone(),
    };
    let worker = Uuid::new_v4();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        // Scheduler: claim due automation windows (durable cron/timer), fire each
        // window exactly once with missed-window coalescing, and dispatch the
        // fired event to its correlated agents/foundation task. Runs before event
        // processing so fired events are picked up in the same tick.
        if let Err(error) = run_scheduler_tick(&state).await {
            tracing::error!(error=%error,"scheduler tick failed")
        }
        // Due sweep: calendar events + reminders whose time arrived get one
        // notification each (claimed exactly once). Runs after the
        // automation scheduler, before event processing.
        if let Err(error) = run_due_sweep(&state).await {
            tracing::error!(error=%error,"due sweep failed")
        }
        // retrieval stops returning them. Owner-scoped sweep; no-op when empty.
        if let Err(error) = run_memory_sweep(&state).await {
            tracing::error!(error=%error,"memory sweep failed")
        }
        if let Err(error) = bus.process_foundation().await {
            tracing::error!(error=%error,"event processor failed")
        }
        if let Err(error) = run_chat_replies(&state).await {
            tracing::error!(error=%error,"chat replies failed")
        }
        if let Err(error) = bus.run_notification_tasks(worker).await {
            tracing::error!(error=%error,"task processor failed")
        }
        let agents_dispatcher = std::sync::Arc::new(agents::AgentDispatcher::new(&state));
        if let Err(error) = orbit_agent_runtime::tick(
            &state.pool,
            state.key_dir.clone(),
            worker,
            agents_dispatcher,
            None,
        )
        .await
        {
            tracing::error!(error=%error,"agent worker failed")
        }
    }
}
/// Chat replies: AGENT_MESSAGE rows parked as QUEUED_REPLY get one FAST-role
/// model call each, then store text. Failures park as FAILED_REPLY with the
/// error, never a faked answer. No tools, no tasks, no permissions.
/// Owner-stated facts worth remembering, pulled from one chat message.
/// Plain substring patterns only (no regex): names become Person memories,
/// likes and favorites become Preference memories. Best-effort by design;
/// anything odd is skipped, never stored.
async fn run_chat_replies(state: &ApiState) -> orbit_core::Result<()> {
    use sqlx::Row;
    let queued = sqlx::query("SELECT owner_id,id,principal_id,correlation_id,payload FROM events WHERE event_type='AGENT_MESSAGE' AND payload->>'status'='QUEUED_REPLY' ORDER BY timestamp LIMIT 5").fetch_all(&state.pool).await?;
    for row in queued {
        let scope = OwnerScope { owner_id: row.get("owner_id"), principal_id: row.get("principal_id") };
        let id: uuid::Uuid = row.get("id");
        let payload: serde_json::Value = row.get("payload");
        let reply_to = payload.get("reply_to").and_then(serde_json::Value::as_str).unwrap_or("");
        let user_row: Option<(Option<String>, serde_json::Value)> = sqlx::query_as("SELECT payload->>'text', payload FROM events WHERE owner_id=$1 AND id=$2::uuid").bind(scope.owner_id).bind(reply_to).fetch_optional(&state.pool).await?;
        let (user_text, user_payload) = user_row.map(|(t, p)| (t.unwrap_or_default(), p)).unwrap_or_default();
        if user_text.trim().is_empty() {
            sqlx::query("UPDATE events SET payload=jsonb_set(payload,'{status}','\"FAILED_REPLY\"') WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).execute(&state.pool).await?;
            continue;
        }
        let pinned: Option<uuid::Uuid> = user_payload.get("model_id").and_then(serde_json::Value::as_str).and_then(|s| s.parse().ok());
        let role = user_payload.get("model_role").and_then(serde_json::Value::as_str).map(|s| match s { "PRIVATE" => orbit_core::ModelRole::Private, "REASONING" => orbit_core::ModelRole::Reasoning, "CODING" => orbit_core::ModelRole::Coding, "VISION" => orbit_core::ModelRole::Vision, "EMBEDDING" => orbit_core::ModelRole::Embedding, _ => orbit_core::ModelRole::Fast }).unwrap_or(orbit_core::ModelRole::Fast);
        let request = orbit_model_router::RoutedRequest {
            role,
            chat: orbit_model_router::ChatRequest { messages: vec![orbit_model_router::ChatMessage { role: "user".into(), content: user_text.clone(), tool_call_id: None, tool_calls: vec![], images: vec![] }], tools: vec![], output_schema: None, max_output_tokens: 1024, reasoning: false },
            context: vec![],
            privacy: orbit_core::PrivacyClass::Private,
            task_id: None,
            task_fence: None,
            agent_id: None,
            automatic: true,
            model_id: pinned,
        };
        let answer = tokio::time::timeout(std::time::Duration::from_secs(120), orbit_model_router::ModelRouter::new(state.pool.clone(), state.key_dir.clone()).complete(&scope, request)).await;
        match answer {
            Ok(Ok(answer)) => {
                let clipped = answer.response.text.chars().take(32768).collect::<String>();
                sqlx::query("UPDATE events SET payload=payload||$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).bind(serde_json::json!({"status":"REPLIED","text":clipped,"model":answer.route.model,"finish_reason":answer.response.finish_reason})).execute(&state.pool).await?;
                for (memory_type, subject, value) in orbit_memory::extract_owner_facts(&user_text) {
                    let candidate = orbit_memory::Candidate { memory_type, subject, value: serde_json::json!({"text": value}), source_references: vec![], related_entities: vec![], privacy_class: orbit_core::PrivacyClass::Private, confidence: 0.8, valid_until: None, entity_id: None };
                    let provenance = orbit_memory::owner_provenance(&scope, &candidate);
                    let _ = orbit_memory::ingest(&state.pool, &scope, candidate, provenance, None, None).await;
                }
            }
            Ok(Err(e)) => {
                let msg = e.to_string();
                sqlx::query("UPDATE events SET payload=payload||$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).bind(serde_json::json!({"status":"FAILED_REPLY","error":msg})).execute(&state.pool).await?;
            }
            Err(_) => {
                sqlx::query("UPDATE events SET payload=payload||$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).bind(serde_json::json!({"status":"FAILED_REPLY","error":"reply timed out"})).execute(&state.pool).await?;
            }
        }
    }
    Ok(())
}
async fn run_scheduler_tick(state: &ApiState) -> orbit_core::Result<()> {
    let workers=sqlx::query("SELECT owner_id,id FROM principals WHERE principal_type='SYSTEM' AND source='orbit-worker'").fetch_all(&state.pool).await?;
    for row in workers {
        use sqlx::Row;
        let scope = OwnerScope {
            owner_id: row.get("owner_id"),
            principal_id: row.get("id"),
        };
        orbit_scheduler::tick(&state.pool, &scope).await?;
    }
    Ok(())
}

/// Due sweep: exactly-once notifications for time-arrived calendar events +
/// reminders, and for new mail matching a triage rule that asks for a
/// summary (label-only rules stay silent). Mail bodies are never copied
/// into the notification — subject + sender only; the body stays behind
/// the authenticated reader. SKIP LOCKED so multi-worker ticks don't
/// double-fire.
async fn run_due_sweep(state: &ApiState) -> orbit_core::Result<()> {
    use sqlx::Row;
    // Calendar events whose start arrived and never fired.
    let due_events = sqlx::query("SELECT owner_id,id,title,starts_at FROM calendar_events WHERE starts_at IS NOT NULL AND starts_at <= now() AND notified_at IS NULL ORDER BY starts_at LIMIT 20 FOR UPDATE SKIP LOCKED").fetch_all(&state.pool).await?;
    for e in due_events {
        let owner: uuid::Uuid = e.get("owner_id");
        let id: uuid::Uuid = e.get("id");
        let title: String = e.get("title");
        let mut tx = state.pool.begin().await?;
        let claimed: bool = sqlx::query_scalar("UPDATE calendar_events SET notified_at=now() WHERE owner_id=$1 AND id=$2 AND notified_at IS NULL RETURNING true").bind(owner).bind(id).fetch_optional(&mut *tx).await?.unwrap_or(false);
        if !claimed { continue; }
        let corr = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO notifications(id,owner_id,correlation_id,severity,title,body) VALUES($1,$2,$3,'ACTION_REQUIRED','Event starting',$4)").bind(uuid::Uuid::new_v4()).bind(owner).bind(corr).bind(format!("Starting now: {title}")).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    // Reminders whose time arrived, not done, never fired.
    let due_rems = sqlx::query("SELECT owner_id,id,title FROM reminders WHERE done=false AND remind_at IS NOT NULL AND remind_at <= now() AND notified_at IS NULL ORDER BY remind_at LIMIT 20 FOR UPDATE SKIP LOCKED").fetch_all(&state.pool).await?;
    for r in due_rems {
        let owner: uuid::Uuid = r.get("owner_id");
        let id: uuid::Uuid = r.get("id");
        let title: String = r.get("title");
        let mut tx = state.pool.begin().await?;
        let claimed: bool = sqlx::query_scalar("UPDATE reminders SET notified_at=now() WHERE owner_id=$1 AND id=$2 AND notified_at IS NULL RETURNING true").bind(owner).bind(id).fetch_optional(&mut *tx).await?.unwrap_or(false);
        if !claimed { continue; }
        let corr = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO notifications(id,owner_id,correlation_id,severity,title,body) VALUES($1,$2,$3,'ACTION_REQUIRED','Reminder',$4)").bind(uuid::Uuid::new_v4()).bind(owner).bind(corr).bind(format!("Reminder due: {title}")).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    // New mail: only when a triage rule with summarize=true matches.
    // Label-only rules stay silent by design.
    let fresh = sqlx::query("SELECT owner_id,id,account_id,metadata FROM email_messages WHERE notified_at IS NULL ORDER BY received_at LIMIT 20 FOR UPDATE SKIP LOCKED").fetch_all(&state.pool).await?;
    for m in fresh {
        let owner: uuid::Uuid = m.get("owner_id");
        let id: uuid::Uuid = m.get("id");
        let meta: serde_json::Value = m.get("metadata");
        let from = meta.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let subject = meta.get("subject").and_then(|v| v.as_str()).unwrap_or("(no subject)");
        let topic = meta.get("topic").and_then(|v| v.as_str()).unwrap_or("");
        let rules: Vec<(serde_json::Value, serde_json::Value)> = sqlx::query("SELECT matcher,action FROM triage_rules WHERE owner_id=$1 AND enabled").bind(owner).fetch_all(&state.pool).await?.iter().map(|r| (r.get("matcher"), r.get("action"))).collect();
        let mut wants_summary = false;
        for (matcher, action) in &rules {
            if crate::email::triage_matches(matcher, from, subject, topic) {
                wants_summary = action.get("summarize").and_then(|v| v.as_bool()).unwrap_or(false);
                break;
            }
        }
        let mut tx = state.pool.begin().await?;
        sqlx::query("UPDATE email_messages SET notified_at=now() WHERE owner_id=$1 AND id=$2").bind(owner).bind(id).execute(&mut *tx).await?;
        if wants_summary {
            let corr = uuid::Uuid::new_v4();
            sqlx::query("INSERT INTO notifications(id,owner_id,correlation_id,severity,title,body) VALUES($1,$2,$3,'INFO','Mail needs a look',$4)").bind(uuid::Uuid::new_v4()).bind(owner).bind(corr).bind(format!("From {from}: {subject}")).execute(&mut *tx).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

async fn run_memory_sweep(state: &ApiState) -> orbit_core::Result<()> {
    let workers=sqlx::query("SELECT owner_id,id FROM principals WHERE principal_type='SYSTEM' AND source='orbit-worker'").fetch_all(&state.pool).await?;
    for row in workers {
        use sqlx::Row;
        let scope = OwnerScope {
            owner_id: row.get("owner_id"),
            principal_id: row.get("id"),
        };
        orbit_memory::sweep_expired(&state.pool, &scope).await?;
    }
    Ok(())
}
