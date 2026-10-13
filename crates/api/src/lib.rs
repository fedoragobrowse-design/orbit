pub mod browser_routes;
pub mod agents;
pub mod auth;
pub mod automations;
pub mod brief;
pub mod calendar;
pub mod computers;
pub mod connectors;
pub mod control;
pub mod email;
pub mod executors;
pub mod foundation;
pub use executors::ExecutorRegistry;
pub mod gateway;
pub mod inbox;
pub mod marketplace;
pub mod mcp_server;
pub mod memory;
pub mod models;
pub mod notes;
pub mod ops;
pub mod proactive;
pub mod push;
pub mod runtimes;
pub mod search;
pub mod desktop_observation;
pub mod observations;
pub mod shell_routes;
pub mod skills;
pub mod updates;
pub mod tokens;
pub mod uploads;
pub mod utility_tabs;
pub mod workspace_routes;
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
            Error::AskOwnerParked(_) => (StatusCode::CONFLICT, "ASK_OWNER_PARKED"),
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
        .merge(mcp_server::router(state.clone()))
        .merge(marketplace::router())
        .merge(computers::router())
        .merge(desktop_observation::router())
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
        .merge(workspace_routes::router())
        .merge(shell_routes::router())
        .merge(browser_routes::router())
        .merge(proactive::router())
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
    let backends = build_backend_registry();
    // Bounded task pump: at most 2 concurrent tasks on full profile, 1 on Pi.
    // The semaphore permit is held for the whole claim→tick→settle span so an
    // over-capacity worker parks instead of spawning unbounded tasks.
    let task_permits = std::sync::Arc::new(tokio::sync::Semaphore::new(task_concurrency().max(1)));
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        if let Err(error) = run_housekeeping(&state, &bus, worker).await {
            tracing::error!(error=%error,"housekeeping tick failed")
        }
        if let Err(error) = run_task_pump(&state, worker, &backends, &task_permits).await {
            tracing::error!(error=%error,"task pump failed")
        }
    }
}
/// Worker profile: Pi 4 2GiB fits one live task and one live browser at a
/// time; full keeps two of each. Proactive drains one candidate per tick on
/// Pi so observation bursts queue instead of fanning out model work.
const MAX_TASK_CONCURRENCY_FULL: usize = 2;
const MAX_TASK_CONCURRENCY_PI: usize = 1;
const MAX_BROWSER_SESSIONS_FULL: usize = 2;
const MAX_BROWSER_SESSIONS_PI: usize = 1;
const PROACTIVE_DRAIN_FULL: i64 = 20;
const PROACTIVE_DRAIN_PI: i64 = 1;

/// True when `ORBIT_PROFILE=pi` (case-insensitive). Anything else — missing,
/// `full`, typos — is the full profile: fail open to full capacity, never to
/// an unbounded or zero-worker shape.
pub fn profile_is_pi() -> bool {
    concurrency_is_pi(&std::env::var("ORBIT_PROFILE").unwrap_or_default())
}

fn concurrency_is_pi(profile: &str) -> bool {
    profile.eq_ignore_ascii_case("pi")
}

pub(crate) fn task_concurrency() -> usize {
    if profile_is_pi() {
        MAX_TASK_CONCURRENCY_PI
    } else {
        MAX_TASK_CONCURRENCY_FULL
    }
}

/// Live browser-session ceiling for this profile (1 pi / 2 full). Enforced
/// at session create; over-capacity creates fail with `BROWSER_BUSY`
/// (`Unavailable` → 503) so the caller retries instead of stacking
/// Chromium contexts on a 2GiB host.
pub fn browser_concurrency() -> usize {
    if profile_is_pi() {
        MAX_BROWSER_SESSIONS_PI
    } else {
        MAX_BROWSER_SESSIONS_FULL
    }
}

/// Observation-outbox rows drained per housekeeping tick (1 pi / 20 full).
pub(crate) fn proactive_drain_limit() -> i64 {
    if profile_is_pi() {
        PROACTIVE_DRAIN_PI
    } else {
        PROACTIVE_DRAIN_FULL
    }
}

/// Build the governed backend registry once per worker boot. Fail-closed OMP
/// default: an invalid `agent_backend` value falls back to OMP, never to an
/// unmanaged inline path — the registry is always `Some`.
///
/// The registry wraps the admitted AIec execution connection only; when no
/// AIec connection is admitted, the inner TaskRuntime fails closed with
/// `SANDBOX_UNAVAILABLE` and the task parks `WAITING_FOR_RESOURCE` through
/// the normal `Unavailable` path. There is no host fallback — sandbox-off
/// local execution arrives in a later slice through the execution-host
/// service, not by executing on the server host here.
fn build_backend_registry() -> std::sync::Arc<orbit_agent_backend::registry::BackendRegistry> {
    use orbit_sandbox_dispatch::GovernedExec;
    let runtime: std::sync::Arc<dyn orbit_task_runtime::TaskRuntime> =
        std::sync::Arc::new(UnavailableRuntime);
    let exec = std::sync::Arc::new(GovernedExec::new(
        runtime,
        "orbit-agent-runner".to_string(),
        1024,
        1,
    ));
    let default = configured_backend_default();
    std::sync::Arc::new(orbit_agent_backend::registry::BackendRegistry::new(
        exec,
        "/workspace/omp/packages/coding-agent/scripts/omp",
        default,
    ))
}

/// Fail-closed backend default: parse `ORBIT_AGENT_BACKEND`, fall back to OMP
/// on missing/invalid. Per-run settings selection happens in the task pump
/// via [`run_task_pump`]; this only seeds the registry default.
fn configured_backend_default() -> orbit_agent_backend::BackendKind {
    let raw = std::env::var("ORBIT_AGENT_BACKEND").unwrap_or_else(|_| "OMP".to_string());
    orbit_agent_backend::BackendKind::parse(&raw).unwrap_or(orbit_agent_backend::BackendKind::Omp)
}

/// TaskRuntime that always fails closed. The worker never executes model
/// backends or tools on the host: when no admitted AIec connection backs the
/// registry, backend steps return `WAITING_FOR_RESOURCE` (`SANDBOX_UNAVAILABLE`)
/// through the normal `Unavailable` path, never a host fallback.
struct UnavailableRuntime;
#[async_trait::async_trait]
impl orbit_task_runtime::TaskRuntime for UnavailableRuntime {
    async fn create(&self, _spec: orbit_task_runtime::RuntimeSpec) -> orbit_core::Result<orbit_task_runtime::RuntimeHandle> {
        Err(orbit_core::Error::Unavailable("SANDBOX_UNAVAILABLE".to_string()))
    }
    async fn execute(&self, _handle: &orbit_task_runtime::RuntimeHandle, _task: orbit_task_runtime::RuntimeTask) -> orbit_core::Result<orbit_task_runtime::RuntimeResult> {
        Err(orbit_core::Error::Unavailable("SANDBOX_UNAVAILABLE".to_string()))
    }
    async fn put_file(&self, _handle: &orbit_task_runtime::RuntimeHandle, _path: &str, _bytes: &[u8]) -> orbit_core::Result<()> {
        Err(orbit_core::Error::Unavailable("SANDBOX_UNAVAILABLE".to_string()))
    }
    async fn collect_artifacts(&self, _handle: &orbit_task_runtime::RuntimeHandle) -> orbit_core::Result<Vec<orbit_task_runtime::Artifact>> {
        Err(orbit_core::Error::Unavailable("SANDBOX_UNAVAILABLE".to_string()))
    }
    async fn destroy(&self, _handle: orbit_task_runtime::RuntimeHandle) -> orbit_core::Result<()> {
        Ok(())
    }
}
/// Housekeeping keeps the existing 1-second schedule (scheduler, due sweep,
/// memory sweep, foundation events, chat replies, notifications) and never
/// awaits model/browser execution.
async fn run_housekeeping(state: &ApiState, bus: &orbit_event_bus::PostgresEventBus, worker: Uuid) -> orbit_core::Result<()> {
    // Scheduler: claim due automation windows (durable cron/timer), fire each
    // window exactly once with missed-window coalescing, and dispatch the
    // fired event to its correlated agents/foundation task. Runs before event
    // processing so fired events are picked up in the same tick.
    if let Err(error) = run_scheduler_tick(state).await {
        tracing::error!(error=%error,"scheduler tick failed")
    }
    // Due sweep: calendar events + reminders whose time arrived get one
    // notification each (claimed exactly once). Runs after the
    // automation scheduler, before event processing.
    if let Err(error) = run_due_sweep(state).await {
        tracing::error!(error=%error,"due sweep failed")
    }
    // Proactive drain: unpublished observation-outbox rows queue one
    // candidate per matching enabled rule (replay-safe via the UNIQUE
    // fire-key guard). The per-tick ceiling is profile-gated (1 pi / 20
    // full) so an outbox burst on a 2GiB host queues instead of fanning
    // out candidate inserts + downstream model work in one tick.
    if let Err(error) = crate::proactive::drain_observation_outbox(&state.pool, proactive_drain_limit()).await {
        tracing::error!(error=%error,"proactive drain failed")
    }
    // retrieval stops returning them. Owner-scoped sweep; no-op when empty.
    if let Err(error) = run_memory_sweep(state).await {
        tracing::error!(error=%error,"memory sweep failed")
    }
    // Desktop observation expiry: drop `desktop` rows past expires_at so OCR
    // text lives at most retention_hours (24h default) unless explicitly kept.
    if let Err(error) = desktop_observation::sweep_expired_desktop_observations(&state.pool).await {
        tracing::error!(error=%error,"desktop observation expiry sweep failed")
    }
    if let Err(error) = bus.process_foundation().await {
        tracing::error!(error=%error,"event processor failed")
    }
    if let Err(error) = run_chat_replies(state).await {
        tracing::error!(error=%error,"chat replies failed")
    }
    if let Err(error) = bus.run_notification_tasks(worker).await {
        tracing::error!(error=%error,"task processor failed")
    }
    // Idle session stops (timers proven below): browsers idle 5min and
    // terminals idle 15min flip to STOPPED with recoverable state (rows +
    // events + workspace dirs survive; only the live PTY/Chromium context
    // dies). The host daemons own process teardown via their own timers.
    match sweep_idle_browser_sessions(&state.pool).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(stopped = n, "idle browser sessions stopped"),
        Err(error) => tracing::error!(error=%error, "idle browser sweep failed"),
    }
    match sweep_idle_terminal_sessions(&state.pool).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(stopped = n, "idle terminal sessions stopped"),
        Err(error) => tracing::error!(error=%error, "idle terminal sweep failed"),
    }
    Ok(())
}
/// Idle session sweeps: STOP idle browser sessions after 5 minutes and idle
/// terminal sessions after 15 minutes of no `updated_at` touch. Every
/// actuation/snapshot/input path stamps `updated_at=now()`, so a swept row
/// was genuinely unattended. Sweeps only flip the row to `STOPPED` and
/// release grants/holds; the browser-host/execution-host daemons own process
/// teardown via their own idle timers (recoverable state: rows + events +
/// workspace dirs survive, only the live PTY/Chromium context dies).
async fn sweep_idle_browser_sessions(pool: &PgPool) -> orbit_core::Result<u64> {
    // 5-minute browser idle window (profile-independent: a stale Chromium
    // context is the expensive thing on either profile).
    let rows = sqlx::query(
        "SELECT id, owner_id FROM browser_sessions WHERE state='RUNNING' AND updated_at < now() - make_interval(mins => 5) LIMIT 50",
    )
    .fetch_all(pool)
    .await?;
    let mut stopped = 0u64;
    for row in rows {
        use sqlx::Row;
        let id: Uuid = row.get("id");
        let owner: Uuid = row.get("owner_id");
        let mut tx = pool.begin().await?;
        let affected = sqlx::query(
            "UPDATE browser_sessions SET state='STOPPED', takeover=false, revision=revision+1, updated_at=now() WHERE id=$1 AND state='RUNNING'",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if affected == 1 {
            // Release the session grant + any takeover hold with the stop so
            // a later reopen starts from a clean grant set.
            sqlx::query("DELETE FROM scope_grants WHERE owner_id=$1 AND scope_key=$2")
                .bind(owner)
                .bind(format!("browser-session:{id}"))
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "INSERT INTO run_events(owner_id, browser_session_id, kind, payload) VALUES($1, $2, 'STATUS', '{\"idle\": true}')"
            )
            .bind(owner)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            stopped += 1;
        }
        tx.commit().await?;
    }
    Ok(stopped)
}

async fn sweep_idle_terminal_sessions(pool: &PgPool) -> orbit_core::Result<u64> {
    // 15-minute terminal idle window (profile-independent). Mirror of the
    // exec-host daemon's own reap: the row flips to STOPPED here so the API
    // stops advertising a dead PTY; the daemon kills the process group.
    // Scoped to SHELL rows (the PTY-backed kind); BACKEND/BROWSER rows are
    // owned by their own lifecycles.
    let res = sqlx::query(
        "UPDATE execution_sessions SET state='STOPPED', updated_at=now() WHERE kind='SHELL' AND state='RUNNING' AND updated_at < now() - make_interval(mins => 15)",
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
/// Task pump: run agent/gateway tasks through `agent-runtime` with a concrete
/// `AgentBackend` (never `None`). One live task per conversation: a
/// conversation that already has a live RUNNING task queues later turns
/// behind it (the claim is simply skipped this pass). Cancel/kill-switch
/// propagates via the task fence/lease checks inside `tick_single`/`run`.
async fn run_task_pump(state: &ApiState, worker: Uuid, backends: &std::sync::Arc<orbit_agent_backend::registry::BackendRegistry>, task_permits: &std::sync::Arc<tokio::sync::Semaphore>) -> orbit_core::Result<()> {
    // Drain one pump pass: spawn at most `task_concurrency()` concurrent
    // claim→tick→settle tasks (2 full / 1 pi). Each spawned task holds one
    // semaphore permit for its whole span, so over-capacity work parks
    // instead of spawning unbounded tasks. Housekeeping already ran on the
    // 1s schedule and never awaits these tasks beyond this pass.
    let mut pending: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let rows = sqlx::query("SELECT owner_id,id FROM tasks WHERE consumer IN ('agents','gateway') AND (state='QUEUED' OR (state='RUNNING' AND lease_until<now())) ORDER BY created_at,id LIMIT 10").fetch_all(&state.pool).await?;
    for row in rows {
        use sqlx::Row;
        let owner: Uuid = row.get("owner_id");
        let task: Uuid = row.get("id");
        // Per-conversation single-live-task queue: skip a claim while another
        // live RUNNING task for the same conversation exists. `tick_single`
        // re-checks this under an advisory lock at claim time, so this
        // pre-check is only a cheap filter, not the authority.
        let conversation: Option<String> = sqlx::query_scalar("SELECT checkpoint->>'conversation_id' FROM tasks WHERE owner_id=$1 AND id=$2").bind(owner).bind(task).fetch_optional(&state.pool).await?.flatten();
        if let Some(conversation) = conversation {
            let live: i64 = sqlx::query_scalar("SELECT count(*) FROM tasks WHERE owner_id=$1 AND id!=$2 AND consumer IN ('agents','gateway') AND state='RUNNING' AND checkpoint->>'conversation_id'=$3 AND lease_until>now()").bind(owner).bind(task).bind(&conversation).fetch_one(&state.pool).await?;
            if live > 0 {
                continue;
            }
        }
        let permit = match task_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => break,
        };
        let backend = backend_for_task(&state.pool, backends, owner, task).await;
        let pool = state.pool.clone();
        let key_dir = state.key_dir.clone();
        let pump_state = state.clone();
        pending.push(tokio::spawn(async move {
            // Hold the permit across the whole tick so concurrency stays bounded.
            let _permit = permit;
            let agents_dispatcher = std::sync::Arc::new(agents::AgentDispatcher::new(&pump_state));
            record_active_backend(&pool, owner, task, backend.kind()).await;
            if let Err(error) = orbit_agent_runtime::tick_single(&pool, key_dir, worker, agents_dispatcher, Some(backend), owner, task).await {
                tracing::error!(error=%error,"agent worker failed")
            }
        }));
    }
    for task in pending {
        let _ = task.await;
    }
    Ok(())
}
/// Resolve the backend for one task from owner settings (`agent_backend`),
/// with a per-agent override when the task's `agent_definitions.definition`
/// carries an `agent_backend` key. Fail-closed to OMP on invalid. A backend
/// already recorded in the task checkpoint (a prior pump pass claimed this
/// task) wins so a run never switches backends mid-flight. The selected kind
/// is persisted into the task checkpoint so the run records which backend
/// owns it.
async fn backend_for_task(pool: &PgPool, backends: &std::sync::Arc<orbit_agent_backend::registry::BackendRegistry>, owner: Uuid, task: Uuid) -> std::sync::Arc<dyn orbit_agent_backend::AgentBackend> {
    let raw: Option<String> = sqlx::query_scalar("SELECT value->>'agent_backend' FROM settings WHERE owner_id=$1").bind(owner).fetch_optional(pool).await.unwrap_or(None).flatten();
    // Explicit per-agent choice in the task's agent definition wins over the
    // owner-wide settings default when valid. The agent is resolved from the
    // task's run row, falling back to the checkpoint-recorded agent id.
    let agent_override: Option<String> = async {
        let agent: Option<Uuid> = sqlx::query_scalar("SELECT agent_id FROM agent_runs WHERE owner_id=$1 AND task_id=$2").bind(owner).bind(task).fetch_optional(pool).await.unwrap_or(None);
        let agent = match agent {
            Some(agent) => Some(agent),
            None => sqlx::query_scalar("SELECT (checkpoint->>'agent_id')::uuid FROM tasks WHERE owner_id=$1 AND id=$2 AND checkpoint ? 'agent_id'").bind(owner).bind(task).fetch_optional(pool).await.unwrap_or(None).flatten(),
        };
        match agent {
            Some(agent) => sqlx::query_scalar("SELECT definition->>'agent_backend' FROM agent_definitions WHERE owner_id=$1 AND id=$2").bind(owner).bind(agent).fetch_optional(pool).await.unwrap_or(None).flatten(),
            None => None,
        }
    }
    .await;
    // Sticky per-task choice recorded by an earlier pump pass wins when valid.
    let checkpoint_raw: Option<String> = sqlx::query_scalar("SELECT checkpoint->>'agent_backend' FROM tasks WHERE owner_id=$1 AND id=$2").bind(owner).bind(task).fetch_optional(pool).await.unwrap_or(None).flatten();
    let pick = checkpoint_raw.or(agent_override).or(raw).unwrap_or_else(|| "OMP".to_string());
    let kind = orbit_agent_backend::BackendKind::parse(&pick).unwrap_or(orbit_agent_backend::BackendKind::Omp);
    backends.get(kind)
}
/// Record the active backend kind in the task checkpoint (`agent_backend`)
/// and on its `agent_runs` row (`route.backend`) so the run visibly records
/// which backend owns it. Best-effort: a missing run row or a racing claim
/// only skips the annotation, never the task itself.
async fn record_active_backend(pool: &PgPool, owner: Uuid, task: Uuid, kind: orbit_agent_backend::BackendKind) {
    let name = kind.as_str();
    let _ = sqlx::query("UPDATE tasks SET checkpoint=checkpoint||jsonb_build_object('agent_backend',$3) WHERE owner_id=$1 AND id=$2").bind(owner).bind(task).bind(name).execute(pool).await;
    let _ = sqlx::query("UPDATE agent_runs SET route=COALESCE(route,'{}'::jsonb)||jsonb_build_object('backend',$3) WHERE owner_id=$1 AND task_id=$2").bind(owner).bind(task).bind(name).execute(pool).await;
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
/// double-fire. Calendar/reminder claims additionally emit one CALENDAR_DUE
/// / REMINDER_DUE event each (fire-key idempotent) after the claim commits.
/// Owner scope for worker-originated emits (due sweep): the owner's SYSTEM
/// `orbit-worker` principal when present, else any owner principal. The
/// events table needs a principal_id; the SYSTEM trust on due events comes
/// from the emit itself, not from which principal row is named here.
async fn worker_scope(pool: &sqlx::PgPool, owner: uuid::Uuid) -> orbit_core::Result<OwnerScope> {
    use sqlx::Row;
    if let Some(r) = sqlx::query("SELECT id FROM principals WHERE owner_id=$1 AND principal_type='SYSTEM' AND source='orbit-worker' ORDER BY id LIMIT 1").bind(owner).fetch_optional(pool).await? {
        let principal_id: uuid::Uuid = r.get("id");
        return Ok(OwnerScope { owner_id: owner, principal_id });
    }
    let r = sqlx::query("SELECT id FROM principals WHERE owner_id=$1 ORDER BY id LIMIT 1").bind(owner).fetch_optional(pool).await?.ok_or(orbit_core::Error::NotFound)?;
    let principal_id: uuid::Uuid = r.get("id");
    Ok(OwnerScope { owner_id: owner, principal_id })
}
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
        // Due-sweep fire key: one CALENDAR_DUE event per calendar row,
        // idempotent on calendar-due:<id> (CAS claim above preserved; the
        // event insert is its own tx so a crash between claim and emit
        // replays as a silent no-op, never a double-fire).
        let scope = worker_scope(&state.pool, owner).await?;
        crate::observations::emit_due_event(&state.pool, &scope, orbit_core::EventType::CalendarDue, id, &title).await?;
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
        // Same fire-key pattern: one REMINDER_DUE per reminder row.
        let scope = worker_scope(&state.pool, owner).await?;
        crate::observations::emit_due_event(&state.pool, &scope, orbit_core::EventType::ReminderDue, id, &title).await?;
    }
    // New mail: only when a triage rule with summarize=true matches.
    // Label-only rules stay silent by design. Explicit per-rule priority
    // first (`action.priority`, default 0), then created_at, then id.
    let fresh = sqlx::query("SELECT owner_id,id,account_id,metadata FROM email_messages WHERE notified_at IS NULL ORDER BY received_at LIMIT 20 FOR UPDATE SKIP LOCKED").fetch_all(&state.pool).await?;
    for m in fresh {
        let owner: uuid::Uuid = m.get("owner_id");
        let id: uuid::Uuid = m.get("id");
        let meta: serde_json::Value = m.get("metadata");
        let from = meta.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let subject = meta.get("subject").and_then(|v| v.as_str()).unwrap_or("(no subject)");
        let topic = meta.get("topic").and_then(|v| v.as_str()).unwrap_or("");
        let mut rules: Vec<(serde_json::Value, serde_json::Value)> = sqlx::query("SELECT matcher,action FROM triage_rules WHERE owner_id=$1 AND enabled").bind(owner).fetch_all(&state.pool).await?.iter().map(|r| (r.get("matcher"), r.get("action"))).collect();
        // Explicit priority first, then creation order, then id (no DDL:
        // priority is an optional action key, default 0).
        rules.sort_by(|a, b| crate::email::rule_priority(&a.1).cmp(&crate::email::rule_priority(&b.1)));
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
