pub mod agents;
pub mod auth;
pub mod automations;
pub mod brief;
pub mod computers;
pub mod email;
pub mod foundation;
pub mod gateway;
pub mod marketplace;
pub mod mcp;
pub mod memory;
pub mod models;
pub mod ops;
pub mod push;
pub mod runtimes;
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
        .merge(brief::router())
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
        // Memory: transition ACTIVE records past valid_until to EXPIRED so
        // retrieval stops returning them. Owner-scoped sweep; no-op when empty.
        if let Err(error) = run_memory_sweep(&state).await {
            tracing::error!(error=%error,"memory sweep failed")
        }
        if let Err(error) = bus.process_foundation().await {
            tracing::error!(error=%error,"event processor failed")
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
        )
        .await
        {
            tracing::error!(error=%error,"agent worker failed")
        }
    }
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
