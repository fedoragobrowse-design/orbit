//! Governed tool execution registry.
//!
//! Routes an already-authorized tool call to its existing executor. Every
//! call still enters through `propose`, validates schemas, classifies risk,
//! evaluates policy, consumes authorization and records results upstream;
//! this registry only selects the executor. A registered descriptor without
//! an executor is `TOOL_EXECUTOR_UNAVAILABLE`, never an invented completion.

use orbit_core::{AuthorizedAction, Error, OwnerScope, Result};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone)]
pub struct ExecutorRegistry {
    pub pool: PgPool,
    pub key_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub origin: String,
}

impl ExecutorRegistry {
    pub async fn route(
        &self,
        scope: &OwnerScope,
        task: Uuid,
        agent: Uuid,
        name: &str,
        args: &Value,
        action: AuthorizedAction,
    ) -> Result<Value> {
        {
            let snapshot = action.snapshot();
            if snapshot.tool_name != name
                || snapshot.task_id != task
                || snapshot.agent_id != Some(agent)
                || snapshot.arguments != *args
                || snapshot.owner_id != scope.owner_id
                || snapshot.principal_id != scope.principal_id
            {
                return Err(Error::Forbidden);
            }
        }
        match name {
            "memory.search" | "memory.propose" => {
                orbit_memory::execute_authorized(&self.pool, &self.key_dir, scope, &action).await
            }
            "shell.execute" => {
                use orbit_tools::ToolExecutor;
                let executor = crate::runtimes::ShellExecutor {
                    pool: self.pool.clone(),
                    artifact_dir: self.artifact_dir.clone(),
                    key_dir: self.key_dir.clone(),
                };
                Ok(executor.execute(scope, action).await?.output)
            }
            _ if name.starts_with("browser.session.") => {
                crate::browser_routes::execute_session_tool(
                    &self.pool,
                    &self.artifact_dir,
                    scope,
                    name,
                    args,
                )
                .await
            }
            _ if name.starts_with("files.") => {
                Err(Error::Unavailable("TOOL_EXECUTOR_UNAVAILABLE".into()))
            }
            _ if name.starts_with("mcp.") => {
                let suffix = name
                    .strip_prefix("mcp.")
                    .and_then(|rest| rest.split_once('.'))
                    .map(|(_, tool)| tool)
                    .filter(|tool| !tool.is_empty())
                    .ok_or(Error::Forbidden)?;
                let row = sqlx::query(
                    "SELECT connection_id, original_name FROM mcp_tools WHERE owner_id=$1 AND registry_name=$2",
                )
                .bind(scope.owner_id)
                .bind(name)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(Error::Forbidden)?;
                let connection_id: Uuid = row.get("connection_id");
                let original_name: String = row.get("original_name");
                if original_name != suffix {
                    return Err(Error::Forbidden);
                }
                let call_args = action.snapshot().arguments.clone();
                let authorization = action.authorization_id();
                let manager = orbit_mcp::ConnectionManager::new(
                    self.pool.clone(),
                    self.key_dir.clone(),
                    self.artifact_dir.clone(),
                );
                manager
                    .call_once(scope, connection_id, &original_name, call_args, authorization)
                    .await
            }
            _ if name == "notifications.create"
                || name == "reports.save"
                || name.starts_with("orbit-control.")
                || name.starts_with("orbit-data.")
                || name.starts_with("ha-control.") =>
            {
                use orbit_tools::ToolExecutor;
                let tools = orbit_tools::SafeTools {
                    pool: self.pool.clone(),
                    artifact_dir: self.artifact_dir.clone(),
                    key_dir: self.key_dir.clone(),
                };
                Ok(tools.execute(scope, action).await?.output)
            }
            _ => Err(Error::Forbidden),
        }
    }
}
