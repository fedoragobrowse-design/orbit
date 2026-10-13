//! Owner-facing StreamableHTTP MCP servers (McpServer slice).
//!
//! Three authenticated services — `orbit-control`, `orbit-data`, `ha-control` —
//! expose the existing in-process tool descriptors over MCP at
//! `POST+GET /mcp/orbit-control`, `/mcp/orbit-data`, `/mcp/ha-control`.
//! HTTPS is enforced by the front proxy, never here.
//!
//! Auth: rmcp's tower service injects the full `http::request::Parts` into
//! every request's extensions, so each handler resolves the `Authorization:
//! Bearer orb_…` header from `ctx.extensions` and authenticates the token
//! in-process (scoped hashed API tokens, explicit service/tool grants).
//! There are no HTTP self-calls: list/call dispatch runs `orbit_tools`
//! descriptors and the execution pipeline directly.
//!
//! Reads execute synchronously. Mutations submit as durable `tool_calls` rows
//! (approvals survive client disconnect); progress surfaces through the
//! task's state. `cancel` maps to the run: cancelling the MCP task cancels
//! the underlying Orbit task. Denials and unavailable executors return as
//! `isError` results with structured `code` payloads, never protocol errors.
//!
//! `orbit-data` outputs keep their `UNTRUSTED_EXTERNAL` taint: results carry
//! `trust_level`/`tainted` markers verbatim and are never promoted.

use std::collections::BTreeMap;
use std::sync::Arc;

use orbit_core::{Error, OwnerScope};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ContentBlock,
        DetailedTask, GetTaskParams, GetTaskResult, Implementation, InputRequests,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
        Task, TaskPayload, Tool, ToolAnnotations,
    },
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum McpService {
    OrbitControl,
    OrbitData,
    HaControl,
}
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

impl McpService {
    pub fn as_str(&self) -> &'static str {
        match self {
            McpService::OrbitControl => "orbit-control",
            McpService::OrbitData => "orbit-data",
            McpService::HaControl => "ha-control",
        }
    }

    pub fn route_path(&self) -> &'static str {
        match self {
            McpService::OrbitControl => "/mcp/orbit-control",
            McpService::OrbitData => "/mcp/orbit-data",
            McpService::HaControl => "/mcp/ha-control",
        }
    }
}

/// Shared state cloned into every per-connection server instance.
#[derive(Clone)]
pub struct McpServerState {
    pub pool: PgPool,
    pub key_dir: std::path::PathBuf,
    pub artifact_dir: std::path::PathBuf,
    pub origin: String,
}

/// One rmcp server instance serving a single Orbit MCP service.
#[derive(Clone)]
pub struct OrbitMcpServer {
    service: McpService,
    state: McpServerState,
}

/// Structured `isError` payload codes.
pub const CODE_DENIED: &str = "DENIED";
pub const CODE_UNAVAILABLE: &str = "UNAVAILABLE";
pub const CODE_CONNECT_FIRST: &str = "CONNECT_FIRST";
pub const CODE_PENDING_APPROVAL: &str = "PENDING_APPROVAL";
pub const CODE_NOT_FOUND: &str = "NOT_FOUND";

fn is_error(code: &str, message: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(&format!("{code}: {message}"))])
}

/// Resolve the bearer token from the injected HTTP request parts.
fn bearer_from(ctx: &RequestContext<RoleServer>) -> Option<String> {
    let parts = ctx.extensions.get::<http::request::Parts>()?;
    let value = parts.headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let raw = value.strip_prefix("Bearer ")?;
    let raw = raw.strip_prefix(crate::tokens::PREFIX).unwrap_or(raw);
    if raw.is_empty() || raw.len() > 256 {
        return None;
    }
    Some(raw.to_owned())
}

fn invalid_auth() -> McpError {
    McpError::invalid_params("invalid or missing API token", None)
}

/// Authenticate the token and load its explicit grants for this service.
/// Unknown tokens, revoked tokens, and tokens without grants deny closed.
async fn authenticate_token(
    pool: &PgPool,
    bearer: &str,
) -> Result<(OwnerScope, Uuid), McpError> {
    let full = format!("{}{bearer}", crate::tokens::PREFIX);
    let row = sqlx::query(
        "SELECT id, owner_id FROM api_tokens WHERE token_hash=$1 AND revoked=false",
    )
    .bind(crate::auth::hash(&full))
    .fetch_optional(pool)
    .await
    .map_err(|_| McpError::internal_error("token lookup unavailable", None))?
    .ok_or_else(invalid_auth)?;
    let token_id: Uuid = row.get("id");
    let owner: Uuid = row.get("owner_id");
    Ok((
        OwnerScope {
            owner_id: owner,
            principal_id: mcp_principal(pool, owner).await?,
        },
        token_id,
    ))
}

/// The `MCP_SERVER` principal for this owner, created on first use so
/// token-authenticated calls attribute audit rows to a real principal.
async fn mcp_principal(pool: &PgPool, owner: Uuid) -> Result<Uuid, McpError> {
    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM principals WHERE owner_id=$1 AND principal_type='MCP_SERVER' LIMIT 1",
    )
    .bind(owner)
    .fetch_optional(pool)
    .await
    .map_err(|_| McpError::internal_error("principal lookup unavailable", None))?
    {
        return Ok(id);
    }
    let id = Uuid::new_v4();
    // Racy first-use creation collapses to the existing row.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'MCP_SERVER','API_TOKEN','OWNER_AUTHENTICATED','mcp-server') ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(pool)
    .await
    .map_err(|_| McpError::internal_error("principal creation unavailable", None))?;
    if let Some(id) = inserted {
        return Ok(id);
    }
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM principals WHERE owner_id=$1 AND principal_type='MCP_SERVER' LIMIT 1",
    )
    .bind(owner)
    .fetch_one(pool)
    .await
    .map_err(|_| McpError::internal_error("principal lookup unavailable", None))
}

/// Explicit tool grants for this token+service; empty means deny-all.
async fn token_grants(
    pool: &PgPool,
    owner: Uuid,
    token_id: Uuid,
    service: McpService,
) -> Result<Vec<String>, McpError> {
    sqlx::query_scalar::<_, String>(
        "SELECT tool_name FROM api_token_grants WHERE owner_id=$1 AND token_id=$2 AND service=$3 ORDER BY tool_name",
    )
    .bind(owner)
    .bind(token_id)
    .bind(service.as_str())
    .fetch_all(pool)
    .await
    .map_err(|_| McpError::internal_error("grant lookup unavailable", None))
}

/// Descriptors for this service, as `(name, input_schema, output_schema,
/// description, read_only)`. Each service lists only its own namespace.
fn service_descriptors(service: McpService) -> Vec<(String, Value, Value, String, bool)> {
    let prefix = format!("{}.", service.as_str());
    orbit_tools::descriptors()
        .into_iter()
        .filter(|d| d.name.starts_with(&prefix))
        .map(|d| {
            let read_only = d.default_risk == orbit_core::RiskLevel::Low;
            (d.name, d.input_schema, d.output_schema, String::new(), read_only)
        })
        .collect()
}

fn to_tool(
    name: String,
    input_schema: Value,
    output_schema: Value,
    description: String,
    read_only: bool,
) -> Tool {
    let input = input_schema
        .as_object()
        .cloned()
        .unwrap_or_else(|| Map::new());
    let mut tool = Tool::new(name, description, Arc::new(input));
    if let Some(output) = output_schema.as_object() {
        tool.output_schema = Some(Arc::new(output.clone()));
    }
    let mut annotations = ToolAnnotations::new();
    annotations.read_only_hint = Some(read_only);
    annotations.open_world_hint = Some(false);
    tool.annotations = Some(annotations);
    tool
}

impl OrbitMcpServer {
    async fn auth(
        &self,
        ctx: &RequestContext<RoleServer>,
    ) -> Result<(OwnerScope, Vec<String>), McpError> {
        let bearer = bearer_from(ctx).ok_or_else(invalid_auth)?;
        let (scope, token_id) = authenticate_token(&self.state.pool, &bearer).await?;
        let grants = token_grants(&self.state.pool, scope.owner_id, token_id, self.service).await?;
        // Touch last_used without failing the call if the write races.
        let _ = sqlx::query("UPDATE api_tokens SET last_used=now() WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(token_id)
            .execute(&self.state.pool)
            .await;
        Ok((scope, grants))
    }

    fn granted(
        grants: &[String],
        name: &str,
    ) -> Result<(), CallToolResult> {
        if grants.iter().any(|g| g == name) {
            Ok(())
        } else {
            Err(is_error(
                CODE_DENIED,
                &format!("token is not granted tool {name}"),
            ))
        }
    }
}

impl ServerHandler for OrbitMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .build(),
        )
        .with_server_info(Implementation::new(self.service.as_str(), env!("CARGO_PKG_VERSION")))
        .with_instructions(match self.service {
            McpService::OrbitControl => {
                "Orbit control plane: durable task submission; mutations need owner approval"
            }
            McpService::OrbitData => {
                "Orbit data plane: read-only evidence; all outputs are UNTRUSTED_EXTERNAL"
            }
            McpService::HaControl => {
                "Home Assistant control: connect Home Assistant first under Connections"
            }
        })
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let (_, grants) = self.auth(&ctx).await?;
        let mut result = ListToolsResult::default();
        // List returns only the descriptors this token is granted: listing
        // never leaks tools outside the token's explicit grants.
        result.tools = service_descriptors(self.service)
            .into_iter()
            .filter(|(name, _, _, _, _)| grants.iter().any(|g| g == name))
            .map(|(name, input_schema, output_schema, description, read_only)| {
                to_tool(name, input_schema, output_schema, description, read_only)
            })
            .collect();
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let (scope, grants) = self.auth(&ctx).await?;
        if let Err(denied) = Self::granted(&grants, &name) {
            return Ok(denied.into());
        }
        let args = request
            .arguments
            .map(|o| Value::Object(o))
            .unwrap_or(Value::Null);
        match execute_mcp_tool(&self.state, &scope, self.service, &name, args).await {
            Ok(output) => Ok(CallToolResult::structured(output).into()),
            Err(Error::Forbidden) => Ok(is_error(
                CODE_DENIED,
                &format!("tool {name} denied by policy or grant"),
            )
            .into()),
            Err(Error::Unavailable(code)) => Ok(is_error(CODE_UNAVAILABLE, &code).into()),
            Err(Error::Validation(message)) if message.starts_with("connect ") => {
                Ok(is_error(CODE_CONNECT_FIRST, &message).into())
            }
            Err(Error::AskOwnerParked(approval)) => Ok(CallToolResult::structured(json!({
                "code": CODE_PENDING_APPROVAL,
                "approval_id": approval.get("approval_id"),
                "call_id": approval.get("call_id"),
            }))
            .into()),
            Err(error) => Ok(is_error("FAILED", &error.to_string()).into()),
        }
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        let (scope, _) = self.auth(&ctx).await?;
        let task_id: Uuid = request
            .task_id
            .parse()
            .map_err(|_| McpError::invalid_params("task_id must be a UUID", None))?;
        task_status(&self.state.pool, &scope, task_id)
            .await?
            .ok_or_else(|| McpError::invalid_params("unknown task", None))
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let (scope, _) = self.auth(&ctx).await?;
        // Cancel maps to the run: the MCP task id IS the Orbit task id, so
        // cancelling here cancels the underlying durable run.
        let task_id: Uuid = request
            .task_id
            .parse()
            .map_err(|_| McpError::invalid_params("task_id must be a UUID", None))?;
        cancel_mcp_task(&self.state.pool, &scope, task_id).await
    }
}

/// Execute one granted tool call in-process (no HTTP self-calls).
///
/// Reads (`Low` risk) run synchronously through `SafeTools`. Mutations submit
/// as durable `tool_calls` rows: admitted-but-approval-gated calls park in
/// `WAITING_FOR_APPROVAL` (surviving disconnect) and report
/// `PENDING_APPROVAL`; policy-denied calls report `DENIED`.
async fn execute_mcp_tool(
    state: &McpServerState,
    scope: &OwnerScope,
    service: McpService,
    name: &str,
    args: Value,
) -> Result<Value, Error> {
    let descriptor = orbit_tools::descriptors()
        .into_iter()
        .find(|d| d.name == name)
        .ok_or(Error::Forbidden)?;
    if !matches!(service, McpService::OrbitData) && name.starts_with("orbit-data.") {
        // Namespaces never cross services: a control token cannot reach
        // data tools even if a grant row names them.
        return Err(Error::Forbidden);
    }
    orbit_tools::validate_value(&descriptor.input_schema, &args)?;

    // ha-control returns connect-first until an enabled HA connection exists.
    if name.starts_with("ha-control.") {
        let enabled: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ha_connections WHERE owner_id=$1 AND enabled LIMIT 1",
        )
        .bind(scope.owner_id)
        .fetch_optional(&state.pool)
        .await?;
        if enabled.is_none() {
            return Err(Error::Validation(
                "connect Home Assistant first under Connections".into(),
            ));
        }
    }

    if descriptor.default_risk == orbit_core::RiskLevel::Low {
        return execute_read(state, scope, &descriptor, args).await;
    }
    submit_mutation(state, scope, name, &descriptor, args).await
}

/// Synchronous read path: verify a submission envelope in-process, then run.
async fn execute_read(
    state: &McpServerState,
    scope: &OwnerScope,
    descriptor: &orbit_core::ToolDescriptor,
    args: Value,
) -> Result<Value, Error> {
    let snapshot = orbit_core::ActionSnapshot {
        action_id: Uuid::new_v4(),
        owner_id: scope.owner_id,
        principal_id: scope.principal_id,
        agent_id: None,
        task_id: Uuid::nil(),
        tool_name: descriptor.name.clone(),
        tool_version: descriptor.version.clone(),
        arguments: args,
        input_artifact_digests: BTreeMap::new(),
        scope_revisions: BTreeMap::new(),
        policy_revision: policy_revision(&state.pool, scope).await?,
        authorization_epoch: authorization_epoch(&state.pool, scope).await?,
        requires_sandbox: false,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    };
    let action = orbit_core::AuthorizedAction::from_submission(
        snapshot,
        Uuid::new_v4(),
        current_fence(&state.pool, scope).await?,
    );
    let tools = orbit_tools::SafeTools {
        pool: state.pool.clone(),
        artifact_dir: state.artifact_dir.clone(),
        key_dir: state.key_dir.clone(),
    };
    use orbit_tools::ToolExecutor;
    Ok(tools.execute(scope, action).await?.output)
}

/// Durable mutation path: journal the proposal through admission (policy,
/// risk, scope grants), then submit as a `tool_calls` row on its own task so
/// approvals survive client disconnect.
async fn submit_mutation(
    state: &McpServerState,
    scope: &OwnerScope,
    name: &str,
    descriptor: &orbit_core::ToolDescriptor,
    args: Value,
) -> Result<Value, Error> {

    if orbit_core::ContextBlock::looks_like_injection(&args.to_string()) {
        return Err(Error::Forbidden);
    }
    let risk = orbit_risk::RiskClassifier::classify_action(
        &orbit_risk::ProposedAction {
            tool_name: name.into(),
            arguments: args.clone(),
        },
        descriptor,
        &orbit_risk::ActionContext {
            optional_escalation: None,
        },
    )?;
    let decision = load_policy_decision(&state.pool, scope, name, &args, descriptor, risk.level).await?;
    if decision.get("denied").and_then(Value::as_bool).unwrap_or(true) {
        return Err(Error::Forbidden);
    }

    let call = Uuid::new_v4();
    let task = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    let snapshot = orbit_core::ActionSnapshot {
        action_id: call,
        owner_id: scope.owner_id,
        principal_id: scope.principal_id,
        agent_id: None,
        task_id: task,
        tool_name: name.into(),
        tool_version: descriptor.version.clone(),
        arguments: args.clone(),
        input_artifact_digests: BTreeMap::new(),
        scope_revisions: BTreeMap::new(),
        policy_revision: policy_revision(&state.pool, scope).await?,
        authorization_epoch: authorization_epoch(&state.pool, scope).await?,
        requires_sandbox: descriptor.sandbox_required,
        expires_at,
    };
    let hash = orbit_approvals::canonical_hash(&snapshot)?;
    let snapshot_value = serde_json::to_value(&snapshot)?;
    let descriptor_value = serde_json::to_value(&descriptor)?;
    let digest = orbit_computer_node_protocol::sha256(&serde_json::to_vec(&descriptor_value)?);
    let risk_value = serde_json::to_value(&risk)?;
    let key = format!("mcp:{task}:{name}");

    let needs_approval = decision
        .get("requires_approval")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,title,state) VALUES($1,$2,$3,$4,$5,'QUEUED')")
        .bind(task)
        .bind(scope.owner_id)
        .bind(scope.principal_id)
        .bind(correlation)
        .bind(format!("mcp {name}"))
        .execute(&mut *tx)
        .await?;
    if needs_approval {
        let approval = Uuid::new_v4();
        let preview = orbit_approvals::preview(&snapshot);
        sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state,approval_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'WAITING_FOR_APPROVAL',$12)")
            .bind(call).bind(scope.owner_id).bind(task).bind(&key).bind(&hash)
            .bind(&snapshot_value).bind(&hash).bind(&descriptor_value).bind(&digest)
            .bind(&risk_value).bind(&decision).bind(approval)
            .execute(&mut *tx).await?;
        sqlx::query("INSERT INTO approvals(id,owner_id,task_id,call_id,snapshot,action_hash,risk,reasons,preview,policy_decision,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
            .bind(approval).bind(scope.owner_id).bind(task).bind(call)
            .bind(&snapshot_value).bind(&hash).bind(&risk_value)
            .bind(json!([risk_value.get("reasons")])).bind(&preview).bind(&decision).bind(expires_at)
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE tasks SET state='WAITING_FOR_APPROVAL',wait_reason='approval',checkpoint=checkpoint || jsonb_build_object('phase','APPROVAL','approval_id',$3) WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id).bind(task).bind(approval)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        return Err(Error::AskOwnerParked(
            json!({"approval_id": approval, "call_id": call, "task_id": task}),
        ));
    }
    let authorization = Uuid::new_v4();
    let fence: i64 =
        sqlx::query_scalar("SELECT fence FROM tasks WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(task)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state,authorization_id,task_fence,submitted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'SUBMITTED',$12,$13,now())")
        .bind(call).bind(scope.owner_id).bind(task).bind(&key).bind(&hash)
        .bind(&snapshot_value).bind(&hash).bind(&descriptor_value).bind(&digest)
        .bind(&risk_value).bind(&decision).bind(authorization).bind(fence)
        .execute(&mut *tx).await?;
    tx.commit().await?;

    // Execute under the submission envelope in-process (no HTTP self-call).
    let action = orbit_core::AuthorizedAction::from_submission(snapshot, authorization, fence);
    match route_authorized(state, scope, task, name, &args, action).await {
        Ok(output) => {
            let result = serde_json::to_value(&output)?;
            sqlx::query("UPDATE tool_calls SET state='COMPLETED',result=$3,completed_at=now() WHERE owner_id=$1 AND id=$2 AND state='SUBMITTED'")
                .bind(scope.owner_id).bind(call).bind(&result)
                .execute(&state.pool).await?;
            sqlx::query("UPDATE tasks SET state='COMPLETED',updated_at=now() WHERE owner_id=$1 AND id=$2 AND state='QUEUED'")
                .bind(scope.owner_id).bind(task)
                .execute(&state.pool).await?;
            Ok(json!({"call_id": call, "task_id": task, "state": "COMPLETED", "output": output}))
        }
        Err(Error::OutcomeUnknown) => {
            sqlx::query("UPDATE tool_calls SET state='OUTCOME_UNKNOWN',error_code='OUTCOME_UNKNOWN',completed_at=now() WHERE owner_id=$1 AND id=$2 AND state='SUBMITTED'")
                .bind(scope.owner_id).bind(call)
                .execute(&state.pool).await?;
            Ok(json!({"call_id": call, "task_id": task, "state": "OUTCOME_UNKNOWN"}))
        }
        Err(error) => {
            let code = match &error {
                Error::Unauthorized => "UNAUTHORIZED",
                Error::Forbidden => "FORBIDDEN",
                Error::NotFound => "NOT_FOUND",
                Error::Validation(_) => "VALIDATION",
                Error::Conflict(_) => "CONFLICT",
                Error::Unavailable(_) => "UNAVAILABLE",
                _ => "INTERNAL",
            };
            sqlx::query("UPDATE tool_calls SET state='FAILED',error_code=$3,completed_at=now() WHERE owner_id=$1 AND id=$2 AND state='SUBMITTED'")
                .bind(scope.owner_id).bind(call).bind(code)
                .execute(&state.pool).await?;
            sqlx::query("UPDATE tasks SET state='FAILED',updated_at=now() WHERE owner_id=$1 AND id=$2 AND state='QUEUED'")
                .bind(scope.owner_id).bind(task)
                .execute(&state.pool).await?;
            Err(error)
        }
    }
}

/// In-process dispatch for already-authorized MCP calls (mirrors the
/// `ExecutorRegistry` orbit-* arm without importing the dispatcher).
async fn route_authorized(
    state: &McpServerState,
    scope: &OwnerScope,
    task: Uuid,
    name: &str,
    args: &Value,
    action: orbit_core::AuthorizedAction,
) -> Result<Value, Error> {
    {
        let snapshot = action.snapshot();
        if snapshot.tool_name != name
            || snapshot.task_id != task
            || snapshot.arguments != *args
            || snapshot.owner_id != scope.owner_id
            || snapshot.principal_id != scope.principal_id
        {
            return Err(Error::Forbidden);
        }
    }
    use orbit_tools::ToolExecutor;
    let tools = orbit_tools::SafeTools {
        pool: state.pool.clone(),
        artifact_dir: state.artifact_dir.clone(),
        key_dir: state.key_dir.clone(),
    };
    Ok(tools.execute(scope, action).await?.output)
}

async fn policy_revision(pool: &PgPool, scope: &OwnerScope) -> Result<i64, Error> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT revision FROM policies WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(pool)
            .await?
            .unwrap_or(1),
    )
}

async fn authorization_epoch(pool: &PgPool, scope: &OwnerScope) -> Result<i64, Error> {
    sqlx::query_scalar::<_, i64>("SELECT revision FROM authorization_epochs WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::Forbidden)
}

async fn current_fence(pool: &PgPool, scope: &OwnerScope) -> Result<i64, Error> {
    // Reads carry no task; the fence is informational (0) since no dispatch
    // row exists to race against.
    let _ = (pool, scope);
    Ok(0)
}

async fn load_policy_decision(
    pool: &PgPool,
    scope: &OwnerScope,
    name: &str,
    args: &Value,
    descriptor: &orbit_core::ToolDescriptor,
    risk: orbit_core::RiskLevel,
) -> Result<Value, Error> {
    let settings: Value = sqlx::query_scalar("SELECT value FROM settings WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_optional(pool)
        .await?
        .unwrap_or(json!({}));
    let autonomy: orbit_core::AutonomyMode = serde_json::from_value(
        settings.get("autonomy_mode").cloned().unwrap_or(Value::Null),
    )
    .unwrap_or(orbit_core::AutonomyMode::Observe);
    let row = sqlx::query("SELECT revision,rules FROM policies WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_optional(pool)
        .await?;
    let (revision, rules) = match &row {
        Some(r) => (
            r.get("revision"),
            serde_json::from_value(r.get::<Value, _>("rules")).unwrap_or_default(),
        ),
        None => (1, vec![]),
    };
    let grants: Vec<orbit_policy::ScopeGrant> = sqlx::query_scalar(
        "SELECT to_jsonb(g)-'owner_id' FROM scope_grants g WHERE owner_id=$1 AND tool_name=$2",
    )
    .bind(scope.owner_id)
    .bind(name)
    .fetch_all(pool)
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
    .evaluate(scope, name, args, descriptor, risk, &scope_revisions);
    if decision.policy_revision != revision {
        return Err(Error::Conflict("policy changed during evaluation".into()));
    }
    if !settings
        .get("sandbox_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !decision.reason_codes.iter().any(|c| c == "SANDBOX_DISABLED")
    {
        decision.reason_codes.push("SANDBOX_DISABLED".into());
    }
    Ok(serde_json::to_value(&decision)?)
}

async fn task_status(
    pool: &PgPool,
    scope: &OwnerScope,
    task_id: Uuid,
) -> Result<Option<GetTaskResult>, McpError> {
    let row = sqlx::query("SELECT state,created_at,updated_at FROM tasks WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(task_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| McpError::internal_error("task lookup unavailable", None))?;
    let Some(row) = row else { return Ok(None) };
    let state: String = row.get("state");
    let created: chrono::DateTime<chrono::Utc> = row.get("created_at");
    let updated: chrono::DateTime<chrono::Utc> = row.get("updated_at");
    let calls: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(c)-'owner_id' FROM tool_calls c WHERE owner_id=$1 AND task_id=$2 ORDER BY created_at",
    )
    .bind(scope.owner_id)
    .bind(task_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let result_value = calls
        .iter()
        .rev()
        .find_map(|c| c.get("result").cloned())
        .unwrap_or(json!({"task_id": task_id}));
    let as_object = result_value
        .as_object()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let payload = match state.as_str() {
        "COMPLETED" => TaskPayload::Completed { result: as_object },
        "FAILED" => TaskPayload::Failed { error: as_object },
        "CANCELLED" => TaskPayload::Cancelled,
        "WAITING_FOR_APPROVAL" | "WAITING_FOR_RESOURCE" | "WAITING_FOR_INPUT" => {
            TaskPayload::InputRequired {
                input_requests: InputRequests::default(),
            }
        }
        _ => TaskPayload::Working,
    };
    let task = Task::new(
        task_id.to_string(),
        payload.status(),
        created.to_rfc3339(),
        updated.to_rfc3339(),
    );
    Ok(Some(GetTaskResult::new(DetailedTask::new(task, payload))))
}

async fn cancel_mcp_task(pool: &PgPool, scope: &OwnerScope, task_id: Uuid) -> Result<(), McpError> {
    // Cancel maps to the run: the MCP task id IS the Orbit task id.
    let state: Option<String> =
        sqlx::query_scalar("SELECT state FROM tasks WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(task_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| McpError::internal_error("task lookup unavailable", None))?;
    match state.as_deref() {
        None => Err(McpError::invalid_params("unknown task", None)),
        Some("COMPLETED" | "FAILED" | "CANCELLED" | "TIMED_OUT") => Err(McpError::invalid_params(
            "terminal task cannot cancel",
            None,
        )),
        Some(_) => {
            sqlx::query("UPDATE tasks SET state='CANCELLED',revision=revision+1,fence=fence+1,lease_until=NULL,updated_at=now() WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id)
                .bind(task_id)
                .execute(pool)
                .await
                .map_err(|_| McpError::internal_error("task cancel unavailable", None))?;
            Ok(())
        }
    }
}

fn service_for(service: McpService, state: &McpServerState) -> StreamableHttpService<OrbitMcpServer, LocalSessionManager> {
    let inner = state.clone();
    StreamableHttpService::new(
        move || {
            Ok(OrbitMcpServer {
                service,
                state: inner.clone(),
            })
        },
        Default::default(),
        StreamableHttpServerConfig::default().with_json_response(true),
    )
}

/// Mount the three authenticated MCP services. The inner rmcp service reads
/// auth from the injected request parts per call; no axum auth layer wraps
/// these routes (the MCP POST body must reach the rmcp service untouched).
pub fn router(state: crate::ApiState) -> axum::Router<crate::ApiState> {
    let shared = McpServerState {
        pool: state.pool.clone(),
        key_dir: state.key_dir.clone(),
        artifact_dir: state.artifact_dir.clone(),
        origin: state.origin.clone(),
    };
    axum::Router::new()
        .nest_service(
            McpService::OrbitControl.route_path(),
            service_for(McpService::OrbitControl, &shared),
        )
        .nest_service(
            McpService::OrbitData.route_path(),
            service_for(McpService::OrbitData, &shared),
        )
        .nest_service(
            McpService::HaControl.route_path(),
            service_for(McpService::HaControl, &shared),
        )
}
