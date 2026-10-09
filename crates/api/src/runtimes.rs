use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use orbit_aiec_runtime::{AIecRuntime, ConnectionConfig};
use orbit_core::{Error, OwnerScope, Result, RiskLevel, ToolDescriptor, ToolEffects};
use orbit_secrets::SecretStore;
use orbit_task_runtime::{FILE_LIMIT, InputArtifact, RuntimeTask, TRANSFER_LIMIT, TaskRuntime};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/runtimes/connections",
            get(connections).post(create_connection),
        )
        .route(
            "/api/v1/runtimes/connections/{id}",
            get(connection_detail)
                .patch(update_connection)
                .delete(remove_connection),
        )
        .route(
            "/api/v1/runtimes/connections/{id}/test",
            post(test_connection),
        )
        .route("/api/v1/runtimes", get(list_runs))
        .route("/api/v1/runtimes/{id}/cleanup", post(request_cleanup))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionWrite {
    name: String,
    origin: String,
    admitted_addresses: Vec<std::net::IpAddr>,
    ca_pem: Option<String>,
    secret_id: Option<Uuid>,
    credential: Option<String>,
    image: String,
    disk_mb: u32,
    lifetime_seconds: u64,
    enabled: Option<bool>,
}
async fn connection_input(
    state: &ApiState,
    scope: &OwnerScope,
    input: ConnectionWrite,
    old: Option<Uuid>,
) -> Result<(String, ConnectionConfig, bool)> {
    if input.name.trim().is_empty() || input.name.len() > 128 {
        return Err(Error::Validation("invalid connection name".into()));
    }
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let secret_id = match (input.credential, input.secret_id.or(old)) {
        (Some(key), _) => {
            store
                .put(scope, "aiec-tenant-api-key", key.as_bytes())
                .await?
        }
        (None, Some(id)) => {
            store.get(scope, id).await?;
            id
        }
        _ => return Err(Error::Validation("tenant API credential required".into())),
    };
    let config = ConnectionConfig {
        origin: input.origin,
        admitted_addresses: input.admitted_addresses,
        ca_pem: input.ca_pem,
        secret_id,
        image: input.image,
        disk_mb: input.disk_mb,
        lifetime_seconds: input.lifetime_seconds,
    };
    config.validate()?;
    // Admission resolves/pins in the server namespace; it does not contact AIec or prove capacity.
    let _ = AIecRuntime::connect(config.clone(), store.get(scope, secret_id).await?).await?;
    Ok((input.name, config, input.enabled.unwrap_or(true)))
}
fn connection_view(row: &sqlx::postgres::PgRow) -> Value {
    let mut value = row.get::<Value, _>("config");
    if let Some(object) = value.as_object_mut() {
        object.insert("id".into(), json!(row.get::<Uuid, _>("id")));
        object.insert("name".into(), json!(row.get::<String, _>("name")));
        object.insert("revision".into(), json!(row.get::<i64, _>("revision")));
        object.insert("enabled".into(), json!(row.get::<bool, _>("enabled")));
        object.insert("status".into(), json!(row.get::<String, _>("status")));
        object.insert(
            "last_test".into(),
            json!(row.get::<Option<DateTime<Utc>>, _>("last_test")),
        );
    }
    value
}
async fn connections(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query(
        "SELECT * FROM aiec_connections WHERE owner_id=$1 ORDER BY created_at,id LIMIT 50",
    )
    .bind(auth.scope.owner_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(
        json!({"items":rows.iter().map(connection_view).collect::<Vec<_>>(),"next_cursor":null}),
    ))
}
async fn connection_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let row = sqlx::query("SELECT * FROM aiec_connections WHERE owner_id=$1 AND id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(connection_view(&row)))
}
async fn create_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ConnectionWrite>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let (name, config, enabled) = connection_input(&state, &auth.scope, input, None).await?;
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO aiec_connections(id,owner_id,name,config,enabled) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(auth.scope.owner_id)
    .bind(name)
    .bind(json!(config))
    .bind(enabled)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    connection_detail(State(state), headers, Path(id)).await
}
async fn update_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ConnectionWrite>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let old: Value =
        sqlx::query_scalar("SELECT config FROM aiec_connections WHERE owner_id=$1 AND id=$2")
            .bind(auth.scope.owner_id)
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(Error::NotFound)?;
    let old: ConnectionConfig = serde_json::from_value(old).map_err(Error::from)?;
    let (name, config, enabled) =
        connection_input(&state, &auth.scope, input, Some(old.secret_id)).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE aiec_connections SET name=$3,config=$4,enabled=$5,revision=revision+1,status='UNTESTED' WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).bind(name).bind(json!(config)).bind(enabled).execute(&mut *tx).await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE runtime_runs SET cleanup_requested=true WHERE owner_id=$1 AND connection_id=$2 AND cleanup_required").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    connection_detail(State(state), headers, Path(id)).await
}
async fn remove_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let n=sqlx::query("UPDATE aiec_connections SET enabled=false,revision=revision+1,status='REVOKED' WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(Error::NotFound.into());
    }
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    // Retain encrypted connector credential for obligatory system cleanup, never for new agent work.
    sqlx::query("UPDATE runtime_runs SET cleanup_requested=true WHERE owner_id=$1 AND connection_id=$2 AND cleanup_required").bind(auth.scope.owner_id).bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"removed":true,"cleanup_credentials_retained":true}),
    ))
}
async fn adapter(
    pool: &PgPool,
    key_dir: &std::path::Path,
    scope: &OwnerScope,
    connection_id: Uuid,
) -> Result<AIecRuntime> {
    let config: Value =
        sqlx::query_scalar("SELECT config FROM aiec_connections WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(connection_id)
            .fetch_optional(pool)
            .await?
            .ok_or(Error::NotFound)?;
    let config: ConnectionConfig = serde_json::from_value(config)?;
    let store = SecretStore::open(pool.clone(), key_dir).await?;
    let key = store.get(scope, config.secret_id).await?;
    AIecRuntime::connect(config, key).await
}
async fn test_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let runtime = adapter(&state.pool, &state.key_dir, &auth.scope, id).await?;
    let result = runtime.readiness().await?;
    sqlx::query("UPDATE aiec_connections SET status='AUTHENTICATED',last_test=now() WHERE owner_id=$1 AND id=$2 AND enabled").bind(auth.scope.owner_id).bind(id).execute(&state.pool).await?;
    Ok(Json(result))
}
#[derive(Deserialize)]
struct RunQuery {
    task_id: Option<Uuid>,
    cursor: Option<Uuid>,
}
async fn list_runs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<RunQuery>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let rows:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(r)-'action_snapshot'-'creator_id' FROM runtime_runs r WHERE owner_id=$1 AND ($2::uuid IS NULL OR task_id=$2) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT 51").bind(auth.scope.owner_id).bind(query.task_id).bind(query.cursor).fetch_all(&state.pool).await?;
    let next = if rows.len() > 50 {
        rows[49].get("id").cloned()
    } else {
        None
    };
    Ok(Json(
        json!({"items":rows.into_iter().take(50).collect::<Vec<_>>(),"next_cursor":next}),
    ))
}
async fn request_cleanup(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let task: Uuid =
        sqlx::query_scalar("SELECT task_id FROM runtime_runs WHERE owner_id=$1 AND id=$2")
            .bind(auth.scope.owner_id)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::NotFound)?;
    sqlx::query("SELECT id FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .bind(task)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("UPDATE runtime_runs SET cleanup_requested=true WHERE owner_id=$1 AND id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"cleanup_required":true,"resolution":"PENDING_REMOTE_PROOF"}),
    ))
}

pub fn descriptors() -> Vec<ToolDescriptor> {
    vec![ToolDescriptor {
        id: Uuid::from_u128(0x65d70d8d_4fe0_40d1_a647_2ff1e8771150),
        name: "shell.execute".into(),
        version: "1".into(),
        input_schema: json!({"type":"object","required":["image","argv","working_directory","timeout_seconds","input_artifact_ids","output_paths"],"properties":{"image":{"type":"string"},"argv":{"type":"array","minItems":1,"maxItems":128,"items":{"type":"string"}},"working_directory":{"type":"string"},"timeout_seconds":{"type":"integer","minimum":1,"maximum":120},"input_artifact_ids":{"type":"array","maxItems":10,"items":{"type":"string","format":"uuid"}},"output_paths":{"type":"array","maxItems":10,"items":{"type":"string"}},"runtime_spec":{"type":"object"}},"additionalProperties":false}),
        output_schema: json!({"type":"object","required":["runtime_id","result","artifacts","cleanup"],"properties":{"runtime_id":{"type":"string"},"result":{"type":"object"},"artifacts":{"type":"array"},"cleanup":{"type":"string"}},"additionalProperties":false}),
        effects: ToolEffects {
            external: true,
            modifies_data: true,
            reversible: false,
            credential_access: false,
            affected_party: "owner-private isolated workload".into(),
            network: false,
        },
        default_risk: RiskLevel::High,
        permission_keys: vec!["aiec.admitted_image".into()],
        sandbox_required: true,
    }]
}
#[derive(Clone, Serialize, Deserialize)]
struct ConsentSpec {
    connection_id: Uuid,
    revision: i64,
    image: String,
    cpu: u32,
    memory_mb: u32,
    disk_mb: u32,
    lifetime_seconds: u64,
    network_enabled: bool,
    inputs: Vec<InputArtifact>,
}
/// Materialize all resource and byte bindings before consent, not after approval.
pub async fn materialize(pool: &PgPool, scope: &OwnerScope, mut args: Value) -> Result<Value> {
    if args.get("runtime_spec").is_some() {
        return Err(Error::Validation(
            "runtime_spec is server materialized".into(),
        ));
    }
    let image = args
        .get("image")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Validation("image required".into()))?;
    let rows=sqlx::query("SELECT id,revision,config FROM aiec_connections WHERE owner_id=$1 AND enabled AND config->>'image'=$2 ORDER BY id LIMIT 2").bind(scope.owner_id).bind(image).fetch_all(pool).await?;
    if rows.len() != 1 {
        return Err(Error::Unavailable(
            "configure one admitted AIec connection for this image".into(),
        ));
    }
    let row = &rows[0];
    let config: ConnectionConfig = serde_json::from_value(row.get("config"))?;
    let ids: Vec<Uuid> = serde_json::from_value(
        args.get("input_artifact_ids")
            .cloned()
            .ok_or_else(|| Error::Validation("input artifacts required".into()))?,
    )?;
    if ids.len() > 10 {
        return Err(Error::Validation("too many input artifacts".into()));
    }
    let mut inputs = Vec::new();
    let mut total = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id) {
            return Err(Error::Validation("duplicate input artifact".into()));
        }
        let artifact = sqlx::query("SELECT sha256,size FROM artifacts WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(id)
            .fetch_optional(pool)
            .await?
            .ok_or(Error::NotFound)?;
        let size: i64 = artifact.get("size");
        if size < 0 || size as usize > FILE_LIMIT {
            return Err(Error::Validation("runtime inputs cap at 1 MiB/file".into()));
        }
        total += size as usize;
        if total > TRANSFER_LIMIT {
            return Err(Error::Validation(
                "runtime inputs cap at 10 MiB total".into(),
            ));
        }
        inputs.push(InputArtifact {
            artifact_id: id,
            path: format!("/workspace/inputs/{id}"),
            sha256: artifact.get("sha256"),
            size: size as u64,
            bytes: Vec::new(),
        });
    }
    let consent = ConsentSpec {
        connection_id: row.get("id"),
        revision: row.get("revision"),
        image: config.image,
        cpu: 1,
        memory_mb: 512,
        disk_mb: config.disk_mb,
        lifetime_seconds: 1680,
        network_enabled: false,
        inputs,
    };
    let task = task_from_args(&args)?;
    task.validate()?;
    args.as_object_mut()
        .ok_or_else(|| Error::Validation("shell arguments must be an object".into()))?
        .insert("runtime_spec".into(), json!(consent));
    Ok(args)
}
pub async fn materialize_action(
    state: &ApiState,
    scope: &OwnerScope,
    _tool: &str,
    args: Value,
) -> Result<(Value, BTreeMap<String, i64>, BTreeMap<String, String>)> {
    let args = materialize(&state.pool, scope, args).await?;
    let spec: ConsentSpec = serde_json::from_value(args["runtime_spec"].clone())?;
    let revisions = BTreeMap::from([(format!("aiec:{}", spec.connection_id), spec.revision)]);
    let digests = spec
        .inputs
        .iter()
        .map(|i| (i.artifact_id.to_string(), i.sha256.clone()))
        .collect();
    Ok((args, revisions, digests))
}
fn task_from_args(args: &Value) -> Result<RuntimeTask> {
    Ok(RuntimeTask {
        argv: serde_json::from_value(args["argv"].clone())?,
        working_directory: serde_json::from_value(args["working_directory"].clone())?,
        timeout_seconds: serde_json::from_value(args["timeout_seconds"].clone())?,
        output_paths: serde_json::from_value(args["output_paths"].clone())?,
    })
}
/// Creator-lease and runtime-fence constants (seconds): the task waits on a
/// 60-second creator lease renewed every 20 seconds while provisioning; the
/// runtime fence is separate from the task fence and claims cleanup.
pub const CREATOR_LEASE_SECONDS: i64 = 60;
pub const CREATOR_RENEW_SECONDS: i64 = 20;
/// The real dispatch path for `shell.execute`. There is no non-sandbox
/// executor: every authorized action runs create → uploads → execute →
/// collect → trusted artifact persistence → destroy/reconciliation against the
/// admitted AIec origin only. No host, process, or Docker fallback exists.
pub struct ShellExecutor {
    pub pool: PgPool,
    pub artifact_dir: std::path::PathBuf,
    pub key_dir: std::path::PathBuf,
}
#[async_trait::async_trait]
impl orbit_tools::ToolExecutor for ShellExecutor {
    async fn execute(
        &self,
        scope: &OwnerScope,
        action: orbit_core::AuthorizedAction,
    ) -> Result<orbit_tools::ToolResult> {
        orbit_tools::verify_submission(&self.pool, scope, &action).await?;
        let snapshot = action.snapshot();
        if snapshot.tool_name != "shell.execute" {
            return Err(Error::Forbidden);
        }
        let consent: ConsentSpec =
            serde_json::from_value(snapshot.arguments["runtime_spec"].clone())
                .map_err(Error::from)?;
        if consent.network_enabled
            || consent.cpu != 1
            || consent.memory_mb != 512
            || consent.lifetime_seconds != 1680
        {
            return Err(Error::Forbidden);
        }
        let task: RuntimeTask = task_from_args(&snapshot.arguments)?;
        task.validate()?;
        // Resolve input bytes from trusted artifact storage before dispatch.
        let mut inputs = Vec::with_capacity(consent.inputs.len());
        for input in &consent.inputs {
            let row = sqlx::query(
                "SELECT safe_name,sha256,storage_key FROM artifacts WHERE owner_id=$1 AND id=$2",
            )
            .bind(scope.owner_id)
            .bind(input.artifact_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::NotFound)?;
            let bytes = artifact_bytes(
                &self.artifact_dir,
                scope.owner_id,
                &row.get::<String, _>("storage_key"),
            )
            .await?;
            if orbit_aiec_runtime::sha256(&bytes) != input.sha256 {
                return Err(Error::Conflict(
                    "immutable input artifact digest mismatch".into(),
                ));
            }
            inputs.push(InputArtifact {
                artifact_id: input.artifact_id,
                path: input.path.clone(),
                sha256: input.sha256.clone(),
                size: bytes.len() as u64,
                bytes,
            });
        }
        let spec = orbit_task_runtime::RuntimeSpec {
            run_id: snapshot.action_id,
            image: consent.image.clone(),
            cpu: 1,
            memory_mb: 512,
            disk_mb: consent.disk_mb,
            lifetime_seconds: 1680,
            network_enabled: false,
            inputs,
        };
        spec.validate()?;
        let request_digest =
            orbit_aiec_runtime::sha256(&serde_json::to_vec(&spec).map_err(Error::from)?);
        let runtime = adapter(&self.pool, &self.key_dir, scope, consent.connection_id)
            .await
            .map_err(|e| map_unreachable(&e))?;
        let correlation: Uuid =
            sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id)
                .bind(snapshot.task_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(Error::NotFound)?;
        claim_run(
            &self.pool,
            scope,
            &spec,
            &task,
            &consent,
            &action,
            &request_digest,
            correlation,
        )
        .await?;
        // The run UUID doubles as the remote sandbox ID and the POST
        // Idempotency-Key; uncertain submission recovers with GET, never a
        // second POST. Unreachable AIec parks the task in
        // WAITING_FOR_RESOURCE with the exact error for owner recovery.
        let handle = match runtime.create(spec.clone()).await {
            Ok(handle) => {
                transition_run(&self.pool, scope, snapshot.action_id, "RUNNING", true, true)
                    .await?;
                handle
            }
            Err(e) => {
                let (state, reason) = wait_reason(&e);
                park_waiting(
                    &self.pool,
                    scope,
                    snapshot.task_id,
                    action.task_fence(),
                    correlation,
                    snapshot.action_id,
                    &state,
                    &reason,
                )
                .await?;
                return Err(e);
            }
        };
        verify_phase(&self.pool, scope, snapshot, &action).await?;
        if let Err(e) = runtime.upload_inputs(&handle, &spec).await {
            fail_run(&self.pool, scope, snapshot, correlation, &e).await?;
            return Err(e);
        }
        transition_run(&self.pool, scope, snapshot.action_id, "RUNNING", true, true).await?;
        verify_phase(&self.pool, scope, snapshot, &action).await?;
        let outcome = runtime
            .execute(&handle, task)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        let outcome_value = serde_json::to_value(&outcome).map_err(Error::from)?;
        if outcome.outcome == orbit_task_runtime::RuntimeOutcome::OutcomeUnknown
            || outcome.outcome == orbit_task_runtime::RuntimeOutcome::TransportFailure
        {
            sqlx::query("UPDATE runtime_runs SET state='CLEANUP_PENDING',result=$3,cleanup_requested=true,updated_at=now() WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id).bind(snapshot.action_id).bind(&outcome_value).execute(&self.pool).await?;
            sqlx::query("UPDATE tool_calls SET state='OUTCOME_UNKNOWN',result=$3,error_code='AIEC_OUTCOME_UNKNOWN',completed_at=now() WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id).bind(snapshot.action_id).bind(&outcome_value).execute(&self.pool).await?;
            reconcile(&self.pool, &self.key_dir, scope, snapshot.action_id).await?;
            return Err(Error::OutcomeUnknown);
        }
        transition_run(
            &self.pool,
            scope,
            snapshot.action_id,
            "COLLECTING",
            true,
            true,
        )
        .await?;
        runtime.restore_outputs(
            handle.id(),
            snapshot.arguments["output_paths"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        )?;
        let collected = runtime
            .collect_artifacts(&handle)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        let mut persisted = Vec::with_capacity(collected.len());
        for artifact in collected {
            persisted.push(
                persist_artifact(
                    &self.pool,
                    &self.artifact_dir,
                    scope,
                    snapshot,
                    &action,
                    &handle,
                    &artifact,
                )
                .await?,
            );
        }
        transition_run(
            &self.pool,
            scope,
            snapshot.action_id,
            "CLEANUP_PENDING",
            true,
            true,
        )
        .await?;
        let cleanup = match runtime.destroy(handle).await {
            Ok(()) => "DESTROYED",
            Err(_) => {
                reconcile(&self.pool, &self.key_dir, scope, snapshot.action_id).await?;
                "UNRESOLVED"
            }
        };
        let output = json!({"runtime_id": snapshot.action_id, "result": outcome_value, "artifacts": persisted, "cleanup": cleanup});
        orbit_tools::validate_value(&descriptors()[0].output_schema, &output)?;
        let state = if outcome.succeeded() && cleanup == "DESTROYED" {
            "COMPLETED"
        } else if outcome.succeeded() {
            "OUTCOME_UNKNOWN"
        } else {
            "FAILED"
        };
        sqlx::query("UPDATE tool_calls SET state=$3,result=$4,completed_at=now() WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id).bind(snapshot.action_id).bind(state).bind(&output).execute(&self.pool).await?;
        sqlx::query("UPDATE tasks SET state=$3,wait_reason=NULL,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id).bind(snapshot.task_id).bind(if state == "COMPLETED" { "COMPLETED" } else if state == "FAILED" { "FAILED" } else { "WAITING_FOR_RESOURCE" }).execute(&self.pool).await?;
        let mut tx = self.pool.begin().await?;
        orbit_audit::append(
            &mut tx,
            scope,
            correlation,
            None,
            Some(snapshot.task_id),
            "RUNTIME_DISPATCH_SETTLED",
            "shell.execute dispatch settled through AIec",
            json!({"call_id": snapshot.action_id, "state": state, "cleanup": cleanup}),
        )
        .await?;
        tx.commit().await?;
        Ok(orbit_tools::ToolResult {
            output,
            privacy_class: orbit_core::PrivacyClass::Private,
            trust_level: orbit_core::TrustLevel::UntrustedExternal,
            source_reference: format!("runtime-run:{}", snapshot.action_id),
        })
    }
}
/// Unreachable AIec is never a mock success: transport-level failures map to
/// an exact `AIEC_UNAVAILABLE` wait reason for owner recovery.
fn map_unreachable(error: &Error) -> Error {
    match error {
        Error::Unavailable(message) => Error::Unavailable(format!("AIEC_UNAVAILABLE: {message}")),
        Error::Timeout => Error::Unavailable("AIEC_UNAVAILABLE: AIec connection timed out".into()),
        other => Error::Unavailable(format!("AIEC_UNAVAILABLE: {other}")),
    }
}
fn wait_reason(error: &Error) -> (String, String) {
    match error {
        Error::Unavailable(message) if message.contains("provisioning") => ("RUNNING".into(), format!("AIEC_PROVISIONING: {message}")),
        Error::Unavailable(message) => ("WAITING_FOR_RESOURCE".into(), format!("AIEC_UNAVAILABLE: {message}")),
        Error::Timeout => ("WAITING_FOR_RESOURCE".into(), "AIEC_UNAVAILABLE: AIec request timed out".into()),
        Error::OutcomeUnknown => ("WAITING_FOR_RESOURCE".into(), "AIEC_OUTCOME_UNKNOWN: AIec submission was transmitted but unconfirmed; reconciling the same UUID".into()),
        other => ("WAITING_FOR_RESOURCE".into(), format!("AIEC_UNAVAILABLE: {other}")),
    }
}
/// Insert the PREPARED run row before POST commit: run UUID, immutable request
/// digest, owner/task, approved inputs, lifetime, cleanup obligation, creator
/// lease and monotonic runtime fence. The creator lease is held by this worker
/// while the task waits; on proved RUNNING the checkpoint queues once and
/// ownership transfers to the reacquired task worker under the same UUID.
#[allow(clippy::too_many_arguments)]
async fn claim_run(
    pool: &PgPool,
    scope: &orbit_core::OwnerScope,
    spec: &orbit_task_runtime::RuntimeSpec,
    task: &RuntimeTask,
    consent: &ConsentSpec,
    action: &orbit_core::AuthorizedAction,
    request_digest: &str,
    correlation: Uuid,
) -> Result<()> {
    let snapshot = action.snapshot();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let fence_ok: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks WHERE owner_id=$1 AND id=$2 AND fence=$3 AND state='RUNNING' FOR UPDATE)")
        .bind(scope.owner_id).bind(snapshot.task_id).bind(action.task_fence()).fetch_one(&mut *tx).await?;
    if !fence_ok {
        return Err(Error::Conflict("task lease or execution fence lost".into()));
    }
    sqlx::query("INSERT INTO runtime_runs(id,owner_id,task_id,connection_id,authorization_id,action_snapshot,task_fence,spec,command,request_digest,state,creator_id,creator_lease_until,runtime_fence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'PREPARED',$11,now()+make_interval(secs=>$12),$13) ON CONFLICT(authorization_id) DO NOTHING")
        .bind(snapshot.action_id).bind(scope.owner_id).bind(snapshot.task_id).bind(consent.connection_id).bind(action.authorization_id())
        .bind(serde_json::to_value(snapshot).map_err(Error::from)?).bind(action.task_fence())
        .bind(serde_json::to_value(spec).map_err(Error::from)?).bind(serde_json::to_value(task).map_err(Error::from)?)
        .bind(request_digest).bind(scope.principal_id).bind(CREATOR_LEASE_SECONDS as f64).bind(1i64).execute(&mut *tx).await?;
    // PREPARED → CREATING marks the submission under the shared locks; only
    // then may the single POST transmit with this UUID as Idempotency-Key.
    let claimed: bool = sqlx::query_scalar("UPDATE runtime_runs SET state='CREATING',create_submitted=true,updated_at=now() WHERE owner_id=$1 AND id=$2 AND state='PREPARED' RETURNING true")
        .bind(scope.owner_id).bind(snapshot.action_id).fetch_optional(&mut *tx).await?.unwrap_or(false);
    if claimed {
        orbit_audit::append(
            &mut tx,
            scope,
            correlation,
            None,
            Some(snapshot.task_id),
            "RUNTIME_RUN_CLAIMED",
            "runtime run claimed with creator lease and runtime fence",
            json!({"run_id": snapshot.action_id, "request_digest": request_digest}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn transition_run(
    pool: &PgPool,
    scope: &orbit_core::OwnerScope,
    run: Uuid,
    state: &str,
    create_submitted: bool,
    remote_running: bool,
) -> Result<()> {
    sqlx::query("UPDATE runtime_runs SET state=$3,create_submitted=$4 OR create_submitted,remote_running_observed=$5 OR remote_running_observed,creator_lease_until=now()+make_interval(secs=>$6),updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(run).bind(state).bind(create_submitted).bind(remote_running).bind(CREATOR_LEASE_SECONDS as f64).execute(pool).await?;
    Ok(())
}
/// Park the owner task in WAITING_FOR_RESOURCE with the exact resource/error
/// so the safe owner recovery routes (resume/retry/reconcile) can proceed.
async fn park_waiting(
    pool: &PgPool,
    scope: &orbit_core::OwnerScope,
    task: Uuid,
    fence: i64,
    correlation: Uuid,
    run: Uuid,
    state: &str,
    reason: &str,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE tasks SET state=$4,wait_reason=$5,lease_until=NULL,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND id=$2 AND fence=$3")
        .bind(scope.owner_id).bind(task).bind(fence).bind(state).bind(reason).execute(&mut *tx).await?;
    sqlx::query("UPDATE tool_calls SET error_code='AIEC_UNAVAILABLE',evidence=evidence||$3::jsonb WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(run).bind(json!([{"wait_reason": reason}])).execute(&mut *tx).await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        None,
        Some(task),
        "TASK_WAITING_FOR_RESOURCE",
        reason,
        json!({"run_id": run}),
    )
    .await?;
    sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body) VALUES($1,$2,$3,$4,'ACTION_REQUIRED','Assistant needs the AIec resource',$5) ON CONFLICT(owner_id,task_id) DO NOTHING")
        .bind(Uuid::new_v4()).bind(scope.owner_id).bind(task).bind(correlation).bind(reason).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}
async fn fail_run(
    pool: &PgPool,
    scope: &orbit_core::OwnerScope,
    snapshot: &orbit_core::ActionSnapshot,
    correlation: Uuid,
    error: &Error,
) -> Result<()> {
    let output = json!({"error": error.to_string()});
    sqlx::query("UPDATE runtime_runs SET state='CLEANUP_PENDING',result=$3,cleanup_requested=true,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(snapshot.action_id).bind(&output).execute(pool).await?;
    sqlx::query("UPDATE tool_calls SET state='FAILED',result=$3,error_code='AIEC_PHASE_FAILED',completed_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(snapshot.action_id).bind(&output).execute(pool).await?;
    let mut tx = pool.begin().await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        None,
        Some(snapshot.task_id),
        "RUNTIME_PHASE_FAILED",
        "runtime phase failed; cleanup scheduled",
        json!({"run_id": snapshot.action_id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
/// Renew the creator lease while provisioning/status-polling continues. Only
/// the recorded creator holding the task fence may renew.
pub async fn renew_creator_lease(
    pool: &PgPool,
    scope: &orbit_core::OwnerScope,
    run: Uuid,
    task_fence: i64,
) -> Result<()> {
    let n = sqlx::query("UPDATE runtime_runs SET creator_lease_until=now()+make_interval(secs=>$4),updated_at=now() WHERE owner_id=$1 AND id=$2 AND task_fence=$3 AND creator_id=$5 AND creator_lease_until>now()")
        .bind(scope.owner_id).bind(run).bind(task_fence).bind(CREATOR_LEASE_SECONDS as f64).bind(scope.principal_id).execute(pool).await?.rows_affected();
    if n == 0 {
        return Err(Error::Conflict(
            "creator lease lost; destroy is scheduled".into(),
        ));
    }
    Ok(())
}
/// Destroy-on-fence-loss: a worker that lost its task fence or creator lease
/// must not run phases; it schedules destroy and reconciles instead.
pub async fn destroy_on_fence_loss(
    pool: &PgPool,
    key_dir: &std::path::Path,
    scope: &orbit_core::OwnerScope,
    run: Uuid,
) -> Result<()> {
    sqlx::query("UPDATE runtime_runs SET cleanup_requested=true,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(run).execute(pool).await?;
    reconcile(pool, key_dir, scope, run).await
}
/// Restart-safe reconciler: scans eligible/expired-creator rows (never healthy
/// active workloads), claims cleanup with the runtime fence, attempts DELETE
/// then GET for confirmed destroyed. If cleanup wins before `create_submitted`
/// no POST can occur; if any POST might have transmitted, 404, elapsed local
/// deadline, released quota and early DELETE acknowledgement do not prove the
/// remote settled — retain UNRESOLVED and keep probing late appearances.
/// Never creates again or resumes exec.
pub async fn reconcile(
    pool: &PgPool,
    key_dir: &std::path::Path,
    scope: &orbit_core::OwnerScope,
    run: Uuid,
) -> Result<()> {
    let row = sqlx::query("SELECT task_id,connection_id,state,create_submitted,remote_running_observed,destroy_acknowledged,runtime_fence FROM runtime_runs WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(run).fetch_optional(pool).await?.ok_or(Error::NotFound)?;
    if row.get::<String, _>("state") == "DESTROYED" {
        return Ok(());
    }
    // Claim cleanup with the monotonic runtime fence under the epoch lock.
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let fence: i64 = sqlx::query_scalar("UPDATE runtime_runs SET runtime_fence=runtime_fence+1,cleanup_lease_until=now()+make_interval(secs=>60),state=CASE WHEN state='DESTROYED' THEN 'DESTROYED' ELSE 'CLEANUP_CLAIMED' END,updated_at=now() WHERE owner_id=$1 AND id=$2 AND state<>'DESTROYED' RETURNING runtime_fence")
        .bind(scope.owner_id).bind(run).fetch_optional(&mut *tx).await?.ok_or(Error::Conflict("runtime already destroyed".into()))?;
    tx.commit().await?;
    let _ = fence;
    // If cleanup won before any submission, the obligation closes without POST.
    if !row.get::<bool, _>("create_submitted") {
        sqlx::query("UPDATE runtime_runs SET state='DESTROYED',cleanup_required=false,updated_at=now() WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id).bind(run).execute(pool).await?;
        return Ok(());
    }
    let runtime = adapter(pool, key_dir, scope, row.get::<Uuid, _>("connection_id")).await?;
    // Attempt DELETE; a 404 or early ack is not proof the remote settled.
    let destroyed = runtime.request_destroy(run).await.is_ok();
    match runtime.status(run).await {
        Ok(None) | Ok(Some(_)) if destroyed => {
            // 404 after an acknowledged DELETE still requires continued
            // probing for late appearances when a POST might have transmitted.
            let confirmed = matches!(runtime.status(run).await, Ok(None))
                && destroyed
                && row.get::<bool, _>("remote_running_observed");
            if confirmed || destroyed && !row.get::<bool, _>("remote_running_observed") {
                sqlx::query("UPDATE runtime_runs SET state='DESTROYED',destroy_acknowledged=true,cleanup_required=false,updated_at=now() WHERE owner_id=$1 AND id=$2")
                    .bind(scope.owner_id).bind(run).execute(pool).await?;
                return Ok(());
            }
        }
        Ok(Some(sandbox)) if sandbox.state == "destroyed" => {
            sqlx::query("UPDATE runtime_runs SET state='DESTROYED',destroy_acknowledged=true,cleanup_required=false,updated_at=now() WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id).bind(run).execute(pool).await?;
            return Ok(());
        }
        _ => {}
    }
    // Keep probing: UNRESOLVED retains the destroy obligation for the next
    // reconciler pass; late-appearing sandboxes are destroyed, never reused.
    sqlx::query("UPDATE runtime_runs SET state='UNRESOLVED',cleanup_requested=true,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id).bind(run).execute(pool).await?;
    Err(Error::OutcomeUnknown)
}
/// Scan for runs needing reconciliation: cleanup-eligible, expired creators,
/// or UNRESOLVED rows. Healthy active workloads are never touched.
pub async fn reconcile_eligible(
    pool: &PgPool,
    key_dir: &std::path::Path,
    scope: &orbit_core::OwnerScope,
    limit: i64,
) -> Result<Vec<Uuid>> {
    let runs: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM runtime_runs WHERE owner_id=$1 AND cleanup_required AND state NOT IN ('DESTROYED') AND (cleanup_requested OR creator_lease_until<now() OR cleanup_lease_until<now() OR state IN ('CLEANUP_PENDING','UNRESOLVED','QUARANTINED')) ORDER BY updated_at LIMIT $2")
        .bind(scope.owner_id).bind(limit).fetch_all(pool).await?;
    let mut settled = Vec::new();
    for run in runs {
        if reconcile(pool, key_dir, scope, run).await.is_ok() {
            settled.push(run);
        }
    }
    Ok(settled)
}
/// Reacquire the common epoch → task → call → runtime locks before each
/// upload/exec phase and verify current lease/fences, task state, snapshot
/// policy/scope revisions, phase uniqueness and remaining budgets. Revocation,
/// cancellation or cleanup claims prevent new phases; they cannot retract an
/// already transmitted request.
async fn verify_phase(
    pool: &PgPool,
    scope: &orbit_core::OwnerScope,
    snapshot: &orbit_core::ActionSnapshot,
    action: &orbit_core::AuthorizedAction,
) -> Result<()> {
    orbit_tools::verify_submission(pool, scope, action).await?;
    let mut tx = pool.begin().await?;
    let epoch: i64 = sqlx::query_scalar(
        "SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE",
    )
    .bind(scope.owner_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::Forbidden)?;
    if epoch != snapshot.authorization_epoch {
        sqlx::query("UPDATE runtime_runs SET cleanup_requested=true,updated_at=now() WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id).bind(snapshot.action_id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Err(Error::Conflict(
            "authorization epoch changed; destroy is scheduled".into(),
        ));
    }
    let task_ok: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks WHERE owner_id=$1 AND id=$2 AND fence=$3 AND state='RUNNING' AND lease_until>now() FOR UPDATE)")
        .bind(scope.owner_id).bind(snapshot.task_id).bind(action.task_fence()).fetch_one(&mut *tx).await?;
    let run_ok: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_runs WHERE owner_id=$1 AND id=$2 AND task_fence=$3 AND NOT cleanup_requested FOR UPDATE)")
        .bind(scope.owner_id).bind(snapshot.action_id).bind(action.task_fence()).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    if !task_ok || !run_ok {
        return Err(Error::Conflict(
            "task lease or execution fence lost; destroy is scheduled".into(),
        ));
    }
    Ok(())
}
async fn artifact_bytes(dir: &std::path::Path, _owner: Uuid, storage_key: &str) -> Result<Vec<u8>> {
    let parts: Vec<_> = storage_key.split('/').collect();
    if parts.len() != 2 || Uuid::parse_str(parts[0]).is_err() || Uuid::parse_str(parts[1]).is_err()
    {
        return Err(Error::Validation(
            "invalid private artifact storage reference".into(),
        ));
    }
    let path = dir.join(parts[0]).join(parts[1]);
    if tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|_| Error::Unavailable("artifact storage unavailable".into()))?
        .file_type()
        .is_symlink()
    {
        return Err(Error::Forbidden);
    }
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| Error::Unavailable("artifact storage unavailable".into()))?;
    if bytes.len() > FILE_LIMIT {
        return Err(Error::Validation("runtime inputs cap at 1 MiB/file".into()));
    }
    Ok(bytes)
}
/// Persist declared outputs in Orbit's trusted private artifact storage before
/// destroying the sandbox; no long-term state lives in AIec. Nonzero exits
/// remain real task failures with evidence; `timed_out=true` is never success.
async fn persist_artifact(
    pool: &PgPool,
    dir: &std::path::Path,
    scope: &orbit_core::OwnerScope,
    snapshot: &orbit_core::ActionSnapshot,
    action: &orbit_core::AuthorizedAction,
    handle: &orbit_task_runtime::RuntimeHandle,
    artifact: &orbit_task_runtime::Artifact,
) -> Result<Value> {
    if artifact.bytes.len() != artifact.size as usize
        || artifact.bytes.len() > FILE_LIMIT
        || orbit_aiec_runtime::sha256(&artifact.bytes) != artifact.sha256
    {
        return Err(Error::Validation(
            "collected artifact digest mismatch".into(),
        ));
    }
    let name = orbit_agent_runtime::safe_filename(&artifact.safe_name);
    let storage_key = format!("{}/{}", scope.owner_id, artifact.id);
    let parent = dir.join(scope.owner_id.to_string());
    tokio::fs::create_dir_all(&parent)
        .await
        .map_err(|_| Error::Unavailable("private artifact directory unavailable".into()))?;
    if tokio::fs::symlink_metadata(&parent)
        .await
        .map_err(|_| Error::Unavailable("artifact storage unavailable".into()))?
        .file_type()
        .is_symlink()
    {
        return Err(Error::Forbidden);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|_| Error::Unavailable("artifact permissions unavailable".into()))?;
    }
    let path = dir.join(&storage_key);
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(mut file) => {
            use tokio::io::AsyncWriteExt;
            file.write_all(&artifact.bytes)
                .await
                .map_err(|_| Error::Unavailable("artifact write failed".into()))?;
            file.sync_all()
                .await
                .map_err(|_| Error::Unavailable("artifact persistence failed".into()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let prior = tokio::fs::read(&path)
                .await
                .map_err(|_| Error::Unavailable("artifact unavailable".into()))?;
            if orbit_aiec_runtime::sha256(&prior) != artifact.sha256 {
                return Err(Error::Conflict(
                    "existing immutable artifact differs".into(),
                ));
            }
        }
        Err(_) => return Err(Error::Unavailable("artifact storage unavailable".into())),
    }
    sqlx::query("INSERT INTO artifacts(id,owner_id,task_id,authorization_id,title,safe_name,mime_type,size,sha256,source_references,storage_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(authorization_id) DO NOTHING")
        .bind(artifact.id).bind(scope.owner_id).bind(snapshot.task_id).bind(action.authorization_id())
        .bind(&name).bind(&name).bind(&artifact.mime_type).bind(artifact.size as i64).bind(&artifact.sha256)
        .bind(json!([{"kind":"RUNTIME_OUTPUT","runtime_id":handle.id(),"provenance":artifact.provenance}])).bind(&storage_key).execute(pool).await?;
    Ok(json!({"id": artifact.id, "name": name, "sha256": artifact.sha256, "size": artifact.size}))
}

#[cfg(test)]
mod fail_closed_tests {
    use super::{map_unreachable, wait_reason};
    use orbit_core::Error;
    /// Unreachable AIec parks in WAITING_FOR_RESOURCE with the exact AIEC_UNAVAILABLE prefix; dropping the prefix or falling back to host exec breaks this test.
    #[test]
    fn unreachable_maps_to_waiting_with_exact_prefix() {
        let (state, reason) = wait_reason(&Error::Unavailable("AIec authenticated route unreachable".into()));
        assert_eq!(state, "WAITING_FOR_RESOURCE");
        assert_eq!(reason, "AIEC_UNAVAILABLE: AIec authenticated route unreachable");
        let (state, reason) = wait_reason(&Error::Timeout);
        assert_eq!(state, "WAITING_FOR_RESOURCE");
        assert!(reason.starts_with("AIEC_UNAVAILABLE: "), "timeout must keep AIEC_UNAVAILABLE prefix, got {reason:?}");
        let mapped = map_unreachable(&Error::Unavailable("AIec status unavailable".into()));
        assert!(matches!(&mapped, Error::Unavailable(message) if message.starts_with("AIEC_UNAVAILABLE: ")), "adapter mapping must keep AIEC_UNAVAILABLE prefix, got {mapped:?}");
        assert_eq!(wait_reason(&mapped).0, "WAITING_FOR_RESOURCE");
    }
}
