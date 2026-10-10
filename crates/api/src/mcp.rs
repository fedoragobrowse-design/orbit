//! Owner MCP connection management: admission-gated registration, review-required
//! discovery, and schema-pinned grants. Discovery itself never authorizes
//! anything: every discovered tool lands disabled with assessment UNKNOWN and
//! needs an explicit grant row before [`orbit_mcp::ConnectionManager::call_once`]
//! will touch it. Tool execution runs through the approvals pipeline
//! (`call_once` takes the approval's `authorization_id`), so this module only
//! handles connection lifecycle plus grant review — never direct tool calls.
use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{delete, get, post},
};
use orbit_core::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/mcp/connections",
            get(list_connections).post(create_connection),
        )
        .route(
            "/api/v1/mcp/connections/{id}",
            get(connection_detail)
                .patch(update_connection)
                .delete(remove_connection),
        )
        .route(
            "/api/v1/mcp/connections/{id}/discover",
            post(discover_connection),
        )
        .route("/api/v1/mcp/connections/{id}/tools", get(list_tools))
        .route("/api/v1/mcp/grants", get(list_grants).post(create_grant))
        .route("/api/v1/mcp/grants/{id}", delete(revoke_grant))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectionCreate {
    pub name: String,
    pub origin: String,
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub bearer: Option<String>,
    #[serde(default)]
    pub headers: Vec<[String; 2]>,
    #[serde(default)]
    pub header_names: Vec<String>,
    #[serde(default)]
    pub ca_pem: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Deserialize, utoipa::ToSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ConnectionUpdate {
    pub name: Option<String>,
    pub origin: Option<String>,
    pub bearer: Option<String>,
    pub headers: Option<Vec<[String; 2]>>,
    pub header_names: Option<Vec<String>>,
    pub ca_pem: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

fn page(query: &ListQuery) -> Result<(i64, Option<Uuid>), ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let after = match query.cursor.as_deref() {
        Some(c) => Some(
            c.parse()
                .map_err(|_| Error::Validation("invalid cursor".into()))?,
        ),
        None => None,
    };
    Ok((limit, after))
}

fn cursor_page(items: &[Value], limit: i64) -> Value {
    let next_cursor = if items.len() as i64 > limit {
        items.get(limit as usize).and_then(|v| v.get("id")).cloned()
    } else {
        None
    };
    json!({"items": &items[..items.len().min(limit as usize)], "next_cursor": next_cursor})
}

fn manager(state: &ApiState) -> orbit_mcp::ConnectionManager {
    orbit_mcp::ConnectionManager::new(
        state.pool.clone(),
        state.key_dir.clone(),
        state.artifact_dir.clone(),
    )
}

#[utoipa::path(post, path = "/api/v1/mcp/connections", request_body = ConnectionCreate, responses((status = 200, body = Value)))]
pub async fn create_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ConnectionCreate>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    if input.name.trim().is_empty() || input.name.len() > 200 {
        return Err(Error::Validation("mcp connection name invalid".into()).into());
    }
    // Admission runs before anything is persisted: non-HTTP(S) origins,
    // embedded credentials, and query strings are rejected, and link-local /
    // cloud-metadata / private endpoints are denied by AdmittedEndpoint
    // unless the connection is explicitly marked local with admitted
    // addresses.
    let endpoint = orbit_model_router::endpoint::AdmittedEndpoint {
        origin: input.origin.clone(),
        local: input.local,
        admitted_addresses: vec![],
    };
    endpoint
        .url("")
        .map_err(|_| Error::Validation("mcp endpoint rejected by admission".into()))?;
    let id = Uuid::new_v4();
    let mut secret_id = None;
    if input.bearer.as_ref().is_some_and(|b| !b.is_empty()) || !input.headers.is_empty() {
        secret_id = Some(
            orbit_secrets::SecretStore::open(state.pool.clone(), &state.key_dir)
                .await?
                .put(
                    &auth.scope,
                    "mcp-credential",
                    serde_json::to_vec(&json!({"bearer": input.bearer.clone().unwrap_or_default(), "headers": input.headers}))
                        .map_err(Error::from)?
                        .as_slice(),
                )
                .await?,
        );
    }
    let row = sqlx::query(
        "INSERT INTO mcp_connections(id,owner_id,name,endpoint,secret_id,header_names,enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING jsonb_build_object('id',id,'name',name,'endpoint',endpoint,'enabled',enabled,'status',status) record",
    )
    .bind(id)
    .bind(auth.scope.owner_id)
    .bind(&input.name)
    .bind(json!({"origin": input.origin, "local": input.local, "ca_pem": input.ca_pem}))
    .bind(secret_id)
    .bind(serde_json::to_value(&input.header_names).unwrap_or(json!([])))
    .bind(input.enabled.unwrap_or(true))
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(row.get("record")))
}

#[utoipa::path(get, path = "/api/v1/mcp/connections", responses((status = 200, body = Value)))]
pub async fn list_connections(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let (limit, after) = page(&query)?;
    let items: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'name',name,'endpoint',endpoint,'enabled',enabled,'status',status,'last_discovery',last_discovery,'last_error',last_error) FROM mcp_connections WHERE owner_id=$1 AND ($2::uuid IS NULL OR id > $2) ORDER BY id LIMIT $3",
    )
    .bind(auth.scope.owner_id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(cursor_page(&items, limit)))
}

#[utoipa::path(get, path = "/api/v1/mcp/connections/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn connection_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(
        sqlx::query_scalar(
            "SELECT jsonb_build_object('id',id,'name',name,'endpoint',endpoint,'enabled',enabled,'status',status,'server_info',server_info,'last_discovery',last_discovery,'last_activity',last_activity,'last_error',last_error) FROM mcp_connections WHERE owner_id=$1 AND id=$2",
        )
        .bind(auth.scope.owner_id)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?,
    ))
}

#[utoipa::path(patch, path = "/api/v1/mcp/connections/{id}", request_body = ConnectionUpdate, responses((status = 200, body = Value)))]
pub async fn update_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ConnectionUpdate>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    if let Some(origin) = input.origin.as_deref() {
        let endpoint = orbit_model_router::endpoint::AdmittedEndpoint {
            origin: origin.to_owned(),
            local: false,
            admitted_addresses: vec![],
        };
        endpoint
            .url("")
            .map_err(|_| Error::Validation("mcp endpoint rejected by admission".into()))?;
        sqlx::query("UPDATE mcp_connections SET endpoint=jsonb_set(endpoint,'{origin}',to_jsonb($3::text)),revision=revision+1 WHERE owner_id=$1 AND id=$2")
            .bind(auth.scope.owner_id).bind(id).bind(origin).execute(&state.pool).await?;
    }
    if let Some(name) = input.name.as_deref() {
        if name.trim().is_empty() || name.len() > 200 {
            return Err(Error::Validation("mcp connection name invalid".into()).into());
        }
        sqlx::query(
            "UPDATE mcp_connections SET name=$3,revision=revision+1 WHERE owner_id=$1 AND id=$2",
        )
        .bind(auth.scope.owner_id)
        .bind(id)
        .bind(name)
        .execute(&state.pool)
        .await?;
    }
    if let Some(enabled) = input.enabled {
        sqlx::query(
            "UPDATE mcp_connections SET enabled=$3,revision=revision+1 WHERE owner_id=$1 AND id=$2",
        )
        .bind(auth.scope.owner_id)
        .bind(id)
        .bind(enabled)
        .execute(&state.pool)
        .await?;
    }
    connection_detail(State(state), headers, Path(id)).await
}

#[utoipa::path(delete, path = "/api/v1/mcp/connections/{id}", responses((status = 200, body = Value)))]
pub async fn remove_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    // Disable first so in-flight discovery/call batches fail closed even if a
    // later delete races them; the revision bump invalidates live holders.
    sqlx::query(
        "UPDATE mcp_connections SET enabled=false,revision=revision+1 WHERE owner_id=$1 AND id=$2",
    )
    .bind(auth.scope.owner_id)
    .bind(id)
    .execute(&state.pool)
    .await?;
    let row = sqlx::query("SELECT secret_id FROM mcp_connections WHERE owner_id=$1 AND id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    let deleted = sqlx::query("DELETE FROM mcp_connections WHERE owner_id=$1 AND id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(Error::NotFound.into());
    }
    if let Some(r) = row {
        if let Some(secret) = r.get::<Option<Uuid>, _>("secret_id") {
            let _ = orbit_secrets::SecretStore::open(state.pool.clone(), &state.key_dir)
                .await?
                .revoke(&auth.scope, secret)
                .await;
        }
    }
    Ok(Json(json!({"id": id, "deleted": true})))
}

#[utoipa::path(post, path = "/api/v1/mcp/connections/{id}/discover", responses((status = 200, body = Value)))]
pub async fn discover_connection(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let outcome = manager(&state).discover(&auth.scope, id).await?;
    Ok(Json(
        json!({"connection_id": outcome.connection_id, "tools": outcome.tools, "grants_revoked": outcome.grants_revoked, "status": outcome.status}),
    ))
}

#[utoipa::path(get, path = "/api/v1/mcp/connections/{id}/tools", responses((status = 200, body = Value)))]
pub async fn list_tools(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let (limit, after) = page(&query)?;
    let items: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'original_name',original_name,'registry_name',registry_name,'descriptor',descriptor,'schema_digest',schema_digest,'enabled',enabled,'effect_assessment',effect_assessment,'review_reason',review_reason) FROM mcp_tools WHERE owner_id=$1 AND connection_id=$2 AND ($3::uuid IS NULL OR id > $3) ORDER BY id LIMIT $4",
    )
    .bind(auth.scope.owner_id)
    .bind(id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(cursor_page(&items, limit)))
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantCreate {
    pub tool_id: Uuid,
    pub assessment: String,
    pub review_evidence: String,
}

#[utoipa::path(post, path = "/api/v1/mcp/grants", request_body = GrantCreate, responses((status = 200, body = Value)))]
pub async fn create_grant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<GrantCreate>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    if !matches!(input.assessment.as_str(), "READ_ONLY" | "MODIFIES_DATA") {
        return Err(Error::Validation(
            "grant assessment must be READ_ONLY or MODIFIES_DATA".into(),
        )
        .into());
    }
    if input.review_evidence.trim().is_empty() || input.review_evidence.len() > 8192 {
        return Err(Error::Validation("grant review evidence required".into()).into());
    }
    // Grants pin the tool's current schema digest: any later schema change
    // disables the tool and deletes the grant row, so a stale grant can never
    // authorize a changed tool.
    let tool =
        sqlx::query("SELECT schema_digest,enabled FROM mcp_tools WHERE owner_id=$1 AND id=$2")
            .bind(auth.scope.owner_id)
            .bind(input.tool_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(Error::NotFound)?;
    if !tool.get::<bool, _>("enabled") {
        return Err(
            Error::Validation("tool must be enabled before it can be granted".into()).into(),
        );
    }
    let digest: String = tool.get("schema_digest");
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE mcp_tools SET effect_assessment=$3,review_reason='Reviewed: grant pinned to schema digest' WHERE owner_id=$1 AND id=$2",
    )
    .bind(auth.scope.owner_id).bind(input.tool_id).bind(&input.assessment).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO mcp_grants(owner_id,tool_id,schema_digest,revision,assessment,review_evidence) VALUES($1,$2,$3,(SELECT revision FROM mcp_tools WHERE owner_id=$1 AND id=$2),$4,$5) ON CONFLICT(owner_id,tool_id) DO UPDATE SET schema_digest=EXCLUDED.schema_digest,revision=EXCLUDED.revision,assessment=EXCLUDED.assessment,review_evidence=EXCLUDED.review_evidence",
    )
    .bind(auth.scope.owner_id).bind(input.tool_id).bind(&digest).bind(&input.assessment).bind(&input.review_evidence)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"tool_id": input.tool_id, "schema_digest": digest, "assessment": input.assessment, "granted": true}),
    ))
}

#[utoipa::path(get, path = "/api/v1/mcp/grants", responses((status = 200, body = Value)))]
pub async fn list_grants(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let (limit, _) = page(&query)?;
    let items: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('tool_id',g.tool_id,'registry_name',t.registry_name,'schema_digest',g.schema_digest,'assessment',g.assessment,'review_evidence',g.review_evidence,'created_at',g.created_at) FROM mcp_grants g JOIN mcp_tools t ON t.owner_id=g.owner_id AND t.id=g.tool_id WHERE g.owner_id=$1 ORDER BY g.created_at DESC LIMIT $2",
    )
    .bind(auth.scope.owner_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

#[utoipa::path(delete, path = "/api/v1/mcp/grants/{id}", responses((status = 200, body = Value)))]
pub async fn revoke_grant(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let deleted = sqlx::query("DELETE FROM mcp_grants WHERE owner_id=$1 AND tool_id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    if deleted == 0 {
        return Err(Error::NotFound.into());
    }
    Ok(Json(json!({"tool_id": id, "revoked": true})))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_connections,
        create_connection,
        connection_detail,
        update_connection,
        remove_connection,
        discover_connection,
        list_tools,
        list_grants,
        create_grant,
        revoke_grant,
    ),
    components(schemas(ConnectionCreate, ConnectionUpdate, GrantCreate))
)]
pub struct McpApi;
