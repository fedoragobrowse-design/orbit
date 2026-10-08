//! MCP connection management: discovery and bounded tool calls.
//!
//! A connection row pins its server through [`AdmittedEndpoint`] (DNS pinning,
//! no redirects, TLS for remote hosts, metadata/link-local deny) and carries
//! credentials only via [`SecretStore`]. Tool descriptions and annotations from
//! the server never authorize anything: every discovered tool is stored
//! disabled with assessment `UNKNOWN`, and a call requires both an enabled
//! tool row and a grant pinned to the exact schema digest.
//!
//! Wire bounds: discovery pages at most 100 pages / 1000 tools, tool calls are
//! bounded to 30 s, and the HTTP backend ([`BoundedClient`]) caps every
//! response at 1 MiB. Oversized results are spilled to the artifact store and
//! reduced to an artifact reference.

use crate::transport::{BoundedClient, MAX_RESPONSE};
use http::{HeaderName, HeaderValue};
use orbit_core::{Error, OwnerScope, Result, RiskLevel, ToolDescriptor, ToolEffects};
use rmcp::model::{CallToolRequestParams, CallToolResponse, PaginatedRequestParams};
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

const MAX_PAGES: usize = 100;
const MAX_TOOLS: usize = 1000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_INLINE_BYTES: usize = 65536;

/// Outcome of a successful [`ConnectionManager::discover`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveryOutcome {
    pub connection_id: Uuid,
    pub tools: usize,
    pub grants_revoked: usize,
    pub status: String,
}

pub struct ConnectionManager {
    pool: PgPool,
    key_dir: PathBuf,
    artifact_dir: PathBuf,
}

impl ConnectionManager {
    pub fn new(pool: PgPool, key_dir: PathBuf, artifact_dir: PathBuf) -> Self {
        Self {
            pool,
            key_dir,
            artifact_dir,
        }
    }

    /// Re-list a server's tools and upsert them default-denied.
    ///
    /// Pagination is explicit and bounded: at most 100 pages and 1000 tools. A
    /// repeated cursor or a conflicting duplicate tool name fails discovery
    /// without persisting anything. Tools whose schema digest changed are
    /// disabled, reset to `UNKNOWN`, have their grants deleted, and require
    /// review.
    pub async fn discover(
        &self,
        scope: &OwnerScope,
        connection_id: Uuid,
    ) -> Result<DiscoveryOutcome> {
        let remote = self.remote(scope, connection_id).await?;
        let (tools, server_info) =
            tokio::time::timeout(DISCOVERY_TIMEOUT, list_remote_tools(&remote))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|e| e)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
            .bind(scope.owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let mut grants_revoked = 0usize;
        for tool in &tools {
            let registry_name = format!("mcp.{connection_id}.{}", tool.name);
            let descriptor = serde_json::to_value(descriptor(
                tool.id,
                &registry_name,
                &tool.input,
                tool.output.as_ref(),
            ))?;
            let existing = sqlx::query(
                "SELECT id,schema_digest FROM mcp_tools WHERE owner_id=$1 AND connection_id=$2 AND original_name=$3",
            )
            .bind(scope.owner_id)
            .bind(connection_id)
            .bind(&tool.name)
            .fetch_optional(&mut *tx)
            .await?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO mcp_tools(id,owner_id,connection_id,original_name,registry_name,descriptor,schema_digest,enabled,effect_assessment,review_reason) VALUES($1,$2,$3,$4,$5,$6,$7,false,'UNKNOWN','New tool: default denied')",
                    )
                    .bind(tool.id)
                    .bind(scope.owner_id)
                    .bind(connection_id)
                    .bind(&tool.name)
                    .bind(&registry_name)
                    .bind(&descriptor)
                    .bind(&tool.digest)
                    .execute(&mut *tx)
                    .await?;
                }
                Some(row) => {
                    let id: Uuid = row.get("id");
                    let digest: String = row.get("schema_digest");
                    if digest == tool.digest {
                        sqlx::query(
                            "UPDATE mcp_tools SET descriptor=$4 WHERE owner_id=$1 AND id=$2 AND connection_id=$3",
                        )
                        .bind(scope.owner_id)
                        .bind(id)
                        .bind(connection_id)
                        .bind(&descriptor)
                        .execute(&mut *tx)
                        .await?;
                    } else {
                        sqlx::query(
                            "UPDATE mcp_tools SET descriptor=$4,schema_digest=$5,revision=revision+1,enabled=false,effect_assessment='UNKNOWN',review_reason='Schema changed: review required' WHERE owner_id=$1 AND id=$2 AND connection_id=$3",
                        )
                        .bind(scope.owner_id)
                        .bind(id)
                        .bind(connection_id)
                        .bind(&descriptor)
                        .bind(&tool.digest)
                        .execute(&mut *tx)
                        .await?;
                        let deleted =
                            sqlx::query("DELETE FROM mcp_grants WHERE owner_id=$1 AND tool_id=$2")
                                .bind(scope.owner_id)
                                .bind(id)
                                .execute(&mut *tx)
                                .await?
                                .rows_affected();
                        grants_revoked += deleted as usize;
                    }
                }
            }
        }
        let disabled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mcp_tools WHERE owner_id=$1 AND connection_id=$2 AND enabled=false",
        )
        .bind(scope.owner_id)
        .bind(connection_id)
        .fetch_one(&mut *tx)
        .await?;
        let status = if disabled == 0 {
            "ACTIVE"
        } else {
            "REVIEW_REQUIRED"
        };
        sqlx::query(
            "UPDATE mcp_connections SET server_info=$3,last_discovery=now(),last_error=NULL,status=$4 WHERE owner_id=$1 AND id=$2",
        )
        .bind(scope.owner_id)
        .bind(connection_id)
        .bind(&server_info)
        .bind(status)
        .execute(&mut *tx)
        .await?;
        orbit_audit::append(
            &mut tx,
            scope,
            Uuid::new_v4(),
            None,
            None,
            "MCP_DISCOVERY",
            "mcp tool discovery completed",
            json!({"connection_id": connection_id, "tools": tools.len(), "grants_revoked": grants_revoked}),
        )
        .await?;
        tx.commit().await?;
        Ok(DiscoveryOutcome {
            connection_id,
            tools: tools.len(),
            grants_revoked,
            status: status.into(),
        })
    }

    /// Call one granted tool with a 30 s bound and persist raw evidence.
    ///
    /// The tool must be enabled and carry a grant pinned to its current schema
    /// digest. Arguments are validated against the registered input schema and
    /// structured output against the registered output schema. A tool-level
    /// `isError` result is a failure. Results too large to inline are spilled
    /// to the artifact store and reduced to an artifact reference.
    pub async fn call_once(
        &self,
        scope: &OwnerScope,
        connection_id: Uuid,
        tool: &str,
        args: Value,
        authorization_id: Uuid,
    ) -> Result<Value> {
        if tool.is_empty() {
            return Err(Error::Validation("mcp tool name required".into()));
        }
        let row = sqlx::query(
            "SELECT t.id,t.descriptor,t.schema_digest,t.enabled,EXISTS(SELECT 1 FROM mcp_grants g WHERE g.owner_id=t.owner_id AND g.tool_id=t.id AND g.schema_digest=t.schema_digest) AS granted FROM mcp_tools t WHERE t.owner_id=$1 AND t.connection_id=$2 AND t.original_name=$3",
        )
        .bind(scope.owner_id)
        .bind(connection_id)
        .bind(tool)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?;
        if !row.get::<bool, _>("enabled") || !row.get::<bool, _>("granted") {
            return Err(Error::Forbidden);
        }
        let digest: String = row.get("schema_digest");
        let descriptor: ToolDescriptor = serde_json::from_value(row.get("descriptor"))?;
        let arguments = args
            .as_object()
            .cloned()
            .ok_or_else(|| Error::Validation("mcp tool arguments must be an object".into()))?;
        orbit_tools::validate_value(&descriptor.input_schema, &args)?;
        let recorded: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mcp_call_evidence WHERE owner_id=$1 AND authorization_id=$2)",
        )
        .bind(scope.owner_id)
        .bind(authorization_id)
        .fetch_one(&self.pool)
        .await?;
        if recorded {
            return Err(Error::Conflict("tool call already recorded".into()));
        }
        let remote = self.remote(scope, connection_id).await?;
        let name = tool.to_owned();
        let outcome = tokio::time::timeout(REQUEST_TIMEOUT, async move {
            let reqwest_client = remote.client().await?;
            let transport = transport(remote, reqwest_client)?;
            let mut client = rmcp::serve_client((), transport)
                .await
                .map_err(|_| Error::Unavailable("MCP session initialization failed".into()))?;
            let params = CallToolRequestParams::new(name).with_arguments(arguments);
            let result = match client.peer().call_tool_once(params).await {
                Ok(CallToolResponse::Complete(result)) => result,
                Ok(_) => return Err(Error::Validation("MCP tool did not return a result".into())),
                Err(_) => return Err(Error::Unavailable("MCP tool call did not complete".into())),
            };
            let _ = client.close().await;
            Ok::<_, Error>(result)
        })
        .await;
        let result = match outcome {
            Err(_) => {
                self.record(
                    scope,
                    connection_id,
                    tool,
                    &digest,
                    authorization_id,
                    "OUTCOME_UNKNOWN",
                    json!({"abandoned": true}),
                )
                .await?;
                return Err(Error::Timeout);
            }
            Ok(Err(e)) => {
                let state = match e {
                    Error::Unavailable(_) => "OUTCOME_UNKNOWN",
                    _ => "FAILED",
                };
                self.record(
                    scope,
                    connection_id,
                    tool,
                    &digest,
                    authorization_id,
                    state,
                    json!({"abandoned": true}),
                )
                .await?;
                return Err(e);
            }
            Ok(Ok(result)) => result,
        };
        if result.is_error.unwrap_or(false) {
            self.record(
                scope,
                connection_id,
                tool,
                &digest,
                authorization_id,
                "FAILED",
                evidence(&result, None)?,
            )
            .await?;
            return Err(Error::Unavailable("MCP tool reported failure".into()));
        }
        let structured = if descriptor.output_schema != json!({}) {
            let value = result
                .structured_content
                .clone()
                .ok_or_else(|| Error::Validation("MCP tool omitted structured output".into()))?;
            orbit_tools::validate_value(&descriptor.output_schema, &value).map_err(|_| {
                Error::Validation("MCP tool output does not match its registered schema".into())
            })?;
            Some(value)
        } else {
            None
        };
        let output = match structured {
            Some(value) => value,
            None => serde_json::to_value(&result.content)?,
        };
        let output_bytes = serde_json::to_vec(&output)?;
        if output_bytes.len() > MAX_RESPONSE {
            self.record(
                scope,
                connection_id,
                tool,
                &digest,
                authorization_id,
                "FAILED",
                evidence(&result, None)?,
            )
            .await?;
            return Err(Error::Validation("MCP result exceeds 1 MiB".into()));
        }
        let output = if output_bytes.len() > MAX_INLINE_BYTES {
            let reference = self
                .spill(scope, connection_id, tool, authorization_id, &output_bytes)
                .await?;
            self.record(
                scope,
                connection_id,
                tool,
                &digest,
                authorization_id,
                "COMPLETED",
                evidence(&result, Some(&reference))?,
            )
            .await?;
            reference
        } else {
            self.record(
                scope,
                connection_id,
                tool,
                &digest,
                authorization_id,
                "COMPLETED",
                evidence(&result, None)?,
            )
            .await?;
            output
        };
        Ok(output)
    }

    /// Owner-scoped connection load plus admission and credential resolution.
    async fn remote(&self, scope: &OwnerScope, connection_id: Uuid) -> Result<Remote> {
        let row = sqlx::query(
            "SELECT endpoint,secret_id,header_names,enabled FROM mcp_connections WHERE owner_id=$1 AND id=$2",
        )
        .bind(scope.owner_id)
        .bind(connection_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::NotFound)?;
        if !row.get::<bool, _>("enabled") {
            return Err(Error::Forbidden);
        }
        let doc: EndpointDoc = serde_json::from_value(row.get("endpoint"))
            .map_err(|_| Error::Validation("MCP endpoint configuration invalid".into()))?;
        if doc.origin.trim().is_empty() || doc.ca_pem.as_ref().is_some_and(|pem| pem.len() > 65536)
        {
            return Err(Error::Validation(
                "MCP endpoint configuration invalid".into(),
            ));
        }
        let endpoint = orbit_model_router::endpoint::AdmittedEndpoint {
            origin: doc.origin.clone(),
            local: doc.local,
            admitted_addresses: doc.admitted_addresses,
        };
        // Rejects non-HTTP(S) origins, embedded credentials, and query strings.
        endpoint.url("")?;
        let allowlist: Vec<String> = serde_json::from_value(row.get("header_names"))
            .map_err(|_| Error::Validation("MCP header allowlist invalid".into()))?;
        let allowed: HashSet<String> = allowlist.into_iter().map(|n| n.to_lowercase()).collect();
        let mut auth = None;
        let mut headers = HashMap::new();
        if let Some(secret_id) = row.get::<Option<Uuid>, _>("secret_id") {
            let store = orbit_secrets::SecretStore::open(self.pool.clone(), &self.key_dir).await?;
            let raw = store.get(scope, secret_id).await?;
            let secret: SecretDoc = serde_json::from_slice(&raw)
                .map_err(|_| Error::Validation("MCP credential configuration invalid".into()))?;
            if let Some(bearer) = secret.bearer.filter(|b| !b.is_empty()) {
                if bearer.len() > 8192 {
                    return Err(Error::Validation(
                        "MCP credential configuration invalid".into(),
                    ));
                }
                auth = Some(bearer);
            }
            for (name, value) in secret.headers {
                if !allowed.contains(&name.to_lowercase()) {
                    continue;
                }
                let name: HeaderName = name
                    .parse()
                    .map_err(|_| Error::Validation("MCP header configuration invalid".into()))?;
                let value: HeaderValue = value
                    .parse()
                    .map_err(|_| Error::Validation("MCP header configuration invalid".into()))?;
                headers.insert(name, value);
            }
        }
        let uri = doc.origin.trim_end_matches('/').to_owned();
        if uri.is_empty() {
            return Err(Error::Validation(
                "MCP endpoint configuration invalid".into(),
            ));
        }
        Ok(Remote {
            endpoint,
            ca_pem: doc.ca_pem.map(String::into_bytes),
            uri,
            auth,
            headers,
        })
    }

    /// Lock-ordered evidence insert: epochs, then connection/tool evidence.
    async fn record(
        &self,
        scope: &OwnerScope,
        connection_id: Uuid,
        tool: &str,
        digest: &str,
        authorization_id: Uuid,
        state: &str,
        protocol_evidence: Value,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
            .bind(scope.owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT t.schema_digest FROM mcp_tools t LEFT JOIN mcp_grants g ON g.owner_id=t.owner_id AND g.tool_id=t.id AND g.schema_digest=t.schema_digest WHERE t.owner_id=$1 AND t.connection_id=$2 AND t.original_name=$3 AND t.enabled AND g.schema_digest IS NOT NULL",
        )
        .bind(scope.owner_id)
        .bind(connection_id)
        .bind(tool)
        .fetch_optional(&mut *tx)
        .await?;
        if current.as_deref() != Some(digest) {
            return Err(Error::Forbidden);
        }
        let insert = sqlx::query(
            "INSERT INTO mcp_call_evidence(id,owner_id,connection_id,authorization_id,tool_name,schema_digest,state,protocol_evidence) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(connection_id)
        .bind(authorization_id)
        .bind(tool)
        .bind(digest)
        .bind(state)
        .bind(&protocol_evidence)
        .execute(&mut *tx)
        .await;
        if let Err(sqlx::Error::Database(e)) = &insert {
            if e.is_unique_violation() {
                return Err(Error::Conflict("tool call already recorded".into()));
            }
        }
        insert?;
        sqlx::query("UPDATE mcp_connections SET last_activity=now() WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(connection_id)
            .execute(&mut *tx)
            .await?;
        orbit_audit::append(
            &mut tx,
            scope,
            authorization_id,
            None,
            None,
            "MCP_CALL",
            "mcp tool call settled",
            json!({"connection_id": connection_id, "tool": tool, "schema_digest": digest, "state": state}),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Spill oversized bytes to the private artifact store; returns a reference.
    async fn spill(
        &self,
        scope: &OwnerScope,
        connection_id: Uuid,
        tool: &str,
        authorization_id: Uuid,
        bytes: &[u8],
    ) -> Result<Value> {
        let digest = hex::encode(Sha256::digest(bytes));
        let id = Uuid::new_v4();
        let storage_key = format!("{}/{}", scope.owner_id, id);
        let parent = self.artifact_dir.join(scope.owner_id.to_string());
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
        let path = self.artifact_dir.join(&storage_key);
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                use tokio::io::AsyncWriteExt;
                file.write_all(bytes)
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
                if hex::encode(Sha256::digest(&prior)) != digest {
                    return Err(Error::Conflict(
                        "existing immutable artifact differs".into(),
                    ));
                }
            }
            Err(_) => return Err(Error::Unavailable("artifact storage unavailable".into())),
        }
        sqlx::query(
            "INSERT INTO artifacts(id,owner_id,task_id,authorization_id,title,safe_name,mime_type,size,sha256,source_references,storage_key) VALUES($1,$2,NULL,$3,'mcp-tool-result','mcp-result.json','application/json',$4,$5,$6,$7) ON CONFLICT(authorization_id) DO NOTHING",
        )
        .bind(id)
        .bind(scope.owner_id)
        .bind(authorization_id)
        .bind(bytes.len() as i64)
        .bind(&digest)
        .bind(json!([{"source": format!("mcp:{connection_id}:{tool}")}]))
        .bind(storage_key)
        .execute(&self.pool)
        .await?;
        Ok(json!({"artifact_id": id, "sha256": digest}))
    }
}

#[derive(Deserialize)]
struct EndpointDoc {
    origin: String,
    #[serde(default)]
    local: bool,
    #[serde(default)]
    admitted_addresses: Vec<std::net::IpAddr>,
    #[serde(default)]
    ca_pem: Option<String>,
}

#[derive(Deserialize, Default)]
struct SecretDoc {
    #[serde(default)]
    bearer: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
}

struct Remote {
    endpoint: orbit_model_router::endpoint::AdmittedEndpoint,
    ca_pem: Option<Vec<u8>>,
    uri: String,
    auth: Option<String>,
    headers: HashMap<HeaderName, HeaderValue>,
}

impl Remote {
    async fn client(&self) -> Result<reqwest::Client> {
        // DNS resolution pins here; redirects are refused; TLS is enforced for
        // remote hosts; metadata and link-local addresses are denied.
        self.endpoint.client_with_ca(self.ca_pem.as_deref()).await
    }
}

fn transport(
    remote: Remote,
    client: reqwest::Client,
) -> Result<StreamableHttpClientTransport<BoundedClient>> {
    let uri: Arc<str> = Arc::<str>::from(remote.uri.as_str());
    let mut config =
        StreamableHttpClientTransportConfig::with_uri(uri).reinit_on_expired_session(false);
    if let Some(auth) = remote.auth {
        config = config.auth_header(auth);
    }
    if !remote.headers.is_empty() {
        config = config.custom_headers(remote.headers);
    }
    Ok(StreamableHttpClientTransport::with_client(
        BoundedClient(client),
        config,
    ))
}

struct DiscoveredTool {
    id: Uuid,
    name: String,
    input: Value,
    output: Option<Value>,
    digest: String,
}

/// Digest pins the canonical input and output schemas together.
fn schema_digest(input: &Value, output: Option<&Value>) -> String {
    let canonical = json!({"input": input, "output": output});
    hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).expect("schemas serialize"),
    ))
}

fn descriptor(
    id: Uuid,
    registry_name: &str,
    input: &Value,
    output: Option<&Value>,
) -> ToolDescriptor {
    ToolDescriptor {
        id,
        name: registry_name.into(),
        version: "1".into(),
        input_schema: input.clone(),
        output_schema: output.cloned().unwrap_or(json!({})),
        // Server annotations are hints, never authority: assume the worst.
        effects: ToolEffects {
            external: true,
            modifies_data: true,
            reversible: false,
            credential_access: false,
            affected_party: "OWNER".into(),
            network: true,
        },
        default_risk: RiskLevel::High,
        permission_keys: vec![registry_name.into()],
        sandbox_required: true,
    }
}

/// Page through `tools/list` with explicit, bounded pagination.
async fn list_remote_tools(remote: &Remote) -> Result<(Vec<DiscoveredTool>, Value)> {
    let reqwest_client = remote.client().await?;
    let transport = transport(
        Remote {
            endpoint: orbit_model_router::endpoint::AdmittedEndpoint {
                origin: remote.endpoint.origin.clone(),
                local: remote.endpoint.local,
                admitted_addresses: remote.endpoint.admitted_addresses.clone(),
            },
            ca_pem: remote.ca_pem.clone(),
            uri: remote.uri.clone(),
            auth: remote.auth.clone(),
            headers: remote.headers.clone(),
        },
        reqwest_client,
    )?;
    // The default client handler offers no sampling and declines elicitation.
    let mut client = tokio::time::timeout(REQUEST_TIMEOUT, rmcp::serve_client((), transport))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Unavailable("MCP session initialization failed".into()))?;
    let server_info = client
        .peer_info()
        .map(|info| serde_json::to_value(info.as_ref()))
        .transpose()?
        .unwrap_or(Value::Null);
    let mut tools = Vec::new();
    let mut seen_cursors = HashSet::new();
    let mut seen_names: HashMap<String, String> = HashMap::new();
    let mut cursor: Option<String> = None;
    let mut finished = false;
    for _ in 0..MAX_PAGES {
        let params = PaginatedRequestParams::default().with_cursor(cursor.clone());
        let page = tokio::time::timeout(REQUEST_TIMEOUT, client.peer().list_tools(Some(params)))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Unavailable("MCP tool listing failed".into()))?;
        for tool in page.tools {
            let name = tool.name.to_string();
            if name.is_empty() {
                let _ = client.close().await;
                return Err(Error::Validation("MCP tool name required".into()));
            }
            let input = Value::Object(tool.input_schema.as_ref().clone());
            orbit_tools::validate_schema(&input).map_err(|_| {
                Error::Validation("MCP tool schema is not an acceptable JSON Schema".into())
            })?;
            let output = tool
                .output_schema
                .as_ref()
                .map(|schema| Value::Object(schema.as_ref().clone()));
            if let Some(schema) = &output {
                orbit_tools::validate_schema(schema).map_err(|_| {
                    Error::Validation("MCP tool output schema is not acceptable".into())
                })?;
            }
            let digest = schema_digest(&input, output.as_ref());
            if let Some(previous) = seen_names.insert(name.clone(), digest.clone()) {
                if previous != digest {
                    let _ = client.close().await;
                    return Err(Error::Conflict(
                        "MCP server returned conflicting tools".into(),
                    ));
                }
            }
            tools.push(DiscoveredTool {
                id: Uuid::new_v4(),
                name,
                input,
                output,
                digest,
            });
            if tools.len() > MAX_TOOLS {
                let _ = client.close().await;
                return Err(Error::Validation(
                    "MCP tool catalog exceeds 1000 tools".into(),
                ));
            }
        }
        match page.next_cursor {
            None => {
                finished = true;
                break;
            }
            Some(next) => {
                if !seen_cursors.insert(next.clone()) {
                    let _ = client.close().await;
                    return Err(Error::Validation(
                        "MCP server repeated a page cursor".into(),
                    ));
                }
                cursor = Some(next);
            }
        }
    }
    let _ = client.close().await;
    if !finished {
        return Err(Error::Validation(
            "MCP tool catalog exceeds 100 pages".into(),
        ));
    }
    Ok((tools, server_info))
}

/// Raw protocol evidence: outcome markers plus digests, never credentials.
fn evidence(result: &rmcp::model::CallToolResult, reference: Option<&Value>) -> Result<Value> {
    let content = serde_json::to_value(&result.content)?;
    let content_bytes = serde_json::to_vec(&content)?;
    let body = match reference {
        Some(reference) => reference.clone(),
        None => result.structured_content.clone().unwrap_or(Value::Null),
    };
    let inline = match &body {
        Value::Null => content.clone(),
        body => body.clone(),
    };
    let inline = if serde_json::to_vec(&inline)?.len() > MAX_INLINE_BYTES {
        json!({"omitted": true})
    } else {
        inline
    };
    Ok(json!({
        "is_error": result.is_error,
        "content_digest": hex::encode(Sha256::digest(&content_bytes)),
        "content_bytes": content_bytes.len(),
        "body": inline,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registry names are namespaced `mcp.<connection>.<tool>`: two
    /// connections exposing the same tool name never collide in the shared
    /// tool registry.
    #[test]
    fn registry_names_are_connection_namespaced() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let ra = format!("mcp.{a}.search");
        let rb = format!("mcp.{b}.search");
        assert_ne!(ra, rb);
        assert!(ra.starts_with("mcp."));
        assert!(ra.contains(&a.to_string()));
    }

    /// The schema digest pins input and output schemas together: a server
    /// that changes either schema invalidates existing grants (see
    /// `discover`, which deletes grants on digest change).
    #[test]
    fn digest_changes_when_either_schema_changes() {
        let input = json!({"type": "object"});
        let base = schema_digest(&input, None);
        assert_eq!(base, schema_digest(&input, None));
        assert_ne!(base, schema_digest(&json!({"type": "string"}), None));
        assert_ne!(
            base,
            schema_digest(&input, Some(&json!({"type": "object"})))
        );
    }

    /// Discovery descriptors default-deny: effects assume the worst and risk
    /// starts High, so a newly discovered tool can never execute before
    /// explicit human review + grant.
    #[test]
    fn descriptors_default_deny() {
        let d = descriptor(Uuid::new_v4(), "mcp.conn.tool", &json!({}), None);
        assert_eq!(d.name, "mcp.conn.tool");
        assert!(d.effects.external && d.effects.modifies_data && !d.effects.reversible);
        assert!(matches!(d.default_risk, RiskLevel::High));
        assert!(d.sandbox_required);
    }
}
