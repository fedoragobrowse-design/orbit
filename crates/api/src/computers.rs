//! Server half of the computer node control plane: pairing, the outbound node
//! session, and the owner-facing node and file APIs.
//!
//! A node never listens on a network port; it dials this server. The server
//! therefore never needs a Node-side inbound listener, and a node can only be
//! reached through a paired identity, a live session credential and a signed
//! per-connection nonce.
//!
//! Authority stays narrow at every hop. Pairing creates a node, never a file
//! grant: roots are configured on the node itself and are only reported here.
//! The server may revoke or narrow a reported root, and it may never add or
//! broaden one. Every file request carries an immutable, digest-bound
//! authorization whose snapshot names the node, the root and the exact
//! operation; the node re-checks all of it before touching a file.

use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use orbit_computer_node_protocol::{
    Challenge, Envelope, ExecutionRequest, FileEvent, MessageType, VERSION, action_hash,
    verify_challenge,
};
use orbit_core::{
    ActionSnapshot, Error, Event, EventType, OwnerScope, PrivacyClass, Result, RiskLevel,
    ToolDescriptor, ToolEffects, TrustLevel, validate_event,
};
use orbit_event_bus::{EventBus, PostgresEventBus};
use rand::{RngCore, rngs::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

/// A node that has not reported for this long is shown as disconnected.
pub const OFFLINE_AFTER: Duration = Duration::seconds(60);
/// Pairing codes are deliberately short lived and single use.
const CODE_TTL: Duration = Duration::minutes(5);
const CODE_ENTROPY_BYTES: usize = 10;
const CHALLENGE_TTL: Duration = Duration::seconds(60);
const SESSION_TTL_DAYS: i64 = 30;
const REQUEST_TIMEOUT: Duration = Duration::seconds(30);
const SESSION_CAPACITY: usize = 64;

// ---------------------------------------------------------------- session hub

/// One live node connection.
#[derive(Clone)]
struct Link {
    connection_id: Uuid,
    sender: mpsc::Sender<Envelope>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Value>>>>,
}

/// Every node session this process currently holds, plus the replies owed on it.
#[derive(Clone, Default)]
pub struct NodeHub {
    links: Arc<Mutex<HashMap<Uuid, Link>>>,
}

impl NodeHub {
    pub fn new() -> Self {
        Self::default()
    }

    async fn attach(&self, node: Uuid, link: Link) {
        let mut links = self.links.lock().await;
        // A reconnect replaces the previous connection; the old socket is closed
        // by its own task when its link no longer matches.
        links.insert(node, link);
    }

    /// Drop a link only if it is still the current one, so a stale socket's
    /// teardown cannot evict the reconnect that replaced it.
    async fn detach(&self, node: Uuid, connection: Uuid) {
        let mut links = self.links.lock().await;
        if links
            .get(&node)
            .is_some_and(|link| link.connection_id == connection)
        {
            links.remove(&node);
        }
    }
    /// Drop a node's live link regardless of connection id. Revocation (single
    /// or bulk) sets `connection_id=NULL` in SQL first, so no reconnect can
    /// race this removal — unlike socket teardown, which must use `detach`.
    pub async fn evict(&self, node: Uuid) {
        self.links.lock().await.remove(&node);
    }

    async fn link(&self, node: Uuid) -> Option<Link> {
        self.links.lock().await.get(&node).cloned()
    }

    /// Send one envelope and wait for the matching node response.
    ///
    /// A duplicate of an already-issued request id is refused rather than
    /// executed twice: the node journal owns idempotency, the server must not
    /// create a second effect by resending.
    async fn call(&self, node: Uuid, message_type: MessageType, payload: Value) -> Result<Value> {
        let link = self
            .link(node)
            .await
            .ok_or(Error::Unavailable("computer node is not connected".into()))?;
        let request_id = Uuid::new_v4();
        let (reply, answer) = oneshot::channel();
        {
            let mut pending = link.pending.lock().await;
            if pending.contains_key(&request_id) {
                return Err(Error::Conflict("request id is already in flight".into()));
            }
            pending.insert(request_id, reply);
        }
        let envelope = Envelope {
            version: VERSION,
            request_id,
            node_id: node,
            message_type,
            payload,
        };
        if envelope.payload.to_string().len() > orbit_computer_node_protocol::MAX_FRAME {
            lock_remove(&link, request_id).await;
            return Err(Error::Validation(
                "node request exceeds the frame bound".into(),
            ));
        }
        if link.sender.send(envelope).await.is_err() {
            lock_remove(&link, request_id).await;
            return Err(Error::Unavailable("computer node is not connected".into()));
        }
        match tokio::time::timeout(
            REQUEST_TIMEOUT
                .to_std()
                .map_err(|_| Error::Unavailable("invalid request timeout".into()))?,
            answer,
        )
        .await
        {
            Ok(Ok(value)) => node_result(value),
            Ok(Err(_)) => Err(Error::Unavailable("computer node did not answer".into())),
            Err(_) => {
                lock_remove(&link, request_id).await;
                Err(Error::Timeout)
            }
        }
    }
}

async fn lock_remove(link: &Link, request_id: Uuid) {
    link.pending.lock().await.remove(&request_id);
}

/// Unwrap a node response envelope payload, turning a node-reported failure
/// into the matching server error rather than a silent empty result.
fn node_result(payload: Value) -> Result<Value> {
    tracing::debug!(payload = %payload, "computer node response");
    if payload["ok"].as_bool() == Some(true) {
        return Ok(payload["payload"].clone());
    }
    Err(match payload["error"].as_str().unwrap_or("UNKNOWN") {
        "FORBIDDEN" => Error::Forbidden,
        "NOT_FOUND" => Error::NotFound,
        // The node serializes a stale base as `FILE_VERSION_CONFLICT`; surface it
        // as a conflict (409) rather than a generic 503 so the Files UI can
        // offer a refresh-then-retry instead of an "unavailable" dead end.
        "FILE_VERSION_CONFLICT" => Error::Conflict("file version changed".into()),
        "SECURE_MUTATION_UNAVAILABLE" => Error::UnsupportedCapability,
        "OUTCOME_UNKNOWN" => Error::OutcomeUnknown,
        "UNSUPPORTED" | "UNSUPPORTED_CAPABILITY" => Error::UnsupportedCapability,
        "INVALID" => Error::Validation(
            payload["message"]
                .as_str()
                .unwrap_or("node rejected the request")
                .into(),
        ),
        // `NODE_OFFLINE` is server-side only, but a node may echo it back on a
        // queued request; map it to unavailable either way.
        "NODE_OFFLINE" => Error::Unavailable("computer node is offline".into()),
        other => Error::Unavailable(format!(
            "computer node reported {other}: {}",
            payload["message"].as_str().unwrap_or("no detail")
        )),
    })
}

// -------------------------------------------------------------------- pairing

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_token() -> String {
    hex::encode(random_bytes(32))
}

/// One-use pairing code, hashed at rest and only ever shown to the owner once.
fn new_code() -> String {
    hex::encode(random_bytes(CODE_ENTROPY_BYTES)).to_uppercase()
}

fn normalize_code(input: &str) -> String {
    input
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

fn display_code(code: &str) -> String {
    code.as_bytes()
        .chunks(5)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

fn code_hash(code: &str) -> String {
    orbit_computer_node_protocol::sha256(code.as_bytes())
}

fn verify_key(key: &str) -> Result<()> {
    let raw = STANDARD
        .decode(key)
        .map_err(|_| Error::Validation("identity key must be base64".into()))?;
    if raw.len() != 32 {
        return Err(Error::Validation("identity key must be 32 bytes".into()));
    }
    Ok(())
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub code: String,
    pub identity_key: String,
}

#[utoipa::path(post, path = "/api/v1/computers/pairing-codes", responses((status = 200, body = Value)))]
pub async fn create_pairing_code(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let code = new_code();
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    // Only the newest code is live: pairing is a deliberate, present-tense act.
    sqlx::query(
        "UPDATE computer_pairing_codes SET used_at=now() WHERE owner_id=$1 AND used_at IS NULL",
    )
    .bind(a.scope.owner_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO computer_pairing_codes(id,owner_id,code_hash,expires_at) VALUES($1,$2,$3,now()+make_interval(secs => $4::int))")
        .bind(id)
        .bind(a.scope.owner_id)
        .bind(code_hash(&code))
        .bind(CODE_TTL.num_seconds())
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "PAIRING_CODE_CREATED",
        "owner created a one-use computer pairing code",
        json!({ "pairing_code_id": id }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"id": id, "code": display_code(&code), "expires_in_seconds": CODE_TTL.num_seconds()}),
    ))
}

/// Pairing is authenticated by the one-use code alone, over verified TLS. It
/// creates the node identity and returns the session credential exactly once;
/// the plaintext credential is never stored.
#[utoipa::path(post, path = "/api/v1/computers/pair", request_body = PairRequest, responses((status = 200, body = Value), (status = 403, description = "Code not usable")))]
pub async fn pair(
    State(state): State<ApiState>,
    Json(input): Json<PairRequest>,
) -> Result<Json<Value>, ApiError> {
    verify_key(&input.identity_key)?;
    let normalized = normalize_code(&input.code);
    if normalized.len() != CODE_ENTROPY_BYTES * 2 {
        return Err(Error::Forbidden.into());
    }
    let node_id = Uuid::new_v4();
    let principal = Uuid::new_v4();
    let session = random_token();
    let session_hash = orbit_computer_node_protocol::sha256(session.as_bytes());
    let mut tx = state.pool.begin().await?;
    let code =
        sqlx::query("SELECT owner_id FROM computer_pairing_codes WHERE code_hash=$1 FOR UPDATE")
            .bind(code_hash(&normalized))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Forbidden)?;
    let owner_id: Uuid = code.get("owner_id");
    let spent = sqlx::query("UPDATE computer_pairing_codes SET used_at=now() WHERE owner_id=$1 AND used_at IS NULL AND expires_at>now()")
        .bind(owner_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if spent != 1 {
        return Err(Error::Forbidden.into());
    }
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'COMPUTER_NODE','NODE_SESSION','UNTRUSTED_EXTERNAL','computer-node')")
        .bind(principal)
        .bind(owner_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO computer_nodes(id,owner_id,principal_id,public_key,session_hash,session_expires_at) VALUES($1,$2,$3,$4,$5,now()+make_interval(days => $6::int))")
        .bind(node_id)
        .bind(owner_id)
        .bind(principal)
        .bind(input.identity_key)
        .bind(&session_hash)
        .bind(SESSION_TTL_DAYS)
        .execute(&mut *tx)
        .await?;
    // The principal and node rows must be visible before the pairing event and its
    // audit record reference them, so the identity commit happens first.
    tx.commit().await?;
    let scope = OwnerScope {
        owner_id,
        principal_id: principal,
    };
    let event = Event {
        id: Uuid::new_v4(),
        owner_id,
        event_type: EventType::ComputerConnected,
        source: "computer-node".into(),
        principal_id: principal,
        timestamp: Utc::now(),
        payload: json!({ "node_id": node_id }),
        trust_level: TrustLevel::UntrustedExternal,
        privacy_class: PrivacyClass::Private,
        correlation_id: Uuid::new_v4(),
        related_entities: vec![],
        source_event_key: format!("computer:{node_id}:paired"),
    };
    let event_id = PostgresEventBus {
        pool: state.pool.clone(),
    }
    .publish(&scope, event)
    .await?;
    let mut audit_tx = state.pool.begin().await?;
    orbit_audit::append(
        &mut audit_tx,
        &scope,
        Uuid::new_v4(),
        Some(event_id),
        None,
        "COMPUTER_PAIRED",
        "one-use code paired a computer node",
        json!({ "node_id": node_id }),
    )
    .await?;
    audit_tx.commit().await?;
    Ok(Json(json!({
        "owner_id": owner_id,
        "node_id": node_id,
        "session": session,
        "session_expires_at": Utc::now() + Duration::days(SESSION_TTL_DAYS),
        "roots": [],
    })))
}

// ------------------------------------------------------------ node lifecycle

fn node_view(row: &sqlx::postgres::PgRow, online: bool) -> Value {
    let revoked: Option<DateTime<Utc>> = row.get("revoked_at");
    let last_seen: Option<DateTime<Utc>> = row.get("last_seen");
    let alive = last_seen.is_some_and(|seen| Utc::now() - seen < OFFLINE_AFTER);
    json!({
        "id": row.get::<Uuid, _>("id"),
        "display_name": row.get::<String, _>("display_name"),
        "revision": row.get::<i64, _>("revision"),
        "public_key": row.get::<String, _>("public_key"),
        "session_expires_at": row.get::<DateTime<Utc>, _>("session_expires_at"),
        "capabilities": row.get::<Value, _>("capabilities"),
        "ack_sequence": row.get::<i64, _>("ack_sequence"),
        "last_seen": last_seen,
        "revoked_at": revoked,
        "connected": online || alive,
        "roots": Vec::<Value>::new(),
    })
}

async fn node_row(pool: &PgPool, owner: Uuid, node: Uuid) -> Result<sqlx::postgres::PgRow> {
    sqlx::query("SELECT * FROM computer_nodes WHERE owner_id=$1 AND id=$2")
        .bind(owner)
        .bind(node)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::NotFound)
}

async fn roots_of(pool: &PgPool, owner: Uuid, node: Uuid) -> Result<Vec<Value>> {
    let rows = sqlx::query("SELECT * FROM computer_roots WHERE owner_id=$1 AND node_id=$2 AND NOT revoked ORDER BY display_name,id")
        .bind(owner)
        .bind(node)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(root_view).collect())
}

fn root_view(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": row.get::<Uuid, _>("id"),
        "display_name": row.get::<String, _>("display_name"),
        "mode": row.get::<String, _>("mode"),
        "revision": row.get::<i64, _>("revision"),
        "mutation_available": row.get::<bool, _>("mutation_available"),
        "status": row.get::<Value, _>("status"),
    })
}

#[utoipa::path(get, path = "/api/v1/computers", responses((status = 200, body = Value)))]
pub async fn list_nodes(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT * FROM computer_nodes WHERE owner_id=$1 ORDER BY created_at,id")
        .bind(a.scope.owner_id)
        .fetch_all(&state.pool)
        .await?;
    let online: Vec<Uuid> = state.nodes.links.lock().await.keys().copied().collect();
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        let node: Uuid = row.get("id");
        let mut view = node_view(row, online.contains(&node));
        view["roots"] = json!(roots_of(&state.pool, a.scope.owner_id, node).await?);
        items.push(view);
    }
    Ok(Json(json!({ "items": items })))
}

#[utoipa::path(get, path = "/api/v1/computers/{id}", responses((status = 200, body = Value)))]
pub async fn node_detail(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = node_row(&state.pool, a.scope.owner_id, id).await?;
    let online = state.nodes.link(id).await.is_some();
    let mut view = node_view(&row, online);
    view["roots"] = json!(roots_of(&state.pool, a.scope.owner_id, id).await?);
    let requests: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('request_id',request_id,'state',state,'action_hash',action_hash,'created_at',created_at) FROM computer_requests WHERE owner_id=$1 AND node_id=$2 ORDER BY created_at DESC,request_id DESC LIMIT 20")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_all(&state.pool)
        .await?;
    view["recent_requests"] = json!(requests);
    Ok(Json(view))
}

#[utoipa::path(get, path = "/api/v1/computers/{id}/roots", responses((status = 200, body = Value)))]
pub async fn list_roots(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    node_row(&state.pool, a.scope.owner_id, id).await?;
    Ok(Json(
        json!({ "items": roots_of(&state.pool, a.scope.owner_id, id).await? }),
    ))
}

/// Revoking a node kills its session credential and its reported roots at once.
/// The node drops its local index material when it receives the revocation.
#[utoipa::path(post, path = "/api/v1/computers/{id}/revoke", responses((status = 200, body = Value)))]
pub async fn revoke_node(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = node_row(&state.pool, a.scope.owner_id, id).await?;
    if row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(Error::Conflict("computer node is already revoked".into()).into());
    }
    sqlx::query("UPDATE computer_nodes SET revoked_at=now(),revision=revision+1,connection_id=NULL WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE computer_roots SET revoked=true,revision=revision+1 WHERE owner_id=$1 AND node_id=$2 AND NOT revoked")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "COMPUTER_REVOKED",
        "owner revoked a computer node and its roots",
        json!({ "node_id": id }),
    )
    .await?;
    tx.commit().await?;
    drop_roots(&state, id, Uuid::new_v4(), "NODE_REVOKED").await;
    state.nodes.detach(id, Uuid::nil()).await;
    Ok(Json(json!({ "id": id, "revoked": true })))
}

/// Rotate a node's session credential without re-pairing. The old credential
/// stops working at once; the node must use the returned value from then on.
#[utoipa::path(post, path = "/api/v1/computers/{id}/sessions/renew", responses((status = 200, body = Value)))]
pub async fn renew_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = node_row(&state.pool, a.scope.owner_id, id).await?;
    if row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(Error::Conflict("computer node is revoked".into()).into());
    }
    let session = random_token();
    let digest = orbit_computer_node_protocol::sha256(session.as_bytes());
    sqlx::query("UPDATE computer_nodes SET session_hash=$3,revision=revision+1,last_seen=now() WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(digest)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "COMPUTER_SESSION_RENEWED",
        "owner rotated a computer node session credential",
        json!({ "node_id": id }),
    )
    .await?;
    tx.commit().await?;
    state.nodes.detach(id, Uuid::nil()).await;
    Ok(Json(json!({ "id": id, "session": session })))
}

/// Drop the live socket without revoking the node. The credential survives;
/// the node simply reconnects, and reads report `NODE_OFFLINE` meanwhile.
#[utoipa::path(post, path = "/api/v1/computers/{id}/sessions/revoke", responses((status = 200, body = Value)))]
pub async fn revoke_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let row = node_row(&state.pool, a.scope.owner_id, id).await?;
    if row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(Error::Conflict("computer node is revoked".into()).into());
    }
    sqlx::query("UPDATE computer_nodes SET connection_id=NULL WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&state.pool)
        .await?;
    state.nodes.detach(id, Uuid::nil()).await;
    Ok(Json(json!({ "id": id, "disconnected": true })))
}
/// A server-initiated root reduction. The server can only revoke or narrow what
/// the node already reported; it can never create or broaden a grant.
#[utoipa::path(post, path = "/api/v1/computers/{id}/roots/{root_id}/revoke", responses((status = 200, body = Value)))]
pub async fn revoke_root(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((id, root_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(a.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    node_row(&state.pool, a.scope.owner_id, id).await?;
    let revoked = sqlx::query("UPDATE computer_roots SET revoked=true,revision=revision+1 WHERE owner_id=$1 AND node_id=$2 AND id=$3 AND NOT revoked RETURNING revision")
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(root_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let revision: i64 = revoked.get("revision");
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "COMPUTER_ROOT_REVOKED",
        "owner revoked a computer node root",
        json!({ "node_id": id, "root_id": root_id, "revision": revision }),
    )
    .await?;
    tx.commit().await?;
    drop_roots(&state, id, root_id, "ROOT_REVOKED").await;
    Ok(Json(
        json!({ "node_id": id, "root_id": root_id, "revoked": true, "revision": revision }),
    ))
}

#[utoipa::path(delete, path = "/api/v1/computers/{id}", responses((status = 204, description = "Removed")))]
pub async fn remove_node(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    node_row(&state.pool, a.scope.owner_id, id).await?;
    sqlx::query("DELETE FROM computer_requests WHERE owner_id=$1 AND node_id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM computer_event_receipts WHERE owner_id=$1 AND node_id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM computer_roots WHERE owner_id=$1 AND node_id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM computer_nodes WHERE owner_id=$1 AND id=$2")
        .bind(a.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "COMPUTER_REMOVED",
        "owner removed a revoked computer node",
        json!({ "node_id": id }),
    )
    .await?;
    tx.commit().await?;
    state.nodes.detach(id, Uuid::nil()).await;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

/// Tell a connected node to forget a root (or everything, for a revoked node).
async fn drop_roots(state: &ApiState, node: Uuid, root_id: Uuid, reason: &str) {
    if let Some(link) = state.nodes.link(node).await {
        let payload = json!({ "node_id": node, "root_id": root_id, "reason": reason });
        let _ = link
            .sender
            .send(Envelope {
                version: VERSION,
                request_id: Uuid::new_v4(),
                node_id: node,
                message_type: MessageType::Revoke,
                payload,
            })
            .await;
    }
}

// --------------------------------------------------------------- node session

struct Registered {
    node_id: Uuid,
    principal_id: Uuid,
    public_key: String,
    session_hash: String,
    capabilities: Value,
}

async fn read_envelope(socket: &mut WebSocket, node: Uuid) -> Result<Envelope> {
    let incoming = socket
        .next()
        .await
        .ok_or(Error::Forbidden)?
        .map_err(|_| Error::Forbidden)?;
    match incoming {
        Message::Text(text) => {
            let envelope: Envelope = serde_json::from_str(&text).map_err(|_| Error::Forbidden)?;
            envelope.validate(node).map_err(|_| Error::Forbidden)?;
            Ok(envelope)
        }
        Message::Close(_) => Err(Error::Forbidden),
        _ => Err(Error::Forbidden),
    }
}

/// Record the roots a node reports.
///
/// This is a report, not a grant: the node created these grants locally and the
/// server only records the identifier, mode and revision it is told about. The
/// filesystem path is deliberately not stored — it is owner-private and the
/// server has no use for it.
async fn sync_roots(state: &ApiState, node: &Node, capabilities: &Value) {
    for root in capabilities["roots"].as_array().into_iter().flatten() {
        // The protocol carries the root identifier as `id`; the filesystem path is
        // never reported, so the server stores no owner-private location.
        let (Some(id), Some(mode)) = (
            root["id"]
                .as_str()
                .and_then(|value| Uuid::parse_str(value).ok()),
            root["mode"].as_str(),
        ) else {
            continue;
        };
        if !matches!(mode, "READ" | "READ_WRITE" | "ASK") {
            continue;
        }
        let label = root["display_name"]
            .as_str()
            .unwrap_or("root")
            .chars()
            .take(64)
            .collect::<String>();
        let revision = root["revision"].as_i64().unwrap_or(1);
        let available = root["mutation_available"].as_bool().unwrap_or(false);
        let status = root["index_status"].clone();
        let recorded = sqlx::query("INSERT INTO computer_roots(id,owner_id,node_id,display_name,mode,revision,mutation_available,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (owner_id,id) DO UPDATE SET mode=EXCLUDED.mode,display_name=EXCLUDED.display_name,revision=GREATEST(computer_roots.revision,EXCLUDED.revision),mutation_available=EXCLUDED.mutation_available,status=EXCLUDED.status")
            .bind(id)
            .bind(node.owner_id)
            .bind(node.node_id)
            .bind(label)
            .bind(mode)
            .bind(revision)
            .bind(available)
            .bind(status)
            .execute(&state.pool)
            .await;
        if recorded.is_err() {
            tracing::warn!(node_id = %node.node_id, root_id = %id, "rejected a reported computer node root");
        }
    }
}

use futures_util::StreamExt;
/// REGISTER carries only public identity. The session credential has not been
/// presented yet, so nothing about this node is trusted beyond the key it
/// claims, which must equal the key stored at pairing.
async fn register(state: &ApiState, socket: &mut WebSocket) -> Result<Registered> {
    let first = socket
        .next()
        .await
        .ok_or(Error::Forbidden)?
        .map_err(|_| Error::Forbidden)?;
    let Message::Text(text) = first else {
        return Err(Error::Forbidden);
    };
    let envelope: Envelope = serde_json::from_str(&text).map_err(|_| Error::Forbidden)?;
    if envelope.version != VERSION || envelope.message_type != MessageType::Register {
        return Err(Error::Forbidden);
    }
    let node_id = envelope.node_id;
    let key = envelope.payload["identity_key"]
        .as_str()
        .ok_or(Error::Forbidden)?;
    verify_key(key)?;
    if envelope.payload["protocol_version"].as_u64() != Some(u64::from(VERSION)) {
        return Err(Error::Forbidden);
    }
    let capabilities = envelope.payload["capabilities"].clone();
    let node = sqlx::query("SELECT principal_id,public_key,session_hash,session_expires_at,revoked_at FROM computer_nodes WHERE id=$1")
        .bind(node_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::Forbidden)?;
    if node.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(Error::Forbidden);
    }
    if !bool::from(
        key.as_bytes()
            .ct_eq(node.get::<String, _>("public_key").as_bytes()),
    ) {
        return Err(Error::Forbidden);
    }
    Ok(Registered {
        node_id,
        principal_id: node.get("principal_id"),
        public_key: node.get("public_key"),
        session_hash: node.get("session_hash"),
        capabilities,
    })
}

/// Answer a REGISTER with a fresh nonce bound to this node and session.
///
/// The nonce is sent once and is not reusable: `session_hash` here is derived
/// from the stored session digest and the nonce, so the wire never carries the
/// stored credential and a captured challenge cannot be replayed elsewhere.
async fn challenge(
    socket: &mut WebSocket,
    node: Registered,
) -> Result<(Uuid, Challenge, Registered)> {
    let nonce = random_token();
    let challenge = Challenge {
        nonce: nonce.clone(),
        node_id: node.node_id,
        session_hash: orbit_computer_node_protocol::sha256(
            format!("{}:{}", node.session_hash, nonce).as_bytes(),
        ),
        expires_at: Utc::now() + CHALLENGE_TTL,
    };
    let envelope = Envelope {
        version: VERSION,
        request_id: Uuid::new_v4(),
        node_id: node.node_id,
        message_type: MessageType::Challenge,
        payload: serde_json::to_value(&challenge).map_err(Error::from)?,
    };
    socket
        .send(Message::Text(serde_json::to_string(&envelope)?.into()))
        .await
        .map_err(|_| Error::Unavailable("node closed the connection".into()))?;
    // The AUTHENTICATE reply stays unread here: the caller must read that exact
    // frame itself, so consuming it would leave it reading the frame after it.
    Ok((Uuid::new_v4(), challenge, node))
}

async fn authenticate_session(
    state: &ApiState,
    socket: &mut WebSocket,
    node: Registered,
    challenge: &Challenge,
    connection: Uuid,
) -> Result<Node> {
    let envelope = read_envelope(socket, node.node_id).await?;
    if envelope.message_type != MessageType::Authenticate {
        return Err(Error::Forbidden);
    }
    let session = envelope.payload["session"]
        .as_str()
        .ok_or(Error::Forbidden)?;
    if !bool::from(
        orbit_computer_node_protocol::sha256(session.as_bytes())
            .as_bytes()
            .ct_eq(node.session_hash.as_bytes()),
    ) {
        return Err(Error::Forbidden);
    }
    // The echoed binding must be the one this connection issued, so a challenge
    // taken from another connection cannot be signed into this session.
    if envelope.payload["session_hash"].as_str() != Some(challenge.session_hash.as_str()) {
        return Err(Error::Forbidden);
    }
    let signature = envelope.payload["signature"]
        .as_str()
        .ok_or(Error::Forbidden)?;
    verify_challenge(&node.public_key, challenge, signature).map_err(|_| Error::Forbidden)?;

    let owner = sqlx::query_scalar::<_, Uuid>("SELECT owner_id FROM computer_nodes WHERE id=$1")
        .bind(node.node_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::Forbidden)?;
    sqlx::query("UPDATE computer_nodes SET last_seen=now(),connection_id=$3,capabilities=$4,revision=revision+1 WHERE id=$1 AND session_expires_at>now()")
        .bind(node.node_id)
        .bind(owner)
        .bind(connection)
        .bind(&node.capabilities)
        .execute(&state.pool)
        .await?;
    Ok(Node {
        node_id: node.node_id,
        principal_id: node.principal_id,
        owner_id: owner,
    })
}

struct Node {
    node_id: Uuid,
    principal_id: Uuid,
    owner_id: Uuid,
}

/// The node websocket. This is the only place the server accepts a node frame.
async fn connect(State(state): State<ApiState>, upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| serve(state, socket))
}

async fn serve(state: ApiState, mut socket: WebSocket) {
    let registered = match register(&state, &mut socket).await {
        Ok(node) => node,
        Err(error) => {
            tracing::warn!(%error, "rejected computer node registration");
            return;
        }
    };
    let node_id = registered.node_id;
    let (connection, challenge, registered) = match challenge(&mut socket, registered).await {
        Ok(parts) => parts,
        Err(error) => {
            tracing::warn!(%error, node_id = %node_id, "rejected computer node challenge");
            return;
        }
    };
    let registered_capabilities = registered.capabilities.clone();
    let node =
        match authenticate_session(&state, &mut socket, registered, &challenge, connection).await {
            Ok(node) => node,
            Err(error) => {
                tracing::warn!(%error, node_id = %node_id, "rejected computer node session");
                return;
            }
        };
    // The REGISTER payload already carries the node's current capabilities, so the
    // server records the reported roots before the first request can reference one.
    sync_roots(&state, &node, &registered_capabilities).await;
    tracing::info!(node_id = %node_id, "computer node connected");
    let (sender, receiver) = mpsc::channel::<Envelope>(SESSION_CAPACITY);
    let pending = Arc::new(Mutex::new(HashMap::new()));
    state
        .nodes
        .attach(
            node_id,
            Link {
                connection_id: connection,
                sender,
                pending: pending.clone(),
            },
        )
        .await;
    serve_loop(&state, &node, connection, &mut socket, receiver, pending).await;
    state.nodes.detach(node_id, connection).await;
    sqlx::query("UPDATE computer_nodes SET connection_id=NULL,last_seen=now() WHERE id=$1 AND connection_id=$2")
        .bind(node_id)
        .bind(connection)
        .execute(&state.pool)
        .await
        .ok();
    tracing::info!(node_id = %node_id, "computer node disconnected");
}

async fn serve_loop(
    state: &ApiState,
    node: &Node,
    connection: Uuid,
    socket: &mut WebSocket,
    mut outbound: mpsc::Receiver<Envelope>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Value>>>>,
) {
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        tokio::select! {
            outgoing = outbound.recv() => {
                let Some(envelope) = outgoing else { return };
                if socket.send(Message::Text(serde_json::to_string(&envelope).unwrap_or_default().into())).await.is_err() { return }
            }
            incoming = socket.next() => {
                let Some(incoming) = incoming else { return };
                let Ok(incoming) = incoming else { return };
                match incoming {
                    Message::Text(text) => {
                        let Ok(envelope) = serde_json::from_str::<Envelope>(&text) else { return };
                        if envelope.validate(node.node_id).is_err() { return }
                        match envelope.message_type {
                            MessageType::Heartbeat => {
                                sqlx::query("UPDATE computer_nodes SET last_seen=now() WHERE id=$1 AND connection_id=$2").bind(node.node_id).bind(connection).execute(&state.pool).await.ok();
                            }
                            MessageType::Capabilities => {
                                sqlx::query("UPDATE computer_nodes SET capabilities=$2 WHERE id=$1").bind(node.node_id).bind(&envelope.payload).execute(&state.pool).await.ok();
                                sync_roots(state, node, &envelope.payload).await;
                            }
                            MessageType::EventPush => {
                                let acked = ingest_events(state, node, &envelope.payload).await;
                                let reply = Envelope { version: VERSION, request_id: Uuid::new_v4(), node_id: node.node_id, message_type: MessageType::Ack, payload: json!({ "sequence": acked }) };
                                if socket.send(Message::Text(serde_json::to_string(&reply).unwrap_or_default().into())).await.is_err() { return }
                            }
                            MessageType::Response => {
                                let Some(request_id) = envelope.payload["request_id"].as_str().and_then(|id| Uuid::parse_str(id).ok()) else { return };
                                if let Some(reply) = pending.lock().await.remove(&request_id) { let _ = reply.send(envelope.payload); }
                            }
                            _ => return,
                        }
                    }
                    Message::Ping(bytes) => { if socket.send(Message::Pong(bytes)).await.is_err() { return } }
                    Message::Close(_) => return,
                    _ => {}
                }
            }
            _ = heartbeat.tick() => {
                let live = sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NULL FROM computer_nodes WHERE id=$1").bind(node.node_id).fetch_optional(&state.pool).await.unwrap_or(Some(false)).unwrap_or(false);
                if !live { return }
            }
        }
    }
}

/// Persist node file events exactly once and acknowledge the contiguous
/// sequence, so a reconnect resumes after the last durable ack.
async fn ingest_events(state: &ApiState, node: &Node, payload: &Value) -> i64 {
    let mut acked: i64 = 0;
    let scope = OwnerScope {
        owner_id: node.owner_id,
        principal_id: node.principal_id,
    };
    for raw in payload["events"].as_array().into_iter().flatten() {
        let Ok(event) = serde_json::from_value::<FileEvent>(raw.clone()) else {
            break;
        };
        if event.sequence <= acked {
            continue;
        }
        let kind = match event.event_type.as_str() {
            "FILE_CREATED" => EventType::FileCreated,
            "FILE_MODIFIED" => EventType::FileModified,
            "FILE_DELETED" => EventType::FileDeleted,
            _ => break,
        };
        // File content is never carried by an event; only identity and version.
        let body = json!({
            "file_id": event.file_id,
            "root_id": event.root_id,
            "root_revision": event.root_revision,
            "version": event.version,
            "node_id": node.node_id,
            "metadata": event.metadata,
        });
        if validate_event(kind, &body).is_err() {
            break;
        }
        let outgoing = Event {
            id: Uuid::new_v4(),
            owner_id: node.owner_id,
            event_type: kind,
            source: "computer-node".into(),
            principal_id: node.principal_id,
            timestamp: Utc::now(),
            payload: body,
            trust_level: TrustLevel::UntrustedExternal,
            privacy_class: PrivacyClass::Private,
            correlation_id: Uuid::new_v4(),
            related_entities: vec![],
            // The node sequence is the idempotency key across reconnects.
            source_event_key: format!("computer:{}:{}", node.node_id, event.sequence),
        };
        let Ok(event_id) = PostgresEventBus {
            pool: state.pool.clone(),
        }
        .publish(&scope, outgoing)
        .await
        else {
            break;
        };
        let recorded = sqlx::query("INSERT INTO computer_event_receipts(owner_id,node_id,sequence,event_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(node.owner_id)
            .bind(node.node_id)
            .bind(event.sequence)
            .bind(event_id)
            .execute(&state.pool)
            .await
            .map(|result| result.rows_affected())
            .unwrap_or(0);
        if recorded == 0 {
            break;
        }
        acked = acked.max(event.sequence);
    }
    if acked > 0 {
        sqlx::query("UPDATE computer_nodes SET ack_sequence=GREATEST(ack_sequence,$2),last_seen=now() WHERE id=$1")
            .bind(node.node_id)
            .bind(acked)
            .execute(&state.pool)
            .await
            .ok();
    }
    acked
}

// -------------------------------------------------------------- file requests

/// Read-capable node tools. Mutation tools exist so a proposal can be reviewed;
/// they are never executed from these routes.
/// Registered tool schemas declare absent optional fields as "type": "string"
/// or "type": "integer", so an omitted query parameter must not travel as null.
fn arguments(pairs: Vec<(&'static str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .filter(|(_, value)| !value.is_null())
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

pub fn descriptors() -> Vec<ToolDescriptor> {
    let read_effects = ToolEffects {
        external: true,
        modifies_data: false,
        reversible: true,
        credential_access: false,
        affected_party: "owner-selected computer files".into(),
        network: false,
    };
    let address = json!({
        "type": "object",
        "required": ["node_id", "root_id"],
        "additionalProperties": false,
        "properties": {
            "node_id": {"type": "string", "format": "uuid"},
            "root_id": {"type": "string", "format": "uuid"},
            "relative_path": {"type": "string", "maxLength": 4096},
            "file_id": {"type": "string", "format": "uuid"},
            "expected_version": {"type": ["string", "null"], "maxLength": 128},
            "cursor": {"type": ["string", "null"], "maxLength": 512},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    });
    let search = json!({
        "type": "object",
        "required": ["node_id", "root_ids", "query"],
        "additionalProperties": false,
        "properties": {
            "node_id": {"type": "string", "format": "uuid"},
            "root_ids": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"type": "string", "format": "uuid"}},
            "query": {"type": "string", "minLength": 1, "maxLength": 512},
            "mode": {"enum": ["FILENAME", "TEXT", "SEMANTIC"]},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    });
    let records = json!({
        "type": "object",
        "required": ["items"],
        "additionalProperties": false,
        "properties": {
            "items": {"type": "array", "maxItems": 50},
            "next_cursor": {"type": ["string", "null"], "maxLength": 512},
        },
    });
    vec![
        ToolDescriptor {
            id: Uuid::from_u128(0x0f1e_2d3c_4b5a_6978_8796_a5b4_c3d2_e1f0),
            name: "files.list".into(),
            version: "1".into(),
            input_schema: address.clone(),
            output_schema: records.clone(),
            effects: read_effects.clone(),
            default_risk: RiskLevel::ReadOnly,
            permission_keys: vec!["computer.files.read".into()],
            sandbox_required: false,
        },
        ToolDescriptor {
            id: Uuid::from_u128(0x1a2b_3c4d_5e6f_7081_92a3_b4c5_d6e7_f809),
            name: "files.search".into(),
            version: "1".into(),
            input_schema: search,
            output_schema: records.clone(),
            effects: read_effects.clone(),
            default_risk: RiskLevel::ReadOnly,
            permission_keys: vec!["computer.files.read".into()],
            sandbox_required: false,
        },
        ToolDescriptor {
            id: Uuid::from_u128(0x2b3c_4d5e_6f70_8192_a3b4_c5d6_e7f8_0901),
            name: "files.metadata".into(),
            version: "1".into(),
            input_schema: address.clone(),
            output_schema: records.clone(),
            effects: read_effects.clone(),
            default_risk: RiskLevel::ReadOnly,
            permission_keys: vec!["computer.files.read".into()],
            sandbox_required: false,
        },
        ToolDescriptor {
            id: Uuid::from_u128(0x3c4d_5e6f_7081_92a3_b4c5_d6e7_f809_1a2b),
            name: "files.read".into(),
            version: "1".into(),
            input_schema: address.clone(),
            output_schema: json!({
                "type": "object",
                "required": ["file_id", "sha256", "size"],
                "additionalProperties": false,
                "properties": {
                    "file_id": {"type": "string", "format": "uuid"},
                    "relative_path": {"type": "string", "maxLength": 4096},
                    "version": {"type": "string", "maxLength": 128},
                    "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    "size": {"type": "integer", "minimum": 0, "maximum": 10485760},
                    "privacy_class": {"type": "string"},
                    "text_preview": {"type": "string", "maxLength": 8192},
                    "content_base64": {"type": "string"},
                },
            }),
            effects: read_effects.clone(),
            default_risk: RiskLevel::Low,
            permission_keys: vec!["computer.files.read".into()],
            sandbox_required: false,
        },
        ToolDescriptor {
            id: Uuid::from_u128(0x4d5e_6f70_8192_a3b4_c5d6_e7f8_0901_2b3c),
            name: "files.watch".into(),
            version: "1".into(),
            input_schema: address,
            output_schema: json!({
                "type": "object",
                "required": ["watch_id", "status"],
                "additionalProperties": false,
                "properties": {
                    "watch_id": {"type": "string", "maxLength": 128},
                    "status": {"type": "string"},
                },
            }),
            effects: read_effects,
            default_risk: RiskLevel::Low,
            permission_keys: vec!["computer.files.read".into()],
            sandbox_required: false,
        },
    ]
}

fn descriptor_for(tool: &str) -> Result<ToolDescriptor> {
    descriptors()
        .into_iter()
        .find(|d| d.name == tool)
        .ok_or(Error::Forbidden)
}

fn message_for(tool: &str) -> Result<MessageType> {
    Ok(match tool {
        "files.list" => MessageType::FileList,
        "files.search" => MessageType::FileSearch,
        "files.read" => MessageType::FileRead,
        "files.metadata" => MessageType::FileMetadata,
        // The plan's `files.watch` tool travels the same authorized-read path:
        // the node starts a recursive watch and returns its watch id.
        "files.watch" => MessageType::FileWatch,
        _ => return Err(Error::Forbidden),
    })
}

/// An owner request that is ready to reach the node: the durable submission
/// journal row plus the ephemeral execution envelope built from it.
struct Dispatch {
    snapshot: ActionSnapshot,
    authorization: Uuid,
    fence: i64,
}

async fn submit(
    state: &ApiState,
    scope: &OwnerScope,
    tool: &str,
    arguments: Value,
) -> Result<Dispatch> {
    let descriptor = descriptor_for(tool)?;
    orbit_tools::validate_value(&descriptor.input_schema, &arguments)?;
    let node: Uuid = serde_json::from_value(arguments["node_id"].clone())
        .map_err(|_| Error::Validation("node_id must be a uuid".into()))?;
    let mut roots = roots_of(&state.pool, scope.owner_id, node).await?;
    let mut scopes = BTreeMap::new();
    for root in &roots {
        let id: Uuid = serde_json::from_value(root["id"].clone())
            .map_err(|_| Error::Validation("root id is invalid".into()))?;
        scopes.insert(
            format!("root:{id}"),
            root["revision"].as_i64().unwrap_or_default(),
        );
    }
    if arguments.get("root_ids").is_some() {
        roots.retain(|root| {
            arguments["root_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| root["id"].as_str() == id.as_str()))
        });
    }
    if roots.is_empty() {
        return Err(Error::Forbidden);
    }
    let risk = orbit_risk::RiskClassifier::classify_action(
        &orbit_risk::ProposedAction {
            tool_name: tool.to_owned(),
            arguments: arguments.clone(),
        },
        &descriptor,
        &orbit_risk::ActionContext {
            optional_escalation: None,
        },
    )?;
    let decision = policy(state, scope, &descriptor, risk.level, &scopes, &arguments).await?;
    if decision.0 {
        return Err(Error::Forbidden);
    }

    let task = Uuid::new_v4();
    let call = Uuid::new_v4();
    let authorization = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let fence = 1i64;
    let (epoch, policy_revision) = decision.1;
    let snapshot = ActionSnapshot {
        action_id: call,
        owner_id: scope.owner_id,
        principal_id: scope.principal_id,
        agent_id: None,
        task_id: task,
        tool_name: tool.to_owned(),
        tool_version: descriptor.version.clone(),
        arguments: arguments.clone(),
        input_artifact_digests: BTreeMap::new(),
        scope_revisions: scopes,
        policy_revision,
        authorization_epoch: epoch,
        requires_sandbox: descriptor.sandbox_required,
        expires_at: Utc::now() + REQUEST_TIMEOUT,
    };
    let hash = orbit_approvals::canonical_hash(&snapshot)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    // An interactive request is its own short task, so the submission journal
    // is complete even though no agent run owns it.
    sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,title,state,lease_holder,lease_until,fence) VALUES($1,$2,$3,$4,$5,'RUNNING',$6,now()+interval '5 minutes',$7)")
        .bind(task)
        .bind(scope.owner_id)
        .bind(scope.principal_id)
        .bind(correlation)
        .bind(format!("computer {tool}"))
        .bind(scope.principal_id)
        .bind(fence)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state,authorization_id,task_fence,dispatch_holder,submitted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'SUBMITTED',$12,$13,$14,now())")
        .bind(call)
        .bind(scope.owner_id)
        .bind(task)
        .bind(format!("interactive:{call}"))
        .bind(&hash)
        .bind(serde_json::to_value(&snapshot).map_err(Error::from)?)
        .bind(&hash)
        .bind(serde_json::to_value(&descriptor).map_err(Error::from)?)
        .bind(orbit_computer_node_protocol::sha256(serde_json::to_vec(&descriptor).map_err(Error::from)?.as_slice()))
        .bind(serde_json::to_value(&risk).map_err(Error::from)?)
        .bind(serde_json::to_value(&decision.2).map_err(Error::from)?)
        .bind(authorization)
        .bind(fence)
        .bind(scope.principal_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        None,
        Some(task),
        "COMPUTER_REQUEST_SUBMITTED",
        "owner submitted an authorized computer node request",
        json!({ "call_id": call, "authorization_id": authorization, "tool": tool, "action_hash": hash }),
    )
    .await?;
    tx.commit().await?;
    Ok(Dispatch {
        snapshot,
        authorization,
        fence,
    })
}

/// `(denied, (epoch, policy_revision), decision)`.
async fn policy(
    state: &ApiState,
    scope: &OwnerScope,
    descriptor: &ToolDescriptor,
    risk: RiskLevel,
    scopes: &BTreeMap<String, i64>,
    arguments: &Value,
) -> Result<(bool, (i64, i64), Value)> {
    let epoch =
        sqlx::query_scalar::<_, i64>("SELECT revision FROM authorization_epochs WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or(Error::Forbidden)?;
    // An owner who never customised their policy still has the documented base
    // policy, exactly as the policy views report it; absence is not a denial.
    let (revision, rules) =
        match sqlx::query("SELECT revision,rules FROM policies WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_optional(&state.pool)
            .await?
        {
            Some(row) => (row.get::<i64, _>("revision"), row.get::<Value, _>("rules")),
            None => (1, json!([])),
        };
    let grants: Vec<orbit_policy::ScopeGrant> = sqlx::query_scalar(
        "SELECT to_jsonb(g)-'owner_id' FROM scope_grants g WHERE owner_id=$1 AND tool_name=$2",
    )
    .bind(scope.owner_id)
    .bind(&descriptor.name)
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .filter_map(|value| serde_json::from_value(value).ok())
    .collect();
    let settings: Value = sqlx::query_scalar("SELECT value FROM settings WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_optional(&state.pool)
        .await?
        .unwrap_or(json!({}));
    let autonomy: orbit_core::AutonomyMode =
        serde_json::from_value(settings["autonomy_mode"].clone())
            .unwrap_or(orbit_core::AutonomyMode::Observe);
    let engine = orbit_policy::PolicyEngine {
        revision,
        autonomy,
        rules: serde_json::from_value(rules).unwrap_or_default(),
        grants,
    };
    let decision = engine.evaluate(scope, &descriptor.name, arguments, descriptor, risk, scopes);
    Ok((
        decision.denied,
        (epoch, decision.policy_revision),
        serde_json::to_value(&decision).map_err(Error::from)?,
    ))
}

/// Close a submitted request out. A node that reported success gets COMPLETED;
/// anything else is a FAILED call with the node's own error code, never a
/// silent success and never a retry of a mutation.
async fn settle(state: &ApiState, dispatch: &Dispatch, outcome: Result<Value>) -> Result<Value> {
    let task = dispatch.snapshot.task_id;
    let call = dispatch.snapshot.action_id;
    let mut tx = state.pool.begin().await?;
    let (state_name, failure) = match &outcome {
        Ok(_) => ("COMPLETED", None),
        Err(error) => ("FAILED", Some(error_code(error))),
    };
    let result = match &outcome {
        Ok(value) => value.clone(),
        Err(error) => json!({ "error": error.to_string() }),
    };
    let code = failure.clone();
    sqlx::query("UPDATE tool_calls SET state=$4,result=$5,error_code=$6,completed_at=now() WHERE owner_id=$1 AND id=$2 AND state='SUBMITTED'")
        .bind(dispatch.snapshot.owner_id)
        .bind(call)
        .bind(dispatch.authorization)
        .bind(state_name)
        .bind(result)
        .bind(failure)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE tasks SET state=$3,updated_at=now() WHERE owner_id=$1 AND id=$2")
        .bind(dispatch.snapshot.owner_id)
        .bind(task)
        .bind(if outcome.is_ok() {
            "COMPLETED"
        } else {
            "FAILED"
        })
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        &OwnerScope {
            owner_id: dispatch.snapshot.owner_id,
            principal_id: dispatch.snapshot.principal_id,
        },
        dispatch.snapshot.task_id,
        None,
        Some(task),
        "COMPUTER_REQUEST_SETTLED",
        "computer node request settled",
        json!({ "call_id": call, "authorization_id": dispatch.authorization, "error_code": code }),
    )
    .await?;
    tx.commit().await?;
    outcome
}

fn error_code(error: &Error) -> String {
    match error {
        Error::Unauthorized => "UNAUTHORIZED",
        Error::Forbidden => "FORBIDDEN",
        Error::NotFound => "NOT_FOUND",
        Error::Validation(_) => "INVALID",
        Error::Conflict(_) => "CONFLICT",
        Error::Unavailable(_) => "UNAVAILABLE",
        Error::UnsupportedCapability => "UNSUPPORTED",
        Error::Timeout => "TIMEOUT",
        Error::OutcomeUnknown => "OUTCOME_UNKNOWN",
        _ => "INTERNAL",
    }
    .into()
}

/// Run one authorized read against a connected node.
async fn node_read(
    state: &ApiState,
    scope: &OwnerScope,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    let message = message_for(tool)?;
    let node: Uuid = serde_json::from_value(arguments["node_id"].clone())
        .map_err(|_| Error::Validation("node_id must be a uuid".into()))?;
    // A node whose last heartbeat is older than 60 seconds counts as
    // disconnected even if its socket has not torn down yet; per the plan an
    // offline node answers `NODE_OFFLINE`, never a stale read.
    mark_offline_stale(state, node).await;
    let dispatch = submit(state, scope, tool, arguments).await?;
    let snapshot = serde_json::to_value(&dispatch.snapshot).map_err(Error::from)?;
    let request = ExecutionRequest {
        authorization_id: dispatch.authorization,
        task_fence: dispatch.fence,
        snapshot: snapshot.clone(),
        action_hash: action_hash(&snapshot).map_err(|error| {
            Error::Serialization(serde_json::Error::io(std::io::Error::other(
                error.to_string(),
            )))
        })?,
        content_base64: None,
    };
    let result = state
        .nodes
        .call(
            node,
            message,
            serde_json::to_value(&request).map_err(Error::from)?,
        )
        .await;
    settle(state, &dispatch, result).await
}

/// Clear the live link when the heartbeat is stale so `call` reports
/// `NODE_OFFLINE` instead of racing a dead socket. DB `last_seen` stays the
/// source of truth for the status surface; this only drops the socket handle.
async fn mark_offline_stale(state: &ApiState, node: Uuid) {
    let stale = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT last_seen FROM computer_nodes WHERE id=$1",
    )
    .bind(node)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .flatten()
    .is_none_or(|seen| Utc::now() - seen >= OFFLINE_AFTER);
    if stale {
        state.nodes.detach(node, Uuid::nil()).await;
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct FileQuery {
    pub node_id: Uuid,
    pub root_id: Uuid,
    pub relative_path: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// Query-string pairs carry no sequence syntax, so the roots a search spans are
/// a bounded comma-separated list rather than a repeated key.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct SearchQuery {
    pub node_id: Uuid,
    #[serde(deserialize_with = "comma_separated_uuids")]
    pub root_ids: Vec<Uuid>,
    pub query: String,
    pub mode: Option<String>,
    pub limit: Option<u32>,
}

fn comma_separated_uuids<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Uuid>, D::Error> {
    let raw = String::deserialize(deserializer)?;
    let mut ids = Vec::new();
    for part in raw.split(',').filter(|part| !part.trim().is_empty()) {
        ids.push(Uuid::parse_str(part.trim()).map_err(serde::de::Error::custom)?);
    }
    if ids.is_empty() {
        return Err(serde::de::Error::custom(
            "root_ids must list at least one root",
        ));
    }
    Ok(ids)
}

#[utoipa::path(get, path = "/api/v1/files/list", responses((status = 200, body = Value)))]
pub async fn list_files(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 50);
    let arguments = arguments(vec![
        ("node_id", json!(q.node_id)),
        ("root_id", json!(q.root_id)),
        ("relative_path", json!(q.relative_path)),
        ("cursor", json!(q.cursor)),
        ("limit", json!(limit)),
    ]);
    Ok(Json(
        node_read(&state, &a.scope, "files.list", arguments).await?,
    ))
}

#[utoipa::path(get, path = "/api/v1/files/search", responses((status = 200, body = Value)))]
pub async fn search_files(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    if q.root_ids.is_empty()
        || q.root_ids.len() > 16
        || q.query.trim().is_empty()
        || q.query.len() > 512
    {
        return Err(Error::Validation(
            "one to sixteen roots and a bounded query are required".into(),
        )
        .into());
    }
    let mode = q.mode.clone().unwrap_or_else(|| "FILENAME".into());
    if !matches!(mode.as_str(), "FILENAME" | "TEXT" | "SEMANTIC") {
        return Err(
            Error::Validation("search mode must be FILENAME, TEXT or SEMANTIC".into()).into(),
        );
    }
    let arguments = json!({
        // Every node request names one anchor root; a search additionally carries
        // the full span so the node can widen it to roots it already holds.
        "root_id": q.root_ids[0],
        "node_id": q.node_id,
        "root_ids": q.root_ids,
        "query": q.query.trim(),
        "mode": mode,
        "limit": q.limit.unwrap_or(50).clamp(1, 50),
    });
    Ok(Json(
        node_read(&state, &a.scope, "files.search", arguments).await?,
    ))
}

#[utoipa::path(get, path = "/api/v1/files/metadata", responses((status = 200, body = Value)))]
pub async fn file_metadata(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let arguments = arguments(vec![
        ("node_id", json!(q.node_id)),
        ("root_id", json!(q.root_id)),
        ("relative_path", json!(q.relative_path)),
        ("file_id", json!(q.cursor)),
    ]);
    Ok(Json(
        node_read(&state, &a.scope, "files.metadata", arguments).await?,
    ))
}

#[utoipa::path(get, path = "/api/v1/files/read", responses((status = 200, body = Value)))]
pub async fn read_file(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let arguments = arguments(vec![
        ("node_id", json!(q.node_id)),
        ("root_id", json!(q.root_id)),
        ("relative_path", json!(q.relative_path)),
        ("file_id", json!(q.cursor)),
    ]);
    Ok(Json(
        node_read(&state, &a.scope, "files.read", arguments).await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/files/watch", responses((status = 200, body = Value)))]
pub async fn watch_files(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<FileQuery>,
) -> Result<Json<Value>, ApiError> {
    // Subscribe through the plan's `files.watch` tool over the same
    // authorized-read path as list/search/read. The node starts a recursive
    // watch on the granted root and returns its watch id; callers narrow with
    // the node-held registration, never by widening the root.
    let a = authenticate(&state, &headers, false).await?;
    let arguments = arguments(vec![
        ("node_id", json!(q.node_id)),
        ("root_id", json!(q.root_id)),
        ("relative_path", json!(q.relative_path)),
        ("file_id", json!(q.cursor)),
    ]);
    Ok(Json(
        node_read(&state, &a.scope, "files.watch", arguments).await?,
    ))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ProposalWrite {
    pub node_id: Uuid,
    pub root_id: Uuid,
    pub relative_path: String,
    pub content_base64: String,
    pub expected_version: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ProposalMove {
    pub node_id: Uuid,
    pub root_id: Uuid,
    pub relative_path: String,
    pub destination_path: String,
    pub expected_version: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ProposalCopy {
    pub node_id: Uuid,
    pub root_id: Uuid,
    pub relative_path: String,
    pub destination_path: String,
}

/// Record a mutation as a proposal and return the approval id. Nothing is sent
/// to the node until the owner approves that id through `/api/v1/approvals`.
async fn propose(
    state: &ApiState,
    scope: &OwnerScope,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    let node: Uuid = serde_json::from_value(arguments["node_id"].clone())
        .map_err(|_| Error::Validation("node_id must be a uuid".into()))?;
    let roots = roots_of(&state.pool, scope.owner_id, node).await?;
    let root: Uuid = serde_json::from_value(arguments["root_id"].clone())
        .map_err(|_| Error::Validation("root_id must be a uuid".into()))?;
    let grant = roots
        .iter()
        .find(|r| r["id"].as_str() == Some(root.to_string().as_str()))
        .ok_or(Error::Forbidden)?;
    // Only READ_WRITE roots may even propose a mutation, and never without
    // consent; the node re-checks both before any effect.
    let mode = grant["mode"].as_str().unwrap_or("READ");
    if !matches!(mode, "READ_WRITE" | "ASK") {
        return Err(Error::Forbidden.into());
    }
    let arguments = {
        let mut arguments = arguments;
        arguments["consent_required"] = json!(true);
        arguments
    };
    let descriptor = descriptor_for(tool)?;
    orbit_tools::validate_value(&descriptor.input_schema, &arguments)?;
    // Fail a stale base now, before an approval id exists for it: when the
    // caller names an expected version, the live file (when reachable) must
    // still carry it. An offline node proves nothing, so the check is skipped
    // there and the node enforces the version again at dispatch.
    if let Some(expected) = arguments["expected_version"].as_str()
        && let Some(node_id) = arguments["node_id"]
            .as_str()
            .and_then(|s| s.parse::<Uuid>().ok())
        && let Some(root_id) = arguments["root_id"]
            .as_str()
            .and_then(|s| s.parse::<Uuid>().ok())
        && state.nodes.link(node_id).await.is_some()
    {
        let probe = crate::computers::arguments(vec![
            ("node_id", json!(node_id)),
            ("root_id", json!(root_id)),
            ("relative_path", arguments["relative_path"].clone()),
            ("file_id", arguments["file_id"].clone()),
        ]);
        if let Ok(live) = node_read(state, scope, "files.metadata", probe).await
            && let Some(current) = live["version"].as_str()
            && current != expected
        {
            return Err(Error::Conflict("file version changed".into()).into());
        }
    }
    let scopes = BTreeMap::from([(
        format!("root:{root}"),
        grant["revision"].as_i64().unwrap_or_default(),
    )]);
    let risk = orbit_risk::RiskClassifier::classify_action(
        &orbit_risk::ProposedAction {
            tool_name: tool.to_owned(),
            arguments: arguments.clone(),
        },
        &descriptor,
        &orbit_risk::ActionContext {
            optional_escalation: None,
        },
    )?;
    let (denied, (epoch, policy_revision), decision) =
        policy(state, scope, &descriptor, risk.level, &scopes, &arguments).await?;
    if denied {
        return Err(Error::Forbidden.into());
    }

    let task = Uuid::new_v4();
    let call = Uuid::new_v4();
    let approval = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let snapshot = ActionSnapshot {
        action_id: call,
        owner_id: scope.owner_id,
        principal_id: scope.principal_id,
        agent_id: None,
        task_id: task,
        tool_name: tool.to_owned(),
        tool_version: descriptor.version.clone(),
        arguments,
        input_artifact_digests: BTreeMap::new(),
        scope_revisions: scopes,
        policy_revision,
        authorization_epoch: epoch,
        requires_sandbox: descriptor.sandbox_required,
        expires_at: Utc::now() + Duration::hours(1),
    };
    let hash = orbit_approvals::canonical_hash(&snapshot)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,title,state,lease_holder,lease_until,fence) VALUES($1,$2,$3,$4,$5,'RUNNING',$6,now()+interval '1 hour',1)")
        .bind(task)
        .bind(scope.owner_id)
        .bind(scope.principal_id)
        .bind(correlation)
        .bind(format!("propose {tool}"))
        .bind(scope.principal_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state,approval_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'WAITING_FOR_APPROVAL',$12)")
        .bind(call)
        .bind(scope.owner_id)
        .bind(task)
        .bind(format!("proposal:{call}"))
        .bind(&hash)
        .bind(serde_json::to_value(&snapshot).map_err(Error::from)?)
        .bind(&hash)
        .bind(serde_json::to_value(&descriptor).map_err(Error::from)?)
        .bind(orbit_computer_node_protocol::sha256(serde_json::to_vec(&descriptor).map_err(Error::from)?.as_slice()))
        .bind(serde_json::to_value(&risk).map_err(Error::from)?)
        .bind(decision)
        .bind(approval)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE tasks SET state='WAITING_FOR_APPROVAL',wait_reason=$3 WHERE owner_id=$1 AND id=$2",
    )
    .bind(scope.owner_id)
    .bind(task)
    .bind(format!("approval:{approval}"))
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO approvals(id,owner_id,task_id,call_id,snapshot,action_hash,risk,reasons,preview,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now()+interval '1 hour')")
        .bind(approval)
        .bind(scope.owner_id)
        .bind(task)
        .bind(call)
        .bind(serde_json::to_value(&snapshot).map_err(Error::from)?)
        .bind(&hash)
        .bind(serde_json::to_value(&risk).map_err(Error::from)?)
        .bind(json!([risk.reasons]))
        .bind(orbit_approvals::preview(&snapshot))
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        None,
        Some(task),
        "COMPUTER_MUTATION_PROPOSED",
        "owner proposed a computer file mutation for approval",
        json!({ "call_id": call, "approval_id": approval, "tool": tool, "action_hash": hash }),
    )
    .await?;
    tx.commit().await?;
    let preview = orbit_approvals::preview(&snapshot);
    crate::push::enqueue_approval_push(state, scope, approval, &preview).await;
    Ok(json!({ "approval_id": approval, "call_id": call, "task_id": task, "state": "WAITING_FOR_APPROVAL", "tool": tool, "preview": preview }))
}

#[utoipa::path(post, path = "/api/v1/files/write", request_body = ProposalWrite, responses((status = 200, body = Value)))]
pub async fn propose_write(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ProposalWrite>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let arguments = json!({
        "node_id": input.node_id,
        "root_id": input.root_id,
        "relative_path": input.relative_path,
        "content_base64": input.content_base64,
        "expected_version": input.expected_version,
    });
    Ok(Json(
        propose(&state, &a.scope, "files.write", arguments).await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/files/move", request_body = ProposalMove, responses((status = 200, body = Value)))]
pub async fn propose_move(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ProposalMove>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let arguments = json!({
        "node_id": input.node_id,
        "root_id": input.root_id,
        "relative_path": input.relative_path,
        "destination_path": input.destination_path,
        "expected_version": input.expected_version,
    });
    Ok(Json(
        propose(&state, &a.scope, "files.move", arguments).await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/files/copy", request_body = ProposalCopy, responses((status = 200, body = Value)))]
pub async fn propose_copy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<ProposalCopy>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let arguments = json!({
        "node_id": input.node_id,
        "root_id": input.root_id,
        "relative_path": input.relative_path,
        "destination_path": input.destination_path,
    });
    Ok(Json(
        propose(&state, &a.scope, "files.copy", arguments).await?,
    ))
}

// ------------------------------------------------------------------ registry

/// Seed the owner tool registry from the built-in descriptors. Registration is
/// idempotent: a descriptor already present keeps its identity and only gains a
/// refreshed body and digest.
pub async fn seed_tools(state: &ApiState) -> orbit_core::Result<()> {
    // Before the owner exists there is nobody to seed; ensure_setup runs first
    // and the next start fills the registry in.
    let owner: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT owner_id FROM installation WHERE singleton")
            .fetch_optional(&state.pool)
            .await?
            .flatten();
    let Some(owner) = owner else { return Ok(()) };
    let mut all = orbit_tools::descriptors();
    all.extend(crate::runtimes::descriptors());
    all.extend(descriptors());
    for descriptor in all {
        let body = serde_json::to_value(&descriptor)?;
        let digest = orbit_computer_node_protocol::sha256(&serde_json::to_vec(&descriptor)?);
        sqlx::query("INSERT INTO tool_registry(id,owner_id,name,version,descriptor,descriptor_digest,provider_name) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(owner_id,name) DO UPDATE SET version=EXCLUDED.version,descriptor=EXCLUDED.descriptor,descriptor_digest=EXCLUDED.descriptor_digest")
            .bind(descriptor.id)
            .bind(owner)
            .bind(&descriptor.name)
            .bind(&descriptor.version)
            .bind(&body)
            .bind(digest)
            .bind(orbit_tools::provider_name(descriptor.id))
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/computers", get(list_nodes))
        .route("/api/v1/computers/pairing-codes", post(create_pairing_code))
        .route("/api/v1/computers/pair", post(pair))
        .route("/api/v1/computers/connect", get(connect))
        .route(
            "/api/v1/computers/{id}",
            get(node_detail).delete(remove_node),
        )
        .route("/api/v1/computers/{id}/revoke", post(revoke_node))
        .route("/api/v1/computers/{id}/sessions/renew", post(renew_session))
        .route(
            "/api/v1/computers/{id}/sessions/revoke",
            post(revoke_session),
        )
        .route("/api/v1/computers/{id}/roots", get(list_roots))
        .route(
            "/api/v1/computers/{id}/roots/{root_id}/revoke",
            post(revoke_root),
        )
        .route("/api/v1/files/list", get(list_files))
        .route("/api/v1/files/search", get(search_files))
        .route("/api/v1/files/read", get(read_file))
        .route("/api/v1/files/metadata", get(file_metadata))
        .route("/api/v1/files/watch", post(watch_files))
        .route("/api/v1/files/write", post(propose_write))
        .route("/api/v1/files/move", post(propose_move))
        .route("/api/v1/files/copy", post(propose_copy))
}
