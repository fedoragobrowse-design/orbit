//! Owner-scoped email connector API: accounts, ingestion checkpoints,
//! received messages, persistent drafts, and approval-gated dispatch.
//!
//! Credentials travel in write-only form (`SecretId` references are never
//! returned) and live in the encrypted secret store. Sending resolves an
//! immutable draft version into exact digest-bound arguments and dispatches
//! exactly once through [`EmailProvider::execute`]; SMTP uncertainty lands in
//! `OUTCOME_UNKNOWN` and is never auto-resent.

use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use orbit_core::{ActionSnapshot, AuthorizedAction, Error};
use orbit_email::{AccountConfig, Credential, DraftContent, EmailProvider, MailService};
use orbit_secrets::SecretStore;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

async fn service(state: &ApiState) -> Result<MailService, ApiError> {
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    Ok(MailService { pool: state.pool.clone(), secrets: store })
}

const ACCOUNT_VIEW: &str = "SELECT jsonb_build_object('id',id,'name',name,'config',config,'revision',revision,'enabled',enabled,'last_sync',last_sync,'last_error',last_error,'created_at',created_at) FROM email_accounts";
/// Owner-visible draft projection. SMTP dispatch evidence stays out of it: a
/// draft list is not a delivery log, and evidence can name remote identifiers.
const DRAFT_VIEW: &str = "SELECT to_jsonb(d)-'smtp_evidence' FROM email_drafts d";

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/email/accounts", get(list_accounts).post(create_account))
        .route("/api/v1/email/accounts/{id}", get(account_detail).patch(update_account).delete(remove_account))
        .route("/api/v1/email/accounts/{id}/test", post(test_account))
        .route("/api/v1/email/accounts/{id}/sync", post(sync_account))
        .route("/api/v1/email/messages", get(list_messages))
        .route("/api/v1/email/messages/{id}", get(message_detail))
        .route("/api/v1/email/drafts", get(list_drafts).post(create_draft))
        .route("/api/v1/email/drafts/{id}", get(draft_detail).patch(update_draft))
        .route("/api/v1/email/drafts/{id}/send", post(send_draft))
        .route("/api/v1/email/checkpoints", get(list_checkpoints))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountCreate {
    pub name: String,
    pub config: Value,
    pub imap_credential: Value,
    pub smtp_credential: Value,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdate {
    pub name: Option<String>,
    pub config: Option<Value>,
    pub imap_credential: Option<Value>,
    pub smtp_credential: Option<Value>,
    pub enabled: Option<bool>,
    pub expected_revision: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftCreate {
    pub account_id: Uuid,
    pub content: Value,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftUpdate {
    pub expected_version: i64,
    pub content: Value,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    pub expected_version: i64,
    pub content_digest: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageQuery {
    pub account_id: Option<Uuid>,
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftQuery {
    pub account_id: Option<Uuid>,
    pub state: Option<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckpointQuery {
    pub account_id: Option<Uuid>,
}

fn account_name(name: &str) -> Result<(), Error> {
    if name.trim().is_empty() || name.len() > 128 {
        return Err(Error::Validation("invalid mail account name".into()));
    }
    Ok(())
}

fn parse_config(value: &Value) -> Result<AccountConfig, Error> {
    let config: AccountConfig = serde_json::from_value(value.clone())
        .map_err(|_| Error::Validation("invalid mail configuration".into()))?;
    config.validate()?;
    Ok(config)
}

/// Canonical write-only credential bytes; error messages never echo secrets.
fn credential_bytes(value: &Value) -> Result<Vec<u8>, Error> {
    let credential: Credential = serde_json::from_value(value.clone())
        .map_err(|_| Error::Validation("invalid mail credential".into()))?;
    if credential.username.trim().is_empty()
        || credential.username.len() > 1024
        || credential.password.is_empty()
        || credential.password.len() > 16384
    {
        return Err(Error::Validation("invalid mail credential".into()));
    }
    serde_json::to_vec(&json!({"username": credential.username, "password": credential.password}))
        .map_err(Error::from)
}

fn parse_content(value: &Value) -> Result<DraftContent, Error> {
    serde_json::from_value(value.clone())
        .map_err(|_| Error::Validation("invalid draft content".into()))
}

async fn account_view(state: &ApiState, owner: Uuid, id: Uuid) -> Result<Value, ApiError> {
    let query = format!("{ACCOUNT_VIEW} WHERE owner_id=$1 AND id=$2");
    Ok(sqlx::query_scalar(&query)
        .bind(owner)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?)
}
#[utoipa::path(get, path = "/api/v1/email/accounts", responses((status = 200, body = Value)))]
pub async fn list_accounts(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let query = format!("{ACCOUNT_VIEW} WHERE owner_id=$1 ORDER BY created_at DESC,id DESC LIMIT 50");
    let items: Vec<Value> = sqlx::query_scalar(&query).bind(auth.scope.owner_id).fetch_all(&state.pool).await?;
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

#[utoipa::path(get, path = "/api/v1/email/accounts/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn account_detail(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(account_view(&state, auth.scope.owner_id, id).await?))
}

#[utoipa::path(post, path = "/api/v1/email/accounts", request_body = AccountCreate, responses((status = 200, body = Value)))]
pub async fn create_account(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<AccountCreate>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    account_name(&input.name)?;
    let config = parse_config(&input.config)?;
    let imap = credential_bytes(&input.imap_credential)?;
    let smtp = credential_bytes(&input.smtp_credential)?;
    // Secrets land in the encrypted store before the account row exists; the
    // row below is the only durable link to them.
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let imap_id = store.put(&auth.scope, "email-imap-credential", &imap).await?;
    let smtp_id = store.put(&auth.scope, "email-smtp-credential", &smtp).await?;
    let id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO email_accounts(id,owner_id,name,config,imap_secret_id,smtp_secret_id) VALUES($1,$2,$3,$4,$5,$6)")
        .bind(id)
        .bind(auth.scope.owner_id)
        .bind(&input.name)
        .bind(json!(config))
        .bind(imap_id)
        .bind(smtp_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(&mut tx, &auth.scope, Uuid::new_v4(), None, None, "EMAIL_ACCOUNT_CREATED", "owner added mail account", json!({"account_id": id, "name": input.name})).await?;
    tx.commit().await?;
    Ok(Json(account_view(&state, auth.scope.owner_id, id).await?))
}

#[utoipa::path(patch, path = "/api/v1/email/accounts/{id}", params(("id" = Uuid, Path)), request_body = AccountUpdate, responses((status = 200, body = Value)))]
pub async fn update_account(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<AccountUpdate>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let row = sqlx::query("SELECT name,config,imap_secret_id,smtp_secret_id,revision,enabled FROM email_accounts WHERE owner_id=$1 AND id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    if row.get::<i64, _>("revision") != input.expected_revision {
        return Err(Error::Conflict("mail account changed; refresh and retry".into()).into());
    }
    let name: String = match &input.name {
        Some(name) => name.clone(),
        None => row.get("name"),
    };
    account_name(&name)?;
    let config = match &input.config {
        Some(value) => parse_config(value)?,
        None => serde_json::from_value(row.get::<Value, _>("config")).map_err(Error::from)?,
    };
    let enabled = input.enabled.unwrap_or_else(|| row.get::<bool, _>("enabled"));
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let old_imap: Uuid = row.get("imap_secret_id");
    let old_smtp: Uuid = row.get("smtp_secret_id");
    // New secrets are stored before the swap; omitted credentials reuse the
    // existing secret only after proving it still decrypts.
    let imap_id = match &input.imap_credential {
        Some(value) => store.put(&auth.scope, "email-imap-credential", &credential_bytes(value)?).await?,
        None => {
            store.get(&auth.scope, old_imap).await.map_err(|_| Error::Conflict("mail credential missing; supply a new credential".to_owned()))?;
            old_imap
        }
    };
    let smtp_id = match &input.smtp_credential {
        Some(value) => store.put(&auth.scope, "email-smtp-credential", &credential_bytes(value)?).await?,
        None => {
            store.get(&auth.scope, old_smtp).await.map_err(|_| Error::Conflict("mail credential missing; supply a new credential".to_owned()))?;
            old_smtp
        }
    };
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let changed = sqlx::query("UPDATE email_accounts SET name=$3,config=$4,imap_secret_id=$5,smtp_secret_id=$6,enabled=$7,revision=revision+1 WHERE owner_id=$1 AND id=$2 AND revision=$8")
        .bind(auth.scope.owner_id)
        .bind(id)
        .bind(&name)
        .bind(json!(config))
        .bind(imap_id)
        .bind(smtp_id)
        .bind(enabled)
        .bind(input.expected_revision)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if changed != 1 {
        return Err(Error::Conflict("mail account changed; refresh and retry".into()).into());
    }
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(&mut tx, &auth.scope, Uuid::new_v4(), None, None, "EMAIL_ACCOUNT_UPDATED", "owner updated mail account", json!({"account_id": id, "name": name, "credential_rotated": imap_id != old_imap || smtp_id != old_smtp})).await?;
    tx.commit().await?;
    if imap_id != old_imap {
        store.revoke(&auth.scope, old_imap).await?;
    }
    if smtp_id != old_smtp {
        store.revoke(&auth.scope, old_smtp).await?;
    }
    Ok(Json(account_view(&state, auth.scope.owner_id, id).await?))
}

#[utoipa::path(delete, path = "/api/v1/email/accounts/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn remove_account(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT imap_secret_id,smtp_secret_id FROM email_accounts WHERE owner_id=$1 AND id=$2 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let imap_id: Uuid = row.get("imap_secret_id");
    let smtp_id: Uuid = row.get("smtp_secret_id");
    // Disable first so polling and in-flight sync batches fail closed even if
    // a revoke below fails; the revision bump invalidates live sync leases.
    sqlx::query("UPDATE email_accounts SET enabled=false,revision=revision+1 WHERE owner_id=$1 AND id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(&mut tx, &auth.scope, Uuid::new_v4(), None, None, "EMAIL_ACCOUNT_REMOVED", "owner removed mail account", json!({"account_id": id})).await?;
    tx.commit().await?;
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    store.revoke(&auth.scope, imap_id).await?;
    store.revoke(&auth.scope, smtp_id).await?;
    Ok(Json(json!({"removed": true, "ingestion_stopped": true})))
}

#[utoipa::path(post, path = "/api/v1/email/accounts/{id}/test", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn test_account(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mail = service(&state).await?;
    Ok(Json(mail.test(&auth.scope, id).await?))
}

#[utoipa::path(post, path = "/api/v1/email/accounts/{id}/sync", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn sync_account(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mail = service(&state).await?;
    Ok(Json(mail.sync(&auth.scope, id).await?))
}

#[utoipa::path(get, path = "/api/v1/email/messages", responses((status = 200, body = Value)))]
pub async fn list_messages(State(state): State<ApiState>, headers: HeaderMap, Query(query): Query<MessageQuery>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'account_id',account_id,'mailbox',mailbox,'message_id',message_id,'thread_references',thread_references,'metadata',metadata,'authentication',authentication,'privacy_class',privacy_class,'trust_level',trust_level,'received_at',received_at,'attachment_count',jsonb_array_length(attachments)) \
         FROM email_messages WHERE owner_id=$1 AND ($2::uuid IS NULL OR account_id=$2) \
         AND ($3::uuid IS NULL OR (received_at,id) < (SELECT received_at,id FROM email_messages WHERE owner_id=$1 AND id=$3)) \
         ORDER BY received_at DESC,id DESC LIMIT $4",
    )
    .bind(auth.scope.owner_id)
    .bind(query.account_id)
    .bind(query.cursor)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let next_cursor = if rows.len() as i64 > limit { rows[(limit - 1) as usize].get("id").cloned() } else { None };
    let items: Vec<Value> = rows.into_iter().take(limit as usize).collect();
    Ok(Json(json!({"items": items, "next_cursor": next_cursor})))
}

#[utoipa::path(get, path = "/api/v1/email/messages/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn message_detail(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    // body_text holds only text/plain MIME parts, so there is no active HTML
    // and no remote image to render; attachments are returned as refs (name,
    // MIME, digest) without bytes, which the client must fetch explicitly.
    let record: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'account_id',account_id,'mailbox',mailbox,'message_id',message_id,'thread_references',thread_references,'metadata',metadata,'body_text',body_text,\
         'attachments',COALESCE((SELECT jsonb_agg(jsonb_build_object('name',a->'name','mime',a->'mime','sha256',a->'sha256')) FROM jsonb_array_elements(attachments) AS a),'[]'::jsonb),\
         'authentication',authentication,'privacy_class',privacy_class,'trust_level',trust_level,'received_at',received_at) \
         FROM email_messages WHERE owner_id=$1 AND id=$2",
    )
    .bind(auth.scope.owner_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(Json(record.ok_or(Error::NotFound)?))
}

#[utoipa::path(get, path = "/api/v1/email/drafts", responses((status = 200, body = Value)))]
pub async fn list_drafts(State(state): State<ApiState>, headers: HeaderMap, Query(query): Query<DraftQuery>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    if let Some(status) = &query.state {
        if !matches!(status.as_str(), "DRAFT" | "SUBMITTED" | "SENT" | "FAILED" | "OUTCOME_UNKNOWN") {
            return Err(Error::Validation("invalid draft state".into()).into());
        }
    }
    let list = format!("{} WHERE owner_id=$1 AND ($2::uuid IS NULL OR account_id=$2) AND ($3::text IS NULL OR state=$3) ORDER BY updated_at DESC,id DESC LIMIT 50", DRAFT_VIEW);
    let items: Vec<Value> = sqlx::query_scalar(&list)
        .bind(auth.scope.owner_id)
        .bind(query.account_id)
        .bind(query.state)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

#[utoipa::path(post, path = "/api/v1/email/drafts", request_body = DraftCreate, responses((status = 200, body = Value)))]
pub async fn create_draft(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<DraftCreate>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let content = parse_content(&input.content)?;
    let mail = service(&state).await?;
    Ok(Json(mail.store_draft(&auth.scope, input.account_id, content).await?))
}

async fn draft_view(state: &ApiState, owner: Uuid, id: Uuid) -> Result<Value, ApiError> {
    let detail = format!("{DRAFT_VIEW} WHERE owner_id=$1 AND id=$2");
    let mut record: Value = sqlx::query_scalar(&detail)
        .bind(owner)
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    let versions: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('version',version,'content_digest',content_digest,'created_at',created_at) \
         FROM email_draft_versions WHERE owner_id=$1 AND draft_id=$2 ORDER BY version DESC",
    )
    .bind(owner)
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    if let Some(object) = record.as_object_mut() {
        object.insert("versions".into(), json!(versions));
    }
    Ok(record)
}

#[utoipa::path(get, path = "/api/v1/email/drafts/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn draft_detail(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    Ok(Json(draft_view(&state, auth.scope.owner_id, id).await?))
}

#[utoipa::path(patch, path = "/api/v1/email/drafts/{id}", params(("id" = Uuid, Path)), request_body = DraftUpdate, responses((status = 200, body = Value)))]
pub async fn update_draft(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<DraftUpdate>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let content = parse_content(&input.content)?;
    let mail = service(&state).await?;
    Ok(Json(mail.edit_draft(&auth.scope, id, input.expected_version, content).await?))
}

#[utoipa::path(post, path = "/api/v1/email/drafts/{id}/send", params(("id" = Uuid, Path)), request_body = SendRequest, responses((status = 200, body = Value)))]
pub async fn send_draft(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<SendRequest>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    if input.content_digest.len() != 64 {
        return Err(Error::Validation("content digest required for send".into()).into());
    }
    let mail = service(&state).await?;
    // Resolve the immutable draft version into exact, digest-bound arguments;
    // any version drift or prior submission conflicts here, before dispatch.
    let probe = json!({"draft_id": id, "expected_version": input.expected_version});
    let (materialized, scope_revisions, input_digests) = mail.materialize_send(&auth.scope, &probe).await?;
    if materialized.get("content_digest") != Some(&json!(input.content_digest)) {
        return Err(Error::Conflict("draft version changed or already submitted".into()).into());
    }
    let account: Uuid = serde_json::from_value(materialized.get("account_id").cloned().unwrap_or(Value::Null)).map_err(|_| Error::Conflict("draft version changed or already submitted".into()))?;
    // Lock authorization_epochs first, then re-verify every bound revision is
    // still live before constructing the authorized dispatch envelope.
    let mut tx = state.pool.begin().await?;
    let epoch: i64 = sqlx::query_scalar("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(auth.scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT d.version,d.state,d.content_digest,d.account_id,a.revision AS account_revision FROM email_drafts d JOIN email_accounts a ON a.owner_id=d.owner_id AND a.id=d.account_id WHERE d.owner_id=$1 AND d.id=$2")
        .bind(auth.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let live = row.get::<i64, _>("version") == input.expected_version
        && row.get::<String, _>("state") == "DRAFT"
        && row.get::<String, _>("content_digest") == input.content_digest
        && row.get::<Uuid, _>("account_id") == account
        && scope_revisions.get(&format!("email_account:{account}")) == Some(&row.get::<i64, _>("account_revision"))
        && scope_revisions.get(&format!("email_draft:{id}")) == Some(&input.expected_version);
    if !live {
        return Err(Error::Conflict("draft version changed or already submitted".into()).into());
    }
    let policy_revision: i64 = sqlx::query_scalar("SELECT revision FROM policies WHERE owner_id=$1")
        .bind(auth.scope.owner_id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(1);
    let correlation = Uuid::new_v4();
    tx.commit().await?;
    // Owner-originated dispatch outside any agent task: the authenticated owner
    // session plus CSRF plus the exact digest match above is the approval.
    // Agent-initiated sends additionally pass through the gateway approval
    // queue before reaching EmailProvider::execute.
    let authorization_id = Uuid::new_v4();
    let snapshot = ActionSnapshot {
        action_id: Uuid::new_v4(),
        owner_id: auth.scope.owner_id,
        principal_id: auth.scope.principal_id,
        agent_id: None,
        task_id: Uuid::new_v4(),
        tool_name: "email.send".into(),
        tool_version: "1".into(),
        arguments: materialized,
        input_artifact_digests: input_digests,
        scope_revisions,
        policy_revision,
        authorization_epoch: epoch,
        requires_sandbox: false,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
    };
    let action = AuthorizedAction::from_submission(snapshot, authorization_id, 0);
    // Exactly one dispatch attempt: execute() marks SUBMITTED before the SMTP
    // bytes can escape, records SENT/FAILED/OUTCOME_UNKNOWN itself, and its
    // conditional update makes replays conflict instead of resending.
    match mail.execute(&auth.scope, &action).await {
        Ok(output) => {
            let mut tx = state.pool.begin().await?;
            orbit_audit::append(&mut tx, &auth.scope, correlation, None, None, "EMAIL_DRAFT_SENT", "owner sent approved draft", json!({"draft_id": id, "expected_version": input.expected_version, "account_id": account, "authorization_id": authorization_id, "message_id": output.get("message_id")})).await?;
            tx.commit().await?;
            Ok(Json(output))
        }
        Err(Error::OutcomeUnknown) => {
            let mut tx = state.pool.begin().await?;
            orbit_audit::append(&mut tx, &auth.scope, correlation, None, None, "EMAIL_SEND_UNCERTAIN", "SMTP outcome unknown; never auto-resend", json!({"draft_id": id, "expected_version": input.expected_version, "account_id": account, "authorization_id": authorization_id})).await?;
            tx.commit().await?;
            Err(Error::OutcomeUnknown.into())
        }
        Err(other) => Err(other.into()),
    }
}

#[utoipa::path(get, path = "/api/v1/email/checkpoints", responses((status = 200, body = Value)))]
pub async fn list_checkpoints(State(state): State<ApiState>, headers: HeaderMap, Query(query): Query<CheckpointQuery>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let items: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('account_id',account_id,'mailbox',mailbox,'uidvalidity',uidvalidity,'last_uid',last_uid,'rescan_offset',rescan_offset) \
         FROM email_checkpoints WHERE owner_id=$1 AND ($2::uuid IS NULL OR account_id=$2) ORDER BY account_id,mailbox",
    )
    .bind(auth.scope.owner_id)
    .bind(query.account_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(json!({"items": items, "next_cursor": null})))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_accounts, create_account, account_detail, update_account, remove_account,
        test_account, sync_account, list_messages, message_detail,
        list_drafts, create_draft, draft_detail, update_draft, send_draft,
        list_checkpoints
    ),
    components(schemas(AccountCreate, AccountUpdate, DraftCreate, DraftUpdate, SendRequest, MessageQuery, DraftQuery, CheckpointQuery))
)]
pub struct EmailApi;
