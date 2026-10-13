//! Opt-in personal desktop observation consent (step 8, server half).
//!
//! Default OFF: no consent row means no capture, and a consent row alone
//! never starts capture. Capture additionally requires the owner's on-machine
//! portal pick (XDG ScreenCast window chooser); the server never enables
//! capture remotely. Server-to-node directives (sent by the node transport,
//! which watches this table) only ever narrow, pause, or revoke.
//!
//! Retention: `retention_hours` defaults to 24 and `0` means keep
//! indefinitely (no per-row expiry). Observation writers set
//! `source_observations.expires_at` via [`desktop_observation_expiry`]; the
//! housekeeping sweep ([`sweep_expired_desktop_observations`]) deletes
//! expired `desktop` rows. OCR text therefore lives at most 24h unless the
//! owner explicitly keeps it.
//!
//! Mobile (`MOBILE_USER`) principals inspect and pause only: reads and the
//! pause endpoints stay open, while grant / resume / narrow / revoke /
//! delete return 403.
//!
//! No silent fallback: granting requires the node to report
//! `capabilities.desktop_observation.supported == true` (portal capture).
//! Anything else fails with `DESKTOP_CAPTURE_UNAVAILABLE`, never X11.

use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{delete, get, post, put},
};
use chrono::{DateTime, Duration, Utc};
use orbit_core::{Error, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Retention default (hours) for a new consent: OCR 24h default expiry.
const DEFAULT_RETENTION_HOURS: i32 = 24;
/// Retention ceiling: one year. `0` means keep indefinitely.
const MAX_RETENTION_HOURS: i32 = 8760;
const MAX_SOURCE_APP_LEN: usize = 128;

/// Expiry for one desktop observation row: `observed_at + retention`, or
/// `None` (no expiry) when the owner chose explicit keep (`retention_hours
/// == 0`). Writers call this; readers/the sweep honor `expires_at`.
pub fn desktop_observation_expiry(
    retention_hours: i32,
    observed_at: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if retention_hours <= 0 {
        None
    } else {
        observed_at.checked_add_signed(Duration::hours(retention_hours as i64))
    }
}

/// Housekeeping: delete expired `desktop` observation rows. Returns the
/// number removed. Outbox rows follow via `ON DELETE CASCADE`.
pub async fn sweep_expired_desktop_observations(pool: &PgPool) -> Result<u64> {
    let done =
        sqlx::query("DELETE FROM source_observations WHERE source_type='desktop' AND expires_at IS NOT NULL AND expires_at < now()")
            .execute(pool)
            .await?;
    Ok(done.rows_affected())
}

async fn principal_type(pool: &PgPool, owner: Uuid, principal: Uuid) -> Result<String> {
    let found: Option<String> =
        sqlx::query_scalar("SELECT principal_type FROM principals WHERE owner_id=$1 AND id=$2")
            .bind(owner)
            .bind(principal)
            .fetch_optional(pool)
            .await?;
    Ok(found.unwrap_or_default())
}

/// Mobile inspects + pauses only: grant / resume / narrow / revoke / delete
/// are owner-desktop actions.
async fn deny_mobile(pool: &PgPool, owner: Uuid, principal: Uuid) -> Result<()> {
    if principal_type(pool, owner, principal).await? == "MOBILE_USER" {
        return Err(Error::Forbidden);
    }
    Ok(())
}

async fn node_row(
    pool: &PgPool,
    owner: Uuid,
    node: Uuid,
) -> Result<sqlx::postgres::PgRow> {
    sqlx::query("SELECT * FROM computer_nodes WHERE owner_id=$1 AND id=$2")
        .bind(owner)
        .bind(node)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::NotFound)
}

/// Portal support is node-reported and read verbatim: absent means
/// unsupported (fail closed, never an X11 fallback).
fn desktop_supported(caps: &Value) -> bool {
    caps.get("desktop_observation")
        .and_then(|d| d.get("supported"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Node-reported capture state, passed through verbatim (`OFF | RUNNING |
/// PAUSED | UNAVAILABLE | PERMISSION_DENIED`, or null when unreported).
fn node_desktop_state(caps: &Value) -> Value {
    caps.get("desktop_observation")
        .and_then(|d| d.get("state"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn consent_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    expires_at.is_some_and(|e| e <= Utc::now())
}

fn consent_view(
    row: &sqlx::postgres::PgRow,
    node_name: &str,
    caps: &Value,
    revoked: bool,
) -> Value {
    let expires_at: Option<DateTime<Utc>> = row.get("expires_at");
    json!({
        "id": row.get::<Uuid, _>("id"),
        "node_id": row.get::<Uuid, _>("node_id"),
        "node_name": node_name,
        "source_app": row.get::<String, _>("source_app"),
        "mode": row.get::<String, _>("mode"),
        "revision": row.get::<i64, _>("revision"),
        "retention_hours": row.get::<i32, _>("retention_hours"),
        "expires_at": expires_at,
        "consent_expired": consent_expired(expires_at),
        "node_revoked": revoked,
        "node_state": node_desktop_state(caps),
        "created_at": row.get::<DateTime<Utc>, _>("created_at"),
        "updated_at": row.get::<DateTime<Utc>, _>("updated_at"),
    })
}

fn clean_source_app(raw: &str) -> Result<String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > MAX_SOURCE_APP_LEN {
        return Err(Error::Validation("source_app required, maximum 128 characters".into()));
    }
    Ok(v.to_owned())
}

fn check_retention(retention_hours: i32) -> Result<()> {
    if !(0..=MAX_RETENTION_HOURS).contains(&retention_hours) {
        return Err(Error::Validation(
            "retention_hours must be 0 (keep indefinitely) through 8760".into(),
        ));
    }
    Ok(())
}

fn check_expiry(expires_at: Option<DateTime<Utc>>) -> Result<()> {
    if expires_at.is_some_and(|e| e <= Utc::now()) {
        return Err(Error::Validation("expires_at must be in the future".into()));
    }
    Ok(())
}

async fn bump_node_revision(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner: Uuid,
    node: Uuid,
) -> Result<()> {
    sqlx::query("UPDATE computer_nodes SET revision=revision+1 WHERE owner_id=$1 AND id=$2")
        .bind(owner)
        .bind(node)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

// ------------------------------------------------------------------- status

/// Persistent-indicator read: every consent with its node name, verbatim
/// node capture state, and computed expiry. `observing` is true while any
/// non-revoked, non-expired `GRANTED` consent stands on a live node.
#[utoipa::path(get, path = "/api/v1/observation/status", responses((status = 200, body = Value)))]
pub async fn status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query(
        "SELECT c.*, n.display_name AS node_name, n.capabilities AS caps, n.revoked_at AS node_revoked_at FROM desktop_observation_consents c JOIN computer_nodes n ON n.owner_id=c.owner_id AND n.id=c.node_id WHERE c.owner_id=$1 ORDER BY c.updated_at DESC,c.id DESC LIMIT 100",
    )
    .bind(a.scope.owner_id)
    .fetch_all(&state.pool)
    .await?;
    let mut consents = Vec::with_capacity(rows.len());
    let mut observing = false;
    for row in &rows {
        let caps: Value = row.try_get("caps").unwrap_or(Value::Null);
        let revoked: bool = row
            .try_get::<Option<DateTime<Utc>>, _>("node_revoked_at")
            .unwrap_or(None)
            .is_some();
        let view = consent_view(
            row,
            &row.try_get::<String, _>("node_name").unwrap_or_else(|_| "Computer".into()),
            &caps,
            revoked,
        );
        if view["mode"] == json!("GRANTED")
            && view["consent_expired"] == json!(false)
            && !revoked
        {
            observing = true;
        }
        consents.push(view);
    }
    Ok(Json(json!({ "observing": observing, "consents": consents })))
}

// ------------------------------------------------------------------ consents

#[utoipa::path(get, path = "/api/v1/computers/{id}/observation/consents", responses((status = 200, body = Value)))]
pub async fn list_consents(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let node = node_row(&state.pool, a.scope.owner_id, id).await?;
    let caps: Value = node.try_get("capabilities").unwrap_or(Value::Null);
    let revoked = node.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some();
    let name: String = node.try_get("display_name").unwrap_or_else(|_| "Computer".into());
    let rows = sqlx::query("SELECT * FROM desktop_observation_consents WHERE owner_id=$1 AND node_id=$2 ORDER BY updated_at DESC,id DESC LIMIT 100")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_all(&state.pool)
        .await?;
    let items: Vec<Value> = rows.iter().map(|r| consent_view(r, &name, &caps, revoked)).collect();
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub source_app: String,
    #[serde(default = "grant_retention_default")]
    pub retention_hours: i32,
    pub expires_at: Option<DateTime<Utc>>,
}
fn grant_retention_default() -> i32 {
    DEFAULT_RETENTION_HOURS
}

/// Owner opt-in gate for one node's window/app. Fails closed with
/// `DESKTOP_CAPTURE_UNAVAILABLE` when the node reports no portal support.
/// Granting never starts capture by itself: the node additionally needs the
/// owner's on-machine portal pick.
#[utoipa::path(post, path = "/api/v1/computers/{id}/observation/consents", request_body = GrantRequest, responses((status = 200, body = Value)))]
pub async fn grant_consent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<GrantRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    deny_mobile(&state.pool, a.scope.owner_id, a.scope.principal_id).await?;
    let source_app = clean_source_app(&input.source_app)?;
    check_retention(input.retention_hours)?;
    check_expiry(input.expires_at)?;
    let node = node_row(&state.pool, a.scope.owner_id, id).await?;
    if node.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some() {
        return Err(Error::Conflict("computer node is revoked".into()).into());
    }
    let caps: Value = node.try_get("capabilities").unwrap_or(Value::Null);
    if !desktop_supported(&caps) {
        return Err(Error::Unavailable(
            "DESKTOP_CAPTURE_UNAVAILABLE: node does not report portal screen capture support".into(),
        )
        .into());
    }
    let name: String = node.try_get("display_name").unwrap_or_else(|_| "Computer".into());
    let clash: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM desktop_observation_consents WHERE owner_id=$1 AND node_id=$2 AND source_app=$3 AND mode IN ('GRANTED','PAUSED')",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(&source_app)
    .fetch_optional(&state.pool)
    .await?;
    if clash.is_some() {
        return Err(Error::Conflict("observation consent already stands for this source".into()).into());
    }
    let consent = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("INSERT INTO desktop_observation_consents(id,owner_id,node_id,source_app,mode,retention_hours,expires_at) VALUES($1,$2,$3,$4,'GRANTED',$5,$6) RETURNING *")
        .bind(consent)
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(&source_app)
        .bind(input.retention_hours)
        .bind(input.expires_at)
        .fetch_one(&mut *tx)
        .await?;
    bump_node_revision(&mut tx, a.scope.owner_id, id).await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "DESKTOP_OBSERVATION_GRANTED",
        "owner granted desktop observation consent",
        json!({ "node_id": id, "consent_id": consent, "source_app": source_app, "retention_hours": input.retention_hours }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(consent_view(&row, &name, &caps, false)))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionRequest {
    pub expected_revision: i64,
}

async fn transition(
    state: &ApiState,
    owner: Uuid,
    principal: Uuid,
    node: Uuid,
    consent: Uuid,
    input_revision: i64,
    from: &[&str],
    to: &str,
    op: &str,
    reason: &str,
    mobile_ok: bool,
) -> Result<Value> {
    if !mobile_ok {
        deny_mobile(&state.pool, owner, principal).await?;
    }
    let node_row = node_row(&state.pool, owner, node).await?;
    let caps: Value = node_row.try_get("capabilities").unwrap_or(Value::Null);
    let revoked = node_row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some();
    let name: String = node_row.try_get("display_name").unwrap_or_else(|_| "Computer".into());
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM desktop_observation_consents WHERE owner_id=$1 AND node_id=$2 AND id=$3 FOR UPDATE")
        .bind(owner)
        .bind(node)
        .bind(consent)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    let mode: String = row.get("mode");
    if !from.contains(&mode.as_str()) {
        return Err(Error::Conflict(format!("consent is {mode}, cannot {to}")).into());
    }
    if row.get::<i64, _>("revision") != input_revision {
        return Err(Error::Conflict("consent revision changed".into()).into());
    }
    if to == "GRANTED" && consent_expired(row.get("expires_at")) {
        return Err(Error::Conflict("consent expired; grant again".into()).into());
    }
    let updated = sqlx::query("UPDATE desktop_observation_consents SET mode=$4,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND node_id=$2 AND id=$3 RETURNING *")
        .bind(owner)
        .bind(node)
        .bind(consent)
        .bind(to)
        .fetch_one(&mut *tx)
        .await?;
    bump_node_revision(&mut tx, owner, node).await?;
    let audit_scope = orbit_core::OwnerScope { owner_id: owner, principal_id: principal };
    orbit_audit::append(
        &mut tx,
        &audit_scope,
        Uuid::new_v4(),
        None,
        None,
        op,
        reason,
        json!({ "node_id": node, "consent_id": consent, "mode": to }),
    )
    .await?;
    tx.commit().await?;
    Ok(consent_view(&updated, &name, &caps, revoked))
}

/// Pause capture for one consent. Mobile-allowed: this is the kill path the
/// persistent indicator and phones use.
#[utoipa::path(post, path = "/api/v1/computers/{id}/observation/consents/{consent_id}/pause", request_body = RevisionRequest, responses((status = 200, body = Value)))]
pub async fn pause_consent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((id, consent)): Path<(Uuid, Uuid)>,
    Json(input): Json<RevisionRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    // Idempotent pause: an already-paused consent reads back unchanged.
    let current: Option<String> = sqlx::query_scalar(
        "SELECT mode FROM desktop_observation_consents WHERE owner_id=$1 AND node_id=$2 AND id=$3",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(consent)
    .fetch_optional(&state.pool)
    .await?;
    if current.as_deref() == Some("PAUSED") {
        return list_one(&state, a.scope.owner_id, id, consent).await;
    }
    Ok(Json(
        transition(&state, a.scope.owner_id, a.scope.principal_id, id, consent, input.expected_revision, &["GRANTED"], "PAUSED", "DESKTOP_OBSERVATION_PAUSED", "owner paused desktop observation", true).await?,
    ))
}

async fn list_one(state: &ApiState, owner: Uuid, node: Uuid, consent: Uuid) -> Result<Json<Value>, ApiError> {
    let node_row = node_row(&state.pool, owner, node).await?;
    let caps: Value = node_row.try_get("capabilities").unwrap_or(Value::Null);
    let revoked = node_row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some();
    let name: String = node_row.try_get("display_name").unwrap_or_else(|_| "Computer".into());
    let row = sqlx::query("SELECT * FROM desktop_observation_consents WHERE owner_id=$1 AND node_id=$2 AND id=$3")
        .bind(owner)
        .bind(node)
        .bind(consent)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(consent_view(&row, &name, &caps, revoked)))
}

/// Resume a paused consent. Owner-desktop only: resuming re-arms capture.
#[utoipa::path(post, path = "/api/v1/computers/{id}/observation/consents/{consent_id}/resume", request_body = RevisionRequest, responses((status = 200, body = Value)))]
pub async fn resume_consent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((id, consent)): Path<(Uuid, Uuid)>,
    Json(input): Json<RevisionRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    Ok(Json(
        transition(&state, a.scope.owner_id, a.scope.principal_id, id, consent, input.expected_revision, &["PAUSED"], "GRANTED", "DESKTOP_OBSERVATION_RESUMED", "owner resumed desktop observation", false).await?,
    ))
}

/// Revoke a consent. Terminal: the row stays as a tombstone, capture for
/// the source stops, and a fresh grant starts a new row.
#[utoipa::path(post, path = "/api/v1/computers/{id}/observation/consents/{consent_id}/revoke", request_body = RevisionRequest, responses((status = 200, body = Value)))]
pub async fn revoke_consent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((id, consent)): Path<(Uuid, Uuid)>,
    Json(input): Json<RevisionRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    Ok(Json(
        transition(&state, a.scope.owner_id, a.scope.principal_id, id, consent, input.expected_revision, &["GRANTED", "PAUSED"], "REVOKED", "DESKTOP_OBSERVATION_REVOKED", "owner revoked desktop observation consent", false).await?,
    ))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NarrowRequest {
    pub source_app: Option<String>,
    pub retention_hours: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub clear_expires_at: bool,
    pub expected_revision: i64,
}

/// Narrow (or otherwise adjust) a live consent: source, retention, expiry.
/// Revoked consents are terminal and refuse the update.
#[utoipa::path(put, path = "/api/v1/computers/{id}/observation/consents/{consent_id}", request_body = NarrowRequest, responses((status = 200, body = Value)))]
pub async fn narrow_consent(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((id, consent)): Path<(Uuid, Uuid)>,
    Json(input): Json<NarrowRequest>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    deny_mobile(&state.pool, a.scope.owner_id, a.scope.principal_id).await?;
    let source_app = input.source_app.as_deref().map(clean_source_app).transpose()?;
    if let Some(r) = input.retention_hours {
        check_retention(r)?;
    }
    if let Some(e) = input.expires_at {
        check_expiry(Some(e))?;
    }
    if source_app.is_none() && input.retention_hours.is_none() && input.expires_at.is_none() && !input.clear_expires_at {
        return Err(Error::Validation("nothing to update".into()).into());
    }
    let node_row = node_row(&state.pool, a.scope.owner_id, id).await?;
    let caps: Value = node_row.try_get("capabilities").unwrap_or(Value::Null);
    let revoked = node_row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some();
    let name: String = node_row.try_get("display_name").unwrap_or_else(|_| "Computer".into());
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query("SELECT * FROM desktop_observation_consents WHERE owner_id=$1 AND node_id=$2 AND id=$3 FOR UPDATE")
        .bind(a.scope.owner_id)
        .bind(id)
        .bind(consent)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound)?;
    if row.get::<String, _>("mode") == "REVOKED" {
        return Err(Error::Conflict("consent is revoked".into()).into());
    }
    if row.get::<i64, _>("revision") != input.expected_revision {
        return Err(Error::Conflict("consent revision changed".into()).into());
    }
    let updated = sqlx::query(
        "UPDATE desktop_observation_consents SET source_app=COALESCE($4,source_app),retention_hours=COALESCE($5,retention_hours),expires_at=CASE WHEN $6 THEN NULL WHEN $7 IS NOT NULL THEN $7 ELSE expires_at END,revision=revision+1,updated_at=now() WHERE owner_id=$1 AND node_id=$2 AND id=$3 RETURNING *",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .bind(consent)
    .bind(source_app)
    .bind(input.retention_hours)
    .bind(input.clear_expires_at)
    .bind(input.expires_at)
    .fetch_one(&mut *tx)
    .await?;
    bump_node_revision(&mut tx, a.scope.owner_id, id).await?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "DESKTOP_OBSERVATION_UPDATED",
        "owner updated desktop observation consent",
        json!({ "node_id": id, "consent_id": consent }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(consent_view(&updated, &name, &caps, revoked)))
}

/// Node-level pause: pause every granted consent on the node at once. This
/// is the one-tap path behind the persistent indicator. Mobile-allowed.
#[utoipa::path(post, path = "/api/v1/computers/{id}/observation/pause", responses((status = 200, body = Value)))]
pub async fn pause_node(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    node_row(&state.pool, a.scope.owner_id, id).await?;
    let mut tx = state.pool.begin().await?;
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE desktop_observation_consents SET mode='PAUSED',revision=revision+1,updated_at=now() WHERE owner_id=$1 AND node_id=$2 AND mode='GRANTED' RETURNING id",
    )
    .bind(a.scope.owner_id)
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    if !ids.is_empty() {
        bump_node_revision(&mut tx, a.scope.owner_id, id).await?;
        orbit_audit::append(
            &mut tx,
            &a.scope,
            Uuid::new_v4(),
            None,
            None,
            "DESKTOP_OBSERVATION_PAUSED",
            "owner paused desktop observation for a node",
            json!({ "node_id": id, "consent_ids": ids }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "node_id": id, "paused": ids })))
}

// ------------------------------------------------------------- inspect/delete

#[derive(Deserialize)]
pub struct ObservationFilter {
    pub cursor: Option<i64>,
    pub limit: Option<i64>,
    pub source_type: Option<String>,
    pub source_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// Inspect retained observations by source and time. Owner-scoped, newest
/// first; each row carries its `expires_at` so the UI can show the 24h
/// default (or explicit keep) honestly.
#[utoipa::path(get, path = "/api/v1/observations", responses((status = 200, body = Value)))]
pub async fn list_observations(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<ObservationFilter>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = page.limit.unwrap_or(30).clamp(1, 100);
    let offset = page.cursor.unwrap_or(0);
    if offset < 0 {
        return Err(Error::Validation("invalid cursor".into()).into());
    }
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "SELECT to_jsonb(t)-'owner_id' AS record FROM source_observations t WHERE owner_id=",
    );
    qb.push_bind(a.scope.owner_id);
    if let Some(t) = page.source_type.as_deref().filter(|s| !s.is_empty()) {
        qb.push(" AND source_type=");
        qb.push_bind(t);
    }
    if let Some(s) = page.source_id.as_deref().filter(|s| !s.is_empty()) {
        qb.push(" AND source_id=");
        qb.push_bind(s);
    }
    if let Some(since) = page.since {
        qb.push(" AND observed_at>=");
        qb.push_bind(since);
    }
    if let Some(until) = page.until {
        qb.push(" AND observed_at<=");
        qb.push_bind(until);
    }
    qb.push(" ORDER BY observed_at DESC,id DESC LIMIT ");
    qb.push_bind(limit + 1);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    let mut items: Vec<Value> = qb.build_query_scalar().fetch_all(&state.pool).await?;
    let next = if items.len() > limit as usize {
        items.pop();
        Some(offset + limit)
    } else {
        None
    };
    Ok(Json(json!({ "items": items, "next_cursor": next })))
}

#[derive(Deserialize)]
pub struct ObservationBulkDelete {
    pub source_type: Option<String>,
    pub source_id: Option<String>,
    pub before: Option<DateTime<Utc>>,
}

/// Delete retained observations by source and/or time (e.g. everything from
/// one node, or everything observed before a date). At least one filter is
/// required; an unfiltered wipe is refused. Owner-desktop only.
#[utoipa::path(delete, path = "/api/v1/observations", responses((status = 200, body = Value)))]
pub async fn delete_observations_bulk(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(filter): Query<ObservationBulkDelete>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    deny_mobile(&state.pool, a.scope.owner_id, a.scope.principal_id).await?;
    let has_filter = filter
        .source_type
        .as_deref()
        .is_some_and(|s| !s.is_empty())
        || filter.source_id.as_deref().is_some_and(|s| !s.is_empty())
        || filter.before.is_some();
    if !has_filter {
        return Err(Error::Validation("at least one of source_type, source_id, before is required".into()).into());
    }
    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> =
        sqlx::QueryBuilder::new("DELETE FROM source_observations WHERE owner_id=");
    qb.push_bind(a.scope.owner_id);
    if let Some(t) = filter.source_type.as_deref().filter(|s| !s.is_empty()) {
        qb.push(" AND source_type=");
        qb.push_bind(t);
    }
    if let Some(s) = filter.source_id.as_deref().filter(|s| !s.is_empty()) {
        qb.push(" AND source_id=");
        qb.push_bind(s);
    }
    if let Some(before) = filter.before {
        qb.push(" AND observed_at<");
        qb.push_bind(before);
    }
    let mut tx = state.pool.begin().await?;
    let done = qb.build().execute(&mut *tx).await?;
    let deleted = done.rows_affected();
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "OBSERVATIONS_DELETED",
        "owner deleted retained observations",
        json!({ "deleted": deleted, "source_type": filter.source_type, "source_id": filter.source_id, "before": filter.before }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "deleted": deleted })))
}

/// Delete one retained observation. Owner-desktop only.
#[utoipa::path(delete, path = "/api/v1/observations/{id}", responses((status = 200, body = Value)))]
pub async fn delete_observation(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    deny_mobile(&state.pool, a.scope.owner_id, a.scope.principal_id).await?;
    let mut tx = state.pool.begin().await?;
    let gone: Option<Uuid> = sqlx::query_scalar("DELETE FROM source_observations WHERE owner_id=$1 AND id=$2 RETURNING id")
        .bind(a.scope.owner_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    gone.ok_or(Error::NotFound)?;
    orbit_audit::append(
        &mut tx,
        &a.scope,
        Uuid::new_v4(),
        None,
        None,
        "OBSERVATIONS_DELETED",
        "owner deleted a retained observation",
        json!({ "observation_id": id }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "id": id, "deleted": true })))
}

// ------------------------------------------------------------------- router

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/observation/status", get(status))
        .route(
            "/api/v1/computers/{id}/observation/consents",
            get(list_consents).post(grant_consent),
        )
        .route("/api/v1/computers/{id}/observation/pause", post(pause_node))
        .route(
            "/api/v1/computers/{id}/observation/consents/{consent_id}/pause",
            post(pause_consent),
        )
        .route(
            "/api/v1/computers/{id}/observation/consents/{consent_id}/resume",
            post(resume_consent),
        )
        .route(
            "/api/v1/computers/{id}/observation/consents/{consent_id}/revoke",
            post(revoke_consent),
        )
        .route(
            "/api/v1/computers/{id}/observation/consents/{consent_id}",
            put(narrow_consent),
        )
        .route(
            "/api/v1/observations",
            get(list_observations).delete(delete_observations_bulk),
        )
        .route("/api/v1/observations/{id}", delete(delete_observation))
}
