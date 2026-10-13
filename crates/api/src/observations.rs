//! Bounded observation stream (step 7): one versioned event per source mutation.
//!
//! Every sync path funnels through [`record_observation`]: cache row +
//! resume cursor + observation row + foundation outbox in ONE transaction.
//! The cursor advances only with a committed observation — on crash/restart
//! the poller replays from the last committed cursor and the ingest UNIQUE
//! (`owner_id, source_type, source_id, external_key, source_version`) makes
//! the replay a silent no-op (`Ok(None)`). Cursor-behind is safe (replay);
//! cursor-ahead would be data loss, so the two writes never separate.
//!
//! Emits: `SOURCE_CHANGED {observation_id, source_type, source_id,
//! source_version, external_key, source_reference}` plus the due-sweep fire
//! keys `CALENDAR_DUE` / `REMINDER_DUE` (one per calendar event / reminder).
//! Idempotency rides the existing `events(owner_id, source, source_event_key)`
//! UNIQUE (EventBus pattern): an already-recorded version returns its
//! observation id without writing. Silence rule: empty syncs (zero rows)
//! write nothing.

use orbit_core::{Error, EventType, OwnerScope, Result, literal, validate_event};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const MAX_TYPE_LEN: usize = 64;
const MAX_ID_LEN: usize = 512;
const MAX_VERSION_LEN: usize = 256;
const MAX_KEY_LEN: usize = 1024;

/// Bounded, validated observation input. [`deny_unknown_fields`] keeps the
/// wire shape exact; trust/privacy literals match the 0043 CHECKs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationInput {
    pub source_type: String,
    pub source_id: String,
    pub version: String,
    pub external_key: String,
    #[serde(default)]
    pub artifact_id: Option<Uuid>,
    #[serde(default = "default_trust")]
    pub trust: String,
    #[serde(default = "default_privacy")]
    pub privacy: String,
    #[serde(default)]
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_trust() -> String {
    "UNTRUSTED_EXTERNAL".into()
}
fn default_privacy() -> String {
    "PRIVATE".into()
}

fn field(v: &str, cap: usize) -> Result<String> {
    let v = v.trim();
    if v.is_empty() || v.len() > cap || v.chars().any(char::is_control) {
        return Err(Error::Validation("observation field out of bounds".into()));
    }
    Ok(v.to_owned())
}

fn validated(input: &ObservationInput) -> Result<(String, String, String, String)> {
    Ok((
        field(&input.source_type, MAX_TYPE_LEN)?,
        field(&input.source_id, MAX_ID_LEN)?,
        field(&input.version, MAX_VERSION_LEN)?,
        field(&input.external_key, MAX_KEY_LEN)?,
    ))
}

fn trust_ok(v: &str) -> bool {
    matches!(
        v,
        "OWNER_AUTHENTICATED" | "SYSTEM" | "UNTRUSTED_EXTERNAL"
    )
}
fn privacy_ok(v: &str) -> bool {
    matches!(
        v,
        "PUBLIC" | "PERSONAL" | "PRIVATE" | "HIGHLY_PRIVATE" | "SECRET"
    )
}

/// Record one versioned observation: cache + cursor + observation + outbox in
/// ONE transaction. Returns `Ok(Some(observation_id))` on a fresh write,
/// `Ok(None)` when this exact version already exists (replay silence).
///
/// `cursor` is the opaque poller resume token (round-tripped, never parsed);
/// it is stored only on commit. `artifact` is the co-written cache row id for
/// `source_observations.artifact_id` (pass `None` when the sync path keeps no
/// artifact row). Trust/privacy are TEXT literals per the 0043 CHECKs.
#[allow(clippy::too_many_arguments)]
pub async fn record_observation(
    pool: &PgPool,
    scope: &OwnerScope,
    source_type: &str,
    source_id: &str,
    version: &str,
    external_key: &str,
    artifact: Option<Uuid>,
    trust: &str,
    privacy: &str,
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Option<Uuid>> {
    let input = ObservationInput {
        source_type: source_type.into(),
        source_id: source_id.into(),
        version: version.into(),
        external_key: external_key.into(),
        artifact_id: artifact,
        trust: trust.into(),
        privacy: privacy.into(),
        observed_at,
    };
    record(pool, scope, &input, None).await
}

/// Same as [`record_observation`] with an explicit opaque resume `cursor`.
/// `None` leaves `source_cursors` untouched (versioned event still written).
pub async fn record_observation_with_cursor(pool: &PgPool, scope: &OwnerScope, input: &ObservationInput, cursor: Option<&str>) -> Result<Option<Uuid>> {
    record(pool, scope, input, cursor).await
}

async fn record(
    pool: &PgPool,
    scope: &OwnerScope,
    input: &ObservationInput,
    cursor: Option<&str>,
) -> Result<Option<Uuid>> {
    let (source_type, source_id, version, external_key) = validated(input)?;
    if !trust_ok(&input.trust) {
        return Err(Error::Validation("unknown trust level".into()));
    }
    if !privacy_ok(&input.privacy) {
        return Err(Error::Validation("unknown privacy class".into()));
    }
    if let Some(c) = cursor {
        field(c, MAX_KEY_LEN)?;
    }
    let event_type = literal(EventType::SourceChanged);
    let source = format!("{source_type}:{source_id}");
    let fire_key = format!("{source_type}:{source_id}:{external_key}:{version}");
    let observed = input.observed_at.unwrap_or_else(chrono::Utc::now);

    let mut tx = pool.begin().await?;
    // Replay guard: this exact version already recorded → silent no-op.
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM source_observations WHERE owner_id=$1 AND source_type=$2 AND source_id=$3 AND external_key=$4 AND source_version=$5",
    )
    .bind(scope.owner_id)
    .bind(&source_type)
    .bind(&source_id)
    .bind(&external_key)
    .bind(&version)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Ok(None);
    }
    let observation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_observations(id,owner_id,source_type,source_id,source_version,external_key,artifact_id,trust_level,privacy_class,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(observation_id)
    .bind(scope.owner_id)
    .bind(&source_type)
    .bind(&source_id)
    .bind(&version)
    .bind(&external_key)
    .bind(input.artifact_id)
    .bind(&input.trust)
    .bind(&input.privacy)
    .bind(observed)
    .execute(&mut *tx)
    .await?;
    // Cursor advances only with the committed observation (same tx).
    if let Some(c) = cursor {
        sqlx::query(
            "INSERT INTO source_cursors(owner_id,source_type,source_id,cursor,updated_at) VALUES($1,$2,$3,$4,now()) ON CONFLICT(owner_id,source_type,source_id) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=now()",
        )
        .bind(scope.owner_id)
        .bind(&source_type)
        .bind(&source_id)
        .bind(c)
        .execute(&mut *tx)
        .await?;
    }
    let payload = json!({
        "observation_id": observation_id,
        "source_type": source_type,
        "source_id": source_id,
        "source_version": version,
        "external_key": external_key,
        "source_reference": format!("{source_type}:{source_id}:{external_key}"),
    });
    validate_event(EventType::SourceChanged, &payload)?;
    let event_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(owner_id,source,source_event_key) DO NOTHING",
    )
    .bind(event_id)
    .bind(scope.owner_id)
    .bind(&event_type)
    .bind(&source)
    .bind(scope.principal_id)
    .bind(&payload)
    .bind(&input.trust)
    .bind(&input.privacy)
    .bind(event_id)
    .bind(&fire_key)
    .execute(&mut *tx)
    .await?;
    let stored: Uuid = sqlx::query_scalar(
        "SELECT id FROM events WHERE owner_id=$1 AND source=$2 AND source_event_key=$3",
    )
    .bind(scope.owner_id)
    .bind(&source)
    .bind(&fire_key)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(scope.owner_id)
    .bind(stored)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO observation_outbox(id,owner_id,observation_id,event_id) VALUES($1,$2,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(scope.owner_id)
    .bind(observation_id)
    .bind(stored)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(observation_id))
}

/// Due-sweep trigger event: one `CALENDAR_DUE` / `REMINDER_DUE` event plus a
/// foundation delivery, idempotent on the fire key (`<kind>:<row id>`, the
/// existing CAS pattern). Returns `true` when this call fired, `false` on
/// replay. `source_reference` satisfies `validate_event` for both kinds.
pub async fn emit_due_event(
    pool: &PgPool,
    scope: &OwnerScope,
    kind: EventType,
    row_id: Uuid,
    title: &str,
) -> Result<bool> {
    let (event_type, fire_key) = match kind {
        EventType::CalendarDue => (literal(EventType::CalendarDue), format!("calendar-due:{row_id}")),
        EventType::ReminderDue => (literal(EventType::ReminderDue), format!("reminder-due:{row_id}")),
        _ => return Err(Error::Validation("emit_due_event takes CalendarDue or ReminderDue".into())),
    };
    let title: String = title.chars().take(256).collect();
    if title.trim().is_empty() || title.chars().any(char::is_control) {
        return Err(Error::Validation("due event title out of bounds".into()));
    }
    let payload: Value = json!({
        "source_reference": fire_key,
        "fire_key": fire_key,
        "row_id": row_id,
        "title": title,
    });
    validate_event(kind, &payload)?;
    let mut tx = pool.begin().await?;
    let event_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,$3,'due-sweep',$4,$5,'SYSTEM','PRIVATE',$6,$7) ON CONFLICT(owner_id,source,source_event_key) DO NOTHING RETURNING id",
    )
    .bind(event_id)
    .bind(scope.owner_id)
    .bind(&event_type)
    .bind(scope.principal_id)
    .bind(&payload)
    .bind(event_id)
    .bind(&fire_key)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if inserted {
        sqlx::query(
            "INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(event_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(true);
    }
    Ok(false)
}
