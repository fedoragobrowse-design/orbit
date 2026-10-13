/// Per-case proactive candidates: durable queue fed by the observation
/// outbox (step 9, CandidatePipe slice).
///
/// Flow: `drain_observation_outbox` claims unpublished `observation_outbox`
/// rows (`FOR UPDATE SKIP LOCKED`), matches each observation against enabled
/// proactive automations (event trigger on SOURCE_CHANGED/CALENDAR_DUE/
/// REMINDER_DUE with a matching source binding), builds one
/// [`CandidateInsert`] per match via the deterministic builders in
/// `orbit-scheduler::proactive_builders`, and inserts into
/// `proactive_candidates` — all in the same transaction that stamps
/// `published_at`, so replay is a no-op:
/// `ON CONFLICT(owner_id, automation_id, fire_key) DO NOTHING`.
///
/// Rule config (behavior, source_scopes, cooldown, quiet hours, daily caps,
/// confidence floor, action scopes) is owned by RuleFields in
/// `policy_scope`; this module reads it generically via
/// `parse_rule_config` and never defines rule fields. Draft content
/// (summary/evidence/proposed_action + synthesis gate) is owned by
/// DeterministicFirst; this module only inserts what the builders return,
/// verbatim — quarantine (`needs_review`) drafts are stored as-is and never
/// synthesized (synthesis is out of scope for this slice anyway: no model
/// calls here).
use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Insert-ready candidate. Column names mirror `proactive_candidates`
/// (0044): `automation_id`, `observation_id`, `fire_key`, `summary`,
/// `evidence_refs`, `proposed_action`. State/revision/timestamps stay
/// database defaults (`PENDING`/1/now).
#[derive(Debug, Clone)]
pub struct CandidateInsert {
    pub automation_id: Uuid,
    pub observation_id: Option<Uuid>,
    pub fire_key: String,
    pub summary: String,
    pub evidence_refs: Value,
    pub proposed_action: Value,
}

impl From<orbit_scheduler::proactive_builders::CandidateDraft> for CandidateInsert {
    fn from(d: orbit_scheduler::proactive_builders::CandidateDraft) -> Self {
        Self {
            automation_id: d.automation_id,
            observation_id: d.observation_id,
            fire_key: d.fire_key,
            summary: d.summary,
            evidence_refs: d.evidence_refs,
            proposed_action: d.proposed_action,
        }
    }
}

/// Drain outcome for worker logging/tests.
#[derive(Debug, Default)]
pub struct DrainStats {
    pub claimed: usize,
    pub inserted: usize,
    pub skipped: usize,
}

/// Claim up to `limit` unpublished outbox rows and queue one candidate per
/// matching enabled proactive rule, transactionally.
///
/// Per-claim transaction: claim row (`published_at` stamp) + match rules +
/// insert candidates + debounce/cap checks all commit atomically. Two
/// workers racing the same row serialize on `FOR UPDATE SKIP LOCKED`; a
/// crash between claim and insert replays as a silent no-op via the
/// `UNIQUE(owner_id, automation_id, fire_key)` guard. `published_at` is
/// stamped even when no rule matches so the row never redrains.
pub async fn drain_observation_outbox(pool: &PgPool, limit: i64) -> orbit_core::Result<DrainStats> {
    let mut stats = DrainStats::default();
    let rows = sqlx::query(
        "SELECT o.id, o.owner_id, o.observation_id, o.event_id, s.source_type, s.source_id, \
         s.source_version, s.external_key, s.trust_level \
         FROM observation_outbox o JOIN source_observations s \
         ON s.owner_id = o.owner_id AND s.id = o.observation_id \
         WHERE o.published_at IS NULL ORDER BY o.created_at, o.id LIMIT $1 \
         FOR UPDATE OF o SKIP LOCKED",
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(pool)
    .await?;
    for row in rows {
        stats.claimed += 1;
        let outbox_id: Uuid = row.get("id");
        let owner: Uuid = row.get("owner_id");
        let observation_id: Uuid = row.get("observation_id");
        let source_type: String = row.get("source_type");
        let source_id: String = row.get("source_id");
        let source_version: String = row.get("source_version");
        let external_key: String = row.get("external_key");
        match drain_one(
            pool,
            outbox_id,
            owner,
            observation_id,
            &source_type,
            &source_id,
            &source_version,
            &external_key,
        )
        .await
        {
            Ok(n) => {
                stats.inserted += n as usize;
                if n == 0 {
                    stats.skipped += 1;
                }
            }
            Err(e) => {
                tracing::error!(error=%e, outbox_id=%outbox_id, "proactive drain failed");
                stats.skipped += 1;
            }
        }
    }
    Ok(stats)
}

async fn drain_one(
    pool: &PgPool,
    outbox_id: Uuid,
    owner: Uuid,
    observation_id: Uuid,
    source_type: &str,
    source_id: &str,
    source_version: &str,
    external_key: &str,
) -> orbit_core::Result<i64> {
    let mut tx = pool.begin().await?;
    // Claim first: stamp published_at in the same tx as the candidate
    // inserts, so a crash either replays the whole claim (guarded by the
    // UNIQUE no-op) or never claimed at all. Never stamp-then-insert in
    // separate transactions.
    let claimed: bool = sqlx::query_scalar(
        "UPDATE observation_outbox SET published_at = now() WHERE id = $1 AND owner_id = $2 AND published_at IS NULL RETURNING true",
    )
    .bind(outbox_id)
    .bind(owner)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(false);
    if !claimed {
        return Ok(0);
    }
    // Enabled proactive rules bound to this source: trigger.kind = event,
    // event_type SOURCE_CHANGED, and either a free-form `source` match or a
    // structured source_type+source_id pair match. OFF-behavior and disabled
    // rows are excluded here; remaining gates (cooldown/caps/confidence)
    // apply per rule below. Legacy non-rule triggers never match: they lack
    // the event shape entirely.
    let rules = sqlx::query(
        "SELECT id, policy_scope FROM automations WHERE owner_id = $1 AND enabled \
         AND trigger->>'kind' = 'event' AND trigger->>'event_type' = 'SOURCE_CHANGED' \
         AND (trigger->>'source' = $2 OR (trigger->>'source_type' = $3 AND trigger->>'source_id' = $4)) \
         ORDER BY id FOR UPDATE SKIP LOCKED",
    )
    .bind(owner)
    .bind(format!("{source_type}:{source_id}"))
    .bind(source_type)
    .bind(source_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut inserted: i64 = 0;
    for rule in rules {
        let automation_id: Uuid = rule.get("id");
        let policy_scope: Value = rule.get("policy_scope");
        let cfg = orbit_scheduler::parse_rule_config(&policy_scope).unwrap_or_default();
        // OFF behavior never queues; legacy rows without a behavior key are
        // not proactive rules (RuleFields owns the behavior contract).
        if cfg
            .behavior
            .is_none_or(|b| b == orbit_scheduler::RuleBehavior::Off)
        {
            continue;
        }
        // source_scopes gate: empty (RuleFields rejects at validation for
        // new rules, but be liberal at runtime) or prefix match on
        // "<type>:<id>" / "<type>".
        if !cfg.source_scopes.is_empty()
            && !cfg.source_scopes.iter().any(|s| {
                s == source_type
                    || s == &format!("{source_type}:{source_id}")
                    || format!("{source_type}:{source_id}").starts_with(s.as_str())
            })
        {
            continue;
        }
        // Cooldown: skip when this rule queued anything recently.
        if let Some(cool) = cfg.cooldown_seconds {
            if cool > 0 {
                let recent: bool = sqlx::query_scalar(
                    "SELECT true FROM proactive_candidates WHERE owner_id = $1 AND automation_id = $2 \
                     AND created_at > now() - make_interval(secs => $3) LIMIT 1",
                )
                .bind(owner)
                .bind(automation_id)
                .bind(cool as f64)
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(false);
                if recent {
                    continue;
                }
            }
        }
        // Daily cap: skip when today's queued count hit max_runs_per_day.
        if let Some(cap) = cfg.max_runs_per_day {
            let today: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM proactive_candidates WHERE owner_id = $1 AND automation_id = $2 \
                 AND created_at >= date_trunc('day', now())",
            )
            .bind(owner)
            .bind(automation_id)
            .fetch_one(&mut *tx)
            .await?;
            if today >= cap as i64 {
                continue;
            }
        }
        // Debounce: same source version already queued for this rule.
        let fire_key = format!("watch:{source_type}:{source_id}:{external_key}:{source_version}");
        let draft = orbit_scheduler::proactive_builders::draft_watched_file_change(
            automation_id,
            Some(observation_id),
            source_type,
            source_id,
            external_key,
            source_version,
            &format!("{source_type}:{source_id} changed"),
        );
        let insert = CandidateInsert::from(draft);
        // Confidence floor: below-minimum drafts never queue (RuleFields
        // owns the floor; DeterministicFirst owns the confidence value).
        if let Some(min) = cfg.minimum_confidence {
            if !orbit_scheduler::proactive_builders::confidence_met(&insert.proposed_action, min) {
                continue;
            }
        }
        let did: bool = sqlx::query_scalar(
            "INSERT INTO proactive_candidates(id, owner_id, automation_id, observation_id, fire_key, summary, evidence_refs, proposed_action) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id, automation_id, fire_key) DO NOTHING RETURNING true",
        )
        .bind(Uuid::new_v4())
        .bind(owner)
        .bind(insert.automation_id)
        .bind(insert.observation_id)
        .bind(&fire_key)
        .bind(&insert.summary)
        .bind(&insert.evidence_refs)
        .bind(&insert.proposed_action)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);
        if did {
            inserted += 1;
        }
    }
    tx.commit().await?;
    Ok(inserted)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidatePage {
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/proactive/candidates", responses((status = 200, body = Value)))]
pub async fn list_candidates(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(page): Query<CandidatePage>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let limit = page.limit.unwrap_or(20).clamp(1, 100);
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(c) - 'owner_id' FROM proactive_candidates c WHERE owner_id = $1 \
         AND ($2::uuid IS NULL OR (c.created_at, c.id) < (SELECT created_at, id FROM proactive_candidates WHERE owner_id = $1 AND id = $2)) \
         ORDER BY c.created_at DESC, c.id DESC LIMIT $3",
    )
    .bind(auth.scope.owner_id)
    .bind(page.cursor)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;
    let next_cursor = if rows.len() as i64 > limit {
        rows[(limit - 1) as usize].get("id").cloned()
    } else {
        None
    };
    let items: Vec<Value> = rows.into_iter().take(limit as usize).collect();
    Ok(Json(json!({"items": items, "next_cursor": next_cursor})))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RevisionBody {
    pub expected_revision: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SnoozeBody {
    pub expected_revision: i64,
    pub snoozed_until: chrono::DateTime<chrono::Utc>,
}

async fn transition(
    pool: &PgPool,
    owner: Uuid,
    id: Uuid,
    expected_revision: i64,
    state: &str,
    snoozed_until: Option<chrono::DateTime<chrono::Utc>>,
) -> orbit_core::Result<Value> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT state, revision FROM proactive_candidates WHERE owner_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(owner)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let cur: String = row.get("state");
    let rev: i64 = row.get("revision");
    if rev != expected_revision {
        return Err(Error::Conflict("stale revision".into()));
    }
    // Terminal states never transition; snoozed rows wake only via a fresh
    // candidate (new fire key), never by re-opening.
    if matches!(cur.as_str(), "DONE" | "DISMISSED" | "FAILED") {
        return Err(Error::Conflict("candidate is terminal".into()));
    }
    let updated: Option<Value> = sqlx::query_scalar(
        "UPDATE proactive_candidates SET state = $3, snoozed_until = $4, revision = revision + 1, updated_at = now() \
         WHERE owner_id = $1 AND id = $2 AND revision = $5 RETURNING to_jsonb(proactive_candidates) - 'owner_id'",
    )
    .bind(owner)
    .bind(id)
    .bind(state)
    .bind(snoozed_until)
    .bind(expected_revision)
    .fetch_optional(&mut *tx)
    .await?;
    let updated = updated.ok_or(Error::Conflict("stale revision".into()))?;
    tx.commit().await?;
    Ok(updated)
}

#[utoipa::path(post, path = "/api/v1/proactive/candidates/{id}/approve", responses((status = 200, body = Value)))]
pub async fn approve_candidate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionBody>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    Ok(Json(
        transition(
            &state.pool,
            auth.scope.owner_id,
            id,
            input.expected_revision,
            "AWAITING_APPROVAL",
            None,
        )
        .await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/proactive/candidates/{id}/dismiss", responses((status = 200, body = Value)))]
pub async fn dismiss_candidate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RevisionBody>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    Ok(Json(
        transition(
            &state.pool,
            auth.scope.owner_id,
            id,
            input.expected_revision,
            "DISMISSED",
            None,
        )
        .await?,
    ))
}

#[utoipa::path(post, path = "/api/v1/proactive/candidates/{id}/snooze", responses((status = 200, body = Value)))]
pub async fn snooze_candidate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<SnoozeBody>,
) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    Ok(Json(
        transition(
            &state.pool,
            auth.scope.owner_id,
            id,
            input.expected_revision,
            "SNOOZED",
            Some(input.snoozed_until),
        )
        .await?,
    ))
}

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/proactive/candidates", get(list_candidates))
        .route(
            "/api/v1/proactive/candidates/{id}/approve",
            post(approve_candidate),
        )
        .route(
            "/api/v1/proactive/candidates/{id}/dismiss",
            post(dismiss_candidate),
        )
        .route(
            "/api/v1/proactive/candidates/{id}/snooze",
            post(snooze_candidate),
        )
}
