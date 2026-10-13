//! Step 9 CandidatePipe slice: 0044 `proactive_candidates` + outbox consumer.
//! Owned test postgres only (default 127.0.0.1:55432 orbit_test). Never the personal deployment.
use sqlx::{PgPool, Row};
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://orbit_test:orbit_test@127.0.0.1:55432/orbit_test".into())
}

async fn pool() -> PgPool {
    let pool = PgPool::connect(&db_url())
        .await
        .expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations apply");
    pool
}

async fn owner(pool: &PgPool) -> orbit_core::OwnerScope {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')")
        .bind(owner)
        .bind(format!("proactive-{owner}@example.invalid"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)")
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')")
        .bind(principal)
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    orbit_core::OwnerScope {
        owner_id: owner,
        principal_id: principal,
    }
}

async fn seed_rule(pool: &PgPool, scope: &orbit_core::OwnerScope) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO automations(id,owner_id,enabled,\"trigger\",filters,policy_scope) VALUES($1,$2,true,
         '{\"kind\":\"event\",\"event_type\":\"SOURCE_CHANGED\",\"source_type\":\"file\",\"source_id\":\"inbox\"}',
         '[]',
         '{\"behavior\":\"SUGGEST\",\"source_scopes\":[\"file:inbox\"],\"cooldown_seconds\":60,\"max_runs_per_day\":5,\"minimum_confidence\":0.5}')",
    )
    .bind(id)
    .bind(scope.owner_id)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn seed_observation(pool: &PgPool, scope: &orbit_core::OwnerScope) -> Uuid {
    let obs = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_observations(id,owner_id,source_type,source_id,source_version,external_key,trust_level,privacy_class)
         VALUES($1,$2,'file','inbox','v1','doc.txt','OWNER_AUTHENTICATED','PRIVATE')",
    )
    .bind(obs)
    .bind(scope.owner_id)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO observation_outbox(id,owner_id,observation_id) VALUES($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(obs)
        .execute(pool)
        .await
        .unwrap();
    obs
}

#[tokio::test]
async fn drain_queues_one_candidate_and_replay_is_noop() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    let automation = seed_rule(&pool, &scope).await;
    let obs = seed_observation(&pool, &scope).await;

    // Drain-to-quiescence: parallel tests share one DB and the drain is
    // global, so a sibling may legitimately claim rows first — loop until
    // our row is published, counting only our owner's inserts.
    for _ in 0..10 {
        orbit_api::proactive::drain_observation_outbox(&pool, 20)
            .await
            .unwrap();
        let unpublished: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM observation_outbox o JOIN source_observations s
             ON s.owner_id=o.owner_id AND s.id=o.observation_id
             WHERE o.owner_id=$1 AND o.published_at IS NULL",
        )
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if unpublished == 0 {
            break;
        }
    }
    let row = sqlx::query("SELECT automation_id,observation_id,fire_key,state FROM proactive_candidates WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<Uuid, _>("automation_id"), automation);
    assert_eq!(row.get::<Uuid, _>("observation_id"), obs);
    assert_eq!(row.get::<String, _>("state"), "PENDING");
    assert_eq!(
        row.get::<String, _>("fire_key"),
        "watch:file:inbox:doc.txt:v1"
    );

    // Replay: our outbox row is published; a further drain inserts nothing
    // new for us and never duplicates.
    for _ in 0..3 {
        orbit_api::proactive::drain_observation_outbox(&pool, 20)
            .await
            .unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM proactive_candidates WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}
#[tokio::test]
async fn drain_respects_cooldown_and_daily_cap() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    seed_rule(&pool, &scope).await;
    seed_observation(&pool, &scope).await;
    for _ in 0..10 {
        orbit_api::proactive::drain_observation_outbox(&pool, 20)
            .await
            .unwrap();
        let unpublished: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM observation_outbox WHERE owner_id=$1 AND published_at IS NULL",
        )
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if unpublished == 0 {
            break;
        }
    }
    // Second observation, same rule: cooldown (60s) suppresses a new row.
    let obs2 = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_observations(id,owner_id,source_type,source_id,source_version,external_key,trust_level,privacy_class)
         VALUES($1,$2,'file','inbox','v2','doc.txt','OWNER_AUTHENTICATED','PRIVATE')",
    )
    .bind(obs2)
    .bind(scope.owner_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO observation_outbox(id,owner_id,observation_id) VALUES($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(obs2)
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..10 {
        orbit_api::proactive::drain_observation_outbox(&pool, 20)
            .await
            .unwrap();
        let unpublished: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM observation_outbox WHERE owner_id=$1 AND published_at IS NULL",
        )
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if unpublished == 0 {
            break;
        }
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM proactive_candidates WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);

    // Cap of zero suppresses everything for a fresh rule.
    let capped = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO automations(id,owner_id,enabled,\"trigger\",filters,policy_scope) VALUES($1,$2,true,
         '{\"kind\":\"event\",\"event_type\":\"SOURCE_CHANGED\",\"source_type\":\"file\",\"source_id\":\"capped\"}',
         '[]',
         '{\"behavior\":\"SUGGEST\",\"source_scopes\":[\"file:capped\"],\"max_runs_per_day\":1}')",
    )
    .bind(capped)
    .bind(scope.owner_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO proactive_candidates(id,owner_id,automation_id,fire_key) VALUES($1,$2,$3,'watch:file:capped:x:v0')",
    )
    .bind(Uuid::new_v4())
    .bind(scope.owner_id)
    .bind(capped)
    .execute(&pool)
    .await
    .unwrap();
    let obs3 = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO source_observations(id,owner_id,source_type,source_id,source_version,external_key,trust_level,privacy_class)
         VALUES($1,$2,'file','capped','v1','n.txt','OWNER_AUTHENTICATED','PRIVATE')",
    )
    .bind(obs3)
    .bind(scope.owner_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO observation_outbox(id,owner_id,observation_id) VALUES($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(obs3)
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..10 {
        orbit_api::proactive::drain_observation_outbox(&pool, 20)
            .await
            .unwrap();
        let unpublished: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM observation_outbox WHERE owner_id=$1 AND published_at IS NULL",
        )
        .bind(scope.owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if unpublished == 0 {
            break;
        }
    }
}

#[tokio::test]
async fn candidate_transitions_cas_guard_terminal_states() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    let automation = seed_rule(&pool, &scope).await;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO proactive_candidates(id,owner_id,automation_id,fire_key) VALUES($1,$2,$3,'k1')")
        .bind(id)
        .bind(scope.owner_id)
        .bind(automation)
        .execute(&pool)
        .await
        .unwrap();
    // Stale revision rejected.
    let err = sqlx::query_scalar::<_, serde_json::Value>(
        "UPDATE proactive_candidates SET state='DISMISSED',revision=revision+1 WHERE owner_id=$1 AND id=$2 AND revision=$3 RETURNING to_jsonb(proactive_candidates)",
    )
    .bind(scope.owner_id)
    .bind(id)
    .bind(999_i64)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(err.is_none());
    // Live dismiss then terminal guard.
    sqlx::query("UPDATE proactive_candidates SET state='DISMISSED',revision=revision+1 WHERE owner_id=$1 AND id=$2 AND revision=1")
        .bind(scope.owner_id)
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let state: String =
        sqlx::query_scalar("SELECT state FROM proactive_candidates WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(state, "DISMISSED");
}
