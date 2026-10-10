//! Global-search live test: seeds one row per source with a shared marker
//! word, asserts the envelope returns all five; empty query 422s.
//! Hermetic per-run database, dropped after (ops.rs pattern).
use axum::{Json, extract::State};
use axum::http::{HeaderMap, header};
use orbit_api::{ApiState, search};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::var("ORBIT_TEST_KEY_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir().join("orbit-test-secrets")));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_search_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db}")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_search_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db}")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap, Uuid) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("search-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("search-token-{owner}");
    let csrf = format!("search-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-search-{owner}"));
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    headers.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    headers.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, headers, owner)
}
const MARKER: &str = "zephyrquince";
#[tokio::test]
async fn search_returns_four_source_envelope_and_rejects_empty_query() {
    let (pool, db, key_dir) = pool().await;
    let (state, headers, owner) = ctx(&pool).await;
    let principal: Uuid = sqlx::query_scalar("SELECT id FROM principals WHERE owner_id=$1").bind(owner).fetch_one(&pool).await.unwrap();
    sqlx::query("INSERT INTO memory_records(id,owner_id,type,subject,normalized_subject,entity_key,value,source,source_reference,confidence,trust_level,privacy_class,status) VALUES($1,$2,'PREFERENCE',$3,$3,'k','{\"note\":\"x\"}','test','test',0.9,'OWNER_AUTHENTICATED','PRIVATE','ACTIVE')").bind(Uuid::new_v4()).bind(owner).bind(format!("likes {MARKER} tea")).execute(&pool).await.unwrap();
    let ev = Uuid::new_v4();
    sqlx::query("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,'USER_MESSAGE','test',$3,$4,'OWNER_AUTHENTICATED','PRIVATE',$5,'search-seed')").bind(ev).bind(owner).bind(principal).bind(json!({"text": format!("about {MARKER}")})).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
    let task = Uuid::new_v4();
    sqlx::query("INSERT INTO tasks(id,owner_id,event_id,principal_id,correlation_id,title,state,checkpoint,expires_at) VALUES($1,$2,$3,$4,$5,$6,'QUEUED','{\"phase\":\"NOTIFICATION\"}',now()+interval '1 hour')").bind(task).bind(owner).bind(ev).bind(principal).bind(Uuid::new_v4()).bind(format!("plan {MARKER} trip")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body) VALUES($1,$2,$3,$4,'INFO',$5,'b')").bind(Uuid::new_v4()).bind(owner).bind(task).bind(Uuid::new_v4()).bind(format!("{MARKER} reminder")).execute(&pool).await.unwrap();
    let Json(full) = match search::search(State(state.clone()), headers.clone(), Json(search::SearchQuery { query: MARKER.into(), limit: None })).await { Ok(Json(v)) => Json(v), Err(_) => panic!("seeded search must succeed") };
    assert_eq!(full["memory"].as_array().map(Vec::len).unwrap_or(0), 1, "memory hit");
    assert_eq!(full["tasks"].as_array().map(Vec::len).unwrap_or(0), 1, "task hit");
    assert_eq!(full["events"].as_array().map(Vec::len).unwrap_or(0), 1, "event hit");
    assert_eq!(full["notifications"].as_array().map(Vec::len).unwrap_or(0), 1, "notification hit");
    assert!(full["files_note"].is_string(), "files note present");
    assert!(search::search(State(state.clone()), headers.clone(), Json(search::SearchQuery { query: "   ".into(), limit: None })).await.is_err(), "empty query must fail validation");
    let _ = std::fs::remove_dir_all(state.key_dir.clone());
    cleanup(&pool, &db, &key_dir).await;
}
