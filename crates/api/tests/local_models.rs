//! Local model manager: owner-scoped OLLAMA proxy; non-OLLAMA 422; unreachable 503.
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use orbit_api::models::{LocalBenchmark, LocalPull};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_local_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_local_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap, HeaderMap) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("local-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'SYSTEM','INTERNAL','SYSTEM','orbit-worker')").bind(Uuid::new_v4()).bind(owner).execute(pool).await.unwrap();
    let token = format!("tok-session-{owner}");
    let csrf = format!("tok-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-local-{owner}"));
    let mut read = HeaderMap::new();
    read.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    let mut write = read.clone();
    write.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, read, write)
}
fn provider_cfg(id: Uuid, kind: &str, origin: &str) -> serde_json::Value {
    json!({"id": id, "name": "t", "kind": kind, "origin": origin, "local": true, "admitted_addresses": ["127.0.0.1"], "credential_id": null, "enabled": true})
}
async fn insert_provider(pool: &PgPool, owner: Uuid, cfg: &serde_json::Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO model_providers(id,owner_id,configuration,credential_id) VALUES($1,$2,$3,NULL)").bind(id).bind(owner).bind(cfg).execute(pool).await.unwrap();
    id
}
async fn owner_of(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM users ORDER BY email LIMIT 1").fetch_one(pool).await.unwrap()
}
async fn stub() -> (tokio::net::TcpListener, u16) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}
#[tokio::test]
async fn local_models_pull_benchmark_proxy_stub() {
    let (pool, db, key_dir) = pool().await;
    let (state, _read, write) = ctx(&pool).await;
    let owner = owner_of(&pool).await;
    let (l, port) = stub().await;
    tokio::spawn(async move {
        for _ in 0..3 {
            let Ok((mut s, _)) = l.accept().await else { break };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_owned();
            let body = if req.contains("GET /api/tags") {
                json!({"models": [{"name": "gemma3:4b", "size": 1234, "modified_at": "2026-01-01T00:00:00Z"}]}).to_string()
            } else if req.contains("POST /api/pull") {
                json!({"status": "success"}).to_string()
            } else {
                json!({"response": "ok", "done": true, "total_duration": 42_000_000}).to_string()
            };
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
    let id = insert_provider(&pool, owner, &provider_cfg(Uuid::new_v4(), "OLLAMA", &format!("http://127.0.0.1:{port}"))).await;
    let listed = match orbit_api::models::local_models(State(state.clone()), write.clone(), Path(id)).await { Ok(v) => v, Err(_) => panic!("list local") };
    assert_eq!(listed.0["models"].as_array().unwrap().len(), 1);
    assert_eq!(listed.0["models"][0]["name"], json!("gemma3:4b"));
    let pulled = match orbit_api::models::local_pull(State(state.clone()), write.clone(), Path(id), axum::Json(LocalPull { name: "gemma3:4b".into() })).await { Ok(v) => v, Err(_) => panic!("pull") };
    assert_eq!(pulled.0["status"], json!("success"));
    let bench = match orbit_api::models::local_benchmark(State(state.clone()), write.clone(), Path(id), axum::Json(LocalBenchmark { model: "gemma3:4b".into() })).await { Ok(v) => v, Err(_) => panic!("benchmark") };
    assert!(bench.0.get("elapsed_ms").and_then(|v| v.as_i64()).unwrap_or(-1) >= 0, "server-measured latency present");
    assert_eq!(bench.0["daemon_total_ms"], json!(42));
    // A second owner's provider id is invisible here.
    let owner2 = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner2).bind(format!("local2-{owner2}@example.invalid")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner2).execute(&pool).await.unwrap();
    let id2 = insert_provider(&pool, owner2, &provider_cfg(Uuid::new_v4(), "OLLAMA", &format!("http://127.0.0.1:{port}"))).await;
    assert!(orbit_api::models::local_models(State(state.clone()), write.clone(), Path(id2)).await.is_err(), "cross-owner provider must 404");
    cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn local_rejects_non_ollama_and_unreachable() {
    let (pool, db, key_dir) = pool().await;
    let (state, _read, write) = ctx(&pool).await;
    let owner = owner_of(&pool).await;
    let cloud = insert_provider(&pool, owner, &provider_cfg(Uuid::new_v4(), "OPENAI_COMPATIBLE", "https://api.example.invalid")).await;
    assert!(orbit_api::models::local_models(State(state.clone()), write.clone(), Path(cloud)).await.is_err(), "non-OLLAMA kind must 422");
    let dead = insert_provider(&pool, owner, &provider_cfg(Uuid::new_v4(), "OLLAMA", "http://127.0.0.1:1")).await;
    assert!(orbit_api::models::local_models(State(state.clone()), write.clone(), Path(dead)).await.is_err(), "unreachable daemon must 503, never fake empty");
    assert!(orbit_api::models::local_pull(State(state.clone()), write.clone(), Path(dead), axum::Json(LocalPull { name: "x".into() })).await.is_err(), "unreachable pull must 503");
    cleanup(&pool, &db, &key_dir).await;
}
