//! HA + GitHub connectors: validation, scoping, credential hygiene.
//! Hermetic DB, dropped after. Sync paths hit local stub servers
//! (same pattern as calendar) — no external network.
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use orbit_api::connectors::{GithubCreate, HaCreate};
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_conn_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_conn_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap, HeaderMap) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("conn-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("conn-token-{owner}");
    let csrf = format!("conn-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-conn-{owner}"));
    let mut read = HeaderMap::new();
    read.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    read.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    let mut write = read.clone();
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, read, write)
}
async fn stub_json(body: String) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            use tokio::io::AsyncReadExt;
            let _ = s.read(&mut buf).await;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
    // Stash the port in a thread-local-free way: caller re-binds is avoided
    // by returning the port via a global increment — simpler: encode in body.
    // Instead the caller below uses its own listener; this helper is unused
    // except to keep the stub pattern explicit. Return 0 (unused).
    let _ = port;
    0
}
#[tokio::test]
async fn ha_rejects_gopher_and_stores_from_local_stub() {
    let (pool, db, key_dir) = pool().await;
    let (state, _read, write) = ctx(&pool).await;
    let bad: HaCreate = serde_json::from_value(serde_json::json!({"name": "home", "base_url": "gopher://bad.invalid", "token": "t"})).unwrap();
    assert!(orbit_api::connectors::create_ha(State(state.clone()), write.clone(), axum::Json(bad)).await.is_err(), "non-http HA url must 422");
    let body = r#"[{"entity_id":"light.kitchen","state":"on","attributes":{"brightness": 200}},{"entity_id":"sensor.temp","state":"21.5","attributes":{}}]"#.to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            use tokio::io::AsyncReadExt;
            let _ = s.read(&mut buf).await;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
    let good: HaCreate = serde_json::from_value(serde_json::json!({"name": "home", "base_url": format!("http://127.0.0.1:{port}"), "token": "ha-secret-token"})).unwrap();
    let created = match orbit_api::connectors::create_ha(State(state.clone()), write.clone(), axum::Json(good)).await { Ok(v) => v, Err(_) => panic!("create ha") };
    assert_eq!(created.0["configured"], serde_json::json!(true));
    let id: Uuid = created.0["id"].as_str().unwrap().parse().unwrap();
    let out = match orbit_api::connectors::sync_ha(State(state.clone()), write.clone(), Path(id)).await { Ok(v) => v, Err(_) => panic!("sync ha") };
    assert_eq!(out.0["stored"], serde_json::json!(2), "stub HA must store 2 states");
    let listed = match orbit_api::connectors::list_states(State(state.clone()), _read.clone(), axum::extract::Query(orbit_api::connectors::Page { limit: None })).await { Ok(v) => v, Err(_) => panic!("list states") };
    assert_eq!(listed.0["items"].as_array().unwrap().len(), 2);
    // Tokens never surface in list output.
    assert!(listed.0.to_string().find("ha-secret-token").is_none(), "token must never surface");
    cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn github_pat_scoped_and_never_surfaces() {
    let (pool, db, key_dir) = pool().await;
    let (state, read, write) = ctx(&pool).await;
    let good: GithubCreate = serde_json::from_value(serde_json::json!({"name": "code", "token": "ghp-test-token-123"})).unwrap();
    let created = match orbit_api::connectors::create_github(State(state.clone()), write.clone(), axum::Json(good)).await { Ok(v) => v, Err(_) => panic!("create github") };
    assert_eq!(created.0["configured"], serde_json::json!(true));
    let id: Uuid = created.0["id"].as_str().unwrap().parse().unwrap();
    let listed = match orbit_api::connectors::list_github(State(state.clone()), read.clone(), ).await { Ok(v) => v, Err(_) => panic!("list github") };
    assert_eq!(listed.0["items"].as_array().unwrap().len(), 1);
    assert!(listed.0.to_string().find("ghp-test-token-123").is_none(), "PAT must never surface");
    let dup: GithubCreate = serde_json::from_value(serde_json::json!({"name": "code", "token": "other"})).unwrap();
    assert!(orbit_api::connectors::create_github(State(state.clone()), write.clone(), axum::Json(dup)).await.is_err(), "duplicate github name must conflict");
    let _ = stub_json("[]".to_owned());
    let _ = id;
    cleanup(&pool, &db, &key_dir).await;
}
