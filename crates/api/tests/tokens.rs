//! API tokens: create → use on a read → revoke → 401; scoping.
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use orbit_api::tokens::TokenCreate;
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_tok_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_tok_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn session_ctx(pool: &PgPool) -> (ApiState, HeaderMap) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("tok-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'SYSTEM','INTERNAL','SYSTEM','orbit-worker')").bind(Uuid::new_v4()).bind(owner).execute(pool).await.unwrap();
    let token = format!("tok-session-{owner}");
    let csrf = format!("tok-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-tok-{owner}"));
    let mut write = HeaderMap::new();
    write.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    write.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, write)
}
#[tokio::test]
async fn token_create_use_revoke_fails_closed() {
    let (pool, db, key_dir) = pool().await;
    let (state, write) = session_ctx(&pool).await;
    let made = match orbit_api::tokens::create_token(State(state.clone()), write.clone(), axum::Json(TokenCreate { name: "laptop".into() })).await { Ok(v) => v, Err(_) => panic!("create token") };
    let plain = made.0["token"].as_str().unwrap().to_owned();
    assert!(plain.starts_with("orb_"), "token carries orb_ prefix");
    let id: Uuid = made.0["id"].as_str().unwrap().parse().unwrap();
    // Only the hash is stored.
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE id=$1").bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(stored, orbit_api::auth::hash(&plain));
    assert!(!stored.contains(&plain[4..8]), "plaintext never stored");
    // Use on a read: bearer alone authenticates.
    let mut bearer = HeaderMap::new();
    bearer.insert(header::AUTHORIZATION, format!("Bearer {plain}").parse().unwrap());
    let listed = match orbit_api::tokens::list_tokens(State(state.clone()), bearer.clone()).await { Ok(v) => v, Err(_) => panic!("bearer list") };
    assert_eq!(listed.0["items"].as_array().unwrap().len(), 1);
    // Revoke via session, bearer then fails closed.
    match orbit_api::tokens::revoke_token(State(state.clone()), write.clone(), Path(id)).await { Ok(_) => {}, Err(_) => panic!("revoke token") };
    assert!(orbit_api::tokens::list_tokens(State(state.clone()), bearer.clone()).await.is_err(), "revoked bearer must 401");
    // A second owner sees nothing.
    let (state2, write2) = session_ctx(&pool).await;
    let listed2 = match orbit_api::tokens::list_tokens(State(state2.clone()), write2.clone()).await { Ok(v) => v, Err(_) => panic!("second owner list") };
    assert!(listed2.0["items"].as_array().unwrap().is_empty(), "tokens are owner-scoped");
    cleanup(&pool, &db, &key_dir).await;
}
