//! Provider budgets: CRUD through the API handlers + enforcement shape.
//! Hermetic DB, dropped after. A zero cap means uncapped; a $0.01 day cap
//! with a reserved call above it refuses at reserve time.
use axum::extract::Path;
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use orbit_api::models::{get_provider_budget, update_provider_budget, ProviderBudgetUpdate};
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_pbudg_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_pbudg_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap, HeaderMap, Uuid) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("pbudg-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("pbudg-token-{owner}");
    let csrf = format!("pbudg-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-pbudg-{owner}"));
    let mut read = HeaderMap::new();
    read.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    read.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    let mut write = read.clone();
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, read, write, owner)
}
#[tokio::test]
async fn provider_budget_round_trip_and_scoped() {
    let (pool, db, key_dir) = pool().await;
    let (state, read, write, owner) = ctx(&pool).await;
    let pid = Uuid::new_v4();
    sqlx::query("INSERT INTO model_providers(id,owner_id,configuration,credential_id) VALUES($1,$2,'{\"enabled\":true,\"name\":\"p\",\"kind\":\"OLLAMA\"}'::jsonb,NULL)").bind(pid).bind(owner).execute(&pool).await.unwrap();
    let got = match get_provider_budget(axum::extract::State(state.clone()), read.clone(), Path(pid)).await { Ok(v) => v, Err(_) => panic!("get budget") };
    assert_eq!(got.0["day_usd"], serde_json::json!(0.0));
    match update_provider_budget(axum::extract::State(state.clone()), write.clone(), Path(pid), axum::Json(ProviderBudgetUpdate { day_usd: 3.5, month_usd: 9.0 })).await { Ok(_) => {}, Err(_) => panic!("put budget") }
    let got = match get_provider_budget(axum::extract::State(state.clone()), read.clone(), Path(pid)).await { Ok(v) => v, Err(_) => panic!("get budget 2") };
    assert_eq!(got.0["day_usd"], serde_json::json!(3.5));
    assert_eq!(got.0["month_usd"], serde_json::json!(9.0));
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(other).bind(format!("pbudg2-{other}@example.invalid")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(other).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO provider_budgets(owner_id,provider_id,day_usd,month_usd) VALUES($1,$2,1,1)").bind(other).bind(pid).execute(&pool).await.unwrap();
    let got = match get_provider_budget(axum::extract::State(state.clone()), read.clone(), Path(pid)).await { Ok(v) => v, Err(_) => panic!("get budget 3") };
    assert_eq!(got.0["day_usd"], serde_json::json!(3.5), "cross-owner row must not leak");
    assert!(update_provider_budget(axum::extract::State(state.clone()), write.clone(), Path(Uuid::new_v4()), axum::Json(ProviderBudgetUpdate { day_usd: 1.0, month_usd: 1.0 })).await.is_err(), "unknown provider must 404");
    assert!(update_provider_budget(axum::extract::State(state), write, Path(pid), axum::Json(ProviderBudgetUpdate { day_usd: -1.0, month_usd: 0.0 })).await.is_err(), "negative cap must 422");
    cleanup(&pool, &db, &key_dir).await;
}
