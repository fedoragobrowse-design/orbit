//! Browser sandbox agent (D17): default-deny seed, approval gate, URL screen.
use orbit_api::ApiState;
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_brows_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_brows_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
#[tokio::test]
async fn browser_descriptors_seed_disabled_and_gate_holds() {
    let (pool, db, key_dir) = pool().await;
    let owner = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("brows-{owner}@example.invalid")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO installation(singleton,owner_id) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET owner_id=$1").bind(owner).execute(&pool).await.unwrap();
    let state = ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() };
    orbit_api::computers::seed_tools(&state).await.expect("seed runs");
    // Browser tools register but stay disabled; file tools stay enabled.
    let bnav: bool = sqlx::query_scalar("SELECT enabled FROM tool_registry WHERE owner_id=$1 AND name='browser.navigate'").bind(owner).fetch_one(&pool).await.expect("browser.navigate registered");
    let bfill: bool = sqlx::query_scalar("SELECT enabled FROM tool_registry WHERE owner_id=$1 AND name='browser.fill_submit'").bind(owner).fetch_one(&pool).await.expect("browser.fill_submit registered");
    assert!(!bnav && !bfill, "browser tools seed disabled (default-deny)");
    let flist: bool = sqlx::query_scalar("SELECT enabled FROM tool_registry WHERE owner_id=$1 AND name='files.list'").bind(owner).fetch_one(&pool).await.expect("files.list registered");
    assert!(flist, "file tools stay enabled");
    // Descriptor marks: sandbox-required, High risk, untrusted page content.
    let desc: serde_json::Value = sqlx::query_scalar("SELECT descriptor FROM tool_registry WHERE owner_id=$1 AND name='browser.navigate'").bind(owner).fetch_one(&pool).await.unwrap();
    assert_eq!(desc["sandbox_required"], serde_json::json!(true));
    assert_eq!(desc["default_risk"], serde_json::json!("HIGH"));
    assert!(desc["effects"]["affected_party"].as_str().unwrap_or_default().contains("untrusted"), "page content marked untrusted");
    // Re-seed never silently re-enables an owner-disabled row, and never
    // disables an owner who explicitly enabled it.
    sqlx::query("UPDATE tool_registry SET enabled=true WHERE owner_id=$1 AND name='browser.navigate'").bind(owner).execute(&pool).await.unwrap();
    orbit_api::computers::seed_tools(&state).await.expect("reseed runs");
    let still_on: bool = sqlx::query_scalar("SELECT enabled FROM tool_registry WHERE owner_id=$1 AND name='browser.navigate'").bind(owner).fetch_one(&pool).await.unwrap();
    assert!(still_on, "owner-enabled browser tool survives reseed");
    // Agent admission denies the still-disabled fill_submit (not admitted → DENIED, never executed).
    let scope = orbit_core::OwnerScope { owner_id: owner, principal_id: Uuid::new_v4() };
    let dispatcher = orbit_api::agents::AgentDispatcher { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts") };
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(scope.principal_id).bind(owner).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'SYSTEM','INTERNAL','SYSTEM','orbit-worker')").bind(Uuid::new_v4()).bind(owner).execute(&pool).await.unwrap();
    let agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_definitions(id,owner_id,definition) VALUES($1,$2,jsonb_build_object('allowed_tools',jsonb_build_array('browser.fill_submit')))").bind(agent).bind(owner).execute(&pool).await.unwrap();
    let task = Uuid::new_v4();
    sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,title,state) VALUES($1,$2,$3,$4,'b','RUNNING')").bind(task).bind(owner).bind(scope.principal_id).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
    let out = orbit_agent_runtime::Dispatcher::propose(&dispatcher, &scope, task, agent, "browser.fill_submit", serde_json::json!({"node_id": Uuid::new_v4(), "url": "https://example.com", "fields": {}}), "k1").await.expect("propose records");
    assert_eq!(out["state"], serde_json::json!("DENIED"), "disabled browser tool is denied, never approval-parked");
    cleanup(&pool, &db, &key_dir).await;
}
