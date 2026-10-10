//! E19a SSRF regression: calendar ICS/CalDAV fetch, HA sync fetch, and the
//! browser URL screen all route through `AdmittedEndpoint` semantics.
//! Hermetic DBs (`orbit_ssrf_<pid>_<tag>`), dropped WITH (FORCE) after.
//! No external network: rejection cases use literal IPs/userinfo forms that
//! never need DNS; the legit-URL case passes a screen that fails open only
//! when a hostname is unresolvable (fetch-time DNS-pinning is the backstop).
use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use axum::response::IntoResponse;
use orbit_api::ApiState;
use orbit_api::calendar::SourceCreate;
use orbit_api::connectors::HaCreate;
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_ssrf_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_ssrf_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("ssrf-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("ssrf-token-{owner}");
    let csrf = format!("ssrf-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-ssrf-{owner}"));
    let mut write = HeaderMap::new();
    write.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    write.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, write)
}
fn cal(url: &str) -> SourceCreate {
    serde_json::from_value(serde_json::json!({"name": "evil", "kind": "ics", "url": url, "enabled": true})).unwrap()
}
fn ha(base: &str) -> HaCreate {
    serde_json::from_value(serde_json::json!({"name": "evil", "base_url": base, "token": "t"})).unwrap()
}
fn status_of(r: orbit_api::ApiError) -> u16 {
    r.into_response().status().as_u16()
}
#[tokio::test]
async fn ssrf_calendar_create_rejects_metadata_and_loopback() {
    let (pool, db, key_dir) = pool().await;
    let (state, write) = ctx(&pool).await;
    for url in ["http://169.254.169.254/x.ics", "https://169.254.169.254/x.ics", "http://127.0.0.1:8123/x.ics", "http://user:pass@example.invalid/x.ics", "http://2130706433/x.ics"] {
        let code = status_of(orbit_api::calendar::create_source(State(state.clone()), write.clone(), axum::Json(cal(url))).await.expect_err("SSRF calendar url must fail"));
        assert!(code == 403 || code == 422, "calendar {url} must 403/422, got {code}");
    }
    // Fetch-level screen holds without any DB row.
    assert!(orbit_calendar::fetch_ics("http://169.254.169.254/x.ics").await.is_err(), "metadata fetch must fail");
    assert!(orbit_calendar::fetch_caldav(&orbit_calendar::CalendarSource { kind: "caldav".into(), url: "http://127.0.0.1:5232/".into(), username: None, password: None }).await.is_err(), "loopback caldav must fail");
    cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn ssrf_ha_create_and_sync_reject_loopback() {
    let (pool, db, key_dir) = pool().await;
    let (state, write) = ctx(&pool).await;
    for base in ["http://127.0.0.1:8123", "http://169.254.169.254/", "https://169.254.169.254/"] {
        let code = status_of(orbit_api::connectors::create_ha(State(state.clone()), write.clone(), axum::Json(ha(base))).await.expect_err("SSRF HA base must fail"));
        assert!(code == 403 || code == 422, "HA {base} must 403/422, got {code}");
    }
    // Sync-time screen holds for pre-existing rows: insert directly, sync must fail.
    let owner: Uuid = sqlx::query_scalar("SELECT id FROM users").fetch_one(&pool).await.unwrap();
    let scope = orbit_core::OwnerScope { owner_id: owner, principal_id: Uuid::new_v4() };
    let store = orbit_secrets::SecretStore::open(pool.clone(), &state.key_dir).await.unwrap();
    let cred = store.put(&scope, "ha-token", b"ssrf-token").await.unwrap();
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO ha_connections(id,owner_id,name,base_url,credential_id) VALUES($1,$2,'legacy','http://127.0.0.1:8123',$3)").bind(id).bind(owner).bind(cred).execute(&pool).await.unwrap();
    let code = status_of(orbit_api::connectors::sync_ha(State(state.clone()), write.clone(), Path(id)).await.expect_err("loopback sync must fail"));
    assert!(code == 403 || code == 422, "HA sync must 403/422, got {code}");
    cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn ssrf_browser_screen_rejects_bypass_forms() {
    for url in ["http://169.254.169.254/", "https://169.254.169.254/", "http://127.0.0.1/", "http://[::1]/", "http://user@127.0.0.1/", "http://user:pass@example.invalid/", "http://2130706433/", "http://0x7f.0.0.1/", "http://0x7F.0.0.1/", "gopher://example.invalid/", "file:///etc/passwd", "http://10.0.0.1/", "http://192.168.1.1/", "https://localhost/"] {
        assert!(orbit_api::computers::screen_browser_url(url).await.is_err(), "browser {url} must fail the screen");
    }
}
#[tokio::test]
async fn ssrf_browser_screen_fails_closed_on_unresolvable() {
    // Fail-closed: `nonexistent.invalid` (RFC 2606/6761 reserved TLD) never
    // resolves, so the screen denies even though the shape is http(s) — the
    // node fetch has no backstop for names the server cannot see.
    assert!(orbit_api::computers::screen_browser_url("http://nonexistent.invalid/").await.is_err(), "unresolvable host must fail closed");
    assert!(orbit_api::computers::screen_browser_url("https://nonexistent.invalid/a?b=c").await.is_err(), "unresolvable host must fail closed");
}
