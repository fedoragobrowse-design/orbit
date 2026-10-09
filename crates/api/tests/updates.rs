//! OTA slice: publish stores a row + lists it + leaves an audit row; malformed
//! digest/signature formats rejected; check answers newer vs current. Owned test
//! postgres only (default 127.0.0.1:55432 orbit_test). Never the personal deployment.
use axum::{Json,extract::{Query,State}};
use axum::http::{HeaderMap,header};
use orbit_api::{ApiState,updates};
use serde_json::{Value,json};
use sqlx::PgPool;
use uuid::Uuid;
fn db_url() -> String { std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://orbit_test:orbit_test@127.0.0.1:55432/orbit_test".into()) }
async fn pool() -> PgPool { let pool = PgPool::connect(&db_url()).await.expect("owned test postgres reachable"); sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply"); pool }
struct Ctx { state: ApiState, owner: Uuid, headers: HeaderMap }
async fn ctx(pool: &PgPool, tag: &str) -> Ctx {
 let owner = Uuid::new_v4();let principal = Uuid::new_v4();
 sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("ota-{tag}-{owner}@example.invalid")).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
 let token = format!("ota-token-{tag}-{owner}");let csrf = format!("ota-csrf-{tag}-{owner}");
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
 let key_dir = std::env::var("ORBIT_TEST_KEY_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir().join("orbit-test-secrets"));
 let base = std::env::temp_dir().join(format!("orbit-ota-{tag}-{owner}"));
 let artifact_dir = base.join("artifacts");
 let origin = "http://127.0.0.1:8080".to_string();
 let mut headers = HeaderMap::new();
 headers.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
 headers.insert(header::ORIGIN, origin.parse().unwrap());
 headers.insert("x-csrf-token", csrf.parse().unwrap());
 let state = ApiState { pool: pool.clone(), origin, key_dir, artifact_dir, nodes: orbit_api::computers::NodeHub::new() };
 Ctx { state, owner, headers }
}
macro_rules! ok { ($r:expr,$what:literal) => { match $r { Ok(v) => v, Err(_) => panic!(concat!($what, " must succeed")) } }; }
fn good_digest() -> String { "0123456789abcdef".repeat(4) }
fn good_sig() -> String { "a".repeat(128) }
async fn publish(c: &Ctx, version: &str, digest: &str, sig: &str) -> Result<Value, orbit_core::Error> {
 updates::publish(State(c.state.clone()), c.headers.clone(), Json(updates::PublishRequest { version: version.into(), channel: None, digest: digest.into(), signature: sig.into(), artifact_url: format!("https://releases.example.invalid/orbit-{version}.bin"), notes: Some("notes".into()) })).await.map(|Json(v)| v).map_err(|e| e.0)
}
async fn check(c: &Ctx, current: &str) -> Value {
 let Json(r) = ok!(updates::check(State(c.state.clone()), c.headers.clone(), Query(updates::CheckQuery { channel: None, current: Some(current.into()) })).await, "check");
 serde_json::to_value(&r).unwrap()
}
#[tokio::test]
async fn publish_stores_row_lists_and_audits() {
 let pool = pool().await;let c = ctx(&pool, "store").await;
 let out = ok!(publish(&c, "0.2.0", &good_digest(), &good_sig()).await, "publish");
 assert_eq!(out["published"], json!(true));
 assert_eq!(out["version"], json!("0.2.0"));
 let Json(list) = ok!(updates::releases(State(c.state.clone()), c.headers.clone()).await, "releases");
 assert!(list["items"].as_array().unwrap().iter().any(|r| r["version"] == "0.2.0" && r["digest"] == good_digest()), "published row must list");
 let op: Option<String> = sqlx::query_scalar("SELECT operation FROM audit_events WHERE owner_id=$1 AND operation='UPDATE_PUBLISHED'").bind(c.owner).fetch_optional(&pool).await.unwrap();
 assert_eq!(op.as_deref(), Some("UPDATE_PUBLISHED"));
}
#[tokio::test]
async fn tampered_digest_format_rejected() {
 let pool = pool().await;let c = ctx(&pool, "digest").await;
 let short = "0123456789abcdef".repeat(3);
 for bad in ["not-hex".to_string(), "z".repeat(64), short] {
  let err = publish(&c, "0.2.1", &bad, &good_sig()).await.err().unwrap_or_else(|| panic!("digest {bad:?} must be rejected"));
  assert!(matches!(err, orbit_core::Error::Validation(_)), "digest format must 422");
  assert!(err.to_string().contains("digest"), "error names the digest: {err}");
 }
}
#[tokio::test]
async fn malformed_signature_format_rejected() {
 let pool = pool().await;let c = ctx(&pool, "sig").await;
 for bad in [String::new(), "!!!".to_string(), "ab".to_string()] {
  let err = publish(&c, "0.2.2", &good_digest(), &bad).await.err().unwrap_or_else(|| panic!("signature {bad:?} must be rejected"));
  assert!(matches!(err, orbit_core::Error::Validation(_)), "signature format must 422");
  assert!(err.to_string().contains("signature"), "error names the signature: {err}");
 }
}
#[tokio::test]
async fn check_reports_update_available_when_newer() {
 let pool = pool().await;let c = ctx(&pool, "newer").await;
 ok!(publish(&c, "0.3.0", &good_digest(), &good_sig()).await, "publish");
 let v = check(&c, "0.2.0").await;
 assert_eq!(v["update_available"], json!(true));
 assert_eq!(v["latest_version"], json!("0.3.0"));
 assert_eq!(v["digest"], json!(good_digest()));
}
#[tokio::test]
async fn check_reports_current_when_up_to_date() {
 let pool = pool().await;let c = ctx(&pool, "current").await;
 ok!(publish(&c, "0.4.0", &good_digest(), &good_sig()).await, "publish");
 let v = check(&c, "0.4.0").await;
 assert_eq!(v["update_available"], json!(false));
 assert_eq!(v["latest_version"], json!("0.4.0"));
}
#[tokio::test]
async fn check_reports_no_update_on_empty_channel() {
 let pool = pool().await;let c = ctx(&pool, "empty").await;
 let v = check(&c, "0.1.0").await;
 assert_eq!(v["update_available"], json!(false));
 assert_eq!(v["latest_version"], json!("0.1.0"));
}
