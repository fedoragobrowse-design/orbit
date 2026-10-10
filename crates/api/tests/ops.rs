//! Ops slice: kill switch, automation dry-run, encrypted backup/restore.
//! Owned test postgres only (default 127.0.0.1:55432 orbit_test). Never the personal deployment.
use axum::{Json, extract::State};
use axum::http::{HeaderMap, header};
use orbit_api::{ApiState, ops};
use orbit_core::EventType;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
 // Hermetic per-run database + key dir: the shared orbit_test DB accumulates secret rows encrypted under keys this run cannot reopen.
 if let Ok(url) = std::env::var("DATABASE_URL") {
  let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
  sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
  return (pool, None, std::env::var("ORBIT_TEST_KEY_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir().join("orbit-test-secrets")));
 }
 let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
 let db = format!("orbit_ops_{}_{tag}", std::process::id());
 let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
 sqlx::query(&format!("DROP DATABASE IF EXISTS {db}")).execute(&admin).await.unwrap();
 sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
 let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
 sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
 (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
 if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_ops_")) {
  pool.close().await;
  let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
  sqlx::query(&format!("DROP DATABASE IF EXISTS {db}")).execute(&admin).await.unwrap();
  std::fs::remove_dir_all(key_dir).ok();
 }
}
struct Ctx { state: ApiState, scope: orbit_core::OwnerScope, headers: HeaderMap, key_dir: std::path::PathBuf, artifact_dir: std::path::PathBuf }
async fn ctx(pool: &PgPool, tag: &str, key_dir: &std::path::Path) -> Ctx {
 let owner = Uuid::new_v4();let principal = Uuid::new_v4();
 sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("ops-{tag}-{owner}@example.invalid")).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
 let token = format!("ops-token-{tag}-{owner}");let csrf = format!("ops-csrf-{tag}-{owner}");
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
 let key_dir = key_dir.to_owned();
 let base = std::env::temp_dir().join(format!("orbit-ops-{tag}-{owner}"));
 let artifact_dir = base.join("artifacts");
 let origin = "http://127.0.0.1:8080".to_string();
 let mut headers = HeaderMap::new();
 headers.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
 headers.insert(header::ORIGIN, origin.parse().unwrap());
 headers.insert("x-csrf-token", csrf.parse().unwrap());
 let state = ApiState { pool: pool.clone(), origin, key_dir: key_dir.clone(), artifact_dir: artifact_dir.clone(), nodes: orbit_api::computers::NodeHub::new() };
 Ctx { state, scope: orbit_core::OwnerScope { owner_id: owner, principal_id: principal }, headers, key_dir, artifact_dir }
}
macro_rules! ok { ($r:expr,$what:literal) => { match $r { Ok(v) => v, Err(_) => panic!(concat!($what, " must succeed")) } }; }
async fn publish(state: &ApiState, headers: &HeaderMap, key: &str) -> Result<Value, orbit_core::Error> {
 orbit_api::foundation::publish(State(state.clone()), headers.clone(), Json(orbit_api::foundation::PublishRequest { event_type: EventType::UserMessage, payload: json!({"text": "ops probe"}), source_event_key: key.into(), privacy_class: None })).await.map(|Json(v)| serde_json::to_value(v).unwrap()).map_err(|e| e.0)
}
fn must_fail<T>(r: Result<T, orbit_api::ApiError>, what: &str) { assert!(r.is_err(), "{what} must fail while frozen"); }
#[tokio::test]
async fn kill_switch_freezes_mutations_reads_stay_open() {
 let (pool, db, key_dir) = pool().await;let c = ctx(&pool, "kill", &key_dir).await;
 ok!(publish(&c.state, &c.headers, "ops-kill-before").await, "publish before kill");
 // Engage.
 let Json(killed) = ok!(ops::kill(State(c.state.clone()), c.headers.clone()).await, "kill");
 assert_eq!(killed["frozen"], json!(true));
 // Mutations through the central guard now 403: events + automations create.
 let err = publish(&c.state, &c.headers, "ops-kill-during").await.err().unwrap_or_else(|| panic!("publish while frozen must fail"));
 assert!(matches!(err, orbit_core::Error::Forbidden), "publish while frozen must 403");
 must_fail(orbit_api::automations::create_automation(State(c.state.clone()), c.headers.clone(), Json(orbit_api::automations::CreateAutomationRequest { trigger: json!({"kind":"timer","run_at":"2030-01-01T00:00:00Z"}), filters: Value::Null, agent_id: None, instructions: "ops".into(), policy_scope: Value::Null, model_role: "FAST".into(), notification_behavior: "IN_APP".into(), timezone: "UTC".into(), enabled: true })).await.map(|Json(v)| v), "automation create");
 // Marketplace installs go through the same guard: frozen means 403 here too.
 must_fail(orbit_api::marketplace::install(State(c.state.clone()), c.headers.clone(), Json(orbit_api::marketplace::InstallRequest { name: "orbit-test".into(), manifest: None, allow_unsigned: None, approved_capabilities: None, accept_trust_level: None })).await.map(|Json(v)| v), "marketplace install");
 // Reads stay open: approvals inbox + ops status + automation dry-run path (preview read).
 let _ = ok!(orbit_api::gateway::list_approvals(State(c.state.clone()), c.headers.clone(), axum::extract::Query(orbit_api::gateway::Page { cursor: None, limit: None })).await, "approvals readable while frozen");
 let Json(st) = ok!(ops::status(State(c.state.clone()), c.headers.clone()).await, "status");
 assert_eq!(st["frozen"], json!(true));
 // Restore is a mutation: blocked while frozen.
 must_fail(ops::restore(State(c.state.clone()), c.headers.clone(), Json(ops::RestoreRequest { artifact_id: Uuid::new_v4() })).await.map(|Json(v)| v), "restore");
 // Resume lifts the freeze; mutations succeed again.
 let Json(resumed) = ok!(ops::resume(State(c.state.clone()), c.headers.clone()).await, "resume");
 assert_eq!(resumed["frozen"], json!(false));
 ok!(publish(&c.state, &c.headers, "ops-kill-after").await, "publish after resume");
 let _ = std::fs::remove_dir_all(c.artifact_dir.parent().unwrap());
 cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn revoke_nodes_marks_all_live_revoked() {
 let (pool, db, key_dir) = pool().await;let c = ctx(&pool, "revoke", &key_dir).await;
 let node = Uuid::new_v4();let principal = Uuid::new_v4();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'COMPUTER_NODE','node-key','OWNER_AUTHENTICATED','test')").bind(principal).bind(c.scope.owner_id).execute(&pool).await.unwrap();
 sqlx::query("INSERT INTO computer_nodes(id,owner_id,principal_id,public_key,session_hash,session_expires_at,display_name) VALUES($1,$2,$3,'k','h'||$1::text,now()+interval '1 hour','n')").bind(node).bind(c.scope.owner_id).bind(principal).execute(&pool).await.unwrap();
 let Json(out) = ok!(ops::revoke_nodes(State(c.state.clone()), c.headers.clone()).await, "revoke-nodes");
 assert_eq!(out["revoked"], json!(1));
 let revoked: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar("SELECT revoked_at FROM computer_nodes WHERE owner_id=$1 AND id=$2").bind(c.scope.owner_id).bind(node).fetch_one(&pool).await.unwrap();
 assert!(revoked.is_some(), "node must carry revoked_at after bulk revoke");
 let Json(out) = ok!(ops::revoke_nodes(State(c.state.clone()), c.headers.clone()).await, "revoke-nodes again");
 assert_eq!(out["revoked"], json!(0), "second run revokes nothing");
 let _ = std::fs::remove_dir_all(c.artifact_dir.parent().unwrap());
 cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn automation_dry_run_has_zero_side_effects() {
 let (pool, db, key_dir) = pool().await;let c = ctx(&pool, "dryrun", &key_dir).await;
 let Json(created) = ok!(orbit_api::automations::create_automation(State(c.state.clone()), c.headers.clone(), Json(orbit_api::automations::CreateAutomationRequest { trigger: json!({"kind":"timer","run_at":"2030-01-01T00:00:00Z"}), filters: Value::Null, agent_id: None, instructions: "summarize inbox".into(), policy_scope: Value::Null, model_role: "FAST".into(), notification_behavior: "IN_APP".into(), timezone: "UTC".into(), enabled: true })).await, "create automation");
 let id = created["id"].as_str().expect("automation id").to_string();
 let count = async || -> (i64, i64, i64) {
  let tasks: i64 = sqlx::query_scalar("SELECT count(*) FROM tasks WHERE owner_id=$1").bind(c.scope.owner_id).fetch_one(&pool).await.unwrap();
  let events: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE owner_id=$1").bind(c.scope.owner_id).fetch_one(&pool).await.unwrap();
  let fires: i64 = sqlx::query_scalar("SELECT count(*) FROM automation_fires WHERE owner_id=$1").bind(c.scope.owner_id).fetch_one(&pool).await.unwrap();
  (tasks, events, fires)
 };
 let before = count().await;
 let Json(dry) = ok!(ops::dry_run(State(c.state.clone()), c.headers.clone(), axum::extract::Path(Uuid::parse_str(&id).unwrap())).await, "dry-run");
 assert_eq!(dry["would_dispatch"]["consumer"], json!("foundation"));
 assert_eq!(dry["automation_id"].as_str().unwrap(), id);
 assert!(dry["preview"]["next_run"].is_string() || dry["preview"]["next_run"].is_null());
 let after = count().await;
 assert_eq!(before, after, "dry-run must create no task/event/fire rows");
 let _ = std::fs::remove_dir_all(c.artifact_dir.parent().unwrap());
 cleanup(&pool, &db, &key_dir).await;
}
#[tokio::test]
async fn encrypted_backup_round_trips_one_row() {
 let (pool, db, key_dir) = pool().await;let c = ctx(&pool, "backup", &key_dir).await;
 let mem = Uuid::new_v4();
 sqlx::query("INSERT INTO memory_records(id,owner_id,type,subject,normalized_subject,entity_key,value,source,source_reference,confidence,trust_level,privacy_class) VALUES($1,$2,'PERSON','Ada','ada','person:ada','{\"role\":\"owner\"}','test','ops',0.9,'OWNER_AUTHENTICATED','PRIVATE')").bind(mem).bind(c.scope.owner_id).execute(&pool).await.unwrap();
 let Json(bk) = ok!(ops::backup(State(c.state.clone()), c.headers.clone()).await, "backup");
 let artifact = Uuid::parse_str(bk["artifact_id"].as_str().expect("artifact id")).unwrap();
 // Ciphertext at rest must not contain the plaintext subject.
 let raws: Vec<Vec<u8>> = sqlx::query_scalar("SELECT ciphertext FROM secrets_metadata WHERE owner_id=$1").bind(c.scope.owner_id).fetch_all(&pool).await.unwrap();
 assert!(!raws.is_empty());
 for raw in &raws { assert!(!raw.windows(3).any(|w| w == b"Ada"), "backup ciphertext must not leak plaintext"); }
 // Delete the row, restore, assert identical content.
 sqlx::query("DELETE FROM memory_records WHERE owner_id=$1 AND id=$2").bind(c.scope.owner_id).bind(mem).execute(&pool).await.unwrap();
 let Json(rs) = ok!(ops::restore(State(c.state.clone()), c.headers.clone(), Json(ops::RestoreRequest { artifact_id: artifact })).await, "restore");
 assert_eq!(rs["restored"].as_str().unwrap(), artifact.to_string());
 let row: Value = sqlx::query_scalar("SELECT to_jsonb(m)-'owner_id' FROM memory_records m WHERE owner_id=$1 AND id=$2").bind(c.scope.owner_id).bind(mem).fetch_one(&pool).await.unwrap();
 assert_eq!(row["subject"], json!("Ada"));
 assert_eq!(row["value"], json!({"role":"owner"}));
 assert_eq!(row["type"], json!("PERSON"));
 assert_eq!(bk["tables"]["memory_records"], json!(1));
 let _ = std::fs::remove_dir_all(c.artifact_dir.parent().unwrap());
 cleanup(&pool, &db, &key_dir).await;
}
