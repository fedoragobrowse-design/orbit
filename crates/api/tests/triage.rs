//! Triage rules: CRUD validation + matcher unit tests (pure) + one live
//! applier test proving a matching rule labels the message and queues a
//! summary task whose drafts stay DRAFT (never sent). Hermetic DB, dropped after.
use orbit_api::email::{create_triage_rule, list_triage_rules, triage_matches, TriageRuleCreate};
use axum::{Json, extract::State};
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_triage_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db}")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_triage_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db}")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap, Uuid) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("triage-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("triage-token-{owner}");
    let csrf = format!("triage-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-triage-{owner}"));
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    headers.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    headers.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, headers, owner)
}
#[test]
fn matcher_is_plain_substring_only() {
    assert!(triage_matches(&json!({"from_contains": "ANA"}), "ana@example.com", "hi", ""));
    assert!(!triage_matches(&json!({"subject_contains": "invoice"}), "a@b.c", "hello", ""));
    assert!(triage_matches(&json!({"from_contains": "a", "subject_contains": "b"}), "a@x", "b here", ""));
    assert!(!triage_matches(&json!({}), "a", "b", ""));
    assert!(!triage_matches(&json!({"bogus": "x"}), "x", "x", "x"));
}
#[tokio::test]
async fn triage_rule_labels_message_and_queues_summary_task() {
    let (pool, db, key_dir) = pool().await;
    let (state, headers, owner) = ctx(&pool).await;
    let scope = orbit_core::OwnerScope { owner_id: owner, principal_id: sqlx::query_scalar("SELECT id FROM principals WHERE owner_id=$1").bind(owner).fetch_one(&pool).await.unwrap() };
    let Json(rule): Json<Value> = match create_triage_rule(State(state.clone()), headers.clone(), Json(TriageRuleCreate { name: "bills".into(), matcher: json!({"subject_contains": "invoice"}), action: json!({"label": "bills", "summarize": true}) })).await { Ok(Json(v)) => Json(v), Err(_) => panic!("rule create must succeed") };
    assert_eq!(rule["matcher"]["subject_contains"], json!("invoice"));
    let Json(list): Json<Value> = match list_triage_rules(State(state.clone()), headers.clone()).await { Ok(Json(v)) => Json(v), Err(_) => panic!("list must succeed") };
    assert_eq!(list["items"].as_array().map(Vec::len).unwrap_or(0), 1);
    let bad = create_triage_rule(State(state.clone()), headers.clone(), Json(TriageRuleCreate { name: "x".into(), matcher: json!({"regex": ".*"}), action: json!({}) })).await;
    assert!(bad.is_err(), "unknown matcher key must fail validation");
    let account = Uuid::new_v4();
    sqlx::query("INSERT INTO email_accounts(id,owner_id,name,config,imap_secret_id,smtp_secret_id) VALUES($1,$2,'t','{\"imap_host\":\"h\",\"imap_port\":993,\"smtp_host\":\"h\",\"smtp_port\":465,\"from_address\":\"me@example.invalid\",\"mailboxes\":[\"INBOX\"]}'::jsonb,$3,$3)").bind(account).bind(owner).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
    let message = Uuid::new_v4();
    sqlx::query("INSERT INTO email_messages(id,owner_id,account_id,mailbox,uidvalidity,uid,source_key,message_id,thread_references,metadata,body_text,attachments) VALUES($1,$2,$3,'INBOX',1,1,'k','m','[]',$4,'body','[]')").bind(message).bind(owner).bind(account).bind(json!({"from": "billing@shop.example", "subject": "Your invoice is ready"})).execute(&pool).await.unwrap();
    let mail = orbit_email::MailService { pool: pool.clone(), secrets: orbit_secrets::SecretStore::open(pool.clone(), &state.key_dir).await.unwrap() };
    let mut tx = pool.begin().await.unwrap();
    mail.apply_triage_rules(&scope, account, message, &json!({"from": "billing@shop.example", "subject": "Your invoice is ready"}), &mut tx).await.expect("applier must succeed");
    tx.commit().await.unwrap();
    let label: Option<String> = sqlx::query_scalar("SELECT metadata->>'triage_label' FROM email_messages WHERE id=$1").bind(message).fetch_one(&pool).await.unwrap();
    assert_eq!(label.as_deref(), Some("bills"), "message labeled");
    let tasks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE owner_id=$1 AND checkpoint->>'phase'='TRIAGE_SUMMARY'").bind(owner).fetch_one(&pool).await.unwrap();
    assert_eq!(tasks, 1, "one summary task queued");
    let drafts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_drafts WHERE owner_id=$1").bind(owner).fetch_one(&pool).await.unwrap();
    assert_eq!(drafts, 0, "no draft auto-created, let alone sent");
    let _ = std::fs::remove_dir_all(state.key_dir.clone());
    cleanup(&pool, &db, &key_dir).await;
}
