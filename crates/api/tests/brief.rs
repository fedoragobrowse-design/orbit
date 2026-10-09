//! Morning-brief live test: seeds one pending approval, one notification,
//! one open task, one event, one enabled automation; asserts the brief
//! aggregates all of them and that the empty brief still returns counts.
use axum::{Json, extract::State};
use axum::http::{HeaderMap, header};
use orbit_api::{ApiState, brief};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;
fn db_url() -> String { std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://orbit_test:orbit_test@127.0.0.1:55432/orbit_test".into()) }
async fn pool() -> PgPool { let pool = PgPool::connect(&db_url()).await.expect("owned test postgres reachable"); sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply"); pool }
async fn ctx(pool: &PgPool, tag: &str) -> (ApiState, HeaderMap, Uuid) {
 let owner = Uuid::new_v4();let principal = Uuid::new_v4();
 sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("brief-{tag}-{owner}@example.invalid")).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
 let token = format!("brief-token-{tag}-{owner}");let csrf = format!("brief-csrf-{tag}-{owner}");
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
 let key_dir = std::env::temp_dir().join(format!("orbit-brief-{tag}-{owner}"));let artifact_dir = key_dir.join("artifacts");
 let origin = "http://127.0.0.1:8080".to_string();let mut headers = HeaderMap::new();
 headers.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());headers.insert(header::ORIGIN, origin.parse().unwrap());headers.insert("x-csrf-token", csrf.parse().unwrap());
 (ApiState { pool: pool.clone(), origin, key_dir, artifact_dir, nodes: orbit_api::computers::NodeHub::new() }, headers, owner)
}
#[tokio::test]
async fn brief_aggregates_seeded_rows_and_empty_counts() {
 let pool = pool().await;let (state, headers, owner) = ctx(&pool, "seed").await;
 let Json(empty) = match brief::brief(State(state.clone()), headers.clone()).await { Ok(Json(v)) => Json(v), Err(_) => panic!("empty brief must succeed") };
 assert_eq!(empty["approvals_pending"], json!(0));assert_eq!(empty["tasks_open"], json!(0));
 let principal: Uuid = sqlx::query_scalar("SELECT id FROM principals WHERE owner_id=$1").bind(owner).fetch_one(&pool).await.unwrap();
 let ev = Uuid::new_v4();sqlx::query("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,'USER_MESSAGE','test',$3,'{}','OWNER_AUTHENTICATED','PRIVATE',$4,'brief-seed')").bind(ev).bind(owner).bind(principal).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
 let task = Uuid::new_v4();sqlx::query("INSERT INTO tasks(id,owner_id,event_id,principal_id,correlation_id,title,state,checkpoint,expires_at) VALUES($1,$2,$3,$4,$5,'brief task','QUEUED','{\"phase\":\"NOTIFICATION\"}',now()+interval '1 hour')").bind(task).bind(owner).bind(ev).bind(principal).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
 let call = Uuid::new_v4();sqlx::query("INSERT INTO tool_calls(id,owner_id,task_id,proposal_key,proposal_digest,snapshot,action_hash,descriptor,descriptor_digest,risk,policy_decision,state) VALUES($1,$2,$3,'brief','brief','{}','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}','brief','{}','{}','WAITING_FOR_APPROVAL')").bind(call).bind(owner).bind(task).execute(&pool).await.unwrap();
 sqlx::query("INSERT INTO approvals(id,owner_id,task_id,call_id,snapshot,action_hash,risk,reasons,preview,state,expires_at) VALUES($1,$2,$3,$4,'{}','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}','[]','{}','PENDING',now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(task).bind(call).execute(&pool).await.unwrap();
 sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body) VALUES($1,$2,$3,$4,'INFO','brief note','hello')").bind(Uuid::new_v4()).bind(owner).bind(task).bind(Uuid::new_v4()).execute(&pool).await.unwrap();
 sqlx::query("INSERT INTO automations(id,owner_id,enabled,\"trigger\",filters,instructions,policy_scope,model_role,notification_behavior,timezone) VALUES($1,$2,true,'{\"kind\":\"timer\",\"run_at\":\"2030-01-01T00:00:00Z\"}','[]','brief','{}','FAST','IN_APP','UTC')").bind(Uuid::new_v4()).bind(owner).execute(&pool).await.unwrap();
 let Json(full) = match brief::brief(State(state.clone()), headers.clone()).await { Ok(Json(v)) => Json(v), Err(_) => panic!("seeded brief must succeed") };
 assert_eq!(full["approvals_pending"], json!(1));assert_eq!(full["notifications_unread"], json!(1));assert_eq!(full["tasks_open"], json!(1));
 assert_eq!(full["recent_events"].as_array().map(Vec::len).unwrap_or(0), 1);assert_eq!(full["automations_enabled"].as_array().map(Vec::len).unwrap_or(0), 1);
 assert!(full["generated_at"].is_string(), "brief stamps generation time");
 let _ = std::fs::remove_dir_all(state.key_dir.clone());
}
