//! Password change + recovery-code regression: wrong-current 401,
//! bearer cannot change password, minted code single-use, wrong email
//! no-oracle 401, expired code rejected.
use axum::{Json, extract::State};
use axum::http::{HeaderMap, header};
use orbit_api::{ApiState, auth};
use sqlx::{PgPool, Row as _};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use uuid::Uuid;
async fn pool(tag:&str)->(PgPool,Option<String>,std::path::PathBuf){
 let t:String=Uuid::new_v4().simple().to_string()[..8].to_owned();
 let db=format!("orbit_pw_{}_{tag}_{t}",std::process::id());
 let admin=PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
 sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
 sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
 let pool=PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
 sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
 (pool,Some(db),std::env::temp_dir().join(format!("orbit-pw-{tag}-{}_{t}",std::process::id())))
}
async fn cleanup(pool:&PgPool,db:&Option<String>,key_dir:&std::path::Path){
 if let Some(db)=db.as_ref().filter(|d|d.starts_with("orbit_pw_")){
  pool.close().await;
  let admin=PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
  sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
  std::fs::remove_dir_all(key_dir).ok();
 }
}
struct Ctx{state:ApiState,headers:HeaderMap,email:String}
async fn ctx(pool:&PgPool,key_dir:&std::path::Path,tag:&str,password:&str)->Ctx{
 let owner=Uuid::new_v4();let principal=Uuid::new_v4();let email=format!("pw-{tag}-{owner}@example.invalid");
 let encoded=argon2::Argon2::default().hash_password(password.as_bytes(),&argon2::password_hash::SaltString::from_b64("cHctZml4dHVyZS1zYWx0").unwrap()).map(|p|p.to_string()).unwrap();
 sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t',$3)").bind(owner).bind(&email).bind(encoded).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'SYSTEM','INTERNAL','SYSTEM','orbit-worker')").bind(Uuid::new_v4()).bind(owner).execute(pool).await.unwrap();
 let token=format!("pw-token-{tag}-{owner}");let csrf=format!("pw-csrf-{tag}-{owner}");
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
 let base=std::env::temp_dir().join(format!("orbit-pw-{tag}-{owner}"));
 let mut headers=HeaderMap::new();
 headers.insert(header::COOKIE,format!("orbit_session={token}").parse().unwrap());
 headers.insert(header::ORIGIN,"http://127.0.0.1:8080".parse().unwrap());
 headers.insert("x-csrf-token",csrf.parse().unwrap());
 let state=ApiState{pool:pool.clone(),origin:"http://127.0.0.1:8080".into(),key_dir:key_dir.to_owned(),artifact_dir:base.join("artifacts"),nodes:orbit_api::computers::NodeHub::new()};
 Ctx{state,headers,email}
}
macro_rules! ok{($r:expr,$what:literal)=>{match $r{Ok(v)=>v,Err(_)=>panic!(concat!($what," must succeed"))}}}
fn bearer_of(plain:&str)->HeaderMap{let mut h=HeaderMap::new();h.insert(header::AUTHORIZATION,format!("Bearer {plain}").parse().unwrap());h}
#[tokio::test]
async fn change_password_round_trip(){
 let (pool,db,key_dir)=pool("roundtrip").await;let c=ctx(&pool,&key_dir,"roundtrip","initial-password-123").await;
 // Wrong current password → 401.
 let err=auth::change_password(State(c.state.clone()),c.headers.clone(),Json(auth::ChangePasswordRequest{current_password:"nope-nope-nope!".into(),new_password:"replacement-password-123".into()})).await.err().unwrap_or_else(||panic!("wrong current must fail"));
 assert!(matches!(err.0,orbit_core::Error::Unauthorized),"wrong current must 401");
 // Bearer token cannot change password (session-only).
 let berr=auth::change_password(State(c.state.clone()),bearer_of("whatever"),Json(auth::ChangePasswordRequest{current_password:"initial-password-123".into(),new_password:"replacement-password-123".into()})).await.err().unwrap_or_else(||panic!("bearer must fail"));
 assert!(matches!(berr.0,orbit_core::Error::Unauthorized|orbit_core::Error::Forbidden),"bearer must 401/403");
 // Correct change.
 let Json(done)=ok!(auth::change_password(State(c.state.clone()),c.headers.clone(),Json(auth::ChangePasswordRequest{current_password:"initial-password-123".into(),new_password:"replacement-password-123".into()})).await,"change");
 assert_eq!(done["changed"],serde_json::json!(true));
 // New password verifies via login path (hash check direct).
 let row=sqlx::query("SELECT password_hash FROM users WHERE email=$1").bind(&c.email).fetch_one(&pool).await.unwrap();
 let encoded:String=row.get("password_hash");
 assert!(argon2::Argon2::default().verify_password(b"replacement-password-123",&argon2::password_hash::PasswordHash::new(&encoded).unwrap()).is_ok(),"new hash must verify");
 cleanup(&pool,&db,&key_dir).await;
}
#[tokio::test]
async fn recovery_code_single_use_no_oracle_expiry(){
 let (pool,db,key_dir)=pool("recover").await;let c=ctx(&pool,&key_dir,"recover","initial-password-123").await;
 let Json(minted)=ok!(auth::mint_recovery_code(State(c.state.clone()),c.headers.clone()).await,"mint");
 let code=minted["recovery_code"].as_str().expect("code shown once").to_owned();
 // Wrong email + right code → identical 401 (no oracle).
 let err=auth::recover(State(c.state.clone()),c.headers.clone(),Json(auth::RecoverRequest{email:"nobody@example.invalid".into(),recovery_code:code.clone(),new_password:"fresh-password-12345".into()})).await.err().unwrap_or_else(||panic!("unknown email must 401"));
 assert!(matches!(err.0,orbit_core::Error::Unauthorized),"unknown email must 401");
 // Real recovery burns the code.
 let resp=ok!(auth::recover(State(c.state.clone()),c.headers.clone(),Json(auth::RecoverRequest{email:c.email.clone(),recovery_code:code.clone(),new_password:"fresh-password-12345".into()})).await,"recover");
 assert_eq!(axum::response::IntoResponse::into_response(resp).status().as_u16(),200,"recover must 200");
 // Reuse of the same code → 401.
 let err2=auth::recover(State(c.state.clone()),c.headers.clone(),Json(auth::RecoverRequest{email:c.email.clone(),recovery_code:code,new_password:"another-password-123".into()})).await.err().unwrap_or_else(||panic!("reused code must 401"));
 assert!(matches!(err2.0,orbit_core::Error::Unauthorized),"reused code must 401");
 // Recovery wiped all sessions; re-seat one so mint2 authenticates.
 let owner:Uuid=sqlx::query("SELECT id FROM users WHERE email=$1").bind(&c.email).fetch_one(&pool).await.unwrap().get("id");
 let principal:Uuid=sqlx::query("SELECT id FROM principals WHERE owner_id=$1 AND principal_type='WEB_USER' LIMIT 1").bind(owner).fetch_one(&pool).await.unwrap().get("id");
 let cookie=c.headers.get(axum::http::header::COOKIE).unwrap().to_str().unwrap().strip_prefix("orbit_session=").unwrap().to_owned();
 let csrf=c.headers.get("x-csrf-token").unwrap().to_str().unwrap().to_owned();
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&cookie)).bind(&csrf).execute(&pool).await.unwrap();
 // Expired code → 401.
 let Json(m2)=ok!(auth::mint_recovery_code(State(c.state.clone()),c.headers.clone()).await,"mint2");
 let code2=m2["recovery_code"].as_str().unwrap().to_owned();
 sqlx::query("UPDATE installation SET recovery_token_expires=now()-interval '1 hour' WHERE singleton").execute(&pool).await.unwrap();
 let err3=auth::recover(State(c.state.clone()),c.headers.clone(),Json(auth::RecoverRequest{email:c.email.clone(),recovery_code:code2,new_password:"another-password-123".into()})).await.err().unwrap_or_else(||panic!("expired code must 401"));
 assert!(matches!(err3.0,orbit_core::Error::Unauthorized),"expired code must 401");
 cleanup(&pool,&db,&key_dir).await;
}
