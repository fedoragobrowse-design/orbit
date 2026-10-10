//! E19b auth/freeze regression: frozen backup blocked, restore no-steal,
//! bearer cannot mint tokens, per-IP login buckets.
use axum::{Json, extract::{Path, State}};
use axum::http::{HeaderMap, header};
use orbit_api::{ApiState, ops};
use orbit_api::tokens::TokenCreate;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;
async fn pool(tag:&str)->(PgPool,Option<String>,std::path::PathBuf){
 let t:String=Uuid::new_v4().simple().to_string()[..8].to_owned();
 let db=format!("orbit_authz_{}_{tag}_{t}",std::process::id());
 let admin=PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
 sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
 sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
 let pool=PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
 sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
 (pool,Some(db),std::env::temp_dir().join(format!("orbit-authz-{tag}-{}_{t}",std::process::id())))
}
async fn cleanup(pool:&PgPool,db:&Option<String>,key_dir:&std::path::Path){
 if let Some(db)=db.as_ref().filter(|d|d.starts_with("orbit_authz_")){
  pool.close().await;
  let admin=PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
  sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
  std::fs::remove_dir_all(key_dir).ok();
 }
}
struct Ctx{state:ApiState,headers:HeaderMap,owner:Uuid,artifact_base:std::path::PathBuf}
async fn ctx(pool:&PgPool,key_dir:&std::path::Path,tag:&str)->Ctx{
 let owner=Uuid::new_v4();let principal=Uuid::new_v4();
 sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("authz-{tag}-{owner}@example.invalid")).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'SYSTEM','INTERNAL','SYSTEM','orbit-worker')").bind(Uuid::new_v4()).bind(owner).execute(pool).await.unwrap();
 let token=format!("authz-token-{tag}-{owner}");let csrf=format!("authz-csrf-{tag}-{owner}");
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
 let base=std::env::temp_dir().join(format!("orbit-authz-{tag}-{owner}"));
 let mut headers=HeaderMap::new();
 headers.insert(header::COOKIE,format!("orbit_session={token}").parse().unwrap());
 headers.insert(header::ORIGIN,"http://127.0.0.1:8080".parse().unwrap());
 headers.insert("x-csrf-token",csrf.parse().unwrap());
 let state=ApiState{pool:pool.clone(),origin:"http://127.0.0.1:8080".into(),key_dir:key_dir.to_owned(),artifact_dir:base.join("artifacts"),nodes:orbit_api::computers::NodeHub::new()};
 Ctx{state,headers,owner,artifact_base:base}
}
macro_rules! ok{($r:expr,$what:literal)=>{match $r{Ok(v)=>v,Err(_)=>panic!(concat!($what," must succeed"))}}}
fn bearer_of(plain:&str)->HeaderMap{let mut h=HeaderMap::new();h.insert(header::AUTHORIZATION,format!("Bearer {plain}").parse().unwrap());h}
#[tokio::test]
async fn frozen_backup_blocked_resume_restores(){
 let (pool,db,key_dir)=pool("freeze").await;let c=ctx(&pool,&key_dir,"freeze").await;
 let Json(killed)=ok!(ops::kill(State(c.state.clone()),c.headers.clone()).await,"kill");
 assert_eq!(killed["frozen"],json!(true));
 let err=ops::backup(State(c.state.clone()),c.headers.clone()).await.err().unwrap_or_else(||panic!("backup while frozen must fail"));
 assert!(matches!(err.0,orbit_core::Error::Forbidden),"frozen backup must 403");
 let Json(resumed)=ok!(ops::resume(State(c.state.clone()),c.headers.clone()).await,"resume");
 assert_eq!(resumed["frozen"],json!(false));
 let Json(bk)=ok!(ops::backup(State(c.state.clone()),c.headers.clone()).await,"backup after resume");
 assert!(bk["artifact_id"].as_str().is_some(),"backup returns artifact id");
 let _=std::fs::remove_dir_all(&c.artifact_base);cleanup(&pool,&db,&key_dir).await;
}
#[tokio::test]
async fn restore_does_not_reassign_foreign_rows(){
 let (pool,db,key_dir)=pool("nosteal").await;let a=ctx(&pool,&key_dir,"nosteal-a").await;let b=ctx(&pool,&key_dir,"nosteal-b").await;
 let mem=Uuid::new_v4();
 // B owns a row, backs it up, then loses it; A claims the same id meanwhile.
 sqlx::query("INSERT INTO memory_records(id,owner_id,type,subject,normalized_subject,entity_key,value,source,source_reference,confidence,trust_level,privacy_class) VALUES($1,$2,'PERSON','Ada','ada','person:ada','{\"role\":\"owner\"}','test','ops',0.9,'OWNER_AUTHENTICATED','PRIVATE')").bind(mem).bind(b.owner).execute(&pool).await.unwrap();
 let Json(bk)=ok!(ops::backup(State(b.state.clone()),b.headers.clone()).await,"backup");
 let artifact=Uuid::parse_str(bk["artifact_id"].as_str().unwrap()).unwrap();
 // Cross-owner artifact is unreadable: the secrets store scopes rows by owner.
 assert!(ops::restore(State(a.state.clone()),a.headers.clone(),Json(ops::RestoreRequest{artifact_id:artifact})).await.is_err(),"foreign artifact must fail closed");
 sqlx::query("DELETE FROM memory_records WHERE owner_id=$1 AND id=$2").bind(b.owner).bind(mem).execute(&pool).await.unwrap();
 sqlx::query("INSERT INTO memory_records(id,owner_id,type,subject,normalized_subject,entity_key,value,source,source_reference,confidence,trust_level,privacy_class) VALUES($1,$2,'PERSON','Ada','ada','person:ada','{\"role\":\"owner\"}','test','ops',0.9,'OWNER_AUTHENTICATED','PRIVATE')").bind(mem).bind(a.owner).execute(&pool).await.unwrap();
 // B restores: the colliding id is skipped, never reassigned to the caller.
 let Json(rs)=ok!(ops::restore(State(b.state.clone()),b.headers.clone(),Json(ops::RestoreRequest{artifact_id:artifact})).await,"restore as second owner");
 assert_eq!(rs["restored"].as_str().unwrap(),artifact.to_string());
 let owner:Uuid=sqlx::query_scalar("SELECT owner_id FROM memory_records WHERE id=$1").bind(mem).fetch_one(&pool).await.unwrap();
 assert_eq!(owner,a.owner,"foreign row keeps its original owner");
 let b_rows:i64=sqlx::query_scalar("SELECT count(*) FROM memory_records WHERE owner_id=$1 AND id=$2").bind(b.owner).bind(mem).fetch_one(&pool).await.unwrap();
 assert_eq!(b_rows,0,"second owner gains no copy of the foreign id");
 let _=std::fs::remove_dir_all(&a.artifact_base);let _=std::fs::remove_dir_all(&b.artifact_base);cleanup(&pool,&db,&key_dir).await;
}
#[tokio::test]
async fn bearer_cannot_mint_or_revoke_session_can(){
 let (pool,db,key_dir)=pool("bearer").await;let c=ctx(&pool,&key_dir,"bearer").await;
 let Json(made)=ok!(orbit_api::tokens::create_token(State(c.state.clone()),c.headers.clone(),Json(TokenCreate{name:"laptop".into()})).await,"session create");
 let plain=made["token"].as_str().unwrap().to_owned();
 let bearer=bearer_of(&plain);
 let err=orbit_api::tokens::create_token(State(c.state.clone()),bearer.clone(),Json(TokenCreate{name:"evil".into()})).await.err().unwrap_or_else(||panic!("bearer mint must fail"));
 assert!(matches!(err.0,orbit_core::Error::Forbidden),"bearer mint must 403");
 let id:Uuid=made["id"].as_str().unwrap().parse().unwrap();
 let err=orbit_api::tokens::revoke_token(State(c.state.clone()),bearer.clone(),Path(id)).await.err().unwrap_or_else(||panic!("bearer revoke must fail"));
 assert!(matches!(err.0,orbit_core::Error::Forbidden),"bearer revoke must 403");
 ok!(orbit_api::tokens::revoke_token(State(c.state.clone()),c.headers.clone(),Path(id)).await,"session revoke");
 let listed:Value=sqlx::query_scalar("SELECT to_jsonb(t) FROM api_tokens t WHERE id=$1").bind(id).fetch_one(&pool).await.unwrap();
 assert_eq!(listed["revoked"],json!(true));
 let _=std::fs::remove_dir_all(&c.artifact_base);cleanup(&pool,&db,&key_dir).await;
}
fn login_headers(ip:&str)->HeaderMap{let mut h=HeaderMap::new();h.insert(header::ORIGIN,"http://127.0.0.1:8080".parse().unwrap());h.insert("x-forwarded-for",ip.parse().unwrap());h}
async fn login_status(state:&ApiState,ip:&str,email:&str)->u16{
 match orbit_api::auth::login(State(state.clone()),login_headers(ip),Json(orbit_api::auth::LoginRequest{email:email.into(),password:"wrong-password-123".into()})).await{
  Ok(resp)=>(resp.status()).as_u16(),
  Err(_)=>401,
 }
}
#[tokio::test]
async fn login_buckets_are_per_ip(){
 let (pool,db,key_dir)=pool("loginip").await;let c=ctx(&pool,&key_dir,"loginip").await;
 let email=format!("authz-loginip-{}@example.invalid",c.owner);
 for _ in 0..10{assert_eq!(login_status(&c.state,"10.9.9.9",&email).await,401);}
 assert_eq!(login_status(&c.state,"10.9.9.9",&email).await,429,"eleventh failure from A must RATE_LIMIT");
 let other=login_status(&c.state,"10.9.9.10",&email).await;
 assert!(other==401||other==200,"clean IP must not inherit A's lockout, got {other}");
 assert_ne!(other,429);
 let _=std::fs::remove_dir_all(&c.artifact_base);cleanup(&pool,&db,&key_dir).await;
}
