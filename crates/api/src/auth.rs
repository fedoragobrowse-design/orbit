use crate::{ApiError,ApiState,AuthSession};
use axum::{extract::State,http::{HeaderMap,header},response::{IntoResponse,Response},routing::{get,post},Json,Router};
use argon2::{Argon2,PasswordHasher,PasswordVerifier,password_hash::{SaltString,PasswordHash}};
use orbit_core::{Error,OwnerScope};
use rand::{RngCore,rngs::OsRng};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use sqlx::{Row,Postgres,Transaction};
use uuid::Uuid;
use utoipa::ToSchema;
use subtle::ConstantTimeEq;

pub fn hash(value:&str)->String {hex::encode(Sha256::digest(value.as_bytes()))}
pub fn random()->String {let mut bytes=[0u8;32];OsRng.fill_bytes(&mut bytes);hex::encode(bytes)}
pub fn origin(state:&ApiState,headers:&HeaderMap)->Result<(),ApiError>{if headers.get(header::ORIGIN).and_then(|h|h.to_str().ok())!=Some(state.origin.as_str()){return Err(Error::Forbidden.into())}Ok(())}
pub async fn ensure_setup(state:&ApiState)->orbit_core::Result<()> {
 tokio::fs::create_dir_all(&state.key_dir).await.map_err(|_|Error::Unavailable("key directory unavailable".into()))?;
 let mut tx=state.pool.begin().await?;
 let row=sqlx::query("SELECT owner_id,setup_token_hash FROM installation WHERE singleton FOR UPDATE").fetch_one(&mut *tx).await?;
 if row.get::<Option<Uuid>,_>("owner_id").is_none() && row.get::<Option<String>,_>("setup_token_hash").is_none(){
  let token=random();let path=state.key_dir.join("bootstrap-token");
  use tokio::io::AsyncWriteExt;
  let mut options=tokio::fs::OpenOptions::new();options.write(true).create_new(true);
  #[cfg(unix)] options.mode(0o600);
  let mut file=options.open(path).await.map_err(|_|Error::Unavailable("bootstrap token file unavailable; preserve existing keys".into()))?;
  file.write_all(token.as_bytes()).await.map_err(|_|Error::Unavailable("bootstrap token persistence failed".into()))?;file.sync_all().await.map_err(|_|Error::Unavailable("bootstrap token persistence failed".into()))?;
  sqlx::query("UPDATE installation SET setup_token_hash=$1 WHERE singleton").bind(hash(&token)).execute(&mut *tx).await?;
 }
 tx.commit().await?;Ok(())
}
pub async fn bootstrap_token(state:&ApiState)->orbit_core::Result<String>{
 let row=sqlx::query("SELECT owner_id,setup_token_hash FROM installation WHERE singleton").fetch_one(&state.pool).await?;
 if row.get::<Option<Uuid>,_>("owner_id").is_some(){return Err(Error::Conflict("owner already configured".into()))}
 let token=tokio::fs::read_to_string(state.key_dir.join("bootstrap-token")).await.map_err(|_|Error::Unavailable("bootstrap token file unavailable".into()))?;
 if row.get::<Option<String>,_>("setup_token_hash")!=Some(hash(&token)){return Err(Error::Unavailable("bootstrap token does not match installation".into()))}Ok(token)
}
pub async fn authenticate(state:&ApiState,headers:&HeaderMap,mutation:bool)->Result<AuthSession,ApiError>{
 if let Some(raw)=crate::tokens::bearer(headers){
  let full=format!("{}{raw}",crate::tokens::PREFIX);
  let row=sqlx::query("SELECT id,owner_id FROM api_tokens WHERE token_hash=$1 AND revoked=false").bind(hash(&full)).fetch_optional(&state.pool).await?.ok_or(Error::Unauthorized)?;
  let owner:Uuid=row.get("owner_id");
  sqlx::query("UPDATE api_tokens SET last_used=now() WHERE id=$1").bind(row.get::<Uuid,_>("id")).execute(&state.pool).await?;
  let principal=sqlx::query("SELECT id FROM principals WHERE owner_id=$1 AND principal_type='SYSTEM' LIMIT 1").bind(owner).fetch_optional(&state.pool).await?.map(|r|r.get("id")).unwrap_or(Uuid::nil());
  return Ok(AuthSession{scope:OwnerScope{owner_id:owner,principal_id:principal},csrf_token:String::new(),session_id:Uuid::nil()});
 }
 let token=headers.get(header::COOKIE).and_then(|v|v.to_str().ok()).and_then(|v|v.split(';').map(str::trim).find_map(|p|p.strip_prefix("orbit_session="))).ok_or(Error::Unauthorized)?;
 let row=sqlx::query("SELECT id,owner_id,principal_id,csrf_token FROM sessions WHERE token_hash=$1 AND expires_at>now()").bind(hash(token)).fetch_optional(&state.pool).await?.ok_or(Error::Unauthorized)?;
 let csrf:String=row.get("csrf_token");
 if mutation {origin(state,headers)?;let supplied=headers.get("x-csrf-token").and_then(|v|v.to_str().ok()).unwrap_or("");if !bool::from(csrf.as_bytes().ct_eq(supplied.as_bytes())){return Err(Error::Forbidden.into())}}
 Ok(AuthSession{scope:OwnerScope{owner_id:row.get("owner_id"),principal_id:row.get("principal_id")},csrf_token:csrf,session_id:row.get("id")})
}
#[derive(Deserialize,ToSchema)] #[serde(deny_unknown_fields)]
pub struct SetupRequest {pub setup_token:String,pub email:String,pub display_name:String,pub password:String}
#[derive(Deserialize,ToSchema)] #[serde(deny_unknown_fields)]
pub struct LoginRequest {pub email:String,pub password:String}
#[derive(Serialize,ToSchema)]
pub struct User {pub id:Uuid,pub email:String,pub display_name:String}
#[derive(Serialize,ToSchema)]
pub struct SessionResponse {pub user:User,pub csrf_token:String}
fn cookie(state:&ApiState,token:&str)->String{format!("orbit_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000{}",if state.origin.starts_with("https://"){"; Secure"}else{""})}
async fn session(tx:&mut Transaction<'_,Postgres>,state:&ApiState,user:User)->Result<Response,ApiError>{
 let principal=Uuid::new_v4();let id=Uuid::new_v4();let token=random();let csrf=random();
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','PASSWORD','OWNER_AUTHENTICATED','web')").bind(principal).bind(user.id).execute(&mut **tx).await?;
 sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '30 days')").bind(id).bind(user.id).bind(principal).bind(hash(&token)).bind(&csrf).execute(&mut **tx).await?;
 Ok(([(header::SET_COOKIE,cookie(state,&token))],Json(SessionResponse{user,csrf_token:csrf})).into_response())
}
#[utoipa::path(post,path="/api/v1/auth/setup",request_body=SetupRequest,responses((status=200,body=SessionResponse),(status=409,description="Owner configured")))]
pub async fn setup(State(state):State<ApiState>,headers:HeaderMap,Json(input):Json<SetupRequest>)->Result<Response,ApiError>{
 origin(&state,&headers)?;
 let email=input.email.trim().to_lowercase();let display=input.display_name.trim();
 if !email.contains('@')||email.len()>254||display.is_empty()||display.len()>100||input.password.len()<12||input.password.len()>1024{return Err(Error::Validation("valid email, display name and 12–1024 character password required".into()).into())}
 let password=input.password;let encoded=tokio::task::spawn_blocking(move||Argon2::default().hash_password(password.as_bytes(),&SaltString::generate(&mut OsRng)).map(|p|p.to_string())).await.map_err(|_|Error::Unavailable("password hashing unavailable".into()))?.map_err(|_|Error::Unavailable("password hashing failed".into()))?;
 let mut tx=state.pool.begin().await?;
 let row=sqlx::query("SELECT owner_id,setup_token_hash FROM installation WHERE singleton FOR UPDATE").fetch_one(&mut *tx).await?;
 if row.get::<Option<Uuid>,_>("owner_id").is_some(){return Err(Error::Conflict("owner already configured".into()).into())}
 if row.get::<Option<String>,_>("setup_token_hash").as_deref().map(|s|bool::from(s.as_bytes().ct_eq(hash(&input.setup_token).as_bytes()))).unwrap_or(false)!=true{return Err(Error::Forbidden.into())}
 let id=Uuid::new_v4();
 sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,$3,$4)").bind(id).bind(&email).bind(display).bind(encoded).execute(&mut *tx).await?;
 sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(id).execute(&mut *tx).await?;
 sqlx::query("INSERT INTO settings(owner_id) VALUES($1)").bind(id).execute(&mut *tx).await?;
 sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'SYSTEM','INTERNAL','SYSTEM','orbit-worker')").bind(Uuid::new_v4()).bind(id).execute(&mut *tx).await?;
 sqlx::query("UPDATE installation SET owner_id=$1,setup_token_hash=NULL WHERE singleton").bind(id).execute(&mut *tx).await?;
 let response=session(&mut tx,&state,User{id,email,display_name:display.to_owned()}).await?;tx.commit().await?;
 let _=tokio::fs::remove_file(state.key_dir.join("bootstrap-token")).await;
 Ok(response)
}
#[utoipa::path(post,path="/api/v1/auth/login",request_body=LoginRequest,responses((status=200,body=SessionResponse),(status=401,description="Invalid credentials")))]
pub async fn login(State(state):State<ApiState>,headers:HeaderMap,Json(input):Json<LoginRequest>)->Result<Response,ApiError>{
 origin(&state,&headers)?;
 if input.email.len()>254||input.password.len()>1024{return Err(Error::Unauthorized.into())}
 let email=input.email.trim().to_lowercase();
 let ipf=headers.get("x-forwarded-for").and_then(|v|v.to_str().ok()).unwrap_or("").split(',').next().unwrap_or("").trim();
 // Per-IP+email composite bucket: one attacker's failures must not lock out
 // the owner on another egress IP. Follow-up: axum ConnectInfo peer IP.
 let attempts:i32=sqlx::query_scalar("INSERT INTO login_attempts(key_hash,attempts,window_start) VALUES($1,1,now()) ON CONFLICT(key_hash) DO UPDATE SET attempts=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN 1 ELSE login_attempts.attempts+1 END,window_start=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN now() ELSE login_attempts.window_start END RETURNING attempts").bind(hash(&format!("{ipf}:{email}"))).fetch_one(&state.pool).await?;
 // Global per-email backstop: rotating X-Forwarded-For must not grant
 // unbounded guesses (100/15min ceiling; ConnectInfo is the real fix).
 let global:i32=sqlx::query_scalar("INSERT INTO login_attempts(key_hash,attempts,window_start) VALUES($1,1,now()) ON CONFLICT(key_hash) DO UPDATE SET attempts=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN 1 ELSE login_attempts.attempts+1 END,window_start=CASE WHEN login_attempts.window_start<now()-interval '15 minutes' THEN now() ELSE login_attempts.window_start END RETURNING attempts").bind(hash(&format!("global:{email}"))).fetch_one(&state.pool).await?;
 if attempts>10||global>100{return Ok((axum::http::StatusCode::TOO_MANY_REQUESTS,Json(json!({"error":{"code":"RATE_LIMITED","message":"Try again later","request_id":Uuid::new_v4()}}))).into_response())}
 let row=sqlx::query("SELECT id,email,display_name,password_hash FROM users WHERE email=$1").bind(&email).fetch_optional(&state.pool).await?;
 let encoded=row.as_ref().map(|r|r.get::<String,_>("password_hash")).unwrap_or_else(||"$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
 let valid=tokio::task::spawn_blocking(move||PasswordHash::new(&encoded).map(|p|Argon2::default().verify_password(input.password.as_bytes(),&p).is_ok()).unwrap_or(false)).await.map_err(|_|Error::Unavailable("password verification unavailable".into()))?;
 if !valid{return Err(Error::Unauthorized.into())}let row=row.ok_or(Error::Unauthorized)?;
 let mut tx=state.pool.begin().await?;let response=session(&mut tx,&state,User{id:row.get("id"),email:row.get("email"),display_name:row.get("display_name")}).await?;tx.commit().await?;Ok(response)
}
#[utoipa::path(get,path="/api/v1/auth/session",responses((status=200,body=SessionResponse)))]
pub async fn current(State(state):State<ApiState>,headers:HeaderMap)->Result<Json<SessionResponse>,ApiError>{let auth=authenticate(&state,&headers,false).await?;let row=sqlx::query("SELECT id,email,display_name FROM users WHERE id=$1").bind(auth.scope.owner_id).fetch_one(&state.pool).await?;Ok(Json(SessionResponse{user:User{id:row.get("id"),email:row.get("email"),display_name:row.get("display_name")},csrf_token:auth.csrf_token}))}
#[utoipa::path(get,path="/api/v1/auth/status",responses((status=200,body=Value)))]
pub async fn status(State(state):State<ApiState>)->Result<Json<Value>,ApiError>{let row=sqlx::query("SELECT owner_id IS NOT NULL AS configured FROM installation WHERE singleton").fetch_one(&state.pool).await?;Ok(Json(json!({"configured":row.get::<bool,_>("configured")})))}
#[utoipa::path(post,path="/api/v1/auth/logout",responses((status=204,description="Revoked")))]
pub async fn logout(State(state):State<ApiState>,headers:HeaderMap)->Result<Response,ApiError>{let auth=authenticate(&state,&headers,true).await?;sqlx::query("DELETE FROM sessions WHERE owner_id=$1 AND id=$2").bind(auth.scope.owner_id).bind(auth.session_id).execute(&state.pool).await?;Ok((axum::http::StatusCode::NO_CONTENT,[(header::SET_COOKIE,format!("orbit_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{}",if state.origin.starts_with("https://"){"; Secure"}else{""}))]).into_response())}

pub fn router()->Router<ApiState>{Router::new().route("/api/v1/auth/status",get(status)).route("/api/v1/auth/setup",post(setup)).route("/api/v1/auth/login",post(login)).route("/api/v1/auth/logout",post(logout)).route("/api/v1/auth/session",get(current))}
