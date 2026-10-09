//! Owner-scoped signed release channel for OTA updates: publish stable releases, check for newer versions, list owner rows. Publish verifies the digest (64 hex sha256) and the signature (ed25519 format, same discipline as marketplace) then inserts plus an audit row; check and list are owner reads through the central guard.
use crate::{ApiError,ApiState,authenticate};
use axum::{Json,Router,extract::{Query,State},http::HeaderMap,routing::{get,post}};
use orbit_core::Error;
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use std::cmp::Ordering;
use uuid::Uuid;
/// Only channel published or served: one pinned channel keeps rollback and audit reasoning trivial.
const STABLE: &str = "stable";
/// Release-notes ceiling keeps the row bounded.
const MAX_NOTES: usize = 8192;
#[derive(Deserialize,utoipa::ToSchema)] #[serde(deny_unknown_fields)] pub struct PublishRequest { pub version: String, #[serde(default)] pub channel: Option<String>, pub digest: String, pub signature: String, pub artifact_url: String, #[serde(default)] pub notes: Option<String> }
#[derive(Deserialize)] pub struct CheckQuery { pub channel: Option<String>, pub current: Option<String> }
#[derive(Serialize,utoipa::ToSchema)] pub struct CheckResponse { pub update_available: bool, pub latest_version: String, pub digest: String, pub notes: String }
/// Semver-split numeric compare, no new deps: each dot part compares by leading digits, missing parts are 0.
fn split_ver(v: &str) -> Vec<u64> { v.split('.').map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().unwrap_or(0)).collect() }
pub fn compare_versions(a: &str, b: &str) -> Ordering { let (pa, pb) = (split_ver(a), split_ver(b)); for i in 0..pa.len().max(pb.len()) { let ord = pa.get(i).unwrap_or(&0).cmp(pb.get(i).unwrap_or(&0)); if ord != Ordering::Equal { return ord; } } Ordering::Equal }
/// Newer means a different string that orders greater, so rebuilds of the same version never read as updates.
pub fn is_newer(latest: &str, current: &str) -> bool { latest != current && compare_versions(latest, current) == Ordering::Greater }
fn valid_version(v: &str) -> bool { let t = v.trim(); !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_')) }
/// Digest format check (marketplace discipline): 64 hex chars, optional `sha256:` prefix, normalized to lowercase.
pub fn valid_digest(s: &str) -> Option<String> { let t = s.trim().strip_prefix("sha256:").unwrap_or(s.trim()); if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) { Some(t.to_ascii_lowercase()) } else { None } }
/// Signature format check only (64-byte ed25519 as 128 hex or ~88 base64): key custody and rotation stay owner-side.
fn valid_signature(s: &str) -> bool { let t = s.trim(); (32..=512).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')) }
#[utoipa::path(post,path="/api/v1/updates/publish",request_body=PublishRequest,responses((status=200,body=Value)))]
pub async fn publish(State(state): State<ApiState>,headers: HeaderMap,Json(input): Json<PublishRequest>)->Result<Json<Value>,ApiError>{
 let a=authenticate(&state,&headers,true).await?;
 let version=input.version.trim().to_owned();
 if !valid_version(&version){return Err(Error::Validation("release version must be 1-64 chars of alphanumerics . - + _".into()).into())}
 let channel=input.channel.unwrap_or_else(|| STABLE.into());
 if channel != STABLE{return Err(Error::Validation("only the stable release channel is published".into()).into())}
 let digest=valid_digest(&input.digest).ok_or_else(|| Error::Validation("release digest must be 64 hex chars (sha256)".into()))?;
 if !valid_signature(&input.signature){return Err(Error::Validation("release signature format invalid (ed25519)".into()).into())}
 let url=input.artifact_url.trim().to_owned();
 if url.len() > 2048 || !url.starts_with("https://"){return Err(Error::Validation("release artifact_url must be an https URL".into()).into())}
 let notes=input.notes.unwrap_or_default();
 if notes.len() > MAX_NOTES{return Err(Error::Validation("release notes too large".into()).into())}
 let mut tx=state.pool.begin().await?;
 sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(a.scope.owner_id).fetch_one(&mut *tx).await?;
 sqlx::query("INSERT INTO releases(id,owner_id,version,channel,digest,signature,artifact_url,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id,channel,version) DO UPDATE SET digest=EXCLUDED.digest,signature=EXCLUDED.signature,artifact_url=EXCLUDED.artifact_url,notes=EXCLUDED.notes,published_at=now()").bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(&version).bind(&channel).bind(&digest).bind(input.signature.trim()).bind(&url).bind(&notes).execute(&mut *tx).await?;
 sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(a.scope.owner_id).execute(&mut *tx).await?;
 orbit_audit::append(&mut tx,&a.scope,Uuid::new_v4(),None,None,"UPDATE_PUBLISHED","owner published a signed release",json!({"version":version,"channel":channel,"digest":digest})).await?;
 tx.commit().await?;
 Ok(Json(json!({"version":version,"channel":channel,"digest":digest,"published":true})))
}
#[utoipa::path(get,path="/api/v1/updates/check",responses((status=200,body=CheckResponse)))]
pub async fn check(State(state): State<ApiState>,headers: HeaderMap,Query(q): Query<CheckQuery>)->Result<Json<CheckResponse>,ApiError>{
 let a=authenticate(&state,&headers,false).await?;
 let current=q.current.as_deref().map(str::trim).filter(|s| !s.is_empty()).ok_or_else(|| Error::Validation("current version required".into()))?.to_owned();
 let channel=q.channel.as_deref().unwrap_or(STABLE);
 let rows: Vec<(String,String,String)> = sqlx::query_as("SELECT version,digest,notes FROM releases WHERE owner_id=$1 AND channel=$2").bind(a.scope.owner_id).bind(channel).fetch_all(&state.pool).await?;
 let mut latest: Option<(String,String,String)> = None;
 for row in rows { if latest.as_ref().map_or(true, |(v,_,_)| compare_versions(&row.0, v) == Ordering::Greater) { latest = Some(row); } }
 match latest { Some((v,d,n)) => Ok(Json(CheckResponse { update_available: is_newer(&v, &current), latest_version: v, digest: d, notes: n })), None => Ok(Json(CheckResponse { update_available: false, latest_version: current, digest: String::new(), notes: String::new() })) }
}
#[utoipa::path(get,path="/api/v1/updates/releases",responses((status=200,body=Value)))]
pub async fn releases(State(state): State<ApiState>,headers: HeaderMap)->Result<Json<Value>,ApiError>{
 let a=authenticate(&state,&headers,false).await?;
 let items: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('version',version,'channel',channel,'digest',digest,'artifact_url',artifact_url,'notes',notes,'published_at',published_at) FROM releases WHERE owner_id=$1 ORDER BY published_at DESC,version DESC LIMIT 100").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
 Ok(Json(json!({"items":items,"next_cursor":null})))
}
#[derive(utoipa::OpenApi)] #[openapi(paths(publish,check,releases),components(schemas(PublishRequest,CheckResponse)))] pub struct UpdatesApi;
pub fn router()->Router<ApiState>{Router::new().route("/api/v1/updates/check",get(check)).route("/api/v1/updates/publish",post(publish)).route("/api/v1/updates/releases",get(releases))}
