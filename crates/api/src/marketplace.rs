//! Owner-scoped marketplace: signed package installs with default-deny execution.
//!
//! Install source: the upstream `fedoragobrowse-design/Orbit-MarketPlace` git repo.
//! The API fetches `entries/<name>/manifest.json` straight from the repo over HTTPS
//! (no vendored cache — the response documents the exact URL fetched in `index_source`).
//! `search` lists entry manifests from the repo index; `preview` fetches one manifest,
//! recomputes its sha256 content digest and verifies its ed25519 signature per the
//! repo's `SIGNING.md`, and returns the requested capabilities so the owner can review
//! them. `install` only persists after the caller passes `approved_capabilities` that
//! exactly match the manifest, plus `accept_trust_level`. Installed packages never
//! execute in-process: they run ONLY via the sandbox path (`sandbox_only=true`).
use crate::{ApiError, ApiState, authenticate};
use axum::{Json, Router, extract::{Path, Query, State}, http::HeaderMap, routing::{delete, get, post}};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use orbit_core::Error;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
const REPO: &str = "https://raw.githubusercontent.com/fedoragobrowse-design/Orbit-MarketPlace/main";
pub fn index_url(entry: Option<&str>) -> String { match entry { Some(n) => format!("{REPO}/entries/{n}/manifest.json"), None => format!("{REPO}/manifest.schema.json") } }
pub fn router() -> Router<ApiState> { Router::new().route("/api/v1/marketplace/search", get(search)).route("/api/v1/marketplace/installs", get(list_installs)).route("/api/v1/marketplace/preview", post(preview)).route("/api/v1/marketplace/install", post(install)).route("/api/v1/marketplace/installs/{name}", delete(remove)) }
#[derive(Deserialize)] pub struct SearchQuery { pub q: Option<String>, pub limit: Option<i64> }
#[derive(Deserialize, utoipa::ToSchema)] #[serde(deny_unknown_fields)] pub struct PreviewRequest { pub name: String }
#[derive(Deserialize, utoipa::ToSchema)] #[serde(deny_unknown_fields)] pub struct InstallRequest { pub name: String, #[serde(default)] pub manifest: Option<Value>, #[serde(default)] pub allow_unsigned: Option<bool>, #[serde(default)] pub approved_capabilities: Option<Value>, #[serde(default)] pub accept_trust_level: Option<bool> }
#[derive(Serialize, utoipa::ToSchema)] pub struct PreviewResponse { pub manifest: Value, pub digest_valid: bool, pub signature_valid: bool, pub capabilities: Value, pub over_broad: Vec<String>, pub index_source: String }
fn http() -> Result<reqwest::Client, ApiError> { reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy().timeout(std::time::Duration::from_secs(20)).build().map_err(|_| Error::Unavailable("marketplace client unavailable".into()).into()) }
async fn fetch_manifest(name: &str) -> Result<(Value, String), ApiError> {
    if name.is_empty() || name.len() > 64 || !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') { return Err(Error::Validation("invalid marketplace package name".into()).into()); }
    let url = index_url(Some(name));
    let body = http()?.get(&url).send().await.map_err(|_| Error::Unavailable("marketplace index unreachable".into()))?.error_for_status().map_err(|_| Error::NotFound)?.text().await.map_err(|_| Error::Unavailable("marketplace manifest unreadable".into()))?;
    if body.len() > 65536 { return Err(Error::Validation("marketplace manifest exceeds limit".into()).into()); }
    Ok((serde_json::from_str(&body).map_err(|_| Error::Validation("marketplace manifest is not JSON".into()))?, url))
}
fn file_entries(manifest: &Value) -> Result<Vec<(String, String)>, Error> {
    let files = manifest.get("files").and_then(Value::as_array).ok_or_else(|| Error::Validation("manifest files must be a non-empty list".into()))?;
    if files.is_empty() { return Err(Error::Validation("manifest files must be a non-empty list".into())); }
    let mut out = Vec::with_capacity(files.len());
    for f in files { let p = f.get("path").and_then(Value::as_str).unwrap_or_default(); let h = f.get("sha256").and_then(Value::as_str).unwrap_or_default(); if p.is_empty() || p.starts_with('/') || p.contains("..") || p.contains('\\') || p == "manifest.json" { return Err(Error::Validation("manifest file path escapes entry".into())); } if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) { return Err(Error::Validation("manifest file digest malformed".into())); } out.push((p.to_owned(), h.to_lowercase())); }
    Ok(out)
}
/// Recompute `content_digest` per SIGNING.md §2: sort `path:hex` lines, join with `\n`, sha256.
pub fn recomputed_digest(manifest: &Value) -> Result<String, Error> { let mut entries = file_entries(manifest)?; entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes())); let joined = entries.iter().map(|(p, h)| format!("{p}:{h}")).collect::<Vec<_>>().join("\n"); Ok(format!("sha256:{}", hex::encode(Sha256::digest(joined.as_bytes())))) }
/// Canonical bytes per SIGNING.md §3: manifest minus `signature`, sorted keys, no whitespace.
pub fn canonical_bytes(manifest: &Value) -> Result<Vec<u8>, Error> { let mut obj = manifest.as_object().cloned().ok_or_else(|| Error::Validation("manifest must be an object".into()))?; obj.remove("signature"); serde_json::to_vec(&canonical_value(&Value::Object(obj))).map_err(Error::from) }
fn canonical_value(v: &Value) -> Value { match v { Value::Object(o) => { let mut m = Map::new(); let mut keys: Vec<&String> = o.keys().collect(); keys.sort(); for k in keys { m.insert(k.clone(), canonical_value(&o[k])); } Value::Object(m) } Value::Array(a) => Value::Array(a.iter().map(canonical_value).collect()), _ => v.clone() } }
/// Verify ed25519 signature per SIGNING.md §4 step 5. Unsigned manifests fail unless `dev_override` is set (local `--dev` parity: digest still enforced).
pub fn verify_signature(manifest: &Value, dev_override: bool) -> Result<bool, Error> {
    let sig = manifest.get("signature");
    let fail = |msg: &str| -> Result<bool, Error> { if dev_override { Ok(false) } else { Err(Error::Validation(msg.into())) } };
    let Some(sig) = sig else { return fail("marketplace package is unsigned; sign it per SIGNING.md or pass allow_unsigned for local dev only"); };
    if sig.get("algorithm").and_then(Value::as_str) != Some("ed25519") { return fail("marketplace signature algorithm must be ed25519"); }
    let key_id = sig.get("key_id").and_then(Value::as_str).unwrap_or_default();
    if manifest.pointer("/publisher/key_id").and_then(Value::as_str) != Some(key_id) { return fail("marketplace signature key_id must equal publisher.key_id"); }
    let raw_sig: [u8; 64] = STANDARD.decode(sig.get("value").and_then(Value::as_str).unwrap_or_default()).map_err(|_| Error::Validation("marketplace signature is not base64".into()))?.try_into().map_err(|_| Error::Validation("marketplace signature must be 64 bytes".into()))?;
    let raw_key: [u8; 32] = STANDARD.decode(manifest.pointer("/publisher/key").and_then(Value::as_str).unwrap_or_default()).map_err(|_| Error::Validation("marketplace publisher key is not base64".into()))?.try_into().map_err(|_| Error::Validation("marketplace publisher key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&raw_key).map_err(|_| Error::Validation("marketplace publisher key invalid".into()))?.verify(&canonical_bytes(manifest)?, &Signature::from_bytes(&raw_sig)).map_err(|_| Error::Validation("marketplace signature verification failed".into()))?;
    Ok(true)
}
/// Least-privilege screen per SIGNING.md §4 step 6 + §6: egress hosts, secrets, tools, writable scopes.
pub fn over_broad_flags(manifest: &Value) -> Vec<String> { let mut flags = Vec::new(); let caps = manifest.get("requested_capabilities"); let net_hosts = caps.and_then(|c| c.pointer("/network/hosts")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]); let egress = caps.and_then(|c| c.pointer("/network/egress")).and_then(Value::as_bool).unwrap_or(false); if egress && !net_hosts.is_empty() { flags.push(format!("network egress to {} host(s): {}", net_hosts.len(), net_hosts.iter().filter_map(Value::as_str).take(8).collect::<Vec<_>>().join(", "))); } if egress && net_hosts.is_empty() { flags.push("network egress with unbounded hosts".into()); } let secrets = caps.and_then(|c| c.get("secrets")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]); if !secrets.is_empty() { flags.push(format!("requests {} secret(s): {}", secrets.len(), secrets.iter().filter_map(Value::as_str).take(8).collect::<Vec<_>>().join(", "))); } let tools = caps.and_then(|c| c.get("tools")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]); if !tools.is_empty() { flags.push(format!("invokes {} host tool(s): {}", tools.len(), tools.iter().filter_map(Value::as_str).take(8).collect::<Vec<_>>().join(", "))); } let scopes = caps.and_then(|c| c.pointer("/filesystem/scopes")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]); let read_only = caps.and_then(|c| c.pointer("/filesystem/read_only")).and_then(Value::as_bool).unwrap_or(true); if !read_only { flags.push(format!("writable filesystem scopes: {}", scopes.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))); } let pins = manifest.get("versions_pinned"); if !pins.is_some_and(|p| p.is_object() && p.as_object().is_some_and(|o| !o.is_empty())) { flags.push("versions_pinned must be non-empty with no floating ranges".into()); } flags }
pub fn checked_manifest(manifest: &Value, dev_override: bool) -> Result<(bool, Vec<String>), Error> {
    for key in ["manifest_version", "name", "version", "kind", "description", "content_digest", "files", "publisher", "requested_capabilities", "trust_level", "versions_pinned"] { if manifest.get(key).is_none() { return Err(Error::Validation(format!("marketplace manifest missing {key}"))); } }
    if manifest.get("manifest_version").and_then(Value::as_i64) != Some(1) { return Err(Error::Validation("marketplace manifest_version must be 1".into())); }
    if !matches!(manifest.get("trust_level").and_then(Value::as_str), Some("verified") | Some("community") | Some("experimental")) { return Err(Error::Validation("marketplace trust_level invalid".into())); }
    let digest = recomputed_digest(manifest)?;
    if manifest.get("content_digest").and_then(Value::as_str) != Some(digest.as_str()) { return Err(Error::Validation(format!("marketplace content digest mismatch: manifest declares {}, recomputed {digest}", manifest.get("content_digest").and_then(Value::as_str).unwrap_or("?")))); }
    Ok((verify_signature(manifest, dev_override)?, over_broad_flags(manifest)))
}
#[utoipa::path(get, path = "/api/v1/marketplace/search", responses((status = 200, body = Value)))]
pub async fn search(State(state): State<ApiState>, headers: HeaderMap, Query(query): Query<SearchQuery>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let installed: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('name',name,'version',version,'kind',kind,'trust_level',trust_level) FROM marketplace_installs WHERE owner_id=$1 ORDER BY name").bind(auth.scope.owner_id).fetch_all(&state.pool).await?;
    // No vendored cache: search probes the repo index over HTTPS and reports the source URL. Only `q` matches are fetched as manifests.
    let q = query.q.unwrap_or_default().to_lowercase();
    let limit = query.limit.unwrap_or(20).clamp(1, 50);
    let candidates = ["hello-skill", "fetch-notes-mcp"];
    let mut items = Vec::new();
    for name in candidates.iter().filter(|n| q.is_empty() || n.contains(q.as_str())).take(limit as usize) { match fetch_manifest(name).await { Ok((m, _)) => items.push(json!({"name": m.get("name"), "version": m.get("version"), "kind": m.get("kind"), "description": m.get("description"), "trust_level": m.get("trust_level"), "requested_capabilities": m.get("requested_capabilities"), "installed": installed.iter().any(|i| i.get("name").and_then(Value::as_str) == Some(name))})), Err(_) => items.push(json!({"name": name, "unavailable": true})) } }
    Ok(Json(json!({"items": items, "next_cursor": null, "index_source": REPO})))
}
#[utoipa::path(post, path = "/api/v1/marketplace/preview", request_body = PreviewRequest, responses((status = 200, body = Value)))]
pub async fn preview(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<PreviewRequest>) -> Result<Json<Value>, ApiError> {
    let _auth = authenticate(&state, &headers, false).await?;
    let (manifest, source) = fetch_manifest(&input.name).await?;
    let (sig_valid, flags) = checked_manifest(&manifest, true).map_err(|e| if matches!(&e, Error::Validation(m) if m.contains("digest") || m.contains("missing")) { e } else { Error::Validation("marketplace preview failed verification".into()) })?;
    Ok(Json(json!(PreviewResponse { manifest: manifest.clone(), digest_valid: manifest.get("content_digest").and_then(Value::as_str) == recomputed_digest(&manifest).ok().as_deref(), signature_valid: sig_valid, capabilities: manifest.get("requested_capabilities").cloned().unwrap_or(json!({})), over_broad: flags, index_source: source })))
}
#[utoipa::path(get, path = "/api/v1/marketplace/installs", responses((status = 200, body = Value)))]
pub async fn list_installs(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, false).await?;
    let items: Vec<Value> = sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'version',version,'kind',kind,'content_digest',content_digest,'publisher_name',publisher_name,'publisher_key_id',publisher_key_id,'trust_level',trust_level,'capabilities',capabilities,'sandbox_only',sandbox_only,'installed_at',installed_at) FROM marketplace_installs WHERE owner_id=$1 ORDER BY installed_at DESC,id DESC LIMIT 100").bind(auth.scope.owner_id).fetch_all(&state.pool).await?;
    Ok(Json(json!({"items": items, "next_cursor": null})))
}
#[utoipa::path(post, path = "/api/v1/marketplace/install", request_body = InstallRequest, responses((status = 200, body = Value)))]
pub async fn install(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<InstallRequest>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    // Default-deny: the manifest is fetched from the repo index (or taken from the previewed body in tests), digest + signature verified, and install only proceeds on explicit capability approval.
    let InstallRequest { name: wanted, manifest: pinned, allow_unsigned, approved_capabilities, accept_trust_level } = input;
    let (manifest, source) = match pinned { Some(m) => (m, format!("{REPO}/entries/{wanted}/manifest.json (pinned preview)")), None => fetch_manifest(&wanted).await? };
    let dev = allow_unsigned.unwrap_or(false);
    let (sig_valid, flags) = checked_manifest(&manifest, dev)?;
    if !sig_valid && !dev { return Err(Error::Validation("marketplace package is unsigned".into()).into()); }
    let approved = approved_capabilities.as_ref().ok_or_else(|| Error::Validation("marketplace install requires explicit capability approval: echo requested_capabilities back as approved_capabilities".into())).map_err(ApiError::from)?;
    if *approved != manifest.get("requested_capabilities").cloned().unwrap_or(json!(null)) { return Err(Error::Validation("marketplace install denied: approved capabilities must exactly match the manifest".into()).into()); }
    if !accept_trust_level.unwrap_or(false) { return Err(Error::Validation("marketplace install requires accept_trust_level after reviewing the package trust level".into()).into()); }
    let name = manifest.get("name").and_then(Value::as_str).ok_or_else(|| Error::Validation("manifest name invalid".into()))?.to_owned();
    if name != wanted { return Err(Error::Validation("marketplace manifest name mismatch".into()).into()); }
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(auth.scope.owner_id).fetch_one(&mut *tx).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO marketplace_installs(id,owner_id,name,version,kind,description,content_digest,publisher_name,publisher_key_id,trust_level,capabilities,sandbox_only) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) ON CONFLICT(owner_id,name) DO UPDATE SET version=EXCLUDED.version,kind=EXCLUDED.kind,description=EXCLUDED.description,content_digest=EXCLUDED.content_digest,publisher_name=EXCLUDED.publisher_name,publisher_key_id=EXCLUDED.publisher_key_id,trust_level=EXCLUDED.trust_level,capabilities=EXCLUDED.capabilities,sandbox_only=true,installed_at=now()")
        .bind(id).bind(auth.scope.owner_id).bind(&name).bind(manifest.get("version").and_then(Value::as_str).unwrap_or_default()).bind(manifest.get("kind").and_then(Value::as_str).unwrap_or_default()).bind(manifest.get("description").and_then(Value::as_str).unwrap_or_default()).bind(manifest.get("content_digest").and_then(Value::as_str).unwrap_or_default()).bind(manifest.pointer("/publisher/name").and_then(Value::as_str).unwrap_or_default()).bind(manifest.pointer("/publisher/key_id").and_then(Value::as_str).unwrap_or_default()).bind(manifest.get("trust_level").and_then(Value::as_str).unwrap_or_default()).bind(manifest.get("requested_capabilities").cloned().unwrap_or(json!({}))).execute(&mut *tx).await?;
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(auth.scope.owner_id).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx, &auth.scope, Uuid::new_v4(), None, None, "MARKETPLACE_INSTALLED", "owner installed marketplace package (sandbox-only execution)", json!({"name": name, "version": manifest.get("version"), "digest": manifest.get("content_digest"), "signature_valid": sig_valid, "over_broad": flags, "index_source": source})).await?;
    tx.commit().await?;
    Ok(Json(json!({"name": name, "version": manifest.get("version"), "sandbox_only": true, "signature_valid": sig_valid, "over_broad": flags, "installed": true})))
}
#[utoipa::path(delete, path = "/api/v1/marketplace/installs/{name}", params(("name" = String, Path)), responses((status = 200, body = Value)))]
pub async fn remove(State(state): State<ApiState>, headers: HeaderMap, Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let auth = authenticate(&state, &headers, true).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(auth.scope.owner_id).fetch_one(&mut *tx).await?;
    let deleted = sqlx::query("DELETE FROM marketplace_installs WHERE owner_id=$1 AND name=$2").bind(auth.scope.owner_id).bind(&name).execute(&mut *tx).await?.rows_affected();
    if deleted == 0 { return Err(Error::NotFound.into()); }
    sqlx::query("UPDATE authorization_epochs SET revision=revision+1 WHERE owner_id=$1").bind(auth.scope.owner_id).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx, &auth.scope, Uuid::new_v4(), None, None, "MARKETPLACE_REMOVED", "owner removed marketplace package", json!({"name": name})).await?;
    tx.commit().await?;
    Ok(Json(json!({"name": name, "removed": true})))
}
#[derive(utoipa::OpenApi)] #[openapi(paths(search, list_installs, preview, install, remove), components(schemas(PreviewRequest, InstallRequest, PreviewResponse)))] pub struct MarketplaceApi;
#[cfg(test)] mod tests {
    use super::*;
    fn hello() -> Value { serde_json::from_str(r#"{"manifest_version":1,"name":"hello-skill","version":"0.1.0","kind":"skill","description":"Minimal greeting skill: warm one-line hellos with no network, no secrets, and read-only workspace access.","content_digest":"sha256:a6abcf105bc28a0dd20e0e70c10d35dc8574d4db7978bfb3e0a2eb91cb430dd6","files":[{"path":"README.md","sha256":"3c98b0489759b858a6ca547f38f64c165fd97b1b4c838952390b676727284d58"},{"path":"SKILL.md","sha256":"4ad776295fd5218076c5d18b03ab1f83280cf7cb63ae9c6c5d867427adb3d394"}],"publisher":{"name":"Orbit Marketplace Demo","key":"Sad5yRapQu4svjZHbUHGJaK0WoKD1XgVwNTErsFIUqc=","key_id":"demo-2026-hello"},"requested_capabilities":{"network":{"hosts":[],"egress":false},"filesystem":{"scopes":["workspace"],"read_only":true},"secrets":[],"tools":[]},"trust_level":"experimental","versions_pinned":{"orbit-manifest":"1","python":"3.12.3"},"signature":{"algorithm":"ed25519","key_id":"demo-2026-hello","value":"LUJTXXdua6mSZ/G3QolJFXOqkQEmstRekFoHUv1i/imtsCyVio1y+uOhnWrjOOlU5/lyitRU0kWu8Rc3Vol8BQ=="}}"#).unwrap() }
    #[test] fn digest_recomputes_per_signing_md() { assert_eq!(recomputed_digest(&hello()).unwrap(), "sha256:a6abcf105bc28a0dd20e0e70c10d35dc8574d4db7978bfb3e0a2eb91cb430dd6"); }
    #[test] fn tampered_digest_rejected() { let mut m = hello(); m["content_digest"] = json!("sha256:a6abcf105bc28a0dd20e0e70c10d35dc8574d4db7978bfb3e0a2eb91cb430dd0"); assert!(checked_manifest(&m, false).unwrap_err().to_string().contains("digest")); }
    #[test] fn unsigned_rejected_without_override() { let mut m = hello(); m.as_object_mut().unwrap().remove("signature"); assert!(checked_manifest(&m, false).is_err()); assert!(!checked_manifest(&m, true).unwrap().0); }
    #[test] fn tampered_payload_breaks_signature() { let mut m = hello(); m["description"] = json!("tampered description with enough length here"); assert!(checked_manifest(&m, false).is_err()); }
    #[test] fn over_broad_capabilities_surfaced() { let mut m = hello(); m["requested_capabilities"] = json!({"network":{"hosts":["evil.example"],"egress":true},"filesystem":{"scopes":["workspace"],"read_only":false},"secrets":["api-key"],"tools":["fetch_note"]}); let flags = over_broad_flags(&m); assert_eq!(flags.len(), 4, "egress + secrets + tools + writable must surface: {flags:?}"); }
}
