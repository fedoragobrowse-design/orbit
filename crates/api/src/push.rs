//! Owner-scoped Web Push subscriptions: registration, VAPID key
//! distribution, and best-effort approval alerts.
//!
//! VAPID key custody mirrors the email connector: the P-256 private key
//! lives in the encrypted secret store (`push-vapid-private` purpose)
//! and `push_vapid_keys` keeps only the `SecretId` link plus the public
//! key. Subscription endpoints and their `p256dh`/`auth` secrets are
//! owner-scoped rows. Sending is fire-and-forget: `enqueue_approval_push`
//! is called after the approval transaction commits and a push failure
//! never rolls back the approval row.

use crate::{ApiError, ApiState, authenticate};
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use orbit_core::{Error, OwnerScope};
use orbit_secrets::SecretStore;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::Row;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Raw stored VAPID keypair: 32-byte P-256 private scalar + 65-byte
/// uncompressed public point. Fixed lengths keep a truncated secret
/// from becoming a weak key.
const VAPID_SECRET_LEN: usize = 97;
const VAPID_PURPOSE: &str = "push-vapid-private";

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SubscribeRequest { pub endpoint: String, pub p256dh: String, pub auth: String }
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UnsubscribeRequest { pub endpoint: String }

#[derive(Serialize, utoipa::ToSchema)]
pub struct SubscribeResponse {
    pub subscribed: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct VapidKeyResponse {
    pub public_key: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct TestPushResponse {
    pub attempted: i64,
    pub delivered: i64,
}

fn valid_subscription(input: &SubscribeRequest) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if input.endpoint.len() > 2048
        || !input.endpoint.starts_with("https://")
        || input.p256dh.is_empty()
        || input.auth.is_empty()
    {
        return Err(Error::Validation("invalid push subscription".into()));
    }
    let p256dh = URL_SAFE_NO_PAD
        .decode(input.p256dh.trim())
        .map_err(|_| Error::Validation("invalid p256dh key".into()))?;
    let auth = URL_SAFE_NO_PAD
        .decode(input.auth.trim())
        .map_err(|_| Error::Validation("invalid auth secret".into()))?;
    if p256dh.len() != 65 || p256dh[0] != 0x04 || auth.len() != 16 {
        return Err(Error::Validation("invalid push subscription keys".into()));
    }
    Ok((p256dh, auth))
}

/// Load the owner's VAPID keypair, minting one on first use. The mint is
/// `ON CONFLICT DO NOTHING` plus re-read so two racing first-use calls
/// keep a single keypair; the loser's key bytes stay only in its store row.
async fn vapid_keypair(
    state: &ApiState,
    scope: &OwnerScope,
) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    if let Some(row) = sqlx::query("SELECT secret_id FROM push_vapid_keys WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_optional(&state.pool)
        .await?
    {
        let id: Uuid = row.get("secret_id");
        let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
        let raw = store.get(scope, id).await?;
        if raw.len() == VAPID_SECRET_LEN {
            return Ok((raw[..32].to_vec(), raw[32..].to_vec()));
        }
    }
    let (private, public) = generate_vapid_pair()?;
    let mut secret = Vec::with_capacity(VAPID_SECRET_LEN);
    secret.extend_from_slice(&private);
    secret.extend_from_slice(&public);
    let store = SecretStore::open(state.pool.clone(), &state.key_dir).await?;
    let id = store.put(scope, VAPID_PURPOSE, &secret).await?;
    let public_b64 = URL_SAFE_NO_PAD.encode(&public);
    sqlx::query("INSERT INTO push_vapid_keys(owner_id,secret_id,public_key) VALUES($1,$2,$3) ON CONFLICT(owner_id) DO NOTHING")
        .bind(scope.owner_id)
        .bind(id)
        .bind(&public_b64)
        .execute(&state.pool)
        .await?;
    let row = sqlx::query("SELECT secret_id FROM push_vapid_keys WHERE owner_id=$1")
        .bind(scope.owner_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(Error::Unavailable("push key setup failed".into()))?;
    let winner: Uuid = row.get("secret_id");
    if winner == id {
        return Ok((private, public));
    }
    let raw = store.get(scope, winner).await?;
    if raw.len() != VAPID_SECRET_LEN {
        return Err(Error::Unavailable("push key setup failed".into()).into());
    }
    Ok((raw[..32].to_vec(), raw[32..].to_vec()))
}

fn generate_vapid_pair() -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    let private = p256::SecretKey::random(&mut OsRng);
    let public = private.public_key().to_sec1_bytes().to_vec();
    Ok((private.to_bytes().to_vec(), public))
}

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// RFC 8291 §3.4 key schedule (HKDF-SHA-256 expanded into discrete
/// HMAC steps; each expansion is one block so one HMAC per step).
/// The ECDH secret comes from a fresh ephemeral sender keypair per
/// message (§3.1), so the long-lived VAPID signing key never doubles
/// as an encryption key; the sender point is returned for the record
/// header.
fn push_cek_nonce(secret: &[u8], auth_secret: &[u8], ua_public: &[u8], sender_public: &[u8], salt: &[u8]) -> ([u8; 16], [u8; 12]) {
    use hmac::{Hmac, Mac};
    fn mac(key: &[u8], data: &[u8]) -> Vec<u8> { let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key"); m.update(data); m.finalize().into_bytes().to_vec() }
    // HKDF-Extract(salt=auth_secret, IKM=ecdh_secret) then
    // HKDF-Expand(PRK_key, "WebPush: info" || 0x00 || ua_public || as_public, 32).
    let mut key_info = b"WebPush: info".to_vec(); key_info.push(0); key_info.extend_from_slice(ua_public); key_info.extend_from_slice(sender_public); key_info.push(1);
    let prk_key = mac(auth_secret, secret); let ikm = mac(&prk_key, &key_info);
    // RFC 8188 §4.2: HKDF-Extract(salt, IKM), then single-block expands.
    let prk = mac(salt, &ikm);
    let mut cek_info = b"Content-Encoding: aes128gcm".to_vec(); cek_info.push(0); cek_info.push(1);
    let mut nonce_info = b"Content-Encoding: nonce".to_vec(); nonce_info.push(0); nonce_info.push(1);
    let cek_full = mac(&prk, &cek_info); let nonce_full = mac(&prk, &nonce_info);
    let mut cek = [0u8; 16]; let mut nonce = [0u8; 12]; cek.copy_from_slice(&cek_full[..16]); nonce.copy_from_slice(&nonce_full[..12]); (cek, nonce)
}
fn ephemeral_ecdh(ua_public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};
    let peer = PublicKey::from_sec1_bytes(ua_public).map_err(|_| Error::Validation("invalid p256dh key".into()))?;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let point = EncodedPoint::from(ephemeral.public_key()).as_bytes().to_vec();
    Ok((point, ephemeral.diffie_hellman(&peer).raw_secret_bytes().to_vec()))
}
/// RFC 8188 §2 single-record `aes128gcm` body: 16-byte salt, 4-byte
/// big-endian record size, 1-byte keyid length, ephemeral key, then the
/// AES-128-GCM ciphertext of `plaintext || 0x02` (2 = padding delimiter).
/// `rs` is fixed 4096 like the RFC 8291 §5 example: the only MUST is
/// `rs` > plaintext + delimiter + padding + tag, and a fixed size also
/// hides the plaintext length from the push service.
fn encrypt_record(ua_public: &[u8], auth_secret: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};
    if plaintext.len() + 17 > 3993 { return Err(Error::Validation("push payload too large".into())); }
    let mut salt = [0u8; 16]; OsRng.fill_bytes(&mut salt);
    let (sender_public, secret) = ephemeral_ecdh(ua_public)?;
    let (cek, nonce) = push_cek_nonce(&secret, auth_secret, ua_public, &sender_public, &salt);
    let mut padded = plaintext.to_vec(); padded.push(2);
    let ciphertext = Aes128Gcm::new_from_slice(&cek).map_err(|_| Error::Unavailable("push encryption failed".into()))?.encrypt(Nonce::from_slice(&nonce), padded.as_slice()).map_err(|_| Error::Unavailable("push encryption failed".into()))?;
    let mut body = Vec::with_capacity(86 + ciphertext.len()); body.extend_from_slice(&salt); body.extend_from_slice(&4096u32.to_be_bytes()); body.push(sender_public.len() as u8); body.extend_from_slice(&sender_public); body.extend_from_slice(&ciphertext); Ok(body)
}

/// RFC 8292 VAPID JWT: ES256 over
/// `b64(header).b64({aud,exp,sub})`; `aud` is the push origin so a
/// stolen token cannot move across push services, `exp` caps reuse at
/// 12h (spec max 24h).
fn vapid_auth(
    endpoint: &str,
    origin: &str,
    private: &[u8],
    public: &[u8],
) -> Result<String, Error> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let push_origin = push_service_origin(endpoint)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Error::Unavailable("clock unavailable".into()))?.as_secs() as i64;
    let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = json!({"aud": push_origin, "exp": now + 12 * 3600, "sub": origin});
    let body = b64url(serde_json::to_vec(&claims)?.as_slice());
    let signing_input = format!("{header}.{body}");
    let key = SigningKey::from_bytes(private.into()).map_err(|_| Error::Unavailable("push key unavailable".into()))?;
    let signature: Signature = key.sign(signing_input.as_bytes());
    // JWS ES256 uses raw R||S, not DER.
    Ok(format!("vapid t={}.{}.{},k={}", header, body, b64url(&signature.to_bytes()), b64url(public)))
}

fn push_service_origin(endpoint: &str) -> Result<String, Error> {
    let rest = endpoint.strip_prefix("https://").ok_or(Error::Validation("invalid push endpoint".into()))?;
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || host.len() > 253 {
        return Err(Error::Validation("invalid push endpoint".into()));
    }
    Ok(format!("https://{host}"))
}

async fn send_to_subscription(
    client: &reqwest::Client,
    origin: &str,
    vapid_private: &[u8],
    vapid_public: &[u8],
    endpoint: &str,
    p256dh: &[u8],
    auth: &[u8],
    payload: &Value,
) -> Result<bool, Error> {
    let plaintext = serde_json::to_vec(payload)?;
    if plaintext.len() + 17 > 3993 {
        return Err(Error::Validation("push payload too large".into()));
    }
    let body = encrypt_record(p256dh, auth, &plaintext)?;
    let auth_header = vapid_auth(endpoint, origin, vapid_private, vapid_public)?;
    let response = client
        .post(endpoint)
        .header("Content-Encoding", "aes128gcm")
        .header("TTL", "3600")
        .header("Authorization", auth_header)
        .body(body)
        .send()
        .await
        .map_err(|_| Error::Unavailable("push service unreachable".into()))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Ok(false);
    }
    if !status.is_success() {
        return Err(Error::Unavailable("push delivery rejected".into()));
    }
    Ok(true)
}

async fn subscriptions(
    state: &ApiState,
    owner: Uuid,
) -> Result<Vec<(Uuid, String, Vec<u8>, Vec<u8>)>, ApiError> {
    let rows = sqlx::query("SELECT id,endpoint,p256dh,auth FROM push_subscriptions WHERE owner_id=$1")
        .bind(owner)
        .fetch_all(&state.pool)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let endpoint: String = row.get("endpoint");
        let p256dh = URL_SAFE_NO_PAD.decode(row.get::<String, _>("p256dh").as_str()).unwrap_or_default();
        let auth = URL_SAFE_NO_PAD.decode(row.get::<String, _>("auth").as_str()).unwrap_or_default();
        if p256dh.len() == 65 && auth.len() == 16 {
            out.push((row.get("id"), endpoint, p256dh, auth));
        }
    }
    Ok(out)
}

/// Fan out one payload to every live subscription. Stale endpoints
/// (410/404) are pruned; any other failure is swallowed because push is
/// advisory — the approvals table stays authoritative.
async fn fanout(state: &ApiState, scope: &OwnerScope, payload: &Value) -> (i64, i64) {
    let subs = subscriptions(state, scope.owner_id).await.unwrap_or_default();
    if subs.is_empty() {
        return (0, 0);
    }
    let keypair = vapid_keypair(state, scope).await;
    let Ok((private, public)) = keypair else { return (subs.len() as i64, 0) };
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build() {
        Ok(client) => client,
        Err(_) => return (subs.len() as i64, 0),
    };
    let mut delivered = 0i64;
    for (id, endpoint, p256dh, auth) in &subs {
        match send_to_subscription(&client, &state.origin, &private, &public, endpoint, p256dh, auth, payload).await {
            Ok(true) => delivered += 1,
            Ok(false) => {
                let _ = sqlx::query("DELETE FROM push_subscriptions WHERE owner_id=$1 AND id=$2")
                    .bind(scope.owner_id)
                    .bind(id)
                    .execute(&state.pool)
                    .await;
            }
            Err(_) => {}
        }
    }
    (subs.len() as i64, delivered)
}

/// Best-effort approval alert. Call only after the approval transaction
/// commits; never propagates an error.
pub async fn enqueue_approval_push(state: &ApiState, scope: &OwnerScope, approval_id: Uuid, preview: &Value) {
    let tool = preview.get("tool_name").and_then(Value::as_str).unwrap_or("action");
    let payload = json!({"title": "Orbit approval needed", "body": format!("{tool} is waiting for your decision"), "url": format!("/approvals/{approval_id}")});
    let state = state.clone();
    let scope = scope.clone();
    tokio::spawn(async move {
        fanout(&state, &scope, &payload).await;
    });
}

#[utoipa::path(post, path = "/api/v1/push/subscribe", request_body = SubscribeRequest, responses((status = 200, body = SubscribeResponse)))]
pub async fn subscribe(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(input): Json<SubscribeRequest>,
) -> Result<Json<SubscribeResponse>, ApiError> {
    let auth_session = authenticate(&state, &headers, true).await?;
    let (p256dh, auth) = valid_subscription(&input).map_err(ApiError)?;
    let _ = (p256dh, auth);
    sqlx::query("INSERT INTO push_subscriptions(id,owner_id,endpoint,p256dh,auth) VALUES($1,$2,$3,$4,$5) ON CONFLICT(owner_id,endpoint) DO UPDATE SET p256dh=EXCLUDED.p256dh,auth=EXCLUDED.auth")
        .bind(Uuid::new_v4())
        .bind(auth_session.scope.owner_id)
        .bind(input.endpoint.trim())
        .bind(input.p256dh.trim())
        .bind(input.auth.trim())
        .execute(&state.pool)
        .await?;
    Ok(Json(SubscribeResponse { subscribed: true }))
}

#[utoipa::path(delete, path = "/api/v1/push/subscribe", request_body = UnsubscribeRequest, responses((status = 200, body = SubscribeResponse)))]
pub async fn unsubscribe(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<UnsubscribeRequest>) -> Result<Json<SubscribeResponse>, ApiError> {
    let auth_session = authenticate(&state, &headers, true).await?;
    sqlx::query("DELETE FROM push_subscriptions WHERE owner_id=$1 AND endpoint=$2")
        .bind(auth_session.scope.owner_id)
        .bind(input.endpoint.trim())
        .execute(&state.pool)
        .await?;
    Ok(Json(SubscribeResponse { subscribed: false }))
}

#[utoipa::path(get, path = "/api/v1/push/vapid-key", responses((status = 200, body = VapidKeyResponse)))]
pub async fn vapid_key(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<VapidKeyResponse>, ApiError> {
    let auth_session = authenticate(&state, &headers, false).await?;
    let (_, public) = vapid_keypair(&state, &auth_session.scope).await?;
    Ok(Json(VapidKeyResponse { public_key: URL_SAFE_NO_PAD.encode(&public) }))
}

#[utoipa::path(post, path = "/api/v1/push/test", responses((status = 200, body = TestPushResponse)))]
pub async fn test_push(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<TestPushResponse>, ApiError> {
    let auth_session = authenticate(&state, &headers, true).await?;
    let payload = json!({"title": "Orbit test notification", "body": "Push alerts are on for approvals.", "url": "/approvals"});
    let (attempted, delivered) = fanout(&state, &auth_session.scope, &payload).await;
    if attempted == 0 { return Err(Error::Validation("no push subscriptions registered".into()).into()); }
    Ok(Json(TestPushResponse { attempted, delivered }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(subscribe, unsubscribe, vapid_key, test_push),
    components(schemas(SubscribeRequest, UnsubscribeRequest, SubscribeResponse, VapidKeyResponse, TestPushResponse))
)]
pub struct PushApi;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/push/subscribe", post(subscribe).delete(unsubscribe))
        .route("/api/v1/push/vapid-key", get(vapid_key))
        .route("/api/v1/push/test", post(test_push))
}
#[cfg(test)]
mod tests {
    use super::*;
    /// RFC 8291 Appendix A: fixed inputs MUST reproduce the CEK/nonce.
    #[test]
    fn rfc8291_appendix_a_vectors() {
        fn b64(s: &str) -> Vec<u8> { URL_SAFE_NO_PAD.decode(s.chars().filter(|c| !c.is_whitespace()).collect::<String>().as_str()).unwrap() }
        let ua_public = b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        let as_public = b64("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
        let as_private = b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw");
        let auth_secret = b64("BTBZMqHH6r4Tts7J_aSIgg");
        let salt = b64("DGv6ra1nlYgDCS1FRnbzlw");
        let peer = p256::PublicKey::from_sec1_bytes(&ua_public).unwrap();
        let key = p256::SecretKey::from_bytes((&as_private[..]).into()).unwrap();
        let ecdh = p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine()).raw_secret_bytes().to_vec();
        assert_eq!(b64url(&ecdh), "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
        let (cek, nonce) = push_cek_nonce(&ecdh, &auth_secret, &ua_public, &as_public, &salt);
        assert_eq!(b64url(&cek), "oIhVW04MRdy2XN9CiKLxTg");
        assert_eq!(b64url(&nonce), "4h_95klXJ5E_qnoN");
    }
}
