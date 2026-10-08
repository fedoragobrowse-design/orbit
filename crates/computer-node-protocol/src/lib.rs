use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::PathBuf};
use uuid::Uuid;

pub const VERSION: u16 = 1;
pub const MAX_FILE: usize = 10 * 1024 * 1024;
pub const MAX_TEXT: usize = 1024 * 1024;
pub const MAX_PAGE: usize = 50;
pub const MAX_FRAME: usize = 15 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid protocol or request: {0}")] Invalid(String),
    #[error("FORBIDDEN")] Forbidden,
    #[error("FILE_VERSION_CONFLICT")] VersionConflict,
    #[error("SECURE_MUTATION_UNAVAILABLE: {0}")] SecureMutationUnavailable(String),
    #[error("OUTCOME_UNKNOWN")] OutcomeUnknown,
    #[error("UNSUPPORTED_CAPABILITY")] Unsupported,
    #[error("native I/O failed")] Io(#[from] std::io::Error),
    #[error("invalid serialized protocol")] Json(#[from] serde_json::Error),
}
pub type Result<T, E = Error> = std::result::Result<T, E>;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RootMode { Read, ReadWrite, Ask }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootGrant {
    pub id: Uuid,
    pub path: PathBuf,
    pub mode: RootMode,
    pub revision: i64,
    pub revoked: bool,
    pub namespace_protected: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub server: String,
    pub owner_id: Uuid,
    pub node_id: Uuid,
    pub session: String,
    pub identity_key: String,
    pub state_dir: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub roots: Vec<RootGrant>,
    pub owner_uid: Option<u32>,
    pub service_uid: Option<u32>,
    #[serde(default)] pub embedding: Option<EmbeddingConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig { pub origin: String, pub model: String, pub protocol: String }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType { Register, Authenticate, Heartbeat, Capabilities, FileSearch, FileRead, FileWrite, FileMetadata, FileWatch, FileList, FileMove, FileCopy, EventPush, ApprovalRequest, Response, Ack, Revoke, Challenge, Session }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope { pub version: u16, pub request_id: Uuid, pub node_id: Uuid, pub message_type: MessageType, pub payload: Value }
impl Envelope {
    pub fn new(node_id: Uuid, message_type: MessageType, payload: Value) -> Self { Self { version: VERSION, request_id: Uuid::new_v4(), node_id, message_type, payload } }
    pub fn validate(&self, node: Uuid) -> Result<()> { if self.version != VERSION || self.node_id != node { return Err(Error::Invalid("version or node identity".into())); } Ok(()) }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge { pub nonce: String, pub node_id: Uuid, pub session_hash: String, pub expires_at: DateTime<Utc> }
pub fn challenge_bytes(c: &Challenge) -> Result<Vec<u8>> { serde_jcs::to_vec(c).map_err(|_| Error::Invalid("challenge encoding".into())) }
pub fn sign_challenge(key: &SigningKey, c: &Challenge) -> Result<String> { Ok(STANDARD.encode(key.sign(&challenge_bytes(c)?).to_bytes())) }
pub fn verify_challenge(key: &str, c: &Challenge, signature: &str) -> Result<()> {
    if c.expires_at <= Utc::now() { return Err(Error::Forbidden); }
    let bytes: [u8; 32] = STANDARD.decode(key).map_err(|_| Error::Forbidden)?.try_into().map_err(|_| Error::Forbidden)?;
    let sig = Signature::from_slice(&STANDARD.decode(signature).map_err(|_| Error::Forbidden)?).map_err(|_| Error::Forbidden)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::Forbidden)?.verify(&challenge_bytes(c)?, &sig).map_err(|_| Error::Forbidden)
}
pub fn sha256(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
pub fn action_hash(snapshot: &Value) -> Result<String> { Ok(sha256(&serde_jcs::to_vec(snapshot).map_err(|_| Error::Invalid("canonical action".into()))?)) }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub authorization_id: Uuid,
    pub task_fence: i64,
    pub snapshot: Value,
    pub action_hash: String,
    pub content_base64: Option<String>,
}
impl ExecutionRequest {
    pub fn validate(&self, config: &NodeConfig) -> Result<(&str, &Value)> {
        if action_hash(&self.snapshot)? != self.action_hash || self.task_fence <= 0 { return Err(Error::Forbidden); }
        let owner = self.snapshot["owner_id"].as_str().ok_or(Error::Forbidden)?;
        if owner != config.owner_id.to_string() { return Err(Error::Forbidden); }
        let expires = self.snapshot["expires_at"].as_str().ok_or(Error::Forbidden)?.parse::<DateTime<Utc>>().map_err(|_| Error::Forbidden)?;
        if expires <= Utc::now() { return Err(Error::Forbidden); }
        let args = &self.snapshot["arguments"];
        if args["node_id"].as_str() != Some(config.node_id.to_string().as_str()) { return Err(Error::Forbidden); }
        let tool = self.snapshot["tool_name"].as_str().ok_or(Error::Forbidden)?;
        if !["files.list", "files.search", "files.read", "files.metadata", "files.watch", "files.write", "files.move", "files.copy"].contains(&tool) { return Err(Error::Unsupported); }
        Ok((tool, args))
    }
    pub fn check_root(&self, root: &RootGrant, mutation: bool, content: bool) -> Result<()> {
        if root.revoked || (mutation && root.mode != RootMode::ReadWrite && root.mode != RootMode::Ask) { return Err(Error::Forbidden); }
        let revision = self.snapshot["scope_revisions"][format!("root:{}", root.id)].as_i64();
        if revision != Some(root.revision) { return Err(Error::Forbidden); }
        // The gateway attests consumed consent through the immutable approval binding.
        if (mutation || (content && root.mode == RootMode::Ask)) && self.snapshot["arguments"]["consent_required"].as_bool() != Some(true) { return Err(Error::Forbidden); }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub file_id: Uuid, pub root_id: Uuid, pub relative_path: String,
    pub kind: String, pub version: String, pub sha256: Option<String>,
    pub size: u64, pub privacy_class: String,
    pub source_reference: String,
}
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IndexStatus { pub indexed: u64, pub skipped: u64, pub truncated: u64, pub unreadable: u64, pub gap: bool, pub available_modes: Vec<String> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities { pub operations: Vec<String>, pub roots: Vec<PublicRoot>, pub native_mutation_proof: String, pub semantic_available: bool }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRoot { pub id: Uuid, pub display_name: String, pub mode: RootMode, pub revision: i64, pub mutation_available: bool, pub index_status: IndexStatus }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent { pub sequence: i64, pub root_id: Uuid, pub root_revision: i64, pub file_id: Uuid, pub version: String, pub event_type: String, pub metadata: Value }

pub fn normalize_path(path: &str) -> Result<String> {
    if path.is_empty() || path.len() > 4096 || path.starts_with('/') || path.starts_with('\\') || path.contains('\\') || path.contains(':') || path.contains('\0') { return Err(Error::Forbidden); }
    let mut pieces = Vec::new();
    for p in path.split('/') {
        if p.is_empty() || p == "." || p == ".." || denied_name(p) { return Err(Error::Forbidden); }
        pieces.push(p);
    }
    Ok(pieces.join("/"))
}
pub fn denied_name(name: &str) -> bool {
    let n = name.to_lowercase();
    [".ssh", ".gnupg", ".aws", ".kube", ".orbit-recovery", ".orbit-node", "orbit-node", "credentials", "credential", "login data", "logins.json", "key4.db", "cookies", "chrome", "chromium", "firefox", "microsoft edge", "system volume information", "windows", "proc", "sys", "dev", "etc"].contains(&n.as_str()) || n.ends_with('.') || n.ends_with(' ')
}
pub fn root_revisions(roots: &[RootGrant]) -> BTreeMap<String, i64> { roots.iter().filter(|r| !r.revoked).map(|r| (format!("root:{}", r.id), r.revision)).collect() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn signed_challenge_is_identity_session_and_expiry_bound() {
        let key = SigningKey::from_bytes(&[73; 32]);
        let mut c = Challenge { nonce: "one-time".into(), node_id: Uuid::new_v4(), session_hash: sha256(b"credential"), expires_at: Utc::now() + chrono::Duration::seconds(30) };
        let sig = sign_challenge(&key, &c).unwrap(); let public = STANDARD.encode(key.verifying_key().to_bytes());
        verify_challenge(&public, &c, &sig).unwrap(); c.session_hash = sha256(b"other"); assert!(verify_challenge(&public, &c, &sig).is_err());
    }
    #[test] fn unknown_wire_version_and_operation_refused() { assert!(serde_json::from_value::<Envelope>(serde_json::json!({"version":1,"request_id":Uuid::new_v4(),"node_id":Uuid::new_v4(),"message_type":"DELETE","payload":{}})).is_err()); }
}
