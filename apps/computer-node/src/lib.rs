pub mod index;
pub mod transport;
pub mod admin;
#[cfg(target_os = "linux")] pub mod linux;
#[cfg(windows)] pub mod windows;
use orbit_computer_node_protocol::sha256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMetadata { pub identity: String, pub size: u64, pub modified_ns: i128, pub kind: String, pub digest: Option<String> }
impl NativeMetadata { pub fn version(&self) -> String { sha256(format!("{}:{}:{}:{}", self.identity, self.size, self.modified_ns, self.digest.as_deref().unwrap_or("")).as_bytes()) } }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeMutation {
    pub request_id: uuid::Uuid, pub authorization_id: uuid::Uuid, pub action_hash: String,
    pub operation: String, pub source: Option<String>, pub destination: String,
    pub expected_version: Option<String>, pub expected_digest: Option<String>,
    pub content: Option<Vec<u8>>, pub stage_name: String,
    pub owner_uid: Option<u32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeOutcome { pub outcome: String, pub metadata: Option<NativeMetadata>, pub recovery_reference: Option<String>, pub evidence: serde_json::Value }
#[cfg(target_os = "linux")] pub use linux as native;
#[cfg(windows)] pub use windows as native;
#[cfg(not(any(target_os = "linux", windows)))] pub mod native {
    use super::*;
    pub fn read(_: &RootGrant, _: &str, _: usize) -> Result<Vec<u8>> { Err(Error::Unsupported) }
    pub fn metadata(_: &RootGrant, _: &str) -> Result<NativeMetadata> { Err(Error::Unsupported) }
    pub fn entries(_: &RootGrant, _: &str) -> Result<Vec<String>> { Err(Error::Unsupported) }
    pub fn mutate(_: &RootGrant, _: &RootGrant, _: &NativeMutation) -> Result<NativeOutcome> { Err(Error::SecureMutationUnavailable("unsupported OS".into())) }
}
pub fn file_id(root: uuid::Uuid, identity: &str) -> uuid::Uuid {
    let hash = sha256(format!("{root}:{identity}").as_bytes());
    let mut bytes: [u8; 16] = hex::decode(&hash[..32]).expect("hex digest").try_into().expect("16 bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x50; bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}
