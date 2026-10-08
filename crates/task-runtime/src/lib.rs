use async_trait::async_trait;
use chrono::{DateTime, Utc};
use orbit_core::{Error, PrivacyClass, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FILE_LIMIT: usize = 1024 * 1024;
pub const TRANSFER_LIMIT: usize = 10 * FILE_LIMIT;
pub const LIFETIME_SECONDS: u64 = 1680;
pub const CLOCK_MARGIN_SECONDS: i64 = 30;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputArtifact {
    pub artifact_id: Uuid,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    #[serde(skip)]
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpec {
    pub run_id: Uuid,
    pub image: String,
    pub cpu: u32,
    pub memory_mb: u32,
    pub disk_mb: u32,
    pub lifetime_seconds: u64,
    pub network_enabled: bool,
    pub inputs: Vec<InputArtifact>,
}
impl RuntimeSpec {
    pub fn validate(&self) -> Result<()> {
        if self.image.is_empty() || self.image.len() > 256 || self.cpu != 1 || self.memory_mb != 512 || self.disk_mb == 0 || self.lifetime_seconds != LIFETIME_SECONDS || self.network_enabled {
            return Err(Error::Validation("AIec requires admitted image, 1 CPU, 512 MiB, exact disk floor, 1680-second lifetime and no network".into()));
        }
        let mut total = 0usize;
        let mut paths = std::collections::BTreeSet::new();
        for input in &self.inputs {
            workspace_path(&input.path, false)?;
            if !paths.insert(&input.path) || input.size > FILE_LIMIT as u64 || input.sha256.len() != 64 || !input.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Validation("invalid or duplicate runtime input".into()));
            }
            total = total.checked_add(input.size as usize).ok_or_else(|| Error::Validation("transfer overflow".into()))?;
        }
        if total > TRANSFER_LIMIT { return Err(Error::Validation("runtime inputs exceed 10 MiB".into())); }
        Ok(())
    }
}
/// Public ID is the sole remote identity; no runtime_path or host capability is exposed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeHandle {
    id: Uuid,
    created_at: DateTime<Utc>,
    lifetime_seconds: u64,
}
impl RuntimeHandle {
    pub fn observed(id: Uuid, created_at: DateTime<Utc>, lifetime_seconds: u64) -> Self { Self { id, created_at, lifetime_seconds } }
    pub fn id(&self) -> Uuid { self.id }
    pub fn created_at(&self) -> DateTime<Utc> { self.created_at }
    pub fn lifetime_seconds(&self) -> u64 { self.lifetime_seconds }
    pub fn require_remaining(&self, seconds: u64) -> Result<()> {
        let remaining = (self.created_at + chrono::Duration::seconds(self.lifetime_seconds as i64) - Utc::now()).num_seconds() - CLOCK_MARGIN_SECONDS;
        if remaining < seconds as i64 { return Err(Error::Timeout); }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTask {
    pub argv: Vec<String>,
    pub working_directory: String,
    pub timeout_seconds: u64,
    pub output_paths: Vec<String>,
}
impl RuntimeTask {
    pub fn validate(&self) -> Result<()> {
        workspace_path(&self.working_directory, true)?;
        if self.argv.is_empty() || self.argv.len() > 128 || self.argv.iter().any(|s| s.contains('\0') || s.len() > 65536) || self.argv.iter().map(String::len).sum::<usize>() > 131072 || !(1..=120).contains(&self.timeout_seconds) || self.output_paths.len() > 10 {
            return Err(Error::Validation("invalid bounded runtime command".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for path in &self.output_paths { workspace_path(path, false)?; if !seen.insert(path) { return Err(Error::Validation("duplicate output path".into())); } }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeOutcome { Exited, TimedOut, TransportFailure, OutcomeUnknown }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeResult {
    pub outcome: RuntimeOutcome,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: Option<u64>,
    /// REST has no truncation bit; output completeness is not asserted.
    pub output_completeness: String,
}
impl RuntimeResult { pub fn succeeded(&self) -> bool { self.outcome == RuntimeOutcome::Exited && self.exit_code == Some(0) } }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub id: Uuid,
    pub safe_name: String,
    pub mime_type: String,
    pub size: u64,
    pub sha256: String,
    pub privacy_class: PrivacyClass,
    pub provenance: String,
    pub private_storage_reference: String,
    #[serde(skip)]
    pub bytes: Vec<u8>,
}
#[async_trait]
pub trait TaskRuntime: Send + Sync {
    async fn create(&self, spec: RuntimeSpec) -> Result<RuntimeHandle>;
    async fn execute(&self, handle: &RuntimeHandle, task: RuntimeTask) -> Result<RuntimeResult>;
    async fn collect_artifacts(&self, handle: &RuntimeHandle) -> Result<Vec<Artifact>>;
    async fn destroy(&self, handle: RuntimeHandle) -> Result<()>;
}
/// Reject ambiguous lexical paths before any remote request, even when the guest is untrusted.
pub fn workspace_path(path: &str, allow_root: bool) -> Result<()> {
    if (allow_root && path == "/workspace") || (path.starts_with("/workspace/") && path.len() <= 1024 && !path.contains(['\0', '\\', ':']) && path[11..].split('/').all(|c| !c.is_empty() && c != "." && c != ".." && c.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))) { return Ok(()); }
    Err(Error::Validation("path must be an unambiguous /workspace descendant".into()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn confines_paths() { for p in ["/workspace/../secret", "/workspace/x/", "/workspace//x", "/workspace/.orbit/../../x", "/tmp/x", "/workspace/x\\y", "/workspace/x:y"] { assert!(workspace_path(p,false).is_err(), "{p}"); } assert!(workspace_path("/workspace/input.bin",false).is_ok()); }
    #[test] fn lifetime_is_creation_based() { let h=RuntimeHandle::observed(Uuid::new_v4(),Utc::now()-chrono::Duration::seconds(1500),1680); assert!(h.require_remaining(240).is_err()); }
    #[test] fn timeout_never_succeeds() { let r=RuntimeResult{outcome:RuntimeOutcome::TimedOut,exit_code:Some(0),stdout:String::new(),stderr:String::new(),duration_ms:None,output_completeness:"UNKNOWN".into()}; assert!(!r.succeeded()); }
}
