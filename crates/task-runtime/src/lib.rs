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
    /// Guest network posture. The guest never gets a raw interface: `NONE`
    /// is fully offline, `BROKERED_MODEL` brokers HTTPS to one model origin
    /// only, `BROKERED_WEB` brokers HTTPS to an allowlisted web origin set.
    /// The boolean this replaces confused "no egress configured" with "no
    /// network enforced"; the enum forces the caller to name the posture.
    pub network: NetworkMode,
    pub inputs: Vec<InputArtifact>,
    /// Brokered model egress grant. Present only with
    /// `NetworkMode::BrokeredModel`. Origin only — credentials never enter
    /// the guest or this struct.
    #[serde(default)]
    pub egress: Option<ModelEgress>,
    /// Brokered web egress grant (managed browser). Present only with
    /// `NetworkMode::BrokeredWeb`. Origins only — no credentials, no cookies.
    #[serde(default)]
    pub web_egress: Option<WebEgress>,
}
/// Guest network posture. SCREAMING_SNAKE_CASE on the wire; unknown variants
/// fail closed at deserialization.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkMode {
    None,
    BrokeredModel,
    BrokeredWeb,
}
/// Brokered web origin set: origins only, no credentials or client state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebEgress {
    pub origins: Vec<String>,
}
impl WebEgress {
    pub fn validate(&self) -> Result<()> {
        if self.origins.is_empty() || self.origins.len() > 16 {
            return Err(Error::Validation("brokered web egress needs 1 to 16 origins".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for origin in &self.origins {
            if !is_bare_http_origin(origin) || !seen.insert(origin) {
                return Err(Error::Validation("brokered web origin must be a unique bare http(s) origin".into()));
            }
        }
        Ok(())
    }
    /// Guard environment JSON: outside-topology broker allowing only these
    /// origins. Origins only — no credentials, cookies, or client state.
    pub fn guard_environment(&self) -> serde_json::Value {
        serde_json::json!({"workspace":{"type":"empty"},"guard":{"topology":"outside","policy_template":"brokered-web","allow":self.origins.iter().map(|origin| serde_json::json!({"origin": origin})).collect::<Vec<_>>()}})
    }
}
/// Bare `http(s)://host[:port]` origin check without new dependencies:
/// no userinfo, path, query, or fragment; host is non-empty.
fn is_bare_http_origin(origin: &str) -> bool {
    if origin.is_empty() || origin.len() > 256 || origin.chars().any(char::is_control) {
        return false;
    }
    let rest = if let Some(rest) = origin.strip_prefix("https://") {
        rest
    } else if let Some(rest) = origin.strip_prefix("http://") {
        rest
    } else {
        return false;
    };
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return false;
    }
    // Host (up to an optional :port) is non-empty; port is digits only.
    let host = rest.split(':').next().unwrap_or_default();
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if let Some(port) = rest.split(':').nth(1) {
        if rest.matches(':').count() > 1 && !(rest.starts_with('[') && rest.contains("]:")) {
            return false;
        }
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    true
}
/// Brokered model endpoint: origin + model name, no credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEgress {
     pub origin: String,
     pub model: String,
 }
 impl ModelEgress {
     pub fn validate(&self) -> Result<()> {
         if self.origin.is_empty() || self.origin.len() > 256 || !(self.origin.starts_with("https://") || self.origin.starts_with("http://")) || self.model.is_empty() || self.model.len() > 256 {
             return Err(Error::Validation("invalid brokered model egress".into()));
         }
         Ok(())
     }
     /// Guard environment JSON: outside-topology broker allowing only this origin.
     pub fn guard_environment(&self) -> serde_json::Value {
         serde_json::json!({"workspace":{"type":"empty"},"guard":{"topology":"outside","policy_template":"brokered-egress","allow":[{"origin":self.origin}]}})
     }
 }
 impl RuntimeSpec {
     pub fn validate(&self) -> Result<()> {
        if self.image.is_empty() || self.image.len() > 256 || self.cpu != 1 || self.memory_mb != 512 || self.disk_mb == 0 || self.lifetime_seconds != LIFETIME_SECONDS {
            return Err(Error::Validation("AIec requires admitted image, 1 CPU, 512 MiB, exact disk floor and 1680-second lifetime".into()));
        }
        // The posture must name its grant exactly: NONE carries no egress,
        // BROKERED_MODEL carries model egress only, BROKERED_WEB carries web
        // egress only. Any other combination is a confused grant and unusable.
        match (&self.network, &self.egress, &self.web_egress) {
            (NetworkMode::None, None, None) => {}
            (NetworkMode::BrokeredModel, Some(egress), None) => egress.validate()?,
            (NetworkMode::BrokeredWeb, None, Some(web)) => web.validate()?,
            _ => return Err(Error::Validation("network mode and egress grant mismatch: NONE carries no egress, BROKERED_MODEL carries model egress only, BROKERED_WEB carries web egress only".into())),
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
/// `TaskRuntime::session_*` fail-closed marker. No host, process, or Docker
/// fallback exists: callers surface this `Unavailable` as 503.
pub const INTERACTIVE_SHELL_UNAVAILABLE: &str = "INTERACTIVE_SHELL_UNAVAILABLE";
/// Interactive shell request: absolute subtree-relative cwd (`/` is the
/// staged root) plus initial pty size. Bounds mirror the shell-sessions API.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractiveSpec {
    pub cols: u32,
    pub rows: u32,
    pub cwd: String,
}
impl InteractiveSpec {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1024).contains(&self.cols) || !(1..=1024).contains(&self.rows) {
            return Err(Error::Validation("pty size out of bounds".into()));
        }
        validate_interactive_cwd(&self.cwd)?;
        Ok(())
    }
}
/// Opaque handle to a started interactive shell.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InteractiveHandle {
    pub id: Uuid,
}
/// Subtree-relative absolute path: `/` plus per-segment workspace names
/// (no traversal, separators, NUL, or control characters).
pub fn validate_interactive_cwd(cwd: &str) -> Result<()> {
    if cwd.is_empty() || cwd.len() > 1024 || !cwd.starts_with('/') {
        return Err(Error::Validation("cwd must be an absolute subtree path".into()));
    }
    if cwd == "/" {
        return Ok(());
    }
    for segment in cwd[1..].split('/') {
        if segment.is_empty()
            || segment.len() > 255
            || segment == "."
            || segment == ".."
            || segment.contains('\0')
            || segment.contains('\\')
            || segment.chars().any(char::is_control)
        {
            return Err(Error::Validation("invalid cwd segment".into()));
        }
    }
    Ok(())
}
/// Interactive shell text bound: one input intent per call (agent commands
/// stay one proposal per command; shell input is never an agent proposal).
pub fn validate_interactive_text(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > 65536 || text.contains('\0') {
        return Err(Error::Validation("shell input must be 1 byte to 64 KiB".into()));
    }
    Ok(())
}
#[async_trait]
pub trait TaskRuntime: Send + Sync {
    async fn create(&self, spec: RuntimeSpec) -> Result<RuntimeHandle>;
    async fn execute(&self, handle: &RuntimeHandle, task: RuntimeTask) -> Result<RuntimeResult>;
    async fn put_file(&self, handle: &RuntimeHandle, path: &str, bytes: &[u8]) -> Result<()>;
    async fn collect_artifacts(&self, handle: &RuntimeHandle) -> Result<Vec<Artifact>>;
    async fn destroy(&self, handle: RuntimeHandle) -> Result<()>;
    /// Start an interactive shell. Default: fail closed with
    /// `INTERACTIVE_SHELL_UNAVAILABLE` (503 at the API layer).
    async fn session_start(&self, _spec: InteractiveSpec) -> Result<InteractiveHandle> {
        Err(Error::Unavailable(INTERACTIVE_SHELL_UNAVAILABLE.into()))
    }
    /// Send one bounded input intent to a started shell.
    async fn session_input(&self, _handle: &InteractiveHandle, _text: &str) -> Result<()> {
        Err(Error::Unavailable(INTERACTIVE_SHELL_UNAVAILABLE.into()))
    }
    /// Resize a started shell's pty.
    async fn session_resize(&self, _handle: &InteractiveHandle, _cols: u32, _rows: u32) -> Result<()> {
        Err(Error::Unavailable(INTERACTIVE_SHELL_UNAVAILABLE.into()))
    }
    /// Stop a started shell. Idempotent at the API layer via revision CAS.
    async fn session_stop(&self, _handle: InteractiveHandle) -> Result<()> {
        Err(Error::Unavailable(INTERACTIVE_SHELL_UNAVAILABLE.into()))
    }
    /// Whether this runtime can host interactive shells. Probes capability
    /// without starting anything; `false` means `session_*` fail closed.
    fn supports_interactive(&self) -> bool {
        false
    }
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
    fn base_spec() -> RuntimeSpec { RuntimeSpec { run_id: Uuid::new_v4(), image: "admitted-image".into(), cpu: 1, memory_mb: 512, disk_mb: 1024, lifetime_seconds: LIFETIME_SECONDS, network: NetworkMode::None, inputs: Vec::new(), egress: None, web_egress: None } }
    #[test] fn network_modes_name_their_grants() {
        base_spec().validate().unwrap();
        let mut model = base_spec();
        model.network = NetworkMode::BrokeredModel;
        model.egress = Some(ModelEgress { origin: "https://openrouter.ai".into(), model: "m".into() });
        model.validate().unwrap();
        let mut web = base_spec();
        web.network = NetworkMode::BrokeredWeb;
        web.web_egress = Some(WebEgress { origins: vec!["https://example.com".into()] });
        web.validate().unwrap();
        // Confused grants fail closed: mode without grant, grant without mode,
        // both grants, or the wrong grant for the mode.
        let mut bare_model = base_spec();
        bare_model.network = NetworkMode::BrokeredModel;
        assert!(bare_model.validate().is_err(), "BROKERED_MODEL without model egress must fail");
        let mut stray = base_spec();
        stray.egress = Some(ModelEgress { origin: "https://openrouter.ai".into(), model: "m".into() });
        assert!(stray.validate().is_err(), "NONE with a stray egress grant must fail");
        let mut both = base_spec();
        both.network = NetworkMode::BrokeredModel;
        both.egress = Some(ModelEgress { origin: "https://openrouter.ai".into(), model: "m".into() });
        both.web_egress = Some(WebEgress { origins: vec!["https://example.com".into()] });
        assert!(both.validate().is_err(), "both grants at once must fail");
        let mut swapped = base_spec();
        swapped.network = NetworkMode::BrokeredWeb;
        swapped.egress = Some(ModelEgress { origin: "https://openrouter.ai".into(), model: "m".into() });
        assert!(swapped.validate().is_err(), "BROKERED_WEB with model egress must fail");
        let mut bad_web = base_spec();
        bad_web.network = NetworkMode::BrokeredWeb;
        bad_web.web_egress = Some(WebEgress { origins: vec!["ftp://example.com".into()] });
        assert!(bad_web.validate().is_err(), "non-http web origin must fail");
    }
    #[test] fn network_mode_wire_is_screaming() {
        assert_eq!(serde_json::to_value(NetworkMode::None).unwrap(), serde_json::json!("NONE"));
        assert_eq!(serde_json::to_value(NetworkMode::BrokeredModel).unwrap(), serde_json::json!("BROKERED_MODEL"));
        assert_eq!(serde_json::to_value(NetworkMode::BrokeredWeb).unwrap(), serde_json::json!("BROKERED_WEB"));
        assert!(serde_json::from_value::<NetworkMode>(serde_json::json!("unrestricted")).is_err(), "unknown posture fails closed");
        let value = serde_json::to_value(base_spec()).unwrap();
        assert_eq!(value["network"], serde_json::json!("NONE"));
    }
}
