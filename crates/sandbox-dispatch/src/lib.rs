//! Orbit's own governed sandbox dispatch (the in-repo sOMP-equivalent).
//!
//! Replaces the broken external `somp` binary. Composes [`TaskRuntime`] sandbox
//! lifecycle with the [`RiskClassifier`] deterministic floor behind an ordered,
//! fail-closed gate: risk floor → Jev destructive-bash verdict → secret-path
//! deny → depth guard → create → stage → baseline → exec → diff → scrub → destroy.
//! Both agent backends (OMP, Claude SDK) route tool/command execution and
//! subagent spawns through here; nothing shells out to an external binary.

use orbit_core::{Error, OwnerScope, Result, RiskLevel};
use orbit_risk::{ActionContext, ProposedAction, RiskClassifier};
use orbit_task_runtime::{ModelEgress, RuntimeSpec, RuntimeTask, TaskRuntime, LIFETIME_SECONDS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// A file staged into the guest workspace before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageFile {
    pub path: String,
    pub content: Vec<u8>,
}

/// One governed execution request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub files: Vec<StageFile>,
    pub timeout_s: u64,
    pub depth: u32,
    /// True only when this exact command already passed Dispatcher approval
    /// (`Dispatcher::submit`). Fail-closed: `Confirm`-level commands with
    /// `approved=false` are rejected. `Block`/secret/depth reject regardless.
    pub approved: bool,
}

/// Outcome of a governed execution. `diff` mirrors the guest `git diff` so the
/// caller can audit exactly what the guest changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecOutcome {
    pub sandbox_id: Uuid,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub diff: Value,
    pub duration_ms: u64,
}

/// Gate verdict — matches the existing risk vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Allow,
    Confirm,
    Block,
}

/// Jev-style destructive-bash verdict shape (`p_destructive` + `confidence`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JevVerdict {
    pub p_destructive: f64,
    pub confidence: f64,
    pub verdict: Verdict,
    pub reason: String,
}

impl JevVerdict {
    pub fn decide(p_destructive: f64, confidence: f64, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let verdict = if p_destructive >= 0.8 && confidence >= 0.5 {
            Verdict::Block
        } else if p_destructive >= 0.4 {
            Verdict::Confirm
        } else {
            Verdict::Allow
        };
        Self { p_destructive, confidence, verdict, reason }
    }
}

/// Deterministic destructive-bash score over argv text. Conservative direction:
/// over-flags escalate, never allow. Mirrors the `jev_gate::decide_with_threshold`
/// shape (probability + confidence → Allow/Confirm/Block).
pub fn decide_with_threshold(argv: &[String], threshold: f64) -> JevVerdict {
    let blob = argv.join("\n").to_lowercase();
    let mut p = 0.0f64;
    let mut reasons: Vec<&str> = Vec::new();
    let has = |s: &str| blob.contains(s);
    if (has("rm") && (has("-rf") || has("-fr") || has("--recursive")))
        && (has("--no-preserve-root") || has(" /") || has("/*") || blob.trim_end().ends_with('/'))
    {
        p = p.max(0.95);
        reasons.push("RM_RF_ROOT");
    }
    if (has("curl") || has("wget")) && blob.contains('|') && (has("sh") || has("bash")) {
        p = p.max(0.85);
        reasons.push("PIPE_TO_SHELL");
    }
    if has("mkfs") || has(":(){:|:&};:") || has("dd ") && has("of=/dev/") {
        p = p.max(0.95);
        reasons.push("DISK_OR_FORK_DESTRUCTIVE");
    }
    if (has("chmod") || has("chown")) && has("-r") && (has(" /") || has("/*")) {
        p = p.max(0.7);
        reasons.push("RECURSIVE_PERM_ROOT");
    }
    if p == 0.0 && (has("rm ") || has("rm\t")) {
        p = p.max(0.45);
        reasons.push("RM_ANY");
    }
    if p == 0.0 && (has("shutdown") || has("reboot") || has("halt") || has("poweroff")) {
        p = p.max(0.6);
        reasons.push("HOST_POWER");
    }
    let confidence = if reasons.is_empty() { 0.9 } else { 0.7 };
    let verdict = if p >= threshold.max(0.8) && confidence >= 0.5 {
        Verdict::Block
    } else if p >= 0.4 {
        Verdict::Confirm
    } else {
        Verdict::Allow
    };
    JevVerdict { p_destructive: p, confidence, verdict, reason: if reasons.is_empty() { "NO_DESTRUCTIVE_PATTERN".into() } else { reasons.join(",") } }
}

/// Stable hash of a command for dedupe/audit.
pub fn command_hash(argv: &[String]) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    for arg in argv {
        hasher.update(arg.as_bytes());
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}
/// Deterministic network-egress deny (in-repo port of sOMP's
/// `jev_gate::deny_network_command`; never depends on or shells out to somp).
///
/// Joins argv, lowercases, then denies on URL markers (`http://` etc),
/// socket-tool markers at command start or after shell separators, and
/// `/dev/tcp|udp` + `/inet/tcp|udp` redirections. Wrapper prefixes
/// (`env`/`timeout`/`sudo`/`bash`/`sh`/`xargs` …) are stripped in a loop so
/// `timeout 5 curl …` still fails closed, while prose (`echo curl`) stays
/// allowed. Returns the matched token for the `EGRESS_DENY:<token>` reason.
const WRAPPERS: &[&str] = &[
    "env", "timeout", "sudo", "doas", "runuser", "su", "nice", "nohup", "stdbuf", "unshare",
    "nsenter", "setsid", "flock", "ionice", "taskset", "numactl", "strace", "watch", "sh", "bash",
    "dash", "zsh", "fish", "ksh", "xargs", "script",
];

/// Strip leading wrapper names; returns (remainder, progressed). Loops so
/// `sudo timeout 5 curl` strips twice. Flags/args between the wrapper and
/// the real command are NOT parsed — the remainder is token-scanned instead.
fn strip_wrappers(mut s: &str) -> (&str, bool) {
    let mut progressed = false;
    while let Some(r) = WRAPPERS.iter().find_map(|w| {
        let t = s.trim_start();
        if t == *w || (t.starts_with(w) && t[w.len()..].starts_with([' ', '\t', '\n'])) {
            Some(&t[w.len()..])
        } else {
            None
        }
    }) {
        s = r;
        progressed = true;
    }
    (s.trim_start(), progressed)
}

/// Any whitespace/punct-delimited token of `s` names `tool`
/// (path-basename-aware: `/usr/bin/ping` counts as `ping`).
fn remainder_has_tool(s: &str, tool: &str) -> bool {
    s.split([
        ' ', '\t', '\n', ';', '|', '&', '(', ')', '`', '"', '\'', '{', '}', '$', ',', ':', '=', '+',
    ])
    .any(|tok| tok == tool || (tok.contains('/') && tok.rsplit('/').next() == Some(tool)))
}

/// Whole command + every shell-separator tail: each is an independent
/// candidate for tool matching.
fn egress_candidates(lower: &str) -> Vec<&str> {
    const SEPS: &[&str] = &[";", "&&", "||", "|", "$(", "`", "\n"];
    let mut out = vec![lower];
    let mut rest = lower;
    while let Some(idx) = SEPS.iter().filter_map(|s| rest.find(s)).min() {
        let tail = &rest[idx..];
        let tail = tail.trim_start_matches([';', '&', '|', '(', '`', '$', '{', ' ', '\t']);
        out.push(tail);
        rest = &rest[(idx + 1).min(rest.len())..];
    }
    out
}

/// True when the candidate invokes `tool`: direct at start
/// (absolute-path aware), or as any argv token once a WRAPPERS prefix was
/// stripped. `echo curl` prose stays false.
fn candidate_has_tool(cand: &str, tool: &str) -> bool {
    const AFTER: [char; 9] = [' ', '\t', '\n', '-', '/', '"', '\'', ')', '}'];
    let t = cand.trim_start();
    if t == tool || (t.starts_with(tool) && t[tool.len()..].starts_with(AFTER)) {
        return true;
    }
    if let Some(first) = t.split([' ', '\t', '\n']).next() {
        if first.contains('/') && first.rsplit('/').next() == Some(tool) {
            return true;
        }
    }
    let (stripped, progressed) = strip_wrappers(t);
    if progressed && remainder_has_tool(stripped, tool) {
        return true;
    }
    false
}

/// True when `lower` invokes `tool` at command start or after a shell
/// separator. Shared by the tool-marker loop.
fn starts_tool(lower: &str, tool: &str) -> bool {
    egress_candidates(lower).iter().any(|c| candidate_has_tool(c, tool))
}

pub fn deny_network_command(argv: &[String]) -> Option<&'static str> {
    const URL_MARKERS: &[&str] = &[
        "http://", "https://", "ws://", "wss://", "ftp://", "ssh://", "git://",
    ];
    const TOOL_MARKERS: &[&str] = &[
        "curl", "wget", "ssh", "scp", "sftp", "ftp", "nc", "ncat", "socat", "telnet", "rsync",
        "openssl", "s_client", "psql", "mysql", "redis-cli", "ping", "dig", "nmap",
    ];
    const REDIR_MARKERS: &[&str] = &["/dev/tcp/", "/dev/udp/", "/inet/tcp/", "/inet/udp/"];
    let lower = argv.join(" ").to_lowercase();
    for &m in URL_MARKERS {
        if lower.contains(m) {
            return Some(m.trim_end_matches("://"));
        }
    }
    for &name in TOOL_MARKERS {
        if starts_tool(&lower, name) {
            return Some(name);
        }
    }
    REDIR_MARKERS.iter().copied().find(|m| lower.contains(m))
}

/// Secret-path deny list. Never overridden by model or advisor.
fn secret_path_hit(argv: &[String]) -> Option<&'static str> {
    const DENY: &[&str] = &[
        ".ssh", ".aws", "id_rsa", "id_ed25519", ".pem", "/etc/shadow", "/etc/passwd",
        "credentials.json", ".gnupg", "master-", ".env", "release.key",
    ];
    let blob = argv.join("\n").to_lowercase();
    DENY.iter().copied().find(|p| blob.contains(p))
}

fn shell_descriptor() -> orbit_core::ToolDescriptor {
    use orbit_core::{ToolDescriptor, ToolEffects};
    ToolDescriptor {
        id: Uuid::nil(),
        name: "shell.execute".into(),
        version: "1".into(),
        input_schema: Value::Null,
        output_schema: Value::Null,
        effects: ToolEffects { external: false, modifies_data: true, reversible: false, credential_access: false, affected_party: "owner".into(), network: false },
        default_risk: RiskLevel::High,
        permission_keys: Vec::new(),
        sandbox_required: true,
    }
}

/// Thin gate for any model-proposed bash: deterministic floor + Jev verdict.
/// `Block`/`Confirm` from either source short-circuit; `Allow` proceeds.
/// Network egress is ADVISORY here (`EGRESS:<token>` reason on the Jev
/// verdict, never a hard block): internet access stays allowed until an
/// owner policy rule denies it. See `deny_network_command`.
pub fn classify_command(argv: &[String]) -> Result<Verdict> {
    let egress = deny_network_command(argv);
    let action = ProposedAction { tool_name: "shell.execute".into(), arguments: serde_json::json!({"command": argv.join(" ")}) };
    let assessment = RiskClassifier::classify_action(&action, &shell_descriptor(), &ActionContext::default())?;
    let floor_verdict = match assessment.level {
        RiskLevel::Forbidden | RiskLevel::Critical => Verdict::Block,
        RiskLevel::High | RiskLevel::Medium => Verdict::Confirm,
        _ => Verdict::Allow,
    };
    if floor_verdict == Verdict::Block {
        return Ok(Verdict::Block);
    }
    let jev = decide_with_threshold(argv, 0.8);
    let mut jev = jev;
    if let Some(token) = egress {
        jev.reason = format!("EGRESS:{token} {}", jev.reason);
    }
    match (floor_verdict, jev.verdict) {
        (Verdict::Block, _) | (_, Verdict::Block) => Ok(Verdict::Block),
        (Verdict::Confirm, _) | (_, Verdict::Confirm) => Ok(Verdict::Confirm),
        _ => Ok(Verdict::Allow),
    }
}

/// Governed sandbox execution — the in-repo sOMP dispatch.
pub struct GovernedExec {
    rt: Arc<dyn TaskRuntime>,
    pub image: String,
    pub disk_mb: u32,
    pub max_depth: u32,
    /// Brokered model egress for backends that call a model from the guest.
    /// `None` keeps the strict no-network Guard. Set via [`GovernedExec::with_egress`].
    pub egress: Option<ModelEgress>,
}

impl GovernedExec {
    pub fn new(rt: Arc<dyn TaskRuntime>, image: String, disk_mb: u32, max_depth: u32) -> Self {
        Self { rt, image, disk_mb, max_depth, egress: None }
    }
    pub fn with_egress(mut self, egress: ModelEgress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Ordered fail-closed gate + staged sandbox execution. The sandbox is
    /// destroyed in a `finally` path on every outcome.
    pub async fn dispatch(&self, scope: &OwnerScope, req: ExecRequest) -> Result<ExecOutcome> {
        let _ = scope.owner_id;
        // (a0) egress screen is ADVISORY: record the token for policy, do
        // not refuse here. Internet stays allowed until an owner policy
        // rule denies it (policy crate, shell.execute egress rule).
        let _egress_token = deny_network_command(&req.command);
        // (a) deterministic risk floor.
        let action = ProposedAction { tool_name: "shell.execute".into(), arguments: serde_json::json!({"command": req.command.join(" ")}) };
        let assessment = RiskClassifier::classify_action(&action, &shell_descriptor(), &ActionContext::default())?;
        if matches!(assessment.level, RiskLevel::Forbidden | RiskLevel::Critical) {
            return Err(Error::Forbidden);
        }
        // (b) Jev destructive-bash verdict. Block never proceeds; Confirm needs
        // prior Dispatcher approval (`approved`), still re-verified here.
        match decide_with_threshold(&req.command, 0.8).verdict {
            Verdict::Block => return Err(Error::Forbidden),
            Verdict::Confirm if !req.approved => return Err(Error::Validation("command requires owner confirmation".into())),
            _ => {}
        }
        // Medium/High floor likewise requires prior approval rather than auto-exec.
        if matches!(assessment.level, RiskLevel::High | RiskLevel::Medium) && !req.approved {
            return Err(Error::Validation("command requires owner confirmation".into()));
        }
        // (c) secret-path deny.
        if secret_path_hit(&req.command).is_some() {
            return Err(Error::Forbidden);
        }
        // (d) depth guard.
        if req.depth > self.max_depth {
            return Err(Error::Validation("subagent depth exceeded".into()));
        }
        if req.command.is_empty() || req.timeout_s == 0 || req.timeout_s > 120 {
            return Err(Error::Validation("invalid exec request bounds".into()));
        }

        let started = Instant::now();
        let run_id = Uuid::new_v4();
        let spec = RuntimeSpec {
            run_id,
            image: self.image.clone(),
            cpu: 1,
            memory_mb: 512,
            disk_mb: self.disk_mb,
            lifetime_seconds: LIFETIME_SECONDS,
            network_enabled: false,
            inputs: Vec::new(),
            egress: self.egress.clone(),
        };
        spec.validate()?;
        let handle = self.rt.create(spec).await?;
        let sandbox_id = handle.id();

        let run = async {
            // Stage TASK.md-equivalent + requested files into /workspace/repository.
            if req.files.len() > 10 {
                return Err(Error::Validation("too many stage files".into()));
            }
            for file in &req.files {
                orbit_task_runtime::workspace_path(&file.path, false)?;
                if file.content.len() > orbit_task_runtime::FILE_LIMIT {
                    return Err(Error::Validation("stage file exceeds 1 MiB".into()));
                }
                self.rt.put_file(&handle, &file.path, &file.content).await?;
            }
            // Baseline so the diff captures exactly what the guest changed.
            let baseline = RuntimeTask {
                argv: vec!["sh".into(), "-c".into(), "cd /workspace/repository 2>/dev/null || (mkdir -p /workspace/repository && cd /workspace/repository); git init -q 2>/dev/null; git add -A 2>/dev/null; git -c user.email=orbit -c user.name=orbit commit -qm baseline 2>/dev/null; true".into()],
                working_directory: "/workspace".into(),
                timeout_seconds: 30,
                output_paths: Vec::new(),
            };
            self.rt.execute(&handle, baseline).await?;
            // Execute the requested command.
            let task = RuntimeTask {
                argv: req.command.clone(),
                working_directory: "/workspace/repository".into(),
                timeout_seconds: req.timeout_s,
                output_paths: Vec::new(),
            };
            let result = self.rt.execute(&handle, task).await?;
            // Diff of guest changes.
            let diff_task = RuntimeTask {
                argv: vec!["sh".into(), "-c".into(), "git add -N . 2>/dev/null; git diff --stat; echo '---'; git diff".into()],
                working_directory: "/workspace/repository".into(),
                timeout_seconds: 30,
                output_paths: Vec::new(),
            };
            let diff_out = self.rt.execute(&handle, diff_task).await?;
            // Scrub staged request content from the guest before destroy.
            let scrub = RuntimeTask {
                argv: vec!["sh".into(), "-c".into(), "git checkout -q . 2>/dev/null; git clean -fdq 2>/dev/null; true".into()],
                working_directory: "/workspace/repository".into(),
                timeout_seconds: 30,
                output_paths: Vec::new(),
            };
            let _ = self.rt.execute(&handle, scrub).await;
            Ok::<_, Error>((result, diff_out.stdout))
        }
        .await;

        // Finally: always destroy the sandbox, then propagate gate/exec outcome.
        let destroy_err = self.rt.destroy(handle).await.err();
        let (result, diff_stdout) = run?;
        if let Some(e) = destroy_err {
            return Err(e);
        }
        let duration_ms = started.elapsed().as_millis() as u64;
        Ok(ExecOutcome {
            sandbox_id,
            exit_code: result.exit_code.unwrap_or(-1),
            stdout: result.stdout,
            stderr: result.stderr,
            diff: Value::String(diff_stdout),
            duration_ms,
        })
    }

    /// Run a subagent in its own AIec sandbox: stage `task_text` as TASK.md and
    /// exec the model-loop command. Replaces the `somp dispatch` path.
    pub async fn run_subagent(&self, scope: &OwnerScope, task_text: &str, args: SubagentArgs, depth: u32) -> Result<ExecOutcome> {
        if task_text.is_empty() || task_text.len() > 65536 {
            return Err(Error::Validation("invalid subagent task text".into()));
        }
        let mut files = vec![StageFile { path: "/workspace/repository/TASK.md".into(), content: task_text.as_bytes().to_vec() }];
        files.extend(args.files);
        self.dispatch(scope, ExecRequest { command: args.command, files, timeout_s: args.timeout_s, depth: depth + 1, approved: args.approved }).await
    }
}

/// Arguments for a subagent run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubagentArgs {
    pub command: Vec<String>,
    pub files: Vec<StageFile>,
    pub timeout_s: u64,
    /// Same fail-closed approval threading as [`ExecRequest::approved`].
    pub approved: bool,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_bash_blocked_by_gate() {
        let argv = vec!["sh".into(), "-c".into(), "rm -rf / --no-preserve-root".into()];
        assert_eq!(classify_command(&argv).unwrap(), Verdict::Block);
        // Deterministic floor alone, independent of any model.
        let jev = decide_with_threshold(&argv, 0.8);
        assert_eq!(jev.verdict, Verdict::Block);
    }

    #[test]
    fn benign_echo_allowed() {
        let argv = vec!["echo".into(), "ok".into()];
        let jev = decide_with_threshold(&argv, 0.8);
        assert_eq!(jev.verdict, Verdict::Allow);
    }

    #[test]
    fn command_hash_stable() {
        let a = vec!["echo".to_string(), "ok".to_string()];
        let b = vec!["echo".to_string(), "ok".to_string()];
        assert_eq!(command_hash(&a), command_hash(&b));
        assert_eq!(command_hash(&a).len(), 64);
    }

    #[test]
    fn secret_path_deny_hits() {
        let argv = vec!["cat".into(), "~/.ssh/id_rsa".into()];
        assert!(secret_path_hit(&argv).is_some());
        let clean = vec!["echo".into(), "ok".into()];
        assert!(secret_path_hit(&clean).is_none());
    }
    #[test]
    fn egress_deny_curl_pipe() {
        let argv = vec!["curl".into(), "https://example.com/x".into(), "|".into(), "sh".into()];
        assert!(deny_network_command(&argv).is_some());
        assert_eq!(classify_command(&argv).unwrap(), Verdict::Block);
    }

    #[test]
    fn egress_advisory_wrapper_laundered() {
        // Internet allowed until policy denies: screen fires, gate stays Allow.
        let argv = vec!["timeout".into(), "5".into(), "curl".into(), "https://example.com/x".into()];
        assert!(deny_network_command(&argv).is_some());
        assert_eq!(classify_command(&argv).unwrap(), Verdict::Confirm);
    }

    #[test]
    fn egress_deny_prose_non_fire() {
        let argv = vec!["echo".into(), "curl".into()];
        assert!(deny_network_command(&argv).is_none());
        assert_eq!(decide_with_threshold(&argv, 0.8).verdict, Verdict::Allow);
    }

    #[test]
    fn egress_advisory_openssl_s_client() {
        let argv = vec!["openssl".into(), "s_client".into(), "-connect".into(), "example.com:443".into()];
        assert!(deny_network_command(&argv).is_some());
        assert_eq!(classify_command(&argv).unwrap(), Verdict::Confirm);
    }
    use orbit_task_runtime::{Artifact, RuntimeHandle, RuntimeOutcome, RuntimeResult};
    use parking_lot::Mutex;

    /// Fake runtime proving the full lifecycle: gate → create → stage → baseline →
    /// exec → diff → destroy. Gate rejects create no sandbox.
    struct FakeRuntime {
        created: Mutex<Vec<Uuid>>,
        put: Mutex<Vec<String>>,
        execs: Mutex<Vec<Vec<String>>>,
        destroyed: Mutex<Vec<Uuid>>,
        diff_stdout: String,
    }
    #[async_trait::async_trait]
    impl TaskRuntime for FakeRuntime {
        async fn create(&self, spec: RuntimeSpec) -> Result<RuntimeHandle> {
            spec.validate()?;
            self.created.lock().push(spec.run_id);
            Ok(RuntimeHandle::observed(spec.run_id, chrono::Utc::now(), LIFETIME_SECONDS))
        }
        async fn execute(&self, _handle: &RuntimeHandle, task: RuntimeTask) -> Result<RuntimeResult> {
            task.validate()?;
            self.execs.lock().push(task.argv.clone());
            let out = if task.argv.iter().any(|a| a.contains("git diff")) { self.diff_stdout.clone() } else { "ok".into() };
            Ok(RuntimeResult { outcome: RuntimeOutcome::Exited, exit_code: Some(0), stdout: out, stderr: String::new(), duration_ms: Some(1), output_completeness: "TEST".into() })
        }
        async fn put_file(&self, _handle: &RuntimeHandle, path: &str, bytes: &[u8]) -> Result<()> {
            orbit_task_runtime::workspace_path(path, false)?;
            self.put.lock().push(format!("{path}:{}", bytes.len()));
            Ok(())
        }
        async fn collect_artifacts(&self, _handle: &RuntimeHandle) -> Result<Vec<Artifact>> { Ok(Vec::new()) }
        async fn destroy(&self, handle: RuntimeHandle) -> Result<()> {
            self.destroyed.lock().push(handle.id());
            Ok(())
        }
    }

    fn test_exec(image: &str) -> (GovernedExec, Arc<FakeRuntime>) {
        let fake = Arc::new(FakeRuntime { created: Mutex::new(Vec::new()), put: Mutex::new(Vec::new()), execs: Mutex::new(Vec::new()), destroyed: Mutex::new(Vec::new()), diff_stdout: " M out.txt".into() });
        let rt: Arc<dyn TaskRuntime> = fake.clone();
        (GovernedExec::new(rt, image.into(), 1024, 1), fake)
    }
    fn scope() -> OwnerScope { OwnerScope { owner_id: Uuid::new_v4(), principal_id: Uuid::new_v4() } }

    #[tokio::test]
    async fn dispatch_full_lifecycle() {
        let (exec, fake) = test_exec("admitted-image");
        let outcome = exec.dispatch(&scope(), ExecRequest {
            command: vec!["echo".into(), "ok".into()],
            files: vec![StageFile { path: "/workspace/repository/TASK.md".into(), content: b"do it".to_vec() }],
            timeout_s: 30, depth: 0, approved: true,
        }).await.unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.stdout, "ok");
        assert!(outcome.diff.as_str().unwrap().contains("out.txt"));
        // create → stage → baseline → exec → diff → scrub → destroy, exactly once each end.
        assert_eq!(fake.created.lock().len(), 1);
        assert_eq!(*fake.put.lock(), vec!["/workspace/repository/TASK.md:5".to_string()]);
        assert_eq!(fake.execs.lock().len(), 4);
        assert_eq!(fake.execs.lock()[1], vec!["echo".to_string(), "ok".to_string()]);
        assert_eq!(*fake.destroyed.lock(), *fake.created.lock());
        assert_eq!(outcome.sandbox_id, fake.created.lock()[0]);
    }

    #[tokio::test]
    async fn gate_rejects_create_nothing() {
        let (exec, fake) = test_exec("admitted-image");
        // Destructive bash: Block, no sandbox ever created.
        let err = exec.dispatch(&scope(), ExecRequest {
            command: vec!["sh".into(), "-c".into(), "rm -rf / --no-preserve-root".into()],
            files: Vec::new(), timeout_s: 30, depth: 0, approved: true,
        }).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden));
        assert!(fake.created.lock().is_empty());
        // Secret path: Block even with approval.
        let err = exec.dispatch(&scope(), ExecRequest {
            command: vec!["cat".into(), "~/.ssh/id_rsa".into()],
            files: Vec::new(), timeout_s: 30, depth: 0, approved: true,
        }).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden));
        assert!(fake.created.lock().is_empty());
        // shell.execute floor is High → Confirm-level needs approval first.
        let err = exec.dispatch(&scope(), ExecRequest {
            command: vec!["echo".into(), "hi".into()],
            files: Vec::new(), timeout_s: 30, depth: 0, approved: false,
        }).await.unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
        assert!(fake.created.lock().is_empty());
    }

    #[tokio::test]
    async fn subagent_stages_task_md() {
        let (exec, fake) = test_exec("admitted-image");
        let outcome = exec.run_subagent(&scope(), "sub task", SubagentArgs {
            command: vec!["echo".into(), "sub".into()], files: Vec::new(), timeout_s: 30, approved: true,
        }, 0).await.unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(*fake.put.lock(), vec!["/workspace/repository/TASK.md:8".to_string()]);
        // Depth guard: max_depth=1, depth 1 → 2 exceeds.
        let err = exec.run_subagent(&scope(), "deep", SubagentArgs {
            command: vec!["echo".into(), "x".into()], files: Vec::new(), timeout_s: 30, approved: true,
        }, 1).await.unwrap_err();
        assert!(matches!(err, Error::Validation(_)));
    }
}
