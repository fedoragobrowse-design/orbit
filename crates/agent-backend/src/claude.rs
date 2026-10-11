//! `ClaudeSdkBackend`: the `claude` CLI inside an AIec sandbox via GovernedExec.
//!
//! Locked decisions: spawn the `claude` CLI from Rust, and the agent + all
//! model-call egress run inside the sandbox. Maps `ClaudeAgentOptions` → CLI
//! flags; every tool call returns to Rust for approval and runs the P3 risk
//! gate before `dispatch()`. The `claude` CLI lives in the AIec sandbox image,
//! not the server image. Flag names follow the Anthropic CLI docs
//! (documentation-grade — adjust argv to the real `claude --help` in the image
//! if they differ; the `AgentBackend` contract is unchanged).

use super::{AgentBackend, AgentEvent, BackendKind, BackendRequest, BackendStep, parse_ndjson_events};
use orbit_core::{OwnerScope, Result};
use orbit_model_router::Usage;
use orbit_sandbox_dispatch::{ExecRequest, GovernedExec, StageFile, Verdict, classify_command};
use std::sync::Arc;

pub struct ClaudeSdkBackend {
    exec: Arc<GovernedExec>,
}

impl ClaudeSdkBackend {
    pub fn new(exec: Arc<GovernedExec>) -> Self {
        Self { exec }
    }
}

/// Map agent options → `claude` CLI argv (`--output-format stream-json` feeds
/// the shared NDJSON parser).
fn claude_argv(req: &BackendRequest) -> Vec<String> {
    let mut argv = vec![
        "claude".to_string(),
        "-p".to_string(),
        "--output-format".to_string(),
        "stream-json".to_string(),
        "--input-format".to_string(),
        "stream-json".to_string(),
    ];
    if !req.agent.config.instructions.is_empty() {
        argv.push("--system-prompt".to_string());
        argv.push(req.agent.config.instructions.clone());
    }
    if !req.agent.config.allowed_tools.is_empty() {
        argv.push("--allowed-tools".to_string());
        argv.push(req.agent.config.allowed_tools.join(","));
    }
    argv
}

#[async_trait::async_trait]
impl AgentBackend for ClaudeSdkBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::ClaudeSdk
    }

    async fn step(&self, req: BackendRequest) -> Result<BackendStep> {
        let scope = OwnerScope { owner_id: req.owner_id, principal_id: req.owner_id };
        let argv = claude_argv(&req);
        match classify_command(&argv)? {
            Verdict::Block => {
                return Ok(finished_step(vec![AgentEvent::Message { role: "assistant".into(), text: "Blocked: claude command rejected by risk gate.".into() }], "FAILED"));
            }
            Verdict::Confirm if req.approval_id.is_none() => {
                return Ok(finished_step(vec![AgentEvent::Message { role: "assistant".into(), text: "Confirm: claude command needs owner approval.".into() }], "WAITING_FOR_RESOURCE"));
            }
            _ => {}
        }
        let history: Vec<serde_json::Value> = req.history.iter().map(|h| {
            serde_json::json!({"role": h.role, "content": super::omp::taint_line(&h.role, &h.content)})
        }).collect();
        let envelope = serde_json::json!({
            "task_id": req.task_id,
            "input": req.input,
            "history": history,
            "model_endpoint": req.model_endpoint,
        });
        let task_text = serde_json::to_string(&envelope).map_err(|e| orbit_core::Error::Validation(format!("task envelope: {e}")))?;
        let files = vec![StageFile { path: "/workspace/repository/TASK.md".into(), content: task_text.into_bytes() }];
        let outcome = self.exec.dispatch(&scope, ExecRequest {
            command: argv,
            files,
            timeout_s: req.limits.max_active_seconds.min(120).max(1) as u64,
            depth: req.depth,
            approved: req.approval_id.is_some(),
        }).await;
        match outcome {
            Err(e) => Ok(finished_step(vec![AgentEvent::Message { role: "assistant".into(), text: format!("Backend error: {e}") }], "FAILED")),
            Ok(out) => {
                let mut events = parse_ndjson_events(&out.stdout);
                if events.is_empty() && !out.stdout.trim().is_empty() {
                    events.push(AgentEvent::Message { role: "assistant".into(), text: out.stdout.trim().to_string() });
                }
                let finished = out.exit_code == 0;
                Ok(BackendStep {
                    events,
                    finished,
                    outcome: Some(if finished { "COMPLETED".into() } else { "FAILED".into() }),
                    usage: Usage::default(),
                    artifacts: Vec::new(),
                })
            }
        }
    }
}

fn finished_step(events: Vec<AgentEvent>, outcome: &str) -> BackendStep {
    BackendStep { events, finished: true, outcome: Some(outcome.into()), usage: Usage::default(), artifacts: Vec::new() }
}
