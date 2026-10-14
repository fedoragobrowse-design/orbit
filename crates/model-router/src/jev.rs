//! Jev decision-model advisor: hosted `POST /api/v1/agent/risk` as an
//! advisory-only [`RiskAdvisor`](orbit_risk::RiskAdvisor).
//!
//! The deterministic floor always wins: this advisor may ONLY escalate.
//! Unconfigured key, network error, non-2xx, parse error, timeout, or
//! insufficient credits all degrade to `None` (floor kept), never fail-open.
//! The credential lives in `SecretStore` behind a provider row whose origin
//! is `https://jevtypesafeai.com`; the key itself never enters logs, prompts,
//! or the repo.

use orbit_core::{OwnerScope, RiskLevel};
use orbit_risk::{ActionContext, ProposedAction, RiskAdvisor, RiskAssessment};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::path::PathBuf;
use std::time::Duration;

const JEV_ORIGIN: &str = "https://jevtypesafeai.com";
const JEV_RISK_PATH: &str = "/api/v1/agent/risk";
const JEV_TIMEOUT_SECS: u64 = 8;
/// Cap the serialized action blob so one classification stays far under the
/// 64k state budget (action + arguments, truncated, never secrets).
const MAX_STATE_CHARS: usize = 8000;

#[derive(Debug, Clone, Default)]
pub struct JevAdvisor {
    pool: Option<PgPool>,
    key_dir: Option<PathBuf>,
    decision_model: Option<String>,
}

impl JevAdvisor {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn new(pool: PgPool, key_dir: PathBuf, decision_model: Option<String>) -> Self {
        Self {
            pool: Some(pool),
            key_dir: Some(key_dir),
            decision_model,
        }
    }

    fn state_of(action: &ProposedAction) -> String {
        let mut state = format!(
            "tool: {}\narguments: {}",
            action.tool_name, action.arguments
        );
        if state.len() > MAX_STATE_CHARS {
            state.truncate(MAX_STATE_CHARS);
        }
        state
    }
}
impl RiskAdvisor for JevAdvisor {
    fn advise(
        &self,
        _action: &ProposedAction,
        _context: &ActionContext,
    ) -> Option<RiskAssessment> {
        // Synchronous trait: hosted fetch needs async; the async entry point
        // is `advise_async` below. Return None here so sync callers keep floor.
        None
    }
}

impl JevAdvisor {
    /// Async advisory fetch. Returns `None` on ANY failure (unconfigured,
    /// network, non-2xx, parse, timeout, 402) so callers keep the floor.
    pub async fn advise_async(
        &self,
        scope: &OwnerScope,
        action: &ProposedAction,
        _context: &ActionContext,
    ) -> Option<RiskAssessment> {
        let (pool, key_dir) = match (&self.pool, &self.key_dir) {
            (Some(p), Some(k)) => (p, k),
            _ => return None,
        };
        // Provider row pinned to Jev origin; key from SecretStore, never logged.
        let cred_id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT credential_id FROM model_providers WHERE owner_id=$1 AND configuration->>'origin'=$2 AND COALESCE((configuration->>'enabled')::boolean, false) AND credential_id IS NOT NULL LIMIT 1",
        )
        .bind(scope.owner_id)
        .bind(JEV_ORIGIN)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        let cred_id = match cred_id {
            Some(id) => id,
            None => return None,
        };
        let key = match orbit_secrets::SecretStore::open(pool.clone(), &key_dir)
            .await
            .ok()
        {
            Some(s) => match s.get(scope, cred_id).await {
                Ok(k) => k,
                Err(_) => return None,
            },
            None => return None,
        };
        let state = Self::state_of(action);
        let body = json!({
            "tool": action.tool_name,
            "arguments": action.arguments,
            "context": state,
        });
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(JEV_TIMEOUT_SECS))
            .build()
        {
            Ok(c) => c,
            Err(_) => return None,
        };
        let key = match std::str::from_utf8(&key) {
            Ok(k) => k,
            Err(_) => return None,
        };
        let mut req = client.post(format!("{JEV_ORIGIN}{JEV_RISK_PATH}")).bearer_auth(key);
        if let Some(m) = self.decision_model.as_deref() {
            req = req.header("X-Jev-Model", m);
        }
        let resp = match req.json(&body).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };
        if !resp.status().is_success() {
            return None;
        }
        let v: Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return None,
        };
        let level = match v.get("action").and_then(|a| a.as_str()) {
            Some("block") => RiskLevel::Critical,
            Some("confirm") => RiskLevel::High,
            Some("allow") => return None,
            _ => return None,
        };
        let risk = v.get("risk").and_then(|r| r.as_f64()).unwrap_or(0.0);
        let cats = v
            .get("categories")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str())
                    .take(8)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let conf = v.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);
        Some(RiskAssessment::advisory(
            level,
            format!("JEV:{level:?}:risk={risk:.2}:conf={conf:.2}:{cats}"),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disabled_advisor_returns_none() {
        let advisor = JevAdvisor::disabled();
        let scope = OwnerScope { owner_id: uuid::Uuid::nil(), principal_id: uuid::Uuid::nil() };
        let action = ProposedAction { tool_name: "shell.execute".into(), arguments: serde_json::json!({"command": ["rm", "-rf", "/"]}) };
        let ctx = ActionContext { optional_escalation: None };
        assert!(advisor.advise_async(&scope, &action, &ctx).await.is_none());
    }
    #[test]
    fn sync_advise_always_none() {
        let advisor = JevAdvisor::disabled();
        let action = ProposedAction { tool_name: "x".into(), arguments: serde_json::json!({}) };
        let ctx = ActionContext { optional_escalation: None };
        assert!(advisor.advise(&action, &ctx).is_none());
    }
    #[test]
    fn state_truncates_long_arguments() {
        let big = "x".repeat(20000);
        let action = ProposedAction { tool_name: "t".into(), arguments: serde_json::json!({"blob": big}) };
        assert!(JevAdvisor::state_of(&action).len() <= MAX_STATE_CHARS);
    }
}
