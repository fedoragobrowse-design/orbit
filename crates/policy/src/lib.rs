use orbit_core::{AutonomyMode, OwnerScope, RiskLevel, ToolDescriptor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyLayer {
    Administrator,
    Owner,
    Integration,
    Tool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: Uuid,
    pub layer: PolicyLayer,
    pub tool_pattern: String,
    pub scope_key: Option<String>,
    pub deny: bool,
    pub requires_approval: bool,
    pub requires_sandbox: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGrant {
    pub id: Uuid,
    pub tool_name: String,
    pub scope_key: String,
    pub scope_revision: i64,
    pub max_risk: RiskLevel,
    pub autonomy_modes: Vec<AutonomyMode>,
    pub parameter_bounds: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyOutcome {
    Allow,
    Deny,
    RequireApproval,
    SandboxOnly,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub outcome: PolicyOutcome,
    pub denied: bool,
    pub requires_approval: bool,
    pub requires_sandbox: bool,
    pub matched_rules: Vec<Uuid>,
    pub policy_revision: i64,
    pub scope_revisions: BTreeMap<String, i64>,
    pub reason_codes: Vec<String>,
}
pub struct PolicyEngine {
    pub revision: i64,
    pub autonomy: AutonomyMode,
    pub rules: Vec<PolicyRule>,
    pub grants: Vec<ScopeGrant>,
}
impl PolicyEngine {
    pub fn evaluate(
        &self,
        _scope: &OwnerScope,
        name: &str,
        args: &Value,
        descriptor: &ToolDescriptor,
        risk: RiskLevel,
        scopes: &BTreeMap<String, i64>,
    ) -> PolicyDecision {
        let safe_local = matches!(
            name,
            "notifications.create" | "reports.save" | "memory.search" | "memory.propose"
        );
        let scoped_default = matches!(
            name,
            "files.search"
                | "files.read"
                | "files.list"
                | "files.metadata"
                | "files.watch"
                | "email.read"
                | "email.search"
                | "email.draft"
        );
        let modifying = matches!(
            name,
            "files.write"
                | "files.move"
                | "files.copy"
                | "email.send"
                | "email.archive"
                | "email.label"
                | "shell.execute"
        );
        let explicitly_forbidden = name == "files.delete"
            || name.starts_with("payments.")
            || name.starts_with("secrets.")
            || name.starts_with("host.")
            || risk == RiskLevel::Forbidden;
        let mut denied = explicitly_forbidden
            || (!safe_local && !scoped_default && !modifying && !name.starts_with("mcp."));
        let mut reasons = vec!["SYSTEM_DEFAULTS".into()];
        if (scoped_default || modifying || name.starts_with("mcp.")) && scopes.is_empty() {
            denied = true;
            reasons.push("EXPLICIT_RESOURCE_SCOPE_REQUIRED".into());
        }
        let mut approval = modifying
            || risk >= RiskLevel::High
            || args.get("consent_required").and_then(Value::as_bool) == Some(true);
        let mut sandbox = descriptor.sandbox_required || name == "shell.execute";
        let mut matched = Vec::new();
        for rule in &self.rules {
            let matches_name = rule.tool_pattern == name
                || rule.tool_pattern == "*"
                || rule
                    .tool_pattern
                    .strip_suffix(".*")
                    .is_some_and(|prefix| name.starts_with(&format!("{prefix}.")));
            if matches_name
                && rule
                    .scope_key
                    .as_ref()
                    .is_none_or(|key| scopes.contains_key(key))
            {
                denied |= rule.deny;
                approval |= rule.requires_approval;
                sandbox |= rule.requires_sandbox;
                matched.push(rule.id);
            }
        }
        // Node/connector admission is an explicit resource grant. Autonomous modifying
        // effects require an additional bounded tool+resource grant, not merely a mode.
        let automatic_grant = !scopes.is_empty()
            && scopes.iter().all(|(key, revision)| {
                self.grants.iter().any(|grant| {
                    grant.tool_name == name
                        && grant.scope_key == *key
                        && grant.scope_revision == *revision
                        && risk <= grant.max_risk
                        && grant.autonomy_modes.contains(&self.autonomy)
                        && bounds_match(&grant.parameter_bounds, args)
                })
            });
        if name.starts_with("mcp.") && !automatic_grant {
            approval = true;
        }
        if descriptor.effects.external && descriptor.effects.modifies_data {
            match self.autonomy {
                AutonomyMode::Chat | AutonomyMode::Observe => {
                    denied = true;
                    reasons.push("AUTONOMY_EXTERNAL_MUTATION_CEILING".into());
                }
                AutonomyMode::Assist => approval = true,
                AutonomyMode::TrustedAutomation | AutonomyMode::Custom => {
                    if !automatic_grant {
                        approval = true;
                    }
                }
            }
        }
        // A LOW scoped explicit grant can remove only the default low-effect consent,
        // never a layer requirement, ASK-root consent, or HIGH/CRITICAL consent.
        if automatic_grant
            && risk <= RiskLevel::Low
            && !modifying
            && args.get("consent_required").and_then(Value::as_bool) != Some(true)
            && !self
                .rules
                .iter()
                .any(|r| matched.contains(&r.id) && r.requires_approval)
        {
            approval = false;
        }
        if explicitly_forbidden {
            reasons.push("SYSTEM_FORBIDDEN_CAPABILITY".into());
        }
        if risk >= RiskLevel::High {
            approval = true;
            reasons.push("HIGH_RISK_CONSENT_CEILING".into());
        }
        let outcome = if denied {
            PolicyOutcome::Deny
        } else if approval {
            PolicyOutcome::RequireApproval
        } else if sandbox {
            PolicyOutcome::SandboxOnly
        } else {
            PolicyOutcome::Allow
        };
        PolicyDecision {
            outcome,
            denied,
            requires_approval: approval,
            requires_sandbox: sandbox,
            matched_rules: matched,
            policy_revision: self.revision,
            scope_revisions: scopes.clone(),
            reason_codes: reasons,
        }
    }
    pub fn permits_proactive_models(&self) -> bool {
        self.autonomy != AutonomyMode::Chat
    }
}
/// Bounds are allowlisted exact values or numeric maxima; unspecified parameters
/// are not granted automatically. Identity fields are already bound by scope.
pub fn bounds_match(bounds: &Value, args: &Value) -> bool {
    let (Some(bounds), Some(args)) = (bounds.as_object(), args.as_object()) else {
        return false;
    };
    !bounds.is_empty()
        && args.iter().all(|(key, value)| {
            bounds.get(key).is_some_and(|bound| {
                if let Some(max) = bound.get("maximum").and_then(Value::as_f64) {
                    value.as_f64().is_some_and(|v| v <= max && v >= 0.0)
                } else if let Some(values) = bound.get("enum").and_then(Value::as_array) {
                    values.contains(value)
                } else {
                    bound == value
                }
            })
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    use orbit_core::ToolEffects;
    use serde_json::json;
    fn tool(
        name: &str,
        risk: RiskLevel,
        sandbox: bool,
        external: bool,
        modifies: bool,
    ) -> ToolDescriptor {
        ToolDescriptor {
            id: Uuid::new_v4(),
            name: name.into(),
            version: "1".into(),
            input_schema: json!({}),
            output_schema: json!({}),
            effects: ToolEffects {
                external,
                modifies_data: modifies,
                reversible: !modifies,
                credential_access: false,
                affected_party: "owner".into(),
                network: false,
            },
            default_risk: risk,
            permission_keys: vec![],
            sandbox_required: sandbox,
        }
    }
    fn engine(mode: AutonomyMode) -> PolicyEngine {
        PolicyEngine {
            revision: 7,
            autonomy: mode,
            rules: vec![],
            grants: vec![],
        }
    }
    fn scope() -> OwnerScope {
        OwnerScope {
            owner_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
        }
    }
    fn grant_for(tool: &str, key: &str) -> ScopeGrant {
        ScopeGrant {
            id: Uuid::new_v4(),
            tool_name: tool.into(),
            scope_key: key.into(),
            scope_revision: 2,
            max_risk: RiskLevel::Low,
            autonomy_modes: vec![AutonomyMode::TrustedAutomation],
            parameter_bounds: json!({"limit":{"maximum":50}}),
        }
    }
    fn deny_all() -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            layer: PolicyLayer::Administrator,
            tool_pattern: "*".into(),
            scope_key: None,
            deny: true,
            requires_approval: false,
            requires_sandbox: false,
        }
    }
    #[test]
    fn allow_for_safe_local_effect() {
        let d = engine(AutonomyMode::Observe).evaluate(
            &scope(),
            "notifications.create",
            &json!({}),
            &tool("notifications.create", RiskLevel::Low, false, false, true),
            RiskLevel::Low,
            &BTreeMap::new(),
        );
        assert!(
            matches!(d.outcome, PolicyOutcome::Allow)
                && !d.denied
                && !d.requires_approval
                && !d.requires_sandbox
                && d.policy_revision == 7
                && d.reason_codes.contains(&"SYSTEM_DEFAULTS".to_string())
        );
    }
    #[test]
    fn modifying_effects_require_approval() {
        let scopes = BTreeMap::from([("root:r".to_string(), 2)]);
        let d = engine(AutonomyMode::Assist).evaluate(
            &scope(),
            "files.write",
            &json!({"expected_version":1}),
            &tool("files.write", RiskLevel::High, false, true, true),
            RiskLevel::High,
            &scopes,
        );
        assert!(
            matches!(d.outcome, PolicyOutcome::RequireApproval)
                && !d.denied
                && d.requires_approval
                && d.scope_revisions == scopes
        );
    }
    #[test]
    fn sandbox_only_when_consent_is_granted_but_isolation_remains() {
        let scopes = BTreeMap::from([("root:r".to_string(), 2)]);
        let mut e = engine(AutonomyMode::TrustedAutomation);
        e.grants.push(grant_for("files.read", "root:r"));
        let d = e.evaluate(
            &scope(),
            "files.read",
            &json!({"limit":10}),
            &tool("files.read", RiskLevel::Low, true, false, false),
            RiskLevel::Low,
            &scopes,
        );
        assert!(
            matches!(d.outcome, PolicyOutcome::SandboxOnly)
                && !d.denied
                && !d.requires_approval
                && d.requires_sandbox
        );
    }
    #[test]
    fn forbidden_capabilities_are_denied() {
        for name in ["files.delete", "payments.send", "host.exec"] {
            let d = engine(AutonomyMode::TrustedAutomation).evaluate(
                &scope(),
                name,
                &json!({}),
                &tool(name, RiskLevel::ReadOnly, false, true, true),
                RiskLevel::Forbidden,
                &BTreeMap::new(),
            );
            assert!(
                matches!(d.outcome, PolicyOutcome::Deny) && d.denied,
                "{name} must be denied"
            );
        }
        let unknown = engine(AutonomyMode::Assist).evaluate(
            &scope(),
            "evil.tool",
            &json!({}),
            &tool("evil.tool", RiskLevel::Medium, false, true, true),
            RiskLevel::Medium,
            &BTreeMap::new(),
        );
        assert!(unknown.denied && matches!(unknown.outcome, PolicyOutcome::Deny));
    }
    #[test]
    fn deny_wins_and_sandbox_survives_consent() {
        let scopes = BTreeMap::from([("aiec:one".to_string(), 1)]);
        let mut e = engine(AutonomyMode::Assist);
        let d = e.evaluate(
            &scope(),
            "shell.execute",
            &json!({}),
            &tool("shell.execute", RiskLevel::High, true, true, true),
            RiskLevel::High,
            &scopes,
        );
        assert!(!d.denied && d.requires_approval && d.requires_sandbox);
        e.rules.push(deny_all());
        let d = e.evaluate(
            &scope(),
            "shell.execute",
            &json!({}),
            &tool("shell.execute", RiskLevel::High, true, true, true),
            RiskLevel::High,
            &scopes,
        );
        assert!(
            d.denied
                && d.requires_approval
                && d.requires_sandbox
                && matches!(d.outcome, PolicyOutcome::Deny)
        );
    }
    #[test]
    fn grant_cannot_override_higher_layer_denial() {
        let scopes = BTreeMap::from([("aiec:one".to_string(), 2)]);
        let mut e = engine(AutonomyMode::TrustedAutomation);
        e.rules.push(deny_all());
        e.grants.push(grant_for("shell.execute", "aiec:one"));
        let d = e.evaluate(
            &scope(),
            "shell.execute",
            &json!({}),
            &tool("shell.execute", RiskLevel::High, true, true, true),
            RiskLevel::High,
            &scopes,
        );
        assert!(d.denied && matches!(d.outcome, PolicyOutcome::Deny));
    }
    #[test]
    fn high_risk_is_never_automatic() {
        let scopes = BTreeMap::from([("aiec:one".to_string(), 1)]);
        let mut e = engine(AutonomyMode::TrustedAutomation);
        e.grants.push(grant_for("shell.execute", "aiec:one"));
        let d = e.evaluate(
            &scope(),
            "shell.execute",
            &json!({}),
            &tool("shell.execute", RiskLevel::High, true, true, true),
            RiskLevel::High,
            &scopes,
        );
        assert!(!d.denied && d.requires_approval && d.requires_sandbox);
    }
    #[test]
    fn autonomy_ceiling_denies_unattended_external_mutation() {
        let scopes = BTreeMap::from([("aiec:one".to_string(), 1)]);
        let d = engine(AutonomyMode::Observe).evaluate(
            &scope(),
            "shell.execute",
            &json!({}),
            &tool("shell.execute", RiskLevel::High, true, true, true),
            RiskLevel::High,
            &scopes,
        );
        assert!(
            d.denied
                && d.reason_codes
                    .contains(&"AUTONOMY_EXTERNAL_MUTATION_CEILING".to_string())
        );
    }
    #[test]
    fn mode_is_not_permission() {
        assert!(!bounds_match(&json!({}), &json!({"amount":100})));
        assert!(!bounds_match(
            &json!({"limit":{"maximum":5}}),
            &json!({"limit":6})
        ));
        assert!(bounds_match(
            &json!({"limit":{"maximum":50}}),
            &json!({"limit":10})
        ));
    }
}
