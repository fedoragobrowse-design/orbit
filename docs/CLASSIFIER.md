# Classifier (orbit-risk)

## Interface
- `RiskAdvisor::advise(&ProposedAction, &ActionContext) -> Option<RiskAssessment>`: pluggable, advisory-only. `Some` proposes an escalation; `None` means abstain/outage (keep the deterministic floor).
- `RiskAssessment::advisory(level, reason)`: helper for advisors. Only `level` + `reasons` flow into the classifier; `effects` in the audit record always comes from the `ToolDescriptor`.
- `RiskClassifier::classify_action(action, descriptor, context)`: exact historical signature/behavior contract; internally delegates to `classify_action_with_advisor(.., &RulesAdvisor)`. Existing call sites (`crates/api/src/agents.rs:77,260`, `crates/api/src/computers.rs:1306,1820`) compile unchanged.
- `RiskClassifier::classify_action_with_advisor(action, descriptor, context, advisor)`: pluggable entry point. Merge rule: `level = max(deterministic_floor, advisory_level)`; advisory reasons merged with an `ADVISORY:` prefix; a below-floor advisory records `ADVISORY_IGNORED_BELOW_FLOOR` and does not move `level`.

## Backends
- `RulesAdvisor` (default): wraps the deterministic known-harmful-argv heuristics (`ARGV_KNOWN_HARMFUL_RM_RF_ROOT`, `ARGV_PIPE_TO_SHELL`, `ARGV_CREDENTIAL_PATH`), each `High`+. Returns `None` for benign argv.
- `HttpAdvisor` (feature `http-advisor`, stub): unconfigured endpoint, network error, non-2xx, parse error, or timeout all return `None` — degrade to rules, never allow. No transport lives in `orbit-risk` by design.

## Advisory-only rule
Advisors can only escalate, never lower: `classify_action_with_advisor` takes the max, so an advisory `ReadOnly`/`Low` against a `High`/`Forbidden` floor leaves `level` untouched while recording the rejection in `reasons` for audit. `ActionContext::optional_escalation` follows the same max semantics (`CLASSIFIER_ESCALATION_ONLY`).

## Reason + confidence → audit (no call-site edits)
- `RiskAssessment.reasons` flows to the approvals/audit insert unchanged (`computers.rs` binds `risk.reasons`); advisory escalations and ignored-below-floor markers appear there automatically.
- `EventClassifier::Classification { reason, confidence, .. }` is populated by `EventClassifier::classify` (`reason` per event-type code, `confidence: 1.0`); audit consumers read those fields with no signature changes.

## JEV note
A hosted-model (JEV-style) advisor would be a remote API: the adapter belongs in `model-router` (which owns transports, credentials, retries), not in `orbit-risk`. It would implement `RiskAdvisor` via `model-router`, return `Some` only on a confident high-risk verdict, and return `None` on any error — preserving advisory-only max semantics. Not required for this slice.

## Status

Core advisory path: BUILT with unit proof in-crate (deterministic floor + advisory-max merge; see `crates/risk/src/lib.rs` tests). Not LIVE-PROVEN at the HTTP layer — no e2e path exercises classification end-to-end; roadmap per docs/PARITY.md. The J10 injection story is proven at the gateway layer instead (`crates/api/tests/injection.rs`, 6 tests; kill-switch guard in `crates/api/tests/ops.rs`).
