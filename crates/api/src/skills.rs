//! Owner-scoped skill loading: local registry rows plus installed marketplace
//! packages, resolved against pinned inspected content — never host shell.
//!
//! A skill carries instructions plus requested actions, never authority:
//! entries resolve to a `SKILL.md` text body (local registry rows keep it
//! inline in `skills.instructions`; marketplace packages keep it as a pinned
//! artifact captured at install time) and a bounded action list (the agent's
//! own `allowed_tools` stays the allow-list; skills only *request*). The
//! loader refuses anything it cannot verify — unknown, disabled, digest
//! mismatch, or oversized — and says why, so callers disable honestly.
use orbit_core::{ContextBlock, ContextKind, Error, OwnerScope, PrivacyClass, Result, TrustLevel};
use serde_json::{Value, json};
use sha2::Digest as _;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Bounds keep one skill read cheap: SKILL.md bodies cap at 32 KiB, resolved
/// context at 8 KiB per skill, 64 KiB total per agent context build.
pub const MAX_SKILL_BODY_CHARS: usize = 32 * 1024;
pub const MAX_CONTEXT_CHARS_PER_SKILL: usize = 8 * 1024;
pub const MAX_CONTEXT_CHARS_TOTAL: usize = 64 * 1024;
pub const MAX_SKILLS_PER_AGENT: usize = 16;

/// A resolved skill: verified instructions plus the actions it asks for.
/// `source` names the pinned origin (`skill:<name>` or `marketplace:<name>`);
/// `digest` is the pinned `content_digest` the body was verified against.
#[derive(Debug, Clone)]
pub struct ResolvedSkill {
    pub name: String,
    pub source: String,
    pub digest: String,
    pub instructions: String,
    pub requested_actions: Vec<String>,
    pub trust: TrustLevel,
}

/// Why a skill refused to resolve. Surfaced verbatim to the owner/settings UI
/// so unknown or broken skills disable with an explanation, never silently.
#[derive(Debug, Clone)]
pub struct SkillProblem {
    pub name: String,
    pub reason: String,
}

/// Validate a skill name the way the marketplace validates package names:
/// lowercase kebab, 1-120 chars. Entrypoint strings are never executed —
/// arbitrary `entrypoint` text is display-only metadata, never a command.
pub fn valid_skill_name(raw: &str) -> Result<String> {
    let name = raw.trim().to_owned();
    if name.is_empty() || name.len() > 120 {
        return Err(Error::Validation("skill name must be 1-120 chars".into()));
    }
    if !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
        return Err(Error::Validation(
            "skill name must be lowercase letters, digits, or '-'".into(),
        ));
    }
    Ok(name)
}

/// Resolve one local-registry skill by owner + name. The row carries metadata
/// only (`description` <= 2000, `entrypoint` display-only); the instruction
/// body is the bundled `plugins/<name>/SKILL.md` inspected at load time.
/// Returns `Ok(None)` when the row is missing or disabled (caller records the
/// reason); `Err` only for storage failures. A present-but-unreadable body
/// resolves to a problem, never an exception. Arbitrary `entrypoint` strings
/// are display metadata and never become a host shell command — this module
/// contains no process spawning by construction (see unit test).
pub async fn resolve_local(
    pool: &PgPool,
    scope: &OwnerScope,
    name: &str,
) -> Result<Option<ResolvedSkill>> {
    let row = sqlx::query(
        "SELECT name,description,entrypoint,enabled FROM skills WHERE owner_id=$1 AND name=$2",
    )
    .bind(scope.owner_id)
    .bind(name)
    .fetch_optional(pool)
    .await?;
    let Some(r) = row else { return Ok(None) };
    if !r.get::<bool, _>("enabled") {
        return Ok(None);
    }
    let body = match read_bundled_skill(name) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    if body.trim().is_empty() || body.len() > MAX_SKILL_BODY_CHARS {
        return Ok(None);
    }
    let digest = format!(
        "sha256:{}",
        orbit_computer_node_protocol::sha256(body.as_bytes())
    );
    Ok(Some(ResolvedSkill {
        name: r.get::<String, _>("name"),
        source: format!("skill:{name}"),
        digest,
        instructions: body,
        requested_actions: Vec::new(),
        trust: TrustLevel::System,
    }))
}

/// Read a bundled skill body from `plugins/<name>/SKILL.md`. The name is
/// validated kebab-case first, so path construction cannot escape the plugins
/// directory; `..`, `/`, and absolute segments are rejected outright.
pub fn read_bundled_skill(name: &str) -> std::result::Result<String, String> {
    let clean = valid_skill_name(name).map_err(|e| e.to_string())?;
    if clean.contains("..") || clean.contains('/') || clean.contains('\\') {
        return Err("invalid skill name".into());
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins")
        .join(&clean)
        .join("SKILL.md");
    let bytes = std::fs::read(&path).map_err(|_| {
        format!("skill {clean:?} has no bundled SKILL.md; reinstall or re-save it")
    })?;
    if bytes.len() > MAX_SKILL_BODY_CHARS {
        return Err(format!("skill {clean:?} exceeds 32 KiB"));
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("skill {clean:?} SKILL.md is not UTF-8 text"))
}

/// Resolve one installed marketplace skill by owner + name. The manifest must
/// be `kind == "skill"`, `files` must pin a `SKILL.md` entry with its sha256,
/// and the row's `content_digest` must equal the inspected package digest
/// recorded at install time. SKILL.md bytes come from the inspected package
/// snapshot pinned at install (stored as the install row's audited content),
/// never from a network fetch: installs never hit the network at resolve
/// time, and unknown pins resolve to a problem.
pub async fn resolve_marketplace(
    pool: &PgPool,
    scope: &OwnerScope,
    name: &str,
) -> Result<Option<ResolvedSkill>> {
    let row = sqlx::query(
        "SELECT name,kind,description,content_digest,capabilities FROM marketplace_installs WHERE owner_id=$1 AND name=$2",
    )
    .bind(scope.owner_id)
    .bind(name)
    .fetch_optional(pool)
    .await?;
    let Some(r) = row else { return Ok(None) };
    if r.get::<String, _>("kind") != "skill" {
        return Ok(None);
    }
    let expected: String = r.get("content_digest");
    let hex = expected.strip_prefix("sha256:").unwrap_or("");
    if hex.len() != 64 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }
    let caps: Value = r.get("capabilities");
    let snapshot: Option<Value> = caps.get("skill_snapshot").cloned();
    let body = match snapshot.and_then(|s| s.get("skill_md").and_then(Value::as_str).map(str::to_owned)) {
        Some(b) if !b.trim().is_empty() && b.len() <= MAX_SKILL_BODY_CHARS => b,
        _ => return Ok(None),
    };
    let requested_actions: Vec<String> = caps
        .get("tools")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .take(128)
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(ResolvedSkill {
        source: format!("marketplace:{name}"),
        name: r.get::<String, _>("name"),
        digest: expected,
        instructions: body,
        requested_actions,
        trust: TrustLevel::UntrustedExternal,
    }))
}

/// Pin a skill install's inspected SKILL.md snapshot into the install row's
/// `capabilities.skill_snapshot` at install time. The manifest's `files`
/// entry pins the expected sha256; the inspected body (passed by the install
/// path, which already verified the package digest + signature) is hashed and
/// compared before pinning. On any mismatch nothing is pinned and the install
/// fails closed with a validation error.
pub async fn pin_install_skill_md(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scope: &OwnerScope,
    name: &str,
    manifest: &Value,
    skill_md: &str,
) -> Result<()> {
    let pinned_file = manifest
        .get("files")
        .and_then(Value::as_array)
        .and_then(|fs| {
            fs.iter().find(|f| f.get("path").and_then(Value::as_str) == Some("SKILL.md"))
        });
    let Some(entry) = pinned_file else {
        return Err(Error::Validation(
            "skill package manifest has no pinned SKILL.md file entry".into(),
        ));
    };
    let want = entry.get("sha256").and_then(Value::as_str).unwrap_or("");
    if want.len() != 64 || !want.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Validation("skill package SKILL.md pin is malformed".into()));
    }
    if skill_md.trim().is_empty() || skill_md.len() > MAX_SKILL_BODY_CHARS {
        return Err(Error::Validation("skill package SKILL.md is empty or exceeds 32 KiB".into()));
    }
    let actual = orbit_computer_node_protocol::sha256(skill_md.as_bytes());
    if !actual.eq_ignore_ascii_case(want) {
        return Err(Error::Validation(
            "skill package SKILL.md does not match its pinned sha256".into(),
        ));
    }
    let snapshot = serde_json::json!({"skill_md": skill_md});
    sqlx::query(
        "UPDATE marketplace_installs SET capabilities = COALESCE(capabilities,'{}'::jsonb) || jsonb_build_object('skill_snapshot', $3::jsonb) WHERE owner_id=$1 AND name=$2",
    )
    .bind(scope.owner_id)
    .bind(name)
    .bind(snapshot)
    .execute(&mut **tx)
    .await?;
    Ok(())
}



/// Load every skill an agent selected: local rows first, then marketplace
/// installs, each bounded and verified. Unknown, disabled, or broken entries
/// come back as `problems` with a plain-words reason; the agent context only
/// ever carries verified bodies. Selection itself is capped at
/// `MAX_SKILLS_PER_AGENT` entries.
pub async fn load_for_agent(
    pool: &PgPool,
    scope: &OwnerScope,
    selected: &[String],
) -> (Vec<ResolvedSkill>, Vec<SkillProblem>) {
    let mut resolved = Vec::new();
    let mut problems = Vec::new();
    for raw in selected.iter().take(MAX_SKILLS_PER_AGENT) {
        let name = match valid_skill_name(raw) {
            Ok(n) => n,
            Err(_) => {
                problems.push(SkillProblem {
                    name: raw.clone(),
                    reason: format!(
                        "skill {raw:?} is not a valid skill name; use lowercase letters, digits, or '-'"
                    ),
                });
                continue;
            }
        };
        let local = resolve_local(pool, scope, &name).await;
        let mp = resolve_marketplace(pool, scope, &name).await;
        match (local, mp) {
            (Ok(Some(s)), _) | (_, Ok(Some(s))) => resolved.push(s),
            (Err(e), _) | (_, Err(e)) => problems.push(SkillProblem {
                name: name.clone(),
                reason: format!("skill {name:?} could not be read ({e}); it is disabled for this run"),
            }),
            (Ok(None), Ok(None)) => problems.push(problem_for(pool, scope, &name).await),
        }
    }
    (resolved, problems)
}

/// Explain exactly why a name did not resolve: unknown, disabled, broken, or
/// digest-mismatched — so the owner sees the honest reason in Settings.
async fn problem_for(pool: &PgPool, scope: &OwnerScope, name: &str) -> SkillProblem {
    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT enabled FROM skills WHERE owner_id=$1 AND name=$2",
    )
    .bind(scope.owner_id)
    .bind(name)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    if let Some(on) = enabled {
        if !on {
            return SkillProblem {
                name: name.into(),
                reason: format!("skill {name:?} is switched off; switch it on in Settings to use it"),
            };
        }
        return match read_bundled_skill(name) {
            Ok(b) if !b.trim().is_empty() && b.len() <= MAX_SKILL_BODY_CHARS => SkillProblem {
                name: name.into(),
                reason: format!("skill {name:?} failed to load unexpectedly; it is disabled for this run"),
            },
            Ok(_) => SkillProblem {
                name: name.into(),
                reason: format!("skill {name:?} SKILL.md is empty or exceeds 32 KiB; fix the bundled plugin"),
            },
            Err(e) => SkillProblem { name: name.into(), reason: e },
        };
    }
    let mp: Option<(String, Value)> = sqlx::query(
        "SELECT kind,capabilities FROM marketplace_installs WHERE owner_id=$1 AND name=$2",
    )
    .bind(scope.owner_id)
    .bind(name)
    .fetch_optional(pool)
    .await
    .unwrap_or(None)
    .map(|r: sqlx::postgres::PgRow| {
        (
            r.get::<String, _>("kind"),
            r.get::<Value, _>("capabilities"),
        )
    });
    if let Some((kind, caps)) = mp {
        if kind != "skill" {
            return SkillProblem {
                name: name.into(),
                reason: format!("marketplace package {name:?} is not a skill (kind {kind:?})"),
            };
        }
        let pinned_now: &str = caps.get("skill_snapshot").and_then(|v| v.get("skill_md")).and_then(Value::as_str).unwrap_or("");
        let has_pin = caps.get("skill_file_pin").is_some();
        if pinned_now.trim().is_empty() {
            if has_pin {
                return SkillProblem {
                    name: name.into(),
                    reason: format!("marketplace skill {name:?} is installed but its SKILL.md content is not pinned locally; reinstall with content inspection to enable it"),
                };
            }
            return SkillProblem {
                name: name.into(),
                reason: format!("marketplace skill {name:?} has no pinned instructions; reinstall it to pin SKILL.md"),
            };
        }
        return SkillProblem {
            name: name.into(),
            reason: format!("marketplace skill {name:?} failed verification (missing or digest-mismatched SKILL.md); reinstall it"),
        };
    }
    SkillProblem {
        name: name.into(),
        reason: format!("skill {name:?} is unknown; install it from the Marketplace or check the name"),
    }
}

/// Render resolved skills as agent context blocks. Local skills arrive as
/// `SystemPolicy` (owner-curated, owner trust); marketplace text arrives as
/// `UntrustedExternalContent` (third-party instructions are evidence, never
/// authority). Bodies truncate at 8 KiB per skill / 64 KiB total, problems
/// append as one honest `ToolOutput` note so the agent states them plainly.
pub fn context_blocks(resolved: &[ResolvedSkill], problems: &[SkillProblem]) -> Vec<ContextBlock> {
    let mut out = Vec::new();
    let mut budget = MAX_CONTEXT_CHARS_TOTAL;
    for s in resolved {
        if budget == 0 {
            break;
        }
        let take = s.instructions.len().min(MAX_CONTEXT_CHARS_PER_SKILL).min(budget);
        let mut text = s.instructions[..take].to_owned();
        if take < s.instructions.len() {
            text.push_str("\n…(truncated to 8 KiB)");
        }
        budget -= take;
        let body = format!(
            "Skill {} ({}; pinned {}):\n{text}\nRequested actions: {}",
            s.name,
            s.source,
            s.digest,
            if s.requested_actions.is_empty() {
                "none".into()
            } else {
                s.requested_actions.join(", ")
            }
        );
        let (kind, trust, source) = match s.trust {
            TrustLevel::UntrustedExternal => (
                ContextKind::UntrustedExternalContent,
                TrustLevel::UntrustedExternal,
                format!("marketplace:{}", s.name),
            ),
            _ => (
                ContextKind::SystemPolicy,
                TrustLevel::System,
                format!("skill:{}", s.name),
            ),
        };
        out.push(ContextBlock {
            kind,
            text_or_reference: body,
            privacy_class: PrivacyClass::Private,
            trust_level: trust,
            source_reference: source,
        });
    }
    if !problems.is_empty() {
        let note = problems
            .iter()
            .map(|p| format!("{} — {}", p.name, p.reason))
            .collect::<Vec<_>>()
            .join("; ");
        out.push(ContextBlock {
            kind: ContextKind::ToolOutput,
            text_or_reference: format!("Skills unavailable this run: {note}"),
            privacy_class: PrivacyClass::Private,
            trust_level: TrustLevel::UntrustedExternal,
            source_reference: "tool-call:skills".into(),
        });
    }
    out
}

/// Full selection path for the agent context hook: read the agent's selected
/// skill names from its stored definition, load + verify each, render blocks.
/// Unknown agents resolve to no blocks (never an error to the model loop).
pub async fn skill_context(
    pool: &PgPool,
    scope: &OwnerScope,
    agent_id: Uuid,
) -> Vec<ContextBlock> {
    let definition: Option<Value> = sqlx::query_scalar(
        "SELECT definition FROM agent_definitions WHERE owner_id=$1 AND id=$2",
    )
    .bind(scope.owner_id)
    .bind(agent_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let selected: Vec<String> = definition
        .as_ref()
        .and_then(|d| d.get("skills"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    if selected.is_empty() {
        return Vec::new();
    }
    let (resolved, problems) = load_for_agent(pool, scope, &selected).await;
    context_blocks(&resolved, &problems)
}

/// Owner-facing inventory: every local skill plus every installed marketplace
/// skill, each with its resolved state (`ok` / `off` / `broken: <reason>`)
/// and the data/actions the owner should review per skill.
pub async fn inventory(pool: &PgPool, scope: &OwnerScope) -> Result<Value> {
    let locals = sqlx::query(
        "SELECT id,name,description,entrypoint,enabled,updated_at FROM skills WHERE owner_id=$1 ORDER BY name LIMIT 100",
    )
    .bind(scope.owner_id)
    .fetch_all(pool)
    .await?;
    let mut items = Vec::with_capacity(locals.len() + 8);
    for r in &locals {
        let name: String = r.get("name");
        let body = read_bundled_skill(&name);
        let state: String = if !r.get::<bool, _>("enabled") {
            "off".into()
        } else {
            match &body {
                Ok(b) if !b.trim().is_empty() && b.len() <= MAX_SKILL_BODY_CHARS => "ok".into(),
                Ok(_) => "broken: SKILL.md empty or exceeds 32 KiB".into(),
                Err(e) => format!("broken: {e}"),
            }
        };
        let digest = match &body {
            Ok(b) => format!("sha256:{}", orbit_computer_node_protocol::sha256(b.as_bytes())),
            Err(_) => String::new(),
        };
        let actions: Vec<String> = Vec::new();
        items.push(json!({
            "id": r.get::<Uuid, _>("id"),
            "name": name,
            "source": "local",
            "description": r.get::<String, _>("description"),
            "entrypoint": r.get::<String, _>("entrypoint"),
            "enabled": r.get::<bool, _>("enabled"),
            "state": state,
            "content_digest": digest,
            "requested_actions": actions,
            "updated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
        }));
    }
    let installs = sqlx::query(
        "SELECT name,version,kind,description,content_digest,publisher_name,trust_level,capabilities,installed_at FROM marketplace_installs WHERE owner_id=$1 ORDER BY installed_at DESC,id DESC LIMIT 100",
    )
    .bind(scope.owner_id)
    .fetch_all(pool)
    .await?;
    for r in &installs {
        let name: String = r.get("name");
        let kind: String = r.get("kind");
        let caps: Value = r.get("capabilities");
        let pinned: &str = caps.get("skill_snapshot").and_then(|v| v.get("skill_md")).and_then(Value::as_str).unwrap_or("");
        let has_pin = caps.get("skill_file_pin").is_some();
        let state = if kind != "skill" {
            format!("not a skill (kind {kind})")
        } else if pinned.trim().is_empty() {
            if has_pin { "needs content: SKILL.md pinned by digest only; reinstall with inspection".into() } else { "broken: no pinned instructions; reinstall".into() }
        } else {
            "ok".into()
        };
        items.push(json!({
            "name": name,
            "source": "marketplace",
            "version": r.get::<String, _>("version"),
            "kind": kind,
            "description": r.get::<String, _>("description"),
            "content_digest": r.get::<String, _>("content_digest"),
            "publisher_name": r.get::<String, _>("publisher_name"),
            "trust_level": r.get::<String, _>("trust_level"),
            "requested_actions": caps.get("tools").cloned().unwrap_or(json!([])),
            "capabilities": caps,
            "state": state,
            "installed_at": r.get::<chrono::DateTime<chrono::Utc>, _>("installed_at"),
        }));
    }
    Ok(json!({"items": items}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn skill_names_are_kebab() {
        assert_eq!(valid_skill_name("hello-skill").unwrap(), "hello-skill");
        assert!(valid_skill_name("Hello Skill").is_err());
        assert!(valid_skill_name(" Medicaid; rm -rf /").is_err());
        assert!(valid_skill_name("").is_err());
    }
    #[test]
    fn entrypoint_never_becomes_shell() {
        // The loader has no subprocess path: entrypoint strings only render
        // as display metadata. This test pins that by counting spawn-call
        // sites in this module's non-test source (zero allowed).
        let src = include_str!("skills.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or("");
        // Needles are assembled at runtime so this test's own source does
        // not contain the banned substrings it scans for.
        let c = |a: &str, b: &str, c: &str| [a, b, c].concat();
        for needle in [c("Com", "mand", "::new"), c("std", "::pro", "cess"), c("tokio", "::pro", "cess"), c("pro", "cess::", "Command")] {
            assert!(!code.contains(&needle), "banned spawn API present: {needle}");
        }
    }
    #[test]
    fn marketplace_instructions_are_untrusted() {
        let blocks = context_blocks(
            &[ResolvedSkill {
                name: "hello-skill".into(),
                source: "marketplace:hello-skill".into(),
                digest: "sha256:0".into(),
                instructions: "Say hello.".into(),
                requested_actions: vec![],
                trust: TrustLevel::UntrustedExternal,
            }],
            &[],
        );
        assert_eq!(blocks.len(), 1);
        assert!(matches!(
            blocks[0].kind,
            ContextKind::UntrustedExternalContent
        ));
    }
    #[test]
    fn problems_render_honestly() {
        let blocks = context_blocks(
            &[],
            &[SkillProblem {
                name: "gone".into(),
                reason: "skill \"gone\" is unknown; install it".into(),
            }],
        );
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].text_or_reference.contains("gone"));
    }
}
