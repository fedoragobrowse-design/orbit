//! Scheduler core: automation triggers, cron evaluation, and idempotent firing.
//!
//! No model calls and no side effects beyond the database. All SQL is
//! owner-scoped. Timezones are UTC or fixed numeric offsets (`+02:00`);
//! named IANA zones are rejected until a tz database (e.g. `chrono-tz`) is
//! added. Wall-clock iteration goes through a gap/fold-aware conversion, so
//! nonexistent local times are skipped and repeated local times fire once.
//!
//! Step 9 proactive candidates: deterministic builders live in
//! [`proactive_builders`]. Watchers never execute skills or tools and never
//! call models directly; the only path to a model call is the synthesis
//! gate in that module.
pub mod proactive_builders;
pub use proactive_builders::{
    CandidateDraft, SynthesisDecision, SynthesisInput, confidence_met, decide_synthesis,
    draft_calendar_due, draft_matched_mail, draft_reminder_due, draft_stale_task,
    draft_watched_file_change, parked_from_router_error,
};

use chrono::{DateTime, Datelike, Duration, FixedOffset, NaiveDateTime, TimeZone, Timelike, Utc};
use orbit_core::{Error, EventType, OwnerScope, Result, literal, validate_event};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};
use uuid::Uuid;

pub const SOURCE: &str = "scheduler";
pub const CONSUMER: &str = "foundation";
const CLAIM_LIMIT: i64 = 50;
const MAX_FILTERS: usize = 50;
/// Minute-by-minute scan cap for missed-window coalescing (~2 years).
const MAX_SCAN_MINUTES: i64 = 1_051_200;
const COLUMNS: &str = "id,owner_id,enabled,\"trigger\",filters,agent_id,instructions,policy_scope,model_role,notification_behavior,timezone,version,revision,next_run,last_run,created_at,updated_at";
const CLAIM_COLUMNS: &str = "a.id,a.owner_id,a.enabled,a.\"trigger\",a.filters,a.agent_id,a.instructions,a.policy_scope,a.model_role,a.notification_behavior,a.timezone,a.version,a.revision,a.next_run,a.last_run,a.created_at,a.updated_at";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Automation {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub enabled: bool,
    pub trigger: Value,
    pub filters: Value,
    pub agent_id: Option<Uuid>,
    pub instructions: String,
    pub policy_scope: Value,
    pub model_role: String,
    pub notification_behavior: String,
    pub timezone: String,
    pub version: i64,
    pub revision: i64,
    pub next_run: Option<DateTime<Utc>>,
    pub last_run: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Typed trigger: event selector, cron schedule with timezone, or one-shot timer.
///
/// Event triggers bind an `event_type` to an exact source: either a free-form
/// `source` string or a structured `source_type` + `source_id` pair. The
/// proactive rule types (`SOURCE_CHANGED`, `CALENDAR_DUE`, `REMINDER_DUE`)
/// always require one of those bindings; legacy types keep it optional so
/// existing automations validate unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Trigger {
    #[serde(rename = "event")]
    Event {
        event_type: String,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        source_type: Option<String>,
        #[serde(default)]
        source_id: Option<String>,
    },
    #[serde(rename = "cron")]
    Cron {
        expression: String,
        timezone: String,
    },
    #[serde(rename = "timer")]
    Timer { run_at: DateTime<Utc> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub field: String,
    pub operator: String,
    pub value: Option<Value>,
}
/// Proactive per-case rule behavior: how a matched observation may act.
///
/// Stored inside the automation's `policy_scope` JSONB object (no new
/// columns, so legacy rows keep working): `policy_scope.behavior` holds one
/// of these literals. Absent = legacy automation, treated as `Auto` for
/// compatibility but skipping the new proactive gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleBehavior {
    Off,
    Suggest,
    Ask,
    Auto,
}

impl Default for RuleBehavior {
    fn default() -> Self {
        Self::Auto
    }
}

/// Bounded action-scope reference: which tool+resource grant an AUTO rule may
/// consume. Revisions pin the grant so a stale grant never authorizes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionScopeRef {
    pub tool: String,
    pub scope_key: String,
    pub scope_revision: i64,
}

/// Quiet-hours window inside `policy_scope.quiet_hours`. Times are `HH:MM`
/// wall-clock in the named fixed-offset timezone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietHours {
    pub start: String,
    pub end: String,
    #[serde(default = "default_quiet_timezone")]
    pub timezone: String,
}

fn default_quiet_timezone() -> String {
    "UTC".into()
}

/// Parsed per-case proactive rule config from `policy_scope`. Every field is
/// optional at the JSON layer: defaults keep legacy automations validating
/// unchanged, while rule-style triggers get their floors enforced in
/// [`validate_rule_config`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    #[serde(default)]
    pub behavior: Option<RuleBehavior>,
    #[serde(default)]
    pub source_scopes: Vec<String>,
    #[serde(default)]
    pub cooldown_seconds: Option<i64>,
    #[serde(default)]
    pub quiet_hours: Option<QuietHours>,
    #[serde(default)]
    pub max_runs_per_day: Option<i32>,
    #[serde(default)]
    pub max_daily_micro_usd: Option<i64>,
    #[serde(default)]
    pub minimum_confidence: Option<f64>,
    #[serde(default)]
    pub action_scopes: Vec<ActionScopeRef>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            behavior: None,
            source_scopes: Vec::new(),
            cooldown_seconds: None,
            quiet_hours: None,
            max_runs_per_day: None,
            max_daily_micro_usd: None,
            minimum_confidence: None,
            action_scopes: Vec::new(),
        }
    }
}

fn parse_hhmm(s: &str) -> Result<(u32, u32)> {
    let (h, m) = s.split_once(':').ok_or_else(|| Error::Validation("quiet_hours times must be HH:MM".into()))?;
    let h: u32 = h.parse().map_err(|_| Error::Validation("quiet_hours hour must be 00..23".into()))?;
    let m: u32 = m.parse().map_err(|_| Error::Validation("quiet_hours minute must be 00..59".into()))?;
    if h > 23 || m > 59 {
        return Err(Error::Validation("quiet_hours times must be HH:MM".into()));
    }
    Ok((h, m))
}

/// Parse the `policy_scope` rule section without touching the database.
/// Unknown `policy_scope` keys outside the rule set are preserved verbatim
/// for legacy callers; only the known rule keys are type-checked here.
pub fn parse_rule_config(policy_scope: &Value) -> Result<RuleConfig> {
    let obj = policy_scope.as_object().ok_or_else(|| Error::Validation("policy_scope must be an object".into()))?;
    let mut cfg = RuleConfig::default();
    if let Some(v) = obj.get("behavior") {
        if !v.is_null() {
            cfg.behavior = Some(serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid behavior: {e}")))?);
        }
    }
    if let Some(v) = obj.get("source_scopes") {
        let scopes: Vec<String> = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid source_scopes: {e}")))?;
        if scopes.len() > 64 || scopes.iter().any(|s| s.is_empty() || s.len() > 256) {
            return Err(Error::Validation("source_scopes must be 1..256 char strings, max 64".into()));
        }
        cfg.source_scopes = scopes;
    }
    if let Some(v) = obj.get("cooldown_seconds") {
        if !v.is_null() {
            let c: i64 = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid cooldown_seconds: {e}")))?;
            if c < 0 || c > 86_400 * 30 {
                return Err(Error::Validation("cooldown_seconds must be 0..2592000".into()));
            }
            cfg.cooldown_seconds = Some(c);
        }
    }
    if let Some(v) = obj.get("quiet_hours") {
        if !v.is_null() {
            let q: QuietHours = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid quiet_hours: {e}")))?;
            parse_hhmm(&q.start)?;
            parse_hhmm(&q.end)?;
            resolve_offset(&q.timezone)?;
            cfg.quiet_hours = Some(q);
        }
    }
    if let Some(v) = obj.get("max_runs_per_day") {
        if !v.is_null() {
            let n: i32 = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid max_runs_per_day: {e}")))?;
            if n < 1 || n > 10_000 {
                return Err(Error::Validation("max_runs_per_day must be 1..10000".into()));
            }
            cfg.max_runs_per_day = Some(n);
        }
    }
    if let Some(v) = obj.get("max_daily_micro_usd") {
        if !v.is_null() {
            let n: i64 = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid max_daily_micro_usd: {e}")))?;
            if n < 0 {
                return Err(Error::Validation("max_daily_micro_usd must be >= 0".into()));
            }
            cfg.max_daily_micro_usd = Some(n);
        }
    }
    if let Some(v) = obj.get("minimum_confidence") {
        if !v.is_null() {
            let n: f64 = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid minimum_confidence: {e}")))?;
            if !(0.0..=1.0).contains(&n) || !n.is_finite() {
                return Err(Error::Validation("minimum_confidence must be 0..1".into()));
            }
            cfg.minimum_confidence = Some(n);
        }
    }
    if let Some(v) = obj.get("action_scopes") {
        let refs: Vec<ActionScopeRef> = serde_json::from_value(v.clone()).map_err(|e| Error::Validation(format!("invalid action_scopes: {e}")))?;
        if refs.len() > 64 {
            return Err(Error::Validation("too many action_scopes".into()));
        }
        for r in &refs {
            if r.tool.is_empty() || r.tool.len() > 256 || r.scope_key.is_empty() || r.scope_key.len() > 256 || r.scope_revision < 0 {
                return Err(Error::Validation("invalid action scope ref".into()));
            }
        }
        cfg.action_scopes = refs;
    }
    Ok(cfg)
}

/// Convenience: read just the behavior, defaulting to legacy `Auto`.
pub fn rule_behavior(policy_scope: &Value) -> RuleBehavior {
    parse_rule_config(policy_scope).ok().and_then(|c| c.behavior).unwrap_or(RuleBehavior::Auto)
}

/// Proactive floors for observation-bound rules. Legacy automations (no
/// `behavior` key) skip this: they keep exact historical semantics. New
/// rules (behavior present) get: source_scopes required, numeric bounds
/// re-checked, and AUTO additionally requiring an agent + at least one
/// action scope + a daily budget + a confidence floor. Pure value checks.
pub fn validate_rule_config(trigger: &Trigger, policy_scope: &Value, agent_id: Option<Uuid>) -> Result<RuleConfig> {
    let cfg = parse_rule_config(policy_scope)?;
    let is_rule_trigger = matches!(trigger, Trigger::Event { event_type, .. } if event_type == "SOURCE_CHANGED" || event_type == "CALENDAR_DUE" || event_type == "REMINDER_DUE");
    let has_behavior = cfg.behavior.is_some();
    if !is_rule_trigger && !has_behavior {
        return Ok(cfg);
    }
    if is_rule_trigger && !has_behavior {
        return Err(Error::Validation("observation triggers require policy_scope.behavior (OFF|SUGGEST|ASK|AUTO)".into()));
    }
    if cfg.source_scopes.is_empty() {
        return Err(Error::Validation("proactive rules require policy_scope.source_scopes".into()));
    }
    if cfg.behavior == Some(RuleBehavior::Auto) {
        if agent_id.is_none() {
            return Err(Error::Validation("AUTO rules require agent_id".into()));
        }
        if cfg.action_scopes.is_empty() {
            return Err(Error::Validation("AUTO rules require policy_scope.action_scopes".into()));
        }
        if cfg.max_daily_micro_usd.is_none() {
            return Err(Error::Validation("AUTO rules require policy_scope.max_daily_micro_usd".into()));
        }
        if cfg.minimum_confidence.is_none() {
            return Err(Error::Validation("AUTO rules require policy_scope.minimum_confidence".into()));
        }
    }
    Ok(cfg)
}


/// Lease over a due automation: the schedule slot that must fire exactly once.
#[derive(Debug, Clone)]
pub struct DueClaim {
    pub automation: Automation,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub missed_count: i64,
}

fn row_to_automation(r: &PgRow) -> std::result::Result<Automation, sqlx::Error> {
    Ok(Automation {
        id: r.try_get("id")?,
        owner_id: r.try_get("owner_id")?,
        enabled: r.try_get("enabled")?,
        trigger: r.try_get("trigger")?,
        filters: r.try_get("filters")?,
        agent_id: r.try_get("agent_id")?,
        instructions: r.try_get("instructions")?,
        policy_scope: r.try_get("policy_scope")?,
        model_role: r.try_get("model_role")?,
        notification_behavior: r.try_get("notification_behavior")?,
        timezone: r.try_get("timezone")?,
        version: r.try_get("version")?,
        revision: r.try_get("revision")?,
        next_run: r.try_get("next_run")?,
        last_run: r.try_get("last_run")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// Parse and validate a trigger JSON value into its typed form.
pub fn parse_trigger(value: &Value) -> Result<Trigger> {
    let trigger: Trigger = serde_json::from_value(value.clone())
        .map_err(|e| Error::Validation(format!("invalid trigger: {e}")))?;
    match &trigger {
        Trigger::Event { event_type, source, source_type, source_id } => {
            if event_type.is_empty() || event_type.len() > 64 {
                return Err(Error::Validation(
                    "event trigger needs a 1..64 char event_type".into(),
                ));
            }
            serde_json::from_value::<EventType>(Value::String(event_type.clone()))
                .map_err(|_| Error::Validation(format!("unknown event_type {event_type}")))?;
            if let Some(s) = source {
                if s.is_empty() || s.len() > 256 {
                    return Err(Error::Validation(
                        "event trigger source must be 1..256 chars".into(),
                    ));
                }
            }
            if let Some(t) = source_type {
                if !matches!(t.as_str(), "email" | "calendar" | "file" | "browser" | "desktop" | "connector") {
                    return Err(Error::Validation(format!("unknown source_type {t}")).into());
                }
            }
            if let Some(s) = source_id {
                if s.is_empty() || s.len() > 256 {
                    return Err(Error::Validation(
                        "event trigger source_id must be 1..256 chars".into(),
                    ));
                }
            }
            // Proactive observation triggers bind exact sources/filters: a
            // bare SOURCE_CHANGED/CALENDAR_DUE/REMINDER_DUE would fan out to
            // every observation, so require a source or a typed source pair.
            if matches!(event_type.as_str(), "SOURCE_CHANGED" | "CALENDAR_DUE" | "REMINDER_DUE") {
                let has_source = source.as_ref().is_some_and(|s| !s.is_empty());
                let has_pair = source_type.is_some() && source_id.is_some();
                if !has_source && !has_pair {
                    return Err(Error::Validation(
                        "SOURCE_CHANGED/CALENDAR_DUE/REMINDER_DUE triggers require a source or source_type+source_id binding".into(),
                    ));
                }
            }
        }
        Trigger::Cron {
            expression,
            timezone,
        } => {
            parse_cron(expression)?;
            resolve_offset(timezone)?;
        }
        Trigger::Timer { .. } => {}
    }
    Ok(trigger)
}

const OPERATORS: [&str; 10] = [
    "eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "not_in", "exists",
];

fn valid_field(field: &str) -> bool {
    if field.is_empty() || field.len() > 256 || field.split('.').count() > 8 {
        return false;
    }
    field.split('.').all(|seg| {
        let mut c = seg.chars();
        matches!(c.next(), Some('a'..='z' | 'A'..='Z' | '_'))
            && seg.len() <= 64
            && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
    })
}

/// Validate a typed filter conjunction. Pure value checks, never SQL.
pub fn validate_filters(value: &Value) -> Result<Vec<Filter>> {
    let arr = value
        .as_array()
        .ok_or_else(|| Error::Validation("filters must be an array".into()))?;
    if arr.len() > MAX_FILTERS {
        return Err(Error::Validation("too many filters".into()));
    }
    arr.iter()
        .map(|f| {
            let filter: Filter = serde_json::from_value(f.clone())
                .map_err(|e| Error::Validation(format!("invalid filter: {e}")))?;
            if !valid_field(&filter.field) {
                return Err(Error::Validation(format!(
                    "invalid filter field {}",
                    filter.field
                )));
            }
            if !OPERATORS.contains(&filter.operator.as_str()) {
                return Err(Error::Validation(format!(
                    "unknown filter operator {}",
                    filter.operator
                )));
            }
            match filter.operator.as_str() {
                "exists" => {
                    if let Some(v) = &filter.value {
                        if !v.is_boolean() {
                            return Err(Error::Validation(
                                "exists takes an optional boolean".into(),
                            ));
                        }
                    }
                }
                "gt" | "gte" | "lt" | "lte" => {
                    if !filter.value.as_ref().is_some_and(Value::is_number) {
                        return Err(Error::Validation(format!(
                            "{} requires a numeric value",
                            filter.operator
                        )));
                    }
                }
                "contains" => {
                    if !filter.value.as_ref().is_some_and(|v| {
                        v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 1024)
                    }) {
                        return Err(Error::Validation(
                            "contains requires a non-empty string value".into(),
                        ));
                    }
                }
                "in" | "not_in" => {
                    if !filter.value.as_ref().is_some_and(|v| {
                        v.as_array().is_some_and(|a| !a.is_empty() && a.len() <= 50)
                    }) {
                        return Err(Error::Validation(format!(
                            "{} requires a non-empty array value",
                            filter.operator
                        )));
                    }
                }
                _ => {
                    if filter.value.as_ref().is_none_or(Value::is_null) {
                        return Err(Error::Validation(format!(
                            "{} requires a value",
                            filter.operator
                        )));
                    }
                }
            }
            Ok(filter)
        })
        .collect()
}

fn lookup<'a>(payload: &'a Value, field: &str) -> Option<&'a Value> {
    let mut cur = payload;
    for seg in field.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Pure in-memory conjunction evaluation over an event payload.
pub fn filter_matches(payload: &Value, filters: &[Filter]) -> bool {
    filters.iter().all(|f| {
        let got = lookup(payload, &f.field);
        match f.operator.as_str() {
            "exists" => got.is_some() == f.value.as_ref().and_then(Value::as_bool).unwrap_or(true),
            "eq" => got == f.value.as_ref(),
            "ne" => got != f.value.as_ref(),
            "contains" => matches!((got.and_then(Value::as_str), f.value.as_ref().and_then(Value::as_str)), (Some(h), Some(n)) if h.contains(n)),
            "in" => f.value.as_ref().and_then(Value::as_array).is_some_and(|a| got.is_some_and(|g| a.contains(g))),
            "not_in" => f.value.as_ref().and_then(Value::as_array).is_some_and(|a| !got.is_some_and(|g| a.contains(g))),
            op @ ("gt" | "gte" | "lt" | "lte") => {
                let pair = got.and_then(Value::as_f64).zip(f.value.as_ref().and_then(Value::as_f64));
                pair.is_some_and(|(g, w)| match op {
                    "gt" => g > w,
                    "gte" => g >= w,
                    "lt" => g < w,
                    _ => g <= w,
                })
            }
            _ => false,
        }
    })
}

/// Resolve a timezone name to a fixed offset. Only UTC and numeric offsets are
/// supported without a tz database; named IANA zones are rejected explicitly.
pub fn resolve_offset(tz: &str) -> Result<FixedOffset> {
    let t = tz.trim();
    if t.eq_ignore_ascii_case("utc")
        || t.eq_ignore_ascii_case("z")
        || t == "Etc/UTC"
        || t == "Etc/Zulu"
    {
        return FixedOffset::east_opt(0)
            .ok_or_else(|| Error::Validation("invalid timezone".into()));
    }
    let (neg, digits) = if let Some(rest) = t.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = t.strip_prefix('-') {
        (true, rest)
    } else {
        return Err(Error::Validation(format!(
            "unsupported timezone {tz}: use UTC or a numeric offset like +02:00"
        )));
    };
    if !digits.bytes().all(|b| b.is_ascii_digit() || b == b':') || digits.is_empty() {
        return Err(Error::Validation(format!(
            "unsupported timezone {tz}: use UTC or a numeric offset like +02:00"
        )));
    }
    let (h, m) = match digits.split_once(':') {
        Some((h, m)) => (h.to_owned(), m.to_owned()),
        None if digits.len() == 4 => (digits[..2].to_owned(), digits[2..].to_owned()),
        None if (1..=2).contains(&digits.len()) => (digits.to_owned(), "00".to_owned()),
        None => {
            return Err(Error::Validation(format!(
                "unsupported timezone {tz}: use UTC or a numeric offset like +02:00"
            )));
        }
    };
    let hh: i32 = h
        .parse()
        .map_err(|_| Error::Validation(format!("bad timezone hour in {tz}")))?;
    let mm: i32 = m
        .parse()
        .map_err(|_| Error::Validation(format!("bad timezone minute in {tz}")))?;
    if hh > 14 || mm > 59 || (hh == 14 && mm != 0) {
        return Err(Error::Validation(format!(
            "timezone offset out of range in {tz}"
        )));
    }
    let secs = (hh * 3600 + mm * 60) * if neg { -1 } else { 1 };
    FixedOffset::east_opt(secs).ok_or_else(|| Error::Validation("invalid timezone".into()))
}

struct CronField {
    bits: u64,
    restricted: bool,
}
struct CronSchedule {
    minute: CronField,
    hour: CronField,
    dom: CronField,
    month: CronField,
    dow: CronField,
}

const MONTH_NAMES: [(&str, i32); 12] = [
    ("JAN", 1),
    ("FEB", 2),
    ("MAR", 3),
    ("APR", 4),
    ("MAY", 5),
    ("JUN", 6),
    ("JUL", 7),
    ("AUG", 8),
    ("SEP", 9),
    ("OCT", 10),
    ("NOV", 11),
    ("DEC", 12),
];
const DOW_NAMES: [(&str, i32); 7] = [
    ("SUN", 0),
    ("MON", 1),
    ("TUE", 2),
    ("WED", 3),
    ("THU", 4),
    ("FRI", 5),
    ("SAT", 6),
];

fn cron_value(token: &str, names: &[(&str, i32)]) -> Result<i32> {
    let upper = token.to_ascii_uppercase();
    if let Some((_, n)) = names.iter().find(|(name, _)| *name == upper) {
        return Ok(*n);
    }
    token
        .parse::<i32>()
        .map_err(|_| Error::Validation(format!("bad cron value {token}")))
}

fn parse_cron_field(part: &str, lo: i32, hi: i32, names: &[(&str, i32)]) -> Result<CronField> {
    let mut bits: u64 = 0;
    if part == "*" {
        for v in lo..=hi {
            bits |= 1u64 << (v as u32);
        }
        return Ok(CronField {
            bits,
            restricted: false,
        });
    }
    for item in part.split(',') {
        if item.is_empty() {
            return Err(Error::Validation("empty cron list item".into()));
        }
        let (base, step) = match item.split_once('/') {
            Some((b, s)) => {
                let n: u32 = s
                    .parse()
                    .map_err(|_| Error::Validation(format!("bad cron step {s}")))?;
                if n == 0 || n > 59 {
                    return Err(Error::Validation(format!(
                        "cron step out of range in {item}"
                    )));
                }
                (b, n)
            }
            None => (item, 1),
        };
        let (from, to) = if base == "*" {
            (lo, hi)
        } else if let Some((a, b)) = base.split_once('-') {
            let (mut a, mut b) = (cron_value(a, names)?, cron_value(b, names)?);
            if lo == 0 {
                if a == 7 {
                    a = 0;
                }
                if b == 7 {
                    b = 0;
                }
            }
            // Cron treats Sunday as both 0 and 7, so MON-SUN wraps: cover
            // the tail of the week plus Sunday itself.
            if lo == 0 && b == 0 && a > 0 {
                bits |= 1u64;
                (a, 6)
            } else {
                (a, b)
            }
        } else {
            let mut v = cron_value(base, names)?;
            if lo == 0 && v == 7 {
                v = 0;
            }
            // Bare `n/step` means `n-max/step` in Vixie cron.
            if step > 1 { (v, hi) } else { (v, v) }
        };
        if from < lo || to > hi || from > to {
            return Err(Error::Validation(format!(
                "cron range out of bounds in {item}"
            )));
        }
        let mut v = from;
        while v <= to {
            bits |= 1u64 << (v as u32);
            v += step as i32;
        }
    }
    if bits == 0 {
        return Err(Error::Validation("cron field matched nothing".into()));
    }
    Ok(CronField {
        bits,
        restricted: true,
    })
}

/// Minimal 5-field cron parser: minute hour day-of-month month day-of-week.
fn parse_cron(expression: &str) -> Result<CronSchedule> {
    let parts: Vec<&str> = expression.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(Error::Validation("cron expression needs 5 fields".into()));
    }
    Ok(CronSchedule {
        minute: parse_cron_field(parts[0], 0, 59, &[])?,
        hour: parse_cron_field(parts[1], 0, 23, &[])?,
        dom: parse_cron_field(parts[2], 1, 31, &[])?,
        month: parse_cron_field(parts[3], 1, 12, &MONTH_NAMES)?,
        dow: parse_cron_field(parts[4], 0, 7, &DOW_NAMES)?,
    })
}

fn bit(field: &CronField, v: u32) -> bool {
    field.bits & (1u64 << v) != 0
}

fn day_matches(sched: &CronSchedule, dom: u32, weekday_sun0: u32) -> bool {
    let dom_ok = bit(&sched.dom, dom);
    let dow_ok = bit(&sched.dow, weekday_sun0) || (weekday_sun0 == 0 && bit(&sched.dow, 7));
    match (sched.dom.restricted, sched.dow.restricted) {
        (false, false) => true,
        (true, false) => dom_ok,
        (false, true) => dow_ok,
        (true, true) => dom_ok || dow_ok,
    }
}

fn wall_matches(sched: &CronSchedule, wall: &NaiveDateTime) -> bool {
    bit(&sched.minute, wall.minute())
        && bit(&sched.hour, wall.hour())
        && bit(&sched.month, wall.month())
        && day_matches(sched, wall.day(), wall.weekday().num_days_from_sunday())
}

/// Wall-clock to instant with DST semantics: gaps are skipped, folds fire once.
fn wall_to_instant(offset: FixedOffset, wall: &NaiveDateTime) -> Option<DateTime<Utc>> {
    use chrono::LocalResult;
    match offset.from_local_datetime(wall) {
        LocalResult::Single(dt) => Some(dt.with_timezone(&Utc)),
        LocalResult::Ambiguous(first, _) => Some(first.with_timezone(&Utc)),
        LocalResult::None => None,
    }
}

fn truncate_minute(dt: DateTime<Utc>, offset: FixedOffset) -> NaiveDateTime {
    let wall = dt.with_timezone(&offset).naive_local();
    wall.date()
        .and_hms_opt(wall.hour(), wall.minute(), 0)
        .expect("valid wall clock")
}

/// Next cron instant strictly after `from`, or `None` if none within the scan cap.
pub fn cron_next(
    expression: &str,
    offset: FixedOffset,
    from: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>> {
    let sched = parse_cron(expression)?;
    let mut wall = truncate_minute(from, offset);
    for _ in 0..MAX_SCAN_MINUTES {
        wall = wall
            .checked_add_signed(Duration::minutes(1))
            .ok_or_else(|| Error::Validation("cron scan overflow".into()))?;
        if !wall_matches(&sched, &wall) {
            continue;
        }
        if let Some(instant) = wall_to_instant(offset, &wall) {
            if instant > from {
                return Ok(Some(instant));
            }
        }
    }
    Ok(None)
}

/// Next scheduled run strictly after `from`. Event triggers have no schedule.
pub fn compute_next_run(trigger: &Trigger, from: DateTime<Utc>) -> Result<Option<DateTime<Utc>>> {
    match trigger {
        Trigger::Event { .. } => Ok(None),
        Trigger::Timer { run_at } => Ok((*run_at > from).then_some(*run_at)),
        Trigger::Cron {
            expression,
            timezone,
        } => cron_next(expression, resolve_offset(timezone)?, from),
    }
}

struct WindowScan {
    count: i64,
    next_after: Option<DateTime<Utc>>,
}

/// Single minute-by-minute scan counting occurrences in `[start, end]` (the
/// coalesced missed window) plus the next occurrence after `end`.
fn scan_window(
    sched: &CronSchedule,
    offset: FixedOffset,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<WindowScan> {
    let mut wall = truncate_minute(start, offset);
    let mut count: i64 = 0;
    for _ in 0..MAX_SCAN_MINUTES {
        if wall_matches(sched, &wall) {
            if let Some(instant) = wall_to_instant(offset, &wall) {
                if instant > end {
                    return Ok(WindowScan {
                        count,
                        next_after: Some(instant),
                    });
                }
                if instant + Duration::minutes(1) > start {
                    count += 1;
                }
            }
        }
        wall = wall
            .checked_add_signed(Duration::minutes(1))
            .ok_or_else(|| Error::Validation("cron scan overflow".into()))?;
    }
    Ok(WindowScan {
        count,
        next_after: None,
    })
}

/// Claim due automations, leasing each row with a revision bump so concurrent
/// schedulers skip locked rows. Callers then [`fire`] each due claim.
pub async fn claim_due(pool: &PgPool, owner: Option<Uuid>) -> Result<Vec<DueClaim>> {
    let mut tx = pool.begin().await?;
    let rows = if let Some(owner_id) = owner {
        sqlx::query(&format!(
            "WITH due AS (SELECT id FROM automations WHERE enabled AND next_run IS NOT NULL AND next_run <= now() AND owner_id=$1 ORDER BY next_run,id LIMIT {CLAIM_LIMIT} FOR UPDATE SKIP LOCKED) UPDATE automations a SET revision=a.revision+1,updated_at=now() FROM due WHERE a.id=due.id RETURNING {CLAIM_COLUMNS}"
        ))
        .bind(owner_id)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(&format!(
            "WITH due AS (SELECT id FROM automations WHERE enabled AND next_run IS NOT NULL AND next_run <= now() ORDER BY next_run,id LIMIT {CLAIM_LIMIT} FOR UPDATE SKIP LOCKED) UPDATE automations a SET revision=a.revision+1,updated_at=now() FROM due WHERE a.id=due.id RETURNING {CLAIM_COLUMNS}"
        ))
        .fetch_all(&mut *tx)
        .await?
    };
    let now = Utc::now();
    let mut claims = Vec::with_capacity(rows.len());
    for row in &rows {
        let automation = row_to_automation(row).map_err(Error::from)?;
        let Some(window_start) = automation.next_run else {
            continue;
        };
        if window_start > now {
            continue;
        }
        let trigger = parse_trigger(&automation.trigger)?;
        let missed = match &trigger {
            Trigger::Cron {
                expression,
                timezone,
            } => {
                let sched = parse_cron(expression)?;
                Some(scan_window(
                    &sched,
                    resolve_offset(timezone)?,
                    window_start,
                    now,
                )?)
            }
            Trigger::Timer { .. } => None,
            // Event triggers never carry a schedule; skip, don't fail the batch.
            Trigger::Event { .. } => continue,
        };
        let missed_count = missed
            .as_ref()
            .map(|s| s.count.saturating_sub(1))
            .unwrap_or(0);
        claims.push(DueClaim {
            automation,
            window_start,
            window_end: now,
            missed_count,
        });
    }
    tx.commit().await?;
    Ok(claims)
}

/// Fire one automation window: insert exactly one `SCHEDULE_TRIGGER` /
/// `TIMER_TRIGGER` event plus its foundation delivery row in-transaction.
/// The `fire_key` (automation + window) makes retries idempotent: a repeat
/// returns the already-fired event id, and missed windows coalesce into the
/// single trigger with `missed_count`. Returns `Ok(None)` when nothing is due.
pub async fn fire(pool: &PgPool, scope: &OwnerScope, automation_id: Uuid) -> Result<Option<Uuid>> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2 FOR UPDATE"
    ))
    .bind(scope.owner_id)
    .bind(automation_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let automation = row_to_automation(&row).map_err(Error::from)?;
    if !automation.enabled {
        return Err(Error::Validation("automation is disabled".into()));
    }
    let Some(window_start) = automation.next_run else {
        return Err(Error::Validation(
            "automation has no pending schedule".into(),
        ));
    };
    let now = Utc::now();
    if window_start > now {
        tx.rollback().await?;
        return Ok(None);
    }
    let trigger = parse_trigger(&automation.trigger)?;
    let (event_type, missed_count, next_after) = match &trigger {
        Trigger::Cron {
            expression,
            timezone,
        } => {
            let sched = parse_cron(expression)?;
            let scan = scan_window(&sched, resolve_offset(timezone)?, window_start, now)?;
            (
                EventType::ScheduleTrigger,
                scan.count.saturating_sub(1),
                scan.next_after,
            )
        }
        Trigger::Timer { .. } => (EventType::TimerTrigger, 0, None),
        Trigger::Event { .. } => {
            return Err(Error::Validation(
                "event automations fire from the event bus".into(),
            ));
        }
    };
    // Idempotency guard first: one fire row per automation window.
    let fire_key = format!("{automation_id}:{}", window_start.timestamp());
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO automation_fires(id,owner_id,automation_id,fire_key,window_start,window_end,missed_count) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(automation_id,fire_key) DO NOTHING RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(scope.owner_id)
    .bind(automation_id)
    .bind(&fire_key)
    .bind(window_start)
    .bind(now)
    .bind(missed_count.min(i32::MAX as i64) as i32)
    .fetch_optional(&mut *tx)
    .await?;
    if inserted.is_none() {
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM events WHERE owner_id=$1 AND source='scheduler' AND source_event_key=$2",
        )
        .bind(scope.owner_id)
        .bind(&fire_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(existing);
    }
    let event_id = Uuid::new_v4();
    let correlation = Uuid::new_v4();
    let payload = json!({
        "automation_id": automation_id.to_string(),
        "fire_key": fire_key,
        "window_start": window_start,
        "window_end": now,
        "missed_count": missed_count,
    });
    validate_event(event_type, &payload)?;
    sqlx::query(
        "INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,related_entities,source_event_key) VALUES($1,$2,$3,'scheduler',$4,$5,'SYSTEM','PRIVATE',$6,'[]',$7) ON CONFLICT(owner_id,source,source_event_key) DO NOTHING",
    )
    .bind(event_id)
    .bind(scope.owner_id)
    .bind(literal(event_type))
    .bind(scope.principal_id)
    .bind(&payload)
    .bind(correlation)
    .bind(&fire_key)
    .execute(&mut *tx)
    .await?;
    let stored: Uuid = sqlx::query_scalar(
        "SELECT id FROM events WHERE owner_id=$1 AND source='scheduler' AND source_event_key=$2",
    )
    .bind(scope.owner_id)
    .bind(&fire_key)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING")
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(stored)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE automations SET next_run=$1,last_run=now(),revision=revision+1,updated_at=now() WHERE owner_id=$2 AND id=$3")
        .bind(next_after)
        .bind(scope.owner_id)
        .bind(automation_id)
        .execute(&mut *tx)
        .await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        Some(stored),
        None,
        "AUTOMATION_FIRED",
        "scheduler window fired",
        json!({"automation_id": automation_id, "fire_key": fire_key, "missed_count": missed_count, "event_type": literal(event_type)}),
    )
    .await?;
    tx.commit().await?;
    Ok(Some(stored))
}

/// CRUD plus dispatch. All SQL is owner-scoped; every mutation locks the
/// owner's authorization epoch first so concurrent schedulers serialize.
pub async fn create(
    pool: &PgPool,
    scope: &OwnerScope,
    automation: Automation,
) -> Result<Automation> {
    let initial_trigger = parse_trigger(&automation.trigger)?;
    validate_filters(&automation.filters)?;
    if !automation.policy_scope.is_object() {
        return Err(Error::Validation("policy_scope must be an object".into()));
    }
    validate_rule_config(&initial_trigger, &automation.policy_scope, automation.agent_id)?;
    if automation.instructions.trim().is_empty() || automation.instructions.len() > 8000 {
        return Err(Error::Validation(
            "automation instructions must be 1..8000 chars".into(),
        ));
    }
    serde_json::from_value::<orbit_core::ModelRole>(Value::String(automation.model_role.clone()))
        .map_err(|_| Error::Validation(format!("unknown model_role {}", automation.model_role)))?;
    if !matches!(automation.notification_behavior.as_str(), "NONE" | "IN_APP" | "PUSH" | "EMAIL_DIGEST") {
        return Err(Error::Validation(format!(
            "unknown notification_behavior {}",
            automation.notification_behavior
        )));
    }
    if let Some(agent) = automation.agent_id {
        let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_definitions WHERE owner_id=$1 AND id=$2 AND enabled)")
            .bind(scope.owner_id).bind(agent).fetch_one(pool).await?;
        if !enabled {
            return Err(Error::Validation(
                "automation agent is unknown or disabled".into(),
            ));
        }
    }
    let next = compute_next_run(&initial_trigger, Utc::now())?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(&format!("INSERT INTO automations(id,owner_id,enabled,\"trigger\",filters,agent_id,instructions,policy_scope,model_role,notification_behavior,timezone,version,revision,next_run) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,1,$12) RETURNING {COLUMNS}"))
        .bind(automation.id).bind(scope.owner_id).bind(automation.enabled).bind(&automation.trigger).bind(&automation.filters)
        .bind(automation.agent_id).bind(automation.instructions.trim()).bind(&automation.policy_scope)
        .bind(&automation.model_role).bind(&automation.notification_behavior).bind(&automation.timezone).bind(next)
        .fetch_one(&mut *tx).await?;
    let created = row_to_automation(&row).map_err(Error::from)?;
    orbit_audit::append(
        &mut tx,
        scope,
        Uuid::new_v4(),
        None,
        None,
        "AUTOMATION_CREATED",
        "automation created",
        json!({"automation_id": created.id}),
    )
    .await?;
    tx.commit().await?;
    Ok(created)
}

pub async fn get(pool: &PgPool, scope: &OwnerScope, id: Uuid) -> Result<Automation> {
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2"
    ))
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(Error::NotFound)?;
    row_to_automation(&row).map_err(Error::from)
}

pub async fn list(
    pool: &PgPool,
    scope: &OwnerScope,
    cursor: Option<Uuid>,
    limit: i64,
) -> Result<(Vec<Automation>, Option<Uuid>)> {
    let rows = sqlx::query(&format!("SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3"))
        .bind(scope.owner_id).bind(cursor).bind(limit.clamp(1, 50) + 1).fetch_all(pool).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in &rows {
        items.push(row_to_automation(row).map_err(Error::from)?);
    }
    let next = if items.len() > limit.clamp(1, 50) as usize {
        items.pop();
        items.last().map(|a| a.id)
    } else {
        None
    };
    Ok((items, next))
}

/// Replace trigger/filters/instructions/etc, guarded by `expected_revision`.
/// Re-arms the schedule from the new trigger; fires already recorded keep
/// their history. Does not execute anything.
pub async fn update(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    expected_revision: i64,
    patch: Value,
) -> Result<Automation> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2 FOR UPDATE"
    ))
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let mut current = row_to_automation(&row).map_err(Error::from)?;
    if current.revision != expected_revision {
        return Err(Error::Conflict("automation changed".into()));
    }
    if let Some(v) = patch.get("trigger") {
        parse_trigger(v)?;
        current.trigger = v.clone();
    }
    if let Some(v) = patch.get("filters") {
        validate_filters(v)?;
        current.filters = v.clone();
    }
    if let Some(v) = patch.get("instructions") {
        let s = v
            .as_str()
            .ok_or_else(|| Error::Validation("instructions must be a string".into()))?;
        if s.trim().is_empty() || s.len() > 8000 {
            return Err(Error::Validation(
                "automation instructions must be 1..8000 chars".into(),
            ));
        }
        current.instructions = s.trim().to_owned();
    }
    if let Some(v) = patch.get("policy_scope") {
        if !v.is_object() {
            return Err(Error::Validation("policy_scope must be an object".into()));
        }
        current.policy_scope = v.clone();
    }
    if let Some(v) = patch.get("model_role") {
        serde_json::from_value::<orbit_core::ModelRole>(Value::String(
            v.as_str().unwrap_or("").to_owned(),
        ))
        .map_err(|_| Error::Validation(format!("unknown model_role {v}")))?;
        current.model_role = v.as_str().unwrap_or("").to_owned();
    }
    if let Some(v) = patch.get("notification_behavior") {
        if !matches!(v.as_str(), Some("NONE" | "IN_APP" | "PUSH" | "EMAIL_DIGEST")) {
            return Err(Error::Validation("unknown notification_behavior".into()));
        }
        current.notification_behavior = v.as_str().unwrap_or("NONE").to_owned();
    }
    if let Some(v) = patch.get("timezone") {
        resolve_offset(v.as_str().unwrap_or(""))?;
        current.timezone = v.as_str().unwrap_or("UTC").to_owned();
    }
    if let Some(v) = patch.get("agent_id") {
        current.agent_id = if v.is_null() {
            None
        } else {
            Some(
                serde_json::from_value(v.clone())
                    .map_err(|_| Error::Validation("invalid agent_id".into()))?,
            )
        };
        if let Some(agent) = current.agent_id {
            let enabled: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_definitions WHERE owner_id=$1 AND id=$2 AND enabled)")
                .bind(scope.owner_id).bind(agent).fetch_one(&mut *tx).await?;
            if !enabled {
                return Err(Error::Validation(
                    "automation agent is unknown or disabled".into(),
                ));
            }
        }
    }
    let trigger = parse_trigger(&current.trigger)?;
    validate_rule_config(&trigger, &current.policy_scope, current.agent_id)?;
    let next = compute_next_run(&trigger, Utc::now())?;
    let updated = sqlx::query(&format!("UPDATE automations SET \"trigger\"=$1,filters=$2,agent_id=$3,instructions=$4,policy_scope=$5,model_role=$6,notification_behavior=$7,timezone=$8,next_run=$9,revision=revision+1,updated_at=now() WHERE owner_id=$10 AND id=$11 RETURNING {COLUMNS}"))
        .bind(&current.trigger).bind(&current.filters).bind(current.agent_id).bind(&current.instructions)
        .bind(&current.policy_scope).bind(&current.model_role).bind(&current.notification_behavior)
        .bind(&current.timezone).bind(next).bind(scope.owner_id).bind(id)
        .fetch_one(&mut *tx).await?;
    let automation = row_to_automation(&updated).map_err(Error::from)?;
    orbit_audit::append(
        &mut tx,
        scope,
        Uuid::new_v4(),
        None,
        None,
        "AUTOMATION_UPDATED",
        "automation updated",
        json!({"automation_id": id, "revision": automation.revision}),
    )
    .await?;
    tx.commit().await?;
    Ok(automation)
}

/// Enable or pause an automation. Pausing keeps history and stops future
/// claims; re-enabling re-arms the schedule from now. Guarded by revision.
pub async fn set_enabled(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    enabled: bool,
    expected_revision: i64,
) -> Result<Automation> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2 FOR UPDATE"
    ))
    .bind(scope.owner_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let current = row_to_automation(&row).map_err(Error::from)?;
    if current.revision != expected_revision {
        return Err(Error::Conflict("automation changed".into()));
    }
    let next = if enabled {
        compute_next_run(&parse_trigger(&current.trigger)?, Utc::now())?
    } else {
        None
    };
    let updated = sqlx::query(&format!("UPDATE automations SET enabled=$1,next_run=$2,revision=revision+1,updated_at=now() WHERE owner_id=$3 AND id=$4 RETURNING {COLUMNS}"))
        .bind(enabled).bind(next).bind(scope.owner_id).bind(id).fetch_one(&mut *tx).await?;
    let automation = row_to_automation(&updated).map_err(Error::from)?;
    orbit_audit::append(
        &mut tx,
        scope,
        Uuid::new_v4(),
        None,
        None,
        if enabled {
            "AUTOMATION_ENABLED"
        } else {
            "AUTOMATION_PAUSED"
        },
        "automation enable state changed",
        json!({"automation_id": id, "enabled": enabled}),
    )
    .await?;
    tx.commit().await?;
    Ok(automation)
}

pub async fn remove(pool: &PgPool, scope: &OwnerScope, id: Uuid) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let n = sqlx::query("DELETE FROM automations WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(Error::NotFound);
    }
    orbit_audit::append(
        &mut tx,
        scope,
        Uuid::new_v4(),
        None,
        None,
        "AUTOMATION_DELETED",
        "automation deleted",
        json!({"automation_id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Side-effect-free preview: next scheduled run plus the missed-window count
/// that would coalesce into a single trigger. Never inserts fires or events.
pub async fn preview(pool: &PgPool, scope: &OwnerScope, id: Uuid) -> Result<Value> {
    let automation = get(pool, scope, id).await?;
    let trigger = parse_trigger(&automation.trigger)?;
    let now = Utc::now();
    let (next_run, missed_would_coalesce) = match &trigger {
        Trigger::Cron {
            expression,
            timezone,
        } => {
            let sched = parse_cron(expression)?;
            let offset = resolve_offset(timezone)?;
            let next = cron_next(expression, offset, now)?;
            let missed = match automation.next_run {
                Some(start) if start <= now => scan_window(&sched, offset, start, now)?
                    .count
                    .saturating_sub(1),
                _ => 0,
            };
            (next.or(automation.next_run), missed)
        }
        Trigger::Timer { run_at } => (
            (*run_at > now).then_some(*run_at).or(automation.next_run),
            0,
        ),
        Trigger::Event { .. } => (None, 0),
    };
    Ok(
        json!({"automation_id": id, "enabled": automation.enabled, "next_run": next_run, "missed_would_coalesce": missed_would_coalesce, "last_run": automation.last_run}),
    )
}

/// Fire history for one automation, newest first, with the task each fire
/// dispatched to (if any).
pub async fn history(
    pool: &PgPool,
    scope: &OwnerScope,
    id: Uuid,
    cursor: Option<Uuid>,
    limit: i64,
) -> Result<(Vec<Value>, Option<Uuid>)> {
    get(pool, scope, id).await?;
    let rows = sqlx::query("SELECT f.id,f.fire_key,f.window_start,f.window_end,f.missed_count,f.state,f.created_at,e.id AS event_id,t.id AS task_id,t.state AS task_state FROM automation_fires f LEFT JOIN events e ON e.owner_id=f.owner_id AND e.source='scheduler' AND e.source_event_key=f.fire_key LEFT JOIN tasks t ON t.owner_id=f.owner_id AND t.event_id=e.id WHERE f.owner_id=$1 AND f.automation_id=$2 AND ($3::uuid IS NULL OR f.id>$3) ORDER BY f.id LIMIT $4")
        .bind(scope.owner_id).bind(id).bind(cursor).bind(limit.clamp(1, 50) + 1).fetch_all(pool).await?;
    let mut items: Vec<Value> = rows.iter().map(|r| json!({"id": r.get::<Uuid, _>("id"), "fire_key": r.get::<String, _>("fire_key"), "window_start": r.get::<DateTime<Utc>, _>("window_start"), "window_end": r.get::<DateTime<Utc>, _>("window_end"), "missed_count": r.get::<i32, _>("missed_count"), "state": r.get::<String, _>("state"), "created_at": r.get::<DateTime<Utc>, _>("created_at"), "event_id": r.get::<Option<Uuid>, _>("event_id"), "task_id": r.get::<Option<Uuid>, _>("task_id"), "task_state": r.get::<Option<String>, _>("task_state")})).collect();
    let next = if items.len() > limit.clamp(1, 50) as usize {
        items.pop();
        items
            .last()
            .and_then(|v| v["id"].as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
    } else {
        None
    };
    Ok((items, next))
}

/// Dispatch one fired window to a correlated task.
///
/// Called with the worker scope immediately after [`fire`] succeeds in the
/// same tick: inserts exactly one `agents`-consumer task (agent runs) or one
/// `foundation`-consumer task (in-app notification) per fired event, keyed on
/// the fired event id so retries stay idempotent. The task checkpoint carries
/// the automation id, fire key, and window so history stays correlated.
pub async fn dispatch(
    pool: &PgPool,
    scope: &OwnerScope,
    automation_id: Uuid,
    event_id: Uuid,
    fire_key: String,
    missed_count: i64,
) -> Result<Uuid> {
    let automation = get(pool, scope, automation_id).await?;
    let event =
        sqlx::query("SELECT correlation_id,event_type FROM events WHERE owner_id=$1 AND id=$2")
            .bind(scope.owner_id)
            .bind(event_id)
            .fetch_optional(pool)
            .await?
            .ok_or(Error::NotFound)?;
    let correlation: Uuid = event.get("correlation_id");
    let (consumer, checkpoint) = if automation.notification_behavior == "IN_APP"
        && automation.agent_id.is_none()
    {
        (
            "foundation",
            json!({"phase": "NOTIFICATION", "automation_id": automation_id, "fire_key": fire_key, "source_event_id": event_id, "missed_count": missed_count}),
        )
    } else {
        let agent = automation.agent_id.ok_or_else(|| {
            Error::Validation("automation needs an agent or IN_APP notification behavior".into())
        })?;
        let definition: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_definitions WHERE owner_id=$1 AND id=$2 AND enabled)")
            .bind(scope.owner_id).bind(agent).fetch_one(pool).await?;
        if !definition {
            return Err(Error::Validation(
                "automation agent is unknown or disabled".into(),
            ));
        }
        (
            "agents",
            json!({"phase": "CONTEXT", "automatic": true, "automation_id": automation_id, "agent_id": agent, "fire_key": fire_key, "source_event_id": event_id, "missed_count": missed_count, "instructions": automation.instructions}),
        )
    };
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
        .bind(scope.owner_id)
        .fetch_one(&mut *tx)
        .await?;
    let task = sqlx::query_scalar::<_, Uuid>("INSERT INTO tasks(id,owner_id,event_id,principal_id,correlation_id,title,consumer,checkpoint) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id,consumer,event_id) DO UPDATE SET event_id=EXCLUDED.event_id RETURNING id")
        .bind(Uuid::new_v4()).bind(scope.owner_id).bind(event_id).bind(scope.principal_id).bind(correlation)
        .bind(format!("Automation {}", automation_id)).bind(consumer).bind(&checkpoint)
        .fetch_one(&mut *tx).await?;
    orbit_audit::append(
        &mut tx,
        scope,
        correlation,
        Some(event_id),
        Some(task),
        "AUTOMATION_DISPATCHED",
        "automation window dispatched to task",
        json!({"automation_id": automation_id, "fire_key": fire_key, "consumer": consumer}),
    )
    .await?;
    tx.commit().await?;
    Ok(task)
}

/// Worker tick: claim due automations, fire each window exactly once, and
/// dispatch the fired event to its correlated task. Returns (fired, dispatched).
pub async fn tick(pool: &PgPool, scope: &OwnerScope) -> Result<(usize, usize)> {
    let claims = claim_due(pool, Some(scope.owner_id)).await?;
    let mut fired = 0usize;
    let mut dispatched = 0usize;
    for claim in claims {
        let id = claim.automation.id;
        let key = format!("{id}:{}", claim.window_start.timestamp());
        match fire(pool, scope, id).await? {
            None => continue,
            Some(event_id) => {
                fired += 1;
                // Event automations never reach fire(); timer/cron windows always dispatch.
                if dispatch(pool, scope, id, event_id, key, claim.missed_count)
                    .await
                    .is_ok()
                {
                    dispatched += 1;
                }
            }
        }
    }
    Ok((fired, dispatched))
}

/// Re-arm an automation's schedule from its current trigger, guarded by
/// `expected_revision`. Advances the revision without inserting any fires.
pub async fn reschedule(
    pool: &PgPool,
    scope: &OwnerScope,
    automation_id: Uuid,
    expected_revision: i64,
) -> Result<Automation> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(&format!(
        "SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2 FOR UPDATE"
    ))
    .bind(scope.owner_id)
    .bind(automation_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(Error::NotFound)?;
    let automation = row_to_automation(&row).map_err(Error::from)?;
    if automation.revision != expected_revision {
        return Err(Error::Conflict("automation changed".into()));
    }
    let trigger = parse_trigger(&automation.trigger)?;
    let next = compute_next_run(&trigger, Utc::now())?;
    let updated = sqlx::query(&format!(
        "UPDATE automations SET next_run=$1,revision=revision+1,updated_at=now() WHERE owner_id=$2 AND id=$3 RETURNING {COLUMNS}"
    ))
    .bind(next)
    .bind(scope.owner_id)
    .bind(automation_id)
    .fetch_one(&mut *tx)
    .await?;
    let automation = row_to_automation(&updated).map_err(Error::from)?;
    orbit_audit::append(
        &mut tx,
        scope,
        Uuid::new_v4(),
        None,
        None,
        "AUTOMATION_RESCHEDULED",
        "automation schedule recomputed",
        json!({"automation_id": automation_id, "revision": automation.revision}),
    )
    .await?;
    tx.commit().await?;
    Ok(automation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn cron_every_minute_next() {
        let off = FixedOffset::east_opt(0).unwrap();
        assert_eq!(
            cron_next("* * * * *", off, utc(2026, 10, 7, 12, 0)).unwrap(),
            Some(utc(2026, 10, 7, 12, 1))
        );
    }

    #[test]
    fn cron_daily_midnight_utc() {
        let off = FixedOffset::east_opt(0).unwrap();
        assert_eq!(
            cron_next("0 0 * * *", off, utc(2026, 10, 7, 12, 0)).unwrap(),
            Some(utc(2026, 10, 8, 0, 0))
        );
    }

    #[test]
    fn cron_dom_or_dow() {
        // First of month OR Monday: 2026-10-07 is a Wednesday, next Monday is 10-12.
        let off = FixedOffset::east_opt(0).unwrap();
        assert_eq!(
            cron_next("0 0 1 * MON", off, utc(2026, 10, 7, 12, 0)).unwrap(),
            Some(utc(2026, 10, 12, 0, 0))
        );
    }

    #[test]
    fn cron_offset_shifts_wall_clock() {
        let off = resolve_offset("+02:00").unwrap();
        // 00:30 wall in +02:00 == 22:30 UTC previous day.
        assert_eq!(
            cron_next("30 0 * * *", off, utc(2026, 10, 7, 12, 0)).unwrap(),
            Some(utc(2026, 10, 7, 22, 30))
        );
    }

    #[test]
    fn trigger_rejects_unknown_fields_and_zones() {
        assert!(
            parse_trigger(
                &json!({"kind": "cron", "expression": "* * * * *", "timezone": "UTC", "extra": 1})
            )
            .is_err()
        );
        assert!(
            parse_trigger(
                &json!({"kind": "cron", "expression": "* * * * *", "timezone": "America/New_York"})
            )
            .is_err()
        );
        assert!(parse_trigger(&json!({"kind": "timer", "run_at": "2026-10-08T00:00:00Z"})).is_ok());
        assert!(parse_trigger(&json!({"kind": "event", "event_type": "EMAIL_RECEIVED"})).is_ok());
        assert!(parse_trigger(&json!({"kind": "event", "event_type": "NOPE"})).is_err());
    }
    #[test]
    fn missed_window_coalesces_to_single_trigger() {
        // Every-minute cron, three hours missed: scan counts 181 occurrences in
        // [start, end] but fire/dispatch emit exactly one trigger; the rest is
        // recorded as missed_count = count - 1.
        let off = FixedOffset::east_opt(0).unwrap();
        let sched = parse_cron("* * * * *").unwrap();
        let start = utc(2026, 10, 7, 9, 0);
        let end = utc(2026, 10, 7, 12, 0);
        let scan = scan_window(&sched, off, start, end).unwrap();
        assert_eq!(scan.count, 181);
        assert_eq!(scan.count.saturating_sub(1), 180);
        // The follow-up schedule continues from the end of the window, not
        // from each missed occurrence: exactly one next run.
        assert_eq!(scan.next_after, Some(utc(2026, 10, 7, 12, 1)));
    }

    #[test]
    fn missed_window_single_occurrence_has_zero_missed() {
        // No backlog: exactly one occurrence in the window means a normal
        // single fire with missed_count 0, not a burst.
        let off = FixedOffset::east_opt(0).unwrap();
        let sched = parse_cron("0 12 * * *").unwrap();
        let scan = scan_window(
            &sched,
            off,
            utc(2026, 10, 7, 12, 0),
            utc(2026, 10, 7, 12, 0),
        )
        .unwrap();
        assert_eq!(scan.count, 1);
        assert_eq!(scan.count.saturating_sub(1), 0);
        assert_eq!(scan.next_after, Some(utc(2026, 10, 8, 12, 0)));
    }

    #[test]
    fn filters_validate_and_match() {
        let filters = validate_filters(&json!([
            {"field": "severity", "operator": "eq", "value": "URGENT"},
            {"field": "count", "operator": "gte", "value": 3},
        ]))
        .unwrap();
        assert!(filter_matches(
            &json!({"severity": "URGENT", "count": 5}),
            &filters
        ));
        assert!(!filter_matches(
            &json!({"severity": "URGENT", "count": 1}),
            &filters
        ));
        assert!(
            validate_filters(&json!([{"field": "a;DROP", "operator": "eq", "value": 1}])).is_err()
        );
    }

    #[test]
    fn observation_triggers_require_source_binding() {
        // Legacy types keep exact semantics: bare event_type still validates.
        assert!(parse_trigger(&json!({"kind": "event", "event_type": "EMAIL_RECEIVED"})).is_ok());
        for t in ["SOURCE_CHANGED", "CALENDAR_DUE", "REMINDER_DUE"] {
            assert!(parse_trigger(&json!({"kind": "event", "event_type": t})).is_err(), "{t} without source must fail");
            assert!(parse_trigger(&json!({"kind": "event", "event_type": t, "source": "email:inbox"})).is_ok());
            assert!(parse_trigger(&json!({"kind": "event", "event_type": t, "source_type": "email", "source_id": "inbox"})).is_ok());
            assert!(parse_trigger(&json!({"kind": "event", "event_type": t, "source_type": "email"})).is_err(), "{t} half pair must fail");
        }
        // Unknown extra trigger keys still rejected.
        assert!(parse_trigger(&json!({"kind": "event", "event_type": "SOURCE_CHANGED", "source": "x", "bogus": 1})).is_err());
    }

    #[test]
    fn rule_config_defaults_keep_legacy_valid() {
        // Empty policy_scope parses; legacy (no behavior, non-rule trigger)
        // validates unchanged.
        let cron = parse_trigger(&json!({"kind": "cron", "expression": "0 9 * * *", "timezone": "UTC"})).unwrap();
        let cfg = parse_rule_config(&json!({})).unwrap();
        assert!(cfg.behavior.is_none());
        validate_rule_config(&cron, &json!({}), None).unwrap();
        // Observation trigger without behavior fails even with scopes.
        let obs = parse_trigger(&json!({"kind": "event", "event_type": "SOURCE_CHANGED", "source": "email:inbox"})).unwrap();
        assert!(validate_rule_config(&obs, &json!({"source_scopes": ["email:inbox"]}), None).is_err());
        // New rules need source_scopes.
        assert!(validate_rule_config(&obs, &json!({"behavior": "SUGGEST"}), None).is_err());
        // ASK validates with scopes alone.
        validate_rule_config(&obs, &json!({"behavior": "ASK", "source_scopes": ["email:inbox"]}), None).unwrap();
        // AUTO needs agent + action scopes + budget + confidence.
        let agent = Uuid::new_v4();
        let base = json!({"behavior": "AUTO", "source_scopes": ["email:inbox"]});
        assert!(validate_rule_config(&obs, &base, Some(agent)).is_err());
        let full = json!({"behavior": "AUTO", "source_scopes": ["email:inbox"], "action_scopes": [{"tool": "mail.read", "scope_key": "email:inbox", "scope_revision": 1}], "max_daily_micro_usd": 1000, "minimum_confidence": 0.7});
        validate_rule_config(&obs, &full, Some(agent)).unwrap();
        // Bad numerics rejected at parse time.
        assert!(parse_rule_config(&json!({"cooldown_seconds": -1})).is_err());
        assert!(parse_rule_config(&json!({"max_runs_per_day": 0})).is_err());
        assert!(parse_rule_config(&json!({"minimum_confidence": 2.0})).is_err());
        assert!(parse_rule_config(&json!({"quiet_hours": {"start": "25:00", "end": "01:00"}})).is_err());
    }
}
