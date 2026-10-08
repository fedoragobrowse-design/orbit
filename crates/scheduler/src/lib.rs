//! Scheduler core: automation triggers, cron evaluation, and idempotent firing.
//!
//! No model calls and no side effects beyond the database. All SQL is
//! owner-scoped. Timezones are UTC or fixed numeric offsets (`+02:00`);
//! named IANA zones are rejected until a tz database (e.g. `chrono-tz`) is
//! added. Wall-clock iteration goes through a gap/fold-aware conversion, so
//! nonexistent local times are skipped and repeated local times fire once.

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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Trigger {
    #[serde(rename = "event")]
    Event { event_type: String, source: Option<String> },
    #[serde(rename = "cron")]
    Cron { expression: String, timezone: String },
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
    let trigger: Trigger =
        serde_json::from_value(value.clone()).map_err(|e| Error::Validation(format!("invalid trigger: {e}")))?;
    match &trigger {
        Trigger::Event { event_type, source } => {
            if event_type.is_empty() || event_type.len() > 64 {
                return Err(Error::Validation("event trigger needs a 1..64 char event_type".into()));
            }
            serde_json::from_value::<EventType>(Value::String(event_type.clone()))
                .map_err(|_| Error::Validation(format!("unknown event_type {event_type}")))?;
            if let Some(s) = source {
                if s.is_empty() || s.len() > 256 {
                    return Err(Error::Validation("event trigger source must be 1..256 chars".into()));
                }
            }
        }
        Trigger::Cron { expression, timezone } => {
            parse_cron(expression)?;
            resolve_offset(timezone)?;
        }
        Trigger::Timer { .. } => {}
    }
    Ok(trigger)
}

const OPERATORS: [&str; 10] = ["eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "not_in", "exists"];

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
    let arr = value.as_array().ok_or_else(|| Error::Validation("filters must be an array".into()))?;
    if arr.len() > MAX_FILTERS {
        return Err(Error::Validation("too many filters".into()));
    }
    arr.iter()
        .map(|f| {
            let filter: Filter =
                serde_json::from_value(f.clone()).map_err(|e| Error::Validation(format!("invalid filter: {e}")))?;
            if !valid_field(&filter.field) {
                return Err(Error::Validation(format!("invalid filter field {}", filter.field)));
            }
            if !OPERATORS.contains(&filter.operator.as_str()) {
                return Err(Error::Validation(format!("unknown filter operator {}", filter.operator)));
            }
            match filter.operator.as_str() {
                "exists" => {
                    if let Some(v) = &filter.value {
                        if !v.is_boolean() {
                            return Err(Error::Validation("exists takes an optional boolean".into()));
                        }
                    }
                }
                "gt" | "gte" | "lt" | "lte" => {
                    if !filter.value.as_ref().is_some_and(Value::is_number) {
                        return Err(Error::Validation(format!("{} requires a numeric value", filter.operator)));
                    }
                }
                "contains" => {
                    if !filter.value.as_ref().is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 1024)) {
                        return Err(Error::Validation("contains requires a non-empty string value".into()));
                    }
                }
                "in" | "not_in" => {
                    if !filter.value.as_ref().is_some_and(|v| v.as_array().is_some_and(|a| !a.is_empty() && a.len() <= 50)) {
                        return Err(Error::Validation(format!("{} requires a non-empty array value", filter.operator)));
                    }
                }
                _ => {
                    if filter.value.as_ref().is_none_or(Value::is_null) {
                        return Err(Error::Validation(format!("{} requires a value", filter.operator)));
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
    if t.eq_ignore_ascii_case("utc") || t.eq_ignore_ascii_case("z") || t == "Etc/UTC" || t == "Etc/Zulu" {
        return FixedOffset::east_opt(0).ok_or_else(|| Error::Validation("invalid timezone".into()));
    }
    let (neg, digits) = if let Some(rest) = t.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = t.strip_prefix('-') {
        (true, rest)
    } else {
        return Err(Error::Validation(format!("unsupported timezone {tz}: use UTC or a numeric offset like +02:00")));
    };
    if !digits.bytes().all(|b| b.is_ascii_digit() || b == b':') || digits.is_empty() {
        return Err(Error::Validation(format!("unsupported timezone {tz}: use UTC or a numeric offset like +02:00")));
    }
    let (h, m) = match digits.split_once(':') {
        Some((h, m)) => (h.to_owned(), m.to_owned()),
        None if digits.len() == 4 => (digits[..2].to_owned(), digits[2..].to_owned()),
        None if (1..=2).contains(&digits.len()) => (digits.to_owned(), "00".to_owned()),
        None => return Err(Error::Validation(format!("unsupported timezone {tz}: use UTC or a numeric offset like +02:00"))),
    };
    let hh: i32 = h.parse().map_err(|_| Error::Validation(format!("bad timezone hour in {tz}")))?;
    let mm: i32 = m.parse().map_err(|_| Error::Validation(format!("bad timezone minute in {tz}")))?;
    if hh > 14 || mm > 59 || (hh == 14 && mm != 0) {
        return Err(Error::Validation(format!("timezone offset out of range in {tz}")));
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
    ("JAN", 1), ("FEB", 2), ("MAR", 3), ("APR", 4), ("MAY", 5), ("JUN", 6),
    ("JUL", 7), ("AUG", 8), ("SEP", 9), ("OCT", 10), ("NOV", 11), ("DEC", 12),
];
const DOW_NAMES: [(&str, i32); 7] = [
    ("SUN", 0), ("MON", 1), ("TUE", 2), ("WED", 3), ("THU", 4), ("FRI", 5), ("SAT", 6),
];

fn cron_value(token: &str, names: &[(&str, i32)]) -> Result<i32> {
    let upper = token.to_ascii_uppercase();
    if let Some((_, n)) = names.iter().find(|(name, _)| *name == upper) {
        return Ok(*n);
    }
    token.parse::<i32>().map_err(|_| Error::Validation(format!("bad cron value {token}")))
}

fn parse_cron_field(part: &str, lo: i32, hi: i32, names: &[(&str, i32)]) -> Result<CronField> {
    let mut bits: u64 = 0;
    if part == "*" {
        for v in lo..=hi {
            bits |= 1u64 << (v as u32);
        }
        return Ok(CronField { bits, restricted: false });
    }
    for item in part.split(',') {
        if item.is_empty() {
            return Err(Error::Validation("empty cron list item".into()));
        }
        let (base, step) = match item.split_once('/') {
            Some((b, s)) => {
                let n: u32 = s.parse().map_err(|_| Error::Validation(format!("bad cron step {s}")))?;
                if n == 0 || n > 59 {
                    return Err(Error::Validation(format!("cron step out of range in {item}")));
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
                if a == 7 { a = 0; }
                if b == 7 { b = 0; }
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
            if lo == 0 && v == 7 { v = 0; }
            // Bare `n/step` means `n-max/step` in Vixie cron.
            if step > 1 { (v, hi) } else { (v, v) }
        };
        if from < lo || to > hi || from > to {
            return Err(Error::Validation(format!("cron range out of bounds in {item}")));
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
    Ok(CronField { bits, restricted: true })
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
    wall.date().and_hms_opt(wall.hour(), wall.minute(), 0).expect("valid wall clock")
}

/// Next cron instant strictly after `from`, or `None` if none within the scan cap.
pub fn cron_next(expression: &str, offset: FixedOffset, from: DateTime<Utc>) -> Result<Option<DateTime<Utc>>> {
    let sched = parse_cron(expression)?;
    let mut wall = truncate_minute(from, offset);
    for _ in 0..MAX_SCAN_MINUTES {
        wall = wall.checked_add_signed(Duration::minutes(1)).ok_or_else(|| Error::Validation("cron scan overflow".into()))?;
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
        Trigger::Cron { expression, timezone } => cron_next(expression, resolve_offset(timezone)?, from),
    }
}

struct WindowScan {
    count: i64,
    next_after: Option<DateTime<Utc>>,
}

/// Single minute-by-minute scan counting occurrences in `[start, end]` (the
/// coalesced missed window) plus the next occurrence after `end`.
fn scan_window(sched: &CronSchedule, offset: FixedOffset, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<WindowScan> {
    let mut wall = truncate_minute(start, offset);
    let mut count: i64 = 0;
    for _ in 0..MAX_SCAN_MINUTES {
        if wall_matches(sched, &wall) {
            if let Some(instant) = wall_to_instant(offset, &wall) {
                if instant > end {
                    return Ok(WindowScan { count, next_after: Some(instant) });
                }
                if instant + Duration::minutes(1) > start {
                    count += 1;
                }
            }
        }
        wall = wall.checked_add_signed(Duration::minutes(1)).ok_or_else(|| Error::Validation("cron scan overflow".into()))?;
    }
    Ok(WindowScan { count, next_after: None })
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
        let Some(window_start) = automation.next_run else { continue };
        if window_start > now {
            continue;
        }
        let trigger = parse_trigger(&automation.trigger)?;
        let missed = match &trigger {
            Trigger::Cron { expression, timezone } => {
                let sched = parse_cron(expression)?;
                Some(scan_window(&sched, resolve_offset(timezone)?, window_start, now)?)
            }
            Trigger::Timer { .. } => None,
            // Event triggers never carry a schedule; skip, don't fail the batch.
            Trigger::Event { .. } => continue,
        };
        let missed_count = missed.as_ref().map(|s| s.count.saturating_sub(1)).unwrap_or(0);
        claims.push(DueClaim { automation, window_start, window_end: now, missed_count });
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
    let row = sqlx::query(&format!("SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2 FOR UPDATE"))
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
        return Err(Error::Validation("automation has no pending schedule".into()));
    };
    let now = Utc::now();
    if window_start > now {
        tx.rollback().await?;
        return Ok(None);
    }
    let trigger = parse_trigger(&automation.trigger)?;
    let (event_type, missed_count, next_after) = match &trigger {
        Trigger::Cron { expression, timezone } => {
            let sched = parse_cron(expression)?;
            let scan = scan_window(&sched, resolve_offset(timezone)?, window_start, now)?;
            (EventType::ScheduleTrigger, scan.count.saturating_sub(1), scan.next_after)
        }
        Trigger::Timer { .. } => (EventType::TimerTrigger, 0, None),
        Trigger::Event { .. } => return Err(Error::Validation("event automations fire from the event bus".into())),
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
    let stored: Uuid = sqlx::query_scalar("SELECT id FROM events WHERE owner_id=$1 AND source='scheduler' AND source_event_key=$2")
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

/// Re-arm an automation's schedule from its current trigger, guarded by
/// `expected_revision`. Advances the revision without inserting any fires.
pub async fn reschedule(pool: &PgPool, scope: &OwnerScope, automation_id: Uuid, expected_revision: i64) -> Result<Automation> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(&format!("SELECT {COLUMNS} FROM automations WHERE owner_id=$1 AND id=$2 FOR UPDATE"))
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
        assert_eq!(cron_next("* * * * *", off, utc(2026, 10, 7, 12, 0)).unwrap(), Some(utc(2026, 10, 7, 12, 1)));
    }

    #[test]
    fn cron_daily_midnight_utc() {
        let off = FixedOffset::east_opt(0).unwrap();
        assert_eq!(cron_next("0 0 * * *", off, utc(2026, 10, 7, 12, 0)).unwrap(), Some(utc(2026, 10, 8, 0, 0)));
    }

    #[test]
    fn cron_dom_or_dow() {
        // First of month OR Monday: 2026-10-07 is a Wednesday, next Monday is 10-12.
        let off = FixedOffset::east_opt(0).unwrap();
        assert_eq!(cron_next("0 0 1 * MON", off, utc(2026, 10, 7, 12, 0)).unwrap(), Some(utc(2026, 10, 12, 0, 0)));
    }

    #[test]
    fn cron_offset_shifts_wall_clock() {
        let off = resolve_offset("+02:00").unwrap();
        // 00:30 wall in +02:00 == 22:30 UTC previous day.
        assert_eq!(cron_next("30 0 * * *", off, utc(2026, 10, 7, 12, 0)).unwrap(), Some(utc(2026, 10, 7, 22, 30)));
    }

    #[test]
    fn trigger_rejects_unknown_fields_and_zones() {
        assert!(parse_trigger(&json!({"kind": "cron", "expression": "* * * * *", "timezone": "UTC", "extra": 1})).is_err());
        assert!(parse_trigger(&json!({"kind": "cron", "expression": "* * * * *", "timezone": "America/New_York"})).is_err());
        assert!(parse_trigger(&json!({"kind": "timer", "run_at": "2026-10-08T00:00:00Z"})).is_ok());
        assert!(parse_trigger(&json!({"kind": "event", "event_type": "EMAIL_RECEIVED"})).is_ok());
        assert!(parse_trigger(&json!({"kind": "event", "event_type": "NOPE"})).is_err());
    }

    #[test]
    fn filters_validate_and_match() {
        let filters = validate_filters(&json!([
            {"field": "severity", "operator": "eq", "value": "URGENT"},
            {"field": "count", "operator": "gte", "value": 3},
        ]))
        .unwrap();
        assert!(filter_matches(&json!({"severity": "URGENT", "count": 5}), &filters));
        assert!(!filter_matches(&json!({"severity": "URGENT", "count": 1}), &filters));
        assert!(validate_filters(&json!([{"field": "a;DROP", "operator": "eq", "value": 1}])).is_err());
    }
}
