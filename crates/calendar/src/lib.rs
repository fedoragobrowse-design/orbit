//! Calendar connector: ICS feed URLs + CalDAV servers poll into `calendar_events`.
//! Third-party bytes stay untrusted: UID/title bounded, control chars rejected,
//! timestamps parsed strictly, raw truncated at 64 KiB. No OAuth — Google/Graph
//! stay `usable:false` by design; CalDAV basic-auth + public ICS only.
use chrono::{DateTime, Utc};
use orbit_core::{Error, OwnerScope, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;
pub const MAX_RAW_BYTES: usize = 64 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarSource {
    pub kind: String,
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}
impl CalendarSource {
    pub fn validate(&self) -> Result<()> {
        if self.kind != "ics" && self.kind != "caldav" {
            return Err(Error::Validation("calendar source kind must be ics|caldav".into()));
        }
        if self.url.is_empty() || self.url.len() > 2048 {
            return Err(Error::Validation("invalid calendar url".into()));
        }
        if !(self.url.starts_with("https://") || self.url.starts_with("http://")) {
            return Err(Error::Validation("calendar url must be http(s)".into()));
        }
        for cred in [&self.username, &self.password] {
            if let Some(s) = cred {
                if s.is_empty() || s.len() > 512 || s.chars().any(char::is_control) {
                    return Err(Error::Validation("invalid calendar credential".into()));
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEvent {
    pub uid: String,
    pub title: String,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
}
fn unfold(lines: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in lines.lines() {
        let line = line.trim_end_matches('\r');
        if (line.starts_with(' ') || line.starts_with('\t')) && !out.is_empty() {
            let last = out.len() - 1;
            out[last].push_str(line.trim_start());
        } else {
            out.push(line.to_owned());
        }
    }
    out
}
fn clean_field(s: &str) -> String {
    s.replace("\\n", "\n").replace("\\,", ",").replace("\\;", ";").replace("\\\\", "\\")
        .chars().filter(|c| !c.is_control() || *c == '\n').take(512).collect::<String>().trim().to_owned()
}
fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    let s = s.split(';').next_back().unwrap_or(s).split(':').next_back().unwrap_or(s);
    for fmt in ["%Y%m%dT%H%M%SZ", "%Y%m%dT%H%M%S", "%Y%m%d"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
        if let Ok(date) = chrono::NaiveDate::parse_from_str(s, fmt) {
            return date.and_hms_opt(0, 0, 0).map(|t| t.and_utc());
        }
    }
    s.parse::<DateTime<Utc>>().ok()
}
/// Hand-rolled ICS VEVENT parser (~40 lines, no new dep): unfolds continuation
/// lines, reads UID/SUMMARY/DTSTART/DTEND per VEVENT, bounds every field.
pub fn parse_ics(body: &str) -> Result<Vec<ParsedEvent>> {
    if body.len() > 1024 * 1024 {
        return Err(Error::Validation("ics feed exceeds 1 MiB bound".into()));
    }
    let mut events = Vec::new();
    let mut cur: Option<(String, String, Option<DateTime<Utc>>, Option<DateTime<Utc>>)> = None;
    for line in unfold(body) {
        if line == "BEGIN:VEVENT" {
            cur = Some((String::new(), String::new(), None, None));
        } else if line == "END:VEVENT" {
            if let Some((uid, title, start, end)) = cur.take() {
                if uid.is_empty() || uid.len() > 256 || uid.chars().any(char::is_control) {
                    continue;
                }
                let title = if title.is_empty() { "(untitled)".into() } else { title };
                events.push(ParsedEvent { uid, title, starts_at: start, ends_at: end });
                if events.len() > 2000 {
                    return Err(Error::Validation("ics feed exceeds event bound".into()));
                }
            }
        } else if let Some((uid, title, start, end)) = cur.as_mut() {
            let (key, val) = match line.split_once(':') {
                Some(p) => p,
                None => continue,
            };
            let base = key.split(';').next().unwrap_or(key);
            match base {
                "UID" if val.chars().any(char::is_control) => *uid = String::new(),
                "UID" => *uid = clean_field(val).chars().take(256).collect(),
                "SUMMARY" => *title = clean_field(val),
                "DTSTART" => *start = parse_dt(val),
                "DTEND" => *end = parse_dt(val),
                _ => {}
            }
        }
    }
    Ok(events)
}
fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(3)).no_proxy().timeout(std::time::Duration::from_secs(20)).build().map_err(|_| Error::Unavailable("calendar client unavailable".into()))
}
pub async fn fetch_ics(url: &str) -> Result<String> {
    let body = http()?.get(url).send().await.map_err(|_| Error::Unavailable("calendar feed unreachable".into()))?.error_for_status().map_err(|_| Error::Unavailable("calendar feed error".into()))?.text().await.map_err(|_| Error::Unavailable("calendar feed unreadable".into()))?;
    if body.len() > 1024 * 1024 {
        return Err(Error::Validation("ics feed exceeds 1 MiB bound".into()));
    }
    Ok(body)
}
const PROPFIND: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?><propfind xmlns=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><prop><resourcetype/><C:calendar-data/></prop></propfind>";
/// CalDAV poll: PROPFIND for calendar objects, then parse any embedded
/// VEVENT blocks from the multistatus body as ICS.
pub async fn fetch_caldav(source: &CalendarSource) -> Result<String> {
    let mut req = http()?.request(reqwest::Method::from_bytes(b"PROPFIND").unwrap(), &source.url).header("Depth", "1").header("Content-Type", "application/xml").body(PROPFIND.to_owned());
    if let (Some(u), Some(p)) = (source.username.as_deref(), source.password.as_deref()) {
        req = req.basic_auth(u, Some(p));
    }
    let body = req.send().await.map_err(|_| Error::Unavailable("caldav unreachable".into()))?.error_for_status().map_err(|_| Error::Unavailable("caldav error".into()))?.text().await.map_err(|_| Error::Unavailable("caldav unreadable".into()))?;
    if body.len() > 1024 * 1024 {
        return Err(Error::Validation("caldav response exceeds 1 MiB bound".into()));
    }
    Ok(body)
}
pub async fn store_events(pool: &PgPool, scope: &OwnerScope, source: &str, events: Vec<ParsedEvent>, raw: &str) -> Result<usize> {
    let raw: String = raw.chars().take(MAX_RAW_BYTES).collect();
    let mut n = 0;
    for e in events {
        let id = Uuid::new_v4();
        let res = sqlx::query("INSERT INTO calendar_events(id,owner_id,source,uid,title,starts_at,ends_at,raw) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id,source,uid) DO UPDATE SET title=EXCLUDED.title,starts_at=EXCLUDED.starts_at,ends_at=EXCLUDED.ends_at,raw=EXCLUDED.raw,updated_at=now()").bind(id).bind(scope.owner_id).bind(source).bind(&e.uid).bind(&e.title).bind(e.starts_at).bind(e.ends_at).bind(&raw).execute(pool).await;
        if res.is_ok() {
            n += 1;
        }
    }
    Ok(n)
}
pub async fn sync_source(pool: &PgPool, scope: &OwnerScope, name: &str, source: &CalendarSource) -> Result<Value> {
    source.validate()?;
    let body = if source.kind == "ics" { fetch_ics(&source.url).await? } else { fetch_caldav(source).await? };
    let events = parse_ics(&body)?;
    let stored = store_events(pool, scope, name, events, &body).await?;
    Ok(json!({"source": name, "stored": stored}))
}
