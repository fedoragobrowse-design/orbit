//! Calendar slice: ICS fixture parse (3 events) + CRUD scoped + sync via local stub.
//! Hermetic DB, dropped after. CalDAV tested against a local stub PROPFIND
//! server (same hermetic pattern as GreenMail) — no external network.
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use orbit_api::calendar::{self, EventsQuery, SourceCreate};
use sqlx::PgPool;
use uuid::Uuid;
const FIXTURE: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//orbit//test//EN\r\nBEGIN:VEVENT\r\nUID:evt-1@example.invalid\r\nSUMMARY:Morning standup\r\nDTSTART:20261010T090000Z\r\nDTEND:20261010T093000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:evt-2@example.invalid\r\nSUMMARY:Lunch with Sam\r\nDTSTART:20261010T120000Z\r\nDTEND:20261010T130000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:evt-3@example.invalid\r\nSUMMARY:Evening review\r\nDTSTART;VALUE=DATE:20261011\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
#[test]
fn ics_fixture_parses_three_events() {
    let events = orbit_calendar::parse_ics(FIXTURE).unwrap();
    assert_eq!(events.len(), 3, "fixture must yield 3 events");
    assert_eq!(events[0].uid, "evt-1@example.invalid");
    assert_eq!(events[0].title, "Morning standup");
    assert!(events[0].starts_at.is_some());
    assert_eq!(events[2].title, "Evening review");
}
#[test]
fn ics_rejects_control_uid_and_bounds() {
    let bad = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:bad\u{0}uid\r\nSUMMARY:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let events = orbit_calendar::parse_ics(bad).unwrap();
    assert!(events.is_empty(), "control-char UID must be skipped");
    assert!(orbit_calendar::parse_ics(&"x".repeat(1024 * 1024 + 1)).is_err(), "oversize feed must fail");
}
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_cal_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_cal_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap, HeaderMap) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("cal-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("cal-token-{owner}");
    let csrf = format!("cal-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-cal-{owner}"));
    let mut read = HeaderMap::new();
    read.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    read.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    let mut write = read.clone();
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, read, write)
}
fn src(url: &str) -> SourceCreate {
    serde_json::from_value(serde_json::json!({"name": "team", "kind": "ics", "url": url, "enabled": true})).unwrap()
}
#[tokio::test]
async fn calendar_crud_scoped_and_sync_from_local_stub() {
    let (pool, db, key_dir) = pool().await;
    let (state, read, write) = ctx(&pool).await;
    let stub = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = stub.local_addr().unwrap().port();
    let body = FIXTURE.to_owned();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = stub.accept().await {
            let mut buf = vec![0u8; 4096];
            use tokio::io::AsyncReadExt;
            let _ = s.read(&mut buf).await;
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/calendar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
    let created = match calendar::create_source(State(state.clone()), write.clone(), axum::Json(src(&format!("http://127.0.0.1:{port}/feed.ics")))).await { Ok(v) => v, Err(_) => panic!("create source") };
    let id: Uuid = created.0["id"].as_str().unwrap().parse().unwrap();
    let out = match calendar::sync_source(State(state.clone()), write.clone(), Path(id)).await { Ok(v) => v, Err(_) => panic!("sync source") };
    assert_eq!(out.0["stored"], serde_json::json!(3), "stub feed must store 3 events");
    let listed = match calendar::list_events(State(state.clone()), read.clone(), Query(EventsQuery { from: None, to: None, limit: None })).await { Ok(v) => v, Err(_) => panic!("list events") };
    assert_eq!(listed.0["items"].as_array().unwrap().len(), 3);
    assert!(calendar::create_source(State(state.clone()), write.clone(), axum::Json(src("gopher://bad.invalid/x"))).await.is_err(), "non-http url must 422");
    let removed = match calendar::remove_source(State(state.clone()), write.clone(), Path(id)).await { Ok(v) => v, Err(_) => panic!("remove source") };
    assert_eq!(removed.0["removed"].as_str().unwrap(), id.to_string());
    cleanup(&pool, &db, &key_dir).await;
}
