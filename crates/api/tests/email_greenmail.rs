//! GreenMail live-connector proof: IMAP/SMTP round-trip against the disposable
//! fixture (`greenmail/standalone:2.1.14`, host 127.0.0.1:19993 IMAPS /
//! 127.0.0.1:19465 SMTPS, users assistant/recipient@orbit.test per
//! deploy/examples/compose.test.yaml). Flow: create account -> test()
//! returns CONNECTED -> seed one message over SMTPS -> sync() ingests it ->
//! stored body/attachments still carry UNTRUSTED_EXTERNAL taint and satisfy
//! the quarantine_store guard (attachment digest match, body re-quarantines).
//! Gated: skips (Ok, no fail) unless both fixture TCP ports accept. The
//! fixture presents the disposable test CA, so TLS trust needs its PEM via
//! ORBIT_GREENMAIL_CA_PEM (inline) or ORBIT_GREENMAIL_CA_FILE (path); as a
//! fallback the test reads it from the `orbit-test-ca-trust` volume, e.g.
//! `docker run --rm -v orbit-test-ca-trust:/trust:ro alpine:3.22 cat
//! /trust/ca.crt`. Owned test postgres only (default 127.0.0.1:55432
//! orbit_test). Never the personal deployment.
use base64::Engine as _;
use orbit_core::OwnerScope;
use serde_json::{Value, json};
use sha2::Digest as _;
use sqlx::{PgPool, Row};
use uuid::Uuid;
fn imap_port() -> u16 { std::env::var("ORBIT_GREENMAIL_IMAP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(19993) }
fn smtp_port() -> u16 { std::env::var("ORBIT_GREENMAIL_SMTP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(19465) }
async fn live() -> bool {
    for port in [imap_port(), smtp_port()] {
        if tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect(("127.0.0.1", port))).await.map(|r| r.is_ok()) != Ok(true) {
            return false;
        }
    }
    true
}
fn ca_pem() -> Option<String> {
    if let Ok(pem) = std::env::var("ORBIT_GREENMAIL_CA_PEM") {
        if pem.contains("BEGIN CERTIFICATE") {
            return Some(pem);
        }
    }
    if let Ok(path) = std::env::var("ORBIT_GREENMAIL_CA_FILE") {
        if let Ok(pem) = std::fs::read_to_string(path) {
            if pem.contains("BEGIN CERTIFICATE") {
                return Some(pem);
            }
        }
    }
    let out = std::process::Command::new("timeout").args(["25", "docker", "run", "--rm", "-v", "orbit-test-ca-trust:/trust:ro", "alpine:3.22", "cat", "/trust/ca.crt"]).output().ok()?;
    let pem = String::from_utf8(out.stdout).ok()?;
    pem.contains("BEGIN CERTIFICATE").then_some(pem)
}
/// Fixture flapping mid-test surfaces as Unavailable; re-probe and skip only
/// when the fixture is actually down, otherwise fail loudly.
async fn gate<T>(label: &str, r: Result<T, orbit_core::Error>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            let detail = format!("{e:?}");
            if matches!(e, orbit_core::Error::Unavailable(_)) && !live().await {
                eprintln!("SKIP: GreenMail fixture unreachable during {label}; live-connector proof skipped");
                return None;
            }
            panic!("GreenMail {label} failed while fixture is up: {detail}");
        }
    }
}
fn db_url() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://orbit_test:orbit_test@127.0.0.1:55432/orbit_test".into())
}
#[tokio::test]
async fn greenmail_imap_smtp_roundtrip_with_quarantine() {
    if !live().await {
        eprintln!("SKIP: GreenMail fixture not reachable on 127.0.0.1:{}/{}; live-connector proof skipped", imap_port(), smtp_port());
        return;
    }
    let Some(ca) = ca_pem() else {
        eprintln!("SKIP: GreenMail fixture CA unavailable (set ORBIT_GREENMAIL_CA_PEM or ORBIT_GREENMAIL_CA_FILE); live-connector proof skipped");
        return;
    };
    let pool = PgPool::connect(&db_url()).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("greenmail-proof-{owner}@example.invalid")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(&pool).await.unwrap();
    let scope = OwnerScope { owner_id: owner, principal_id: principal };
    // Stable across runs: the shared test DB keeps secret rows encrypted under this key, so a fresh dir per run would fail reopen with "master key missing".
    let key_dir = std::env::var("ORBIT_TEST_KEY_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir().join("orbit-test-secrets"));
    let store = orbit_secrets::SecretStore::open(pool.clone(), &key_dir).await.expect("secret store opens");
    let credential = orbit_email::Credential { username: "assistant@orbit.test".into(), password: "orbit-fixture-pass".into() };
    let credential_bytes = serde_json::to_vec(&json!({"username": credential.username, "password": credential.password})).unwrap();
    let imap_id = store.put(&scope, "email-imap-credential", &credential_bytes).await.unwrap();
    let smtp_id = store.put(&scope, "email-smtp-credential", &credential_bytes).await.unwrap();
    let config = orbit_email::AccountConfig { imap_host: "127.0.0.1".into(), imap_port: imap_port(), smtp_host: "127.0.0.1".into(), smtp_port: smtp_port(), from_address: "assistant@orbit.test".into(), mailboxes: vec!["INBOX".into()], archive_mailbox: None, poll_seconds: 60, ca_pem: Some(ca) };
    let account = Uuid::new_v4();
    sqlx::query("INSERT INTO email_accounts(id,owner_id,name,config,imap_secret_id,smtp_secret_id) VALUES($1,$2,'greenmail-proof',$3,$4,$5)").bind(account).bind(owner).bind(serde_json::to_value(&config).unwrap()).bind(imap_id).bind(smtp_id).execute(&pool).await.unwrap();
    let service = orbit_email::MailService { pool: pool.clone(), secrets: store };
    let Some(tested) = gate("test()", service.test(&scope, account).await).await else { return; };
    assert_eq!(tested["status"], "CONNECTED", "test() must report CONNECTED against the live fixture");
    let token = format!("orbit-greenmail-proof-{account}");
    let attachment_bytes = format!("{token}-attachment").into_bytes();
    let draft = orbit_email::DraftContent { from: "assistant@orbit.test".into(), to: vec!["assistant@orbit.test".into()], cc: vec![], bcc: vec![], subject: format!("{token}-subject"), body: format!("{token}-body"), in_reply_to: None, references: vec![], attachments: vec![orbit_email::Attachment { name: "proof.txt".into(), mime: "text/plain".into(), sha256: hex::encode(sha2::Sha256::digest(&attachment_bytes)), content_base64: base64::engine::general_purpose::STANDARD.encode(&attachment_bytes) }] };
    let Some(()) = gate("send_once()", orbit_email::transport::send_once(&config, &credential, &draft, Uuid::new_v4()).await).await else { return; };
    let mut row: Option<(Uuid, String, Value, String, i64)> = None;
    let mut received_total = 0i64;
    for _ in 0..6 {
        let Some(out) = gate("sync()", service.sync(&scope, account).await).await else { return; };
        received_total += out["received"].as_i64().unwrap_or(0);
        let rows = sqlx::query("SELECT id,body_text,attachments,trust_level,uid FROM email_messages WHERE owner_id=$1 AND account_id=$2").bind(owner).bind(account).fetch_all(&pool).await.unwrap();
        if let Some(r) = rows.into_iter().find(|r| r.get::<String, _>("body_text").contains(&token)) {
            let id: Uuid = r.get("id");
            let body: String = r.get("body_text");
            let attachments: Value = r.get("attachments");
            let trust: String = r.get("trust_level");
            let uid: i64 = r.get("uid");
            row = Some((id, body, attachments, trust, uid));
            break;
        }
        if out["received"].as_i64().unwrap_or(0) == 0 {
            break;
        }
    }
    let (id, body, attachments, trust, uid) = row.unwrap_or_else(|| panic!("sync ingested {received_total} message(s) but none carries the seeded token {token}; quarantine path unproven while fixture is up"));
    assert!(received_total >= 1, "sync must ingest a nonzero count while the fixture is up");
    assert_eq!(trust, "UNTRUSTED_EXTERNAL", "stored body must carry taint");
    let event = sqlx::query("SELECT event_type,trust_level FROM events WHERE owner_id=$1 AND payload->>'message_id'=$2").bind(owner).bind(id.to_string()).fetch_optional(&pool).await.unwrap().expect("ingested mail must leave a tainted EMAIL_RECEIVED event");
    assert_eq!(event.get::<String, _>("event_type"), "EMAIL_RECEIVED");
    assert_eq!(event.get::<String, _>("trust_level"), "UNTRUSTED_EXTERNAL");
    let attachments = attachments.as_array().expect("stored attachments must be an array");
    let proof = attachments.iter().find(|a| a["name"] == "proof.txt").expect("seeded attachment must survive sync");
    let bytes = base64::engine::general_purpose::STANDARD.decode(proof["content_base64"].as_str().unwrap()).unwrap();
    assert_eq!(bytes, attachment_bytes, "stored attachment bytes must round-trip");
    assert_eq!(proof["sha256"].as_str().unwrap(), hex::encode(sha2::Sha256::digest(&bytes)).as_str(), "stored message path must satisfy the quarantine_store attachment digest check");
    let quarantined = orbit_email::quarantine_store(&format!("email-body-{uid}.txt"), "text/plain", body.as_bytes()).expect("stored body must satisfy the quarantine_store guard");
    assert_eq!(quarantined.size, body.len());
}
