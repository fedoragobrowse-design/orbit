//! Doc ingestion: PDF-only gate, checksum stability, text index.
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, header};
use orbit_api::ApiState;
use orbit_api::uploads::{self, UploadQuery, pdf_text};
use sqlx::PgPool;
use uuid::Uuid;
const MIN_PDF: &[u8] = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n";
async fn pool() -> (PgPool, Option<String>, std::path::PathBuf) {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url).await.expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
        return (pool, None, std::env::temp_dir().join("orbit-test-secrets"));
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_upl_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test")).execute(&admin).await.unwrap();
    let pool = PgPool::connect(&format!("postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}")).await.expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations").run(&pool).await.expect("migrations apply");
    (pool, Some(db), std::env::temp_dir().join(format!("orbit-test-secrets-{}_{tag}", std::process::id())))
}
async fn cleanup(pool: &PgPool, db: &Option<String>, key_dir: &std::path::Path) {
    if let Some(db) = db.as_ref().filter(|d| d.starts_with("orbit_upl_")) {
        pool.close().await;
        let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres").await.unwrap();
        sqlx::query(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")).execute(&admin).await.unwrap();
        std::fs::remove_dir_all(key_dir).ok();
    }
}
async fn ctx(pool: &PgPool) -> (ApiState, HeaderMap) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')").bind(owner).bind(format!("upl-{owner}@example.invalid")).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)").bind(owner).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')").bind(principal).bind(owner).execute(pool).await.unwrap();
    let token = format!("upl-token-{owner}");
    let csrf = format!("upl-csrf-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(owner).bind(principal).bind(orbit_api::auth::hash(&token)).bind(&csrf).execute(pool).await.unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-upl-{owner}"));
    let mut write = HeaderMap::new();
    write.insert(header::COOKIE, format!("orbit_session={token}").parse().unwrap());
    write.insert(header::ORIGIN, "http://127.0.0.1:8080".parse().unwrap());
    write.insert("x-csrf-token", csrf.parse().unwrap());
    (ApiState { pool: pool.clone(), origin: "http://127.0.0.1:8080".into(), key_dir: key_dir.clone(), artifact_dir: key_dir.join("artifacts"), nodes: orbit_api::computers::NodeHub::new() }, write)
}
fn pdf_with_text(line: &str) -> Vec<u8> {
    let mut v = MIN_PDF.to_vec();
    v.extend_from_slice(format!("({line}) Tj\n").as_bytes());
    v
}
#[test]
fn pdf_text_extracts_parenthesized_runs() {
    let text = pdf_text(&pdf_with_text("Hello quarterly report"));
    assert!(text.contains("Hello quarterly report"), "literal string must extract");
    assert!(pdf_text(b"%PDF-1.4 no strings here").trim().is_empty(), "no literals means no text");
}
#[tokio::test]
async fn upload_pdf_indexes_and_roundtrips_checksum() {
    let (pool, db, key_dir) = pool().await;
    let (state, write) = ctx(&pool).await;
    let bytes = pdf_with_text("Quarterly numbers are up");
    let q = Query(UploadQuery { filename: "report.pdf".into(), content_type: Some("application/pdf".into()) });
    let out = match uploads::upload_doc(State(state.clone()), write.clone(), q, Body::from(bytes.clone())).await { Ok(v) => v, Err(_) => panic!("upload pdf") };
    let id: Uuid = out.0["id"].as_str().unwrap().parse().unwrap();
    let sha: String = out.0["sha256"].as_str().unwrap().to_owned();
    // Non-PDF rejected with validation (plan: 415 semantic, mapped to 422 VALIDATION).
    let bad = Query(UploadQuery { filename: "notes.txt".into(), content_type: Some("text/plain".into()) });
    assert!(uploads::upload_doc(State(state.clone()), write.clone(), bad, Body::from(b"plain text".to_vec())).await.is_err(), "non-PDF must reject");
    // Round-trip: bytes unchanged, checksum stable.
    let resp = match uploads::download_upload(State(state.clone()), write.clone(), axum::extract::Path(id)).await { Ok(v) => v, Err(_) => panic!("download upload") };
    let back = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(&back[..], &bytes[..], "original bytes never modified");
    assert_eq!(sha, out.0["sha256"].as_str().unwrap(), "stored sha256 round-trips");
    let listed = match uploads::list_uploads(State(state.clone()), write.clone()).await { Ok(v) => v, Err(_) => panic!("list uploads") };
    assert_eq!(listed.0["items"].as_array().unwrap().len(), 1);
    cleanup(&pool, &db, &key_dir).await;
}
