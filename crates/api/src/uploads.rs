//! Document ingestion (growth C14): PDF-only upload → sealed bytes +
//! extracted text indexed as a memory DOCUMENT with `upload:<id>`
//! provenance. Original bytes are never modified; the stored sha256
//! must match on every read.
use axum::{Json, Router, body::Body, extract::{Path, Query, State}, http::HeaderMap, response::{IntoResponse, Response}, routing::{get, post}};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
use crate::{ApiError, ApiState, authenticate};
const MAX_DOC_BYTES: usize = 50 * 1024 * 1024;
const MAX_TEXT_CHARS: usize = 200_000;
/// Extract printable text runs from a PDF byte stream. This is a bounded
/// intentionally-lossy preview (parenthesized literal strings + hex
/// strings), not a full PDF renderer — enough to index and summarize,
/// never presented as the document itself.
pub fn pdf_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() && out.len() < MAX_TEXT_CHARS {
        match bytes[i] {
            b'(' => {
                i += 1;
                let mut depth = 1i32;
                let mut lit = Vec::new();
                while i < bytes.len() && depth > 0 && lit.len() < 8192 {
                    match bytes[i] {
                        b'\\' if i + 1 < bytes.len() => { lit.push(bytes[i + 1]); i += 2; }
                        b'(' => { depth += 1; lit.push(b'('); i += 1; }
                        b')' => { depth -= 1; if depth > 0 { lit.push(b')'); } i += 1; }
                        b'\r' | b'\n' => { lit.push(b' '); i += 1; }
                        c => { lit.push(c); i += 1; }
                    }
                }
                let s = String::from_utf8_lossy(&lit);
                if !s.trim().is_empty() { out.push_str(s.trim()); out.push('\n'); }
            }
            b'<' if i + 1 < bytes.len() && bytes[i + 1] == b'<' => { i += 2; }
            b'<' => {
                i += 1;
                let mut hex = Vec::new();
                while i < bytes.len() && bytes[i] != b'>' && hex.len() < 8192 { if bytes[i].is_ascii_hexdigit() { hex.push(bytes[i]); } i += 1; }
                if i < bytes.len() { i += 1; }
                if hex.len() >= 8 {
                    let pairs: Vec<u8> = hex.chunks(2).filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or(""), 16).ok()).collect();
                    let s = String::from_utf8_lossy(&pairs);
                    let clean: String = s.chars().filter(|c| !c.is_control() || *c == '\n').collect();
                    if clean.trim().len() >= 4 { out.push_str(clean.trim()); out.push('\n'); }
                }
            }
            _ => { i += 1; }
        }
    }
    out.chars().take(MAX_TEXT_CHARS).collect()
}
#[derive(Deserialize)]
pub struct UploadQuery { pub filename: String, pub content_type: Option<String> }
#[utoipa::path(post, path = "/api/v1/uploads", responses((status = 200, body = Value)))]
pub async fn upload_doc(State(state): State<ApiState>, headers: HeaderMap, Query(q): Query<UploadQuery>, body: Body) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let bytes = axum::body::to_bytes(body, MAX_DOC_BYTES + 1).await.map_err(|_| Error::Validation("upload body unreadable".into()))?;
    if bytes.len() > MAX_DOC_BYTES { return Err(Error::Validation("document exceeds 50 MB".into()).into()); }
    let name = q.filename.trim();
    if name.is_empty() || name.len() > 256 || name.contains(['\0', '\\']) || name.contains("..") || name.starts_with('/') || name.contains(':') {
        return Err(Error::Validation("upload name fails path-traversal screen".into()).into());
    }
    let lower = name.to_ascii_lowercase();
    let claimed = q.content_type.as_deref().unwrap_or("application/pdf");
    if !lower.ends_with(".pdf") || (claimed != "application/pdf" && claimed != "application/octet-stream") || !bytes.starts_with(b"%PDF-") {
        return Err(Error::Validation("unsupported media type; PDFs only".into()).into());
    }
    let quarantined = orbit_email::quarantine_store(name, "application/pdf", &bytes)?;
    let stored = orbit_agent_runtime::attachments::upload(&state.pool, &state.artifact_dir, &a.scope, &quarantined.name, "application/pdf", &bytes).await?;
    let id: Uuid = serde_json::from_value::<Uuid>(stored["id"].clone()).map_err(|_| Error::Unavailable("upload identity unavailable".to_string()))?;
    let text = pdf_text(&bytes);
    let preview: String = text.chars().take(4000).collect();
    let candidate = orbit_memory::Candidate { memory_type: orbit_core::MemoryType::Document, subject: format!("upload:{name}"), value: json!({"upload_id": id, "filename": name, "sha256": stored["sha256"], "chars": text.len(), "preview": preview}), source_references: vec![], related_entities: vec![], privacy_class: orbit_core::PrivacyClass::Private, confidence: 0.8, valid_until: None, entity_id: None };
    let provenance = orbit_memory::Provenance { source: "OWNER_UPLOAD".into(), references: vec![format!("upload:{id}")], trust: orbit_core::TrustLevel::OwnerAuthenticated, privacy: orbit_core::PrivacyClass::Private, correlation_id: Uuid::new_v4(), task_id: None };
    let outcome = orbit_memory::ingest(&state.pool, &a.scope, candidate, provenance, None, None).await?;
    Ok(Json(json!({"id": id, "name": stored["name"], "size": stored["size"], "sha256": stored["sha256"], "chars": text.len(), "memory_id": outcome.memory_id})))
}
#[utoipa::path(get, path = "/api/v1/uploads", responses((status = 200, body = Value)))]
pub async fn list_uploads(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id,title AS name,mime_type,size,sha256,created_at FROM artifacts WHERE owner_id=$1 AND mime_type='application/pdf' ORDER BY created_at DESC LIMIT 100").bind(a.scope.owner_id).fetch_all(&state.pool).await?;
    let items: Vec<Value> = rows.iter().map(|r| json!({"id": r.try_get::<Uuid,_>("id").ok(), "name": r.try_get::<String,_>("name").unwrap_or_default(), "mime_type": r.try_get::<String,_>("mime_type").unwrap_or_default(), "size": r.try_get::<i64,_>("size").unwrap_or(0), "sha256": r.try_get::<String,_>("sha256").unwrap_or_default(), "created_at": r.try_get::<chrono::DateTime<chrono::Utc>,_>("created_at").ok()})).collect();
    Ok(Json(json!({"items": items})))
}
#[utoipa::path(get, path = "/api/v1/uploads/{id}", responses((status = 200)))]
pub async fn download_upload(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Response, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let (name, bytes, _source) = orbit_agent_runtime::attachments::read(&state.pool, &state.artifact_dir, &a.scope, id).await?;
    let body = axum::body::Body::from(bytes);
    let mut head = axum::http::HeaderMap::new();
    head.insert(axum::http::header::CONTENT_TYPE, "application/pdf".parse().unwrap());
    head.insert(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"").parse().unwrap());
    Ok((head, body).into_response())
}
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/uploads", post(upload_doc).get(list_uploads))
        .route("/api/v1/uploads/{id}", get(download_upload))
}
