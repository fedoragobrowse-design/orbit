//! P4 Files tab + document ingestion. The tab lists/gets/imports owner
//! files backed by the sealed artifact store (`artifacts`/`chat_attachments`
//! from 0003/0004, written through `attachments::upload`): bytes are stored
//! where those rows already point (`artifact_dir`), never on a node, and
//! every stored row carries UNTRUSTED_EXTERNAL trust. Uploaded text content
//! is screened with `ContextBlock::looks_like_injection` — a hit sets the
//! `quarantined` flag on the returned item (and the stored metadata) but is
//! never executed; the bytes still round-trip immutably with sha256 match.
//! Owner-scoped throughout; size caps match the existing 10 MiB
//! TRANSFER/attachment bound (`MAX_FILE_BYTES` == `MAX_DOC_BYTES`).
use axum::{Json, Router, body::Body, extract::{Path, Query, State}, http::HeaderMap, response::{IntoResponse, Response}, routing::{get, post}};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
use crate::{ApiError, ApiState, authenticate};
const MAX_FILE_BYTES: usize = 10 * 1024 * 1024;
const MAX_FILES_LIST: i64 = 200;
const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
/// Shared files-tab row shape: artifact rows plus the injection-screen flag.
/// Every row is third-party bytes: `tainted` is always true and `trust_level`
/// is always UNTRUSTED_EXTERNAL. Bytes are never executed.
fn file_view(id: Uuid, name: &str, mime: &str, size: i64, sha: &str, quarantined: bool, created_at: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    json!({"id": id, "name": name, "mime_type": mime, "size": size, "sha256": sha, "quarantined": quarantined, "tainted": true, "trust_level": "UNTRUSTED_EXTERNAL", "created_at": created_at})
}
/// Decode a byte slice for the injection screen only: lossy UTF-8, bounded.
fn screen_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).into_owned()
}
/// P4 Files tab list: owner artifacts newest-first. `node`/`kind` filters
/// narrow by stored metadata (upload source node / mime prefix); unknown
/// filter values match nothing rather than erroring.
#[utoipa::path(get, path = "/api/v1/files", responses((status = 200, body = Value)))]
pub async fn list_files_tab(State(state): State<ApiState>, headers: HeaderMap, Query(q): Query<FileListQuery>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let rows = sqlx::query("SELECT id,title AS name,mime_type,size,sha256,source_references,created_at FROM artifacts WHERE owner_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2").bind(a.scope.owner_id).bind(MAX_FILES_LIST).fetch_all(&state.pool).await?;
    let mut items = Vec::with_capacity(rows.len());
    for r in &rows {
        let mime: String = r.try_get::<String, _>("mime_type").unwrap_or_default();
        let source: Value = r.try_get::<Value, _>("source_references").unwrap_or(json!([]));
        if let Some(node) = q.node.as_deref() {
            if !node.is_empty() && source.to_string().find(node).is_none() {
                continue;
            }
        }
        if let Some(kind) = q.kind.as_deref() {
            if !kind.is_empty() && !mime.starts_with(kind) {
                continue;
            }
        }
        let quarantined = source.get("quarantined").and_then(Value::as_bool).unwrap_or_else(|| source.as_array().is_some_and(|refs| refs.iter().any(|v| v.get("quarantined").and_then(Value::as_bool).unwrap_or(false))));
        items.push(file_view(r.try_get::<Uuid, _>("id")?, &r.try_get::<String, _>("name").unwrap_or_default(), &mime, r.try_get::<i64, _>("size").unwrap_or(0), &r.try_get::<String, _>("sha256").unwrap_or_default(), quarantined, r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok()));
    }
    Ok(Json(json!({"items": items})))
}
/// P4 Files tab get: metadata for one owner artifact.
#[utoipa::path(get, path = "/api/v1/files/{id}", responses((status = 200, body = Value)))]
pub async fn get_file_tab(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = sqlx::query("SELECT id,title AS name,mime_type,size,sha256,source_references,created_at FROM artifacts WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;
    let source: Value = row.try_get::<Value, _>("source_references").unwrap_or(json!([]));
    let quarantined = source.get("quarantined").and_then(Value::as_bool).unwrap_or_else(|| source.as_array().is_some_and(|refs| refs.iter().any(|v| v.get("quarantined").and_then(Value::as_bool).unwrap_or(false))));
    Ok(Json(file_view(row.try_get::<Uuid, _>("id")?, &row.try_get::<String, _>("name").unwrap_or_default(), &row.try_get::<String, _>("mime_type").unwrap_or_default(), row.try_get::<i64, _>("size").unwrap_or(0), &row.try_get::<String, _>("sha256").unwrap_or_default(), quarantined, row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok())))
}
/// P4 Files tab import: multipart (`file` field, optional `filename`) or a
/// raw body with `?filename=`. Stores via `attachments::upload` (sealed
/// bytes under `artifact_dir`, 10 MiB cap), screened by
/// `ContextBlock::looks_like_injection` into the `quarantined` flag.
/// With `?kind=image` only PNG/JPEG/WebP/GIF at 5 MiB or less are accepted;
/// the sniffed image MIME is stored so the Files tab can filter on it.
/// Every stored row is third-party bytes: `tainted` is always true, trust is
/// always UNTRUSTED_EXTERNAL, and the bytes are never executed.
#[utoipa::path(post, path = "/api/v1/files/import", responses((status = 200, body = Value)))]
pub async fn import_file_tab(State(state): State<ApiState>, headers: HeaderMap, Query(q): Query<ImportQuery>, req: axum::http::Request<Body>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let (name, bytes) = read_import_body(req, q.filename.as_deref()).await?;
    let image_mime = if q.kind.as_deref().unwrap_or("").eq_ignore_ascii_case("image") {
        Some(check_image(&name, &bytes)?)
    } else {
        None
    };
    store_import(&state, &a.scope, &name, &bytes, image_mime.as_deref()).await.map(|v| Json(v))
}
/// Image gate for `?kind=image`: sniffed magic (never the claimed name or
/// content type) must be PNG/JPEG/GIF/WebP and the bytes must fit 5 MiB.
/// Returns the sniffed MIME for storage. Anything else is rejected.
fn check_image(name: &str, bytes: &[u8]) -> Result<String, ApiError> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(Error::Validation("image exceeds 5 MiB".into()).into());
    }
    let mut sniffed = orbit_email::sniff_mime(name, bytes);
    if sniffed == "application/octet-stream" && is_webp(bytes) {
        sniffed = "image/webp".to_string();
    }
    match sniffed.as_str() {
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" => Ok(sniffed),
        _ => Err(Error::Validation("kind=image accepts only PNG, JPEG, WebP or GIF images".into()).into()),
    }
}
/// RIFF....WEBP magic, which the shared MIME sniffer does not cover.
fn is_webp(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP"
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileListQuery { pub node: Option<String>, pub kind: Option<String> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportQuery { pub filename: Option<String>, pub content_type: Option<String>, pub kind: Option<String> }
/// Read the import payload: multipart `file` part wins when the content type
/// is multipart, otherwise the whole body with `?filename=` naming it.
async fn read_import_body(req: axum::http::Request<Body>, fallback_name: Option<&str>) -> Result<(String, Vec<u8>), ApiError> {
    let content_type = req.headers().get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    if content_type.starts_with("multipart/") {
        let boundary = multer::parse_boundary(&content_type).map_err(|_| Error::Validation("multipart boundary missing".to_string()))?;
        let body = axum::body::to_bytes(req.into_body(), MAX_FILE_BYTES + 1).await.map_err(|_| Error::Validation("upload body unreadable".to_string()))?;
        if body.len() > MAX_FILE_BYTES {
            return Err(Error::Validation("file exceeds 10 MiB".into()).into());
        }
        let mut multipart = multer::Multipart::new(futures_util::stream::once(async move { Ok::<_, std::io::Error>(axum::body::Bytes::from(body)) }), boundary);
        while let Some(field) = multipart.next_field().await.map_err(|_| Error::Validation("multipart field unreadable".to_string()))? {
            let field_name = field.name().unwrap_or("").to_owned();
            let file_name = field.file_name().map(str::to_owned);
            let data = field.bytes().await.map_err(|_| Error::Validation("multipart field unreadable".to_string()))?;
            if field_name == "file" || file_name.is_some() {
                let name = file_name.or_else(|| fallback_name.map(str::to_owned)).unwrap_or_else(|| "upload.bin".into());
                return Ok((name, data.to_vec()));
            }
        }
        return Err(Error::Validation("multipart import needs a file field".into()).into());
    }
    let body = axum::body::to_bytes(req.into_body(), MAX_FILE_BYTES + 1).await.map_err(|_| Error::Validation("upload body unreadable".to_string()))?;
    if body.len() > MAX_FILE_BYTES {
        return Err(Error::Validation("file exceeds 10 MiB".into()).into());
    }
    let name = fallback_name.unwrap_or("upload.bin").to_owned();
    Ok((name, body.to_vec()))
}
/// Screen + seal one import: quarantine-store guard, injection screen into
/// the quarantined flag, sealed artifact write with the flag in metadata.
/// `image_mime` carries the sniffed image MIME from the `?kind=image` gate so
/// it is stored (never the claimed content type); otherwise the sniffed MIME
/// from quarantine-store is kept. Response always carries `tainted: true`.
async fn store_import(state: &ApiState, scope: &orbit_core::OwnerScope, name: &str, bytes: &[u8], image_mime: Option<&str>) -> Result<Value, ApiError> {
    if bytes.is_empty() {
        return Err(Error::Validation("import is empty".into()).into());
    }
    let quarantined_blob = orbit_email::quarantine_store(name, "application/octet-stream", bytes)?;
    let quarantined = orbit_core::ContextBlock::looks_like_injection(&screen_text(bytes));
    let mime = image_mime.unwrap_or(&quarantined_blob.mime);
    let stored = orbit_agent_runtime::attachments::upload(&state.pool, &state.artifact_dir, scope, &quarantined_blob.name, mime, bytes).await?;
    let id: Uuid = serde_json::from_value::<Uuid>(stored["id"].clone()).map_err(|_| Error::Unavailable("upload identity unavailable".to_string()))?;
    if quarantined {
        let marker = json!([{"kind": "OWNER_UPLOAD", "attachment_id": id, "quarantined": true}]);
        sqlx::query("UPDATE artifacts SET source_references=$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).bind(&marker).execute(&state.pool).await?;
        sqlx::query("UPDATE chat_attachments SET source_reference=$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).bind(&marker).execute(&state.pool).await?;
    }
    Ok(json!({"id": id, "name": stored["name"], "mime_type": stored["mime_type"], "size": stored["size"], "sha256": stored["sha256"], "quarantined": quarantined, "tainted": true, "trust_level": "UNTRUSTED_EXTERNAL"}))
}
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
    let bytes = axum::body::to_bytes(body, MAX_FILE_BYTES + 1).await.map_err(|e| if e.to_string().contains("length limit exceeded") { Error::Validation("document exceeds 10 MB".into()) } else { Error::Validation("upload body unreadable".into()) })?;
    if bytes.len() > MAX_FILE_BYTES { return Err(Error::Validation("document exceeds 10 MB".into()).into()); }
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
/// P4 image bytes: owner-scoped immutable render of a stored image artifact.
/// Only image/* rows are served, sniffed again at read time; the bytes are
/// third-party content rendered with an untrusted badge in the UI and are
/// never executed. Served inline with no-store so browsers render the image.
#[utoipa::path(get, path = "/api/v1/files/{id}/content", responses((status = 200)))]
pub async fn get_file_content(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Response, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row = sqlx::query("SELECT mime_type FROM artifacts WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?.ok_or(Error::NotFound)?;
    let stored_mime: String = row.try_get::<String, _>("mime_type").unwrap_or_default();
    if !stored_mime.starts_with("image/") {
        return Err(Error::Validation("only stored images can be rendered".into()).into());
    }
    let (_name, bytes, _source) = orbit_agent_runtime::attachments::read(&state.pool, &state.artifact_dir, &a.scope, id).await?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(Error::Validation("image exceeds 5 MiB".into()).into());
    }
    let sniffed = orbit_email::sniff_mime("", &bytes);
    let sniffed = if sniffed == "application/octet-stream" && is_webp(&bytes) { "image/webp".to_string() } else { sniffed };
    if !matches!(sniffed.as_str(), "image/png" | "image/jpeg" | "image/gif" | "image/webp") {
        return Err(Error::Validation("stored bytes are not a supported image".into()).into());
    }
    let mut head = axum::http::HeaderMap::new();
    head.insert(axum::http::header::CONTENT_TYPE, sniffed.parse().unwrap());
    head.insert(axum::http::header::CONTENT_DISPOSITION, "inline".parse().unwrap());
    head.insert(axum::http::header::CACHE_CONTROL, "private, no-store".parse().unwrap());
    head.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    Ok((head, axum::body::Body::from(bytes)).into_response())
}
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/uploads", post(upload_doc).get(list_uploads))
        .route("/api/v1/uploads/{id}", get(download_upload))
        .route("/api/v1/files", get(list_files_tab))
        .route("/api/v1/files/import", post(import_file_tab))
        .route("/api/v1/files/{id}", get(get_file_tab))
        .route("/api/v1/files/{id}/content", get(get_file_content))
}
