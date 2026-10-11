//! Owner-scoped notes: single-author text rows plus bulk JSON import.
//! Notes are owner-authored, so they carry no taint; untrusted external
//! content arrives through the inbox/connectors instead.
use crate::{ApiError, ApiState, authenticate};
use axum::{Json, Router, extract::{Path, Query, State}, http::HeaderMap, routing::{get, post}};
use orbit_core::Error;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
const MAX_TITLE: usize = 256;
const MAX_BODY: usize = 100_000;
const MAX_IMPORT_ROWS: usize = 200;
fn check_note(title: &str, body: &str) -> Result<(), Error> {
    if title.len() > MAX_TITLE {
        return Err(Error::Validation("note title too long (256 bytes max)".into()));
    }
    if body.len() > MAX_BODY {
        return Err(Error::Validation("note body too long (100KB max)".into()));
    }
    if title.chars().any(char::is_control) {
        return Err(Error::Validation("note title must not contain control characters".into()));
    }
    Ok(())
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteCreate { pub title: Option<String>, pub body: Option<String> }
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NotePatch { pub title: Option<String>, pub body: Option<String> }
#[derive(Deserialize)]
pub struct NotesQuery { pub limit: Option<i64> }
#[utoipa::path(get, path = "/api/v1/notes", responses((status = 200, body = Value)))]
pub async fn list_notes(State(state): State<ApiState>, headers: HeaderMap, Query(q): Query<NotesQuery>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM notes t WHERE owner_id=$1 ORDER BY updated_at DESC,id DESC LIMIT $2").bind(a.scope.owner_id).bind(limit).fetch_all(&state.pool).await?;
    Ok(Json(json!({"items": rows})))
}
#[utoipa::path(post, path = "/api/v1/notes", request_body = NoteCreate, responses((status = 200, body = Value)))]
pub async fn create_note(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<NoteCreate>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let title = input.title.unwrap_or_default();
    let body = input.body.unwrap_or_default();
    check_note(&title, &body)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO notes(id,owner_id,title,body) VALUES($1,$2,$3,$4)").bind(id).bind(a.scope.owner_id).bind(&title).bind(&body).execute(&state.pool).await?;
    Ok(Json(json!({"id": id, "title": title, "body": body})))
}
#[utoipa::path(get, path = "/api/v1/notes/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn get_note(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, false).await?;
    let row: Option<Value> = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM notes t WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_optional(&state.pool).await?;
    Ok(Json(row.ok_or(Error::NotFound)?))
}
#[utoipa::path(patch, path = "/api/v1/notes/{id}", request_body = NotePatch, params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn patch_note(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>, Json(input): Json<NotePatch>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if input.title.is_none() && input.body.is_none() {
        return Err(Error::Validation("patch needs title and/or body".into()).into());
    }
    if let Some(title) = &input.title {
        check_note(title, "")?;
    }
    if let Some(body) = &input.body {
        check_note("", body)?;
    }
    let done = sqlx::query("UPDATE notes SET title=COALESCE($3,title),body=COALESCE($4,body),updated_at=now() WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).bind(input.title.as_deref()).bind(input.body.as_deref()).execute(&state.pool).await?.rows_affected();
    if done == 0 {
        return Err(Error::NotFound.into());
    }
    let row: Value = sqlx::query_scalar("SELECT to_jsonb(t)-'owner_id' FROM notes t WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).fetch_one(&state.pool).await?;
    Ok(Json(row))
}
#[utoipa::path(delete, path = "/api/v1/notes/{id}", params(("id" = Uuid, Path)), responses((status = 200, body = Value)))]
pub async fn delete_note(State(state): State<ApiState>, headers: HeaderMap, Path(id): Path<Uuid>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    let done = sqlx::query("DELETE FROM notes WHERE owner_id=$1 AND id=$2").bind(a.scope.owner_id).bind(id).execute(&state.pool).await?.rows_affected();
    if done == 0 {
        return Err(Error::NotFound.into());
    }
    Ok(Json(json!({"removed": id})))
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NoteImportRow { pub title: Option<String>, pub body: Option<String> }
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NotesImport { pub notes: Vec<NoteImportRow> }
#[utoipa::path(post, path = "/api/v1/notes/import", request_body = NotesImport, responses((status = 200, body = Value)))]
pub async fn import_notes(State(state): State<ApiState>, headers: HeaderMap, Json(input): Json<NotesImport>) -> Result<Json<Value>, ApiError> {
    let a = authenticate(&state, &headers, true).await?;
    if input.notes.len() > MAX_IMPORT_ROWS {
        return Err(Error::Validation("too many notes in one import (200 max)".into()).into());
    }
    let mut imported = 0i64;
    let mut errors = Vec::new();
    for (index, row) in input.notes.iter().enumerate() {
        let title = row.title.clone().unwrap_or_default();
        let body = row.body.clone().unwrap_or_default();
        if let Err(e) = check_note(&title, &body) {
            errors.push(json!({"index": index, "reason": e.to_string()}));
            continue;
        }
        sqlx::query("INSERT INTO notes(id,owner_id,title,body) VALUES($1,$2,$3,$4)").bind(Uuid::new_v4()).bind(a.scope.owner_id).bind(&title).bind(&body).execute(&state.pool).await?;
        imported += 1;
    }
    Ok(Json(json!({"imported": imported, "skipped": errors.len(), "errors": errors})))
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_notes, create_note, get_note, patch_note, delete_note, import_notes))]
pub struct NotesApi;
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/notes", get(list_notes).post(create_note))
        .route("/api/v1/notes/{id}", get(get_note).patch(patch_note).delete(delete_note))
        .route("/api/v1/notes/import", post(import_notes))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn note_bounds_reject_oversize_title_body_and_control_chars() {
        assert!(check_note("ok", "body").is_ok());
        assert!(check_note("", "").is_ok());
        assert!(check_note(&"t".repeat(257), "").is_err());
        assert!(check_note("", &"b".repeat(100_001)).is_err());
        assert!(check_note("bad\u{0}title", "").is_err());
    }
    #[test]
    fn import_rejects_unknown_fields() {
        assert!(serde_json::from_value::<NotesImport>(json!({"notes": [], "bogus": 1})).is_err());
        assert!(serde_json::from_value::<NotesImport>(json!({"notes": [{"title": "t", "bogus": 1}]})).is_err());
        let ok: NotesImport = serde_json::from_value(json!({"notes": [{"title": "t", "body": "b"}, {}]})).unwrap();
        assert_eq!(ok.notes.len(), 2);
    }
    #[test]
    fn create_and_patch_reject_unknown_fields() {
        assert!(serde_json::from_value::<NoteCreate>(json!({"title": "t", "bogus": 1})).is_err());
        assert!(serde_json::from_value::<NotePatch>(json!({"bogus": 1})).is_err());
    }
}
