use orbit_core::{Error,OwnerScope,Result};
use sqlx::{PgPool,Row};
use sha2::{Digest,Sha256};
use serde_json::{Value,json};
use std::path::{Path,PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub const MAX_ATTACHMENT_BYTES:usize=10*1024*1024;
fn storage_path(root:&Path,key:&str)->Result<PathBuf>{
 let parts:Vec<_>=key.split('/').collect();
 if parts.len()!=2||parts.iter().any(|s|Uuid::parse_str(s).is_err()){return Err(Error::Validation("invalid private artifact storage reference".into()))}
 Ok(root.join(parts[0]).join(parts[1]))
}
pub async fn upload(pool:&PgPool,root:&Path,scope:&OwnerScope,name:&str,mime:&str,bytes:&[u8])->Result<Value>{
 if bytes.len()>MAX_ATTACHMENT_BYTES{return Err(Error::Validation("attachment exceeds 10 MiB".into()))}
 let name=crate::safe_filename(name);let id=Uuid::new_v4();let key=format!("{}/{id}",scope.owner_id);let digest=hex::encode(Sha256::digest(bytes));let path=storage_path(root,&key)?;
 let mime=if mime.len()<=120&&mime.bytes().all(|c|c.is_ascii_graphic()) {mime}else{"application/octet-stream"};
 tokio::fs::create_dir_all(path.parent().expect("artifact parent")).await.map_err(|_|Error::Unavailable("artifact storage unavailable".into()))?;
 #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;tokio::fs::set_permissions(path.parent().expect("artifact parent"),std::fs::Permissions::from_mode(0o700)).await.map_err(|_|Error::Unavailable("private artifact directory unavailable".into()))?;}
 let mut options=tokio::fs::OpenOptions::new();options.write(true).create_new(true);
 #[cfg(unix)] options.mode(0o600);
 let mut file=options.open(&path).await.map_err(|_|Error::Unavailable("private attachment creation failed".into()))?;
 file.write_all(bytes).await.map_err(|_|Error::Unavailable("attachment write failed".into()))?;file.sync_all().await.map_err(|_|Error::Unavailable("attachment persistence failed".into()))?;drop(file);
 let mut tx=pool.begin().await?;
 sqlx::query("INSERT INTO artifacts(id,owner_id,title,safe_name,mime_type,size,sha256,privacy_class,trust_level,source_references,storage_key) VALUES($1,$2,$3,$3,$4,$5,$6,'PRIVATE','UNTRUSTED_EXTERNAL',$7,$8)").bind(id).bind(scope.owner_id).bind(&name).bind(mime).bind(bytes.len() as i64).bind(&digest).bind(json!([{"kind":"OWNER_UPLOAD","attachment_id":id}])).bind(&key).execute(&mut *tx).await?;
 sqlx::query("INSERT INTO chat_attachments(id,owner_id,name,mime_type,size,sha256,storage_key,source_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8)").bind(id).bind(scope.owner_id).bind(&name).bind(mime).bind(bytes.len() as i64).bind(&digest).bind(&key).bind(json!([{"kind":"OWNER_UPLOAD","attachment_id":id}])).execute(&mut *tx).await?;tx.commit().await?;
 Ok(json!({"id":id,"name":name,"mime_type":mime,"size":bytes.len(),"sha256":digest,"privacy_class":"PRIVATE"}))
}
pub async fn read(pool:&PgPool,root:&Path,scope:&OwnerScope,id:Uuid)->Result<(String,Vec<u8>,Value)> {
 let r=sqlx::query("SELECT safe_name,size,sha256,storage_key,privacy_class,source_references FROM artifacts WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).fetch_optional(pool).await?.ok_or(Error::NotFound)?;
 if r.get::<String,_>("privacy_class")=="SECRET"{return Err(Error::Forbidden)}
 let source:Value=r.get("source_references");validate_file_sources(pool,scope,&source).await?;
 let size:i64=r.get("size");if size<0||size>MAX_ATTACHMENT_BYTES as i64{return Err(Error::Validation("artifact exceeds attachment bound".into()))}
 let path=storage_path(root,&r.get::<String,_>("storage_key"))?;
 let file=tokio::fs::File::open(path).await.map_err(|_|Error::Unavailable("attachment storage unavailable".into()))?;
 use tokio::io::AsyncReadExt;let mut bytes=Vec::with_capacity(size as usize);file.take(MAX_ATTACHMENT_BYTES as u64+1).read_to_end(&mut bytes).await.map_err(|_|Error::Unavailable("attachment read failed".into()))?;
 if bytes.len()!=size as usize||hex::encode(Sha256::digest(&bytes))!=r.get::<String,_>("sha256"){return Err(Error::Conflict("immutable attachment digest mismatch".into()))}
 Ok((crate::safe_filename(&r.get::<String,_>("safe_name")),bytes,source))
}
pub async fn validate_file_sources(pool:&PgPool,scope:&OwnerScope,source:&Value)->Result<()> {
 let references=source.as_array().cloned().unwrap_or_else(||vec![source.clone()]);
 for reference in references {
  if let (Some(node),Some(root))=(reference.get("node_id").and_then(Value::as_str),reference.get("root_id").and_then(Value::as_str)) {
   let node=Uuid::parse_str(node).map_err(|_|Error::Forbidden)?;let root=Uuid::parse_str(root).map_err(|_|Error::Forbidden)?;
   let permitted:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM computer_roots r JOIN computer_nodes n ON n.owner_id=r.owner_id AND n.id=r.node_id WHERE r.owner_id=$1 AND r.node_id=$2 AND r.id=$3 AND NOT r.revoked AND n.revoked_at IS NULL AND r.mode IN ('READ','READ_WRITE','ASK'))").bind(scope.owner_id).bind(node).bind(root).fetch_one(pool).await?;
   if !permitted{return Err(Error::Forbidden)}
  }
 }Ok(())
}
