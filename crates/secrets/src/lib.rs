use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use orbit_core::{Error, OwnerScope, Result};
use rand::{rngs::OsRng, RngCore};
use sqlx::{PgPool, Row};
use std::{fs::{self, OpenOptions}, io::{Read, Write}, path::Path};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub type SecretId = Uuid;
/// Deliberately has no Debug or Serialize implementation.
impl Clone for SecretStore {fn clone(&self)->Self{Self{pool:self.pool.clone(),key:self.key.clone()}}}
pub struct SecretStore { pool: PgPool, key: std::sync::Arc<Zeroizing<Vec<u8>>> }
impl SecretStore {
    pub async fn open(pool: PgPool, directory: &Path) -> Result<Self> {
        let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets_metadata").fetch_one(&pool).await?;
        let path = directory.join("master-v1.key");
        if !directory.exists() { fs::create_dir_all(directory).map_err(|_| Error::Unavailable("secret key directory unavailable".into()))?; }
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            if fs::symlink_metadata(directory).map_err(key_error)?.file_type().is_symlink() { return Err(key_error(())); }
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(key_error)?;
        }
        if !path.exists() {
            if existing != 0 { return Err(Error::Unavailable("master key missing; restore the original external key".into())); }
            let mut key = Zeroizing::new(vec![0;32]); OsRng.fill_bytes(&mut key);
            let mut options = OpenOptions::new(); options.write(true).create_new(true);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            match options.open(&path) {
                Ok(mut file) => { file.write_all(&key).map_err(key_error)?; file.sync_all().map_err(key_error)?; fs::File::open(directory).and_then(|f| f.sync_all()).map_err(key_error)?; },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(key_error(e)),
            }
        }
        let metadata = fs::symlink_metadata(&path).map_err(key_error)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() { return Err(key_error(())); }
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; if metadata.permissions().mode() & 0o077 != 0 { return Err(Error::Unavailable("master key permissions must be owner-only".into())); } }
        let mut key = Zeroizing::new(Vec::new()); fs::File::open(&path).and_then(|f| f.take(33).read_to_end(&mut key)).map_err(key_error)?;
        if key.len()!=32 { return Err(key_error(())); }
        let store = Self { pool, key: std::sync::Arc::new(key) };
        // Verify existing ciphertext before allowing any new write under this key.
        if let Some(row) = sqlx::query("SELECT owner_id,id,key_version,purpose,nonce,ciphertext FROM secrets_metadata LIMIT 1").fetch_optional(&store.pool).await? { store.decrypt_row(&row)?; }
        Ok(store)
    }
    pub async fn put(&self, scope:&OwnerScope, purpose:&str, plaintext:&[u8]) -> Result<SecretId> {
        if plaintext.is_empty() || plaintext.len()>65536 || purpose.len()>128 { return Err(Error::Validation("invalid secret size or purpose".into())); }
        let id=Uuid::new_v4(); let version=1i32; let mut nonce=[0u8;24]; OsRng.fill_bytes(&mut nonce);
        let aad=aad(scope.owner_id,id,version,purpose);
        let ciphertext=XChaCha20Poly1305::new_from_slice(&self.key).map_err(key_error)?.encrypt(XNonce::from_slice(&nonce),Payload { msg:plaintext,aad:&aad }).map_err(key_error)?;
        sqlx::query("INSERT INTO secrets_metadata(id,owner_id,key_version,purpose,nonce,ciphertext) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(scope.owner_id).bind(version).bind(purpose).bind(nonce.as_slice()).bind(ciphertext).execute(&self.pool).await?;
        Ok(id)
    }
    pub async fn get(&self,scope:&OwnerScope,id:SecretId)->Result<Zeroizing<Vec<u8>>> {
        let row=sqlx::query("SELECT owner_id,id,key_version,purpose,nonce,ciphertext FROM secrets_metadata WHERE owner_id=$1 AND id=$2 AND revoked_at IS NULL").bind(scope.owner_id).bind(id).fetch_optional(&self.pool).await?.ok_or(Error::NotFound)?;
        self.decrypt_row(&row)
    }
    pub async fn revoke(&self,scope:&OwnerScope,id:SecretId)->Result<()> {
        sqlx::query("UPDATE secrets_metadata SET revoked_at=now(),ciphertext=''::bytea WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).execute(&self.pool).await?; Ok(())
    }
    fn decrypt_row(&self,row:&sqlx::postgres::PgRow)->Result<Zeroizing<Vec<u8>>> {
        let owner:Uuid=row.try_get("owner_id")?; let id:Uuid=row.try_get("id")?; let version:i32=row.try_get("key_version")?; let purpose:String=row.try_get("purpose")?; let nonce:Vec<u8>=row.try_get("nonce")?; let mut ciphertext:Vec<u8>=row.try_get("ciphertext")?;
        if nonce.len()!=24 || version!=1 { return Err(key_error(())); }
        let result=XChaCha20Poly1305::new_from_slice(&self.key).map_err(key_error)?.decrypt(XNonce::from_slice(&nonce),Payload {msg:&ciphertext,aad:&aad(owner,id,version,&purpose)}).map(Zeroizing::new).map_err(|_| Error::Unavailable("secret authentication failed; restore the matching external key".into())); ciphertext.zeroize(); result
    }
}
fn key_error<T>(_:T)->Error { Error::Unavailable("external master key unavailable or invalid".into()) }
fn aad(owner:Uuid,id:Uuid,version:i32,purpose:&str)->Vec<u8> { let mut out=b"orbit-secret-v1\0".to_vec(); out.extend_from_slice(owner.as_bytes()); out.extend_from_slice(id.as_bytes()); out.extend_from_slice(&version.to_be_bytes()); out.extend_from_slice(&(purpose.len() as u32).to_be_bytes()); out.extend_from_slice(purpose.as_bytes()); out }

#[cfg(test)] mod tests {
 use super::*;
 #[test] fn aad_binds_owner_id_version_and_metadata() { let a=Uuid::new_v4(); let b=Uuid::new_v4(); let key=[7u8;32]; let nonce=[3u8;24]; let cipher=XChaCha20Poly1305::new_from_slice(&key).unwrap(); let encrypted=cipher.encrypt(XNonce::from_slice(&nonce),Payload{msg:b"canary",aad:&aad(a,b,1,"model")}).unwrap(); for binding in [aad(b,b,1,"model"),aad(a,a,1,"model"),aad(a,b,2,"model"),aad(a,b,1,"email")] { assert!(cipher.decrypt(XNonce::from_slice(&nonce),Payload{msg:&encrypted,aad:&binding}).is_err()); } }
}
