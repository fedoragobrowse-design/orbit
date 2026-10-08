use orbit_core::{ActionSnapshot,Error,Result};
use sha2::{Digest,Sha256};
use serde_json::Value;

/// RFC 8785 canonicalization (UTF-16 property ordering, ECMAScript number
/// serialization) must not be replaced by merely sorting serde_json maps.
pub fn canonical_hash<T:serde::Serialize>(value:&T)->Result<String>{
 let bytes=serde_jcs::to_vec(value).map_err(|_|Error::Validation("action is not RFC8785 canonicalizable".into()))?;
 Ok(hex::encode(Sha256::digest(bytes)))
}
pub fn verify_snapshot(snapshot:&ActionSnapshot,expected:&str)->Result<()>{
 if expected.len()!=64||canonical_hash(snapshot)?!=expected{return Err(Error::Conflict("immutable action digest changed".into()));}Ok(())
}
pub fn preview(snapshot:&ActionSnapshot)->Value{
 serde_json::json!({"tool_name":snapshot.tool_name,"tool_version":snapshot.tool_version,"arguments":snapshot.arguments,"input_artifact_digests":snapshot.input_artifact_digests,"scope_revisions":snapshot.scope_revisions,"requires_sandbox":snapshot.requires_sandbox,"expires_at":snapshot.expires_at})
}
#[cfg(test)]mod tests{
 use super::*;use serde_json::json;
 #[test]fn canonical_order_is_not_insertion_order(){assert_eq!(canonical_hash(&json!({"b":2,"a":1})).unwrap(),canonical_hash(&json!({"a":1,"b":2})).unwrap());assert_ne!(canonical_hash(&json!({"body":"first"})).unwrap(),canonical_hash(&json!({"body":"second"})).unwrap());}
 #[test]fn known_sha_of_canonical_empty_object(){assert_eq!(canonical_hash(&json!({})).unwrap(),"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");}
}
