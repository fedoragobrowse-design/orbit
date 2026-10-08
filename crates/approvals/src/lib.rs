use orbit_core::{ActionSnapshot, Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// RFC 8785 canonicalization (UTF-16 property ordering, ECMAScript number
/// serialization) must not be replaced by merely sorting serde_json maps.
pub fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<String> {
    let bytes = serde_jcs::to_vec(value)
        .map_err(|_| Error::Validation("action is not RFC8785 canonicalizable".into()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}
pub fn verify_snapshot(snapshot: &ActionSnapshot, expected: &str) -> Result<()> {
    if expected.len() != 64 || canonical_hash(snapshot)? != expected {
        return Err(Error::Conflict("immutable action digest changed".into()));
    }
    Ok(())
}
pub fn preview(snapshot: &ActionSnapshot) -> Value {
    serde_json::json!({"tool_name":snapshot.tool_name,"tool_version":snapshot.tool_version,"arguments":snapshot.arguments,"input_artifact_digests":snapshot.input_artifact_digests,"scope_revisions":snapshot.scope_revisions,"requires_sandbox":snapshot.requires_sandbox,"expires_at":snapshot.expires_at})
}
#[cfg(test)]
mod tests {
    use super::*;
    use orbit_core::ActionSnapshot;
    use serde_json::json;
    fn snapshot() -> ActionSnapshot {
        ActionSnapshot {
            action_id: uuid::Uuid::new_v4(),
            owner_id: uuid::Uuid::new_v4(),
            principal_id: uuid::Uuid::new_v4(),
            agent_id: None,
            task_id: uuid::Uuid::new_v4(),
            tool_name: "files.write".into(),
            tool_version: "1".into(),
            arguments: json!({"path":"a"}),
            input_artifact_digests: Default::default(),
            scope_revisions: Default::default(),
            policy_revision: 1,
            authorization_epoch: 1,
            requires_sandbox: true,
            expires_at: chrono::Utc::now(),
        }
    }
    #[test]
    fn canonical_order_is_not_insertion_order() {
        assert_eq!(
            canonical_hash(&json!({"b":2,"a":1})).unwrap(),
            canonical_hash(&json!({"a":1,"b":2})).unwrap()
        );
        assert_ne!(
            canonical_hash(&json!({"body":"first"})).unwrap(),
            canonical_hash(&json!({"body":"second"})).unwrap()
        );
    }
    #[test]
    fn known_sha_of_canonical_empty_object() {
        assert_eq!(
            canonical_hash(&json!({})).unwrap(),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
    #[test]
    fn snapshot_hash_is_stable_and_sensitive_to_arguments() {
        let s = snapshot();
        let hash = canonical_hash(&s).unwrap();
        assert_eq!(hash.len(), 64);
        assert_eq!(canonical_hash(&s).unwrap(), hash);
        let mut changed = s.clone();
        changed.arguments = json!({"path":"b"});
        assert_ne!(canonical_hash(&changed).unwrap(), hash);
    }
    #[test]
    fn snapshot_mismatch_is_a_conflict() {
        let s = snapshot();
        let hash = canonical_hash(&s).unwrap();
        assert!(verify_snapshot(&s, &hash).is_ok());
        assert!(
            verify_snapshot(
                &s,
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
        let mut tampered = s.clone();
        tampered.requires_sandbox = false;
        assert!(verify_snapshot(&tampered, &hash).is_err());
    }
    #[test]
    fn sandbox_flag_is_part_of_consent() {
        let s = snapshot();
        assert!(preview(&s)["requires_sandbox"].as_bool().unwrap());
    }
}
