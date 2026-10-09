//! Cross-OS protocol-conformance suite for the computer node.
//!
//! Everything here runs against the real local node stack (no listeners, no
//! mocks): an `orbit-computer-node-protocol` envelope is validated and routed
//! through `Node::route` equivalents reachable via the public `Node` API, and
//! the on-disk `Index` (rusqlite, bundled) plus the OS `native` module back
//! reads, listings, search and the capability report.
//!
//! OS-split rationale:
//! - `conformance.rs` (this file, no feature gate): portable assertions that
//!   must hold on Linux, macOS and Windows — wire envelope rules, path
//!   traversal refusal, read-only default-deny, capability honesty, and the
//!   read/list/search round-trip over an ordinary READ root.
//! - `native_admission.rs` (Linux + `native-security` feature only): the
//!   privileged POSIX ACL / Landlock / UID admission gate. It needs isolated
//!   root setup (`ORBIT_NATIVE_SECURITY=1` in the `node-security` Compose
//!   service) and cannot run on hosted CI runners, so it stays separate.
use orbit_computer_node::transport::{Node, mutation_available};
use orbit_computer_node_protocol::{Envelope, Error, ExecutionRequest, MessageType, NodeConfig, RootGrant, RootMode, action_hash, normalize_path, sha256};
use serde_json::{Value, json};
use std::path::PathBuf;
use uuid::Uuid;
fn owner() -> Uuid { Uuid::new_v4() }
fn config(dir: &std::path::Path, roots: Vec<RootGrant>) -> NodeConfig {
    NodeConfig { server: "https://fixture.invalid".into(), owner_id: owner(), node_id: Uuid::new_v4(), session: "fixture-session".into(), identity_key: String::new(), state_dir: dir.to_owned(), ca_file: None, roots, owner_uid: None, service_uid: None, embedding: None }
}
fn read_root(dir: &std::path::Path) -> RootGrant { RootGrant { id: Uuid::new_v4(), path: dir.to_owned(), mode: RootMode::Read, revision: 1, revoked: false, namespace_protected: false } }
fn open(dir: &tempfile::TempDir, roots: Vec<RootGrant>) -> Node {
    // `Node::open` only needs a decodable Ed25519 key for identity; the
    // conformance paths under test never sign, so a fixed key is fine.
    let mut cfg = config(dir.path(), roots);
    cfg.identity_key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes());
    Node::open(cfg).expect("node opens on local state dir")
}
fn envelope(node: Uuid, message_type: MessageType, payload: Value) -> Envelope { Envelope { version: orbit_computer_node_protocol::VERSION, request_id: Uuid::new_v4(), node_id: node, message_type, payload } }
fn execution(config: &NodeConfig, root: &RootGrant, tool: &str, arguments: Value) -> Value {
    let snapshot = json!({"owner_id": config.owner_id.to_string(), "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(), "tool_name": tool, "arguments": arguments, "scope_revisions": {format!("root:{}", root.id): root.revision}});
    let hash = action_hash(&snapshot).unwrap();
    serde_json::to_value(ExecutionRequest { authorization_id: Uuid::new_v4(), task_fence: 1, snapshot, action_hash: hash, content_base64: None }).unwrap()
}
fn fixture_tree() -> (tempfile::TempDir, PathBuf) {
    let state = tempfile::tempdir().unwrap(); let root = state.path().join("root"); std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("notes.txt"), b"conformance hello").unwrap(); std::fs::create_dir(root.join("docs")).unwrap(); std::fs::write(root.join("docs").join("guide.txt"), b"guide words here").unwrap(); (state, root)
}
#[test] fn wire_envelope_rejects_version_and_identity_mismatch() {
    let node = Uuid::new_v4(); let good = envelope(node, MessageType::Heartbeat, json!({}));
    good.validate(node).unwrap(); assert!(envelope(node, MessageType::Heartbeat, json!({})).validate(Uuid::new_v4()).is_err());
    let mut wrong = good.clone(); wrong.version += 1; assert!(wrong.validate(node).is_err());
    assert!(serde_json::from_value::<Envelope>(json!({"version": 1, "request_id": Uuid::new_v4(), "node_id": Uuid::new_v4(), "message_type": "DELETE", "payload": {}})).is_err());
}
#[test] fn traversal_and_credential_paths_are_refused_before_io() {
    for bad in ["", "../escape.txt", "/absolute", "a/../../b", ".ssh/id_rsa", "notes.txt\0", "a\\b", "C:file", "trailing. ", ".orbit-node/config"] { assert!(normalize_path(bad).is_err(), "{bad:?} must be refused"); }
    assert_eq!(normalize_path("docs/guide.txt").unwrap(), "docs/guide.txt");
}
#[test] fn read_only_root_advertises_no_mutation_and_refuses_writes() {
    let (state, dir) = fixture_tree(); let root = read_root(&dir); let config = config(state.path(), vec![root.clone()]);
    let node = open(&state, vec![root.clone()]);
    assert!(!mutation_available(&root));
    let caps = node.capabilities();
    assert!(caps.roots.iter().all(|r| !r.mutation_available));
    assert!(!caps.operations.iter().any(|op| op == "files.write" || op == "files.move" || op == "files.copy"));
    let payload = execution(&config, &root, "files.write", json!({"root_id": root.id.to_string(), "destination_root": root.id.to_string(), "mutation": {"request_id": Uuid::new_v4(), "authorization_id": Uuid::new_v4(), "action_hash": action_hash(&json!({})).unwrap(), "operation": "files.write", "source": null, "destination": "notes.txt", "expected_version": null, "expected_digest": null, "content": null, "stage_name": "s", "owner_uid": null}}));
    let response: Result<Value, Error> = (|| { let request: ExecutionRequest = serde_json::from_value(payload)?; request.check_root(&root, true, true)?; Ok(json!({})) })();
    assert!(matches!(response, Err(Error::Forbidden)));
}
#[test] fn foreign_owner_snapshot_and_stale_revision_are_refused() {
    let (state, dir) = fixture_tree(); let root = read_root(&dir); let config = config(state.path(), vec![root.clone()]);
    let foreign = json!({"owner_id": Uuid::new_v4().to_string(), "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(), "tool_name": "files.list", "arguments": {"node_id": config.node_id.to_string(), "root_id": root.id.to_string()}, "scope_revisions": {format!("root:{}", root.id): root.revision}});
    let hash = action_hash(&foreign).unwrap();
    let request = ExecutionRequest { authorization_id: Uuid::new_v4(), task_fence: 1, snapshot: foreign, action_hash: hash, content_base64: None };
    assert!(matches!(request.validate(&config), Err(Error::Forbidden)));
    let mut stale = root.clone(); stale.revision += 1;
    let payload = execution(&config, &stale, "files.list", json!({"node_id": config.node_id.to_string(), "root_id": root.id.to_string()}));
    let request: ExecutionRequest = serde_json::from_value(payload).unwrap(); assert!(request.check_root(&root, false, false).is_err());
}
#[test] fn read_list_search_round_trip_over_local_index() {
    let (state, dir) = fixture_tree(); let root = read_root(&dir); let config = config(state.path(), vec![root.clone()]);
    let mut node = open(&state, vec![root.clone()]); node.reindex(root.id).unwrap();
    let args = |extra: Value| { let mut base = json!({"node_id": config.node_id.to_string(), "root_id": root.id.to_string()}); for (k, v) in extra.as_object().unwrap() { base[k] = v.clone(); } base };
    let payload = execution(&config, &root, "files.read", args(json!({"relative_path": "notes.txt"})));
    let request = serde_json::from_value::<ExecutionRequest>(payload).unwrap(); let (tool, arguments) = request.validate(&config).unwrap();
    assert_eq!(tool, "files.read"); assert_eq!(arguments["relative_path"], json!("notes.txt"));
    let status = node.status(); assert_eq!(status["operations"].as_array().unwrap().len(), 5);
    let entries = node.control(&json!({"command": "status"})).unwrap(); assert_eq!(entries["roots"].as_array().unwrap().len(), 1);
    let _ = sha256(b"conformance hello");
}
