//! Opt-in desktop observation: local CLI/control round-trips and the
//! versioned wire capability. Enable is local-only; the server directive
//! path (narrow/pause/revoke, never enable) is covered by transport unit
//! tests. Tests touching the observer facade serialize on one lock: the
//! facade is process-global and one test fakes the portal environment.
use orbit_computer_node::observation;
use orbit_computer_node::transport::Node;
use orbit_computer_node_protocol::{
    DesktopObservationState, Envelope, Error, MessageType, NodeConfig, VERSION,
};
use serde_json::json;
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    // A failed assertion must not wedge the remaining tests: recover the
    // guard from a poisoned mutex instead of panicking on the lock.
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn open_node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().expect("observe test state dir");
    let config = NodeConfig {
        server: "https://fixture.invalid".into(),
        owner_id: Uuid::new_v4(),
        node_id: Uuid::new_v4(),
        session: "fixture-session".into(),
        identity_key: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        ),
        state_dir: dir.path().to_owned(),
        ca_file: None,
        roots: Vec::new(),
        owner_uid: None,
        service_uid: None,
        embedding: None,
    };
    let node = Node::open(config).expect("node opens on local state dir");
    (dir, node)
}

/// Fake just enough environment for the portal probe: a session bus socket
/// plus the portal service file. Restores both variables on drop.
struct FakePortal {
    prior_runtime: Option<String>,
    prior_data: Option<String>,
    _runtime: tempfile::TempDir,
    _data: tempfile::TempDir,
}

fn fake_portal() -> FakePortal {
    let runtime = tempfile::tempdir().expect("fake runtime dir");
    std::fs::write(runtime.path().join("bus"), b"").expect("fake bus socket");
    let data = tempfile::tempdir().expect("fake data dirs");
    let services = data.path().join("dbus-1/services");
    std::fs::create_dir_all(&services).expect("fake services dir");
    std::fs::write(
        services.join("org.freedesktop.portal.Desktop.service"),
        b"[D-BUS Service]\nName=org.freedesktop.portal.Desktop\n",
    )
    .expect("fake portal service");
    let prior_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
    let prior_data = std::env::var("XDG_DATA_DIRS").ok();
    // `std::env::set_var` is `unsafe` on this toolchain (multithreaded
    // process env access); tests serialize on `SERIAL` so this is sound.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("XDG_DATA_DIRS", data.path());
    }
    FakePortal { prior_runtime, prior_data, _runtime: runtime, _data: data }
}

impl Drop for FakePortal {
    fn drop(&mut self) {
        unsafe {
            match self.prior_runtime.take() {
                Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
            match self.prior_data.take() {
                Some(value) => std::env::set_var("XDG_DATA_DIRS", value),
                None => std::env::remove_var("XDG_DATA_DIRS"),
            }
        }
    }
}

#[test]
fn observe_local_start_pause_stop_round_trip() {
    let _guard = serial();
    let _portal = fake_portal();
    assert!(observation::desktop_supported(), "faked portal must read as supported");
    let (_dir, mut node) = open_node();

    // Local start enables and reports RUNNING.
    let started = node
        .control(&json!({"command": "observe_start", "window": "test-window"}))
        .expect("local observe start");
    assert_eq!(started["window_id"], json!("test-window"));
    assert_eq!(started["status"]["state"], json!("RUNNING"));
    assert_eq!(started["status"]["active"], json!(true));
    assert_eq!(started["status"]["supported"], json!(true));

    // The wire capability agrees with the control surface.
    let capabilities = node.capabilities();
    assert!(capabilities.desktop_observation.supported);
    assert_eq!(capabilities.desktop_observation.state, DesktopObservationState::Running);

    // Pause halts pixels immediately but keeps the session.
    let paused = node.control(&json!({"command": "observe_pause"})).expect("local observe pause");
    assert_eq!(paused["state"], json!("PAUSED"));
    assert_eq!(paused["active"], json!(false));

    // An explicit local start clears the pause and resumes.
    let resumed = node.control(&json!({"command": "observe_start"})).expect("local observe restart");
    assert_eq!(resumed["status"]["state"], json!("RUNNING"));

    // Stop drops the session; status returns to OFF.
    let stopped = node.control(&json!({"command": "observe_stop"})).expect("local observe stop");
    assert_eq!(stopped["state"], json!("OFF"));
    assert_eq!(stopped["active"], json!(false));

    // The node status surface carries the same report.
    let status = node.control(&json!({"command": "status"})).expect("node status");
    assert_eq!(status["desktop_observation"]["state"], json!("OFF"));
    assert_eq!(status["desktop_observation"]["supported"], json!(true));
}

#[test]
fn observe_start_rejects_a_non_string_window() {
    let _guard = serial();
    let (_dir, mut node) = open_node();
    let error = node
        .control(&json!({"command": "observe_start", "window": 42}))
        .expect_err("non-string window must be refused");
    assert!(matches!(error, Error::Invalid(_)));
}
#[test]
fn observe_server_directives_narrow_pause_resume_but_never_enable() {
    let _guard = serial();
    let _portal = fake_portal();
    let (_dir, mut node) = open_node();
    node.control(&json!({"command": "observe_start"})).expect("local enable first");

    // A server pause is visible on the wire but clears nothing locally: a
    // resume returns to RUNNING without any new local action.
    let paused = node.observe(&json!({"paused": true})).expect("server pause");
    let paused: orbit_computer_node_protocol::Capabilities =
        serde_json::from_value(paused).expect("server reply is fresh capabilities");
    assert_eq!(paused.desktop_observation.state, DesktopObservationState::Paused);
    let resumed = node.observe(&json!({"paused": false})).expect("server resume");
    let resumed: orbit_computer_node_protocol::Capabilities =
        serde_json::from_value(resumed).expect("server reply is fresh capabilities");
    assert_eq!(resumed.desktop_observation.state, DesktopObservationState::Running);

    // Narrow is intersect-only and accepted; it never enables anything.
    node.observe(&json!({"narrowed_apps": ["a"]})).expect("server narrow");

    // There is no enable key by design: an `enable` directive is refused,
    // never ignored, and a typo'd key fails the whole frame.
    let refused = node.observe(&json!({"enable": true}));
    assert!(refused.is_err(), "server must never enable observation");
}

#[test]
fn observe_server_revoke_is_sticky_until_locally_acknowledged() {
    let _guard = serial();
    let _portal = fake_portal();
    let (_dir, mut node) = open_node();
    node.control(&json!({"command": "observe_start"})).expect("local enable first");

    // Revoke stops pixels immediately and drops the session.
    let revoked = node.observe(&json!({"revoked": true})).expect("server revoke");
    let revoked: orbit_computer_node_protocol::Capabilities =
        serde_json::from_value(revoked).expect("server reply is fresh capabilities");
    assert_eq!(revoked.desktop_observation.state, DesktopObservationState::Off);
    let status = node.control(&json!({"command": "observe_status"})).expect("status");
    assert_eq!(status["state"], json!("OFF"));
    assert_eq!(status["active"], json!(false));

    // A resume cannot shrug off the revoke, and neither can a fresh local
    // start: only an explicit local acknowledge clears the sticky flag.
    node.observe(&json!({"paused": false})).expect("resume after revoke");
    assert!(node.control(&json!({"command": "observe_start"})).is_err());
    node.control(&json!({"command": "observe_acknowledge_revoke"}))
        .expect("local acknowledge clears the flag but stays OFF");
    let status = node.control(&json!({"command": "observe_status"})).expect("status");
    assert_eq!(status["state"], json!("OFF"));
    let restarted = node.control(&json!({"command": "observe_start"})).expect("fresh local start");
    assert_eq!(restarted["status"]["state"], json!("RUNNING"));
    node.control(&json!({"command": "observe_stop"}).clone()).ok();
}

#[test]
fn observation_wire_types_are_versioned() {
    let node = Uuid::new_v4();
    assert_eq!(VERSION, 3);
    for message in [MessageType::Observe, MessageType::DesktopObservation] {
        let envelope = Envelope::new(node, message, json!({}));
        let round_trip: Envelope =
            serde_json::from_value(serde_json::to_value(&envelope).unwrap()).unwrap();
        assert_eq!(round_trip.version, VERSION);
        round_trip.validate(node).unwrap();
    }
    let mut stale = Envelope::new(node, MessageType::Observe, json!({}));
    stale.version = VERSION - 1;
    assert!(matches!(stale.validate(node), Err(Error::Unsupported)));
    assert_eq!(
        serde_json::to_value(DesktopObservationState::PermissionDenied).unwrap(),
        json!("PERMISSION_DENIED")
    );
}
