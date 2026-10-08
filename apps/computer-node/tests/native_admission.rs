//! Explicit native-security gate. Setup alone uses administrator capabilities;
//! each actual actor is a separate process with real UIDs, no groups/capabilities.
#![cfg(all(target_os = "linux", feature = "native-security"))]
use orbit_computer_node::{admin, native};
use orbit_computer_node_protocol::{NodeConfig, RootGrant, RootMode};
use std::{ffi::CString, fs::{self, File, OpenOptions}, io::Write, os::{fd::AsRawFd, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt, PermissionsExt}}}, path::{Path, PathBuf}, process::Command};
const SERVICE: u32 = 61001;
const OWNER: u32 = 61002;
const OTHER: u32 = 61003;
fn config(path: &Path) -> NodeConfig {
    NodeConfig { server: "https://fixture.invalid".into(), owner_id: uuid::Uuid::new_v4(), node_id: uuid::Uuid::new_v4(), session: String::new(), identity_key: String::new(), state_dir: path.to_owned(), ca_file: None, roots: vec![], owner_uid: Some(OWNER), service_uid: Some(SERVICE), embedding: None }
}
fn grant(path: &Path) -> RootGrant { RootGrant { id: uuid::Uuid::new_v4(), path: path.to_owned(), mode: RootMode::ReadWrite, revision: 1, revoked: false, namespace_protected: true } }
fn fixture() -> tempfile::TempDir {
    assert_eq!(unsafe { libc::geteuid() }, 0, "native admission gate requires isolated root setup; do not run on a personal host");
    assert_eq!(std::env::var("ORBIT_NATIVE_SECURITY").as_deref(), Ok("1"), "use isolated node-security Compose service");
    let temp = tempfile::Builder::new().prefix("orbit-admission-").tempdir_in("/var/lib").expect("protected local /var/lib fixture parent");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap(); temp
}
fn child(path: &Path, actor: &str, action: &str, should_succeed: bool) {
    let status = Command::new(std::env::current_exe().unwrap()).args(["--ignored", "--exact", "native_actor", "--nocapture"])
        .env("ORBIT_NATIVE_CHILD_PATH", path).env("ORBIT_NATIVE_ACTOR", actor).env("ORBIT_NATIVE_ACTION", action).status().unwrap();
    assert_eq!(status.success(), should_succeed, "real {actor} process {action} unexpected result");
}
#[repr(C)] struct CapHeader { version: u32, pid: i32 }
#[repr(C)] #[derive(Default, Clone, Copy)] struct CapData { effective: u32, permitted: u32, inheritable: u32 }
fn drop_actor(uid: u32) {
    unsafe {
        assert_eq!(libc::setgroups(0, std::ptr::null()), 0);
        assert_eq!(libc::setresgid(uid, uid, uid), 0);
        assert_eq!(libc::setresuid(uid, uid, uid), 0);
        let header = CapHeader { version: 0x20080522, pid: 0 }; let zero = [CapData::default(); 2];
        assert_eq!(libc::syscall(libc::SYS_capset, &header, zero.as_ptr()), 0);
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        let mut observed = [CapData::default(); 2]; assert_eq!(libc::syscall(libc::SYS_capget, &header, observed.as_mut_ptr()), 0);
        assert!(observed.iter().all(|c| c.effective == 0 && c.permitted == 0 && c.inheritable == 0));
        assert_eq!(libc::getuid(), uid); assert_eq!(libc::geteuid(), uid);
        assert_eq!(libc::getgroups(0, std::ptr::null_mut()), 0);
    }
}
#[test]
#[ignore = "subprocess entrypoint, invoked only by native admission tests"]
fn native_actor() {
    let path = PathBuf::from(std::env::var_os("ORBIT_NATIVE_CHILD_PATH").expect("fixture actor path"));
    let actor = std::env::var("ORBIT_NATIVE_ACTOR").unwrap(); let action = std::env::var("ORBIT_NATIVE_ACTION").unwrap();
    let uid = match actor.as_str() { "service" => SERVICE, "owner" => OWNER, "other" => OTHER, _ => panic!("unknown actor") };
    drop_actor(uid);
    match action.as_str() {
        "admit" => admin::admit(&grant(&path), &config(&path)).unwrap(),
        "content" => { let mut f = OpenOptions::new().write(true).open(path.join("notes.txt")).unwrap(); f.write_all(b"owner edit").unwrap(); f.sync_all().unwrap(); },
        "mkdir" => fs::create_dir(path.join("new-directory")).unwrap(),
        "rename" => fs::rename(path.join("notes.txt"), path.join("renamed.txt")).unwrap(),
        "unlink" => fs::remove_file(path.join("notes.txt")).unwrap(),
        "recovery" => { fs::read_dir(path.join(".orbit-recovery")).unwrap(); },
        "read" => { assert!(!native::read(&grant(&path), "notes.txt", 1024).unwrap().is_empty()); },
        "private-tool" => { assert!(native::read(&grant(&path), ".orbit-recovery/evidence", 1024).is_err()); },
        "published" => { let f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path.join("published.txt")).unwrap(); admin::apply_published_acl(f.as_raw_fd(), OWNER).unwrap(); },
        "published-content" => { let mut f = OpenOptions::new().write(true).open(path.join("published.txt")).unwrap(); f.write_all(b"published owner edit").unwrap(); },
        "control-owner" | "control-other" => {
            let listener = std::os::unix::net::UnixListener::bind(path.join(format!("peer-{uid}.sock"))).unwrap();
            let socket_path = path.join(format!("peer-{uid}.sock"));
            let join = std::thread::spawn(move || std::os::unix::net::UnixStream::connect(socket_path).unwrap());
            let (stream, _) = listener.accept().unwrap(); let _client = join.join().unwrap();
            let result = admin::authorize_control_peer(&stream, &config(&path));
            if action == "control-owner" { assert_eq!(result.unwrap(), OWNER); } else { assert!(result.is_err()); }
        },
        _ => panic!("unknown action"),
    }
}
// Test fixtures use the same kernel POSIX xattr format as setfacl(1), but do not
// depend on a command-line utility or lexical simulation of ACL authorization.
fn raw_acl(path: &Path, entries: &[(u16, u16, u32)]) {
    let mut bytes = 2u32.to_le_bytes().to_vec(); for (t,p,id) in entries { bytes.extend(t.to_le_bytes()); bytes.extend(p.to_le_bytes()); bytes.extend(id.to_le_bytes()); }
    let f = File::open(path).unwrap(); assert_eq!(unsafe { libc::fsetxattr(f.as_raw_fd(), c"system.posix_acl_access".as_ptr(), bytes.as_ptr().cast(), bytes.len(), 0) }, 0, "native POSIX ACL setup unavailable");
}
fn chown(path: &Path, uid: u32) { let name = CString::new(path.as_os_str().as_bytes()).unwrap(); assert_eq!(unsafe { libc::chown(name.as_ptr(), uid, uid) }, 0); }
#[test]
fn protected_namespace_owner_content_and_private_recovery() {
    let temp = fixture(); let root = temp.path().join("shared"); fs::create_dir(&root).unwrap(); fs::write(root.join("notes.txt"), b"preserved original bytes").unwrap();
    let before = fs::metadata(root.join("notes.txt")).unwrap();
    assert!(admin::prepare(&config(&root), &root, false).is_err());
    assert_eq!(fs::metadata(root.join("notes.txt")).unwrap().uid(), before.uid());
    assert_eq!(fs::read(root.join("notes.txt")).unwrap(), b"preserved original bytes");
    admin::prepare(&config(&root), &root, true).unwrap();
    assert_eq!(fs::read(root.join("notes.txt")).unwrap(), b"preserved original bytes");
    child(&root, "service", "admit", true); child(&root, "owner", "content", true); child(&root, "service", "read", true);
    assert_eq!(fs::read(root.join("notes.txt")).unwrap(), b"owner editoriginal bytes");
    for action in ["mkdir", "rename", "unlink", "recovery"] { child(&root, "owner", action, false); }
    for action in ["content", "mkdir", "rename"] { child(&root, "other", action, false); }
    child(&root, "service", "private-tool", true);
    child(&root, "service", "published", true); child(&root, "owner", "published-content", true);
    child(&root, "service", "admit", true);
}
#[test]
fn foreign_namespace_acls_and_permission_changes_fail_closed() {
    let temp = fixture(); let root = temp.path().join("shared"); admin::prepare(&config(&root), &root, true).unwrap();
    let base = [(1,7,u32::MAX),(2,5,OWNER),(4,0,u32::MAX),(16,7,u32::MAX),(32,0,u32::MAX)];
    for tag in [2, 8] {
        let entries = if tag == 2 { vec![base[0], base[1], (2,7,OTHER), base[2], base[3], base[4]] } else { vec![base[0], base[1], base[2], (8,7,OTHER), base[3], base[4]] };
        raw_acl(&root, &entries); child(&root, "service", "admit", false);
        // Prove the kernel really permits foreign namespace write for that UID/group.
        child(&root, "other", "mkdir", true); fs::remove_dir(root.join("new-directory")).unwrap();
    }
    raw_acl(&root, &[(1,7,u32::MAX),(2,5,OWNER),(4,0,u32::MAX),(16,5,u32::MAX),(32,0,u32::MAX)]);
    child(&root, "service", "admit", true);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap(); child(&root, "service", "admit", false);
}
#[test]
fn credential_descendants_and_hardlink_identities_are_rejected() {
    let temp = fixture(); let root = temp.path().join("shared"); admin::prepare(&config(&root), &root, true).unwrap();
    fs::create_dir(root.join(".ssh")).unwrap(); chown(&root.join(".ssh"), SERVICE);
    assert!(admin::admit(&grant(&root), &config(&root)).is_err()); child(&root, "service", "admit", false); fs::remove_dir(root.join(".ssh")).unwrap();
    fs::write(root.join("notes.txt"), b"credential hardlink canary").unwrap(); chown(&root.join("notes.txt"), SERVICE);
    fs::hard_link(root.join("notes.txt"), temp.path().join("credential-alias")).unwrap(); child(&root, "service", "admit", false);
}
#[test]
fn arbitrary_owner_ancestry_remains_read_only_without_permission_removal() {
    let temp = fixture(); let home = temp.path().join("owner-home"); fs::create_dir(&home).unwrap(); chown(&home, OWNER); fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
    let root = home.join("notes"); fs::create_dir(&root).unwrap(); chown(&root, OWNER); fs::write(root.join("notes.txt"), b"home bytes").unwrap();
    let before = fs::metadata(&home).unwrap(); assert!(admin::prepare(&config(&root), &root, true).is_err());
    let after = fs::metadata(&home).unwrap(); assert_eq!((before.uid(), before.mode()), (after.uid(), after.mode())); assert_eq!(fs::read(root.join("notes.txt")).unwrap(), b"home bytes");
    child(&root, "service", "admit", false);
    // Ordinary home folders retain real read access rather than forced conversion.
    child(&root, "owner", "read", true);
}
#[test]
fn control_socket_peer_is_configured_owner_or_admin_only() {
    let temp = fixture(); let owner = temp.path().join("owner-control"); let other = temp.path().join("other-control");
    fs::create_dir(&owner).unwrap(); chown(&owner, OWNER); fs::create_dir(&other).unwrap(); chown(&other, OTHER);
    child(&owner, "owner", "control-owner", true); child(&other, "other", "control-other", true);
}
