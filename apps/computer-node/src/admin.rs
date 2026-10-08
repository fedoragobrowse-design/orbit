//! Linux installation is a local administrator operation, never a server grant.
//! ACLs use the kernel's POSIX ACL xattr encoding; no external chmod/setfacl
//! process can accidentally follow a link during preparation.
use orbit_computer_node_protocol::{Error, NodeConfig, Result, RootGrant};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::{ffi::{CStr, CString, OsStr}, fs::{self, File, OpenOptions}, io::Write, os::{fd::{AsRawFd, FromRawFd, RawFd}, unix::{ffi::OsStrExt, fs::OpenOptionsExt, net::{UnixListener, UnixStream}}}, process::Command};

    pub const SERVICE_HOME: &str = "/var/lib/orbit-node";
    const SERVICE_RECORD: &str = "/etc/orbit-node/service.json";
    const UNDEFINED: u32 = u32::MAX;
    const ACCESS: &CStr = c"system.posix_acl_access";
    const DEFAULT: &CStr = c"system.posix_acl_default";
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ServiceIdentity { pub owner_uid: u32, pub service_uid: u32, pub service_gid: u32 }
    #[derive(Clone, Copy)]
    struct AclEntry { tag: u16, perm: u16, id: u32 }
    #[repr(C)]
    struct OpenHow { flags: u64, mode: u64, resolve: u64 }
    fn unavailable(reason: impl Into<String>) -> Error { Error::SecureMutationUnavailable(reason.into()) }
    fn check(rc: i32) -> Result<()> { if rc < 0 { Err(std::io::Error::last_os_error().into()) } else { Ok(()) } }
    fn admin() -> Result<()> { if unsafe { libc::geteuid() } != 0 { Err(Error::Forbidden) } else { Ok(()) } }
    fn cpath(path: &OsStr) -> Result<CString> { CString::new(path.as_bytes()).map_err(|_| Error::Invalid("NUL path".into())) }
    fn stat(fd: RawFd) -> Result<libc::stat> {
        let mut st = unsafe { std::mem::zeroed() }; check(unsafe { libc::fstat(fd, &mut st) })?; Ok(st)
    }
    fn open_child(parent: RawFd, name: &OsStr, directory: bool) -> Result<File> {
        let name = cpath(name)?;
        let how = OpenHow { flags: (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { libc::O_NONBLOCK }) as u64, mode: 0, resolve: 0x08 | 0x04 | 0x02 };
        let fd = unsafe { libc::syscall(libc::SYS_openat2, parent, name.as_ptr(), &how, std::mem::size_of::<OpenHow>()) };
        if fd < 0 { return Err(unavailable(format!("secure handle lookup failed: {}", std::io::Error::last_os_error()))); }
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }
    fn normalized(path: &Path) -> Result<()> {
        if !path.is_absolute() || path == Path::new("/") || path.components().any(|c| !matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_))) {
            return Err(Error::Invalid("an absolute, non-root path without traversal is required".into()));
        }
        for system in ["/etc", "/proc", "/sys", "/dev", "/boot", "/usr", "/bin", "/sbin", "/root"] {
            if path.starts_with(system) { return Err(Error::Forbidden); }
        }
        let name = path.file_name().ok_or(Error::Forbidden)?.to_string_lossy();
        if orbit_computer_node_protocol::denied_name(&name) { return Err(Error::Forbidden); }
        Ok(())
    }
    fn acl(fd: RawFd, key: &CStr) -> Result<Vec<AclEntry>> {
        let mut bytes = [0u8; 65536];
        let n = unsafe { libc::fgetxattr(fd, key.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENODATA) { return Ok(Vec::new()); }
            return Err(unavailable(format!("ACL cannot be audited: {e}")));
        }
        let b = &bytes[..n as usize];
        if b.len() < 4 || (b.len() - 4) % 8 != 0 || u32::from_le_bytes(b[..4].try_into().unwrap()) != 2 { return Err(unavailable("unknown ACL encoding")); }
        b[4..].chunks_exact(8).map(|e| {
            let tag = u16::from_le_bytes(e[..2].try_into().unwrap()); let perm = u16::from_le_bytes(e[2..4].try_into().unwrap());
            if !matches!(tag, 1 | 2 | 4 | 8 | 16 | 32) || perm & !7 != 0 { return Err(unavailable("invalid ACL entry")); }
            Ok(AclEntry { tag, perm, id: u32::from_le_bytes(e[4..].try_into().unwrap()) })
        }).collect()
    }
    fn set_acl(fd: RawFd, owner: Option<u32>, directory: bool) -> Result<()> {
        let mut entries = vec![(1u16, if directory { 7u16 } else { 6u16 }, UNDEFINED)];
        if let Some(owner) = owner { entries.push((2, if directory { 5 } else { 6 }, owner)); }
        entries.push((4, 0, UNDEFINED));
        if owner.is_some() { entries.push((16, if directory { 5 } else { 6 }, UNDEFINED)); }
        entries.push((32, 0, UNDEFINED));
        let mut bytes = Vec::with_capacity(4 + entries.len() * 8); bytes.extend_from_slice(&2u32.to_le_bytes());
        for (tag, perm, id) in entries { bytes.extend_from_slice(&tag.to_le_bytes()); bytes.extend_from_slice(&perm.to_le_bytes()); bytes.extend_from_slice(&id.to_le_bytes()); }
        check(unsafe { libc::fsetxattr(fd, ACCESS.as_ptr(), bytes.as_ptr().cast(), bytes.len(), 0) })?;
        if directory { let rc = unsafe { libc::fremovexattr(fd, DEFAULT.as_ptr()) }; if rc < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) { check(rc)?; } }
        Ok(())
    }
    fn filesystem(fd: RawFd) -> Result<()> {
        let mut info: libc::statfs = unsafe { std::mem::zeroed() }; check(unsafe { libc::fstatfs(fd, &mut info) })?;
        // Native local Linux filesystems with openat2/renameat2/directory fsync.
        // Remote filesystems, FUSE, FAT and unknown filesystems fail closed.
        if !matches!(info.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e | 0x01021994 | 0x794c7630) { return Err(unavailable("unsupported or nonlocal filesystem")); }
        // glibc's statfs omits f_flags, so the read-only verdict comes from statvfs f_flag.
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() }; check(unsafe { libc::fstatvfs(fd, &mut vfs) })?;
        if vfs.f_flag & libc::ST_RDONLY as libc::c_ulong != 0 { return Err(unavailable("read-only filesystem")); }
        Ok(())
    }
    fn namespace(fd: RawFd, service: u32, ancestor: bool, private: bool, owner: u32) -> Result<()> {
        let st = stat(fd)?; filesystem(fd)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR || !(st.st_uid == service || (ancestor && st.st_uid == 0)) { return Err(unavailable("directory ownership is not protected")); }
        if st.st_mode & 0o7000 != 0 || st.st_mode & 0o022 != 0 { return Err(unavailable("foreign group/other directory-write permission")); }
        let entries = acl(fd, ACCESS)?;
        for e in &entries {
            if e.perm & 2 != 0 && !((e.tag == 1 && (st.st_uid == service || st.st_uid == 0)) || (e.tag == 2 && (e.id == service || e.id == 0))) && e.tag != 16 { return Err(unavailable("foreign directory-write ACL")); }
            if private && e.tag != 1 && e.tag != 16 && e.perm != 0 { return Err(unavailable("recovery namespace is not service-private")); }
        }
        if !acl(fd, DEFAULT)?.is_empty() { return Err(unavailable("default ACLs are not admitted; new entries receive explicit ACLs")); }
        if !ancestor && !private && !entries.iter().any(|e| e.tag == 2 && e.id == owner && e.perm == 5) { return Err(unavailable("owner needs directory read/traverse, not write")); }
        Ok(())
    }
    fn ancestors(path: &Path, service: u32, owner: u32) -> Result<(File, String)> {
        normalized(path)?;
        let mut current = File::open("/")?;
        namespace(current.as_raw_fd(), service, true, false, owner)?;
        let components: Vec<_> = path.components().filter_map(|c| if let std::path::Component::Normal(s) = c { Some(s) } else { None }).collect();
        for name in &components[..components.len() - 1] {
            current = open_child(current.as_raw_fd(), name, true)?;
            namespace(current.as_raw_fd(), service, true, false, owner)?;
        }
        Ok((current, components.last().unwrap().to_string_lossy().into_owned()))
    }
    fn names(fd: RawFd) -> Result<Vec<std::ffi::OsString>> {
        // Duplicate offsets are harmless: each directory is enumerated once.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) }; if duplicate < 0 { return Err(std::io::Error::last_os_error().into()); }
        let dir = unsafe { libc::fdopendir(duplicate) }; if dir.is_null() { unsafe { libc::close(duplicate); } return Err(std::io::Error::last_os_error().into()); }
        let mut result = Vec::new();
        loop {
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() { let e = std::io::Error::last_os_error(); unsafe { libc::closedir(dir); } if e.raw_os_error() != Some(0) { return Err(e.into()); } break; }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." { result.push(OsStr::from_bytes(name).to_owned()); }
        }
        Ok(result)
    }
    fn scan(fd: File, service: u32, owner: u32, private: bool, preparing: bool, depth: usize, collected: &mut Vec<(File, bool, bool)>) -> Result<()> {
        if depth > 128 || collected.len() >= 100_000 { return Err(unavailable("admission tree exceeds audit bound")); }
        let st = stat(fd.as_raw_fd())?; filesystem(fd.as_raw_fd())?;
        let directory = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if !directory && (st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1) { return Err(unavailable("symlink, special file or hardlinked identity")); }
        if !preparing {
            if directory { namespace(fd.as_raw_fd(), service, false, private, owner)?; }
            else {
                if st.st_uid != service || st.st_mode & 0o7000 != 0 || st.st_mode & 0o007 != 0 { return Err(unavailable("file ownership/permissions changed")); }
                let entries = acl(fd.as_raw_fd(), ACCESS)?;
                if entries.iter().any(|e| (e.tag == 2 && e.id != owner && e.id != service && e.perm != 0) || ((e.tag == 4 || e.tag == 8 || e.tag == 32) && e.perm != 0)) { return Err(unavailable("foreign file ACL")); }
                if !private && !entries.iter().any(|e| e.tag == 2 && e.id == owner && e.perm == 6) { return Err(unavailable("owner file-content ACL changed")); }
            }
        }
        if directory {
            for name in names(fd.as_raw_fd())? {
                let text = name.to_str().ok_or_else(|| unavailable("non-UTF8 name"))?;
                let recovery = depth == 0 && text == ".orbit-recovery";
                if orbit_computer_node_protocol::denied_name(text) && !recovery { return Err(unavailable(format!("denied credential/system descendant: {text}"))); }
                if recovery && preparing { return Err(unavailable("existing recovery evidence must not be re-prepared")); }
                let child = open_child(fd.as_raw_fd(), &name, false)?;
                scan(child, service, owner, private || recovery, preparing, depth + 1, collected)?;
            }
        }
        collected.push((fd, directory, private)); Ok(())
    }
    fn ids(config: &NodeConfig) -> Result<(u32, u32)> {
        let owner = config.owner_uid.ok_or_else(|| unavailable("service install --owner is required"))?;
        let service = config.service_uid.ok_or_else(|| unavailable("dedicated service UID is required"))?;
        if service == 0 || owner == 0 || owner == service { return Err(unavailable("owner/service must be distinct unprivileged UIDs")); }
        Ok((owner, service))
    }
    fn reject_whole_home(path: &Path, owner: u32) -> Result<()> {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() }; let mut out = std::ptr::null_mut(); let mut buffer = vec![0u8; 65536];
        let rc = unsafe { libc::getpwuid_r(owner, &mut pwd, buffer.as_mut_ptr().cast(), buffer.len(), &mut out) };
        if rc != 0 { return Err(unavailable("owner OS identity cannot be checked")); }
        if !out.is_null() && path == Path::new(unsafe { CStr::from_ptr(pwd.pw_dir) }.to_str().map_err(|_| Error::Forbidden)?) { return Err(Error::Forbidden); }
        Ok(())
    }
    pub fn admit(root: &RootGrant, config: &NodeConfig) -> Result<()> {
        let (owner, service) = ids(config)?;
        reject_whole_home(&root.path, owner)?;
        if root.revoked { return Err(Error::Forbidden); }
        if root.path.starts_with(&config.state_dir) || config.state_dir.starts_with(&root.path) { return Err(Error::Forbidden); }
        let (parent, name) = ancestors(&root.path, service, owner)?;
        let tree = open_child(parent.as_raw_fd(), OsStr::new(&name), true)?;
        let mut held = Vec::new(); scan(tree, service, owner, false, false, 0, &mut held)?;
        Ok(())
    }
    /// Admission for a READ root on a node with no installed service identity.
    /// Such a node holds no namespace authority, so the tree only has to be
    /// unambiguous: local filesystem, no symlinks or hardlinked identity, no
    /// denied names, no foreign or group/other write permission, and nothing
    /// inside the node's own state directory.
    pub fn admit_read_only(root: &RootGrant, config: &NodeConfig) -> Result<()> {
        let owner = unsafe { libc::geteuid() };
        if root.revoked { return Err(Error::Forbidden); }
        reject_whole_home(&root.path, owner)?;
        if root.path.starts_with(&config.state_dir) || config.state_dir.starts_with(&root.path) { return Err(Error::Forbidden); }
        let mut collected = Vec::new();
        let (parent, name) = read_only_ancestors(&root.path, owner)?;
        let tree = open_child(parent.as_raw_fd(), OsStr::new(&name), true)?;
        scan_read_only(tree, owner, 0, &mut collected)
    }
    /// Walk the ancestors with the same openat2 guarantees as a mutating
    /// admission, checking only that no foreign principal can rewrite the path.
    fn read_only_ancestors(path: &Path, owner: u32) -> Result<(File, String)> {
        normalized(path)?;
        let mut current = File::open("/")?;
        read_only_namespace(current.as_raw_fd())?;
        let components: Vec<_> = path.components().filter_map(|c| if let std::path::Component::Normal(s) = c { Some(s) } else { None }).collect();
        for name in &components[..components.len() - 1] {
            current = open_child(current.as_raw_fd(), name, true)?;
            read_only_namespace(current.as_raw_fd())?;
        }
        let _ = owner;
        Ok((current, components.last().ok_or(Error::Forbidden)?.to_string_lossy().into_owned()))
    }
    fn read_only_namespace(fd: RawFd) -> Result<()> {
        let st = stat(fd)?; filesystem(fd)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR { return Err(unavailable("path ancestor is not a directory")); }
        if st.st_mode & 0o7000 != 0 || st.st_mode & 0o022 != 0 { return Err(unavailable("foreign group/other directory-write permission")); }
        for entry in acl(fd, ACCESS)?.iter().chain(acl(fd, DEFAULT)?.iter()) {
            if entry.tag != 1 && entry.perm != 0 { return Err(unavailable("foreign ancestor ACL grant")); }
        }
        Ok(())
    }
    fn name_of(fd: RawFd) -> String {
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap_or_default();
        link.to_string_lossy().into_owned()
    }
    fn scan_read_only(fd: File, owner: u32, depth: usize, collected: &mut Vec<File>) -> Result<()> {
        if depth > 128 || collected.len() >= 100_000 { return Err(unavailable("read-only tree exceeds audit bound")); }
        let here = name_of(fd.as_raw_fd());
        let st = stat(fd.as_raw_fd())?; filesystem(fd.as_raw_fd())?;
        let directory = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if !directory && (st.st_mode & libc::S_IFMT != libc::S_IFREG || st.st_nlink != 1) { return Err(unavailable(format!("symlink, special file or hardlinked identity: {here}"))); }
        if st.st_uid != owner { return Err(unavailable(format!("read-only root must be owned by the node owner: {here}"))); }
        // Any write bit outside the owner would let another principal change what
        // this read-only root reports, so it fails closed.
        if st.st_mode & 0o7000 != 0 || st.st_mode & 0o022 != 0 { return Err(unavailable(format!("group/other write permission in a read-only root: {here}"))); }
        for entry in acl(fd.as_raw_fd(), ACCESS)?.iter().chain(acl(fd.as_raw_fd(), DEFAULT)?.iter()) {
            if entry.perm != 0 { return Err(unavailable(format!("read-only root must not carry ACL grants: {here}"))); }
        }
        if directory {
            for name in names(fd.as_raw_fd())? {
                let text = name.to_str().ok_or_else(|| unavailable("non-UTF8 name"))?;
                if orbit_computer_node_protocol::denied_name(text) { return Err(unavailable(format!("denied credential/system descendant: {text}"))); }
                let child = open_child(fd.as_raw_fd(), &name, false)?;
                scan_read_only(child, owner, depth + 1, collected)?;
            }
        }
        collected.push(fd); Ok(())
    }
    pub fn prepare(config: &NodeConfig, path: &Path, consent: bool) -> Result<PathBuf> {
        admin()?; let (owner, service) = ids(config)?;
        reject_whole_home(path, owner)?;
        let (parent, name) = ancestors(path, service, owner).map_err(|e| unavailable(format!("{e}; keep this folder READ-only; prepare a separate /var/lib/orbit-node/shared/<root-id> tree. Home ancestor permissions will not be changed.")))?;
        let cname = CString::new(name.clone()).map_err(|_| Error::Forbidden)?;
        let existing = open_child(parent.as_raw_fd(), OsStr::new(&name), true);
        let absent = matches!(&existing, Err(Error::SecureMutationUnavailable(_))) && unsafe { libc::faccessat(parent.as_raw_fd(), cname.as_ptr(), libc::F_OK, libc::AT_SYMLINK_NOFOLLOW) } < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
        let mut held = Vec::new();
        if !absent { scan(existing?, service, owner, false, true, 0, &mut held)?; }
        println!("Prepare {}: {} existing objects. Change object ownership to dedicated UID {service}; directory ACL owner UID {owner}=r-x, group/other=---; regular-file ACL owner=rw-, group/other=---. Remove inherited ACLs and set-id bits. Preserve all existing file bytes. Create service-private .orbit-recovery (0700). Native atomic-save/new-file creation must use Orbit. Ancestors are audited, never changed.", path.display(), held.len());
        if !consent { return Err(Error::Invalid("preview only: explicit local --consent is required".into())); }
        if absent {
            check(unsafe { libc::mkdirat(parent.as_raw_fd(), cname.as_ptr(), 0o700) })?;
            held.push((open_child(parent.as_raw_fd(), OsStr::new(&name), true)?, true, false));
        }
        for (fd, directory, _) in &held {
            check(unsafe { libc::fchown(fd.as_raw_fd(), service, UNDEFINED) })?;
            check(unsafe { libc::fchmod(fd.as_raw_fd(), if *directory { 0o700 } else { 0o600 }) })?;
            set_acl(fd.as_raw_fd(), Some(owner), *directory)?; fd.sync_all()?;
        }
        let tree = open_child(parent.as_raw_fd(), OsStr::new(&name), true)?;
        check(unsafe { libc::mkdirat(tree.as_raw_fd(), c".orbit-recovery".as_ptr(), 0o700) })?;
        let recovery = open_child(tree.as_raw_fd(), OsStr::new(".orbit-recovery"), true)?;
        check(unsafe { libc::fchown(recovery.as_raw_fd(), service, UNDEFINED) })?; set_acl(recovery.as_raw_fd(), None, true)?;
        recovery.sync_all()?; tree.sync_all()?; parent.sync_all()?;
        let root = RootGrant { id: uuid::Uuid::new_v4(), path: path.to_owned(), mode: orbit_computer_node_protocol::RootMode::ReadWrite, revision: 1, revoked: false, namespace_protected: true };
        admit(&root, config)?; Ok(path.to_owned())
    }
    pub fn apply_published_acl(fd: RawFd, owner_uid: u32) -> Result<()> {
        let st = stat(fd)?;
        if st.st_uid != unsafe { libc::geteuid() } || st.st_nlink != 1 || st.st_mode & libc::S_IFMT != libc::S_IFREG { return Err(unavailable("publication must use a service-owned single-link file")); }
        set_acl(fd, Some(owner_uid), false)
    }
    pub fn apply_directory_acl(fd: RawFd, owner_uid: u32) -> Result<()> { set_acl(fd, Some(owner_uid), true) }
    fn account(name: &str) -> Result<(u32, u32, String, String)> {
        let name = CString::new(name).map_err(|_| Error::Invalid("invalid OS username".into()))?;
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() }; let mut out = std::ptr::null_mut(); let mut buffer = vec![0u8; 65536];
        let rc = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buffer.as_mut_ptr().cast(), buffer.len(), &mut out) };
        if rc != 0 || out.is_null() { return Err(Error::Invalid("OS account not found".into())); }
        Ok((pwd.pw_uid, pwd.pw_gid, unsafe { CStr::from_ptr(pwd.pw_dir) }.to_string_lossy().into_owned(), unsafe { CStr::from_ptr(pwd.pw_shell) }.to_string_lossy().into_owned()))
    }
    pub fn installed_identity() -> Result<ServiceIdentity> {
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(SERVICE_RECORD)?;
        let st = stat(file.as_raw_fd())?;
        if st.st_uid != 0 || st.st_mode & 0o022 != 0 || st.st_nlink != 1 { return Err(Error::Forbidden); }
        let identity: ServiceIdentity = serde_json::from_reader(file)?;
        let (uid, gid, home, shell) = account("orbit-node")?;
        if identity.service_uid == 0 || uid != identity.service_uid || gid != identity.service_gid || home != SERVICE_HOME || !(shell.ends_with("/nologin") || shell == "/bin/false") { return Err(unavailable("dedicated service account changed")); }
        let passwd = fs::read_to_string("/etc/passwd")?;
        if passwd.lines().filter(|line| line.split(':').nth(2).and_then(|n| n.parse::<u32>().ok()) == Some(uid)).count() != 1 { return Err(unavailable("service UID shared by another account")); }
        for line in fs::read_to_string("/etc/group")?.lines() {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() == 4 && fields[2].parse::<u32>().ok() == Some(gid) && !fields[3].is_empty() { return Err(unavailable("service group has unrelated members")); }
        }
        Ok(identity)
    }
    fn run(program: &str, args: &[&str]) -> Result<()> { if Command::new(program).args(args).status()?.success() { Ok(()) } else { Err(unavailable(format!("{program} failed"))) } }
    fn create_private(path: &Path, uid: u32, gid: u32, owner: Option<u32>) -> Result<()> {
        fs::create_dir(path)?;
        let fd = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)?;
        check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) })?; check(unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) })?;
        set_acl(fd.as_raw_fd(), owner, true)?; fd.sync_all()?; Ok(())
    }
    fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> { let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(path)?; f.write_all(bytes)?; f.sync_all()?; Ok(()) }
    pub fn install(owner: &str, consent: bool) -> Result<()> {
        admin()?; let (owner_uid, _, _, _) = account(owner)?;
        if owner_uid == 0 { return Err(Error::Invalid("owner must be an unprivileged OS user".into())); }
        let binary = std::env::current_exe()?;
        if binary.as_os_str().as_bytes().iter().any(|b| b.is_ascii_whitespace() || *b == b'%' || *b == b'"' || *b == b'\\') { return Err(Error::Invalid("service executable path contains unsupported systemd characters".into())); }
        let executable = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&binary)?; let st = stat(executable.as_raw_fd())?;
        if st.st_uid != 0 || st.st_mode & 0o6022 != 0 { return Err(Error::Invalid("install the node binary root-owned, non-setid and non-writable by others first".into())); }
        println!("Install for OS owner {owner} (UID {owner_uid}): create a locked orbit-node system account with nologin; create /etc/orbit-node and /var/lib/orbit-node with private state and protected shared namespace; install orbit-computer-node.service running unprivileged with no capabilities. Existing installation artifacts are never overwritten. Pairing config is /var/lib/orbit-node/state/node.json; owner controls the service via its protected local socket. No service is started before pairing.");
        if !consent { return Err(Error::Invalid("preview only: explicit local --consent is required".into())); }
        for p in [SERVICE_RECORD, SERVICE_HOME, "/etc/systemd/system/orbit-computer-node.service", "/etc/orbit-node"] { if fs::symlink_metadata(p).is_ok() { return Err(Error::Invalid(format!("existing installation artifact preserved: {p}"))); } }
        if account("orbit-node").is_ok() { return Err(Error::Invalid("existing orbit-node account must be reviewed, not reused silently".into())); }
        run("useradd", &["--system", "--user-group", "--no-create-home", "--home-dir", SERVICE_HOME, "--shell", "/usr/sbin/nologin", "orbit-node"])?;
        let (service_uid, service_gid, _, _) = account("orbit-node")?;
        let identity = ServiceIdentity { owner_uid, service_uid, service_gid };
        create_private(Path::new("/etc/orbit-node"), 0, 0, None)?;
        let etc = File::open("/etc/orbit-node")?;
        check(unsafe { libc::fchmod(etc.as_raw_fd(), 0o755) })?;
        create_private(Path::new(SERVICE_HOME), 0, 0, Some(owner_uid))?;
        let base = File::open(SERVICE_HOME)?;
        // Service traverse only on the administrator-owned installation ancestor.
        let service_acl = [(1u16,7u16,UNDEFINED),(2,5,owner_uid),(2,5,service_uid),(4,0,UNDEFINED),(16,5,UNDEFINED),(32,0,UNDEFINED)];
        let mut b = 2u32.to_le_bytes().to_vec(); for (t,p,id) in service_acl { b.extend(t.to_le_bytes()); b.extend(p.to_le_bytes()); b.extend(id.to_le_bytes()); }
        check(unsafe { libc::fsetxattr(base.as_raw_fd(), ACCESS.as_ptr(), b.as_ptr().cast(), b.len(), 0) })?;
        create_private(Path::new("/var/lib/orbit-node/state"), service_uid, service_gid, Some(owner_uid))?;
        create_private(Path::new("/var/lib/orbit-node/shared"), service_uid, service_gid, Some(owner_uid))?;
        write_new(Path::new(SERVICE_RECORD), &serde_json::to_vec_pretty(&identity)?, 0o644)?;
        let unit = format!("[Unit]\nDescription=Orbit scoped computer node\nAfter=network-online.target\nWants=network-online.target\nConditionPathExists=/var/lib/orbit-node/state/node.json\n\n[Service]\nType=simple\nUser=orbit-node\nGroup=orbit-node\nExecStart={} serve --config /var/lib/orbit-node/state/node.json\nRestart=on-failure\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictSUIDSGID=yes\nLockPersonality=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\n[Install]\nWantedBy=multi-user.target\n", binary.display());
        write_new(Path::new("/etc/systemd/system/orbit-computer-node.service"), unit.as_bytes(), 0o644)?;
        run("systemctl", &["daemon-reload"])?; run("systemctl", &["enable", "orbit-computer-node.service"])?; Ok(())
    }
    #[repr(C)] struct CapHeader { version: u32, pid: i32 }
    #[repr(C)] #[derive(Default, Clone, Copy)] struct CapData { effective: u32, permitted: u32, inheritable: u32 }
    pub fn assert_service_identity(config: &NodeConfig) -> Result<()> {
        let (_, service) = ids(config)?;
        if unsafe { libc::geteuid() } != service || unsafe { libc::getuid() } != service { return Err(unavailable("paired mutation node must run as its dedicated service UID, never root")); }
        let header = CapHeader { version: 0x20080522, pid: 0 }; let mut data = [CapData::default(); 2];
        if unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) } < 0 { return Err(std::io::Error::last_os_error().into()); }
        if data.iter().any(|d| d.effective != 0 || d.permitted != 0 || d.inheritable != 0) { return Err(unavailable("paired node has capabilities")); }
        check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
        let installed = installed_identity()?;
        if installed.service_uid != service || Some(installed.owner_uid) != config.owner_uid { return Err(Error::Forbidden); }
        Ok(())
    }
    pub fn authorize_control_peer(stream: &UnixStream, config: &NodeConfig) -> Result<u32> {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() }; let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        check(unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut peer as *mut libc::ucred).cast(), &mut size) })?;
        if size as usize != std::mem::size_of::<libc::ucred>() || (peer.uid != 0 && Some(peer.uid) != config.owner_uid) { return Err(Error::Forbidden); } Ok(peer.uid)
    }
    pub fn bind_control(config: &NodeConfig) -> Result<UnixListener> {
        let (owner, service) = ids(config)?;
        let (parent, name) = ancestors(&config.state_dir, service, owner)?;
        let dir = open_child(parent.as_raw_fd(), OsStr::new(&name), true)?; namespace(dir.as_raw_fd(), service, false, false, owner)?;
        let socket = config.state_dir.join("control.sock");
        // Serialize service starts across crash recovery. A process-lifetime
        // CLOEXEC directory lock also keeps the native worker from inheriting it.
        static CONTROL_LOCK: std::sync::OnceLock<File> = std::sync::OnceLock::new();
        if CONTROL_LOCK.get().is_some() { return Err(Error::Invalid("control listener already bound".into())); }
        check(unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) })?;
        if let Ok(st) = fs::symlink_metadata(&socket) {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            if st.uid() != service || !st.file_type().is_socket() { return Err(Error::Forbidden); }
            match UnixStream::connect(&socket) {
                Ok(_) => return Err(Error::Invalid("control socket is already active".into())),
                Err(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => {
                    check(unsafe { libc::unlinkat(dir.as_raw_fd(), c"control.sock".as_ptr(), 0) })?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        CONTROL_LOCK.set(dir).map_err(|_| Error::Invalid("control listener already bound".into()))?;
        let listener = UnixListener::bind(&socket)?;
        let fd = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(&socket)?;
        let st = stat(fd.as_raw_fd())?; if st.st_uid != service || st.st_mode & libc::S_IFMT != libc::S_IFSOCK { return Err(Error::Forbidden); }
        let path = cpath(socket.as_os_str())?;
        let entries = [(1u16,6u16,UNDEFINED),(2,6,owner),(4,0,UNDEFINED),(16,6,UNDEFINED),(32,0,UNDEFINED)];
        let mut bytes = 2u32.to_le_bytes().to_vec(); for (t,p,id) in entries { bytes.extend(t.to_le_bytes()); bytes.extend(p.to_le_bytes()); bytes.extend(id.to_le_bytes()); }
        check(unsafe { libc::setxattr(path.as_ptr(), ACCESS.as_ptr(), bytes.as_ptr().cast(), bytes.len(), 0) })?; Ok(listener)
    }
    pub fn connect_control(config: &NodeConfig) -> Result<UnixStream> {
        let (owner, service) = ids(config)?; let uid = unsafe { libc::geteuid() }; if uid != 0 && uid != owner { return Err(Error::Forbidden); }
        let socket = config.state_dir.join("control.sock"); let stream = UnixStream::connect(socket)?;
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() }; let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        check(unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut peer as *mut libc::ucred).cast(), &mut size) })?;
        if peer.uid != service { return Err(Error::Forbidden); } Ok(stream)
    }
}
#[cfg(target_os = "linux")]
pub use platform::*;
#[cfg(not(target_os = "linux"))]
pub fn install(_: &str, _: bool) -> Result<()> { Err(Error::Unsupported) }
#[cfg(not(target_os = "linux"))]
pub fn prepare(_: &NodeConfig, _: &Path, _: bool) -> Result<PathBuf> { Err(Error::Unsupported) }
#[cfg(not(target_os = "linux"))]
pub fn admit(_: &RootGrant, _: &NodeConfig) -> Result<()> { Err(Error::Unsupported) }
#[cfg(not(target_os = "linux"))]
pub fn admit_read_only(_: &RootGrant, _: &NodeConfig) -> Result<()> { Err(Error::Unsupported) }
