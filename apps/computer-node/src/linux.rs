use crate::{NativeMetadata, NativeMutation, NativeOutcome};
use orbit_computer_node_protocol::{Error, Result, RootGrant, MAX_FILE, normalize_path, denied_name, sha256};
use std::{ffi::{CString, CStr}, fs::File, io::{Read, Write}, os::fd::{AsRawFd, FromRawFd, OwnedFd}, os::unix::fs::MetadataExt};

#[repr(C)] struct OpenHow { flags: u64, mode: u64, resolve: u64 }
fn c(s: &str) -> Result<CString> { CString::new(s).map_err(|_| Error::Forbidden) }
fn io_fd(fd: libc::c_long) -> Result<OwnedFd> { if fd < 0 { Err(std::io::Error::last_os_error().into()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) }) } }
pub fn root_handle(root: &RootGrant) -> Result<OwnedFd> {
    let path = root.path.to_str().ok_or(Error::Forbidden)?;
    io_fd(unsafe { libc::open(c(path)?.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) } as _)
}
fn at(fd: i32, path: &str, flags: i32, mode: u32, internal: bool) -> Result<OwnedFd> {
    if !internal && path != "." { normalize_path(path)?; }
    let how = OpenHow { flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64, mode: mode as u64, resolve: 0x08 | 0x04 | 0x02 };
    io_fd(unsafe { libc::syscall(libc::SYS_openat2, fd, c(path)?.as_ptr(), &how, std::mem::size_of::<OpenHow>()) })
}
fn handle_metadata(fd: &OwnedFd, digest: bool) -> Result<NativeMetadata> {
    let file = File::from(fd.try_clone()?); let m = file.metadata()?;
    if m.file_type().is_file() && m.nlink() != 1 { return Err(Error::Forbidden); }
    if !m.is_file() && !m.is_dir() { return Err(Error::Forbidden); }
    let hash = if digest && m.is_file() { Some(sha256(&bounded(File::from(fd.try_clone()?), MAX_FILE)?)) } else { None };
    Ok(NativeMetadata { identity: format!("{}:{}", m.dev(), m.ino()), size: m.len(), modified_ns: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128, kind: if m.is_dir() { "DIRECTORY" } else { "FILE" }.into(), digest: hash })
}
fn bounded(file: File, max: usize) -> Result<Vec<u8>> { let mut bytes = Vec::new(); file.take((max + 1) as u64).read_to_end(&mut bytes)?; if bytes.len() > max { return Err(Error::Invalid("file exceeds limit".into())); } Ok(bytes) }
pub fn metadata(root: &RootGrant, path: &str) -> Result<NativeMetadata> { let fd = root_handle(root)?; let f = at(fd.as_raw_fd(), path, libc::O_RDONLY, 0, false)?; handle_metadata(&f, true) }
pub fn metadata_only(root: &RootGrant, path: &str) -> Result<NativeMetadata> { let fd = root_handle(root)?; let f = at(fd.as_raw_fd(), path, libc::O_PATH, 0, false)?; handle_metadata(&f, false) }
pub fn read(root: &RootGrant, path: &str, max: usize) -> Result<Vec<u8>> {
    if root.revoked { return Err(Error::Forbidden); }
    let fd = root_handle(root)?; let f = at(fd.as_raw_fd(), path, libc::O_RDONLY, 0, false)?;
    if handle_metadata(&f, false)?.kind != "FILE" { return Err(Error::Forbidden); }
    bounded(File::from(f), max.min(MAX_FILE))
}
pub fn entries(root: &RootGrant, path: &str) -> Result<Vec<String>> {
    let fd = root_handle(root)?; let dirfd = at(fd.as_raw_fd(), path, libc::O_RDONLY | libc::O_DIRECTORY, 0, false)?;
    let raw = unsafe { libc::dup(dirfd.as_raw_fd()) }; if raw < 0 { return Err(std::io::Error::last_os_error().into()); }
    let dir = unsafe { libc::fdopendir(raw) }; if dir.is_null() { unsafe { libc::close(raw); } return Err(std::io::Error::last_os_error().into()); }
    let mut entries = Vec::new();
    loop { let item = unsafe { libc::readdir(dir) }; if item.is_null() { break; } let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_string_lossy().into_owned(); if name != "." && name != ".." && !denied_name(&name) { entries.push(name); } }
    unsafe { libc::closedir(dir); } entries.sort(); Ok(entries)
}
#[repr(C)] struct Ruleset { handled_access_fs: u64 }
#[repr(C, packed)] struct PathRule { allowed_access: u64, parent_fd: i32 }
pub fn landlock_abi() -> Result<i32> {
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0, 1) };
    if abi < 3 { return Err(Error::SecureMutationUnavailable("Landlock ABI >=3 required".into())); } Ok(abi as i32)
}
pub fn restrict(roots: &[&OwnedFd]) -> Result<()> {
    let abi = landlock_abi()?;
    // Handle every filesystem right understood by the running ABI, granting only ordinary root I/O.
    let bits = if abi >= 9 { 17 } else if abi >= 5 { 16 } else { 15 };
    let handled = (1u64 << bits) - 1;
    let rules = io_fd(unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &Ruleset { handled_access_fs: handled }, std::mem::size_of::<Ruleset>(), 0) })?;
    let allowed = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 7) | (1 << 8) | (1 << 13) | (1 << 14);
    for root in roots { let rule = PathRule { allowed_access: allowed, parent_fd: root.as_raw_fd() }; if unsafe { libc::syscall(libc::SYS_landlock_add_rule, rules.as_raw_fd(), 1, &rule, 0) } < 0 { return Err(std::io::Error::last_os_error().into()); } }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 || unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rules.as_raw_fd(), 0) } < 0 { return Err(Error::SecureMutationUnavailable("Landlock restriction failed".into())); } Ok(())
}
fn parent(root: &OwnedFd, path: &str) -> Result<(OwnedFd, String)> { let path = normalize_path(path)?; let (p,n) = path.rsplit_once('/').unwrap_or((".", path.as_str())); Ok((at(root.as_raw_fd(), p, libc::O_RDONLY | libc::O_DIRECTORY, 0, false)?, n.into())) }
fn rename(a: &OwnedFd, an: &str, b: &OwnedFd, bn: &str, flags: u32) -> Result<()> {
    if unsafe { libc::syscall(libc::SYS_renameat2, a.as_raw_fd(), c(an)?.as_ptr(), b.as_raw_fd(), c(bn)?.as_ptr(), flags) } < 0 { return Err(std::io::Error::last_os_error().into()); } Ok(())
}
fn sync(fd: &OwnedFd) -> Result<()> { if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 { return Err(std::io::Error::last_os_error().into()); } Ok(()) }
fn open_recovery(root: &OwnedFd) -> Result<OwnedFd> {
    if unsafe { libc::mkdirat(root.as_raw_fd(), c(".orbit-recovery")?.as_ptr(), 0o700) } < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) { return Err(std::io::Error::last_os_error().into()); }
    let fd = at(root.as_raw_fd(), ".orbit-recovery", libc::O_RDONLY | libc::O_DIRECTORY, 0, true)?;
    let m = File::from(fd.try_clone()?).metadata()?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 { return Err(Error::Forbidden); } Ok(fd)
}
pub fn mutate(root: &RootGrant, destination_root: &RootGrant, request: &NativeMutation) -> Result<NativeOutcome> { mutate_journaled(root, destination_root, request, |_| Err(Error::Forbidden)) }
pub fn mutate_journaled(root: &RootGrant, destination_root: &RootGrant, request: &NativeMutation, mut before_effect: impl FnMut(serde_json::Value) -> Result<()>) -> Result<NativeOutcome> {
    if !root.namespace_protected || !destination_root.namespace_protected || root.revoked || destination_root.revoked { return Err(Error::SecureMutationUnavailable("protected namespace required".into())); }
    normalize_path(&request.destination)?;
    let r = root_handle(root)?; let d = root_handle(destination_root)?;
    // This function runs only in the fresh single-threaded worker, before opening any content handles.
    restrict(&[&r, &d])?;
    let (dp, dn) = parent(&d, &request.destination)?;
    let recovery = open_recovery(&d)?;
    let source = request.source.as_deref().map(|p| parent(&r, p)).transpose()?;
    let source_fd = source.as_ref().map(|(p,n)| at(p.as_raw_fd(), n, libc::O_RDONLY, 0, false)).transpose()?;
    let original = source_fd.as_ref().map(|f| handle_metadata(f, true)).transpose()?;
    if let Some(m) = &original { if Some(m.version()) != request.expected_version || m.digest != request.expected_digest { return Err(Error::VersionConflict); } if m.kind != "FILE" { return Err(Error::Forbidden); } }
    if request.operation != "files.write" && source_fd.is_none() { return Err(Error::Forbidden); }
    let replacement = request.operation == "files.write" && request.expected_version.is_some();
    if replacement && request.source.as_deref() != Some(request.destination.as_str()) { return Err(Error::Forbidden); }
    let stage = normalize_path(&request.stage_name)?;
    if stage.contains('/') { return Err(Error::Forbidden); }
    let proposed = if request.operation == "files.move" { None } else {
        let bytes = if request.operation == "files.copy" { bounded(File::from(source_fd.as_ref().ok_or(Error::Forbidden)?.try_clone()?), MAX_FILE)? } else { request.content.clone().ok_or(Error::Forbidden)? };
        if bytes.len() > MAX_FILE { return Err(Error::Invalid("file exceeds limit".into())); }
        if request.operation == "files.copy" && original.as_ref().and_then(|m| m.digest.as_ref()) != Some(&sha256(&bytes)) { return Err(Error::VersionConflict); }
        let stagefd = at(recovery.as_raw_fd(), &stage, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600, true)?;
        { let mut file = File::from(stagefd); file.write_all(&bytes)?; file.sync_all()?; crate::admin::apply_published_acl(file.as_raw_fd(), request.owner_uid.ok_or(Error::Forbidden)?)?; }
        let ready = at(recovery.as_raw_fd(), &stage, libc::O_RDONLY, 0, true)?;
        Some(handle_metadata(&ready, true)?)
    };
    sync(&recovery)?;
    let evidence = serde_json::json!({"source":original,"proposed":proposed,"destination":request.destination,"source_path":request.source,"stage":stage,"destination_root":destination_root.id,"source_root":root.id,"operation":request.operation,"phase":"PREPARED"});
    before_effect(evidence.clone())?;
    // Recheck identity/digest immediately before publication under parent-owned serial locks.
    if let Some((sp,sn)) = &source {
        let fresh = at(sp.as_raw_fd(), sn, libc::O_RDONLY, 0, false)?;
        if handle_metadata(&fresh, true)?.version() != original.as_ref().ok_or(Error::Forbidden)?.version() { return Err(Error::VersionConflict); }
    }
    let publication = match request.operation.as_str() {
        "files.move" => { let (sp,sn) = source.as_ref().ok_or(Error::Forbidden)?; rename(sp,sn,&dp,&dn,libc::RENAME_NOREPLACE) },
        "files.copy" | "files.write" => rename(&recovery,&stage,&dp,&dn,if replacement {libc::RENAME_EXCHANGE} else {libc::RENAME_NOREPLACE}),
        _ => return Err(Error::Unsupported),
    };
    if let Err(e) = publication { return match &e { Error::Io(io) if io.raw_os_error() == Some(libc::EXDEV) => Err(Error::Invalid("cross-filesystem move denied".into())), Error::Io(io) if io.raw_os_error() == Some(libc::EEXIST) => Err(Error::VersionConflict), _ => Err(e) }; }
    let published = at(dp.as_raw_fd(), &dn, libc::O_RDONLY, 0, false)?;
    let current = handle_metadata(&published, true)?;
    let predecessor = if replacement { Some(handle_metadata(&at(recovery.as_raw_fd(), &stage, libc::O_RDONLY, 0, true)?, true)?) } else { None };
    let target = proposed.as_ref().or(original.as_ref()).ok_or(Error::Forbidden)?;
    let proven = current.identity == target.identity && current.digest == target.digest && predecessor.as_ref().map(|p| p.digest == original.as_ref().and_then(|o| o.digest.clone())).unwrap_or(true);
    sync(&published)?; sync(&dp)?; sync(&recovery)?;
    if request.operation == "files.move" { sync(&source.as_ref().ok_or(Error::Forbidden)?.0)?; }
    Ok(NativeOutcome { outcome: if proven { "APPLIED" } else { "OUTCOME_UNKNOWN" }.into(), metadata: Some(current.clone()), recovery_reference: replacement.then(|| format!("recovery:{}:{stage}", destination_root.id)), evidence: serde_json::json!({"prepared":evidence,"published":current,"predecessor":predecessor,"phase":"PUBLISHED"}) })
}
pub fn recovery_metadata(root: &RootGrant, name: &str) -> Result<NativeMetadata> {
    let root = root_handle(root)?; if normalize_path(name)?.contains('/') { return Err(Error::Forbidden); }
    let recovery = at(root.as_raw_fd(), ".orbit-recovery", libc::O_RDONLY | libc::O_DIRECTORY, 0, true)?;
    handle_metadata(&at(recovery.as_raw_fd(), name, libc::O_RDONLY, 0, true)?, true)
}
