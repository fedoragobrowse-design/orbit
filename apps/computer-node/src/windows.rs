//! Windows native filesystem boundary. Distribution remains gated on native Windows CI.
//! No path replacement, POSIX rename flags, or relaxed file sharing are used here.
use crate::{NativeMetadata, NativeMutation, NativeOutcome};
use orbit_computer_node_protocol::{Error, Result, RootGrant, RootMode, denied_name, normalize_path, sha256};
use serde_json::{Value, json};
use std::{ffi::c_void, fs::File, io::{Read, Seek, SeekFrom, Write}, mem::size_of, os::windows::io::{AsRawHandle, FromRawHandle}, ptr};

type Handle = *mut c_void;
type Status = i32;
const READ: u32 = 1;
const WRITE: u32 = 2;
const DELETE: u32 = 0x10000;
const ATTR: u32 = 0x80;
const SYNC: u32 = 0x100000;
const DIR: u32 = 1;
const NONDIR: u32 = 0x40;
const NO_REPARSE: u32 = 0x200000;
const SYNCHRONOUS: u32 = 0x20;
const SHARE_READ: u32 = 1;
const SHARE_WRITE: u32 = 2;
const SHARE_DELETE: u32 = 4;
const OPEN: u32 = 1;
const CREATE: u32 = 2;
const OPEN_IF: u32 = 3;
const MAX: usize = 10 * 1024 * 1024;
const NO_MORE_FILES: Status = 0x80000006u32 as i32;

#[repr(C)] struct Unicode { length: u16, maximum: u16, buffer: *mut u16 }
#[repr(C)] struct Attributes { length: u32, root: Handle, name: *mut Unicode, flags: u32, security: *mut c_void, qos: *mut c_void }
#[repr(C)] #[derive(Default)] struct IoStatus { status: usize, information: usize }
#[repr(C)] #[derive(Default)] struct BasicInfo { created: i64, accessed: i64, written: i64, changed: i64, attributes: u32 }
#[repr(C)] #[derive(Default)] struct StandardInfo { allocation: i64, eof: i64, links: u32, delete_pending: u8, directory: u8 }
#[repr(C)] #[derive(Default)] struct IdInfo { volume: u64, id: [u8; 16] }
#[repr(C)] struct RenameInfo { replace: u8, root: Handle, length: u32, name: [u16; 1] }
#[repr(C)] struct VersionInfo { size: u32, major: u32, minor: u32, build: u32, platform: u32, service_pack: [u16;128] }
#[repr(C)] struct AceHeader { kind: u8, flags: u8, size: u16 }
#[repr(C)] struct AllowedAce { header: AceHeader, mask: u32, sid: u32 }
#[repr(C)] struct AclSize { count: u32, used: u32, free: u32 }

#[link(name="ntdll")]
unsafe extern "system" {
    fn NtCreateFile(handle: *mut Handle, access: u32, attrs: *mut Attributes, status: *mut IoStatus, allocation: *mut i64, file_attrs: u32, share: u32, disposition: u32, options: u32, ea: *mut c_void, ea_len: u32) -> Status;
    fn NtQueryInformationFile(handle: Handle, status: *mut IoStatus, info: *mut c_void, length: u32, class: u32) -> Status;
    fn NtSetInformationFile(handle: Handle, status: *mut IoStatus, info: *mut c_void, length: u32, class: u32) -> Status;
    fn NtQueryDirectoryFile(handle: Handle, event: Handle, apc: *mut c_void, context: *mut c_void, status: *mut IoStatus, info: *mut c_void, length: u32, class: u32, single: u8, filter: *mut Unicode, restart: u8) -> Status;
    fn RtlNtStatusToDosError(status: Status) -> u32;
    fn RtlGetVersion(version: *mut VersionInfo) -> Status;
}
#[link(name="kernel32")]
unsafe extern "system" {
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: *mut c_void, disposition: u32, flags: u32, template: Handle) -> Handle;
    fn GetFileInformationByHandleEx(handle: Handle, class: u32, info: *mut c_void, size: u32) -> i32;
    fn GetVolumeInformationByHandleW(handle: Handle, name: *mut u16, name_len: u32, serial: *mut u32, component: *mut u32, flags: *mut u32, fs: *mut u16, fs_len: u32) -> i32;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn LocalFree(memory: Handle) -> Handle;
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
}
#[link(name="advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(text: *const u16, revision: u32, descriptor: *mut *mut c_void, size: *mut u32) -> i32;
    fn GetSecurityInfo(handle: Handle, kind: u32, information: u32, owner: *mut *mut c_void, group: *mut *mut c_void, dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
    fn GetSecurityDescriptorControl(descriptor: *mut c_void, control: *mut u16, revision: *mut u32) -> i32;
    fn GetAclInformation(acl: *mut c_void, info: *mut c_void, length: u32, class: u32) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut c_void) -> i32;
    fn EqualSid(a: *mut c_void, b: *mut c_void) -> i32;
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(token: Handle, class: u32, info: *mut c_void, length: u32, required: *mut u32) -> i32;
}

fn unavailable(message: &str) -> Error { Error::SecureMutationUnavailable(message.into()) }
fn nt(status: Status) -> Result<()> {
    if status < 0 { return Err(Error::Io(std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32))); }
    Ok(())
}
fn win(ok: i32) -> Result<()> { if ok == 0 { Err(Error::Io(std::io::Error::last_os_error())) } else { Ok(()) } }
fn wide(text: &str) -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() }
struct Memory(*mut c_void);
impl Drop for Memory { fn drop(&mut self) { if !self.0.is_null() { unsafe { LocalFree(self.0); } } } }
struct NativeHandle(File);
impl NativeHandle {
    fn raw(&self) -> Handle { self.0.as_raw_handle() }
    fn query<T: Default>(&self, class: u32) -> Result<T> {
        let mut result = T::default(); let mut ios = IoStatus::default();
        nt(unsafe { NtQueryInformationFile(self.raw(), &mut ios, (&mut result as *mut T).cast(), size_of::<T>() as u32, class) })?;
        Ok(result)
    }
    fn identity(&self) -> Result<IdInfo> {
        let mut id = IdInfo::default();
        win(unsafe { GetFileInformationByHandleEx(self.raw(), 18, (&mut id as *mut IdInfo).cast(), size_of::<IdInfo>() as u32) })?;
        Ok(id)
    }
    fn canonical_name(&self) -> Result<String> {
        let mut buf = vec![0u64; 1025]; let mut ios = IoStatus::default();
        nt(unsafe { NtQueryInformationFile(self.raw(), &mut ios, buf.as_mut_ptr().cast(), (buf.len()*8) as u32, 9) })?;
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), ios.information) };
        if bytes.len() < 4 { return Err(unavailable("invalid native filename")); }
        let n = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        if n % 2 != 0 || n + 4 > bytes.len() { return Err(unavailable("invalid native filename length")); }
        let utf16: Vec<_> = bytes[4..4+n].chunks_exact(2).map(|x| u16::from_ne_bytes([x[0],x[1]])).collect();
        String::from_utf16(&utf16).map_err(|_| Error::Forbidden)
    }
    fn check(&self, directory: bool, internal: bool) -> Result<()> {
        let basic: BasicInfo = self.query(4)?; let standard: StandardInfo = self.query(5)?;
        if basic.attributes & 0x400 != 0 || standard.delete_pending != 0 || (standard.directory != 0) != directory || (!directory && standard.links != 1) { return Err(Error::Forbidden); }
        let name = self.canonical_name()?;
        if !internal && name.split('\\').filter(|x| !x.is_empty()).any(denied_name) { return Err(Error::Forbidden); }
        Ok(())
    }
    fn snapshot(&self, max: usize) -> Result<Vec<u8>> {
        self.check(false, true)?;
        let standard: StandardInfo = self.query(5)?;
        if standard.eof < 0 || standard.eof as usize > max.min(MAX) { return Err(Error::Invalid("file exceeds bounded transfer".into())); }
        let mut file = &self.0; file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(standard.eof as usize);
        file.take(max.min(MAX) as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > max.min(MAX) { return Err(Error::Invalid("file changed beyond bound".into())); }
        Ok(bytes)
    }
    fn metadata(&self) -> Result<NativeMetadata> {
        let basic: BasicInfo = self.query(4)?; let standard: StandardInfo = self.query(5)?; let id = self.identity()?;
        let directory = standard.directory != 0;
        self.check(directory, true)?;
        let digest = if directory { None } else { Some(sha256(&self.snapshot(MAX)?)) };
        // NT timestamps are 100ns since 1601; only change detection, not a claimed UTC instant.
        Ok(NativeMetadata { identity: format!("{:016x}:{}", id.volume, hex::encode(id.id)), size: standard.eof.max(0) as u64, modified_ns: i128::from(basic.written.max(basic.changed))*100, kind: if directory { "DIRECTORY" } else { "FILE" }.into(), digest })
    }
}

fn simple(name: &str, internal: bool) -> Result<()> {
    if name.is_empty() || name.encode_utf16().count() > 255 || name.contains(['/', '\\', ':', '\0']) || name == "." || name == ".." || name.ends_with(['.', ' ']) || name.chars().any(|c| c < ' ' || "<>\"|?*".contains(c)) || (!internal && denied_name(name)) { return Err(Error::Forbidden); }
    let stem = name.split('.').next().unwrap_or("").to_uppercase();
    if ["CON","PRN","AUX","NUL","CLOCK$","CONIN$","CONOUT$"].contains(&stem.as_str()) || (stem.len()==4 && (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.as_bytes()[3].is_ascii_digit()) { return Err(Error::Forbidden); }
    Ok(())
}
fn relative(path: &str) -> Result<Vec<String>> {
    let path = normalize_path(path)?;
    path.split('/').map(|x| { simple(x, false)?; Ok(x.to_string()) }).collect()
}
fn open_at(parent: &NativeHandle, name: &str, directory: bool, access: u32, share: u32, disposition: u32, internal: bool, security: *mut c_void) -> Result<NativeHandle> {
    simple(name, internal)?;
    let mut chars: Vec<u16> = name.encode_utf16().collect();
    let mut unicode = Unicode { length: (chars.len()*2) as u16, maximum: (chars.len()*2) as u16, buffer: chars.as_mut_ptr() };
    let mut attrs = Attributes { length: size_of::<Attributes>() as u32, root: parent.raw(), name: &mut unicode, flags: 0x40 | 0x1000, security, qos: ptr::null_mut() };
    let mut raw = ptr::null_mut(); let mut ios = IoStatus::default();
    nt(unsafe { NtCreateFile(&mut raw, access | ATTR | SYNC, &mut attrs, &mut ios, ptr::null_mut(), 0x80, share, disposition, NO_REPARSE | SYNCHRONOUS | if directory { DIR } else { NONDIR }, ptr::null_mut(), 0) })?;
    let handle = NativeHandle(unsafe { File::from_raw_handle(raw) });
    handle.check(directory, internal)?;
    Ok(handle)
}
fn optional_at(parent: &NativeHandle, name: &str, internal: bool) -> Result<Option<NativeHandle>> {
    match open_at(parent, name, false, READ | DELETE, SHARE_READ, OPEN, internal, ptr::null_mut()) {
        Ok(h) => Ok(Some(h)),
        Err(Error::Io(e)) if matches!(e.raw_os_error(), Some(2 | 3)) => Ok(None),
        Err(e) => Err(e),
    }
}
fn require_platform() -> Result<()> {
    let mut version = VersionInfo { size: size_of::<VersionInfo>() as u32, major: 0, minor: 0, build: 0, platform: 0, service_pack: [0;128] };
    nt(unsafe { RtlGetVersion(&mut version) }).map_err(|_| unavailable("RtlGetVersion unavailable"))?;
    if version.major < 10 || version.build < 19041 { return Err(unavailable("Windows 10 build 19041 or newer required")); }
    Ok(())
}
struct Root { chain: Vec<NativeHandle> }
impl Root {
    fn handle(&self) -> &NativeHandle { self.chain.last().unwrap() }
    fn acquire(grant: &RootGrant, mutation: bool) -> Result<Self> {
        require_platform()?;
        if grant.revoked || grant.revision <= 0 || (mutation && !matches!(grant.mode, RootMode::ReadWrite | RootMode::Ask)) { return Err(Error::Forbidden); }
        let text = grant.path.to_str().ok_or(Error::Forbidden)?;
        let bytes = text.as_bytes();
        if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" || text.contains('/') || text[3..].contains(':') { return Err(Error::Forbidden); }
        let drive = wide(&text[..3]);
        if unsafe { GetDriveTypeW(drive.as_ptr()) } != 3 { return Err(unavailable("only local fixed NTFS volumes supported")); }
        let raw = unsafe { CreateFileW(drive.as_ptr(), READ | 0x20 | ATTR | SYNC, SHARE_READ | SHARE_WRITE, ptr::null_mut(), 3, 0x02000000 | 0x00200000, ptr::null_mut()) };
        if raw as isize == -1 { return Err(Error::Io(std::io::Error::last_os_error())); }
        let handle = NativeHandle(unsafe { File::from_raw_handle(raw) }); handle.check(true, false)?;
        let mut fs = [0u16;32]; let mut flags = 0u32;
        win(unsafe { GetVolumeInformationByHandleW(handle.raw(), ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut(), &mut flags, fs.as_mut_ptr(), fs.len() as u32) })?;
        if String::from_utf16_lossy(&fs[..fs.iter().position(|x| *x==0).unwrap_or(fs.len())]) != "NTFS" || flags & 0x80000 != 0 { return Err(unavailable("local writable NTFS required")); }
        let mut root = Root { chain: vec![handle] };
        let parts: Vec<_> = text[3..].trim_end_matches('\\').split('\\').collect();
        if parts.iter().any(|p| p.is_empty()) { return Err(Error::Forbidden); }
        for p in &parts { root.chain.push(open_at(root.handle(), p, true, READ | 0x20, SHARE_READ|SHARE_WRITE, OPEN, false, ptr::null_mut())?); }
        // A whole profile exposes credential descendants even if its top-level name is benign.
        for key in ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "SYSTEMROOT"] {
            if let Ok(path) = std::env::var(key) { if text.trim_end_matches('\\').eq_ignore_ascii_case(path.trim_end_matches('\\')) { return Err(Error::Forbidden); } }
        }
        if mutation { root.audit_descendants()?; }
        Ok(root)
    }
    fn parent(&self, path: &str) -> Result<(Vec<NativeHandle>, String)> {
        let mut parts = relative(path)?; let name = parts.pop().ok_or(Error::Forbidden)?; let mut chain = Vec::new();
        for p in parts { let parent = chain.last().unwrap_or(self.handle()); chain.push(open_at(parent, &p, true, 0x20, SHARE_READ|SHARE_WRITE, OPEN, false, ptr::null_mut())?); }
        Ok((chain, name))
    }
    fn audit_descendants(&self) -> Result<()> {
        fn scan(dir: &NativeHandle, count: &mut usize, depth: usize) -> Result<()> {
            if depth > 64 { return Err(unavailable("root admission depth exceeded")); }
            for (name, directory, attrs) in directory_entries(dir)? {
                *count += 1; if *count > 100_000 { return Err(unavailable("root admission size exceeded")); }
                if name.eq_ignore_ascii_case(".orbit-recovery") { let recovery = open_at(dir, &name, true, 0x20 | 0x20000, SHARE_READ|SHARE_WRITE, OPEN, true, ptr::null_mut())?; private_directory(&recovery)?; continue; }
                simple(&name, false)?;
                if attrs & 0x400 != 0 { return Err(Error::Forbidden); }
                if directory { let child = open_at(dir, &name, true, READ|0x20, SHARE_READ|SHARE_WRITE, OPEN, false, ptr::null_mut())?; scan(&child,count,depth+1)?; }
                else { let file = open_at(dir,&name,false,ATTR,SHARE_READ|SHARE_WRITE|SHARE_DELETE,OPEN,false,ptr::null_mut())?; file.check(false,false)?; }
            }
            Ok(())
        }
        scan(self.handle(), &mut 0, 0)
    }
}
fn directory_entries(dir: &NativeHandle) -> Result<Vec<(String,bool,u32)>> {
    let mut output = Vec::new(); let mut restart = 1u8;
    loop {
        let mut buf = vec![0u64;8192]; let mut ios = IoStatus::default();
        let status = unsafe { NtQueryDirectoryFile(dir.raw(),ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),&mut ios,buf.as_mut_ptr().cast(),(buf.len()*8) as u32,1,0,ptr::null_mut(),restart) };
        restart = 0; if status == NO_MORE_FILES { break; } nt(status)?;
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(),ios.information) };
        let mut pos = 0;
        loop {
            if pos+64 > bytes.len() { return Err(unavailable("malformed native directory entry")); }
            let u32at = |n| u32::from_ne_bytes(bytes[pos+n..pos+n+4].try_into().unwrap());
            let next = u32at(0) as usize; let attrs = u32at(56); let length = u32at(60) as usize;
            if length%2!=0 || pos+64+length>bytes.len() { return Err(unavailable("malformed native directory name")); }
            let chars: Vec<_> = bytes[pos+64..pos+64+length].chunks_exact(2).map(|x| u16::from_ne_bytes([x[0],x[1]])).collect();
            let name = String::from_utf16(&chars).map_err(|_|Error::Forbidden)?;
            if name!="." && name!=".." { output.push((name,attrs&0x10!=0,attrs)); }
            if output.len()>100_000 { return Err(unavailable("directory enumeration bound exceeded")); }
            if next==0 { break; } if next<64 || pos+next>=bytes.len() { return Err(unavailable("malformed native directory offset")); } pos+=next;
        }
    }
    Ok(output)
}
fn private_descriptor() -> Result<Memory> {
    let mut sd = ptr::null_mut();
    win(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide("D:P(A;;FA;;;SY)(A;;FA;;;OW)").as_ptr(),1,&mut sd,ptr::null_mut()) })?;
    Ok(Memory(sd))
}
fn private_directory(dir: &NativeHandle) -> Result<()> {
    let mut sd = ptr::null_mut(); let mut acl = ptr::null_mut(); let mut owner = ptr::null_mut();
    let code = unsafe { GetSecurityInfo(dir.raw(),1,1|4,&mut owner,ptr::null_mut(),&mut acl,ptr::null_mut(),&mut sd) };
    if code != 0 { return Err(unavailable("cannot verify private recovery ACL")); } let _sd = Memory(sd);
    let mut control = 0u16; let mut revision = 0u32;
    win(unsafe { GetSecurityDescriptorControl(sd,&mut control,&mut revision) })?;
    if acl.is_null() || control&0x1000==0 { return Err(unavailable("recovery DACL must be protected")); }
    let mut info = AclSize { count:0,used:0,free:0 };
    win(unsafe { GetAclInformation(acl,(&mut info as *mut AclSize).cast(),size_of::<AclSize>() as u32,2) })?;
    let mut system = ptr::null_mut(); let mut rights = ptr::null_mut();
    win(unsafe { ConvertStringSidToSidW(wide("S-1-5-18").as_ptr(),&mut system) })?; let _sys=Memory(system);
    win(unsafe { ConvertStringSidToSidW(wide("S-1-3-4").as_ptr(),&mut rights) })?; let _rights=Memory(rights);
    let mut token=ptr::null_mut(); win(unsafe { OpenProcessToken(GetCurrentProcess(),8,&mut token) })?;
    let mut needed=0; unsafe { GetTokenInformation(token,1,ptr::null_mut(),0,&mut needed); }
    let mut user=vec![0usize;(needed as usize+size_of::<usize>()-1)/size_of::<usize>()];
    let ok=unsafe { GetTokenInformation(token,1,user.as_mut_ptr().cast(),needed,&mut needed) }; unsafe { CloseHandle(token); } win(ok)?;
    let current=unsafe { *(user.as_ptr().cast::<*mut c_void>()) };
    if unsafe { EqualSid(owner,current) }==0 { return Err(unavailable("recovery owner differs from node account")); }
    for n in 0..info.count {
        let mut raw=ptr::null_mut(); win(unsafe { GetAce(acl,n,&mut raw) })?;
        let ace=unsafe { &*raw.cast::<AllowedAce>() };
        let sid=unsafe { ptr::addr_of!((*raw.cast::<AllowedAce>()).sid).cast_mut().cast::<c_void>() };
        if ace.header.kind!=0 || ace.header.flags&0x10!=0 || !(unsafe { EqualSid(sid,system)!=0 || EqualSid(sid,rights)!=0 || EqualSid(sid,current)!=0 }) { return Err(unavailable("recovery DACL permits another principal")); }
    }
    if info.count==0 { return Err(unavailable("empty recovery DACL")); } Ok(())
}
fn recovery(root: &Root) -> Result<NativeHandle> {
    let sd=private_descriptor()?;
    let dir=open_at(root.handle(),".orbit-recovery",true,READ|0x20|0x20000,SHARE_READ|SHARE_WRITE,OPEN_IF,true,sd.0)?;
    private_directory(&dir)?; Ok(dir)
}
fn rename(file: &NativeHandle, destination: &NativeHandle, name: &str, internal: bool) -> Result<()> {
    simple(name,internal)?;
    if file.identity()?.volume != destination.identity()?.volume { return Err(unavailable("cross-volume mutation denied")); }
    let chars:Vec<_>=name.encode_utf16().collect();
    let length=(size_of::<RenameInfo>()+chars.len()*2) as u32;
    let mut storage=vec![0usize;(length as usize+size_of::<usize>()-1)/size_of::<usize>()];
    let info=storage.as_mut_ptr().cast::<RenameInfo>();
    unsafe { (*info).replace=0; (*info).root=destination.raw(); (*info).length=(chars.len()*2) as u32; ptr::copy_nonoverlapping(chars.as_ptr(),ptr::addr_of_mut!((*info).name).cast::<u16>(),chars.len()); }
    let mut ios=IoStatus::default();
    nt(unsafe { NtSetInformationFile(file.raw(),&mut ios,storage.as_mut_ptr().cast(),length,10) })
}
fn public_handle(root: &Root, path: &str, access: u32, share: u32) -> Result<NativeHandle> {
    let (chain,name)=root.parent(path)?; open_at(chain.last().unwrap_or(root.handle()),&name,false,access,share,OPEN,false,ptr::null_mut())
}
pub fn read(root: &RootGrant, path: &str, max: usize) -> Result<Vec<u8>> {
    let root=Root::acquire(root,false)?;
    public_handle(&root,path,READ,SHARE_READ)?.snapshot(max)
}
pub fn metadata(root: &RootGrant, path: &str) -> Result<NativeMetadata> {
    let root=Root::acquire(root,false)?;
    let (chain,name)=root.parent(path)?; let parent=chain.last().unwrap_or(root.handle());
    match open_at(parent,&name,false,READ,SHARE_READ,OPEN,false,ptr::null_mut()) {
        Ok(file)=>file.metadata(),
        Err(Error::Io(e)) if e.raw_os_error()==Some(5) || e.raw_os_error()==Some(267) => open_at(parent,&name,true,READ|0x20,SHARE_READ|SHARE_WRITE,OPEN,false,ptr::null_mut())?.metadata(),
        Err(e)=>Err(e),
    }
}
pub fn entries(root: &RootGrant, path: &str) -> Result<Vec<String>> {
    let root=Root::acquire(root,false)?;
    let mut chain=Vec::new();
    if !path.is_empty() { for name in relative(path)? { let dir=open_at(chain.last().unwrap_or(root.handle()),&name,true,READ|0x20,SHARE_READ|SHARE_WRITE,OPEN,false,ptr::null_mut())?; chain.push(dir); } }
    let mut names:Vec<_>=directory_entries(chain.last().unwrap_or(root.handle()))?.into_iter().filter_map(|(n,_,attrs)| if attrs&0x400==0 && simple(&n,false).is_ok() {Some(n)} else {None}).collect();
    names.sort_by_key(|n|n.to_lowercase()); Ok(names)
}
fn binding(source: &RootGrant, destination: &RootGrant, request: &NativeMutation) -> Result<String> {
    Ok(sha256(&serde_json::to_vec(&json!({"request":request,"root":source.id,"revision":source.revision,"destination_root":destination.id,"destination_revision":destination.revision}))?))
}
fn unknown(evidence: Value) -> NativeOutcome {
    NativeOutcome { outcome:"OUTCOME_UNKNOWN".into(),metadata:None,recovery_reference:evidence["predecessor_name"].as_str().map(|x|format!(".orbit-recovery/{x}")),evidence }
}
/// Each callback is a synchronous durable SQLite FULL commit/ack boundary, not a wake hint.
/// The IPC parent must retain evidence and serialize source-identity/destination-path locks.
pub fn mutate_journaled(root: &RootGrant, destination_root: &RootGrant, request: &NativeMutation, mut commit: impl FnMut(Value)->Result<()>) -> Result<NativeOutcome> {
    if request.action_hash.len()!=64 || !request.action_hash.bytes().all(|x|x.is_ascii_hexdigit()) || request.authorization_id.is_nil() || request.request_id.is_nil() { return Err(Error::Forbidden); }
    if !["files.write","files.copy","files.move"].contains(&request.operation.as_str()) { return Err(Error::Forbidden); }
    let source_root=Root::acquire(root,true)?; let target_root=Root::acquire(destination_root,true)?;
    if source_root.handle().identity()?.volume!=target_root.handle().identity()?.volume { return Err(unavailable("cross-volume mutation denied")); }
    let (target_chain,target_name)=target_root.parent(&request.destination)?;
    let target_parent=target_chain.last().unwrap_or(target_root.handle());
    let private=recovery(&target_root)?;
    let stage_name=format!("{}.stage",request.request_id);
    let predecessor_name=format!("{}.predecessor",request.request_id);
    // Stage names are derived from request IDs, never trusted server-provided internal paths.
    if request.stage_name!=request.request_id.to_string() && request.stage_name!=stage_name { return Err(Error::Invalid("stage name must bind request ID".into())); }
    let source_path=if request.operation=="files.write" { &request.destination } else { request.source.as_ref().ok_or_else(||Error::Invalid("source required".into()))? };
    let mut source_chain=Vec::new(); let mut source_name=String::new();
    let original=if request.expected_version.is_some() || request.operation!="files.write" {
        let (chain,name)=source_root.parent(source_path)?; source_chain=chain; source_name=name;
        Some(open_at(source_chain.last().unwrap_or(source_root.handle()),&source_name,false,READ|DELETE,SHARE_READ,OPEN,false,ptr::null_mut())?)
    } else { None };
    if request.operation=="files.write" && root.id!=destination_root.id { return Err(Error::Forbidden); }
    let base=original.as_ref().map(|h|h.metadata()).transpose()?;
    if let Some(base)=&base {
        if request.expected_version.as_deref()!=Some(base.version().as_str()) || request.expected_digest.as_deref()!=base.digest.as_deref() { return Err(Error::VersionConflict); }
    } else if request.expected_digest.is_some() { return Err(Error::VersionConflict); }
    // A held DELETE source prevents reopening it exclusively. For existing writes, original
    // itself is the target proof. All other operations prove vacancy before staging.
    if request.operation!="files.write" || original.is_none() {
        if optional_at(target_parent,&target_name,false)?.is_some() { return Err(Error::VersionConflict); }
    }
    let stage=if request.operation=="files.move" { None } else {
        let bytes=if request.operation=="files.copy" { original.as_ref().unwrap().snapshot(MAX)? } else { request.content.clone().ok_or_else(||Error::Invalid("write bytes required".into()))? };
        if bytes.len()>MAX { return Err(Error::Invalid("write exceeds 10 MiB".into())); }
        if request.operation=="files.copy" && Some(sha256(&bytes)).as_ref()!=base.as_ref().and_then(|b|b.digest.as_ref()) { return Err(Error::VersionConflict); }
        let sd=private_descriptor()?;
        let file=open_at(&private,&stage_name,false,READ|WRITE|DELETE,SHARE_READ,CREATE,true,sd.0)?;
        let mut writer=&file.0; writer.write_all(&bytes)?; file.0.sync_all()?;
        if file.snapshot(MAX)?!=bytes { return Err(unavailable("staged content validation failed")); }
        Some(file)
    };
    let proposed=stage.as_ref().or(original.as_ref()).unwrap();
    let proposed_metadata=proposed.metadata()?;
    let mut evidence=json!({"format":1,"platform":"WINDOWS_NTFS_HELD_HANDLE_V1","phase":"PREPARED","binding":binding(root,destination_root,request)?,"request_id":request.request_id,"authorization_id":request.authorization_id,"action_hash":request.action_hash,"root_id":root.id,"root_revision":root.revision,"destination_root_id":destination_root.id,"destination_revision":destination_root.revision,"source_path":source_path,"destination_path":request.destination,"source_root_identity":source_root.handle().metadata()?.identity,"destination_root_identity":target_root.handle().metadata()?.identity,"destination_parent_identity":target_parent.metadata()?.identity,"source_parent_identity":source_chain.last().unwrap_or(source_root.handle()).metadata()?.identity,"source_name":source_name,"stage_name":stage_name,"predecessor_name":if request.operation=="files.write" && original.is_some(){Some(&predecessor_name)}else{None},"original":base,"proposed":proposed_metadata});
    commit(evidence.clone())?;
    if request.operation=="files.write" {
        if let Some(original)=&original {
            // No mutation before approved version/digest have been checked under exclusive sharing.
            if original.metadata()?.version()!=evidence["original"].clone().try_into_metadata()?.version() { return Err(Error::VersionConflict); }
            rename(original,&private,&predecessor_name,true)?;
            evidence["phase"]=json!("ORIGINAL_TO_RECOVERY");
            if commit(evidence.clone()).is_err() { return Ok(unknown(evidence)); }
        }
    }
    let publication=rename(proposed,target_parent,&target_name,false);
    if let Err(error)=publication {
        if original.is_some() && request.operation=="files.write" { evidence["publication_error"]=json!(error.to_string()); let _=commit(evidence.clone()); return Ok(unknown(evidence)); }
        return Err(error);
    }
    evidence["phase"]=json!("PUBLISHED");
    if commit(evidence.clone()).is_err() { return Ok(unknown(evidence)); }
    // Query the published object through the held handle, and independently look up its name
    // with read-attribute-only access compatible with the original exclusive DELETE handle.
    let verification = (|| -> Result<NativeMetadata> {
        let observed=proposed.metadata()?;
        let named=open_at(target_parent,&target_name,false,ATTR,SHARE_READ|SHARE_WRITE|SHARE_DELETE,OPEN,false,ptr::null_mut())?;
        let id=named.identity()?;
        let named_identity=format!("{:016x}:{}",id.volume,hex::encode(id.id));
        if observed.identity!=proposed_metadata.identity || observed.digest!=proposed_metadata.digest || named_identity!=observed.identity { return Err(Error::OutcomeUnknown); }
        // FlushBuffers requires write access. The stage was flushed before publication;
        // read/delete-only original/move handles are intentionally never upgraded.
        if stage.is_some() { proposed.0.sync_all()?; }
        if let Some(original)=&original { if request.operation=="files.write" && original.metadata()?.digest!=evidence["original"]["digest"].as_str().map(str::to_owned) { return Err(Error::OutcomeUnknown); } }
        Ok(observed)
    })();
    let observed=match verification { Ok(value)=>value, Err(error)=>{ evidence["phase"]=json!("PUBLICATION_CONFLICT"); evidence["verification_error"]=json!(error.to_string()); let _=commit(evidence.clone()); return Ok(unknown(evidence)); } };
    evidence["phase"]=json!("VERIFIED"); evidence["published"]=serde_json::to_value(&observed)?;
    if commit(evidence.clone()).is_err() { return Ok(unknown(evidence)); }
    Ok(NativeOutcome { outcome:"APPLIED".into(),metadata:Some(observed),recovery_reference:if request.operation=="files.write" && original.is_some(){Some(format!(".orbit-recovery/{predecessor_name}"))}else{None},evidence })
}
trait EvidenceMetadata { fn try_into_metadata(self)->Result<NativeMetadata>; }
impl EvidenceMetadata for Value { fn try_into_metadata(self)->Result<NativeMetadata> { Ok(serde_json::from_value(self)?) } }
/// Inspection only. Never rename, recreate a stage, roll back, or replay a mutation.
/// Even VERIFIED rows must prove the currently named published identity and digest.
pub fn revalidate(root: &RootGrant, destination_root: &RootGrant, request: &NativeMutation, evidence: &Value) -> Result<NativeOutcome> {
    if evidence["binding"].as_str()!=Some(binding(root,destination_root,request)?.as_str()) { return Err(Error::VersionConflict); }
    let inspect=|| -> Result<NativeOutcome> {
        let source_root=Root::acquire(root,false)?; let target_root=Root::acquire(destination_root,false)?;
        if source_root.handle().metadata()?.identity!=evidence["source_root_identity"].as_str().ok_or(Error::OutcomeUnknown)? || target_root.handle().metadata()?.identity!=evidence["destination_root_identity"].as_str().ok_or(Error::OutcomeUnknown)? { return Err(Error::OutcomeUnknown); }
        let (chain,name)=target_root.parent(&request.destination)?; let parent=chain.last().unwrap_or(target_root.handle());
        if parent.metadata()?.identity!=evidence["destination_parent_identity"].as_str().ok_or(Error::OutcomeUnknown)? { return Err(Error::OutcomeUnknown); }
        let published=open_at(parent,&name,false,READ|DELETE,SHARE_READ,OPEN,false,ptr::null_mut())?;
        let observed=published.metadata()?; let proposed:NativeMetadata=serde_json::from_value(evidence["proposed"].clone())?;
        if observed.identity!=proposed.identity || observed.digest!=proposed.digest { return Err(Error::OutcomeUnknown); }
        if let Some(name)=evidence["predecessor_name"].as_str() {
            let private=recovery_existing(&target_root)?;
            let predecessor=open_at(&private,name,false,READ|DELETE,SHARE_READ,OPEN,true,ptr::null_mut())?.metadata()?;
            let original:NativeMetadata=serde_json::from_value(evidence["original"].clone())?;
            if predecessor.identity!=original.identity || predecessor.digest!=original.digest { return Err(Error::OutcomeUnknown); }
        }
        if request.operation=="files.move" {
            let (chain,name)=source_root.parent(request.source.as_deref().ok_or(Error::OutcomeUnknown)?)?;
            if optional_at(chain.last().unwrap_or(source_root.handle()),&name,false)?.is_some() { return Err(Error::OutcomeUnknown); }
        }
        Ok(NativeOutcome {outcome:"APPLIED".into(),metadata:Some(observed),recovery_reference:evidence["predecessor_name"].as_str().map(|n|format!(".orbit-recovery/{n}")),evidence:evidence.clone()})
    };
    match inspect() { Ok(result)=>Ok(result), Err(_)=>Ok(unknown(evidence.clone())) }
}
fn recovery_existing(root: &Root)->Result<NativeHandle> {
    let dir=open_at(root.handle(),".orbit-recovery",true,READ|0x20|0x20000,SHARE_READ|SHARE_WRITE,OPEN,true,ptr::null_mut())?;
    private_directory(&dir)?; Ok(dir)
}
#[cfg(feature="native-security")]
pub fn mutate(root:&RootGrant,destination:&RootGrant,request:&NativeMutation)->Result<NativeOutcome> {
    mutate_journaled(root,destination,request,|_|Err(unavailable("native mutations require a durable journal callback")))
}

/// ASK indexing must not read bytes or compute a content digest.
pub fn metadata_only(root: &RootGrant, path: &str) -> Result<NativeMetadata> {
    let root=Root::acquire(root,false)?;
    let (chain,name)=root.parent(path)?; let parent=chain.last().unwrap_or(root.handle());
    let handle=match open_at(parent,&name,false,ATTR,SHARE_READ|SHARE_WRITE|SHARE_DELETE,OPEN,false,ptr::null_mut()) {
        Ok(file)=>file,
        Err(Error::Io(error)) if matches!(error.raw_os_error(),Some(5|267))=>open_at(parent,&name,true,ATTR|0x20,SHARE_READ|SHARE_WRITE,OPEN,false,ptr::null_mut())?,
        Err(error)=>return Err(error),
    };
    let basic:BasicInfo=handle.query(4)?; let standard:StandardInfo=handle.query(5)?; let id=handle.identity()?;
    Ok(NativeMetadata {identity:format!("{:016x}:{}",id.volume,hex::encode(id.id)),size:standard.eof.max(0) as u64,modified_ns:i128::from(basic.written.max(basic.changed))*100,kind:if standard.directory!=0{"DIRECTORY"}else{"FILE"}.into(),digest:None})
}

/// Internal evidence is exposed only to the authenticated local recovery workflow.
pub fn recovery_metadata(root: &RootGrant, name: &str) -> Result<NativeMetadata> {
    simple(name,true)?;
    if !(name.ends_with(".stage") || name.ends_with(".predecessor")) { return Err(Error::Forbidden); }
    let root=Root::acquire(root,false)?; let private=recovery_existing(&root)?;
    open_at(&private,name,false,READ,SHARE_READ,OPEN,true,ptr::null_mut())?.metadata()
}

/// A source build is not native security proof. Advertising stays disabled until the
/// install/CI integration records an actual Windows native gate, not Linux results.
pub fn mutation_available() -> bool { false }
