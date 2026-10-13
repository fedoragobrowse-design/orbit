//! Durable bounded-context file watching for one node.
//!
//! The watcher callback only maps kernel paths to debounced drain work; the
//! transport thread owns the `Index` and all durable state. They share an
//! `mpsc` wake channel plus one `AtomicBool` overflow flag — never a database
//! handle — so the single-writer sqlite invariant from `index.rs` survives.
//!
//! Overflow semantics: a `notify` rescan/overflow notice (or an internal
//! queue overrun) marks the index gap; the next drain pass runs one bounded
//! [`Index::reconcile`] per affected root, which diffs a full scan into the
//! durable EventPush outbox and clears the gap.
use crate::index::Index;
use orbit_computer_node_protocol::{Error, Result, RootGrant};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Debounce window: coalesce bursts of kernel events per path before diffing.
pub const DEBOUNCE: Duration = Duration::from_millis(250);
/// Drained paths per pass: bounds one `observe_paths` transaction.
pub const DRAIN_CAP: usize = 512;
/// Unacked queued events retained after an overflow reconcile scan.
pub const RECONCILE_CAP: usize = 500;
/// Overflow notices coalesced per root per drain pass (one scan each).
pub const OVERFLOW_ROOT_CAP: usize = 64;

pub struct ObserveWake {
    pub root: Uuid,
    pub rel: Option<String>,
    pub overflow: bool,
}

/// Create the wake channel shared by the watcher callback and the drain pump.
pub fn wake_channel() -> (Sender<ObserveWake>, Receiver<ObserveWake>) {
    mpsc::channel()
}

/// Attach the `notify` watcher to every watched root. Called on start and on
/// every watch create/cancel so the kernel set tracks the durable table.
pub fn sync_watches(
    watcher: &mut impl notify::Watcher,
    roots: &[RootGrant],
    index: &Index,
) -> Result<()> {
    for root in roots {
        if root.revoked {
            continue;
        }
        if index.watches_for_root(root.id)?.is_empty() {
            let _ = watcher.unwatch(&root.path);
            continue;
        }
        watcher
            .watch(&root.path, notify::RecursiveMode::Recursive)
            .map_err(|_| Error::Invalid("file watch failed".into()))?;
    }
    Ok(())
}

/// Translate one `notify` event into debounced drain work. Pure path mapping:
/// no I/O, no database access; safe to call on the watcher callback thread.
pub fn route_notify_event(
    event: &notify::Event,
    roots: &[RootGrant],
    tx: &Sender<ObserveWake>,
    overflow: &AtomicBool,
) {
    use notify::event::EventKind::*;
    if event.need_rescan() {
        overflow.store(true, Ordering::SeqCst);
        for root in roots.iter().take(OVERFLOW_ROOT_CAP) {
            let _ = tx.send(ObserveWake { root: root.id, rel: None, overflow: true });
        }
        return;
    }
    if !matches!(event.kind, Any | Create(_) | Modify(_) | Remove(_) | Other) {
        return;
    }
    for path in &event.paths {
        for root in roots {
            if root.revoked {
                continue;
            }
            let Ok(rel) = path.strip_prefix(&root.path) else { continue };
            let rel = rel.to_string_lossy().replace('\\', "/");
            if rel.is_empty() {
                continue;
            }
            let _ = tx.send(ObserveWake { root: root.id, rel: Some(rel), overflow: false });
        }
    }
}

/// Drain debounced wakes into [`Index::observe_paths`] / [`Index::reconcile`].
/// Runs on the transport thread (the only `Index` writer) once per heartbeat.
pub fn drain(
    rx: &Receiver<ObserveWake>,
    roots: &HashMap<Uuid, RootGrant>,
    index: &mut Index,
    overflow: &AtomicBool,
) -> Result<()> {
    let deadline = Instant::now() + DEBOUNCE;
    let mut by_root: HashMap<Uuid, HashSet<String>> = HashMap::new();
    let mut overflows: HashSet<Uuid> = HashSet::new();
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(timeout) {
            Ok(wake) => {
                if wake.overflow {
                    overflows.insert(wake.root);
                } else if let Some(rel) = wake.rel {
                    by_root.entry(wake.root).or_default().insert(rel);
                }
            }
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    if overflow.swap(false, Ordering::SeqCst) {
        for root in roots.keys() {
            overflows.insert(*root);
        }
    }
    for (root_id, paths) in &by_root {
        let Some(root) = roots.get(root_id) else { continue };
        if overflows.contains(root_id) {
            continue;
        }
        let paths: HashSet<String> = paths.iter().take(DRAIN_CAP).cloned().collect();
        index.observe_paths(root, &paths)?;
    }
    for root_id in overflows.into_iter().take(OVERFLOW_ROOT_CAP) {
        let Some(root) = roots.get(&root_id) else { continue };
        if index.watches_for_root(root.id)?.is_empty() {
            continue;
        }
        index.reconcile(root, RECONCILE_CAP)?;
    }
    Ok(())
}
// ─── Opt-in personal desktop observation (step 8) ───
//
// Personal desktop observation is OFF by default and can only be switched on
// by an explicit local action on this machine
// ([`DesktopObserver::enable_local`]). The server may only narrow, pause or
// revoke an active observer — there is deliberately no remote-enable entry
// point, so a compromised or coercive server cannot start watching pixels.
//
// On Linux, capture flows through the XDG Desktop Portal ScreenCast
// interface: the user picks the shared window in the compositor's own
// dialog and frames arrive over PipeWire. There is no silent fallback to
// X11 capture: without a portal (or without the user's window selection)
// every poll reports [`DESKTOP_CAPTURE_UNAVAILABLE`].
//
// Privacy rules enforced on every frame before anything leaves this module:
// at most one frame per [`DESKTOP_FRAME_INTERVAL`] and only while the
// observer is locally enabled and the selected window actually changed;
// windows without a usable app/window identity are discarded;
// password-manager, authentication and secret dialogs plus user-marked
// private apps are always discarded. Raw PipeWire buffers are transient
// locals — hashed, optionally snapshotted, and dropped in the same call;
// only approved [`DesktopEvidence`] snapshots are ever returned. Nothing
// here is archived to disk.

/// Marker reported whenever a desktop frame cannot be produced because the
/// XDG Desktop Portal ScreenCast path is unsupported here. Callers must
/// surface this; silently substituting another capture backend is forbidden.
pub const DESKTOP_CAPTURE_UNAVAILABLE: &str = "DESKTOP_CAPTURE_UNAVAILABLE";
/// At most one desktop evidence frame per ten seconds, and only while the
/// observer is locally enabled and the selected window actually changed.
pub const DESKTOP_FRAME_INTERVAL: Duration = Duration::from_secs(10);
/// Raw frames larger than this are discarded outright, never truncated into
/// a corrupt snapshot and never archived: sources MUST fit their snapshots
/// inside this bound.
pub const DESKTOP_MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024;

/// App-id fragments that are never observable: password managers, auth
/// agents, login screens and lock dialogs. Matched case-insensitively.
const DENIED_APP_SUBSTRINGS: &[&str] = &[
    "keepass", "bitwarden", "1password", "lastpass", "dashlane", "enpass",
    "passbolt", "authy", "authenticator", "yubico", "keyring", "kwallet",
    "seahorse", "secret-service", "polkit", "gdm", "sddm", "greetd",
    "logind", "screensaver", "screenlock",
];
/// Window-title fragments that are never observable: secrets, credentials,
/// one-time codes and elevation prompts. Matched case-insensitively; the
/// fail-closed direction is deliberate (an over-denied title only skips a
/// frame, an under-denied one leaks a secret).
const DENIED_TITLE_SUBSTRINGS: &[&str] = &[
    "password", "passphrase", "passkey", "secret", "private key", "seed phrase",
    "recovery key", "recovery code", "otp", "one-time", "2fa", "two-factor",
    "mfa", "verification code", "sudo", "polkit", "authentication",
    "authenticate", "unlock", "sign in", "signin", "log in", "login",
];

/// Which window a frame came from. The portal reports the app id chosen in
/// the compositor picker; the title is advisory only and never trusted for
/// allow-listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowIdentity {
    pub app_id: Option<String>,
    pub title: String,
}

/// One decoded frame from the user-selected PipeWire stream. Transient by
/// construction: produced by the [`DesktopFrameSource`], filtered by
/// [`DesktopObserver::poll_frame`], then dropped in the same call. Never
/// stored, never archived, never returned to callers.
#[derive(Debug, Clone)]
pub struct RawDesktopFrame {
    pub identity: WindowIdentity,
    pub width: u32,
    pub height: u32,
    /// Decoded bytes (e.g. RGBA). Must already fit
    /// [`DESKTOP_MAX_SNAPSHOT_BYTES`]; larger frames are discarded.
    pub pixels: Vec<u8>,
}

/// An approved evidence snapshot: the only desktop pixels that may leave
/// this module. Emitted only for a locally-enabled, unpaused, unrevoked
/// observer, for a known non-denied window, at most once per
/// [`DESKTOP_FRAME_INTERVAL`], and only when the window changed.
#[derive(Debug, Clone)]
pub struct DesktopEvidence {
    pub app_id: String,
    pub title: String,
    pub width: u32,
    pub height: u32,
    /// SHA-256 hex of the snapshot bytes.
    pub digest: String,
    /// Bounded snapshot bytes carried as evidence.
    pub snapshot: Vec<u8>,
    /// Unix millis at approval time.
    pub captured_at_ms: u64,
}

impl DesktopEvidence {
    /// Small JSON summary for transport/status surfaces (never the pixels).
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "app_id": self.app_id,
            "title": self.title,
            "width": self.width,
            "height": self.height,
            "digest": self.digest,
            "bytes": self.snapshot.len(),
            "captured_at_ms": self.captured_at_ms,
        })
    }
}

/// Frame supply behind the policy layer. The default
/// [`PortalScreenCastSource`] gates on real portal availability; tests and
/// future PipeWire decoders plug in here without touching policy.
pub trait DesktopFrameSource {
    /// Whether the XDG Desktop Portal ScreenCast path exists on this machine.
    fn portal_available(&self) -> bool;
    /// Pull one frame from the user-selected window stream. `Ok(None)` means
    /// "no frame right now" (no user selection yet, or stream idle) — never
    /// an error, never a fallback capture.
    fn capture_selected_window(&mut self) -> Result<Option<RawDesktopFrame>>;
    /// Drop any selected stream. Called on local disable and server revoke.
    fn reset_stream(&mut self) {}
}

/// Session-bus socket for the current user, without shelling out.
fn session_bus_socket() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        let bus = std::path::PathBuf::from(dir).join("bus");
        if bus.is_file() {
            return Some(bus);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let bus = std::path::PathBuf::from(format!("/run/user/{}/bus", unsafe { libc::getuid() }));
        if bus.is_file() {
            return Some(bus);
        }
    }
    None
}

/// Whether `org.freedesktop.portal.Desktop` is installed for the session bus.
fn portal_service_present() -> bool {
    const SERVICE: &str = "org.freedesktop.portal.Desktop.service";
    let mut dirs: Vec<std::path::PathBuf> = vec![
        "/usr/share/dbus-1/services".into(),
        "/usr/local/share/dbus-1/services".into(),
    ];
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(std::path::PathBuf::from(home).join(".local/share/dbus-1/services"));
    }
    if let Ok(extra) = std::env::var("XDG_DATA_DIRS") {
        for dir in extra.split(':') {
            dirs.push(std::path::PathBuf::from(dir).join("dbus-1/services"));
        }
    }
    dirs.iter().any(|dir| dir.join(SERVICE).is_file())
}

/// Probe for the XDG Desktop Portal ScreenCast path. Linux-only and
/// fail-closed: anything missing (or any other OS) reports unsupported, and
/// there is deliberately no X11 fallback probe here.
pub fn portal_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        session_bus_socket().is_some() && portal_service_present()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// XDG Desktop Portal ScreenCast session plus PipeWire selected-window
/// capture. The compositor's picker is the only way a stream is selected:
/// [`note_user_selection`](PortalScreenCastSource::note_user_selection) is
/// called from the portal `Response` handler after the user picks a window,
/// and nothing else may establish a stream.
#[derive(Debug, Default)]
pub struct PortalScreenCastSource {
    /// PipeWire node id handed over by the portal after user selection.
    /// `None` = the user has not picked a window (or the stream was reset).
    selected_node: Option<u32>,
}

impl PortalScreenCastSource {
    /// Record the user-selected stream. Only the portal `Response` handler
    /// calls this, after the compositor picker closes with a selection.
    pub fn note_user_selection(&mut self, pipewire_node: u32) {
        self.selected_node = Some(pipewire_node);
    }
    /// Drop any selected stream (disable / revoke / session end).
    pub fn close_selection(&mut self) {
        self.selected_node = None;
    }
    pub fn selected_node(&self) -> Option<u32> {
        self.selected_node
    }
}

impl DesktopFrameSource for PortalScreenCastSource {
    fn portal_available(&self) -> bool {
        portal_available()
    }
    fn capture_selected_window(&mut self) -> Result<Option<RawDesktopFrame>> {
        if !portal_available() {
            return Err(Error::Invalid(format!(
                "{DESKTOP_CAPTURE_UNAVAILABLE}: no XDG Desktop Portal ScreenCast on this machine"
            )));
        }
        let Some(_node) = self.selected_node else {
            // Portal present but the user has not picked a window in the
            // compositor dialog: no frame, and never a capture taken without
            // that picker step.
            return Ok(None);
        };
        // Fail closed: pulling PipeWire buffers needs the PipeWire wire
        // client behind this seam. Report unavailable rather than fall back
        // to X11 or fabricate pixels.
        Err(Error::Invalid(format!(
            "{DESKTOP_CAPTURE_UNAVAILABLE}: PipeWire stream pull is not wired in this build"
        )))
    }
    fn reset_stream(&mut self) {
        self.close_selection();
    }
}

/// Observer lifecycle as seen by status surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopStatus {
    /// Never enabled locally, or disabled after being enabled.
    Disabled,
    /// Server revoked consent; sticky until locally acknowledged.
    Revoked,
    /// Server paused; local enable alone does not resume pixels.
    Paused,
    /// Enabled locally but no portal ScreenCast path on this machine.
    Unavailable,
    /// Enabled, unpaused, portal present: polls may emit evidence.
    Ready,
}

fn denied_app(app_id: &str) -> bool {
    let app = app_id.to_lowercase();
    DENIED_APP_SUBSTRINGS.iter().any(|denied| app.contains(denied))
}

fn denied_title(title: &str) -> bool {
    let title = title.to_lowercase();
    DENIED_TITLE_SUBSTRINGS.iter().any(|denied| title.contains(denied))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Opt-in personal desktop observer. Default OFF; only [`enable_local`](DesktopObserver::enable_local)
/// (an explicit on-machine action) starts pixels, and only
/// [`acknowledge_revocation_local`](DesktopObserver::acknowledge_revocation_local)
/// plus a fresh `enable_local` recovers from a server revoke. The server
/// surface is exactly: pause, resume (clears pause only — pixels still need
/// the local enable flag), narrow (intersect-only, never widens), revoke.
/// There is no remote-enable method by design.
#[derive(Debug)]
pub struct DesktopObserver<S = PortalScreenCastSource> {
    source: S,
    enabled_local: bool,
    server_paused: bool,
    server_revoked: bool,
    /// Server allow-list narrowing. `None` = any non-denied window; once set,
    /// updates only intersect (shrink), so the server can never broaden scope.
    narrowed_apps: Option<HashSet<String>>,
    /// Local user-marked private apps. Extra deny entries, exact match.
    private_apps: HashSet<String>,
    last_emit_at: Option<Instant>,
    last_change_key: Option<String>,
    last_identity: Option<WindowIdentity>,
}

impl<S: DesktopFrameSource> DesktopObserver<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            enabled_local: false,
            server_paused: false,
            server_revoked: false,
            narrowed_apps: None,
            private_apps: HashSet::new(),
            last_emit_at: None,
            last_change_key: None,
            last_identity: None,
        }
    }

    /// Explicit local opt-in. Refused while a server revocation is pending
    /// acknowledgement, so a revoke cannot be shrugged off by re-enabling.
    pub fn enable_local(&mut self) {
        if self.server_revoked {
            return;
        }
        self.enabled_local = true;
    }

    /// Explicit local opt-out. Also drops any selected portal stream.
    pub fn disable_local(&mut self) {
        self.enabled_local = false;
        self.source.reset_stream();
    }

    pub fn enabled(&self) -> bool {
        self.enabled_local
    }

    /// Local user marks an app private: its windows are always discarded.
    pub fn add_private_app_local(&mut self, app_id: &str) {
        let app_id = app_id.trim().to_lowercase();
        if !app_id.is_empty() {
            self.private_apps.insert(app_id);
        }
    }

    /// Local user unmarks a private app. Local-only: the server cannot call this.
    pub fn remove_private_app_local(&mut self, app_id: &str) {
        self.private_apps.remove(app_id.trim().to_lowercase().as_str());
    }

    /// Server pauses observation. Pixels stop; local state is untouched.
    pub fn apply_server_pause(&mut self) {
        self.server_paused = true;
    }

    /// Server clears a pause. This only clears the pause flag — pixels still
    /// require the local enable flag, so resume can never enable remotely.
    pub fn apply_server_resume(&mut self) {
        self.server_paused = false;
    }

    /// Server narrows the observable app scope. Intersect-only: once set, the
    /// scope can only shrink, never widen back out.
    pub fn apply_server_narrow(&mut self, apps: &[String]) {
        let incoming: HashSet<String> = apps
            .iter()
            .map(|app| app.trim().to_lowercase())
            .filter(|app| !app.is_empty())
            .collect();
        match &mut self.narrowed_apps {
            Some(current) => {
                *current = current.intersection(&incoming).cloned().collect();
            }
            None => {
                self.narrowed_apps = Some(incoming);
            }
        }
    }

    /// Server revokes consent. Sticky: stops pixels immediately, forces local
    /// off, drops the portal stream, and blocks `enable_local` until the
    /// revocation is locally acknowledged.
    pub fn apply_server_revoke(&mut self) {
        self.server_revoked = true;
        self.enabled_local = false;
        self.source.reset_stream();
    }

    /// Local acknowledgement of a server revoke. Clears the flag but leaves
    /// the observer disabled: pixels need a fresh explicit `enable_local`.
    pub fn acknowledge_revocation_local(&mut self) {
        self.server_revoked = false;
    }

    pub fn status(&self) -> DesktopStatus {
        if self.server_revoked {
            DesktopStatus::Revoked
        } else if !self.enabled_local {
            DesktopStatus::Disabled
        } else if self.server_paused {
            DesktopStatus::Paused
        } else if !self.source.portal_available() {
            DesktopStatus::Unavailable
        } else {
            DesktopStatus::Ready
        }
    }

    /// Most recent approved window identity, if any frame has been approved.
    pub fn last_identity(&self) -> Option<&WindowIdentity> {
        self.last_identity.as_ref()
    }

    fn scope_allows(&self, app_id: &str) -> bool {
        match &self.narrowed_apps {
            Some(allowed) => allowed.contains(app_id),
            None => true,
        }
    }

    /// Poll for one approved evidence snapshot. Returns `Ok(None)` while
    /// disabled, paused, revoked, rate-limited, unchanged, denied, or when
    /// the stream is idle; returns `Err(DESKTOP_CAPTURE_UNAVAILABLE)` when
    /// the portal path is unsupported. Raw frames never escape: they are
    /// filtered here and dropped in the same call.
    pub fn poll_frame(&mut self) -> Result<Option<DesktopEvidence>> {
        if self.server_revoked || !self.enabled_local || self.server_paused {
            return Ok(None);
        }
        if !self.source.portal_available() {
            return Err(Error::Invalid(format!(
                "{DESKTOP_CAPTURE_UNAVAILABLE}: desktop portal not supported on this machine"
            )));
        }
        if let Some(emitted_at) = self.last_emit_at {
            if emitted_at.elapsed() < DESKTOP_FRAME_INTERVAL {
                return Ok(None);
            }
        }
        let raw = match self.source.capture_selected_window()? {
            Some(frame) => frame,
            None => return Ok(None),
        };
        let approved = self.approve_frame(raw);
        if approved.is_some() {
            self.last_emit_at = Some(Instant::now());
        }
        Ok(approved)
    }

    /// Approve one transient raw frame into evidence, or discard it. The
    /// frame is consumed either way: approved pixels move into the snapshot,
    /// everything else falls out of scope here — unwritten, unarchived.
    fn approve_frame(&mut self, raw: RawDesktopFrame) -> Option<DesktopEvidence> {
        let app = raw
            .identity
            .app_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_lowercase);
        let title = raw.identity.title.trim().to_string();
        if app.is_none() && title.is_empty() {
            // Identity unknown: cannot prove these pixels are not a secret
            // dialog or a private app. Discard.
            return None;
        }
        match app.as_deref() {
            Some(app_id) => {
                if denied_app(app_id) || self.private_apps.contains(app_id) || !self.scope_allows(app_id) {
                    return None;
                }
            }
            None => {
                // Unidentified app under a narrowed allow-list: membership
                // cannot be proven, so the frame is discarded.
                if self.narrowed_apps.is_some() {
                    return None;
                }
            }
        }
        if denied_title(&title) {
            return None;
        }
        if raw.pixels.is_empty() || raw.pixels.len() > DESKTOP_MAX_SNAPSHOT_BYTES {
            return None;
        }
        let digest = orbit_computer_node_protocol::sha256(&raw.pixels);
        let change_key = orbit_computer_node_protocol::sha256(
            format!(
                "{}|{}|{}|{}|{digest}",
                app.as_deref().unwrap_or(""),
                title,
                raw.width,
                raw.height
            )
            .as_bytes(),
        );
        if self.last_change_key.as_deref() == Some(change_key.as_str()) {
            return None;
        }
        self.last_change_key = Some(change_key);
        self.last_identity = Some(WindowIdentity {
            app_id: raw.identity.app_id.clone(),
            title: title.clone(),
        });
        Some(DesktopEvidence {
            app_id: app.unwrap_or_default(),
            title,
            width: raw.width,
            height: raw.height,
            digest,
            snapshot: raw.pixels,
            captured_at_ms: now_ms(),
        })
    }

    #[cfg(test)]
    fn rewind_for_tests(&mut self) {
        self.last_emit_at = self.last_emit_at.map(|at| at - DESKTOP_FRAME_INTERVAL);
    }
}

impl DesktopObserver<PortalScreenCastSource> {
    /// Observer backed by the real portal ScreenCast source. Still OFF until
    /// `enable_local`.
    pub fn portal() -> Self {
        Self::new(PortalScreenCastSource::default())
    }
    /// Portal session handle: the only path to record the user's compositor
    /// picker selection.
    pub fn portal_source_mut(&mut self) -> &mut PortalScreenCastSource {
        &mut self.source
    }
}
// ─── Transport-facing desktop session facade ───
//
// Thin process-global wrappers over [`DesktopObserver`] so transport /
// status surfaces have a stable call-site API without owning pixels or
// policy. Every rule still lives in the observer: local opt-in only, at
// most one changed frame per [`DESKTOP_FRAME_INTERVAL`], denylist +
// private-app + narrowed-scope discards, transient raw frames, approved
// [`DesktopEvidence`] snapshots only.
//
// Transport MUST NOT call [`desktop_start`] on server instruction: it is
// the local-action entry point (local admin/CLI path). Server directives
// travel only through pause / narrow / revoke on the observer. The portal
// compositor picker is the sole stream selector; `window` below is only a
// local display label until real portal ids wire in.

/// MIME label for [`DesktopFrame::bytes`] (raw RGBA8 until a PipeWire
/// decoder lands behind [`DesktopFrameSource`]).
pub const DESKTOP_FRAME_MIME: &str = "application/x-orbit-desktop-raw";

/// Established desktop session handle. `window_id` is the portal-selected
/// window label (requested hint echoed back until real portal ids land);
/// `app_id` is empty until the first approved frame identifies the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSession {
    pub window_id: String,
    pub app_id: String,
}

/// Approved transport frame: converted from [`DesktopEvidence`], never from
/// raw pixels. `None` from [`desktop_poll_frame`] means not running,
/// denied, discarded, unchanged, or rate-limited — never an error.
#[derive(Debug, Clone)]
pub struct DesktopFrame {
    pub window_id: String,
    pub app_id: String,
    pub captured_at: chrono::DateTime<chrono::Utc>,
    pub mime_type: String,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl From<DesktopEvidence> for DesktopFrame {
    fn from(evidence: DesktopEvidence) -> Self {
        let window_id = if evidence.title.is_empty() {
            evidence.app_id.clone()
        } else {
            evidence.title.clone()
        };
        Self {
            window_id,
            app_id: evidence.app_id,
            captured_at: chrono::DateTime::from_timestamp_millis(evidence.captured_at_ms as i64)
                .unwrap_or_else(chrono::Utc::now),
            mime_type: DESKTOP_FRAME_MIME.into(),
            sha256: evidence.digest,
            bytes: evidence.snapshot,
        }
    }
}

struct DesktopCaptureState {
    observer: DesktopObserver<PortalScreenCastSource>,
    session: Option<DesktopSession>,
    permission_denied: bool,
}

static DESKTOP_STATE: std::sync::LazyLock<std::sync::Mutex<DesktopCaptureState>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(DesktopCaptureState {
            observer: DesktopObserver::portal(),
            session: None,
            permission_denied: false,
        })
    });

fn desktop_state() -> &'static std::sync::Mutex<DesktopCaptureState> {
    &DESKTOP_STATE
}

/// Whether the portal ScreenCast path is reachable. No side effects.
pub fn desktop_supported() -> bool {
    portal_available()
}

/// Establish a local desktop session. Local-action entry point only —
/// transport MUST NOT call this on server instruction. Clears a sticky
/// denial (fresh user prompt) and enables the observer locally. Errors with
/// [`DESKTOP_CAPTURE_UNAVAILABLE`] where the portal is unsupported; never
/// falls back to another backend.
pub fn desktop_start(window: Option<&str>) -> Result<DesktopSession> {
    if !portal_available() {
        return Err(Error::Invalid(format!(
            "{DESKTOP_CAPTURE_UNAVAILABLE}: desktop portal not supported on this machine"
        )));
    }
    let label = window.map(str::trim).filter(|hint| !hint.is_empty()).unwrap_or("portal-selected");
    let mut state = desktop_state().lock().expect("desktop state");
    state.permission_denied = false;
    state.observer.enable_local();
    let session = DesktopSession { window_id: label.into(), app_id: String::new() };
    state.session = Some(session.clone());
    Ok(session)
}

/// Halt observation immediately. Idempotent: safe with no active session.
pub fn desktop_stop() {
    let mut state = desktop_state().lock().expect("desktop state");
    state.observer.disable_local();
    state.session = None;
}

/// Whether a locally-started session is active (enabled, unpaused,
/// unrevoked). Selection alone never counts: the observer must be enabled.
pub fn desktop_active() -> bool {
    let state = desktop_state().lock().expect("desktop state");
    state.session.is_some() && state.observer.enabled() && matches!(
        state.observer.status(),
        DesktopStatus::Ready | DesktopStatus::Unavailable
    )
}

/// Sticky portal-denial flag for status surfaces. Set when the user denies
/// the compositor picker; cleared only by a fresh local [`desktop_start`]
/// or [`desktop_clear_permission_denied_local`]. The server cannot clear it.
pub fn desktop_permission_denied() -> bool {
    desktop_state().lock().expect("desktop state").permission_denied
}

/// Record the user's portal-picker denial (called from the portal
/// `Response` handler on cancel/deny). Stops pixels and drops the session;
/// re-enable needs a fresh local [`desktop_start`].
pub fn desktop_note_permission_denied() {
    let mut state = desktop_state().lock().expect("desktop state");
    state.permission_denied = true;
    state.observer.disable_local();
    state.session = None;
}

/// Local-only clear of the sticky denial without starting a session.
pub fn desktop_clear_permission_denied_local() {
    desktop_state().lock().expect("desktop state").permission_denied = false;
}
/// Observer status for status surfaces. Thin read of the process-global
/// observer; no policy here.
pub fn desktop_status() -> DesktopStatus {
    desktop_state().lock().expect("desktop state").observer.status()
}

/// Server pause directive: pixels stop, local state untouched. Never enables.
pub fn desktop_apply_server_pause() {
    desktop_state().lock().expect("desktop state").observer.apply_server_pause();
}

/// Server resume directive: clears the pause flag only. Pixels still require
/// the local enable flag, so this can never enable remotely.
pub fn desktop_apply_server_resume() {
    desktop_state().lock().expect("desktop state").observer.apply_server_resume();
}

/// Server narrow directive: intersect-only scope shrink. Never widens.
pub fn desktop_apply_server_narrow(apps: &[String]) {
    desktop_state().lock().expect("desktop state").observer.apply_server_narrow(apps);
}

/// Server revoke directive: sticky, forces local off, drops the stream.
pub fn desktop_apply_server_revoke() {
    desktop_state().lock().expect("desktop state").observer.apply_server_revoke();
}

/// Local acknowledgement of a server revoke. Leaves the observer disabled:
/// pixels need a fresh explicit local start.
pub fn desktop_acknowledge_revocation_local() {
    desktop_state().lock().expect("desktop state").observer.acknowledge_revocation_local();
}

/// Poll one approved frame, or `None` when not running, denied, discarded,
/// unchanged, or rate-limited (max one per [`DESKTOP_FRAME_INTERVAL`]).
/// Raw frames never escape: filtering happens inside the observer and the
/// transient buffer is dropped in the same call.
pub fn desktop_poll_frame() -> Option<DesktopFrame> {
    let mut state = desktop_state().lock().expect("desktop state");
    if state.permission_denied {
        return None;
    }
    let evidence = state.observer.poll_frame().ok()??;
    if let Some(session) = state.session.as_mut() {
        if session.app_id.is_empty() {
            session.app_id = evidence.app_id.clone();
        }
    }
    Some(DesktopFrame::from(evidence))
}


#[cfg(test)]
mod desktop_tests {
    use super::*;
    use std::collections::VecDeque;

    struct FakeSource {
        available: bool,
        frames: VecDeque<RawDesktopFrame>,
    }

    impl DesktopFrameSource for FakeSource {
        fn portal_available(&self) -> bool {
            self.available
        }
        fn capture_selected_window(&mut self) -> Result<Option<RawDesktopFrame>> {
            Ok(self.frames.pop_front())
        }
    }

    fn raw(app: Option<&str>, title: &str, seed: u8) -> RawDesktopFrame {
        RawDesktopFrame {
            identity: WindowIdentity { app_id: app.map(str::to_string), title: title.into() },
            width: 16,
            height: 16,
            pixels: vec![seed; 64],
        }
    }

    fn enabled(frames: Vec<RawDesktopFrame>) -> DesktopObserver<FakeSource> {
        let mut observer = DesktopObserver::new(FakeSource { available: true, frames: frames.into() });
        observer.enable_local();
        observer
    }

    #[test]
    fn default_off_emits_nothing() {
        let mut observer =
            DesktopObserver::new(FakeSource { available: true, frames: vec![raw(Some("app"), "win", 1)].into() });
        assert_eq!(observer.status(), DesktopStatus::Disabled);
        assert!(observer.poll_frame().expect("disabled polls cleanly").is_none());
    }

    #[test]
    fn server_directives_never_enable() {
        let mut observer =
            DesktopObserver::new(FakeSource { available: true, frames: VecDeque::new() });
        observer.apply_server_resume();
        observer.apply_server_narrow(&["anything".to_string()]);
        observer.apply_server_pause();
        observer.apply_server_resume();
        assert_eq!(observer.status(), DesktopStatus::Disabled);
        assert!(observer.poll_frame().expect("disabled polls cleanly").is_none());
    }

    #[test]
    fn second_frame_within_interval_is_rate_limited() {
        let mut observer = enabled(vec![raw(Some("app"), "a", 1), raw(Some("app"), "b", 2)]);
        assert!(observer.poll_frame().expect("first changed frame emits").is_some());
        // Digests differ, so only the 10s rate gate can explain a skip here.
        assert!(observer.poll_frame().expect("rate gate holds").is_none());
    }

    #[test]
    fn unchanged_window_suppressed_changed_window_emits() {
        let mut observer = enabled(vec![
            raw(Some("app"), "a", 1),
            raw(Some("app"), "a", 1),
            raw(Some("app"), "a", 2),
        ]);
        assert!(observer.poll_frame().expect("first frame emits").is_some());
        observer.rewind_for_tests();
        assert!(observer.poll_frame().expect("identical frame suppressed").is_none());
        observer.rewind_for_tests();
        assert!(observer.poll_frame().expect("changed frame emits").is_some());
    }

    #[test]
    fn secrets_unknown_and_private_apps_discarded() {
        let mut observer = enabled(vec![
            raw(Some("org.keepassxc.KeePassXC"), "KeePassXC", 1),
            raw(Some("firefox"), "Enter sudo password", 2),
            raw(None, "", 3),
            raw(Some("diary"), "dear diary", 4),
            raw(Some("firefox"), "Orbit notes", 5),
        ]);
        observer.add_private_app_local("diary");
        for _ in 0..4 {
            observer.rewind_for_tests();
            assert!(observer.poll_frame().expect("denied frame discarded").is_none());
        }
        observer.rewind_for_tests();
        let evidence = observer.poll_frame().expect("clean frame").expect("clean frame emits");
        assert_eq!(evidence.app_id, "firefox");
        assert_eq!(observer.last_identity().expect("identity tracked").app_id.as_deref(), Some("firefox"));
    }

    #[test]
    fn unsupported_portal_reports_unavailable() {
        let mut observer =
            DesktopObserver::new(FakeSource { available: false, frames: VecDeque::new() });
        observer.enable_local();
        assert_eq!(observer.status(), DesktopStatus::Unavailable);
        let error = observer.poll_frame().expect_err("unsupported portal must error");
        assert!(error.to_string().contains(DESKTOP_CAPTURE_UNAVAILABLE), "unexpected: {error}");
    }

    #[test]
    fn server_narrow_never_widens() {
        let mut observer = enabled(vec![raw(Some("b"), "win", 9), raw(Some("a"), "win", 8)]);
        observer.apply_server_narrow(&["a".to_string()]);
        observer.apply_server_narrow(&["a".to_string(), "b".to_string()]);
        observer.rewind_for_tests();
        assert!(observer.poll_frame().expect("poll cleanly").is_none(), "b must stay out of scope");
        observer.rewind_for_tests();
        assert!(observer.poll_frame().expect("poll cleanly").is_some(), "a stays in scope");
    }

    #[test]
    fn server_revoke_is_sticky() {
        let mut observer = enabled(vec![]);
        observer.apply_server_revoke();
        assert_eq!(observer.status(), DesktopStatus::Revoked);
        assert!(observer.poll_frame().expect("revoked polls cleanly").is_none());
        observer.enable_local();
        assert_eq!(observer.status(), DesktopStatus::Revoked, "re-enable refused while revoked");
        observer.acknowledge_revocation_local();
        assert_eq!(observer.status(), DesktopStatus::Disabled, "acknowledgement leaves observer off");
        observer.enable_local();
        assert_eq!(observer.status(), DesktopStatus::Ready);
    }
}

