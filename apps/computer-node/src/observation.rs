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

