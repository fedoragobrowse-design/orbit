//! Outbound node transport.
//!
//! The node never listens on a network port and never accepts an inbound
//! connection. It dials the owner's server over verified TLS, answers the
//! server's nonce with its Ed25519 identity, and then exchanges the versioned
//! envelope from `crates/computer-node-protocol`.
//!
//! Grants stay local authority: the server may narrow or revoke a root over the
//! wire, but only a deliberate `roots add` on this machine may broaden one. A
//! reduced or revoked root takes effect on the next dispatch and its local index
//! material is purged.
use crate::{NativeMutation, index::Index, native, observation};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use orbit_computer_node_protocol::{
    Capabilities, Challenge, Envelope, Error, ExecutionRequest, FileEvent, MAX_FILE, MAX_PAGE,
    MAX_TEXT, MessageType, NodeConfig, PublicRoot, Result, RootGrant, RootMode, normalize_path,
    sign_challenge,
};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest},
};

/// Server endpoint the node dials. Outbound only; the server never dials the node.
pub const CONNECT_PATH: &str = "/api/v1/computers/connect";
/// Spec'd liveness interval. The server marks a node disconnected after 60 seconds.
pub const HEARTBEAT: Duration = Duration::from_secs(20);
const BACKOFF_BASE_MS: u64 = 500;
const BACKOFF_CEILING_MS: u64 = 60_000;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A node instance: identity, local index and the server it talks to.
pub struct Node {
    pub config: NodeConfig,
    key: SigningKey,
    index: Index,
    watch_tx: std::sync::mpsc::Sender<observation::ObserveWake>,
    watch_rx: std::sync::mpsc::Receiver<observation::ObserveWake>,
    watch_overflow: std::sync::Arc<std::sync::atomic::AtomicBool>,
    watcher: Option<notify::RecommendedWatcher>,
}

impl Node {
    pub fn open(config: NodeConfig) -> Result<Self> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let raw = STANDARD
            .decode(config.identity_key.as_bytes())
            .map_err(|_| Error::Forbidden)?;
        let key = SigningKey::from_bytes(
            &<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| Error::Forbidden)?,
        );
        std::fs::create_dir_all(&config.state_dir)?;
        let index = Index::open(&config.state_dir.join("index.sqlite"))?;
        let (watch_tx, watch_rx) = observation::wake_channel();
        let mut node = Self { config, key, index, watch_tx, watch_rx, watch_overflow: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)), watcher: None };
        node.restore_watches()?;
        Ok(node)
    }

    pub fn save(&self) -> Result<()> {
        write_config(&self.config)
    }

    /// Reconnect with capped exponential backoff and jitter. A node that cannot
    /// reach its server stays up and keeps retrying instead of exiting.
    pub async fn run(mut self) -> Result<()> {
        let tls = tls_config(self.config.ca_file.as_deref())?;
        self.index.recover(&self.config.roots)?;
        let mut attempt: u32 = 0;
        loop {
            match self.session(&tls).await {
                Ok(()) => attempt = 0,
                Err(error) => tracing::warn!(%error, "node session ended"),
            }
            attempt = attempt.saturating_add(1);
            let ceiling =
                BACKOFF_CEILING_MS.min(BACKOFF_BASE_MS * 2u64.saturating_pow(attempt.min(7)));
            let delay = rand::Rng::gen_range(&mut rand::thread_rng(), ceiling / 2..=ceiling);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }

    async fn session(&mut self, tls: &Arc<rustls::ClientConfig>) -> Result<()> {
        let config = self.config.clone();
        let (host, prefix, port) = split_server(&config.server)?;
        let url = format!("wss://{host}:{port}{prefix}{CONNECT_PATH}");
        let request = url
            .into_client_request()
            .map_err(|_| Error::Invalid("connect endpoint".into()))?;
        let (mut socket, _) = connect_async_tls_with_config(
            request,
            None,
            true,
            Some(Connector::Rustls(tls.clone())),
        )
        .await
        .map_err(|_| Error::Io(std::io::Error::other("server connect failed")))?;

        self.send(&mut socket, MessageType::Register, json!({
            "node_id": config.node_id,
            "identity_key": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.key.verifying_key().to_bytes()),
            "protocol_version": orbit_computer_node_protocol::VERSION,
            "capabilities": self.capabilities(),
        }))
        .await?;

        // The server answers REGISTER with a nonce bound to this node and session.
        let challenge: Challenge =
            serde_json::from_value(self.expect(&mut socket, MessageType::Challenge).await?)?;
        if challenge.node_id != config.node_id || challenge.expires_at <= Utc::now() {
            return Err(Error::Forbidden);
        }
        let signature = sign_challenge(&self.key, &challenge)?;
        self.send(
            &mut socket,
            MessageType::Authenticate,
            json!({
                "node_id": config.node_id,
                "session": config.session,
                "nonce": challenge.nonce,
                "session_hash": challenge.session_hash,
                "signature": signature,
            }),
        )
        .await?;

        let mut heartbeat = tokio::time::interval(HEARTBEAT);
        heartbeat.tick().await;
        loop {
            tokio::select! {
                incoming = socket.next() => {
                    let Some(incoming)=incoming else { return Ok(()); };
                    let incoming = incoming.map_err(|_| Error::Io(std::io::Error::other("server connection lost")))?;
                    match incoming {
                        Message::Text(text) => {
                            let envelope: Envelope = serde_json::from_str(&text)?;
                            envelope.validate(config.node_id)?;
                            if envelope.message_type == MessageType::Ack {
                                if let Some(sequence)=envelope.payload["sequence"].as_i64() { self.index.ack(sequence)?; }
                                continue;
                            }
                            let response = match self.route(&envelope) {
                                Ok(payload) => json!({"request_id":envelope.request_id,"ok":true,"payload":payload}),
                                Err(error) => json!({"request_id":envelope.request_id,"ok":false,"error":error_code(&error),"message":error.to_string()}),
                            };
                            self.send(&mut socket, MessageType::Response, response).await?;
                        }
                        Message::Close(_) => return Ok(()),
                        Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.map_err(|_| Error::Io(std::io::Error::other("server connection lost")))?,
                        _ => {}
                    }
                }
                _ = heartbeat.tick() => {
                    let roots: std::collections::HashMap<uuid::Uuid, RootGrant> = self.config.roots.iter().filter(|r|!r.revoked).map(|r|(r.id,r.clone())).collect();
                    observation::drain(&self.watch_rx, &roots, &mut self.index, &self.watch_overflow)?;
                    let pending = self.index.pending_events()?;
                    if !pending.is_empty() {
                        let events: Vec<Value> = serde_json::to_value(&pending)?.as_array().cloned().unwrap_or_default();
                        self.send(&mut socket, MessageType::EventPush, json!({"events":events})).await?;
                    } else {
                        self.send(&mut socket, MessageType::Heartbeat, json!({"node_id":config.node_id,"pending_events":0})).await?;
                    }
                }
            }
        }
    }

    async fn send(
        &self,
        socket: &mut Socket,
        message_type: MessageType,
        payload: Value,
    ) -> Result<()> {
        let envelope = Envelope::new(self.config.node_id, message_type, payload);
        let frame = serde_json::to_string(&envelope)?;
        if frame.len() > orbit_computer_node_protocol::MAX_FRAME {
            return Err(Error::Invalid("outgoing frame exceeds bound".into()));
        }
        socket
            .send(Message::Text(frame.into()))
            .await
            .map_err(|_| Error::Io(std::io::Error::other("server connection lost")))
    }

    async fn expect(&self, socket: &mut Socket, expected: MessageType) -> Result<Value> {
        let mut frames = 0u32;
        loop {
            frames += 1;
            if frames > 8 {
                return Err(Error::Invalid("server handshake exceeded bound".into()));
            }
            let Some(incoming) = socket.next().await else {
                return Err(Error::Io(std::io::Error::other(
                    "server closed the connection",
                )));
            };
            let incoming =
                incoming.map_err(|_| Error::Io(std::io::Error::other("server connection lost")))?;
            if let Message::Text(text) = incoming {
                let envelope: Envelope = serde_json::from_str(&text)?;
                envelope.validate(self.config.node_id)?;
                if envelope.message_type == expected {
                    return Ok(envelope.payload);
                }
            }
        }
    }

    /// Exact operations this node performs, its real root grants and their revisions.
    pub fn capabilities(&self) -> Capabilities {
        let roots: Vec<PublicRoot> = self
            .config
            .roots
            .iter()
            .filter(|root| !root.revoked)
            .map(|root| PublicRoot {
                id: root.id,
                // The server never learns where a root lives, so the label is a
                // stable local handle rather than the owner's path.
                display_name: format!(
                    "root-{}",
                    root.id
                        .simple()
                        .to_string()
                        .chars()
                        .take(8)
                        .collect::<String>()
                ),
                mode: root.mode,
                revision: root.revision,
                mutation_available: mutation_available(root),
                index_status: self.index.status(root.id).unwrap_or_default(),
            })
            .collect();
        let mut operations = vec![
            "files.list".to_owned(),
            "files.search".to_owned(),
            "files.read".to_owned(),
            "files.metadata".to_owned(),
            "files.watch".to_owned(),
        ];
        if roots.iter().any(|root| root.mutation_available) {
            operations.extend([
                "files.write".to_owned(),
                "files.move".to_owned(),
                "files.copy".to_owned(),
            ]);
        }
        Capabilities {
            semantic_available: self.config.embedding.is_some(),
            operations,
            native_mutation_proof: "openat2+renameat2-noreplace+landlock".into(),
            roots,
        }
    }

    fn route(&mut self, envelope: &Envelope) -> Result<Value> {
        match envelope.message_type {
            MessageType::Heartbeat => Ok(
                json!({"node_id":self.config.node_id,"server_time":Utc::now(),"pending_events":self.index.pending_events()?.len()}),
            ),
            MessageType::Capabilities => Ok(serde_json::to_value(self.capabilities())?),
            MessageType::FileList
            | MessageType::FileSearch
            | MessageType::FileRead
            | MessageType::FileMetadata
            | MessageType::FileWatch => self.files(envelope),
            MessageType::FileWrite | MessageType::FileMove | MessageType::FileCopy => {
                self.mutate(envelope)
            }
            // Legacy rejection-only values: old peers' browser frames decode but are
            // refused as unsupported (managed browser tools live server-side now).
            MessageType::BrowserNavigate | MessageType::BrowserFillSubmit => Err(Error::Unsupported),
            MessageType::Revoke => self.revoke(&envelope.payload),
            other => Err(Error::Invalid(format!(
                "unsupported message type {}",
                label(other)
            ))),
        }
    }

    fn files(&mut self, envelope: &Envelope) -> Result<Value> {
        let request: ExecutionRequest = serde_json::from_value(envelope.payload.clone())?;
        let (tool, arguments) = request.validate(&self.config)?;
        let root = self.root(arguments["root_id"].as_str())?;
        request.check_root(&root, false, tool == "files.read")?;
        match tool {
            // The listing prefix is normalized like every other path, so a
            // traversal segment is refused instead of silently listing nothing.
            "files.list" => {
                let dir = match arguments["relative_path"].as_str() {
                    None | Some("") | Some(".") => String::new(),
                    Some(path) => normalize_path(path)?,
                };
                self.index.list(
                    root.id,
                    if dir.is_empty() { "." } else { dir.as_str() },
                    arguments["cursor"].as_str(),
                    bound(arguments["limit"].as_u64(), MAX_PAGE),
                )
            }
            "files.search" => {
                let query = arguments["query"]
                    .as_str()
                    .ok_or(Error::Invalid("search query required".into()))?;
                let mode = arguments["mode"].as_str().unwrap_or("FILENAME");
                let roots: Vec<uuid::Uuid> = match arguments["root_ids"].as_array() {
                    Some(ids) => ids
                        .iter()
                        .filter_map(|id| id.as_str())
                        .filter_map(|id| uuid::Uuid::parse_str(id).ok())
                        .map(|id| self.root(Some(&id.to_string())).map(|root| root.id))
                        .collect::<Result<Vec<_>>>()?,
                    None => vec![root.id],
                };
                self.index.search(
                    &roots,
                    query,
                    mode,
                    bound(arguments["limit"].as_u64(), MAX_PAGE),
                )
            }
            "files.read" => {
                let path = normalize_path(
                    arguments["relative_path"]
                        .as_str()
                        .ok_or(Error::Invalid("relative path required".into()))?,
                )?;
                let metadata = native::metadata(&root, &path)?;
                if metadata.kind != "FILE" {
                    return Err(Error::Invalid("not a file".into()));
                }
                let bytes = native::read(&root, &path, MAX_FILE)?;
                let digest = metadata.digest.clone().ok_or(Error::Forbidden)?;
                if orbit_computer_node_protocol::sha256(&bytes) != digest {
                    return Err(Error::VersionConflict);
                }
                // Node file content is PRIVATE and untrusted; it is never model instruction.
                Ok(json!({
                    "root_id":root.id,"relative_path":path,"version":metadata.version(),"sha256":digest,"size":bytes.len(),
                    "mime_type":"application/octet-stream","privacy_class":"PRIVATE","trust_level":"UNTRUSTED_EXTERNAL",
                    "content_base64":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,&bytes),
                    "text_preview":String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_TEXT)]).chars().take(4096).collect::<String>(),
                }))
            }
            "files.metadata" => {
                let path = normalize_path(
                    arguments["relative_path"]
                        .as_str()
                        .ok_or(Error::Invalid("relative path required".into()))?,
                )?;
                let metadata = native::metadata(&root, &path)?;
                Ok(
                    json!({"root_id":root.id,"relative_path":path,"kind":metadata.kind,"size":metadata.size,"version":metadata.version(),"sha256":metadata.digest,"privacy_class":"PRIVATE"}),
                )
            }
            "files.watch" => {
                // Watch activation: the watched path is validated against the
                // authorized root grant, persisted to the durable watches
                // table, and attached to the kernel watcher. Renewing an
                // identical registration returns the same id (idempotent); a
                // `cancel:true` argument removes it and returns its last state.
                let path = match arguments["relative_path"].as_str() {
                    None | Some("") | Some(".") => String::new(),
                    Some(p) => normalize_path(p)?,
                };
                if !path.is_empty() {
                    let probe = if root.mode == RootMode::Ask { native::metadata_only(&root, &path) } else { native::metadata(&root, &path) };
                    // A watch target must exist and stay inside the grant; a
                    // vanished path reports FORBIDDEN like any other stale read.
                    probe.map_err(|_| Error::Forbidden)?;
                }
                if arguments["cancel"].as_bool() == Some(true) {
                    let id = arguments["watch_id"].as_str().ok_or(Error::Invalid("watch id required".into()))?;
                    let prior = self.index.watch(id)?.filter(|w|w.root == root.id).ok_or(Error::Forbidden)?;
                    self.index.cancel_watch(id)?;
                    self.sync_watcher()?;
                    return Ok(json!({"watch_id": id, "status": "CANCELLED", "root_id": prior.root, "relative_path": prior.path}));
                }
                let types = match arguments["types"].as_array() {
                    Some(list) => list.iter().filter_map(|t|t.as_str()).map(str::to_owned).collect::<Vec<_>>(),
                    None => crate::index::WATCH_TYPES.iter().map(|s|s.to_string()).collect::<Vec<_>>(),
                };
                let existing = self.index.watches_for_root(root.id)?.into_iter().find(|w|w.path == path && w.types == types);
                let row = match existing {
                    Some(row) => row,
                    None => { let row = self.index.create_watch(root.id, &path, types)?; self.sync_watcher()?; row }
                };
                // An initial scan diff feeds pre-existing files into the EventPush
                // outbox; without it a watch would miss everything already there.
                let status = if path.is_empty() { self.index.scan(&root)? } else {
                    let mut set = std::collections::HashSet::new(); set.insert(path.clone());
                    self.index.observe_paths(&root, &set)?
                };
                let pending = self.index.pending_events()?.len();
                Ok(json!({"watch_id": row.id, "status": if status.gap {"GAP"} else {"ACTIVE"}, "root_id": row.root, "relative_path": row.path, "types": row.types, "pending_events": pending}))
            }
            _ => Err(Error::Unsupported),
        }
    }

    fn mutate(&mut self, envelope: &Envelope) -> Result<Value> {
        let request: ExecutionRequest = serde_json::from_value(envelope.payload.clone())?;
        let (tool, arguments) = request.validate(&self.config)?;
        let root = self.root(arguments["root_id"].as_str())?;
        request.check_root(&root, true, true)?;
        let mutation: NativeMutation = serde_json::from_value(arguments["mutation"].clone())?;
        // The effect is bound to this request ID and to the immutable action hash.
        if mutation.request_id != envelope.request_id || mutation.action_hash != request.action_hash
        {
            return Err(Error::Forbidden);
        }
        if mutation.operation != tool {
            return Err(Error::Forbidden);
        }
        if !mutation_available(&root) {
            return Err(Error::SecureMutationUnavailable(
                "root is not a protected mutation tree".into(),
            ));
        }
        let destination = self.root(arguments["destination_root"].as_str())?;
        let id = envelope.request_id;
        // A duplicate returns the durably proved prior result, or admits the effect
        // outcome is unknown. It never performs a second effect.
        if let Some(prior) = self.index.journal_begin(
            id,
            &request.action_hash,
            request.authorization_id,
            &envelope.payload,
        )? {
            return Ok(json!({"outcome":"REPLAYED","prior":prior}));
        }
        let index = &self.index;
        let outcome = native::mutate_journaled(&root, &destination, &mutation, |evidence| {
            index.prepared(id, &evidence)
        })?;
        let result = serde_json::to_value(&outcome)?;
        self.index.finish(id, &result)?;
        Ok(result)
    }

    /// The server may revoke or narrow a root immediately. It may never broaden
    /// one: a wider grant stays pending until the owner runs `roots add` here.
    pub fn revoke(&mut self, envelope: &Value) -> Result<Value> {
        let id = uuid::Uuid::parse_str(envelope["root_id"].as_str().ok_or(Error::Forbidden)?)
            .map_err(|_| Error::Forbidden)?;
        let revoked = envelope["revoked"].as_bool().unwrap_or(true);
        let root = self
            .config
            .roots
            .iter_mut()
            .find(|root| root.id == id)
            .ok_or(Error::Forbidden)?;
        if let Some(mode) = envelope["mode"].as_str() {
            let requested = match mode {
                "READ" => RootMode::Read,
                "READ_WRITE" => RootMode::ReadWrite,
                "ASK" => RootMode::Ask,
                _ => return Err(Error::Invalid("unknown root mode".into())),
            };
            let wider = |local: RootMode, asked: RootMode| {
                (local == RootMode::Read && asked != RootMode::Read)
                    || (local == RootMode::Ask && asked == RootMode::ReadWrite)
            };
            if wider(root.mode, requested) {
                return Err(Error::Forbidden);
            }
            root.mode = requested;
        }
        if let Some(revision) = envelope["revision"].as_i64() {
            if revision < root.revision {
                return Err(Error::Forbidden);
            }
            root.revision = revision;
        }
        root.revoked = revoked;
        let root = root.clone();
        if root.revoked || root.mode == RootMode::Read {
            self.index.purge(root.id)?;
            // A revoke or narrowing also drops every watch on that root; the
            // kernel set is re-synced so no signalled path can leak back in.
            for watch in self.index.watches_for_root(root.id)? { self.index.cancel_watch(&watch.id)?; }
            self.sync_watcher()?;
        }
        write_config(&self.config)?;
        Ok(serde_json::to_value(self.capabilities())?)
    }

    fn root(&self, id: Option<&str>) -> Result<RootGrant> {
        let id =
            uuid::Uuid::parse_str(id.ok_or(Error::Forbidden)?).map_err(|_| Error::Forbidden)?;
        self.config
            .roots
            .iter()
            .find(|root| root.id == id && !root.revoked)
            .cloned()
            .ok_or(Error::Forbidden)
    }

    /// Owner-driven commands arriving over the protected local control socket.
    /// These are the only way a grant ever broadens, and only a local peer that
    /// the control socket authorises can send them.
    pub fn control(&mut self, command: &Value) -> Result<Value> {
        match command["command"].as_str() {
            Some("status") => Ok(self.status()),
            Some("reindex") => {
                let root_id = uuid::Uuid::parse_str(
                    command["root_id"]
                        .as_str()
                        .ok_or(Error::Invalid("root id required".into()))?,
                )
                .map_err(|_| Error::Invalid("root id required".into()))?;
                self.reindex(root_id)
            }
            Some("root_revoke") => self.revoke(command),
            Some("root_add") => self.add_root(command),
            Some("watch_cancel") => {
                let id = command["watch_id"].as_str().ok_or(Error::Invalid("watch id required".into()))?;
                if !self.index.cancel_watch(id)? { return Err(Error::Invalid("unknown watch id".into())); }
                self.sync_watcher()?;
                Ok(json!({"watch_id": id, "status": "CANCELLED"}))
            }
            _ => Err(Error::Invalid("unknown control command".into())),
        }
    }

    /// Local authority for a new or broadened root. Admission checks ownership,
    /// ACLs, ancestors and filesystem support; an ordinary owner folder stays READ.
    pub fn add_root(&mut self, command: &Value) -> Result<Value> {
        let path = command["path"]
            .as_str()
            .ok_or(Error::Invalid("path required".into()))?;
        let canonical = std::fs::canonicalize(path).map_err(|_| Error::Forbidden)?;
        if !canonical.is_dir() || canonical == canonical.parent().unwrap_or(&canonical) {
            return Err(Error::Invalid(
                "a whole filesystem or file is not a root".into(),
            ));
        }
        let mode = match command["mode"].as_str().unwrap_or("READ") {
            "READ" => RootMode::Read,
            "READ_WRITE" => RootMode::ReadWrite,
            "ASK" => RootMode::Ask,
            _ => return Err(Error::Invalid("unknown root mode".into())),
        };
        let mut root = RootGrant {
            id: uuid::Uuid::new_v4(),
            path: canonical,
            mode,
            revision: 1,
            revoked: false,
            namespace_protected: false,
        };
        // A node without an installed service identity may still hold a READ
        // root; anything beyond READ needs that dedicated namespace identity.
        if mode == RootMode::Read && self.config.service_uid.is_none() {
            crate::admin::admit_read_only(&root, &self.config)?;
        } else {
            crate::admin::admit(&root, &self.config)?;
        }
        if mode != RootMode::Read {
            root.namespace_protected = prepared_tree(root.id).is_dir();
            if !root.namespace_protected {
                root.mode = RootMode::Read;
            }
        }
        self.config
            .roots
            .retain(|existing| existing.path != root.path);
        self.config.roots.push(root.clone());
        write_config(&self.config)?;
        let status = self.index.scan(&root)?;
        Ok(
            json!({"root_id":root.id,"path":root.path,"mode":root.mode,"mutation_available":mutation_available(&root),"index_status":status}),
        )
    }

    pub fn reindex(&mut self, root_id: uuid::Uuid) -> Result<Value> {
        let root = self
            .config
            .roots
            .iter()
            .find(|root| root.id == root_id && !root.revoked)
            .cloned()
            .ok_or(Error::Forbidden)?;
        Ok(serde_json::to_value(self.index.scan(&root)?)?)
    }

    pub fn status(&self) -> Value {
        json!({
            "node_id":self.config.node_id,
            "owner_id":self.config.owner_id,
            "server":self.config.server,
            "roots":self.config.roots.iter().map(|root| json!({"root_id":root.id,"path":root.path,"mode":root.mode,"revision":root.revision,"revoked":root.revoked,"mutation_available":mutation_available(root),"index_status":self.index.status(root.id).unwrap_or_default()})).collect::<Vec<_>>(),
            "watches":self.index.watches().unwrap_or_default().iter().map(|w| json!({"watch_id":w.id,"root_id":w.root,"relative_path":w.path,"types":w.types,"status": if self.config.roots.iter().any(|r|r.id==w.root && r.revoked) {"GAP"} else {"ACTIVE"}})).collect::<Vec<_>>(),
            "semantic_available":self.config.embedding.is_some(),
            "operations":self.capabilities().operations,
        })
    }

    /// (Re)attach the kernel watcher to the durable watch table. Restores
    /// every persisted registration on restart; a missing path un-watches
    /// rather than failing the whole set.
    pub fn sync_watcher(&mut self) -> Result<()> {
        if self.watcher.is_none() {
            let tx = self.watch_tx.clone();
            let overflow = self.watch_overflow.clone();
            let roots = self.config.roots.clone();
            self.watcher = Some(notify::recommended_watcher(move |res: std::result::Result<notify::Event, notify::Error>| {
                match res {
                    Ok(event) => observation::route_notify_event(&event, &roots, &tx, &overflow),
                    Err(_) => overflow.store(true, std::sync::atomic::Ordering::SeqCst),
                }
            }).map_err(|_| Error::Invalid("file watch failed".into()))?);
        }
        let watcher = self.watcher.as_mut().ok_or(Error::Invalid("file watch failed".into()))?;
        observation::sync_watches(watcher, &self.config.roots, &self.index)
    }

    /// Re-attach persisted watches after a restart and replay any unacked
    /// queued events on the next heartbeat (the outbox is never cleared).
    pub fn restore_watches(&mut self) -> Result<()> {
        let watched = self.index.watches()?;
        if watched.is_empty() { return Ok(()); }
        self.sync_watcher()
    }

    pub fn pending(&self) -> Result<Vec<FileEvent>> {
        self.index.pending_events()
    }
}

/// Where a prepared, protected shared tree lives. Nothing else may mutate.
#[cfg(target_os = "linux")]
pub fn prepared_tree(root_id: uuid::Uuid) -> std::path::PathBuf {
    std::path::Path::new(crate::admin::SERVICE_HOME)
        .join("shared")
        .join(root_id.to_string())
}
#[cfg(not(target_os = "linux"))]
pub fn prepared_tree(_root_id: uuid::Uuid) -> std::path::PathBuf {
    std::path::PathBuf::new()
}

/// Mutation needs a deliberately prepared, protected tree, never an ordinary folder.
pub fn mutation_available(root: &RootGrant) -> bool {
    root.mode != RootMode::Read && root.namespace_protected
}

fn label(message_type: MessageType) -> &'static str {
    match message_type {
        MessageType::Register => "REGISTER",
        MessageType::Authenticate => "AUTHENTICATE",
        MessageType::Heartbeat => "HEARTBEAT",
        MessageType::Capabilities => "CAPABILITIES",
        MessageType::FileSearch => "FILE_SEARCH",
        MessageType::FileRead => "FILE_READ",
        MessageType::FileWrite => "FILE_WRITE",
        MessageType::FileMetadata => "FILE_METADATA",
        MessageType::FileWatch => "FILE_WATCH",
        MessageType::FileList => "FILE_LIST",
        MessageType::FileMove => "FILE_MOVE",
        MessageType::FileCopy => "FILE_COPY",
        MessageType::BrowserNavigate => "BROWSER_NAVIGATE",
        MessageType::BrowserFillSubmit => "BROWSER_FILL_SUBMIT",
        MessageType::EventPush => "EVENT_PUSH",
        MessageType::ApprovalRequest => "APPROVAL_REQUEST",
        MessageType::Response => "RESPONSE",
        MessageType::Ack => "ACK",
        MessageType::Revoke => "REVOKE",
        MessageType::Challenge => "CHALLENGE",
        MessageType::Session => "SESSION",
    }
}

fn error_code(error: &Error) -> &'static str {
    match error {
        Error::Forbidden => "FORBIDDEN",
        Error::VersionConflict => "FILE_VERSION_CONFLICT",
        Error::SecureMutationUnavailable(_) => "SECURE_MUTATION_UNAVAILABLE",
        Error::OutcomeUnknown => "OUTCOME_UNKNOWN",
        Error::Unsupported => "UNSUPPORTED_CAPABILITY",
        Error::Io(_) => "IO_FAILED",
        Error::Json(_) | Error::Invalid(_) => "INVALID",
    }
}

fn bound(requested: Option<u64>, max: usize) -> usize {
    requested.unwrap_or(max as u64).min(max as u64).max(1) as usize
}

/// Split the configured server origin into host, optional path prefix and port.
/// Only TLS origins are admitted; there is no plaintext fallback.
fn split_server(server: &str) -> Result<(String, String, u16)> {
    let rest = server.strip_prefix("https://").ok_or(Error::Forbidden)?;
    let (authority, prefix) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let prefix = prefix.trim_end_matches('/').to_owned();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse::<u16>().map_err(|_| Error::Forbidden)?,
        ),
        None => (authority.to_owned(), 443),
    };
    if host.is_empty() || host.contains('/') {
        return Err(Error::Forbidden);
    }
    Ok((host, prefix, port))
}

/// Web PKI roots plus the owner-supplied private CA the node was told to trust.
fn tls_config(ca_file: Option<&Path>) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_file {
        let file = std::fs::File::open(path)?;
        for certificate in rustls_pemfile::certs(&mut std::io::BufReader::new(file)) {
            roots.add(certificate?).map_err(|_| Error::Forbidden)?;
        }
    }
    // The workspace enables both crypto providers through other dependencies, so
    // the node selects ring explicitly instead of relying on a process default.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Forbidden)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Node configuration holds the session credential and identity key; write it
/// owner-readable only, inside the state directory.
pub fn write_config(config: &NodeConfig) -> Result<()> {
    std::fs::create_dir_all(&config.state_dir)?;
    let path = config.state_dir.join("node.json");
    std::fs::write(&path, serde_json::to_vec_pretty(config)?)?;
    restrict(&config.state_dir, 0o700)?;
    restrict(&path, 0o600)?;
    Ok(())
}

/// The node configuration carries the identity key and session credential.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

pub fn read_config(path: &Path) -> Result<NodeConfig> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
