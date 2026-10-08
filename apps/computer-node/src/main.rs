//! `orbit-computer-node`: owner-invoked pairing, root authority and the outbound
//! node service. The node never opens a network listener; the only local socket
//! is the protected control socket whose peer UID must match the owner or admin.
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use orbit_computer_node::transport::{Node, read_config};
use orbit_computer_node_protocol::{Error, NodeConfig, Result, RootMode};
use serde_json::{Value, json};
use std::{io::{BufRead, BufReader, Write}, path::{Path, PathBuf}, sync::Arc};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "orbit-computer-node", version, about = "Orbit computer node", disable_help_subcommand = true)]
struct Cli {
    /// Paired node configuration written by `pair`.
    #[arg(long, global = true, default_value = "node.json")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Exchange a one-use owner pairing code for this node's identity and session.
    Pair {
        #[arg(long)] server: String,
        #[arg(long)] code: String,
        #[arg(long)] ca_file: Option<PathBuf>,
        #[arg(long, default_value = "node.json")] state: PathBuf,
    },
    /// Run the outbound node service against a paired configuration.
    Serve,
    /// Node-local root authority. Broadening a grant is deliberate and local.
    Roots { #[command(subcommand)] command: RootCommand },
    /// Report this node's identity, granted roots and real capabilities.
    Status,
    /// Rescan one root and report real index counters.
    Reindex { root_id: Uuid },
    /// Administrator-only local installation. Never reachable from the server.
    Service { #[command(subcommand)] command: ServiceCommand },
}

#[derive(Subcommand)]
enum RootCommand {
    Add { path: PathBuf, #[arg(long, default_value = "READ")] mode: String },
    List,
    Revoke { root_id: Uuid },
    /// Preview and apply the ownership/ACL preparation a protected tree needs.
    Prepare { path: PathBuf, #[arg(long)] consent: bool },
}

#[derive(Subcommand)]
enum ServiceCommand {
    Install { #[arg(long)] owner: String, #[arg(long)] consent: bool },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config_path = cli.config.clone();
    match cli.command {
        Command::Pair { server, code, ca_file, state } => pair(&server, &code, ca_file.as_deref(), &state).await,
        Command::Serve => serve(read_config(&config_path)?).await,
        Command::Status => report(read_config(&config_path)?, json!({"command":"status"})),
        Command::Reindex { root_id } => report(read_config(&config_path)?, json!({"command":"reindex","root_id":root_id})),
        Command::Roots { command } => roots(&config_path, command),
        Command::Service { command } => service(command),
    }
}

/// Pairing over verified HTTPS only. The one-use owner code decides identity; the
/// node generates its own Ed25519 key here and keeps it on this machine.
async fn pair(server: &str, code: &str, ca_file: Option<&Path>, state: &Path) -> Result<()> {
    if !server.starts_with("https://") { return Err(Error::Forbidden); }
    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    if let Some(path) = ca_file {
        let certificate = reqwest::Certificate::from_pem(&std::fs::read(path)?).map_err(|_| Error::Forbidden)?;
        builder = builder.add_root_certificate(certificate);
    }
    let client = builder.build().map_err(|_| Error::Io(std::io::Error::other("TLS client")))?;
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let response = client
        .post(format!("{}/api/v1/computers/pair", server.trim_end_matches('/')))
        .json(&json!({"code":code,"identity_key":STANDARD.encode(key.verifying_key().to_bytes())}))
        .send()
        .await
        .map_err(|_| Error::Io(std::io::Error::other("pairing endpoint unreachable")))?;
    if !response.status().is_success() { return Err(Error::Forbidden); }
    let body: Value = response.json().await.map_err(|_| Error::Invalid("malformed pairing response".into()))?;
    let owner_id = identity(&body, "owner_id")?;
    let node_id = identity(&body, "node_id")?;
    let session = body["session"].as_str().ok_or(Error::Invalid("session credential missing".into()))?.to_owned();
    let config = NodeConfig {
        server: server.trim_end_matches('/').to_owned(),
        owner_id,
        node_id,
        session,
        identity_key: STANDARD.encode(key.to_bytes()),
        state_dir: state.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_owned(),
        ca_file: ca_file.map(PathBuf::from),
        roots: Vec::new(),
        owner_uid: None,
        service_uid: None,
        embedding: None,
    };
    orbit_computer_node::transport::write_config(&config)?;
    println!("paired node {node_id} for owner {owner_id}; configuration written to {}", state.display());
    Ok(())
}

fn identity(body: &Value, field: &str) -> Result<Uuid> {
    Uuid::parse_str(body[field].as_str().ok_or(Error::Invalid(format!("{field} missing")))?).map_err(|_| Error::Invalid(format!("{field} malformed")))
}

async fn serve(config: NodeConfig) -> Result<()> {
    // A read-only node grants no namespace authority, so it may run as the owner
    // who started it. Any mutating root requires the installed dedicated service
    // identity, and that identity is verified before the socket opens.
    let mutation_configured = config.roots.iter().any(|root| root.mode != RootMode::Read);
    let listener_config = config.clone();
    let node = Node::open(config)?;
    #[cfg(target_os = "linux")]
    {
        if !mutation_configured { return node.run().await; }
        orbit_computer_node::admin::assert_service_identity(&listener_config)?;
        let listener = tokio::net::UnixListener::from_std(orbit_computer_node::admin::bind_control(&listener_config)?)?;
        let node = std::sync::Arc::new(tokio::sync::Mutex::new(node));
        let control_node = node.clone();
        let control_config = listener_config.clone();
        // The owner CLI reaches this service only through the protected control
        // socket, whose peer UID was already checked before the command is read.
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                // The control socket authorises by peer UID before any byte is read,
                // so an unprivileged process on this machine cannot reach the node.
                let Ok(peer) = stream.into_std() else { continue };
                if orbit_computer_node::admin::authorize_control_peer(&peer, &control_config).is_err() { continue; }
                let node = control_node.clone();
                tokio::spawn(async move {
                    let Ok(command) = serde_json::from_reader(BufReader::new(peer)) else { return };
                    let reply = match node.lock().await.control(&command) {
                        Ok(result) => json!({"ok":true,"result":result}),
                        Err(error) => json!({"ok":false,"error":error.to_string()}),
                    };
                    let mut out = std::io::stdout();
                    let _ = writeln!(out, "{reply}");
                });
            }
        });
        match Arc::try_unwrap(node) {
            Ok(node) => node.into_inner().run().await,
            Err(_) => Err(Error::Invalid("control loop retained the node".into())),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if mutation_configured { orbit_computer_node::admin::assert_service_identity(&listener_config)?; }
        node.run().await
    }
}

fn roots(config_path: &Path, command: RootCommand) -> Result<()> {
    let config = read_config(config_path)?;
    match command {
        RootCommand::Add { path, mode } => report(config, json!({"command":"root_add","path":path,"mode":mode})),
        RootCommand::List => report(config, json!({"command":"status"})),
        RootCommand::Revoke { root_id } => report(config, json!({"command":"root_revoke","root_id":root_id})),
        RootCommand::Prepare { path, consent } => {
            if !consent { return Err(Error::Invalid("preparation requires explicit --consent".into())); }
            println!("{}", orbit_computer_node::admin::prepare(&config, &path, consent)?.display());
            Ok(())
        }
    }
}

fn service(command: ServiceCommand) -> Result<()> {
    let ServiceCommand::Install { owner, consent } = command;
    if !consent { return Err(Error::Invalid("installation requires explicit --consent".into())); }
    orbit_computer_node::admin::install(&owner, consent)?;
    println!("orbit-computer-node service installed for {owner}");
    Ok(())
}

/// Prefer the running service's control socket; fall back to the local files when
/// no service owns this node, so offline administration still works.
fn report(config: NodeConfig, command: Value) -> Result<()> {
    if let Some(stream) = orbit_computer_node::admin::connect_control(&config).ok() {
        let mut writer = stream.try_clone()?;
        writeln!(writer, "{command}")?;
        writer.flush()?;
        let mut reply = String::new();
        BufReader::new(&stream).read_line(&mut reply)?;
        println!("{}", reply.trim());
        return Ok(());
    }
    let mut node = Node::open(config)?;
    println!("{}", serde_json::to_string_pretty(&node.control(&command)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn pairing_refuses_a_plaintext_origin() {
        let error = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(pair("http://localhost:8080", "12345", None, Path::new("node.json")));
        assert!(matches!(error, Err(Error::Forbidden)));
    }
}
