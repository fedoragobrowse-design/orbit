use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use orbit_core::{Error, PrivacyClass, Result};
use orbit_model_router::endpoint::AdmittedEndpoint;
use orbit_task_runtime::{Artifact, FILE_LIMIT, RuntimeHandle, RuntimeOutcome, RuntimeResult, RuntimeSpec, RuntimeTask, TRANSFER_LIMIT, TaskRuntime, workspace_path};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, net::IpAddr, sync::Mutex, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const JSON_LIMIT: usize = 2 * FILE_LIMIT;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    pub origin: String,
    pub admitted_addresses: Vec<IpAddr>,
    pub ca_pem: Option<String>,
    pub secret_id: Uuid,
    pub image: String,
    pub disk_mb: u32,
    pub lifetime_seconds: u64,
}
impl ConnectionConfig {
    pub fn validate(&self) -> Result<()> {
        let u=reqwest::Url::parse(&self.origin).map_err(|_| Error::Validation("invalid AIec origin".into()))?;
        if u.path() != "/" || u.query().is_some() || u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() || self.admitted_addresses.is_empty() || self.image.is_empty() || self.image.len()>256 || self.disk_mb==0 || self.lifetime_seconds!=1680 || self.ca_pem.as_ref().is_some_and(|v|v.len()>65536) { return Err(Error::Validation("AIec needs an exact origin, pinned admitted addresses, image, disk floor and 1680-second ceiling".into())); }
        if u.scheme()!="https" && !(u.scheme()=="http" && u.host_str().and_then(|h|h.parse::<IpAddr>().ok()).is_some_and(|ip|ip.is_loopback())) { return Err(Error::Validation("AIec requires HTTPS except actual loopback".into())); }
        Ok(())
    }
}
/// Independently owned REST wire types. No dependency on AIec implementation crates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: Uuid,
    pub image_id: String,
    pub state: String,
    pub runtime: String,
    pub cpu: u32,
    pub memory_mb: u32,
    pub disk_mb: u32,
    pub timeout_seconds: u64,
    pub network: Network,
    pub environment: Value,
    pub created_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network { pub enabled: bool }
#[derive(Serialize)]
struct CreateBody<'a> {
    image: &'a str, runtime: &'static str, isolation: &'static str,
    cpu: u32, memory_mb: u32, disk_mb: u32, timeout_seconds: u64,
    network: Network, environment: Value,
}
#[derive(Serialize)]
struct ExecBody<'a> { command: &'a [String], working_directory: &'a str, environment: BTreeMap<String,String>, timeout_seconds: u64, stdin: Option<String> }
#[derive(Deserialize)]
struct ExecResponse { exit_code: i32, stdout: String, stderr: String, duration_ms: u64, timed_out: bool }
#[derive(Deserialize)]
struct FileResponse { path: String, content_base64: String }
#[derive(Default)]
struct LocalRun { outputs: Vec<String>, commands: BTreeSet<String> }
pub struct AIecRuntime {
    client: reqwest::Client,
    endpoint: AdmittedEndpoint,
    config: ConnectionConfig,
    key: Zeroizing<Vec<u8>>,
    runs: Mutex<BTreeMap<Uuid,LocalRun>>,
    creates: Mutex<BTreeSet<Uuid>>,
}
impl AIecRuntime {
    pub async fn connect(config: ConnectionConfig, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        config.validate()?;
        if key.is_empty() || key.len()>8192 || std::str::from_utf8(&key).is_err() { return Err(Error::Validation("invalid tenant API credential".into())); }
        let endpoint=AdmittedEndpoint{origin:config.origin.clone(),local:config.origin.starts_with("http://"),admitted_addresses:config.admitted_addresses.clone()};
        let client=endpoint.client_with_ca(config.ca_pem.as_deref().map(str::as_bytes)).await?;
        Ok(Self{client,endpoint,config,key,runs:Mutex::new(BTreeMap::new()),creates:Mutex::new(BTreeSet::new())})
    }
    fn request(&self, method: Method, path: &str, timeout: u64) -> Result<reqwest::RequestBuilder> {
        let token=std::str::from_utf8(&self.key).map_err(|_|Error::Forbidden)?.trim();
        Ok(self.client.request(method,self.endpoint.url(path)?).bearer_auth(token).timeout(Duration::from_secs(timeout)))
    }
    fn request_query(&self, method: Method, path: &str, query: &[(&str, &str)], timeout: u64) -> Result<reqwest::RequestBuilder> {
        let token=std::str::from_utf8(&self.key).map_err(|_|Error::Forbidden)?.trim();
        Ok(self.client.request(method,self.endpoint.url_with_query(path,query)?).bearer_auth(token).timeout(Duration::from_secs(timeout)))
    }
    pub async fn readiness(&self) -> Result<Value> {
        let response=self.request(Method::GET,"v1/sandboxes",30)?.send().await.map_err(|_|Error::Unavailable("AIec authenticated route unreachable".into()))?;
        let _: Value=decode(response).await?;
        Ok(json!({"authenticated_routes":true,"effective_origin":self.config.origin,"worker_capacity_verified":false,"network_enforcement_verified":false}))
    }
    pub async fn status(&self,id:Uuid) -> Result<Option<Sandbox>> {
        let response=self.request(Method::GET,&format!("v1/sandboxes/{id}"),30)?.send().await.map_err(|_|Error::Unavailable("AIec status unavailable".into()))?;
        if response.status()==StatusCode::NOT_FOUND { return Ok(None); }
        Ok(Some(decode(response).await?))
    }
    pub fn validate_running(&self,sandbox:&Sandbox,spec:&RuntimeSpec) -> Result<RuntimeHandle> {
        if sandbox.id!=spec.run_id || sandbox.runtime!="firecracker" || sandbox.cpu!=1 || sandbox.memory_mb!=512 || sandbox.disk_mb!=spec.disk_mb || sandbox.timeout_seconds!=1680 || sandbox.network.enabled || sandbox.environment.pointer("/guard/topology").and_then(Value::as_str)!=Some("outside") || sandbox.environment.pointer("/guard/policy_template").and_then(Value::as_str)!=Some("no-network") {
            return Err(Error::Forbidden);
        }
        // image_id may be the deployment's resolved signed digest rather than the admitted alias.
        if sandbox.state=="quarantined" { return Err(Error::Unavailable("AIec sandbox quarantined; cleanup remains required".into())); }
        if sandbox.state!="running" { return Err(Error::Unavailable("AIec sandbox provisioning".into())); }
        let handle=RuntimeHandle::observed(sandbox.id,sandbox.created_at,sandbox.timeout_seconds);
        handle.require_remaining(660)?;
        self.runs.lock().map_err(|_|Error::OutcomeUnknown)?.entry(handle.id()).or_default();
        Ok(handle)
    }
    pub async fn upload_inputs(&self,handle:&RuntimeHandle,spec:&RuntimeSpec) -> Result<()> {
        spec.validate()?;
        handle.require_remaining(660)?;
        let mut total=0usize;
        for input in &spec.inputs {
            if input.bytes.len()!=input.size as usize || input.bytes.len()>FILE_LIMIT || sha256(&input.bytes)!=input.sha256 { return Err(Error::Validation("runtime input digest mismatch".into())); }
            total+=input.bytes.len(); if total>TRANSFER_LIMIT {return Err(Error::Validation("input total exceeded".into()));}
            self.put_file(handle,&input.path,&input.bytes).await?;
            // Verify actual bytes, not just a PUT acknowledgement.
            if sha256(&self.read_file(handle,&input.path).await?)!=input.sha256 { return Err(Error::Validation("uploaded input digest mismatch".into())); }
        }
        Ok(())
    }
    pub async fn mkdir(&self,handle:&RuntimeHandle,path:&str) -> Result<()> {
        workspace_path(path,true)?; handle.require_remaining(300)?;
        let response=self.request(Method::POST,&format!("v1/sandboxes/{}/files/mkdir",handle.id()),30)?.json(&json!({"path":path})).send().await.map_err(|_|Error::OutcomeUnknown)?;
        let _:Value=decode(response).await?; Ok(())
    }
    pub async fn put_file(&self,handle:&RuntimeHandle,path:&str,bytes:&[u8]) -> Result<()> {
        workspace_path(path,false)?; handle.require_remaining(540)?;
        if bytes.len()>FILE_LIMIT {return Err(Error::Validation("file exceeds 1 MiB".into()));}
        // Create each approved parent; these operations never address host paths.
        let parts:Vec<_>=path.split('/').collect();
        for end in 3..parts.len() { self.mkdir(handle,&parts[..end].join("/")).await?; }
        let response=self.request(Method::PUT,&format!("v1/sandboxes/{}/files",handle.id()),30)?.json(&json!({"path":path,"content_base64":STANDARD.encode(bytes),"mode":384})).send().await.map_err(|_|Error::OutcomeUnknown)?;
        let _:Value=decode(response).await?; Ok(())
    }
    pub async fn read_file(&self,handle:&RuntimeHandle,path:&str) -> Result<Vec<u8>> {
        workspace_path(path,false)?; handle.require_remaining(150)?;
        let response=self.request_query(Method::GET,&format!("v1/sandboxes/{}/files/content",handle.id()),&[("path",path)],30)?.send().await.map_err(|_|Error::Unavailable("AIec file read unavailable".into()))?;
        let file:FileResponse=decode(response).await?;
        if file.path!=path || file.content_base64.len()>FILE_LIMIT.div_ceil(3)*4 {return Err(Error::Validation("file response path or encoded size mismatch".into()));}
        let bytes=STANDARD.decode(file.content_base64).map_err(|_|Error::Validation("invalid AIec base64".into()))?;
        if bytes.len()>FILE_LIMIT {return Err(Error::Validation("decoded file exceeds 1 MiB".into()));} Ok(bytes)
    }
    pub fn restore_outputs(&self,id:Uuid,paths:Vec<String>) -> Result<()> {
        for path in &paths {workspace_path(path,false)?;}
        self.runs.lock().map_err(|_|Error::OutcomeUnknown)?.entry(id).or_default().outputs=paths; Ok(())
    }
    pub async fn request_destroy(&self,id:Uuid) -> Result<()> {
        let response=self.request(Method::DELETE,&format!("v1/sandboxes/{id}"),30)?.send().await.map_err(|_|Error::Unavailable("AIec destroy unavailable".into()))?;
        // A 404 is not acknowledgement of a settled create.
        let value:Value=decode(response).await?;
        if value.get("status").and_then(Value::as_str)!=Some("destroyed") {return Err(Error::OutcomeUnknown);} Ok(())
    }
}
#[async_trait]
impl TaskRuntime for AIecRuntime {
    async fn create(&self,spec:RuntimeSpec) -> Result<RuntimeHandle> {
        spec.validate()?;
        if spec.image!=self.config.image || spec.disk_mb!=self.config.disk_mb {return Err(Error::Forbidden);}
        if !self.creates.lock().map_err(|_|Error::OutcomeUnknown)?.insert(spec.run_id) {return Err(Error::OutcomeUnknown);}
        let body=CreateBody{image:&spec.image,runtime:"firecracker",isolation:"microvm",cpu:1,memory_mb:512,disk_mb:spec.disk_mb,timeout_seconds:1680,network:Network{enabled:false},environment:json!({"workspace":{"type":"empty"},"guard":{"topology":"outside","policy_template":"no-network"}})};
        let response=self.request(Method::POST,"v1/sandboxes",1020)?.header("Idempotency-Key",spec.run_id.to_string()).json(&body).send().await.map_err(|_|Error::OutcomeUnknown)?;
        // 409 is status-only recovery. Never issue a second POST.
        if response.status()==StatusCode::CONFLICT {return Err(Error::Unavailable("AIec sandbox provisioning; poll the same UUID".into()));}
        let sandbox:Sandbox=decode(response).await?;
        self.validate_running(&sandbox,&spec)
    }
    async fn execute(&self,handle:&RuntimeHandle,task:RuntimeTask) -> Result<RuntimeResult> {
        task.validate()?; handle.require_remaining(task.timeout_seconds+420)?;
        let digest=sha256(&serde_json::to_vec(&task)?);
        { let mut runs=self.runs.lock().map_err(|_|Error::OutcomeUnknown)?; let run=runs.entry(handle.id()).or_default(); if !run.commands.insert(digest) {return Err(Error::OutcomeUnknown);} run.outputs=task.output_paths.clone(); }
        let body=ExecBody{command:&task.argv,working_directory:&task.working_directory,environment:BTreeMap::new(),timeout_seconds:task.timeout_seconds,stdin:None};
        let response=match self.request(Method::POST,&format!("v1/sandboxes/{}/exec",handle.id()),task.timeout_seconds+120)?.json(&body).send().await {Ok(r)=>r,Err(_)=>return Ok(unknown_result())};
        // Once an exec was transmitted even an invalid/truncated reply is not evidence of no effect.
        let reply:ExecResponse=match decode(response).await {Ok(r)=>r,Err(_)=>return Ok(unknown_result())};
        Ok(RuntimeResult{outcome:if reply.timed_out {RuntimeOutcome::TimedOut}else {RuntimeOutcome::Exited},exit_code:Some(reply.exit_code),stdout:reply.stdout,stderr:reply.stderr,duration_ms:Some(reply.duration_ms),output_completeness:"NOT_ASSERTED_BY_PROVIDER".into()})
    }
    async fn collect_artifacts(&self,handle:&RuntimeHandle) -> Result<Vec<Artifact>> {
        handle.require_remaining(270)?;
        let paths=self.runs.lock().map_err(|_|Error::OutcomeUnknown)?.get(&handle.id()).map(|r|r.outputs.clone()).ok_or(Error::NotFound)?;
        let mut artifacts=Vec::with_capacity(paths.len()); let mut total=0usize;
        for path in paths {
            let bytes=self.read_file(handle,&path).await?; total+=bytes.len(); if total>TRANSFER_LIMIT {return Err(Error::Validation("outputs exceed 10 MiB".into()));}
            let name=path.rsplit('/').next().ok_or(Error::Forbidden)?.to_owned();
            let mime=if name.ends_with(".json") {"application/json"}else if name.ends_with(".txt")||name.ends_with(".md") {"text/plain"}else {"application/octet-stream"};
            artifacts.push(Artifact{id:Uuid::new_v4(),safe_name:name,mime_type:mime.into(),size:bytes.len() as u64,sha256:sha256(&bytes),privacy_class:PrivacyClass::Private,provenance:format!("aiec:{}:{}",handle.id(),path),private_storage_reference:String::new(),bytes});
        }
        Ok(artifacts)
    }
    async fn destroy(&self,handle:RuntimeHandle) -> Result<()> {
        self.request_destroy(handle.id()).await?;
        match self.status(handle.id()).await? {Some(s) if s.state=="destroyed"=>Ok(()),_=>Err(Error::OutcomeUnknown)}
    }
}
fn unknown_result()->RuntimeResult {RuntimeResult{outcome:RuntimeOutcome::OutcomeUnknown,exit_code:None,stdout:String::new(),stderr:String::new(),duration_ms:None,output_completeness:"UNKNOWN".into()}}
pub fn sha256(bytes:&[u8])->String {hex::encode(Sha256::digest(bytes))}
async fn decode<T:DeserializeOwned>(mut response:reqwest::Response)->Result<T> {
    let status=response.status();
    if !status.is_success() {return Err(match status {StatusCode::UNAUTHORIZED=>Error::Unauthorized,StatusCode::FORBIDDEN=>Error::Forbidden,StatusCode::NOT_FOUND=>Error::NotFound,StatusCode::CONFLICT=>Error::Conflict("AIec resource conflict".into()),s if s.is_redirection()=>Error::Forbidden,_=>Error::Unavailable(format!("AIec returned HTTP {}",status.as_u16()))});}
    if response.content_length().is_some_and(|n|n>JSON_LIMIT as u64) {return Err(Error::Validation("AIec response exceeds bound".into()));}
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await.map_err(|_|Error::OutcomeUnknown)? {if bytes.len()+chunk.len()>JSON_LIMIT {return Err(Error::Validation("AIec response exceeds bound".into()));}bytes.extend_from_slice(&chunk);}
    serde_json::from_slice(&bytes).map_err(|_|Error::Validation("invalid bounded AIec JSON response".into()))
}
