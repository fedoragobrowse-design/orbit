use async_trait::async_trait;
use futures_util::Stream;
use orbit_core::{ContextBlock,ModelRole,PrivacyClass,Result};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use std::pin::Pin;
use uuid::Uuid;

#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum ProviderKind { Ollama,OpenaiCompatible,Anthropic,Gemini }
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum InstallationMode {LocalOnly,Hybrid,CloudOnly}
#[derive(Debug,Clone,Default,Serialize,Deserialize)]
#[serde(default)]
pub struct ProviderCapabilities {pub chat:bool,pub tools:bool,pub vision:bool,pub structured_output:bool,pub reasoning:bool,pub embeddings:bool,pub rerank:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ProviderConfig {pub id:Uuid,pub name:String,pub kind:ProviderKind,pub origin:String,pub local:bool,pub admitted_addresses:Vec<std::net::IpAddr>,pub credential_id:Option<Uuid>,pub rerank_path:Option<String>,pub enabled:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ModelConfig {pub id:Uuid,pub provider_id:Uuid,pub model:String,pub name:String,pub roles:Vec<ModelRole>,pub priority:i32,pub context_tokens:u32,pub capabilities:ProviderCapabilities,pub input_usd_per_million:Option<f64>,pub output_usd_per_million:Option<f64>,pub enabled:bool}
#[derive(Debug,Clone,Default,Serialize,Deserialize)]
#[serde(default)]
pub struct ChatRequest {pub messages:Vec<ChatMessage>,pub tools:Vec<ToolSchema>,pub output_schema:Option<Value>,pub max_output_tokens:u32,pub reasoning:bool}
#[derive(Debug,Clone,Default,Serialize,Deserialize)]
#[serde(default)]
pub struct ChatMessage {pub role:String,pub content:String,pub tool_call_id:Option<String>,pub tool_calls:Vec<ToolCall>,pub images:Vec<ImageInput>}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ImageInput {pub mime_type:String,pub data_base64:String,pub privacy_class:PrivacyClass}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ToolSchema {pub name:String,pub description:String,pub input_schema:Value}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct ToolCall {pub id:String,pub name:String,pub arguments:Value}
#[derive(Debug,Clone,Default,Serialize,Deserialize)]
pub struct Usage {pub input_tokens:u64,pub output_tokens:u64,pub cached_tokens:u64,pub known:bool}
#[derive(Debug,Clone,Default,Serialize,Deserialize)]
pub struct ChatResponse {pub text:String,pub tool_calls:Vec<ToolCall>,pub structured_output:Option<Value>,pub usage:Usage,pub finish_reason:Option<String>}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(tag="type",rename_all="SCREAMING_SNAKE_CASE")]
pub enum ModelChunk {Text {text:String}, ToolCallDelta {index:usize,id:Option<String>,name:Option<String>,arguments:String}, Done {response:ChatResponse}}
pub type ModelStream=Pin<Box<dyn Stream<Item=Result<ModelChunk>>+Send>>;
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct EmbeddingRequest {pub input:Vec<String>}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct EmbeddingResponse {pub vectors:Vec<Vec<f32>>,pub usage:Usage}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RerankRequest {pub query:String,pub documents:Vec<String>,pub top_n:usize}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RerankResult {pub index:usize,pub relevance_score:f64}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RerankResponse {pub results:Vec<RerankResult>}
#[async_trait]
pub trait ModelProvider:Send+Sync {
 async fn complete(&self,request:ChatRequest)->Result<ChatResponse>;
 async fn stream(&self,request:ChatRequest)->Result<ModelStream>;
 async fn embed(&self,request:EmbeddingRequest)->Result<EmbeddingResponse>;
 async fn rerank(&self,request:RerankRequest)->Result<RerankResponse>;
 fn capabilities(&self)->ProviderCapabilities;
}
#[derive(Debug,Clone)]
pub struct RoutedRequest {pub role:ModelRole,pub chat:ChatRequest,pub context:Vec<ContextBlock>,pub privacy:PrivacyClass,pub task_id:Option<Uuid>,pub task_fence:Option<i64>,pub agent_id:Option<Uuid>,pub automatic:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RouteMetadata {pub provider_id:Uuid,pub model_id:Uuid,pub model:String,pub local:bool,pub privacy:PrivacyClass,pub reason:String,pub effective_origin:String}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct RoutedResponse {pub response:ChatResponse,pub route:RouteMetadata,pub call_id:Uuid}
