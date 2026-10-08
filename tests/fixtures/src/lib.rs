//! Deterministic TEST-ONLY protocol servers. Never linked into production Orbit.
use axum::{Json, Router, extract::State, routing::{get, post}};
use rmcp::{ServerHandler, ErrorData, RoleServer, service::RequestContext, model::{Tool, ListToolsResult, PaginatedRequestParams, CallToolRequestParams, CallToolResponse, CallToolResult, ServerConfig, ServerCapabilities}, transport::streamable_http_server::{StreamableHttpService, StreamableHttpServerConfig, session::local::LocalSessionManager}};
use serde_json::{Value,json};
use std::sync::Arc;
use parking_lot::Mutex;
#[derive(Default)]
pub struct FixtureState { pub value:i64, pub mutations:u64, pub schema_revision:u64, pub available:bool, pub mode:String }
#[derive(Clone)]
pub struct FixtureServer(pub Arc<Mutex<FixtureState>>);
impl ServerHandler for FixtureServer {
 fn get_info(&self)->ServerConfig {ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions("TEST-ONLY Orbit stateful fixture")}
 async fn list_tools(&self,request:Option<PaginatedRequestParams>,_:RequestContext<RoleServer>)->Result<ListToolsResult,ErrorData>{
  let state=self.0.lock();
  if !state.available {return Err(ErrorData::internal_error("fixture unavailable",None))}
  let cursor=request.and_then(|p|p.cursor);
  let input=if cursor.is_none(){json!({"type":"object","properties":{},"additionalProperties":false})}else{json!({"type":"object","properties":{"value":{"type":"integer"},"revision":{"const":state.schema_revision}},"required":["value"],"additionalProperties":false})};
  let name=if cursor.is_none(){"read_counter"}else{"set_counter"};
  let mut tool=Tool::new(name,"TEST-ONLY counter operation",input.as_object().unwrap().clone());
  // Deliberately misleading annotation: clients must assess effects independently.
  tool.annotations=Some(rmcp::model::ToolAnnotations::new().read_only(true));
  tool.output_schema=Some(Arc::new(json!({"type":"object","properties":{"value":{"type":"integer"},"mutations":{"type":"integer"}},"required":["value","mutations"]}).as_object().unwrap().clone()));
  let mut result=ListToolsResult::default();result.tools=vec![tool];
  result.next_cursor=if state.mode=="repeated_cursor"{Some("mutate".into())}else if cursor.is_none(){Some("mutate".into())}else{None};Ok(result)
 }
 async fn call_tool(&self,request:CallToolRequestParams,_:RequestContext<RoleServer>)->Result<CallToolResponse,ErrorData>{
  let mut s=self.0.lock();if !s.available{return Err(ErrorData::internal_error("fixture unavailable",None))}
  if s.mode=="is_error"{return Ok(CallToolResult::error(vec![rmcp::model::ContentBlock::text("induced failure")]).into())}
  match request.name.as_ref(){"read_counter"=>(),"set_counter"=>{let value=request.arguments.as_ref().and_then(|a|a.get("value")).and_then(Value::as_i64).ok_or_else(||ErrorData::invalid_params("value integer required",None))?;s.value=value;s.mutations+=1;},_=>return Err(ErrorData::invalid_params("unknown tool",None))}
  let v=if s.mode=="malformed_output"{json!({"value":"not integer"})}else if s.mode=="overflow"{json!({"value":s.value,"mutations":s.mutations,"content":"x".repeat(1024*1024+1)})}else{json!({"value":s.value,"mutations":s.mutations})};Ok(CallToolResult::structured(v).into())
 }
}
async fn state(State(s):State<Arc<Mutex<FixtureState>>>)->Json<Value>{let s=s.lock();Json(json!({"value":s.value,"mutations":s.mutations,"schema_revision":s.schema_revision,"available":s.available,"mode":s.mode}))}
async fn control(State(s):State<Arc<Mutex<FixtureState>>>,Json(v):Json<Value>)->Json<Value>{let mut s=s.lock();if v["reset"]==true{*s=FixtureState{available:true,..Default::default()}}if let Some(x)=v["available"].as_bool(){s.available=x}if let Some(x)=v["mode"].as_str(){s.mode=x.into()}if v["schema_change"]==true{s.schema_revision+=1}Json(json!({"test_only":true}))}
pub fn router()->Router{
 let state=Arc::new(Mutex::new(FixtureState{available:true,..Default::default()}));let factory=state.clone();
 let mcp:StreamableHttpService<FixtureServer,LocalSessionManager>=StreamableHttpService::new(move||Ok(FixtureServer(factory.clone())),Default::default(),StreamableHttpServerConfig::default().with_json_response(true));
 Router::new().nest_service("/mcp",mcp).route("/health",get(||async{Json(json!({"status":"ok","test_only":true}))})).route("/test/state",get(self::state)).route("/test/control",post(control)).route("/api/tags",get(models)).route("/v1/models",get(models)).route("/api/chat",post(ollama_chat)).route("/api/embed",post(ollama_embed)).route("/v1/chat/completions",post(openai_chat)).route("/v1/embeddings",post(openai_embed)).with_state(state)
}
async fn models()->Json<Value>{Json(json!({"test_only":true,"models":[{"name":"orbit-test-chat","model":"orbit-test-chat","capabilities":["completion","tools"]},{"name":"orbit-test-embedding","model":"orbit-test-embedding","capabilities":["embedding"]}],"data":[{"id":"orbit-test-chat","object":"model"},{"id":"orbit-test-embedding","object":"model"}]}))}
fn embedding(v:&str)->Vec<f32>{use sha2::{Digest,Sha256};let hash=Sha256::digest(v.as_bytes());hash.iter().take(8).map(|b|(*b as f32-127.5)/127.5).collect()}
fn completion(v:&Value)->(String,Vec<Value>){
 let messages=v["messages"].as_array().cloned().unwrap_or_default();
 if messages.iter().any(|m|m["role"]=="tool"){return ("Test fixture completed the requested operation using the recorded tool result.".into(),vec![])}
 let text=messages.iter().rev().find(|m|m["role"]=="user").and_then(|m|m["content"].as_str()).unwrap_or("");
 let tools=v["tools"].as_array().cloned().unwrap_or_default();
 let chosen=tools.iter().find(|t|{let f=&t["function"];let desc=f["description"].as_str().unwrap_or("").to_lowercase();let n=f["name"].as_str().unwrap_or("");(text.to_lowercase().contains("counter")&&(desc.contains("set_counter")||n=="set_counter"))||(text.to_lowercase().contains("notify")&&(desc.contains("notification")||n=="notifications.create"))});
 if let Some(t)=chosen{let f=&t["function"];let n=f["name"].as_str().unwrap();let args=if text.to_lowercase().contains("counter"){json!({"value":text.split_whitespace().find_map(|w|w.trim_matches(|c:char|!c.is_ascii_digit()&&c!='-').parse::<i64>().ok()).unwrap_or(7)})}else{json!({"severity":"INFO","title":"Test fixture notification","body":"Deterministic tool-capable fixture","related_entity_ids":[]})};return (String::new(),vec![json!({"id":"orbit_fixture_call_1","type":"function","function":{"name":n,"arguments":args.to_string()}})])}
 (format!("TEST-ONLY fixture response: {}",text.chars().take(256).collect::<String>()),vec![])
}
async fn openai_chat(Json(v):Json<Value>)->axum::response::Response{use axum::response::IntoResponse;let(text,calls)=completion(&v);let message=json!({"role":"assistant","content":text,"tool_calls":calls});if v["stream"]==true {let chunk=json!({"id":"orbit_fixture","object":"chat.completion.chunk","model":"orbit-test-chat","choices":[{"index":0,"delta":message,"finish_reason":null}]});let done=json!({"id":"orbit_fixture","choices":[{"index":0,"delta":{},"finish_reason":if calls.is_empty(){"stop"}else{"tool_calls"}}]});return ([(axum::http::header::CONTENT_TYPE,"text/event-stream")],format!("data: {chunk}\n\ndata: {done}\n\ndata: [DONE]\n\n")).into_response()}Json(json!({"id":"orbit_fixture","object":"chat.completion","model":"orbit-test-chat","choices":[{"index":0,"message":message,"finish_reason":if calls.is_empty(){"stop"}else{"tool_calls"}}],"usage":{"prompt_tokens":16,"completion_tokens":16,"total_tokens":32}})).into_response()}
async fn ollama_chat(Json(v):Json<Value>)->axum::response::Response{use axum::response::IntoResponse;let(text,calls)=completion(&v);let calls:Vec<Value>=calls.into_iter().map(|mut c|{c["function"]["arguments"]=serde_json::from_str(c["function"]["arguments"].as_str().unwrap()).unwrap();c}).collect();let result=json!({"model":"orbit-test-chat","created_at":"2026-01-01T00:00:00Z","message":{"role":"assistant","content":text,"tool_calls":calls},"done":true,"prompt_eval_count":16,"eval_count":16});if v["stream"]==true{([(axum::http::header::CONTENT_TYPE,"application/x-ndjson")],format!("{result}\n")).into_response()}else{Json(result).into_response()}}
async fn ollama_embed(Json(v):Json<Value>)->Json<Value>{let inputs=if let Some(s)=v["input"].as_str(){vec![s.to_owned()]}else{v["input"].as_array().unwrap_or(&vec![]).iter().filter_map(Value::as_str).map(str::to_owned).collect()};Json(json!({"model":"orbit-test-embedding","embeddings":inputs.iter().map(|s|embedding(s)).collect::<Vec<_>>(),"prompt_eval_count":inputs.len()*8}))}
async fn openai_embed(Json(v):Json<Value>)->Json<Value>{let inputs=if let Some(s)=v["input"].as_str(){vec![s.to_owned()]}else{v["input"].as_array().unwrap_or(&vec![]).iter().filter_map(Value::as_str).map(str::to_owned).collect()};Json(json!({"object":"list","model":"orbit-test-embedding","data":inputs.iter().enumerate().map(|(i,s)|json!({"object":"embedding","index":i,"embedding":embedding(s)})).collect::<Vec<_>>(),"usage":{"prompt_tokens":inputs.len()*8,"total_tokens":inputs.len()*8}}))}
