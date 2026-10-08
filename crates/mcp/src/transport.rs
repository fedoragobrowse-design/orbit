//! The SDK caps SSE but its JSON path calls Response::bytes without a cap.
//! This HTTP backend bounds bytes before parsing both JSON and SSE, never replays POST.
use std::{sync::Arc,collections::HashMap};
use http::{HeaderName,HeaderValue};
use rmcp::{model::{ClientJsonRpcMessage,ServerJsonRpcMessage},transport::streamable_http_client::{StreamableHttpClient,StreamableHttpError,StreamableHttpPostResponse}};
use futures_util::{StreamExt,stream::BoxStream};
use sse_stream::{Sse,SseStream};
pub const MAX_RESPONSE:usize=1024*1024;
#[derive(Clone)]
pub struct BoundedClient(pub reqwest::Client);
type Error=StreamableHttpError<reqwest::Error>;
fn bad(message:&'static str)->Error{StreamableHttpError::UnexpectedServerResponse(message.into())}
/// Header names an MCP server config may not override. Mirrors the SDK's reserved set:
/// `Accept`, `Mcp-Session-Id`, `Mcp-Protocol-Version` (injected by the worker after init)
/// and `Last-Event-Id` are reserved for protocol use.
fn reserved(name:&HeaderName)->bool{const RESERVED:&[&str]=&["accept","mcp-session-id","last-event-id"];RESERVED.iter().any(|r|name.as_str().eq_ignore_ascii_case(r))}
fn headers(mut b:reqwest::RequestBuilder,session:Option<Arc<str>>,auth:Option<String>,custom:HashMap<HeaderName,HeaderValue>)->Result<reqwest::RequestBuilder,Error>{if let Some(s)=session{b=b.header("mcp-session-id",s.as_ref())}if let Some(a)=auth{b=b.bearer_auth(a)}for(n,v)in custom{if reserved(&n){return Err(StreamableHttpError::ReservedHeaderConflict(n.to_string()));}b=b.header(n,v)}Ok(b)}
async fn bounded_json(mut response:reqwest::Response)->Result<Vec<u8>,Error>{if response.content_length().is_some_and(|n|n>MAX_RESPONSE as u64){return Err(bad("MCP response exceeds 1 MiB"))}let mut bytes=Vec::new();while let Some(chunk)=response.chunk().await.map_err(StreamableHttpError::Client)?{if bytes.len()+chunk.len()>MAX_RESPONSE{return Err(bad("MCP response exceeds 1 MiB"))}bytes.extend_from_slice(&chunk);}Ok(bytes)}
fn sse(response:reqwest::Response,max:usize)->BoxStream<'static,Result<Sse,sse_stream::Error>>{
 // `event_bytes` resets at each blank line, which is the SSE event delimiter, so an
 // oversized single event stops the stream instead of being silently truncated.
 let bytes=async_stream::stream!{
  let mut source=response.bytes_stream();let mut event_bytes=0usize;let mut line_bytes=0usize;
  while let Some(chunk)=source.next().await{
   let chunk=match chunk{Ok(chunk)=>chunk,Err(e)=>{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::other(e));return;}};
   let mut oversized=false;
   for &b in &chunk{event_bytes+=1;if event_bytes>max{oversized=true;break;}if b==b'\n'{if line_bytes==0{event_bytes=0;}line_bytes=0;}else if b!=b'\r'{line_bytes+=1;}}
   if oversized{yield Err(std::io::Error::other("MCP SSE event exceeds bound"));return;}
   yield Ok(chunk);
  }
 };
 SseStream::from_bytes_stream(bytes).boxed()
}
impl StreamableHttpClient for BoundedClient{
 type Error=reqwest::Error;
 async fn post_message(&self,uri:Arc<str>,message:ClientJsonRpcMessage,session:Option<Arc<str>>,auth:Option<String>,custom:HashMap<HeaderName,HeaderValue>)->Result<StreamableHttpPostResponse,Error>{self.post_message_with_max_sse_event_size(uri,message,session,auth,custom,MAX_RESPONSE).await}
 async fn post_message_with_max_sse_event_size(&self,uri:Arc<str>,message:ClientJsonRpcMessage,session:Option<Arc<str>>,auth:Option<String>,custom:HashMap<HeaderName,HeaderValue>,max:usize)->Result<StreamableHttpPostResponse,Error>{
  let attached=session.is_some();let b=headers(self.0.post(uri.as_ref()).header("Accept","application/json, text/event-stream"),session,auth,custom)?;
  let bytes=serde_json::to_vec(&message).map_err(|_|bad("MCP request encoding failed"))?;if bytes.len()>MAX_RESPONSE{return Err(bad("MCP request exceeds 1 MiB"))}let response=b.header("Content-Type","application/json").body(bytes).send().await.map_err(StreamableHttpError::Client)?;
  let status=response.status();if status==reqwest::StatusCode::NOT_FOUND&&attached{return Err(StreamableHttpError::SessionExpired)}if status==reqwest::StatusCode::ACCEPTED||status==reqwest::StatusCode::NO_CONTENT{return Ok(StreamableHttpPostResponse::Accepted)}if !status.is_success(){return Err(bad("MCP HTTP request rejected"))}
  let session=response.headers().get("mcp-session-id").and_then(|v|v.to_str().ok()).map(str::to_owned);let content=response.headers().get("content-type").and_then(|v|v.to_str().ok()).unwrap_or("");
  if content.starts_with("text/event-stream"){return Ok(StreamableHttpPostResponse::Sse(sse(response,max.min(MAX_RESPONSE)),session))}
  if !content.starts_with("application/json"){return Err(bad("MCP response is not JSON or SSE"))}let bytes=bounded_json(response).await?;if bytes.is_empty()&&!matches!(message,ClientJsonRpcMessage::Request(_)){return Ok(StreamableHttpPostResponse::Accepted)}let rpc:ServerJsonRpcMessage=serde_json::from_slice(&bytes).map_err(|_|bad("Malformed MCP JSON response"))?;Ok(StreamableHttpPostResponse::Json(rpc,session))
 }
 async fn delete_session(&self,uri:Arc<str>,session:Arc<str>,auth:Option<String>,custom:HashMap<HeaderName,HeaderValue>)->Result<(),Error>{let r=headers(self.0.delete(uri.as_ref()),Some(session),auth,custom)?.send().await.map_err(StreamableHttpError::Client)?;if r.status().is_success()||r.status()==reqwest::StatusCode::METHOD_NOT_ALLOWED||r.status()==reqwest::StatusCode::NOT_FOUND{Ok(())}else{Err(bad("MCP session close rejected"))}}
 async fn get_stream(&self,uri:Arc<str>,session:Option<Arc<str>>,last:Option<String>,auth:Option<String>,custom:HashMap<HeaderName,HeaderValue>)->Result<BoxStream<'static,Result<Sse,sse_stream::Error>>,Error>{self.get_stream_with_max_sse_event_size(uri,session,last,auth,custom,MAX_RESPONSE).await}
 async fn get_stream_with_max_sse_event_size(&self,uri:Arc<str>,session:Option<Arc<str>>,last:Option<String>,auth:Option<String>,custom:HashMap<HeaderName,HeaderValue>,max:usize)->Result<BoxStream<'static,Result<Sse,sse_stream::Error>>,Error>{let mut b=headers(self.0.get(uri.as_ref()).header("Accept","text/event-stream"),session,auth,custom)?;if let Some(l)=last{b=b.header("Last-Event-ID",l)}let response=b.send().await.map_err(StreamableHttpError::Client)?;if !response.status().is_success(){return Err(bad("MCP event stream unavailable"))}Ok(sse(response,max.min(MAX_RESPONSE)))}
}
