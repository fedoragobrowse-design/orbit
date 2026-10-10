use crate::{endpoint::AdmittedEndpoint,types::*};
use async_trait::async_trait;
use base64::Engine;
use futures_util::StreamExt;
use orbit_core::{Error,Result};
use reqwest::{Client,Response};
use serde_json::{Value,json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
#[cfg(test)]
use uuid::Uuid;

const RESPONSE_LIMIT:usize=8*1024*1024;
/// Credential bytes are private and are never included in Debug/error responses.
pub struct HttpProvider {config:ProviderConfig,model:ModelConfig,endpoint:AdmittedEndpoint,client:Client,credential:Option<Zeroizing<Vec<u8>>>}
impl HttpProvider {
 pub async fn new(config:ProviderConfig,model:ModelConfig,credential:Option<Zeroizing<Vec<u8>>>)->Result<Self>{
  let endpoint=AdmittedEndpoint{origin:config.origin.clone(),local:config.local,admitted_addresses:config.admitted_addresses.clone()};let client=endpoint.client().await?;
  Ok(Self{config,model,endpoint,client,credential})
 }
 fn request(&self,path:&str,body:Value,query:&[(&str,&str)])->Result<reqwest::RequestBuilder>{
  let url=if query.is_empty(){self.endpoint.url(path)?}else{self.endpoint.url_with_query(path,query)?};
  let mut request=self.client.post(url).json(&body);
  if let Some(key)=&self.credential {let key=std::str::from_utf8(key).map_err(|_| Error::Validation("credential must be UTF-8".into()))?;request=match self.config.kind {
   // OAuth subscriber tokens ride as Bearer with the OAuth beta header, never x-api-key: the endpoint rejects a subscription token sent as an API key. Selection comes only from the explicit provider credential_kind; ambient environment is never consulted.
   ProviderKind::Anthropic if self.config.credential_kind==CredentialKind::Oauth=>request.bearer_auth(key).header("anthropic-beta","oauth-2025-04-20"),
   ProviderKind::Anthropic=>request.header("x-api-key",key),ProviderKind::Gemini=>request.header("x-goog-api-key",key),_=>request.bearer_auth(key)};}
  if self.config.kind==ProviderKind::Anthropic {request=request.header("anthropic-version","2023-06-01");}
  Ok(request)
 }
 fn chat_body(&self,request:&ChatRequest,stream:bool)->Result<(String,Value)>{
  validate_request(request,&self.model.capabilities)?;
  let model=&self.model.model;
  match self.config.kind {
   ProviderKind::Ollama=>{
    let messages:Vec<Value>=request.messages.iter().map(|m| {let mut v=json!({"role":m.role,"content":m.content});if !m.images.is_empty(){v["images"]=json!(m.images.iter().map(|i| &i.data_base64).collect::<Vec<_>>());}if !m.tool_calls.is_empty(){v["tool_calls"]=json!(m.tool_calls.iter().map(|t|json!({"function":{"name":t.name,"arguments":t.arguments}})).collect::<Vec<_>>());}if let Some(id)=&m.tool_call_id {v["tool_name"]=json!(id);}v}).collect();
    // num_ctx follows the model config so long-context models size the KV cache once instead of paging; keep_alive is explicit per-model config only, never ambient env.
    let mut body=json!({"model":model,"messages":messages,"stream":stream,"options":{"num_predict":request.max_output_tokens,"num_ctx":self.model.context_tokens.max(8192)}});if let Some(keep_alive)=self.model.keep_alive.as_deref(){body["keep_alive"]=json!(keep_alive);}if !request.tools.is_empty(){body["tools"]=openai_tools(&request.tools);}if let Some(schema)=&request.output_schema{body["format"]=schema.clone();}if request.reasoning {body["think"]=json!(true);}Ok(("api/chat".into(),body))
   },
   ProviderKind::OpenaiCompatible=>{
    let messages:Vec<Value>=request.messages.iter().map(|m|{let content=if m.images.is_empty(){json!(m.content)}else{let mut parts=vec![json!({"type":"text","text":m.content})];parts.extend(m.images.iter().map(|i|json!({"type":"image_url","image_url":{"url":format!("data:{};base64,{}",i.mime_type,i.data_base64)}})));json!(parts)};let mut v=json!({"role":m.role,"content":content});if let Some(id)=&m.tool_call_id{v["tool_call_id"]=json!(id);}if !m.tool_calls.is_empty(){v["tool_calls"]=json!(m.tool_calls.iter().map(|t|json!({"id":t.id,"type":"function","function":{"name":t.name,"arguments":t.arguments.to_string()}})).collect::<Vec<_>>());}v}).collect();
    let mut body=json!({"model":model,"messages":messages,"max_tokens":request.max_output_tokens,"stream":stream});if stream{body["stream_options"]=json!({"include_usage":true});}if !request.tools.is_empty(){body["tools"]=openai_tools(&request.tools);}if let Some(schema)=&request.output_schema{body["response_format"]=json!({"type":"json_schema","json_schema":{"name":"orbit_response","strict":true,"schema":schema}});}if request.reasoning{body["reasoning_effort"]=json!("medium");}Ok(("chat/completions".into(),body))
   },
   ProviderKind::Anthropic=>{
    let system=request.messages.iter().filter(|m|m.role=="system").map(|m|m.content.as_str()).collect::<Vec<_>>().join("\n");
    let messages:Vec<Value>=request.messages.iter().filter(|m|m.role!="system").map(|m|{
     let mut content=vec![];if m.role=="tool"{content.push(json!({"type":"tool_result","tool_use_id":m.tool_call_id,"content":m.content}));}else{if !m.content.is_empty(){content.push(json!({"type":"text","text":m.content}));}for image in &m.images {content.push(json!({"type":"image","source":{"type":"base64","media_type":image.mime_type,"data":image.data_base64}}));}for t in &m.tool_calls{content.push(json!({"type":"tool_use","id":t.id,"name":t.name,"input":t.arguments}));}}
     json!({"role":if m.role=="assistant"{"assistant"}else{"user"},"content":content})}).collect();
    let mut body=json!({"model":model,"system":system,"messages":messages,"max_tokens":request.max_output_tokens,"stream":stream});let mut tools:Vec<Value>=request.tools.iter().map(|t|json!({"name":t.name,"description":t.description,"input_schema":t.input_schema})).collect();
    if let Some(schema)=&request.output_schema{tools.push(json!({"name":"orbit_json_output","description":"Return the requested JSON result","input_schema":schema}));body["tool_choice"]=json!({"type":"tool","name":"orbit_json_output"});}
    if !tools.is_empty(){body["tools"]=json!(tools);}if request.reasoning{if request.max_output_tokens<=1024{return Err(Error::Validation("Anthropic reasoning requires output budget greater than 1024".into()));}if request.output_schema.is_some(){return Err(Error::UnsupportedCapability);}body["thinking"]=json!({"type":"enabled","budget_tokens":1024});}
    Ok(("v1/messages".into(),body))
   },
   ProviderKind::Gemini=>{
    if model.contains('/') || model.contains('?') || model.contains('#'){return Err(Error::Validation("invalid Gemini model ID".into()));}
    let system=request.messages.iter().filter(|m|m.role=="system").map(|m|json!({"text":m.content})).collect::<Vec<_>>();
    let contents:Vec<Value>=request.messages.iter().filter(|m|m.role!="system").map(|m|{let mut parts=vec![];if m.role=="tool"{parts.push(json!({"functionResponse":{"name":m.tool_call_id,"response":{"result":m.content}}}));}else{if !m.content.is_empty(){parts.push(json!({"text":m.content}));}for i in &m.images{parts.push(json!({"inlineData":{"mimeType":i.mime_type,"data":i.data_base64}}));}for t in &m.tool_calls{parts.push(json!({"functionCall":{"name":t.name,"args":t.arguments}}));}}json!({"role":if m.role=="assistant"{"model"}else{"user"},"parts":parts})}).collect();
    let mut body=json!({"contents":contents,"generationConfig":{"maxOutputTokens":request.max_output_tokens}});if !system.is_empty(){body["systemInstruction"]=json!({"parts":system});}if !request.tools.is_empty(){body["tools"]=json!([{"functionDeclarations":request.tools.iter().map(|t|json!({"name":t.name,"description":t.description,"parameters":t.input_schema})).collect::<Vec<_>>()}]);}if let Some(schema)=&request.output_schema{body["generationConfig"]["responseMimeType"]=json!("application/json");body["generationConfig"]["responseJsonSchema"]=schema.clone();}if request.reasoning{body["generationConfig"]["thinkingConfig"]=json!({"thinkingBudget":1024,"includeThoughts":false});}
    let path=format!("v1beta/models/{model}:{}",if stream{"streamGenerateContent"}else{"generateContent"});Ok((path,body))
   }
  }
 }
 async fn send(&self,path:&str,body:Value,stream:bool)->Result<Response>{let query:&[(&str,&str)]=if stream && self.config.kind==ProviderKind::Gemini{&[("alt","sse")]}else{&[]};let response=self.request(path,body,query)?.send().await.map_err(transport_error)?;if !response.status().is_success(){return Err(status_error(response.status().as_u16()));}Ok(response)}
}
#[async_trait]
impl ModelProvider for HttpProvider {
 async fn complete(&self,request:ChatRequest)->Result<ChatResponse>{let(path,body)=self.chat_body(&request,false)?;let response=self.send(&path,body,false).await?;let value=bounded_json(response).await?;let mut output=normalize_response(self.config.kind,&value)?;validate_output(&request,&mut output)?;Ok(output)}
 async fn stream(&self,request:ChatRequest)->Result<ModelStream>{
  let(path,body)=self.chat_body(&request,true)?;let response=self.send(&path,body,true).await?;let kind=self.config.kind;
  Ok(Box::pin(async_stream::try_stream!{
   let mut bytes=response.bytes_stream();let mut pending=Vec::new();let mut total=0usize;let mut accumulator=Accumulator::default();let mut stopped=false;
   while let Some(chunk)=bytes.next().await {let chunk=chunk.map_err(transport_error)?;total+=chunk.len();if total>RESPONSE_LIMIT{Err(Error::Validation("model stream exceeds response limit".into()))?;}pending.extend_from_slice(&chunk);
    while let Some(end)=frame_end(&pending,kind){let frame:Vec<u8>=pending.drain(..end).collect();let text=std::str::from_utf8(&frame).map_err(|_| Error::Validation("invalid provider stream encoding".into()))?;let payload=if kind==ProviderKind::Ollama{text.trim().to_owned()}else{text.lines().filter_map(|line|line.strip_prefix("data:").map(str::trim)).collect::<Vec<_>>().join("\n")};if payload.is_empty(){continue;}if payload=="[DONE]"{stopped=true;break;}let value:Value=serde_json::from_str(&payload).map_err(|_| Error::Validation("invalid provider stream frame".into()))?;if value.get("error").is_some() || value.get("type").and_then(Value::as_str)==Some("error"){Err(Error::Unavailable("provider reported stream failure".into()))?;}
     let (chunks,done)=accumulator.consume(kind,&value)?;for chunk in chunks{yield chunk;}if done{stopped=true;break;}
    }if stopped{break;}
   }
   if !stopped && kind!=ProviderKind::Gemini {Err(Error::Unavailable("provider stream ended before completion".into()))?;}
   if !pending.is_empty() && !stopped {Err(Error::Validation("incomplete stream frame".into()))?;}
   let mut output=accumulator.finish()?;validate_output(&request,&mut output)?;yield ModelChunk::Done{response:output};
  }))
 }
 async fn embed(&self,request:EmbeddingRequest)->Result<EmbeddingResponse>{
  if !self.model.capabilities.embeddings || self.config.kind==ProviderKind::Anthropic{return Err(Error::UnsupportedCapability);}if request.input.is_empty()||request.input.len()>128||request.input.iter().any(|s|s.len()>1024*1024){return Err(Error::Validation("invalid embedding input".into()));}
  let (path,body)=match self.config.kind {ProviderKind::Ollama=>("api/embed".into(),json!({"model":self.model.model,"input":request.input})),ProviderKind::OpenaiCompatible=>("embeddings".into(),json!({"model":self.model.model,"input":request.input})),ProviderKind::Gemini=>{if self.model.model.contains('/') {return Err(Error::Validation("invalid Gemini model ID".into()));}let model=format!("models/{}",self.model.model);(format!("v1beta/{model}:batchEmbedContents"),json!({"requests":request.input.iter().map(|s|json!({"model":model,"content":{"parts":[{"text":s}]}})).collect::<Vec<_>>()}))},ProviderKind::Anthropic=>return Err(Error::UnsupportedCapability)};
  let value=bounded_json(self.send(&path,body,false).await?).await?;let raw=match self.config.kind{ProviderKind::Ollama=>value.get("embeddings").cloned(),ProviderKind::OpenaiCompatible=>{let mut data=value["data"].as_array().cloned().ok_or_else(||Error::Validation("missing embeddings".into()))?;data.sort_by_key(|v|v["index"].as_u64().unwrap_or(u64::MAX));Some(json!(data.iter().map(|v|v["embedding"].clone()).collect::<Vec<_>>()))},ProviderKind::Gemini=>Some(json!(value["embeddings"].as_array().ok_or_else(||Error::Validation("missing embeddings".into()))?.iter().map(|v|v["values"].clone()).collect::<Vec<_>>())),_=>None}.ok_or_else(||Error::Validation("missing embeddings".into()))?;
  let vectors:Vec<Vec<f32>>=serde_json::from_value(raw)?;if vectors.len()!=request.input.len()||vectors.first().is_none_or(Vec::is_empty)||vectors.iter().any(|v|v.len()!=vectors[0].len()||v.iter().any(|x|!x.is_finite())){return Err(Error::Validation("invalid embedding dimensions or values".into()));}Ok(EmbeddingResponse{vectors,usage:parse_usage(self.config.kind,&value)})
 }
 async fn rerank(&self,request:RerankRequest)->Result<RerankResponse>{let path=self.config.rerank_path.as_deref().ok_or(Error::UnsupportedCapability)?;if !self.model.capabilities.rerank{return Err(Error::UnsupportedCapability);}if request.documents.is_empty()||request.documents.len()>128||request.top_n==0||request.top_n>request.documents.len(){return Err(Error::Validation("invalid rerank input".into()));}let n=request.documents.len();let value=bounded_json(self.send(path,json!({"model":self.model.model,"query":request.query,"documents":request.documents,"top_n":request.top_n}),false).await?).await?;let results:Vec<RerankResult>=serde_json::from_value(value["results"].clone())?;let mut seen=std::collections::HashSet::new();if results.len()>request.top_n||results.iter().any(|r|r.index>=n||!r.relevance_score.is_finite()||!seen.insert(r.index)){return Err(Error::Validation("invalid rerank response".into()));}Ok(RerankResponse{results})}
 fn capabilities(&self)->ProviderCapabilities{self.model.capabilities.clone()}
}
fn transport_error(e:reqwest::Error)->Error{if e.is_timeout(){Error::Timeout}else{Error::Unavailable("model endpoint unreachable".into())}}
fn status_error(status:u16)->Error{match status{401|403=>Error::Unavailable("provider rejected configured credentials".into()),429=>Error::Unavailable("provider rate limit reached".into()),400|404|422=>Error::Validation("provider rejected configured model or operation".into()),_=>Error::Unavailable(format!("provider returned HTTP {status}"))}}
async fn bounded_json(response:Response)->Result<Value>{if response.content_length().is_some_and(|n|n>RESPONSE_LIMIT as u64){return Err(Error::Validation("model response exceeds limit".into()));}let mut bytes=response.bytes_stream();let mut buffer=Vec::new();while let Some(chunk)=bytes.next().await{let chunk=chunk.map_err(transport_error)?;if buffer.len()+chunk.len()>RESPONSE_LIMIT{return Err(Error::Validation("model response exceeds limit".into()));}buffer.extend_from_slice(&chunk);}serde_json::from_slice(&buffer).map_err(|_|Error::Validation("invalid provider JSON response".into()))}
fn openai_tools(tools:&[ToolSchema])->Value{json!(tools.iter().map(|t|json!({"type":"function","function":{"name":t.name,"description":t.description,"parameters":t.input_schema}})).collect::<Vec<_>>())}
pub fn validate_request(request:&ChatRequest,cap:&ProviderCapabilities)->Result<()>{
 if !cap.chat||(!request.tools.is_empty()&&!cap.tools)||(request.output_schema.is_some()&&!cap.structured_output)||(request.reasoning&&!cap.reasoning)||(request.messages.iter().any(|m|!m.images.is_empty())&&!cap.vision){return Err(Error::UnsupportedCapability);}
 if request.messages.is_empty()||request.messages.len()>256||request.max_output_tokens==0||request.max_output_tokens>131072{return Err(Error::Validation("invalid chat size or output budget".into()));}
 if serde_json::to_vec(request)?.len()>10*1024*1024{return Err(Error::Validation("chat input exceeds limit".into()));}
 for m in &request.messages{if !matches!(m.role.as_str(),"system"|"user"|"assistant"|"tool"){return Err(Error::Validation("invalid message role".into()));}for i in &m.images {if !matches!(i.mime_type.as_str(),"image/png"|"image/jpeg"|"image/webp"|"image/gif")||i.privacy_class==orbit_core::PrivacyClass::Secret||base64::engine::general_purpose::STANDARD.decode(&i.data_base64).is_err(){return Err(Error::Validation("invalid image input".into()));}}}
 for tool in &request.tools {if tool.name.is_empty()||tool.name.len()>64||!tool.name.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'_'||c==b'-')||tool.name=="orbit_json_output"{return Err(Error::Validation("invalid provider tool name".into()));}jsonschema::validator_for(&tool.input_schema).map_err(|_|Error::Validation("invalid tool JSON Schema".into()))?;}
 if let Some(schema)=&request.output_schema{jsonschema::validator_for(schema).map_err(|_|Error::Validation("invalid output JSON Schema".into()))?;}
 Ok(())
}
pub fn validate_output(request:&ChatRequest,response:&mut ChatResponse)->Result<()> {
 if let Some(schema)=&request.output_schema {
  let output=if let Some(call)=response.tool_calls.iter().find(|t|t.name=="orbit_json_output"){call.arguments.clone()}else{serde_json::from_str(&response.text).map_err(|_|Error::Validation("model returned invalid structured JSON".into()))?};
  if !jsonschema::validator_for(schema).map_err(|_|Error::Validation("invalid output schema".into()))?.is_valid(&output){return Err(Error::Validation("model output failed JSON Schema validation".into()));}response.structured_output=Some(output);response.tool_calls.retain(|t|t.name!="orbit_json_output");
 }
 for call in &response.tool_calls {let tool=request.tools.iter().find(|t|t.name==call.name).ok_or_else(||Error::Validation("model requested unregistered tool".into()))?;if !jsonschema::validator_for(&tool.input_schema).map_err(|_|Error::Validation("invalid tool schema".into()))?.is_valid(&call.arguments){return Err(Error::Validation("model tool arguments failed JSON Schema validation".into()));}}
 Ok(())
}
fn parse_usage(kind:ProviderKind,v:&Value)->Usage {let(u,input,output,cached)=match kind{ProviderKind::Ollama=>(v,"prompt_eval_count","eval_count","cached_tokens"),ProviderKind::OpenaiCompatible=>(&v["usage"],"prompt_tokens","completion_tokens","cached_tokens"),ProviderKind::Anthropic=>(&v["usage"],"input_tokens","output_tokens","cache_read_input_tokens"),ProviderKind::Gemini=>(&v["usageMetadata"],"promptTokenCount","candidatesTokenCount","cachedContentTokenCount")};Usage{input_tokens:u[input].as_u64().unwrap_or(0),output_tokens:u[output].as_u64().unwrap_or(0),cached_tokens:if kind==ProviderKind::OpenaiCompatible{u["prompt_tokens_details"]["cached_tokens"].as_u64().unwrap_or(0)}else{u[cached].as_u64().unwrap_or(0)},known:u[input].is_number()&&u[output].is_number()}}
fn normalize_response(kind:ProviderKind,v:&Value)->Result<ChatResponse>{
 if v.get("error").is_some(){return Err(Error::Unavailable("provider returned an error".into()));}
 let mut out=ChatResponse{usage:parse_usage(kind,v),..Default::default()};
 match kind {
  ProviderKind::Ollama|ProviderKind::OpenaiCompatible=>{let m=if kind==ProviderKind::Ollama{&v["message"]}else{&v["choices"][0]["message"]};if !m.is_object(){return Err(Error::Validation("missing completion message".into()));}out.text=m["content"].as_str().unwrap_or("").to_owned();if let Some(calls)=m["tool_calls"].as_array(){for(index,t)in calls.iter().enumerate(){let f=&t["function"];let arguments=if let Some(text)=f["arguments"].as_str(){serde_json::from_str(text).map_err(|_|Error::Validation("invalid tool JSON".into()))?}else{f["arguments"].clone()};out.tool_calls.push(ToolCall{id:t["id"].as_str().map(str::to_owned).unwrap_or_else(||format!("ollama_{index}")),name:f["name"].as_str().ok_or_else(||Error::Validation("missing tool name".into()))?.into(),arguments});}}out.finish_reason=if kind==ProviderKind::Ollama{v["done_reason"].as_str()}else{v["choices"][0]["finish_reason"].as_str()}.map(str::to_owned);},
  ProviderKind::Anthropic=>{for block in v["content"].as_array().ok_or_else(||Error::Validation("missing Anthropic content".into()))?{match block["type"].as_str(){Some("text")=>out.text.push_str(block["text"].as_str().unwrap_or("")),Some("tool_use")=>out.tool_calls.push(ToolCall{id:block["id"].as_str().unwrap_or("").into(),name:block["name"].as_str().unwrap_or("").into(),arguments:block["input"].clone()}),_=>{}}}out.finish_reason=v["stop_reason"].as_str().map(str::to_owned);},
  ProviderKind::Gemini=>{let candidate=&v["candidates"][0];if !candidate.is_object(){return Err(Error::Validation("Gemini returned no candidate".into()));}for(index,part)in candidate["content"]["parts"].as_array().ok_or_else(||Error::Validation("missing Gemini content".into()))?.iter().enumerate(){if part["thought"]==true{continue;}if let Some(text)=part["text"].as_str(){out.text.push_str(text);}if let Some(f)=part.get("functionCall"){out.tool_calls.push(ToolCall{id:f["id"].as_str().map(str::to_owned).unwrap_or_else(||format!("gemini_{index}")),name:f["name"].as_str().unwrap_or("").into(),arguments:f["args"].clone()});}}out.finish_reason=candidate["finishReason"].as_str().map(str::to_owned);}
 }
 Ok(out)
}
fn frame_end(bytes:&[u8],kind:ProviderKind)->Option<usize>{if kind==ProviderKind::Ollama{bytes.iter().position(|c|*c==b'\n').map(|i|i+1)}else{bytes.windows(2).position(|w|w==b"\n\n").map(|i|i+2).or_else(||bytes.windows(4).position(|w|w==b"\r\n\r\n").map(|i|i+4))}}
#[derive(Default)]struct Accumulator {out:ChatResponse,calls:BTreeMap<usize,(String,String,String)>}
impl Accumulator {
 fn consume(&mut self,kind:ProviderKind,v:&Value)->Result<(Vec<ModelChunk>,bool)>{
  let mut chunks=vec![];let mut done=false;
  match kind {
   ProviderKind::OpenaiCompatible=>{if !v["usage"].is_null(){self.out.usage=parse_usage(kind,v);}let choice=&v["choices"][0];let delta=&choice["delta"];if let Some(text)=delta["content"].as_str(){self.text(text,&mut chunks);}if let Some(calls)=delta["tool_calls"].as_array(){for t in calls{let index=t["index"].as_u64().unwrap_or(0)as usize;self.delta(index,t["id"].as_str(),t["function"]["name"].as_str(),t["function"]["arguments"].as_str().unwrap_or(""),&mut chunks);}}if let Some(reason)=choice["finish_reason"].as_str(){self.out.finish_reason=Some(reason.into());}},
   ProviderKind::Ollama=>{if let Some(text)=v["message"]["content"].as_str(){self.text(text,&mut chunks);}if let Some(calls)=v["message"]["tool_calls"].as_array(){for t in calls{let index=self.calls.len();self.delta(index,None,t["function"]["name"].as_str(),&t["function"]["arguments"].to_string(),&mut chunks);}}if v["done"]==true{self.out.usage=parse_usage(kind,v);self.out.finish_reason=v["done_reason"].as_str().map(str::to_owned);done=true;}},
   ProviderKind::Anthropic=>{let index=v["index"].as_u64().unwrap_or(0)as usize;match v["type"].as_str(){Some("message_start")=>{let usage=parse_usage(kind,&v["message"]);self.out.usage=usage;},Some("content_block_start")=>{let b=&v["content_block"];if b["type"]=="tool_use"{self.delta(index,b["id"].as_str(),b["name"].as_str(),"",&mut chunks);}else if b["type"]=="text"{if let Some(text)=b["text"].as_str(){self.text(text,&mut chunks);}}},Some("content_block_delta")=>{let d=&v["delta"];if d["type"]=="text_delta"{if let Some(text)=d["text"].as_str(){self.text(text,&mut chunks);}}else if d["type"]=="input_json_delta"{self.delta(index,None,None,d["partial_json"].as_str().unwrap_or(""),&mut chunks);}},Some("message_delta")=>{if let Some(output)=v["usage"]["output_tokens"].as_u64(){self.out.usage.output_tokens=output;self.out.usage.known=true;}self.out.finish_reason=v["delta"]["stop_reason"].as_str().map(str::to_owned);},Some("message_stop")=>done=true,_=>{}}},
   ProviderKind::Gemini=>{let out=normalize_response(kind,v)?;self.text(&out.text,&mut chunks);for call in out.tool_calls{let index=self.calls.len();self.delta(index,Some(&call.id),Some(&call.name),&call.arguments.to_string(),&mut chunks);}if !v["usageMetadata"].is_null(){self.out.usage=out.usage;}if out.finish_reason.is_some(){self.out.finish_reason=out.finish_reason;/* Gemini usage may arrive in a following frame. */}},
  }
  Ok((chunks,done))
 }
 fn text(&mut self,text:&str,chunks:&mut Vec<ModelChunk>){if !text.is_empty(){self.out.text.push_str(text);chunks.push(ModelChunk::Text{text:text.into()});}}
 fn delta(&mut self,index:usize,id:Option<&str>,name:Option<&str>,arguments:&str,chunks:&mut Vec<ModelChunk>){let t=self.calls.entry(index).or_default();if let Some(id)=id{t.0.push_str(id);}if let Some(name)=name{t.1.push_str(name);}t.2.push_str(arguments);chunks.push(ModelChunk::ToolCallDelta{index,id:id.map(str::to_owned),name:name.map(str::to_owned),arguments:arguments.into()});}
 fn finish(mut self)->Result<ChatResponse>{for(index,(id,name,args))in self.calls{self.out.tool_calls.push(ToolCall{id:if id.is_empty(){format!("call_{index}")}else{id},name,arguments:if args.is_empty(){json!({})}else{serde_json::from_str(&args).map_err(|_|Error::Validation("invalid streamed tool arguments".into()))?}});}Ok(self.out)}
}
#[cfg(test)]
mod tests {
 use super::*;
 fn configs(kind:ProviderKind,credential_kind:CredentialKind,context_tokens:u32,keep_alive:Option<&str>)->(ProviderConfig,ModelConfig){
  let provider=ProviderConfig{id:Uuid::new_v4(),name:"p".into(),kind,origin:"https://example.com".into(),local:false,admitted_addresses:vec![],credential_id:None,credential_kind,rerank_path:None,enabled:true};
  let model=ModelConfig{id:Uuid::new_v4(),provider_id:provider.id,model:"m".into(),name:"m".into(),roles:vec![],priority:100,context_tokens,capabilities:ProviderCapabilities{chat:true,tools:true,..Default::default()},input_usd_per_million:None,output_usd_per_million:None,keep_alive:keep_alive.map(str::to_owned),enabled:true};
  (provider,model)
 }
 fn provider_with(provider:ProviderConfig,model:ModelConfig,credential:&str)->HttpProvider{
  let client=Client::new();let endpoint=AdmittedEndpoint{origin:provider.origin.clone(),local:provider.local,admitted_addresses:provider.admitted_addresses.clone()};
  HttpProvider{config:provider,model,endpoint,client,credential:Some(Zeroizing::new(credential.as_bytes().to_vec()))}
 }
 #[test]
 fn anthropic_api_key_uses_x_api_key_without_beta(){
  let(provider,model)=configs(ProviderKind::Anthropic,CredentialKind::ApiKey,8192,None);
  let request=provider_with(provider,model,"sk-test").request("v1/messages",json!({}),&[]).unwrap().build().unwrap();
  let headers=request.headers();
  assert_eq!(headers.get("x-api-key").unwrap(),"sk-test");
  assert!(headers.get(reqwest::header::AUTHORIZATION).is_none());
  assert!(headers.get("anthropic-beta").is_none());
  assert_eq!(headers.get("anthropic-version").unwrap(),"2023-06-01");
 }
 #[test]
 fn anthropic_oauth_uses_bearer_with_beta_header(){
  let(provider,model)=configs(ProviderKind::Anthropic,CredentialKind::Oauth,8192,None);
  let request=provider_with(provider,model,"sub-token").request("v1/messages",json!({}),&[]).unwrap().build().unwrap();
  let headers=request.headers();
  assert!(headers.get("x-api-key").is_none());
  assert_eq!(headers.get(reqwest::header::AUTHORIZATION).unwrap(),"Bearer sub-token");
  assert_eq!(headers.get("anthropic-beta").unwrap(),"oauth-2025-04-20");
 }
 #[test]
 fn anthropic_assistant_tool_use_echoes_for_second_turn_ids(){
  // Port of the AIec round-trip invariant: assistant tool_calls must reappear as tool_use blocks carrying the same id, or the following tool_result turn dangles and Messages answers 400.
  let(provider,model)=configs(ProviderKind::Anthropic,CredentialKind::ApiKey,8192,None);
  let client=Client::new();let endpoint=AdmittedEndpoint{origin:provider.origin.clone(),local:false,admitted_addresses:vec![]};
  let adapter=HttpProvider{config:provider,model,endpoint,client,credential:None};
  let request=ChatRequest{messages:vec![
   ChatMessage{role:"user".into(),content:"read a.rs".into(),..Default::default()},
   ChatMessage{role:"assistant".into(),content:"reading now".into(),tool_calls:vec![ToolCall{id:"tu1".into(),name:"read".into(),arguments:json!({"path":"a.rs"})}],..Default::default()},
   ChatMessage{role:"tool".into(),content:"contents".into(),tool_call_id:Some("tu1".into()),..Default::default()},
  ],max_output_tokens:64,..Default::default()};
  let(_,body)=adapter.chat_body(&request,false).unwrap();
  let messages=body["messages"].as_array().unwrap();
  assert_eq!(messages.len(),3);
  let blocks=messages[1]["content"].as_array().unwrap();
  assert_eq!(blocks.len(),2);
  assert_eq!(blocks[0]["type"],"text");
  assert_eq!(blocks[1]["type"],"tool_use");
  assert_eq!(blocks[1]["id"],"tu1");
  assert_eq!(blocks[1]["input"]["path"],"a.rs");
  assert_eq!(messages[2]["content"][0]["tool_use_id"],"tu1");
 }
 #[test]
 fn ollama_body_sizes_ctx_and_keeps_model_loaded(){
  let(provider,model)=configs(ProviderKind::Ollama,CredentialKind::ApiKey,32768,Some("5m"));
  let client=Client::new();let endpoint=AdmittedEndpoint{origin:"http://127.0.0.1:11434".into(),local:true,admitted_addresses:vec![]};
  let adapter=HttpProvider{config:provider,model,endpoint,client,credential:None};
  let request=ChatRequest{messages:vec![ChatMessage{role:"user".into(),content:"hi".into(),..Default::default()}],max_output_tokens:64,..Default::default()};
  let(path,body)=adapter.chat_body(&request,true).unwrap();
  assert_eq!(path,"api/chat");
  assert_eq!(body["options"]["num_ctx"],32768);
  assert_eq!(body["keep_alive"],"5m");
  assert_eq!(body["stream"],true);
 }
 #[test]
 fn ollama_body_floors_ctx_and_omits_keep_alive_when_unset(){
  let(provider,model)=configs(ProviderKind::Ollama,CredentialKind::ApiKey,1024,None);
  let client=Client::new();let endpoint=AdmittedEndpoint{origin:"http://127.0.0.1:11434".into(),local:true,admitted_addresses:vec![]};
  let adapter=HttpProvider{config:provider,model,endpoint,client,credential:None};
  let request=ChatRequest{messages:vec![ChatMessage{role:"user".into(),content:"hi".into(),..Default::default()}],max_output_tokens:64,..Default::default()};
  let(_,body)=adapter.chat_body(&request,false).unwrap();
  assert_eq!(body["options"]["num_ctx"],8192);
  assert!(body.get("keep_alive").is_none());
 }
}
