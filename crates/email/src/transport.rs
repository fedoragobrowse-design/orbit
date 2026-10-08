use crate::{AccountConfig,Credential,DraftContent,Message,Attachment,MAX_MESSAGE_BYTES};
use orbit_core::{Error,Result};
use tokio::{io::{AsyncBufReadExt,AsyncReadExt,AsyncWriteExt,BufReader},net::TcpStream};
use tokio_rustls::{TlsConnector,client::TlsStream};
use std::sync::Arc;
use base64::{Engine,engine::general_purpose::STANDARD};
use serde_json::json;
use mailparse::MailHeaderMap;
use sha2::{Digest,Sha256};
fn unavailable()->Error{Error::Unavailable("verified mail transport failed".into())}
type Stream=BufReader<TlsStream<TcpStream>>;
async fn tls(host:&str,port:u16,ca:Option<&str>)->Result<Stream>{
 let mut roots=rustls::RootCertStore::empty();roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
 if let Some(pem)=ca{for cert in rustls_pemfile::certs(&mut pem.as_bytes()){roots.add(cert.map_err(|_|unavailable())?).map_err(|_|unavailable())?;}}
 let config=rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().map_err(|_|unavailable())?.with_root_certificates(roots).with_no_client_auth();
 let name=rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|_|Error::Validation("invalid TLS mail hostname".into()))?;
 let tcp=TcpStream::connect((host,port)).await.map_err(|_|unavailable())?;
 let stream=TlsConnector::from(Arc::new(config)).connect(name,tcp).await.map_err(|_|unavailable())?;Ok(BufReader::new(stream))
}
async fn line(stream:&mut Stream)->Result<String>{let mut bytes=Vec::new();let n=stream.take(8193).read_until(b'\n',&mut bytes).await.map_err(|_|unavailable())?;if n==0||bytes.len()>8192{return Err(unavailable())}String::from_utf8(bytes).map_err(|_|unavailable())}
fn quoted(s:&str)->Result<String>{if s.len()>1024||s.chars().any(|c|c=='\r'||c=='\n'||c=='\0'){return Err(Error::Validation("invalid IMAP parameter".into()))}Ok(format!("\"{}\"",s.replace('\\',"\\\\").replace('"',"\\\"")))}
pub struct Imap{stream:Stream,tag:u64}
impl Imap{
 pub async fn connect(config:&AccountConfig,credential:&Credential)->Result<Self>{let mut stream=tls(&config.imap_host,config.imap_port,config.ca_pem.as_deref()).await?;let greeting=line(&mut stream).await?;if !greeting.starts_with("* OK"){return Err(unavailable())}let mut imap=Self{stream,tag:0};imap.command(&format!("LOGIN {} {}",quoted(&credential.username)?,quoted(&credential.password)?)).await?;Ok(imap)}
 pub async fn command(&mut self,command:&str)->Result<Vec<u8>>{
  self.tag+=1;let tag=format!("O{:08}",self.tag);self.stream.write_all(format!("{tag} {command}\r\n").as_bytes()).await.map_err(|_|unavailable())?;
  self.stream.flush().await.map_err(|_|unavailable())?;let mut result=Vec::new();
  loop{let l=line(&mut self.stream).await?;if result.len()+l.len()>MAX_MESSAGE_BYTES+65536{return Err(Error::Validation("IMAP response exceeds bound".into()))}result.extend_from_slice(l.as_bytes());
   if l.starts_with(&format!("{tag} ")){if !l.starts_with(&format!("{tag} OK")){return Err(Error::Unavailable("IMAP command rejected".into()))}break}
   if let Some(start)=l.rfind('{'){if l.trim_end().ends_with('}'){let count=l[start+1..].trim_end().trim_end_matches('}').parse::<usize>().map_err(|_|unavailable())?;if count>MAX_MESSAGE_BYTES||result.len()+count>MAX_MESSAGE_BYTES+65536{return Err(Error::Validation("mail message exceeds bound".into()))}let offset=result.len();result.resize(offset+count,0);self.stream.read_exact(&mut result[offset..]).await.map_err(|_|unavailable())?;}}
  }Ok(result)
 }
 pub async fn select(&mut self,mailbox:&str)->Result<i64>{let bytes=self.command(&format!("SELECT {}",quoted(mailbox)?)).await?;let text=String::from_utf8_lossy(&bytes);let start=text.find("[UIDVALIDITY ").ok_or_else(unavailable)?+13;let value=text[start..].split(']').next().ok_or_else(unavailable)?.parse().map_err(|_|unavailable())?;Ok(value)}
 pub async fn search(&mut self,start:i64)->Result<Vec<i64>>{let bytes=self.command(&format!("UID SEARCH UID {}:*",start.max(1))).await?;let text=String::from_utf8_lossy(&bytes);let ids=text.lines().find(|l|l.starts_with("* SEARCH")).ok_or_else(unavailable)?;let mut result=Vec::new();for word in ids.split_whitespace().skip(2){let id=word.parse::<i64>().map_err(|_|unavailable())?;if id>=start{result.push(id)}}result.sort_unstable();result.dedup();Ok(result)}
 pub async fn fetch(&mut self,uid:i64)->Result<Vec<u8>>{let bytes=self.command(&format!("UID FETCH {uid} (BODY.PEEK[])")).await?;let start=bytes.windows(2).position(|w|w==b"\r\n").ok_or_else(unavailable)?;let first=String::from_utf8_lossy(&bytes[..start]);let open=first.rfind('{').ok_or_else(unavailable)?;let count=first[open+1..].trim_end_matches('}').parse::<usize>().map_err(|_|unavailable())?;let begin=start+2;if begin+count>bytes.len(){return Err(unavailable())}Ok(bytes[begin..begin+count].to_vec())}
 pub async fn archive(&mut self,uid:i64,destination:&str)->Result<()>{self.command(&format!("UID MOVE {uid} {}",quoted(destination)?)).await?;Ok(())}
 pub async fn label(&mut self,uid:i64,label:&str)->Result<()>{if !matches!(label,"\\Seen"|"\\Flagged"|"\\Answered"){return Err(Error::UnsupportedCapability)}self.command(&format!("UID STORE {uid} +FLAGS.SILENT ({label})")).await?;Ok(())}
}
pub fn parse_message(raw:&[u8])->Result<Message>{
 if raw.len()>MAX_MESSAGE_BYTES{return Err(Error::Validation("mail exceeds MIME bound".into()))}
 let mail=mailparse::parse_mail(raw).map_err(|_|Error::Validation("malformed MIME message".into()))?;
 let id=mail.headers.get_first_value("Message-ID").unwrap_or_default().trim().to_owned();
 let metadata=json!({"from":mail.headers.get_first_value("From"),"to":mail.headers.get_first_value("To"),"cc":mail.headers.get_first_value("Cc"),"subject":mail.headers.get_first_value("Subject"),"date":mail.headers.get_first_value("Date"),"in_reply_to":mail.headers.get_first_value("In-Reply-To")});
 let mut body=String::new();let mut attachments=Vec::new();let mut count=0;
 fn walk(mail:&mailparse::ParsedMail<'_>,depth:usize,count:&mut usize,body:&mut String,attachments:&mut Vec<Attachment>)->Result<()>{*count+=1;if depth>12||*count>64{return Err(Error::Validation("MIME nesting or part bound exceeded".into()))}if !mail.subparts.is_empty(){for part in &mail.subparts{walk(part,depth+1,count,body,attachments)?}return Ok(())}
  let bytes=mail.get_body_raw().map_err(|_|Error::Validation("MIME body decoding failed".into()))?;if bytes.len()>MAX_MESSAGE_BYTES{return Err(Error::Validation("MIME decoded bound exceeded".into()))}
  let disposition=mail.get_content_disposition();if mail.ctype.mimetype=="text/plain"&&disposition.disposition!=mailparse::DispositionType::Attachment{let text=mail.get_body().map_err(|_|Error::Validation("MIME text decoding failed".into()))?;if body.len()+text.len()>MAX_MESSAGE_BYTES{return Err(Error::Validation("MIME text bound exceeded".into()))}body.push_str(&text);body.push('\n');}else{let name=disposition.params.get("filename").cloned().unwrap_or_else(||"attachment".into());attachments.push(Attachment{name,mime:mail.ctype.mimetype.clone(),sha256:hex::encode(Sha256::digest(&bytes)),content_base64:STANDARD.encode(bytes)});}Ok(())}
 walk(&mail,0,&mut count,&mut body,&mut attachments)?;
 let references=mail.headers.get_first_value("References").unwrap_or_default().split_whitespace().take(64).map(str::to_owned).collect();
 Ok(Message{message_id:id,source_key:hex::encode(Sha256::digest(raw)),metadata,body_text:body,attachments,references})
}
async fn smtp_response(s:&mut Stream)->Result<u16>{let mut count=0;loop{let l=line(s).await?;count+=1;if count>100||l.len()<4{return Err(unavailable())}let code=l[..3].parse::<u16>().map_err(|_|unavailable())?;if l.as_bytes()[3]!=b'-'{return Ok(code)}}}
async fn smtp_command(s:&mut Stream,c:&str,expected:u16)->Result<()>{s.write_all(format!("{c}\r\n").as_bytes()).await.map_err(|_|unavailable())?;s.flush().await.map_err(|_|unavailable())?;if smtp_response(s).await?!=expected{return Err(Error::Unavailable("SMTP command rejected".into()))}Ok(())}
pub fn wire_message(draft:&DraftContent,id:uuid::Uuid)->Result<Vec<u8>>{
 draft.validate()?;let boundary=format!("orbit-{}",id.simple());let mut body=format!("From: {}\r\nTo: {}\r\nCc: {}\r\nSubject: =?UTF-8?B?{}?=\r\nMessage-ID: <{}@orbit.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\r\n",draft.from,draft.to.join(", "),draft.cc.join(", "),STANDARD.encode(draft.subject.as_bytes()),id);
 if let Some(reply)=&draft.in_reply_to{body.push_str(&format!("In-Reply-To: {reply}\r\n"))}if !draft.references.is_empty(){body.push_str(&format!("References: {}\r\n",draft.references.join(" ")))}
 body.push_str(&format!("\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",wrapped_base64(draft.body.as_bytes())));
 for a in &draft.attachments{let bytes=STANDARD.decode(&a.content_base64).map_err(|_|Error::Validation("invalid attachment".into()))?;body.push_str(&format!("--{boundary}\r\nContent-Type: {}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",a.mime,a.name,wrapped_base64(&bytes)));}body.push_str(&format!("--{boundary}--\r\n"));Ok(body.into_bytes())
}
fn wrapped_base64(bytes:&[u8])->String{let encoded=STANDARD.encode(bytes);encoded.as_bytes().chunks(76).map(|s|std::str::from_utf8(s).unwrap()).collect::<Vec<_>>().join("\r\n")}
/// Exactly one SMTP transmission. Once DATA bytes may have escaped, every transport
/// failure is uncertain; callers durably mark SUBMITTED before invoking this.
pub async fn send_once(c:&AccountConfig,credential:&Credential,draft:&DraftContent,id:uuid::Uuid)->Result<()>{
 let mut s=tls(&c.smtp_host,c.smtp_port,c.ca_pem.as_deref()).await?;if smtp_response(&mut s).await?!=220{return Err(unavailable())}smtp_command(&mut s,"EHLO orbit.invalid",250).await?;
 let auth=STANDARD.encode(format!("\0{}\0{}",credential.username,credential.password));smtp_command(&mut s,&format!("AUTH PLAIN {auth}"),235).await?;smtp_command(&mut s,&format!("MAIL FROM:<{}>",draft.from),250).await?;
 for address in draft.to.iter().chain(&draft.cc).chain(&draft.bcc){smtp_command(&mut s,&format!("RCPT TO:<{address}>"),250).await?;}smtp_command(&mut s,"DATA",354).await?;
 let wire=wire_message(draft,id)?;s.write_all(&wire).await.map_err(|_|Error::OutcomeUnknown)?;s.write_all(b".\r\n").await.map_err(|_|Error::OutcomeUnknown)?;s.flush().await.map_err(|_|Error::OutcomeUnknown)?;
 let code=smtp_response(&mut s).await.map_err(|_|Error::OutcomeUnknown)?;if code!=250{return Err(Error::Unavailable("SMTP explicitly rejected DATA".into()))}Ok(())
}
