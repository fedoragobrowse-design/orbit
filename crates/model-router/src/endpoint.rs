use orbit_core::{Error,Result};
use std::{net::{IpAddr,SocketAddr},time::Duration};
use reqwest::{Client,Url};

#[derive(Debug,Clone)]
pub struct AdmittedEndpoint {pub origin:String,pub local:bool,pub admitted_addresses:Vec<IpAddr>}
impl AdmittedEndpoint {
 pub fn url(&self,path:&str)->Result<Url> {
  let mut url=Url::parse(&self.origin).map_err(|_| Error::Validation("invalid endpoint origin".into()))?;
  if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() || !matches!(url.scheme(),"http"|"https") || url.host_str().is_none() {return Err(Error::Validation("endpoint must be an HTTP(S) origin without credentials or query".into()));}
  // Base paths are useful for /v1 gateways; paths supplied here are trusted adapter constants.
  if path.contains("://") || path.starts_with("//") || path.split('/').any(|s| s=="..") {return Err(Error::Validation("invalid endpoint path".into()));}
  let joined=format!("{}/{}",url.path().trim_end_matches('/'),path.trim_start_matches('/')); url.set_path(&joined); Ok(url)
 }
 pub fn url_with_query(&self,path:&str,query:&[(&str,&str)])->Result<Url> {
  let mut url=self.url(path)?;
  {let mut pairs=url.query_pairs_mut();for(key,value) in query {pairs.append_pair(key,value);}}
  Ok(url)
 }
 pub async fn client(&self)->Result<Client> { self.client_with_ca(None).await }
 pub async fn client_with_ca(&self,ca_pem:Option<&[u8]>)->Result<Client> {
  let url=self.url("")?; let host=url.host_str().ok_or(Error::Forbidden)?; let port=url.port_or_known_default().ok_or(Error::Forbidden)?;
  if !self.local && url.scheme()!="https" {return Err(Error::Validation("remote endpoint requires HTTPS".into()));}
  let addresses:Vec<SocketAddr>=tokio::net::lookup_host((host,port)).await.map_err(|_| Error::Unavailable("endpoint DNS lookup failed".into()))?.collect();
  if addresses.is_empty() {return Err(Error::Unavailable("endpoint has no addresses".into()));}
  for address in &addresses {
   let ip=address.ip();
   if forbidden(ip) {return Err(Error::Forbidden);}
   if self.local {
    if !local_address(ip) || !self.admitted_addresses.contains(&ip) {return Err(Error::Validation("local endpoint address is not explicitly admitted".into()));}
   } else if local_address(ip) && !self.admitted_addresses.contains(&ip) {return Err(Error::Forbidden);}
   if !self.admitted_addresses.is_empty() && !self.admitted_addresses.contains(&ip) {return Err(Error::Forbidden);}
  }
  let mut builder=Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy().connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(120)).resolve_to_addrs(host,&addresses);
  if let Some(pem)=ca_pem {builder=builder.add_root_certificate(reqwest::Certificate::from_pem(pem).map_err(|_| Error::Validation("invalid CA certificate".into()))?);}
  builder.build().map_err(|_| Error::Unavailable("endpoint client unavailable".into()))
 }
}
pub fn local_address(ip:IpAddr)->bool {match ip {IpAddr::V4(v)=>v.is_loopback()||v.is_private(),IpAddr::V6(v)=>v.is_loopback()||v.is_unique_local()}}
fn forbidden(ip:IpAddr)->bool {match ip {IpAddr::V4(v)=>v.is_link_local()||v.is_unspecified()||v.is_multicast()||v.is_broadcast()||v.octets()[0]==0,IpAddr::V6(v)=>v.is_unicast_link_local()||v.is_unspecified()||v.is_multicast()||v.to_ipv4_mapped().is_some_and(|v| forbidden(IpAddr::V4(v)))}}

#[cfg(test)] mod tests {use super::*; #[test] fn forbids_metadata_and_origin_injection(){assert!(forbidden("169.254.169.254".parse().unwrap()));assert!(forbidden("::ffff:169.254.169.254".parse().unwrap())); let e=AdmittedEndpoint{origin:"https://example.com".into(),local:false,admitted_addresses:vec![]};assert!(e.url("https://evil.test").is_err()); assert!(e.url("../secrets").is_err());} }
