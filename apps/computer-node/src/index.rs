use crate::{file_id, native, NativeMutation, NativeOutcome};
use orbit_computer_node_protocol::{Error, Result, RootGrant, RootMode, FileRecord, IndexStatus, FileEvent, MAX_TEXT, MAX_FILE, MAX_PAGE};
use rusqlite::{Connection, params, OptionalExtension};
use serde_json::{Value, json};
use std::{collections::{HashMap, HashSet}, path::Path};
use uuid::Uuid;
fn db<T>(r: rusqlite::Result<T>) -> Result<T> { r.map_err(|_| Error::Invalid("local state database operation failed".into())) }
pub struct Index { pub connection: Connection }
impl Index {
 pub fn open(path: &Path) -> Result<Self> {
    let connection = db(Connection::open(path))?;
    db(connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS files(root TEXT NOT NULL,id TEXT NOT NULL,path TEXT NOT NULL,record TEXT NOT NULL,text TEXT NOT NULL,vector BLOB,embedding_space TEXT,PRIMARY KEY(root,id),UNIQUE(root,path));
      CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(root UNINDEXED,id UNINDEXED,path,text);
      CREATE TABLE IF NOT EXISTS index_status(root TEXT PRIMARY KEY,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS outgoing(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,hash TEXT NOT NULL,authorization TEXT NOT NULL,request TEXT NOT NULL,evidence TEXT,result TEXT,state TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS watches(id TEXT PRIMARY KEY,root TEXT NOT NULL,types TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS incidents(key TEXT PRIMARY KEY,evidence TEXT NOT NULL);
    "))?; Ok(Self { connection })
 }
 pub fn purge(&mut self, root: Uuid) -> Result<()> {
    let tx = db(self.connection.transaction())?;
    for sql in ["DELETE FROM files WHERE root=?", "DELETE FROM search WHERE root=?", "DELETE FROM index_status WHERE root=?", "DELETE FROM watches WHERE root=?"] { db(tx.execute(sql, [root.to_string()]))?; }
    db(tx.commit())?; Ok(())
 }
 pub fn status(&self, root: Uuid) -> Result<IndexStatus> {
    let s: Option<String> = db(self.connection.query_row("SELECT status FROM index_status WHERE root=?", [root.to_string()], |r| r.get(0)).optional())?;
    Ok(s.map(|s|serde_json::from_str(&s)).transpose()?.unwrap_or(IndexStatus { available_modes:vec!["FILENAME".into(),"TEXT".into()],..Default::default() }))
 }
 pub fn mark_gap(&self, root: Uuid) -> Result<()> { let mut status = self.status(root)?; status.gap=true; self.save_status(root,&status) }
 fn save_status(&self, root:Uuid,status:&IndexStatus)->Result<()> { db(self.connection.execute("INSERT INTO index_status(root,status) VALUES(?,?) ON CONFLICT(root) DO UPDATE SET status=excluded.status",params![root.to_string(),serde_json::to_string(status)?]))?; Ok(()) }
 pub fn scan(&mut self, root:&RootGrant) -> Result<IndexStatus> {
    if root.revoked { self.purge(root.id)?; return Ok(IndexStatus::default()); }
    let old=self.records(root.id)?; let old:HashMap<Uuid,FileRecord>=old.into_iter().map(|r|(r.file_id,r)).collect();
    let mut records=Vec::new(); let mut texts=HashMap::new(); let mut status=IndexStatus{available_modes:vec!["FILENAME".into(),"TEXT".into()],..Default::default()};
    let mut dirs=vec![".".to_string()]; let mut seen=HashSet::new();
    while let Some(dir)=dirs.pop() {
      let entries=match native::entries(root,&dir) { Ok(e)=>e,Err(_)=>{status.unreadable+=1;continue;} };
      for name in entries {
       let path=if dir=="." {name} else {format!("{dir}/{name}")};
       let meta=match if root.mode==RootMode::Ask {native::metadata_only(root,&path)} else {native::metadata(root,&path)} {Ok(m)=>m,Err(_)=>{status.unreadable+=1;continue;}};
       if !seen.insert(meta.identity.clone()) {status.skipped+=1;continue;}
       let id=file_id(root.id,&meta.identity); let version=meta.version();
       if meta.kind=="DIRECTORY" {dirs.push(path.clone());}
       let mut text=String::new();
       if meta.kind=="FILE" && root.mode!=RootMode::Ask {
        if meta.size>MAX_TEXT as u64 {status.truncated+=1;}
        match native::read(root,&path,MAX_FILE) {Ok(bytes)=> {let extracted=&bytes[..bytes.len().min(MAX_TEXT)]; match std::str::from_utf8(extracted) {Ok(s) if !s.contains('\0')=>text=s.to_owned(),_=>status.skipped+=1}},Err(_)=>status.unreadable+=1}
       }
       let record=FileRecord{file_id:id,root_id:root.id,relative_path:path,kind:meta.kind,version:version.clone(),sha256:if root.mode==RootMode::Ask {None}else{meta.digest},size:meta.size,privacy_class:"PRIVATE".into(),source_reference:format!("root:{}:file:{id}:{version}",root.id)};
       texts.insert(id,text);records.push(record);
      }
    }
    status.indexed=records.len() as u64;
    let tx=db(self.connection.transaction())?;
    db(tx.execute("DELETE FROM search WHERE root=?",[root.id.to_string()]))?;
    for record in &records {
      let text=&texts[&record.file_id];
      db(tx.execute("INSERT INTO files(root,id,path,record,text) VALUES(?,?,?,?,?) ON CONFLICT(root,id) DO UPDATE SET path=excluded.path,record=excluded.record,text=excluded.text,vector=CASE WHEN files.record=excluded.record THEN files.vector ELSE NULL END",params![root.id.to_string(),record.file_id.to_string(),record.relative_path,serde_json::to_string(record)?,text]))?;
      db(tx.execute("INSERT INTO search(root,id,path,text) VALUES(?,?,?,?)",params![root.id.to_string(),record.file_id.to_string(),record.relative_path,text]))?;
      if old.get(&record.file_id).map(|r|r.version.as_str())!=Some(record.version.as_str()) {
        let kind=if old.contains_key(&record.file_id){"FILE_MODIFIED"}else{"FILE_CREATED"};
        let event=json!({"root_id":root.id,"root_revision":root.revision,"file_id":record.file_id,"version":record.version,"event_type":kind,"metadata":{"relative_path":record.relative_path,"size":record.size,"privacy_class":"PRIVATE","trust_level":"UNTRUSTED_EXTERNAL"}});
        db(tx.execute("INSERT INTO outgoing(event) VALUES(?)",[event.to_string()]))?;
      }
    }
    let present:HashSet<_>=records.iter().map(|r|r.file_id).collect();
    for record in old.values().filter(|r|!present.contains(&r.file_id)) {
      db(tx.execute("DELETE FROM files WHERE root=? AND id=?",params![root.id.to_string(),record.file_id.to_string()]))?;
      let event=json!({"root_id":root.id,"root_revision":root.revision,"file_id":record.file_id,"version":record.version,"event_type":"FILE_DELETED","metadata":{"relative_path":record.relative_path}});
      db(tx.execute("INSERT INTO outgoing(event) VALUES(?)",[event.to_string()]))?;
    }
    db(tx.execute("INSERT INTO index_status(root,status) VALUES(?,?) ON CONFLICT(root) DO UPDATE SET status=excluded.status",params![root.id.to_string(),serde_json::to_string(&status)?]))?;
    db(tx.commit())?; Ok(status)
 }
 pub fn records(&self,root:Uuid)->Result<Vec<FileRecord>> { let mut q=db(self.connection.prepare("SELECT record FROM files WHERE root=? ORDER BY path"))?; let rows=db(q.query_map([root.to_string()],|r|r.get::<_,String>(0)))?; rows.map(|r|Ok(serde_json::from_str(&db(r)?)?)).collect() }
 pub fn record(&self,root:Uuid,id:Uuid)->Result<FileRecord> { let s:Option<String>=db(self.connection.query_row("SELECT record FROM files WHERE root=? AND id=?",params![root.to_string(),id.to_string()],|r|r.get(0)).optional())?; serde_json::from_str(&s.ok_or(Error::Forbidden)?).map_err(Into::into) }
 pub fn list(&self,root:Uuid,dir:&str,cursor:Option<&str>,limit:usize)->Result<Value> {
    let prefix=if dir=="." {String::new()} else {format!("{dir}/")};
    let mut entries:Vec<_>=self.records(root)?.into_iter().filter(|r|r.relative_path.strip_prefix(&prefix).is_some_and(|p|!p.contains('/'))&&cursor.is_none_or(|c|r.relative_path.as_str()>c)).collect();
    let limit=limit.clamp(1,MAX_PAGE);let next=if entries.len()>limit{Some(entries[limit-1].relative_path.clone())}else{None};entries.truncate(limit);
    Ok(json!({"entries":entries,"next_cursor":next,"index_status":self.status(root)?}))
 }
 pub fn search(&self,roots:&[Uuid],query:&str,mode:&str,limit:usize)->Result<Value> {
    if query.len()>4096 || query.is_empty(){return Err(Error::Invalid("bounded query required".into()));}
    if mode=="SEMANTIC" {return Err(Error::Unsupported);}
    if !["FILENAME","TEXT"].contains(&mode){return Err(Error::Unsupported);}
    let mut results=Vec::new();
    for root in roots {
      if mode=="FILENAME" {for r in self.records(*root)?.into_iter().filter(|r|r.relative_path.to_lowercase().contains(&query.to_lowercase())) {results.push(json!({"file_id":r.file_id,"root_id":r.root_id,"relative_path":r.relative_path,"version":r.version,"privacy_class":"PRIVATE","snippet":""}));}}
      else {
       let terms=query.split_whitespace().map(|s|format!("\"{}\"",s.replace('"',"\"\""))).collect::<Vec<_>>().join(" AND ");
       let mut q=db(self.connection.prepare("SELECT files.record,substr(files.text,1,512) FROM search JOIN files ON files.root=search.root AND files.id=search.id WHERE search MATCH ? AND search.root=? ORDER BY rank LIMIT 50"))?;
       for row in db(q.query_map(params![terms,root.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))))? {let(s,snippet)=db(row)?;let r:FileRecord=serde_json::from_str(&s)?;results.push(json!({"file_id":r.file_id,"root_id":r.root_id,"relative_path":r.relative_path,"version":r.version,"privacy_class":"PRIVATE","snippet":snippet}));}
      }
    }
    results.truncate(limit.clamp(1,MAX_PAGE)); Ok(json!({"matches":results,"index_status":roots.iter().map(|id|self.status(*id)).collect::<Result<Vec<_>>>()?}))
 }
 pub fn pending_events(&self)->Result<Vec<FileEvent>> {let mut q=db(self.connection.prepare("SELECT sequence,event FROM outgoing WHERE acked=0 ORDER BY sequence LIMIT 50"))?;let rows=db(q.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?))))?;rows.map(|r|{let(seq,s)=db(r)?;let mut v:Value=serde_json::from_str(&s)?;v["sequence"]=json!(seq);Ok(serde_json::from_value(v)?)}).collect()}
 pub fn ack(&self,seq:i64)->Result<()> {db(self.connection.execute("UPDATE outgoing SET acked=1 WHERE sequence<=?",[seq]))?;Ok(())}
 pub fn journal_begin(&self,id:Uuid,hash:&str,auth:Uuid,request:&Value)->Result<Option<Value>> {
    let existing:Option<(String,String,Option<String>)>=db(self.connection.query_row("SELECT hash,state,result FROM requests WHERE id=?",[id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?;
    if let Some((old,state,result))=existing {if old!=hash{return Err(Error::Invalid("request id conflicts with immutable action".into()));}return if state=="RESULT" {Ok(Some(serde_json::from_str(&result.ok_or(Error::OutcomeUnknown)?)?))}else{Err(Error::OutcomeUnknown)};}
    db(self.connection.execute("INSERT INTO requests(id,hash,authorization,request,state) VALUES(?,?,?,?,'BEGUN')",params![id.to_string(),hash,auth.to_string(),request.to_string()]))?; Ok(None)
 }
 pub fn prepared(&self,id:Uuid,evidence:&Value)->Result<()> {db(self.connection.execute("UPDATE requests SET evidence=?,state='PREPARED' WHERE id=?",params![evidence.to_string(),id.to_string()]))?;Ok(())}
 pub fn finish(&self,id:Uuid,result:&Value)->Result<()> {db(self.connection.execute("UPDATE requests SET result=?,state='RESULT' WHERE id=?",params![result.to_string(),id.to_string()]))?;Ok(())}
 pub fn recover(&self,roots:&[RootGrant])->Result<()> {
    let mut q=db(self.connection.prepare("SELECT id,request,evidence,result FROM requests WHERE evidence IS NOT NULL"))?;
    let rows=db(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?))))?;
    for row in rows {
      let(id,request,evidence,result)=db(row)?;let req:Value=serde_json::from_str(&request)?;let ev:Value=serde_json::from_str(&evidence)?;
      let mutation:NativeMutation=serde_json::from_value(req["mutation"].clone())?;
      let dst=roots.iter().find(|r|Some(r.id.to_string())==req["destination_root"].as_str().map(str::to_owned));
      let src=roots.iter().find(|r|Some(r.id.to_string())==req["source_root"].as_str().map(str::to_owned));
      let Some(dst)=dst else {continue;};let Some(src)=src else{continue;};
      #[cfg(windows)] let recovered=native::revalidate(src,dst,&mutation,&ev);
      #[cfg(target_os="linux")] let recovered=self.recover_linux(src,dst,&mutation,&ev);
      #[cfg(not(any(windows,target_os="linux")))] let recovered:Result<NativeOutcome>=Err(Error::OutcomeUnknown);
      match recovered {
        Ok(outcome)=>{self.finish(id.parse().map_err(|_|Error::Forbidden)?,&serde_json::to_value(&outcome)?)?;}
        Err(_)=>{if result.is_some(){db(self.connection.execute("UPDATE requests SET state='UNCERTAIN' WHERE id=?",[&id]))?;}}
      }
    } Ok(())
 }
 #[cfg(target_os="linux")]
 fn recover_linux(&self,src:&RootGrant,dst:&RootGrant,m:&NativeMutation,ev:&Value)->Result<NativeOutcome> {
    let prepared=ev.get("prepared").unwrap_or(ev);let published=native::metadata(dst,&m.destination)?;
    let expected=if m.operation=="files.move"{&prepared["source"]}else{&prepared["proposed"]};
    if Some(published.identity.as_str())!=expected["identity"].as_str()||published.digest.as_deref()!=expected["digest"].as_str(){return Err(Error::OutcomeUnknown);}
    let predecessor=if m.operation=="files.write"&&m.expected_version.is_some(){Some(native::recovery_metadata(dst,&m.stage_name)?)}else{None};
    if let Some(p)=&predecessor {if p.digest.as_deref()!=prepared["source"]["digest"].as_str(){
      let key=format!("{}:{}",m.request_id,p.version());let evidence=json!({"event_type":"LATE_NATIVE_EDIT","authorization_id":m.authorization_id,"action_hash":m.action_hash,"published":published,"predecessor":p,"recovery_reference":format!("recovery:{}:{}",dst.id,m.stage_name)});
      let changed=db(self.connection.execute("INSERT OR IGNORE INTO incidents(key,evidence) VALUES(?,?)",params![key,evidence.to_string()]))?;
      if changed>0 {let event=json!({"root_id":dst.id,"root_revision":dst.revision,"file_id":file_id(dst.id,&published.identity),"version":published.version(),"event_type":"FILE_MODIFIED","metadata":evidence});db(self.connection.execute("INSERT INTO outgoing(event) VALUES(?)",[event.to_string()]))?;}return Err(Error::OutcomeUnknown);
    }}
    if m.operation=="files.move"&&native::metadata(src,m.source.as_deref().ok_or(Error::Forbidden)?).is_ok(){return Err(Error::OutcomeUnknown);}
    Ok(NativeOutcome{outcome:"APPLIED".into(),metadata:Some(published),recovery_reference:predecessor.map(|_|format!("recovery:{}:{}",dst.id,m.stage_name)),evidence:ev.clone()})
 }
}
