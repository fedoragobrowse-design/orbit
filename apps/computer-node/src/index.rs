use crate::{file_id, native, NativeMutation, NativeOutcome};
use orbit_computer_node_protocol::{Error, Result, RootGrant, RootMode, FileRecord, IndexStatus, FileEvent, MAX_TEXT, MAX_FILE, MAX_PAGE, normalize_path};
use rusqlite::{Connection, params, OptionalExtension};
use serde_json::{Value, json};
use std::{collections::{HashMap, HashSet}, path::Path};
use uuid::Uuid;
fn db<T>(r: rusqlite::Result<T>) -> Result<T> { r.map_err(|_| Error::Invalid("local state database operation failed".into())) }
pub struct Index { pub connection: Connection }
#[derive(Debug, Clone)]
pub struct WatchRow { pub id: String, pub root: Uuid, pub path: String, pub types: Vec<String> }
pub const WATCH_TYPES: [&str; 3] = ["FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED"];

impl Index {
 pub fn open(path: &Path) -> Result<Self> {
    let connection = db(Connection::open(path))?;
    db(connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS files(root TEXT NOT NULL,id TEXT NOT NULL,path TEXT NOT NULL,record TEXT NOT NULL,text TEXT NOT NULL,vector BLOB,embedding_space TEXT,PRIMARY KEY(root,id),UNIQUE(root,path));
      CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(root UNINDEXED,id UNINDEXED,path,text);
      CREATE TABLE IF NOT EXISTS index_status(root TEXT PRIMARY KEY,status TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS outgoing(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,hash TEXT NOT NULL,authorization TEXT NOT NULL,request TEXT NOT NULL,evidence TEXT,result TEXT,state TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS watches(id TEXT PRIMARY KEY,root TEXT NOT NULL,types TEXT NOT NULL,path TEXT NOT NULL DEFAULT '');
      CREATE TABLE IF NOT EXISTS incidents(key TEXT PRIMARY KEY,evidence TEXT NOT NULL);
    "))?;
    if db(connection.query_row("SELECT COUNT(*) FROM pragma_table_info('watches') WHERE name='path'",[],|r| r.get::<_,i64>(0)))? == 0 { db(connection.execute("ALTER TABLE watches ADD COLUMN path TEXT NOT NULL DEFAULT ''", []))?; }
    Ok(Self { connection })
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
    emit_scan_diff(&tx,root,&records,&texts,&old)?;
    db(tx.commit())?;
    let mut current=self.status(root.id)?; current.indexed=status.indexed; current.skipped=status.skipped; current.truncated=status.truncated; current.unreadable=status.unreadable; Ok(current)
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

fn put_record(tx:&rusqlite::Transaction<'_>,root:&Uuid,record:&FileRecord,text:&str)->Result<()> {
  db(tx.execute("INSERT INTO files(root,id,path,record,text) VALUES(?,?,?,?,?) ON CONFLICT(root,id) DO UPDATE SET path=excluded.path,record=excluded.record,text=excluded.text,vector=CASE WHEN files.record=excluded.record THEN files.vector ELSE NULL END",params![root.to_string(),record.file_id.to_string(),record.relative_path,serde_json::to_string(record)?,text]))?;
  db(tx.execute("INSERT INTO search(root,id,path,text) VALUES(?,?,?,?)",params![root.to_string(),record.file_id.to_string(),record.relative_path,text]))?; Ok(())
}
fn queue_event(tx:&rusqlite::Transaction<'_>,event:Value)->Result<()> { db(tx.execute("INSERT INTO outgoing(event) VALUES(?)",[event.to_string()]))?; Ok(()) }
/// Collapse a queued duplicate for the same file into the incoming outcome.
/// Returns the event type to queue: CREATE absorbs a later MODIFY (the server
/// never saw the file, so it must learn CREATE with the newest version), any
/// prior plus DELETE stays DELETE, and CREATE plus DELETE suppresses both.
fn coalesce_kind(tx:&rusqlite::Transaction<'_>,root:&Uuid,file:&Uuid,kind:&str)->Result<Option<String>> {
  // Collapse queued duplicates for the same file before inserting the new
  // outcome: CREATE+MODIFY stays CREATE, any prior plus DELETE stays DELETE.
  // The outbox is small and bounded, so parse each pending event and compare
  // fields exactly rather than relying on LIKE pattern matching.
  let rows:Vec<(i64,String)>=db(db(tx.prepare("SELECT sequence,event FROM outgoing WHERE acked=0 ORDER BY sequence"))?.query_map([],|r|Ok((r.get(0)?,r.get(1)?))))?.map(db).collect::<Result<Vec<_>>>()?;
  let mut remove:Vec<i64>=Vec::new(); let mut queued:Option<String>=Some(kind.to_owned());
  for (seq,body) in &rows {
    let prior:Value=serde_json::from_str(body).map_err(|_|Error::Invalid("local state database operation failed".into()))?;
    if prior["root_id"] != json!(root) || prior["file_id"] != json!(file) {continue;}
    match (prior["event_type"].as_str().unwrap_or(""),queued.as_deref().unwrap_or(kind)) {
      ("FILE_CREATED","FILE_MODIFIED")=>{remove.push(*seq);queued=Some("FILE_CREATED".into());}
      ("FILE_CREATED","FILE_DELETED")=>{remove.push(*seq);queued=None;}
      ("FILE_MODIFIED","FILE_DELETED")=>{remove.push(*seq);}
      ("FILE_MODIFIED","FILE_MODIFIED")=>{remove.push(*seq);}
      _=>{}
    }
  }
  for seq in remove { db(tx.execute("DELETE FROM outgoing WHERE sequence=?",[seq]))?; }
  Ok(queued)
}
fn emit_scan_diff(tx:&rusqlite::Transaction<'_>,root:&RootGrant,records:&[FileRecord],texts:&HashMap<Uuid,String>,old:&HashMap<Uuid,FileRecord>)->Result<()> {
  db(tx.execute("DELETE FROM search WHERE root=?",[root.id.to_string()]))?;
  for record in records {
    let text=texts.get(&record.file_id).map(String::as_str).unwrap_or("");
    put_record(tx,&root.id,record,text)?;
    if old.get(&record.file_id).map(|r|r.version.as_str())!=Some(record.version.as_str()) {
      let kind=if old.contains_key(&record.file_id){"FILE_MODIFIED"}else{"FILE_CREATED"};
      let Some(kind)=coalesce_kind(tx,&root.id,&record.file_id,kind)? else {continue;};
      queue_event(tx,json!({"root_id":root.id,"root_revision":root.revision,"file_id":record.file_id,"version":record.version,"event_type":kind,"metadata":{"relative_path":record.relative_path,"size":record.size,"privacy_class":"PRIVATE","trust_level":"UNTRUSTED_EXTERNAL"}}))?;
    }
  }
  let present:HashSet<_>=records.iter().map(|r|r.file_id).collect();
  for record in old.values().filter(|r|!present.contains(&r.file_id)) {
    db(tx.execute("DELETE FROM files WHERE root=? AND id=?",params![root.id.to_string(),record.file_id.to_string()]))?;
    if coalesce_kind(tx,&root.id,&record.file_id,"FILE_DELETED")?.is_none() {continue;}
    queue_event(tx,json!({"root_id":root.id,"root_revision":root.revision,"file_id":record.file_id,"version":record.version,"event_type":"FILE_DELETED","metadata":{"relative_path":record.relative_path}}))?;
  }
  let mut status:IndexStatus=db(tx.query_row("SELECT status FROM index_status WHERE root=?",[root.id.to_string()],|r|r.get::<_,String>(0)).optional())?
    .map(|s|serde_json::from_str(&s)).transpose()?.unwrap_or(IndexStatus{available_modes:vec!["FILENAME".into(),"TEXT".into()],..Default::default()});
  status.gap=false;
  db(tx.execute("INSERT INTO index_status(root,status) VALUES(?,?) ON CONFLICT(root) DO UPDATE SET status=excluded.status",params![root.id.to_string(),serde_json::to_string(&status)?]))?;
  Ok(())
}
impl Index {
pub fn create_watch(&self,root:Uuid,path:&str,types:Vec<String>)->Result<WatchRow> {
  for t in &types { if !WATCH_TYPES.contains(&t.as_str()) {return Err(Error::Invalid("unknown watch event type".into()));} }
  if types.is_empty() {return Err(Error::Invalid("watch must list at least one event type".into()));}
  if !path.is_empty() { normalize_path(path)?; }
  let id=Uuid::new_v4().to_string();
  db(self.connection.execute("INSERT INTO watches(id,root,types,path) VALUES(?,?,?,?)",params![id,root.to_string(),serde_json::to_string(&types)?,path]))?;
  Ok(WatchRow{id,root,path:path.to_owned(),types})
}
pub fn cancel_watch(&self,id:&str)->Result<bool> { Ok(db(self.connection.execute("DELETE FROM watches WHERE id=?",[id]))? > 0) }
pub fn watch(&self,id:&str)->Result<Option<WatchRow>> {
  let row:Option<(String,String,String)>=db(self.connection.query_row("SELECT root,types,path FROM watches WHERE id=?",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?;
  row.map(|(root,types,path)|Ok(WatchRow{id:id.to_owned(),root:root.parse().map_err(|_|Error::Invalid("local state database operation failed".into()))?,path,types:serde_json::from_str(&types)?})).transpose()
}
pub fn watches(&self)->Result<Vec<WatchRow>> {
  let mut q=db(self.connection.prepare("SELECT id,root,types,path FROM watches ORDER BY id"))?;
  db(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))))?.map(|r|{
    let(id,root,types,path)=db(r)?;let types:Vec<String>=serde_json::from_str(&types).unwrap_or_default();
    Ok(WatchRow{id,root:root.parse().map_err(|_|Error::Invalid("local state database operation failed".into()))?,path,types})
  }).collect()
}
pub fn watches_for_root(&self,root:Uuid)->Result<Vec<WatchRow>> {
  let mut q=db(self.connection.prepare("SELECT id,types,path FROM watches WHERE root=? ORDER BY id"))?;
  db(q.query_map([root.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))))?.map(|r|{
    let(id,types,path)=db(r)?;let types:Vec<String>=serde_json::from_str(&types).unwrap_or_default();
    Ok(WatchRow{id,root,path,types})
  }).collect()
}
pub fn observe_paths(&mut self,root:&RootGrant,paths:&std::collections::HashSet<String>)->Result<IndexStatus> {
  // Incremental notify path: re-stat only the signalled files, diff against
  // the stored records, and queue FILE_CREATED/MODIFIED/DELETED into the
  // durable EventPush outbox. Watch registrations gate which types queue.
  let watched=self.watches_for_root(root.id)?;
  if watched.is_empty() {return self.status(root.id);}
  let mut status=self.status(root.id)?;
  let tx=db(self.connection.transaction())?;
  for rel in paths {
    let rel=match normalize_path(rel) {Ok(p)=>p,Err(_)=>continue};
    if watched.iter().all(|w|!w.path.is_empty() && rel != w.path && !rel.starts_with(&format!("{}/",w.path))) {continue;}
    let meta=(if root.mode==RootMode::Ask {native::metadata_only(root,&rel)} else {native::metadata(root,&rel)}).ok();
    match meta {
      Some(m) if m.kind=="DIRECTORY" =>{}
      Some(m)=>{
        let id=file_id(root.id,&m.identity); let version=m.version();
        let existing:Option<String>=tx.query_row("SELECT record FROM files WHERE root=? AND id=?",params![root.id.to_string(),id.to_string()],|r|r.get(0)).optional().map_err(|_|Error::Invalid("local state database operation failed".into()))?;
        // A reused path whose identity moved belongs to the new file; the old
        // record is picked up as deleted on the next full scan, never dropped.
        if existing.is_none() {
          let clash:Option<String>=tx.query_row("SELECT id FROM files WHERE root=? AND path=?",params![root.id.to_string(),rel.clone()],|r|r.get(0)).optional().map_err(|_|Error::Invalid("local state database operation failed".into()))?;
          if clash.as_deref()!=Some(id.to_string().as_str()) && clash.is_some() {status.skipped+=1;continue;}
        }
        let mut text=String::new();
        if root.mode!=RootMode::Ask {
          if m.size>MAX_TEXT as u64 {status.truncated+=1;}
          match native::read(root,&rel,MAX_FILE) {Ok(bytes)=>{let extracted=&bytes[..bytes.len().min(MAX_TEXT)];match std::str::from_utf8(extracted){Ok(s) if !s.contains('\0')=>text=s.to_owned(),_=>status.skipped+=1}}Err(_)=>{status.unreadable+=1;continue;}}
        }
        let record=FileRecord{file_id:id,root_id:root.id,relative_path:rel.clone(),kind:m.kind.clone(),version:version.clone(),sha256:if root.mode==RootMode::Ask{None}else{m.digest.clone()},size:m.size,privacy_class:"PRIVATE".into(),source_reference:format!("root:{}:file:{id}:{version}",root.id)};
        let prior:Option<FileRecord>=existing.map(|s|serde_json::from_str(&s)).transpose()?;
        if prior.as_ref().is_some_and(|p|p.version==version) {continue;}
        put_record(&tx,&root.id,&record,&text)?;
        let kind=if prior.is_some(){"FILE_MODIFIED"}else{"FILE_CREATED"};
        if watched.iter().all(|w|!w.types.iter().any(|t|t==kind)) {continue;}
        let Some(kind)=coalesce_kind(&tx,&root.id,&id,kind)? else {continue;};
        queue_event(&tx,json!({"root_id":root.id,"root_revision":root.revision,"file_id":id,"version":version,"event_type":kind,"metadata":{"relative_path":rel,"size":m.size,"privacy_class":"PRIVATE","trust_level":"UNTRUSTED_EXTERNAL"}}))?;
      }
      None=>{
        let stored:Vec<FileRecord>={
          let mut q=tx.prepare("SELECT record FROM files WHERE root=? AND path=?").map_err(|_|Error::Invalid("local state database operation failed".into()))?;
          db(q.query_map(params![root.id.to_string(),rel.clone()],|r|r.get::<_,String>(0)))?.map(|r|Ok(serde_json::from_str::<FileRecord>(&db(r)?)?)).collect::<Result<Vec<_>>>()?
        };
        if stored.is_empty() {continue;}
        if watched.iter().all(|w|!w.types.iter().any(|t|t=="FILE_DELETED")) {continue;}
        for record in stored {
          db(tx.execute("DELETE FROM files WHERE root=? AND id=?",params![root.id.to_string(),record.file_id.to_string()]))?;
          db(tx.execute("DELETE FROM search WHERE root=? AND id=?",params![root.id.to_string(),record.file_id.to_string()]))?;
          if coalesce_kind(&tx,&root.id,&record.file_id,"FILE_DELETED")?.is_none() {continue;}
          queue_event(&tx,json!({"root_id":root.id,"root_revision":root.revision,"file_id":record.file_id,"version":record.version,"event_type":"FILE_DELETED","metadata":{"relative_path":record.relative_path}}))?;
        }
      }
    }
  }
  db(tx.execute("INSERT INTO index_status(root,status) VALUES(?,?) ON CONFLICT(root) DO UPDATE SET status=excluded.status",params![root.id.to_string(),serde_json::to_string(&status)?]))?;
  db(tx.commit())?; Ok(status)
}
pub fn reconcile(&mut self,root:&RootGrant,cap:usize)->Result<IndexStatus> {
  // Bounded overflow path: mark the gap, run one full scan (which diffs and
  // clears the gap marker), then trim the unacked outbox back to `cap`.
  self.mark_gap(root.id)?; let status=self.scan(root)?;
  let n:i64=db(self.connection.query_row("SELECT COUNT(*) FROM outgoing WHERE acked=0",[],|r|r.get(0)))?;
  if n as usize > cap { db(self.connection.execute("DELETE FROM outgoing WHERE sequence IN (SELECT sequence FROM outgoing WHERE acked=0 ORDER BY sequence LIMIT ?)",[((n as usize)-cap) as i64]))?; self.mark_gap(root.id)?; }
  Ok(status)
}}
