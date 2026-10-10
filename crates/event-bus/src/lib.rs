use async_trait::async_trait;
use orbit_core::{Event,OwnerScope,Result,Error,literal,validate_event};
use serde_json::{Value,json};
use sqlx::{PgPool,Row};
use uuid::Uuid;

#[derive(Debug,Clone)]
pub struct EventDelivery {pub id:Uuid,pub event_id:Uuid,pub fence:i64}
#[async_trait]
pub trait EventBus:Send+Sync {async fn publish(&self,scope:&OwnerScope,event:Event)->Result<Uuid>;async fn claim(&self,scope:&OwnerScope,consumer:&str,limit:i64)->Result<Vec<EventDelivery>>;}
#[derive(Clone)]
pub struct PostgresEventBus {pub pool:PgPool}
#[async_trait]
impl EventBus for PostgresEventBus {
 async fn publish(&self,scope:&OwnerScope,event:Event)->Result<Uuid>{
  if event.owner_id!=scope.owner_id || event.principal_id!=scope.principal_id {return Err(Error::Forbidden)}
  validate_event(event.event_type,&event.payload)?;
  let mut tx=self.pool.begin().await?;
  let id:Uuid=sqlx::query_scalar("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,related_entities,source_event_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(owner_id,source,source_event_key) DO UPDATE SET source_event_key=EXCLUDED.source_event_key RETURNING id")
   .bind(event.id).bind(scope.owner_id).bind(literal(event.event_type)).bind(&event.source).bind(scope.principal_id).bind(&event.payload).bind(literal(event.trust_level)).bind(literal(event.privacy_class)).bind(event.correlation_id).bind(json!(event.related_entities)).bind(&event.source_event_key).fetch_one(&mut *tx).await?;
  let original=sqlx::query("SELECT event_type,payload,privacy_class FROM events WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).fetch_one(&mut *tx).await?;
  if original.get::<String,_>("event_type")!=literal(event.event_type)||original.get::<Value,_>("payload")!=event.payload||original.get::<String,_>("privacy_class")!=literal(event.privacy_class){return Err(Error::Conflict("source key already identifies different event".into()))}
  if id==event.id {orbit_audit::append(&mut tx,scope,event.correlation_id,Some(id),None,"EVENT_RECEIVED","authenticated transport",json!({"event_type":event.event_type})).await?;}
  sqlx::query("INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(id).execute(&mut *tx).await?;
  tx.commit().await?;Ok(id)
 }
 async fn claim(&self,scope:&OwnerScope,consumer:&str,limit:i64)->Result<Vec<EventDelivery>>{
  let rows=sqlx::query("WITH candidates AS (SELECT id FROM event_deliveries WHERE owner_id=$1 AND consumer=$2 AND (state='PENDING' OR (state='CLAIMED' AND lease_until<now())) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $3) UPDATE event_deliveries d SET state='CLAIMED',lease_until=now()+interval '30 seconds',fence=fence+1,attempts=attempts+1 FROM candidates c WHERE d.id=c.id RETURNING d.id,d.event_id,d.fence").bind(scope.owner_id).bind(consumer).bind(limit.clamp(1,100)).fetch_all(&self.pool).await?;
  Ok(rows.into_iter().map(|r|EventDelivery{id:r.get("id"),event_id:r.get("event_id"),fence:r.get("fence")}).collect())
 }
}
impl PostgresEventBus {
/// Chat-vs-task heuristic. Task signals (imperative work verbs, schedules,
/// short conversational text stay CHAT with a direct model reply, no task row.
/// Deterministic floor only: never lowers risk, never grants permission.
pub fn classify_message(text: &str) -> (&'static str, f64, &'static str) {
 const TASK_SIGNALS: [&str; 24] = ["send","schedule","remind","book","order","buy","cancel","delete","create a","make a","write a","draft","summarize","summarise","email","calendar","file a","pay","transfer","subscribe","unsubscribe","deploy","merge","fix "];
 let lower = text.to_lowercase();
 let trimmed = lower.trim();
 if trimmed.is_empty() { return ("CHAT", 1.0, "empty message stays conversational"); }
 for signal in TASK_SIGNALS {
  if trimmed.contains(signal) { return ("CREATE_TASK", 0.8, "task signal matched"); }
 }
 if trimmed.ends_with('?') || trimmed.len() < 140 { return ("CHAT", 0.7, "question or short chat"); }
 ("CREATE_TASK", 0.5, "long statement defaults to task")
}
 pub async fn process_foundation(&self)->Result<()> {
  let owners=sqlx::query("SELECT owner_id,id FROM principals WHERE principal_type='SYSTEM' AND source='orbit-worker'").fetch_all(&self.pool).await?;
  for owner in owners {
   let scope=OwnerScope{owner_id:owner.get("owner_id"),principal_id:owner.get("id")};
   for delivery in self.claim(&scope,"foundation",20).await? {
    let mut tx=self.pool.begin().await?;
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM event_deliveries WHERE owner_id=$1 AND id=$2 AND fence=$3 AND state='CLAIMED' AND lease_until>now() FOR UPDATE)").bind(scope.owner_id).bind(delivery.id).bind(delivery.fence).fetch_one(&mut *tx).await?;
    if !valid {continue}
    let e=sqlx::query("SELECT correlation_id,event_type,payload FROM events WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(delivery.event_id).fetch_one(&mut *tx).await?;
    let correlation:Uuid=e.get("correlation_id");let kind:String=e.get("event_type");
    let payload_now:Value=e.get("payload");
    let (kind_name, confidence, reason) = if kind=="USER_MESSAGE" {
     let body = payload_now.get("text").and_then(Value::as_str).unwrap_or("");
     Self::classify_message(body)
    } else { ("STORE_ONLY", 1.0, "non-user event stored only") };
    let create = kind_name=="CREATE_TASK";
    let classification=json!({"kind":kind_name,"confidence":confidence,"reason":reason});
    sqlx::query("UPDATE events SET classification=$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(delivery.event_id).bind(&classification).execute(&mut *tx).await?;
    orbit_audit::append(&mut tx,&scope,correlation,Some(delivery.event_id),None,"EVENT_CLASSIFIED","deterministic classification",classification).await?;
    if kind_name=="CHAT" {
     sqlx::query("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,'AGENT_MESSAGE','foundation',$3,$4,'SYSTEM','PRIVATE',$5,$6) ON CONFLICT(owner_id,source,source_event_key) DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(scope.principal_id).bind(json!({"source_reference":delivery.event_id.to_string(),"reply_to":delivery.event_id,"status":"QUEUED_REPLY"})).bind(correlation).bind(format!("chat-reply:{}",delivery.event_id)).execute(&mut *tx).await?;
    }
    if create {
     let title=payload_now.get("title").and_then(Value::as_str).unwrap_or("Message received");
     let task=Uuid::new_v4();
     let task:Uuid=sqlx::query_scalar("INSERT INTO tasks(id,owner_id,event_id,principal_id,correlation_id,title) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(owner_id,consumer,event_id) DO UPDATE SET event_id=EXCLUDED.event_id RETURNING id").bind(task).bind(scope.owner_id).bind(delivery.event_id).bind(scope.principal_id).bind(correlation).bind(title).fetch_one(&mut *tx).await?;
     orbit_audit::append(&mut tx,&scope,correlation,Some(delivery.event_id),Some(task),"TASK_QUEUED","event created notification task",json!({})).await?;
    }
    sqlx::query("UPDATE event_deliveries SET state='ACKNOWLEDGED',lease_until=NULL WHERE owner_id=$1 AND id=$2 AND fence=$3").bind(scope.owner_id).bind(delivery.id).bind(delivery.fence).execute(&mut *tx).await?;tx.commit().await?;
  }
  }
  Ok(())
 }
 pub async fn run_notification_tasks(&self,worker:Uuid)->Result<()> {
  let candidates=sqlx::query("SELECT owner_id,id FROM tasks WHERE consumer='foundation' AND (state='QUEUED' OR (state='RUNNING' AND lease_until<now())) ORDER BY created_at LIMIT 20").fetch_all(&self.pool).await?;
  for candidate in candidates {
   let owner:Uuid=candidate.get("owner_id");let task:Uuid=candidate.get("id");
   let mut tx=self.pool.begin().await?;
   sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(owner).fetch_one(&mut *tx).await?;
   let row=sqlx::query("SELECT * FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(owner).bind(task).fetch_one(&mut *tx).await?;
   let state:String=row.get("state");let expired:bool=row.get::<chrono::DateTime<chrono::Utc>,_>("expires_at")<=chrono::Utc::now();
   let scope=OwnerScope{owner_id:owner,principal_id:row.get("principal_id")};let correlation=row.get("correlation_id");let event:Option<Uuid>=row.get("event_id");
   if !matches!(state.as_str(),"QUEUED"|"RUNNING") {continue}
   if state=="RUNNING" {let active:bool=sqlx::query_scalar("SELECT lease_until>now() FROM tasks WHERE owner_id=$1 AND id=$2").bind(owner).bind(task).fetch_one(&mut *tx).await?;if active{continue}}
   if expired {sqlx::query("UPDATE tasks SET state='TIMED_OUT',fence=fence+1,revision=revision+1,lease_until=NULL WHERE owner_id=$1 AND id=$2").bind(owner).bind(task).execute(&mut *tx).await?;orbit_audit::append(&mut tx,&scope,correlation,event,Some(task),"TASK_TIMED_OUT","absolute expiry",json!({})).await?;terminal_event(&mut tx,&scope,task,correlation,orbit_core::TaskState::TimedOut).await?;tx.commit().await?;continue}
   let fence:i64=sqlx::query_scalar("UPDATE tasks SET state='RUNNING',fence=fence+1,revision=revision+1,lease_holder=$3,lease_until=now()+interval '30 seconds',updated_at=now() WHERE owner_id=$1 AND id=$2 RETURNING fence").bind(owner).bind(task).bind(worker).fetch_one(&mut *tx).await?;
   sqlx::query("INSERT INTO task_steps(id,owner_id,task_id,name,state,fence) VALUES($1,$2,$3,'notification','PREPARED',$4) ON CONFLICT(owner_id,task_id,name) DO UPDATE SET fence=EXCLUDED.fence").bind(Uuid::new_v4()).bind(owner).bind(task).bind(fence).execute(&mut *tx).await?;
   orbit_audit::append(&mut tx,&scope,correlation,event,Some(task),"TASK_RUNNING","notification checkpoint leased",json!({"fence":fence})).await?;
   tx.commit().await?;
   // Renewal is conditional on the current holder/fence and database time.
   self.renew_task(&scope,task,worker,fence).await?;
   let mut tx=self.pool.begin().await?;
   sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(owner).fetch_one(&mut *tx).await?;
   let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tasks WHERE owner_id=$1 AND id=$2 AND fence=$3 AND lease_holder=$4 AND lease_until>now() AND state='RUNNING' FOR UPDATE)").bind(owner).bind(task).bind(fence).bind(worker).fetch_one(&mut *tx).await?;
   if !valid {continue}
   let checkpoint:Value=row.get("checkpoint");
   let source=event.or_else(||checkpoint.get("source_event_id").and_then(Value::as_str).and_then(|s|Uuid::parse_str(s).ok()));
   let payload:Value=if let Some(source)=source{sqlx::query_scalar("SELECT payload FROM events WHERE owner_id=$1 AND id=$2").bind(owner).bind(source).fetch_one(&mut *tx).await?}else{json!({"text":"Retried notification task"})};
   let body=payload.get("text").and_then(Value::as_str).unwrap_or("Event processed");
   sqlx::query("INSERT INTO notifications(id,owner_id,task_id,correlation_id,severity,title,body) VALUES($1,$2,$3,$4,'INFO',$5,$6) ON CONFLICT(owner_id,task_id) DO NOTHING").bind(Uuid::new_v4()).bind(owner).bind(task).bind(correlation).bind(row.get::<String,_>("title")).bind(body).execute(&mut *tx).await?;
   sqlx::query("UPDATE task_steps SET state='COMPLETED' WHERE owner_id=$1 AND task_id=$2 AND fence=$3").bind(owner).bind(task).bind(fence).execute(&mut *tx).await?;
   sqlx::query("UPDATE tasks SET state='COMPLETED',checkpoint='{\"phase\":\"DONE\"}',revision=revision+1,lease_until=NULL,updated_at=now() WHERE owner_id=$1 AND id=$2 AND fence=$3").bind(owner).bind(task).bind(fence).execute(&mut *tx).await?;
   orbit_audit::append(&mut tx,&scope,correlation,event,Some(task),"TASK_COMPLETED","notification persisted",json!({"fence":fence})).await?;
   terminal_event(&mut tx,&scope,task,correlation,orbit_core::TaskState::Completed).await?;tx.commit().await?;
  } Ok(())
 }
 pub async fn renew_task(&self,scope:&OwnerScope,task:Uuid,worker:Uuid,fence:i64)->Result<()>{
  let n=sqlx::query("UPDATE tasks SET lease_until=now()+interval '30 seconds' WHERE owner_id=$1 AND id=$2 AND lease_holder=$3 AND fence=$4 AND state='RUNNING' AND lease_until>now()").bind(scope.owner_id).bind(task).bind(worker).bind(fence).execute(&self.pool).await?.rows_affected();
  if n!=1{return Err(Error::Conflict("task lease lost".into()))}Ok(())
 }
}
/// Terminal events are committed alongside state/audit changes, never as a later best-effort write.
pub async fn terminal_event(tx:&mut sqlx::Transaction<'_,sqlx::Postgres>,scope:&OwnerScope,task:Uuid,correlation:Uuid,state:orbit_core::TaskState)->Result<Uuid>{
 let id=Uuid::new_v4();let kind=if state==orbit_core::TaskState::Completed{"TASK_COMPLETED"}else{"TASK_FAILED"};
 let id:Uuid=sqlx::query_scalar("INSERT INTO events(id,owner_id,event_type,source,principal_id,payload,trust_level,privacy_class,correlation_id,source_event_key) VALUES($1,$2,$3,'task-worker',$4,$5,'SYSTEM','PRIVATE',$6,$7) ON CONFLICT(owner_id,source,source_event_key) DO UPDATE SET source_event_key=EXCLUDED.source_event_key RETURNING id").bind(id).bind(scope.owner_id).bind(kind).bind(scope.principal_id).bind(json!({"task_id":task,"state":state})).bind(correlation).bind(format!("terminal:{task}")).fetch_one(&mut **tx).await?;
 sqlx::query("INSERT INTO event_deliveries(id,owner_id,event_id,consumer) VALUES($1,$2,$3,'foundation') ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(scope.owner_id).bind(id).execute(&mut **tx).await?;Ok(id)
}
