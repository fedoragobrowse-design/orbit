use crate::types::*;
use chrono::{Duration,Utc};
use orbit_core::{OwnerScope,Error,Result,MemoryStatus,MemoryType,TrustLevel,literal};
use serde_json::{Value,json};
use sqlx::{PgPool,Row,Postgres,Transaction};
use uuid::Uuid;

pub(crate) fn record(row:&sqlx::postgres::PgRow)->Result<MemoryRecord>{
 let parse=|name:&str|->Result<Value>{Ok(json!(row.try_get::<String,_>(name)?))};
 Ok(MemoryRecord{id:row.try_get("id")?,owner_id:row.try_get("owner_id")?,memory_type:serde_json::from_value(parse("type")?)?,subject:row.try_get("subject")?,value:row.try_get("value")?,source:row.try_get("source")?,source_reference:row.try_get("source_reference")?,source_references:serde_json::from_value(row.try_get("source_references")?)?,confidence:row.try_get("confidence")?,trust_level:serde_json::from_value(parse("trust_level")?)?,created_at:row.try_get("created_at")?,updated_at:row.try_get("updated_at")?,last_verified_at:row.try_get("last_verified_at")?,valid_from:row.try_get("valid_from")?,valid_until:row.try_get("valid_until")?,privacy_class:serde_json::from_value(parse("privacy_class")?)?,status:serde_json::from_value(parse("status")?)?,related_entities:serde_json::from_value(row.try_get("related_entities")?)?,version:row.try_get("version")?,supersedes_id:row.try_get("supersedes_id")?,entity_key:row.try_get("entity_key")?})
}
pub async fn get(pool:&PgPool,scope:&OwnerScope,id:Uuid)->Result<MemoryRecord>{record(&sqlx::query("SELECT * FROM memory_records WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).fetch_optional(pool).await?.ok_or(Error::NotFound)?)}
pub async fn list(pool:&PgPool,scope:&OwnerScope,kind:Option<MemoryType>,cursor:Option<Uuid>,limit:i64)->Result<(Vec<MemoryRecord>,Option<Uuid>)>{
 let rows=sqlx::query("SELECT * FROM memory_records WHERE owner_id=$1 AND ($2::text IS NULL OR type=$2) AND ($3::uuid IS NULL OR id>$3) ORDER BY id LIMIT $4").bind(scope.owner_id).bind(kind.map(literal)).bind(cursor).bind(limit.clamp(1,50)+1).fetch_all(pool).await?;
 let mut records=rows.iter().map(record).collect::<Result<Vec<_>>>()?;let next=if records.len()>limit.clamp(1,50) as usize{records.pop();records.last().map(|r|r.id)}else{None};Ok((records,next))
}
pub async fn history(pool:&PgPool,scope:&OwnerScope,id:Uuid)->Result<Value>{
 let current=get(pool,scope,id).await?;
 let versions:Vec<Value>=sqlx::query_scalar("SELECT record FROM memory_versions WHERE owner_id=$1 AND memory_id=$2 ORDER BY version DESC").bind(scope.owner_id).bind(id).fetch_all(pool).await?;
 let conflicts=sqlx::query("SELECT id,candidate,state,created_at FROM memory_candidates WHERE owner_id=$1 AND conflicts_with=$2 ORDER BY created_at,id").bind(scope.owner_id).bind(id).fetch_all(pool).await?.iter().map(|r|json!({"id":r.get::<Uuid,_>("id"),"candidate":r.get::<Value,_>("candidate"),"state":r.get::<String,_>("state"),"created_at":r.get::<chrono::DateTime<Utc>,_>("created_at")})).collect::<Vec<_>>();
 Ok(json!({"record":current,"history":versions,"conflicts":conflicts}))
}
async fn lock_owner(tx:&mut Transaction<'_,Postgres>,scope:&OwnerScope)->Result<()>{sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE").bind(scope.owner_id).fetch_one(&mut **tx).await?;Ok(())}
pub async fn ingest(pool:&PgPool,scope:&OwnerScope,candidate:Candidate,provenance:Provenance,supersedes:Option<(Uuid,i64)>,action_id:Option<Uuid>)->Result<CandidateOutcome>{
 let mut tx=pool.begin().await?;lock_owner(&mut tx,scope).await?;
 let (tx,result)=ingest_transaction(tx,scope,candidate,provenance,supersedes,action_id).await?;
 tx.commit().await?;Ok(result)
}
async fn ingest_transaction<'a>(mut tx:Transaction<'a,Postgres>,scope:&OwnerScope,mut candidate:Candidate,provenance:Provenance,supersedes:Option<(Uuid,i64)>,action_id:Option<Uuid>)->Result<(Transaction<'a,Postgres>,CandidateOutcome)>{
 candidate.validate()?;
 if provenance.references.is_empty(){return Err(Error::Validation("memory requires validated provenance".into()))}
 candidate.privacy_class=candidate.privacy_class.max(provenance.privacy);
 candidate.source_references=provenance.references.clone();
 if let Some(action)=action_id {if let Some(result)=sqlx::query_scalar::<_,Value>("SELECT result FROM memory_tool_results WHERE owner_id=$1 AND action_id=$2").bind(scope.owner_id).bind(action).fetch_optional(&mut *tx).await?{return Ok((tx,serde_json::from_value(result)?))} }
 for related in &candidate.related_entities {let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memory_records WHERE owner_id=$1 AND id=$2 AND status<>'FORGOTTEN')").bind(scope.owner_id).bind(related).fetch_one(&mut *tx).await?;if !exists{return Err(Error::Validation("related memory does not exist in owner scope".into()))}}
 if let Some(entity)=candidate.entity_id {let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memory_records WHERE owner_id=$1 AND id=$2 AND status<>'FORGOTTEN')").bind(scope.owner_id).bind(entity).fetch_one(&mut *tx).await?;if !exists{return Err(Error::Validation("entity does not exist in owner scope".into()))}}
 let mut key=candidate.entity_key();
 let previous=if let Some((id,version))=supersedes{
  let row=sqlx::query("SELECT * FROM memory_records WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(scope.owner_id).bind(id).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;let old=record(&row)?;
  if old.version!=version||old.status!=MemoryStatus::Active{return Err(Error::Conflict("memory revision or status changed".into()))}
  if provenance.trust!=TrustLevel::OwnerAuthenticated{return Err(Error::Forbidden)}
  if old.memory_type!=candidate.memory_type{return Err(Error::Validation("supersession cannot change memory type".into()))}
  key=old.entity_key.clone();candidate.privacy_class=candidate.privacy_class.max(old.privacy_class);Some(old)
 }else{
  sqlx::query("SELECT * FROM memory_records WHERE owner_id=$1 AND type=$2 AND entity_key=$3 AND status='ACTIVE' ORDER BY created_at,id LIMIT 1 FOR UPDATE").bind(scope.owner_id).bind(literal(candidate.memory_type)).bind(&key).fetch_optional(&mut *tx).await?.as_ref().map(record).transpose()?
 };
 let candidate_id=Uuid::new_v4();
 let duplicate=previous.as_ref().filter(|p|p.value==candidate.value);
 let conflict=previous.as_ref().filter(|p|p.value!=candidate.value);
 let pending=conflict.is_some()&&provenance.trust!=TrustLevel::OwnerAuthenticated;
 let outcome=if let Some(old)=duplicate{CandidateOutcome{candidate_id,status:"DUPLICATE".into(),memory_id:Some(old.id),conflicts_with:None}}
 else if pending {CandidateOutcome{candidate_id,status:"PENDING_CONFIRMATION".into(),memory_id:None,conflicts_with:conflict.map(|p|p.id)}}
 else{
  let id=Uuid::new_v4();let now=Utc::now();let until=candidate.valid_until.or_else(||(candidate.memory_type==MemoryType::TemporaryContext).then_some(now+Duration::days(7)));
  if until.is_some_and(|t|t<=now){return Err(Error::Validation("valid_until must be in the future".into()))}
  if let Some(old)=&previous {
   sqlx::query("INSERT INTO memory_versions(owner_id,memory_id,version,record) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(scope.owner_id).bind(old.id).bind(old.version).bind(json!(old)).execute(&mut *tx).await?;
   sqlx::query("UPDATE memory_records SET status='SUPERSEDED',updated_at=now(),version=version+1 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(old.id).execute(&mut *tx).await?;
   sqlx::query("DELETE FROM memory_embeddings WHERE owner_id=$1 AND memory_id=$2").bind(scope.owner_id).bind(old.id).execute(&mut *tx).await?;
  }
  sqlx::query("INSERT INTO memory_records(id,owner_id,type,subject,normalized_subject,entity_key,value,source,source_reference,source_references,confidence,trust_level,privacy_class,valid_until,related_entities,supersedes_id,last_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)").bind(id).bind(scope.owner_id).bind(literal(candidate.memory_type)).bind(candidate.subject.trim()).bind(normalize(&candidate.subject)).bind(&key).bind(&candidate.value).bind(&provenance.source).bind(&provenance.references[0]).bind(json!(provenance.references)).bind(candidate.confidence).bind(literal(provenance.trust)).bind(literal(candidate.privacy_class)).bind(until).bind(json!(candidate.related_entities)).bind(previous.as_ref().map(|p|p.id)).bind((provenance.trust==TrustLevel::OwnerAuthenticated).then_some(now)).execute(&mut *tx).await?;
  for related in &candidate.related_entities{sqlx::query("INSERT INTO memory_relations(owner_id,from_id,to_id,kind) SELECT $1,$2,id,CASE WHEN type='PROJECT' THEN 'PROJECT_MEMBER' ELSE 'RELATED' END FROM memory_records WHERE owner_id=$1 AND id=$3").bind(scope.owner_id).bind(id).bind(related).execute(&mut *tx).await?;}
  if let Some(old)=&previous{sqlx::query("INSERT INTO memory_relations(owner_id,from_id,to_id,kind) VALUES($1,$2,$3,'SUPERSEDES')").bind(scope.owner_id).bind(id).bind(old.id).execute(&mut *tx).await?;}
  CandidateOutcome{candidate_id,status:"ACTIVE".into(),memory_id:Some(id),conflicts_with:previous.as_ref().map(|p|p.id)}
 };
 // Accepted candidate bodies duplicate sensitive data unnecessarily; retain content only for confirmation.
 sqlx::query("INSERT INTO memory_candidates(id,owner_id,candidate,conflicts_with,state,memory_id) VALUES($1,$2,$3,$4,$5,$6)").bind(candidate_id).bind(scope.owner_id).bind(if pending{json!({"candidate":candidate,"provenance":{"source":provenance.source,"references":provenance.references,"privacy":candidate.privacy_class,"trust":provenance.trust}})}else{json!({})}).bind(outcome.conflicts_with).bind(if pending{"PENDING_CONFIRMATION"}else{"ACCEPTED"}).bind(outcome.memory_id).execute(&mut *tx).await?;
 if let Some(action)=action_id{sqlx::query("INSERT INTO memory_tool_results(owner_id,action_id,result,memory_id) VALUES($1,$2,$3,$4)").bind(scope.owner_id).bind(action).bind(json!(outcome)).bind(outcome.memory_id).execute(&mut *tx).await?;}
 orbit_audit::append(&mut tx,scope,provenance.correlation_id,None,provenance.task_id,"MEMORY_CANDIDATE",&outcome.status,json!({"candidate_id":candidate_id,"memory_id":outcome.memory_id,"conflicts_with":outcome.conflicts_with,"type":candidate.memory_type})).await?;
 Ok((tx,outcome))
}
pub async fn verify(pool:&PgPool,scope:&OwnerScope,id:Uuid,version:i64)->Result<MemoryRecord>{
 let mut tx=pool.begin().await?;lock_owner(&mut tx,scope).await?;
 let old=record(&sqlx::query("SELECT * FROM memory_records WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(scope.owner_id).bind(id).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?)?;
 if old.version!=version||old.status!=MemoryStatus::Active{return Err(Error::Conflict("memory changed".into()))}
 sqlx::query("INSERT INTO memory_versions(owner_id,memory_id,version,record) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING").bind(scope.owner_id).bind(id).bind(version).bind(json!(old)).execute(&mut *tx).await?;
 let new=record(&sqlx::query("UPDATE memory_records SET last_verified_at=now(),updated_at=now(),version=version+1 WHERE owner_id=$1 AND id=$2 RETURNING *").bind(scope.owner_id).bind(id).fetch_one(&mut *tx).await?)?;
 orbit_audit::append(&mut tx,scope,Uuid::new_v4(),None,None,"MEMORY_VERIFIED","owner verification",json!({"memory_id":id,"version":new.version})).await?;tx.commit().await?;Ok(new)
}
pub async fn forget(pool:&PgPool,scope:&OwnerScope,id:Uuid)->Result<()> {
 let mut tx=pool.begin().await?;lock_owner(&mut tx,scope).await?;
 // A supersession family can contain the same sensitive fact in active and prior history.
 let ids:Vec<Uuid>=sqlx::query_scalar("WITH RECURSIVE family AS (SELECT id,supersedes_id FROM memory_records WHERE owner_id=$1 AND id=$2 UNION SELECT m.id,m.supersedes_id FROM memory_records m JOIN family f ON m.id=f.supersedes_id OR m.supersedes_id=f.id WHERE m.owner_id=$1) SELECT id FROM family").bind(scope.owner_id).bind(id).fetch_all(&mut *tx).await?;
 if ids.is_empty(){return Err(Error::NotFound)}
 sqlx::query("DELETE FROM memory_versions WHERE owner_id=$1 AND memory_id=ANY($2)").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 sqlx::query("DELETE FROM memory_embeddings WHERE owner_id=$1 AND memory_id=ANY($2)").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 sqlx::query("UPDATE memory_candidates SET candidate='{}',state='FORGOTTEN' WHERE owner_id=$1 AND (conflicts_with=ANY($2) OR memory_id=ANY($2))").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 sqlx::query("UPDATE memory_records SET subject='',normalized_subject='',entity_key='forgotten:'||id,value='null',source='',source_reference='',source_references='[]',related_entities='[]',status='FORGOTTEN',forgotten_at=now(),updated_at=now(),version=version+1 WHERE owner_id=$1 AND id=ANY($2)").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 sqlx::query("DELETE FROM memory_relations WHERE owner_id=$1 AND (from_id=ANY($2) OR to_id=ANY($2))").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 sqlx::query("UPDATE memory_tool_results SET result=jsonb_build_object('status','FORGOTTEN','memory_id',memory_id) WHERE owner_id=$1 AND memory_id=ANY($2)").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 // Results and checkpoints may contain retrieved memory snippets. Redact matching references,
 // not append-only audit (which never stores bodies).
 sqlx::query("UPDATE tool_calls SET result=jsonb_build_object('redacted','FORGOTTEN_MEMORY') WHERE owner_id=$1 AND result IS NOT NULL AND EXISTS(SELECT 1 FROM unnest($2::uuid[]) i WHERE result::text LIKE '%'||i::text||'%')").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 sqlx::query("UPDATE tasks SET checkpoint=jsonb_build_object('phase',checkpoint->>'phase','redacted','FORGOTTEN_MEMORY') WHERE owner_id=$1 AND EXISTS(SELECT 1 FROM unnest($2::uuid[]) i WHERE checkpoint::text LIKE '%'||i::text||'%') AND state IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT')").bind(scope.owner_id).bind(&ids).execute(&mut *tx).await?;
 orbit_audit::append(&mut tx,scope,Uuid::new_v4(),None,None,"MEMORY_FORGOTTEN","owner requested erasure",json!({"memory_id":id,"records_removed":ids.len()})).await?;
 tx.commit().await?;Ok(())
}
pub async fn confirm(pool:&PgPool,scope:&OwnerScope,id:Uuid,accept:bool)->Result<Value>{
 let mut tx=pool.begin().await?;lock_owner(&mut tx,scope).await?;
 let row=sqlx::query("SELECT candidate,conflicts_with,state FROM memory_candidates WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(scope.owner_id).bind(id).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
 if row.get::<String,_>("state")!="PENDING_CONFIRMATION"{return Err(Error::Conflict("candidate already decided".into()))}
 if !accept{sqlx::query("UPDATE memory_candidates SET state='REJECTED',candidate='{}' WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).execute(&mut *tx).await?;tx.commit().await?;return Ok(json!({"status":"REJECTED"}))}
 let body:Value=row.get("candidate");let candidate:Candidate=serde_json::from_value(body["candidate"].clone())?;let old_id:Uuid=row.get("conflicts_with");let old=record(&sqlx::query("SELECT * FROM memory_records WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(scope.owner_id).bind(old_id).fetch_one(&mut *tx).await?)?;
 let provenance=Provenance{source:"owner-confirmed-external".into(),references: candidate.source_references.clone(),privacy:candidate.privacy_class,trust:TrustLevel::OwnerAuthenticated,correlation_id:Uuid::new_v4(),task_id:None};
 let (mut tx,result)=ingest_transaction(tx,scope,candidate,provenance,Some((old_id,old.version)),None).await?;
 sqlx::query("UPDATE memory_candidates SET state='ACCEPTED',candidate='{}',memory_id=$3 WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(id).bind(result.memory_id).execute(&mut *tx).await?;
 tx.commit().await?;Ok(json!(result))
}
