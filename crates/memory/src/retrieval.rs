use crate::{types::*,store::record};
use orbit_core::{OwnerScope,Result,Error,PrivacyClass,MemoryStatus,MemoryType,TrustLevel,ContextBlock,ContextKind,literal};
use sqlx::{PgPool,Row};
use serde_json::{Value,json};
use uuid::Uuid;
use chrono::Utc;

pub async fn agent_scope(pool:&PgPool,scope:&OwnerScope,agent_id:Uuid,write:bool)->Result<RetrievalScope>{
 let definition:Value=sqlx::query_scalar("SELECT definition FROM agent_definitions WHERE owner_id=$1 AND id=$2 AND enabled=true").bind(scope.owner_id).bind(agent_id).fetch_optional(pool).await?.ok_or(Error::Forbidden)?;
 let p=&definition["memory_permissions"];
 let types:Vec<MemoryType>=serde_json::from_value(p[if write{"write_types"}else{"read_types"}].clone()).map_err(|_|Error::Forbidden)?;
 if types.is_empty(){return Err(Error::Forbidden)}
 let project_ids=serde_json::from_value(p.get("project_ids").cloned().unwrap_or(json!([])))?;
 Ok(RetrievalScope{types,project_ids,max_privacy:PrivacyClass::HighlyPrivate,agent_id:Some(agent_id)})
}
pub fn context_text(memory:&MemoryRecord)->String{format!("{}: {}",memory.subject,memory.value)}
pub fn permitted(record:&MemoryRecord,scope:&RetrievalScope,request:&SearchRequest,now:chrono::DateTime<Utc>)->bool{
 record.status==MemoryStatus::Active && record.valid_from<=now && record.valid_until.is_none_or(|t|t>now) && record.privacy_class!=PrivacyClass::Secret && record.privacy_class<=scope.max_privacy && (scope.types.is_empty()||scope.types.contains(&record.memory_type)) && (request.types.is_empty()||request.types.contains(&record.memory_type)) && (scope.project_ids.is_empty()||scope.project_ids.contains(&record.id)||record.related_entities.iter().any(|id|scope.project_ids.contains(id))) && request.project_id.is_none_or(|id|id==record.id||record.related_entities.contains(&id))
}
pub fn rank_records(mut records:Vec<(MemoryRecord,Option<f64>)>,request:&SearchRequest,now:chrono::DateTime<Utc>)->Vec<MemoryRecord>{
 let query=normalize(&request.query);let tokens:Vec<_>=query.split_whitespace().collect();
 let score=|m:&MemoryRecord,semantic:Option<f64>|{
  let subject=normalize(&m.subject);let body=normalize(&m.value.to_string());
  let exact=(!query.is_empty()&&subject==query)as i32;
  let project=request.project_id.is_some_and(|p|p==m.id||m.related_entities.contains(&p))as i32;
  let lexical=tokens.iter().map(|token|if subject.contains(token){3}else if body.contains(token){1}else{0}).sum::<i32>();
  let trust=match m.trust_level{TrustLevel::OwnerAuthenticated=>2,TrustLevel::System=>1,TrustLevel::UntrustedExternal=>0};
  (project,exact,lexical,semantic.unwrap_or(-1.0),m.related_entities.len(),m.last_verified_at.unwrap_or(m.updated_at).min(now),trust)
 };
 records.sort_by(|(a,av),(b,bv)|{let aa=score(a,*av);let bb=score(b,*bv);bb.0.cmp(&aa.0).then(bb.1.cmp(&aa.1)).then(bb.2.cmp(&aa.2)).then(bb.3.total_cmp(&aa.3)).then(bb.4.cmp(&aa.4)).then(bb.5.cmp(&aa.5)).then(bb.6.cmp(&aa.6)).then(a.id.cmp(&b.id))});
 let mut result=Vec::new();let mut characters=0;
 for (memory,semantic) in records{
  if !query.is_empty()&&score(&memory,semantic).2==0&&semantic.is_none()&&request.project_id.is_none(){continue}
  let size=context_text(&memory).chars().count();if characters+size>6000{continue}characters+=size;result.push(memory);if result.len()>=request.limit.clamp(1,12){break}
 }result
}
pub async fn search(pool:&PgPool,scope:&OwnerScope,request:&SearchRequest,allowed:&RetrievalScope,vector:Option<&QueryVector>)->Result<Vec<MemoryRecord>>{
 if request.query.chars().count()>2000||request.types.len()>10||!(1..=12).contains(&request.limit){return Err(Error::Validation("invalid memory retrieval request".into()))}
 if let Some(project)=request.project_id{if !allowed.project_ids.is_empty()&&!allowed.project_ids.contains(&project){return Err(Error::Forbidden)}}
 let allowed_types:Vec<_>=allowed.types.iter().map(literal).collect();let requested_types:Vec<_>=request.types.iter().map(literal).collect();
 let privacy:Vec<_>=[PrivacyClass::Public,PrivacyClass::Personal,PrivacyClass::Private,PrivacyClass::HighlyPrivate].into_iter().filter(|p|*p<=allowed.max_privacy).map(literal).collect();
 // Every access filter applies in SQL before semantic distance or ranking is computed.
 let rows=sqlx::query("SELECT m.* FROM memory_records m WHERE m.owner_id=$1 AND m.status='ACTIVE' AND m.valid_from<=now() AND (m.valid_until IS NULL OR m.valid_until>now()) AND m.privacy_class=ANY($2) AND (cardinality($3::text[])=0 OR m.type=ANY($3)) AND (cardinality($4::text[])=0 OR m.type=ANY($4)) AND ($5::uuid IS NULL OR m.id=$5 OR m.related_entities ? $5::text OR EXISTS(SELECT 1 FROM memory_relations r WHERE r.owner_id=$1 AND r.from_id=m.id AND r.to_id=$5 AND r.kind='PROJECT_MEMBER')) AND (cardinality($6::uuid[])=0 OR m.id=ANY($6) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(m.related_entities) e WHERE e::uuid=ANY($6))) ORDER BY m.id")
 .bind(scope.owner_id).bind(privacy).bind(allowed_types).bind(requested_types).bind(request.project_id).bind(&allowed.project_ids).fetch_all(pool).await?;
 let mut candidates=Vec::with_capacity(rows.len());for row in &rows{let m=record(row)?;if permitted(&m,allowed,request,Utc::now()){candidates.push((m,None))}}
 if let Some(vector)=vector{
  if vector.values.is_empty()||vector.values.iter().any(|v|!v.is_finite()){return Err(Error::Validation("invalid query embedding".into()))}
  let ids:Vec<_>=candidates.iter().map(|(r,_)|r.id).collect();
  let matches=sqlx::query("SELECT e.memory_id,1-(e.embedding <=> $5) AS similarity FROM memory_embeddings e JOIN memory_records m ON m.owner_id=e.owner_id AND m.id=e.memory_id WHERE e.owner_id=$1 AND e.memory_id=ANY($2) AND e.provider_id=$3 AND e.model_id=$4 AND e.dimension=$6 AND e.memory_version=m.version")
  .bind(scope.owner_id).bind(ids).bind(vector.provider_id).bind(vector.model_id).bind(pgvector::Vector::from(vector.values.clone())).bind(vector.values.len() as i32).fetch_all(pool).await?;
  for row in matches{let id:Uuid=row.get("memory_id");if let Some((_,similarity))=candidates.iter_mut().find(|(m,_)|m.id==id){*similarity=row.try_get::<Option<f64>,_>("similarity")?}}
 }
 Ok(rank_records(candidates,request,Utc::now()))
}
pub async fn search_for_agent(pool:&PgPool,scope:&OwnerScope,agent_id:Uuid,query:&str)->Result<Vec<ContextBlock>>{
 let allowed=match agent_scope(pool,scope,agent_id,false).await{Ok(s)=>s,Err(Error::Forbidden)=>return Ok(vec![]),Err(e)=>return Err(e)};
 let request=SearchRequest{query:query.to_owned(),types:vec![],project_id:None,limit:12};
 Ok(search(pool,scope,&request,&allowed,None).await?.iter().map(|m|ContextBlock{kind:ContextKind::Memory,text_or_reference:context_text(m),privacy_class:m.privacy_class,trust_level:m.trust_level,source_reference:format!("orbit-memory:{}:{}",m.id,m.version)}).collect())
}
pub async fn store_embedding(pool:&PgPool,scope:&OwnerScope,id:Uuid,vector:QueryVector)->Result<()> {
 if vector.values.is_empty()||vector.values.len()>65536||vector.values.iter().any(|v|!v.is_finite()){return Err(Error::Validation("invalid memory embedding".into()))}
 let result=sqlx::query("INSERT INTO memory_embeddings(owner_id,memory_id,provider_id,model_id,dimension,embedding,memory_version) SELECT owner_id,id,$3,$4,$5,$6,version FROM memory_records WHERE owner_id=$1 AND id=$2 AND status='ACTIVE' AND privacy_class<>'SECRET' ON CONFLICT(owner_id,memory_id,provider_id,model_id,dimension) DO UPDATE SET embedding=EXCLUDED.embedding,memory_version=EXCLUDED.memory_version,created_at=now()")
 .bind(scope.owner_id).bind(id).bind(vector.provider_id).bind(vector.model_id).bind(vector.values.len() as i32).bind(pgvector::Vector::from(vector.values)).execute(pool).await?;
 if result.rows_affected()==0{return Err(Error::Forbidden)}Ok(())
}
