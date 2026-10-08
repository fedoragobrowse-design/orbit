use orbit_core::{OwnerScope,Result};
use serde_json::Value;
use sqlx::{Postgres,Transaction};
use uuid::Uuid;

pub async fn append(tx:&mut Transaction<'_,Postgres>,scope:&OwnerScope,correlation:Uuid,event:Option<Uuid>,task:Option<Uuid>,operation:&str,reason:&str,metadata:Value)->Result<i64>{
 // Callers pass identifiers and operational metadata, never connector bodies or credentials.
 let sequence:i64=sqlx::query_scalar("INSERT INTO audit_events(id,owner_id,correlation_id,principal_id,event_id,task_id,operation,reason,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING sequence")
 .bind(Uuid::new_v4()).bind(scope.owner_id).bind(correlation).bind(scope.principal_id).bind(event).bind(task).bind(operation).bind(reason).bind(metadata).fetch_one(&mut **tx).await?;
 sqlx::query("SELECT pg_notify('orbit_activity',$1)").bind(sequence.to_string()).execute(&mut **tx).await?;
 Ok(sequence)
}
