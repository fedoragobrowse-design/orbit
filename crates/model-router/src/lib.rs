pub mod endpoint;
pub mod provider;
mod types;
use orbit_core::{ContextBlock, Error, ModelRole, OwnerScope, PrivacyClass, Result};
use orbit_secrets::SecretStore;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::path::PathBuf;
pub use types::*;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetLimits {
    pub task_usd: f64,
    pub day_usd: f64,
    pub month_usd: f64,
    pub agent_day_usd: f64,
    pub max_model_calls: i32,
    pub max_input_tokens: i64,
    pub max_output_tokens: i64,
}
impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            task_usd: 1.,
            day_usd: 5.,
            month_usd: 50.,
            agent_day_usd: 5.,
            max_model_calls: 12,
            max_input_tokens: 100000,
            max_output_tokens: 24000,
        }
    }
}
impl BudgetLimits {
    pub fn validate(&self) -> Result<()> {
        if [
            self.task_usd,
            self.day_usd,
            self.month_usd,
            self.agent_day_usd,
        ]
        .iter()
        .any(|n| !n.is_finite() || *n < 0. || *n > 1_000_000.)
            || self.max_model_calls <= 0
            || self.max_input_tokens <= 0
            || self.max_output_tokens <= 0
        {
            return Err(Error::Validation("invalid model budget".into()));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct ModelRouter {
    pool: PgPool,
    key_dir: PathBuf,
}
struct Selection {
    provider: ProviderConfig,
    model: ModelConfig,
    route: RouteMetadata,
    call_id: Uuid,
}
impl ModelRouter {
    pub fn new(pool: PgPool, key_dir: PathBuf) -> Self {
        Self { pool, key_dir }
    }
    pub async fn complete(
        &self,
        scope: &OwnerScope,
        request: RoutedRequest,
    ) -> Result<RoutedResponse> {
        let privacy = effective_privacy(request.privacy, &request.context, &request.chat);
        let selection = self
            .reserve(
                scope,
                request.role,
                privacy,
                Operation::Chat(&request.chat),
                request.task_id,
                request.task_fence,
                request.agent_id,
                request.automatic,
                request.model_id,
            )
            .await?;
        let start = std::time::Instant::now();
        let call_id = selection.call_id;
        let route = selection.route.clone();
        let result = match self.adapter(scope, &selection).await {
            Ok(adapter) => adapter.complete(request.chat).await,
            Err(e) => Err(e),
        };
        self.settle(
            scope,
            call_id,
            result.as_ref().ok().map(|r| &r.usage),
            start.elapsed().as_millis() as i64,
            result.is_ok(),
        )
        .await?;
        match result {
            Ok(response) => Ok(RoutedResponse {
                response,
                route,
                call_id,
            }),
            Err(e) => Err(local_error(e, &route)),
        }
    }
    /// The stream owns a durable reservation. Dropping it keeps the maximum reservation;
    /// only a validated terminal usage frame can settle it downwards.
    pub async fn stream(
        &self,
        scope: &OwnerScope,
        request: RoutedRequest,
    ) -> Result<(ModelStream, RouteMetadata, Uuid)> {
        let privacy = effective_privacy(request.privacy, &request.context, &request.chat);
        let selection = self
            .reserve(
                scope,
                request.role,
                privacy,
                Operation::Chat(&request.chat),
                request.task_id,
                request.task_fence,
                request.agent_id,
                request.automatic,
                request.model_id,
            )
            .await?;
        let adapter = self
            .adapter(scope, &selection)
            .await
            .map_err(|e| local_error(e, &selection.route))?;
        let mut stream = adapter
            .stream(request.chat)
            .await
            .map_err(|e| local_error(e, &selection.route))?;
        let call_id = selection.call_id;
        let route = selection.route;
        let router = self.clone();
        let scope = scope.clone();
        let start = std::time::Instant::now();
        use futures_util::StreamExt;
        let wrapped = Box::pin(
            async_stream::try_stream! {while let Some(item)=stream.next().await{match item {Ok(ModelChunk::Done{response})=>{router.settle(&scope,call_id,Some(&response.usage),start.elapsed().as_millis()as i64,true).await?;yield ModelChunk::Done{response};},Ok(chunk)=>yield chunk,Err(e)=>{router.settle(&scope,call_id,None,start.elapsed().as_millis()as i64,false).await?;Err(e)?;}}}},
        );
        Ok((wrapped, route, call_id))
    }
    pub async fn embed(
        &self,
        scope: &OwnerScope,
        role: ModelRole,
        input: EmbeddingRequest,
        context: &[ContextBlock],
        privacy: PrivacyClass,
    ) -> Result<(EmbeddingResponse, RouteMetadata)> {
        let privacy = context
            .iter()
            .map(|c| c.privacy_class)
            .chain([privacy])
            .max()
            .unwrap_or(PrivacyClass::Private);
        let s = self
            .reserve(
                scope,
                role,
                privacy,
                Operation::Embed(&input),
                None,
                None,
                None,
                true,
                None,
            )
            .await?;
        let start = std::time::Instant::now();
        let result = match self.adapter(scope, &s).await {
            Ok(a) => a.embed(input).await,
            Err(e) => Err(e),
        };
        self.settle(
            scope,
            s.call_id,
            result.as_ref().ok().map(|r| &r.usage),
            start.elapsed().as_millis() as i64,
            result.is_ok(),
        )
        .await?;
        result
            .map(|r| (r, s.route.clone()))
            .map_err(|e| local_error(e, &s.route))
    }
    pub async fn rerank(
        &self,
        scope: &OwnerScope,
        role: ModelRole,
        input: RerankRequest,
        context: &[ContextBlock],
        privacy: PrivacyClass,
    ) -> Result<(RerankResponse, RouteMetadata)> {
        let privacy = context
            .iter()
            .map(|c| c.privacy_class)
            .chain([privacy])
            .max()
            .unwrap_or(PrivacyClass::Private);
        let s = self
            .reserve(
                scope,
                role,
                privacy,
                Operation::Rerank(&input),
                None,
                None,
                None,
                true,
                None,
            )
            .await?;
        let start = std::time::Instant::now();
        let result = match self.adapter(scope, &s).await {
            Ok(a) => a.rerank(input).await,
            Err(e) => Err(e),
        };
        self.settle(
            scope,
            s.call_id,
            None,
            start.elapsed().as_millis() as i64,
            result.is_ok(),
        )
        .await?;
        result
            .map(|r| (r, s.route.clone()))
            .map_err(|e| local_error(e, &s.route))
    }
    async fn adapter(&self, scope: &OwnerScope, s: &Selection) -> Result<provider::HttpProvider> {
        let credential = if let Some(id) = s.provider.credential_id {
            Some(
                SecretStore::open(self.pool.clone(), &self.key_dir)
                    .await?
                    .get(scope, id)
                    .await?,
            )
        } else {
            None
        };
        provider::HttpProvider::new(s.provider.clone(), s.model.clone(), credential).await
    }
    async fn reserve(
        &self,
        scope: &OwnerScope,
        role: ModelRole,
        privacy: PrivacyClass,
        operation: Operation<'_>,
        task_id: Option<Uuid>,
        fence: Option<i64>,
        agent_id: Option<Uuid>,
        automatic: bool,
        pinned: Option<Uuid>,
    ) -> Result<Selection> {
        if privacy == PrivacyClass::Secret {
            return Err(Error::Forbidden);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
            .bind(scope.owner_id)
            .fetch_one(&mut *tx)
            .await?;
        if let Some(task) = task_id {
            let row=sqlx::query("SELECT state,fence,lease_until>now() AS live,expires_at>now() AS unexpired FROM tasks WHERE owner_id=$1 AND id=$2 FOR UPDATE").bind(scope.owner_id).bind(task).fetch_optional(&mut *tx).await?.ok_or(Error::NotFound)?;
            if row.try_get::<String, _>("state")? != "RUNNING"
                || Some(row.try_get::<i64, _>("fence")?) != fence
                || !row.try_get::<Option<bool>, _>("live")?.unwrap_or(false)
                || !row.try_get::<bool, _>("unexpired")?
            {
                return Err(Error::Conflict(
                    "model dispatch lost task lease or fence".into(),
                ));
            }
        }
        let settings: serde_json::Value =
            sqlx::query_scalar("SELECT value FROM settings WHERE owner_id=$1")
                .bind(scope.owner_id)
                .fetch_one(&mut *tx)
                .await?;
        let mode: InstallationMode = serde_json::from_value(
            settings
                .get("installation_mode")
                .cloned()
                .unwrap_or(serde_json::json!("LOCAL_ONLY")),
        )?;
        let private_cloud = settings["allow_private_cloud"].as_bool().unwrap_or(false);
        let rows=sqlx::query("SELECT m.configuration AS model,p.configuration AS provider,p.credential_id FROM models m JOIN model_providers p ON p.owner_id=m.owner_id AND p.id=m.provider_id WHERE m.owner_id=$1 ORDER BY (m.configuration->>'priority')::integer,m.id").bind(scope.owner_id).fetch_all(&mut *tx).await?;
        let mut selected = None;
        let mut role_exists = false;
        let mut privacy_allowed = false;
        for row in rows {
            let model: ModelConfig = serde_json::from_value(row.try_get("model")?)?;
            let mut provider: ProviderConfig = serde_json::from_value(row.try_get("provider")?)?;
            provider.credential_id = row.try_get("credential_id")?;
            if let Some(want) = pinned { if model.id != want { continue; } if !model.roles.contains(&role) { return Err(Error::Validation("pinned model does not carry the requested role".into())); } }
            if pinned.is_none() && !model.roles.contains(&role) { continue; }
            if pinned.is_none() && (!model.enabled || !provider.enabled) { continue; }
            role_exists = true;
            if !route_allowed(mode, privacy, provider.local, private_cloud) {
                continue;
            }
            privacy_allowed = true;
            if !operation.supported(&model.capabilities)
                || operation.is_rerank() && provider.rerank_path.is_none()
            {
                continue;
            }
            let input_bound = operation.input_bound()?;
            if input_bound + operation.output_bound() > u64::from(model.context_tokens) {
                continue;
            }
            selected = Some((provider, model));
            break;
        }
        if pinned.is_some() && selected.is_none() { return Err(Error::NotFound); }
        let (provider, model) = selected.ok_or_else(|| {
            if !role_exists {
                Error::Unavailable(
                    "LOCAL_MODEL_UNAVAILABLE: configure an enabled model for the requested role"
                        .into(),
                )
            } else if !privacy_allowed {
                Error::Forbidden
            } else {
                Error::UnsupportedCapability
            }
        })?;
        if provider.kind == ProviderKind::Anthropic && model.capabilities.embeddings {
            return Err(Error::UnsupportedCapability);
        }
        let prices = model
            .input_usd_per_million
            .zip(model.output_usd_per_million);
        if automatic && !provider.local && prices.is_none() {
            return Err(Error::Unavailable(
                "cloud pricing is unknown; configure prices before automatic calls".into(),
            ));
        }
        let pricing_known = provider.local || prices.is_some();
        let max_input = u64::from(model.context_tokens) - operation.output_bound();
        let max_output = operation.output_bound();
        let reserve = if let Some((input, output)) = prices {
            cost_micro(max_input, max_output, input, output)?
        } else {
            0
        };
        sqlx::query("INSERT INTO model_budgets(owner_id) VALUES($1) ON CONFLICT DO NOTHING")
            .bind(scope.owner_id)
            .execute(&mut *tx)
            .await?;
        let b = sqlx::query("SELECT * FROM model_budgets WHERE owner_id=$1")
            .bind(scope.owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let limits = BudgetLimits {
            task_usd: b.try_get("task_usd")?,
            day_usd: b.try_get("day_usd")?,
            month_usd: b.try_get("month_usd")?,
            agent_day_usd: b.try_get("agent_day_usd")?,
            max_model_calls: b.try_get("max_model_calls")?,
            max_input_tokens: b.try_get("max_input_tokens")?,
            max_output_tokens: b.try_get("max_output_tokens")?,
        };
        let totals=sqlx::query("SELECT COALESCE(sum(COALESCE(actual_micro_usd,reserved_micro_usd)) FILTER(WHERE created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),0)::bigint AS day,COALESCE(sum(COALESCE(actual_micro_usd,reserved_micro_usd)) FILTER(WHERE created_at>=date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),0)::bigint AS month,COALESCE(sum(COALESCE(actual_micro_usd,reserved_micro_usd)) FILTER(WHERE task_id=$2),0)::bigint AS task,COALESCE(sum(COALESCE(actual_micro_usd,reserved_micro_usd)) FILTER(WHERE agent_id=$3 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),0)::bigint AS agent,count(*) FILTER(WHERE task_id=$2)::bigint AS calls,COALESCE(sum(COALESCE(input_tokens,reserved_input_tokens)) FILTER(WHERE task_id=$2 OR ($2 IS NULL AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')),0)::bigint AS input,COALESCE(sum(COALESCE(output_tokens,reserved_output_tokens)) FILTER(WHERE task_id=$2 OR ($2 IS NULL AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')),0)::bigint AS output FROM model_calls WHERE owner_id=$1").bind(scope.owner_id).bind(task_id).bind(agent_id).fetch_one(&mut *tx).await?;
        for (name, cap, applicable) in [
            ("task", limits.task_usd, task_id.is_some()),
            ("day", limits.day_usd, true),
            ("month", limits.month_usd, true),
            ("agent", limits.agent_day_usd, agent_id.is_some()),
        ] {
            if applicable
                && totals.try_get::<i64, _>(name)?.saturating_add(reserve) > usd_cap_micro(cap)?
            {
                return Err(Error::Unavailable(format!(
                    "{name} model cost budget exhausted"
                )));
            }
        }
        let provider_caps: Option<(f64, f64)> = sqlx::query_as("SELECT day_usd::float8,month_usd::float8 FROM provider_budgets WHERE owner_id=$1 AND provider_id=$2").bind(scope.owner_id).bind(provider.id).fetch_optional(&mut *tx).await?;
        if let Some((day_cap, month_cap)) = provider_caps {
            let pday: i64 = sqlx::query_scalar("SELECT COALESCE(sum(COALESCE(actual_micro_usd,reserved_micro_usd)),0)::bigint FROM model_calls WHERE owner_id=$1 AND provider_id=$2 AND created_at>=date_trunc('day',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'").bind(scope.owner_id).bind(provider.id).fetch_one(&mut *tx).await?;
            let pmonth: i64 = sqlx::query_scalar("SELECT COALESCE(sum(COALESCE(actual_micro_usd,reserved_micro_usd)),0)::bigint FROM model_calls WHERE owner_id=$1 AND provider_id=$2 AND created_at>=date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'").bind(scope.owner_id).bind(provider.id).fetch_one(&mut *tx).await?;
            if day_cap > 0.0 && pday.saturating_add(reserve) > usd_cap_micro(day_cap)? {
                return Err(Error::Unavailable("provider model cost budget exhausted".into()));
            }
            if month_cap > 0.0 && pmonth.saturating_add(reserve) > usd_cap_micro(month_cap)? {
                return Err(Error::Unavailable("provider model cost budget exhausted".into()));
            }
        }
        if task_id.is_some()
            && totals.try_get::<i64, _>("calls")? >= i64::from(limits.max_model_calls)
            || totals
                .try_get::<i64, _>("input")?
                .saturating_add(max_input as i64)
                > limits.max_input_tokens
            || totals
                .try_get::<i64, _>("output")?
                .saturating_add(max_output as i64)
                > limits.max_output_tokens
        {
            return Err(Error::Unavailable(
                "model call or token budget exhausted".into(),
            ));
        }
        let call_id = Uuid::new_v4();
        let route = RouteMetadata {
            provider_id: provider.id,
            model_id: model.id,
            model: model.model.clone(),
            local: provider.local,
            privacy,
            reason: if pinned.is_some() { "explicit chat model choice, capability and privacy still enforced".into() } else { "ordered role, explicit capability, installation mode and maximum context privacy".into() },
            effective_origin: provider.origin.clone(),
        };
        sqlx::query("INSERT INTO model_calls(id,owner_id,task_id,agent_id,provider_id,model_id,model,local,privacy_class,operation,reserved_micro_usd,pricing_known,reserved_input_tokens,reserved_output_tokens) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)").bind(call_id).bind(scope.owner_id).bind(task_id).bind(agent_id).bind(provider.id).bind(model.id).bind(&model.model).bind(provider.local).bind(orbit_core::literal(privacy)).bind(operation.name()).bind(reserve).bind(pricing_known).bind(max_input as i64).bind(max_output as i64).execute(&mut *tx).await?;
        let correlation: Uuid = if let Some(task) = task_id {
            sqlx::query_scalar("SELECT correlation_id FROM tasks WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id)
                .bind(task)
                .fetch_one(&mut *tx)
                .await?
        } else {
            call_id
        };
        sqlx::query("INSERT INTO audit_events(id,owner_id,correlation_id,principal_id,task_id,operation,reason,metadata) VALUES($1,$2,$3,$4,$5,'MODEL_SELECTED',$6,$7)").bind(Uuid::new_v4()).bind(scope.owner_id).bind(correlation).bind(scope.principal_id).bind(task_id).bind(&route.reason).bind(serde_json::json!({"call_id":call_id,"route":route,"pricing_known":pricing_known,"reserved_micro_usd":reserve})).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Selection {
            provider,
            model,
            route,
            call_id,
        })
    }
    async fn settle(
        &self,
        scope: &OwnerScope,
        call_id: Uuid,
        usage: Option<&Usage>,
        latency: i64,
        success: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT revision FROM authorization_epochs WHERE owner_id=$1 FOR UPDATE")
            .bind(scope.owner_id)
            .fetch_one(&mut *tx)
            .await?;
        let row=sqlx::query("SELECT c.*,m.configuration FROM model_calls c LEFT JOIN models m ON m.owner_id=c.owner_id AND m.id=c.model_id WHERE c.owner_id=$1 AND c.id=$2 FOR UPDATE OF c").bind(scope.owner_id).bind(call_id).fetch_one(&mut *tx).await?;
        let known = usage.is_some_and(|u| u.known);
        let actual = if known {
            let u = usage.unwrap();
            if row.try_get::<bool, _>("local")?
                && row
                    .try_get::<Option<serde_json::Value>, _>("configuration")?
                    .is_none()
            {
                Some(0)
            } else if let Some(config) =
                row.try_get::<Option<serde_json::Value>, _>("configuration")?
            {
                let m: ModelConfig = serde_json::from_value(config)?;
                if let Some((a, b)) = m.input_usd_per_million.zip(m.output_usd_per_million) {
                    Some(cost_micro(u.input_tokens, u.output_tokens, a, b)?)
                } else if row.try_get::<bool, _>("local")? {
                    Some(0)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        // Missing/ambiguous usage never releases the original capped reservation.
        sqlx::query("UPDATE model_calls SET state=$3,actual_micro_usd=$4,input_tokens=$5,output_tokens=$6,cached_tokens=$7,usage_known=$8,latency_ms=$9,settled_at=now() WHERE owner_id=$1 AND id=$2").bind(scope.owner_id).bind(call_id).bind(if success{"COMPLETED"}else{"FAILED"}).bind(actual).bind(usage.filter(|u|u.known).map(|u|u.input_tokens as i64)).bind(usage.filter(|u|u.known).map(|u|u.output_tokens as i64)).bind(usage.filter(|u|u.known).map(|u|u.cached_tokens as i64)).bind(known).bind(latency).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
pub fn effective_privacy(
    base: PrivacyClass,
    context: &[ContextBlock],
    chat: &ChatRequest,
) -> PrivacyClass {
    context
        .iter()
        .map(|c| c.privacy_class)
        .chain(
            chat.messages
                .iter()
                .flat_map(|m| m.images.iter().map(|i| i.privacy_class)),
        )
        .chain([base])
        .max()
        .unwrap_or(PrivacyClass::Private)
}
pub fn route_allowed(
    mode: InstallationMode,
    privacy: PrivacyClass,
    local: bool,
    private_cloud: bool,
) -> bool {
    if privacy == PrivacyClass::Secret {
        return false;
    }
    if (mode == InstallationMode::LocalOnly && !local)
        || (mode == InstallationMode::CloudOnly && local)
    {
        return false;
    }
    local
        || match privacy {
            PrivacyClass::Public | PrivacyClass::Personal => true,
            PrivacyClass::Private => private_cloud,
            PrivacyClass::HighlyPrivate | PrivacyClass::Secret => false,
        }
}
fn local_error(error: Error, route: &RouteMetadata) -> Error {
    match error {
        Error::Unavailable(reason) if route.local => {
            Error::Unavailable(format!("LOCAL_MODEL_UNAVAILABLE: {reason}"))
        }
        other => other,
    }
}
fn usd_cap_micro(usd: f64) -> Result<i64> {
    if !usd.is_finite() || usd < 0. || usd > 1_000_000. {
        return Err(Error::Validation("invalid cost cap".into()));
    }
    Ok((usd * 1_000_000.).floor() as i64)
}
fn cost_micro(input: u64, output: u64, a: f64, b: f64) -> Result<i64> {
    if !a.is_finite() || !b.is_finite() || a < 0. || b < 0. {
        return Err(Error::Validation("invalid provider price".into()));
    }
    let n = (input as f64 * a + output as f64 * b).ceil();
    if n > i64::MAX as f64 {
        return Err(Error::Validation("model cost overflows".into()));
    }
    Ok(n as i64)
}
enum Operation<'a> {
    Chat(&'a ChatRequest),
    Embed(&'a EmbeddingRequest),
    Rerank(&'a RerankRequest),
}
impl Operation<'_> {
    fn name(&self) -> &str {
        match self {
            Self::Chat(_) => "CHAT",
            Self::Embed(_) => "EMBED",
            Self::Rerank(_) => "RERANK",
        }
    }
    fn is_rerank(&self) -> bool {
        matches!(self, Self::Rerank(_))
    }
    fn output_bound(&self) -> u64 {
        match self {
            Self::Chat(r) => u64::from(r.max_output_tokens),
            _ => 0,
        }
    }
    fn input_bound(&self) -> Result<u64> {
        let n = match self {
            Self::Chat(r) => {
                provider::validate_request(
                    r,
                    &ProviderCapabilities {
                        chat: true,
                        tools: true,
                        vision: true,
                        structured_output: true,
                        reasoning: true,
                        ..Default::default()
                    },
                )?;
                r.messages
                    .iter()
                    .map(|m| {
                        m.content.len() as u64
                            + m.tool_calls
                                .iter()
                                .map(|t| t.arguments.to_string().len() as u64 + 64)
                                .sum::<u64>()
                            + m.images.len() as u64 * 8192
                            + 32
                    })
                    .sum::<u64>()
                    + r.tools
                        .iter()
                        .map(|t| {
                            t.input_schema.to_string().len() as u64
                                + t.description.len() as u64
                                + 64
                        })
                        .sum::<u64>()
            }
            Self::Embed(r) => r.input.iter().map(|s| s.len() as u64 + 32).sum(),
            Self::Rerank(r) => {
                r.query.len() as u64 + r.documents.iter().map(|s| s.len() as u64 + 32).sum::<u64>()
            }
        };
        Ok(n)
    }
    fn supported(&self, c: &ProviderCapabilities) -> bool {
        match self {
            Self::Chat(r) => {
                c.chat
                    && (r.tools.is_empty() || c.tools)
                    && (r.output_schema.is_none() || c.structured_output)
                    && (!r.reasoning || c.reasoning)
                    && (r.messages.iter().all(|m| m.images.is_empty()) || c.vision)
            }
            Self::Embed(_) => c.embeddings,
            Self::Rerank(_) => c.rerank,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn privacy_mode_matrix() {
        for mode in [
            InstallationMode::LocalOnly,
            InstallationMode::Hybrid,
            InstallationMode::CloudOnly,
        ] {
            for p in [
                PrivacyClass::Public,
                PrivacyClass::Personal,
                PrivacyClass::Private,
                PrivacyClass::HighlyPrivate,
                PrivacyClass::Secret,
            ] {
                for local in [false, true] {
                    let allowed = route_allowed(mode, p, local, false);
                    if p == PrivacyClass::Secret
                        || p == PrivacyClass::HighlyPrivate && !local
                        || p == PrivacyClass::Private && !local
                        || mode == InstallationMode::LocalOnly && !local
                        || mode == InstallationMode::CloudOnly && local
                    {
                        assert!(!allowed);
                    } else {
                        assert!(allowed);
                    }
                }
            }
        }
        assert!(route_allowed(
            InstallationMode::Hybrid,
            PrivacyClass::Private,
            false,
            true
        ));
    }
    #[test]
    fn context_escalates_previous_public_route() {
        let chat = ChatRequest::default();
        let context = vec![ContextBlock {
            kind: orbit_core::ContextKind::ToolOutput,
            text_or_reference: "canary".into(),
            privacy_class: PrivacyClass::HighlyPrivate,
            trust_level: orbit_core::TrustLevel::UntrustedExternal,
            source_reference: "node-file".into(),
        }];
        assert_eq!(
            effective_privacy(PrivacyClass::Public, &context, &chat),
            PrivacyClass::HighlyPrivate
        );
    }
    #[test]
    fn reservations_round_up_caps_round_down() {
        assert_eq!(cost_micro(1, 0, 0.01, 0.).unwrap(), 1);
        assert_eq!(usd_cap_micro(0.0000009).unwrap(), 0);
    }
    #[test]
    fn highly_private_never_uses_cloud_even_with_explicit_policy() {
        for mode in [
            InstallationMode::LocalOnly,
            InstallationMode::Hybrid,
            InstallationMode::CloudOnly,
        ] {
            assert!(
                !route_allowed(mode, PrivacyClass::HighlyPrivate, false, true),
                "mode {mode:?} must not admit cloud for HIGHLY_PRIVATE"
            );
            assert!(!route_allowed(mode, PrivacyClass::Secret, false, true));
            assert!(!route_allowed(mode, PrivacyClass::Secret, true, true));
        }
    }
    #[test]
    fn unclassified_material_defaults_private() {
        let chat = ChatRequest::default();
        assert_eq!(
            effective_privacy(PrivacyClass::Private, &[], &chat),
            PrivacyClass::Private
        );
    }
    #[test]
    fn local_failures_surface_wait_code_cloud_errors_pass_through() {
        let local = RouteMetadata {
            provider_id: Uuid::new_v4(),
            model_id: Uuid::new_v4(),
            model: "m".into(),
            local: true,
            privacy: PrivacyClass::Public,
            reason: "r".into(),
            effective_origin: "http://127.0.0.1:11434".into(),
        };
        let cloud = RouteMetadata {
            local: false,
            ..local.clone()
        };
        match local_error(Error::Unavailable("endpoint down".into()), &local) {
            Error::Unavailable(reason) => assert!(
                reason.starts_with("LOCAL_MODEL_UNAVAILABLE"),
                "local outage must carry the wait-state code"
            ),
            other => panic!("unexpected {other:?}"),
        };
        match local_error(Error::Unavailable("endpoint down".into()), &cloud) {
            Error::Unavailable(reason) => assert!(
                !reason.starts_with("LOCAL_MODEL_UNAVAILABLE"),
                "cloud errors must not masquerade as local waits"
            ),
            other => panic!("unexpected {other:?}"),
        }
    }
}
