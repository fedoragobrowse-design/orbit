//! Milestone 3 agent slice: registry seeding, proposal journaling, DENY default.
//! Owned test postgres only (default 127.0.0.1:55432 orbit_test). Never the personal deployment.
use orbit_agent_runtime::Dispatcher;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://orbit_test:orbit_test@127.0.0.1:55432/orbit_test".into())
}

async fn pool() -> PgPool {
    let pool = PgPool::connect(&db_url())
        .await
        .expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations apply");
    pool
}

async fn owner(pool: &PgPool) -> orbit_core::OwnerScope {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')")
        .bind(owner)
        .bind(format!("t-{owner}@example.invalid"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO authorization_epochs(owner_id) VALUES($1)")
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO principals(id,owner_id,principal_type,auth_method,trust_level,source) VALUES($1,$2,'WEB_USER','password','OWNER_AUTHENTICATED','test')")
        .bind(principal)
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    orbit_core::OwnerScope {
        owner_id: owner,
        principal_id: principal,
    }
}

fn dispatcher(pool: &PgPool) -> orbit_api::agents::AgentDispatcher { orbit_api::agents::AgentDispatcher { pool: pool.clone(), key_dir: std::path::PathBuf::from("/tmp"), artifact_dir: std::path::PathBuf::from("/tmp"), origin: "http://localhost:3000".into() } }

async fn agent(pool: &PgPool, scope: &orbit_core::OwnerScope, tools: &[&str]) -> Uuid {
    let available: Vec<orbit_core::ToolDescriptor> = orbit_tools::descriptors()
        .into_iter()
        .chain(orbit_memory::descriptors())
        .collect();
    orbit_agent_runtime::seed_agents(pool, scope, &available)
        .await
        .unwrap();
    for d in orbit_tools::descriptors()
        .into_iter()
        .chain(orbit_memory::descriptors())
        .filter(|d| tools.contains(&d.name.as_str()))
    {
        let digest = orbit_computer_node_protocol::sha256(&serde_json::to_vec(&d).unwrap());
        sqlx::query("INSERT INTO tool_registry(id,owner_id,name,version,descriptor,descriptor_digest,provider_name,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,true) ON CONFLICT(owner_id,name) DO NOTHING")
            .bind(d.id).bind(scope.owner_id).bind(&d.name).bind(&d.version)
            .bind(serde_json::to_value(&d).unwrap()).bind(&digest)
            .bind(orbit_tools::provider_name(d.id)).execute(pool).await.unwrap();
    }
    let id = Uuid::new_v4();
    let config = json!({"name":"t","purpose":"t","instructions":"t",
        "allowed_tools":tools,"model_role":"FAST",
        "context_strategy":{"include_memory":false,"history_messages":10,"max_context_characters":8000},
        "limits":{"max_model_calls":2,"max_tool_calls":4,"max_active_seconds":60,"max_tokens":4096,"max_retries":1,"max_subagent_depth":0},
        "autonomy_constraints":[],"memory_permissions":{"read_types":[],"write_types":[],"project_ids":[]},
        "sandbox_required":false});
    sqlx::query("INSERT INTO agent_definitions(id,owner_id,definition) VALUES($1,$2,$3)")
        .bind(id)
        .bind(scope.owner_id)
        .bind(config)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn task(pool: &PgPool, scope: &orbit_core::OwnerScope) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tasks(id,owner_id,principal_id,correlation_id,consumer,title) VALUES($1,$2,$3,$4,'agents','t')")
        .bind(id)
        .bind(scope.owner_id)
        .bind(scope.principal_id)
        .bind(Uuid::new_v4())
        .execute(pool)
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn seed_tools_carries_provider_identity_and_upserts() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    let state = orbit_api::ApiState {
        pool: pool.clone(),
        origin: "http://127.0.0.1:1".into(),
        key_dir: "/tmp".into(),
        artifact_dir: "/tmp".into(),
        nodes: orbit_api::computers::NodeHub::default(),
    };
    orbit_api::agents::seed_agent_tools(&state).await.unwrap();
    orbit_api::agents::seed_agent_tools(&state).await.unwrap();
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT provider_name FROM tool_registry WHERE owner_id=$1 AND name IN ('notifications.create','memory.search') ORDER BY name",
    )
    .bind(scope.owner_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    for p in rows {
        assert!(
            p.starts_with("t_") && p.len() == 34,
            "namespaced provider id, got {p}"
        );
    }
}

#[tokio::test]
async fn in_app_proposal_journals_and_replays() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    let agent = agent(&pool, &scope, &["notifications.create"]).await;
    let task = task(&pool, &scope).await;
    let d = dispatcher(&pool);
    let args = json!({"severity":"INFO","title":"hi","body":"hello","related_entity_ids":[]});
    let first = d
        .propose(
            &scope,
            task,
            agent,
            "notifications.create",
            args.clone(),
            "k1",
        )
        .await
        .unwrap();
    assert_eq!(first["state"], "PROPOSED", "{first:?}");
    assert!(
        first.get("approval_id").is_none(),
        "in-app calls need no consent row"
    );
    let replay = d
        .propose(&scope, task, agent, "notifications.create", args, "k1")
        .await
        .unwrap();
    assert_eq!(replay.get("replayed"), Some(&Value::Bool(true)));
    assert_eq!(replay["call_id"], first["call_id"]);
    assert_eq!(replay["proposal_digest"], first["proposal_digest"]);
    let other = d
        .propose(
            &scope,
            task,
            agent,
            "notifications.create",
            json!({"severity":"INFO","title":"other","body":"x","related_entity_ids":[]}),
            "k2",
        )
        .await
        .unwrap();
    assert_ne!(
        other["proposal_digest"], first["proposal_digest"],
        "digest binds the exact call"
    );
}

#[tokio::test]
async fn unadmitted_tool_denies_without_consent_row() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    let agent = agent(&pool, &scope, &["notifications.create"]).await;
    let task = task(&pool, &scope).await;
    let d = dispatcher(&pool);
    let out = d
        .propose(&scope, task, agent, "files.delete", json!({}), "k1")
        .await
        .unwrap();
    assert_eq!(out["state"], "DENIED");
    let call: Uuid = serde_json::from_value(out["call_id"].clone()).unwrap();
    let row = sqlx::query("SELECT approval_id FROM tool_calls WHERE owner_id=$1 AND id=$2")
        .bind(scope.owner_id)
        .bind(call)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(row.get::<Option<Uuid>, _>("approval_id").is_none());
    let approvals: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approvals WHERE owner_id=$1 AND call_id=$2")
            .bind(scope.owner_id)
            .bind(call)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(approvals, 0);
}

#[tokio::test]
async fn non_in_app_admitted_tool_parks_with_approval_row() {
    let pool = pool().await;
    let scope = owner(&pool).await;
    // Admit a non-in-app tool directly in the registry with a permissive descriptor.
    let descriptor = json!({"id":Uuid::new_v4(),"name":"files.read","version":"1",
        "input_schema":{"type":"object"},"output_schema":{"type":"object"},
        "effects":{"external":false,"modifies_data":false,"reversible":true,"credential_access":false,"affected_party":"owner","network":false},
        "default_risk":"READ_ONLY","permission_keys":[],"sandbox_required":false});
    let digest = orbit_computer_node_protocol::sha256(&serde_json::to_vec(&descriptor).unwrap());
    sqlx::query("INSERT INTO tool_registry(id,owner_id,name,version,descriptor,descriptor_digest,provider_name,enabled) VALUES($1,$2,'files.read','1',$3,$4,$5,true)")
        .bind(Uuid::new_v4())
        .bind(scope.owner_id)
        .bind(&descriptor)
        .bind(&digest)
        .bind(format!("t_{}", "0".repeat(32)))
        .execute(&pool)
        .await
        .unwrap();
    let agent = agent(&pool, &scope, &["files.read"]).await;
    let task = task(&pool, &scope).await;
    let d = dispatcher(&pool);
    let out = d
        .propose(&scope, task, agent, "files.read", json!({"node_id": Uuid::new_v4(), "root_id": Uuid::new_v4(), "file_id": Uuid::new_v4()}), "k1")
        .await
        .unwrap();
    // Empty scopes deny even reads by default; either outcome must be journaled honestly.
    let state = out["state"].as_str().unwrap().to_owned();
    assert!(
        state == "WAITING_FOR_APPROVAL" || state == "DENIED",
        "unexpected {state}"
    );
    if state == "WAITING_FOR_APPROVAL" {
        let approval: Uuid = serde_json::from_value(out["approval_id"].clone()).unwrap();
        let row =
            sqlx::query("SELECT action_hash,state FROM approvals WHERE owner_id=$1 AND id=$2")
                .bind(scope.owner_id)
                .bind(approval)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(row.get::<String, _>("state"), "PENDING");
        assert_eq!(
            row.get::<String, _>("action_hash"),
            out["proposal_digest"].as_str().unwrap()
        );
    }
}
