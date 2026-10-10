//! Provider credential + OAuth client write-only round-trip.
//! Backend slice of the AppKeysOAuth ticket: rotate endpoint seals a fresh
//! secret and swaps the row; OAuth clients store client-id + sealed secret
//! and report configured/unconfigured. No GET/list/detail/rotate/status
//! response may contain a credential value. Owned test postgres only
//! (default 127.0.0.1:55432 orbit_test). Never the personal deployment.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header},
};
use orbit_api::{ApiState, models};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    // Hermetic per-run database: the shared orbit_test DB accumulates secret
    // rows encrypted under keys this run cannot reopen.
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pool = PgPool::connect(&url)
            .await
            .expect("owned test postgres reachable");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations apply");
        return pool;
    }
    let tag: String = Uuid::new_v4().simple().to_string()[..8].to_owned();
    let db = format!("orbit_modelcred_{}_{tag}", std::process::id());
    let admin = PgPool::connect("postgres://orbit_test:orbit_test@127.0.0.1:55432/postgres")
        .await
        .expect("test postgres admin reachable");
    sqlx::query(&format!("DROP DATABASE IF EXISTS {db}"))
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE DATABASE {db} OWNER orbit_test"))
        .execute(&admin)
        .await
        .unwrap();
    let pool = PgPool::connect(&format!(
        "postgres://orbit_test:orbit_test@127.0.0.1:55432/{db}"
    ))
    .await
    .expect("owned test postgres reachable");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("migrations apply");
    // Stash the name for cleanup: DATABASE_URL is unset, so track via a file.
    std::fs::write(
        std::env::temp_dir().join(format!("orbit-modelcred-db-{tag}-{}", std::process::id())),
        &db,
    )
    .ok();
    pool
}

async fn ctx(pool: &PgPool, tag: &str) -> (ApiState, HeaderMap, Uuid) {
    let owner = Uuid::new_v4();
    let principal = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,display_name,password_hash) VALUES($1,$2,'t','x')")
        .bind(owner)
        .bind(format!("modelcred-{tag}-{owner}@example.invalid"))
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
    let token = format!("modelcred-token-{tag}-{owner}");
    let csrf = format!("modelcred-csrf-{tag}-{owner}");
    sqlx::query("INSERT INTO sessions(id,owner_id,principal_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')")
        .bind(Uuid::new_v4())
        .bind(owner)
        .bind(principal)
        .bind(orbit_api::auth::hash(&token))
        .bind(&csrf)
        .execute(pool)
        .await
        .unwrap();
    let key_dir = std::env::temp_dir().join(format!("orbit-modelcred-{tag}-{owner}"));
    let artifact_dir = key_dir.join("artifacts");
    let origin = "http://127.0.0.1:8080".to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("orbit_session={token}").parse().unwrap(),
    );
    headers.insert(header::ORIGIN, origin.parse().unwrap());
    headers.insert("x-csrf-token", csrf.parse().unwrap());
    (
        ApiState {
            pool: pool.clone(),
            origin,
            key_dir,
            artifact_dir,
            nodes: orbit_api::computers::NodeHub::new(),
        },
        headers,
        owner,
    )
}

/// Owner scope for the test provider row, for server-side secret reads.
async fn test_scope(pool: &PgPool, provider_id: Uuid) -> orbit_core::OwnerScope {
    let owner_id: Uuid = sqlx::query_scalar("SELECT owner_id FROM model_providers WHERE id=$1")
        .bind(provider_id)
        .fetch_one(pool)
        .await
        .unwrap();
    orbit_core::OwnerScope {
        owner_id,
        principal_id: Uuid::new_v4(),
    }
}
/// A response leaks if any string value inside it equals a planted secret.
fn leaks(value: &Value, secrets: &[&str]) -> Option<String> {
    match value {
        Value::String(s) => secrets
            .iter()
            .find(|secret| !secret.is_empty() && s.contains(*secret))
            .map(|s| (*s).to_owned()),
        Value::Array(items) => items.iter().find_map(|item| leaks(item, secrets)),
        Value::Object(map) => map.values().find_map(|item| leaks(item, secrets)),
        _ => None,
    }
}

#[tokio::test]
async fn provider_credential_roundtrip_is_write_only() {
    let pool = pool().await;
    let (state, headers, _) = ctx(&pool, "rotate").await;
    let secret_a = "modelcred-plant-alpha-9f31";
    let secret_b = "modelcred-plant-beta-77c2";

    // Create with a credential: response carries secret_set, never the value.
    let created = match models::create_provider(
        State(state.clone()),
        headers.clone(),
        Json(models::ProviderCreate {
            name: "cred probe".into(),
            kind: "OPENAI_COMPATIBLE".into(),
            origin: "https://models.example.invalid".into(),
            local: Some(false),
            admitted_addresses: None,
            rerank_path: None,
            enabled: None,
            credential: Some(secret_a.into()),
        }),
    )
    .await
    {
        Ok(Json(v)) => v,
        Err(_) => panic!("create with credential must succeed"),
    };
    assert_eq!(created["secret_set"], json!(true));
    assert!(
        leaks(&created, &[secret_a]).is_none(),
        "create response must not contain the secret"
    );
    let id: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
    let revision = created["revision"].as_i64().unwrap();

    // List/detail responses stay clean too.
    let listed = match models::list_providers(
        State(state.clone()),
        headers.clone(),
        axum::extract::Query(models::ListPage {
            cursor: None,
            limit: None,
        }),
    )
    .await
    {
        Ok(Json(v)) => v,
        Err(_) => panic!("provider list must succeed"),
    };
    assert!(
        leaks(&listed, &[secret_a]).is_none(),
        "list response must not contain the secret"
    );
    let detailed = match models::provider_detail(State(state.clone()), headers.clone(), Path(id)).await
    {
        Ok(Json(v)) => v,
        Err(_) => panic!("provider detail must succeed"),
    };
    assert!(
        leaks(&detailed, &[secret_a]).is_none(),
        "detail response must not contain the secret"
    );

    // Rotate: response is the normal provider view, still write-only.
    let rotated = match models::rotate_credential(
        State(state.clone()),
        headers.clone(),
        Path(id),
        Json(models::CredentialRotate {
            credential: secret_b.into(),
            expected_revision: Some(revision),
        }),
    )
    .await
    {
        Ok(Json(v)) => v,
        Err(_) => panic!("credential rotate must succeed"),
    };
    assert_eq!(rotated["secret_set"], json!(true));
    assert!(
        rotated["revision"].as_i64().unwrap() > revision,
        "rotate must bump the provider revision"
    );
    assert!(
        leaks(&rotated, &[secret_a, secret_b]).is_none(),
        "rotate response must not contain either secret"
    );

    // Stale revision is refused rather than overwritten.
    let stale = models::rotate_credential(
        State(state.clone()),
        headers.clone(),
        Path(id),
        Json(models::CredentialRotate {
            credential: "modelcred-stale".into(),
            expected_revision: Some(revision),
        }),
    )
    .await;
    assert!(stale.is_err(), "stale rotate revision must conflict");

    // The sealed secret is actually stored and recoverable server-side.
    let row = sqlx::query("SELECT credential_id FROM model_providers WHERE id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    use sqlx::Row as _;
    let credential_id: Uuid = row.try_get("credential_id").unwrap();
    let scope = test_scope(&pool, id).await;
    let store = orbit_secrets::SecretStore::open(pool.clone(), &state.key_dir)
        .await
        .expect("secret store opens");
    let sealed = store.get(&scope, credential_id).await.expect("sealed secret reads back");
    assert_eq!(sealed.as_slice(), secret_b.as_bytes());
    let _ = std::fs::remove_dir_all(state.key_dir.clone());
}

#[tokio::test]
async fn oauth_client_status_reflects_configured() {
    let pool = pool().await;
    let (state, headers, owner) = ctx(&pool, "oauth").await;
    let client_secret = "modelcred-oauth-plant-51ab";

    // Fresh owner: every connector unconfigured, none usable.
    let status = match models::oauth_status(State(state.clone()), headers.clone()).await {
        Ok(Json(v)) => v,
        Err(_) => panic!("oauth status must succeed"),
    };
    let items = status["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "status covers google/outlook/github");
    for item in items {
        assert_eq!(item["configured"], json!(false));
        assert_eq!(item["usable"], json!(false));
    }

    // Store a github client: response is status-shaped, never the secret.
    let stored = match models::upsert_oauth_client(
        State(state.clone()),
        headers.clone(),
        Path("github".into()),
        Json(models::OAuthClientUpsert {
            client_id: "github-client-id-1234".into(),
            client_secret: client_secret.into(),
        }),
    )
    .await
    {
        Ok(Json(v)) => v,
        Err(_) => panic!("oauth upsert must succeed"),
    };
    assert_eq!(stored["connector"], json!("github"));
    assert_eq!(stored["configured"], json!(true));
    assert_eq!(stored["usable"], json!(false));
    assert!(
        leaks(&stored, &[client_secret]).is_none(),
        "oauth upsert response must not contain the secret"
    );

    // Status now reflects configured for github only.
    let status = match models::oauth_status(State(state.clone()), headers.clone()).await {
        Ok(Json(v)) => v,
        Err(_) => panic!("oauth status must succeed"),
    };
    let by_connector = |name: &str| {
        status["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["connector"] == json!(name))
            .cloned()
            .unwrap()
    };
    let github = by_connector("github");
    let google = by_connector("google");
    assert_eq!(github["configured"], json!(true));
    assert_eq!(google["configured"], json!(false));
    assert!(
        leaks(&status, &[client_secret]).is_none(),
        "oauth status must not contain the secret"
    );
    assert!(
        github["client_id_suffix"]
            .as_str()
            .unwrap()
            .ends_with("1234"),
        "status shows only a client-id suffix"
    );

    // Unknown connectors are rejected.
    let bad = models::upsert_oauth_client(
        State(state.clone()),
        headers.clone(),
        Path("not-a-connector".into()),
        Json(models::OAuthClientUpsert {
            client_id: "x".into(),
            client_secret: "y".into(),
        }),
    )
    .await;
    assert!(bad.is_err(), "unknown connector must be rejected");

    // Delete revokes and returns to unconfigured.
    let removed = match models::delete_oauth_client(
        State(state.clone()),
        headers.clone(),
        Path("github".into()),
    )
    .await
    {
        Ok(Json(v)) => v,
        Err(_) => panic!("oauth delete must succeed"),
    };
    assert_eq!(removed["configured"], json!(false));
    let status = match models::oauth_status(State(state.clone()), headers.clone()).await {
        Ok(Json(v)) => v,
        Err(_) => panic!("oauth status must succeed"),
    };
    assert_eq!(
        status["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["connector"] == json!("github"))
            .unwrap()["configured"],
        json!(false)
    );

    // Owner isolation: a second owner sees unconfigured.
    let (state2, headers2, owner2) = ctx(&pool, "oauth-second").await;
    assert_ne!(owner, owner2);
    let status2 = match models::oauth_status(State(state2.clone()), headers2.clone()).await {
        Ok(Json(v)) => v,
        Err(_) => panic!("second owner status must succeed"),
    };
    for item in status2["items"].as_array().unwrap() {
        assert_eq!(item["configured"], json!(false));
    }
    let _ = std::fs::remove_dir_all(state.key_dir.clone());
    let _ = std::fs::remove_dir_all(state2.key_dir.clone());
}
