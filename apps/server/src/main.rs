use orbit_api::ApiState;
use std::{env,path::PathBuf};
#[tokio::main]
async fn main()->anyhow::Result<()> {
 tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
 let pool=sqlx::postgres::PgPoolOptions::new().max_connections(20).connect(&env::var("DATABASE_URL")?).await?;
 let origin=env::var("ORBIT_PUBLIC_ORIGIN").unwrap_or_else(|_|"http://127.0.0.1:8080".into());
 if !origin.starts_with("https://")&&!origin.starts_with("http://127.0.0.1:")&&!origin.starts_with("http://localhost:")&&!origin.starts_with("http://[::1]:"){anyhow::bail!("public origin must use HTTPS except actual loopback")}
 let state=ApiState{pool,origin,key_dir:PathBuf::from(env::var("ORBIT_KEY_DIR").unwrap_or_else(|_|"data/keys".into())),artifact_dir:PathBuf::from(env::var("ORBIT_ARTIFACT_DIR").unwrap_or_else(|_|"data/artifacts".into())),nodes:orbit_api::computers::NodeHub::new()};
 let command=env::args().nth(1);
 if command.as_deref()==Some("bootstrap-token"){println!("{}",orbit_api::auth::bootstrap_token(&state).await?);return Ok(())}
 if command.as_deref()==Some("recovery-code"){println!("{}",orbit_api::auth::mint_recovery_code_inner(&state).await?);return Ok(())}
 if command.is_some(){anyhow::bail!("supported command: bootstrap-token, recovery-code")}
 orbit_api::initialize(&state).await?;
 tokio::fs::create_dir_all(&state.artifact_dir).await?;
 let bind=env::var("ORBIT_BIND").unwrap_or_else(|_|"127.0.0.1:3000".into());
 let listener=tokio::net::TcpListener::bind(&bind).await?;
 let worker=tokio::spawn(orbit_api::worker(state.clone()));
 axum::serve(listener,orbit_api::router(state)).with_graceful_shutdown(async {let _=tokio::signal::ctrl_c().await;}).await?;
 worker.abort();Ok(())
}
