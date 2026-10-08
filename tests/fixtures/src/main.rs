#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>>{
 let bind=std::env::var("ORBIT_FIXTURE_BIND").unwrap_or_else(|_|"127.0.0.1:18090".into());
 let listener=tokio::net::TcpListener::bind(bind).await?;
 eprintln!("Orbit TEST-ONLY protocol fixtures listening on {}",listener.local_addr()?);
 axum::serve(listener,orbit_fixtures::router()).with_graceful_shutdown(async{let _=tokio::signal::ctrl_c().await;}).await?;Ok(())
}
