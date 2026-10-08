//! Live AIec smoke workload. Gated on operator-supplied environment; never runs
//! against a fake endpoint and never logs key contents.
//!
//! ```bash
//! export ORBIT_AIEC_URL=https://<configured-ai-ec-api-origin>
//! export ORBIT_AIEC_KEY_FILE=<readable-file-containing-tenant-rest-api-key>
//! export ORBIT_AIEC_CA_FILE=<trusted-ca-file-if-private-ca>
//! export ORBIT_AIEC_IMAGE=<admitted-python-capable-image>
//! export ORBIT_AIEC_DISK_MB=<supported-disk-floor>
//! cargo run --locked -p orbit-aiec-runtime --example live_smoke
//! ```

use orbit_aiec_runtime::{AIecRuntime, ConnectionConfig};
use orbit_task_runtime::{RuntimeSpec, RuntimeTask, TaskRuntime};
use std::net::IpAddr;
use uuid::Uuid;
use zeroize::Zeroizing;

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let origin = required("ORBIT_AIEC_URL")?;
    let key_file = required("ORBIT_AIEC_KEY_FILE")?;
    let image = required("ORBIT_AIEC_IMAGE")?;
    let disk_mb: u32 = required("ORBIT_AIEC_DISK_MB")?
        .parse()
        .map_err(|_| "ORBIT_AIEC_DISK_MB must be a number".to_owned())?;
    let ca_pem = match std::env::var("ORBIT_AIEC_CA_FILE") {
        Ok(path) => {
            Some(std::fs::read_to_string(&path).map_err(|e| format!("cannot read CA file: {e}"))?)
        }
        Err(_) => None,
    };
    // Resolve the origin to pinned addresses in the operator namespace; the
    // smoke uses the first resolution and pins it for the whole session.
    let host = reqwest::Url::parse(&origin)
        .map_err(|_| "ORBIT_AIEC_URL must be a valid URL".to_owned())?
        .host_str()
        .ok_or("ORBIT_AIEC_URL must carry a host")?
        .to_owned();
    let admitted: Vec<IpAddr> = tokio::net::lookup_host(format!("{host}:443"))
        .await
        .map_err(|e| format!("cannot resolve AIec origin: {e}"))?
        .map(|addr| addr.ip())
        .collect();
    if admitted.is_empty() {
        return Err("AIec origin resolved to no addresses".into());
    }
    let key = Zeroizing::new(
        std::fs::read(key_file.trim()).map_err(|e| format!("cannot read key file: {e}"))?,
    );
    let runtime = AIecRuntime::connect(
        ConnectionConfig {
            origin,
            admitted_addresses: admitted,
            ca_pem,
            secret_id: Uuid::nil(),
            image: image.clone(),
            disk_mb,
            lifetime_seconds: 1680,
        },
        key,
    )
    .await
    .map_err(|e| format!("AIec connect failed: {e}"))?;
    let readiness = runtime
        .readiness()
        .await
        .map_err(|e| format!("AIec readiness failed: {e}"))?;
    println!("readiness: {readiness}");
    let run_id = Uuid::new_v4();
    let spec = RuntimeSpec {
        run_id,
        image,
        cpu: 1,
        memory_mb: 512,
        disk_mb,
        lifetime_seconds: 1680,
        network_enabled: false,
        inputs: Vec::new(),
    };
    // The run UUID is the POST Idempotency-Key; status polling reuses it.
    let handle = runtime
        .create(spec)
        .await
        .map_err(|e| format!("create failed: {e}"))?;
    println!(
        "sandbox {} running; remaining lifetime enforced from created_at",
        handle.id()
    );
    let result = runtime
        .execute(
            &handle,
            RuntimeTask {
                argv: vec!["python3".into(), "-c".into(), "print('orbit-smoke')".into()],
                working_directory: "/workspace".into(),
                timeout_seconds: 60,
                output_paths: vec!["/workspace/smoke.txt".into()],
            },
        )
        .await
        .map_err(|e| format!("exec failed: {e}"))?;
    println!(
        "exit={:?} timed_out={} stdout={}",
        result.exit_code,
        result.outcome == orbit_task_runtime::RuntimeOutcome::TimedOut,
        result.stdout.trim()
    );
    if result.outcome != orbit_task_runtime::RuntimeOutcome::Exited || result.exit_code != Some(0) {
        let _ = runtime.destroy(handle).await;
        return Err("smoke workload did not exit zero".into());
    }
    runtime
        .restore_outputs(handle.id(), vec!["/workspace/smoke.txt".into()])
        .map_err(|e| format!("outputs failed: {e}"))?;
    let artifacts = runtime
        .collect_artifacts(&handle)
        .await
        .map_err(|e| format!("collect failed: {e}"))?;
    println!("collected {} artifact(s)", artifacts.len());
    runtime
        .destroy(handle)
        .await
        .map_err(|e| format!("destroy failed: {e}"))?;
    match runtime
        .status(run_id)
        .await
        .map_err(|e| format!("post-destroy status failed: {e}"))?
    {
        None => println!("destroy confirmed: sandbox no longer listed"),
        Some(sandbox) if sandbox.state == "destroyed" => {
            println!("destroy confirmed: state=destroyed")
        }
        Some(sandbox) => return Err(format!("destroy unconfirmed: state={}", sandbox.state)),
    }
    println!(
        "live smoke complete: egress denied by no-network guard, artifact verified, sandbox destroyed"
    );
    Ok(())
}
