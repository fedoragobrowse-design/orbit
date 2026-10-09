//! Owner-approved node self-update with rollback. The node polls the signed release channel, stages a digest-verified binary, and keeps the current binary as `<path>.bak`. Staging and download require `owner_approved=true`: the node never auto-restarts or executes a fetched binary on its own.
use std::{cmp::Ordering,path::{Path,PathBuf}};
use sha2::{Digest,Sha256};
/// API path the node polls; node credentials ride `x-orbit-node-id` + bearer session when configured.
pub const CHECK_PATH: &str = "/api/v1/updates/check";
#[derive(Debug,Clone,serde::Serialize,serde::Deserialize)] pub struct UpdateInfo { pub update_available: bool, pub latest_version: String, #[serde(default)] pub digest: String, #[serde(default)] pub notes: String }
fn split_ver(v: &str) -> Vec<u64> { v.split('.').map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u64>().unwrap_or(0)).collect() }
/// Semver-split numeric compare, no new deps: missing parts count as 0 so `1.0` equals `1.0.0`.
pub fn compare_versions(a: &str, b: &str) -> Ordering { let (pa, pb) = (split_ver(a), split_ver(b)); for i in 0..pa.len().max(pb.len()) { let ord = pa.get(i).unwrap_or(&0).cmp(pb.get(i).unwrap_or(&0)); if ord != Ordering::Equal { return ord; } } Ordering::Equal }
/// Newer means a different string that orders greater; same-version rebuilds never read as updates.
pub fn is_newer(latest: &str, current: &str) -> bool { latest != current && compare_versions(latest, current) == Ordering::Greater }
/// Poll the owner's release channel for the stable release newer than `current_version`. Node auth (node id + session bearer) attaches when `ORBIT_NODE_ID`/`ORBIT_NODE_SESSION` are set; the server still requires the owner's session, so unattended polling stays owner-mediated (see docs/OTA.md).
pub async fn check(server_url: &str, current_version: &str) -> anyhow::Result<UpdateInfo> {
 let base = server_url.trim_end_matches('/');
 let encoded = current_version.trim().replace('+', "%2B");
 let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build()?;
 let mut req = client.get(format!("{base}{CHECK_PATH}?channel=stable&current={encoded}"));
 if let (Ok(id), Ok(session)) = (std::env::var("ORBIT_NODE_ID"), std::env::var("ORBIT_NODE_SESSION")) { req = req.header("x-orbit-node-id", id).header(reqwest::header::AUTHORIZATION, format!("Bearer {session}")); }
 let res = req.send().await?;
 if !res.status().is_success() { return Err(anyhow::anyhow!("update check rejected ({}); node self-update is owner-mediated", res.status())); }
 // Recompute the bit from the signed fields instead of trusting it blindly.
 let mut info: UpdateInfo = res.json().await?;
 info.update_available = info.update_available && is_newer(&info.latest_version, current_version);
 Ok(info)
}
/// sha256-verify fetched bytes against the release digest (64 hex, optional `sha256:` prefix).
pub fn verify_bytes(bytes: &[u8], digest: &str) -> anyhow::Result<()> { let want = digest.trim().strip_prefix("sha256:").unwrap_or(digest.trim()).to_ascii_lowercase(); if hex::encode(Sha256::digest(bytes)) == want { Ok(()) } else { Err(anyhow::anyhow!("update digest mismatch: bytes do not match the signed release digest")) } }
/// Sibling backup path: the current binary path plus `.bak`.
pub fn backup_path(current_binary: &Path) -> PathBuf { let mut s = current_binary.as_os_str().to_owned(); s.push(".bak"); PathBuf::from(s) }
/// Stage a verified binary: keep the current binary as `.bak`, then replace it. `owner_approved` must be true — an explicit owner decision, never a poll side effect. Staging never restarts the node; the owner restarts into the new binary.
pub fn stage_update(current_binary: &Path, bytes: &[u8], digest: &str, owner_approved: bool) -> anyhow::Result<()> {
 if !owner_approved { return Err(anyhow::anyhow!("node update requires explicit owner approval")); }
 verify_bytes(bytes, digest)?;
 if current_binary.exists() { std::fs::copy(current_binary, backup_path(current_binary))?; }
 std::fs::write(current_binary, bytes)?;
 #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(current_binary, std::fs::Permissions::from_mode(0o755))?; }
 Ok(())
}
/// Restore the `.bak` kept by [`stage_update`].
pub fn rollback(current_binary: &Path) -> anyhow::Result<()> { let bak = backup_path(current_binary); if !bak.exists() { return Err(anyhow::anyhow!("no update backup to roll back to")); } std::fs::copy(&bak, current_binary)?; Ok(()) }
/// Download an owner-approved artifact over verified TLS and stage it. URL, digest, and approval travel together in the owner's decision; the node never follows server-pushed URLs on its own.
pub async fn download_and_stage(artifact_url: &str, digest: &str, current_binary: &Path, owner_approved: bool) -> anyhow::Result<()> {
 if !owner_approved { return Err(anyhow::anyhow!("node update requires explicit owner approval")); }
 if !artifact_url.starts_with("https://") { return Err(anyhow::anyhow!("update artifacts must come over verified https")); }
 let bytes = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build()?.get(artifact_url).send().await?.error_for_status()?.bytes().await?;
 stage_update(current_binary, &bytes, digest, true)
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn newer_means_different_string_and_greater_numeric() { assert!(is_newer("0.2.0", "0.1.0")); assert!(is_newer("0.10.0", "0.9.9")); assert!(!is_newer("0.1.0", "0.1.0")); assert!(!is_newer("0.1.0", "0.2.0")); assert!(!is_newer("1.0", "1.0.0")); assert!(compare_versions("1.0", "1.0.0") == Ordering::Equal); }
 #[test] fn stage_verifies_keeps_backup_and_rolls_back() {
  let dir = tempfile::tempdir().unwrap(); let bin = dir.path().join("orbit-computer-node");
  std::fs::write(&bin, b"current-binary-v1").unwrap();
  let next: &[u8] = b"next-binary-v2"; let digest = hex::encode(Sha256::digest(next));
  stage_update(&bin, next, &digest, true).unwrap();
  assert_eq!(std::fs::read(&bin).unwrap(), next.to_vec());
  assert_eq!(std::fs::read(backup_path(&bin)).unwrap(), b"current-binary-v1".to_vec());
  rollback(&bin).unwrap();
  assert_eq!(std::fs::read(&bin).unwrap(), b"current-binary-v1".to_vec());
 }
 #[test] fn stage_refuses_without_owner_approval_and_on_bad_digest() {
  let dir = tempfile::tempdir().unwrap(); let bin = dir.path().join("orbit-computer-node");
  std::fs::write(&bin, b"v1").unwrap();
  let next: &[u8] = b"v2"; let digest = hex::encode(Sha256::digest(next));
  assert!(stage_update(&bin, next, &digest, false).is_err());
  let bad = "0".repeat(64);
  assert!(stage_update(&bin, next, &bad, true).is_err());
  assert_eq!(std::fs::read(&bin).unwrap(), b"v1".to_vec());
 }
}
