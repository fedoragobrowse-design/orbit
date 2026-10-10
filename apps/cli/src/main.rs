//! Orbit CLI (growth D15): `orbit login|jobs|approve|brief|search|tail`
//! against a running server with a token stored `0600` at
//! `~/.config/orbit/token`. Hand-parsed argv, std only — no new deps.
//! Every command reads the token file; `login` is the only writer.
use std::io::{Read, Write};
use std::path::PathBuf;
fn token_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".config/orbit/token")
}
fn usage() -> ! {
    eprintln!("usage: orbit [--server URL] <login|jobs|approve|brief|search|tail> [args]");
    eprintln!("  login --server URL --token orb_...   save token (0600)");
    eprintln!("  jobs                                 list jobs");
    eprintln!("  approve --id UUID --decision allow|deny");
    eprintln!("  brief                                morning brief digest");
    eprintln!("  search --query TEXT                  global search");
    eprintln!("  tail --follow                        recent events");
    std::process::exit(2);
}
fn read_token() -> String {
    let path = token_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|_| { eprintln!("no token at {} — run `orbit login` first", path.display()); std::process::exit(1); });
    raw.trim().to_owned()
}
fn server_arg(args: &[String]) -> (String, Vec<String>) {
    let mut server = std::env::var("ORBIT_SERVER").unwrap_or_else(|_| "http://127.0.0.1:18080".into());
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--server" && i + 1 < args.len() { server = args[i + 1].clone(); i += 2; } else { rest.push(args[i].clone()); i += 1; }
    }
    (server, rest)
}
fn flag(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name && i + 1 < args.len() { return Some(args[i + 1].clone()); }
        i += 1;
    }
    None
}
fn get(server: &str, path: &str, token: &str) -> serde_json::Value {
    let url = format!("{server}{path}");
    let mut child = std::process::Command::new("curl").args(["-fsSL", "-m", "20", "-H", &format!("Authorization: Bearer {token}"), &url])
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).spawn().unwrap_or_else(|_| { eprintln!("curl missing — install curl to use the CLI"); std::process::exit(1); });
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    if !child.wait().map(|s| s.success()).unwrap_or(false) { std::process::exit(1); }
    serde_json::from_str(&out).unwrap_or(serde_json::Value::Null)
}
fn post(server: &str, path: &str, token: &str, body: &str) -> serde_json::Value {
    let url = format!("{server}{path}");
    let mut child = std::process::Command::new("curl").args(["-fsSL", "-m", "20", "-X", "POST", "-H", &format!("Authorization: Bearer {token}"), "-H", "Content-Type: application/json", "-d", body, &url])
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit()).spawn().unwrap_or_else(|_| { eprintln!("curl missing — install curl to use the CLI"); std::process::exit(1); });
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    if !child.wait().map(|s| s.success()).unwrap_or(false) { std::process::exit(1); }
    serde_json::from_str(&out).unwrap_or(serde_json::Value::Null)
}
fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() { usage(); }
    let (server, rest) = server_arg(&argv);
    if rest.is_empty() { usage(); }
    match rest[0].as_str() {
        "login" => {
            let token = flag(&rest, "--token").unwrap_or_else(|| { eprintln!("orbit login --token orb_... required"); std::process::exit(2); });
            if !token.starts_with("orb_") { eprintln!("token must start with orb_"); std::process::exit(2); }
            let path = token_path();
            if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).unwrap(); }
            std::fs::write(&path, format!("{token}\n")).unwrap();
            #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap(); }
            // Verify before claiming success.
            let v = get(&server, "/api/v1/tokens", &token);
            if v.is_null() { eprintln!("login failed — server rejected the token"); std::process::exit(1); }
            println!("saved token to {}", path.display());
        }
        "jobs" => {
            let v = get(&server, "/api/v1/tasks?limit=20", &read_token());
            print_items(&v, &["title", "state"]);
        }
        "approve" => {
            let id = flag(&rest, "--id").unwrap_or_else(|| { eprintln!("--id UUID required"); std::process::exit(2); });
            let decision = flag(&rest, "--decision").unwrap_or_else(|| { eprintln!("--decision allow|deny required"); std::process::exit(2); });
            if decision != "allow" && decision != "deny" { eprintln!("decision must be allow|deny"); std::process::exit(2); }
            let v = post(&server, &format!("/api/v1/approvals/{id}/decision"), &read_token(), &serde_json::json!({"decision": decision}).to_string());
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        "brief" => {
            let v = get(&server, "/api/v1/brief", &read_token());
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        "search" => {
            let q = flag(&rest, "--query").unwrap_or_else(|| { eprintln!("--query TEXT required"); std::process::exit(2); });
            let v = post(&server, "/api/v1/search", &read_token(), &serde_json::json!({"query": q, "limit": 5}).to_string());
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        "tail" => {
            let follow = rest.iter().any(|a| a == "--follow");
            loop {
                let v = get(&server, "/api/v1/activity?limit=10", &read_token());
                print_items(&v, &["kind", "created_at"]);
                if !follow { break; }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
        _ => usage(),
    }
}
fn print_items(v: &serde_json::Value, fields: &[&str]) {
    let items = v.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default();
    if items.is_empty() { println!("(empty)"); return; }
    for item in items {
        let line: Vec<String> = fields.iter().map(|f| format!("{f}={}", item.get(f).map(|x| x.to_string()).unwrap_or_else(|| "-".into()))).collect();
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{}", line.join(" "));
    }
}
