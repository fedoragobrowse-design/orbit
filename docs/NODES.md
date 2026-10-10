# Nodes
The lightweight daemon on your other machines (`apps/computer-node`, wire protocol `crates/computer-node-protocol`): one small binary, no Docker, no database. It calls out to your home over verified HTTPS (plain `http://` refused) and only your home can reach it back through that call. Nothing is shared by default — you pick folders with `roots add` (read-only unless `--mode WRITE`); anything outside those folders is refused before it is opened. Revoke on the Computers page and its access dies with the entry.
## Run it anywhere
- Linux/macOS, one line (needs a pairing code from your home's Computers page first): `./install-node.sh --version vX.Y.Z --server https://orbit.example --pair <code>` — pairs, then installs a systemd user unit (Linux) or launchd plist (macOS) running `serve`. Windows: `install-node.ps1` with the same flags (service via `sc.exe`, no auto-restart on crash — see `docs/INSTALL.md`).
- State is one file: `~/.local/share/orbit-node/node.json` (`ORBIT_NODE_STATE_DIR` overrides). Everyday commands: `orbit-computer-node status`, `roots add /path/to/share`, `roots list`, `roots revoke`.
- Requirements on the box: the one binary + network to your home's HTTPS origin. No Docker, no Postgres, no open ports (outbound-only). CPU-idle footprint is one waiting process.
- Docker instead? The home itself runs in compose (`compose.yaml`); the node never needs it.
## Per-platform state
| Platform | State | Install / run | Conformance evidence |
|---|---|---|---|
| Linux x86_64 + arm64 | Complete | `orbit-computer-node pair/serve/roots/service`; mutating roots need the installed service identity (`admin::assert_service_identity`) + prepared protected tree | `cargo test --locked -p orbit-computer-node-protocol -p orbit-computer-node` (protocol unit + `apps/computer-node/tests/conformance.rs`); privileged gate via `deploy/examples/compose.test.yaml --profile native-security` (`apps/computer-node/tests/native_admission.rs`, needs `ORBIT_NATIVE_SECURITY=1` as root) |
| macOS arm64 + x86_64 | CI-gated, not yet passing | Same CLI; non-Linux `admin` stubs return `Unsupported`, so only READ roots work; mutation reports `SECURE_MUTATION_UNAVAILABLE` | `.github/workflows/ci.yaml` `rust` leg (`macos-15` + `macos-15-intel`): protocol check+test on both; node check+test stays on the ubuntu legs until the native port lands (`native::metadata_only` / `mutate_journaled` / Unix control socket have no non-Linux definitions); no macOS node pass claimed until Actions runs |
| Windows x86_64 + arm64 | CI-gated, not yet passing | Same CLI; `mutation_available() == false` on ordinary trees until a Windows native gate is recorded — Linux results do not count | `.github/workflows/ci.yaml` `rust` leg (`windows-2025` + `windows-11-arm`): protocol check+test on both; node check+test stays on the ubuntu legs until the native port lands; no Windows node pass claimed until Actions runs |
| Android | Kotlin-app scope, UNAVAILABLE | No app checked in (`apps/` holds only computer-node, server, web) | `.github/workflows/ci.yaml` `android-apk`: informative UNAVAILABLE notice to `$GITHUB_STEP_SUMMARY` (Gradle wrapper + Kotlin app first; never a faked APK build, never a red gate) |
| iPhone | Companion-only, UNAVAILABLE as native | No Xcode target; PWA is the fast path until a native scope lands | `.github/workflows/ci.yaml` `ios-scope`: informative UNAVAILABLE notice to `$GITHUB_STEP_SUMMARY` (signed/IPA distribution needs Apple-team credentials CI must never fake) |
## Notes
- Wire enums stay `SCREAMING_SNAKE_CASE` (`MessageType`, `RootMode`); unknown wire operations are refused (`conformance.rs::wire_envelope_rejects_version_and_identity_mismatch`).
- Traversal/credential paths are refused before I/O (`normalize_path`/`denied_name`; `traversal_and_credential_paths_are_refused_before_io`).
- Default-deny: READ roots advertise no mutation ops; foreign-owner snapshots and stale scope revisions fail closed.
- No `SQLX_OFFLINE` in CI: the repo has no `.sqlx/` cache and uses only runtime `sqlx::query`/`migrate!` (no compile-time `query!` macros), so offline mode is not applicable.
- Linux leg proven locally; see the CI run for macOS/Windows results.

Roadmap: Android Kotlin node app (UNAVAILABLE — Kotlin app + emulator-tested APK; CI `android-apk` scope job only), iPhone companion app (UNAVAILABLE — Xcode + Apple Developer account; PWA is the fast path). See docs/PARITY.md roadmap.
