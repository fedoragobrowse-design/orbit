# Nodes
Per-platform state of the computer node (`apps/computer-node`, wire protocol `crates/computer-node-protocol`).
| Platform | State | Install / run | Conformance evidence |
|---|---|---|---|
| Linux x86_64 + arm64 | Complete | `orbit-computer-node pair/serve/roots/service`; mutating roots need the installed service identity (`admin::assert_service_identity`) + prepared protected tree | `cargo test --locked -p orbit-computer-node-protocol -p orbit-computer-node` (protocol unit + `apps/computer-node/tests/conformance.rs`); privileged gate via `deploy/examples/compose.test.yaml --profile native-security` (`apps/computer-node/tests/native_admission.rs`, needs `ORBIT_NATIVE_SECURITY=1` as root) |
| macOS arm64 + x86_64 | CI-gated, not yet passing | Same CLI; non-Linux `admin` stubs return `Unsupported`, so only READ roots work; mutation reports `SECURE_MUTATION_UNAVAILABLE` | `.github/workflows/ci.yaml` `rust` leg (`macos-15`, `macos-15-intel`): check+test per target; no macOS pass claimed until Actions runs |
| Windows x86_64 + arm64 | CI-gated, not yet passing | Same CLI; `mutation_available() == false` (`apps/computer-node/src/windows.rs:451`) until a Windows native gate is recorded — Linux results do not count | `.github/workflows/ci.yaml` `rust` leg (`windows-2025`, `windows-11-arm`): check+test per target; no Windows pass claimed until Actions runs |
| Android | Kotlin-app scope, UNAVAILABLE | No app checked in (`apps/` holds only computer-node, server, web) | `.github/workflows/ci.yaml` `android-apk`: honest UNAVAILABLE-until-prereqs gate (Gradle wrapper + Kotlin app first; never a faked APK build) |
| iPhone | Companion-only, UNAVAILABLE as native | No Xcode target; PWA is the fast path until a native scope lands | `.github/workflows/ci.yaml` `ios-scope`: UNAVAILABLE scope note (signed/IPA distribution needs Apple-team credentials CI must never fake) |
## Notes
- Wire enums stay `SCREAMING_SNAKE_CASE` (`MessageType`, `RootMode`); unknown wire operations are refused (`conformance.rs::wire_envelope_rejects_version_and_identity_mismatch`).
- Traversal/credential paths are refused before I/O (`normalize_path`/`denied_name`; `traversal_and_credential_paths_are_refused_before_io`).
- Default-deny: READ roots advertise no mutation ops; foreign-owner snapshots and stale scope revisions fail closed.
- No `SQLX_OFFLINE` in CI: the repo has no `.sqlx/` cache and uses only runtime `sqlx::query`/`migrate!` (no compile-time `query!` macros), so offline mode is not applicable.
- Linux leg proven locally; see the CI run for macOS/Windows results.
