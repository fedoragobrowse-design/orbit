# Install Orbit

One-command install from pinned tagged releases. Scripts refuse to run
unpinned: pass `--version vX.Y.Z` (or set `GITHUB_REF` / `ORBIT_VERSION`
to a tag). No `latest`, no branch installs.

Status: BUILT — `install.sh` + node installers with signed dry-run transcripts (`docs/INSTALL.md:92-230`); no tagged release exists yet so step 2+ is unexecuted by design. See docs/PARITY.md.

## Quick start (server)

```sh
./install.sh --version vX.Y.Z
```

What it does, in order:

1. Detects OS/arch (`linux`/`darwin` x `amd64`/`arm64`); checks
   docker/curl/openssl/sha256-tool and, for each missing one, asks via the
   existing pipe-safe `confirm()` (skipped under `--yes`/`--dry-run`) then
   auto-installs with apt-get/dnf/brew — unknown package manager fails
   closed with the manual command. Honors `--dry-run` (changes nothing).
2. Fetches `orbit-<version>-<os>-<arch>.tar.gz` plus `.sha256` and
   `.minisig`/`.sig` from `https://github.com/<repo>/releases/download/`.
3. Verifies SHA-256 (fail closed if the checksum file is missing or
   mismatches), then verifies the minisign/cosign signature and fails
   closed when the key or verifier is missing.
4. Generates `.env` (`0600`) with `ORBIT_DB_PASSWORD` and
   `ORBIT_APP_DB_PASSWORD` via `openssl rand` (never echoed). `.env` holds
   only DB passwords + ORIGIN — provider credentials never go there.
5. Runs `docker compose up -d --build`; if `ollama` is missing asks
   `Install Ollama for local models?` (existing `confirm()`; Linux via
   `https://ollama.com/install.sh`, macOS via brew, only on yes), then
   pulls the embedding-capable Ollama model and waits for `/ready`, prints
   the URL + bootstrap step.

Signature keys (checked in, public parts only):

- minisign: `deploy/keys/release.pub`
- cosign: `deploy/keys/cosign.pub`

Neither key file exists yet; until the release process publishes them the
installer fails closed at step 3 by design. Do not work around this with
an unverified tarball.

Secrets: generated locally with mode `0600`, never printed. Do not commit
`.env` or `credentials.import`.

Optional API keys + OAuth (`--with-keys`, `--with-oauth`): prompted with
hidden input (`stty -echo`; values never echoed or logged, only names),
staged to one-shot `${ORBIT_CREDENTIALS_IMPORT:-credentials.import}`
(`0600`, `.env`-adjacent, gitignored) — never to `.env`. Chosen design:
installer stages the file and prints redacted `curl` import templates; the
owner imports post-setup (credential write-only via the Models API) then
deletes the file. No server auto-consume in this slice. Import JSON shape:
`{"provider_credentials": [{"name","kind","origin","credential"}], "oauth_clients": [{"connector","client_id","client_secret"}]}`
(`credential` matches `ProviderCreate.credential`;
`PUT /oauth/clients/{connector}` takes `{"client_id","client_secret"}`).
OAuth (google/outlook/github) stays UNAVAILABLE-awaiting-credentials until
verified; the app shows "configured, pending verification" — never fake
green.

Package installs: the installer never calls bare sudo; apt-get/dnf package installs use sudo only when not root and sudo exists (same elevation rule as the docker notice). Everything else runs as the invoking user.

```sh
./install.sh --version vX.Y.Z --dry-run    # print plan, change nothing
./install.sh --version vX.Y.Z --yes        # skip confirmations
./install.sh --version vX.Y.Z --upgrade    # re-pull pinned images, restart
./install.sh --version vX.Y.Z --uninstall  # stop containers (volumes + .env kept)
./install.sh --version vX.Y.Z --with-keys  # also prompt for OpenAI/Anthropic/Gemini keys (hidden, staged 0600)
./install.sh --version vX.Y.Z --with-oauth google,github  # also prompt for OAuth client-id/secret per connector
```

Idempotent: re-running with the same `--version` keeps the existing `.env`
and restarts the stack; `--upgrade` refreshes images.

## Computer node (Linux/macOS)

```sh
./install-node.sh --version vX.Y.Z --server https://orbit.example --pair <code>
```

Pairs over verified HTTPS only (`--server` must be `https://`), writes
`~/.local/share/orbit-node/node.json` (`0700`), then installs:

- Linux: systemd user unit `~/.config/systemd/user/orbit-node.service`
  (`systemctl --user enable --now orbit-node`).
- macOS: launchd plist `~/Library/LaunchAgents/dev.orbit.node.plist`.

Prints `status` at the end. `--ca-file` supplies an extra root CA for
self-signed/fixture setups. The pairing code is never logged.

## Computer node (Windows)

```powershell
.\install-node.ps1 -Version vX.Y.Z -Server https://orbit.example -PairCode <code>
```

Registers the `orbit-node` service via `sc.exe` and starts it, then prints
status. `sc.exe` services do not auto-restart on crash; for
restart-on-failure install [nssm](https://nssm.cc/) and run:

```powershell
nssm install orbit-node "C:\path\to\orbit-computer-node.exe" --config "$env:LOCALAPPDATA\Orbit\Node\node.json" serve
```

`-DryRun` prints the plan. `-CaFile` supplies an extra root CA.

## Verification transcripts

Method: `docker run --rm -v "$PWD/install.sh:/t/install.sh:ro" <image>
sh /t/install.sh --version v9.9.9-test --dry-run` (placeholder version;
`--dry-run` changes nothing). Unpinned runs use the same command without
`--version`. Full runs were not possible: no Docker daemon inside these
containers and no tagged release exists yet, so step 2+ cannot execute
here.

### ubuntu:24.04 --dry-run (exit 0)

Command:

```sh
docker run --rm -v "$PWD/install.sh:/t/install.sh:ro" ubuntu:24.04 sh /t/install.sh --version v9.9.9-test --dry-run
```

Output:

```text
orbit installer v9.9.9-test (linux/amd64)
repo: fedoragobrowse-design/orbit
detect: os=linux arch=amd64 docker=no ollama=no
[dry-run] fetch https://github.com/fedoragobrowse-design/orbit/releases/download/v9.9.9-test/orbit-v9.9.9-test-linux-amd64.tar.gz + orbit-v9.9.9-test-linux-amd64.tar.gz.sha256 + orbit-v9.9.9-test-linux-amd64.tar.gz.minisig
[dry-run] verify SHA-256 (fail closed if checksum file missing or mismatch)
[dry-run] verify minisign/cosign signature with key deploy/keys/release.pub (fail closed if key or tool missing)
[dry-run] extract pinned server/web images or build from pinned tag v9.9.9-test
[dry-run] generate .env (0600, ORBIT_DB_PASSWORD + ORBIT_APP_DB_PASSWORD via openssl rand, never echoed)
[dry-run] docker compose -f compose.yaml up -d --build
[dry-run] pull embedding model 'nomic-embed-text' via 'ollama pull' if ollama present; skip offline with notice
[dry-run] wait up to 180s for http://127.0.0.1:8080/ready, then print URL + bootstrap-token steps
```

### debian:12 --dry-run (exit 0)

Command:

```sh
docker run --rm -v "$PWD/install.sh:/t/install.sh:ro" debian:12 sh /t/install.sh --version v9.9.9-test --dry-run
```

Output:

```text
orbit installer v9.9.9-test (linux/amd64)
repo: fedoragobrowse-design/orbit
detect: os=linux arch=amd64 docker=no ollama=no
[dry-run] fetch https://github.com/fedoragobrowse-design/orbit/releases/download/v9.9.9-test/orbit-v9.9.9-test-linux-amd64.tar.gz + orbit-v9.9.9-test-linux-amd64.tar.gz.sha256 + orbit-v9.9.9-test-linux-amd64.tar.gz.minisig
[dry-run] verify SHA-256 (fail closed if checksum file missing or mismatch)
[dry-run] verify minisign/cosign signature with key deploy/keys/release.pub (fail closed if key or tool missing)
[dry-run] extract pinned server/web images or build from pinned tag v9.9.9-test
[dry-run] generate .env (0600, ORBIT_DB_PASSWORD + ORBIT_APP_DB_PASSWORD via openssl rand, never echoed)
[dry-run] docker compose -f compose.yaml up -d --build
[dry-run] pull embedding model 'nomic-embed-text' via 'ollama pull' if ollama present; skip offline with notice
[dry-run] wait up to 180s for http://127.0.0.1:8080/ready, then print URL + bootstrap-token steps
```

### fedora:41 --dry-run (exit 0)

Command:

```sh
docker run --rm -v "$PWD/install.sh:/t/install.sh:ro" fedora:41 sh /t/install.sh --version v9.9.9-test --dry-run
```

Output:

```text
orbit installer v9.9.9-test (linux/amd64)
repo: fedoragobrowse-design/orbit
detect: os=linux arch=amd64 docker=no ollama=no
[dry-run] fetch https://github.com/fedoragobrowse-design/orbit/releases/download/v9.9.9-test/orbit-v9.9.9-test-linux-amd64.tar.gz + orbit-v9.9.9-test-linux-amd64.tar.gz.sha256 + orbit-v9.9.9-test-linux-amd64.tar.gz.minisig
[dry-run] verify SHA-256 (fail closed if checksum file missing or mismatch)
[dry-run] verify minisign/cosign signature with key deploy/keys/release.pub (fail closed if key or tool missing)
[dry-run] extract pinned server/web images or build from pinned tag v9.9.9-test
[dry-run] generate .env (0600, ORBIT_DB_PASSWORD + ORBIT_APP_DB_PASSWORD via openssl rand, never echoed)
[dry-run] docker compose -f compose.yaml up -d --build
[dry-run] pull embedding model 'nomic-embed-text' via 'ollama pull' if ollama present; skip offline with notice
[dry-run] wait up to 180s for http://127.0.0.1:8080/ready, then print URL + bootstrap-token steps
```

### alpine:3.22 --dry-run (exit 0)

Command:

```sh
docker run --rm -v "$PWD/install.sh:/t/install.sh:ro" alpine:3.22 sh /t/install.sh --version v9.9.9-test --dry-run
```

Output:

```text
orbit installer v9.9.9-test (linux/amd64)
repo: fedoragobrowse-design/orbit
detect: os=linux arch=amd64 docker=no ollama=no
[dry-run] fetch https://github.com/fedoragobrowse-design/orbit/releases/download/v9.9.9-test/orbit-v9.9.9-test-linux-amd64.tar.gz + orbit-v9.9.9-test-linux-amd64.tar.gz.sha256 + orbit-v9.9.9-test-linux-amd64.tar.gz.minisig
[dry-run] verify SHA-256 (fail closed if checksum file missing or mismatch)
[dry-run] verify minisign/cosign signature with key deploy/keys/release.pub (fail closed if key or tool missing)
[dry-run] extract pinned server/web images or build from pinned tag v9.9.9-test
[dry-run] generate .env (0600, ORBIT_DB_PASSWORD + ORBIT_APP_DB_PASSWORD via openssl rand, never echoed)
[dry-run] docker compose -f compose.yaml up -d --build
[dry-run] pull embedding model 'nomic-embed-text' via 'ollama pull' if ollama present; skip offline with notice
[dry-run] wait up to 180s for http://127.0.0.1:8080/ready, then print URL + bootstrap-token steps
```

### Unpinned refusal, all four distros (exit 1)

Command (per distro, e.g. `ubuntu:24.04`):

```sh
docker run --rm -v "$PWD/install.sh:/t/install.sh:ro" ubuntu:24.04 sh /t/install.sh --dry-run
```

Output (identical on `ubuntu:24.04`, `debian:12`, `fedora:41`, `alpine:3.22`):

```text
error: refusing unpinned install: pass --version vX.Y.Z (got 'empty'). GITHUB_REF / ORBIT_VERSION accepted when they name a tag.
```

### install-node.sh --dry-run (exit 0, all four distros)

Command (per distro):

```sh
docker run --rm -v "$PWD/install-node.sh:/t/install-node.sh:ro" ubuntu:24.04 sh /t/install-node.sh --version v9.9.9-test --server https://orbit.example --dry-run
```

Output (state path is `/root/...` because containers run as root):

```text
orbit node installer v9.9.9-test (Linux)
detect: os=Linux bin=<orbit-computer-node from release v9.9.9-test> state=/root/.local/share/orbit-node
[dry-run] mkdir -p /root/.local/share/orbit-node (0700)
[dry-run] <orbit-computer-node from release v9.9.9-test> --config /root/.local/share/orbit-node/node.json pair --server https://orbit.example --state /root/.local/share/orbit-node/node.json --code '<redacted>'
[dry-run] install service: systemd user unit ~/.config/systemd/user/orbit-node.service
[dry-run] enable + start service; '<orbit-computer-node from release v9.9.9-test> --config /root/.local/share/orbit-node/node.json status'
```

No secrets appear in any transcript (pairing code redacted, passwords
never echoed).
