#!/bin/sh
# Orbit installer: pinned tagged releases only. POSIX sh.
# Usage: ./install.sh --version vX.Y.Z [--yes] [--dry-run] [--upgrade] [--uninstall] [--with-keys] [--with-oauth LIST]
set -eu
VERSION="${ORBIT_VERSION:-${GITHUB_REF_NAME:-${GITHUB_REF:-}}}"
DRY_RUN=0; ASSUME_YES=0; UPGRADE=0; UNINSTALL=0; WITH_KEYS=0; WITH_OAUTH=""; STAGED=0; PROV_JSON=""; OAUTH_JSON=""; KEY_VAL=""; OAUTH_ID=""; OAUTH_SEC=""
REPO="${ORBIT_RELEASE_REPO:-fedoragobrowse-design/orbit}"
EMBED_MODEL="${ORBIT_EMBED_MODEL:-nomic-embed-text}"
READY_TIMEOUT="${ORBIT_READY_TIMEOUT:-180}"
COMPOSE_FILE="${ORBIT_COMPOSE_FILE:-compose.yaml}"
ENV_FILE="${ORBIT_ENV_FILE:-.env}"
CRED_IMPORT="${ORBIT_CREDENTIALS_IMPORT:-credentials.import}"
usage() { cat <<'USAGE'
Usage: install.sh --version vX.Y.Z [--yes] [--dry-run] [--upgrade] [--uninstall] [--with-keys] [--with-oauth google[,outlook][,github]]
  --version vX.Y.Z   pinned release tag (or set GITHUB_REF / ORBIT_VERSION). Required.
  --yes              skip confirmation prompts
  --dry-run          print planned actions, change nothing
  --upgrade          re-pull pinned images and restart (requires --version)
  --uninstall        stop containers, keep named volumes and .env (asks unless --yes)
  --with-keys        prompt for OpenAI/Anthropic/Gemini API keys (hidden input; staged 0600, never logged)
  --with-oauth LIST  prompt for OAuth client-id/secret for LIST (google, outlook, github; hidden, staged 0600)
  --help             this text
Env: ORBIT_RELEASE_REPO (default fedoragobrowse-design/orbit),
     ORBIT_EMBED_MODEL (default nomic-embed-text), ORBIT_READY_TIMEOUT (default 180s),
     ORBIT_COMPOSE_FILE, ORBIT_ENV_FILE, ORBIT_PUBLIC_ORIGIN,
     ORBIT_CREDENTIALS_IMPORT (default credentials.import).
USAGE
}
log() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
confirm() { if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then return 0; fi; if [ ! -t 0 ] && [ ! -c /dev/tty ] 2>/dev/null; then die "needs an answer but nothing to ask on (stdin is a pipe): rerun with --yes to accept, or run from a terminal"; fi; printf '%s [y/N] ' "$1"; read -r ans </dev/tty 2>/dev/null || read -r ans; [ "$ans" = "y" ] || [ "$ans" = "Y" ]; }
# shellcheck disable=SC2086
pm_install() { if command -v apt-get >/dev/null 2>&1; then SUDO=""; if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; $SUDO apt-get update && $SUDO apt-get install -y "$1" || die "package install failed for '$1'"; elif command -v dnf >/dev/null 2>&1; then SUDO=""; if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi; $SUDO dnf install -y "$2" || die "package install failed for '$2'"; elif command -v brew >/dev/null 2>&1; then brew install $3 || die "brew install failed for '$3'"; else die "no supported package manager (apt-get/dnf/brew); install manually and rerun"; fi; }
ensure_tool() { if command -v "$1" >/dev/null 2>&1; then return 0; fi; confirm "Missing '$1'. Install it via the system package manager?" || die "missing required command: $1 (apt: '$2'; dnf: '$3'; brew: '$4')"; pm_install "$2" "$3" "$4"; command -v "$1" >/dev/null 2>&1 || die "install of '$1' did not provide the command; install it manually and rerun"; }
ensure_sha256() { if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; then return 0; fi; confirm "Missing 'sha256sum (or shasum)'. Install it via the system package manager?" || die "missing required command: sha256sum (or shasum) (apt: 'coreutils'; dnf: 'coreutils'; brew: 'coreutils')"; pm_install coreutils coreutils coreutils; command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die "sha256 tool install did not provide the command; install it manually and rerun"; }
read_secret() { if [ ! -t 0 ] && [ ! -c /dev/tty ] 2>/dev/null; then log "notice: no terminal to read '$1'; skipping"; return 1; fi; printf '%s (input hidden, never logged): ' "$1" >&2; if [ -c /dev/tty ] 2>/dev/null; then stty -echo </dev/tty 2>/dev/null || true; read -r "$2" </dev/tty || true; stty echo </dev/tty 2>/dev/null || true; else stty -echo 2>/dev/null || true; read -r "$2" || true; stty echo 2>/dev/null || true; fi; printf '\n' >&2; eval "test -n \"\${$2:-}\"" || return 1; }
json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'; }
add_provider() { P_ESC="$(json_escape "$4")"; P_ENTRY="{\"name\":\"$1\",\"kind\":\"$2\",\"origin\":\"$3\",\"credential\":\"$P_ESC\"}"; if [ -z "$PROV_JSON" ]; then PROV_JSON="$P_ENTRY"; else PROV_JSON="${PROV_JSON},${P_ENTRY}"; fi; STAGED=1; log "staged provider credential: $1 (value hidden)"; }
add_oauth() { OI_ESC="$(json_escape "$2")"; OS_ESC="$(json_escape "$3")"; O_ENTRY="{\"connector\":\"$1\",\"client_id\":\"$OI_ESC\",\"client_secret\":\"$OS_ESC\"}"; if [ -z "$OAUTH_JSON" ]; then OAUTH_JSON="$O_ENTRY"; else OAUTH_JSON="${OAUTH_JSON},${O_ENTRY}"; fi; STAGED=1; log "staged oauth client: $1 (values hidden)"; }
# shellcheck disable=SC2086
validate_oauth() { if [ -z "$WITH_OAUTH" ]; then return 0; fi; OAUTH_WORDS="$(printf '%s' "$WITH_OAUTH" | tr '[:upper:]' '[:lower:]' | tr ' ,' ',,')"; OLD_IFS="$IFS"; IFS=','; for conn in $OAUTH_WORDS; do case "$conn" in "") continue;; google|outlook|github) ;; *) die "unknown --with-oauth connector: '$conn' (expected google, outlook and/or github)";; esac; done; IFS="$OLD_IFS"; }
collect_keys() { if [ "$WITH_KEYS" -eq 0 ]; then return 0; fi; for spec in "OpenAI:openai:OPENAI_COMPATIBLE:https://api.openai.com" "Anthropic:anthropic:ANTHROPIC:https://api.anthropic.com" "Gemini:gemini:GEMINI:https://generativelanguage.googleapis.com"; do DN="${spec%%:*}"; rest="${spec#*:}"; NM="${rest%%:*}"; rest="${rest#*:}"; KD="${rest%%:*}"; ORG="${rest#*:}"; confirm "Add ${DN} API key?" || continue; if read_secret "${DN} API key" KEY_VAL; then add_provider "$NM" "$KD" "$ORG" "$KEY_VAL"; else log "notice: skipped ${DN} key"; fi; KEY_VAL=""; done; }
# shellcheck disable=SC2086
collect_oauth() { if [ -z "$WITH_OAUTH" ]; then return 0; fi; OAUTH_WORDS="$(printf '%s' "$WITH_OAUTH" | tr '[:upper:]' '[:lower:]' | tr ' ,' ',,')"; OLD_IFS="$IFS"; IFS=','; for conn in $OAUTH_WORDS; do case "$conn" in "") continue;; google|outlook|github) ;; *) die "unknown --with-oauth connector: '$conn' (expected google, outlook and/or github)";; esac; if read_secret "${conn} OAuth client-id" OAUTH_ID && read_secret "${conn} OAuth client-secret" OAUTH_SEC; then add_oauth "$conn" "$OAUTH_ID" "$OAUTH_SEC"; else log "notice: skipped oauth connector ${conn}"; fi; OAUTH_ID=""; OAUTH_SEC=""; done; IFS="$OLD_IFS"; }
write_import() { if [ "$STAGED" -eq 0 ]; then return 0; fi; umask 077; printf '{"provider_credentials": [%s], "oauth_clients": [%s]}\n' "$PROV_JSON" "$OAUTH_JSON" > "$CRED_IMPORT"; chmod 600 "$CRED_IMPORT"; log "wrote ${CRED_IMPORT} (0600, values hidden); import it post-setup, then delete it"; }
print_import_help() { if [ "$STAGED" -eq 0 ]; then return 0; fi; cat <<HELP
post-install credential import (values stay in ${CRED_IMPORT}; commands below carry names only):
  # after owner setup + login, import each staged entry (credential write-only), then delete ${CRED_IMPORT}:
  curl -sS -X POST http://127.0.0.1:8080/api/v1/providers -H 'Content-Type: application/json' --data '{"name":"<staged-name>","kind":"<OPENAI_COMPATIBLE|ANTHROPIC|GEMINI>","origin":"<staged-origin>","credential":"<value-from-import>"}'
  # oauth clients take client-id/client-secret per connector (google, outlook, github); e.g.:
  curl -sS -X PUT http://127.0.0.1:8080/api/v1/oauth/clients/<google|outlook|github> -H 'Content-Type: application/json' --data '{"client_id":"<id>","client_secret":"<secret>"}'
  # the app shows oauth connectors as "configured, pending verification" until verified; never fake green.
  rm "${CRED_IMPORT}"
HELP
}
maybe_install_ollama() { if command -v ollama >/dev/null 2>&1; then return 0; fi; confirm "Install Ollama for local models?" || { log "notice: skipping Ollama install; memory embeddings stay unavailable until you install ollama and run 'ollama pull $EMBED_MODEL'"; return 0; }; case "$OS_ID" in linux) curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 https://ollama.com/install.sh | sh || die "ollama install script failed";; darwin) command -v brew >/dev/null 2>&1 || die "brew is required to install ollama on macOS; install brew (https://brew.sh) or ollama (https://ollama.com) manually"; brew install ollama || die "brew install ollama failed";; esac; }
normalize_version() {
  case "$1" in refs/tags/*) printf '%s' "${1#refs/tags/}";; *) printf '%s' "$1";;
  esac
}
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2;;
    --version=*) VERSION="${1#--version=}"; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --yes) ASSUME_YES=1; shift;;
    --upgrade) UPGRADE=1; shift;;
    --uninstall) UNINSTALL=1; shift;;
    --with-keys) WITH_KEYS=1; shift;;
    --with-oauth) [ $# -ge 2 ] || die "--with-oauth needs a value (google, outlook and/or github)"; WITH_OAUTH="$2"; shift 2;;
    --with-oauth=*) WITH_OAUTH="${1#--with-oauth=}"; shift;;
    --help|-h) usage; exit 0;;
    *) die "unknown flag: $1 (see --help)";;
  esac
done
VERSION="$(normalize_version "$VERSION")"
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "refusing unpinned install: pass --version vX.Y.Z (got '${VERSION:-empty}'). GITHUB_REF / ORBIT_VERSION accepted when they name a tag.";; esac
validate_oauth
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in Linux) OS_ID=linux;; Darwin) OS_ID=darwin;; *) die "unsupported OS: $OS";; esac
case "$ARCH" in x86_64|amd64) ARCH_ID=amd64;; aarch64|arm64) ARCH_ID=arm64;; *) die "unsupported arch: $ARCH";; esac
TARBALL="orbit-${VERSION}-${OS_ID}-${ARCH_ID}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
log "orbit installer ${VERSION} (${OS_ID}/${ARCH_ID})"
log "repo: ${REPO}"
if [ "$UNINSTALL" -eq 1 ]; then
  log "plan: stop compose project (volumes, ${ENV_FILE} and ${CRED_IMPORT} kept)"
  if [ "$DRY_RUN" -eq 1 ]; then log "[dry-run] docker compose down (volumes kept)"; exit 0; fi
  confirm "Stop Orbit containers?" || exit 1
  need docker; docker compose down; log "uninstalled (volumes kept; 'docker volume rm' to purge)"; exit 0
fi
log "detect: os=${OS_ID} arch=${ARCH_ID} docker=$(command -v docker >/dev/null && echo yes || echo no) ollama=$(command -v ollama >/dev/null && echo yes || echo no)"
if [ "$DRY_RUN" -eq 1 ]; then
  cat <<DRY
[dry-run] check prereqs (docker/curl/openssl/sha256sum); offer auto-install via apt-get/dnf/brew on confirm, else fail-closed manual command
[dry-run] fetch ${BASE_URL}/${TARBALL} + ${TARBALL}.sha256 + ${TARBALL}.minisig
[dry-run] verify SHA-256 (fail closed if checksum file missing or mismatch)
[dry-run] verify minisign/cosign signature with key deploy/keys/release.pub (fail closed if key or tool missing)
[dry-run] extract pinned server/web images or build from pinned tag ${VERSION}
[dry-run] generate ${ENV_FILE} (0600, ORBIT_DB_PASSWORD + ORBIT_APP_DB_PASSWORD via openssl rand, never echoed)
[dry-run] docker compose -f ${COMPOSE_FILE} up -d --build
[dry-run] offer optional Ollama install on confirm (https://ollama.com/install.sh on linux, brew on darwin); pull embedding model '${EMBED_MODEL}' via 'ollama pull', skip offline with notice
[dry-run] wait up to ${READY_TIMEOUT}s for http://127.0.0.1:8080/ready, then print URL + bootstrap-token steps
DRY
  if [ "$WITH_KEYS" -eq 1 ]; then log "[dry-run] prompt for OpenAI/Anthropic/Gemini API keys (hidden input); stage names only to ${CRED_IMPORT} (0600, values never shown)"; fi
  if [ -n "$WITH_OAUTH" ]; then log "[dry-run] prompt for OAuth client-id/secret for '${WITH_OAUTH}' (hidden input); stage to ${CRED_IMPORT} (0600); app shows 'configured, pending verification'"; fi
  if [ "$WITH_KEYS" -eq 1 ] || [ -n "$WITH_OAUTH" ]; then log "[dry-run] print redacted curl import templates; owner imports post-setup then deletes ${CRED_IMPORT}"; fi
  exit 0
fi
ensure_tool docker docker.io docker "--cask docker"; ensure_tool curl curl curl curl; ensure_tool openssl openssl openssl openssl; ensure_sha256
docker info >/dev/null 2>&1 || { if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then log "docker needs elevation; re-run with a docker-capable user or sudo"; fi; die "docker daemon unreachable (docker info failed)"; }
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT INT TERM
log "fetching ${BASE_URL}/${TARBALL}"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$TMPD/pkg.tar.gz" "${BASE_URL}/${TARBALL}" || die "release tarball fetch failed"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$TMPD/pkg.tar.gz.sha256" "${BASE_URL}/${TARBALL}.sha256" || die "checksum file missing; refusing unverified install"
( cd "$TMPD" && { sha256sum -c pkg.tar.gz.sha256 2>/dev/null || shasum -a 256 -c pkg.tar.gz.sha256; } ) || die "SHA-256 mismatch; refusing install"
SIG_OK=0
if curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$TMPD/pkg.tar.gz.minisig" "${BASE_URL}/${TARBALL}.minisig" 2>/dev/null; then
  if [ -f deploy/keys/release.pub ] && command -v minisign >/dev/null 2>&1; then
    minisign -Vm "$TMPD/pkg.tar.gz" -p deploy/keys/release.pub -x "$TMPD/pkg.tar.gz.minisig" || die "minisign signature invalid; refusing install"; SIG_OK=1
  elif command -v cosign >/dev/null 2>&1 && [ -f deploy/keys/cosign.pub ]; then
    cosign verify-blob --key deploy/keys/cosign.pub --signature "$TMPD/pkg.tar.gz.minisig" "$TMPD/pkg.tar.gz" || die "cosign signature invalid; refusing install"; SIG_OK=1
  fi
elif curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$TMPD/pkg.tar.gz.sig" "${BASE_URL}/${TARBALL}.sig" 2>/dev/null; then
  if command -v cosign >/dev/null 2>&1 && [ -f deploy/keys/cosign.pub ]; then
    cosign verify-blob --key deploy/keys/cosign.pub --signature "$TMPD/pkg.tar.gz.sig" "$TMPD/pkg.tar.gz" || die "cosign signature invalid; refusing install"; SIG_OK=1
  fi
fi
[ "$SIG_OK" -eq 1 ] || die "signature check failed closed: release signature key (deploy/keys/release.pub or deploy/keys/cosign.pub) and a verifier (minisign/cosign) are required"
if [ -f "$ENV_FILE" ] && [ "$UPGRADE" -eq 0 ]; then log "keeping existing ${ENV_FILE} (idempotent; --upgrade to refresh images)"; else
  need openssl
  if [ ! -f "$ENV_FILE" ] || confirm "Overwrite ${ENV_FILE} with fresh secrets?"; then
    umask 077; DB_PW="$(openssl rand -hex 32)"; APP_PW="$(openssl rand -hex 32)"
    { printf 'ORBIT_DB_PASSWORD=%s\n' "$DB_PW"; printf 'ORBIT_APP_DB_PASSWORD=%s\n' "$APP_PW"; printf 'ORBIT_PUBLIC_ORIGIN=%s\n' "${ORBIT_PUBLIC_ORIGIN:-http://127.0.0.1:8080}"; } > "$ENV_FILE"; chmod 600 "$ENV_FILE"
    log "wrote ${ENV_FILE} (0600); values not shown"
  fi
fi
collect_keys; collect_oauth; write_import
if [ "$UPGRADE" -eq 1 ]; then docker compose -f "$COMPOSE_FILE" pull || die "compose pull failed"; fi
# shellcheck disable=SC2086
docker compose -f "$COMPOSE_FILE" up -d --build || die "compose up failed"
maybe_install_ollama
if command -v ollama >/dev/null 2>&1; then
  if ollama list >/dev/null 2>&1; then
    if ollama list 2>/dev/null | grep -q "$EMBED_MODEL"; then log "embedding model present: $EMBED_MODEL"; else
      log "pulling embedding model: $EMBED_MODEL"; ollama pull "$EMBED_MODEL" || log "notice: 'ollama pull $EMBED_MODEL' failed (offline?); run it manually later"
    fi
  else log "notice: 'ollama list' unavailable; skipping embedding-model check (install $EMBED_MODEL manually)"; fi
else log "notice: ollama not installed; memory embeddings stay unavailable until you install ollama and run 'ollama pull $EMBED_MODEL'"; fi
i=0; until curl --fail --silent http://127.0.0.1:8080/ready >/dev/null 2>&1; do i=$((i+5)); [ "$i" -ge "$READY_TIMEOUT" ] && die "timeout waiting for /ready after ${READY_TIMEOUT}s (see 'docker compose ps' / 'docker compose logs server')"; sleep 5; done
log "ready: http://127.0.0.1:8080 (API via /api/*, /health, /ready)"
log "bootstrap: docker compose exec server orbit-server bootstrap-token, then create the owner account in the web UI"
print_import_help
