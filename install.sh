#!/bin/sh
# Orbit installer: pinned tagged releases only. POSIX sh.
# Usage: ./install.sh --version v0.1.0 [--yes] [--dry-run] [--upgrade] [--uninstall]
set -eu
VERSION="${ORBIT_VERSION:-${GITHUB_REF_NAME:-${GITHUB_REF:-}}}"
DRY_RUN=0; ASSUME_YES=0; UPGRADE=0; UNINSTALL=0
REPO="${ORBIT_RELEASE_REPO:-fedoragobrowse-design/orbit}"
EMBED_MODEL="${ORBIT_EMBED_MODEL:-nomic-embed-text}"
READY_TIMEOUT="${ORBIT_READY_TIMEOUT:-180}"
COMPOSE_FILE="${ORBIT_COMPOSE_FILE:-compose.yaml}"
ENV_FILE="${ORBIT_ENV_FILE:-.env}"
usage() { cat <<'USAGE'
Usage: install.sh --version vX.Y.Z [--yes] [--dry-run] [--upgrade] [--uninstall]
  --version vX.Y.Z   pinned release tag (or set GITHUB_REF / ORBIT_VERSION). Required.
  --yes              skip confirmation prompts
  --dry-run          print planned actions, change nothing
  --upgrade          re-pull pinned images and restart (requires --version)
  --uninstall        stop containers, keep named volumes and .env (asks unless --yes)
  --help             this text
Env: ORBIT_RELEASE_REPO (default fedoragobrowse-design/orbit),
     ORBIT_EMBED_MODEL (default nomic-embed-text), ORBIT_READY_TIMEOUT (default 180s),
     ORBIT_COMPOSE_FILE, ORBIT_ENV_FILE, ORBIT_PUBLIC_ORIGIN.
USAGE
}
log() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
confirm() { if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then return 0; fi; printf '%s [y/N] ' "$1"; read -r ans; [ "$ans" = "y" ] || [ "$ans" = "Y" ]; }
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
    --help|-h) usage; exit 0;;
    *) die "unknown flag: $1 (see --help)";;
  esac
done
VERSION="$(normalize_version "$VERSION")"
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "refusing unpinned install: pass --version vX.Y.Z (got '${VERSION:-empty}'). GITHUB_REF / ORBIT_VERSION accepted when they name a tag.";; esac
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in Linux) OS_ID=linux;; Darwin) OS_ID=darwin;; *) die "unsupported OS: $OS";; esac
case "$ARCH" in x86_64|amd64) ARCH_ID=amd64;; aarch64|arm64) ARCH_ID=arm64;; *) die "unsupported arch: $ARCH";; esac
TARBALL="orbit-${VERSION}-${OS_ID}-${ARCH_ID}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
log "orbit installer ${VERSION} (${OS_ID}/${ARCH_ID})"
log "repo: ${REPO}"
if [ "$UNINSTALL" -eq 1 ]; then
  log "plan: stop compose project (volumes and ${ENV_FILE} kept)"
  if [ "$DRY_RUN" -eq 1 ]; then log "[dry-run] docker compose down (volumes kept)"; exit 0; fi
  confirm "Stop Orbit containers?" || exit 1
  need docker; docker compose down; log "uninstalled (volumes kept; 'docker volume rm' to purge)"; exit 0
fi
log "detect: os=${OS_ID} arch=${ARCH_ID} docker=$(command -v docker >/dev/null && echo yes || echo no) ollama=$(command -v ollama >/dev/null && echo yes || echo no)"
if [ "$DRY_RUN" -eq 1 ]; then
  cat <<DRY
[dry-run] fetch ${BASE_URL}/${TARBALL} + ${TARBALL}.sha256 + ${TARBALL}.minisig
[dry-run] verify SHA-256 (fail closed if checksum file missing or mismatch)
[dry-run] verify minisign/cosign signature with key deploy/keys/release.pub (fail closed if key or tool missing)
[dry-run] extract pinned server/web images or build from pinned tag ${VERSION}
[dry-run] generate ${ENV_FILE} (0600, ORBIT_DB_PASSWORD + ORBIT_APP_DB_PASSWORD via openssl rand, never echoed)
[dry-run] docker compose -f ${COMPOSE_FILE} up -d --build
[dry-run] pull embedding model '${EMBED_MODEL}' via 'ollama pull' if ollama present; skip offline with notice
[dry-run] wait up to ${READY_TIMEOUT}s for http://127.0.0.1:8080/ready, then print URL + bootstrap-token steps
DRY
  exit 0
fi
need docker; need curl; command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die "missing required command: sha256sum (or shasum)"
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
if [ "$UPGRADE" -eq 1 ]; then docker compose -f "$COMPOSE_FILE" pull || die "compose pull failed"; fi
# shellcheck disable=SC2086
docker compose -f "$COMPOSE_FILE" up -d --build || die "compose up failed"
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
