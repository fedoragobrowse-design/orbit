#!/bin/sh
# Orbit computer-node one-command setup (Linux/macOS). POSIX sh.
#
# On the device that will run the node:
#   scripts/install-node.sh --version vX.Y.Z --server https://orbit.example
#
# With an owner API token (--token or ORBIT_API_TOKEN, minted in the app at
# Settings -> API tokens) this mints its own one-use pairing code
# (POST /api/v1/computers/pairing-codes), pairs over verified HTTPS,
# installs the service and prints status. With --pair <code> from the
# Computers page no token is needed and nothing is minted. Re-running is
# safe: an already paired node keeps its identity and only the service
# entry is refreshed. The token and code are never printed; the code is
# used once, then discarded.
set -eu
VERSION="${ORBIT_VERSION:-${GITHUB_REF_NAME:-${GITHUB_REF:-}}}"
REPO="${ORBIT_RELEASE_REPO:-fedoragobrowse-design/orbit}"
DRY_RUN=0; ASSUME_YES=0
SERVER=""; TOKEN="${ORBIT_API_TOKEN:-}"; CODE=""; CA_FILE=""; BIN=""
usage() { cat <<'USAGE'
Usage: install-node.sh --version vX.Y.Z --server https://orbit.example [--token orb_...] [--pair <code>] [--ca-file FILE] [--bin PATH] [--yes] [--dry-run]
  --version  pinned release tag (or GITHUB_REF / ORBIT_VERSION). Required.
  --server   https server origin for pairing. Required (https only).
  --token    owner API token (or ORBIT_API_TOKEN, Settings -> API tokens).
             Mints a one-use pairing code for you; asked hidden when a
             terminal is present. Prefer env/prompt: argv is visible to ps.
  --pair     one-use owner pairing code from the Computers page. When given,
             no token is needed and no code is minted.
  --ca-file  extra root CA for pairing (fixture/self-signed setups).
  --bin      orbit-computer-node binary (default: PATH, repo build, release).
  --yes      skip confirmation prompts.
  --dry-run  print planned actions, change nothing.
USAGE
}
log() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
confirm() { if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then return 0; fi; printf '%s [y/N] ' "$1"; read -r ans; [ "$ans" = "y" ] || [ "$ans" = "Y" ]; }
normalize_version() { case "$1" in refs/tags/*) printf '%s' "${1#refs/tags/}";; *) printf '%s' "$1";; esac; }
read_secret() {
  if [ ! -t 0 ] && [ ! -c /dev/tty ] 2>/dev/null; then return 1; fi
  printf '%s (input hidden, never logged): ' "$1" >&2
  if [ -c /dev/tty ] 2>/dev/null; then stty -echo </dev/tty 2>/dev/null || true; read -r "$2" </dev/tty || true; stty echo </dev/tty 2>/dev/null || true
  else stty -echo 2>/dev/null || true; read -r "$2" || true; stty echo 2>/dev/null || true; fi
  printf '\n' >&2
  eval "test -n \"\${$2:-}\"" || return 1
}
json_code() {
  if command -v python3 >/dev/null 2>&1; then python3 -c 'import json,sys; print(json.load(sys.stdin).get("code",""))'
  else sed -n 's/.*"code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1; fi
}
resolve_bin() {
  found="$(command -v orbit-computer-node || true)"
  if [ -n "$found" ]; then printf '%s' "$found"; return 0; fi
  if command -v cargo >/dev/null 2>&1 && [ -f apps/computer-node/Cargo.toml ]; then
    printf '%s\n' "building orbit-computer-node from source (locked)" >&2
    cargo build --locked -p orbit-computer-node >&2 || die "cargo build failed"
    [ -x target/release/orbit-computer-node ] || die "build produced no binary at target/release/orbit-computer-node"
    printf '%s' "target/release/orbit-computer-node"; return 0
  fi
  case "$OS" in Linux) FETCH_OS=linux;; Darwin) FETCH_OS=darwin;; *) die "unsupported OS: $OS";; esac
  case "$(uname -m)" in x86_64|amd64) FETCH_ARCH=amd64;; aarch64|arm64) FETCH_ARCH=arm64;; *) die "unsupported arch: $(uname -m)";; esac
  need curl
  ASSET="orbit-computer-node-${VERSION}-${FETCH_OS}-${FETCH_ARCH}"
  URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
  DEST="$STATE_DIR/bin/orbit-computer-node"
  printf '%s\n' "fetching ${URL}" >&2
  mkdir -p "$STATE_DIR/bin"; chmod 700 "$STATE_DIR"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$DEST" "$URL" || die "binary fetch failed (${URL})"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$DEST.sha256" "${URL}.sha256" || die "checksum file missing; refusing unverified binary"
  if command -v sha256sum >/dev/null 2>&1; then ( cd "$STATE_DIR/bin" && sha256sum -c "orbit-computer-node.sha256" ) || die "SHA-256 mismatch; refusing install"
  elif command -v shasum >/dev/null 2>&1; then ( cd "$STATE_DIR/bin" && shasum -a 256 -c "orbit-computer-node.sha256" ) || die "SHA-256 mismatch; refusing install"
  else die "missing sha256 tool (sha256sum or shasum)"; fi
  chmod 755 "$DEST"
  printf '%s' "$DEST"
}
mint_code() {
  need curl
  ENDPOINT="${SERVER}/api/v1/computers/pairing-codes"
  if [ -n "$CA_FILE" ]; then RESP="$(curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 30 --cacert "$CA_FILE" -X POST "$ENDPOINT" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json')" || die "pairing-code request failed (check --server, token and network)"
  else RESP="$(curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 30 -X POST "$ENDPOINT" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json')" || die "pairing-code request failed (check --server, token and network)"; fi
  NEW_CODE="$(printf '%s' "$RESP" | json_code)" || die "pairing-code response unreadable"
  [ -n "$NEW_CODE" ] || die "pairing-code request returned no code (is the token an owner token?)"
  printf '%s' "$NEW_CODE"
}
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2;;
    --version=*) VERSION="${1#--version=}"; shift;;
    --server) [ $# -ge 2 ] || die "--server needs a value"; SERVER="$2"; shift 2;;
    --server=*) SERVER="${1#--server=}"; shift;;
    --token) [ $# -ge 2 ] || die "--token needs a value"; TOKEN="$2"; shift 2;;
    --token=*) TOKEN="${1#--token=}"; shift;;
    --pair) [ $# -ge 2 ] || die "--pair needs a value"; CODE="$2"; shift 2;;
    --pair=*) CODE="${1#--pair=}"; shift;;
    --ca-file) [ $# -ge 2 ] || die "--ca-file needs a value"; CA_FILE="$2"; shift 2;;
    --ca-file=*) CA_FILE="${1#--ca-file=}"; shift;;
    --bin) [ $# -ge 2 ] || die "--bin needs a value"; BIN="$2"; shift 2;;
    --bin=*) BIN="${1#--bin=}"; shift;;
    --yes) ASSUME_YES=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --help|-h) usage; exit 0;;
    *) die "unknown flag: $1 (see --help)";;
  esac
done
VERSION="$(normalize_version "$VERSION")"
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "refusing unpinned install: pass --version vX.Y.Z (got '${VERSION:-empty}')";; esac
[ -n "$SERVER" ] || die "--server is required"
case "$SERVER" in https://*) ;; *) die "--server must be https:// (node pairs over verified HTTPS only)";; esac
SERVER="${SERVER%/}"
[ -n "$CODE" ] || [ -n "$TOKEN" ] || [ "$DRY_RUN" -eq 1 ] || [ -t 0 ] || [ -c /dev/tty ] 2>/dev/null || die "need --pair <code> (Computers page) or --token orb_... (Settings -> API tokens)"
STATE_DIR="${ORBIT_NODE_STATE_DIR:-$HOME/.local/share/orbit-node}"
CONFIG="$STATE_DIR/node.json"
OS="$(uname -s)"
case "$OS" in Linux|Darwin) ;; *) die "unsupported OS: $OS (Linux/macOS only; Windows uses install-node.ps1)";; esac
log "orbit node setup ${VERSION} (${OS})"
if [ -z "$BIN" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then BIN="<orbit-computer-node from release ${VERSION}>"
  else BIN="$(resolve_bin)"; fi
else [ -x "$BIN" ] || die "--bin not executable: $BIN"
fi
log "detect: bin=${BIN} state=${STATE_DIR}"
if [ "$DRY_RUN" -eq 1 ]; then
  if [ -n "$CODE" ]; then PAIR_PLAN="pair with the provided --pair code (never shown), then discard it";
  else PAIR_PLAN="mint one-use code via POST ${SERVER}/api/v1/computers/pairing-codes (never shown), pair, then discard it"; fi
  cat <<DRY
[dry-run] resolve orbit-computer-node binary (--bin, PATH, locked repo build, or verified release fetch)
[dry-run] mkdir -p ${STATE_DIR} (0700)
[dry-run] ${PAIR_PLAN}
[dry-run] install service: $([ "$OS" = "Darwin" ] && echo "launchd plist ~/Library/LaunchAgents/dev.orbit.node.plist" || echo "systemd user unit ~/.config/systemd/user/orbit-node.service")
[dry-run] enable + start service; '${BIN} --config ${CONFIG} status'
DRY
  exit 0
fi
confirm "Set up the Orbit node against $SERVER?" || exit 1
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
PAIRED=0
if [ -f "$CONFIG" ] && "$BIN" --config "$CONFIG" status >/dev/null 2>&1; then
  PAIRED=1; log "already paired; keeping this node's identity"
fi
if [ "$PAIRED" -eq 0 ]; then
  if [ -z "$CODE" ]; then
    if [ -z "$TOKEN" ]; then
      read_secret "Owner API token" TOKEN || die "need --pair <code> (Computers page) or --token orb_... (Settings -> API tokens)"
    fi
    log "minting one-use pairing code"
    CODE="$(mint_code)"
  else log "pairing with the provided code"; fi
  if [ -n "$CA_FILE" ]; then "$BIN" --config "$CONFIG" pair --server "$SERVER" --code "$CODE" --ca-file "$CA_FILE" --state "$CONFIG"
  else "$BIN" --config "$CONFIG" pair --server "$SERVER" --code "$CODE" --state "$CONFIG"; fi
  CODE=""; TOKEN=""
  log "paired; pairing code discarded"
fi
if [ "$OS" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/dev.orbit.node.plist"; mkdir -p "$(dirname "$PLIST")"
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.orbit.node</string>
<key>ProgramArguments</key><array><string>${BIN}</string><string>--config</string><string>${CONFIG}</string><string>serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>${STATE_DIR}/node.log</string>
<key>StandardErrorPath</key><string>${STATE_DIR}/node.log</string>
</dict></plist>
PLIST
  launchctl unload "$PLIST" 2>/dev/null || true; launchctl load "$PLIST"; log "launchd service loaded: $PLIST"
else
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; start manually: $BIN --config $CONFIG serve"
  UNIT="$HOME/.config/systemd/user/orbit-node.service"; mkdir -p "$(dirname "$UNIT")"
  cat > "$UNIT" <<UNIT
[Unit]
Description=Orbit computer node
After=network-online.target
[Service]
ExecStart=${BIN} --config ${CONFIG} serve
Restart=on-failure
[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload; systemctl --user enable --now orbit-node; log "systemd user unit enabled: $UNIT"
fi
CODE=""; TOKEN=""
"$BIN" --config "$CONFIG" status
if [ "$PAIRED" -eq 1 ]; then log "node service refreshed (identity unchanged)"; else log "node paired and service started"; fi
