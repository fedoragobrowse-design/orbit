#!/bin/sh
# Orbit computer-node installer (Linux/macOS). POSIX sh.
# Registers a systemd user unit (Linux) or launchd plist (macOS) running `serve`.
set -eu
VERSION="${ORBIT_VERSION:-${GITHUB_REF_NAME:-${GITHUB_REF:-}}}"
DRY_RUN=0; ASSUME_YES=0
SERVER=""; CODE=""; CA_FILE=""; BIN=""
usage() { cat <<'USAGE'
Usage: install-node.sh --version vX.Y.Z --server https://orbit.example --pair <code> [--ca-file FILE] [--bin PATH] [--yes] [--dry-run]
  --version  pinned release tag (or GITHUB_REF / ORBIT_VERSION). Required.
  --server   https server origin for pairing. Required (https only).
  --pair     one-use owner pairing code. Required.
  --ca-file  extra root CA for pairing (fixture/self-signed setups).
  --bin      orbit-computer-node binary (default: PATH lookup).
  --yes      skip confirmation prompts.
  --dry-run  print planned actions, change nothing.
USAGE
}
log() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
confirm() { if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then return 0; fi; printf '%s [y/N] ' "$1"; read -r ans; [ "$ans" = "y" ] || [ "$ans" = "Y" ]; }
normalize_version() { case "$1" in refs/tags/*) printf '%s' "${1#refs/tags/}";; *) printf '%s' "$1";; esac; }
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;; --version=*) VERSION="${1#--version=}"; shift;;
    --server) SERVER="$2"; shift 2;; --server=*) SERVER="${1#--server=}"; shift;;
    --pair) CODE="$2"; shift 2;; --pair=*) CODE="${1#--pair=}"; shift;;
    --ca-file) CA_FILE="$2"; shift 2;; --ca-file=*) CA_FILE="${1#--ca-file=}"; shift;;
    --bin) BIN="$2"; shift 2;; --bin=*) BIN="${1#--bin=}"; shift;;
    --yes) ASSUME_YES=1; shift;; --dry-run) DRY_RUN=1; shift;;
    --help|-h) usage; exit 0;; *) die "unknown flag: $1 (see --help)";;
  esac
done
VERSION="$(normalize_version "$VERSION")"
case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "refusing unpinned install: pass --version vX.Y.Z (got '${VERSION:-empty}')";; esac
[ -n "$SERVER" ] || die "--server is required"
[ -n "$CODE" ] || [ "$DRY_RUN" -eq 1 ] || die "--pair <code> is required"
case "$SERVER" in https://*) ;; *) die "--server must be https:// (node pairs over verified HTTPS only)";; esac
STATE_DIR="${ORBIT_NODE_STATE_DIR:-$HOME/.local/share/orbit-node}"
OS="$(uname -s)"
if [ -z "$BIN" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then BIN="<orbit-computer-node from release ${VERSION}>"
  else BIN="$(command -v orbit-computer-node || true)"; fi
fi
[ -n "$BIN" ] || die "orbit-computer-node not found (pass --bin PATH from release ${VERSION})"
log "orbit node installer ${VERSION} (${OS})"
log "detect: os=${OS} bin=${BIN} state=${STATE_DIR}"
PAIR_CMD="$BIN --config $STATE_DIR/node.json pair --server $SERVER --state $STATE_DIR/node.json"
[ -n "$CA_FILE" ] && PAIR_CMD="$PAIR_CMD --ca-file $CA_FILE"
if [ "$DRY_RUN" -eq 1 ]; then
  cat <<DRY
[dry-run] mkdir -p ${STATE_DIR} (0700)
[dry-run] ${PAIR_CMD} --code '<redacted>'
[dry-run] install service: $([ "$OS" = "Darwin" ] && echo "launchd plist ~/Library/LaunchAgents/dev.orbit.node.plist" || echo "systemd user unit ~/.config/systemd/user/orbit-node.service")
[dry-run] enable + start service; '${BIN} --config ${STATE_DIR}/node.json status'
DRY
  exit 0
fi
confirm "Pair node with $SERVER and install service?" || exit 1
mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
if [ -n "$CA_FILE" ]; then "$BIN" --config "$STATE_DIR/node.json" pair --server "$SERVER" --code "$CODE" --ca-file "$CA_FILE" --state "$STATE_DIR/node.json"
else "$BIN" --config "$STATE_DIR/node.json" pair --server "$SERVER" --code "$CODE" --state "$STATE_DIR/node.json"; fi
if [ "$OS" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/dev.orbit.node.plist"; mkdir -p "$(dirname "$PLIST")"
  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.orbit.node</string>
<key>ProgramArguments</key><array><string>${BIN}</string><string>--config</string><string>${STATE_DIR}/node.json</string><string>serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>${STATE_DIR}/node.log</string>
<key>StandardErrorPath</key><string>${STATE_DIR}/node.log</string>
</dict></plist>
PLIST
  launchctl unload "$PLIST" 2>/dev/null || true; launchctl load "$PLIST"; log "launchd service loaded: $PLIST"
else
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found; start manually: $BIN --config $STATE_DIR/node.json serve"
  UNIT="$HOME/.config/systemd/user/orbit-node.service"; mkdir -p "$(dirname "$UNIT")"
  cat > "$UNIT" <<UNIT
[Unit]
Description=Orbit computer node
After=network-online.target
[Service]
ExecStart=${BIN} --config ${STATE_DIR}/node.json serve
Restart=on-failure
[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload; systemctl --user enable --now orbit-node; log "systemd user unit enabled: $UNIT"
fi
"$BIN" --config "$STATE_DIR/node.json" status; log "node paired and service started"
