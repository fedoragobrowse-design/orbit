#!/bin/sh
# Thin wrapper: the node setup lives in scripts/install-node.sh.
# Kept so the documented `./install-node.sh` path keeps working.
set -eu
HERE="$(dirname "$0")"
exec sh "$HERE/scripts/install-node.sh" "$@"
