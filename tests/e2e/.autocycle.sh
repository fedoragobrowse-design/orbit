#!/bin/sh
# Bounded watcher: wait for a backend-consistent lock, then run the real e2e
# deployment cycle and stop once it reports ready.
set -e
ROOT=/home/gobrowse/code/orbit
cd "$ROOT"
LOG=/tmp/orbit-e2e.log

echo "waiting for consistent Cargo.lock..."
i=0
while [ $i -lt 120 ]; do
  if cargo metadata --locked --format-version 1 -q >/dev/null 2>&1; then
    echo "lock consistent after ~$((i*20))s"
    break
  fi
  i=$((i + 1))
  sleep 20
done
[ $i -lt 120 ] || { echo "LOCK NEVER CONSISTENT"; exit 1; }

# Let backend's in-flight edits settle so we do not capture a half-written tree.
sleep 45
cargo metadata --locked --format-version 1 -q >/dev/null 2>&1 || { echo "LOCK DRIFTED AGAIN"; exit 1; }

rm -f tests/e2e/.runtime.lock
echo "starting run-server.mjs"
setsid nohup node tests/e2e/run-server.mjs > "$LOG" 2>&1 < /dev/null &
echo $! > /tmp/orbit-e2e.pid

j=0
while [ $j -lt 160 ]; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/ready 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then
    echo "E2E DEPLOYMENT READY after ~$((j*15))s"
    exit 0
  fi
  if ! pgrep -f "run-server.mjs" >/dev/null 2>&1; then
    echo "RUN-SERVER EXITED after ~$((j*15))s"
    grep -aoE "failed to solve[^\\\\]*|Error: [^\\\\]*" "$LOG" | tail -3 || true
    exit 1
  fi
  j=$((j + 1))
  sleep 15
done
echo "READY TIMEOUT"
exit 1