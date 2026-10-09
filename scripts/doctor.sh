#!/usr/bin/env bash
# orbit doctor: local health checks with clear PASS/FAIL lines. No CLI crate
# exists in this repo, so this script is the doctor. Reads ORBIT_BASE
# (default http://127.0.0.1:3000), DATABASE_URL and OLLAMA_URL
# (default http://127.0.0.1:11434). Never touches secrets beyond connectivity.
set -u
BASE="${ORBIT_BASE:-http://127.0.0.1:3000}"
OLLAMA="${OLLAMA_URL:-http://127.0.0.1:11434}"
fail=0
line() { if [ "$1" = 0 ]; then echo "PASS: $2"; else echo "FAIL: $2"; fail=1; fi; }
curl -fsS --max-time 5 "$BASE/health" >/dev/null 2>&1; line $? "API $BASE/health reachable"
curl -fsS --max-time 5 "$BASE/ready" >/dev/null 2>&1; line $? "API $BASE/ready reports ready"
if [ -n "${DATABASE_URL:-}" ]; then
  if command -v pg_isready >/dev/null 2>&1; then pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; line $? "postgres accepts connections (DATABASE_URL)"; else echo "SKIP: pg_isready not installed"; fi
else echo "SKIP: DATABASE_URL unset, DB check skipped"; fi
curl -fsS --max-time 5 "$OLLAMA/api/tags" >/dev/null 2>&1; line $? "Ollama $OLLAMA/api/tags reachable"
if command -v aiec >/dev/null 2>&1; then aiec status >/dev/null 2>&1; line $? "AIec CLI reports status"; else echo "SKIP: aiec CLI not installed"; fi
df_out=$(df -P / 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')
if [ -n "${df_out:-}" ] && [ "$df_out" -lt 90 ]; then line 0 "disk / at ${df_out}% used"; else line 1 "disk / at ${df_out:-%?}% used (>=90%)"; fi
for port in 3000 55432; do
  (exec 3<>/dev/tcp/127.0.0.1/$port) >/dev/null 2>&1; line $? "port 127.0.0.1:$port listening"
done
if [ "$fail" = 0 ]; then echo "doctor: all checks passed"; else echo "doctor: failures present"; fi
exit "$fail"
