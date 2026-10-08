#!/bin/sh
set -eu
# This isolated container has only the five setup capabilities. Native workers
# must drop them and establish no_new_privs/Landlock themselves before any I/O.
export ORBIT_NATIVE_SERVICE_UID=10001 ORBIT_NATIVE_OWNER_UID=10002
found=0
for test in /tests/native_security-* /tests/native_admission-*; do
  [ -f "$test" ] && [ -x "$test" ] || continue
  found=$((found + 1))
  "$test" --test-threads=1 --nocapture
done
[ "$found" -ge 2 ] || { echo 'Native security binaries missing' >&2; exit 1; }
