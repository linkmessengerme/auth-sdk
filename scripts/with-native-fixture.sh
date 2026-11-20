#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/binding-smoke
GOWORK=off go build -o target/binding-smoke/native-fixture scripts/native-fixture.go
ready=$(mktemp "${TMPDIR:-/tmp}/link-native-fixture.XXXXXX")
target/binding-smoke/native-fixture "$ready" &
fixture_pid=$!
trap 'kill "$fixture_pid" 2>/dev/null || true; wait "$fixture_pid" 2>/dev/null || true; rm -f "$ready"' EXIT
for ((i=0; i<100; i++)); do
  [[ -s "$ready" ]] && break
  kill -0 "$fixture_pid"
  sleep 0.05
done
[[ -s "$ready" ]] || { echo 'Fixture did not start' >&2; exit 1; }
"$@" "$(cat "$ready")"
