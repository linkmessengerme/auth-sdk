#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f bindings/generated/LinkAuthCore.swift ]]; then
  echo 'Generate bindings first: bash scripts/generate-bindings.sh' >&2
  exit 1
fi
mkdir -p target/binding-smoke/swift-module-cache
swiftc -parse-as-library \
  -module-cache-path target/binding-smoke/swift-module-cache \
  -I bindings/generated \
  -Xcc -fmodule-map-file=bindings/generated/LinkAuthCoreFFI.modulemap \
  -L target/debug -llink_auth_ffi \
  -Xlinker -rpath -Xlinker "${PWD}/target/debug" \
  bindings/generated/LinkAuthCore.swift bindings/smoke/Smoke.swift \
  -o target/binding-smoke/swift-smoke
target/binding-smoke/swift-smoke "${PWD}/bindings/fixtures"
