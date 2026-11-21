#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Device attestation through the local fixture, with a software key in place
# of App Attest. Generate bindings first: bash scripts/generate-bindings.sh
mkdir -p target/binding-smoke/swift-module-cache
swiftc -parse-as-library -swift-version 5 -warnings-as-errors \
  -module-cache-path target/binding-smoke/swift-module-cache \
  -I bindings/generated -Xcc -fmodule-map-file=bindings/generated/LinkAuthCoreFFI.modulemap \
  -L target/debug -llink_auth_ffi -Xlinker -rpath -Xlinker "${PWD}/target/debug" \
  bindings/generated/LinkAuthCore.swift platforms/apple/Sources/LinkAuthAdapters/*.swift \
  bindings/smoke/AttestSmoke.swift -o target/binding-smoke/attest-swift-smoke
bash scripts/with-native-fixture.sh target/binding-smoke/attest-swift-smoke
