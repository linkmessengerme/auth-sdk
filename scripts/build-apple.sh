#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -s)" == Darwin ]] || { echo 'Apple packaging requires macOS/Xcode.' >&2; exit 1; }
bash scripts/generate-bindings.sh
case "$(uname -m)" in
  arm64) host_target=aarch64-apple-darwin ;;
  x86_64) host_target=x86_64-apple-darwin ;;
  *) echo 'Unsupported build host architecture.' >&2; exit 1 ;;
esac
# Keep the build machine's paths out of the published binaries. The last matching
# prefix wins, so the home directory comes first and the specific roots after it.
path_remap="--remap-path-prefix=${HOME}=/home --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup --remap-path-prefix=${PWD}=/auth-sdk"
export RUSTFLAGS="${RUSTFLAGS:-} ${path_remap}"
cargo build --release --locked -p link-auth-ffi \
  --target aarch64-apple-ios --target aarch64-apple-ios-sim --target "$host_target"
headers="${PWD}/target/packaging/apple/headers"
mkdir -p "$headers" platforms/apple/Artifacts platforms/apple/Generated/LinkAuthCore
cp bindings/generated/LinkAuthCoreFFI.h "$headers/"
cp bindings/generated/LinkAuthCoreFFI.modulemap "$headers/module.modulemap"
cp bindings/generated/LinkAuthCore.swift platforms/apple/Generated/LinkAuthCore/
output="${PWD}/platforms/apple/Artifacts/LinkAuthCoreFFI.xcframework"
# This path is build output, never source or an installed framework.
rm -rf "$output"
xcodebuild -create-xcframework \
  -library "${PWD}/target/aarch64-apple-ios/release/liblink_auth_ffi.a" -headers "$headers" \
  -library "${PWD}/target/aarch64-apple-ios-sim/release/liblink_auth_ffi.a" -headers "$headers" \
  -library "${PWD}/target/${host_target}/release/liblink_auth_ffi.a" -headers "$headers" \
  -output "$output"
swift build --package-path platforms/apple --configuration release
echo 'Local SPM package ready: platforms/apple (iOS arm64 device/simulator; host macOS for tests).'
