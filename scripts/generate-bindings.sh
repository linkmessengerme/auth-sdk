#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --locked -p link-auth-ffi
case "$(uname -s)" in
  Darwin) library=target/debug/liblink_auth_ffi.dylib ;;
  Linux) library=target/debug/liblink_auth_ffi.so ;;
  *) echo 'Run binding generation on macOS or Linux.' >&2; exit 1 ;;
esac

cargo run --locked -p link-auth-ffi --features bindgen --bin uniffi-bindgen -- \
  generate "$library" --metadata-no-deps --no-format --language swift --language kotlin \
  --config crates/auth-ffi/uniffi.toml --out-dir bindings/generated
