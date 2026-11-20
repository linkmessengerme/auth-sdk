#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed NDK (r28 or newer)}"
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK with platform/build-tools 34}"
case "$(uname -s)" in
  Darwin) ndk_host=darwin-x86_64 ;;
  Linux) ndk_host=linux-x86_64 ;;
  *) echo 'Run Android packaging on macOS or Linux.' >&2; exit 1 ;;
esac
toolchain="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${ndk_host}/bin"
[[ -x "$toolchain/clang" ]] || { echo 'NDK compiler not found.' >&2; exit 1; }
bash scripts/generate-bindings.sh
# Keep the build machine's paths out of the published binaries. The last matching
# prefix wins, so the home directory comes first and the specific roots after it.
path_remap="--remap-path-prefix=${HOME}=/home --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup --remap-path-prefix=${PWD}=/auth-sdk"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$toolchain/aarch64-linux-android23-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$toolchain/armv7a-linux-androideabi23-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$toolchain/x86_64-linux-android23-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384 ${path_remap}"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384 ${path_remap}"
export CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384 ${path_remap}"
cargo build --release --locked -p link-auth-ffi \
  --target aarch64-linux-android --target armv7-linux-androideabi --target x86_64-linux-android
for mapping in aarch64-linux-android:arm64-v8a armv7-linux-androideabi:armeabi-v7a x86_64-linux-android:x86_64; do
  rust_target=${mapping%%:*}; abi=${mapping#*:}
  output="platforms/android/build/generated/jniLibs/$abi"
  mkdir -p "$output"
  cp "target/$rust_target/release/liblink_auth_ffi.so" "$output/"
  "$toolchain/llvm-readelf" --program-headers "$output/liblink_auth_ffi.so" | \
    awk '/LOAD/ { if ($NF != "0x4000") { print "Expected 16 KiB ELF alignment"; exit 1 } found=1 } END { if (!found) exit 1 }'
done
if [[ -n "${LINK_GRADLE:-}" ]]; then
  gradle_command=("$LINK_GRADLE")
else
  gradle_command=("${PWD}/platforms/android/gradlew")
fi
"${gradle_command[@]}" --project-dir platforms/android --no-daemon \
  assembleRelease publishReleasePublicationToSdkBundleRepository "$@"
echo 'AAR and Maven bundle ready: platforms/android/build/outputs/aar and build/repository.'
