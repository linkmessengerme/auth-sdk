#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Device attestation through the local fixture, with a software key in place
# of AndroidKeyStore. Same environment as scripts/smoke-native-kotlin.sh.
: "${KOTLIN_RUNTIME_CLASSPATH:?Set Kotlin/JNA/OkHttp/Okio runtime JARs}"
: "${ANDROID_JAR:?Set path to an Android platform android.jar}"
mkdir -p target/binding-smoke
if [[ -n "${KOTLIN_COMPILER_CLASSPATH:-}" ]]; then
  compiler=(java -cp "$KOTLIN_COMPILER_CLASSPATH" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler)
else
  compiler=(kotlinc)
fi
"${compiler[@]}" -no-stdlib -no-reflect -jvm-target 17 -Werror \
  -classpath "${KOTLIN_RUNTIME_CLASSPATH}:${ANDROID_JAR}" \
  bindings/generated/me/linkmessenger/auth/generated/link_auth_ffi.kt \
  platforms/android/src/main/kotlin/me/linkmessenger/auth/*.kt bindings/smoke/AttestSmoke.kt \
  -d target/binding-smoke/attest-kotlin-smoke.jar
bash scripts/with-native-fixture.sh java -Djna.library.path="${PWD}/target/debug" \
  -cp "target/binding-smoke/attest-kotlin-smoke.jar:${KOTLIN_RUNTIME_CLASSPATH}" \
  me.linkmessenger.auth.AttestSmokeKt
