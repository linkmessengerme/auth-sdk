#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Set KOTLIN_RUNTIME_CLASSPATH to the Kotlin stdlib, coroutines-core-jvm and JNA
# JARs, separated by ':'. Tested dependency versions are listed in the README.
# If kotlinc is not installed, KOTLIN_COMPILER_CLASSPATH may point to the
# kotlin-compiler-embeddable JAR and its compiler dependencies (stdlib, reflect,
# trove4j and JetBrains annotations). No global tool installation is performed.
: "${KOTLIN_RUNTIME_CLASSPATH:?Set paths to the Kotlin stdlib, coroutines and JNA JARs}"
sources=(bindings/generated/me/linkmessenger/auth/generated/link_auth_ffi.kt bindings/smoke/Smoke.kt)
if [[ ! -f "${sources[0]}" ]]; then
  echo 'Generate bindings first: bash scripts/generate-bindings.sh' >&2
  exit 1
fi
mkdir -p target/binding-smoke
if [[ -n "${KOTLIN_COMPILER_CLASSPATH:-}" ]]; then
  compiler=(java -cp "$KOTLIN_COMPILER_CLASSPATH" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler)
else
  compiler=(kotlinc)
fi
"${compiler[@]}" -no-stdlib -no-reflect -jvm-target 17 \
  -classpath "$KOTLIN_RUNTIME_CLASSPATH" "${sources[@]}" \
  -d target/binding-smoke/kotlin-smoke.jar
java -Djna.library.path="${PWD}/target/debug" \
  -cp "target/binding-smoke/kotlin-smoke.jar:${KOTLIN_RUNTIME_CLASSPATH}" \
  SmokeKt "${PWD}/bindings/fixtures"
