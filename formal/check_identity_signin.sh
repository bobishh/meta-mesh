#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$ROOT/tla-tools-pin.env"
CACHE_DIR=${XDG_CACHE_HOME:-"$HOME/.cache"}/meta-mesh-tla
TOOLS_JAR="$CACHE_DIR/tla2tools-identity-$TOOLS_RELEASE_ASSET_ID.jar"
LOG_DIR=${1:-$(mktemp -d "${TMPDIR:-/tmp}/meta-mesh-identity-signin.XXXXXX")}
mkdir -p "$CACHE_DIR" "$LOG_DIR"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

if [ ! -f "$TOOLS_JAR" ] || [ "$(sha256 "$TOOLS_JAR")" != "$TOOLS_SHA256" ]; then
  download="$TOOLS_JAR.tmp.$$"
  trap 'rm -f "$download"' EXIT HUP INT TERM
  curl -fL --retry 3 -H 'Accept: application/octet-stream' -H 'X-GitHub-Api-Version: 2022-11-28' \
    -o "$download" "$TOOLS_ASSET_URL"
  actual=$(sha256 "$download")
  if [ "$actual" != "$TOOLS_SHA256" ]; then
    printf 'TLC checksum mismatch: expected %s, got %s\n' "$TOOLS_SHA256" "$actual" >&2
    exit 1
  fi
  mv "$download" "$TOOLS_JAR"
  trap - EXIT HUP INT TERM
fi

find_java() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME/bin/java"; return
  fi
  if command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    command -v java; return
  fi
  for candidate in /opt/homebrew/opt/openjdk@21/bin/java /opt/homebrew/opt/openjdk/bin/java \
    /usr/local/opt/openjdk@21/bin/java /usr/local/opt/openjdk/bin/java; do
    if [ -x "$candidate" ]; then printf '%s\n' "$candidate"; return; fi
  done
  printf '%s\n' 'Java 17 or newer required.' >&2; exit 1
}
JAVA=$(find_java)

run_case() {
  config=$1
  expected=$2
  log="$LOG_DIR/$config.log"
  metadata="$LOG_DIR/$config-state"
  if "$JAVA" -Xmx512m -XX:+UseParallelGC -cp "$TOOLS_JAR" tlc2.TLC \
      -cleanup -deadlock -noGenerateSpecTE -metadir "$metadata" -workers 2 \
      -config "$ROOT/$config.cfg" "$ROOT/IdentitySignIn.tla" >"$log" 2>&1; then
    if [ "$expected" != pass ] || ! grep -Fq 'No error has been found' "$log"; then
      printf 'Unexpected TLC success for %s; log: %s\n' "$config" "$log" >&2
      tail -n 35 "$log" >&2; exit 1
    fi
    printf 'PASS %s\n' "$config"
  else
    if [ "$expected" = pass ] || ! grep -Fq 'Invariant Safety is violated' "$log"; then
      printf 'Unexpected TLC failure for %s; log: %s\n' "$config" "$log" >&2
      tail -n 45 "$log" >&2; exit 1
    fi
    printf 'CAUGHT %s\n' "$config"
  fi
  grep -m1 'states generated' "$log" || true
  rm -rf "$metadata"
}

run_case IdentitySignIn pass
run_case IdentitySignIn_delivery pass
run_case IdentitySignIn_linked pass
run_case IdentitySignIn_offline pass
run_case IdentitySignIn_empty pass
run_case IdentitySignIn_service_unavailable pass
run_case IdentitySignIn_skip_sync failure
run_case IdentitySignIn_false_empty failure
run_case IdentitySignIn_early_success failure
printf 'Logs and counterexamples: %s\n' "$LOG_DIR"
