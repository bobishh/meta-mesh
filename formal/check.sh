#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLS_VERSION=1.8.0
TOOLS_SHA256=32d64fbbc464559fc7192341b27b885fa4eb6b92d1648d2b49fb9cdcb7aacf81
CACHE_DIR=${XDG_CACHE_HOME:-"$HOME/.cache"}/meta-mesh-tla
TOOLS_JAR="$CACHE_DIR/tla2tools-$TOOLS_VERSION.jar"

find_java() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME/bin/java"
    return
  fi
  if command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    command -v java
    return
  fi
  for candidate in \
    /opt/homebrew/opt/openjdk@21/bin/java \
    /opt/homebrew/opt/openjdk/bin/java \
    /usr/local/opt/openjdk@21/bin/java \
    /usr/local/opt/openjdk/bin/java
  do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  printf '%s\n' "Java 17 or newer is required (for example: brew install openjdk@21)." >&2
  exit 1
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mkdir -p "$CACHE_DIR"
if [ ! -f "$TOOLS_JAR" ] || [ "$(sha256 "$TOOLS_JAR")" != "$TOOLS_SHA256" ]; then
  tmp="$TOOLS_JAR.tmp.$$"
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
  curl -fL --retry 3 -o "$tmp" \
    "https://github.com/tlaplus/tlaplus/releases/download/v$TOOLS_VERSION/tla2tools.jar"
  actual=$(sha256 "$tmp")
  if [ "$actual" != "$TOOLS_SHA256" ]; then
    printf 'TLC checksum mismatch: expected %s, got %s\n' "$TOOLS_SHA256" "$actual" >&2
    exit 1
  fi
  mv "$tmp" "$TOOLS_JAR"
  trap - EXIT HUP INT TERM
fi

JAVA=$(find_java)

run_pass() {
  module=$1
  metadata=$(mktemp -d "${TMPDIR:-/tmp}/meta-mesh-tlc-state.XXXXXX")
  if "$JAVA" -XX:+UseParallelGC -cp "$TOOLS_JAR" tlc2.TLC \
      -cleanup -deadlock -noGenerateSpecTE -metadir "$metadata" -workers auto \
      -config "$ROOT/$module.cfg" "$ROOT/$module.tla"; then
    rm -rf "$metadata"
  else
    status=$?
    rm -rf "$metadata"
    return "$status"
  fi
}

run_expected_failure() {
  module=$1
  config=$2
  label=$3
  output=$(mktemp "${TMPDIR:-/tmp}/meta-mesh-tlc.XXXXXX")
  metadata=$(mktemp -d "${TMPDIR:-/tmp}/meta-mesh-tlc-state.XXXXXX")
  if "$JAVA" -XX:+UseParallelGC -cp "$TOOLS_JAR" tlc2.TLC \
      -cleanup -deadlock -noGenerateSpecTE -metadir "$metadata" -workers auto \
      -config "$ROOT/$config.cfg" \
      "$ROOT/$module.tla" >"$output" 2>&1; then
    printf 'Expected the %s mutation to violate an invariant, but TLC passed.\n' "$label" >&2
    cat "$output" >&2
    rm -f "$output"
    rm -rf "$metadata"
    exit 1
  fi
  if ! grep -q 'Invariant Safety is violated' "$output"; then
    printf 'The %s mutation failed for an unexpected reason.\n' "$label" >&2
    cat "$output" >&2
    rm -f "$output"
    rm -rf "$metadata"
    exit 1
  fi
  states=$(grep -m1 'states generated' "$output" || true)
  printf '%s mutation caught (%s)\n' "$label" "${states:-counterexample generated}"
  rm -f "$output"
  rm -rf "$metadata"
}

run_pass AuthorityEpochs
run_expected_failure AuthorityEpochs AuthorityEpochs_grant_reset "old grant clears revocation"
run_expected_failure AuthorityEpochs AuthorityEpochs_snapshot_reset "stale authority snapshot rollback"

run_pass SessionGenerations
run_expected_failure SessionGenerations SessionGenerations_stale_cleanup "stale cleanup closes current session"
run_expected_failure SessionGenerations SessionGenerations_collapsed_tabs "same-device tabs collapse to one session key"

run_pass DurableDelivery
run_expected_failure DurableDelivery DurableDelivery_partial_ack "partial ACK completes delivery"
run_expected_failure DurableDelivery DurableDelivery_empty_ack "empty ACK completes delivery"
