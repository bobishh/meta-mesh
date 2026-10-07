#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLS_VERSION=1.8.0
TOOLS_SHA256=7beec0f04818732a62fa193731711a99aa4f11279499b2360a7d156c519ea78d
CACHE_DIR=${XDG_CACHE_HOME:-"$HOME/.cache"}/meta-mesh-tla
TOOLS_JAR="$CACHE_DIR/tla2tools-$TOOLS_VERSION-coownership.jar"
LOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/meta-mesh-coownership.XXXXXX")
GRAPH_DIR=${COOWNERSHIP_GRAPH_DIR:-}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --graph-dir)
      [ "$#" -ge 2 ] || { printf '%s\n' '--graph-dir requires a path.' >&2; exit 2; }
      GRAPH_DIR=$2
      shift 2
      ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if [ -z "$GRAPH_DIR" ]; then GRAPH_DIR="$LOG_DIR/graph"; fi
mkdir -p "$CACHE_DIR" "$GRAPH_DIR"

find_java() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME/bin/java"
    return
  fi
  if command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    command -v java
    return
  fi
  for candidate in /opt/homebrew/opt/openjdk@21/bin/java /opt/homebrew/opt/openjdk/bin/java \
    /usr/local/opt/openjdk@21/bin/java /usr/local/opt/openjdk/bin/java; do
    if [ -x "$candidate" ]; then printf '%s\n' "$candidate"; return; fi
  done
  printf '%s\n' 'Java 17 or newer required.' >&2
  exit 1
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'
  fi
}

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

run_case() {
  config=$1
  expected=$2
  log="$LOG_DIR/$config.log"
  metadata="$LOG_DIR/$config-state"
  set -- -cleanup -deadlock -noGenerateSpecTE -metadir "$metadata" -workers auto
  if [ "$config" = CoOwnership ]; then
    set -- "$@" -dump dot,actionlabels "$GRAPH_DIR/CoOwnership.dot"
  fi
  if "$JAVA" -XX:+UseParallelGC -cp "$TOOLS_JAR" tlc2.TLC "$@" \
      -config "$ROOT/$config.cfg" "$ROOT/CoOwnership.tla" >"$log" 2>&1; then
    if [ "$expected" != pass ]; then
      printf 'ERROR: expected %s violation for %s; log: %s\n' "$expected" "$config" "$log" >&2
      tail -n 35 "$log" >&2
      exit 1
    fi
    states=$(grep -m1 'states generated' "$log" || true)
    printf 'PASS %-34s %s\n' "$config" "${states:-TLC completed}"
    if [ "$config" = CoOwnership ]; then
      python3 "$ROOT/export_graph.py" "$GRAPH_DIR/CoOwnership.dot" "$GRAPH_DIR/CoOwnership.json"
    fi
  else
    if [ "$expected" = pass ] || ! grep -Fq "Invariant $expected is violated" "$log"; then
      printf 'ERROR: unexpected TLC failure for %s; log: %s\n' "$config" "$log" >&2
      tail -n 50 "$log" >&2
      exit 1
    fi
    states=$(grep -m1 'states generated' "$log" || true)
    printf 'CAUGHT %-32s %s\n' "$config" "${states:-counterexample}"
  fi
  rm -rf "$metadata"
}

run_case CoOwnership pass
run_case CoOwnership_liveness pass
run_case CoOwnership_threshold_bypass IssuedCertificatesHaveQuorum
run_case CoOwnership_stale_replay HeadHasAuthorizedSelection
run_case CoOwnership_forget_conflict KnownConflictFailsClosed
run_case CoOwnership_recovery_bypass RecoveryRestoresSelectedIdentity
conformance_log="$LOG_DIR/rust-conformance.log"
if MESH_TLC_COOWNERSHIP_GRAPH="$GRAPH_DIR/CoOwnership.json" \
    cargo test --manifest-path "$ROOT/../crates/meta-mesh-core/Cargo.toml" \
    --test tlc_coownership -- --ignored --nocapture >"$conformance_log" 2>&1; then
  tail -n 8 "$conformance_log"
else
  tail -n 60 "$conformance_log" >&2
  exit 1
fi
MESH_TLC_COOWNERSHIP_GRAPH="$GRAPH_DIR/CoOwnership.json" \
  python3 "$ROOT/check_coownership_implementation.py"
printf 'Model graph: %s/CoOwnership.json\n' "$GRAPH_DIR"
printf 'Logs and counterexamples: %s\n' "$LOG_DIR"
