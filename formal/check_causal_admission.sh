#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLS_VERSION=1.8.0
TOOLS_SHA256=7beec0f04818732a62fa193731711a99aa4f11279499b2360a7d156c519ea78d
CACHE_DIR=${XDG_CACHE_HOME:-"$HOME/.cache"}/meta-mesh-tla-causal-admission
TOOLS_JAR="$CACHE_DIR/tla2tools-$TOOLS_VERSION.jar"
LOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/meta-mesh-causal-admission.XXXXXX")
GRAPH_DIR=${CAUSAL_ADMISSION_GRAPH_DIR:-}

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
  if [ "$config" = CausalAdmission ]; then
    set -- "$@" -dump dot,actionlabels "$GRAPH_DIR/CausalAdmission.dot"
  fi
  if "$JAVA" -XX:+UseParallelGC -cp "$TOOLS_JAR" tlc2.TLC "$@" \
      -config "$ROOT/$config.cfg" "$ROOT/CausalAdmission.tla" >"$log" 2>&1; then
    if [ "$expected" != pass ]; then
      printf 'ERROR: expected %s violation for %s; log: %s\n' "$expected" "$config" "$log" >&2
      tail -n 35 "$log" >&2
      exit 1
    fi
    states=$(grep -m1 'states generated' "$log" || true)
    printf 'PASS %-42s %s\n' "$config" "${states:-TLC completed}"
    if [ "$config" = CausalAdmission ]; then
      python3 "$ROOT/export_graph.py" "$GRAPH_DIR/CausalAdmission.dot" "$GRAPH_DIR/CausalAdmission.json"
    fi
  else
    if [ "$expected" = pass ] || ! grep -Fq "Invariant $expected is violated" "$log"; then
      printf 'ERROR: unexpected TLC failure for %s; log: %s\n' "$config" "$log" >&2
      tail -n 50 "$log" >&2
      exit 1
    fi
    states=$(grep -m1 'states generated' "$log" || true)
    printf 'CAUGHT %-40s %s\n' "$expected" "${states:-counterexample}"
  fi
  rm -rf "$metadata"
}

run_case CausalAdmission pass
run_case CausalAdmission_liveness pass
run_case CausalAdmission_clocks pass
run_case CausalAdmission_known_hash_bypass KnownHashBypass
run_case CausalAdmission_timestamp_priority TimestampPriority
run_case CausalAdmission_missing_dependency MissingDependencyAcceptance
run_case CausalAdmission_forgetting_quarantine ForgettingQuarantine

conformance_log="$LOG_DIR/rust-conformance.log"
if MESH_TLC_CAUSAL_ADMISSION_GRAPH="$GRAPH_DIR/CausalAdmission.json" \
    cargo test --locked -p meta-mesh-core --test tlc_causal_admission -- --ignored --nocapture \
    >"$conformance_log" 2>&1; then
  tail -n 14 "$conformance_log"
else
  tail -n 60 "$conformance_log" >&2
  exit 1
fi
mutation_log="$LOG_DIR/rust-mutations.log"
if MESH_TLC_CAUSAL_ADMISSION_GRAPH="$GRAPH_DIR/CausalAdmission.json" \
    python3 "$ROOT/check_causal_admission_implementation.py" >"$mutation_log" 2>&1; then
  cat "$mutation_log"
else
  tail -n 80 "$mutation_log" >&2
  exit 1
fi
printf 'Model graph: %s/CausalAdmission.json\n' "$GRAPH_DIR"
printf 'Logs and counterexamples: %s\n' "$LOG_DIR"
