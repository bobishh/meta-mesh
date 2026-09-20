#!/usr/bin/env sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
declaration_path="packages/mesh-transport/wasm/meta_mesh.d.ts"
tracked_api=$(mktemp)
generated_api=$(mktemp)

trap 'rm -f "$tracked_api" "$generated_api"' EXIT HUP INT TERM

# wasm-bindgen emits linker-specific Rust symbol hashes inside InitOutput.
# Compare the stable TypeScript surface while the preceding build validates ABI.
stable_api() {
  awk '
    /^export interface InitOutput \{/ { skipping = 1; next }
    skipping && /^export type SyncInitInput/ { skipping = 0 }
    !skipping { print }
  '
}

cd "$repo_root"
git show "HEAD:$declaration_path" | stable_api > "$tracked_api"
stable_api < "$declaration_path" > "$generated_api"
diff -u "$tracked_api" "$generated_api"
