#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root_dir/crates/meta-mesh-mobile/Cargo.toml"
target_dir="$root_dir/crates/meta-mesh-mobile/target/debug"
generated_dir="$root_dir/crates/meta-mesh-mobile/generated"

case "$(uname -s)" in
  Darwin|Linux) library="$target_dir/libmeta_mesh_mobile.a" ;;
  MINGW*|MSYS*|CYGWIN*) library="$target_dir/meta_mesh_mobile.lib" ;;
  *) echo "Unsupported host for mobile binding generation" >&2; exit 1 ;;
esac

# UniFFI metadata is identical in static and dynamic artifacts. Static output
# avoids linking the full Iroh graph into a host shared library only to inspect
# metadata, which is both faster and substantially less memory-hungry in CI.
cargo rustc --manifest-path "$manifest" --lib -- --crate-type staticlib
cargo run --manifest-path "$manifest" --features bindgen --bin uniffi-bindgen -- \
  generate "$library" --language swift --out-dir "$generated_dir/swift" --no-format
cargo run --manifest-path "$manifest" --features bindgen --bin uniffi-bindgen -- \
  generate "$library" --language kotlin --out-dir "$generated_dir/kotlin" --no-format

find "$generated_dir" -type f -exec perl -0pi -e 's/[ \t]+(?=\n)//g; s/\n+\z/\n/' {} +

echo "Swift and Kotlin bindings generated."
