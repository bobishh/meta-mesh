#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root_dir/crates/meta-mesh-mobile/Cargo.toml"
target_dir="$root_dir/crates/meta-mesh-mobile/target/debug"
generated_dir="$root_dir/crates/meta-mesh-mobile/generated"

case "$(uname -s)" in
  Darwin) library="$target_dir/libmeta_mesh_mobile.dylib" ;;
  Linux) library="$target_dir/libmeta_mesh_mobile.so" ;;
  MINGW*|MSYS*|CYGWIN*) library="$target_dir/meta_mesh_mobile.dll" ;;
  *) echo "Unsupported host for mobile binding generation" >&2; exit 1 ;;
esac

cargo build --manifest-path "$manifest" --lib
cargo run --manifest-path "$manifest" --features bindgen --bin uniffi-bindgen -- \
  generate "$library" --language swift --out-dir "$generated_dir/swift" --no-format
cargo run --manifest-path "$manifest" --features bindgen --bin uniffi-bindgen -- \
  generate "$library" --language kotlin --out-dir "$generated_dir/kotlin" --no-format

find "$generated_dir" -type f -exec perl -0pi -e 's/[ \t]+(?=\n)//g; s/\n+\z/\n/' {} +

echo "Swift and Kotlin bindings generated."
