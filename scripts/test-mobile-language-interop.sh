#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root_dir/crates/meta-mesh-mobile/Cargo.toml"
tests_dir="$root_dir/crates/meta-mesh-mobile/tests"
generated_dir="$root_dir/crates/meta-mesh-mobile/generated"
target_root=${CARGO_TARGET_DIR:-"$root_dir/crates/meta-mesh-mobile/target"}
target_dir="$target_root/debug"

cargo build --locked --manifest-path "$manifest"

case "$(uname -s)" in
  Darwin)
    swiftc \
      "$generated_dir/swift/meta_mesh_mobile.swift" \
      "$tests_dir/swift_interop.swift" \
      -I "$generated_dir/swift" \
      -Xcc "-fmodule-map-file=$generated_dir/swift/meta_mesh_mobileFFI.modulemap" \
      -L "$target_dir" \
      -lmeta_mesh_mobile \
      -o "$target_dir/swift-interop"
    DYLD_LIBRARY_PATH="$target_dir${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
      "$target_dir/swift-interop"
    ;;
  *) echo "Swift/native interop requires macOS; skipped on $(uname -s)." ;;
esac

if ! command -v gradle >/dev/null 2>&1; then
  echo "Gradle is required for Kotlin/native interop." >&2
  exit 1
fi

META_MESH_LIBRARY_PATH="$target_dir" gradle \
  --no-daemon \
  --project-dir "$tests_dir" \
  run
