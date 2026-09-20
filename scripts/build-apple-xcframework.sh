#!/usr/bin/env sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "Apple XCFramework builds require macOS." >&2
  exit 1
fi

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$root_dir/crates/meta-mesh-mobile/Cargo.toml"
target_root=${CARGO_TARGET_DIR:-"$root_dir/crates/meta-mesh-mobile/target"}
generated_dir="$root_dir/crates/meta-mesh-mobile/generated"
output_dir="$generated_dir/apple"
output="$output_dir/meta_mesh_mobileFFI.xcframework"
toolchain=${RUSTUP_TOOLCHAIN:-$(rustup show active-toolchain | awk '{print $1}')}
export IPHONEOS_DEPLOYMENT_TARGET=${IPHONEOS_DEPLOYMENT_TARGET:-17.0}

if [ -z "${RUSTC:-}" ] && command -v rustup >/dev/null 2>&1; then
  RUSTC=$(rustup which rustc --toolchain "$toolchain")
  export RUSTC
fi

rustup target add --toolchain "$toolchain" aarch64-apple-ios aarch64-apple-ios-sim

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build \
    --locked \
    --release \
    --manifest-path "$manifest" \
    --target "$target"
done

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/meta-mesh-xcframework.XXXXXX")
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

for platform in iphoneos iphonesimulator; do
  mkdir -p "$temp_dir/$platform/Headers"
  cp "$generated_dir/swift/meta_mesh_mobileFFI.h" "$temp_dir/$platform/Headers/"
  cp "$generated_dir/swift/meta_mesh_mobileFFI.modulemap" "$temp_dir/$platform/Headers/module.modulemap"
done

cp "$target_root/aarch64-apple-ios/release/libmeta_mesh_mobile.a" \
  "$temp_dir/iphoneos/libmeta_mesh_mobile.a"
cp "$target_root/aarch64-apple-ios-sim/release/libmeta_mesh_mobile.a" \
  "$temp_dir/iphonesimulator/libmeta_mesh_mobile.a"

xcrun strip -S -x "$temp_dir/iphoneos/libmeta_mesh_mobile.a" || true
xcrun strip -S -x "$temp_dir/iphonesimulator/libmeta_mesh_mobile.a" || true

rm -rf "$output"
mkdir -p "$output_dir"
xcodebuild -create-xcframework \
  -library "$temp_dir/iphoneos/libmeta_mesh_mobile.a" \
  -headers "$temp_dir/iphoneos/Headers" \
  -library "$temp_dir/iphonesimulator/libmeta_mesh_mobile.a" \
  -headers "$temp_dir/iphonesimulator/Headers" \
  -output "$output"

echo "Apple XCFramework created: $output"
