#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
crate_dir="$root_dir/crates/meta-mesh"
target_dir="$root_dir/target"
out_dir="$root_dir/dist/wasm"
rust_bin=$(dirname "$(rustup which rustc)")
llvm_prefix=${LLVM_PREFIX:-$(brew --prefix llvm 2>/dev/null || true)}
lld_prefix=${LLD_PREFIX:-$(brew --prefix lld 2>/dev/null || true)}

if [ -z "$llvm_prefix" ] || [ -z "$lld_prefix" ]; then
  echo "build-wasm requires LLVM and LLD with wasm support" >&2
  exit 1
fi

mkdir -p "$out_dir"
PATH="$rust_bin:$llvm_prefix/bin:$lld_prefix/bin:$PATH" \
CC="$llvm_prefix/bin/clang" \
AR="$llvm_prefix/bin/llvm-ar" \
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER="$lld_prefix/bin/ld.lld" \
cargo build --manifest-path "$crate_dir/Cargo.toml" --release --target wasm32-unknown-unknown

wasm-bindgen \
  "$target_dir/wasm32-unknown-unknown/release/meta_mesh.wasm" \
  --out-dir "$out_dir" \
  --target web

mkdir -p "$root_dir/packages/mesh-transport/wasm"
cp "$out_dir"/meta_mesh* "$root_dir/packages/mesh-transport/wasm/"

echo "WASM build complete!"
