#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
crate_dir="$root_dir/crates/meta-mesh"
target_dir=${CARGO_TARGET_DIR:-"$root_dir/target"}
out_dir="$root_dir/dist/wasm"
rust_bin=$(dirname "$(rustup which rustc)")
llvm_prefix=${LLVM_PREFIX:-$(brew --prefix llvm 2>/dev/null || true)}
lld_prefix=${LLD_PREFIX:-$(brew --prefix lld 2>/dev/null || true)}
if [ -z "$llvm_prefix" ] && [ -d /opt/homebrew/opt/llvm ]; then llvm_prefix=/opt/homebrew/opt/llvm; fi
if [ -z "$lld_prefix" ] && [ -d /opt/homebrew/opt/lld ]; then lld_prefix=/opt/homebrew/opt/lld; fi

find_tool() {
  prefix=$1
  shift

  if [ -n "$prefix" ]; then
    for tool in "$@"; do
      if [ -x "$prefix/bin/$tool" ]; then
        printf '%s\n' "$prefix/bin/$tool"
        return 0
      fi
    done
  fi

  for tool in "$@"; do
    tool_path=$(command -v "$tool" 2>/dev/null || true)
    if [ -n "$tool_path" ]; then
      printf '%s\n' "$tool_path"
      return 0
    fi
  done

  return 1
}

clang_bin=$(find_tool "$llvm_prefix" clang || true)
ar_bin=$(find_tool "$llvm_prefix" llvm-ar ar || true)
lld_bin=$(find_tool "$lld_prefix" wasm-ld ld.lld || true)
if [ -z "$lld_bin" ]; then
  rust_sysroot=$(rustc --print sysroot 2>/dev/null || true)
  rust_lld="$rust_sysroot/lib/rustlib/$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')/bin/rust-lld"
  if [ -x "$rust_lld" ]; then lld_bin="$rust_lld"; fi
fi

if [ -z "$clang_bin" ] || [ -z "$ar_bin" ] || [ -z "$lld_bin" ]; then
  echo "build-wasm requires LLVM and LLD with wasm support" >&2
  exit 1
fi

mkdir -p "$out_dir"
PATH="$rust_bin:$(dirname "$clang_bin"):$(dirname "$lld_bin"):$PATH" \
CC="$clang_bin" \
AR="$ar_bin" \
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER="$lld_bin" \
cargo build --manifest-path "$crate_dir/Cargo.toml" --release --target wasm32-unknown-unknown

wasm-bindgen \
  "$target_dir/wasm32-unknown-unknown/release/meta_mesh.wasm" \
  --out-dir "$out_dir" \
  --target web \
  --remove-name-section

mkdir -p "$root_dir/packages/mesh-transport/wasm"
cp "$out_dir"/meta_mesh* "$root_dir/packages/mesh-transport/wasm/"

echo "WASM build complete!"
