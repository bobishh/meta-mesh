#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_dir="$root_dir/crates/meta-mesh-mobile/generated"
framework="$package_dir/apple/meta_mesh_mobileFFI.xcframework"

if [ ! -f "$framework/Info.plist" ]; then
  echo "Missing XCFramework. Run scripts/build-apple-xcframework.sh first." >&2
  exit 1
fi

plutil -lint "$framework/Info.plist"

(
  cd "$package_dir"
  xcodebuild \
    -scheme MetaMeshMobile \
    -destination 'generic/platform=iOS Simulator' \
    CODE_SIGNING_ALLOWED=NO \
    build
)

echo "Apple package verified."
