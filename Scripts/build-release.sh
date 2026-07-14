#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/dist"
PRODUCT_NAME="cengine"
PROJECT_PATH="$ROOT_DIR/cengine.xcodeproj"
CONFIGURATION="Release"
DERIVED_DATA_PATH="${XCODE_DERIVED_DATA:-$ROOT_DIR/.build/xcode-derived}"
SOURCE_PACKAGES_PATH="${XCODE_SOURCE_PACKAGES:-$ROOT_DIR/.build/xcode-source-packages}"
PRODUCTS_DIR="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION"
GIT_COMMIT="${CENGINE_GIT_COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || printf unknown)}"
BUILD_TIME="${CENGINE_BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"

remove_build_rpaths() {
  local binary="$1"
  local rpath
  while IFS= read -r rpath; do
    [[ "$rpath" == *PackageFrameworks* ]] || continue
    install_name_tool -delete_rpath "$rpath" "$binary"
  done < <(otool -l "$binary" | awk '/cmd LC_RPATH/ { found=1; next } found && /path / { print $2; found=0 }')
}

require_uninstrumented() {
  local binary="$1"
  if otool -l "$binary" | grep -q __llvm_prf; then
    echo "Release binary $binary contains LLVM profiling instrumentation; build with code coverage disabled" >&2
    exit 2
  fi
}

xcodebuild \
  -project "$PROJECT_PATH" \
  -scheme "$PRODUCT_NAME" \
  -configuration "$CONFIGURATION" \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  -clonedSourcePackagesDirPath "$SOURCE_PACKAGES_PATH" \
  -skipPackagePluginValidation \
  -skipMacroValidation \
  CENGINE_GIT_COMMIT="$GIT_COMMIT" \
  CENGINE_BUILD_TIME="$BUILD_TIME" \
  ENABLE_CODE_COVERAGE=NO \
  CLANG_COVERAGE_MAPPING=NO \
  build

mkdir -p "$OUTPUT_DIR"
ditto --norsrc --noextattr "$PRODUCTS_DIR/$PRODUCT_NAME" "$OUTPUT_DIR/$PRODUCT_NAME"
remove_build_rpaths "$OUTPUT_DIR/$PRODUCT_NAME"
require_uninstrumented "$OUTPUT_DIR/$PRODUCT_NAME"
codesign --force --entitlements "$ROOT_DIR/Configuration/cengine.entitlements" --sign - "$OUTPUT_DIR/$PRODUCT_NAME"
"$ROOT_DIR/Scripts/verify-entitlements.sh" "$OUTPUT_DIR/$PRODUCT_NAME"
rm -rf "$OUTPUT_DIR/share/cengine"
mkdir -p "$OUTPUT_DIR/share/cengine"
ditto "$ROOT_DIR/.build/guest/vmlinux" "$OUTPUT_DIR/share/cengine/vmlinux"
ditto "$ROOT_DIR/.build/guest/container-initramfs.cpio.gz" "$OUTPUT_DIR/share/cengine/container-initramfs.cpio.gz"
ditto "$ROOT_DIR/.build/guest/storage-initramfs.cpio.gz" "$OUTPUT_DIR/share/cengine/storage-initramfs.cpio.gz"
ditto "$ROOT_DIR/.build/guest/SHA256SUMS" "$OUTPUT_DIR/share/cengine/SHA256SUMS"

echo "Built ad-hoc Xcode-signed $OUTPUT_DIR/$PRODUCT_NAME"
