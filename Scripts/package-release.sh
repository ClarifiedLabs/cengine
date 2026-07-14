#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/.build/release}"
PAYLOAD_ROOT="$BUILD_DIR/payload"
PROJECT_PATH="$ROOT_DIR/cengine.xcodeproj"
DERIVED_DATA_PATH="${XCODE_DERIVED_DATA:-$ROOT_DIR/.build/xcode-derived}"
SOURCE_PACKAGES_PATH="${XCODE_SOURCE_PACKAGES:-$ROOT_DIR/.build/xcode-source-packages}"
PRODUCTS_DIR="$DERIVED_DATA_PATH/Build/Products/Release"
PKG_IDENTIFIER="dev.cengine.app.pkg"
UNINSTALLER_IDENTIFIER="dev.cengine.uninstaller.pkg"
ENGINE_ENTITLEMENTS="$ROOT_DIR/Configuration/cengine.entitlements"
APP_ENTITLEMENTS="$ROOT_DIR/Configuration/cengine-app.entitlements"
COMPONENT_PLIST="$ROOT_DIR/Configuration/cengine-component.plist"
export COPYFILE_DISABLE=1

enabled() { case "${1:-0}" in 1|true|TRUE|yes|YES) return 0;; *) return 1;; esac; }
require_file() { [[ -e "$1" ]] || { echo "Missing $2: $1" >&2; exit 2; }; }
require_nonempty() { [[ -n "$1" ]] || { echo "Missing required release setting: $2" >&2; exit 2; }; }
project_marketing_version() {
  sed -nE 's/.*MARKETING_VERSION = ([0-9]+[.][0-9]+[.][0-9]+);.*/\1/p' "$PROJECT_PATH/project.pbxproj" | head -n 1
}
resolve_version() {
  if [[ -n "${CENGINE_RELEASE_VERSION:-}" ]]; then print -r -- "$CENGINE_RELEASE_VERSION"
  elif [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then print -r -- "${GITHUB_REF#refs/tags/v}"
  else project_marketing_version
  fi
}
remove_build_rpaths() {
  local binary="$1" rpath
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

VERSION="$(resolve_version)"
BUILD_NUMBER="${CENGINE_BUILD_NUMBER:-${GITHUB_RUN_NUMBER:-1}}"
GIT_COMMIT="${CENGINE_GIT_COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || printf unknown)}"
BUILD_TIME="${CENGINE_BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
SIGN_RELEASE="${CENGINE_SIGN_RELEASE:-0}"
NOTARIZE_RELEASE="${CENGINE_NOTARIZE:-0}"
enabled "$NOTARIZE_RELEASE" && SIGN_RELEASE=1
[[ "$VERSION" =~ '^[0-9]+[.][0-9]+[.][0-9]+$' ]] || { echo "Invalid release version '$VERSION'" >&2; exit 2; }
[[ "$BUILD_NUMBER" =~ '^[0-9]+$' ]] || { echo "Invalid build number '$BUILD_NUMBER'" >&2; exit 2; }
require_file "$ENGINE_ENTITLEMENTS" "engine entitlements"
require_file "$APP_ENTITLEMENTS" "app entitlements"
require_file "$COMPONENT_PLIST" "package component plist"
require_file "$ROOT_DIR/Configuration/dev.cengine.engine.plist" "engine launch agent plist"
require_file "$ROOT_DIR/Configuration/dev.cengine.network-helper.plist" "network helper launch daemon plist"

developer_id_application=""
installer_identity=""
team_identifier=""
if enabled "$SIGN_RELEASE"; then
  developer_id_application="${CENGINE_DEVELOPER_ID_APPLICATION:-${DEVELOPER_ID_APPLICATION:-}}"
  installer_identity="${CENGINE_DEVELOPER_ID_INSTALLER:-${DEVELOPER_ID_INSTALLER:-}}"
  require_nonempty "$developer_id_application" CENGINE_DEVELOPER_ID_APPLICATION
  require_nonempty "$installer_identity" CENGINE_DEVELOPER_ID_INSTALLER
  team_identifier="${CENGINE_TEAM_IDENTIFIER:-$(print -r -- "$developer_id_application" | sed -nE 's/.*\(([A-Z0-9]+)\)$/\1/p')}"
  require_nonempty "$team_identifier" CENGINE_TEAM_IDENTIFIER
fi

xcodebuild -project "$PROJECT_PATH" -scheme cengine -configuration Release \
  -derivedDataPath "$DERIVED_DATA_PATH" -clonedSourcePackagesDirPath "$SOURCE_PACKAGES_PATH" \
  -skipPackagePluginValidation -skipMacroValidation \
  MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  CENGINE_GIT_COMMIT="$GIT_COMMIT" CENGINE_BUILD_TIME="$BUILD_TIME" \
  CENGINE_TEAM_IDENTIFIER="$team_identifier" CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="-" \
  ENABLE_CODE_COVERAGE=NO CLANG_COVERAGE_MAPPING=NO build

SOURCE_APP="$PRODUCTS_DIR/cengine.app"
SOURCE_ENGINE="$PRODUCTS_DIR/cengine"
SOURCE_HELPER="$PRODUCTS_DIR/cengine-network-helper"
require_file "$SOURCE_APP" "cengine app"
require_file "$SOURCE_ENGINE" "cengine engine"
require_file "$SOURCE_HELPER" "network helper"

rm -rf "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR" "$PAYLOAD_ROOT/Applications" "$PAYLOAD_ROOT/usr/local/bin"
APP_PATH="$PAYLOAD_ROOT/Applications/cengine.app"
ditto --norsrc --noextattr "$SOURCE_APP" "$APP_PATH"
mkdir -p "$APP_PATH/Contents/MacOS" "$APP_PATH/Contents/Library/LaunchAgents" \
  "$APP_PATH/Contents/Library/LaunchDaemons" "$APP_PATH/Contents/Resources"
ditto --norsrc --noextattr "$SOURCE_ENGINE" "$APP_PATH/Contents/MacOS/cengine-engine"
ditto --norsrc --noextattr "$SOURCE_HELPER" "$APP_PATH/Contents/MacOS/cengine-network-helper"
ditto "$ROOT_DIR/Configuration/dev.cengine.engine.plist" "$APP_PATH/Contents/Library/LaunchAgents/dev.cengine.engine.plist"
ditto "$ROOT_DIR/Configuration/dev.cengine.network-helper.plist" "$APP_PATH/Contents/Library/LaunchDaemons/dev.cengine.network-helper.plist"
mkdir -p "$APP_PATH/Contents/Resources/guest"
ditto "$ROOT_DIR/.build/guest/vmlinux" "$APP_PATH/Contents/Resources/guest/vmlinux"
ditto "$ROOT_DIR/.build/guest/container-initramfs.cpio.gz" "$APP_PATH/Contents/Resources/guest/container-initramfs.cpio.gz"
ditto "$ROOT_DIR/.build/guest/storage-initramfs.cpio.gz" "$APP_PATH/Contents/Resources/guest/storage-initramfs.cpio.gz"
ditto "$ROOT_DIR/.build/guest/SHA256SUMS" "$APP_PATH/Contents/Resources/guest/SHA256SUMS"
remove_build_rpaths "$APP_PATH/Contents/MacOS/cengine"
remove_build_rpaths "$APP_PATH/Contents/MacOS/cengine-engine"
remove_build_rpaths "$APP_PATH/Contents/MacOS/cengine-network-helper"
require_uninstrumented "$APP_PATH/Contents/MacOS/cengine"
require_uninstrumented "$APP_PATH/Contents/MacOS/cengine-engine"
require_uninstrumented "$APP_PATH/Contents/MacOS/cengine-network-helper"
xattr -cr "$PAYLOAD_ROOT"
ln -s /Applications/cengine.app/Contents/MacOS/cengine-engine "$PAYLOAD_ROOT/usr/local/bin/cengine"

UNINSTALLER_COMPONENT_PKG="$BUILD_DIR/cengine-uninstall-component.pkg"
UNINSTALLER_DISTRIBUTION="$BUILD_DIR/cengine-uninstall.dist"
UNINSTALLER_PKG="$BUILD_DIR/cengine-uninstall.pkg"
pkgbuild --nopayload --scripts "$ROOT_DIR/Scripts/Uninstaller" --identifier "$UNINSTALLER_IDENTIFIER" \
  --version "$VERSION" "$UNINSTALLER_COMPONENT_PKG"
sed "s/@VERSION@/$VERSION/g" "$ROOT_DIR/Scripts/Uninstaller/Distribution.xml" > "$UNINSTALLER_DISTRIBUTION"
uninstaller_product_args=(
  --distribution "$UNINSTALLER_DISTRIBUTION"
  --resources "$ROOT_DIR/Scripts/Uninstaller/Resources"
  --package-path "$BUILD_DIR"
)
if enabled "$SIGN_RELEASE"; then
  uninstaller_product_args+=(--sign "$installer_identity")
fi
productbuild "${uninstaller_product_args[@]}" "$UNINSTALLER_PKG"
ditto "$UNINSTALLER_PKG" "$APP_PATH/Contents/Resources/cengine-uninstall.pkg"

if enabled "$SIGN_RELEASE"; then
  codesign --force --timestamp --options runtime --identifier dev.cengine.engine \
    --entitlements "$ENGINE_ENTITLEMENTS" --sign "$developer_id_application" "$APP_PATH/Contents/MacOS/cengine-engine"
  codesign --force --timestamp --options runtime --identifier dev.cengine.network-helper \
    --sign "$developer_id_application" "$APP_PATH/Contents/MacOS/cengine-network-helper"
  codesign --force --timestamp --options runtime --identifier dev.cengine.app \
    --entitlements "$APP_ENTITLEMENTS" --sign "$developer_id_application" "$APP_PATH"
else
  codesign --force --entitlements "$ENGINE_ENTITLEMENTS" --sign - "$APP_PATH/Contents/MacOS/cengine-engine"
  codesign --force --sign - "$APP_PATH/Contents/MacOS/cengine-network-helper"
  codesign --force --entitlements "$APP_ENTITLEMENTS" --sign - "$APP_PATH"
fi
codesign --verify --deep --strict --verbose=2 "$APP_PATH"
"$ROOT_DIR/Scripts/verify-entitlements.sh" "$APP_PATH/Contents/MacOS/cengine-engine" --require com.apple.security.virtualization
"$ROOT_DIR/Scripts/verify-entitlements.sh" "$APP_PATH/Contents/MacOS/cengine-network-helper" --forbid com.apple.vm.networking
[[ "$($APP_PATH/Contents/MacOS/cengine-engine version)" == "cengine $VERSION" ]]

component_pkg="$BUILD_DIR/cengine-component.pkg"
unsigned_pkg="$BUILD_DIR/cengine-$VERSION.unsigned.pkg"
PKG_PATH="$OUTPUT_DIR/cengine-$VERSION.pkg"
pkgbuild --root "$PAYLOAD_ROOT" --identifier "$PKG_IDENTIFIER" --version "$VERSION" \
  --install-location / --ownership recommended --component-plist "$COMPONENT_PLIST" "$component_pkg"
productbuild --package "$component_pkg" "$unsigned_pkg"
if enabled "$SIGN_RELEASE"; then
  productsign --sign "$installer_identity" "$unsigned_pkg" "$PKG_PATH"
  rm -f "$unsigned_pkg"
  pkgutil --check-signature "$PKG_PATH"
else
  mv "$unsigned_pkg" "$PKG_PATH"
fi

if enabled "$NOTARIZE_RELEASE"; then
  notarytool_args=()
  if [[ -n "${CENGINE_NOTARYTOOL_PROFILE:-}" ]]; then
    notarytool_args=(--keychain-profile "$CENGINE_NOTARYTOOL_PROFILE")
  elif [[ -n "${CENGINE_NOTARYTOOL_KEY_PATH:-${APP_STORE_CONNECT_KEY_PATH:-}}" && -n "${CENGINE_NOTARYTOOL_KEY_ID:-${APP_STORE_CONNECT_KEY_ID:-}}" && -n "${CENGINE_NOTARYTOOL_ISSUER_ID:-${APP_STORE_CONNECT_ISSUER_ID:-}}" ]]; then
    notarytool_args=(--key "${CENGINE_NOTARYTOOL_KEY_PATH:-$APP_STORE_CONNECT_KEY_PATH}" --key-id "${CENGINE_NOTARYTOOL_KEY_ID:-$APP_STORE_CONNECT_KEY_ID}" --issuer "${CENGINE_NOTARYTOOL_ISSUER_ID:-$APP_STORE_CONNECT_ISSUER_ID}")
  elif [[ -n "${CENGINE_NOTARYTOOL_APPLE_ID:-${APPLE_ID:-}}" && -n "${CENGINE_NOTARYTOOL_PASSWORD:-${APPLE_APP_SPECIFIC_PASSWORD:-}}" && -n "${CENGINE_NOTARYTOOL_TEAM_ID:-${APPLE_TEAM_ID:-}}" ]]; then
    notarytool_args=(--apple-id "${CENGINE_NOTARYTOOL_APPLE_ID:-$APPLE_ID}" --password "${CENGINE_NOTARYTOOL_PASSWORD:-$APPLE_APP_SPECIFIC_PASSWORD}" --team-id "${CENGINE_NOTARYTOOL_TEAM_ID:-$APPLE_TEAM_ID}")
  else
    echo "Missing notarytool credentials." >&2; exit 2
  fi
  xcrun notarytool submit "$PKG_PATH" --wait "${notarytool_args[@]}"
  xcrun stapler staple "$PKG_PATH"
  xcrun stapler validate "$PKG_PATH"
  spctl --assess --type install --verbose=4 "$PKG_PATH"
fi

echo "Built $PKG_PATH"
