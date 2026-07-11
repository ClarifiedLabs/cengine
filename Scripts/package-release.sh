#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/.build/release}"
PAYLOAD_ROOT="$BUILD_DIR/payload"
DMG_ROOT="$BUILD_DIR/dmg"
PROJECT_PATH="$ROOT_DIR/cengine.xcodeproj"
DERIVED_DATA_PATH="${XCODE_DERIVED_DATA:-$ROOT_DIR/.build/xcode-derived}"
SOURCE_PACKAGES_PATH="${XCODE_SOURCE_PACKAGES:-$ROOT_DIR/.build/xcode-source-packages}"
CONFIGURATION="Release"

PRODUCT_NAME="cengine"
BUNDLE_IDENTIFIER="dev.cengine.engine"
PKG_IDENTIFIER="dev.cengine.engine.pkg"
ENTITLEMENTS_PATH="$ROOT_DIR/Configuration/cengine.entitlements"

export COPYFILE_DISABLE=1

enabled() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

remove_build_rpaths() {
  local binary="$1"
  local rpath
  while IFS= read -r rpath; do
    [[ "$rpath" == *PackageFrameworks* ]] || continue
    install_name_tool -delete_rpath "$rpath" "$binary"
  done < <(otool -l "$binary" | awk '/cmd LC_RPATH/ { found=1; next } found && /path / { print $2; found=0 }')
}

project_marketing_version() {
  sed -nE 's/.*MARKETING_VERSION = ([0-9]+[.][0-9]+[.][0-9]+);.*/\1/p' \
    "$PROJECT_PATH/project.pbxproj" | head -n 1
}

resolve_version() {
  if [[ -n "${CENGINE_RELEASE_VERSION:-}" ]]; then
    printf '%s\n' "$CENGINE_RELEASE_VERSION"
  elif [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
    printf '%s\n' "${GITHUB_REF#refs/tags/v}"
  else
    project_marketing_version
  fi
}

require_file() {
  [[ -e "$1" ]] || { echo "Missing $2: $1" >&2; exit 2; }
}

require_nonempty() {
  [[ -n "$1" ]] || { echo "Missing required release setting: $2" >&2; exit 2; }
}

VERSION="$(resolve_version)"
BUILD_NUMBER="${CENGINE_BUILD_NUMBER:-${GITHUB_RUN_NUMBER:-1}}"
GIT_COMMIT="${CENGINE_GIT_COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short=7 HEAD 2>/dev/null || printf unknown)}"
BUILD_TIME="${CENGINE_BUILD_TIME:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}"
SIGN_RELEASE="${CENGINE_SIGN_RELEASE:-0}"
NOTARIZE_RELEASE="${CENGINE_NOTARIZE:-0}"

if enabled "$NOTARIZE_RELEASE"; then
  SIGN_RELEASE=1
fi

[[ "$VERSION" =~ '^[0-9]+[.][0-9]+[.][0-9]+$' ]] || { echo "Invalid release version '$VERSION' (expected X.Y.Z)" >&2; exit 2; }
[[ "$BUILD_NUMBER" =~ '^[0-9]+$' ]] || { echo "Invalid build number '$BUILD_NUMBER' (expected integer)" >&2; exit 2; }

xcodebuild \
  -project "$PROJECT_PATH" \
  -scheme "$PRODUCT_NAME" \
  -configuration "$CONFIGURATION" \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  -clonedSourcePackagesDirPath "$SOURCE_PACKAGES_PATH" \
  -skipPackagePluginValidation \
  -skipMacroValidation \
  MARKETING_VERSION="$VERSION" \
  CURRENT_PROJECT_VERSION="$BUILD_NUMBER" \
  CENGINE_GIT_COMMIT="$GIT_COMMIT" \
  CENGINE_BUILD_TIME="$BUILD_TIME" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="-" \
  build

PRODUCT="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION/$PRODUCT_NAME"
require_file "$PRODUCT" "cengine product"

rm -rf "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR" "$PAYLOAD_ROOT/usr/local/bin" "$DMG_ROOT"
CLI_PATH="$PAYLOAD_ROOT/usr/local/bin/$PRODUCT_NAME"
PKG_PATH="$OUTPUT_DIR/cengine-$VERSION.pkg"
DMG_PATH="$OUTPUT_DIR/cengine-$VERSION.dmg"
ditto --norsrc --noextattr "$PRODUCT" "$CLI_PATH"
xattr -cr "$PAYLOAD_ROOT"
remove_build_rpaths "$CLI_PATH"

if enabled "$SIGN_RELEASE"; then
  developer_id_application="${CENGINE_DEVELOPER_ID_APPLICATION:-${DEVELOPER_ID_APPLICATION:-}}"
  require_nonempty "$developer_id_application" "CENGINE_DEVELOPER_ID_APPLICATION"
  require_file "$ENTITLEMENTS_PATH" "release entitlements"

  codesign --force \
    --timestamp \
    --options runtime \
    --entitlements "$ENTITLEMENTS_PATH" \
    --identifier "$BUNDLE_IDENTIFIER" \
    --sign "$developer_id_application" \
    "$CLI_PATH"
else
  echo "Skipping Developer ID signing. Set CENGINE_SIGN_RELEASE=1 for public release packages."
  codesign --force --entitlements "$ENTITLEMENTS_PATH" --sign - "$CLI_PATH"
fi

"$ROOT_DIR/Scripts/verify-entitlements.sh" "$CLI_PATH"
actual_version="$($CLI_PATH version)"
[[ "$actual_version" == "cengine $VERSION" ]] || { echo "Built binary reported unexpected version: $actual_version" >&2; exit 1; }

ditto --norsrc --noextattr "$CLI_PATH" "$DMG_ROOT/$PRODUCT_NAME"

component_pkg="$BUILD_DIR/cengine-component.pkg"
unsigned_pkg="$BUILD_DIR/cengine-$VERSION.unsigned.pkg"
pkgbuild \
  --root "$PAYLOAD_ROOT" \
  --identifier "$PKG_IDENTIFIER" \
  --version "$VERSION" \
  --install-location / \
  --ownership recommended \
  "$component_pkg"
productbuild --package "$component_pkg" "$unsigned_pkg"

if enabled "$SIGN_RELEASE"; then
  installer_identity="${CENGINE_DEVELOPER_ID_INSTALLER:-${DEVELOPER_ID_INSTALLER:-}}"
  require_nonempty "$installer_identity" "CENGINE_DEVELOPER_ID_INSTALLER"
  productsign --sign "$installer_identity" "$unsigned_pkg" "$PKG_PATH"
  rm -f "$unsigned_pkg"
  pkgutil --check-signature "$PKG_PATH"
else
  mv "$unsigned_pkg" "$PKG_PATH"
fi

hdiutil create \
  -volname "$PRODUCT_NAME" \
  -srcfolder "$DMG_ROOT" \
  -format UDZO \
  -ov \
  "$DMG_PATH"

if enabled "$SIGN_RELEASE"; then
  codesign --force \
    --timestamp \
    --sign "$developer_id_application" \
    "$DMG_PATH"
  codesign --verify --strict --verbose=2 "$DMG_PATH"
fi
hdiutil verify "$DMG_PATH"

if enabled "$NOTARIZE_RELEASE"; then
  notarytool_args=()
  if [[ -n "${CENGINE_NOTARYTOOL_PROFILE:-}" ]]; then
    notarytool_args=(--keychain-profile "$CENGINE_NOTARYTOOL_PROFILE")
  elif [[ -n "${CENGINE_NOTARYTOOL_KEY_PATH:-${APP_STORE_CONNECT_KEY_PATH:-}}" && -n "${CENGINE_NOTARYTOOL_KEY_ID:-${APP_STORE_CONNECT_KEY_ID:-}}" && -n "${CENGINE_NOTARYTOOL_ISSUER_ID:-${APP_STORE_CONNECT_ISSUER_ID:-}}" ]]; then
    notarytool_args=(
      --key "${CENGINE_NOTARYTOOL_KEY_PATH:-$APP_STORE_CONNECT_KEY_PATH}"
      --key-id "${CENGINE_NOTARYTOOL_KEY_ID:-$APP_STORE_CONNECT_KEY_ID}"
      --issuer "${CENGINE_NOTARYTOOL_ISSUER_ID:-$APP_STORE_CONNECT_ISSUER_ID}"
    )
  elif [[ -n "${CENGINE_NOTARYTOOL_APPLE_ID:-${APPLE_ID:-}}" && -n "${CENGINE_NOTARYTOOL_PASSWORD:-${APPLE_APP_SPECIFIC_PASSWORD:-}}" && -n "${CENGINE_NOTARYTOOL_TEAM_ID:-${APPLE_TEAM_ID:-}}" ]]; then
    notarytool_args=(
      --apple-id "${CENGINE_NOTARYTOOL_APPLE_ID:-$APPLE_ID}"
      --password "${CENGINE_NOTARYTOOL_PASSWORD:-$APPLE_APP_SPECIFIC_PASSWORD}"
      --team-id "${CENGINE_NOTARYTOOL_TEAM_ID:-$APPLE_TEAM_ID}"
    )
  else
    echo "Missing notarytool credentials." >&2
    exit 2
  fi

  for artifact in "$PKG_PATH" "$DMG_PATH"; do
    xcrun notarytool submit "$artifact" --wait "${notarytool_args[@]}"
    xcrun stapler staple "$artifact"
    xcrun stapler validate "$artifact"
  done
  spctl --assess --type install --verbose=4 "$PKG_PATH"
  spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG_PATH"
fi

echo "Built $PKG_PATH"
echo "Built $DMG_PATH"
