#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/.build/release}"
PAYLOAD_ROOT="$BUILD_DIR/payload"
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
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="-" \
  build

PRODUCT="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION/$PRODUCT_NAME"
require_file "$PRODUCT" "cengine product"

rm -rf "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR" "$PAYLOAD_ROOT/usr/local/bin"
CLI_PATH="$PAYLOAD_ROOT/usr/local/bin/$PRODUCT_NAME"
PKG_PATH="$OUTPUT_DIR/cengine-$VERSION.pkg"
ditto --norsrc --noextattr "$PRODUCT" "$CLI_PATH"
xattr -cr "$PAYLOAD_ROOT"

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
fi

"$ROOT_DIR/Scripts/verify-entitlements.sh" "$CLI_PATH"
actual_version="$($CLI_PATH version)"
[[ "$actual_version" == "cengine $VERSION" ]] || { echo "Built binary reported unexpected version: $actual_version" >&2; exit 1; }

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

  xcrun notarytool submit "$PKG_PATH" --wait "${notarytool_args[@]}"
  xcrun stapler staple "$PKG_PATH"
  xcrun stapler validate "$PKG_PATH"
  spctl --assess --type install --verbose=4 "$PKG_PATH"
fi

echo "Built $PKG_PATH"
