#!/bin/sh
set -eu

binary=${1:?usage: sign.sh PATH_TO_BINARY}
entitlements="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/Configuration/cengine.entitlements"

/usr/bin/codesign --force --sign - --timestamp=none --entitlements "$entitlements" "$binary"

actual=$(/usr/bin/codesign -d --entitlements :- "$binary" 2>/dev/null)
case "$actual" in
  *com.apple.security.virtualization*) ;;
  *)
    echo "cengine binary is missing the virtualization entitlement" >&2
    exit 1
    ;;
esac
