#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=Scripts/compat-network-helper.sh
. "$ROOT/Scripts/compat-network-helper.sh"
BINARY=${CENGINE_BINARY:-"$ROOT/.build/xcode-derived/Build/Products/test-compat/cengine"}
HELPER=$(compat_network_helper_local_for_binary "$BINARY")
EXPECTED=$("$ROOT/Scripts/network-helper-fingerprint.sh")
INSTALLED=$(compat_network_helper_installed_fingerprint 2>/dev/null || true)

printf 'host: macOS %s (%s)\n' "$(/usr/bin/sw_vers -productVersion)" "$(/usr/bin/uname -m)"
printf 'binary: %s\n' "$BINARY"
printf 'local helper: %s\n' "$HELPER"
printf 'service: %s\n' "$compat_network_helper_service_name"
printf 'expected fingerprint: %s\n' "$EXPECTED"
printf 'installed fingerprint: %s\n' "${INSTALLED:-missing}"

[ "$(/usr/bin/uname -m)" = arm64 ] || {
    echo "compatibility tests require Apple silicon" >&2
    exit 1
}
major=$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d. -f1)
[ "$major" -ge 26 ] || {
    echo "compatibility tests require macOS 26 or newer" >&2
    exit 1
}
"$ROOT/Scripts/check-compat-network-pools.py"

if ! compat_network_helper_is_current "$EXPECTED" "$HELPER"; then
    echo "compatibility helper is missing or stale; make test-compat will install it" >&2
    exit 1
fi
for path in "$BINARY" "$HELPER"; do
    [ -x "$path" ] || {
        echo "missing compatibility executable: $path" >&2
        exit 1
    }
    /usr/bin/codesign --verify --strict "$path"
done
compat_network_helper_export_environment "$EXPECTED"
"$BINARY" network-helper status
