#!/bin/zsh
set -euo pipefail

binary=${1:?usage: verify-entitlements.sh PATH_TO_BINARY}

codesign --verify --strict --verbose=2 "$binary"
entitlements="$(codesign -d --entitlements :- "$binary" 2>/dev/null)"

if [[ "$entitlements" != *"com.apple.security.virtualization"* ]]; then
  echo "cengine binary is missing com.apple.security.virtualization" >&2
  exit 1
fi

if [[ "$entitlements" == *"com.apple.developer.networking.vmnet"* || "$entitlements" == *"com.apple.vm.networking"* ]]; then
  echo "cengine binary contains an unexpected vmnet entitlement" >&2
  exit 1
fi
