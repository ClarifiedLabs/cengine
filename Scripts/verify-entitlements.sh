#!/bin/zsh
set -euo pipefail

binary=${1:?usage: verify-entitlements.sh PATH_TO_BINARY [--require|--forbid] ENTITLEMENT}
mode=${2:---require}
entitlement=${3:-com.apple.security.virtualization}

codesign --verify --strict --verbose=2 "$binary"
entitlements="$(codesign -d --entitlements :- "$binary" 2>/dev/null)"

case "$mode" in
  --require)
    if [[ "$entitlements" != *"$entitlement"* ]]; then
      echo "$binary is missing $entitlement" >&2
      exit 1
    fi
    ;;
  --forbid)
    if [[ "$entitlements" == *"$entitlement"* ]]; then
      echo "$binary must not claim $entitlement" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown verification mode: $mode" >&2
    exit 2
    ;;
esac
