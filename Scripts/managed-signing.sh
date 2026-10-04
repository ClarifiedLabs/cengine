#!/bin/sh
# Shared build-time signing checks. A caller-selected identity is not a runtime
# trust override: the signed binaries and embedded build team must agree.
managed_signing_team() {
    printf '%s\n' "$1" | /usr/bin/python3 -c '
import re, sys
match = re.fullmatch(r"Developer ID Application: [^\r\n]+ \(([A-Z0-9]{10})\)\n?", sys.stdin.read())
if not match:
    sys.exit("a full Developer ID Application signing identity is required")
print(match[1])
'
}

managed_signing_verify() {
    _ms_path=$1 _ms_identifier=$2 _ms_team=$3
    codesign --verify --strict -R "=anchor apple generic and identifier \"$_ms_identifier\" and certificate leaf[subject.OU] = \"$_ms_team\"" "$_ms_path" || return $?
    _ms_details=$(codesign -dv --verbose=4 "$_ms_path" 2>&1) || return $?
    printf '%s\n' "$_ms_details" | /usr/bin/grep -q '^Authority=Developer ID Application:' || {
        echo "managed executable lacks Developer ID signing: $_ms_path" >&2; return 1;
    }
    printf '%s\n' "$_ms_details" | /usr/bin/grep -q 'flags=.*runtime' || {
        echo "managed executable lacks hardened runtime: $_ms_path" >&2; return 1;
    }
}
