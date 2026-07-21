#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

{
    for path in \
        "$ROOT"/Sources/CEngineNetworkHelper/*.swift \
        "$ROOT/Sources/CEngineCore/PrivilegedPortProtocol.swift" \
        "$ROOT/Sources/CEngineCore/EngineError.swift" \
        "$ROOT/Sources/CEngineCore/VMNetIPv4Configuration.swift" \
        "$ROOT/Configuration/network-helper-Info.plist"
    do
        relative=${path#"$ROOT/"}
        printf 'file:%s\n' "$relative"
        /bin/cat "$path"
        printf '\n'
    done
    printf 'swiftc:'
    /usr/bin/xcrun swiftc --version 2>&1
    printf 'xcode:'
    /usr/bin/xcodebuild -version
    printf 'sdk:'
    /usr/bin/xcrun --sdk macosx --show-sdk-build-version
} | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1 }'
