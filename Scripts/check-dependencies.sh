#!/bin/sh
set -eu

actual=$(sed -n 's/.*\.package(url: "\([^"]*\)".*/\1/p' Package.swift | sort)
expected=$(printf '%s\n' \
  'https://github.com/apple/containerization.git' \
  'https://github.com/apple/swift-nio.git' \
  'https://github.com/apple/swift-system.git' | sort)

if [ "$actual" != "$expected" ]; then
  echo 'Package.swift contains a dependency outside the approved allowlist:' >&2
  printf '%s\n' "$actual" >&2
  exit 1
fi
