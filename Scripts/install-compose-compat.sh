#!/bin/bash
set -euo pipefail

version="5.5.0"
expected="6777710e5a5db5709e5f4b5985844e74b73cc1a6123e3a6690b6ababf2deaf51"
destination="${1:-$HOME/.docker/cli-plugins/docker-compose}"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT

curl -fsSL "https://github.com/docker/compose/releases/download/v${version}/docker-compose-darwin-aarch64" -o "$temporary"
actual="$(shasum -a 256 "$temporary" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
    echo "Docker Compose ${version} checksum mismatch: expected ${expected}, found ${actual}" >&2
    exit 1
fi
mkdir -p "$(dirname "$destination")"
install -m 0755 "$temporary" "$destination"
