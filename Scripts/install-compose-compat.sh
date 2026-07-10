#!/bin/bash
set -euo pipefail

version="5.3.1"
expected="32691ba1196d819fa68cbdc0aad9a5569e730a35ae40c6fdd8458110ecd69488"
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
