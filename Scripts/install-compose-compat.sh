#!/bin/bash
set -euo pipefail

version="5.4.0"
expected="bc3d1fd4c01e3af9b481fc5ea153ea7c006c77eb39be78e9af3e2e8ebecc0d61"
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
