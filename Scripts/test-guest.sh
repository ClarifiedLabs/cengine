#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if command -v go >/dev/null 2>&1 && [ "$(go env GOOS)" = linux ]; then
    cd "$ROOT/Guest"
    exec go test ./...
fi
docker buildx build \
    --progress plain \
    --platform linux/arm64 \
    --file - \
    "$ROOT/Guest" <<'EOF'
FROM golang:1.25-trixie
WORKDIR /src
COPY . .
RUN go test ./...
EOF
