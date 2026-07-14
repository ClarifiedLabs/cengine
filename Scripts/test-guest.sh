#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${CENGINE_GUEST_TEST_IMAGE:-golang:1.25-trixie}

"$ROOT/Scripts/run-isolated-cengine.sh" sh -eu -c '
    docker pull "$1"
    docker run --rm \
        --mount "type=bind,src=$2,dst=/src,readonly" \
        --workdir /src \
        "$1" go test ./...
' cengine-guest-tests "$IMAGE" "$ROOT/guest"
