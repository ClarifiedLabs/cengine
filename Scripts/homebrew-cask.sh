#!/usr/bin/env bash
set -euo pipefail

: "${TAG:?TAG is required}"
: "${DMG_SHA256:?DMG_SHA256 is required}"
: "${TAP_DIR:?TAP_DIR is required}"

version="${TAG#v}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release tag: $TAG" >&2; exit 2; }
[[ "$DMG_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid disk image SHA-256: $DMG_SHA256" >&2; exit 2; }

mkdir -p "$TAP_DIR/Casks"
cat >"$TAP_DIR/Casks/cengine.rb" <<CASK
cask "cengine" do
  version "${version}"
  sha256 "${DMG_SHA256}"

  url "https://github.com/ClarifiedLabs/cengine/releases/download/v#{version}/cengine-#{version}.dmg"
  name "cengine"
  desc "Docker Engine-compatible daemon using Apple Containerization"
  homepage "https://github.com/ClarifiedLabs/cengine"

  depends_on arch: :arm64
  depends_on macos: :tahoe

  binary "cengine"
end
CASK
