#!/usr/bin/env bash
set -euo pipefail

: "${TAG:?TAG is required}"
: "${DMG_SHA256:?DMG_SHA256 is required}"
: "${TAP_DIR:?TAP_DIR is required}"

version="${TAG#v}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release tag: $TAG" >&2; exit 2; }
[[ "$DMG_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid disk image SHA-256: $DMG_SHA256" >&2; exit 2; }
dmg_url="${DMG_URL:-https://github.com/ClarifiedLabs/cengine/releases/download/v${version}/cengine-${version}.dmg}"

mkdir -p "$TAP_DIR/Formula"
rm -f "$TAP_DIR/Casks/cengine.rb"
cat >"$TAP_DIR/Formula/cengine.rb" <<FORMULA
class Cengine < Formula
  desc "Docker Engine-compatible daemon using Apple Containerization"
  homepage "https://github.com/ClarifiedLabs/cengine"
  url "${dmg_url}"
  sha256 "${DMG_SHA256}"
  version "${version}"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos => :tahoe

  conflicts_with cask: "cengine"

  def install
    bin.install "cengine"
  end

  service do
    run [opt_bin/"cengine", "service", "run"]
    keep_alive successful_exit: false
    throttle_interval 60
    process_type :interactive
    log_path var/"log/cengine.log"
    error_log_path var/"log/cengine.log"
    environment_variables PATH: "#{std_service_path_env}:/usr/local/bin"
  end

  test do
    assert_match "cengine #{version}", shell_output("#{bin}/cengine version")
  end
end
FORMULA
