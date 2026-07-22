#!/usr/bin/env bash
set -euo pipefail

: "${TAG:?TAG is required}"
: "${PKG_SHA256:?PKG_SHA256 is required}"
: "${TAP_DIR:?TAP_DIR is required}"
version="${TAG#v}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release tag: $TAG" >&2; exit 2; }
[[ "$PKG_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid SHA-256" >&2; exit 2; }
pkg_url="${PKG_URL:-https://github.com/ClarifiedLabs/cengine/releases/download/v${version}/cengine-${version}.pkg}"

mkdir -p "$TAP_DIR/Casks"
rm -f "$TAP_DIR/Formula/cengine.rb"
cat >"$TAP_DIR/Casks/cengine.rb" <<CASK
cask "cengine" do
  version "${version}"
  sha256 "${PKG_SHA256}"

  url "${pkg_url}"
  name "cengine"
  desc "Docker Engine-compatible daemon using one raw Linux VM per container"
  homepage "https://github.com/ClarifiedLabs/cengine"

  depends_on arch: :arm64
  depends_on macos: :tahoe

  pkg "cengine-${version}.pkg"

  postflight do
    system_command "/usr/bin/open",
                   args: ["/Applications/cengine.app", "--args", "--opened-by-installer"],
                   must_succeed: false
  end

  uninstall early_script: {
              executable: "/bin/sh",
              args: [
                "-c",
                'if [ -x "\$1" ]; then "\$1" --uninstall-support; fi',
                "--",
                "/Applications/cengine.app/Contents/MacOS/cengine",
              ],
              must_succeed: true,
            },
            launchctl: ["dev.cengine.engine", "dev.cengine.network-helper"],
            quit: "dev.cengine.app",
            pkgutil: "dev.cengine.app.pkg",
            delete: ["/Applications/cengine.app", "/usr/local/bin/cengine"]

  zap trash: [
    "~/.cengine",
    "~/Library/Application Support/cengine",
    "~/Library/Caches/dev.cengine.app",
    "~/Library/Logs/cengine",
    "~/Library/Preferences/dev.cengine.app.plist",
    "~/Library/Saved Application State/dev.cengine.app.savedState",
  ]

  caveats <<~EOS
    Open cengine after a fresh install to enable its services. Upgrades resume a previously enabled engine.
    A standard reinstall restores an active cengine Docker context on the next engine start.
    A standard uninstall preserves VM and image data. To remove all cengine data instead:
      brew uninstall --cask --zap cengine
  EOS
end
CASK
