#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts/homebrew-formula.sh"


class HomebrewFormulaTests(unittest.TestCase):
    def test_generates_pkg_cask_and_removes_formula(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "Formula").mkdir()
            (root / "Formula/cengine.rb").write_text("old formula")
            subprocess.run([SCRIPT], check=True, env=os.environ | {
                "TAG": "v1.2.3", "PKG_SHA256": "a" * 64, "TAP_DIR": directory,
            })
            cask = (root / "Casks/cengine.rb").read_text()
            self.assertIn('version "1.2.3"', cask)
            self.assertIn("cengine-1.2.3.pkg", cask)
            self.assertIn('depends_on arch: :arm64', cask)
            self.assertIn("depends_on macos: :tahoe", cask)
            self.assertIn('depends_on formula: "docker"', cask)
            self.assertNotIn('depends_on macos: ">= :tahoe"', cask)
            self.assertIn('pkg "cengine-1.2.3.pkg"', cask)
            # LaunchServices is forbidden in Homebrew's flight-step sandbox.
            # The vendor PKG owns the installer launch, not a cask workaround.
            self.assertNotIn("postflight", cask)
            self.assertNotIn("installer script:", cask)
            self.assertNotIn("/usr/bin/open", cask)
            self.assertNotIn("--opened-by-installer", cask)
            self.assertNotIn("system_command", cask)
            self.assertEqual(cask.count("must_succeed: false"), 1)
            self.assertIn("early_script:", cask)
            self.assertIn('executable: "/bin/sh"', cask)
            self.assertIn('if [ -x "$1" ]; then "$1" --uninstall-support; fi', cask)
            self.assertIn('"/Applications/cengine.app/Contents/MacOS/cengine"', cask)
            self.assertNotIn("must_succeed: true", cask)
            self.assertIn("launchctl:", cask)
            self.assertIn('"dev.cengine.engine"', cask)
            self.assertIn('"dev.cengine.network-helper"', cask)
            self.assertIn('quit: "dev.cengine.app"', cask)
            self.assertIn('pkgutil: "dev.cengine.app.pkg"', cask)
            self.assertIn('"/Applications/cengine.app"', cask)
            self.assertIn('"/usr/local/bin/cengine"', cask)
            for path in [
                "~/.cengine",
                "~/Library/Application Support/cengine",
                "~/Library/Caches/dev.cengine.app",
                "~/Library/Logs/cengine",
                "~/Library/Preferences/dev.cengine.app.plist",
                "~/Library/Saved Application State/dev.cengine.app.savedState",
            ]:
                self.assertIn(f'"{path}"', cask)
            self.assertIn("Open cengine after a fresh install", cask)
            self.assertIn("restores an active cengine Docker context", cask)
            self.assertIn("brew uninstall --cask --zap cengine", cask)
            self.assertFalse((root / "Formula/cengine.rb").exists())

    @unittest.skipUnless(shutil.which("brew"), "Homebrew is required to load the cask DSL")
    def test_homebrew_installation_uses_only_the_vendor_pkg(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            subprocess.run([SCRIPT], check=True, env=os.environ | {
                "TAG": "v1.2.3", "PKG_SHA256": "a" * 64, "TAP_DIR": directory,
            })
            # Parse with Homebrew itself, without installing a package or launching the app.
            cask_path = json.dumps(str(root / "Casks/cengine.rb"))
            result = subprocess.run([
                "brew", "ruby", "-e",
                'require "cask/cask_loader"; '
                f"cask = Cask::CaskLoader::FromContentLoader.new(File.read({cask_path})).load(config: nil); "
                "install_artifacts = cask.artifacts.select { |artifact| artifact.respond_to?(:install_phase) }; "
                "puts JSON.generate({ "
                "install_artifacts: install_artifacts.map { |artifact| artifact.class.name }, "
                "packages: cask.artifacts.grep(Cask::Artifact::Pkg).map(&:summarize) })",
            ], capture_output=True, text=True, timeout=60, env=os.environ | {
                "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1",
                "HOMEBREW_DEVELOPER": "1",
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            artifacts = json.loads(result.stdout)
            self.assertEqual(artifacts["install_artifacts"], ["Cask::Artifact::Pkg"])
            self.assertEqual(artifacts["packages"], ["cengine-1.2.3.pkg"])

    def test_uninstall_script_skips_missing_app_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([SCRIPT], check=True, env=os.environ | {
                "TAG": "v1.2.3", "PKG_SHA256": "a" * 64, "TAP_DIR": directory,
            })
            cask = (pathlib.Path(directory) / "Casks/cengine.rb").read_text()
            self.assertIn('executable: "/bin/sh"', cask)
            self.assertIn('if [ -x "$1" ]; then "$1" --uninstall-support; fi', cask)
            self.assertNotIn(
                'executable: "/Applications/cengine.app/Contents/MacOS/cengine"',
                cask,
            )

    def test_rejects_invalid_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([SCRIPT], capture_output=True, text=True, env=os.environ | {
                "TAG": "v1.2.3", "PKG_SHA256": "bad", "TAP_DIR": directory,
            })
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
