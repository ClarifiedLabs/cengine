#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
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
            self.assertNotIn('depends_on macos: ">= :tahoe"', cask)
            self.assertIn('pkg "cengine-1.2.3.pkg"', cask)
            self.assertIn("postflight do", cask)
            self.assertIn('system_command "/usr/bin/open"', cask)
            self.assertIn('args: ["/Applications/cengine.app"]', cask)
            self.assertIn("must_succeed: false", cask)
            self.assertIn("early_script:", cask)
            self.assertIn('executable: "/bin/sh"', cask)
            self.assertIn('if [ -x "$1" ]; then "$1" --uninstall-support; fi', cask)
            self.assertIn('"/Applications/cengine.app/Contents/MacOS/cengine"', cask)
            self.assertIn("must_succeed: false", cask)
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
            self.assertIn("brew uninstall --cask --zap cengine", cask)
            self.assertFalse((root / "Formula/cengine.rb").exists())

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
