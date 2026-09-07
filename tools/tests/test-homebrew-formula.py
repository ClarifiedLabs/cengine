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
            self.assertIn("postflight_steps do", cask)
            self.assertNotIn("postflight do", cask)
            self.assertIn('run "/bin/sh"', cask)
            self.assertIn('"/usr/bin/open",', cask)
            self.assertIn('\'"$@" || true\'', cask)
            self.assertNotIn("system_command", cask)
            self.assertIn(
                '"/Applications/cengine.app", "--args", "--opened-by-installer",',
                cask,
            )
            postflight = cask.split("postflight_steps do", 1)[1].split("\n  end", 1)[0]
            self.assertNotIn("must_succeed:", postflight)
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
    def test_homebrew_loads_cask_and_postflight_is_best_effort(self) -> None:
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
                "steps = cask.artifacts.grep(Cask::Artifact::PostflightSteps).flat_map(&:steps); "
                "puts JSON.generate(steps)",
            ], capture_output=True, text=True, timeout=60, env=os.environ | {
                "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1",
                "HOMEBREW_DEVELOPER": "1",
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            steps = json.loads(result.stdout)
            self.assertEqual(len(steps), 1)
            step = steps[0]
            self.assertEqual(step["type"], "run")
            self.assertEqual(step["command"]["path"], "/bin/sh")
            args = step["args"]
            self.assertEqual(args[:4], ["-c", '"$@" || true', "--", "/usr/bin/open"])
            self.assertEqual(args[4:], [
                "/Applications/cengine.app", "--args", "--opened-by-installer",
            ])
            # Substitute only the executable: a headless runner's failed `open`
            # must not fail installation, and arguments must survive unchanged.
            mock_open = root / "mock open"
            for status in (0, 1, 42):
                with self.subTest(status=status):
                    mock_open.write_text(f'#!/bin/sh\nprintf \'%s\\n\' "$@"\nexit {status}\n')
                    mock_open.chmod(0o755)
                    result = subprocess.run([
                        "/bin/sh", *args[:3], str(mock_open), *args[4:], "argument with spaces",
                    ], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), args[4:] + ["argument with spaces"])

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
