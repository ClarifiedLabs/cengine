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
    def test_generates_service_formula_and_removes_cask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "Casks").mkdir()
            (root / "Casks/cengine.rb").write_text("old cask")
            subprocess.run([SCRIPT], check=True, env=os.environ | {
                "TAG": "v1.2.3", "DMG_SHA256": "a" * 64, "TAP_DIR": directory,
            })
            formula = (root / "Formula/cengine.rb").read_text()
            self.assertIn('version "1.2.3"', formula)
            self.assertIn("cengine-1.2.3.dmg", formula)
            self.assertIn('depends_on arch: :arm64', formula)
            self.assertIn('depends_on :macos => :tahoe', formula)
            self.assertIn('conflicts_with cask: "cengine"', formula)
            self.assertIn('bin.install "cengine"', formula)
            self.assertIn('run [opt_bin/"cengine", "service", "run"]', formula)
            self.assertIn('keep_alive successful_exit: false', formula)
            self.assertIn('throttle_interval 60', formula)
            self.assertIn('process_type :interactive', formula)
            self.assertIn('environment_variables PATH:', formula)
            self.assertFalse((root / "Casks/cengine.rb").exists())

    def test_rejects_invalid_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([SCRIPT], capture_output=True, text=True, env=os.environ | {
                "TAG": "v1.2.3", "DMG_SHA256": "bad", "TAP_DIR": directory,
            })
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
