#!/usr/bin/env python3
from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts/homebrew-cask.sh"


class HomebrewCaskTests(unittest.TestCase):
    def test_generates_cengine_cask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run([SCRIPT], check=True, env=os.environ | {
                "TAG": "v1.2.3", "DMG_SHA256": "a" * 64, "TAP_DIR": directory,
            })
            cask = (pathlib.Path(directory) / "Casks/cengine.rb").read_text()
            self.assertIn('version "1.2.3"', cask)
            self.assertIn("ClarifiedLabs/cengine/releases/download", cask)
            self.assertIn("cengine-#{version}.dmg", cask)
            self.assertIn('binary "cengine"', cask)
            self.assertNotIn('pkg "', cask)
            self.assertNotIn("pkgutil", cask)

    def test_rejects_invalid_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([SCRIPT], capture_output=True, text=True, env=os.environ | {
                "TAG": "v1.2.3", "DMG_SHA256": "bad", "TAP_DIR": directory,
            })
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
