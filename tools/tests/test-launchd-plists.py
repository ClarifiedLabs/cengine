#!/usr/bin/env python3
"""Validates the launchd service definitions the app registers via SMAppService.

These plists replaced the Homebrew formula's `service` block, whose values were
asserted by test-homebrew-formula.py; a typo here would leave the engine agent
or privileged-port helper unable to launch on end-user machines.
"""
from __future__ import annotations

import pathlib
import plistlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ENGINE_PLIST = ROOT / "Configuration/dev.cengine.engine.plist"
HELPER_PLIST = ROOT / "Configuration/dev.cengine.network-helper.plist"


class LaunchdPlistTests(unittest.TestCase):
    def test_engine_launch_agent(self) -> None:
        plist = plistlib.loads(ENGINE_PLIST.read_bytes())
        self.assertEqual(plist["Label"], "dev.cengine.engine")
        self.assertEqual(plist["BundleProgram"], "Contents/MacOS/cengine-engine")
        self.assertEqual(plist["ProgramArguments"], ["cengine-engine", "service", "run"])
        self.assertIs(plist["RunAtLoad"], True)
        self.assertEqual(plist["KeepAlive"], {"SuccessfulExit": False})
        self.assertEqual(plist["ThrottleInterval"], 60)
        self.assertEqual(plist["ProcessType"], "Interactive")

    def test_network_helper_launch_daemon(self) -> None:
        plist = plistlib.loads(HELPER_PLIST.read_bytes())
        self.assertEqual(plist["Label"], "dev.cengine.network-helper")
        self.assertEqual(plist["BundleProgram"], "Contents/MacOS/cengine-network-helper")
        self.assertEqual(plist["MachServices"], {"dev.cengine.network-helper": True})
        self.assertEqual(plist["ProcessType"], "Interactive")

    def test_labels_match_cask_launchctl_teardown(self) -> None:
        cask_script = (ROOT / "Scripts/homebrew-formula.sh").read_text()
        for plist_path in (ENGINE_PLIST, HELPER_PLIST):
            label = plistlib.loads(plist_path.read_bytes())["Label"]
            self.assertIn(f'"{label}"', cask_script)


if __name__ == "__main__":
    unittest.main()
