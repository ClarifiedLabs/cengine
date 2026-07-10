#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/release.py"
spec = importlib.util.spec_from_file_location("release_tool", SCRIPT)
release_tool = importlib.util.module_from_spec(spec)
assert spec.loader
sys.modules[spec.name] = release_tool
spec.loader.exec_module(release_tool)


def env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}


def git(root: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, text=True, capture_output=True, env=env()).stdout.strip()


def write_project(root: pathlib.Path, version: str = "0.0.1") -> None:
    path = root / release_tool.PROJECT_FILE
    path.parent.mkdir(parents=True)
    path.write_text(f"MARKETING_VERSION = {version};\nMARKETING_VERSION = {version};\n")


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        git(self.root, "init")
        git(self.root, "checkout", "-b", "main")
        git(self.root, "config", "user.name", "Release Test")
        git(self.root, "config", "user.email", "release@example.com")
        write_project(self.root)
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "chore: initialize")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_initial_patch_uses_project_version(self) -> None:
        self.assertEqual(release_tool.resolve_version(self.root, "patch"), "0.0.1")

    def test_patch_increments_latest_tag(self) -> None:
        git(self.root, "tag", "-a", "v0.0.1", "-m", "v0.0.1")
        self.assertEqual(release_tool.resolve_version(self.root, "patch"), "0.0.2")

    def test_updates_every_marketing_version(self) -> None:
        count = release_tool.update_marketing_version(self.root, "1.2.3")
        self.assertEqual(count, 2)
        self.assertEqual((self.root / release_tool.PROJECT_FILE).read_text().count("1.2.3"), 2)

    def test_release_creates_conventional_commit_and_tag(self) -> None:
        git(self.root, "tag", "-a", "v0.0.1", "-m", "v0.0.1")
        release_tool.create_release(self.root, "patch", False, False)
        self.assertEqual(git(self.root, "tag", "-l", "v0.0.2"), "v0.0.2")
        self.assertEqual(git(self.root, "log", "-1", "--pretty=%s"), "chore(release): bump version to v0.0.2")

    def test_dry_run_changes_nothing(self) -> None:
        original = (self.root / release_tool.PROJECT_FILE).read_text()
        release_tool.create_release(self.root, "1.0.0", True, False)
        self.assertEqual((self.root / release_tool.PROJECT_FILE).read_text(), original)
        self.assertEqual(git(self.root, "tag", "-l", "v1.0.0"), "")

    def test_rejects_v_prefix(self) -> None:
        with self.assertRaisesRegex(release_tool.ReleaseError, "must not start"):
            release_tool.resolve_version(self.root, "v1.0.0")


if __name__ == "__main__":
    unittest.main()
