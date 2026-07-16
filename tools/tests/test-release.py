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


def write_kernel_release(root: pathlib.Path, tag: str = "kernel-v0.0.1") -> None:
    path = root / release_tool.KERNEL_RELEASE_FILE
    path.parent.mkdir(parents=True)
    path.write_text(f"{tag}\n")


def write_kernel_source_version(root: pathlib.Path, version: str = "6.18.35") -> None:
    path = root / release_tool.KERNEL_SOURCE_VERSION_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{version}\n")


class ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        git(self.root, "init")
        git(self.root, "checkout", "-b", "main")
        git(self.root, "config", "user.name", "Release Test")
        git(self.root, "config", "user.email", "release@example.com")
        write_project(self.root)
        write_kernel_release(self.root)
        write_kernel_source_version(self.root)
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

    def test_automatic_kernel_release_starts_at_revision_one(self) -> None:
        self.assertEqual(release_tool.next_kernel_release_version(self.root), "6.18.35-1")

    def test_automatic_kernel_release_uses_highest_local_and_origin_revision(self) -> None:
        git(self.root, "tag", "-a", "kernel-v6.18.35-1", "-m", "kernel-v6.18.35-1")
        git(self.root, "tag", "-a", "kernel-v6.18.36-99", "-m", "unrelated")
        with tempfile.TemporaryDirectory() as temporary:
            remote = pathlib.Path(temporary) / "origin.git"
            remote.mkdir()
            git(remote, "init", "--bare")
            git(self.root, "remote", "add", "origin", str(remote))
            git(self.root, "tag", "-a", "kernel-v6.18.35-3", "-m", "kernel-v6.18.35-3")
            git(self.root, "push", "origin", "kernel-v6.18.35-3")
            git(self.root, "tag", "-d", "kernel-v6.18.35-3")
            self.assertEqual(release_tool.next_kernel_release_version(self.root), "6.18.35-4")

    def test_automatic_kernel_release_updates_config_and_creates_tag(self) -> None:
        release_tool.create_kernel_release(self.root, None, False, False)
        self.assertEqual(
            (self.root / release_tool.KERNEL_RELEASE_FILE).read_text(),
            "kernel-v6.18.35-1\n",
        )
        self.assertEqual(git(self.root, "tag", "-l", "kernel-v6.18.35-1"), "kernel-v6.18.35-1")

    def test_kernel_release_updates_config_and_creates_tag(self) -> None:
        release_tool.create_kernel_release(self.root, "6.18.35-2", False, False)
        self.assertEqual(
            (self.root / release_tool.KERNEL_RELEASE_FILE).read_text(),
            "kernel-v6.18.35-2\n",
        )
        self.assertEqual(git(self.root, "tag", "-l", "kernel-v6.18.35-2"), "kernel-v6.18.35-2")
        self.assertEqual(
            git(self.root, "log", "-1", "--pretty=%s"),
            "chore(release): bump kernel to kernel-v6.18.35-2",
        )

    def test_kernel_release_dry_run_changes_nothing(self) -> None:
        original = (self.root / release_tool.KERNEL_RELEASE_FILE).read_text()
        release_tool.create_kernel_release(self.root, "1.2.3", True, False)
        self.assertEqual((self.root / release_tool.KERNEL_RELEASE_FILE).read_text(), original)
        self.assertEqual(git(self.root, "tag", "-l", "kernel-v1.2.3"), "")

    def test_kernel_release_can_tag_configured_version_without_commit(self) -> None:
        original_commit = git(self.root, "rev-parse", "HEAD")
        release_tool.create_kernel_release(self.root, "0.0.1", False, False)
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), original_commit)
        self.assertEqual(git(self.root, "tag", "-l", "kernel-v0.0.1"), "kernel-v0.0.1")

    def test_kernel_release_requires_explicit_unprefixed_version(self) -> None:
        for version in ("patch", "minor", "major", "v1.2.3", "kernel-v1.2.3", "1.2"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(release_tool.ReleaseError, "kernel VERSION"):
                    release_tool.resolve_kernel_version(version)


if __name__ == "__main__":
    unittest.main()
