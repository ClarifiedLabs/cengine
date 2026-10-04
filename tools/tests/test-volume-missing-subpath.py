#!/usr/bin/env python3
"""Engine-free guards for RTM-063's backend-specific refusal classification."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import test_upstream_volumes as primitives


class MissingSubpathTests(unittest.TestCase):
    def check(self, status, *, storage="shared", mode: str | None = "lifecycle", explanation=None):
        daemon = None if mode is None else SimpleNamespace(
            process=SimpleNamespace(args=["cengine", "daemon"]))
        error = SimpleNamespace(response=SimpleNamespace(status_code=status), explanation=(
            "private workload storage channel refused; preserve generation evidence"
            if explanation is None else explanation))
        primitives._assert_missing_subpath_error(daemon, storage, error)

    def test_managed_shared_exact_refusal(self):
        self.check(409)

    def test_reference_and_legacy_keep_existing_status_policy(self):
        for status in (404, 500):
            for mode in (None, "lifecycle"):
                for storage in ("block", "shared"):
                    with self.subTest(status=status, mode=mode, storage=storage):
                        self.check(status, mode=mode, storage=storage)

    def test_conflict_requires_managed_shared(self):
        for mode, storage in ((None, "shared"), ("lifecycle", "block")):
            with self.subTest(mode=mode, storage=storage), self.assertRaises(AssertionError):
                self.check(409, mode=mode, storage=storage)

    def test_other_conflicts_fail(self):
        for text in ("volume is in use", "managed storage ownership unresolved; preserve generation evidence",
                     "private workload storage channel refused; preserve generation evidence extra", ""):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                self.check(409, explanation=text)

    def test_other_statuses_fail(self):
        for status in (200, 400, 401, 403, 503):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                self.check(status)


if __name__ == "__main__":
    unittest.main()
