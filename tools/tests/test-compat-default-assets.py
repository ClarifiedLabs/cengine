#!/usr/bin/env python3
"""Exercise default asset preparation order with inert build tools only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DefaultAssetsTests(unittest.TestCase):
    def run_selection(self, explicit=False, profile=""):
        source = (ROOT / "Scripts/run-compat-tests.sh").read_text()
        prefix = source[:source.index("LOCK=")]
        prepare = source[source.index('if [ "$BUILD_DEFAULT_ASSETS" = 1 ]; then'):source.index('stage "$BUILD_STAGE"')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT / "Scripts", root / "Scripts")
            calls = root / "calls"
            (root / "Scripts/check-managed-guest-assets.py").write_text(
                'import os\nwith open(os.environ["CALLS"],"a") as f: f.write("validate\\n")\n')
            kernel = root / "Scripts/check-guest-kernel.sh"
            kernel.write_text('#!/bin/sh\nprintf "kernel-check\\n" >> "$CALLS"\n')
            kernel.chmod(0o755)
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CENGINE_", "XCODE", "PREPARE_"))}
            env.update(CALLS=str(calls), CENGINE_DEVELOPER_ID_APPLICATION="Developer ID Application: Fixture (ABCDEFGHIJ)")
            if explicit:
                assets = root / "explicit-assets"
                assets.mkdir()
                (assets / "disk-bootstrap.json").write_text(json.dumps({"storageLifecycleVersion": 2}))
                env["CENGINE_COMPAT_MANAGED_ASSET_DIR"] = str(assets)
            if profile:
                env["PREPARE_COMPATIBILITY_PROFILE"] = profile
            # Execute the real prefix and preparation block, but not locking,
            # reset, native build, helper validation, installation or pytest.
            stubs = '''
make() {
    printf 'build\n' >> "$CALLS"
    [ "$1" = -C ] && [ "$2" = "$ROOT" ] && [ "$4" = guest-initramfs ] || return 91
    mkdir -p "$ROOT/.build/guest"
    printf '{"storageLifecycleVersion":2}' > "$ROOT/.build/guest/disk-bootstrap.json"
}
stage() { :; }
'''
            result = subprocess.run(["sh", "-eu", "-c", prefix + stubs + prepare,
                                     str(root / "Scripts/run-compat-tests.sh")], env=env, text=True, capture_output=True)
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_unbuilt_default_assets_build_before_validation(self):
        result, calls = self.run_selection()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["build", "kernel-check", "validate"])

    def test_explicit_assets_validate_without_rebuild(self):
        result, calls = self.run_selection(explicit=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["validate"])

    def test_profile_cannot_trigger_ordinary_asset_build(self):
        result, calls = self.run_selection(profile="rtm096-full-nine-v3")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
