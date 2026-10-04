#!/usr/bin/env python3
"""Engine-free closed early profile build selection; never builds assets."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("early_assets", ROOT / "Scripts/prepare_compatibility_assets.py")
assert spec and spec.loader
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class EarlyAssetsTests(unittest.TestCase):
    def test_closed_build_tag_selection_without_building(self):
        text = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        options = text[text.index("PREPARE_COMPATIBILITY_PROFILE="):text.index("ROOT=$(CDPATH=")]
        tag = text[text.index('    case "$PREPARE_COMPATIBILITY_PROFILE" in'):text.index('\nelse\n    ORDINARY_SOURCE_SHA256=')]
        # Execute only the actual bounded shell selection, not any source/build I/O.
        script = options + "set --\n" + tag + '\nprintf "%s\\n" "$PREPARE_COMPATIBILITY_PROFILE" "$*"\n'
        for profile, expected in ((assets.PROFILE, "cengine_prepare_compat"), (assets.EARLY_PROFILE, "cengine_prepare_early_compat")):
            result = subprocess.run(["sh", "-eu", "-c", script, "selection", "--prepare-compatibility=" + profile], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [profile, "-tags=" + expected])
        self.assertNotIn("cengine_native_faulttest", text)
        storage = text.split('"$BINARY_OUTPUT/out/cengine-init"', 1)[1].split('"$BINARY_OUTPUT/out/cengine-storage"', 1)[0]
        self.assertNotIn('"$@"', storage)

    def test_wrong_combined_replayed_options_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp); (output / "retain").write_bytes(b"unchanged")
            good = "--prepare-compatibility=" + assets.EARLY_PROFILE
            for args in ([good, good], [good, "--prepare-compatibility=" + assets.PROFILE], [good + "junk"], ["--prepare-compatibility=rtm096-all"]):
                result = subprocess.run(["sh", str(ROOT / "Scripts/build-guest-assets.sh"), *args], env={**os.environ, "CENGINE_GUEST_OUTPUT": temp}, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual([p.name for p in output.iterdir()], ["retain"])
                self.assertEqual((output / "retain").read_bytes(), b"unchanged")

    def test_metadata_both_profiles_require_current_complete_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in assets.BUILD_INPUTS:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
            (root / "Guest").mkdir(); (root / "Guest/main.go").write_text("package main\n")
            pin = assets.source_pin(root)
            for profile in assets.PROFILES:
                data = {assets.PROFILE_FIELD: profile, assets.SOURCE_FIELD: pin}
                assets.validate_metadata(data, root)
                for bad in ({assets.PROFILE_FIELD: profile}, {**data, assets.SOURCE_FIELD: "0" * 64}, {**data, assets.PROFILE_FIELD: profile + "x"}, {**data, assets.PROFILE_FIELD: [profile]}):
                    with self.assertRaises(ValueError): assets.validate_metadata(bad, root)
            (root / "Guest/main.go").write_text("package changed\n")
            stale = {assets.PROFILE_FIELD: assets.EARLY_PROFILE, assets.SOURCE_FIELD: pin}
            with self.assertRaises(ValueError): assets.validate_metadata(stale, root)
        assets.validate_metadata({}, Path("/nonexistent"))

    def test_new_metadata_tail_exact_profile_no_fake_asset_provenance(self):
        text = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        tail = text[text.index('python3 - "$OUTPUT"'):]
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            for name in ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"):
                (output / name).write_bytes(name.encode())
            env = dict(os.environ, OUTPUT=temp, PREPARE_COMPATIBILITY_PROFILE=assets.EARLY_PROFILE, PREPARE_COMPATIBILITY_SOURCE_SHA256="a" * 64)
            result = subprocess.run(["sh", "-eu"], input=tail, text=True, env=env, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((output / "disk-bootstrap.json").read_bytes())
            self.assertEqual(data["storageServiceBootVersion"], 2)
            self.assertEqual(data["storageLifecycleVersion"], 2)
            self.assertEqual(data[assets.PROFILE_FIELD], assets.EARLY_PROFILE)
            self.assertEqual(data[assets.SOURCE_FIELD], "a" * 64)


if __name__ == "__main__":
    unittest.main()
