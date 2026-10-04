#!/usr/bin/env python3
"""Closed helper qualification policy; no helper, signing, elevation or VMs."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("helper_policy", ROOT / "Scripts/helper_compatibility_policy.py")
assert spec is not None and spec.loader is not None
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def metadata(prepare="", qualification=""):
    value: dict[str, object] = {"storageLifecycleVersion": 2}
    if prepare:
        value.update(prepareCompatibilityProfile=prepare, prepareCompatibilitySourceSHA256="a" * 64)
    if qualification:
        value.update(storageLifecycleQualification=qualification, storageLifecycleSourcePin="b" * 64)
    return value


class HelperPolicyTests(unittest.TestCase):
    def test_default_contract_and_retired_selectors(self):
        self.assertEqual(P.select({}, metadata()), ("compatible", "lifecycle-v2"))
        self.assertEqual(P.select({"CENGINE_COMPAT_REQUIRE_EXACT_HELPER": "1"}, metadata()), ("exact", "lifecycle-v2"))
        for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
            for value in ("", "0", "1", "legacy", "managed", "lifecycle", "unknown"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    P.select({key: value}, metadata())

    def test_cold_dead_extension_keeps_semantic_selector_and_ordinary_pair_policy(self):
        # lifecycle-v2 invokes the signed client's mandatory additive contract gate;
        # this read-only selector must not duplicate capability parsing or require
        # an exact local fingerprint just because that gate gained an extension.
        self.assertEqual(P.select({}, metadata()), ("compatible", "lifecycle-v2"))
        self.assertEqual(P.select({P.KEYS[4]: "1"}, metadata()), ("exact", "lifecycle-v2"))
        env = {P.KEYS[0]: P.QUALIFICATION}
        self.assertEqual(P.select(env, metadata(qualification=P.QUALIFICATION)),
                         ("exact", "lifecycle-qualification"))
        for key in ("CENGINE_COMPAT_REQUIRED_STORAGE_CONTRACT", "CENGINE_COMPAT_HELPER_SECURITY_REVISION"):
            # Unsigned environment cannot weaken the compiled semantic floor.
            self.assertEqual(P.select({key: "lifecycle-v2"}, metadata()),
                             ("compatible", "lifecycle-v2"))

    def test_prepare_assets_cannot_select_a_retired_helper_contract(self):
        for profile in P.PREPARE_PROFILES:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                P.select({}, metadata(prepare=profile))

    def test_full_prepare_lifecycle_requires_complete_explicit_matching_selection(self):
        full = P.PREPARE_PROFILES[-1]
        env = {P.KEYS[2]: full, P.KEYS[3]: full}
        asset = metadata(prepare=full)
        self.assertEqual(P.select(env, asset), ("exact", "lifecycle-v2"))
        self.assertEqual(P.select({**env, P.KEYS[4]: "1"}, asset), ("exact", "lifecycle-v2"))
        for key in (P.KEYS[2], P.KEYS[3]):
            for value in ("", *P.PREPARE_PROFILES[:-1], "unknown"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    P.select({**env, key: value}, asset)
        for profile in ("", *P.PREPARE_PROFILES[:-1]):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                P.select(env, metadata(prepare=profile))
        for version in (None, True, 1, 2.0, "2"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                P.select(env, {**asset, "storageLifecycleVersion": version})
        for fault in ("before-configure-v1", "after-replacement-before-completion-v1",
                      "after-cold-l2-before-a1-v1"):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                P.select({**env, P.KEYS[1]: fault}, asset)
        with self.assertRaises(ValueError):
            P.select({**env, P.KEYS[0]: P.QUALIFICATION}, metadata(prepare=full, qualification=P.QUALIFICATION))
        for missing in ("prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256"):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                P.select(env, {key: value for key, value in asset.items() if key != missing})
        # Profile-looking environment cannot turn ordinary inert assets into a campaign.
        with self.assertRaises(ValueError):
            P.select(env, metadata())

    def test_qualification_requires_matching_profile_and_exact_pair(self):
        env = {P.KEYS[0]: P.QUALIFICATION}
        asset = metadata(qualification=P.QUALIFICATION)
        self.assertEqual(P.select(env, asset), ("exact", "lifecycle-qualification"))
        for mismatched_env, mismatched_asset in (({}, asset), (env, metadata())):
            with self.assertRaises(ValueError):
                P.select(mismatched_env, mismatched_asset)
        for key, value in ((P.KEYS[1], "before-configure-v1"),
                           (P.KEYS[2], P.PREPARE_PROFILES[-1]), (P.KEYS[3], P.PREPARE_PROFILES[0])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.select({**env, key: value}, asset)
        with self.assertRaises(ValueError):
            P.select(env, metadata(prepare=P.PREPARE_PROFILES[0], qualification=P.QUALIFICATION))

    def test_fault_campaign_remains_exact(self):
        for profile in ("before-configure-v1", "after-replacement-before-completion-v1",
                        "before-takeover-apply-v1", "after-takeover-apply-v1",
                        "after-cold-l2-before-a1-v1", "after-first-cold-completion-v1"):
            env = {P.KEYS[1]: profile}
            self.assertEqual(P.select(env, metadata()), ("exact", "lifecycle-v2"))
            with self.assertRaises(ValueError):
                P.select({**env, P.KEYS[0]: P.QUALIFICATION}, metadata(qualification=P.QUALIFICATION))
            with self.assertRaises(ValueError):
                P.select(env, metadata(prepare=P.PREPARE_PROFILES[-1]))
            for bad in (profile + " ", profile.replace("v1", "v2")):
                with self.assertRaises(ValueError):
                    P.select({P.KEYS[1]: bad}, metadata())

    def test_unknown_incomplete_and_contradictory_selections_refuse(self):
        for key in P.KEYS[:-1]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.select({key: "unknown"}, metadata())
        for name, source in (("prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256"),
                             ("storageLifecycleQualification", "storageLifecycleSourcePin")):
            for asset in ({name: "unknown", source: "a" * 64}, {name: None, source: "a" * 64},
                          {name: []}, {source: "a" * 64}, {name: P.PREPARE_PROFILES[0]},
                          {name: P.PREPARE_PROFILES[0], source: "Z" * 64}):
                with self.subTest(asset=asset), self.assertRaises(ValueError):
                    P.select({}, asset)
        for version in (None, True, 1, 2.0, "2"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                P.select({}, {"storageLifecycleVersion": version})
        for env in ({P.KEYS[2]: P.PREPARE_PROFILES[-1]}, {P.KEYS[3]: P.PREPARE_PROFILES[0]}):
            with self.assertRaises(ValueError):
                P.select(env, metadata())

    def test_metadata_reader_is_bounded_duplicate_free_and_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "disk-bootstrap.json"
            raw = json.dumps(metadata()).encode()
            path.write_bytes(raw)
            before = path.stat()
            self.assertEqual(P.read_metadata(str(directory)), metadata())
            after = path.stat()
            self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns),
                             (after.st_ino, after.st_size, after.st_mtime_ns))
            self.assertEqual(path.read_bytes(), raw)
            for invalid in (b"", b"[]", b"null", b'{"prepareCompatibilityProfile":null,"prepareCompatibilityProfile":"x"}',
                            b" " * 65537):
                path.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    P.read_metadata(str(directory))
            path.unlink()
            other = directory / "other"
            other.write_bytes(raw)
            path.symlink_to(other)
            with self.assertRaises(OSError):
                P.read_metadata(str(directory))
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                P.read_metadata(str(directory))
        with self.assertRaises(ValueError):
            P.read_metadata("")

    def test_shared_shell_gate_selects_from_actual_asset_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            asset = directory / "disk-bootstrap.json"
            # Asset-only PREPARE must not silently take the ordinary lane.
            asset.write_text(json.dumps(metadata(prepare=P.PREPARE_PROFILES[-1])))
            command = (f'. {shlex.quote(str(ROOT / "Scripts/compat-network-helper.sh"))}; '
                       'compat_network_helper_select_policy')
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CENGINE_", "PREPARE_COMPATIBILITY_"))}
            env.update(ROOT=str(ROOT), CENGINE_COMPAT_MANAGED_ASSET_DIR=temporary)
            selected = subprocess.run(["/bin/sh", "-eu", "-c", command], env=env, capture_output=True, text=True)
            self.assertNotEqual(selected.returncode, 0)
            self.assertEqual(selected.stdout, "")
            env.update(CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=P.PREPARE_PROFILES[-1],
                       PREPARE_COMPATIBILITY_PROFILE=P.PREPARE_PROFILES[-1])
            full = subprocess.run(["/bin/sh", "-eu", "-c", command], env=env, capture_output=True, text=True)
            self.assertEqual(full.returncode, 0, full.stderr)
            self.assertEqual(full.stdout.strip(), "exact lifecycle-v2")
            env.pop("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY")
            env.pop("PREPARE_COMPATIBILITY_PROFILE")
            asset.write_text(json.dumps(metadata()))
            accepted = subprocess.run(["/bin/sh", "-eu", "-c", command], env=env, capture_output=True, text=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout.strip(), "compatible lifecycle-v2")
            env["CENGINE_COMPAT_REQUIRE_EXACT_HELPER"] = "1"
            exact = subprocess.run(["/bin/sh", "-eu", "-c", command], env=env, capture_output=True, text=True)
            self.assertEqual(exact.returncode, 0, exact.stderr)
            self.assertEqual(exact.stdout.strip(), "exact lifecycle-v2")
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["disk-bootstrap.json"])

    def test_status_policy_without_built_assets_keeps_authenticated_contract(self):
        command = f'. {shlex.quote(str(ROOT / "Scripts/compat-network-helper.sh"))}; compat_network_helper_select_policy'
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("CENGINE_", "PREPARE_"))}
        env["ROOT"] = str(ROOT)
        for extra, expected in (({}, "compatible lifecycle-v2"),
                                ({"CENGINE_COMPAT_REQUIRE_EXACT_HELPER": "1"}, "exact lifecycle-v2"),
                                ({"CENGINE_COMPAT_LIFECYCLE_FAULT": "before-configure-v1"}, "exact lifecycle-v2"),
                                ({"CENGINE_COMPAT_LIFECYCLE_FAULT": "after-cold-l2-before-a1-v1"}, "exact lifecycle-v2")):
            result = subprocess.run(["sh", "-eu", "-c", command], env={**env, **extra}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)
        for extra in ({"CENGINE_COMPAT_MANAGED_ASSET_DIR": "/missing/explicit-assets"},
                      {"PREPARE_COMPATIBILITY_PROFILE": P.PREPARE_PROFILES[-1]},
                      {"CENGINE_STORAGE_LIFECYCLE_QUALIFICATION": P.QUALIFICATION}):
            result = subprocess.run(["sh", "-eu", "-c", command], env={**env, **extra}, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def test_shell_rejects_retired_selectors_before_reading_assets(self):
        command = f'. {shlex.quote(str(ROOT / "Scripts/compat-network-helper.sh"))}; compat_network_helper_select_policy'
        env = {key: value for key, value in os.environ.items() if not key.startswith("CENGINE_")}
        for key in ("CENGINE_COMPAT_SHARED_STORAGE", "CENGINE_COMPAT_MANAGED_STORAGE"):
            for value in ("", "0", "1", "legacy", "managed", "lifecycle"):
                with self.subTest(key=key, value=value):
                    result = subprocess.run(["/bin/sh", "-eu", "-c", command], env={**env, key: value}, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("retired", result.stderr)


if __name__ == "__main__":
    unittest.main()
