#!/usr/bin/env python3
"""Closed sole-v2 PREPARE selection and real managed asset validator execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FULL = "rtm096-full-nine-v3"
IDENTITY = "Developer ID Application: Fixture Company (ABCDEFGHIJ)"


class PrepareLifecycleSelectionTests(unittest.TestCase):
    def run_selection(self, changes=None, asset_changes=None):
        source = (ROOT / "Scripts/run-compat-tests.sh").read_text()
        prefix = source[:source.index("LOCK=")]
        build = source[source.index('stage "$BUILD_STAGE"'):source.index('HELPER=$(compat_network_helper_local_for_binary')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "Scripts"
            scripts.mkdir()
            log = root / "calls"
            for name in ("network-helper-fingerprint.sh", "xcodebuild", "build-storage-controller.sh", "sign-compat-binary.sh"):
                path = scripts / name
                path.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$CALLS"\n'
                                'case "$0" in *network-helper-fingerprint.sh) printf "%064d\\n" 0;; esac\n')
                path.chmod(0o755)
            assets = root / "assets"
            assets.mkdir()
            metadata = {"storageLifecycleVersion": 2, "prepareCompatibilityProfile": FULL,
                        "prepareCompatibilitySourceSHA256": "a" * 64}
            metadata.update(asset_changes or {})
            (assets / "disk-bootstrap.json").write_text(json.dumps(metadata))
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("CENGINE_", "XCODE", "PREPARE_"))}
            env.update(PREPARE_COMPATIBILITY_PROFILE=FULL, CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=FULL,
                       CENGINE_COMPAT_MANAGED_ASSET_DIR=str(assets), CENGINE_DEVELOPER_ID_APPLICATION=IDENTITY,
                       CENGINE_BINARY=str(root / "cengine"), XCODEBUILD=str(scripts / "xcodebuild"), CALLS=str(log))
            env.update(changes or {})
            # This test owns selection, not hash verification. Keep the validator
            # call observable without manufacturing/building real Guest assets.
            stub = '''python3() {
                case "$1" in */check-managed-guest-assets.py)
                    printf 'asset-validation\\n' >> "$CALLS";;
                *) command python3 "$@";; esac
            }
'''
            command = stub + prefix + '\nROOT=' + shlex.quote(str(root)) + '\nBUILD_STAGE=test\nstage() { :; };\n' + build
            result = subprocess.run(["/bin/sh", "-eu", "-c", command, str(ROOT / "Scripts/run-compat-tests.sh")],
                                    env=env, text=True, capture_output=True)
            return result, log.read_text().splitlines() if log.exists() else []

    def test_full_v2_campaign_validates_assets_and_builds_explicit_controller(self):
        result, calls = self.run_selection()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], "asset-validation")
        controller = [line for line in calls if "build-storage-controller.sh" in line]
        self.assertEqual(len(controller), 1)
        self.assertIn(f"--sign {IDENTITY} --prepare-compatibility={FULL}", controller[0])
        self.assertNotIn(" --compat ", controller[0])
        xcode = next(line for line in calls if "xcodebuild" in line)
        self.assertIn("CENGINE_COMPAT_LIFECYCLE_FAULT= CENGINE_RUNTIME_COMPAT_LIFECYCLE_FAULT_CONDITION=", xcode)
        self.assertNotIn("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION=", xcode)

    def test_incomplete_mismatched_unsigned_and_mixed_campaigns_fail_before_build(self):
        cases = [
            ({"CENGINE_COMPAT_MANAGED_STORAGE": "0"}, {}),
            ({"CENGINE_DEVELOPER_ID_APPLICATION": ""}, {}),
            ({"PREPARE_COMPATIBILITY_PROFILE": ""}, {}),
            ({"CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY": ""}, {}),
            ({"PREPARE_COMPATIBILITY_PROFILE": "unknown"}, {}),
            ({"PREPARE_COMPATIBILITY_PROFILE": "rtm096-normal-a7-v1"}, {}),
            ({"CENGINE_COMPAT_LIFECYCLE_FAULT": "before-configure-v1"}, {}),
            ({"CENGINE_COMPAT_LIFECYCLE_FAULT": "after-replacement-before-completion-v1"}, {}),
            ({"CENGINE_STORAGE_LIFECYCLE_QUALIFICATION": "lifecycle-v2-native-v1"}, {}),
            ({}, {"prepareCompatibilityProfile": "rtm096-early-a1-a3-v2"}),
            ({}, {"prepareCompatibilityProfile": None}),
            ({}, {"prepareCompatibilitySourceSHA256": None}),
            ({}, {"storageLifecycleVersion": 1}),
        ]
        for changes, assets in cases:
            with self.subTest(changes=changes, assets=assets):
                result, calls = self.run_selection(changes, assets)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_matrix_wrapper_exports_closed_route_and_refuses_mixed_campaigns(self):
        source = (ROOT / "tools/managed-prepare-matrix.sh").read_text()
        prefix = source[:source.index('# Build, sign, validate assets and helper')]
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("CENGINE_", "PREPARE_"))}
        env.update(CENGINE_DEVELOPER_ID_APPLICATION=IDENTITY, CENGINE_GIT_COMMIT="fixture", CENGINE_BUILD_TIME="fixture")
        script = prefix + '\nprintf "%s\\n" "$PREPARE_COMPATIBILITY_PROFILE" "$CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY" "$CENGINE_COMPAT_REQUIRE_EXACT_HELPER"\n'
        result = subprocess.run(["sh", "-eu", "-c", script, str(ROOT / "tools/managed-prepare-matrix.sh")],
                                env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [FULL, FULL, "1"])
        for key, value in (("CENGINE_COMPAT_SHARED_STORAGE", "legacy"),
                           ("PREPARE_COMPATIBILITY_PROFILE", "rtm096-normal-a7-v1"),
                           ("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "unknown"),
                           ("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", "lifecycle-v2-native-v1"),
                           ("CENGINE_COMPAT_LIFECYCLE_FAULT", "before-configure-v1")):
            with self.subTest(key=key):
                result = subprocess.run(["sh", "-eu", "-c", script, str(ROOT / "tools/managed-prepare-matrix.sh")],
                                        env={**env, key: value}, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


class PrepareLifecycleAssetValidatorTests(unittest.TestCase):
    """Execute unchanged validator scripts over isolated, genuinely pinned inputs.

    Payloads are inert fixture bytes: PREPARE validation promises source pins and
    paired hashes, not ordinary Go-binary provenance or VM execution.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        spec = importlib.util.spec_from_file_location("prepare_assets", ROOT / "Scripts/prepare_compatibility_assets.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in (*module.BUILD_INPUTS, "Scripts/storage_lifecycle_qualification.py"):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        guest = self.root / "Guest/fixture.go"
        guest.parent.mkdir()
        guest.write_text("package fixture\n")
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.names = ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", "disk-bootstrap.json")
        for name in self.names[:-1]:
            (self.assets / name).write_bytes(name.encode())
        self.pin = module.source_pin(self.root)
        self.metadata = dict(schemaVersion=1, protocolVersion=1, storageServiceBootVersion=2,
                             workloadStorageBootVersion=1, storageLifecycleVersion=2,
                             prepareCompatibilityProfile=FULL, prepareCompatibilitySourceSHA256=self.pin)
        for kind in ("container", "storage"):
            self.metadata[f"{kind}InitramfsSHA256"] = self.digest(f"{kind}-initramfs.cpio.gz")
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith(("CENGINE_", "PREPARE_", "XCODE_", "CODE_SIGN", "PYTHON"))
                            and key != "CONFIGURATION"}
        self.environment.update(         CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=FULL,
                                PREPARE_COMPATIBILITY_PROFILE=FULL, PYTHONDONTWRITEBYTECODE="1")
        self.publish(self.metadata)

    def digest(self, name):
        return hashlib.sha256((self.assets / name).read_bytes()).hexdigest()

    def publish(self, metadata):
        (self.assets / "disk-bootstrap.json").write_text(json.dumps(metadata))
        (self.assets / "SHA256SUMS").write_text("".join(f"{self.digest(name)}  {name}\n" for name in self.names))

    def validate(self, changes=None):
        return subprocess.run([sys.executable, str(self.root / "Scripts/check-managed-guest-assets.py"), str(self.assets)],
                              env={**self.environment, **(changes or {})}, text=True, capture_output=True)

    def assert_refused(self, changes=None, message=None):
        result = self.validate(changes)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("managed guest asset preflight:", result.stderr)
        if message:
            self.assertIn(message, result.stderr)

    def test_exact_full_v2_assets_pass_without_ordinary_provenance(self):
        result = self.validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("ordinaryProvenance", self.metadata)

    def test_missing_partial_mismatched_and_unknown_selectors_refuse(self):
        for changes in (
            {"CENGINE_COMPAT_MANAGED_STORAGE": "0"},
            {"CENGINE_COMPAT_SHARED_STORAGE": "unknown"},
            {"CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY": "", "PREPARE_COMPATIBILITY_PROFILE": ""},
            *[{key: value} for key in ("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "PREPARE_COMPATIBILITY_PROFILE")
              for value in ("", "unknown", "rtm096-normal-a7-v1", "rtm096-early-a1-a3-v2")],
        ):
            with self.subTest(changes=changes):
                self.assert_refused(changes)

    def test_incomplete_unknown_and_mismatched_asset_profiles_refuse(self):
        cases = [{key: value} for key in ("prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256")
                 for value in (None, "", "unknown")]
        cases += [{"prepareCompatibilityProfile": value} for value in ("rtm096-normal-a7-v1", "rtm096-early-a1-a3-v2")]
        for changes in cases:
            with self.subTest(changes=changes):
                self.publish({**self.metadata, **changes})
                self.assert_refused()
        for fields in (("prepareCompatibilityProfile",), ("prepareCompatibilitySourceSHA256",),
                       ("prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256")):
            with self.subTest(missing=fields):
                self.publish({key: value for key, value in self.metadata.items() if key not in fields})
                self.assert_refused()

    def test_lifecycle_version_must_be_exact_integer_two(self):
        for version in (None, True, False, "2", 2.0, 1, 3):
            with self.subTest(version=version):
                self.publish({**self.metadata, "storageLifecycleVersion": version})
                self.assert_refused(message="storageLifecycleVersion: 2")
        self.publish({key: value for key, value in self.metadata.items() if key != "storageLifecycleVersion"})
        self.assert_refused(message="storageLifecycleVersion: 2")

    def test_stale_service_boot_version_is_not_relabelled_as_lifecycle(self):
        for value in (None, 1, True, "2", 2.0, 3):
            with self.subTest(version=value):
                self.publish({**self.metadata, "storageServiceBootVersion": value})
                self.assert_refused(message="storageServiceBootVersion: 2")

    def test_qualification_runtime_fault_and_ordinary_provenance_mixes_refuse(self):
        for key, values in (
            ("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", ("lifecycle-v2-native-v1", "unknown")),
            ("CENGINE_COMPAT_LIFECYCLE_FAULT", ("before-configure-v1", "after-replacement-before-completion-v1", "unknown")),
        ):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.assert_refused({key: value})
        for changes in ({"storageLifecycleQualification": "lifecycle-v2-native-v1"},
                        {"storageLifecycleSourcePin": self.pin},
                        {"ordinaryProvenance": {}}):
            with self.subTest(metadata=changes):
                self.publish({**self.metadata, **changes})
                self.assert_refused()

    def test_prepare_pin_is_current_not_just_well_formed(self):
        self.publish({**self.metadata, "prepareCompatibilitySourceSHA256": "0" * 64})
        self.assert_refused(message="PREPARE compatibility source pin mismatch")
        self.publish(self.metadata)
        (self.root / "Guest/fixture.go").write_text("package changed\n")
        self.assert_refused(message="PREPARE compatibility source pin mismatch")

    def test_manifest_and_metadata_pairing_stay_strict(self):
        for name in self.names:
            with self.subTest(corrupt=name):
                original = (self.assets / name).read_bytes()
                (self.assets / name).write_bytes(original + b"corrupt")
                self.assert_refused(message="managed asset checksum mismatch")
                (self.assets / name).write_bytes(original)
        for kind in ("container", "storage"):
            with self.subTest(unpaired=kind):
                self.publish({**self.metadata, f"{kind}InitramfsSHA256": "0" * 64})
                self.assert_refused(message=f"metadata does not bind {kind} initramfs")
        self.publish(self.metadata)
        manifest = self.assets / "SHA256SUMS"
        lines = manifest.read_text().splitlines(keepends=True)
        for contents in ("".join(lines[:-1]), "".join(lines + lines[:1]),
                         "".join(lines) + "0" * 64 + "  extra\n"):
            with self.subTest(manifest=contents):
                manifest.write_text(contents)
                self.assert_refused(message="SHA256SUMS")

    def test_nonfault_lifecycle_still_requires_current_ordinary_provenance(self):
        metadata = {key: value for key, value in self.metadata.items()
                    if key not in ("prepareCompatibilityProfile", "prepareCompatibilitySourceSHA256")}
        changes = {"CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY": "", "PREPARE_COMPATIBILITY_PROFILE": ""}
        self.publish(metadata)
        self.assert_refused(changes, "current ordinary assets require default-profile provenance")
        self.publish({**metadata, "ordinaryProvenance": dict(schemaVersion=1, policy="closed-ordinary-go-v1",
                                                            sourceSHA256="0" * 64)})
        self.assert_refused(changes, "ordinary source pin mismatch")


if __name__ == "__main__":
    unittest.main()
