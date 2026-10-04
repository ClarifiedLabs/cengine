#!/usr/bin/env python3
"""No builds, VM, installs, signing, downloads or helper access: mock dependencies."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Scripts"))
import storage_lifecycle_qualification as Q
from prepare_compatibility_assets import BUILD_INPUTS

IDENTITY = "Developer ID Application: Fixture Company (ABCDEFGHIJ)"


def environment(**extra):
    value = {key: value for key, value in os.environ.items()
             if not key.startswith(("CENGINE_", "XCODE", "PREPARE_", "CODE_SIGN", "CONFIGURATION"))}
    value.update(extra)
    return value


def selected(**extra):
    return environment(CENGINE_STORAGE_LIFECYCLE_QUALIFICATION=Q.PROFILE,
                       CENGINE_DEVELOPER_ID_APPLICATION=IDENTITY, **extra)


def fixture(root):
    shutil.copytree(ROOT / "Scripts", root / "Scripts")
    for name in set(BUILD_INPUTS + Q.INPUTS):
        file = root / name
        if not file.exists():
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(name)
    policy = root / "Sources/CEngineCore/StorageLifecycleNativePolicy.swift"
    policy.parent.mkdir(parents=True)
    policy.write_text("// native policy fixture\n")
    (root / "Guest").mkdir()
    (root / "Guest/main.go").write_text("package fixture\n")
    return policy


def assets(root, pin, suffix=b""):
    root.mkdir(parents=True, exist_ok=True)
    for name in ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"):
        (root / name).write_bytes(name.encode() + suffix)
    metadata: dict[str, object] = dict(schemaVersion=1, protocolVersion=1, storageServiceBootVersion=2, workloadStorageBootVersion=1, storageLifecycleVersion=2,
                    storageLifecycleQualification=Q.PROFILE, storageLifecycleSourcePin=pin)
    metadata.update({kind + "InitramfsSHA256": hashlib.sha256((root / (kind + "-initramfs.cpio.gz")).read_bytes()).hexdigest()
                     for kind in ("container", "storage")})
    (root / "disk-bootstrap.json").write_text(json.dumps(metadata))
    (root / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
        for name in ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz", "disk-bootstrap.json")))


class QualificationTests(unittest.TestCase):
    def test_closed_selection_and_signing(self):
        self.assertEqual(Q.selection({}), "")
        self.assertEqual(Q.selection(selected()), Q.PROFILE)
        Q.require_signed_managed(selected())
        for bad in ("1", "true", Q.PROFILE + "x", " " + Q.PROFILE):
            with self.assertRaises(ValueError): Q.selection({Q.ENV: bad})
        for key, value in (("CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY", "rtm096-full-nine-v3"),
                           ("PREPARE_COMPATIBILITY_PROFILE", "rtm096-normal-a7-v1"),
                           ("XCODE_COMPAT_CONFIGURATION", "Release"), ("CONFIGURATION", "Debug"),
                           ("CENGINE_SIGN_RELEASE", "1"), ("CENGINE_NOTARIZE", "1"),
                           ("CODE_SIGNING_ALLOWED", "NO"), ("CODE_SIGN_IDENTITY", "-"),
                           ("CENGINE_COMPAT_MANAGED_STORAGE", "0"), ("CENGINE_DEVELOPER_ID_APPLICATION", "-")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                Q.require_signed_managed({**selected(), key: value})

    def test_make_keeps_qualification_outputs_separate(self):
        for target in ("test-compat", "test-compat-helper-install"):
            run = subprocess.run(["make", "-n", target], cwd=ROOT,
                                 env=selected(), capture_output=True, text=True, check=True)
            expected = str(ROOT / ".build" / Q.PROFILE / "xcode-derived")
            self.assertIn(f'XCODE_DERIVED_DATA="{expected}"', run.stdout)
            self.assertIn(expected + "/Build/Products/test-compat/cengine", run.stdout)
        ordinary = subprocess.run(["make", "-n", "test-compat"], cwd=ROOT,
                                  env=environment(), capture_output=True, text=True, check=True)
        self.assertIn('XCODE_DERIVED_DATA=".build/xcode-derived"', ordinary.stdout)

    def test_paths_are_separate_even_through_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            Q.validate_output(root, root / ".build" / Q.PROFILE / "guest")
            for path in (root / ".build/guest", root / ".build/xcode-derived" / Q.PROFILE,
                         root / "dist" / Q.PROFILE, Path(Q.PROFILE) / "relative"):
                with self.assertRaises(ValueError): Q.validate_output(root, path)
            (root / Q.PROFILE).symlink_to(root / ".build/guest")
            with self.assertRaises(ValueError): Q.validate_output(root, root / Q.PROFILE)

    def test_source_pin_tracks_guest_host_build_inputs_not_generated_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); policy = fixture(root)
            pin = Q.source_pin(root)
            for file in (policy, root / "Guest/main.go", root / "Scripts/storage_lifecycle_qualification.py",
                         root / "Configuration/network-helper-Info.plist", root / "Configuration/cengine.entitlements"):
                original = file.read_bytes(); file.write_bytes(original + b"changed")
                self.assertNotEqual(Q.source_pin(root), pin)
                file.write_bytes(original)
            generated = root / ".build" / Q.PROFILE / "receipt"
            generated.parent.mkdir(parents=True); generated.write_text(pin)
            self.assertEqual(Q.source_pin(root), pin)
            policy.unlink(); policy.symlink_to(root / "Guest/main.go")
            with self.assertRaises(ValueError): Q.source_pin(root)
            policy.unlink(); policy.write_text("// restored")
            (root / "Sources/LinkedModule").symlink_to(root / "Guest", target_is_directory=True)
            with self.assertRaises(ValueError): Q.source_pin(root)

    def test_asset_pin_binds_exact_validated_receipt_not_source_inventory(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, selected(), clear=True):
            root = Path(temp); fixture(root)
            source_pin = Q.source_pin(root)
            first, second = (root / Q.PROFILE / name for name in ("first", "second"))
            assets(first, source_pin); assets(second, source_pin, b"different-build")
            pin = Q.assets_sha256(root, first)
            self.assertEqual(pin, hashlib.sha256((first / "SHA256SUMS").read_bytes()).hexdigest())
            self.assertNotEqual(pin, Q.assets_sha256(root, second))
            self.assertEqual(source_pin, Q.source_pin(root))
            receipt = (first / "SHA256SUMS").read_bytes()
            # Line endings are accepted by the normal checker but the sealed bytes differ.
            (first / "SHA256SUMS").write_bytes(receipt.replace(b"\n", b"\r\n"))
            self.assertNotEqual(pin, Q.assets_sha256(root, first))
            for bad in (receipt.split(b"\n", 1)[1], receipt + receipt.splitlines(keepends=True)[0],
                        receipt + b"0" * 64 + b"  extra\n", b"0" * 64 + receipt[64:]):
                (first / "SHA256SUMS").write_bytes(bad)
                with self.assertRaises(ValueError): Q.assets_sha256(root, first)
            assets(first, "f" * 64)
            with self.assertRaises(ValueError): Q.assets_sha256(root, first)
            with patch.dict(os.environ, {Q.ENV: ""}):
                with self.assertRaises(ValueError): Q.assets_sha256(root, second)

    def test_metadata_never_silently_falls_back_to_ordinary_or_prepare(self):
        good = {Q.PROFILE_FIELD: Q.PROFILE, Q.SOURCE_FIELD: "a" * 64}
        with patch.object(Q, "source_pin", return_value="a" * 64):
            Q.validate_metadata({}, ROOT, "")
            Q.validate_metadata(good, ROOT, Q.PROFILE)
            for profile, metadata in (("", good), (Q.PROFILE, {}), (Q.PROFILE, {Q.PROFILE_FIELD: Q.PROFILE}),
                                      (Q.PROFILE, {**good, Q.SOURCE_FIELD: "b" * 64}),
                                      (Q.PROFILE, {**good, Q.PROFILE_FIELD: "unknown"}),
                                      (Q.PROFILE, {**good, "ordinaryProvenance": {}}),
                                      (Q.PROFILE, {**good, "prepareCompatibilityProfile": "rtm096-full-nine-v3"}),
                                      ("", {Q.SOURCE_FIELD: None})):
                with self.subTest(profile=profile, metadata=metadata), self.assertRaises(ValueError):
                    Q.validate_metadata(metadata, ROOT, profile)

    def test_runner_builds_same_signed_selection_for_install_and_suite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fixture(root)
            log = root / "calls"
            for name in ("network-helper-fingerprint.sh", "build-storage-controller.sh", "sign-compat-binary.sh", "xcodebuild"):
                file = root / "Scripts" / name
                file.write_text(f'#!{sys.executable}\nimport json,sys,pathlib,os\nwith open({str(log)!r},"a") as log:\n log.write(json.dumps([pathlib.Path(sys.argv[0]).name,*sys.argv[1:]])+"\\n")\n if pathlib.Path(sys.argv[0]).name == "build-storage-controller.sh": log.write(json.dumps(["controller-assets",os.environ.get("CENGINE_COMPAT_MANAGED_ASSET_DIR")])+"\\n")\nif pathlib.Path(sys.argv[0]).name == "network-helper-fingerprint.sh": print("a"*64)\n')
                file.chmod(0o755)
            source = (ROOT / "Scripts/run-compat-tests.sh").read_text()
            script = source[:source.index("LOCK=")] + '\nBUILD_STAGE=test\nstage() { :; }\n' + source[source.index('stage "$BUILD_STAGE"'):source.index('HELPER=$(compat_network_helper_local_for_binary')]
            directory = root / Q.PROFILE / "guest"
            assets(directory, Q.source_pin(root))
            env = selected(CENGINE_COMPAT_MANAGED_ASSET_DIR=str(directory.relative_to(root)), XCODEBUILD=str(root / "Scripts/xcodebuild"))
            # Exact paired qualification assets cannot be checked as ordinary,
            # even though their hashes and manifest are otherwise correct.
            ordinary = subprocess.run([sys.executable, str(root / "Scripts/check-managed-guest-assets.py"), str(directory)], env=environment(), capture_output=True)
            self.assertNotEqual(ordinary.returncode, 0)
            for mode in ("helper-install", "suite"):
                log.write_text("")
                result = subprocess.run(["sh", "-eu", "-c", script, str(root / "Scripts/run-compat-tests.sh"), mode], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                xcode = next(call for call in calls if call[0] == "xcodebuild")
                self.assertIn("OTHER_SWIFT_FLAGS=$(inherited) -parse-as-library -D CENGINE_STORAGE_LIFECYCLE_QUALIFICATION", xcode)
                self.assertIn("CENGINE_STORAGE_LIFECYCLE_QUALIFICATION=" + Q.PROFILE, xcode)
                self.assertIn("CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN=" + Q.source_pin(root), xcode)
                self.assertIn("CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256=" + hashlib.sha256((directory / "SHA256SUMS").read_bytes()).hexdigest(), xcode)
                self.assertIn(str(root / ".build" / Q.PROFILE / "xcode-derived"), xcode)
                controller = next(call for call in calls if call[0] == "build-storage-controller.sh")
                self.assertEqual(controller[1:4], ["--sign", IDENTITY, "--compat"])
                self.assertIn(["controller-assets", str(directory)], calls)
            for key, value in (("XCODE_COMMON_FLAGS", "OTHER_SWIFT_FLAGS=-D OTHER"), ("XCODE_COMPAT_CONFIGURATION", "Release"),
                               ("XCODE_DERIVED_DATA", str(root / ".build/xcode-derived")), ("CENGINE_BINARY", str(root / "ordinary"))):
                log.write_text("")
                result = subprocess.run(["sh", "-eu", "-c", script, str(root / "Scripts/run-compat-tests.sh"), "suite"], env={**env, key: value}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(log.read_text(), "")

    def test_controller_exact_tags_and_closed_signed_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); fixture(root); log = root / "calls"
            for name, body in {
                "uname": 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac',
                "go": 'printf "CGO_CFLAGS=<%s>\\nCGO_CPPFLAGS=<%s>\\nCGO_CXXFLAGS=<%s>\\nCGO_LDFLAGS=<%s>\\n" "$CGO_CFLAGS" "$CGO_CPPFLAGS" "$CGO_CXXFLAGS" "$CGO_LDFLAGS" >> "$CALLS"; printf "%s\\n" "$*" >> "$CALLS"; test "$GOFLAGS" = ""; test "$GOENV" = off; for arg in "$@"; do case "$arg" in *-sectcreate,__TEXT,__info_plist,*) cp "${arg##*__info_plist,}" "$RECEIPT";; esac; done',
                "codesign": 'printf "%s\\n" "$*" >> "$CALLS"; case "$1" in -dv) printf "Authority=Developer ID Application: Fixture\\nflags=0x10000(runtime)\\n" >&2;; esac',
            }.items():
                file = root / name; file.write_text("#!/bin/sh\n" + body + "\n"); file.chmod(0o755)
            directory = root / Q.PROFILE / "guest"
            assets(directory, Q.source_pin(root))
            env = selected(PATH=f'{root}:{os.environ["PATH"]}', CALLS=str(log), GOFLAGS="-tags=hostile",
                           CGO_CFLAGS='-include /ambient/policy.h', CGO_CPPFLAGS='-UCE_STORAGE_LIFECYCLE_QUALIFICATION',
                           CGO_CXXFLAGS='-include /ambient/policy.h', CGO_LDFLAGS='-Wl,-ambient-link-policy',
                           CENGINE_COMPAT_MANAGED_ASSET_DIR=str(directory), RECEIPT=str(root / "linked.plist"))
            output = str(root / Q.PROFILE / "controller")
            script = str(root / "Scripts/build-storage-controller.sh")
            result = subprocess.run([script, "--sign", IDENTITY, "--compat", output], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("-tags cengine_lifecycle_v2_qualification", log.read_text())
            self.assertIn("CGO_CFLAGS=<-O2 -g -UCE_STORAGE_LIFECYCLE_COMPATIBILITY -DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1>", log.read_text())
            self.assertIn("CGO_CPPFLAGS=<>", log.read_text())
            self.assertIn("CGO_CXXFLAGS=<-O2 -g>", log.read_text())
            self.assertIn("CGO_LDFLAGS=<-O2 -g>", log.read_text())
            self.assertNotIn("/ambient/policy.h", log.read_text())
            self.assertNotIn("ambient-link-policy", log.read_text())
            self.assertIn("--identifier dev.cengine.storage-control.test-compat", log.read_text())
            self.assertIn("-linkmode=external -extldflags=-Wl,-sectcreate,__TEXT,__info_plist,", log.read_text())
            linked = plistlib.loads((root / "linked.plist").read_bytes())
            self.assertEqual(linked["CEngineStorageLifecycleAssetsSHA256"], hashlib.sha256((directory / "SHA256SUMS").read_bytes()).hexdigest())
            self.assertEqual(linked["CEngineStorageLifecycleSourcePin"], Q.source_pin(root))
            log.write_text("")
            missing_assets = {key: value for key, value in env.items() if key != "CENGINE_COMPAT_MANAGED_ASSET_DIR"}
            refused = subprocess.run([script, "--sign", IDENTITY, "--compat", output], env=missing_assets, capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(log.read_text(), "")
            plist_source = (root / "Scripts/build-storage-controller.sh").read_text().split("<<'PY'\n", 1)[1].split("\nPY", 1)[0]
            receipt = root / "receipt.plist"
            subprocess.run([sys.executable, "-", str(receipt), Q.PROFILE, "a" * 64, "ABCDEFGHIJ", "b" * 64], input=plist_source, text=True, check=True)
            value = plistlib.loads(receipt.read_bytes())
            self.assertEqual(value["CEngineStorageLifecycleQualification"], Q.PROFILE)
            self.assertEqual(value["CEngineStorageLifecycleSourcePin"], "a" * 64)
            self.assertEqual(value["CEngineStorageLifecycleAssetsSHA256"], "b" * 64)
            self.assertEqual(value["CFBundleIdentifier"], "dev.cengine.storage-control.test-compat")
            for args in ([output], ["--sign", IDENTITY, output], ["--signed-xpc-test", IDENTITY, "--compat", output],
                         ["--sign", IDENTITY, "--prepare-compatibility=rtm096-full-nine-v3", output],
                         ["--sign", IDENTITY, "--compat", str(root / "ordinary")]):
                log.write_text("")
                result = subprocess.run([script, *args], env=env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(log.read_text(), "")

    def test_guest_tag_selection_and_honest_metadata_tail(self):
        source = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        functions = source[source.index("guest_go() {"):source.index('mkdir -p "$BINARY_OUTPUT/out"')]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); go = root / "go"
            go.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n'); go.chmod(0o755)
            env = selected(GO=str(go), GUEST_GO_CACHE=temp, PREPARE_COMPATIBILITY_PROFILE="", OUTPUT=temp, LIFECYCLE_SOURCE_PIN="a" * 64)
            result = subprocess.run(["sh", "-eu"], input=functions + '\nguest_go build ./cmd/cengine-init\nstorage_go list ./cmd/cengine-storage\nstorage_go build ./cmd/cengine-storage\n', env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertNotIn("-tags", lines[0])
            for line in lines[1:]: self.assertIn("-tags=cengine_lifecycle_v2_qualification", line)
            for name in ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"):
                (root / name).write_text(name)
            result = subprocess.run(["sh", "-eu"], input=source[source.index('python3 - "$OUTPUT"'):], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads((root / "disk-bootstrap.json").read_text())
            self.assertEqual(metadata[Q.PROFILE_FIELD], Q.PROFILE)
            self.assertEqual(metadata[Q.SOURCE_FIELD], "a" * 64)
            self.assertEqual(metadata["storageServiceBootVersion"], 2)
            self.assertEqual(metadata["storageLifecycleVersion"], 2)
            self.assertNotIn("ordinaryProvenance", metadata)

    def test_unknown_and_incompatible_guest_profiles_fail_before_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); marker = root / "keep"; marker.write_text("preserve")
            for env, args in (({**selected(), Q.ENV: "unknown"}, []),
                              (selected(), ["--prepare-compatibility=rtm096-full-nine-v3"]),
                              ({**selected(), "CENGINE_DEVELOPER_ID_APPLICATION": "-"}, []),
                              (selected(), [])):
                result = subprocess.run(["sh", str(ROOT / "Scripts/build-guest-assets.sh"), *args], env={**env, "CENGINE_GUEST_OUTPUT": temp}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(root.iterdir()), [marker])

    def test_helper_fingerprint_changes_with_profile_and_native_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); policy = fixture(root)
            source = (ROOT / "Scripts/network-helper-fingerprint.sh").read_text()
            manifest = 'Configuration/helper-support-sources.txt'
            shutil.copyfile(ROOT / manifest, root / manifest)
            for name in (root / manifest).read_text().splitlines():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists(): path.write_text(name)
            helper = root / "Sources/CEngineNetworkHelper/main.swift"
            helper.parent.mkdir(parents=True); helper.write_text("// helper fixture")
            version = root / "version"
            version.write_text("#!/bin/sh\necho fixture-toolchain\n"); version.chmod(0o755)
            source = source.replace("/usr/bin/xcrun", str(version)).replace("/usr/bin/xcodebuild", str(version))
            def fingerprint(env):
                result = subprocess.run(["sh", "-eu", "-c", source, str(root / "Scripts/network-helper-fingerprint.sh")], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout.strip()
            directory = root / Q.PROFILE / "guest"
            assets(directory, Q.source_pin(root))
            env = selected(CENGINE_COMPAT_MANAGED_ASSET_DIR=str(directory))
            ordinary = fingerprint(environment())
            qualified = fingerprint(env)
            self.assertNotEqual(ordinary, qualified)
            assets(directory, Q.source_pin(root), b"different-build-same-sources")
            self.assertNotEqual(qualified, fingerprint(env))
            self.assertEqual(ordinary, fingerprint(environment(CENGINE_COMPAT_MANAGED_ASSET_DIR="/missing")))
            policy.write_text("// changed native policy")
            assets(directory, Q.source_pin(root))
            self.assertNotEqual(qualified, fingerprint(env))
            self.assertNotEqual(ordinary, fingerprint(environment()))

    def test_signed_plist_and_fingerprint_inputs(self):
        for name in ("cengine-Info.plist", "network-helper-Info.plist"):
            value = plistlib.loads((ROOT / "Configuration" / name).read_bytes())
            self.assertEqual(value["CEngineStorageLifecycleQualification"], "$(CENGINE_STORAGE_LIFECYCLE_QUALIFICATION)")
            self.assertEqual(value["CEngineStorageLifecycleSourcePin"], "$(CENGINE_STORAGE_LIFECYCLE_SOURCE_PIN)")
            self.assertEqual(value["CEngineStorageLifecycleAssetsSHA256"], "$(CENGINE_STORAGE_LIFECYCLE_ASSETS_SHA256)")
        source = (ROOT / "Scripts/network-helper-fingerprint.sh").read_text()
        manifest = 'Configuration/helper-support-sources.txt'
        self.assertIn(f'fingerprint_file "$ROOT/{manifest}"', source)
        self.assertIn(f'done < "$ROOT/{manifest}"', source)
        self.assertIn('fingerprint_file "$ROOT/$relative"', source)
        self.assertIn('Sources/CEngineCore/StorageLifecycleNativePolicy.swift',
                      (ROOT / manifest).read_text().splitlines())
        self.assertIn('"$QUALIFICATION" "$SOURCE_PIN"', source)
        guards = (ROOT / "Scripts/compat-network-helper.sh").read_text()
        self.assertIn('[ "$(compat_network_helper_installed_fingerprint)" = "$_cnh_exact_fingerprint" ]', guards)
        self.assertIn('exact) compat_network_helper_require_exact "$_cnh_managed_binary" "$_cnh_managed_fingerprint" || return $?;;', guards)
        self.assertIn('[ "$_cnh_local_code" = "$_cnh_installed_code" ]', guards)


if __name__ == "__main__":
    unittest.main()
