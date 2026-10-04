#!/usr/bin/env python3
"""Inactive provenance regressions: no guest execution, VM, Docker or elevation."""
import copy
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Scripts"))
import guest_asset_provenance as P  # pyright: ignore[reportMissingImports]

SPEC = importlib.util.spec_from_file_location("initramfs", ROOT / "Scripts/make-initramfs.py")
assert SPEC is not None and SPEC.loader is not None
ARCHIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVE)


def record(name, payload=b"data", inode=1, mode=stat.S_IFREG | 0o755, nlink=1):
    return ARCHIVE.record(name, mode, payload, inode, 0, nlink)


def archive(init=b"init", extra=b""):
    return gzip.compress(record("init", init) + record("sbin/mke2fs", b"mke2fs", 2) + extra + record("TRAILER!!!", b"", 100))


def buildinfo(command="cengine-init"):
    return {"GoVersion": "go1.26.5", "Path": f"{P.MODULE}/cmd/{command}",
            "Main": {"Path": P.MODULE, "Version": "(devel)"},
            "Settings": [{"Key": key, "Value": value} for key, value in P.REQUIRED_SETTINGS.items()]}


class ProvenanceTests(unittest.TestCase):
    def test_current_source_check_never_relabels_stale_or_test_only_receipts(self):
        metadata = {'ordinaryProvenance': dict(schemaVersion=1, policy=P.POLICY, sourceSHA256='a' * 64)}
        with patch.object(P, 'source_pin', return_value='a' * 64):
            P.assert_current_source(ROOT, metadata)
            for value in ({}, {'ordinaryProvenance': None},
                          {'ordinaryProvenance': dict(metadata['ordinaryProvenance'], sourceSHA256='b' * 64)},
                          {'ordinaryProvenance': dict(metadata['ordinaryProvenance'], schemaVersion=True)},
                          {'ordinaryProvenance': dict(metadata['ordinaryProvenance'], policy='other')},
                          *[dict(metadata, **{key: 'test-only'}) for key in (
                              'storageLifecycleQualification', 'storageLifecycleSourcePin',
                              'prepareCompatibilityProfile', 'prepareCompatibilitySourceSHA256')]):
                before = copy.deepcopy(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    P.assert_current_source(ROOT, value)
                self.assertEqual(before, value)

    def test_canonical_archive_and_rejections(self):
        self.assertEqual(P.inspect_archive(archive()), {"init": b"init", "sbin/mke2fs": b"mke2fs"})
        for extra in (record("init", inode=3), record("./init", inode=3), record("/init", inode=3),
                      record("foo/../init", inode=3), record("foo//init", inode=3),
                      record("link", inode=3, mode=stat.S_IFLNK | 0o777), record("link", inode=1),
                      record("link", inode=3, nlink=2)):
            with self.subTest(extra=extra[:100]), self.assertRaises(ValueError):
                P.inspect_archive(archive(extra=extra))
        data = archive()
        for bad in (data[:-1], data + data, data + b"junk", gzip.compress(b"garbage"),
                    gzip.compress(gzip.decompress(data) + gzip.decompress(data)),
                    gzip.compress(gzip.decompress(data)[:-100])):
            with self.subTest(bad=bad[:10]), self.assertRaises((ValueError, P.zlib.error)):
                P.inspect_archive(bad)
        with patch.object(P, "MAX_ARCHIVE", 64), self.assertRaises(ValueError):
            P.inspect_archive(data)
        with patch.object(P, "MAX_COMPRESSED", 10), self.assertRaises(ValueError):
            P.inspect_archive(data)
        with patch.object(P, "MAX_BINARY", 1), self.assertRaises(ValueError):
            P.inspect_archive(data)

    def test_buildinfo_is_closed_and_does_not_trust_profile_labels(self):
        self.assertEqual(P.validate_buildinfo(buildinfo(), "cengine-init"), "go1.26.5")
        mutations = [{}, {**buildinfo(), "Path": f"{P.MODULE}/cmd/cengine-storage"},
                     {**buildinfo(), "Main": {"Path": "other", "Version": "(devel)"}},
                     {**buildinfo(), "GoVersion": ""}]
        for key in P.REQUIRED_SETTINGS:
            bad = buildinfo()
            bad["Settings"] = [setting for setting in bad["Settings"] if setting["Key"] != key]
            mutations.append(bad)
        for key, value in (("-tags", "cengine_prepare_full_compat"),
                           ("-tags", "cengine_lifecycle_v2_qualification"), ("-race", "true"),
                           ("-cover", "true"), ("GOEXPERIMENT", "anything"), ("-ldflags", "-X injected"),
                           ("CGO_ENABLED", "1"), ("GOARM64", "v9.0")):
            bad = buildinfo()
            bad["Settings"].append({"Key": key, "Value": value})
            mutations.append(bad)
        for bad in mutations:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                P.validate_buildinfo(bad, "cengine-init")

    def test_selected_gofiles_not_ignored_or_test_files(self):
        packages = [{"ImportPath": f"{P.MODULE}/{name}", "GoFiles": sorted(files),
                     "IgnoredGoFiles": ["profile_enabled.go", "native_fault_linux.go"],
                     "TestGoFiles": ["enabled_test.go"]} for name, files in (P.INERT | P.LIFECYCLE).items()]
        def document():
            return "\n".join(json.dumps(package) for package in packages)
        P.audit_selected([document()])
        for index in range(len(packages)):
            saved = packages[index]["GoFiles"]
            packages[index]["GoFiles"] = ["enabled.go"]
            with self.assertRaises(ValueError):
                P.audit_selected([document()])
            packages[index]["GoFiles"] = saved
        packages[0]["GoFiles"].append("profile_enabled.go")
        with self.assertRaises(ValueError):
            P.audit_selected([document()])
        with self.assertRaises(ValueError):
            P.audit_selected([])

    def fixture(self, root):
        output = root / "output"
        output.mkdir()
        for name in P.ASSETS[:3]:
            (output / name).write_bytes(b"kernel" if name == "vmlinux" else archive())
        return output

    def publish(self, output, provenance):
        metadata: dict[str, Any] = {key: 1 for key in ("schemaVersion", "protocolVersion", "storageServiceBootVersion", "workloadStorageBootVersion")}
        metadata["storageServiceBootVersion"] = 2
        metadata["storageLifecycleVersion"] = 2
        metadata.update({f"{kind}InitramfsSHA256": P.digest((output / f"{kind}-initramfs.cpio.gz").read_bytes()) for kind in ("container", "storage")})
        metadata["ordinaryProvenance"] = provenance
        self.write_metadata(output, metadata)
        return metadata

    def write_metadata(self, output, metadata):
        (output / "disk-bootstrap.json").write_text(json.dumps(metadata))
        (output / "SHA256SUMS").write_text("".join(f"{P.digest((output / name).read_bytes())}  {name}\n" for name in P.ASSETS))

    def test_validator_binds_exact_typed_metadata_source_kernel_and_actual_images(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(P, "source_pin", return_value="a" * 64), \
                patch.object(P, "kernel_config", return_value=("kernel-v1", "b" * 64)), \
                patch.object(P, "binary_info", side_effect=lambda go, payload, command: {"sha256": P.digest(payload), "goVersion": "go1.26.5"}):
            root = Path(temp)
            output = self.fixture(root)
            receipt = P.kernel_receipt(root, output / "vmlinux", "canonical-release")
            P.atomic_json(output / P.RECEIPT, receipt)
            value = P.provenance(root, output, Path("go"), "a" * 64)
            metadata = self.publish(output, value)
            P.validate(root, output, Path("go"))
            # Compatibility accepts ordinary local kernels, but still inspects
            # real archive/default Go build metadata and current source receipt.
            local = copy.deepcopy(value)
            local['kernel'] = P.kernel_receipt(root, output / 'vmlinux', 'unverified')
            self.publish(output, local)
            P.validate(root, output, Path('go'), require_release_kernel=False)
            with self.assertRaises(ValueError):
                P.validate(root, output, Path('go'))
            self.write_metadata(output, metadata)
            (output / P.RECEIPT).unlink()  # Staged distribution needs no sidecar.
            P.validate(root, output, Path("go"))
            changes = [((), "schemaVersion", True), (("ordinaryProvenance",), "schemaVersion", True),
                       ((), "storageServiceBootVersion", 1), ((), "storageServiceBootVersion", True),
                       ((), "storageLifecycleVersion", 1), ((), "storageLifecycleVersion", 3),
                       ((), "storageLifecycleVersion", True), ((), "storageLifecycleVersion", "2"),
                       (("ordinaryProvenance",), "sourceSHA256", "c" * 64),
                       (("ordinaryProvenance",), "policy", "relabeled-full-nine"),
                       (("ordinaryProvenance", "kernel"), "origin", "local"),
                       (("ordinaryProvenance", "kernel"), "origin", "custom-release"),
                       (("ordinaryProvenance", "kernel"), "origin", "unverified"),
                       (("ordinaryProvenance", "kernel"), "sha256", "d" * 64),
                       (("ordinaryProvenance", "kernel"), "release", "other"),
                       (("ordinaryProvenance", "kernel"), "inputSHA256", "d" * 64),
                       (("ordinaryProvenance", "containerBinary"), "goVersion", "go1.25.0"),
                       (("ordinaryProvenance", "storageBinary"), "sha256", "d" * 64),
                       (("ordinaryProvenance",), "mke2fsSHA256", "d" * 64),
                       ((), "containerInitramfsSHA256", "d" * 64), ((), "prepareCompatibilityProfile", "rtm096-full-nine-v3"),
                       ((), "storageLifecycleQualification", "lifecycle-v2-native-v1"),
                       ((), "storageLifecycleSourcePin", "e" * 64)]
            for path, key, replacement in changes:
                bad = copy.deepcopy(metadata)
                target = bad
                for part in path:
                    target = target[part]
                target[key] = replacement
                self.write_metadata(output, bad)
                with self.subTest(path=path, key=key), self.assertRaises(ValueError):
                    P.validate(root, output, Path("go"))
            self.write_metadata(output, metadata)
            (output / "container-initramfs.cpio.gz").write_bytes(archive(init=b"changed"))
            with self.assertRaises(ValueError):
                P.validate(root, output, Path("go"))
            del metadata["storageLifecycleVersion"]
            self.write_metadata(output, metadata)
            with self.assertRaises(ValueError):
                P.validate(root, output, Path("go"))
            metadata["storageLifecycleVersion"] = 2
            del metadata["ordinaryProvenance"]
            self.write_metadata(output, metadata)
            with self.assertRaises(ValueError):
                P.validate(root, output, Path("go"))

    def test_go_inspector_uses_private_file_and_closed_environment(self):
        observed = []
        ambient = {"HOME": "/hostile/home", "XDG_CONFIG_HOME": "/hostile/config",
                   "GOENV": "/hostile/goenv", "GOFLAGS": "-tags=injected", "GOEXPERIMENT": "injected",
                   "GOTELEMETRY": "on", "GOTELEMETRYDIR": "/hostile/telemetry",
                   "TEST_TELEMETRY_DIR": "/hostile/test-telemetry", "GO_TELEMETRY_CHILD": "1",
                   "GO_TELEMETRY_CHILD_UPLOAD": "1"}
        def run(args, **kwargs):
            binary = Path(args[-1])
            self.assertEqual(binary.name, "guest")
            self.assertEqual(binary.read_bytes(), b"ELF")
            self.assertEqual(stat.S_IMODE(binary.parent.stat().st_mode), 0o700)
            self.assertEqual(kwargs["env"]["GOENV"], "off")
            self.assertEqual(kwargs["env"]["GOFLAGS"], "")
            self.assertEqual(kwargs["env"]["HOME"], str(binary.parent))
            for key in ambient.keys() - {"HOME", "GOENV", "GOFLAGS"}:
                self.assertNotIn(key, kwargs["env"])
            config = "Library/Application Support" if sys.platform == "darwin" else ".config"
            telemetry = binary.parent / config / "go/telemetry"
            self.assertEqual((telemetry / "mode").read_text(), "off\n")
            self.assertEqual(list(telemetry.iterdir()), [telemetry / "mode"])
            observed.append(binary.parent)
            return subprocess.CompletedProcess(args, 0, json.dumps(buildinfo()).encode())
        with patch.dict(os.environ, ambient), patch.object(P.subprocess, "run", side_effect=run):
            self.assertEqual(P.binary_info(Path("/trusted/go"), b"ELF", "cengine-init")["sha256"], P.digest(b"ELF"))
            with self.assertRaisesRegex(ValueError, "unexpected guest command"):
                P.binary_info(Path("/trusted/go"), b"ELF", "cengine-storage")
        for directory in observed:
            self.assertFalse(directory.exists())

    def test_closed_environment_disables_real_go_telemetry(self):
        go = ROOT / ".build/toolchains/go1.26.5.darwin-arm64/go/bin/go"
        if not go.is_file():
            self.skipTest("pinned host Go is not installed; no provisioning in unit tests")
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp)
            with patch.dict(os.environ, {"GOTELEMETRY": "on", "GOTELEMETRYDIR": "/hostile/telemetry",
                                         "XDG_CONFIG_HOME": "/hostile/config", "TEST_TELEMETRY_DIR": "/hostile/test",
                                         "GO_TELEMETRY_CHILD": "1", "GO_TELEMETRY_CHILD_UPLOAD": "1"}):
                environment = P.closed_environment(cache)
            result = subprocess.check_output([str(go), "env", "GOTELEMETRY", "GOTELEMETRYDIR"],
                                             env=environment, text=True, timeout=30)
            mode, directory = result.splitlines()
            self.assertEqual(mode, "off")
            telemetry = Path(directory)
            self.assertTrue(telemetry.is_relative_to(cache))
            self.assertEqual(list(telemetry.iterdir()), [telemetry / "mode"])
        self.assertFalse(cache.exists())

    def test_source_pin_contains_new_validator_and_mke2fs_version(self):
        from prepare_compatibility_assets import BUILD_INPUTS  # pyright: ignore[reportMissingImports]
        self.assertIn("Scripts/guest_asset_provenance.py", BUILD_INPUTS)
        self.assertIn("Scripts/storage_lifecycle_qualification.py", BUILD_INPUTS)
        self.assertIn("Configuration/e2fsprogs-version", BUILD_INPUTS)

    def test_real_stripped_ordinary_and_tagged_binaries(self):
        go = ROOT / ".build/toolchains/go1.26.5.darwin-arm64/go/bin/go"
        if not go.is_file():
            self.skipTest("pinned host Go is not installed; no provisioning in unit tests")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "go.mod").write_text(f"module {P.MODULE}\n\ngo 1.25.0\n")
            cache = root / "cache"
            cache.mkdir()
            environment = P.closed_environment(cache)
            for command in ("cengine-init", "cengine-storage"):
                source = root / "cmd" / command
                source.mkdir(parents=True)
                (source / "main.go").write_text("package main\nfunc main() {}\n")
                for tagged in (False, True):
                    binary = root / "guest"
                    args = [str(go), "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", str(binary)]
                    if tagged:
                        args.append("-tags=cengine_prepare_full_compat")
                    subprocess.run([*args, "./cmd/" + command], cwd=root, env=environment, check=True, capture_output=True)
                    payload = binary.read_bytes()
                    if tagged:
                        with self.assertRaisesRegex(ValueError, "tagged"):
                            P.binary_info(go, payload, command)
                    else:
                        self.assertEqual(P.binary_info(go, payload, command)["goVersion"], "go1.26.5")
                        stripped_info = payload.replace(b"go1.26.5", b"XXXXXXXX")
                        with self.assertRaises((ValueError, subprocess.SubprocessError)):
                            P.binary_info(go, stripped_info, command)

    def test_release_entrypoints_fail_before_xcode_or_signing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("Scripts", "Configuration"):
                shutil.copytree(ROOT / name, root / name)
            (root / "Scripts/ensure-go-toolchain.sh").write_text("#!/bin/sh\nprintf '/unused/trusted/go\\n'\n")
            binary = root / "bin"
            binary.mkdir()
            marker = root / "expensive-called"
            for name in ("xcodebuild", "codesign"):
                tool = binary / name
                tool.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
                tool.chmod(0o755)
            for name in ("build-release.sh", "package-release.sh"):
                environment = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}", "CENGINE_RELEASE_VERSION": "1.0.0",
                               "CENGINE_SIGN_RELEASE": "0", "CENGINE_NOTARIZE": "0"}
                result = subprocess.run(["zsh", str(root / "Scripts" / name)], env=environment, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ordinary guest assets refused", result.stderr)
                self.assertFalse(marker.exists())

    def test_build_source_pin_checks_before_and_after_inspection(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(P, "kernel_config", return_value=("kernel-v1", "b" * 64)), \
                patch.object(P, "binary_info", return_value={"sha256": "c" * 64, "goVersion": "go1.26.5"}):
            root = Path(temp)
            output = self.fixture(root)
            with patch.object(P, "source_pin", return_value="b" * 64), self.assertRaisesRegex(ValueError, "during build"):
                P.provenance(root, output, Path("go"), "a" * 64)
            with patch.object(P, "source_pin", side_effect=["a" * 64, "b" * 64]), self.assertRaisesRegex(ValueError, "while inspecting"):
                P.provenance(root, output, Path("go"), "a" * 64)

    def test_duplicate_json_is_rejected(self):
        with self.assertRaises(ValueError):
            P.load_json('{"schemaVersion":1,"schemaVersion":1}')

    def test_failed_build_invalidates_old_metadata_before_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            for name in ("disk-bootstrap.json", "SHA256SUMS"):
                (output / name).write_text("old claim")
            result = subprocess.run(["sh", str(ROOT / "Scripts/build-guest-assets.sh")],
                                    env={**os.environ, "CENGINE_GUEST_OUTPUT": str(output)}, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((output / "disk-bootstrap.json").exists())
            self.assertFalse((output / "SHA256SUMS").exists())


class FetchTests(unittest.TestCase):
    def test_canonical_fetch_fastpath_and_cache_never_promote_custom_or_legacy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("Scripts", "Configuration"):
                shutil.copytree(ROOT / name, root / name)
            downloads = root / "downloads"
            downloads.mkdir()
            _, inputs = P.kernel_config(root)
            for name, data in (("cengine-kernel-arm64", b"canonical"), ("kernel-input.sha256", (inputs + "\n").encode())):
                (downloads / name).write_bytes(data)
            (downloads / "SHA256SUMS").write_text("".join(f"{P.digest((downloads / name).read_bytes())}  {name}\n" for name in ("cengine-kernel-arm64", "kernel-input.sha256")))
            binary = root / "bin"
            binary.mkdir()
            curl = binary / "curl"
            curl.write_text(f'#!{sys.executable}\nimport pathlib,sys,shutil\nargs=sys.argv[1:]\npathlib.Path({str(root / "calls")!r}).open("a").write(args[-1]+"\\n")\nshutil.copyfile(pathlib.Path({str(downloads)!r})/args[-1].split("/")[-1],args[args.index("--output")+1])\n')
            curl.chmod(0o755)
            output = root / "output"
            output.mkdir()
            environment = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
                           "CENGINE_GUEST_OUTPUT": str(output), "CENGINE_GUEST_CACHE": str(root / "cache")}
            for key in ("CENGINE_LOCAL_KERNEL", "CENGINE_KERNEL_RELEASE_BASE_URL", "CENGINE_KERNEL_FORCE"):
                environment.pop(key, None)
            def fetch(**extra):
                subprocess.run([str(root / "Scripts/fetch-kernel.sh")], env={**environment, **extra}, check=True, capture_output=True)
                return json.loads((output / P.RECEIPT).read_text())["origin"]
            self.assertEqual(fetch(CENGINE_KERNEL_RELEASE_BASE_URL="https://custom.invalid/release"), "custom-release")
            self.assertEqual(fetch(), "canonical-release")
            self.assertEqual(len((root / "calls").read_text().splitlines()), 6)
            self.assertEqual(fetch(), "canonical-release")
            self.assertEqual(len((root / "calls").read_text().splitlines()), 6)
            (output / "vmlinux").write_bytes(b"changed")
            self.assertEqual(fetch(), "canonical-release")
            self.assertEqual((output / "vmlinux").read_bytes(), b"canonical")
            (output / P.RECEIPT).unlink()
            (output / "vmlinux").write_bytes(b"legacy stamp cannot bless this")
            self.assertEqual(fetch(), "canonical-release")
            self.assertEqual((output / "vmlinux").read_bytes(), b"canonical")
            local = root / "local"
            local.write_bytes(b"local")
            for name in ("disk-bootstrap.json", "SHA256SUMS"):
                (output / name).write_text("old")
            self.assertEqual(fetch(CENGINE_LOCAL_KERNEL=str(local)), "local")
            self.assertFalse((output / "disk-bootstrap.json").exists())
            self.assertFalse((output / "SHA256SUMS").exists())
            self.assertEqual(fetch(), "canonical-release")
            # A cached receipt does not bless changed bytes, even if the attacker
            # rewrites the non-origin checksum manifest to agree with those bytes.
            release, _ = P.kernel_config(root)
            cache = root / "cache/kernel-releases/canonical" / release
            (cache / "cengine-kernel-arm64").write_bytes(b"cache contamination")
            (cache / "SHA256SUMS").write_text("".join(f"{P.digest((cache / name).read_bytes())}  {name}\n" for name in ("cengine-kernel-arm64", "kernel-input.sha256")))
            (output / P.RECEIPT).unlink()
            self.assertEqual(fetch(), "canonical-release")
            self.assertEqual(len((root / "calls").read_text().splitlines()), 9)
            self.assertEqual((output / "vmlinux").read_bytes(), b"canonical")
            self.assertEqual(fetch(CENGINE_KERNEL_RELEASE_BASE_URL="https://custom.invalid/release"), "custom-release")
            (downloads / "cengine-kernel-arm64").write_bytes(b"second custom source")
            (downloads / "SHA256SUMS").write_text("".join(f"{P.digest((downloads / name).read_bytes())}  {name}\n" for name in ("cengine-kernel-arm64", "kernel-input.sha256")))
            self.assertEqual(fetch(CENGINE_KERNEL_RELEASE_BASE_URL="https://other-custom.invalid/release"), "custom-release")
            self.assertEqual((output / "vmlinux").read_bytes(), b"second custom source")


if __name__ == "__main__":
    unittest.main()
