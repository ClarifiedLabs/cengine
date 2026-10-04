#!/usr/bin/env python3
"""Engine-free profile/source-pin regressions; never compile or boot guest assets."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_compatibility_assets", ROOT / "Scripts/prepare_compatibility_assets.py")
assert SPEC is not None and SPEC.loader is not None
PROFILE: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class PrepareCompatibilityAssetTests(unittest.TestCase):
    def source(self, root):
        for name in PROFILE.BUILD_INPUTS:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        guest = root / "Guest"
        guest.mkdir()
        (guest / "go.mod").write_text("module fixture\n")
        (guest / "main.go").write_text("package main\n")
        return guest

    def test_ordinary_metadata_is_inert_without_source_access(self):
        PROFILE.validate_metadata({}, Path("/no/such/source"))

    def test_profile_requires_exact_pair_and_current_source_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = self.source(root)
            pin = PROFILE.source_pin(root)
            metadata = {PROFILE.PROFILE_FIELD: PROFILE.PROFILE, PROFILE.SOURCE_FIELD: pin}
            PROFILE.validate_metadata(metadata, root)
            for bad in (
                {PROFILE.PROFILE_FIELD: PROFILE.PROFILE}, {PROFILE.SOURCE_FIELD: pin},
                {**metadata, PROFILE.PROFILE_FIELD: "unknown"},
                {**metadata, PROFILE.SOURCE_FIELD: "A" * 64},
                {**metadata, PROFILE.SOURCE_FIELD: None},
                {**metadata, PROFILE.SOURCE_FIELD: "0" * 64},
            ):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    PROFILE.validate_metadata(bad, root)
            (guest / "main.go").write_text("package changed\n")
            with self.assertRaisesRegex(ValueError, "source pin mismatch"):
                PROFILE.validate_metadata(metadata, root)

    def test_build_scripts_and_configuration_are_in_source_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.source(root)
            for name in PROFILE.BUILD_INPUTS:
                before = PROFILE.source_pin(root)
                path = root / name
                path.write_bytes(path.read_bytes() + b"changed")
                self.assertNotEqual(before, PROFILE.source_pin(root), name)

    def test_all_regular_guest_files_change_pin_and_reject_stale_metadata(self):
        # A log/dotfile can be a go:embed input; there are no artifact exclusions.
        names = ("new_test.go", "build.log", "entry.s", "entry.S", "native.c",
                 "native.cc", "native.cpp", "native.cxx", "native.h", "native.syso",
                 "assets/arbitrary.bin", "assets/.hidden", ".payload/data",
                 "vendor/modules.txt", "vendor/dependency/.vendor-config")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = self.source(root)
            for name in names:
                with self.subTest(name=name):
                    path = guest / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    before_add = PROFILE.source_pin(root)
                    path.write_bytes(b"first contents")
                    before_change = PROFILE.source_pin(root)
                    self.assertNotEqual(before_add, before_change)
                    metadata = {PROFILE.PROFILE_FIELD: PROFILE.PROFILE,
                                PROFILE.SOURCE_FIELD: before_change}
                    PROFILE.validate_metadata(metadata, root)
                    path.write_bytes(b"second contents")
                    self.assertNotEqual(before_change, PROFILE.source_pin(root))
                    with self.assertRaisesRegex(ValueError, "source pin mismatch"):
                        PROFILE.validate_metadata(metadata, root)

    def test_deleted_selectors_change_pin_and_universal_main_remains_in_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = self.source(root)
            main = guest / "cmd/cengine-storage/main.go"
            main.parent.mkdir(parents=True)
            main.write_text("package main\n")
            selector = main.with_name("lifecycle_disabled_linux.go")
            selector.write_text("// obsolete selector\n")
            before = PROFILE.source_pin(root)
            selector.unlink()
            self.assertNotEqual(before, PROFILE.source_pin(root))
            self.assertIn("Guest/cmd/cengine-storage/main.go", PROFILE.source_inventory(root))
            self.assertNotIn("Guest/cmd/cengine-storage/lifecycle_disabled_linux.go", PROFILE.source_inventory(root))

    def test_source_symlink_and_byte_bounds_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = self.source(root)
            link = guest / "link.go"
            link.symlink_to(guest / "main.go")
            with self.assertRaises(ValueError):
                PROFILE.source_pin(root)
            link.unlink()
            link = guest / "directory"
            link.symlink_to(root / "Scripts", target_is_directory=True)
            with self.assertRaises(ValueError):
                PROFILE.source_pin(root)
            link.unlink()
            old = PROFILE.MAX_SOURCE_BYTES
            try:
                PROFILE.MAX_SOURCE_BYTES = 1
                with self.assertRaises(ValueError):
                    PROFILE.source_pin(root)
            finally:
                PROFILE.MAX_SOURCE_BYTES = old

    def test_empty_missing_nonregular_and_file_count_bounds_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = self.source(root)
            with patch.object(PROFILE, "MAX_FILES", len(PROFILE.BUILD_INPUTS) + 1):
                with self.assertRaisesRegex(ValueError, "file bound"):
                    PROFILE.source_pin(root)
            fifo = guest / "payload.bin"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "non-regular"):
                PROFILE.source_pin(root)
            fifo.unlink()
            for path in guest.iterdir():
                path.unlink()
            with self.assertRaisesRegex(ValueError, "no files"):
                PROFILE.source_pin(root)
            guest.rmdir()
            with self.assertRaisesRegex(ValueError, "source directory required"):
                PROFILE.source_pin(root)
            guest.symlink_to(root / "Scripts", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "source directory required"):
                PROFILE.source_pin(root)

    def test_extensionless_and_dangling_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest = self.source(root)
            for target in (guest / "main.go", guest / "missing"):
                link = guest / ".embedded-link"
                link.symlink_to(target)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    PROFILE.source_pin(root)
                link.unlink()

    def test_unreadable_inventory_walk_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.source(root)
            def failed_walk(*args, **kwargs):
                kwargs["onerror"](PermissionError("unreadable source subtree"))
            with patch.object(PROFILE.os, "walk", failed_walk):
                with self.assertRaises(PermissionError):
                    PROFILE.source_pin(root)

    def audit_fixture(self, root):
        guest = self.source(root)
        goroot = root / "toolchain"
        standard = goroot / "src/runtime"
        standard.mkdir(parents=True)
        (standard / "runtime.go").write_text("package runtime\n")
        package = {"Dir": str(guest), "GoFiles": ["main.go"],
                   "Module": {"Dir": str(guest), "GoMod": str(guest / "go.mod")}}
        stdlib = {"Dir": str(standard), "Standard": True, "Goroot": True,
                  "GoFiles": ["runtime.go"]}
        return guest, goroot, package, stdlib

    def test_selected_input_audit_covers_all_file_kinds_and_trusts_only_stdlib(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            guest, goroot, package, stdlib = self.audit_fixture(root)
            for field, name in (("CgoFiles", "cgo.go"), ("CFiles", "native.c"),
                                ("CXXFiles", "native.cpp"), ("HFiles", "native.h"),
                                ("MFiles", "native.m"), ("FFiles", "native.f"),
                                ("SFiles", "native.S"), ("SysoFiles", "native.syso"),
                                ("SwigFiles", "native.swig"), ("SwigCXXFiles", "native.swigcxx"),
                                ("EmbedFiles", ".arbitrary-payload")):
                (guest / name).write_bytes(b"inventoried input")
                package[field] = [name]
            document = json.dumps(stdlib) + "\n" + json.dumps(package)
            PROFILE.audit_selected_inputs(root, goroot, [document])
            # No claim to hash stdlib; its contents are separately trusted.
            pin = PROFILE.source_pin(root)
            (goroot / "src/runtime/runtime.go").write_text("separate provenance")
            self.assertEqual(pin, PROFILE.source_pin(root))
            PROFILE.audit_selected_inputs(root, goroot, [document])
            for bad in ({**stdlib, "Goroot": False},
                        {**stdlib, "Dir": str(root)},
                        {**stdlib, "Standard": False}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    PROFILE.audit_selected_inputs(root, goroot, [json.dumps(bad)])

    def test_audit_allows_checkout_toolchain_parent_aliases_but_not_guest_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            root = parent / "project"
            guest, goroot, package, stdlib = self.audit_fixture(root)
            alias = parent / "alias"
            alias.symlink_to(root, target_is_directory=True)
            document = (json.dumps(stdlib) + json.dumps(package)).replace(str(root), str(alias))
            PROFILE.audit_selected_inputs(root, goroot, [document])
            link = guest / "injected"
            link.symlink_to(guest / "main.go")
            with self.assertRaisesRegex(ValueError, "symlink"):
                PROFILE.audit_selected_inputs(root, goroot, [document])

    def test_selected_external_uninventoried_overlay_and_module_inputs_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            guest, goroot, package, _ = self.audit_fixture(root)
            external = root / "external"
            external.mkdir()
            (external / "injected.go").write_text("package external\n")
            cases = [
                {**package, "Dir": str(external)},
                {**package, "GoFiles": [str(external / "injected.go")]},
                {**package, "GoFiles": ["../external/injected.go"]},
                {**package, "EmbedFiles": ["not-in-inventory"]},
                {**package, "CompiledGoFiles": [str(external / "injected.go")]},
                {**package, "Module": {"Dir": str(external)}},
                {**package, "Module": {"GoMod": str(external / "go.mod")}},
                {**package, "Module": {"Replace": {"Dir": str(external)}}},
            ]
            for bad in cases:
                with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "external|uninventoried"):
                    PROFILE.audit_selected_inputs(root, goroot, [json.dumps(bad)])
            # Simulate a selected file appearing after the bounded inventory.
            inventory = PROFILE.source_inventory(root)
            (guest / "injected.go").write_text("package injected\n")
            with patch.object(PROFILE, "source_inventory", return_value=inventory):
                with self.assertRaisesRegex(ValueError, "uninventoried"):
                    PROFILE.audit_selected_inputs(root, goroot, [json.dumps({**package, "GoFiles": ["injected.go"]})])

    def test_empty_incomplete_and_oversized_selected_audits_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            _, goroot, package, _ = self.audit_fixture(root)
            for documents in ([], [""], [" \n"], ["{}"],
                              [json.dumps({**package, "GoFiles": []})],
                              [json.dumps({**package, "Incomplete": True})],
                              [json.dumps({**package, "Error": {"Err": "bad input"}})]):
                with self.subTest(documents=documents), self.assertRaises(ValueError):
                    PROFILE.audit_selected_inputs(root, goroot, documents)
            document = json.dumps(package)
            with patch.object(PROFILE, "MAX_AUDIT_BYTES", len(document) - 1):
                with self.assertRaisesRegex(ValueError, "audit byte bound"):
                    PROFILE.audit_selected_inputs(root, goroot, [document])
            with patch.object(PROFILE, "MAX_FILES", len(PROFILE.source_inventory(root))):
                with self.assertRaisesRegex(ValueError, "package bound"):
                    PROFILE.audit_selected_inputs(root, goroot, [document * (PROFILE.MAX_FILES + 1)])

    def test_all_go_environments_are_closed_offline_and_vendor_without_ambient_tags(self):
        builder = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        wrapper = builder[builder.index("guest_go() {"):builder.index('mkdir -p "$BINARY_OUTPUT/out"')]
        self.assertNotIn("PREPARE_GO_CACHE", wrapper)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_go = root / "go"
            fake_go.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                               "print(json.dumps({'args': sys.argv[1:], 'env': dict(os.environ)}))\n")
            fake_go.chmod(0o755)
            hostile = dict(os.environ, GO=str(fake_go), GUEST_GO_CACHE=str(root / "cache"),
                           GOFLAGS="-overlay=/external/overlay.json -modfile=/external/go.mod -tags=hostile",
                           GOWORK="/external/go.work", GOENV="/external/go-env", GOROOT="/external/go",
                           GOEXPERIMENT="injected", GOCACHEPROG="external-command",
                           GOTOOLCHAIN="auto", GOPROXY="https://external.invalid", CGO_ENABLED="1")
            for profile in ("", PROFILE.PROFILE):
                for command in ("build", "list", "env"):
                    with self.subTest(profile=profile or "ordinary", command=command):
                        result = subprocess.run(["sh", "-eu"], input=wrapper + f"guest_go {command}\n",
                                                text=True, capture_output=True,
                                                env=dict(hostile, PREPARE_COMPATIBILITY_PROFILE=profile))
                        self.assertEqual(result.returncode, 0, result.stderr)
                        actual = json.loads(result.stdout)
                        expected_args = [command] + (["-mod=vendor"] if command != "env" else [])
                        self.assertEqual(actual["args"], expected_args)
                        self.assertNotIn("-tags=hostile", actual["args"])
                        for key, value in {"GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "GO111MODULE": "on",
                                           "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off",
                                           "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0"}.items():
                            self.assertEqual(actual["env"][key], value)
                        for key in ("GOROOT", "GOEXPERIMENT", "GOCACHEPROG"):
                            self.assertNotIn(key, actual["env"])
                        self.assertEqual(actual["env"]["GOCACHE"], str(root / "cache/build"))
                        self.assertEqual(actual["env"]["GOMODCACHE"], str(root / "cache/mod"))
        self.assertIn('guest_go list -deps -json "$@" ./cmd/cengine-init', builder)
        self.assertIn('storage_go list -deps -json ./cmd/cengine-storage', builder)
        self.assertLess(builder.index('audit-inputs "$ROOT"'), builder.index('guest_go build "$@"'))
        # Ordinary production binaries get the same selected-input audit: the
        # whole list/audit block must not sit inside a profile conditional.
        build_section = builder[builder.index('cd "$ROOT/Guest"'):builder.index('guest_go build "$@"')]
        self.assertNotIn("PREPARE_COMPATIBILITY_PROFILE", build_section)
        self.assertNotIn("if [", build_section)

    def test_profile_output_is_explicit_absolute_and_not_production(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            PROFILE.validate_output(root, root / "private-profile-output")
            for output in (Path("relative"), root / ".build/guest"):
                with self.assertRaises(ValueError):
                    PROFILE.validate_output(root, output)

    def test_unknown_option_rejected_before_output_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            marker = output / "keep"
            marker.write_text("unchanged")
            result = subprocess.run(["sh", str(ROOT / "Scripts/build-guest-assets.sh"), "--unknown"],
                                    env={**os.environ, "CENGINE_GUEST_OUTPUT": str(output)}, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(marker.read_text(), "unchanged")
            self.assertEqual(sorted(p.name for p in output.iterdir()), ["keep"])

    def test_real_metadata_tail_keeps_default_exact_and_profile_explicit(self):
        builder = (ROOT / "Scripts/build-guest-assets.sh").read_text()
        self.assertIn("set -- -tags=cengine_prepare_compat", builder)
        self.assertNotIn("cengine_native_faulttest", builder)
        storage = builder.split('"$BINARY_OUTPUT/out/cengine-init"', 1)[1].split('"$BINARY_OUTPUT/out/cengine-storage"', 1)[0]
        self.assertNotIn('"$@"', storage)
        tail = builder[builder.index('python3 - "$OUTPUT"'):]
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temp:
                output = Path(temp)
                for name in ("vmlinux", "container-initramfs.cpio.gz", "storage-initramfs.cpio.gz"):
                    (output / name).write_bytes(name.encode())
                env = dict(os.environ, OUTPUT=str(output))
                env.pop("PREPARE_COMPATIBILITY_PROFILE", None)
                env.pop("PREPARE_COMPATIBILITY_SOURCE_SHA256", None)
                if enabled:
                    env.update(PREPARE_COMPATIBILITY_PROFILE=PROFILE.PROFILE, PREPARE_COMPATIBILITY_SOURCE_SHA256="a" * 64)
                result = subprocess.run(["sh", "-eu"], input=tail, text=True, env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads((output / "disk-bootstrap.json").read_text())
                fields = {PROFILE.PROFILE_FIELD, PROFILE.SOURCE_FIELD} & set(metadata)
                self.assertEqual(fields, {PROFILE.PROFILE_FIELD, PROFILE.SOURCE_FIELD} if enabled else set())
                if enabled:
                    self.assertEqual(metadata[PROFILE.PROFILE_FIELD], PROFILE.PROFILE)
                for prefix in ("container", "storage"):
                    self.assertEqual(metadata[prefix + "InitramfsSHA256"], hashlib.sha256((output / (prefix + "-initramfs.cpio.gz")).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
