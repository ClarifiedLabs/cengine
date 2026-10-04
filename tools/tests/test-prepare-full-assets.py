#!/usr/bin/env python3
"""Engine-free exact full-profile selection; no compiler or assets invoked."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('full_assets', ROOT / 'Scripts/prepare_compatibility_assets.py')
assert spec and spec.loader
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class FullAssetsTests(unittest.TestCase):
    def test_exact_full_option_selects_only_full_tag(self):
        text = (ROOT / 'Scripts/build-guest-assets.sh').read_text()
        options = text[text.index('PREPARE_COMPATIBILITY_PROFILE='):text.index('ROOT=$(CDPATH=')]
        tags = text[text.index('    case "$PREPARE_COMPATIBILITY_PROFILE" in'):text.index('\nelse\n    ORDINARY_SOURCE_SHA256=')]
        result = subprocess.run(['sh', '-eu', '-c', options + 'set --\n' + tags + '\nprintf "%s\\n" "$PREPARE_COMPATIBILITY_PROFILE" "$*"\n', 'options', '--prepare-compatibility=' + assets.FULL_PROFILE], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [assets.FULL_PROFILE, '-tags=cengine_prepare_full_compat'])
        self.assertNotIn('cengine_native_faulttest', text)

    def test_storage_list_and_build_share_explicit_tag_only_for_full(self):
        text = (ROOT / 'Scripts/build-guest-assets.sh').read_text()
        functions = text[text.index('guest_go() {'):text.index('mkdir -p "$BINARY_OUTPUT/out"')]
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / 'go'
            fake.write_text(f'#!{sys.executable}\nimport json,sys,os\nprint(json.dumps(dict(args=sys.argv[1:],flags=os.environ.get("GOFLAGS"))))\n')
            fake.chmod(0o755)
            for profile in ('', *assets.PROFILES):
                for command in ('list', 'build'):
                    env = dict(os.environ, GO=str(fake), GUEST_GO_CACHE=temp, PREPARE_COMPATIBILITY_PROFILE=profile, GOFLAGS='-tags=hostile')
                    result = subprocess.run(['sh', '-eu'], input=functions + f'storage_go {command} ./cmd/cengine-storage\n', env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    actual = json.loads(result.stdout)
                    expected = [command, '-mod=vendor'] + (['-tags=cengine_prepare_full_compat'] if profile == assets.FULL_PROFILE else []) + ['./cmd/cengine-storage']
                    self.assertEqual(actual['args'], expected)
                    self.assertEqual(actual['flags'], '')
        self.assertIn('storage_go list -deps -json ./cmd/cengine-storage', text)
        self.assertNotIn('guest_go list -deps -json ./cmd/cengine-storage', text)
        self.assertIn('GOARCH=arm64 storage_go build -trimpath -buildvcs=false', text)
        self.assertLess(text.index('audit-inputs "$ROOT"'), text.index('guest_go build "$@"'))
        # The selected-input audit also covers ordinary production binaries, so
        # it must not be gated on an explicit compatibility profile.
        build_section = text[text.index('cd "$ROOT/Guest"'):text.index('guest_go build "$@"')]
        self.assertNotIn('PREPARE_COMPATIBILITY_PROFILE', build_section)

    def test_full_metadata_claims_v2_without_qualification(self):
        text = (ROOT / 'Scripts/build-guest-assets.sh').read_text()
        tail = text[text.index('python3 - "$OUTPUT"'):]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('vmlinux', 'container-initramfs.cpio.gz', 'storage-initramfs.cpio.gz'):
                (root / name).write_bytes(name.encode())
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(('CENGINE_', 'PREPARE_', 'ORDINARY_', 'LIFECYCLE_'))}
            env.update(OUTPUT=temp, PREPARE_COMPATIBILITY_PROFILE=assets.FULL_PROFILE,
                       PREPARE_COMPATIBILITY_SOURCE_SHA256='a' * 64)
            subprocess.run(['sh', '-eu'], input=tail, env=env, text=True, check=True)
            metadata = json.loads((root / 'disk-bootstrap.json').read_text())
            self.assertEqual(metadata['storageLifecycleVersion'], 2)
            self.assertEqual(metadata['storageServiceBootVersion'], 2)
            self.assertEqual(metadata['prepareCompatibilityProfile'], assets.FULL_PROFILE)
            self.assertEqual(metadata['prepareCompatibilitySourceSHA256'], 'a' * 64)
            self.assertNotIn('storageLifecycleQualification', metadata)
            self.assertNotIn('storageLifecycleSourcePin', metadata)
        # V2 production sessions are not gated on the qualification tag. Do not
        # add that tag to full assets: it changes PID1 selection and privileges.
        session = (ROOT / 'Guest/internal/storageboot/lifecycle_session.go').read_text()
        self.assertNotIn('//go:build', session)
        entry = (ROOT / 'Guest/cmd/cengine-storage/main.go').read_text()
        self.assertIn('return storageboot.RunLifecycle(context.Background(), verified, managementIP.String())', entry)
        self.assertIn('storageboot.RunLifecycleWorker()', entry)
        self.assertNotIn('cengine.storage_mode', entry)
        self.assertNotIn('storageboot.Run(', entry)
        for name in ('lifecycle_disabled_linux.go', 'lifecycle_enabled_linux.go'):
            self.assertFalse((ROOT / 'Guest/cmd/cengine-storage' / name).exists())

    def test_full_metadata_still_needs_complete_current_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in assets.BUILD_INPUTS:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
            (root / 'Guest').mkdir(); source = root / 'Guest/bridge.s'; source.write_bytes(b'assembly')
            pin = assets.source_pin(root)
            metadata = {assets.PROFILE_FIELD: assets.FULL_PROFILE, assets.SOURCE_FIELD: pin}
            assets.validate_metadata(metadata, root)
            source.write_bytes(b'changed')
            with self.assertRaises(ValueError): assets.validate_metadata(metadata, root)
            for bad in ({assets.PROFILE_FIELD: assets.FULL_PROFILE}, {assets.SOURCE_FIELD: pin}, {**metadata, assets.PROFILE_FIELD: assets.FULL_PROFILE + '-optional'}):
                with self.assertRaises(ValueError): assets.validate_metadata(bad, root)

    def test_full_guest_rejects_runtime_fault_before_output_access(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'keep'
            marker.write_bytes(b'retained')
            for fault in ('before-configure-v1', 'after-replacement-before-completion-v1'):
                result = subprocess.run(['sh', str(ROOT / 'Scripts/build-guest-assets.sh'),
                    '--prepare-compatibility=' + assets.FULL_PROFILE],
                    env=dict(os.environ, CENGINE_GUEST_OUTPUT=temp, CENGINE_COMPAT_LIFECYCLE_FAULT=fault),
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('PREPARE cannot combine lifecycle runtime faults', result.stderr)
                self.assertEqual([p.name for p in Path(temp).iterdir()], ['keep'])
                self.assertEqual(marker.read_bytes(), b'retained')

    def test_combined_options_fail_before_output_access(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp); marker = output / 'keep'; marker.write_bytes(b'retained')
            flag = '--prepare-compatibility=' + assets.FULL_PROFILE
            for args in ([flag, flag], [flag, '--prepare-compatibility=' + assets.PROFILE], [flag + 'x']):
                result = subprocess.run(['sh', str(ROOT / 'Scripts/build-guest-assets.sh'), *args], env=dict(os.environ, CENGINE_GUEST_OUTPUT=temp), capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual([p.name for p in output.iterdir()], ['keep'])
                self.assertEqual(marker.read_bytes(), b'retained')


if __name__ == '__main__': unittest.main()
