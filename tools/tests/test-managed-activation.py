#!/usr/bin/env python3
"""Engine-free regressions: no signing, helper access, production guest builds or VMs."""
import ast
import __future__
from contextlib import redirect_stdout
from dataclasses import dataclass, field
import hashlib
import errno
import io
import json
import os
from pathlib import Path
import pathlib
import shlex
import subprocess
import tempfile
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tests/Compatibility'))
import harness

IDENTITY = 'Developer ID Application: Fixture Company (ABCDEFGHIJ)'


class ManagedActivationTests(unittest.TestCase):
    def run_shell(self, script, **kwargs):
        return subprocess.run(['/bin/sh', '-eu', '-c', script], text=True, capture_output=True, **kwargs)

    def assets(self, root):
        root.mkdir()
        for name in ('vmlinux', 'container-initramfs.cpio.gz', 'storage-initramfs.cpio.gz'):
            (root / name).write_bytes(name.encode())
        metadata: dict[str, object] = dict(schemaVersion=1, protocolVersion=1, storageServiceBootVersion=2, workloadStorageBootVersion=1, storageLifecycleVersion=2)
        for prefix in ('container', 'storage'):
            metadata[f'{prefix}InitramfsSHA256'] = hashlib.sha256((root / f'{prefix}-initramfs.cpio.gz').read_bytes()).hexdigest()
        (root / 'disk-bootstrap.json').write_text(json.dumps(metadata))
        self.manifest(root)
        return metadata

    def ordinary_assets(self, root):
        sys.path.insert(0, str(ROOT / 'Scripts'))
        import guest_asset_provenance as provenance
        import runpy
        fixture = runpy.run_path(str(ROOT / 'tools/tests/test-guest-asset-provenance.py'))
        go = ROOT / '.build/toolchains/go1.26.5.darwin-arm64/go/bin/go'
        if not go.is_file():
            self.skipTest('pinned host Go unavailable; no provisioning in tests')
        metadata = self.assets(root)
        # Compile tiny fixture commands, not production guests; inspect actual
        # default Go buildinfo rather than trusting a profile label.
        if not hasattr(type(self), '_ordinary_binaries'):
            type(self)._ordinary_binaries = {}
            with tempfile.TemporaryDirectory() as temp:
                module = Path(temp)
                (module / 'go.mod').write_text('module dev.cengine/guest\n\ngo 1.26.5\n')
                environment = dict(os.environ, GOENV='off', GOFLAGS='', GOWORK='off', GOTOOLCHAIN='local',
                    CGO_ENABLED='0', GOOS='linux', GOARCH='arm64', GOARM64='v8.0')
                environment.pop('GOEXPERIMENT', None)
                for kind, command in (('container', 'cengine-init'), ('storage', 'cengine-storage')):
                    source = module / 'cmd' / command
                    source.mkdir(parents=True)
                    (source / 'main.go').write_text('package main\nfunc main() {}\n')
                    binary = module / command
                    subprocess.run([str(go), 'build', '-trimpath', '-o', str(binary), './cmd/' + command],
                                   cwd=module, env=environment, check=True, capture_output=True)
                    type(self)._ordinary_binaries[kind] = binary.read_bytes()
        for kind, binary in self._ordinary_binaries.items():
            data = fixture['archive'](init=binary)
            (root / f'{kind}-initramfs.cpio.gz').write_bytes(data)
            metadata[f'{kind}InitramfsSHA256'] = hashlib.sha256(data).hexdigest()
        metadata['storageLifecycleVersion'] = 2
        metadata['ordinaryProvenance'] = provenance.provenance(ROOT, root, go, provenance.source_pin(ROOT))
        (root / 'disk-bootstrap.json').write_text(json.dumps(metadata))
        self.manifest(root)
        return metadata

    def full_assets(self, root):
        sys.path.insert(0, str(ROOT / 'Scripts'))
        from prepare_compatibility_assets import FULL_PROFILE, source_pin
        metadata = self.assets(root)
        metadata.update(prepareCompatibilityProfile=FULL_PROFILE,
                        prepareCompatibilitySourceSHA256=source_pin(ROOT))
        (root / 'disk-bootstrap.json').write_text(json.dumps(metadata))
        self.manifest(root)
        return metadata

    def test_lifecycle_assets_require_current_default_profile_and_paired_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'ordinary'
            valid = self.ordinary_assets(root)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('CENGINE_', 'PREPARE_'))}
            command = [sys.executable, str(ROOT / 'Scripts/check-managed-guest-assets.py'), str(root)]
            accepted = subprocess.run(command, env=environment, text=True, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            mutations = [dict(valid, storageLifecycleVersion=value) for value in (None, 1, True, '2')]
            mutations += [dict(valid, ordinaryProvenance=value) for value in (None, {},
                dict(valid['ordinaryProvenance'], sourceSHA256='0' * 64),
                dict(valid['ordinaryProvenance'], policy='qualification'))]
            mutations += [dict(valid, **{key: 'test-only'}) for key in (
                'storageLifecycleQualification', 'storageLifecycleSourcePin',
                'prepareCompatibilityProfile', 'prepareCompatibilitySourceSHA256')]
            for metadata in mutations:
                (root / 'disk-bootstrap.json').write_text(json.dumps(metadata))
                self.manifest(root)
                before = {path.name: path.read_bytes() for path in root.iterdir()}
                with self.subTest(metadata=metadata):
                    self.assertNotEqual(subprocess.run(command, env=environment, capture_output=True).returncode, 0)
                    self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir()})
            (root / 'disk-bootstrap.json').write_text(json.dumps(valid))
            self.manifest(root)
            for key, value in (('CENGINE_STORAGE_LIFECYCLE_QUALIFICATION', 'lifecycle-v2-native-v1'),
                               ('CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY', 'rtm096-full-nine-v3'),
                               ('PREPARE_COMPATIBILITY_PROFILE', 'rtm096-full-nine-v3')):
                with self.subTest(key=key):
                    self.assertNotEqual(subprocess.run(command, env=dict(environment, **{key: value}), capture_output=True).returncode, 0)
            (root / 'storage-initramfs.cpio.gz').write_bytes(b'changed')
            self.assertNotEqual(subprocess.run(command, env=environment, capture_output=True).returncode, 0)
            # Rehashing a replacement is not default-profile provenance.
            valid['storageInitramfsSHA256'] = hashlib.sha256(b'changed').hexdigest()
            (root / 'disk-bootstrap.json').write_text(json.dumps(valid))
            self.manifest(root)
            self.assertNotEqual(subprocess.run(command, env=environment, capture_output=True).returncode, 0)

    def test_retired_asset_selectors_reject_even_empty(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'ordinary'
            self.ordinary_assets(root)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('CENGINE_', 'PREPARE_'))}
            command = [sys.executable, str(ROOT / 'Scripts/check-managed-guest-assets.py'), str(root)]
            for key in ('CENGINE_COMPAT_SHARED_STORAGE', 'CENGINE_COMPAT_MANAGED_STORAGE'):
                for value in ('', '0', '1', 'legacy', 'managed', 'lifecycle', 'unexpected-selector'):
                    with self.subTest(key=key, value=value):
                        result = subprocess.run(command, env=dict(environment, **{key: value}),
                                                text=True, capture_output=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('retired', result.stderr)

    def test_lifecycle_runner_rejects_invalid_selection_before_build_or_lock(self):
        source = (ROOT / 'Scripts/run-compat-tests.sh').read_text()
        prefix = source[:source.index('LOCK=')]
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('CENGINE_', 'PREPARE_', 'XCODE'))}
        cases = [(key, value, 'retired')
                 for key in ('CENGINE_COMPAT_SHARED_STORAGE', 'CENGINE_COMPAT_MANAGED_STORAGE')
                 for value in ('', '0', '1', 'legacy', 'managed', 'lifecycle', 'unexpected-selector')]
        cases += [('CENGINE_STORAGE_LIFECYCLE_QUALIFICATION', 'lifecycle-v2-native-v1',
                   'requires signed managed storage')]
        for key, value, message in cases:
            with self.subTest(key=key, value=value):
                result = subprocess.run(['/bin/sh', '-c', prefix, str(ROOT / 'Scripts/run-compat-tests.sh')],
                    env=dict(environment, **{key: value}), text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_lifecycle_daemon_arguments_use_default_and_reject_profile_mixes(self):
        tree = ast.parse((ROOT / 'Tests/Compatibility/conftest.py').read_text())
        function = next(node for node in tree.body if getattr(node, 'name', None) == 'managed_storage_arguments')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<arguments>', 'exec'), namespace)
        arguments = namespace['managed_storage_arguments']
        self.assertEqual(arguments({}), [])
        full = dict(CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY='rtm096-full-nine-v3',
                    PREPARE_COMPATIBILITY_PROFILE='rtm096-full-nine-v3')
        self.assertEqual(arguments(full), [])
        for key in ('CENGINE_COMPAT_SHARED_STORAGE', 'CENGINE_COMPAT_MANAGED_STORAGE'):
            for value in ('', '0', '1', 'legacy', 'managed', 'lifecycle', 'unexpected-selector'):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'retired'):
                    arguments({key: value})
        for key, value in (('CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY', 'unknown'),
                           ('PREPARE_COMPATIBILITY_PROFILE', 'rtm096-early-a1-a3-v2'),
                           ('CENGINE_COMPAT_LIFECYCLE_FAULT', 'before-configure-v1'),
                           ('CENGINE_COMPAT_LIFECYCLE_FAULT', 'after-replacement-before-completion-v1'),
                           ('CENGINE_STORAGE_LIFECYCLE_QUALIFICATION', 'lifecycle-v2-native-v1')):
            with self.subTest(full_key=key, value=value), self.assertRaises(ValueError):
                arguments(dict(full, **{key: value}))
        for key, value in (('CENGINE_STORAGE_LIFECYCLE_QUALIFICATION', 'lifecycle-v2-native-v1'),
                           ('CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY', 'rtm096-full-nine-v3'),
                           ('PREPARE_COMPATIBILITY_PROFILE', 'rtm096-full-nine-v3')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                arguments({key: value})

    def manifest(self, root):
        (root / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n'
            for name in ('vmlinux', 'container-initramfs.cpio.gz', 'storage-initramfs.cpio.gz', 'disk-bootstrap.json')))

    def test_managed_assets_require_both_versions_and_all_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'experimental'
            valid = self.ordinary_assets(root)
            command = ['python3', str(ROOT / 'Scripts/check-managed-guest-assets.py'), str(root)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            for field in ('storageServiceBootVersion', 'workloadStorageBootVersion'):
                for value in (None, 0, 1 if field == 'storageServiceBootVersion' else 2, True, '1'):
                    metadata = dict(valid, **{field: value})
                    (root / 'disk-bootstrap.json').write_text(json.dumps(metadata))
                    self.manifest(root)
                    self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            (root / 'disk-bootstrap.json').write_text(json.dumps(valid))
            self.manifest(root)
            (root / 'vmlinux').write_bytes(b'tampered kernel')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_managed_assets_reject_duplicate_metadata_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'experimental'
            self.assets(root)
            command = ['python3', str(ROOT / 'Scripts/check-managed-guest-assets.py'), str(root)]
            metadata = root / 'disk-bootstrap.json'
            metadata.write_text(metadata.read_text()[:-1] + ', "schemaVersion":1}')
            self.manifest(root)
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            metadata.unlink()
            metadata.symlink_to(root / 'vmlinux')
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_signing_identity_rejects_ad_hoc_team_only_and_non_developer_id(self):
        source = f'. {shlex.quote(str(ROOT / "Scripts/managed-signing.sh"))}; '
        result = self.run_shell(source + 'managed_signing_team ' + shlex.quote(IDENTITY))
        self.assertEqual(result.stdout.strip(), 'ABCDEFGHIJ')
        for invalid in ('-', 'ABCDEFGHIJ', 'Apple Development: Fixture (ABCDEFGHIJ)', IDENTITY + '\ninjection'):
            self.assertNotEqual(self.run_shell(source + 'managed_signing_team ' + shlex.quote(invalid)).returncode, 0)

    def test_verifiers_pass_an_inline_requirement_as_one_exact_argument(self):
        with tempfile.TemporaryDirectory(prefix='signing argv ') as temp:
            root = Path(temp)
            log = root / 'calls.jsonl'
            signer = root / 'codesign'
            signer.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if len(args) == 5 and args[:3] == ['--verify', '--strict', '-R']:
    roles = {'cengine': 'engine', 'cengine-helper': 'network-helper',
             'cengine-storage-controller': 'storage-control', 'installed-helper': 'network-helper'}
    role = roles[pathlib.Path(args[4]).name]
    expected = '=anchor apple generic and identifier "dev.cengine.' + role + '.test-compat" and certificate leaf[subject.OU] = "ABCDEFGHIJ"'
    if args[3] != expected:
        sys.exit('expected one exact inline requirement starting with =')
elif len(args) == 3 and args[:2] == ['-dv', '--verbose=4']:
    print('TeamIdentifier=ABCDEFGHIJ\\nAuthority=Developer ID Application: Fixture\\nflags=0x10000(runtime)', file=sys.stderr)
else:
    sys.exit('unexpected codesign invocation')
''')
            signer.chmod(0o755)
            environment = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', CALLS=str(log))
            binary = root / 'cengine'
            # Prove this mock rejects the exact prior bug, not just a different argv shape.
            requirement = 'anchor apple generic and identifier "dev.cengine.engine.test-compat" and certificate leaf[subject.OU] = "ABCDEFGHIJ"'
            rejected = subprocess.run([str(signer), '--verify', '--strict', '-R', requirement, str(binary)],
                                      env=environment, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('starting with =', rejected.stderr)
            log.write_text('')
            source = f'. {shlex.quote(str(ROOT / "Scripts/managed-signing.sh"))}; '
            result = self.run_shell(source + f'managed_signing_verify {shlex.quote(str(binary))} '
                'dev.cengine.engine.test-compat ABCDEFGHIJ', env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Replace only the command dependency; execute the real helper validator body.
            helper_source = (ROOT / 'Scripts/compat-network-helper.sh').read_text().replace(
                '/usr/bin/codesign', shlex.quote(str(signer)))
            library = root / 'helper.sh'
            library.write_text(helper_source)
            result = self.run_shell(f'. {shlex.quote(str(library))}; '
                f'compat_network_helper_path={shlex.quote(str(root / "installed-helper"))}; '
                f'compat_network_helper_validate_managed_signatures {shlex.quote(str(binary))} '
                f'{shlex.quote(str(root / "cengine-helper"))}', env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            verifications = [args for args in calls if args[0] == '--verify']
            self.assertEqual(len(verifications), 5)
            self.assertEqual([Path(args[-1]).name for args in verifications],
                ['cengine', 'cengine', 'cengine-helper', 'cengine-storage-controller', 'installed-helper'])

    def test_managed_signer_refuses_adhoc_before_any_codesign(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('CENGINE_', 'PREPARE_'))}
        result = subprocess.run(['/bin/bash', str(ROOT / 'Scripts/sign-compat-binary.sh'), '/does/not/exist'],
                                env=environment, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('a full Developer ID Application signing identity is required', result.stderr)

    def controller_fixture(self, root: Path):
        log = root / 'calls'
        for name, body in {
            # Record effective Go/cgo flags: ambient compile/link inputs must
            # never reach the controller compile, in any selection mode.
            'uname': 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac',
            'go': 'printf "CGO_CFLAGS=<%s>\\nCGO_CPPFLAGS=<%s>\\nCGO_CXXFLAGS=<%s>\\nCGO_LDFLAGS=<%s>\\n" "$CGO_CFLAGS" "$CGO_CPPFLAGS" "$CGO_CXXFLAGS" "$CGO_LDFLAGS" >> "$CALLS"; printf "GOFLAGS=<%s>\\n" "$GOFLAGS" >> "$CALLS"; printf "%s\\n" "$*" >> "$CALLS"; while [ "$1" != -o ]; do shift; done; shift; touch "$1"',
            'codesign': 'printf "%s\\n" "$*" >> "$CALLS"; case "$1" in -dv) printf "Authority=Developer ID Application: Fixture\\nflags=0x10000(runtime)\\n" >&2;; esac',
        }.items():
            script = root / name
            script.write_text('#!/bin/sh\n' + body + '\n')
            script.chmod(0o755)
        return dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', CALLS=str(log),
                    GOFLAGS='-tags=ambient_must_not_apply')

    def test_controller_main_runs_lifecycle_and_validates_arguments(self):
        source = (ROOT / 'Guest/cmd/cengine-storage-controller/main.go').read_text()
        self.assertIn('storagebootstrap.RunLifecycleChild(context.Background())', source)
        self.assertIn('if !validLifecycleArguments(os.Args)', source)
        self.assertIn('os.Exit(64)', source)

    def test_controller_namespace_tracks_exact_signing_identifier(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = self.controller_fixture(root)
            # A forced include is processed after command-line -U; resetting
            # just the compatibility macro cannot block either injection path.
            header = root / 'ambient-policy.h'
            header.write_text('#define CE_STORAGE_LIFECYCLE_COMPATIBILITY 1\n'
                              '#define CE_STORAGE_LIFECYCLE_QUALIFICATION 1\n')
            forced_include = '-include ' + shlex.quote(str(header))
            environment.update(CGO_CFLAGS='-O0 -DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1 ' + forced_include,
                               CGO_CPPFLAGS='-DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1 -DCE_STORAGE_LIFECYCLE_QUALIFICATION=1 ' + forced_include,
                               CGO_CXXFLAGS=forced_include, CGO_LDFLAGS='-Wl,-ambient-link-policy',
                               CENGINE_NETWORK_HELPER_SERVICE_NAME='dev.cengine.network-helper.test-compat',
                               CENGINE_STORAGE_CONTROLLER_IDENTIFIER='dev.cengine.storage-control.test-compat')
            environment.pop('CENGINE_STORAGE_LIFECYCLE_QUALIFICATION', None)
            log = root / 'calls'
            for options, compatibility, tag in (
                ([], False, ''),
                (['--sign', IDENTITY], False, ''),
                (['--sign', IDENTITY, '--compat'], True, ''),
                (['--sign', IDENTITY, '--prepare-compatibility=rtm096-full-nine-v3'], True, 'cengine_prepare_full_compat'),
            ):
                with self.subTest(options=options):
                    log.write_text('')
                    result = subprocess.run([str(ROOT / 'Scripts/build-storage-controller.sh'), *options,
                                             str(root / 'controller')], env=environment, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = log.read_text()
                    expected = '-O2 -g -UCE_STORAGE_LIFECYCLE_COMPATIBILITY'
                    if compatibility:
                        expected += ' -DCE_STORAGE_LIFECYCLE_COMPATIBILITY=1'
                    self.assertIn(f'CGO_CFLAGS=<{expected}>', calls)
                    self.assertIn('CGO_CPPFLAGS=<>', calls)
                    self.assertIn('CGO_CXXFLAGS=<-O2 -g>', calls)
                    self.assertIn('CGO_LDFLAGS=<-O2 -g>', calls)
                    self.assertNotIn(str(header), calls)
                    self.assertNotIn('ambient-link-policy', calls)
                    if tag:
                        self.assertIn('-tags ' + tag + ' -o', calls)
                    else:
                        self.assertNotIn('-tags', calls)
                    self.assertNotIn('cengine_lifecycle_v2_qualification', calls)
                    self.assertNotIn('CE_STORAGE_LIFECYCLE_QUALIFICATION', calls)
                    self.assertNotIn('__info_plist', calls)
                    if options:
                        identifier = 'dev.cengine.storage-control' + ('.test-compat' if compatibility else '')
                        self.assertIn('--identifier ' + identifier + ' --sign', calls)

    def test_controller_full_compat_selection_is_closed_and_signed(self):
        FULL_PROFILE = 'rtm096-full-nine-v3'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            environment = self.controller_fixture(root)
            log = root / 'calls'
            script = str(ROOT / 'Scripts/build-storage-controller.sh')

            # Ordinary production build, signed: production v2 child route only
            # (no full-compat or qualification tag), production identifier,
            # ordinary timestamp. Ambient GOFLAGS never applies.
            result = subprocess.run([script, '--sign', IDENTITY, str(root / 'controller')],
                                    env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text()
            self.assertIn('build -trimpath -o', calls)
            self.assertNotIn('cengine_lifecycle_v2_qualification', calls)
            self.assertIn('./cmd/cengine-storage-controller', calls)
            self.assertNotIn('cengine_prepare_full_compat', calls)
            self.assertNotIn('storagebootstrap_testendpoint', calls)
            self.assertIn('--options runtime --timestamp --identifier dev.cengine.storage-control ', calls)
            self.assertNotIn('--timestamp=none', calls)
            self.assertIn('GOFLAGS=<>', calls)

            # Closed selected profile: explicit tag plus signed test-compat
            # identifier and timestamp=none; ambient GOFLAGS still blanked.
            log.write_text('')
            result = subprocess.run([script, '--sign', IDENTITY,
                                     '--prepare-compatibility=' + FULL_PROFILE, str(root / 'controller-full')],
                                    env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text()
            self.assertIn('build -trimpath -tags cengine_prepare_full_compat -o', calls)
            self.assertIn('--options runtime --timestamp=none --identifier dev.cengine.storage-control.test-compat', calls)
            self.assertIn('GOFLAGS=<>', calls)

            # The xpc-test helper binary is a separate mode: never combined
            # with the full-compat compile selection.
            log.write_text('')
            result = subprocess.run([script, '--signed-xpc-test', IDENTITY,
                                     '--prepare-compatibility=' + FULL_PROFILE, str(root / 'xpc-full')],
                                    env=environment, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unknown controller build option: --signed-xpc-test', result.stderr)
            self.assertEqual(log.read_text(), '')

            # Unsigned selection is never enabled: rejected before any go or
            # codesign invocation.
            for arguments in (
                ['--prepare-compatibility=' + FULL_PROFILE, str(root / 'unsigned')],
                ['--prepare-compatibility=rtm096-all', str(root / 'invalid')],
                ['--prepare-compatibility=' + FULL_PROFILE + 'junk', str(root / 'invalid')],
                ['--compat', str(root / 'legacy-flag')],
            ):
                log.write_text('')
                result = subprocess.run([script, *arguments], env=environment, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0, arguments)
                self.assertEqual(log.read_text(), '', arguments)
            self.assertIn('compatibility builds require --sign', result.stderr)

            for key, value in (('CENGINE_COMPAT_LIFECYCLE_FAULT', 'before-configure-v1'),
                               ('CENGINE_COMPAT_LIFECYCLE_FAULT', 'after-replacement-before-completion-v1'),
                               ('CENGINE_STORAGE_LIFECYCLE_QUALIFICATION', 'lifecycle-v2-native-v1')):
                log.write_text('')
                result = subprocess.run([script, '--sign', IDENTITY,
                    '--prepare-compatibility=' + FULL_PROFILE, str(root / 'mixed')],
                    env={**environment, key: value}, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(log.read_text(), '')

            # Existing signed --compat selects identity only, not instrumentation.
            log.write_text('')
            result = subprocess.run([script, '--sign', IDENTITY, '--compat', str(root / 'compat')],
                                    env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('cengine_prepare_full_compat', log.read_text())
            self.assertIn('--identifier dev.cengine.storage-control.test-compat', log.read_text())

            # Removed xpc-test entrypoints cannot fall back to a test executable.
            log.write_text('')
            result = subprocess.run([script, '--signed-xpc-test', IDENTITY, str(root / 'xpc-test')],
                                    env=environment, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(log.read_text(), '')

    def test_signed_compatibility_signs_all_components_without_adhoc_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log = root / 'calls'
            for name in ('cengine', 'cengine-helper', 'cengine-storage-controller'):
                binary = root / name
                binary.write_text('#!/bin/sh\nexit 0\n')
                binary.chmod(0o755)
            signer = root / 'codesign'
            signer.write_text('#!/bin/sh\n'
                'printf "%s\\n" "$*" >> "$CALLS"\n'
                'case "$1" in -dv)\n'
                '  for last do :; done\n'
                '  case "$last" in */cengine) id=engine;; */cengine-helper) id=network-helper;; *) id=storage-control;; esac\n'
                '  printf "Identifier=dev.cengine.%s.test-compat\\nAuthority=Developer ID Application: Fixture\\nflags=0x10000(runtime)\\n" "$id" >&2;;\n'
                'esac\n')
            signer.chmod(0o755)
            environment = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', CALLS=str(log))
            result = subprocess.run(['/bin/bash', str(ROOT / 'Scripts/sign-compat-binary.sh'), '--sign', IDENTITY,
                                     str(root / 'cengine')], env=environment, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            sign_calls = [line for line in log.read_text().splitlines() if line.startswith('--force')]
            self.assertEqual(len(sign_calls), 3)
            for line in sign_calls:
                self.assertIn('--options runtime', line)
                self.assertIn('--sign ' + IDENTITY, line)
                self.assertNotIn('--sign - ', line)

    def test_compatibility_signer_mode_matrix(self):
        cases = [(None, identity, controller, identity == IDENTITY and controller)
                 for identity in (None, '', '-', 'ABCDEFGHIJ', IDENTITY)
                 for controller in (False, True)]
        cases += [({key: value}, IDENTITY, True, False)
                  for key in ('CENGINE_COMPAT_SHARED_STORAGE', 'CENGINE_COMPAT_MANAGED_STORAGE')
                  for value in ('', '0', '1', 'legacy', 'managed', 'lifecycle', 'unexpected-selector')]
        for selectors, identity, controller_present, accepted in cases:
            with self.subTest(selectors=selectors, identity=identity, controller=controller_present), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                log = root / 'calls.jsonl'
                roles = {'cengine': 'engine', 'cengine-helper': 'network-helper'}
                if controller_present:
                    roles['cengine-storage-controller'] = 'storage-control'
                for name in roles:
                    binary = root / name
                    binary.write_text('#!/bin/sh\nexit 0\n')
                    binary.chmod(0o755)
                signer = root / 'codesign'
                signer.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if args[:2] == ['-dv', '--verbose=4']:
    roles = {'cengine': 'engine', 'cengine-helper': 'network-helper',
             'cengine-storage-controller': 'storage-control'}
    print('Identifier=dev.cengine.' + roles[pathlib.Path(args[-1]).name] + '.test-compat', file=sys.stderr)
    print('Authority=Developer ID Application: Fixture\\nflags=0x10000(runtime)', file=sys.stderr)
''')
                signer.chmod(0o755)
                environment = {key: value for key, value in os.environ.items()
                               if not key.startswith(('CENGINE_', 'PREPARE_'))}
                environment.update(PATH=f'{root}:{os.environ["PATH"]}', CALLS=str(log))
                environment.update(selectors or {})
                command = ['/bin/bash', str(ROOT / 'Scripts/sign-compat-binary.sh')]
                if identity is not None:
                    command += ['--sign', identity]
                result = subprocess.run(command + [str(root / 'cengine')],
                    env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                if not accepted:
                    if selectors is not None:
                        self.assertIn('retired', result.stderr)
                        self.assertEqual(calls, [])
                    elif identity == IDENTITY:
                        self.assertIn('managed controller is missing', result.stderr)
                    else:
                        self.assertEqual(calls, [])
                    continue
                expected_roles = roles
                sign_calls = [args for args in calls if args[0] == '--force']
                self.assertEqual({Path(args[-1]).name for args in sign_calls}, set(expected_roles))
                self.assertEqual(len(sign_calls), len(expected_roles))
                for args in sign_calls:
                    self.assertEqual(args[args.index('--sign') + 1], identity or '-')
                    if identity:
                        self.assertEqual(args[args.index('--options') + 1], 'runtime')
                    else:
                        self.assertNotIn('--options', args)
                verifications = [args for args in calls if '-R' in args]
                if identity:
                    self.assertEqual(len(verifications), len(expected_roles))
                    for name, role in expected_roles.items():
                        requirement = f'=anchor apple generic and identifier "dev.cengine.{role}.test-compat" and certificate leaf[subject.OU] = "ABCDEFGHIJ"'
                        self.assertIn(['--verify', '--strict', '-R', requirement, str(root / name)], verifications)
                else:
                    self.assertEqual(verifications, [])

    def test_runner_always_requires_signing_and_controller(self):
        source = (ROOT / 'Scripts/run-compat-tests.sh').read_text()
        # Execute only real identity/asset preflight and build/sign selection, with
        # inert build dependencies. Never lock, reset, install, or contact a helper.
        prefix = source[:source.index('LOCK=')]
        build = source[source.index('stage "$BUILD_STAGE"'):source.index('HELPER=$(compat_network_helper_local_for_binary')]
        cases = ((None, False), ('', False), ('-', False), ('ABCDEFGHIJ', False),
                 ('Apple Development: Fixture (ABCDEFGHIJ)', False), (IDENTITY, True))
        for identity, accepted in cases:
            with self.subTest(identity=identity), tempfile.TemporaryDirectory(prefix='compat signing ') as temp:
                root = Path(temp)
                scripts = root / 'Scripts'
                scripts.mkdir()
                log = root / 'calls.jsonl'
                for name in ('network-helper-fingerprint.sh', 'build-storage-controller.sh', 'sign-compat-binary.sh', 'xcodebuild'):
                    command = scripts / name
                    command.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps([pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
if pathlib.Path(sys.argv[0]).name == 'network-helper-fingerprint.sh':
    print('a' * 64)
''')
                    command.chmod(0o755)
                environment = {key: value for key, value in os.environ.items()
                    if not key.startswith(('CENGINE_', 'PREPARE_', 'XCODE'))}
                environment.update(CALLS=str(log),
                    XCODEBUILD=str(scripts / 'xcodebuild'), CENGINE_BINARY=str(root / 'cengine'))
                if identity is not None:
                    environment['CENGINE_DEVELOPER_ID_APPLICATION'] = identity
                assets = root / 'ordinary'
                self.ordinary_assets(assets)
                environment['CENGINE_COMPAT_MANAGED_ASSET_DIR'] = str(assets)
                result = subprocess.run(['/bin/sh', '-c', prefix +
                    f'\nROOT={shlex.quote(str(root))}\nBUILD_STAGE=test\nstage() {{ :; }}\n' + build,
                    str(ROOT / 'Scripts/run-compat-tests.sh')], env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                if not accepted:
                    self.assertIn('Developer ID Application', result.stderr)
                    self.assertEqual(calls, [])
                    continue
                self.assertEqual([args[0] for args in calls], ['network-helper-fingerprint.sh', 'xcodebuild'] +
                    ['build-storage-controller.sh', 'sign-compat-binary.sh'])
                self.assertIn('CENGINE_TEAM_IDENTIFIER=' + ('ABCDEFGHIJ' if identity else ''), calls[1])
                self.assertEqual(calls[-1], ['sign-compat-binary.sh'] +
                    (['--sign', identity] if identity else []) + [str(root / 'cengine')])
                self.assertEqual(calls[2], ['build-storage-controller.sh', '--sign', IDENTITY, '--compat',
                                          str(root / 'cengine-storage-controller')])

    def test_runner_always_builds_controller_and_only_opts_in_full_profile_explicitly(self):
        source = (ROOT / 'Scripts/run-compat-tests.sh').read_text()
        prefix = source[:source.index('LOCK=')]
        build = source[source.index('stage "$BUILD_STAGE"'):source.index('HELPER=$(compat_network_helper_local_for_binary')]
        for selection, expected_controller_args in (
            (None, ['--sign', IDENTITY, '--compat']),
            ('rtm096-full-nine-v3', ['--sign', IDENTITY, '--prepare-compatibility=rtm096-full-nine-v3']),
        ):
            with self.subTest(selection=selection), tempfile.TemporaryDirectory(prefix='compat controller ') as temp:
                root = Path(temp)
                scripts = root / 'Scripts'
                scripts.mkdir()
                log = root / 'calls.jsonl'
                for name in ('network-helper-fingerprint.sh', 'build-storage-controller.sh', 'sign-compat-binary.sh', 'xcodebuild'):
                    command = scripts / name
                    command.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps([pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
if pathlib.Path(sys.argv[0]).name == 'network-helper-fingerprint.sh':
    print('a' * 64)
''')
                    command.chmod(0o755)
                environment = {key: value for key, value in os.environ.items()
                    if not key.startswith(('CENGINE_', 'PREPARE_', 'XCODE'))}
                assets = root / 'experimental'
                if selection is None:
                    self.ordinary_assets(assets)
                else:
                    self.full_assets(assets)
                environment.update(CALLS=str(log),
                    XCODEBUILD=str(scripts / 'xcodebuild'), CENGINE_BINARY=str(root / 'cengine'),
                    CENGINE_DEVELOPER_ID_APPLICATION=IDENTITY, CENGINE_COMPAT_MANAGED_ASSET_DIR=str(assets))
                if selection is not None:
                    environment['CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY'] = selection
                    environment['PREPARE_COMPATIBILITY_PROFILE'] = selection
                result = subprocess.run(['/bin/sh', '-c', prefix +
                    f'\nROOT={shlex.quote(str(root))}\nBUILD_STAGE=test\nstage() {{ :; }}\n' + build,
                    str(ROOT / 'Scripts/run-compat-tests.sh')], env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                controller = [args for args in calls if args[0] == 'build-storage-controller.sh']
                self.assertEqual(len(controller), 1)
                self.assertEqual(controller[0], ['build-storage-controller.sh'] + expected_controller_args +
                                 [str(root / 'cengine-storage-controller')])

        # A non-closed value is rejected during preflight, before any build.
        with tempfile.TemporaryDirectory(prefix='compat controller ') as temp:
            root = Path(temp)
            log = root / 'calls.jsonl'
            environment = {key: value for key, value in os.environ.items()
                if not key.startswith(('CENGINE_', 'PREPARE_', 'XCODE'))}
            environment.update(CALLS=str(log),
                CENGINE_DEVELOPER_ID_APPLICATION=IDENTITY,
                CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY='rtm096-all',
                CENGINE_COMPAT_MANAGED_ASSET_DIR=str(root / 'experimental'))
            self.ordinary_assets(root / 'experimental')
            result = subprocess.run(['/bin/sh', '-c', prefix,
                str(ROOT / 'Scripts/run-compat-tests.sh')], env=environment, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY', result.stderr)
            self.assertFalse(log.exists())

    def test_matrix_wrapper_opts_controller_into_closed_full_compat_selection(self):
        wrapper = (ROOT / 'tools/managed-prepare-matrix.sh').read_text()
        self.assertIn('export CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY=rtm096-full-nine-v3', wrapper)
        self.assertIn('export PREPARE_COMPATIBILITY_PROFILE=rtm096-full-nine-v3', wrapper)
        self.assertIn('export CENGINE_COMPAT_REQUIRE_EXACT_HELPER=1', wrapper)
        runner = (ROOT / 'Scripts/run-compat-tests.sh').read_text()
        self.assertIn('--sign "$CENGINE_DEVELOPER_ID_APPLICATION"', runner)
        self.assertIn('"--prepare-compatibility=$CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY"', runner)
        self.assertIn("''|rtm096-full-nine-v3) ;;", runner)
        controller_script = (ROOT / 'Scripts/build-storage-controller.sh').read_text()
        self.assertIn('--prepare-compatibility=rtm096-full-nine-v3)', controller_script)
        self.assertIn('build_tags=(-tags cengine_prepare_full_compat)', controller_script)
        self.assertIn('"${build_tags[@]}"', controller_script)

    def test_managed_helper_pair_mismatch_fails_before_authenticated_status(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / 'cengine'
            binary.write_text('#!/bin/sh\necho SHOULD-NOT-RUN\n')
            binary.chmod(0o755)
            assets = Path(temp) / 'assets'
            self.assets(assets)
            source = f'. {shlex.quote(str(ROOT / "Scripts/compat-network-helper.sh"))}; '
            result = self.run_shell(source + 'compat_network_helper_validate_installation() { :; }; '
                'compat_network_helper_installed_fingerprint() { echo stale; }; '
                f'ROOT={shlex.quote(str(ROOT))}; '
                f'CENGINE_COMPAT_MANAGED_ASSET_DIR={shlex.quote(str(assets))}; '
                'CENGINE_COMPAT_REQUIRE_EXACT_HELPER=1; '
                f'compat_network_helper_require {shlex.quote(str(binary))} {"a" * 64}')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('SHOULD-NOT-RUN', result.stdout)
            self.assertIn('exact locally built installed helper', result.stderr)
            self.assertIn('attended command', result.stderr)

    def test_managed_pair_uses_stable_signed_code_and_rejects_changed_code(self):
        source = f'. {shlex.quote(str(ROOT / "Scripts/compat-network-helper.sh"))}; '
        # Signature verification is isolated here; production checks Apple anchor,
        # exact identifiers, same team and runtime on all four executables.
        common = source + 'compat_network_helper_local_for_binary() { echo /local/helper; }; ' + \
            f'compat_network_helper_installed_fingerprint() {{ echo {"a" * 64}; }}; ' + \
            'compat_network_helper_validate_managed_signatures() { echo signatures-checked; }; '
        equal = self.run_shell(common + f'compat_network_helper_code_digest() {{ echo {"b" * 64}; }}; '
            f'compat_network_helper_require_managed /local/daemon {"a" * 64}')
        self.assertEqual(equal.returncode, 0, equal.stderr)
        self.assertIn('signatures-checked', equal.stdout)
        changed = self.run_shell(common + 'compat_network_helper_code_digest() { echo "$1"; }; '
            f'compat_network_helper_require_managed /local/daemon {"a" * 64}')
        self.assertNotEqual(changed.returncode, 0)
        self.assertNotIn('signatures-checked', changed.stdout)

    def helper_requirement_fixture(self, root, requirement='lifecycle-v2', *, fingerprint_drift=False, code_drift=False, profile='ordinary'):
        """Run the real shell gates with inert OS commands and an authenticated-client stand-in."""
        installed = root / 'support/compat/installed'
        installed.mkdir(parents=True)
        helper = installed / 'cengine-helper'
        helper.write_text('#!/bin/sh\nexit 0\n')
        helper.chmod(0o755)
        token = installed / 'client-token'
        token.write_text('fixture-token')
        token.chmod(0o600)
        fingerprint = ('b' if fingerprint_drift else 'a') * 64
        (installed / 'manifest').write_text(f'fingerprint={fingerprint}\nowner_uid={os.getuid()}\n'
            f'helper_sha256={hashlib.sha256(helper.read_bytes()).hexdigest()}\n')
        (root / 'helper.plist').write_text('fixture plist')
        assets = root / 'assets'
        metadata = self.assets(assets)
        if profile == 'full':
            metadata.update(prepareCompatibilityProfile='rtm096-full-nine-v3',
                            prepareCompatibilitySourceSHA256='c' * 64)
        if requirement == 'lifecycle-qualification':
            metadata.update(storageLifecycleQualification='lifecycle-v2-native-v1', storageLifecycleSourcePin='c' * 64)
        (assets / 'disk-bootstrap.json').write_text(json.dumps(metadata))
        capabilities = dict(schemaVersion=1, securityRevision=1,
            profile='lifecycle-qualification' if requirement == 'lifecycle-qualification' else 'ordinary',
            storageContracts=['lifecycle-v2', 'lifecycle-v2-adopted-service-change-v1', 'lifecycle-v2-stable-host-identity-v1'])
        response = dict(buildFingerprint=fingerprint, serviceName='dev.cengine.network-helper.test-compat',
                        ownerUID=os.getuid(), protocolVersion=5, capabilities=capabilities)
        (root / 'status.json').write_text(json.dumps(response))
        binary = root / 'cengine'
        binary.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
with open(os.environ['STATUS_CALLS'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
assert sys.argv[1:] == ['helper', 'status', '--require-managed', os.environ['REQUIREMENT']]
# Real Swift authentication/capability validation has separate native coverage.
# Model its fail-closed exit; a shell retry without --require-managed is forbidden.
if os.environ.get('CLIENT_REJECT') == '1':
    sys.exit(42)
print(pathlib.Path(os.environ['STATUS_RESPONSE']).read_text())
''')
        binary.chmod(0o755)
        source = (ROOT / 'Scripts/compat-network-helper.sh').read_text()
        commands = {
            '/usr/bin/codesign': '''import os, pathlib, sys
args = sys.argv[1:]
path = pathlib.Path(args[-1])
installed = str(path) == os.environ['INSTALLED_HELPER']
component = 'installed-helper' if installed else path.name
if args[0] == '--verify':
    if os.environ.get('BAD_SIGNATURE') == component:
        sys.exit(1)
    if '-R' in args:
        roles = {'cengine': 'engine', 'cengine-helper': 'network-helper',
                 'cengine-storage-controller': 'storage-control', 'installed-helper': 'network-helper'}
        assert args[3] == '=anchor apple generic and identifier "dev.cengine.' + roles[component] + '.test-compat" and certificate leaf[subject.OU] = "ABCDEFGHIJ"'
else:
    digest = ('d' if installed and os.environ['CODE_DRIFT'] == '1' else 'c') * 64
    print('TeamIdentifier=ABCDEFGHIJ\\nAuthority=Developer ID Application: Fixture\\nflags=0x10000(runtime)\\nCandidateCDHashFull sha256=' + digest, file=sys.stderr)
''',
            '/usr/bin/stat': '''import os, pathlib, sys
field, path = sys.argv[2:]
if field == '%u': print(os.getuid() if pathlib.Path(path).name == 'client-token' else 0)
elif field == '%Lp': print('600')
elif field == '%Sp': print('-rwxr-xr-x')
else: sys.exit(1)
''',
            '/bin/launchctl': "import sys\nassert sys.argv[1:] == ['print', 'system/dev.cengine.network-helper.test-compat']\n",
        }
        for command, body in commands.items():
            mock = root / Path(command).name
            mock.write_text(f'#!{sys.executable}\n' + body)
            mock.chmod(0o755)
            source = source.replace(command, shlex.quote(str(mock)))
        library = root / 'helper.sh'
        library.write_text(source)
        variables = dict(ROOT=ROOT, compat_network_helper_support_root=root / 'support',
            compat_network_helper_parent=installed.parent, compat_network_helper_root=installed,
            compat_network_helper_path=helper, compat_network_helper_token_path=token,
            compat_network_helper_manifest_path=installed / 'manifest', compat_network_helper_plist=root / 'helper.plist')
        script = f'. {shlex.quote(str(library))}; ' + ''.join(
            f'{key}={shlex.quote(str(value))}; ' for key, value in variables.items())
        script += f'compat_network_helper_require {shlex.quote(str(binary))} {"a" * 64}'
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('CENGINE_', 'PREPARE_'))}
        environment.update(CENGINE_COMPAT_MANAGED_ASSET_DIR=str(assets),
            STATUS_CALLS=str(root / 'status-calls'), STATUS_RESPONSE=str(root / 'status.json'),
            INSTALLED_HELPER=str(helper), CODE_DRIFT='1' if code_drift else '0', REQUIREMENT=requirement)
        if profile == 'full':
            environment.update(CENGINE_STORAGE_CONTROLLER_PREPARE_COMPATIBILITY='rtm096-full-nine-v3',
                               PREPARE_COMPATIBILITY_PROFILE='rtm096-full-nine-v3')
        elif profile in ('before-configure-v1', 'after-replacement-before-completion-v1'):
            environment['CENGINE_COMPAT_LIFECYCLE_FAULT'] = profile
        if requirement == 'lifecycle-qualification':
            environment['CENGINE_STORAGE_LIFECYCLE_QUALIFICATION'] = 'lifecycle-v2-native-v1'
        return script, environment

    def test_ordinary_helper_accepts_fingerprint_and_code_drift_through_authenticated_status(self):
        for requirement in ('lifecycle-v2',):
            for fingerprint_drift, code_drift in ((True, False), (False, True), (True, True)):
                with self.subTest(requirement=requirement, fingerprint=fingerprint_drift, code=code_drift), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    script, environment = self.helper_requirement_fixture(root, requirement,
                        fingerprint_drift=fingerprint_drift, code_drift=code_drift)
                    result = self.run_shell(script, env=environment)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f'policy: compatible; required contract: {requirement}', result.stderr)
                    self.assertIn('Privileged Helper capabilities:', result.stderr)
                    self.assertEqual([json.loads(line) for line in (root / 'status-calls').read_text().splitlines()],
                                     [['helper', 'status', '--require-managed', requirement]])
                    if fingerprint_drift:
                        self.assertIn('compatible provisioned helper differs', result.stderr)

    def test_exact_helper_rejects_fingerprint_or_code_drift_before_status(self):
        for profile in ('explicit', 'full', 'before-configure-v1',
                        'after-replacement-before-completion-v1', 'qualification'):
            requirement = 'lifecycle-qualification' if profile == 'qualification' else 'lifecycle-v2'
            for fingerprint_drift, code_drift in ((True, False), (False, True)):
                with self.subTest(profile=profile, fingerprint=fingerprint_drift), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    script, environment = self.helper_requirement_fixture(root, requirement, profile=profile,
                        fingerprint_drift=fingerprint_drift, code_drift=code_drift)
                    if profile == 'explicit':
                        environment['CENGINE_COMPAT_REQUIRE_EXACT_HELPER'] = '1'
                    result = self.run_shell(script, env=environment)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('exact locally built installed helper', result.stderr)
                    self.assertIn('attended command', result.stderr)
                    self.assertFalse((root / 'status-calls').exists())

    def test_profile_helper_accepts_exact_pair_with_required_contract(self):
        for profile in ('full', 'before-configure-v1', 'after-replacement-before-completion-v1', 'qualification'):
            requirement = 'lifecycle-qualification' if profile == 'qualification' else 'lifecycle-v2'
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script, environment = self.helper_requirement_fixture(root, requirement, profile=profile)
                result = self.run_shell(script, env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'policy: exact; required contract: {requirement}', result.stderr)
                self.assertEqual([json.loads(line) for line in (root / 'status-calls').read_text().splitlines()],
                                 [['helper', 'status', '--require-managed', requirement]])

    def test_default_helper_does_not_require_default_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script, environment = self.helper_requirement_fixture(root, fingerprint_drift=True, code_drift=True)
            environment.pop('CENGINE_COMPAT_MANAGED_ASSET_DIR')
            (root / 'Scripts').symlink_to(ROOT / 'Scripts', target_is_directory=True)
            script = script.replace(f'ROOT={shlex.quote(str(ROOT))};', f'ROOT={shlex.quote(str(root))};')
            self.assertFalse((root / '.build/guest').exists())
            result = self.run_shell(script, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('policy: compatible; required contract: lifecycle-v2', result.stderr)
            self.assertEqual([json.loads(line) for line in (root / 'status-calls').read_text().splitlines()],
                             [['helper', 'status', '--require-managed', 'lifecycle-v2']])

    def test_explicit_helper_assets_and_profiles_still_validate_metadata(self):
        for profile in ('ordinary', 'full', 'before-configure-v1', 'qualification'):
            requirement = 'lifecycle-qualification' if profile == 'qualification' else 'lifecycle-v2'
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script, environment = self.helper_requirement_fixture(root, requirement, profile=profile)
                (root / 'assets/disk-bootstrap.json').unlink()
                result = self.run_shell(script, env=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('managed helper policy refused', result.stderr)
                self.assertFalse((root / 'status-calls').exists())

    def test_helper_retired_selectors_reject_even_empty_before_status(self):
        for key in ('CENGINE_COMPAT_SHARED_STORAGE', 'CENGINE_COMPAT_MANAGED_STORAGE'):
            for selection in ('', '0', '1', 'legacy', 'managed', 'lifecycle', 'unexpected-selector'):
                with self.subTest(key=key, selection=selection), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    script, environment = self.helper_requirement_fixture(root)
                    environment[key] = selection
                    result = self.run_shell(script, env=environment)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('retired', result.stderr)
                    self.assertFalse((root / 'status-calls').exists())

    def test_ordinary_helper_still_rejects_signature_and_installed_integrity_failures(self):
        for failure in ('cengine', 'cengine-helper', 'cengine-storage-controller', 'installed-helper', 'integrity'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script, environment = self.helper_requirement_fixture(root, fingerprint_drift=True, code_drift=True)
                if failure == 'integrity':
                    Path(environment['INSTALLED_HELPER']).write_text('tampered installed bytes')
                else:
                    environment['BAD_SIGNATURE'] = failure
                result = self.run_shell(script, env=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'status-calls').exists())
                if failure == 'integrity':
                    self.assertIn('does not match its installed manifest', result.stderr)

    def test_missing_capability_client_failure_has_no_status_fallback(self):
        for requirement in ('lifecycle-v2', 'lifecycle-qualification'):
            with self.subTest(requirement=requirement), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script, environment = self.helper_requirement_fixture(root, requirement)
                response = json.loads((root / 'status.json').read_text())
                del response['capabilities']
                (root / 'status.json').write_text(json.dumps(response))
                environment['CLIENT_REJECT'] = '1'
                result = self.run_shell(script, env=environment)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertIn('authenticated health check', result.stderr)
                self.assertEqual([json.loads(line) for line in (root / 'status-calls').read_text().splitlines()],
                                 [['helper', 'status', '--require-managed', requirement]])

    def test_old_lifecycle_contract_client_refusal_has_no_status_fallback(self):
        cases = [(requirement, contracts)
                 for requirement in ('lifecycle-v2', 'lifecycle-qualification')
                 for contracts in (['bootstrap-v1'], ['lifecycle-v2'], ['lifecycle-v2', 'lifecycle-v2-adopted-service-change-v1'])]
        for requirement, contracts in cases:
            with self.subTest(requirement=requirement, contracts=contracts), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                script, environment = self.helper_requirement_fixture(root, requirement)
                response = json.loads((root / 'status.json').read_text())
                response['capabilities']['storageContracts'] = contracts
                (root / 'status.json').write_text(json.dumps(response))
                # The native client rejects the missing mandatory extension; shell
                # policy must preserve that failure rather than retry legacy status.
                environment['CLIENT_REJECT'] = '1'
                result = self.run_shell(script, env=environment)
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertIn('authenticated health check', result.stderr)
                self.assertEqual([json.loads(line) for line in (root / 'status-calls').read_text().splitlines()],
                                 [['helper', 'status', '--require-managed', requirement]])

    def test_code_digest_parser_requires_one_full_sha256_not_truncated_cdhash(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            signer = root / 'codesign'
            signer.write_text('#!/bin/sh\nprintf "%s\\n" "$SIGNATURE_DETAILS" >&2\n')
            signer.chmod(0o755)
            # Substitute only the inert command dependency in the actual source.
            source = (ROOT / 'Scripts/compat-network-helper.sh').read_text().replace('/usr/bin/codesign', shlex.quote(str(signer)))
            library = root / 'helper.sh'
            library.write_text(source)
            command = f'. {shlex.quote(str(library))}; compat_network_helper_code_digest /fixture'
            digest = 'a' * 64
            for details, accepted in ((f'CandidateCDHashFull sha256={digest}', True),
                    (f'CDHash={digest[:40]}', False), ('CandidateCDHashFull sha256=abcd', False),
                    (f'CandidateCDHashFull sha256={digest}\\nCandidateCDHashFull sha256={digest}', False)):
                result = self.run_shell(command, env=dict(os.environ, SIGNATURE_DETAILS=details))
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    self.assertEqual(result.stdout.strip(), digest)

    def test_release_rejects_a_team_override_instead_of_embedding_requirement_syntax(self):
        source = (ROOT / 'Scripts/package-release.sh').read_text()
        self.assertIn('team_identifier=$(managed_signing_team "$developer_id_application")', source)
        self.assertIn('$CENGINE_TEAM_IDENTIFIER != $team_identifier', source)
        self.assertNotIn('team_identifier="${CENGINE_TEAM_IDENTIFIER:-', source)

    def test_runner_normalizes_absolute_and_relative_paths_without_starting(self):
        source = (ROOT / 'Scripts/run-compat-tests.sh').read_text()
        # Run the actual preflight prefix only. No lock/reset/build/install/daemon.
        prefix = source[:source.index('LOCK=')]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            assets = root / 'experimental'
            self.ordinary_assets(assets)
            for derived in (str(root / 'absolute DD'), '.build/relative DD'):
                environment = dict(os.environ, XCODE_DERIVED_DATA=derived,
                    CENGINE_DEVELOPER_ID_APPLICATION=IDENTITY, CENGINE_COMPAT_MANAGED_ASSET_DIR=str(assets))
                for key in ('CENGINE_BINARY', 'XCODE_PROJECT', 'XCODE_SOURCE_PACKAGES'):
                    environment.pop(key, None)
                # $0 supplies the original script directory to its real ROOT calculation.
                result = subprocess.run(['/bin/sh', '-c', prefix + '\nprintf "%s\\n" "$XCODE_DERIVED_DATA" "$BINARY" "$CENGINE_KERNEL"',
                    str(ROOT / 'Scripts/run-compat-tests.sh')], env=environment, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = result.stdout.splitlines()
                expected = derived if derived.startswith('/') else str(ROOT / derived)
                self.assertEqual(lines, [expected, expected + '/Build/Products/test-compat/cengine', str(assets / 'vmlinux')])
            self.assertNotIn('"$ROOT/$XCODE_DERIVED_DATA"', source)


class StartupFailure(BaseException):
    """Match pytest.fail's BaseException behavior without importing pytest."""
    def __init__(self, message, *, pytrace=True):
        super().__init__(message)
        self.pytrace = pytrace


class ManagedStartupTests(unittest.TestCase):
    SECRET = 'legacy-spec-token=SECRET managed-spec-token=SECRET log-secret=SECRET'

    @classmethod
    def setUpClass(cls):
        source = ROOT / 'Tests/Compatibility/conftest.py'
        tree = ast.parse(source.read_text())
        names = {'managed_storage_arguments', 'Daemon', 'daemon', 'daemon_survived',
                 'pytest_runtest_makereport'}
        nodes = [node for node in tree.body if getattr(node, 'name', None) in names]
        for node in nodes:
            if isinstance(node, ast.FunctionDef):
                node.decorator_list = []
        cls.code = compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec',
                           flags=__future__.annotations.compiler_flag)

    def setup_fixture(self, *, outcome='death', marker_error=False, stop_error=False,
                      cleanup_error=False, manual=False, repair_root=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        work = base / 'work'
        work.mkdir(mode=0o700)
        asset = base / 'asset'
        asset.touch()
        events = []
        process = Mock(returncode=None)
        process.poll.side_effect = lambda: process.returncode
        process.wait.return_value = 0

        def terminate():
            events.append('stop')
            if stop_error:
                raise OSError(self.SECRET)
            process.returncode = -15

        def kill():
            events.append('kill')
            process.returncode = -9

        process.terminate.side_effect = terminate
        process.kill.side_effect = kill
        fake_subprocess = SimpleNamespace(
            Popen=Mock(), run=Mock(), TimeoutExpired=subprocess.TimeoutExpired,
            DEVNULL=subprocess.DEVNULL, STDOUT=subprocess.STDOUT, PIPE=subprocess.PIPE)
        clock = Mock(side_effect=[0, 0, 61])
        fake_time = SimpleNamespace(monotonic=clock, sleep=Mock())

        def retain(directory, binary, *, reason):
            events.append('retain')
            self.assertTrue(value._retain_root)
            self.assertEqual(reason, 'unsafe-disk-phase')
            if marker_error:
                raise OSError(self.SECRET)
            harness.retain_compatibility_root(directory, binary, reason=reason)

        def cleanup(binary, *, roots):
            events.append('owned-cleanup')
            self.assertEqual(binary, value.owner_binary)
            self.assertTrue(harness.compatibility_root_owned_by(value.work, binary))
            self.assertEqual(roots, (value.root,))
            if outcome != 'success':
                self.assertTrue(value.root_retained)
            if cleanup_error:
                raise OSError(self.SECRET)
            process.returncode = -9 if process.returncode is None else process.returncode

        def remove(directory, binary):
            events.append('remove')
            return harness.remove_compatibility_root(directory, binary)

        def fail(message, **kwargs):
            raise StartupFailure(message, **kwargs)

        # AST extraction omits the production global deliberately: never let an
        # offline startup test census native clients or contact/restart a helper.
        boundary = Mock(spec_set=('prepare', 'created'))
        creation = Mock()
        creation.attach_mock(boundary.prepare, 'prepare')
        creation.attach_mock(boundary.created, 'created')
        namespace = dict(__name__=__name__, dataclass=dataclass, field=field, pathlib=pathlib,
            HELPER_FIXTURE_BOUNDARY=boundary,
            local_build_image_preflight=lambda request: {},
            subprocess=fake_subprocess, time=fake_time, os=SimpleNamespace(environ={}),
            compatibility_environment=Mock(return_value={}),
            COMPATIBILITY_OWNER_FILE=harness.COMPATIBILITY_OWNER_FILE,
            compatibility_root_retained=harness.compatibility_root_retained,
            preretain_compatibility_root=harness.preretain_compatibility_root,
            release_compatibility_root=harness.release_compatibility_root,
            retain_compatibility_root=Mock(side_effect=retain), terminate_compatibility_runtime=Mock(side_effect=cleanup),
            remove_compatibility_root=Mock(side_effect=remove), pytest=SimpleNamespace(fail=fail),
            tempfile=SimpleNamespace(mkdtemp=Mock(return_value=str(work))),
            DEFAULT_BINARY=asset, DEFAULT_KERNEL=asset, DEFAULT_CONTAINER_INITRAMFS=asset,
            DEFAULT_STORAGE_INITRAMFS=asset, clone_tree=Mock())
        exec(self.code, namespace)
        value = namespace['Daemon'](binary=asset, kernel=asset, container_initramfs=asset,
                                    storage_initramfs=asset, work=work)
        namespace['Daemon'] = Mock(return_value=value)
        creation.attach_mock(namespace['tempfile'].mkdtemp, 'mkdtemp')
        creation.attach_mock(namespace['Daemon'], 'daemon')
        request = SimpleNamespace(node=SimpleNamespace())  # No report_setup published yet.
        if manual:
            request.param = 'lifecycle-first-start'
            request.node.get_closest_marker = lambda name: SimpleNamespace(args=('RTM-119',))
            namespace['os'].environ.update(CENGINE_COMPAT_LIFECYCLE_FAULT='before-configure-v1')
        if repair_root:
            request.param = 'lifecycle-root-permissions'
            request.node.get_closest_marker = lambda name: SimpleNamespace(args=('RTM-122',))
        fixture = namespace['daemon'](request, base / 'empty-cache')
        value._fixture_started = True

        def capture(root, backend):
            self.assertEqual(root.stat().st_mode & 0o7777, 0o700)
            self.assertEqual(backend, 'lifecycle')
            if getattr(value, '_fixture_started', False):
                self.assertTrue(harness.compatibility_root_retained(value.work))
            (root / 'boot-evidence').write_text(self.SECRET)
            if outcome == 'capture-error':
                raise OSError(self.SECRET)

        backend = patch.dict(sys.modules, storage_backend_proof=SimpleNamespace(capture_backend_root=capture))
        backend.start()
        self.addCleanup(backend.stop)

        def launch(*args, **kwargs):
            self.assertEqual(value.root.stat().st_mode & 0o7777, 0o755 if repair_root else 0o700)
            process.returncode = None
            kwargs['stdout'].write(self.SECRET.encode())
            kwargs['stdout'].flush()
            if outcome == 'popen-error':
                raise OSError(self.SECRET)
            if outcome == 'death':
                process.returncode = 71
            else:
                value.socket.touch()
            return process

        fake_subprocess.Popen.side_effect = launch
        fake_subprocess.run.return_value = SimpleNamespace(returncode=0 if outcome == 'success' else 1,
            stdout='OK' if outcome == 'success' else self.SECRET, stderr=self.SECRET)
        if outcome == 'ping-error':
            fake_subprocess.run.side_effect = RuntimeError(self.SECRET)
        if outcome == 'clock-error':
            clock.side_effect = RuntimeError(self.SECRET)
        if outcome == 'sleep-error':
            fake_time.sleep.side_effect = RuntimeError(self.SECRET)
        if outcome == 'environment-error':
            namespace['compatibility_environment'].side_effect = OSError(self.SECRET)
        return SimpleNamespace(value=value, fixture=fixture, process=process, namespace=namespace,
                               events=events, request=request, subprocess=fake_subprocess,
                               boundary=boundary, creation=creation)

    def assert_fixture_creation_order(self, case):
        asset = case.namespace['DEFAULT_BINARY']
        self.assertEqual(case.creation.mock_calls, [
            call.prepare(asset), call.mkdtemp(prefix='cengine-compat-'),
            call.daemon(binary=asset, kernel=asset, container_initramfs=asset,
                        storage_initramfs=asset, work=case.value.work),
            call.created(case.value),
        ])

    def test_permission_fault_is_injected_after_strict_pin_on_each_start(self):
        case = self.setup_fixture(outcome='success', repair_root=True)
        self.assertIs(next(case.fixture), case.value)
        self.assertEqual(case.value.root.stat().st_mode & 0o7777, 0o755)
        # Simulate only the engine's repair; the harness must never do this.
        case.value.root.chmod(0o700)
        case.value.stop()
        case.namespace['time'].monotonic.side_effect = [0, 0]
        case.value.start()
        self.assertEqual(case.value.root.stat().st_mode & 0o7777, 0o755)
        self.assertEqual(case.subprocess.Popen.call_count, 2)
        for phase in ('setup', 'call'):
            self.report(case, phase)
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.report(case, 'teardown')
        self.assertFalse(case.value.work.exists())

    def test_manual_fault_start_qualifies_before_cleanup_and_does_not_latch(self):
        case = self.setup_fixture(manual=True)
        self.assertIs(next(case.fixture), case.value)
        self.assert_fixture_creation_order(case)
        self.assertTrue(case.value.root_retained)
        case.subprocess.Popen.assert_not_called()
        case.process.wait.return_value = 71

        def qualify(value):
            self.assertIs(value, case.value)
            self.assertEqual(case.events, [])
            self.assertEqual(case.process.poll(), 71)
            case.process.terminate.assert_not_called()
            case.process.kill.assert_not_called()
            return True

        case.value.start(qualify_lifecycle_fault=qualify)
        case.process.wait.assert_called_once_with(timeout=60)
        self.assertFalse(case.value._retain_root)
        self.assertIsNone(case.value._log)
        self.assertTrue(case.value.root_retained)
        case.namespace['terminate_compatibility_runtime'].assert_not_called()
        # A qualified first failure is not authority to forgive another one.
        with self.assertRaises(ValueError):
            case.value.start(qualify_lifecycle_fault=qualify)
        for phase in ('setup', 'call'):
            self.report(case, phase)
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.assertTrue(case.value.root_retained)
        self.report(case, 'teardown')
        self.assertFalse(case.value.work.exists())

    def test_manual_start_unexpected_results_keep_generic_retention(self):
        for outcome in ('zero', 'signal', 'timeout', 'unqualified', 'proof-error', 'spawn-error'):
            with self.subTest(outcome=outcome):
                case = self.setup_fixture(manual=True,
                    outcome='popen-error' if outcome == 'spawn-error' else 'death')
                next(case.fixture)
                proof = Mock(return_value=outcome != 'unqualified')
                case.process.wait.return_value = {'zero': 0, 'signal': -9}.get(outcome, 71)
                if outcome == 'timeout':
                    case.process.wait.side_effect = subprocess.TimeoutExpired('daemon', 60)
                if outcome == 'proof-error':
                    proof.side_effect = OSError(self.SECRET)
                with self.assertRaises(StartupFailure) as failure:
                    case.value.start(qualify_lifecycle_fault=proof)
                self.assertNotIn(self.SECRET, str(failure.exception))
                self.assertTrue(case.value._retain_root)
                self.assertEqual(case.events[0], 'retain')
                self.assertIn('owned-cleanup', case.events)
                if outcome in ('zero', 'signal', 'timeout', 'spawn-error'):
                    proof.assert_not_called()
                for phase in ('setup', 'call'):
                    self.report(case, phase)
                with self.assertRaises(StopIteration):
                    next(case.fixture)
                self.report(case, 'teardown')
                self.assertTrue(case.value.work.exists())

    def test_manual_mode_is_not_a_generic_startup_failure_escape(self):
        case = self.setup_fixture(manual=True)
        case.request.node.get_closest_marker = lambda name: SimpleNamespace(args=('RTM-117',))
        with self.assertRaises(ValueError):
            next(case.fixture)
        case.subprocess.Popen.assert_not_called()
        case = self.setup_fixture(outcome='success')
        with self.assertRaises(ValueError):
            case.value.start(qualify_lifecycle_fault=lambda value: True)
        case.subprocess.Popen.assert_not_called()

    def test_manual_fixture_failed_report_preserves_preretained_root(self):
        case = self.setup_fixture(manual=True)
        next(case.fixture)
        case.process.wait.return_value = 71
        case.value.start(qualify_lifecycle_fault=lambda value: True)
        self.report(case, 'setup', passed=False)
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.report(case, 'teardown')
        self.assertFalse(case.value._retain_root)
        self.assertTrue(case.value.work.exists())
        self.assertTrue(case.value.root_retained)

    def test_new_daemon_root_is_private_even_with_permissive_umask(self):
        for mask in (0o022, 0o000):
            with self.subTest(umask=oct(mask)):
                previous = os.umask(mask)
                try:
                    case = self.setup_fixture()
                finally:
                    os.umask(previous)
                self.assertEqual(case.value.root.stat().st_mode & 0o777, 0o700)
                case.subprocess.Popen.assert_not_called()

    def test_existing_retained_root_is_not_repaired_or_reused(self):
        case = self.setup_fixture()
        root = case.value.root
        root.rmdir()
        previous = os.umask(0o022)
        try:
            root.mkdir(mode=0o755)
        finally:
            os.umask(previous)
        evidence = root / 'retained-evidence'
        evidence.write_text(self.SECRET)
        case.value.retain_root(reason='unsafe-disk-phase')
        marker = case.value.work / harness.COMPATIBILITY_RETAIN_FILE
        original_marker = marker.read_bytes()
        with self.assertRaises(FileExistsError):
            case.value.__post_init__()
        self.assertEqual(root.stat().st_mode & 0o777, 0o755)
        self.assertEqual(evidence.read_text(), self.SECRET)
        self.assertEqual(marker.read_bytes(), original_marker)
        self.assertTrue(case.value.root_retained)
        case.subprocess.Popen.assert_not_called()

    def assert_managed_failure(self, **kwargs):
        case = self.setup_fixture(**kwargs)
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(StartupFailure) as error:
            next(case.fixture)
        self.assertFalse(error.exception.pytrace)
        self.assertIn(f'root retained: {case.value.work}', str(error.exception))
        self.assertNotIn(self.SECRET, str(error.exception) + output.getvalue())
        self.assertTrue(case.value.root_retained)
        self.assertTrue(case.value.work.is_dir())
        self.assertEqual((case.value.root / 'boot-evidence').read_text(), self.SECRET)
        self.assertIsNone(case.value._log)
        if not (kwargs.get('stop_error') and kwargs.get('cleanup_error')):
            self.assertIsNotNone(case.process.returncode)
        self.assertEqual(case.events[0], 'retain')
        self.assertIn('owned-cleanup', case.events)
        self.assertNotIn('remove', case.events)
        self.assertFalse(hasattr(case.request.node, 'report_setup'))
        case.namespace['remove_compatibility_root'].assert_not_called()
        return case, str(error.exception)

    def test_readiness_death_retains_before_fixture_cleanup(self):
        case, _ = self.assert_managed_failure(outcome='death')
        self.assertEqual(case.value.log_path.read_text(), self.SECRET)
        self.assertTrue((case.value.work / harness.COMPATIBILITY_RETAIN_FILE).is_file())
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))
        self.assertTrue(case.value.work.is_dir())
        case.subprocess.run.assert_not_called()

    def test_timeout_and_startup_exceptions_retain_evidence(self):
        for outcome in ('timeout', 'ping-error', 'clock-error', 'sleep-error', 'popen-error',
                        'capture-error', 'environment-error'):
            with self.subTest(outcome=outcome):
                self.assert_managed_failure(outcome=outcome)

    def test_marker_io_failure_still_latches_and_stops_processes(self):
        case, _ = self.assert_managed_failure(outcome='timeout', marker_error=True)
        self.assertTrue((case.value.work / harness.COMPATIBILITY_RETAIN_FILE).is_file())
        case.value._retain_root = False  # The outer runner has no pytest memory.
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))
        self.assertEqual((case.value.root / 'boot-evidence').read_text(), self.SECRET)
        self.assertLess(case.events.index('retain'), case.events.index('stop'))
        self.assertLess(case.events.index('stop'), case.events.index('owned-cleanup'))
        case.process.terminate.assert_called_once()

    def test_stop_failure_cannot_skip_owned_cleanup_or_expose_secrets(self):
        case, message = self.assert_managed_failure(outcome='timeout', marker_error=True, stop_error=True)
        self.assertIn('process cleanup incomplete', message)
        self.assertEqual(case.process.returncode, -9)

    def test_persistent_cleanup_errors_remain_sanitized_during_fixture_unwind(self):
        for stop_error in (False, True):
            with self.subTest(stop_error=stop_error):
                case, message = self.assert_managed_failure(
                    outcome='timeout', marker_error=True, stop_error=stop_error, cleanup_error=True)
                self.assertIn('process cleanup incomplete', message)
                self.assertEqual(case.events.count('owned-cleanup'), 2)
                if stop_error:
                    self.assertEqual(case.events.count('stop'), 2)
                    self.assertIsNone(case.process.returncode)  # Explicit cleanup failure, not hidden success.

    def test_already_retained_failure_never_dumps_raw_logs(self):
        case = self.setup_fixture(outcome='death')
        case.value._retain_root = True
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(StartupFailure) as error:
            next(case.fixture)
        self.assertFalse(error.exception.pytrace)
        self.assertNotIn(self.SECRET, str(error.exception) + output.getvalue())
        self.assertIn('root retained:', str(error.exception))
        self.assertIn('retain', case.events)  # Every lifecycle failure remains fenced.
        self.assertNotIn('remove', case.events)
        self.assertTrue(case.value.work.is_dir())

    def test_retained_liveness_failure_reports_only_metadata(self):
        case, _ = self.assert_managed_failure()
        for failed in (False, True):
            with self.subTest(failed=failed):
                case.request.node.report_call = SimpleNamespace(failed=failed)
                survived = case.namespace['daemon_survived'](case.value, case.request)
                next(survived)
                output = io.StringIO()
                with redirect_stdout(output):
                    if failed:
                        with self.assertRaises(StopIteration):
                            next(survived)
                    else:
                        with self.assertRaises(StartupFailure) as error:
                            next(survived)
                        self.assertNotIn(self.SECRET, str(error.exception))
                self.assertNotIn(self.SECRET, output.getvalue())

    def report(self, case, phase, *, passed=True):
        report = SimpleNamespace(passed=passed, failed=not passed)
        hook = case.namespace['pytest_runtest_makereport'](
            case.request.node, SimpleNamespace(when=phase))
        next(hook)
        with self.assertRaises(StopIteration):
            hook.send(SimpleNamespace(get_result=lambda: report))

    def test_success_releases_managed_only_after_clean_teardown_report(self):
        case = self.setup_fixture(outcome='success')
        self.assertIs(next(case.fixture), case.value)
        self.assert_fixture_creation_order(case)
        self.assertTrue(case.value.root_retained)
        self.assertIsNone(case.process.returncode)
        self.report(case, 'setup')
        self.report(case, 'call')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.assertTrue(case.value.root_retained)
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))
        self.report(case, 'teardown')
        self.assertEqual(case.events, ['stop', 'owned-cleanup', 'remove'])
        self.assertFalse(case.value.work.exists())
        self.assertIsNone(case.value._log)

    def test_expected_call_xfail_releases_only_after_owned_cleanup_and_teardown(self):
        case = self.setup_fixture(outcome='success')
        self.assertIs(next(case.fixture), case.value)
        self.report(case, 'setup')
        case.request.node.report_call = SimpleNamespace(
            passed=False, failed=False, skipped=True, wasxfail='unsupported direct build')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.assertEqual(case.events, ['stop', 'owned-cleanup'])
        self.assertTrue(case.value.root_retained)
        self.assertTrue(case.value.work.is_dir())
        self.report(case, 'teardown')
        self.assertEqual(case.events, ['stop', 'owned-cleanup', 'remove'])
        self.assertFalse(case.value.work.exists())

    def select_staged_runtime(self, case):
        owner = case.value.owner_binary
        marker = case.value.work / harness.COMPATIBILITY_OWNER_FILE
        before = marker.read_bytes()
        staged = (case.value.work / 'upgrade-bin' / 'cengine').resolve()
        staged.parent.mkdir()
        staged.touch()
        harness.register_compatibility_executable(case.value.work, owner, staged)
        case.value.binary = staged
        self.assertEqual(case.value.owner_binary, owner)
        self.assertEqual(marker.read_bytes(), before)
        self.assertEqual(harness.compatibility_registered_executables(case.value.work, owner), (staged,))
        self.assertFalse(harness.compatibility_root_owned_by(case.value.work, staged))
        return staged

    def test_staged_runtime_preserves_original_cleanup_owner(self):
        case = self.setup_fixture(outcome='success')
        staged = self.select_staged_runtime(case)
        self.assertIs(next(case.fixture), case.value)
        self.assertEqual(case.subprocess.Popen.call_args.args[0][0], str(staged))
        self.report(case, 'setup')
        self.report(case, 'call')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.assertTrue(case.value.work.exists())
        self.report(case, 'teardown')
        self.assertEqual(case.events, ['stop', 'owned-cleanup', 'remove'])
        self.assertFalse(case.value.work.exists())
        self.assertEqual(case.value.binary, staged)

    def test_staged_startup_failure_retains_under_original_owner(self):
        case = self.setup_fixture(outcome='death')
        staged = self.select_staged_runtime(case)
        with self.assertRaises(StartupFailure):
            next(case.fixture)
        self.assertEqual(case.subprocess.Popen.call_args.args[0][0], str(staged))
        self.assertTrue(case.value._retain_root)
        self.assertIn('owned-cleanup', case.events)
        self.assertNotIn('remove', case.events)
        marker = case.value.work / harness.COMPATIBILITY_RETAIN_FILE
        # Existing retention markers are never overwritten, even on failure.
        self.assertEqual(json.loads(marker.read_bytes())['reason'], 'managed-fixture-active')
        case.namespace['retain_compatibility_root'].assert_called_once_with(
            case.value.work, case.value.owner_binary, reason='unsafe-disk-phase')
        self.assertEqual(case.value.binary, staged)

    def test_staged_failed_missing_or_retained_reports_preserve_evidence(self):
        for failure in ('setup', 'call', 'teardown', 'missing-setup', 'missing-call', 'retained'):
            with self.subTest(failure=failure):
                case = self.setup_fixture(outcome='success')
                self.select_staged_runtime(case)
                next(case.fixture)
                if failure == 'retained':
                    case.value.retain_root(reason='unsafe-disk-phase')
                for phase in ('setup', 'call'):
                    if failure != 'missing-' + phase:
                        self.report(case, phase, passed=failure != phase)
                with self.assertRaises(StopIteration):
                    next(case.fixture)
                self.report(case, 'teardown', passed=failure != 'teardown')
                self.assertTrue(case.value.work.is_dir())
                self.assertTrue(harness.compatibility_root_retained(case.value.work))
                self.assertIn('owned-cleanup', case.events)
                self.assertNotIn('remove', case.events)

    def test_prepublication_io_failure_prevents_all_engine_side_effects(self):
        for manual in (False, True):
            with self.subTest(boundary_refusal=True, manual=manual):
                case = self.setup_fixture(outcome='success', manual=manual)
                case.boundary.prepare.side_effect = OSError(self.SECRET)
                with self.assertRaises(StartupFailure) as failure:
                    next(case.fixture)
                self.assertEqual(str(failure.exception),
                                 'test helper fixture isolation refused; no root created')
                self.assertFalse(failure.exception.pytrace)
                self.assertEqual(case.creation.mock_calls,
                                 [call.prepare(case.namespace['DEFAULT_BINARY'])])
                case.subprocess.Popen.assert_not_called()
                case.subprocess.run.assert_not_called()
                case.namespace['clone_tree'].assert_not_called()
                case.namespace['terminate_compatibility_runtime'].assert_not_called()
        for operation in ('open', 'write', 'fsync'):
            with self.subTest(operation=operation):
                case = self.setup_fixture(outcome='success')
                with patch.object(harness.os, operation, side_effect=OSError(errno.ENOSPC, 'full')):
                    with self.assertRaises(StartupFailure):
                        next(case.fixture)
                case.subprocess.Popen.assert_not_called()
                case.subprocess.run.assert_not_called()
                case.namespace['clone_tree'].assert_not_called()
                case.namespace['terminate_compatibility_runtime'].assert_not_called()
                self.assertFalse((case.value.root / 'boot-evidence').exists())

    def test_short_prepublication_write_never_starts_and_remains_retained(self):
        case = self.setup_fixture(outcome='success')
        with patch.object(harness.os, 'write', return_value=0):
            with self.assertRaises(StartupFailure):
                next(case.fixture)
        case.subprocess.Popen.assert_not_called()
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_marker_release_obeys_root_inode_claim(self):
        case = self.setup_fixture(outcome='success')
        next(case.fixture)
        self.report(case, 'setup')
        self.report(case, 'call')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        with harness._compatibility_root_claim(case.value.work, case.value.binary):
            self.report(case, 'teardown')
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_setup_exception_before_yield_cannot_queue_marker_release(self):
        case = self.setup_fixture(outcome='success')
        cache = case.value.work.parent / 'empty-cache' / 'content'
        cache.mkdir(parents=True)
        case.namespace['clone_tree'].side_effect = OSError(errno.ENOSPC, 'full')
        with self.assertRaises(OSError):
            next(case.fixture)
        case.subprocess.Popen.assert_not_called()
        self.assertFalse(hasattr(case.request.node, '_managed_root_cleanup'))
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_failed_or_missing_reports_never_release_managed_marker(self):
        for failure in ('setup', 'call', 'teardown', 'missing-setup', 'missing-call'):
            with self.subTest(failure=failure):
                case = self.setup_fixture(outcome='success')
                next(case.fixture)
                for phase in ('setup', 'call'):
                    if failure != 'missing-' + phase:
                        self.report(case, phase, passed=failure != phase)
                with self.assertRaises(StopIteration):
                    next(case.fixture)
                self.report(case, 'teardown', passed=failure != 'teardown')
                self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_restart_keeps_preexisting_marker_and_sticky_faults(self):
        case = self.setup_fixture(outcome='success')
        next(case.fixture)
        marker = case.value.work / harness.COMPATIBILITY_RETAIN_FILE
        before = marker.stat()
        case.namespace['time'].monotonic.side_effect = None
        case.namespace['time'].monotonic.return_value = 0
        case.value.restart()
        self.assert_fixture_creation_order(case)
        self.assertEqual(marker.stat().st_ino, before.st_ino)
        case.value.retain_root(reason='unsafe-disk-phase')
        self.assertTrue(case.value._retain_root)
        self.report(case, 'setup')
        self.report(case, 'call')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.report(case, 'teardown')
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_cleanup_failure_keeps_marker_before_teardown_report(self):
        for fault in ('stop_error', 'cleanup_error'):
            with self.subTest(fault=fault):
                case = self.setup_fixture(outcome='success', **{fault: True})
                next(case.fixture)
                self.report(case, 'setup')
                self.report(case, 'call')
                with self.assertRaises(StartupFailure):
                    next(case.fixture)
                self.assertTrue(case.value._retain_root)
                self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))
                self.report(case, 'teardown', passed=False)
                self.assertTrue(case.value.work.exists())

    def test_mutated_or_replaced_marker_cannot_be_released(self):
        for mutation in ('empty', 'bytes', 'symlink', 'fifo', 'replacement', 'mode', 'root'):
            with self.subTest(mutation=mutation):
                case = self.setup_fixture(outcome='success')
                next(case.fixture)
                marker = case.value.work / harness.COMPATIBILITY_RETAIN_FILE
                original = marker.read_bytes()
                if mutation == 'empty':
                    marker.write_bytes(b'')
                elif mutation == 'bytes':
                    marker.write_bytes(original + b' ')
                elif mutation == 'mode':
                    marker.chmod(0o644)
                elif mutation == 'root':
                    saved = case.value.work.with_name('saved')
                    case.value.work.rename(saved)
                    case.value.work.mkdir(mode=0o700)
                    (case.value.work / harness.COMPATIBILITY_OWNER_FILE).write_text(str(case.value.binary))
                    marker.write_bytes(original)
                else:
                    marker.rename(marker.with_suffix('.saved'))
                    if mutation == 'symlink':
                        marker.symlink_to(marker.with_suffix('.saved'))
                    elif mutation == 'fifo':
                        os.mkfifo(marker)
                    else:
                        marker.write_bytes(original)
                        marker.chmod(0o600)
                self.report(case, 'setup')
                self.report(case, 'call')
                with self.assertRaises(StopIteration):
                    next(case.fixture)
                self.report(case, 'teardown')
                self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_new_fixture_never_adopts_a_prior_marker(self):
        for contents in (b'', b'{"schemaVersion":1,"reason":"managed-fixture-active"}\n'):
            case = self.setup_fixture(outcome='success')
            marker = case.value.work / harness.COMPATIBILITY_RETAIN_FILE
            marker.write_bytes(contents)
            with self.assertRaises(StartupFailure):
                next(case.fixture)
            case.subprocess.Popen.assert_not_called()
            case.namespace['terminate_compatibility_runtime'].assert_not_called()
            self.assertEqual(marker.read_bytes(), contents)
            self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_marker_lookup_io_fault_cannot_authorize_real_removal(self):
        case = self.setup_fixture(outcome='success')
        next(case.fixture)
        marker = case.value.work / harness.COMPATIBILITY_RETAIN_FILE
        real_lstat = Path.lstat
        def fault(path, *args, **kwargs):
            if path == marker:
                raise OSError(errno.EIO, 'injected marker lookup fault')
            return real_lstat(path, *args, **kwargs)
        with patch.object(Path, 'lstat', fault):
            self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))
        with self.assertRaises(StopIteration):
            next(case.fixture)

    def test_cross_process_retention_invalidates_fixture_receipt(self):
        case = self.setup_fixture(outcome='success')
        next(case.fixture)
        harness.retain_compatibility_root(case.value.work, case.value.binary, reason='cleanup-incomplete')
        self.assertFalse(case.value._retain_root)  # No shared Python latch.
        self.report(case, 'setup')
        self.report(case, 'call')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        self.report(case, 'teardown')
        self.assertFalse(harness.remove_compatibility_root(case.value.work, case.value.binary))

    def test_missing_marker_never_enters_legacy_teardown_or_dumps_logs(self):
        case = self.setup_fixture(outcome='success')
        next(case.fixture)
        (case.value.work / harness.COMPATIBILITY_RETAIN_FILE).unlink()
        self.report(case, 'setup')
        self.report(case, 'call', passed=False)
        case.process.returncode = 71
        output = io.StringIO()
        with redirect_stdout(output):
            survived = case.namespace['daemon_survived'](case.value, case.request)
            next(survived)
            with self.assertRaises(StopIteration):
                next(survived)
            with self.assertRaises(StopIteration):
                next(case.fixture)
        self.report(case, 'teardown')
        self.assertTrue(case.value.work.exists())
        case.namespace['remove_compatibility_root'].assert_not_called()
        self.assertNotIn(self.SECRET, output.getvalue())

    def test_release_has_no_fallible_post_unlink_marker_io(self):
        case = self.setup_fixture(outcome='success')
        next(case.fixture)
        self.report(case, 'setup')
        self.report(case, 'call')
        with self.assertRaises(StopIteration):
            next(case.fixture)
        with patch.object(harness.os, 'fsync', side_effect=OSError(errno.EIO, 'full')) as sync:
            self.report(case, 'teardown')
        sync.assert_not_called()
        self.assertFalse(case.value.work.exists())

    def test_standalone_managed_start_preserves_manual_api(self):
        case = self.setup_fixture(outcome='success')
        case.value._fixture_started = False
        case.value.start()
        self.assertFalse(case.value.root_retained)
        case.value.stop()

    def test_retired_selector_failure_has_no_daemon_side_effects(self):
        for key in ('CENGINE_COMPAT_SHARED_STORAGE', 'CENGINE_COMPAT_MANAGED_STORAGE'):
            for selection in ('', '0', '1', 'legacy', 'managed', 'lifecycle', 'unexpected-selector'):
                case = self.setup_fixture(outcome='success')
                # Exercise the real standalone entry guard before capture/Popen.
                with self.assertRaises(ValueError):
                    case.namespace["os"].environ[key] = selection
                    case.value.start()
                self.assertIsNone(case.value.process)
                case.subprocess.Popen.assert_not_called()
                self.assertFalse((case.value.root / "boot-evidence").exists())



if __name__ == '__main__':
    unittest.main()
