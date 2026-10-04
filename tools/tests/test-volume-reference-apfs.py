#!/usr/bin/env python3
"""Disk-free APFS authority regressions; all diskutil/sudo commands are fakes."""
from __future__ import annotations

import builtins
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from typing import Callable

MODULE = Path(__file__).resolve().parents[1] / 'volume_reference_apfs.py'
spec = importlib.util.spec_from_file_location('apfs_setup', MODULE)
assert spec and spec.loader
apfs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apfs)
RUN = '62cbecee-fb7a-4237-9774-d780cb184c45'
NEW = 'C0216729-31FD-4E71-BD89-7C19EC9D7EE1'


def raw_inventory():
    return {'Containers': [{'APFSContainerUUID': apfs.CONTAINER, 'ContainerReference': 'disk7',
        'CapacityCeiling': apfs.CEILING, 'CapacityFree': apfs.QUOTA + apfs.HEADROOM + 1024**3,
        'PhysicalStores': [{'DeviceIdentifier': 'disk6s2', 'DiskUUID': apfs.STORE, 'Size': apfs.CEILING}],
        'Volumes': [{'APFSVolumeUUID': apfs.DATA, 'DeviceIdentifier': 'disk7s1', 'Name': 'data',
                     'Roles': [], 'CapacityQuota': 0, 'CapacityReserve': 0}]}]}


class FakeDisk:
    def __init__(self, mount):
        self.raw = raw_inventory()
        self.mount = mount
        self.created = self.mounted = self.owners = False
        self.calls = []
        self.needs_chown = False
        self.fail: str | None = None
        self.hook: Callable | None = None
        self.data = {'VolumeUUID': apfs.DATA, 'DeviceIdentifier': 'disk7s1',
            'MountPoint': str(apfs.DATA_PATH), 'FilesystemType': 'apfs', 'Internal': False,
            'APFSContainerReference': 'disk7', 'VolumeName': 'data', 'GlobalPermissionsEnabled': False}
        self.store = {'DiskUUID': apfs.STORE, 'Internal': False, 'BusProtocol': 'USB',
            'Content': 'Apple_APFS', 'DeviceIdentifier': 'disk6s2', 'APFSContainerReference': 'disk7'}

    def disk(self, *args):
        if args == ('apfs', 'list', '-plist'):
            return copy.deepcopy(self.raw)
        assert args[:2] == ('info', '-plist'), args
        target = args[-1]
        if target == 'disk6s2':
            return copy.deepcopy(self.store)
        if target == str(apfs.DATA_PATH):
            return copy.deepcopy(self.data)
        if target in (NEW, str(self.mount)) and self.created:
            return {'VolumeUUID': NEW, 'DeviceIdentifier': 'disk7s2', 'Internal': False,
                'FilesystemType': 'apfs', 'APFSContainerReference': 'disk7', 'APFSSnapshot': False,
                'VolumeName': 'cengine-ref-' + RUN, 'GlobalPermissionsEnabled': self.owners,
                'MountPoint': str(self.mount) if self.mounted else ''}
        raise AssertionError(args)

    def command(self, argv, *, full=False):
        # The test will fail rather than launch an unrecognized real command.
        self.calls.append(argv)
        assert argv[:2] == ['/usr/bin/sudo', '-n'], argv
        if argv[2] == '/usr/sbin/chown':
            assert argv == ['/usr/bin/sudo', '-n', '/usr/sbin/chown', f'{apfs.UID}:{apfs.GID}', str(self.mount)]
            assert self.mounted and self.owners and self.needs_chown
            if self.fail == 'chown':
                raise subprocess.CalledProcessError(1, argv, stderr=b'chown failed')
            self.needs_chown = False
            return subprocess.CompletedProcess(argv, 0, b'', b'') if full else b''
        assert argv[2] == apfs.DISKUTIL, argv
        verb = argv[3]
        if self.hook:
            self.hook(verb)
        if verb == 'apfs':
            assert argv[4:] == ['addVolume', apfs.CONTAINER, 'APFS', 'cengine-ref-' + RUN,
                                '-quota', str(apfs.QUOTA), '-nomount'], argv
            if self.fail != 'sudo':
                self.created = True
                self.raw['Containers'][0]['Volumes'].append({'APFSVolumeUUID': NEW,
                    'DeviceIdentifier': 'disk7s2', 'Name': 'cengine-ref-' + RUN, 'Roles': [],
                    'CapacityQuota': apfs.QUOTA, 'CapacityReserve': 0})
        elif verb == 'enableOwnership':
            assert self.mounted, 'diskutil enableOwnership requires a mounted volume'
            assert argv[4:] == [NEW], argv
            self.owners = True
        elif verb == 'mount':
            assert argv[4:] == ['nobrowse', '-mountOptions', 'owners', '-mountPoint', str(self.mount), NEW]
            self.mounted = True
        else:
            raise AssertionError(argv)
        if self.fail in (verb, 'sudo'):
            raise subprocess.CalledProcessError(1, argv, stderr=b'fake sudo/diskutil failure')
        return subprocess.CompletedProcess(argv, 0, b'fake success', b'fake warning') if full else b''


class SetupTests(unittest.TestCase):
    def setUp(self):
        # Tiny private ordinary directories only; no real disk or VM operations.
        self.temp = tempfile.TemporaryDirectory(prefix='apfs-guard-', dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.contexts = ExitStack()
        self.addCleanup(self.contexts.close)
        self.home = Path(self.temp.name).resolve()
        self.contexts.enter_context(patch.object(apfs, 'HOME', self.home))
        self.contexts.enter_context(patch.object(apfs, 'UID', os.getuid()))
        self.contexts.enter_context(patch.object(apfs, 'GID', os.getgid()))
        self.contexts.enter_context(patch.object(apfs, 'host_check'))
        self.contexts.enter_context(patch.object(apfs, 'acl_safe'))
        self.data_path = self.home / 'existing-data'
        self.data_path.mkdir()
        self.contexts.enter_context(patch.object(apfs, 'DATA_PATH', self.data_path))
        self.root, self.parent, self.mount = apfs.layout(RUN)
        self.fake = FakeDisk(self.mount)
        self.contexts.enter_context(patch.object(apfs, 'disk', self.fake.disk))
        self.contexts.enter_context(patch.object(apfs, 'command', self.fake.command))
        self.source_sha = hashlib.sha256(MODULE.read_bytes()).hexdigest()
        self.args = apfs.parser().parse_args(['prepare', '--allow-private-copy', '--run-id', RUN,
            '--setup-sha256', self.source_sha, '--allow-new-apfs-volume',
            '--expect-container-uuid', apfs.CONTAINER, '--expect-store-uuid', apfs.STORE,
            '--expect-data-uuid', apfs.DATA])

    def prepare(self):
        apfs.prepare(self.args)
        self.contexts.enter_context(patch.object(apfs, '__file__', str(self.root / '.build/ref/artifacts' / MODULE.name)))

    def events(self):
        return [json.loads(line) for line in (self.root / '.build/ref/artifacts/receipt.jsonl').read_text().splitlines()]

    def test_prepare_is_private_and_disk_free(self):
        self.prepare()
        self.assertFalse(self.fake.calls)
        self.assertEqual(stat.S_IMODE((self.root / '.build/ref/artifacts' / MODULE.name).stat().st_mode), 0o600)
        receipt = self.root / '.build/ref/artifacts/receipt.jsonl'
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
        self.assertFalse(self.parent.exists())

    def test_complete_only_exact_allowlisted_mutations(self):
        self.prepare()
        self.assertEqual(apfs.create(self.args), NEW)
        self.assertEqual([c[3] for c in self.fake.calls], ['apfs', 'mount', 'enableOwnership'])
        self.assertEqual(self.events()[-1]['phase'], 'complete')
        self.assertEqual(self.events()[-1]['volume_uuid'], NEW)
        self.assertEqual(stat.S_IMODE(self.mount.stat().st_mode), 0o700)
        self.assertEqual(self.fake.data['GlobalPermissionsEnabled'], False)
        with self.assertRaises(apfs.Refusal):
            apfs.create(self.args)
        self.assertEqual(len(self.fake.calls), 3)

    def test_explicit_authorization_and_three_pins(self):
        self.prepare()
        for key in ('allow_new_apfs_volume', 'expect_container_uuid', 'expect_store_uuid', 'expect_data_uuid'):
            args = copy.copy(self.args)
            setattr(args, key, False if key.startswith('allow') else apfs.DATA)
            if key == 'expect_data_uuid':
                args.expect_data_uuid = apfs.STORE
            with self.subTest(key=key), self.assertRaises(apfs.Refusal):
                apfs.create(args)
        self.assertFalse(self.fake.calls)

    def test_source_sha_and_private_execution_required(self):
        apfs.prepare(self.args)
        with self.assertRaises(apfs.Refusal):
            apfs.create(self.args)
        with patch.object(apfs, '__file__', str(self.root / '.build/ref/artifacts' / MODULE.name)):
            self.args.setup_sha256 = '0' * 64
            with self.assertRaises(apfs.Refusal):
                apfs.create(self.args)
        self.assertFalse(self.fake.calls)

    def test_existing_mount_parent_is_never_adopted(self):
        self.prepare()
        self.parent.mkdir()
        sentinel = self.parent / 'untouched'
        sentinel.write_text('keep')
        with self.assertRaises(FileExistsError):
            apfs.create(self.args)
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertFalse(self.fake.calls)

    def test_sudo_failure_never_retries_or_cleans(self):
        self.prepare()
        self.fake.fail = 'sudo'
        with self.assertRaises(subprocess.CalledProcessError):
            apfs.create(self.args)
        self.assertEqual(len(self.fake.calls), 1)
        self.assertTrue(self.mount.exists())
        self.assertEqual(self.events()[-1]['phase'], 'failed-no-cleanup')
        self.assertIn('post-add-inventory', [e['phase'] for e in self.events()])

    def test_add_failure_still_records_new_uuid_and_stops(self):
        self.prepare()
        self.fake.fail = 'apfs'
        with self.assertRaises(subprocess.CalledProcessError):
            apfs.create(self.args)
        self.assertEqual(len(self.fake.calls), 1)
        owned = [e for e in self.events() if e['phase'] == 'volume-owned']
        self.assertEqual(owned[0]['volume_uuid'], NEW)
        self.assertTrue(self.mount.exists())

    def test_ownership_failure_preserves_receipt_no_further_mutation(self):
        self.prepare()
        self.fake.fail = 'enableOwnership'
        with self.assertRaises(subprocess.CalledProcessError):
            apfs.create(self.args)
        self.assertEqual([c[3] for c in self.fake.calls], ['apfs', 'mount', 'enableOwnership'])
        self.assertIn('volume-owned', [e['phase'] for e in self.events()])

    def test_mounted_shadow_stops_before_any_mount_command(self):
        self.prepare()
        with patch.object(apfs.os.path, 'ismount', return_value=True), self.assertRaises(apfs.Refusal):
            apfs.create(self.args)
        self.assertFalse(self.fake.calls)

    def test_replaced_mount_inode_stops_before_mount(self):
        self.prepare()
        def hook(verb):
            if verb == 'apfs':
                self.mount.rename(self.parent / 'old-mount')
                self.mount.mkdir(mode=0o700)
        self.fake.hook = hook
        with self.assertRaises(apfs.Refusal):
            apfs.create(self.args)
        self.assertEqual([c[3] for c in self.fake.calls], ['apfs'])

    def test_timeout_is_explicitly_unknown_and_preserves_add_intent(self):
        self.prepare()
        def timeout(verb):
            raise subprocess.TimeoutExpired(['fake-add'], 120, output=b'partial', stderr=b'late operation')
        self.fake.hook = timeout
        with self.assertRaises(subprocess.TimeoutExpired):
            apfs.create(self.args)
        self.assertEqual(len(self.fake.calls), 1)
        unknown = [e for e in self.events() if e['phase'] == 'mutation-outcome-unknown']
        self.assertEqual(unknown[0]['stderr'], 'late operation')
        self.assertIn('add-intent', [e['phase'] for e in self.events()])

    def test_failed_sudo_diagnostics_survive_attribution_failure(self):
        self.prepare()
        self.fake.fail = 'sudo'
        with self.assertRaises(subprocess.CalledProcessError):
            apfs.create(self.args)
        failed = [e for e in self.events() if e['phase'] == 'mutation-outcome-unknown']
        self.assertEqual(failed[0]['stderr'], 'fake sudo/diskutil failure')
        self.assertIn('post-add-attribution-failed', [e['phase'] for e in self.events()])

    def test_post_add_inspection_failure_retains_command_result(self):
        self.prepare()
        original = apfs.inspect
        def inspect():
            if self.fake.created:
                raise apfs.Refusal('device disappeared')
            return original()
        with patch.object(apfs, 'inspect', inspect), self.assertRaises(apfs.Refusal):
            apfs.create(self.args)
        self.assertEqual(len(self.fake.calls), 1)
        self.assertIn('command-complete', [e['phase'] for e in self.events()])
        self.assertIn('post-add-attribution-failed', [e['phase'] for e in self.events()])

    def test_success_stderr_is_durable(self):
        self.prepare()
        apfs.create(self.args)
        completed = [e for e in self.events() if e['phase'] == 'command-complete']
        self.assertTrue(completed)
        self.assertTrue(all(e['stderr'] == 'fake warning' for e in completed))

    def test_interrupt_during_completion_record_is_unknown(self):
        self.prepare()
        original = apfs.Journal.append
        def append(journal, phase, **fields):
            if phase == 'command-complete':
                raise KeyboardInterrupt('fake completion interruption')
            original(journal, phase, **fields)
        with patch.object(apfs.Journal, 'append', append), self.assertRaises(KeyboardInterrupt):
            apfs.create(self.args)
        self.assertIn('mutation-outcome-unknown', [e['phase'] for e in self.events()])
        self.assertEqual(len(self.fake.calls), 1)

    def test_every_prepared_security_field_is_checked(self):
        self.prepare()
        path = self.root / '.build/ref/artifacts/receipt.jsonl'
        state = self.events()[0]
        for key in ('mountpoint', 'container_uuid', 'store_uuid', 'data_uuid', 'quota_bytes', 'reserve_bytes'):
            modified = dict(state, **{key: 'corrupted'})
            path.write_text(json.dumps(modified) + '\n')
            with self.subTest(key=key), self.assertRaises(apfs.Refusal):
                apfs.create(self.args)
        self.assertFalse(self.fake.calls)

    def fake_root_ownership(self):
        # Simulate Apple's root-owned mounted root without any real chown/mount.
        self.fake.needs_chown = True
        original_stat, original_lstat, original_fstat = os.stat, os.lstat, os.fstat
        original_path_stat, original_path_lstat = Path.stat, Path.lstat
        def convert(info):
            if self.fake.mounted and self.fake.needs_chown:
                mount_info = original_lstat(self.mount)
                if (info.st_dev, info.st_ino) == (mount_info.st_dev, mount_info.st_ino):
                    fields = list(info)
                    fields[0], fields[4], fields[5] = stat.S_IFDIR | 0o755, 0, 0
                    return os.stat_result(fields)
            return info
        self.contexts.enter_context(patch.object(os, 'stat', lambda *a, **kw: convert(original_stat(*a, **kw))))
        self.contexts.enter_context(patch.object(os, 'lstat', lambda *a, **kw: convert(original_lstat(*a, **kw))))
        self.contexts.enter_context(patch.object(os, 'fstat', lambda *a, **kw: convert(original_fstat(*a, **kw))))
        # Python 3.9 pathlib caches stat/lstat accessors, unlike newer Python.
        self.contexts.enter_context(patch.object(Path, 'stat', lambda *a, **kw: convert(original_path_stat(*a, **kw))))
        self.contexts.enter_context(patch.object(Path, 'lstat', lambda *a, **kw: convert(original_path_lstat(*a, **kw))))

    def test_only_exact_new_root_can_be_chowned(self):
        self.prepare()
        self.fake_root_ownership()
        apfs.create(self.args)
        self.assertEqual(self.fake.calls[-1], ['/usr/bin/sudo', '-n', '/usr/sbin/chown',
                                             f'{apfs.UID}:{apfs.GID}', str(self.mount)])
        self.assertEqual(self.events()[-1]['phase'], 'complete')

    def test_chown_failure_is_terminal_and_unknown(self):
        self.prepare()
        self.fake_root_ownership()
        self.fake.fail = 'chown'
        with self.assertRaises(subprocess.CalledProcessError):
            apfs.create(self.args)
        self.assertEqual(self.fake.calls[-1][2], '/usr/sbin/chown')
        self.assertEqual(self.events()[-1]['phase'], 'failed-no-cleanup')
        self.assertIn('mutation-outcome-unknown', [e['phase'] for e in self.events()])

    def test_external_identity_and_capacity_guards(self):
        for target, key, value in ((self.fake.store, 'DiskUUID', apfs.DATA),
                (self.fake.store, 'Internal', True), (self.fake.store, 'BusProtocol', 'PCI'),
                (self.fake.data, 'VolumeUUID', NEW), (self.fake.data, 'MountPoint', '/other'),
                (self.fake.raw['Containers'][0], 'CapacityFree', apfs.QUOTA + apfs.HEADROOM - 1),
                (self.fake.raw['Containers'][0], 'CapacityCeiling', apfs.CEILING + 1)):
            with self.subTest(key=key), patch.dict(target, {key: value}), self.assertRaises(apfs.Refusal):
                apfs.inspect()

    def test_inventory_requires_exactly_one_ours(self):
        before = apfs.inspect()
        self.fake.command(['/usr/bin/sudo', '-n', apfs.DISKUTIL, 'apfs', 'addVolume', apfs.CONTAINER,
                           'APFS', 'cengine-ref-' + RUN, '-quota', str(apfs.QUOTA), '-nomount'])
        after = apfs.inspect()
        self.assertEqual(apfs.new_volume(before, after, 'cengine-ref-' + RUN), NEW)
        for key, value in (('Name', 'someone-else'), ('CapacityQuota', 0),
                           ('CapacityReserve', 1), ('Roles', ['Data'])):
            changed = copy.deepcopy(after)
            changed['inventory'][apfs.CONTAINER]['volumes'][NEW][key] = value
            with self.subTest(key=key), self.assertRaises(apfs.Refusal):
                apfs.new_volume(before, changed, 'cengine-ref-' + RUN)
        for alteration in ('old-volume', 'extra-volume', 'data-owner', 'data-inode'):
            changed = copy.deepcopy(after)
            if alteration == 'old-volume':
                changed['inventory'][apfs.CONTAINER]['volumes'][apfs.DATA]['Name'] = 'changed'
            elif alteration == 'extra-volume':
                changed['inventory'][apfs.CONTAINER]['volumes']['other'] = {}
            elif alteration == 'data-owner':
                changed['data']['GlobalPermissionsEnabled'] = True
            else:
                changed['data_inode'][1] += 1
            with self.subTest(alteration=alteration), self.assertRaises(apfs.Refusal):
                apfs.new_volume(before, changed, 'cengine-ref-' + RUN)

    def test_shared_symlink_hardlink_paths_refused(self):
        shared = self.home / 'shared'
        shared.mkdir(mode=0o775)
        shared.chmod(0o775)
        with self.assertRaises(apfs.Refusal):
            apfs.trusted(shared)
        link = self.home / 'link'
        link.symlink_to(shared)
        with self.assertRaises(apfs.Refusal):
            apfs.trusted(link)
        file = self.home / 'file'
        file.write_bytes(b'x')
        os.link(file, self.home / 'hardlink')
        with self.assertRaises(apfs.Refusal):
            apfs.trusted(file, regular=True)


class BootstrapTests(unittest.TestCase):
    def bootstrap(self):
        text = MODULE.with_suffix('.md').read_text()
        return compile(text.split("<<'PY'\n", 1)[1].split('\nPY', 1)[0], '<bootstrap>', 'exec')

    def test_wrong_digest_executes_no_checkout_code(self):
        code = self.bootstrap()
        execute = builtins.exec
        with patch.object(sys, 'argv', ['-', '0' * 64, RUN]), patch.object(builtins, 'exec') as launch:
            with self.assertRaises(SystemExit):
                execute(code, {})
            launch.assert_not_called()

    def test_exact_hashed_bytes_are_compiled_not_reread(self):
        code = self.bootstrap()
        data = MODULE.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        execute, compile_source = builtins.exec, builtins.compile
        with patch.object(sys, 'argv', ['-', digest, RUN]), patch.object(builtins, 'exec') as launch, \
                patch.object(builtins, 'compile', wraps=compile_source) as compiler:
            execute(code, {})
            self.assertEqual(compiler.call_count, 1)
            self.assertEqual(compiler.call_args.args[0], data)
            launch.assert_called_once()


class ACLTests(unittest.TestCase):
    def test_deny_only_acl_and_allow_refusal(self):
        for extra, accepted in ((b'', True), (b' 0: group:everyone deny delete\n', True),
                (b' 0: user:other allow write,append\n', False), (b' unknown ACL\n', False)):
            with self.subTest(extra=extra), patch.object(apfs, 'command', return_value=b'drwx------ path\n' + extra):
                if accepted:
                    apfs.acl_safe(Path('/test'))
                else:
                    with self.assertRaises(apfs.Refusal):
                        apfs.acl_safe(Path('/test'))


if __name__ == '__main__':
    unittest.main()
