#!/usr/bin/env python3
"""Engine-free builder regressions: fake Lima, no VM/network/Docker operations."""
from __future__ import annotations

import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from typing import Callable

MODULE = Path(__file__).resolve().parents[1] / 'volume_reference_build.py'
spec = importlib.util.spec_from_file_location('volume_reference_build', MODULE)
assert spec and spec.loader
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class FakeCommands:
    def __init__(self):
        self.calls = []
        self.fail: str | None = None
        self.before: Callable | None = None
        self.stopped = True
        self.status_name: str | None = None
        self.filesystem = 'apfs'
        self.networks = b'pinned default networks\n'
        self.image = b'QFI\xfb' + bytes(100)

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        root = Path(kwargs['cwd'])
        state = json.loads((root / 'state.json').read_text())
        vm = root / 'lima' / state['name']
        command = argv[1]
        if self.before:
            self.before(command, root, vm)
        if command == self.fail:
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
        if command == '--version':
            output = b'limactl version 2.2.0\n'
        elif argv[0] == '/bin/df':
            output = b'Filesystem 512-blocks Used Available Capacity Mounted on\n/dev/disk3s5 100 10 90 10% /System/Volumes/Data\n'
        elif argv[0] == '/usr/sbin/diskutil':
            if argv[-1] != '/dev/disk3s5':
                raise AssertionError('diskutil does not accept arbitrary directories')
            output = plistlib.dumps({'FilesystemType': self.filesystem, 'MountPoint': str(root)})
        elif argv[0] == '/usr/bin/curl':
            (root / 'ubuntu.img').write_bytes(self.image)
            output = b''
        elif command == 'create':
            vm.mkdir(mode=0o700)
            (vm / 'lima.yaml').write_bytes((root / 'builder.yaml').read_bytes())
            config = root / 'lima/_config'
            config.mkdir(mode=0o700)
            (config / 'user').write_bytes(b'private-key')
            (config / 'user.pub').write_bytes(b'public-key')
            output = b''
        elif command == 'start':
            (root / 'lima/_config/networks.yaml').write_bytes(self.networks)
            with (vm / 'disk').open('wb') as stream:
                stream.write(bytes(510) + b'\x55\xaaEFI PART')
                stream.truncate(8 * builder.GIB)
            output = b''
        elif command == 'list':
            sealed = state['phase'] in ('shutdown-requested', 'stopped', 'cloning')
            output = json.dumps({'name': self.status_name or state['name'], 'dir': str(vm),
                                 'vmType': 'vz', 'arch': 'aarch64',
                                 'status': 'Stopped' if sealed and self.stopped else 'Running'}).encode()
        elif command == 'shell':
            if argv[-1] == '/etc/vr-packages.tsv':
                output = b'docker-ce\t5:29.2.1-1~ubuntu.24.04~noble\n'
            else:
                output = ('SEALED-' + state['run_id'] + '\n').encode()
        else:
            raise AssertionError(argv)
        kwargs['stdout'].write(output)
        return types.SimpleNamespace(returncode=0)


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vb-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root = self.home / 'run'
        self.source = self.home / 'source'
        self.source.mkdir(mode=0o700)
        self.prefix = self.home / 'lima-source'
        (self.prefix / 'bin').mkdir(parents=True, mode=0o700)
        (self.prefix / 'share/lima').mkdir(parents=True, mode=0o700)
        for path in (self.prefix / 'bin/limactl', self.prefix / 'share/lima/lima-guestagent.Linux-aarch64.gz'):
            path.write_bytes(b'pinned fake Lima resource\n')
        (self.prefix / 'bin/limactl').chmod(0o700)
        self.docker = self.home / 'docker-source'
        self.docker.write_bytes(b'pinned fake Docker CLI\n')
        self.builder_source = self.source / 'volume_reference_build.py'
        self.builder_source.write_bytes(MODULE.read_bytes())
        self.reference_source = self.source / 'volume_reference.py'
        self.reference_source.write_bytes(MODULE.with_name('volume_reference.py').read_bytes())
        (self.source / 'fixtures').mkdir(mode=0o700)
        (self.source / 'fixtures/volume-reference.txt').write_bytes((MODULE.parent / 'fixtures/volume-reference.txt').read_bytes())
        self.fake = FakeCommands()
        self.enterContext(patch.object(builder, 'HOME', self.home))
        self.enterContext(patch.object(builder, 'host_check'))
        self.enterContext(patch.object(builder, 'free_space'))
        self.enterContext(patch.object(builder, 'GIB', 1024**2))
        self.enterContext(patch.object(builder, 'LIMA_TREE_SHA', builder.tree_pin(self.prefix)))
        self.enterContext(patch.object(builder, 'DOCKER_SHA', builder.sha(self.docker.read_bytes())))
        self.enterContext(patch.object(builder, 'UBUNTU_SHA', builder.sha(self.fake.image)))
        self.enterContext(patch.object(builder, 'UBUNTU_BYTES', len(self.fake.image)))
        self.enterContext(patch.object(builder, 'NETWORKS_SHA', builder.sha(self.fake.networks)))
        self.enterContext(patch.object(builder, '__file__', str(self.builder_source)))
        self.enterContext(patch.dict(os.environ, {'LIMA_HOME': str(self.home / 'foreign'),
                          'COLIMA_HOME': str(self.home / 'colima'), 'DOCKER_HOST': 'unix:///foreign.sock',
                          'DOCKER_CONTEXT': 'foreign', 'SSH_AUTH_SOCK': '/foreign.sock', 'HTTP_PROXY': 'http://foreign.invalid'}))
        self.clones = []

    def args(self):
        return builder.parser().parse_args(['prepare', '--allow-private-copies', '--root', str(self.root),
            '--builder-sha256', builder.sha(self.builder_source.read_bytes()), '--lima-prefix', str(self.prefix),
            '--docker', str(self.docker)])

    def prepare(self):
        return builder.prepare(self.args())

    def receipt(self):
        return json.loads((self.root / 'state.json').read_text())

    def clone(self, source, target):
        self.clones.append((source, target))
        shutil.copyfile(source, target)  # TEST ONLY: production uses clonefile without fallback.

    def build(self):
        args = builder.parser().parse_args(['build', '--allow-disposable-vm', '--root', str(self.root),
                                          '--run-id', self.receipt()['run_id']])
        with patch.object(builder, '__file__', str(self.root / 'volume_reference_build.py')):
            return builder.build(args, self.fake, self.clone, lambda _: None)

    def journal(self):
        return [json.loads(line) for line in (self.root / 'artifacts/events.jsonl').read_text().splitlines()]

    def test_prepare_is_engine_and_network_free_with_pinned_private_copies(self):
        with patch.object(builder.subprocess, 'Popen', side_effect=AssertionError('no subprocess in prepare')):
            result = self.prepare()
        self.assertEqual(result['phase'], 'prepared')
        self.assertFalse((self.root / 'ubuntu.img').exists())
        self.assertEqual(list((self.root / 'lima').iterdir()), [])
        self.assertIn('/volume_reference_build.py build', result['next'])
        for relative in self.receipt()['records']:
            path = self.root / relative
            self.assertEqual(path.stat().st_mode & 0o077, 0, relative)
            if path.is_file() and relative not in ('lock', 'artifacts/events.jsonl'):
                self.assertIn('sha256', self.receipt()['records'][relative])
        self.assertEqual(self.journal()[-1]['step'], 'prepared')
        self.assertEqual((self.root / 'fixtures/volume-reference.txt').read_bytes(),
                         (self.source / 'fixtures/volume-reference.txt').read_bytes())

    def test_full_lifecycle_exact_owned_vm_no_docker_invocations(self):
        self.prepare()
        result = self.build()
        self.assertEqual(result['phase'], 'complete')
        self.assertEqual(result['engine_version'], '29.2.1')
        self.assertEqual(result['builder_status'], 'Stopped')
        self.assertEqual(self.receipt()['phase'], 'complete')
        self.assertEqual(len(self.clones), 1)
        disk, clone = self.clones[0]
        self.assertNotEqual(disk.stat().st_ino, clone.stat().st_ino)
        self.assertEqual(disk.read_bytes(), clone.read_bytes())
        self.assertEqual((self.root / 'base.sha256').read_text().strip(), builder.sha(clone.read_bytes()))
        for argv, kwargs in self.fake.calls:
            self.assertNotIn('--force', argv)
            self.assertNotIn('delete', argv)
            self.assertNotIn('clone', argv)
            self.assertEqual(kwargs['env']['LIMA_HOME'], str(self.root / 'lima'))
            for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'SSH_AUTH_SOCK', 'HTTP_PROXY', 'COLIMA_HOME'):
                self.assertNotIn(name, kwargs['env'])
            self.assertLessEqual(kwargs['timeout'], 900)
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            if argv[1] in ('start', 'list', 'shell'):
                self.assertIn(self.receipt()['name'], argv)
        calls = len(self.fake.calls)
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertEqual(len(self.fake.calls), calls)

    def test_unapproved_generated_networks_fail_before_guest_commands(self):
        self.prepare()
        self.fake.networks = b'foreign socket_vmnet configuration\n'
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertFalse(any(a[1] == 'shell' for a, _ in self.fake.calls))
        self.assertEqual(self.clones, [])

    def test_filesystem_device_is_a_local_disk_not_arbitrary_path(self):
        header = b'Filesystem 512-blocks Used Available Capacity Mounted on\n'
        self.assertEqual(builder.filesystem_device(header + b'/dev/disk3s5 100 10 90 10% /System/Volumes/Data\n'), '/dev/disk3s5')
        for row in (b'', b'/Users/twt/vr2 100 10 90 10% /\n', b'server:/share 100 10 90 10% /\n',
                    b'/dev/disk3s5 100\n', b'/dev/disk3s5 100 10 90 10% /\n/dev/disk4s1 100 10 90 10% /\n'):
            with self.subTest(row=row), self.assertRaises(builder.Refusal):
                builder.filesystem_device(header + row)

    def test_config_and_guest_contracts(self):
        config = builder.make_config(self.root, 'token')
        self.assertEqual((config['cpus'], config['memory'], config['disk']), (2, '2GiB', '8GiB'))
        for field in ('mounts', 'networks', 'additionalDisks'):
            self.assertEqual(config[field], [])
        self.assertNotIn('base', config)
        self.assertEqual(config['vmOpts']['vz']['diskImageFormat'], 'raw')
        self.assertFalse(config['ssh']['forwardAgent'])
        self.assertFalse(config['ssh']['loadDotSSHPubKeys'])
        self.assertTrue(config['provision'][1]['skipDefaultDependencyResolution'])
        text = json.dumps(config)
        for value in ('get.docker.com', 'apt-get', 'latest', 'docker info', 'systemctl start', 'guestSocket'):
            self.assertNotIn(value, text)
        self.assertEqual(builder.install_script('token').count('curl -q '), 3)
        for name, digest in builder.DEBS:
            self.assertIn(name, text)
            self.assertIn(digest, text)
        install = builder.install_script('token')
        self.assertLess(install.index('exit 101'), install.index('dpkg -i'))
        self.assertNotIn('systemctl unmask', install)
        seal = builder.seal_script('token')
        for value in ('authorized_keys2', 'ssh_host_', 'cloud-init clean --logs --machine-id --seed',
                      'shutdown -h +1', 'ExecMainStartTimestampMonotonic', 'SEALED-token'):
            self.assertIn(value, seal)
        self.assertNotIn('rm -rf', seal)

    def test_guest_scripts_parse_without_execution(self):
        for shell, script in (('/bin/sh', builder.BOOT),
                              ('/bin/bash', builder.install_script('1234')),
                              ('/bin/bash', builder.seal_script('1234'))):
            result = subprocess.run([shell, '-n'], input=script, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_pins_are_not_mutable_cli_options(self):
        self.assertEqual(builder.REFERENCE_SHA, 'cc191c4159d66fe608f5c7414243d2d5c1ea201418e941cff81c6da985d9ab22')
        self.assertEqual(len(builder.DEBS), 3)
        with self.assertRaises(SystemExit), patch('sys.stderr', new=io.StringIO()):
            builder.parser().parse_args(['build', '--root', str(self.root), '--run-id', 'x', '--image', '/existing.raw'])

    def test_refuse_opt_in_wrong_pins_and_existing_root_before_writes(self):
        for key, value in (('allow_private_copies', False), ('builder_sha256', '0' * 64)):
            args = self.args()
            setattr(args, key, value)
            with self.assertRaises(builder.Refusal):
                builder.prepare(args)
            self.assertFalse(self.root.exists())
        self.docker.write_bytes(b'changed')
        with self.assertRaises(builder.Refusal):
            self.prepare()
        self.assertFalse(self.root.exists())
        self.root.mkdir()
        with self.assertRaises(builder.Refusal):
            self.prepare()

    def test_source_symlink_and_tree_change_refused(self):
        (self.prefix / 'bin/rogue').symlink_to(self.docker)
        with self.assertRaises(builder.Refusal):
            self.prepare()
        self.assertFalse(self.root.exists())
        (self.prefix / 'bin/rogue').unlink()
        (self.prefix / 'share/lima/lima-guestagent.Linux-aarch64.gz').write_bytes(b'changed')
        with self.assertRaises(builder.Refusal):
            self.prepare()
        self.assertFalse(self.root.exists())

    def test_private_tool_and_foreign_globals_refused_before_commands(self):
        for target in ('lima-tools/bin/limactl', 'lima-tools/bin/docker', 'volume_reference.py',
                       'fixtures/volume-reference.txt', 'builder.yaml'):
            with self.subTest(target=target):
                self.prepare()
                (self.root / target).write_bytes(b'changed')
                with self.assertRaises(builder.Refusal):
                    self.build()
                self.assertEqual(self.fake.calls, [])
                shutil.rmtree(self.root)
        self.prepare()
        (self.root / 'lima/_config').mkdir()
        (self.root / 'lima/_config/default.yaml').write_text('mounts: [~]')
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertEqual(self.fake.calls, [])

    def test_failure_logs_are_durable_no_retry_or_automatic_cleanup(self):
        self.prepare()
        self.fake.fail = 'start'
        with self.assertRaises(subprocess.TimeoutExpired):
            self.build()
        self.assertEqual(self.receipt()['phase'], 'failed')
        self.assertTrue((self.root / 'lima' / self.receipt()['name']).is_dir())
        self.assertEqual(self.clones, [])
        self.assertEqual(self.journal()[-1]['step'], 'failed')
        count = len(self.fake.calls)
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertEqual(len(self.fake.calls), count)
        self.assertTrue(list((self.root / 'artifacts').glob('*-start/stderr')))

    def test_never_clone_running_or_foreign_vm(self):
        self.prepare()
        self.fake.stopped = False
        with self.assertRaisesRegex(builder.Refusal, 'cleanly stop'):
            self.build()
        self.assertEqual(self.clones, [])
        self.assertLessEqual(len(self.fake.calls), builder.MAX_COMMANDS)
        self.assertFalse(any('--force' in argv for argv, _ in self.fake.calls))

    def test_clone_failure_has_no_copy_fallback(self):
        self.prepare()
        with patch.object(self, 'clone', side_effect=OSError(errno.ENOTSUP, 'not supported')):
            with self.assertRaises(OSError):
                self.build()
        self.assertEqual(self.receipt()['phase'], 'failed')
        self.assertFalse((self.root / 'docker-29.2.1.raw').exists())
        self.assertFalse((self.root / 'base.sha256').exists())

    def test_foreign_status_never_seals_or_clones(self):
        self.prepare()
        self.fake.status_name = 'colima'
        with self.assertRaisesRegex(builder.Refusal, 'foreign builder'):
            self.build()
        self.assertFalse(any(argv[1] == 'shell' for argv, _ in self.fake.calls))
        self.assertEqual(self.clones, [])

    def test_create_refuses_injected_existing_instance(self):
        self.prepare()
        def inject(command, root, vm):
            if command == '-q':
                vm.mkdir(mode=0o700)
                (vm / 'disk').write_bytes(b'preexisting VM disk must never be adopted')
        self.fake.before = inject
        with self.assertRaisesRegex(builder.Refusal, 'unexpected state before create'):
            self.build()
        self.assertFalse(any(argv[1] == 'create' for argv, _ in self.fake.calls))
        self.assertEqual(self.clones, [])

    def test_same_inode_clone_or_bad_format_refused(self):
        self.prepare()
        with patch.object(self, 'clone', side_effect=lambda source, target: os.link(source, target)):
            with self.assertRaises(builder.Refusal):
                self.build()
        self.assertFalse((self.root / 'base.sha256').exists())
        self.assertEqual(self.receipt()['phase'], 'cloning')  # Identity violation: journal remains authoritative.
        self.assertIn('failed', [item['step'] for item in self.journal()])

    def test_apfs_is_mandatory_before_download(self):
        self.prepare()
        self.fake.filesystem = 'hfs'
        with self.assertRaisesRegex(builder.Refusal, 'APFS'):
            self.build()
        self.assertFalse((self.root / 'ubuntu.img').exists())
        self.assertEqual(list((self.root / 'lima').iterdir()), [])

    def test_failed_state_and_partial_logs_are_fsynced(self):
        self.prepare()
        self.fake.fail = 'start'
        original = os.fsync
        synced = []
        def sync(fd):
            synced.append(os.fstat(fd).st_ino)
            return original(fd)
        with patch.object(builder.os, 'fsync', side_effect=sync):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.build()
        self.assertIn((self.root / 'artifacts/events.jsonl').stat().st_ino, synced)
        self.assertIn((self.root / 'state.json').stat().st_ino, synced)
        self.assertIn((self.root / 'artifacts').stat().st_ino, synced)
        for path in (self.root / 'artifacts').glob('*-start/*'):
            self.assertIn(path.stat().st_ino, synced)

    def test_parent_replacement_is_rejected_even_when_run_inode_survives(self):
        self.prepare()
        parked = self.home.with_name(self.home.name + '-old')
        self.home.rename(parked)
        self.home.mkdir(mode=0o700)
        (parked / 'run').rename(self.root)
        self.addCleanup(lambda: shutil.rmtree(parked))
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertEqual(self.fake.calls, [])

    def test_private_source_required_and_opt_in_before_vm_side_effects(self):
        self.prepare()
        args = builder.parser().parse_args(['build', '--root', str(self.root), '--run-id', self.receipt()['run_id']])
        with self.assertRaisesRegex(builder.Refusal, 'allow-disposable-vm'):
            builder.build(args, self.fake)
        args.allow_disposable_vm = True
        with self.assertRaisesRegex(builder.Refusal, 'private pinned builder'):
            builder.build(args, self.fake)
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.receipt()['phase'], 'prepared')

    def test_wrong_image_hash_never_creates_vm(self):
        self.prepare()
        self.fake.image = bytes(len(self.fake.image))
        with self.assertRaisesRegex(builder.Refusal, 'SHA mismatch'):
            self.build()
        self.assertFalse(any(argv[1] == 'create' for argv, _ in self.fake.calls))
        self.assertEqual(self.clones, [])

    def test_owned_vm_replacement_stops_before_sealing(self):
        self.prepare()
        def replace(operation, root, vm):
            if operation == 'list':
                (vm / 'lima.yaml').write_bytes(b'replaced configuration')
        self.fake.before = replace
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertFalse(any(argv[1] == 'shell' for argv, _ in self.fake.calls))
        self.assertEqual(self.clones, [])
        self.assertIn('failed', [item['step'] for item in self.journal()])

    def test_bounded_runner_output_and_time(self):
        self.prepare()
        with builder.Builder(self.root) as run:
            for code, timeout in (("import sys;sys.stdout.buffer.write(b'x'*2000000)", 5),
                                  ('import time;time.sleep(10)', .05)):
                stdout, stderr = io.BytesIO(), io.BytesIO()
                with self.assertRaises((builder.Refusal, subprocess.TimeoutExpired)):
                    run.run_bounded([sys.executable, '-B', '-c', code], stdout=stdout, stderr=stderr,
                                    timeout=timeout, env=run.environment(), cwd=self.root, stdin=subprocess.DEVNULL)
                self.assertLessEqual(len(stdout.getvalue()), builder.MAX_OUTPUT)

    def test_free_space_and_root_ancestry_guards(self):
        with patch.object(builder, 'free_space', side_effect=builder.Refusal('space')):
            with self.assertRaises(builder.Refusal):
                self.prepare()
        self.assertFalse(self.root.exists())
        self.prepare()
        (self.root / 'host-home').rename(self.root / 'old-home')
        (self.root / 'host-home').mkdir(mode=0o700)
        with self.assertRaises(builder.Refusal):
            self.build()
        self.assertEqual(self.fake.calls, [])


if __name__ == '__main__':
    unittest.main()
