#!/usr/bin/env python3
"""Inert administrator-script tests: no sudo, launchd, or privileged writes."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

# Every external command in the administrator body is intercepted. Filesystem
# commands are allowed only inside the temporary fixture; ownership is simulated
# for validation, while actual inode/bytes/mode/owner preservation is asserted.
FAKE_COMMAND = r'''
import json, os, pathlib, shutil, stat, sys
command, *args = sys.argv[1:]
base = pathlib.Path(os.environ["FIXTURE"]).resolve()
with (base / "commands.jsonl").open("a") as log:
    log.write(json.dumps([command, *args]) + "\n")
fail = os.environ.get("FAIL_COMMAND")
needle = os.environ.get("FAIL_ARGUMENT", "")
marker = base / "failed-once"
if command == fail and any(needle in arg for arg in args) and not marker.exists():
    marker.touch()
    sys.exit(37)
if (os.environ.get("FAIL_STATE_RESTORE") == "1" and command == "mv"
        and args[0].endswith("/storage-lifecycle-v2")
        and ".rollback." in args[1]):
    sys.exit(38)
if command in ("launchctl", "codesign", "plutil", "sleep"):
    sys.exit(0)
if command == "dirname":
    print(os.path.dirname(args[0]))
    sys.exit(0)
if command == "stat":
    value = os.lstat(args[-1])
    if args[1] == "%u":
        print(501 if args[-1] == os.environ.get("UNCONTROLLED") else 0)
    elif args[1] == "%Sp":
        print(stat.filemode(value.st_mode))
    else:
        raise AssertionError(args)
    sys.exit(0)
if command == "chown":
    assert "-R" not in args, "recursive ownership change"
    sys.exit(0)
if command == "chmod":
    paths = args[1:]
else:
    paths = [arg for arg in args if not arg.startswith("-")]
for path in paths:
    candidate = pathlib.Path(path)
    assert candidate.is_absolute() and candidate.is_relative_to(base), path
    assert candidate.parent.resolve().is_relative_to(base), path
if command == "mkdir":
    for path in paths:
        pathlib.Path(path).mkdir(parents="-p" in args, exist_ok="-p" in args)
elif command == "rmdir":
    for path in paths:
        os.rmdir(path)
elif command == "rm":
    assert "-r" not in args and "-rf" not in args, "recursive deletion"
    for path in paths:
        pathlib.Path(path).unlink(missing_ok="-f" in args)
elif command == "mv":
    assert len(paths) == 2
    # Match mv directory-target behavior, so an accidental nested rename fails
    # the preservation assertions just as it would with the real utility.
    source, target = map(pathlib.Path, paths)
    if target.is_dir():
        target /= source.name
    os.rename(source, target)
    if os.environ.get("CRASH_AFTER_ROOT_RENAME") == str(source):
        os.kill(os.getppid(), 9)
elif command in ("cp", "ditto"):
    shutil.copyfile(*paths)
elif command == "chmod":
    for path in paths:
        os.chmod(path, int(args[0], 8))
else:
    raise AssertionError((command, args))
'''


def snapshot(path):
    if not path.exists() and not path.is_symlink():
        return None
    entries = [path]
    if path.is_dir() and not path.is_symlink():
        entries += sorted(path.rglob('*'))
    result = {}
    for entry in entries:
        metadata = entry.lstat()
        contents = (os.readlink(entry) if entry.is_symlink() else
                    entry.read_bytes() if entry.is_file() else None)
        result[str(entry.relative_to(path))] = (
            metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid, contents)
    return result


class HelperInstallPreservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / 'Support/cengine/compat/dev.cengine.network-helper.test-compat'
        self.root.mkdir(parents=True)
        self.state = self.root / 'storage-lifecycle-v2'
        self.state.mkdir(mode=0o700)
        (self.state / 'authority').write_bytes(b'protected\x00authority\xff')
        (self.state / 'authority').chmod(0o600)
        (self.state / 'journal').mkdir(mode=0o750)
        (self.state / 'journal/record').write_bytes(b'retained generation 19')
        (self.state / 'journal/record').chmod(0o640)
        for name in ('cengine-network-helper', 'client-token', 'manifest'):
            (self.root / name).write_text('old ' + name)
        self.plist = self.base / 'helper.plist'
        self.plist.write_text('old plist')
        self.sources = self.base / 'sources'
        self.sources.mkdir()
        for name in ('helper', 'token', 'manifest', 'plist'):
            (self.sources / name).write_text('new ' + name)
        self.dispatcher = self.base / 'fake.py'
        self.dispatcher.write_text(FAKE_COMMAND)
        source = (ROOT / 'Scripts/compat-network-helper.sh').read_text()
        function = source.split('compat_network_helper_install() {', 1)[1]
        body = function.split("if compat_network_helper_run_as_administrator '\n", 1)[1]
        body = body.split('\n\' "$compat_network_helper_root"', 1)[0]
        body = body.replace('log_dir=/Library/Logs/cengine',
                            'log_dir=' + shlex.quote(str(self.base / 'logs')))
        body = re.sub(r'/(?:usr/)?(?:s?bin)/([a-z]+)', lambda match:
                      shlex.quote(sys.executable) + ' ' + shlex.quote(str(self.dispatcher))
                      + ' ' + match[1], body)
        self.script = self.base / 'admin.sh'
        self.script.write_text(body)

    def run_install(self, fail='', argument='', uncontrolled=None, fail_state_restore=False,
                    crash_after_root_rename=False):
        environment = dict(os.environ, FIXTURE=str(self.base), FAIL_COMMAND=fail,
                           FAIL_ARGUMENT=argument, UNCONTROLLED=str(uncontrolled or ''),
                           FAIL_STATE_RESTORE='1' if fail_state_restore else '0',
                           CRASH_AFTER_ROOT_RENAME=str(self.root) if crash_after_root_rename else '')
        result = subprocess.run([
            '/bin/sh', str(self.script), str(self.root), str(self.sources / 'helper'),
            str(self.root / 'cengine-helper'), str(self.sources / 'token'),
            str(self.root / 'client-token'), str(self.sources / 'manifest'),
            str(self.root / 'manifest'), str(self.sources / 'plist'), str(self.plist),
            'dev.cengine.network-helper.test-compat', str(os.getuid()),
        ], env=environment, text=True, capture_output=True)
        log = self.base / 'commands.jsonl'
        self.commands = [json.loads(line) for line in log.read_text().splitlines()]
        return result

    def assert_no_backups(self):
        self.assertEqual(list(self.root.parent.glob('*.rollback.*')), [])
        self.assertEqual(list(self.base.glob('*.rollback.*')), [])

    def test_update_and_rename_preserve_exact_authority(self):
        before = snapshot(self.state)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(snapshot(self.state), before)
        self.assertEqual((self.root / 'cengine-helper').read_text(), 'new helper')
        self.assertFalse((self.root / 'cengine-network-helper').exists())
        self.assert_no_backups()
        for command in self.commands:
            if command[0] in ('chown', 'chmod'):
                self.assertFalse(any('storage-lifecycle-v2' in arg for arg in command))

    def test_first_install_does_not_create_authority(self):
        shutil.rmtree(self.root)
        self.plist.unlink()
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())
        self.assert_no_backups()

    def test_failures_restore_original_installation_and_authority(self):
        original = snapshot(self.root)
        plist = snapshot(self.plist)
        for command, argument in (
            ('mv', str(self.root)), ('mv', str(self.plist)),
            ('mkdir', str(self.root)), ('ditto', ''), ('cp', 'manifest'),
            ('codesign', ''), ('plutil', ''), ('mv', 'storage-lifecycle-v2'),
            ('launchctl', 'bootstrap'), ('launchctl', 'kickstart'), ('launchctl', 'print'),
        ):
            with self.subTest(command=command, argument=argument):
                (self.base / 'failed-once').unlink(missing_ok=True)
                result = self.run_install(command, argument)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual(snapshot(self.root), original, result.stderr)
                self.assertEqual(snapshot(self.plist), plist, result.stderr)
                self.assert_no_backups()

    def test_killed_installer_retry_refuses_stranded_authority(self):
        original = snapshot(self.root)
        plist = snapshot(self.plist)
        result = self.run_install(crash_after_root_rename=True)
        self.assertEqual(result.returncode, -9, result.stderr)
        backups = list(self.root.parent.glob('*.rollback.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(snapshot(backups[0]), original)
        self.assertFalse(self.root.exists())
        # Both an absent root and a partially populated replacement must refuse
        # a previous PID backup before starting a helper with fresh authority.
        for partial_root in (False, True):
            with self.subTest(partial_root=partial_root):
                if partial_root:
                    self.root.mkdir()
                    (self.root / 'cengine-helper').write_text('partial replacement')
                before = snapshot(self.root)
                (self.base / 'commands.jsonl').unlink()
                result = self.run_install()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('interrupted helper installation', result.stderr)
                self.assertEqual(snapshot(self.root), before)
                self.assertEqual(snapshot(backups[0]), original)
                self.assertEqual(snapshot(self.plist), plist)
                self.assertFalse(any(command[0] == 'launchctl' for command in self.commands))

    def test_failed_authority_restore_retains_both_roots_for_recovery(self):
        authority = snapshot(self.state)
        old_helper = snapshot(self.root / 'cengine-network-helper')
        plist = snapshot(self.plist)
        result = self.run_install('launchctl', 'kickstart', fail_state_restore=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.state), authority)
        backups = list(self.root.parent.glob('*.rollback.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(snapshot(backups[0] / 'cengine-network-helper'), old_helper)
        self.assertFalse((backups[0] / 'storage-lifecycle-v2').exists())
        plist_backups = list(self.base.glob('helper.plist.rollback.*'))
        self.assertEqual(len(plist_backups), 1)
        self.assertEqual(snapshot(plist_backups[0]), plist)

    def test_failed_first_install_leaves_no_installation(self):
        shutil.rmtree(self.root)
        self.plist.unlink()
        result = self.run_install('launchctl', 'kickstart')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.plist.exists())
        self.assert_no_backups()

    def test_legacy_update_without_authority_does_not_create_it(self):
        shutil.rmtree(self.state)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())
        self.assertFalse((self.root / 'cengine-network-helper').exists())
        self.assert_no_backups()

    def assert_refused_unchanged(self, **kwargs):
        before, plist = snapshot(self.root), snapshot(self.plist)
        result = self.run_install(**kwargs)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(snapshot(self.plist), plist)
        self.assertFalse(any(command[0] == 'launchctl' for command in self.commands))
        self.assert_no_backups()

    def test_unknown_entries_are_refused_unchanged(self):
        for name in ('unknown', '.hidden', '..hidden'):
            with self.subTest(name=name):
                entry = self.root / name
                entry.write_text('must not delete')
                self.assert_refused_unchanged()
                entry.unlink()
        (self.root / 'unknown-directory').mkdir()
        self.assert_refused_unchanged()

    def test_uncontrolled_root_and_state_are_refused_unchanged(self):
        for path in (self.root, self.state):
            with self.subTest(path=path, owner='nonroot'):
                self.assert_refused_unchanged(uncontrolled=path)
            mode = stat.S_IMODE(path.stat().st_mode)
            for unsafe in (0o770, 0o707):
                with self.subTest(path=path, mode=unsafe):
                    path.chmod(unsafe)
                    self.assert_refused_unchanged()
            path.chmod(mode)

    def test_symlink_root_state_and_installer_file_are_refused(self):
        for path in (self.root, self.state, self.root / 'client-token'):
            with self.subTest(path=path):
                saved = self.base / 'saved'
                path.rename(saved)
                before = snapshot(saved)
                path.symlink_to(saved)
                self.assert_refused_unchanged()
                self.assertEqual(snapshot(saved), before)
                path.unlink()
                saved.rename(path)


if __name__ == '__main__':
    unittest.main()
