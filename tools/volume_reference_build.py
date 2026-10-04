#!/usr/bin/env python3
r"""Opt-in Docker 29.2.1 image builder; NEVER touches an existing Lima/Colima VM.

prepare makes a NEW private /Users/twt run root and pinned private tool copies.
It does not download or operate a VM. Review this file, then explicitly pin it:
  python3 -B tools/volume_reference_build.py prepare --allow-private-copies \
    --root /Users/twt/vr2 --builder-sha256 <SHA256-of-this-file>
Run the PRIVATE copy, using the UUID printed by prepare:
  python3 -B /Users/twt/vr2/volume_reference_build.py build \
    --root /Users/twt/vr2 --run-id <UUID> --allow-disposable-vm

build downloads only the pinned Ubuntu image; the guest downloads exactly three
pinned debs. No apt install, templates, host mounts, Docker start, disk adoption,
force-stop, teardown, retry, or cleanup is implemented. Failed runs are terminal.
Logs, fsynced external journal, receipt, and the stopped builder remain. A sealed
flat raw APFS clone and digest are emitted, NOT a running Docker reference.

Trust: invoking UID/root, Apple system tools/libraries, reviewed source hashes.
Source trees on shared ancestors are read as DATA only, SHA verified, and copied
without ACLs/xattrs/symlinks. Execution uses only private pinned copies and system
binaries. As in volume_reference.py, malicious same-UID/root actors, hostile
mounts and ACLs granting extra write access are outside the trust boundary.
"""
from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import selectors
import stat
import subprocess
import sys
import time
import types
import uuid

GIB = 1024**3
HOME = Path('/Users/twt')
SCHEMA = 'cengine-pinned-docker-builder-v1'
LIMA_PREFIX = Path('/opt/homebrew/Cellar/lima/2.2.0')
DOCKER_SOURCE = Path('/opt/homebrew/Cellar/docker/29.8.0/bin/docker')
LIMA_TREE_SHA = '8075d3e3337d70c309c0e332c73ae8a760185cd8f68bfeb8f3cea4a07843a348'
DOCKER_SHA = 'b1ca8cf8e294fd128ef4a5f5fb2531a059dd981548dfa810fe19d5d6c695e486'
REFERENCE_SHA = 'cc191c4159d66fe608f5c7414243d2d5c1ea201418e941cff81c6da985d9ab22'
FIXTURE_SHA = 'e16685c2ef06ed01d2eab8cb834a8f1a122077bbd909c8fd61a9784f49d71365'
UBUNTU_URL = ('https://cloud-images.ubuntu.com/releases/noble/release-20260705/'
              'ubuntu-24.04-server-cloudimg-arm64.img')
UBUNTU_SHA = '7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc'
UBUNTU_BYTES = 615630848
DEB_PREFIX = 'https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/arm64/'
DEBS = (
    ('containerd.io_2.2.1-1~ubuntu.24.04~noble_arm64.deb',
     'd0f9b60d9286f784c4b8681ab7bc81c2ca7140a05d308792f4f962997396f6cb'),
    ('docker-ce-cli_29.2.1-1~ubuntu.24.04~noble_arm64.deb',
     'f8e009c2dac0f422ac87356717eb4168171415bb68f357eee21e02dd8bc78f54'),
    ('docker-ce_29.2.1-1~ubuntu.24.04~noble_arm64.deb',
     'bad17cec4430fd8ad2e17385877abb3e583e897cc91eaf0eb242ae55835a0f6a'),
)
DIRECTORIES = ('lima', 'host-home', 'cache', 'tmp', 'docker-config', 'artifacts',
               'fixtures', 'lima-tools')
MAX_OUTPUT = 1024 * 1024
MAX_FILES = 5000
MAX_COMMANDS = 32
# Lima 2.2 writes this reviewed default on first start even with networks: [].
# It is not authorization to attach any named network; builder.yaml stays pinned.
NETWORKS_SHA = '2fed4d81dc833fe20760dcb9ba80d265b8802a43d5ab28600edf51ce0dc9cdf3'


def source_bytes(path, limit=128 * 1024**2):
    """Untrusted source bytes only; never execute by the original pathname."""
    path = Path(path).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise RuntimeError(f'bounded single-link source file required: {path}')
        data = stream.read(limit + 1)
        after = os.fstat(fd)
        if (len(data) > limit or (before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino,
                after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise RuntimeError(f'source changed/oversized: {path}')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_reference():
    path = Path(__file__).resolve().with_name('volume_reference.py')
    data = source_bytes(path, MAX_OUTPUT)
    if sha(data) != REFERENCE_SHA:
        raise RuntimeError('adjacent reference source SHA mismatch; review changed source first')
    module = types.ModuleType('pinned_volume_reference')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


ref = load_reference()
require = ref.require
Refusal = ref.Refusal


def host_check():
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64'
            and int(platform.mac_ver()[0].split('.')[0]) >= 26,
            'requires macOS 26+ Apple silicon')
    require(os.getuid() != 0 and HOME.stat().st_uid == os.getuid(),
            'run as the owner of /Users/twt, never sudo')


def free_space(path, minimum):
    fs = os.statvfs(path)
    require(fs.f_bavail * fs.f_frsize >= minimum, 'insufficient free disk space')


def tree_files(path):
    """Bounded, no-symlink source inventory. Hashes approve all Lima resources."""
    result = []
    pending = [path]
    seen = total = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                seen += 1
                require(seen <= MAX_FILES, 'source tree file limit exceeded')
                info = entry.stat(follow_symlinks=False)
                require(not entry.is_symlink(), 'symlink in source tree refused')
                child = Path(entry.path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            'nonregular/hardlinked source refused')
                    total += info.st_size
                    require(total <= GIB, 'source tree size limit exceeded')
                    result.append(child)
    return sorted(result)


def tree_pin(path):
    return sha(json.dumps([[str(p.relative_to(path)), bool(p.stat().st_mode & 0o111),
                            sha(source_bytes(p))] for p in tree_files(path)],
                          separators=(',', ':')).encode())


def bounded_identity(path, *, hashed=False):
    result = ref.identity(path)
    if not hashed:
        return result
    deadline = time.monotonic() + 300
    with ref.trusted_parent(path) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 8 * GIB,
                'hash input must be a bounded regular file')
        require((before.st_dev, before.st_ino) == (result['dev'], result['ino']),
                'hash input replaced')
        digest = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            require(time.monotonic() < deadline, 'hash deadline exceeded')
            digest.update(block)
        require(ref.file_stamp(os.fstat(fd)) == ref.file_stamp(before), 'hash input changed')
    require(ref.identity(path) == result, 'hash pathname changed')
    result['sha256'] = digest.hexdigest()
    return result


def filesystem_device(output):
    """diskutil accepts a device or mountpoint, not an arbitrary run directory."""
    rows = output.decode('utf-8', errors='strict').splitlines()
    require(len(rows) == 2, 'unexpected df filesystem result')
    fields = rows[1].split()
    require(len(fields) >= 6 and re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*', fields[0]),
            'expected exactly one local disk device')
    return fields[0]


def clone_apfs(source, target):
    """clonefile(2), NOT cp -c (which may fall back to a full copy)."""
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    clone = library.clonefile
    clone.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
    clone.restype = ctypes.c_int
    if clone(os.fsencode(source), os.fsencode(target), 1) != 0:  # CLONE_NOFOLLOW
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


BOOT = '''set -eu
# Lima boot mode runs /bin/sh, not the shebang interpreter.
systemctl list-unit-files --type=timer --no-legend --no-pager | while read -r unit rest; do
    [ -z "$unit" ] || systemctl mask --now --no-block "$unit"
done
systemctl mask --now --no-block apt-daily.service apt-daily-upgrade.service \\
 unattended-upgrades.service cron.service snapd.service snapd.socket \\
 snapd.seeded.service packagekit.service fwupd.service
printf 'APT::Periodic::Enable "0";\\n' >/etc/apt/apt.conf.d/99-volume-reference-no-updates
systemctl mask docker.service docker.socket containerd.service
'''


def install_script(token):
    downloads = '\n'.join(
        f"curl -q --fail --location --proto '=https' --proto-redir '=https' "
        f"--connect-timeout 15 --max-time 120 --max-filesize 25000000 "
        f"--output '{name}' '{DEB_PREFIX}{name}'" for name, _ in DEBS)
    sums = '\n'.join(f'{digest}  {name}' for name, digest in DEBS)
    return '''#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
test "$(uname -m)" = aarch64
test ! -e /etc/vr-builder-id
printf '%s\\n' TOKEN >/etc/vr-builder-id
for c in systemctl cloud-init sudo sshd rsync curl iptables nft tar timeout; do command -v "$c"; done
for p in docker-ce docker-ce-cli containerd.io; do
    if dpkg-query -W "$p" 2>/dev/null; then echo "preexisting $p refused" >&2; exit 1; fi
done
mkdir -m 700 /var/tmp/vr-debs
cd /var/tmp/vr-debs
DOWNLOADS
sha256sum -c <<'SUMS'
SUM_LINES
SUMS
test ! -e /usr/sbin/policy-rc.d
printf '#!/bin/sh\\nexit 101\\n' >/usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
timeout 120 dpkg -i ./*.deb
rm /usr/sbin/policy-rc.d
# Keep masked until sealing. Docker MUST NEVER run in this builder.
test "$(dpkg-query -W -f='${Version}' docker-ce)" = '5:29.2.1-1~ubuntu.24.04~noble'
test "$(dpkg-query -W -f='${Version}' docker-ce-cli)" = '5:29.2.1-1~ubuntu.24.04~noble'
test "$(dpkg-query -W -f='${Version}' containerd.io)" = '2.2.1-1~ubuntu.24.04~noble'
apt-mark hold docker-ce docker-ce-cli containerd.io
dockerd --version
docker --version
containerd --version
CHECK_EMPTY
dpkg-query -W -f='${binary:Package}\\t${Version}\\n' >/etc/vr-packages.tsv
touch /etc/vr-builder-complete
'''.replace('TOKEN', token).replace('DOWNLOADS', downloads).replace('SUM_LINES', sums).replace('CHECK_EMPTY', CHECK_EMPTY)


CHECK_EMPTY = '''for unit in docker.service docker.socket containerd.service; do
    if systemctl is-active --quiet "$unit"; then echo "$unit unexpectedly active" >&2; exit 1; fi
    test "$(systemctl show "$unit" -p ActiveEnterTimestampMonotonic --value)" = 0
    case "$unit" in *.service)
        test "$(systemctl show "$unit" -p ExecMainStartTimestampMonotonic --value)" = 0 ;;
    esac
done
for d in /var/lib/docker /var/lib/containerd; do
    [ ! -e "$d" ] || [ -z "$(find "$d" -mindepth 1 -print -quit)" ]
done'''


def seal_script(token):
    return '''set -euo pipefail
test "$(cat /etc/vr-builder-id)" = TOKEN
test -f /etc/vr-builder-complete
CHECK_EMPTY
# Disable before unmasking; unmask does not start units.
systemctl unmask docker.service docker.socket containerd.service
systemctl disable docker.service docker.socket containerd.service
CHECK_EMPTY
# Remove all login keys, not just the current Lima user; no host paths exist here.
find /home /root -xdev \\( -type f -o -type l \\) \\( -name authorized_keys -o -name authorized_keys2 \\) -delete
rm -f /etc/ssh/ssh_host_*
cloud-init clean --logs --machine-id --seed
rm -f /var/lib/dbus/machine-id
sync
# Schedule from this authenticated connection, before removing its credentials
# could require reconnection. Never issue a host force-stop fallback.
shutdown -h +1
printf '%s\\n' SEALED-TOKEN
'''.replace('CHECK_EMPTY', CHECK_EMPTY).replace('TOKEN', token)


def make_config(root, token):
    return {
        'minimumLimaVersion': '2.2.0', 'vmType': 'vz', 'arch': 'aarch64', 'os': 'Linux',
        'images': [{'location': str(root / 'ubuntu.img'), 'arch': 'aarch64', 'digest': 'sha256:' + UBUNTU_SHA}],
        'cpus': 2, 'memory': '2GiB', 'disk': '8GiB', 'additionalDisks': [],
        'mounts': [], 'networks': [], 'mountType': 'virtiofs', 'mountInotify': False,
        'ssh': {'loadDotSSHPubKeys': False, 'forwardAgent': False, 'forwardX11': False, 'forwardX11Trusted': False},
        'containerd': {'system': False, 'user': False}, 'upgradePackages': False,
        'hostResolver': {'enabled': False},
        'vmOpts': {'vz': {'diskImageFormat': 'raw', 'rosetta': {'enabled': False, 'binfmt': False}}},
        'portForwards': [{'guestPortRange': [1, 65535], 'proto': 'any', 'ignore': True}],
        'provision': [{'mode': 'boot', 'script': BOOT},
                      {'mode': 'dependency', 'skipDefaultDependencyResolution': True,
                       'script': '#!/bin/sh\nset -eu\ncommand -v rsync\n'},
                      {'mode': 'system', 'script': install_script(token)}],
        'probes': [{'mode': 'readiness', 'description': 'pinned packages, no Docker daemon',
                    'script': '#!/bin/sh\nset -eu\ntest -f /etc/vr-builder-complete\n'}],
    }


class Builder:
    def __init__(self, root, runner=None):
        self.root = ref.canonical(root)
        self.runner = runner or self.run_bounded
        self.deadline = time.monotonic() + 2100
        self.state = {}
        self.journal = self.lock = None
        self.receipt = None

    def __enter__(self):
        # Verify ownership BEFORE opening appendable state or locks.
        for relative in ('.', 'artifacts', 'lock', 'state.json', 'artifacts/events.jsonl'):
            info = ref.identity(self.root / relative)
            require(info['uid'] == os.getuid() and info['permissions'] & 0o077 == 0,
                    'private owned run files/directories required')
        self.lock = os.open(self.root / 'lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.receipt = bounded_identity(self.root / 'state.json', hashed=True)
            self.state = json.loads(source_bytes(self.root / 'state.json', MAX_OUTPUT))
            self.guard()
            self.journal = os.open(self.root / 'artifacts/events.jsonl', os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            return self
        except BaseException:
            os.close(self.lock)
            raise

    def __exit__(self, kind, error, traceback):
        try:
            if error is not None and self.state.get('phase') not in ('prepared', 'complete', 'failed'):
                # Write through the retained descriptor even if a path was replaced.
                self.event('failed', error=str(error)[:4096])
                try:
                    self.guard()
                    self.state['phase'] = 'failed'
                    self.persist()
                except BaseException as persist_error:
                    self.event('failed-receipt-unwritable', error=str(persist_error)[:4096])
        finally:
            if self.journal is not None:
                os.close(self.journal)
            if self.lock is not None:
                os.close(self.lock)

    @property
    def vm(self):
        return self.root / 'lima' / self.state['name']

    def event(self, step, **values):
        assert self.journal is not None
        data = (json.dumps({'time': time.time(), 'step': step, **values}, sort_keys=True) + '\n').encode()
        require(len(data) <= MAX_OUTPUT, 'journal event too large')
        view = memoryview(data)
        while view:
            count = os.write(self.journal, view)
            require(count > 0, 'journal short write')
            view = view[count:]
        os.fsync(self.journal)

    def guard(self):
        require(time.monotonic() < self.deadline, 'overall run deadline exceeded')
        if self.receipt:
            require(bounded_identity(self.root / 'state.json', hashed=True) == self.receipt, 'receipt replaced')
        s = self.state
        require(s['schema'] == SCHEMA and s['root'] == str(self.root), 'foreign receipt')
        require(s['name'] == 'vb-' + uuid.UUID(s['run_id']).hex[:12], 'foreign builder name')
        for path, record in s['ancestors'].items():
            ref.check_identity(Path(path), record)
        for relative, record in s['records'].items():
            require(relative == '.' or (not Path(relative).is_absolute() and '..' not in Path(relative).parts), 'foreign record path')
            require(bounded_identity(self.root / relative, hashed='sha256' in record) == record,
                    f'private identity/content changed: {relative}')
        for path, record in s['system'].items():
            ref.check_identity(Path(path), record)
        home = self.root / 'lima'
        require(set(p.name for p in home.iterdir()) <= {'_config', s['name']}, 'foreign Lima home entries')
        config = home / '_config'
        if config.exists() or config.is_symlink():
            require(ref.identity(config)['mode'] == stat.S_IFDIR, 'invalid Lima globals')
            require(set(p.name for p in config.iterdir()) <= {'user', 'user.pub', 'networks.yaml'}, 'foreign Lima global config')
            networks = config / 'networks.yaml'
            if os.path.lexists(networks):
                require(bounded_identity(networks, hashed=True)['sha256'] == NETWORKS_SHA,
                        'unexpected Lima default networks content')
        # Reject unrecorded immutable tools/config additions before every execution.
        for dirname in ('lima-tools', 'fixtures'):
            for path in tree_files(self.root / dirname):
                require(str(path.relative_to(self.root)) in s['records'], 'unrecorded private tool/fixture')
        self.quota()

    def quota(self):
        free_space(self.root, 10 * GIB)
        total = count = 0
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            count += len(dirs) + len(files)
            require(count <= MAX_FILES, 'run file limit exceeded')
            for name in files:
                info = (Path(directory) / name).lstat()
                if stat.S_ISREG(info.st_mode):
                    require(info.st_size <= 8 * GIB, 'oversized run file')
                    total += info.st_size
                    require(total <= 20 * GIB, 'run disk budget exceeded')

    def persist(self):
        ref.check_identity(self.root / 'state.json', self.receipt)
        ref.save(self.root, self.state)
        self.receipt = bounded_identity(self.root / 'state.json', hashed=True)

    def phase(self, value):
        self.guard()
        self.event(value)
        self.state['phase'] = value
        self.persist()

    def record(self, path, hashed=False):
        self.state['records'][str(path.relative_to(self.root))] = bounded_identity(path, hashed=hashed)

    def new_file(self, relative, data, executable=False):
        self.guard()
        path = self.root / relative
        ref.write_new(path, data)
        if executable:
            os.chmod(path, 0o700)
        self.record(path, hashed=True)
        ref.sync_directory(path.parent)
        self.persist()

    def environment(self):
        return {'PATH': str(self.root / 'lima-tools/bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
                'HOME': str(self.root / 'host-home'), 'LIMA_HOME': str(self.root / 'lima'),
                'XDG_CONFIG_HOME': str(self.root / 'host-home'), 'XDG_CACHE_HOME': str(self.root / 'cache'),
                'LIMA_CACHE_HOME': str(self.root / 'cache'), 'TMPDIR': str(self.root / 'tmp'),
                'DOCKER_CONFIG': str(self.root / 'docker-config'), 'LANG': 'C', 'LC_ALL': 'C', 'TERM': 'dumb'}

    def run_bounded(self, argv, *, stdout, stderr, timeout, **kwargs):
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
        assert process.stdout is not None and process.stderr is not None
        try:
            with selectors.DefaultSelector() as selector:
                for source, target in ((process.stdout, stdout), (process.stderr, stderr)):
                    os.set_blocking(source.fileno(), False)
                    selector.register(source, selectors.EVENT_READ, [target, 0])
                while selector.get_map():
                    require(time.monotonic() < deadline, 'command timed out')
                    self.quota()
                    for key, _ in selector.select(min(1, max(0, deadline - time.monotonic()))):
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        target, count = key.data
                        target.write(block[:max(0, MAX_OUTPUT - count)])
                        key.data[1] += len(block)
                        require(key.data[1] <= MAX_OUTPUT, 'command output limit exceeded')
                return subprocess.CompletedProcess(argv, process.wait(timeout=max(.01, deadline - time.monotonic())))
        finally:
            if process.poll() is None:
                process.kill()  # Only OUR command child; never scan/kill VM processes.
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def invoke(self, argv, label, timeout):
        self.guard()
        s = self.state
        require(s['commands'] < MAX_COMMANDS and 0 < timeout <= 900, 'command bound exceeded')
        require(argv[0] in s['system'] or argv[0] == str(self.root / 'lima-tools/bin/limactl'), 'unapproved executable')
        s['commands'] += 1
        self.event('command-start', label=label, argv=argv)
        self.persist()
        log = self.root / 'artifacts' / f'{s["commands"]:02d}-{label}'
        ref.private_directory(log)
        ref.sync_directory(log.parent)
        handles = []
        try:
            for stream in ('stdout', 'stderr'):
                ref.write_new(log / stream, b'')
                handles.append((log / stream).open('ab'))
            ref.sync_directory(log)
            result = self.runner(argv, stdout=handles[0], stderr=handles[1], timeout=timeout,
                                 env=self.environment(), cwd=self.root, stdin=subprocess.DEVNULL)
        finally:
            for handle in handles:
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
        self.event('command-finish', label=label, returncode=result.returncode)
        require(result.returncode == 0, f'{label} failed; preserve {log}')
        require(all((log / name).stat().st_size <= MAX_OUTPUT for name in ('stdout', 'stderr')), 'output bound exceeded')
        return (log / 'stdout').read_bytes()

    def lima(self, arguments, label, timeout=30):
        return self.invoke([str(self.root / 'lima-tools/bin/limactl'), *arguments], label, timeout)

    def capture(self, *, started=False):
        self.guard()
        for path in (self.vm, self.vm / 'lima.yaml'):
            self.record(path, hashed=path.name == 'lima.yaml')
        config = self.root / 'lima/_config'
        if config.exists():
            self.record(config)
            for path in config.iterdir():
                self.record(path, hashed=True)
        disk = self.vm / 'disk'
        if started or os.path.lexists(disk):
            require(disk.stat().st_size == 8 * GIB, 'builder disk size is not 8GiB')
            self.record(disk)
        require(not any(os.path.lexists(self.vm / p) for p in ('basedisk', 'diffdisk')), 'legacy/backing disks refused')
        self.persist()

    def status(self, expected):
        self.guard()
        require(str(self.vm.relative_to(self.root)) in self.state['records']
                and str((self.vm / 'lima.yaml').relative_to(self.root)) in self.state['records'],
                'builder ownership has not been committed')
        output = self.lima(['list', self.state['name'], '--json'], 'status').decode()
        records = [json.loads(line) for line in output.splitlines() if line.strip()]
        require(len(records) == 1, 'expected exactly one owned builder')
        row = records[0]
        require(row.get('name') == self.state['name'] and row.get('dir') == str(self.vm)
                and row.get('vmType') == 'vz' and row.get('arch') == 'aarch64', 'foreign builder status')
        require(row.get('status') in expected, f'unexpected builder status: {row.get("status")}')
        return row['status']


def prepare(args):
    require(args.allow_private_copies, 'prepare requires --allow-private-copies')
    host_check()
    root = ref.canonical(args.root, exists=False)
    require(HOME in root.parents and not root.name.startswith('.'), 'new root must be beneath /Users/twt')
    require(not os.path.lexists(root), 'existing run root refused; no adoption/resume')
    for path in [HOME / '.lima', HOME / '.colima', *[Path(os.environ[k]).expanduser().resolve()
                 for k in ('LIMA_HOME', 'COLIMA_HOME') if os.environ.get(k)]]:
        require(root != path and path not in root.parents, 'ambient Lima/Colima root refused')
    ancestors = {str(p): ref.identity(p) for p in root.parents}
    require(len(os.fsencode(root / 'lima/vb-000000000000/ssh.sock')) < 88, 'run root too long for Unix sockets')
    free_space(root.parent, 24 * GIB)
    source = Path(__file__).resolve()
    builder_data = source_bytes(source, MAX_OUTPUT)
    require(sha(builder_data) == args.builder_sha256, 'builder source SHA mismatch; explicitly approve current changes')
    prefix = Path(args.lima_prefix).resolve(strict=True)
    require(tree_pin(prefix) == LIMA_TREE_SHA, 'Lima 2.2.0 complete source tree SHA mismatch')
    reference_data = source_bytes(source.with_name('volume_reference.py'), MAX_OUTPUT)
    fixture_data = source_bytes(source.parent / 'fixtures/volume-reference.txt', MAX_OUTPUT)
    docker_data = source_bytes(args.docker)
    require(sha(reference_data) == REFERENCE_SHA and sha(fixture_data) == FIXTURE_SHA
            and sha(docker_data) == DOCKER_SHA, 'reference/fixture/Docker CLI source SHA mismatch')
    system = {path: ref.identity(Path(path), hashed=True) for path in ('/usr/bin/curl', '/bin/df', '/usr/sbin/diskutil')}
    # Revalidate captured parent identities immediately before the first mutation.
    for path, record in ancestors.items():
        ref.check_identity(Path(path), record)
    records = {'.': ref.private_directory(root)}
    for relative in DIRECTORIES:
        records[relative] = ref.private_directory(root / relative)
    for relative in ('lock', 'artifacts/events.jsonl'):
        ref.write_new(root / relative, b'')
        records[relative] = ref.identity(root / relative)
    token = str(uuid.uuid4())
    state = {'schema': SCHEMA, 'root': str(root), 'run_id': token, 'name': 'vb-' + uuid.UUID(token).hex[:12],
             'phase': 'preparing', 'records': records, 'ancestors': ancestors, 'system': system, 'commands': 0}
    ref.save(root, state)
    ref.sync_directory(root / 'artifacts')
    ref.sync_directory(root.parent)
    with Builder(root) as run:
        run.event('preparing', sources={'lima': LIMA_TREE_SHA, 'docker': DOCKER_SHA,
                  'reference': REFERENCE_SHA, 'fixture': FIXTURE_SHA, 'builder': args.builder_sha256})
        # Copy DATA, never shutil.copytree: no inherited modes, ACLs, links or xattrs.
        for path in tree_files(prefix):
            relative = Path('lima-tools') / path.relative_to(prefix)
            data = source_bytes(path)
            executable = bool(path.stat().st_mode & 0o111)
            for parent in reversed(relative.parents):
                if str(parent) == '.':
                    continue
                target = root / parent
                if not target.exists():
                    run.guard()
                    run.state['records'][str(parent)] = ref.private_directory(target)
            run.new_file(str(relative), data, executable)
        require(tree_pin(root / 'lima-tools') == LIMA_TREE_SHA, 'Lima copy SHA mismatch')
        run.new_file('lima-tools/bin/docker', docker_data, True)
        run.new_file('volume_reference.py', reference_data)
        run.new_file('fixtures/volume-reference.txt', fixture_data)
        run.new_file('volume_reference_build.py', builder_data, True)
        run.new_file('builder.yaml', (json.dumps(make_config(root, token), indent=2) + '\n').encode())
        run.guard()
        for directory, _, _ in os.walk(root, topdown=False):
            ref.sync_directory(Path(directory))
        run.phase('prepared')
    return {'root': str(root), 'run_id': token, 'phase': 'prepared',
            'next': f'python3 -B {root}/volume_reference_build.py build --root {root} --run-id {token} --allow-disposable-vm'}


def build(args, runner=None, clone=clone_apfs, sleeper=time.sleep):
    require(args.allow_disposable_vm, 'build requires --allow-disposable-vm')
    host_check()
    with Builder(args.root, runner) as run:
        require(run.state['run_id'] == args.run_id, 'run UUID mismatch')
        require(run.state['phase'] == 'prepared', 'only freshly prepared runs may build; no resume/retry')
        require(Path(__file__).resolve() == run.root / 'volume_reference_build.py', 'execute the private pinned builder copy')
        require(not os.path.lexists(run.vm) and not any((run.root / 'lima').iterdir()), 'existing Lima instance/global state refused')
        run.phase('preflight')
        require(run.lima(['--version'], 'version', 10).decode().strip() == 'limactl version 2.2.0', 'requires pinned Lima 2.2.0')
        device = filesystem_device(run.invoke(['/bin/df', '-P', str(run.root)], 'filesystem', 15))
        diskinfo = plistlib.loads(run.invoke(['/usr/sbin/diskutil', 'info', '-plist', device], 'apfs', 15))
        mountpoint = diskinfo.get('MountPoint')
        require(diskinfo.get('FilesystemType') == 'apfs' and isinstance(mountpoint, str)
                and Path(mountpoint).is_absolute()
                and os.stat(mountpoint).st_dev == os.stat(run.root).st_dev,
                'same-device APFS is required; no full-copy fallback')
        run.phase('downloading')
        image = run.root / 'ubuntu.img'
        require(not os.path.lexists(image), 'existing image refused')
        run.invoke(['/usr/bin/curl', '-q', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
                    '--connect-timeout', '15', '--max-time', '300', '--max-filesize', str(UBUNTU_BYTES),
                    '--output', str(image), UBUNTU_URL], 'ubuntu', 330)
        os.chmod(image, 0o400)
        require(image.stat().st_size == UBUNTU_BYTES, 'Ubuntu image length mismatch')
        run.record(image, hashed=True)
        require(run.state['records']['ubuntu.img']['sha256'] == UBUNTU_SHA, 'Ubuntu SHA mismatch')
        with image.open('rb') as stream:
            os.fsync(stream.fileno())
            header = stream.read(104)
        ref.sync_directory(run.root)
        require(header[:4] == b'QFI\xfb' and int.from_bytes(header[16:20], 'big') == 0,
                'expected standalone qcow2 image without backing file')
        run.persist()
        run.phase('creating')
        require(not os.path.lexists(run.vm) and not any((run.root / 'lima').iterdir()), 'unexpected state before create')
        run.lima(['create', '--tty=false', '--name', run.state['name'], str(run.root / 'builder.yaml')], 'create', 120)
        run.capture()
        run.phase('starting')
        require('lima/' + run.state['name'] + '/disk' in run.state['records']
                or not os.path.lexists(run.vm / 'disk'), 'unrecorded disk before first start')
        run.lima(['start', '--tty=false', '--timeout', '750s', run.state['name']], 'start', 900)
        run.capture(started=True)
        run.status({'Running'})
        run.new_file('packages.tsv', run.lima(['shell', '--workdir', '/', run.state['name'], 'sudo', 'cat', '/etc/vr-packages.tsv'], 'packages'))
        run.phase('sealing')
        output = run.lima(['shell', '--workdir', '/', run.state['name'], 'sudo', 'timeout', '30', 'bash', '-c',
                           seal_script(args.run_id)], 'seal', 45).decode()
        require(output.strip().endswith('SEALED-' + args.run_id), 'guest sealing acknowledgement missing')
        run.phase('shutdown-requested')
        for attempt in range(18):
            sleeper(5)
            if run.status({'Running', 'Stopped'}) == 'Stopped':
                break
        else:
            raise Refusal('builder did not cleanly stop; preserve it, NEVER force-stop or clone')
        run.phase('stopped')
        disk = run.vm / 'disk'
        run.guard()
        require(disk.stat().st_size == 8 * GIB, 'unexpected flat disk size')
        with disk.open('rb') as stream:
            header = stream.read(520)
        require(header[510:512] == b'\x55\xaa' and header[512:520] == b'EFI PART', 'expected flat raw GPT disk, not qcow/backing image')
        with disk.open('rb') as stream:
            os.fsync(stream.fileno())
        before = bounded_identity(disk, hashed=True)
        target = run.root / 'docker-29.2.1.raw'
        require(not os.path.lexists(target), 'existing clone target refused')
        run.status({'Stopped'})
        run.phase('cloning')
        clone(disk, target)
        os.chmod(target, 0o400)
        with target.open('rb') as stream:
            os.fsync(stream.fileno())
        ref.sync_directory(run.root)
        after = bounded_identity(target, hashed=True)
        require(after['dev'] == before['dev'] and after['ino'] != before['ino']
                and target.stat().st_size == 8 * GIB and after['sha256'] == before['sha256'],
                'clone must be separate same-volume inode with identical flat raw bytes')
        require(bounded_identity(disk, hashed=True) == before, 'stopped source disk changed during clone')
        run.record(target, hashed=True)
        run.persist()
        run.new_file('base.sha256', (after['sha256'] + '\n').encode())
        free_space(run.root, 18 * GIB)  # Existing reference preflight reserves 8+8+2 GiB.
        result = {'root': str(run.root), 'run_id': args.run_id, 'phase': 'complete',
                  'image': str(target), 'image_sha256': after['sha256'], 'engine_version': '29.2.1',
                  'builder': run.state['name'], 'builder_status': 'Stopped'}
        run.new_file('result.json', (json.dumps(result, indent=2) + '\n').encode())
        run.phase('complete')
        return result


def parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    prep = commands.add_parser('prepare', help='private pinned copies only; no VM or downloads')
    prep.add_argument('--allow-private-copies', action='store_true')
    prep.add_argument('--root', required=True)
    prep.add_argument('--builder-sha256', required=True)
    prep.add_argument('--lima-prefix', default=str(LIMA_PREFIX))
    prep.add_argument('--docker', default=str(DOCKER_SOURCE))
    start = commands.add_parser('build', help='opt-in download, disposable VM, seal, raw APFS clone')
    start.add_argument('--allow-disposable-vm', action='store_true')
    start.add_argument('--root', required=True)
    start.add_argument('--run-id', required=True)
    return parser


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = prepare(args) if args.command == 'prepare' else build(args)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Refusal, RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'volume-reference-build: {error}\nNo cleanup or retry. Preserve the root and artifacts/events.jsonl.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
