#!/usr/bin/env python3
"""One-off, pinned external APFS setup. No VM, cleanup, adoption, or retry.

First review this source and use the HASH-BEFORE-EXEC bootstrap documented in
volume_reference_apfs.md to prepare a private copy (no disk mutation). NEVER
execute prepare directly from the shared checkout: self-hashing is too late.
Then run ONLY the printed private copy with create, --allow-new-apfs-volume,
--setup-sha256, --run-id and all three --expect-*-uuid arguments. Never sudo Python.

Trust: Apple system utilities, root and UID 501. Reject symlinks, shared writable
ancestors and ACL allow entries (deny-only ACLs are safe). The repository lives
on noowners storage: it is DATA only; the executable authority and fsynced 0600
receipt live in a NEW HOME directory's .build/ref/artifacts, outside the volume.
A private 0700 parent protects the mount while its initially root-owned root is
changed to 501:20/0700. Native owners are enabled, never synthesized/ignored.
Concurrent malicious root/same-UID actions and physical device removal cannot be
made transactional with diskutil; detected changes are terminal, never cleaned.
An interrupted add may leave a volume before its UUID can be recorded: retain the
pre-add inventory/name receipt and investigate manually, never rerun or adopt.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import sys
import uuid
from typing import Literal, overload

HOME = Path('/Users/twt')
UID, GID = 501, 20
CONTAINER = '89F892A3-6816-4A52-AF76-FC099523EE9A'
STORE = '29BC231A-395E-4FF6-B43C-28DA0B0C09EF'
DATA = '2EC9A86C-F2E8-490D-8655-BFD9E1CEEEC2'
DATA_PATH = Path('/Volumes/data')
QUOTA = 48 * 1024**3
HEADROOM = 24 * 1024**3
CEILING = 4000577273856
DISKUTIL = '/usr/sbin/diskutil'
SCHEMA = 'cengine-one-off-apfs-v1'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(HOME), 'LC_ALL': 'C'}


class Refusal(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


@overload
def command(argv, *, full: Literal[False] = False) -> bytes: ...


@overload
def command(argv, *, full: Literal[True]) -> subprocess.CompletedProcess[bytes]: ...


def command(argv, *, full=False):
    # No shell, inherited tool paths, prompts or retries. Disk Arbitration can
    # outlive a timeout: journal outcome-unknown and require manual reconciliation.
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, cwd='/', timeout=120,
                            check=True)
    return result if full else result.stdout


def disk(*args):
    return plistlib.loads(command([DISKUTIL, *args]))


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode)]


def acl_safe(path):
    output = command(['/bin/ls', '-lde', str(path)]).decode('utf-8', 'strict')
    for line in output.splitlines()[1:]:
        require(re.fullmatch(r'\s*\d+: .+ deny [a-z_,]+', line) is not None,
                f'ACL allow/unknown entry refused: {path}')


def trusted(path, *, private=False, regular=False):
    """No-follow inode-pinned walk; deny-only ACLs permitted, never ignored."""
    path = Path(path)
    require(path.is_absolute() and str(path) == str(path.resolve(strict=True)),
            f'canonical nonsymlink path required: {path}')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path('/')
    info = os.fstat(fd)
    try:
        for index, part in enumerate(('', *path.parts[1:])):
            if part:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if index != len(path.parts) - 1 or not regular:
                    flags |= os.O_DIRECTORY
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                current /= part
            info = os.fstat(fd)
            require(info.st_uid in {0, UID} and not info.st_mode & 0o022,
                    f'untrusted ownership/writable path: {current}')
            acl_safe(current)
            require(stamp(current.lstat()) == stamp(info), f'path replaced: {current}')
        require(stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode),
                f'wrong file type: {path}')
        if regular:
            require(info.st_nlink == 1, 'hardlink refused')
        if private:
            require(info.st_uid == UID and stat.S_IMODE(info.st_mode) == (0o600 if regular else 0o700),
                    f'private UID 501 permissions required: {path}')
        return stamp(info)
    finally:
        os.close(fd)


def host_check():
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64'
            and int(platform.mac_ver()[0].split('.')[0]) >= 26, 'macOS 26+ arm64 required')
    require(os.getuid() == UID and os.geteuid() == UID and HOME.stat().st_uid == UID,
            'run as UID 501, never sudo Python')
    trusted(HOME)
    rows = command(['/bin/df', '-P', str(HOME)]).decode().splitlines()
    require(len(rows) == 2, 'ambiguous HOME filesystem')
    device = rows[1].split()[0]
    require(re.fullmatch(r'/dev/disk[0-9]+(?:s[0-9]+)*', device), 'nonlocal HOME refused')
    info = disk('info', '-plist', device)
    require(info.get('FilesystemType') == 'apfs' and info.get('GlobalPermissionsEnabled') is True
            and info.get('Internal') is True, 'HOME authority requires internal native-owners APFS')


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def mkdir_new(path):
    trusted(path.parent)
    os.mkdir(path, 0o700)  # EEXIST is terminal, including dangling symlinks.
    trusted(path, private=True)
    sync_dir(path.parent)


def write_new(path, data):
    trusted(path.parent, private=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    sync_dir(path.parent)


def layout(run_id):
    require(str(uuid.UUID(run_id)) == run_id, 'canonical lowercase run UUID required')
    root = HOME / ('vr-apfs-' + run_id + '-setup')
    parent = HOME / ('vr-apfs-' + run_id)
    return root, parent, parent / 'volume'


def source_data(path):
    # Original repository is deliberately read as data, never imported/executed
    # by create. A reviewed SHA is the trust anchor for the private copy.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size < 1024**2, 'bounded single-link source required')
        data = stream.read(1024**2)
        after = os.fstat(stream.fileno())
        require((stamp(before), before.st_mtime_ns, before.st_ctime_ns, before.st_size)
                == (stamp(after), after.st_mtime_ns, after.st_ctime_ns, after.st_size),
                'source changed while reading')
        return data


def prepare(args):
    require(args.allow_private_copy, '--allow-private-copy required')
    host_check()
    root, parent, mount = layout(args.run_id)
    data = source_data(Path(__file__).resolve(strict=True))
    require(hashlib.sha256(data).hexdigest() == args.setup_sha256, 'reviewed setup SHA mismatch')
    require(not os.path.lexists(parent), 'mount parent already occupied')
    mkdir_new(root)
    for path in (root / '.build', root / '.build/ref', root / '.build/ref/artifacts'):
        mkdir_new(path)
    write_new(root / '.build/ref/artifacts/volume_reference_apfs.py', data)
    state = {'schema': SCHEMA, 'phase': 'prepared', 'run_id': args.run_id,
             'setup_sha256': args.setup_sha256, 'mountpoint': str(mount),
             'container_uuid': CONTAINER, 'store_uuid': STORE, 'data_uuid': DATA,
             'quota_bytes': QUOTA, 'reserve_bytes': 0}
    write_new(root / '.build/ref/artifacts/receipt.jsonl', (json.dumps(state) + '\n').encode())
    print(f'Private source: {root}/.build/ref/artifacts/volume_reference_apfs.py\nReceipt: {root}/.build/ref/artifacts/receipt.jsonl')
    return root


def inventory(raw):
    """Ignore live usage, not identity/topology/name/role/quota/reserve changes."""
    result = {}
    for container in raw['Containers']:
        key = container['APFSContainerUUID']
        require(key not in result, 'duplicate container UUID')
        volumes = {}
        for volume in container['Volumes']:
            vid = volume['APFSVolumeUUID']
            require(vid not in volumes, 'duplicate volume UUID')
            volumes[vid] = {k: volume[k] for k in ('DeviceIdentifier', 'Name', 'Roles',
                                                   'CapacityQuota', 'CapacityReserve')}
        result[key] = {'reference': container['ContainerReference'],
                       'ceiling': container['CapacityCeiling'],
                       'stores': container['PhysicalStores'], 'volumes': volumes}
    return result


def data_identity(info):
    keys = ('VolumeUUID', 'DeviceIdentifier', 'MountPoint', 'FilesystemType',
            'GlobalPermissionsEnabled', 'Internal', 'APFSContainerReference', 'VolumeName')
    return {key: info[key] for key in keys}


def inspect():
    raw = disk('apfs', 'list', '-plist')
    inv = inventory(raw)
    require(CONTAINER in inv, 'pinned external container absent')
    container = next(c for c in raw['Containers'] if c['APFSContainerUUID'] == CONTAINER)
    stores = container['PhysicalStores']
    require(len(stores) == 1 and stores[0]['DiskUUID'] == STORE
            and stores[0]['Size'] == CEILING and container['CapacityCeiling'] == CEILING,
            'physical store identity/size mismatch')
    store = disk('info', '-plist', stores[0]['DeviceIdentifier'])
    require(store.get('DiskUUID') == STORE and store.get('Internal') is False
            and store.get('BusProtocol') == 'USB' and store.get('Content') == 'Apple_APFS'
            and store.get('DeviceIdentifier') == stores[0]['DeviceIdentifier']
            and store.get('APFSContainerReference') == container['ContainerReference'],
            'external physical store verification failed')
    data = disk('info', '-plist', str(DATA_PATH))
    require(data.get('VolumeUUID') == DATA and data.get('Internal') is False
            and data.get('MountPoint') == str(DATA_PATH) and data.get('FilesystemType') == 'apfs'
            and data.get('APFSContainerReference') == container['ContainerReference']
            and DATA in inv[CONTAINER]['volumes']
            and data.get('DeviceIdentifier') == inv[CONTAINER]['volumes'][DATA]['DeviceIdentifier'],
            'original data volume identity changed')
    require(type(container['CapacityFree']) is int and container['CapacityFree'] >= QUOTA + HEADROOM,
            'external container needs 48 GiB quota + 24 GiB free headroom')
    return {'inventory': inv, 'data': data_identity(data),
            'data_inode': stamp(DATA_PATH.lstat()), 'free_bytes': container['CapacityFree']}


def new_volume(before, after, name):
    expected = json.loads(json.dumps(before['inventory']))
    actual = after['inventory']
    require(CONTAINER in actual, 'container disappeared')
    old = expected[CONTAINER]['volumes']
    added = set(actual[CONTAINER]['volumes']) - set(old)
    require(len(added) == 1, 'inventory must add exactly one volume')
    vid = added.pop()
    require(vid not in {v for c in expected.values() for v in c['volumes']}, 'volume UUID reused')
    volume = actual[CONTAINER]['volumes'][vid]
    require(volume['Name'] == name and volume['CapacityQuota'] == QUOTA
            and volume['CapacityReserve'] == 0 and volume['Roles'] == [],
            'new volume name/quota/reserve/roles mismatch')
    old[vid] = volume
    require(expected == actual and before['data'] == after['data']
            and before['data_inode'] == after['data_inode'], 'unrelated disk/data identity changed')
    return vid


class Journal:
    def __init__(self, path):
        self.path = path
        self.pin = trusted(path, private=True, regular=True)
        self.fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW)
        require(stamp(os.fstat(self.fd)) == self.pin, 'receipt replaced while opening')
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def append(self, phase, **fields):
        require(trusted(self.path, private=True, regular=True) == self.pin, 'receipt identity changed')
        data = (json.dumps({'phase': phase, **fields}, sort_keys=True) + '\n').encode()
        require(os.write(self.fd, data) == len(data), 'short receipt write')
        os.fsync(self.fd)

    def close(self):
        os.close(self.fd)


def create(args):
    require(args.allow_new_apfs_volume, '--allow-new-apfs-volume required')
    require((args.expect_container_uuid, args.expect_store_uuid, args.expect_data_uuid)
            == (CONTAINER, STORE, DATA), 'all three explicit UUID pins must match reviewed identities')
    host_check()
    root, parent, mount = layout(args.run_id)
    trusted(root, private=True)
    source = root / '.build/ref/artifacts/volume_reference_apfs.py'
    require(Path(__file__).absolute() == source, 'create must execute the NEW private setup copy')
    trusted(source, private=True, regular=True)
    require(hashlib.sha256(source_data(source)).hexdigest() == args.setup_sha256, 'private source SHA mismatch')
    journal = Journal(root / '.build/ref/artifacts/receipt.jsonl')
    mount_fd = None
    try:
        receipt = os.read(journal.fd, 1024**2).decode().splitlines()
        require(len(receipt) == 1, 'already attempted; no retry/adoption permitted')
        state = json.loads(receipt[0])
        require(state == {'schema': SCHEMA, 'phase': 'prepared', 'run_id': args.run_id,
                'setup_sha256': args.setup_sha256, 'mountpoint': str(mount),
                'container_uuid': CONTAINER, 'store_uuid': STORE, 'data_uuid': DATA,
                'quota_bytes': QUOTA, 'reserve_bytes': 0}, 'prepared receipt mismatch')
        journal.append('preflight-started')
        before = inspect()
        name = 'cengine-ref-' + args.run_id
        require(all(v['Name'] != name for c in before['inventory'].values() for v in c['volumes'].values()),
                'our unique volume name already exists')
        mkdir_new(parent)
        mkdir_new(mount)
        parent_pin, mount_pin = trusted(parent, private=True), trusted(mount, private=True)
        mount_fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        require(stamp(os.fstat(mount_fd)) == mount_pin, 'mountpoint replaced while opening')
        journal.append('intent', before=before, name=name, mountpoint=str(mount),
                       parent_inode=parent_pin, mount_inode=mount_pin)

        def empty_mount():
            require(trusted(parent, private=True) == parent_pin
                    and trusted(mount, private=True) == mount_pin
                    and stamp(os.fstat(mount_fd)) == mount_pin
                    and not os.path.ismount(mount) and not list(mount.iterdir()),
                    'mountpoint changed, occupied or already mounted')

        def stable():
            fresh = inspect()
            require(fresh['inventory'] == before['inventory'] and fresh['data'] == before['data']
                    and fresh['data_inode'] == before['data_inode'], 'pre-add identity changed')
            empty_mount()

        def mutate(argv):
            journal.append('command-intent', argv=argv)
            try:
                result = command(argv, full=True)
                journal.append('command-complete', argv=argv,
                               stdout=result.stdout[:1024**2].decode('utf-8', 'replace'),
                               stderr=result.stderr[:1024**2].decode('utf-8', 'replace'))
            except BaseException as error:
                # Even nonzero exits can have partial effects. Until completion
                # is durably recorded, every failure needs manual reconciliation.
                journal.append('mutation-outcome-unknown', argv=argv,
                               error=str(error), error_type=type(error).__name__,
                               stdout=(getattr(error, 'output', None) or b'')[:1024**2].decode('utf-8', 'replace'),
                               stderr=(getattr(error, 'stderr', None) or b'')[:1024**2].decode('utf-8', 'replace'))
                raise

        # sudo -n never prompts; failure is terminal even before add. No sudo
        # validation/timestamp refresh is performed by this script.
        stable()
        journal.append('add-intent', argv=[DISKUTIL, 'apfs', 'addVolume', CONTAINER, 'APFS', name,
                                         '-quota', str(QUOTA), '-nomount'])
        stable()  # Fresh pins immediately before the ONLY addVolume invocation.
        add_error = None
        try:
            mutate(['/usr/bin/sudo', '-n', DISKUTIL, 'apfs', 'addVolume', CONTAINER,
                    'APFS', name, '-quota', str(QUOTA), '-nomount'])
        except BaseException as error:
            add_error = error
        try:
            # Even a failed diskutil can have created a volume. This is an
            # observation, not proof that a timed-out operation has finished.
            after = inspect()
            journal.append('post-add-inventory', observed=after)
            vid = new_volume(before, after, name)
            journal.append('volume-owned', volume_uuid=vid, name=name)
        except BaseException as observation_error:
            journal.append('post-add-attribution-failed', error=str(observation_error))
            if add_error is not None:
                raise add_error from observation_error
            raise
        if add_error is not None:
            raise add_error

        def volume_info(*, mounted, owners_required=True):
            fresh = inspect()
            require(new_volume(before, fresh, name) == vid, 'owned volume changed')
            require(trusted(parent, private=True) == parent_pin, 'private mount parent changed')
            info = disk('info', '-plist', vid)
            require(info.get('VolumeUUID') == vid and info.get('Internal') is False
                    and info.get('FilesystemType') == 'apfs'
                    and info.get('APFSContainerReference') == fresh['inventory'][CONTAINER]['reference']
                    and info.get('DeviceIdentifier') == fresh['inventory'][CONTAINER]['volumes'][vid]['DeviceIdentifier']
                    and info.get('MountPoint', '') == (str(mount) if mounted else '')
                    and info.get('VolumeName') == name and info.get('APFSSnapshot') is False,
                    'owned volume identity/mount verification failed')
            if mounted:
                at_path = disk('info', '-plist', str(mount))
                require(at_path.get('VolumeUUID') == vid and at_path.get('MountPoint') == str(mount)
                        and (not owners_required or at_path.get('GlobalPermissionsEnabled') is True),
                        'mount shadow/ownership mismatch')
            return info

        info = volume_info(mounted=False)
        needs_persistent_owners = info.get('GlobalPermissionsEnabled') is not True
        journal.append('mount-intent', volume_uuid=vid, mountpoint=str(mount))
        volume_info(mounted=False)
        empty_mount()
        mutate(['/usr/bin/sudo', '-n', DISKUTIL, 'mount', 'nobrowse', '-mountOptions',
                'owners', '-mountPoint', str(mount), vid])
        info = volume_info(mounted=True, owners_required=False)
        # enableOwnership requires a mounted volume. The private parent protects
        # the initial root; mount -o owners enables native semantics immediately.
        # Persist the setting if it was disabled before our explicit mount.
        if needs_persistent_owners or info.get('GlobalPermissionsEnabled') is not True:
            journal.append('enable-owners-intent', volume_uuid=vid)
            volume_info(mounted=True, owners_required=False)
            mutate(['/usr/bin/sudo', '-n', DISKUTIL, 'enableOwnership', vid])
        info = volume_info(mounted=True)
        require(info.get('GlobalPermissionsEnabled') is True, 'native owners required')
        root_pin = trusted(mount)
        journal.append('mounted', volume_uuid=vid, root_inode=root_pin)
        # Pin the newly mounted root before any path-based privileged chown.
        fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(stamp(os.fstat(fd)) == root_pin, 'new root replaced')
            if root_pin[2:4] != [UID, GID]:
                journal.append('chown-new-root-intent', volume_uuid=vid, root_inode=root_pin)
                volume_info(mounted=True)
                require(trusted(mount) == root_pin, 'new root inode changed')
                # Apple pathname tools cannot prevent malicious same-UID/root
                # races; this explicit trust boundary is not an absolute guarantee.
                mutate(['/usr/bin/sudo', '-n', '/usr/sbin/chown', f'{UID}:{GID}', str(mount)])
            require(os.fstat(fd).st_uid == UID and os.fstat(fd).st_gid == GID
                    and stamp(mount.lstat()) == stamp(os.fstat(fd)), 'new root chown failed/replaced')
            os.fchmod(fd, 0o700)
            os.fsync(fd)
            require(trusted(mount, private=True) == stamp(os.fstat(fd)), 'private root changed')
        finally:
            os.close(fd)
        volume_info(mounted=True)
        journal.append('complete', volume_uuid=vid, mountpoint=str(mount),
                       quota_bytes=QUOTA, reserve_bytes=0, native_owners=True, uid=UID, gid=GID, mode='0700')
        print(json.dumps({'volume_uuid': vid, 'mountpoint': str(mount), 'receipt': str(journal.path)}, indent=2))
        return vid
    except BaseException as error:
        journal.append('failed-no-cleanup', error=str(error))
        raise
    finally:
        if mount_fd is not None:
            os.close(mount_fd)
        journal.close()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('action', choices=('prepare', 'create'))
    result.add_argument('--run-id', required=True)
    result.add_argument('--setup-sha256', required=True)
    result.add_argument('--allow-private-copy', action='store_true')
    result.add_argument('--allow-new-apfs-volume', action='store_true')
    result.add_argument('--expect-container-uuid')
    result.add_argument('--expect-store-uuid')
    result.add_argument('--expect-data-uuid')
    return result


def main():
    args = parser().parse_args()
    try:
        (prepare if args.action == 'prepare' else create)(args)
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'REFUSED; retain all receipts and volumes, no cleanup: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
