"""Linux fs-verity on freshly formatted root and direct-volume ext4 disks."""

from __future__ import annotations

import uuid

import docker
import pytest
from docker.types import Mount


IMAGE = "mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
PROBE = r"""
import errno
import fcntl
import os
import struct
import sys

phase = sys.argv[1]
mounts = open('/proc/self/mountinfo').read().splitlines()
for directory in ('/root', '/data'):
    mountpoint = '/' if directory == '/root' else directory
    mount = [line for line in mounts if line.split()[4] == mountpoint]
    assert len(mount) == 1 and mount[0].split(' - ')[1].split()[0] == 'ext4', mount
    path = directory + '/verity-blob'
    payload = b'cengine-fsverity\n' * 1024
    if phase == 'enable':
        with open(path, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        with open(path, 'rb') as stream:
            # Linux struct fsverity_enable_arg: v1, SHA-256, 4 KiB blocks.
            argument = struct.pack('=IIIIQIIQ11Q', 1, 1, 4096, 0, 0, 0, 0, 0, *([0] * 11))
            fcntl.ioctl(stream.fileno(), 0x40806685, argument)
    with open(path, 'rb') as stream:
        digest = bytearray(struct.pack('=HH', 0, 64) + bytes(64))
        fcntl.ioctl(stream.fileno(), 0xc0046686, digest)
        assert struct.unpack_from('=HH', digest) == (1, 32), digest
        assert stream.read() == payload
    digest_path = path + '.digest'
    if phase == 'enable':
        with open(digest_path, 'wb') as stream:
            stream.write(digest[4:36])
    else:
        assert open(digest_path, 'rb').read() == digest[4:36]
    try:
        descriptor = os.open(path, os.O_WRONLY)
    except OSError as error:
        assert error.errno == errno.EPERM, error
    else:
        os.close(descriptor)
        raise AssertionError('verity file accepted writable open')
    # Files without verity stay writable on a verity-capable filesystem.
    with open(directory + '/ordinary', 'wb') as stream:
        stream.write(b'writable')
    if phase == 'verify':
        os.unlink(path)
        assert not os.path.exists(path)
print('fsverity-' + phase + '-ok')
"""


@pytest.mark.compat("RTM-134")
def test_fsverity_root_and_direct_volume_survive_restart(client: docker.DockerClient):
    volume = client.volumes.create(f"compat-verity-{uuid.uuid4().hex[:8]}")
    container = None
    try:
        container = client.containers.run(
            IMAGE, ["sleep", "infinity"], detach=True,
            mounts=[Mount(target="/data", source=volume.name, type="volume")],
        )
        for phase in ("enable", "verify"):
            if phase == "verify":
                container.restart(timeout=10)
            result = container.exec_run(["python3", "-c", PROBE, phase])
            assert result.exit_code == 0, result.output.decode()
            assert result.output.strip() == f"fsverity-{phase}-ok".encode()
    finally:
        if container is not None:
            container.remove(force=True)
        volume.remove()
