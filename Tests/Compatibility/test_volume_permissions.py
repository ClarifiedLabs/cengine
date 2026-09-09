"""Named-volume copy-up and shared NFS caller-credential contracts (secret-free)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import threading
import uuid

import docker
from docker.types import Mount
import pytest


def _tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data, uid, gid, mode in entries:
            info = tarfile.TarInfo(name)
            info.uid, info.gid, info.mode = uid, gid, mode
            if data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            archive.addfile(info, None if data is None else io.BytesIO(data))
    return output.getvalue()


@pytest.fixture
def permissions_image(client: docker.DockerClient, tmp_path):
    """Load a deterministic scratch image without requiring a builder VM."""
    binary = tmp_path / "probe"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(binary),
         str(Path(__file__).parent / "fixtures" / "volume-permissions.go")],
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64",
             "GOWORK": "off"},
        check=True, capture_output=True, text=True, timeout=120,
    )
    layer = _tar([
        ("probe", binary.read_bytes(), 0, 0, 0o755),
        ("etc", None, 0, 0, 0o755),
        ("etc/passwd", b"root:x:0:0:root:/:/probe\nowner:x:10001:10001:owner:/:/probe\n", 0, 0, 0o644),
        ("etc/group", b"root:x:0:\nowner:x:10001:\nteam:x:20000:owner\n", 0, 0, 0o644),
        ("empty", None, 10001, 10001, 0o700),
        ("populated", None, 10001, 20000, 0o3770),
        ("populated/seed", b"image-seed\n", 10001, 20000, 0o640),
        ("nocopy", None, 10001, 10001, 0o700),
        ("nocopy/seed", b"image-seed\n", 10001, 10001, 0o600),
        ("existing", None, 10001, 10001, 0o700),
        ("existing/seed", b"image-seed\n", 10001, 10001, 0o600),
        ("data", None, 0, 0, 0o755),
        ("control", None, 10001, 10001, 0o700),
    ])
    config = json.dumps({
        "architecture": "arm64", "os": "linux",
        "config": {"Cmd": ["/probe", "serve"]},
        "rootfs": {"type": "layers", "diff_ids": [
            "sha256:" + hashlib.sha256(layer).hexdigest(),
        ]},
    }).encode()
    config_digest = hashlib.sha256(config).hexdigest()
    layer_digest = hashlib.sha256(layer).hexdigest()
    tag = f"compat-volume-permissions:{uuid.uuid4().hex[:12]}"
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": f"sha256:{config_digest}", "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": f"sha256:{layer_digest}", "size": len(layer)}],
    }).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    index = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": f"sha256:{manifest_digest}", "size": len(manifest),
            "annotations": {"io.containerd.image.name": tag,
                            "org.opencontainers.image.ref.name": tag},
        }],
    }).encode()
    client.images.load(_tar([
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}', 0, 0, 0o644),
        ("index.json", index, 0, 0, 0o644),
        (f"blobs/sha256/{config_digest}", config, 0, 0, 0o644),
        (f"blobs/sha256/{layer_digest}", layer, 0, 0, 0o644),
        (f"blobs/sha256/{manifest_digest}", manifest, 0, 0, 0o644),
    ]))
    try:
        yield tag
    finally:
        client.images.remove(tag, force=True)


def _probe(container, *args, user=None):
    result = container.exec_run(["/probe", *map(str, args)], user=user)
    assert result.exit_code == 0, result.output.decode(errors="replace")
    return result.output


def _metadata(container, path, uid, gid, mode):
    output = _probe(container, "stat", path)
    assert json.loads(output.splitlines()[0]) == {"uid": uid, "gid": gid, "mode": mode}


def _configure(container, path, uid, gid, mode):
    _probe(container, "configure", path, uid, gid, oct(mode), user="0:0")


def _storage_mode(daemon, volume, expected):
    modes = json.loads((daemon.root / "volume-storage.json").read_text())
    assert modes[volume.name] == expected


@pytest.mark.compat("RTM-053")
def test_named_volume_copyup_preserves_root_metadata_and_existing_data(
    daemon, client: docker.DockerClient, permissions_image,
):
    # Do not parameterize: the ledger requires one unique ID per collected test.
    for storage in ("block", "shared"):
        print(f"copy-up backend: {storage}")
        volumes = {}
        containers = []
        try:
            for role in ("empty", "populated", "nocopy", "existing"):
                volumes[role] = client.volumes.create(
                    f"rtm053-{storage}-{role}-{uuid.uuid4().hex[:8]}",
                    labels={"dev.cengine.compat": "true"},
                )
            if storage == "shared":
                # Both consumers exist before any volume's first mount.
                keeper = client.containers.create(
                    permissions_image,
                    mounts=[Mount(target=f"/{role}", source=volume.name,
                                  type="volume", no_copy=True)
                            for role, volume in volumes.items()],
                )
                containers.append(keeper)

            def target(existing_nocopy):
                value = client.containers.create(
                    permissions_image,
                    mounts=[Mount(target=f"/{role}", source=volume.name,
                                  type="volume", no_copy=(role == "nocopy" or
                                      (role == "existing" and existing_nocopy)))
                            for role, volume in volumes.items()],
                )
                containers.append(value)
                value.start()
                return value

            first = target(True)
            for volume in volumes.values():
                _storage_mode(daemon, volume, storage)
            _metadata(first, "/empty", 10001, 10001, 0o700)
            _metadata(first, "/populated", 10001, 20000, 0o3770)
            _metadata(first, "/populated/seed", 10001, 20000, 0o640)
            _probe(first, "read-seed", "/populated/seed", user="10001:10001")
            _probe(first, "create", "/empty/nonroot", 10001, 10001, user="10001:10001")
            _probe(first, "create", "/populated/nonroot", 10001, 20000, user="10001:10001")
            _metadata(first, "/nocopy", 0, 0, 0o755)
            _probe(first, "absent", "/nocopy/seed")
            _probe(first, "deny-create", "/nocopy/denied", user="10001:10001")
            # Seed a *nonempty* volume with metadata unlike the image source.
            _configure(first, "/existing", 10002, 20002, 0o3710)
            _probe(first, "create", "/existing/preserved", 10002, 20002, user="10002:20002")
            # Remove before creating the replacement: direct volumes must not
            # accidentally gain a second known consumer before backend selection.
            first.remove(force=True)
            containers.remove(first)
            second = target(False)
            _metadata(second, "/existing", 10002, 20002, 0o3710)
            _probe(second, "verify", "/existing/preserved", 10002, 20002, user="10002:20002")
            _probe(second, "absent", "/existing/seed")
            _metadata(second, "/nocopy", 0, 0, 0o755)
            _probe(second, "absent", "/nocopy/seed")
            _probe(second, "verify", "/empty/nonroot", 10001, 10001, user="10001:10001")
            _metadata(second, "/populated", 10001, 20000, 0o3770)
            _probe(second, "verify", "/populated/nonroot", 10001, 20000, user="10001:10001")
        finally:
            for container in reversed(containers):
                container.remove(force=True)
            for volume in volumes.values():
                volume.remove(force=True)


@pytest.mark.compat("RTM-054")
def test_shared_volume_enforces_caller_ownership_permissions_and_groups(
    daemon, client: docker.DockerClient, permissions_image,
):
    volume = client.volumes.create(
        f"rtm054-{uuid.uuid4().hex[:12]}", labels={"dev.cengine.compat": "true"},
    )
    containers = []
    try:
        # Fresh backend selection requires BOTH creates before EITHER start.
        initializer = client.containers.create(
            permissions_image,
            mounts=[Mount(target="/data", source=volume.name, type="volume", no_copy=True)],
        )
        containers.append(initializer)
        consumer = client.containers.create(
            permissions_image, user="owner",
            mounts=[Mount(target="/data", source=volume.name, type="volume", no_copy=True)],
        )
        containers.append(consumer)
        initializer.start()
        _configure(initializer, "/data", 10001, 10001, 0o700)
        consumer.start()
        _storage_mode(daemon, volume, "shared")
        # The same descriptor-first check on the workload root is a control.
        _probe(consumer, "create", "/control/local", 10001, 10001)
        _probe(consumer, "create", "/data/private", 10001, 10001)
        _probe(initializer, "verify", "/data/private", 10001, 10001, user="10001:10001")
        _probe(initializer, "deny-create", "/data/denied", user="10002:10002")
        # Grant directory search, not file access: denial must concern the
        # 0600 file itself rather than merely its inaccessible parent.
        _configure(initializer, "/data", 10001, 10001, 0o755)
        _probe(initializer, "deny", "/data/private", user="10002:10002")
        _probe(consumer, "deny-chown", "/data/private", 10002, 20002)
        _probe(consumer, "verify", "/data/private", 10001, 10001)

        _probe(initializer, "mkdir", "/data/team")
        _configure(initializer, "/data/team", 0, 20000, 0o2770)
        _probe(consumer, "group", "/data/team", 20000)
        _probe(initializer, "verify", "/data/team/group-file", 10001, 20000, user="10001:20000")
        _probe(initializer, "deny-create", "/data/team/denied", user="10002:10002")

        _probe(initializer, "mkdir", "/data/public")
        _configure(initializer, "/data/public", 0, 0, 0o1777)
        barrier = threading.Barrier(2)

        def stress(container, user):
            barrier.wait(timeout=10)
            _probe(container, "stress", "/data/public", user=user)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(stress, consumer, None),
                       pool.submit(stress, initializer, "10002:10002")]
            for future in futures:
                future.result(timeout=120)
        # Independent VM lookups after both streams also catch identity leaks.
        _probe(initializer, "verify-stress", "/data/public", user="10001:10001")
        _probe(consumer, "verify-stress", "/data/public", user="10002:10002")
        _probe(consumer, "deny", "/data/public/caller-10002-0")
        _probe(initializer, "deny", "/data/public/caller-10001-0", user="10002:10002")
        consumer.restart(timeout=5)
        _probe(consumer, "verify", "/data/private", 10001, 10001)
        _probe(initializer, "verify", "/data/private", 10001, 10001, user="10001:10001")
    finally:
        for container in reversed(containers):
            container.remove(force=True)
        volume.remove(force=True)
