"""Raw one-container-per-VM runtime regression contracts."""

from __future__ import annotations

import time
import uuid

import docker
import pytest
from docker.types import Mount


@pytest.mark.compat("CTR-035")
def test_debian_package_install_uses_ext4_rootfs(client: docker.DockerClient):
    output = client.containers.run(
        "debian:trixie-slim",
        ["sh", "-ec", "apt-get update >/dev/null && apt-get install -y ca-certificates >/dev/null && test -d /etc/ssl && echo ext4-ok"],
        remove=True,
    )
    assert output.strip() == b"ext4-ok"


@pytest.mark.compat("VOL-006")
def test_volume_preserves_inodes_across_link_and_rename(client: docker.DockerClient):
    volume = client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}", labels={"dev.cengine.compat": "true"}
    )
    output = client.containers.run(
        "alpine:latest",
        ["sh", "-ec", "mkdir -p /data/a/etc/ssl; printf payload >/data/a/file; ln /data/a/file /data/a/link; before=$(stat -c %i /data/a/file); mv /data/a /data/b; test \"$before\" = \"$(stat -c %i /data/b/link)\"; cat /data/b/link"],
        mounts=[Mount(target="/data", source=volume.name, type="volume")],
        remove=True,
    )
    assert output == b"payload"


@pytest.mark.compat("REC-004")
def test_running_workload_survives_daemon_process_replacement(daemon, client: docker.DockerClient):
    container = client.containers.run("alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True)
    container.reload()
    started_at = container.attrs["State"]["StartedAt"]
    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=180, version="auto")
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            value = recovered.containers.get(container.id)
            value.reload()
            if value.status == "running":
                assert value.attrs["State"]["StartedAt"] == started_at
                return
            time.sleep(0.2)
        pytest.fail("running shim workload was not recovered")
    finally:
        recovered.close()
