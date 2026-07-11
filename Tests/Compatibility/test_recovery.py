"""VM-backed daemon persistence and recovery contracts."""

from __future__ import annotations

import os
import time
import uuid

import docker
import pytest
from docker.types import Mount


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("REC-001")
def test_daemon_restart_recovers_resources_and_restart_policy(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-recovery-{suffix}")
    volume = client.volumes.create(
        f"compat-recovery-{suffix}", labels={"dev.cengine.compat": "true"}
    )
    container = client.containers.create(
        IMAGE, command="top", name=f"recovery-{suffix}",
        mounts=[Mount(target="/data", source=volume.name, type="volume")],
        restart_policy={"Name": "always"},
    )
    container.start()
    original_id = container.id

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        assert recovered.ping()
        deadline = time.monotonic() + 30
        while True:
            value = recovered.containers.get(container.name)
            value.reload()
            if value.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"container did not recover after daemon restart: {value.attrs['State']}")
            time.sleep(0.2)
        assert value.id == original_id
        assert recovered.networks.get(network.name).name == network.name
        assert recovered.volumes.get(volume.name).name == volume.name
        assert value.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
        assert any(mount["Name"] == volume.name for mount in value.attrs["Mounts"])
    finally:
        recovered.close()
