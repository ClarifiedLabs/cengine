"""Cengine-owned Docker resource filtering contracts."""

from __future__ import annotations

import os
import uuid

import docker
import pytest
from docker.types import Mount


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("NET-001")
def test_network_list_filters_labels(client: docker.DockerClient):
    project = f"project-{uuid.uuid4().hex[:8]}"
    matching = client.networks.create(
        f"compat-{uuid.uuid4().hex[:8]}", labels={"com.docker.compose.project": project}
    )
    client.networks.create(f"compat-{uuid.uuid4().hex[:8]}", labels={"com.docker.compose.project": "other"})
    found = client.networks.list(filters={"label": f"com.docker.compose.project={project}"})
    assert [network.id for network in found] == [matching.id]


@pytest.mark.compat("VOL-001")
def test_volume_list_filters_labels(client: docker.DockerClient):
    project = f"project-{uuid.uuid4().hex[:8]}"
    matching = client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}",
        labels={"dev.cengine.compat": "true", "com.docker.compose.project": project},
    )
    client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}",
        labels={"dev.cengine.compat": "true", "com.docker.compose.project": "other"},
    )
    found = client.volumes.list(filters={"label": f"com.docker.compose.project={project}"})
    assert [volume.name for volume in found] == [matching.name]


@pytest.mark.compat("VOL-002")
def test_empty_named_volume_copies_image_directory(client: docker.DockerClient):
    client.images.pull("nginx:alpine")
    volume = client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}", labels={"dev.cengine.compat": "true"}
    )
    container = client.containers.create(
        "nginx:alpine", command=["sh", "-c", "sleep 300"],
        mounts=[Mount(target="/usr/share/nginx/html", source=volume.name, type="volume")],
    )
    container.start()
    code, _ = container.exec_run(["test", "-f", "/usr/share/nginx/html/index.html"])
    assert code == 0


@pytest.mark.compat("VOL-003")
def test_volume_nocopy_leaves_empty_volume_empty(client: docker.DockerClient):
    client.images.pull("nginx:alpine")
    volume = client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}", labels={"dev.cengine.compat": "true"}
    )
    container = client.containers.create(
        "nginx:alpine", command=["sh", "-c", "sleep 300"],
        mounts=[Mount(
            target="/usr/share/nginx/html", source=volume.name, type="volume", no_copy=True,
        )],
    )
    container.start()
    code, _ = container.exec_run(["test", "-f", "/usr/share/nginx/html/index.html"])
    assert code != 0


@pytest.mark.compat("VOL-004")
def test_volume_subpath_mounts_existing_directory(client: docker.DockerClient):
    volume = client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}", labels={"dev.cengine.compat": "true"}
    )
    client.containers.run(
        IMAGE, ["sh", "-c", "mkdir -p /seed/nested && printf subpath-ok >/seed/nested/marker"],
        mounts=[Mount(target="/seed", source=volume.name, type="volume")], remove=True,
    )
    container = client.containers.create(
        IMAGE, ["cat", "/data/marker"],
        mounts=[Mount(target="/data", source=volume.name, type="volume", read_only=True, subpath="nested")],
    )
    inspect = client.api.inspect_container(container.id)
    assert inspect["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] == "nested"
    container.start()
    assert container.wait(timeout=60)["StatusCode"] == 0
    assert container.logs().strip() == b"subpath-ok"
    with pytest.raises(docker.errors.APIError) as caught:
        client.containers.create(
            IMAGE, ["true"],
            mounts=[Mount(target="/data", source=volume.name, type="volume", subpath="../escape")],
        )
    assert caught.value.response.status_code == 400


@pytest.mark.compat("VOL-005")
def test_tmpfs_size_and_mode_options(client: docker.DockerClient):
    output = client.containers.run(
        IMAGE, ["sh", "-c", "stat -c %a /cache; df -k /cache | tail -1 | awk '{print $2}'"],
        mounts=[Mount(target="/cache", source="", type="tmpfs", tmpfs_size=1_048_576, tmpfs_mode=0o700)],
        remove=True,
    ).decode().splitlines()
    assert output[0] == "700"
    assert int(output[1]) == 1024
