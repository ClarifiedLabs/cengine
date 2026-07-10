"""Cengine-owned Docker resource filtering contracts."""

from __future__ import annotations

import uuid

import docker
import pytest
from docker.types import Mount


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
