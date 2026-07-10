"""Docker SDK system compatibility tests adapted from Podman's suite."""

from __future__ import annotations

import os

import docker
import pytest


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("SYS-001")
def test_info(client: docker.DockerClient):
    info = client.info()
    assert info["Driver"] == "apple-containerization"
    assert info["OSType"] == "linux"
    assert info["Architecture"] == "arm64"
    assert info["DockerRootDir"]


@pytest.mark.compat("SYS-002")
def test_info_container_details(client: docker.DockerClient, top):
    assert client.info()["Containers"] == 1
    client.containers.create(image=IMAGE)
    assert client.info()["Containers"] == 2


@pytest.mark.compat("SYS-003")
def test_version(client: docker.DockerClient):
    version = client.version()
    assert version["Platform"]["Name"] == "cengine"
    assert version["ApiVersion"] == "1.44"
