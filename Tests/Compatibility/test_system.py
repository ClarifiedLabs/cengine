"""Docker system API compatibility contracts, seeded from Podman's suite."""

from __future__ import annotations

import os

import docker
import pytest


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("SYS-001")
def test_info(client: docker.DockerClient):
    info = client.info()
    assert info["Driver"] == "cengine-raw-vm"
    assert info["OSType"] == "linux"
    assert info["Architecture"] == "arm64"
    assert info["DockerRootDir"]
    assert "name=seccomp,profile=builtin" in info["SecurityOptions"]


@pytest.mark.compat("SYS-002")
def test_info_container_details(client: docker.DockerClient, top):
    assert client.info()["Containers"] == 1
    client.containers.create(image=IMAGE)
    assert client.info()["Containers"] == 2


@pytest.mark.compat("SYS-003")
def test_version(client: docker.DockerClient, daemon):
    version = client.version()
    assert version["Platform"]["Name"] == "cengine"
    assert version["ApiVersion"] == "1.55"
    assert version["MinAPIVersion"] == "1.44"

    minimum = docker.DockerClient(
        base_url=f"unix://{daemon['socket']}", timeout=180, version="1.44"
    )
    try:
        assert minimum.ping()
        assert minimum.info()["Name"]
        assert minimum.containers.list(all=True) is not None
    finally:
        minimum.close()


@pytest.mark.compat("SYS-004")
def test_info_reports_images_and_versioned_native_engine_details(client: docker.DockerClient, daemon):
    info = client.info()
    assert info["Images"] == len(client.images.list(all=True))
    assert info["DiscoveredDevices"] == []
    assert {"Containerd", "FirewallBackend", "NRI"}.isdisjoint(info)

    legacy = docker.APIClient(
        base_url=f"unix://{daemon['socket']}", timeout=180, version="1.49"
    )
    try:
        assert "DiscoveredDevices" not in legacy.info()
    finally:
        legacy.close()
