"""Optional differential contracts against an explicitly selected Docker Engine."""

from __future__ import annotations

import os
import uuid

import docker
import pytest
from docker import errors


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
pytestmark = pytest.mark.oracle


def lifecycle_contract(value: docker.DockerClient, name: str) -> dict:
    container = value.containers.create(
        IMAGE, command="top", name=name, labels={"dev.cengine.compat.oracle": name}
    )
    try:
        created = value.api.inspect_container(container.id)
        container.start()
        try:
            container.remove()
            conflict = None
        except errors.APIError as error:
            conflict = error.response.status_code
        listed = value.containers.list(all=True, filters={"label": f"dev.cengine.compat.oracle={name}"})
        container.stop(timeout=1)
        container.reload()
        return {
            "create_keys": sorted({"Id", "Name", "State", "Config", "HostConfig", "Mounts", "NetworkSettings"} & created.keys()),
            "created_status": created["State"]["Status"],
            "running_remove_status": conflict,
            "label_filter_count": len(listed),
            "final_status": container.attrs["State"]["Status"],
            "field_types": {
                "Mounts": type(created["Mounts"]).__name__,
                "Config": type(created["Config"]).__name__,
                "HostConfig": type(created["HostConfig"]).__name__,
            },
        }
    finally:
        try:
            container.remove(force=True)
        except errors.NotFound:
            pass


@pytest.mark.compat("ORC-001")
def test_container_lifecycle_matches_reference_docker(client: docker.DockerClient):
    host = os.environ.get("DOCKER_REFERENCE_HOST")
    if not host:
        pytest.skip("set DOCKER_REFERENCE_HOST to run Docker differential contracts")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        platform = reference.version().get("Platform", {}).get("Name", "")
        if platform == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must identify a reference Docker Engine, not cengine")
        reference.ping()
        reference.images.pull(IMAGE)
        suffix = uuid.uuid4().hex[:8]
        expected = lifecycle_contract(reference, f"compat-oracle-reference-{suffix}")
        actual = lifecycle_contract(client, f"compat-oracle-cengine-{suffix}")
        assert actual == expected
    finally:
        reference.close()
