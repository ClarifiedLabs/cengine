"""Optional differential contracts against an explicitly selected Docker Engine."""

from __future__ import annotations

import json
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


def image_metadata_contract(value: docker.DockerClient) -> dict:
    platform = json.dumps({"os": "linux", "architecture": "arm64"}, separators=(",", ":"))
    response = value.api._get(
        value.api._url("/images/{0}/json", IMAGE), params={"platform": platform},
    )
    value.api._raise_for_status(response)
    inspected = response.json()
    listed_response = value.api._get(
        value.api._url("/images/json"), params={"manifests": "true"},
    )
    value.api._raise_for_status(listed_response)
    listed = next(item for item in listed_response.json() if IMAGE in item.get("RepoTags", []))
    manifests = listed.get("Manifests") or []
    selected = next(
        (
            item for item in manifests
            if item.get("Kind") == "image"
            and (item.get("ImageData") or {}).get("Platform", {}).get("architecture") == "arm64"
        ),
        None,
    )
    return {
        "inspect_descriptor": isinstance(inspected.get("Descriptor"), dict),
        "inspect_identity": isinstance(inspected.get("Identity"), dict),
        "architecture": inspected.get("Architecture"),
        "os": inspected.get("Os"),
        "manifest_shape": None if selected is None else {
            "available": type(selected.get("Available")).__name__,
            "descriptor": isinstance(selected.get("Descriptor"), dict),
            "kind": selected.get("Kind"),
            "platform": (selected.get("ImageData") or {}).get("Platform"),
            "size_keys": sorted((selected.get("Size") or {}).keys()),
        },
    }


@pytest.mark.compat("ORC-002")
def test_image_metadata_matches_reference_docker(client: docker.DockerClient):
    host = os.environ.get("DOCKER_REFERENCE_HOST")
    if not host:
        pytest.skip("set DOCKER_REFERENCE_HOST to run Docker differential contracts")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        if reference.version().get("Platform", {}).get("Name", "") == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must identify a reference Docker Engine, not cengine")
        reference.images.pull(IMAGE, platform="linux/arm64")
        expected = image_metadata_contract(reference)
        if expected["manifest_shape"] is None or not expected["inspect_descriptor"]:
            pytest.skip("reference Docker Engine does not use a multi-platform image store")
        assert image_metadata_contract(client) == expected
    finally:
        reference.close()
