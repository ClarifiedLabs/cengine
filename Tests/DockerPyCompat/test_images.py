"""Docker SDK image compatibility tests adapted from Podman's suite."""

from __future__ import annotations

import io
import json
import os

import docker
import pytest
from docker import errors


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
BUSYBOX = "busybox:latest"
KNOWN_GAP = pytest.mark.xfail(strict=True)


@KNOWN_GAP(reason="IMG-001: image tagging endpoint is not implemented")
@pytest.mark.compat("IMG-001")
def test_tag_valid_image(client: docker.DockerClient):
    image = client.images.get(IMAGE)
    assert image.tag("demo", "alpine")
    assert any("alpine" in tag for tag in client.images.get(IMAGE).tags)


@KNOWN_GAP(reason="IMG-002: image retagging endpoint is not implemented")
@pytest.mark.compat("IMG-002")
def test_retag_valid_image(client: docker.DockerClient):
    image = client.images.get(IMAGE)
    assert image.tag("demo", "rename")
    assert "demo:test" not in client.images.get(IMAGE).tags


@KNOWN_GAP(reason="IMG-003: image list reference filters are not implemented")
@pytest.mark.compat("IMG-003")
def test_list_images(client: docker.DockerClient):
    assert len(client.images.list(filters={"reference": "alpine"})) == 1
    client.images.pull(BUSYBOX)
    assert len(client.images.list(filters={"reference": "alpine"})) == 1


@KNOWN_GAP(reason="IMG-004: registry search is not implemented")
@pytest.mark.compat("IMG-004")
def test_search_image(client: docker.DockerClient):
    assert any("alpine" in item["name"].lower() for item in client.images.search("alpine"))


@pytest.mark.compat("IMG-005")
def test_search_bogus_image(client: docker.DockerClient):
    with pytest.raises(errors.APIError):
        client.images.search("bogus/bogus")


@pytest.mark.compat("IMG-006")
def test_remove_image(client: docker.DockerClient):
    with pytest.raises(errors.NotFound):
        client.images.remove("dummy")
    client.images.remove(IMAGE)
    with pytest.raises(errors.NotFound):
        client.images.get(IMAGE)


@pytest.mark.compat("IMG-007")
def test_image_history(client: docker.DockerClient):
    image = client.images.get(IMAGE)
    assert any(image.id in entry.values() for entry in image.history())


@pytest.mark.compat("IMG-008")
def test_get_image_exists_not(client: docker.DockerClient):
    with pytest.raises(errors.NotFound):
        client.images.get("image_does_not_exist")


@KNOWN_GAP(reason="IMG-009: Docker image save/export is not implemented")
@pytest.mark.compat("IMG-009")
def test_save_image(client: docker.DockerClient):
    assert b"".join(client.images.get(IMAGE).save(named=True))


@KNOWN_GAP(reason="IMG-010: Docker image save/load round trips are not implemented")
@pytest.mark.compat("IMG-010")
def test_load_image(client: docker.DockerClient):
    archive = b"".join(client.images.get(IMAGE).save(named=True))
    assert client.images.load(archive)


@pytest.mark.compat("IMG-011")
def test_load_corrupt_image(client: docker.DockerClient):
    with pytest.raises(errors.APIError):
        client.images.load(io.BytesIO(b"This is a corrupt tarball"))


@KNOWN_GAP(reason="IMG-012: direct docker build is intentionally unsupported; use Buildx")
@pytest.mark.compat("IMG-012")
def test_build_image(client: docker.DockerClient):
    client.images.build(fileobj=io.BytesIO(b"FROM alpine:latest\n"), tag="labels")


@KNOWN_GAP(reason="IMG-013: direct docker build is intentionally unsupported; use Buildx")
@pytest.mark.compat("IMG-013")
def test_build_image_via_api_client(client: docker.DockerClient):
    for line in client.api.build(fileobj=io.BytesIO(b"FROM alpine:latest\n")):
        assert "errorDetail" not in json.loads(line)


@KNOWN_GAP(reason="IMG-014: image push is not implemented")
@pytest.mark.compat("IMG-014")
def test_push_error(client: docker.DockerClient):
    response = client.images.push("non-existent.lan:5000/alpine", "latest")
    assert "no such host" in response
