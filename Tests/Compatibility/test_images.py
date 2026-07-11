"""Docker image API compatibility contracts, seeded from Podman's suite."""

from __future__ import annotations

import base64
import io
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
import uuid

import docker
import pytest
from docker import errors


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
BUSYBOX = "busybox:latest"
REGISTRY_IMAGE = "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
REGISTRY_AUTH = {"username": "compat", "password": "compat-password"}
REGISTRY_FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "Fixtures/registry"
KNOWN_GAP = pytest.mark.xfail(strict=True)


@pytest.mark.compat("IMG-001")
def test_tag_valid_image(client: docker.DockerClient):
    image = client.images.get(IMAGE)
    assert image.tag("demo", "alpine")
    assert "demo:alpine" in client.images.get(IMAGE).tags


@pytest.mark.compat("IMG-002")
def test_retag_valid_image(client: docker.DockerClient):
    image = client.images.get(IMAGE)
    assert image.tag("demo", "rename")
    assert "demo:rename" in client.images.get(IMAGE).tags
    assert IMAGE in client.images.get("demo:rename").tags


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


@pytest.mark.compat("IMG-009")
def test_save_image(client: docker.DockerClient):
    assert b"".join(client.images.get(IMAGE).save(named=True))


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


@pytest.mark.compat("IMG-014")
def test_push_error(client: docker.DockerClient):
    client.images.get(IMAGE).tag("non-existent.lan:5000/alpine", "latest")
    response = client.images.push("non-existent.lan:5000/alpine", "latest")
    assert "non-existent.lan" in response
    assert "resolve" in response.lower() or "no such host" in response.lower()


@pytest.mark.compat("IMG-015")
def test_authenticated_push_round_trip(client: docker.DockerClient):
    client.images.pull(REGISTRY_IMAGE)
    registry = client.containers.create(
        REGISTRY_IMAGE,
        name=f"compat-registry-{uuid.uuid4().hex[:8]}",
        environment={
            "REGISTRY_AUTH": "htpasswd",
            "REGISTRY_AUTH_HTPASSWD_REALM": "compatibility registry",
            "REGISTRY_AUTH_HTPASSWD_PATH": "/auth/htpasswd",
        },
        mounts=[docker.types.Mount("/auth", str(REGISTRY_FIXTURE), type="bind", read_only=True)],
        ports={"5000/tcp": None},
    )
    registry.start()
    registry.reload()
    host_port = registry.attrs["NetworkSettings"]["Ports"]["5000/tcp"][0]["HostPort"]
    endpoint = f"127.0.0.1:{host_port}"
    request = urllib.request.Request(f"http://{endpoint}/v2/")
    credentials = base64.b64encode(b"compat:compat-password").decode()
    request.add_header("Authorization", f"Basic {credentials}")
    deadline = time.monotonic() + 30
    while True:
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                assert response.status == 200
            break
        except (OSError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)

    reference = f"{endpoint}/compat/alpine:roundtrip"
    source = client.images.get(IMAGE)
    assert source.tag(reference)
    messages = list(client.images.push(reference, auth_config=REGISTRY_AUTH, stream=True, decode=True))
    assert not [message for message in messages if message.get("error")]
    assert any(message.get("status") == "Pushed" for message in messages)

    client.images.remove(reference)
    pulled = list(client.api.pull(reference, auth_config=REGISTRY_AUTH, stream=True, decode=True))
    assert not [message for message in pulled if message.get("error")]
    assert any(message.get("status") == "Pull complete" for message in pulled)
    restored = client.images.get(reference)
    assert reference in restored.tags
    output = client.containers.run(reference, ["echo", "registry-roundtrip"], remove=True)
    assert output.strip() == b"registry-roundtrip"
