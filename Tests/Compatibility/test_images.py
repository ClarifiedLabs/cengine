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
MULTI_PLATFORM_IMAGE = "mirror.gcr.io/library/alpine:latest"
BUSYBOX = "busybox:latest"
REGISTRY_IMAGE = "registry@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
REGISTRY_AUTH = {"username": "compat", "password": "compat-password"}
REGISTRY_FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "Fixtures/registry"
KNOWN_GAP = pytest.mark.xfail(strict=True)


def platform_value(architecture: str, os_name: str = "linux") -> str:
    return json.dumps({"os": os_name, "architecture": architecture}, separators=(",", ":"))


def image_request(client: docker.DockerClient, path: str, *, params=None):
    response = client.api._get(client.api._url(path), params=params)
    return client.api._result(response, json=True)


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


@pytest.mark.compat("IMG-004")
def test_search_image(client: docker.DockerClient):
    results = image_request(
        client,
        "/images/search",
        params={
            "term": "library/alpine",
            "limit": 5,
            "filters": json.dumps({"is-official": ["true"], "stars": ["1"]}),
        },
    )
    assert 1 <= len(results) <= 5
    assert any("alpine" in item["name"].lower() for item in results)
    assert all(item["is_official"] is True for item in results)
    assert all(item["is_automated"] is False for item in results)
    assert all(item["star_count"] >= 1 for item in results)


@pytest.mark.compat("IMG-005")
def test_search_bogus_image(client: docker.DockerClient):
    with pytest.raises(errors.APIError) as caught:
        client.images.search("https://docker.io/library/alpine")
    assert caught.value.status_code == 400


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


@pytest.mark.compat("IMG-016")
def test_multi_platform_manifest_summary_preserves_local_variants(client: docker.DockerClient):
    images = image_request(client, "/images/json", params={"manifests": "true"})
    image = next(item for item in images if MULTI_PLATFORM_IMAGE in item["RepoTags"])
    assert image["Descriptor"]["mediaType"] in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
    variants = {
        (item.get("ImageData") or {}).get("Platform", {}).get("architecture"): item
        for item in image["Manifests"]
        if item["Kind"] == "image" and item["Available"]
    }
    assert {"arm64", "amd64"} <= variants.keys()
    assert all(item["ID"] == item["Descriptor"]["digest"] for item in variants.values())


@pytest.mark.compat("IMG-017")
def test_platform_specific_inspect_and_missing_platform(client: docker.DockerClient):
    amd64 = image_request(
        client, f"/images/{MULTI_PLATFORM_IMAGE}/json",
        params={"platform": platform_value("amd64")},
    )
    assert amd64["Architecture"] == "amd64"
    assert amd64["Os"] == "linux"
    response = client.api._get(
        client.api._url("/images/{0}/json", MULTI_PLATFORM_IMAGE),
        params={"platform": platform_value("amd64", "windows")},
    )
    with pytest.raises(errors.NotFound):
        client.api._raise_for_status(response)


@pytest.mark.compat("IMG-018")
def test_multi_platform_save_and_load_round_trip(client: docker.DockerClient):
    platforms = [
        ("platform", platform_value("arm64")),
        ("platform", platform_value("amd64")),
    ]
    response = client.api._get(
        client.api._url("/images/{0}/get", MULTI_PLATFORM_IMAGE), params=platforms,
    )
    client.api._raise_for_status(response)
    archive = response.content
    assert archive
    client.images.remove(MULTI_PLATFORM_IMAGE, force=True)
    load = client.api._post(
        client.api._url("/images/load"), params=platforms, data=archive,
        headers={"Content-Type": "application/x-tar"},
    )
    client.api._raise_for_status(load)
    for architecture in ("arm64", "amd64"):
        restored = image_request(
            client, f"/images/{MULTI_PLATFORM_IMAGE}/json",
            params={"platform": platform_value(architecture)},
        )
        assert restored["Architecture"] == architecture


@pytest.mark.compat("IMG-019")
def test_platform_selective_delete_retains_other_variant(client: docker.DockerClient):
    response = client.api._delete(
        client.api._url("/images/{0}", MULTI_PLATFORM_IMAGE),
        params={"force": "true", "platforms": platform_value("arm64")},
    )
    removed = client.api._result(response, json=True)
    assert any(item.get("Deleted") for item in removed)
    amd64 = image_request(
        client, f"/images/{MULTI_PLATFORM_IMAGE}/json",
        params={"platform": platform_value("amd64")},
    )
    assert amd64["Architecture"] == "amd64"
    missing = client.api._get(
        client.api._url("/images/{0}/json", MULTI_PLATFORM_IMAGE),
        params={"platform": platform_value("arm64")},
    )
    with pytest.raises(errors.NotFound):
        client.api._raise_for_status(missing)


@pytest.mark.compat("IMG-020")
def test_container_reports_selected_image_manifest_descriptor(client: docker.DockerClient):
    image = image_request(
        client, f"/images/{MULTI_PLATFORM_IMAGE}/json",
        params={"platform": platform_value("arm64")},
    )
    container = client.api.create_container(
        MULTI_PLATFORM_IMAGE, command=["echo", "descriptor"], platform="linux/arm64",
        name=f"compat-image-descriptor-{uuid.uuid4().hex[:8]}",
    )
    try:
        inspected = client.api.inspect_container(container["Id"])
        assert inspected["Image"] == image["Id"]
        assert inspected["ImageManifestDescriptor"]["digest"] != image["Descriptor"]["digest"]
        listed = next(item for item in client.api.containers(all=True) if item["Id"] == container["Id"])
        assert listed["ImageManifestDescriptor"] == inspected["ImageManifestDescriptor"]
    finally:
        client.api.remove_container(container["Id"], force=True)


@pytest.mark.compat("IMG-021")
def test_image_identity_records_trusted_pull_origin(client: docker.DockerClient):
    inspected = image_request(client, f"/images/{MULTI_PLATFORM_IMAGE}/json")
    repositories = {item["Repository"] for item in inspected["Identity"]["Pull"]}
    assert "mirror.gcr.io/library/alpine" in repositories
    listed = image_request(client, "/images/json", params={"identity": "true"})
    image = next(item for item in listed if MULTI_PLATFORM_IMAGE in item["RepoTags"])
    available = next(item for item in image["Manifests"] if item["Kind"] == "image" and item["Available"])
    assert {item["Repository"] for item in available["ImageData"]["Identity"]["Pull"]} == repositories


@pytest.mark.compat("IMG-022")
def test_image_attestations_support_filters_and_statement_opt_in(client: docker.DockerClient):
    metadata = image_request(
        client, f"/images/{MULTI_PLATFORM_IMAGE}/attestations",
        params={"platform": platform_value("arm64")},
    )
    assert metadata
    assert all("Descriptor" in item and "PredicateType" in item for item in metadata)
    assert all("Statement" not in item for item in metadata)
    predicate = metadata[0]["PredicateType"]
    statements = image_request(
        client, f"/images/{MULTI_PLATFORM_IMAGE}/attestations",
        params=[
            ("platform", platform_value("arm64")),
            ("type", predicate),
            ("statement", "true"),
        ],
    )
    assert statements
    assert all(item["PredicateType"] == predicate and isinstance(item["Statement"], dict) for item in statements)


@pytest.mark.compat("IMG-023")
def test_manifest_options_reject_conflicts_and_preserve_identity_after_retag(client: docker.DockerClient):
    conflict = client.api._get(
        client.api._url("/images/{0}/json", MULTI_PLATFORM_IMAGE),
        params={"manifests": "true", "platform": platform_value("arm64")},
    )
    with pytest.raises(errors.APIError) as raised:
        client.api._raise_for_status(conflict)
    assert raised.value.response.status_code == 400
    original = image_request(client, f"/images/{MULTI_PLATFORM_IMAGE}/json")["Identity"]
    alias = f"identity-retag-{uuid.uuid4().hex[:8]}:latest"
    assert client.images.get(MULTI_PLATFORM_IMAGE).tag(alias)
    assert image_request(client, f"/images/{alias}/json")["Identity"] == original
