"""Docker container API compatibility contracts, seeded from Podman's suite."""

from __future__ import annotations

import io
import os
import tarfile
import threading
import time
import uuid

import docker
import pytest
from docker import errors
from docker.types import Mount


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
KNOWN_GAP = pytest.mark.xfail(strict=True)


@pytest.mark.compat("CTR-001")
def test_create_container(client: docker.DockerClient, top):
    client.containers.create(image=IMAGE, detach=True)
    assert len(client.containers.list(all=True)) == 2


@pytest.mark.compat("CTR-002")
def test_create_network(client: docker.DockerClient, top):
    client.networks.create(
        f"compat-{uuid.uuid4().hex[:8]}", driver="bridge", labels={"dev.cengine.compat": "true"}
    )
    client.containers.create(image=IMAGE, detach=True)


@pytest.mark.compat("CTR-003")
def test_start_container(client: docker.DockerClient, top):
    client.containers.create(image=IMAGE, name=f"container-{uuid.uuid4().hex[:8]}")
    assert len(client.containers.list(all=True)) == 2


@pytest.mark.compat("CTR-004")
def test_start_container_with_random_port_bind(client: docker.DockerClient, top):
    container = client.containers.create(image=IMAGE, ports={"1234/tcp": None})
    container.start(); container.reload()
    bindings = container.attrs["NetworkSettings"]["Ports"]["1234/tcp"]
    assert bindings and int(bindings[0]["HostPort"]) > 0


@pytest.mark.compat("CTR-005")
def test_stop_container(top):
    top.stop(); top.reload()
    assert top.status in ("stopped", "exited")


@pytest.mark.compat("CTR-006")
def test_kill_container(top):
    top.kill(); top.reload()
    assert top.status in ("stopped", "exited")


@pytest.mark.compat("CTR-007")
def test_restart_container(top):
    top.stop(); top.restart(); top.reload()
    assert top.status == "running"


@pytest.mark.compat("CTR-008")
def test_remove_container(client: docker.DockerClient, top):
    top.remove(force=True)
    assert client.containers.list() == []


@pytest.mark.compat("CTR-009")
def test_remove_container_without_force(client: docker.DockerClient, top):
    with pytest.raises(errors.APIError) as caught:
        top.remove()
    assert caught.value.response.status_code == 409
    top.stop(); top.remove()
    assert client.containers.list() == []


@pytest.mark.compat("CTR-010")
def test_pause_container(top):
    top.pause(); top.reload()
    assert top.status == "paused"


@pytest.mark.compat("CTR-011")
def test_pause_stopped_container(top):
    top.stop()
    with pytest.raises(errors.APIError) as caught:
        top.pause()
    assert caught.value.response.status_code == 409


@pytest.mark.compat("CTR-012")
def test_unpause_container(top):
    top.pause(); top.unpause(); top.reload()
    assert top.status == "running"


@pytest.mark.compat("CTR-013")
def test_list_container(client: docker.DockerClient, top):
    client.containers.create(image=IMAGE, detach=True)
    assert len(client.containers.list(all=True)) == 2


@pytest.mark.compat("CTR-014")
def test_filters(client: docker.DockerClient, top):
    assert client.containers.list(all=True, filters={"id": top.id}) == [top]
    assert client.containers.list(all=True, filters={"name": top.name}) == [top]


@pytest.mark.compat("CTR-015")
def test_copy_to_container(client: docker.DockerClient, top):
    content = b"Hello World!"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:") as value:
        info = tarfile.TarInfo("a.txt")
        info.uid = 1042; info.gid = 1043; info.mode = 0o644; info.size = len(content)
        value.addfile(info, io.BytesIO(content))
    archive.seek(0); top.put_archive("/tmp/", archive)
    code, output = top.exec_run(["stat", "-c", "%u:%g", "/tmp/a.txt"])
    assert (code, output.rstrip()) == (0, b"1042:1043")
    code, output = top.exec_run(["cat", "/tmp/a.txt"])
    assert (code, output.rstrip()) == (0, content)


@KNOWN_GAP(reason="CTR-016: direct docker build is intentionally unsupported; use Buildx")
@pytest.mark.compat("CTR-016")
def test_mount_preexisting_dir(client: docker.DockerClient, top):
    dockerfile = b"FROM alpine:latest\nRUN mkdir -p /workspace && chown 1042:1043 /workspace"
    image, _ = client.images.build(fileobj=io.BytesIO(dockerfile))
    container = client.containers.create(image=image.id, command="top", volumes={"compat-preexisting": {"bind": "/workspace"}})
    container.start()
    _, output = container.exec_run(["stat", "-c", "%u:%g", "/workspace"])
    assert output.rstrip() == b"1042:1043"


@KNOWN_GAP(reason="CTR-017: direct docker build is intentionally unsupported; use Buildx")
@pytest.mark.compat("CTR-017")
def test_non_existent_workdir(client: docker.DockerClient, top):
    dockerfile = b"FROM alpine:latest\nWORKDIR /workspace/scratch\nRUN touch test"
    image, _ = client.images.build(fileobj=io.BytesIO(dockerfile))
    container = client.containers.create(image=image.id, command="top", volumes={"compat-workdir": {"bind": "/workspace"}})
    container.start()
    code, _ = container.exec_run(["stat", "/workspace/scratch/test"])
    assert code == 0


@KNOWN_GAP(reason="CTR-018: direct docker build is intentionally unsupported; use Buildx")
@pytest.mark.compat("CTR-018")
def test_build_pull(client: docker.DockerClient, top):
    dockerfile = b"FROM alpine:latest\nUSER 1000:1000\n"
    _, logs = client.images.build(fileobj=io.BytesIO(dockerfile), pull=True)
    assert any("pull" in entry.get("stream", "").lower() for entry in logs)


@pytest.mark.compat("CTR-019")
def test_mount_options_by_default(client: docker.DockerClient, top):
    volume = client.volumes.create("compat-volume", labels={"dev.cengine.compat": "true"})
    container = client.containers.create(
        image=IMAGE, command="top", mounts=[Mount(target="/vol-mnt", source=volume.name, type="volume")]
    )
    inspect = client.api.inspect_container(container.id)
    assert inspect["HostConfig"]["Binds"] == ["compat-volume:/vol-mnt"]
    assert inspect["Mounts"][0]["Destination"] == "/vol-mnt"


@pytest.mark.compat("CTR-020")
def test_wait_next_exit(client: docker.DockerClient, top):
    container = client.containers.create(image=IMAGE, command=["true"])
    result: list[dict] = []
    waiter = threading.Thread(target=lambda: result.append(container.wait(condition="next-exit", timeout=180)))
    waiter.start(); time.sleep(0.5)
    assert waiter.is_alive(), "next-exit returned before the next start"
    container.start(); waiter.join(timeout=180)
    assert not waiter.is_alive() and result[0]["StatusCode"] == 0


@pytest.mark.compat("CTR-021")
def test_container_inspect_compatibility(client: docker.DockerClient, top):
    inspect = client.api.inspect_container(top.id)
    required_host_config = {"Binds", "Mounts", "PortBindings", "LogConfig", "NetworkMode"}
    assert required_host_config <= inspect["HostConfig"].keys()
    assert {"Id", "Name", "State", "Config", "HostConfig", "Mounts", "NetworkSettings"} <= inspect.keys()


@pytest.mark.compat("CTR-022")
def test_rename_container(client: docker.DockerClient):
    container = client.containers.create(image=IMAGE, name=f"before-{uuid.uuid4().hex[:8]}")
    renamed = f"after-{uuid.uuid4().hex[:8]}"
    container.rename(renamed)
    container.reload()
    assert container.name == renamed
    assert client.containers.get(renamed).id == container.id


@pytest.mark.compat("CTR-023")
def test_rename_container_name_conflict(client: docker.DockerClient):
    first = client.containers.create(image=IMAGE, name=f"first-{uuid.uuid4().hex[:8]}")
    second = client.containers.create(image=IMAGE, name=f"second-{uuid.uuid4().hex[:8]}")
    with pytest.raises(errors.APIError) as caught:
        second.rename(first.name)
    assert caught.value.response.status_code == 409
