"""Docker container API compatibility contracts, seeded from Podman's suite."""

from __future__ import annotations

import io
import os
import subprocess
import tarfile
import threading
import time
import urllib.request
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
    network = client.networks.create(
        f"compat-{uuid.uuid4().hex[:8]}", driver="bridge", labels={"dev.cengine.compat": "true"}
    )
    network.reload()
    assert network.attrs["Driver"] == "bridge"
    assert network.attrs["Labels"]["dev.cengine.compat"] == "true"


@pytest.mark.compat("CTR-003")
def test_start_container(client: docker.DockerClient, top):
    container = client.containers.create(image=IMAGE, command="top", name=f"container-{uuid.uuid4().hex[:8]}")
    container.start(); container.reload()
    assert container.status == "running"


@pytest.mark.compat("CTR-004")
def test_start_container_with_random_port_bind(client: docker.DockerClient, top):
    container = client.containers.create(
        image=IMAGE,
        command=["sh", "-c", "while true; do { echo -e 'HTTP/1.1 200 OK\\r\\nContent-Length: 9\\r\\n\\r\\nreachable'; } | nc -l -p 1234; done"],
        ports={"1234/tcp": ("127.0.0.1", None)},
    )
    container.start(); container.reload()
    bindings = container.attrs["NetworkSettings"]["Ports"]["1234/tcp"]
    assert bindings and int(bindings[0]["HostPort"]) > 0
    url = f"http://127.0.0.1:{bindings[0]['HostPort']}"
    deadline = time.monotonic() + 10
    while True:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                assert response.read() == b"reachable"
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


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


@pytest.mark.compat("CTR-024")
def test_exec_attached_output_and_exit_code(client: docker.DockerClient, top):
    result = top.exec_run(["sh", "-c", "printf stdout; printf stderr >&2; exit 23"], demux=True)
    assert result.exit_code == 23
    assert result.output == (b"stdout", b"stderr")


@pytest.mark.compat("CTR-025")
def test_copy_from_container_round_trip(client: docker.DockerClient, top):
    top.exec_run(["sh", "-c", "printf archive-roundtrip >/tmp/from-container.txt"])
    stream, stat = top.get_archive("/tmp/from-container.txt")
    archive = io.BytesIO(b"".join(stream))
    with tarfile.open(fileobj=archive, mode="r:") as value:
        member = next(member for member in value.getmembers() if member.isfile())
        extracted = value.extractfile(member)
        assert extracted is not None and extracted.read() == b"archive-roundtrip"
    assert stat["name"] == "from-container.txt"


@pytest.mark.compat("CTR-026")
def test_container_configuration_round_trip(client: docker.DockerClient):
    container = client.containers.create(
        IMAGE, command=["sh", "-c", "sleep 300"], environment={"COMPAT_VALUE": "roundtrip"},
        working_dir="/tmp", user="0:0", read_only=True, labels={"dev.cengine.compat": "true"},
        restart_policy={"Name": "on-failure", "MaximumRetryCount": 2},
    )
    inspect = client.api.inspect_container(container.id)
    assert "COMPAT_VALUE=roundtrip" in inspect["Config"]["Env"]
    assert inspect["Config"]["WorkingDir"] == "/tmp"
    assert inspect["Config"]["User"] == "0:0"
    assert inspect["HostConfig"]["ReadonlyRootfs"] is True
    assert inspect["HostConfig"]["RestartPolicy"] == {"Name": "on-failure", "MaximumRetryCount": 2}


@pytest.mark.compat("CTR-027")
def test_container_stats_complete(daemon, top):
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = f"unix://{daemon['socket']}"
    result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.ID}}", top.id],
        env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
    )
    assert result.returncode == 0 and result.stdout.strip() == top.id[:12]


@pytest.mark.compat("CTR-028")
def test_top_and_update(client: docker.DockerClient, top):
    processes = top.top(ps_args="-ef")
    assert processes["Titles"] and processes["Processes"]
    warnings = top.update(mem_limit="64m", restart_policy={"Name": "always"})
    assert warnings == {"Warnings": []} or warnings == []
    top.reload()
    assert top.attrs["HostConfig"]["Memory"] == 64 * 1024 * 1024
    assert top.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"


@pytest.mark.compat("NET-002")
def test_network_connect_disconnect(client: docker.DockerClient):
    first = client.networks.create(f"compat-{uuid.uuid4().hex[:8]}")
    second = client.networks.create(f"compat-{uuid.uuid4().hex[:8]}")
    container = client.containers.create(IMAGE, command="top")
    first.connect(container, aliases=["primary-alias"])
    second.connect(container, aliases=["secondary-alias"])
    container.reload()
    assert {first.name, second.name} <= set(container.attrs["NetworkSettings"]["Networks"])
    second.disconnect(container)
    container.reload()
    assert first.name in container.attrs["NetworkSettings"]["Networks"]
    assert second.name not in container.attrs["NetworkSettings"]["Networks"]


@KNOWN_GAP(reason="NET-003: docker-py network= create requests with an empty endpoint object return HTTP 500")
@pytest.mark.compat("NET-003")
def test_create_container_on_network(client: docker.DockerClient):
    network = client.networks.create(f"compat-{uuid.uuid4().hex[:8]}")
    container = client.containers.create(IMAGE, command="top", network=network.name)
    container.reload()
    assert network.name in container.attrs["NetworkSettings"]["Networks"]


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
