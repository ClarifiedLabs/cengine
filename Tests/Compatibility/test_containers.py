"""Docker container API compatibility contracts, seeded from Podman's suite."""

from __future__ import annotations

import io
import os
import socket
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
GATEWAY_MODE_IPV4 = "com.docker.network.bridge.gateway_mode_ipv4"
GATEWAY_MODE_IPV6 = "com.docker.network.bridge.gateway_mode_ipv6"


def _network_container(client: docker.DockerClient, network, *, command="top"):
    container = client.containers.create(IMAGE, command=command, network=network.name)
    container.start()
    return container


def _gateway(network) -> str:
    network.reload()
    return next(config["Gateway"] for config in network.attrs["IPAM"]["Config"] if ":" not in config["Gateway"])


def _assert_peer_reachable(client: docker.DockerClient, network) -> None:
    server = _network_container(
        client, network,
        command=[
            "sh", "-c",
            "while true; do { printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 7\\r\\n\\r\\npeer-ok'; } | nc -l -p 8080; done",
        ],
    )
    server.reload()
    address = server.attrs["NetworkSettings"]["Networks"][network.name]["IPAddress"]
    peer = _network_container(client, network)
    code, output = peer.exec_run([
        "sh", "-c",
        f"for i in 1 2 3 4 5; do wget -qO- -T 2 http://{address}:8080 && exit 0; sleep 1; done; exit 1",
    ])
    assert (code, output) == (0, b"peer-ok")


def _host_http_request(container, gateway: str) -> tuple[int, bytes, bool]:
    accepted = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 0)); listener.listen(); listener.settimeout(4)
        port = listener.getsockname()[1]

        def serve() -> None:
            try:
                connection, _ = listener.accept()
                accepted.set()
                with connection:
                    connection.recv(4096)
                    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nhost-ok")
            except TimeoutError:
                pass

        server = threading.Thread(target=serve)
        server.start()
        code, output = container.exec_run([
            "sh", "-c", f"wget -qO- -T 2 http://{gateway}:{port}"
        ])
        server.join(timeout=5)
        assert not server.is_alive()
        return code, output, accepted.is_set()


def _can_reach_internet(container) -> bool:
    code, _ = container.exec_run(["sh", "-c", "nc -z -w 5 1.1.1.1 443"])
    return code == 0


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
    assert inspect["HostConfig"]["Memory"] == 1_073_741_824
    assert inspect["HostConfig"]["NanoCpus"] == 4_000_000_000


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


@pytest.mark.compat("CTR-029")
def test_follow_logs_streams_output_and_closes(client: docker.DockerClient):
    container = client.containers.create(
        IMAGE, command=["sh", "-c", "printf stdout-line; printf stderr-line >&2"]
    )
    container.start()
    output = b"".join(container.logs(stream=True, follow=True))
    assert b"stdout-line" in output
    assert b"stderr-line" in output


@pytest.mark.compat("CTR-030")
def test_streaming_stats_produces_multiple_samples(top):
    stream = top.stats(stream=True, decode=True)
    try:
        first = next(stream)
        second = next(stream)
    finally:
        stream.close()
    for sample in (first, second):
        assert sample["read"]
        assert "cpu_stats" in sample
        assert "memory_stats" in sample


@pytest.mark.compat("CTR-031")
def test_container_and_exec_tty_resize(client: docker.DockerClient):
    container = client.containers.create(IMAGE, command="top", tty=True)
    container.start()
    container.resize(height=40, width=120)
    exec_id = client.api.exec_create(container.id, ["sh", "-c", "sleep 10"], tty=True)["Id"]
    client.api.exec_start(exec_id, detach=True, tty=True)
    client.api.exec_resize(exec_id, height=50, width=140)


@pytest.mark.compat("CTR-032")
def test_log_time_tail_stream_and_timestamp_filters(client: docker.DockerClient):
    container = client.containers.create(
        IMAGE, command=["sh", "-c", "echo old; sleep 1; echo new; echo hidden >&2"]
    )
    container.start()
    time.sleep(0.4)
    since = time.time()
    assert container.wait(timeout=60)["StatusCode"] == 0
    output = container.logs(stdout=True, stderr=False, since=since, tail=1, timestamps=True)
    assert b"new" in output and b"old" not in output and b"hidden" not in output
    assert b"T" in output.split(b" ", 1)[0]

    following = client.containers.create(
        IMAGE, command=["sh", "-c", "sleep 1; echo followed; echo ignored >&2"]
    )
    following.start()
    streamed = b"".join(following.logs(
        stream=True, follow=True, stdout=True, stderr=False, tail=0, timestamps=True,
    ))
    assert b"followed" in streamed and b"ignored" not in streamed
    assert following.wait(timeout=60)["StatusCode"] == 0


@pytest.mark.compat("CTR-033")
def test_multiple_containers_stream_stats_concurrently(client: docker.DockerClient):
    containers = [client.containers.run(IMAGE, "top", detach=True) for _ in range(2)]
    samples: dict[str, list[dict]] = {}

    def collect(container) -> None:
        stream = container.stats(stream=True, decode=True)
        try:
            samples[container.id] = [next(stream), next(stream)]
        finally:
            stream.close()

    readers = [threading.Thread(target=collect, args=(container,)) for container in containers]
    for reader in readers:
        reader.start()
    for reader in readers:
        reader.join(timeout=15)
    assert all(not reader.is_alive() for reader in readers)
    assert all(len(values) == 2 for values in samples.values())


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


@pytest.mark.compat("NET-003")
def test_create_container_on_network(client: docker.DockerClient):
    network = client.networks.create(f"compat-{uuid.uuid4().hex[:8]}")
    container = client.containers.create(IMAGE, command="top", network=network.name)
    container.reload()
    assert network.name in container.attrs["NetworkSettings"]["Networks"]


@pytest.mark.compat("NET-004")
def test_udp_port_forwarding(client: docker.DockerClient):
    container = client.containers.create(
        IMAGE,
        command=["sh", "-c", "while true; do printf udp-ok | nc -u -l -p 1234; done"],
        ports={"1234/udp": ("127.0.0.1", None)},
    )
    container.start(); container.reload()
    binding = container.attrs["NetworkSettings"]["Ports"]["1234/udp"][0]
    address = (binding["HostIp"], int(binding["HostPort"]))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as value:
        value.settimeout(1)
        deadline = time.monotonic() + 10
        while True:
            value.sendto(b"ping", address)
            try:
                payload, _ = value.recvfrom(1024)
                assert payload == b"udp-ok"
                break
            except TimeoutError:
                if time.monotonic() >= deadline:
                    raise


@pytest.mark.compat("NET-005")
def test_occupied_host_port_returns_server_error(client: docker.DockerClient):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0)); listener.listen()
        port = listener.getsockname()[1]
        container = client.containers.create(
            IMAGE, command="top", ports={"1234/tcp": ("127.0.0.1", port)}
        )
        with pytest.raises(errors.APIError) as caught:
            container.start()
        assert caught.value.response.status_code == 500


@pytest.mark.compat("NET-006")
def test_concurrent_random_port_allocation_is_unique(client: docker.DockerClient):
    containers = [
        client.containers.create(IMAGE, command="top", ports={"8080/tcp": ("127.0.0.1", None)})
        for _ in range(8)
    ]
    failures: list[Exception] = []

    def start(container) -> None:
        try:
            container.start()
        except Exception as error:
            failures.append(error)

    starters = [threading.Thread(target=start, args=(container,)) for container in containers]
    for starter in starters:
        starter.start()
    for starter in starters:
        starter.join(timeout=60)
    assert not failures
    for container in containers:
        container.reload()
    ports = [container.attrs["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"] for container in containers]
    assert len(set(ports)) == len(containers)


@pytest.mark.compat("NET-008")
def test_bridge_network_allows_peers_host_and_internet(client: docker.DockerClient):
    network = client.networks.create(f"compat-normal-{uuid.uuid4().hex[:8]}")
    _assert_peer_reachable(client, network)
    container = _network_container(client, network)
    assert _host_http_request(container, _gateway(network)) == (0, b"host-ok", True)
    assert _can_reach_internet(container)


@pytest.mark.compat("NET-009")
def test_internal_network_allows_peers_and_host_but_not_internet(client: docker.DockerClient):
    network = client.networks.create(f"compat-internal-{uuid.uuid4().hex[:8]}", internal=True)
    _assert_peer_reachable(client, network)
    container = _network_container(client, network)
    assert _host_http_request(container, _gateway(network)) == (0, b"host-ok", True)
    assert not _can_reach_internet(container)


@pytest.mark.compat("NET-010")
def test_isolated_gateway_allows_only_network_peers(client: docker.DockerClient):
    network = client.networks.create(
        f"compat-isolated-{uuid.uuid4().hex[:8]}", internal=True,
        options={GATEWAY_MODE_IPV4: "isolated", GATEWAY_MODE_IPV6: "isolated"},
    )
    _assert_peer_reachable(client, network)
    container = _network_container(client, network)
    code, _, accepted = _host_http_request(container, _gateway(network))
    assert code != 0 and not accepted
    assert not _can_reach_internet(container)


@pytest.mark.compat("NET-011")
def test_isolated_gateway_options_round_trip_and_require_internal(client: docker.DockerClient):
    with pytest.raises(errors.APIError) as caught:
        client.networks.create(
            f"compat-invalid-isolated-{uuid.uuid4().hex[:8]}",
            options={GATEWAY_MODE_IPV4: "isolated"},
        )
    assert caught.value.response.status_code == 400
    network = client.networks.create(
        f"compat-isolated-options-{uuid.uuid4().hex[:8]}", internal=True,
        options={GATEWAY_MODE_IPV4: "isolated"},
    )
    network.reload()
    assert network.attrs["Internal"] is True
    assert network.attrs["Options"][GATEWAY_MODE_IPV4] == "isolated"


@pytest.mark.compat("NET-012")
def test_isolated_gateway_filter_cannot_be_bypassed_by_adding_a_route(client: docker.DockerClient):
    network = client.networks.create(
        f"compat-isolated-route-{uuid.uuid4().hex[:8]}", internal=True,
        options={GATEWAY_MODE_IPV4: "isolated"},
    )
    container = client.containers.create(IMAGE, command="top", network=network.name, privileged=True)
    container.start()
    gateway = _gateway(network)
    code, output = container.exec_run(
        ["sh", "-c", f"ip route add default via {gateway}; ip route"], privileged=True
    )
    assert code == 0 and gateway.encode() in output
    code, _, accepted = _host_http_request(container, gateway)
    assert code != 0 and not accepted
    assert not _can_reach_internet(container)


@pytest.mark.compat("CTR-034")
def test_network_none_has_only_loopback(client: docker.DockerClient):
    container = client.containers.create(IMAGE, command="top", network_mode="none")
    container.start(); container.reload()
    code, links = container.exec_run(["sh", "-c", "ls /sys/class/net"])
    assert code == 0 and links.split() == [b"lo"]
    code, routes = container.exec_run(["sh", "-c", "ip route show"])
    assert code == 0 and routes.strip() == b""
    assert container.attrs["HostConfig"]["NetworkMode"] == "none"
    assert container.attrs["NetworkSettings"]["Networks"] == {}


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
