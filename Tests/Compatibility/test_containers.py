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

from harness import docker_environment


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
KNOWN_GAP = pytest.mark.xfail(strict=True)
GATEWAY_MODE_IPV4 = "com.docker.network.bridge.gateway_mode_ipv4"
GATEWAY_MODE_IPV6 = "com.docker.network.bridge.gateway_mode_ipv6"
ENDPOINT_SYSCTLS = "com.docker.network.endpoint.sysctls"


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
    result = subprocess.run(
        ["docker", "stats", "--no-stream", "--format", "{{.ID}}", top.id],
        env=docker_environment(daemon["socket"]), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15,
    )
    assert result.returncode == 0 and result.stdout.strip() == top.id[:12]


@pytest.mark.compat("CTR-028")
def test_top_and_update(client: docker.DockerClient, top):
    processes = top.top(ps_args="-ef")
    assert processes["Titles"] and processes["Processes"]
    top.reload()
    started_at = top.attrs["State"]["StartedAt"]
    code, boot_id = top.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
    assert code == 0
    warnings = top.update(
        mem_limit="64m", cpu_quota=200_000, cpu_period=100_000,
        restart_policy={"Name": "always"},
    )
    assert warnings == {"Warnings": []} or warnings == []
    top.reload()
    code, limits = top.exec_run([
        "sh", "-c", "cat /sys/fs/cgroup/memory.max; cat /sys/fs/cgroup/cpu.max",
    ])
    assert code == 0, limits
    code, updated_boot_id = top.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
    assert code == 0
    assert top.attrs["HostConfig"]["Memory"] == 64 * 1024 * 1024
    assert top.attrs["HostConfig"]["NanoCpus"] == 2_000_000_000
    assert top.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
    assert top.attrs["State"]["StartedAt"] == started_at
    assert updated_boot_id == boot_id
    assert limits.splitlines() == [b"67108864", b"200000 100000"]


@pytest.mark.compat("CTR-041")
def test_restart_policy_update_preserves_running_vm(top):
    top.reload()
    started_at = top.attrs["State"]["StartedAt"]
    code, boot_id = top.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
    assert code == 0

    warnings = top.update(restart_policy={"Name": "unless-stopped"})
    assert warnings == {"Warnings": []} or warnings == []
    top.reload()
    code, updated_boot_id = top.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])

    assert code == 0
    assert top.status == "running"
    assert top.attrs["State"]["StartedAt"] == started_at
    assert updated_boot_id == boot_id
    assert top.attrs["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"


@pytest.mark.compat("CTR-042")
def test_live_resource_update_rejects_limits_above_vm_capacity(top):
    top.reload()
    memory = top.attrs["HostConfig"]["Memory"]
    started_at = top.attrs["State"]["StartedAt"]
    code, boot_id = top.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
    assert code == 0

    with pytest.raises(errors.APIError) as caught:
        top.update(mem_limit="2g")

    assert caught.value.response.status_code == 409
    top.reload()
    code, updated_boot_id = top.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
    assert code == 0
    assert top.status == "running"
    assert top.attrs["HostConfig"]["Memory"] == memory
    assert top.attrs["State"]["StartedAt"] == started_at
    assert updated_boot_id == boot_id


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


@pytest.mark.compat("NET-013")
def test_creating_container_preserves_existing_network_connectivity(client: docker.DockerClient):
    network = client.networks.get("default")
    container = _network_container(client, network)
    gateway = _gateway(network)
    assert _host_http_request(container, gateway) == (0, b"host-ok", True)

    client.containers.create(IMAGE, command="true")
    time.sleep(0.5)

    for _ in range(3):
        assert _host_http_request(container, gateway) == (0, b"host-ok", True)
    code, _ = container.exec_run([
        "sh", "-c", "nslookup registry-1.docker.io >/dev/null && nc -z -w 5 1.1.1.1 443",
    ])
    assert code == 0


@pytest.mark.compat("NET-014")
def test_explicit_endpoint_mac_address_is_applied_and_survives_recovery(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-mac-{suffix}")
    mac = "02:42:ac:11:00:42"
    container = client.containers.create(
        IMAGE, command="top", name=f"mac-{suffix}", network=network.name,
        networking_config={
            network.name: client.api.create_endpoint_config(mac_address=mac),
        },
    )
    container.start(); container.reload()
    assert container.attrs["NetworkSettings"]["Networks"][network.name]["MacAddress"] == mac
    code, address = container.exec_run(["cat", "/sys/class/net/eth0/address"])
    assert (code, address.strip()) == (0, mac.encode())

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        deadline = time.monotonic() + 30
        while True:
            value = recovered.containers.get(container.name)
            value.reload()
            if value.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"container with explicit MAC did not recover: {value.attrs['State']}")
            time.sleep(0.2)
        assert value.attrs["NetworkSettings"]["Networks"][network.name]["MacAddress"] == mac
        code, address = value.exec_run(["cat", "/sys/class/net/eth0/address"])
        assert (code, address.strip()) == (0, mac.encode())
    finally:
        recovered.close()


@pytest.mark.compat("NET-015")
def test_invalid_and_duplicate_endpoint_mac_addresses_are_rejected(client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-mac-invalid-{suffix}")
    with pytest.raises(errors.APIError) as malformed:
        client.containers.create(
            IMAGE, command="top", network=network.name,
            networking_config={network.name: client.api.create_endpoint_config(mac_address="not-a-mac")},
        )
    assert malformed.value.response.status_code == 400
    with pytest.raises(errors.APIError) as multicast:
        client.containers.create(
            IMAGE, command="top", network=network.name,
            networking_config={network.name: client.api.create_endpoint_config(mac_address="03:42:ac:11:00:02")},
        )
    assert multicast.value.response.status_code == 400

    mac = "02:42:ac:11:00:55"
    client.containers.create(
        IMAGE, command="top", network=network.name,
        networking_config={network.name: client.api.create_endpoint_config(mac_address=mac)},
    )
    with pytest.raises(errors.APIError) as duplicate:
        client.containers.create(
            IMAGE, command="top", network=network.name,
            networking_config={network.name: client.api.create_endpoint_config(mac_address=mac)},
        )
    assert duplicate.value.response.status_code == 409

    other = client.networks.create(f"compat-mac-connect-{suffix}")
    connected = client.containers.create(IMAGE, command="top")
    connect_mac = "02:42:ac:11:00:56"
    other.connect(connected, mac_address=connect_mac)
    connected.reload()
    assert connected.attrs["NetworkSettings"]["Networks"][other.name]["MacAddress"] == connect_mac
    collision = client.containers.create(IMAGE, command="top")
    with pytest.raises(errors.APIError) as duplicate_connect:
        other.connect(collision, mac_address=connect_mac)
    assert duplicate_connect.value.response.status_code == 409


def _connect_with_gateway_priority(client, network_id, container_id, priority, alias):
    # docker-py 7.2.0 has no gw_priority argument, so post the endpoint directly.
    response = client.api._post_json(
        client.api._url("/networks/{0}/connect", network_id),
        data={
            "Container": container_id,
            "EndpointConfig": {"Aliases": [alias], "GwPriority": priority},
        },
    )
    client.api._raise_for_status(response)


@pytest.mark.compat("NET-016")
def test_gateway_priority_selects_default_route_and_survives_recovery(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    low = client.networks.create(f"compat-gw-low-{suffix}")
    high = client.networks.create(f"compat-gw-high-{suffix}")
    container = client.containers.create(IMAGE, command="top", name=f"gw-{suffix}")
    _connect_with_gateway_priority(client, low.id, container.id, 10, "low")
    _connect_with_gateway_priority(client, high.id, container.id, 100, "high")
    container.start(); container.reload()

    networks = container.attrs["NetworkSettings"]["Networks"]
    assert networks[high.name]["GwPriority"] == 100
    assert networks[low.name]["GwPriority"] == 10
    high_gateway = _gateway(high)
    low_gateway = _gateway(low)

    def default_route() -> bytes:
        code, output = container.exec_run(["sh", "-c", "ip route show default"])
        assert code == 0, output
        return output

    assert high_gateway.encode() in default_route()
    assert low_gateway.encode() not in default_route()

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        deadline = time.monotonic() + 30
        while True:
            value = recovered.containers.get(container.name)
            value.reload()
            if value.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"container did not recover: {value.attrs['State']}")
            time.sleep(0.2)
        assert value.attrs["NetworkSettings"]["Networks"][high.name]["GwPriority"] == 100
        code, output = value.exec_run(["sh", "-c", "ip route show default"])
        assert code == 0 and high_gateway.encode() in output
    finally:
        recovered.close()


@pytest.mark.compat("NET-017")
def test_publishing_sctp_port_is_rejected_as_intentional_gap(client: docker.DockerClient):
    with pytest.raises(errors.APIError) as caught:
        client.containers.create(IMAGE, command="top", ports={"132/sctp": ("127.0.0.1", None)})
    assert caught.value.response.status_code == 400
    # TCP and UDP publishing on the same container still succeeds.
    container = client.containers.create(
        IMAGE, command="top", ports={"80/tcp": ("127.0.0.1", None), "90/udp": ("127.0.0.1", None)},
    )
    container.start(); container.reload()
    published = container.attrs["NetworkSettings"]["Ports"]
    assert published["80/tcp"] and published["90/udp"]


@pytest.mark.compat("NET-018")
def test_explicit_network_address_families_apply_and_survive_recovery(
    daemon, client: docker.DockerClient
):
    suffix = uuid.uuid4().hex[:8]
    name = f"compat-v6-only-{suffix}"
    response = client.api._post_json(
        client.api._url("/networks/create"),
        data={
            "Name": name,
            "EnableIPv4": False,
            "EnableIPv6": True,
            "IPAM": {"Config": [{"Subnet": "fd00:18::/120", "Gateway": "fd00:18::1"}]},
        },
    )
    client.api._raise_for_status(response)
    network = client.networks.get(response.json()["Id"])
    container = client.containers.create(IMAGE, command="top", name=f"v6-only-{suffix}", network=name)
    container.start(); container.reload(); network.reload()
    assert network.attrs["EnableIPv4"] is False
    assert network.attrs["EnableIPv6"] is True
    assert [config["Subnet"] for config in network.attrs["IPAM"]["Config"]] == ["fd00:18::/120"]
    endpoint = container.attrs["NetworkSettings"]["Networks"][name]
    assert endpoint["IPAddress"] == ""
    assert endpoint["GlobalIPv6Address"].startswith("fd00:18::")
    code, addresses = container.exec_run(["sh", "-c", "ip -o -4 addr show dev eth0; ip -o -6 addr show dev eth0"])
    assert code == 0 and b" inet " not in addresses and b" inet6 fd00:18::" in addresses

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        deadline = time.monotonic() + 30
        while True:
            value = recovered.containers.get(container.name)
            value.reload()
            if value.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"IPv6-only container did not recover: {value.attrs['State']}")
            time.sleep(0.2)
        endpoint = value.attrs["NetworkSettings"]["Networks"][name]
        assert endpoint["IPAddress"] == ""
        assert endpoint["GlobalIPv6Address"].startswith("fd00:18::")
        recovered_network = recovered.networks.get(name)
        assert recovered_network.attrs["EnableIPv4"] is False
        assert recovered_network.attrs["EnableIPv6"] is True
        peer = recovered.containers.create(
            IMAGE, command="top", name=f"v6-peer-{suffix}", network=name
        )
        peer.start()
        code, hosts = peer.exec_run(["getent", "hosts", container.name])
        assert code == 0 and b"fd00:18::" in hosts
    finally:
        recovered.close()


@pytest.mark.compat("NET-019")
def test_endpoint_sysctls_apply_validate_and_survive_recovery(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-sysctl-{suffix}")
    name = f"sysctl-{suffix}"
    settings = "net.ipv4.conf.IFNAME.forwarding=1,net.ipv4.conf.ifname.log_martians=1"
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": name},
        data={
            "Image": IMAGE,
            "Cmd": ["top"],
            "NetworkingConfig": {"EndpointsConfig": {network.name: {"DriverOpts": {ENDPOINT_SYSCTLS: settings}}}},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    container.start(); container.reload()
    endpoint = container.attrs["NetworkSettings"]["Networks"][network.name]
    assert endpoint["DriverOpts"][ENDPOINT_SYSCTLS] == settings
    code, values = container.exec_run([
        "sh", "-c", "cat /proc/sys/net/ipv4/conf/eth0/forwarding /proc/sys/net/ipv4/conf/eth0/log_martians",
    ])
    assert (code, values.split()) == (0, [b"1", b"1"])

    invalid = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"invalid-sysctl-{suffix}"},
        data={
            "Image": IMAGE,
            "NetworkingConfig": {"EndpointsConfig": {network.name: {
                "DriverOpts": {ENDPOINT_SYSCTLS: "net.ipv4.conf.eth0.forwarding=1"},
            }}},
        },
    )
    assert invalid.status_code == 400

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        deadline = time.monotonic() + 30
        while True:
            value = recovered.containers.get(name)
            value.reload()
            if value.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"sysctl container did not recover: {value.attrs['State']}")
            time.sleep(0.2)
        code, values = value.exec_run([
            "sh", "-c", "cat /proc/sys/net/ipv4/conf/eth0/forwarding /proc/sys/net/ipv4/conf/eth0/log_martians",
        ])
        assert (code, values.split()) == (0, [b"1", b"1"])
    finally:
        recovered.close()


@pytest.mark.compat("NET-020")
def test_network_ipam_status_tracks_allocations_and_api_version(client: docker.DockerClient, daemon):
    suffix = uuid.uuid4().hex[:8]
    name = f"compat-ipam-status-{suffix}"
    response = client.api._post_json(
        client.api._url("/networks/create"),
        data={"Name": name, "IPAM": {"Config": [{"Subnet": "10.20.30.2/29", "Gateway": "10.20.30.1"}]}},
    )
    client.api._raise_for_status(response)
    container = client.containers.create(IMAGE, command="top", network=name)
    network = client.networks.get(name)
    network.reload()
    status = network.attrs["Status"]["IPAM"]["Subnets"]["10.20.30.2/29"]
    assert status == {"IPsInUse": 4, "DynamicIPsAvailable": 4}

    legacy = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="1.51")
    try:
        assert "Status" not in legacy.networks.get(name).attrs
    finally:
        legacy.close()


@pytest.mark.compat("NET-021")
def test_network_prune_filters_limit_deleted_networks(client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    selected = client.networks.create(f"prune-selected-{suffix}", labels={"project": "selected"})
    retained = client.networks.create(f"prune-retained-{suffix}", labels={"project": "retained"})
    with pytest.raises(errors.APIError) as invalid:
        client.api.prune_networks(filters={"label": [""]})
    assert invalid.value.response.status_code == 400
    selected.reload(); retained.reload()
    result = client.api.prune_networks(filters={"label": ["project=selected"]})
    assert result["NetworksDeleted"] == [selected.name]
    with pytest.raises(errors.NotFound):
        client.networks.get(selected.id)
    retained.reload()


@pytest.mark.compat("NET-022")
def test_network_ipam_and_family_validation_is_explicit(
    client: docker.DockerClient, daemon,
):
    suffix = uuid.uuid4().hex[:8]
    unsupported = [
        {
            "Name": f"aux-{suffix}",
            "IPAM": {"Config": [{
                "Subnet": "10.210.0.0/24",
                "AuxiliaryAddresses": {"reserved": "10.210.0.10"},
            }]},
        },
        {
            "Name": f"multi-{suffix}",
            "IPAM": {"Config": [
                {"Subnet": "10.211.0.0/24"},
                {"Subnet": "10.212.0.0/24"},
            ]},
        },
        {
            "Name": f"custom-v6-{suffix}",
            "EnableIPv6": True,
            "IPAM": {"Config": [{
                "Subnet": "fd00:22::/64",
                "Gateway": "fd00:22::fe",
            }]},
        },
        {
            "Name": f"asymmetric-{suffix}",
            "Internal": True,
            "EnableIPv6": True,
            "Options": {GATEWAY_MODE_IPV4: "isolated"},
        },
    ]
    for request in unsupported:
        response = client.api._post_json(client.api._url("/networks/create"), data=request)
        assert response.status_code == 501, response.text

    disabled = client.api._post_json(
        client.api._url("/networks/create"),
        data={"Name": f"disabled-{suffix}", "EnableIPv4": False, "EnableIPv6": False},
    )
    assert disabled.status_code == 400

    legacy = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="1.47")
    try:
        response = legacy.api._post_json(
            legacy.api._url("/networks/create"),
            data={"Name": f"legacy-ipv4-{suffix}", "EnableIPv4": False},
        )
        legacy.api._raise_for_status(response)
        network = client.networks.get(response.json()["Id"])
        network.reload()
        assert network.attrs["EnableIPv4"] is True
        network.remove()
    finally:
        legacy.close()


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
