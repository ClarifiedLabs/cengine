"""VM-backed daemon persistence and recovery contracts."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import uuid

import docker
import pytest
from docker.types import Mount


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


@pytest.mark.compat("REC-001")
def test_daemon_restart_recovers_resources_and_restart_policy(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-recovery-{suffix}")
    volume = client.volumes.create(
        f"compat-recovery-{suffix}", labels={"dev.cengine.compat": "true"}
    )
    container = client.containers.create(
        IMAGE, command="top", name=f"recovery-{suffix}",
        mounts=[Mount(target="/data", source=volume.name, type="volume")],
        restart_policy={"Name": "always"},
    )
    container.start()
    original_id = container.id

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        assert recovered.ping()
        deadline = time.monotonic() + 30
        while True:
            value = recovered.containers.get(container.name)
            value.reload()
            if value.status == "running":
                break
            if time.monotonic() >= deadline:
                pytest.fail(f"container did not recover after daemon restart: {value.attrs['State']}")
            time.sleep(0.2)
        assert value.id == original_id
        assert recovered.networks.get(network.name).name == network.name
        assert recovered.volumes.get(volume.name).name == volume.name
        assert value.attrs["HostConfig"]["RestartPolicy"]["Name"] == "always"
        assert any(mount["Name"] == volume.name for mount in value.attrs["Mounts"])
    finally:
        recovered.close()


@pytest.mark.compat("REC-002")
def test_daemon_restart_during_active_io_and_stats(daemon, client: docker.DockerClient):
    container = client.containers.create(
        IMAGE,
        command=["sh", "-c", "i=0; while true; do echo tick-$i; i=$((i+1)); sleep 1; done"],
        name=f"recovery-streams-{uuid.uuid4().hex[:8]}",
        restart_policy={"Name": "always"},
    )
    container.start()
    received: dict[str, list[object]] = {"logs": [], "stats": []}

    def consume(name: str, stream) -> None:
        try:
            for value in stream:
                if len(received[name]) < 5:
                    received[name].append(value)
        except Exception:
            pass  # abrupt daemon termination is expected to close active HTTP streams
        finally:
            close = getattr(stream, "close", None)
            if close is not None:
                try:
                    close()
                except OSError:
                    pass

    stream_clients = {
        name: docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
        for name in ("logs", "stats")
    }
    streams = {
        "logs": stream_clients["logs"].containers.get(container.id).logs(stream=True, follow=True),
        "stats": stream_clients["stats"].containers.get(container.id).stats(stream=True, decode=True),
    }
    readers = [threading.Thread(target=consume, args=(name, stream), daemon=True) for name, stream in streams.items()]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + 15
    while not all(received.values()):
        if time.monotonic() >= deadline:
            pytest.fail(f"streams did not become active before restart: {received}")
        time.sleep(0.1)

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
                pytest.fail(f"streaming container did not recover: {value.attrs['State']}")
            time.sleep(0.2)
        sample = value.stats(stream=False)
        assert sample["read"] and "cpu_stats" in sample
    finally:
        recovered.close()


@pytest.mark.compat("REC-003")
def test_daemon_restart_recreates_usable_network_interfaces(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-network-recovery-{suffix}")
    container = client.containers.create(
        IMAGE, command="top", name=f"network-recovery-{suffix}", network=network.name,
        restart_policy={"Name": "always"},
    )
    container.start(); container.reload()
    code, carrier = container.exec_run(["cat", "/sys/class/net/eth0/carrier"])
    assert (code, carrier.strip()) == (0, b"1")
    code, _ = container.exec_run(["sh", "-c", "nslookup registry-1.docker.io >/dev/null && nc -z -w 5 1.1.1.1 443"])
    assert code == 0

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
                pytest.fail(f"networked container did not recover: {value.attrs['State']}")
            time.sleep(0.2)
        recovered_address = value.attrs["NetworkSettings"]["Networks"][network.name]["IPAddress"]
        assert recovered_address
        code, carrier = value.exec_run(["cat", "/sys/class/net/eth0/carrier"])
        assert (code, carrier.strip()) == (0, b"1")
        code, output = value.exec_run([
            "sh", "-c", "nslookup registry-1.docker.io && nc -z -w 5 1.1.1.1 443"
        ])
        assert code == 0, output.decode(errors="replace")
    finally:
        recovered.close()


@pytest.mark.compat("REC-005")
def test_vmnet_reservation_is_released_when_infrastructure_shim_exits(
    daemon, client: docker.DockerClient
):
    suffix = uuid.uuid4().hex[:8]
    network = client.networks.create(f"compat-vmnet-owner-{suffix}")
    pattern = str(daemon.root / "infrastructure" / "shim.json")
    result = subprocess.run(
        ["pgrep", "-f", pattern], text=True, stdout=subprocess.PIPE, check=True
    )
    shim_pids = [int(value) for value in result.stdout.split()]
    assert len(shim_pids) == 1
    os.kill(shim_pids[0], signal.SIGKILL)

    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=60, version="auto")
    try:
        value = recovered.networks.get(network.id)
        container = recovered.containers.create(IMAGE, command="top", network=value.name)
        container.start()
        code, carrier = container.exec_run(["cat", "/sys/class/net/eth0/carrier"])
        assert (code, carrier.strip()) == (0, b"1")
    finally:
        recovered.close()
