"""Testcontainers/Ryuk compatibility contracts."""

from __future__ import annotations

import socket
import time
import uuid

import docker
import pytest


RYUK_IMAGE = "testcontainers/ryuk:0.13.0"


def _container_logs(container) -> str:
    try:
        return container.logs().decode(errors="replace")
    except docker.errors.NotFound:
        return "<container was already auto-removed>"


def _wait_for_ryuk_port(container) -> tuple[str, int]:
    deadline = time.monotonic() + 15
    last_state = "created"
    while time.monotonic() < deadline:
        container.reload()
        last_state = container.status
        if last_state == "exited":
            pytest.fail(f"Ryuk exited before becoming ready:\n{container.logs().decode(errors='replace')}")
        bindings = container.attrs["NetworkSettings"]["Ports"].get("8080/tcp")
        if bindings:
            host = bindings[0]["HostIp"]
            if host in ("", "0.0.0.0", "::"):
                host = "127.0.0.1"
            port = int(bindings[0]["HostPort"])
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    return host, port
            except OSError:
                pass
        time.sleep(0.1)
    pytest.fail(f"Ryuk did not publish port 8080 while {last_state}")


def _wait_for_ryuk_filter(container, host: str, port: int, value: str) -> socket.socket:
    deadline = time.monotonic() + 15
    last_error = "connection was not attempted"
    while time.monotonic() < deadline:
        connection = None
        try:
            connection = socket.create_connection((host, port), timeout=2)
            connection.sendall((value + "\n").encode())
            acknowledgement = connection.recv(4)
            if acknowledgement == b"ACK\n":
                return connection
            last_error = f"unexpected acknowledgement {acknowledgement!r}"
        except OSError as error:
            last_error = str(error)
        if connection is not None:
            connection.close()
        container.reload()
        if container.status == "exited":
            pytest.fail(f"Ryuk exited before acknowledging the cleanup filter:\n{_container_logs(container)}")
        time.sleep(0.1)
    pytest.fail(
        f"Ryuk did not acknowledge the cleanup filter ({last_error}):\n"
        + _container_logs(container)
    )


def _assert_ryuk_reaps(client: docker.DockerClient, daemon, *, privileged: bool) -> None:
    token = uuid.uuid4().hex
    label = f"dev.cengine.compat.ryuk={token}"
    reaper = client.containers.create(
        RYUK_IMAGE,
        detach=True,
        auto_remove=True,
        privileged=privileged,
        ports={"8080/tcp": None},
        volumes={str(daemon.socket): {"bind": "/var/run/docker.sock", "mode": "rw"}},
        environment={
            "RYUK_CONNECTION_TIMEOUT": "30s",
            "RYUK_RECONNECTION_TIMEOUT": "10s",
            "RYUK_VERBOSE": "true",
        },
    )
    target = None
    try:
        reaper.start()
        host, port = _wait_for_ryuk_port(reaper)
        with _wait_for_ryuk_filter(reaper, host, port, f"label={label}"):
            target = client.containers.run(
                "alpine:latest", ["sh", "-c", "sleep 300"], detach=True,
                labels={"dev.cengine.compat.ryuk": token},
            )

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                target.reload()
            except docker.errors.NotFound:
                target = None
                return
            time.sleep(0.1)
        pytest.fail(
            "Ryuk accepted the filter but did not reap the labeled container:\n"
            + _container_logs(reaper)
        )
    finally:
        if target is not None:
            try:
                target.remove(force=True)
            except (docker.errors.NotFound, docker.errors.APIError):
                pass
        try:
            reaper.remove(force=True)
        except docker.errors.NotFound:
            pass


@pytest.mark.compat("TST-001")
def test_ryuk_reaps_through_bound_cengine_socket(client: docker.DockerClient, daemon):
    _assert_ryuk_reaps(client, daemon, privileged=False)


@pytest.mark.compat("TST-002")
def test_privileged_ryuk_reaps_through_bound_cengine_socket(client: docker.DockerClient, daemon):
    _assert_ryuk_reaps(client, daemon, privileged=True)


@pytest.mark.compat("TST-003")
def test_shellless_ryuk_exec_reports_command_not_found(client: docker.DockerClient, daemon):
    reaper = client.containers.create(
        RYUK_IMAGE,
        detach=True,
        environment={
            "RYUK_CONNECTION_TIMEOUT": "30s",
            "RYUK_RECONNECTION_TIMEOUT": "10s",
        },
        ports={"8080/tcp": None},
        volumes={str(daemon.socket): {"bind": "/var/run/docker.sock", "mode": "rw"}},
    )
    try:
        reaper.start()
        _wait_for_ryuk_port(reaper)
        result = reaper.exec_run(["/bin/sh", "-c", "true"])
        assert result.exit_code in (126, 127), result.output.decode(errors="replace")
    finally:
        try:
            reaper.remove(force=True)
        except docker.errors.NotFound:
            pass


@pytest.mark.compat("TST-004")
def test_ryuk_keeps_multiple_control_connections_open(client: docker.DockerClient, daemon):
    token = uuid.uuid4().hex
    filters = [
        f"label=dev.cengine.compat.ryuk={token}",
        "label=dev.cengine.compat.shared=true",
    ]
    reaper = client.containers.create(
        RYUK_IMAGE,
        detach=True,
        auto_remove=True,
        ports={"8080/tcp": None},
        volumes={str(daemon.socket): {"bind": "/var/run/docker.sock", "mode": "rw"}},
        environment={
            "RYUK_CONNECTION_TIMEOUT": "30s",
            "RYUK_RECONNECTION_TIMEOUT": "2s",
            "RYUK_VERBOSE": "true",
        },
    )
    connections: list[socket.socket] = []
    target = None
    try:
        reaper.start()
        host, port = _wait_for_ryuk_port(reaper)
        for index in range(4):
            ordered = filters if index % 2 == 0 else list(reversed(filters))
            connection = _wait_for_ryuk_filter(reaper, host, port, "&".join(ordered))
            connections.append(connection)

        target = client.containers.run(
            "alpine:latest", ["sh", "-c", "sleep 300"], detach=True,
            labels={"dev.cengine.compat.ryuk": token, "dev.cengine.compat.shared": "true"},
        )
        connections.pop().close()
        time.sleep(3)
        target.reload()
        assert target.status == "running", _container_logs(reaper)
    finally:
        for connection in connections:
            connection.close()
        if target is not None:
            try:
                target.remove(force=True)
            except (docker.errors.NotFound, docker.errors.APIError):
                pass
        try:
            reaper.remove(force=True)
        except docker.errors.NotFound:
            pass
