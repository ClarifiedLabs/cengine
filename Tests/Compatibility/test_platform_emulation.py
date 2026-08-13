"""linux/amd64 container execution through Rosetta for Linux."""

from __future__ import annotations

import subprocess
import uuid

import docker
import pytest


AMD64_IMAGE = "debian:trixie-slim"
AMD64_PLATFORM = "linux/amd64"


def host_has_rosetta() -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/arch", "-x86_64", "/usr/bin/true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@pytest.fixture(scope="module", autouse=True)
def require_rosetta_host():
    if not host_has_rosetta():
        pytest.skip("host does not have Rosetta installed for linux/amd64 emulation")


@pytest.mark.compat("RTM-045")
def test_amd64_containers_run_and_exec_via_rosetta(client: docker.DockerClient):
    client.images.pull(AMD64_IMAGE, platform=AMD64_PLATFORM)

    echoed = client.containers.run(
        AMD64_IMAGE, ["echo", "foo"], platform=AMD64_PLATFORM, remove=True,
    )
    assert echoed.decode().strip() == "foo"

    machine = client.containers.run(
        AMD64_IMAGE, ["uname", "-m"], platform=AMD64_PLATFORM, remove=True,
    )
    assert machine.decode().strip() == "x86_64"

    container = client.containers.create(
        AMD64_IMAGE,
        ["sh", "-c", "while :; do sleep 1; done"],
        platform=AMD64_PLATFORM,
        name=f"rtm045-amd64-exec-{uuid.uuid4().hex[:8]}",
        detach=True,
    )
    try:
        container.start()
        probed = container.exec_run(["uname", "-m"])
        assert probed.exit_code == 0, probed.output.decode(errors="replace")
        assert probed.output.decode().strip() == "x86_64"
    finally:
        container.remove(force=True)
