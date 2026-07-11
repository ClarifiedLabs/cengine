"""End-to-end compatibility contracts using the Docker CLI."""

from __future__ import annotations

import os
import pathlib
import subprocess
import uuid

import pytest


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")


def docker(daemon, *arguments: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
    socket = daemon["socket"]
    assert isinstance(socket, pathlib.Path)
    environment = os.environ.copy()
    environment["DOCKER_HOST"] = f"unix://{socket}"
    result = subprocess.run(
        ["docker", *arguments], env=environment, input=input, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
    )
    assert result.returncode == 0, f"docker {' '.join(arguments)} failed:\n{result.stdout}"
    process = daemon["process"]
    assert isinstance(process, subprocess.Popen)
    assert process.poll() is None, f"cengine exited after docker {' '.join(arguments)}"
    return result


@pytest.mark.compat("CLI-001")
def test_cli_system_and_image_commands(daemon):
    assert "cengine" in docker(daemon, "version", "--format", "{{.Server.Platform.Name}}").stdout
    assert docker(daemon, "info", "--format", "{{.Driver}}").stdout.strip() == "apple-containerization"
    assert docker(daemon, "info", "--format", "{{.CgroupVersion}}").stdout.strip() == "2"
    docker(daemon, "pull", IMAGE)
    assert IMAGE.split(":", 1)[0] in docker(daemon, "image", "ls", "--format", "{{.Repository}}").stdout


@pytest.mark.compat("CLI-002")
def test_cli_container_lifecycle(daemon):
    name = f"cli-lifecycle-{uuid.uuid4().hex[:8]}"
    docker(daemon, "create", "--name", name, IMAGE, "top")
    docker(daemon, "start", name)
    assert "running" in docker(daemon, "inspect", "--format", "{{.State.Status}}", name).stdout
    assert name in docker(daemon, "ps", "--format", "{{.Names}}").stdout
    docker(daemon, "stop", "--time", "1", name)
    docker(daemon, "rm", name)


@pytest.mark.compat("CLI-003")
def test_cli_run_attached_output(daemon):
    result = docker(daemon, "run", "--rm", IMAGE, "echo", "cli-output-roundtrip")
    assert result.stdout.strip() == "cli-output-roundtrip"


@pytest.mark.compat("CLI-004")
def test_cli_run_attached_stdin(daemon):
    result = docker(daemon, "run", "--rm", "-i", IMAGE, "cat", input="stdin-roundtrip\n")
    assert result.stdout == "stdin-roundtrip\n"


@pytest.mark.compat("CLI-005")
def test_cli_network_and_volume_lifecycle(daemon):
    network = f"cli-network-{uuid.uuid4().hex[:8]}"
    volume = f"cli-volume-{uuid.uuid4().hex[:8]}"
    docker(daemon, "network", "create", network)
    assert network in docker(daemon, "network", "ls", "--format", "{{.Name}}").stdout
    docker(daemon, "network", "rm", network)
    docker(daemon, "volume", "create", volume)
    assert volume in docker(daemon, "volume", "ls", "--format", "{{.Name}}").stdout
    docker(daemon, "volume", "rm", volume)


@pytest.mark.compat("CLI-006")
def test_cli_system_disk_usage(daemon):
    summary = docker(daemon, "system", "df").stdout
    assert all(heading in summary for heading in ("Images", "Containers", "Local Volumes", "Build Cache"))
    verbose = docker(daemon, "system", "df", "--verbose").stdout
    assert "Images space usage" in verbose
    assert "Local Volumes space usage" in verbose


@pytest.mark.compat("CLI-007")
def test_cli_detached_kind_shaped_run(daemon):
    name = f"kind-shaped-{uuid.uuid4().hex[:8]}"
    network = f"compat-kind-{uuid.uuid4().hex[:8]}"
    docker(daemon, "network", "create", network)
    result = docker(
        daemon, "run", "--detach", "--tty", "--name", name,
        "--privileged", "--tmpfs", "/tmp", "--tmpfs", "/run",
        "--volume", "/var", "--volume", "/lib/modules:/lib/modules:ro",
        "--network", network, IMAGE, "top",
    )
    assert len(result.stdout.strip()) == 64
    assert docker(daemon, "inspect", "--format", "{{.State.Status}}", name).stdout.strip() == "running"
    assert docker(daemon, "inspect", "--format", "{{.HostConfig.NetworkMode}}", name).stdout.strip() == network
    mounts = docker(daemon, "inspect", "--format", "{{json .Mounts}}", name).stdout
    assert '"Destination":"/var"' in mounts and '"Source":"/lib/modules"' in mounts
    docker(daemon, "rm", "--force", "--volumes", name)
    docker(daemon, "network", "rm", network)
