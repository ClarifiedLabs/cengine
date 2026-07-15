"""Raw one-container-per-VM runtime regression contracts."""

from __future__ import annotations

import concurrent.futures
import subprocess
import time
import uuid

import docker
import pytest
from docker.types import Mount


@pytest.mark.compat("CTR-035")
def test_debian_package_install_uses_ext4_rootfs(client: docker.DockerClient):
    output = client.containers.run(
        "debian:trixie-slim",
        ["sh", "-ec", "apt-get update >/dev/null && apt-get install -y ca-certificates >/dev/null && test -d /etc/ssl && echo ext4-ok"],
        remove=True,
    )
    assert output.strip() == b"ext4-ok"


@pytest.mark.compat("CTR-045")
def test_unprivileged_standard_devices_are_world_accessible(client: docker.DockerClient):
    output = client.containers.run(
        "alpine:latest",
        [
            "sh", "-ec",
            "for device in null zero full random urandom tty; do "
            "test \"$(stat -c %a /dev/$device)\" = 666; done; "
            "printf writable >/dev/null; echo devices-ok",
        ],
        user="65534:65534",
        remove=True,
    )
    assert output.strip() == b"devices-ok"


@pytest.mark.compat("CTR-046")
def test_concurrent_vm_starts_remain_responsive(daemon, client: docker.DockerClient):
    container_ids: list[str] = []

    def start_container(index: int) -> str:
        local = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=180, version="auto")
        try:
            container = local.containers.create(
                "alpine:latest", ["sh", "-c", "while :; do sleep 1; done"],
                name=f"concurrent-vm-{index}-{uuid.uuid4().hex[:8]}",
            )
            container_ids.append(container.id)
            container.start()
            result = container.exec_run(["sh", "-c", "printf responsive"])
            assert result.exit_code == 0
            assert result.output == b"responsive"
            return container.id
        finally:
            local.close()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            started = list(pool.map(start_container, range(12)))
        assert len(set(started)) == 12
    finally:
        for container_id in container_ids:
            try:
                client.containers.get(container_id).remove(force=True)
            except docker.errors.NotFound:
                pass


@pytest.mark.compat("CTR-036")
def test_exec_hijack_closes_after_process_exit(daemon, client: docker.DockerClient):
    container = client.containers.run(
        "alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True
    )
    result = subprocess.run(
        [
            "docker", "--host", f"unix://{daemon.socket}", "exec", container.id,
            "sh", "-c", "printf exec-complete",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode(errors="replace")
    assert result.stdout == b"exec-complete"


@pytest.mark.compat("CTR-037")
def test_short_lived_container_reaches_exited_state(client: docker.DockerClient):
    container = client.containers.run("alpine:latest", ["/bin/true"], detach=True)
    result = container.wait(timeout=30)
    assert result["StatusCode"] == 0
    container.reload()
    assert container.status == "exited"


@pytest.mark.compat("CTR-038")
def test_attached_exec_streams_stdin_before_eof(daemon, client: docker.DockerClient):
    container = client.containers.run(
        "alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True
    )
    result = subprocess.run(
        [
            "docker", "--host", f"unix://{daemon.socket}", "exec", "-i", container.id,
            "sh", "-c", "read value; printf 'received:%s' \"$value\"",
        ],
        input=b"streamed-input\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout.decode(errors="replace")
    assert result.stdout == b"received:streamed-input"


@pytest.mark.compat("CTR-039")
def test_attached_exec_preserves_multiline_stdin_bytes(daemon, client: docker.DockerClient):
    container = client.containers.run(
        "alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True
    )
    payload = (
        b"apiVersion: apps/v1\n"
        b"spec:\n"
        b"  template:\n"
        b"    spec:\n"
        b"      nodeSelector:\n"
        b"        kubernetes.io/os: linux\n"
    )
    result = subprocess.run(
        ["docker", "--host", f"unix://{daemon.socket}", "exec", "-i", container.id, "cat"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == payload


@pytest.mark.compat("CTR-040")
def test_exec_inherits_and_overrides_container_environment(client: docker.DockerClient):
    container = client.containers.run(
        "nginx:alpine", ["sh", "-c", "sleep 300"], detach=True,
        environment={"LEVEL": "container", "CONTAINER_ONLY": "present"},
    )
    result = container.exec_run(
        ["sh", "-c", "printf '%s|%s|%s' \"$NGINX_VERSION\" \"$LEVEL\" \"$CONTAINER_ONLY\""],
        environment={"LEVEL": "exec"},
    )
    assert result.exit_code == 0
    image_value, level, container_only = result.output.decode().split("|")
    assert image_value
    assert level == "exec"
    assert container_only == "present"


@pytest.mark.compat("CTR-043")
def test_attached_exec_streams_large_stdin_without_filesystem_polling(daemon, client: docker.DockerClient):
    container = client.containers.run(
        "alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True
    )
    payload_size = 128 * 1024 * 1024
    started = time.monotonic()
    result = subprocess.run(
        ["docker", "--host", f"unix://{daemon.socket}", "exec", "-i", container.id, "wc", "-c"],
        input=b"x" * payload_size,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout.strip() == str(payload_size).encode()
    assert elapsed < 5, f"128 MiB attached exec transfer took {elapsed:.2f}s"


@pytest.mark.compat("CTR-044")
def test_attached_exec_flushes_short_output_before_eof(daemon, client: docker.DockerClient):
    container = client.containers.run(
        "alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True
    )

    # Buildx keeps attached stdin open while short-lived setup commands run. The
    # remote process must still finish without waiting for client-side stdin EOF.
    process = subprocess.Popen(
        [
            "docker", "--host", f"unix://{daemon.socket}", "exec", "-i", container.id,
            "printf", "%s", "open-stdin",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert process.wait(timeout=10) == 0
        assert process.stdout.read() == b"open-stdin"
    finally:
        process.stdin.close()
        if process.poll() is None:
            process.kill()

    for index in range(20):
        expected = f"eof-{index:02d}".encode()
        result = subprocess.run(
            [
                "docker", "--host", f"unix://{daemon.socket}", "exec", container.id,
                "printf", "%s", expected.decode(),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert result.stdout == expected


@pytest.mark.compat("VOL-006")
def test_volume_preserves_inodes_across_link_and_rename(client: docker.DockerClient):
    volume = client.volumes.create(
        f"compat-volume-{uuid.uuid4().hex[:8]}", labels={"dev.cengine.compat": "true"}
    )
    output = client.containers.run(
        "alpine:latest",
        ["sh", "-ec", "mkdir -p /data/a/etc/ssl; printf payload >/data/a/file; ln /data/a/file /data/a/link; before=$(stat -c %i /data/a/file); mv /data/a /data/b; test \"$before\" = \"$(stat -c %i /data/b/link)\"; cat /data/b/link"],
        mounts=[Mount(target="/data", source=volume.name, type="volume")],
        remove=True,
    )
    assert output == b"payload"


@pytest.mark.compat("REC-004")
def test_running_workload_survives_daemon_process_replacement(daemon, client: docker.DockerClient):
    container = client.containers.run("alpine:latest", ["sh", "-c", "while :; do sleep 1; done"], detach=True)
    container.reload()
    started_at = container.attrs["State"]["StartedAt"]
    daemon.restart(kill=True)
    recovered = docker.DockerClient(base_url=f"unix://{daemon.socket}", timeout=180, version="auto")
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            value = recovered.containers.get(container.id)
            value.reload()
            if value.status == "running":
                assert value.attrs["State"]["StartedAt"] == started_at
                return
            time.sleep(0.2)
        pytest.fail("running shim workload was not recovered")
    finally:
        recovered.close()
