"""Bounded Docker-facing ports of pinned Moby and runc runtime assertions."""

from __future__ import annotations

import pathlib
import socket
import time
import uuid

import docker
import pytest
from docker.types import Mount, Ulimit


ALPINE_IMAGE = "alpine:latest"


def wait_for(predicate, description: str, *, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = predicate()
        if observed:
            return observed
        time.sleep(0.1)
    pytest.fail(f"timed out waiting for {description}: last value {observed!r}")


@pytest.mark.compat("RTM-040")
def test_moby_exec_identity_exit_and_close_stdin_ports(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
    """Port Moby docker-v29.6.2 exec assertions to the Docker API.

    Sources: integration/container/exec_test.go::TestExec,
    TestExecWithCloseStdin, and TestExecUser; and
    integration/container/exec_linux_test.go::TestFailedExecExitCode.
    The port uses Alpine plus bind-mounted identity files instead of building
    BusyBox variants, and checks observable Docker behavior rather than Moby
    daemon internals. TestExecWithGroupAdd is excluded because GroupAdd remains
    an explicit pre-mutation architecture gap.
    """
    suffix = uuid.uuid4().hex[:8]
    passwd_file = tmp_path / "passwd"
    group_file = tmp_path / "group"
    passwd_file.write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "app:x:1000:1000:app:/home/app:/bin/sh\n"
    )
    group_file.write_text(
        "root:x:0:\napp:x:1000:\nstaff:x:3000:\nextra:x:4000:app\n"
    )
    container = client.containers.run(
        ALPINE_IMAGE, ["top"], detach=True,
        name=f"upstream-moby-exec-{suffix}", user="app:staff",
        working_dir="/tmp",
        mounts=[
            Mount("/etc/passwd", str(passwd_file), type="bind", read_only=True),
            Mount("/etc/group", str(group_file), type="bind", read_only=True),
        ],
    )
    try:
        exec_id = client.api.exec_create(
            container.id,
            ["sh", "-ec", "printf 'cwd=%s env=%s' \"$PWD\" \"$FOO\""],
            workdir="/", environment={"FOO": "BAR"}, stdout=True, stderr=True,
        )["Id"]
        assert client.api.exec_inspect(exec_id)["ID"] == exec_id
        output = client.api.exec_start(exec_id, detach=False, tty=False)
        assert output == b"cwd=/ env=BAR"

        inherited = container.exec_run([
            "sh", "-ec",
            "printf '%s %s ' \"$(id -u)\" \"$(id -g)\"; id -G",
        ])
        assert inherited.exit_code == 0, inherited.output.decode(errors="replace")
        identity = inherited.output.decode().split()
        assert identity[:2] == ["1000", "3000"]
        assert set(identity[2:]) == {"3000", "4000"}

        attached_id = client.api.exec_create(
            container.id, ["sh", "-ec", "cat; printf closeIO"],
            stdin=True, stdout=True, stderr=True,
        )["Id"]
        response = client.api._post_json(
            client.api._url("/exec/{0}/start", attached_id),
            headers={"Connection": "Upgrade", "Upgrade": "tcp"},
            data={"Detach": False, "Tty": False},
            stream=True,
        )
        stream = client.api._get_raw_response_socket(response)
        raw_socket = getattr(stream, "_sock", stream)
        if hasattr(raw_socket, "settimeout"):
            raw_socket.settimeout(10)
        raw_socket.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response.close()
        assert b"closeIO" in b"".join(chunks)
        assert client.api.exec_inspect(attached_id)["ExitCode"] == 0

        missing = container.exec_run(["upstream-command-does-not-exist"])
        not_executable = container.exec_run(["/etc"])
        assert missing.exit_code == 127
        assert not_executable.exit_code == 126
    finally:
        container.remove(force=True)


def parse_process_status(output: bytes) -> tuple[dict[str, str], list[str]]:
    lines = output.decode().splitlines()
    status: dict[str, str] = {}
    limits: list[str] = []
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
        elif line:
            limits.append(line)
    return status, limits


@pytest.mark.compat("RTM-041")
def test_runc_capability_and_rlimit_ports(client: docker.DockerClient):
    """Port applicable runc v1.3.3 capability and rlimit assertions.

    Sources: tests/integration/capabilities.bats::"runc run with some
    capabilities" and tests/integration/rlimits.bats::"runc run with
    RLIMIT_NOFILE(Smaller than system's hard value)" plus its runc-exec
    counterpart. Ambient/unknown-capability cases are excluded because the
    Docker surface does not expose arbitrary OCI ambient sets and rejects
    unknown Docker capability names before mutation.
    """
    probe = (
        "grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' "
        "/proc/self/status; ulimit -Sn; ulimit -Hn"
    )
    container = client.containers.create(
        ALPINE_IMAGE,
        ["sh", "-ec", f"({probe}) >/tmp/init-process-status; exec top"],
        cap_drop=["ALL"], cap_add=["SYS_ADMIN"],
        security_opt=["no-new-privileges=true"],
        ulimits=[Ulimit(name="nofile", soft=2048, hard=4096)],
    )
    try:
        container.start()
        def read_init_snapshot():
            result = container.exec_run(["cat", "/tmp/init-process-status"])
            return result if result.exit_code == 0 else None

        init_output = wait_for(
            read_init_snapshot, "init capability and rlimit snapshot",
        )
        assert init_output.exit_code == 0
        exec_output = container.exec_run(["sh", "-ec", probe])
        assert exec_output.exit_code == 0, exec_output.output.decode(errors="replace")

        for output in (init_output.output, exec_output.output):
            status, limits = parse_process_status(output)
            assert status["CapInh"] == "0000000000000000"
            assert status["CapAmb"] == "0000000000000000"
            assert status["CapPrm"] == "0000000000200000"
            assert status["CapEff"] == "0000000000200000"
            assert status["CapBnd"] == "0000000000200000"
            assert status["NoNewPrivs"] == "1"
            assert limits == ["2048", "4096"]
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-042")
def test_runc_masked_path_and_readonly_bind_ports(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
    """Port applicable runc v1.3.3 mask and read-only bind assertions.

    Sources: tests/integration/mask.bats::"mask paths [file]" and "mask paths
    [directory]"; tests/integration/mounts_recursive.bats::the rbind ro/rro
    request shapes. Docker structured bind flags replace direct OCI mount
    options. This adaptation verifies top-level policy and a later explicit
    child mount, but does not claim recursive enforcement over a pre-existing
    Linux nested mount that cannot be fabricated across macOS virtiofs.
    Shared/slave success is deliberately not ported: cengine rejects those
    Docker requests because virtiofs cannot provide a real peer/master mount.
    """
    suffix = uuid.uuid4().hex[:8]
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "testfile").write_text("Forbidden information!\n")
    (fixture / "testdir").mkdir()
    (fixture / "testdir" / "secret").write_text("Forbidden information!\n")
    nonrecursive = tmp_path / "nonrecursive"
    recursive = tmp_path / "recursive"
    nonrecursive.mkdir()
    recursive.mkdir()
    (nonrecursive / "marker").write_text("parent\n")
    (nonrecursive / "subvolume").mkdir()
    (recursive / "marker").write_text("parent\n")

    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"upstream-runc-mount-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["top"],
            "HostConfig": {
                "MaskedPaths": ["/fixture/testfile", "/fixture/testdir"],
                "Mounts": [
                    {
                        "Type": "bind", "Source": str(fixture),
                        "Target": "/fixture", "ReadOnly": True,
                    },
                    {
                        "Type": "bind", "Source": str(nonrecursive),
                        "Target": "/nonrecursive", "ReadOnly": True,
                        "BindOptions": {
                            "NonRecursive": True, "ReadOnlyNonRecursive": True,
                        },
                    },
                    {"Type": "tmpfs", "Target": "/nonrecursive/subvolume"},
                    {
                        "Type": "bind", "Source": str(recursive),
                        "Target": "/recursive", "ReadOnly": True,
                        "BindOptions": {"ReadOnlyForceRecursive": True},
                    },
                ],
            },
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    try:
        container.start()
        masked = container.exec_run([
            "sh", "-ec",
            "test ! -s /fixture/testfile; "
            "test -z \"$(ls -A /fixture/testdir)\"; "
            "! echo leak >/fixture/testfile 2>/dev/null; "
            "! touch /fixture/testdir/leak 2>/dev/null; "
            "! umount /fixture/testfile 2>/dev/null",
        ])
        assert masked.exit_code == 0, masked.output.decode(errors="replace")

        mount_modes = container.exec_run([
            "sh", "-ec",
            "! touch /nonrecursive/parent-write 2>/dev/null; "
            "touch /nonrecursive/subvolume/child-write; "
            "! touch /recursive/parent-write 2>/dev/null",
        ])
        assert mount_modes.exit_code == 0, mount_modes.output.decode(errors="replace")

        initial_volumes = {volume.name for volume in client.volumes.list()}
        rejected_name = f"upstream-runc-shared-gap-{suffix}"
        with pytest.raises(docker.errors.APIError) as error:
            rejected = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": rejected_name},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/must-not-leak": {}},
                    "HostConfig": {"Binds": [f"{fixture}:/shared:rshared"]},
                },
            )
            client.api._raise_for_status(rejected)
        assert error.value.status_code == 501
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(rejected_name)
        assert {volume.name for volume in client.volumes.list()} == initial_volumes
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-043")
def test_moby_ipc_shm_health_ports(client: docker.DockerClient):
    """Port distinct Moby docker-v29.6.2 IPC/shm/health assertions.

    Sources: integration/container/run_linux_test.go::TestContainerShmSize and
    integration/container/health_test.go::TestHealthCheckWorkdir. Existing
    RTM-033/035 cover persistence and start-interval timing; this adaptation
    instead proves tmpfs enforcement and health-check cwd inheritance.
    TestHealthCheckProcessKilled is excluded because cengine does not retain
    Docker's per-probe health log yet.
    """
    workdir = "/tmp/upstream-health-workdir"
    health_script = f'test "$PWD" = "{workdir}"'
    container = client.containers.run(
        ALPINE_IMAGE, ["top"], detach=True,
        working_dir=workdir, shm_size="8m",
        healthcheck={
            "test": ["CMD-SHELL", health_script],
            "interval": 1_000_000_000,
            "timeout": 200_000_000,
            "retries": 1,
        },
    )
    try:
        def healthy():
            container.reload()
            return container.attrs["State"].get("Health", {}).get("Status") == "healthy"

        assert wait_for(healthy, "healthy workdir-aware check", timeout=15)
        container.reload()
        assert container.attrs["HostConfig"]["IpcMode"] == "private"
        assert container.attrs["HostConfig"]["ShmSize"] == 8 * 1024 * 1024
        size = container.exec_run([
            "sh", "-ec", "df -kP /dev/shm | awk 'NR == 2 { print $2 }'",
        ])
        assert size.exit_code == 0
        assert size.output.strip() == b"8192"
        enforced = container.exec_run([
            "sh", "-ec",
            "dd if=/dev/zero of=/dev/shm/fill bs=1M count=12 2>/dev/null && exit 1; "
            "test \"$(du -k /dev/shm/fill | awk '{ print $1 }')\" -le 8192",
        ])
        assert enforced.exit_code == 0, enforced.output.decode(errors="replace")
    finally:
        container.remove(force=True)
