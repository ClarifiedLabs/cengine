"""Isolated, VM-backed executable-upgrade and failed-uplink recovery contracts."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import time
import uuid

import docker
import pytest
from docker.types import Mount

from harness import (
    compatibility_environment,
    compatibility_runtime_processes,
    register_compatibility_executable,
    terminate_compatibility_runtime,
)


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_MISMATCH = "infrastructure VM belongs to a different or older cengine build"


def _shim_request(specification: dict, operation: str, payload: dict | None = None) -> dict:
    # VMShimProtocol: length-prefixed JSON, with Codable Data encoded as base64.
    request = {
        "version": 5, "id": str(uuid.uuid4()), "token": specification["token"],
        "operation": operation,
    }
    if payload is not None:
        request["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    body = json.dumps(request).encode()
    deadline = time.monotonic() + 30
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect(specification["socketPath"])
        connection.sendall(struct.pack(">I", len(body)) + body)

        def receive(size: int) -> bytes:
            result = bytearray()
            while len(result) < size:
                remaining = deadline - time.monotonic()
                assert remaining > 0, f"{operation} shim reply timed out"
                connection.settimeout(remaining)
                chunk = connection.recv(size - len(result))
                assert chunk, f"{operation} shim reply ended prematurely"
                result.extend(chunk)
            return bytes(result)

        size, = struct.unpack(">I", receive(4))
        assert 0 < size <= 16 * 1024 * 1024
        response = json.loads(receive(size))
    assert response["version"] == request["version"]
    assert response["id"] == request["id"]
    assert response["token"] == request["token"]
    assert response["operation"] == operation
    return response


def _successful_payload(response: dict) -> dict:
    assert not response.get("error"), response.get("error")
    return json.loads(base64.b64decode(response["payload"], validate=True))


def _status(specification: dict) -> dict:
    return _successful_payload(_shim_request(specification, "status"))


def _strict_shutdown(daemon) -> None:
    result = subprocess.run(
        [str(daemon.binary.resolve()), "system", "shutdown", "--for-upgrade",
         "--root", str(daemon.root), "--socket", str(daemon.socket)],
        env=compatibility_environment(), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=90,
    )
    assert result.returncode == 0, result.stdout


def _assert_same_root_is_exclusive(daemon) -> None:
    # A different endpoint (and a symlink spelling of the root) must not bypass
    # either the daemon writer lock or the strict upgrade lock.
    alias = daemon.work / "root-alias"
    alias.symlink_to(daemon.root, target_is_directory=True)
    alternate_socket = daemon.work / "alternate.sock"
    specification = daemon.root / "infrastructure" / "shim.json"
    before = specification.read_bytes()
    commands = [
        (["daemon", "--metadata-only"], "another cengine daemon is already running"),
        (["system", "shutdown", "--for-upgrade"], "engine is still running"),
    ]
    for command, expected_error in commands:
        result = subprocess.run(
            [str(daemon.binary.resolve()), *command, "--root", str(alias),
             "--socket", str(alternate_socket)],
            env=compatibility_environment(), text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=20,
        )
        assert result.returncode != 0, result.stdout
        assert expected_error in result.stdout, result.stdout
        assert specification.read_bytes() == before
        assert not alternate_socket.exists()


def _assert_exited(pids: set[int]) -> None:
    # Do not accept a stopped VM or an unlinked socket as proof its writer exited.
    deadline = time.monotonic() + 5
    while pids:
        for pid in list(pids):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pids.remove(pid)
        assert not pids or time.monotonic() < deadline, f"upgrade left live peers: {pids}"
        if pids:
            time.sleep(0.05)


def _replacement_with_new_uuid(binary: pathlib.Path) -> tuple[pathlib.Path, uuid.UUID, uuid.UUID]:
    replacement = binary.with_name("cengine.next")
    shutil.copy2(binary, replacement)
    contents = bytearray(replacement.read_bytes())
    # The compatibility build is a native arm64, 64-bit Mach-O executable.
    magic, cpu, _, _, count, commands_size, _, _ = struct.unpack_from("<8I", contents)
    assert (magic, cpu) == (0xFEEDFACF, 0x0100000C), "expected native arm64 Mach-O"
    offset = 32
    commands_end = offset + commands_size
    assert commands_end <= len(contents)
    original = None
    changed = uuid.uuid4()
    for _ in range(count):
        assert offset + 8 <= commands_end
        command, size = struct.unpack_from("<II", contents, offset)
        assert size >= 8 and offset + size <= commands_end
        if command == 0x1B:  # LC_UUID identifies the image already mapped by old shims.
            assert size == 24 and original is None
            original = uuid.UUID(bytes=bytes(contents[offset + 8:offset + 24]))
            contents[offset + 8:offset + 24] = changed.bytes
        offset += size
    assert original is not None and original != changed
    replacement.write_bytes(contents)
    subprocess.run(
        ["/usr/bin/codesign", "--force", "--timestamp=none", "--sign", "-",
         "--identifier", "dev.cengine.engine.test-compat", "--entitlements",
         str(REPO_ROOT / "Configuration/cengine.entitlements"), str(replacement)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", str(replacement)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
    )
    return replacement, original, changed


def _egress(container) -> None:
    code, output = container.exec_run([
        "sh", "-ec", "test \"$(cat /sys/class/net/eth0/carrier)\" = 1; "
        "timeout 15 nslookup registry-1.docker.io; timeout 10 nc -z -w 5 1.1.1.1 443",
    ])
    assert code == 0, output.decode(errors="replace")


def _restore_upgrade_daemon(daemon, original_binary: pathlib.Path) -> None:
    runtime_stopped = False
    try:
        try:
            daemon.stop()
        finally:
            try:
                _strict_shutdown(daemon)
            finally:
                # The original owner also covers its explicitly registered staged executable.
                terminate_compatibility_runtime(original_binary, roots=(daemon.root,))
                runtime_stopped = True
    finally:
        daemon.binary = original_binary
        if runtime_stopped:
            daemon.start()  # Preserve autouse daemon_survived and fixture cleanup ownership.


@pytest.mark.compat("RTM-056")
def test_same_path_upgrade_refuses_old_writer_then_preserves_data_and_egress(
    daemon, client: docker.DockerClient,
):
    original_binary = daemon.binary
    original_digest = hashlib.sha256(original_binary.read_bytes()).digest()
    staged_directory = daemon.work / "upgrade-bin"
    staged_directory.mkdir()
    staged_binary = (staged_directory / "cengine").resolve()
    shutil.copy2(original_binary, staged_binary)
    frameworks = original_binary.resolve().parent / "PackageFrameworks"
    if frameworks.is_dir():
        (staged_directory / "PackageFrameworks").symlink_to(frameworks, target_is_directory=True)

    register_compatibility_executable(daemon.work, original_binary, staged_binary)
    try:
        daemon.stop()
        _strict_shutdown(daemon)
        assert not compatibility_runtime_processes(original_binary, roots=(daemon.root,))
        daemon.binary = staged_binary
        daemon.start()

        suffix = uuid.uuid4().hex[:8]
        network = client.networks.create(f"upgrade-{suffix}")
        volume = client.volumes.create(f"upgrade-{suffix}")
        containers = []
        pending = []
        for policy in ("always", "unless-stopped"):
            container = client.containers.create(
                IMAGE, command="top", name=f"upgrade-{policy}-{suffix}",
                network=network.name, restart_policy={"Name": policy},
                mounts=[Mount(target="/data", source=volume.name, type="volume")],
            )
            pending.append((container, policy))
        # Both consumers must exist before first start to select shared storage
        # rather than permanently assigning the volume to one VM's block device.
        for container, policy in pending:
            container.start()
            marker = f"{policy}-{suffix}"
            code, output = container.exec_run([
                "sh", "-ec", f"printf '%s' '{marker}' > /upgrade-marker; "
                f"printf '%s' '{marker}' > /data/{policy}; sync",
            ])
            assert code == 0, output.decode(errors="replace")
            _egress(container)
            containers.append((container.id, policy, marker))

        spec_path = daemon.root / "infrastructure" / "shim.json"
        original_spec = spec_path.read_bytes()
        spec_inode = spec_path.stat().st_ino
        specification = json.loads(original_spec)
        writer = _status(specification)
        assert writer["state"] == "running"
        _assert_same_root_is_exclusive(daemon)
        assert _status(specification)["processIdentifier"] == writer["processIdentifier"]
        daemon.stop(kill=True)  # Retain both container VMs and their shared writer.
        old_processes = compatibility_runtime_processes(staged_binary, roots=(daemon.root,))
        old_pids = {process.pid for process in old_processes}
        assert writer["processIdentifier"] in old_pids
        assert len(old_pids) == len(containers) + 1

        replacement, old_uuid, new_uuid = _replacement_with_new_uuid(staged_binary)
        assert uuid.UUID(writer["executableUUID"]) == old_uuid
        os.replace(replacement, staged_binary)  # Never modify a mapped executable inode.
        assert uuid.UUID(_status(specification)["executableUUID"]) == old_uuid
        started = time.monotonic()
        with pytest.raises(pytest.fail.Exception, match=BUILD_MISMATCH):
            daemon.start()
        assert time.monotonic() - started < 30, "mismatch probe did not fail promptly"
        assert spec_path.read_bytes() == original_spec
        assert spec_path.stat().st_ino == spec_inode
        retained = _status(specification)
        for key in ("processIdentifier", "processStartTime", "executableUUID", "state"):
            assert retained[key] == writer[key], key
        assert {
            process.pid for process in compatibility_runtime_processes(
                staged_binary, roots=(daemon.root,),
            )
        } == old_pids, "refused startup replaced or launched a VM writer"

        _strict_shutdown(daemon)  # The updated executable must retire the old mapped peers.
        _assert_exited(old_pids.copy())
        assert not compatibility_runtime_processes(staged_binary, roots=(daemon.root,))
        daemon.start()
        new_specification = json.loads(spec_path.read_bytes())
        assert uuid.UUID(_status(new_specification)["executableUUID"]) == new_uuid
        assert client.volumes.get(volume.name).name == volume.name
        assert client.networks.get(network.id).id == network.id
        for container_id, policy, marker in containers:
            container = client.containers.get(container_id)
            # Strict administrative shutdown may record a manual stop; restore it explicitly.
            if container.status != "running":
                container.start()
            container.reload()
            assert container.attrs["HostConfig"]["RestartPolicy"]["Name"] == policy
            for path in ("/upgrade-marker", f"/data/{policy}"):
                code, output = container.exec_run(["cat", path])
                assert code == 0, output.decode(errors="replace")
                assert output.decode() == marker, f"{policy} {path}: {output!r}"
            _egress(container)
    finally:
        _restore_upgrade_daemon(daemon, original_binary)
        assert hashlib.sha256(original_binary.read_bytes()).digest() == original_digest


def _persisted_fabric(daemon) -> list[dict]:
    persisted = json.loads((daemon.root / "networks.json").read_bytes())
    networks = []
    for network_id, value in sorted(persisted.items()):
        record = value["record"]
        if not record["subnet"] and not record["ipv6Subnet"]:
            continue
        options = record.get("options") or {}
        isolated = any(
            record[f"enableIPv{family}"]
            and options.get(f"com.docker.network.bridge.gateway_mode_ipv{family}") == "isolated"
            for family in (4, 6)
        )
        networks.append({
            "id": network_id, "vlan": value["vlan"], "subnet": record["subnet"],
            "gateway": record["gateway"], "ipv6Subnet": record["ipv6Subnet"],
            "internalNetwork": record["internalNetwork"], "isolated": isolated, "ports": [],
        })
    return networks


@pytest.mark.compat("RTM-057")
def test_identical_failed_fabric_retries_reach_helper_then_restore_real_egress(
    daemon, client: docker.DockerClient,
):
    network = client.networks.create(f"fabric-retry-{uuid.uuid4().hex[:8]}")
    container = client.containers.create(IMAGE, command="top", network=network.name)
    container.start()
    _egress(container)
    specification = json.loads((daemon.root / "infrastructure" / "shim.json").read_bytes())
    writer = _status(specification)
    networks = _persisted_fabric(daemon)
    target = next(value for value in networks if value["id"] == network.id)
    assert target["subnet"] and not target["internalNetwork"] and not target["isolated"]
    invalid = [
        dict(value, gateway="not-an-ipv4-address") if value["id"] == network.id else value
        for value in networks
    ]
    network_state = (daemon.root / "networks.json").read_bytes()

    daemon.stop(kill=True)  # Retain the VMs without daemon reconciliation.
    try:
        for attempt in range(3):
            response = _shim_request(specification, "configureFabric", {"networks": invalid})
            # This exact error originates in the real privileged helper's vmnet validation,
            # not Docker metadata validation or a mocked/fault-injected uplink.
            failure = response.get("error")
            assert failure is not None, f"failed desired fabric was cached on retry {attempt}"
            assert "invalid IPv4 gateway not-an-ipv4-address" in failure["message"], failure
        assert (daemon.root / "networks.json").read_bytes() == network_state
    finally:
        try:
            _successful_payload(_shim_request(
                specification, "configureFabric", {"networks": networks},
            ))
        finally:
            daemon.start()

    restored = _status(specification)
    assert restored["processIdentifier"] == writer["processIdentifier"]
    assert restored["processStartTime"] == writer["processStartTime"]
    container.reload()
    assert container.status == "running"
    _egress(container)
    # Also exercise Docker's real attachment path after repairing the failed uplink.
    attached = client.containers.create(IMAGE, command="top", network=network.name)
    attached.start()
    _egress(attached)
