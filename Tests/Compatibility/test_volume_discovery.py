"""Focused copy-up and shared-volume sync regressions (not power-loss tests)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import uuid

import docker
from docker.types import Mount
import pytest

from volume_probe import close_exec_stream, tar_bytes
from storage_backend_proof import daemon_startup_mode, verify_backend


ALPINE = "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
LABELS = {"dev.cengine.compat": "true"}
SENTINEL = b"rtm055-authoritative-lost-found-data\n"

# os.File.Sync issues real fsync calls for BOTH the file and its parent directory.
# Keep this stdlib-only fixture here so the regression has no builder dependency.
SYNC_PROBE = r'''
package main

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "time"
)

func run() error {
    if len(os.Args) < 3 {
        return fmt.Errorf("expected write/read and path")
    }
    path := os.Args[2]
    result := map[string]any{}
    switch os.Args[1] {
    case "write":
        if len(os.Args) != 4 {
            return fmt.Errorf("expected payload")
        }
        data := []byte(strings.Repeat(os.Args[3], 8192))
        f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
        if err != nil { return err }
        defer f.Close()
        n, err := f.Write(data)
        if err != nil { return err }
        if n != len(data) { return io.ErrShortWrite }
        if err := f.Sync(); err != nil { return fmt.Errorf("file fsync: %w", err) }
        if err := f.Close(); err != nil { return err }
        directory, err := os.Open(filepath.Dir(path))
        if err != nil { return err }
        defer directory.Close()
        if err := directory.Sync(); err != nil { return fmt.Errorf("directory fsync: %w", err) }
        if err := directory.Close(); err != nil { return err }
        result["file_sync"], result["directory_sync"] = true, true
    case "read":
    default:
        return fmt.Errorf("unknown operation")
    }
    // A fresh descriptor after all write descriptors were closed; ReadFile closes it.
    data, err := os.ReadFile(path)
    if err != nil { return err }
    result["sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
    result["size"] = len(data)
    return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
    time.AfterFunc(30*time.Second, func() {
        fmt.Fprintln(os.Stderr, "sync probe timed out")
        os.Exit(124)
    })
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
'''


def _storage_mode(daemon, volume, expected, containers=(), destination="/data"):
    modes = json.loads((daemon.root / "volume-storage.json").read_text())
    assert modes[volume.name] == expected, modes
    for container in containers:
        text = _exec(container, "cat", "/proc/self/mountinfo").decode()
        proof = verify_backend(daemon.root, expected, text, destination,
                               startup_mode=daemon_startup_mode(daemon))
        directory = Path(__file__).resolve().parents[2] / ".build/volume-hunt/backend-proofs"
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / (volume.name + ".jsonl")).open("a") as output:
            output.write(json.dumps({"container": container.id, "proof": proof}) + "\n")


def _exec(container, *command):
    # One host deadline includes create/start/inspect, not only the hijacked
    # stream. Guest timeout and the Go watchdog remain independent safeguards.
    api = container.client.api
    previous_timeout = api.timeout
    deadline = time.monotonic() + 50

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("exec deadline exceeded")
        return value

    try:
        api.timeout = remaining()
        exec_id = api.exec_create(
            container.id, ["timeout", "40", *command], stdout=True, stderr=True,
        )["Id"]
        api.timeout = remaining()
        stream = api.exec_start(exec_id, socket=True)
        raw_socket = getattr(stream, "_sock", stream)
        data = bytearray()
        try:
            while True:
                raw_socket.settimeout(remaining())
                chunk = raw_socket.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                assert len(data) <= 65536, "unexpectedly large probe output"
        finally:
            close_exec_stream(stream)
        # Non-TTY Docker exec uses an eight-byte stdout/stderr frame header.
        output = bytearray()
        while data:
            assert len(data) >= 8, "truncated exec frame header"
            channel, length = struct.unpack(">BxxxI", data[:8])
            assert channel in (1, 2) and len(data) >= 8 + length, "invalid exec frame"
            output.extend(data[8:8 + length])
            del data[:8 + length]
        api.timeout = remaining()
        status = api.exec_inspect(exec_id)
        remaining()
        assert status["ExitCode"] == 0, output.decode(errors="replace")
        return bytes(output)
    finally:
        api.timeout = previous_timeout


def _create(client, containers, volume, target, *, no_copy):
    container = client.containers.create(
        ALPINE, command=["sleep", "600"], network_mode="none", labels=LABELS,
        mounts=[Mount(target=target, source=volume.name, type="volume", no_copy=no_copy)],
    )
    containers.append(container)
    return container


def _cleanup(containers, volume, client=None):
    errors = []
    for container in reversed(containers):
        try:
            (client or container.client).api.remove_container(container.id, force=True)
        except docker.errors.NotFound:
            pass
        except Exception as error:
            errors.append(str(error))
    try:
        # Use known owned identities directly, even if post-restart inspect fails.
        (client or volume.client).api.remove_volume(volume.name)  # Never prune.
    except docker.errors.NotFound:
        pass
    except Exception as error:
        errors.append(str(error))
    if errors:
        message = "owned volume cleanup failed: " + "; ".join(errors)
        if sys.exc_info()[0] is not None:
            print(message)
        else:
            raise AssertionError(message)


def _assert_lost_found(container):
    output = _exec(container, "sh", "-ec", """
        test "$(ls -A /etc/apk)" = lost+found
        test "$(ls -A /etc/apk/lost+found)" = sentinel
        stat -c '%u:%g:%a' /etc/apk
        stat -c '%u:%g:%a' /etc/apk/lost+found/sentinel
        sha256sum /etc/apk/lost+found/sentinel
        cat /etc/apk/lost+found/sentinel
    """)
    lines = output.splitlines()
    assert lines[:2] == [b"12345:23456:711", b"12345:23456:640"], output
    assert lines[2].split()[0].decode() == hashlib.sha256(SENTINEL).hexdigest(), output
    assert b"\n".join(lines[3:]) + b"\n" == SENTINEL, output


@pytest.mark.compat("RTM-058")
def test_volume_lost_found_data_remains_authoritative(daemon, client: docker.DockerClient):
    # A single ledger ID, with a fresh volume for each backend selection.
    for storage in ("block", "shared"):
        print(f"lost+found backend: {storage}")
        volume = client.volumes.create(f"rtm055-{storage}-{uuid.uuid4().hex[:12]}", labels=LABELS)
        containers = []
        try:
            keeper = None
            if storage == "shared":
                keeper = _create(client, containers, volume, "/etc/apk", no_copy=True)
            first = _create(client, containers, volume, "/etc/apk", no_copy=True)
            # BOTH shared consumers are known before the FIRST start.
            first.start()
            _storage_mode(daemon, volume, storage, [first], "/etc/apk")
            _exec(first, "sh", "-ec", """
                mkdir -p /etc/apk/lost+found
                printf 'rtm055-authoritative-lost-found-data\n' > /etc/apk/lost+found/sentinel
                chown 12345:23456 /etc/apk /etc/apk/lost+found/sentinel
                chmod 0711 /etc/apk
                chmod 0640 /etc/apk/lost+found/sentinel
            """)
            _assert_lost_found(first)
            # Remove the sole block consumer before creating a replacement, so
            # that case cannot silently select the shared backend instead.
            first.remove(force=True)
            containers.remove(first)
            replacement = _create(client, containers, volume, "/etc/apk", no_copy=False)
            replacement.start()
            _storage_mode(daemon, volume, storage, [replacement], "/etc/apk")
            # /etc/apk in pinned Alpine contains repositories, keys, etc. None
            # may seed this nonempty volume or replace its authoritative root.
            _assert_lost_found(replacement)
            if keeper is not None:
                keeper.start()
                _storage_mode(daemon, volume, "shared", [keeper], "/etc/apk")
                _assert_lost_found(keeper)
        finally:
            _cleanup(containers, volume)


@pytest.fixture
def sync_probe_archive(tmp_path):
    source = tmp_path / "sync-probe.go"
    binary = tmp_path / "sync-probe"
    source.write_text(SYNC_PROBE)
    subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), str(source)],
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off"},
        check=True, capture_output=True, text=True, timeout=120,
    )
    return tar_bytes([("sync-probe", binary.read_bytes(), 0o755)])


def _readback(container, expected):
    # Each invocation opens and closes a fresh file descriptor.
    for _ in range(2):
        result = json.loads(_exec(container, "/tmp/sync-probe", "read", "/data/payload"))
        assert result == expected
    return result


@pytest.mark.compat("RTM-059")
def test_shared_volume_sync_and_cross_consumer_readback(
    daemon, client: docker.DockerClient, sync_probe_archive,
):
    token = uuid.uuid4().hex
    volume = client.volumes.create(f"rtm056-{token[:12]}", labels=LABELS)
    containers = []
    recovered = None
    try:
        writer = _create(client, containers, volume, "/data", no_copy=True)
        consumer = _create(client, containers, volume, "/data", no_copy=True)
        # Fresh shared selection: both creates precede either start.
        for container in containers:
            container.start()
            assert container.put_archive("/tmp", sync_probe_archive)
        _storage_mode(daemon, volume, "shared", containers)
        for source, peer, payload in (
            (writer, consumer, "writer-synced-data\n"),
            (consumer, writer, "consumer-replaced-synced-data\n"),
        ):
            data = payload.encode() * 8192  # Bounded nonempty payload, not an empty-file shortcut.
            expected = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
            result = json.loads(_exec(source, "/tmp/sync-probe", "write", "/data/payload", payload))
            assert result == {**expected, "file_sync": True, "directory_sync": True}
            _readback(peer, expected)
            _readback(source, expected)
        # Graceful workload restarts exercise reopen and cross-consumer visibility.
        # This is NOT proof of storage-VM loss, host crash, or physical power-loss durability.
        for container in containers:
            container.restart(timeout=5)
        _storage_mode(daemon, volume, "shared", containers)
        for container in containers:
            _readback(container, expected)
        # Record the acknowledged bytes OUTSIDE the storage VM and ephemeral
        # daemon root, then kill only this test's API daemon. Storage/workload
        # VMs remain alive: this is adoption, never physical power-loss proof.
        directory = Path(__file__).resolve().parents[2] / ".build/volume-hunt" / ("rtm056-" + token)
        directory.mkdir(parents=True)
        acknowledgment = {"expected": expected, "containers": [c.id for c in containers],
                          "volume": volume.name, "storage": "shared", "image": ALPINE,
                          "fault": "API daemon SIGKILL; storage VM remains alive"}
        with (directory / "acknowledged.json").open("w") as output:
            json.dump(acknowledgment, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        # Construct a fresh pool before restart without an API negotiation call,
        # so cleanup can use it even if restart, ping or recovery inspect fails.
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=60, version=client.api._version,
        )
        daemon.restart(kill=True)
        assert recovered.ping()
        containers = [recovered.containers.get(c.id) for c in containers]
        volume = recovered.volumes.get(volume.name)
        _storage_mode(daemon, volume, "shared", containers)
        observations = []
        for container in containers:
            assert container.attrs["State"]["Running"], container.attrs["State"]
            observations.append({
                "container": container.id, "state": container.attrs["State"],
                "acknowledged_readback": _readback(container, expected),
            })
        # Pre-kill bytes alone could pass with two mistakenly adopted copies.
        # A new write must still be visible through the other consumer VM.
        payload = "post-adoption-shared-write\n"
        data = payload.encode() * 8192
        expected_after = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        result = json.loads(_exec(containers[0], "/tmp/sync-probe", "write", "/data/payload", payload))
        assert result == {**expected_after, "file_sync": True, "directory_sync": True}
        for observation, container in zip(observations, containers):
            observation["post_adoption_readback"] = _readback(container, expected_after)
        (directory / "recovered.json").write_text(json.dumps({
            "acknowledgment": acknowledgment, "post_adoption_write": result,
            "observations": observations,
        }, indent=2) + "\n")
    finally:
        try:
            _cleanup(containers, volume, client=recovered)
        finally:
            if recovered is not None:
                recovered.close()
