"""RTM-072: attached exec must activate output before waiting on PID metadata.

Docker API ExecStart (non-detached, non-TTY) upgrades to the multiplexed stream;
ExecInspect reports completion. This probe uses only the image root, never binds.
"""
from __future__ import annotations

import concurrent.futures
import json
import socket
import struct
import time
import uuid

import docker
import pytest


@pytest.mark.compat("RTM-072")
def test_attached_exec_immediate_output_activates_without_metadata_deadlock(client, daemon):
    # One collected contract ID; all four boundary sizes remain mandatory.
    for size in (8191, 8192, 8193, 32768):
        _assert_immediate_output(client, daemon, size)


def _assert_immediate_output(client, daemon, size):
    container = client.containers.create(
        "alpine:latest", ["sleep", "120"],
        name="exec-output-start-" + uuid.uuid4().hex, network_mode="none",
        labels={"dev.cengine.compat": "true"},
    )
    try:
        container.start()
        # printf starts writing immediately: no bind, file read, sleep, retry,
        # preflight exec or readiness exchange can hide the startup dependency.
        payload = (b"0123456789abcdef" * ((size + 15) // 16))[:size]
        stderr = b"exec-output-start-stderr\n"
        command = "printf '%s' '" + payload.decode() + "'; printf '%s\\n' exec-output-start-stderr >&2; exit 23"
        exec_id = client.api.exec_create(
            container.id, ["sh", "-c", command], stdout=True, stderr=True,
        )["Id"]
        body = json.dumps({"Detach": False, "Tty": False}).encode()
        request = (
            f"POST /v{client.api._version}/exec/{exec_id}/start HTTP/1.1\r\n"
            "Host: localhost\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        deadline = time.monotonic() + 20
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(5)
            stream.connect(str(daemon.socket))
            stream.sendall(request)

            def inspect_in_parallel():
                # A separate client/connection exercises a guest-backed control
                # RPC while the attached output stream is starting/draining.
                with docker.APIClient(
                    base_url=f"unix://{daemon.socket}", version=client.api._version,
                    timeout=5,
                ) as control:
                    return control.exec_inspect(exec_id)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                control = pool.submit(inspect_in_parallel)
                received = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    assert remaining > 0, f"exec output deadline exceeded at {size} bytes"
                    stream.settimeout(remaining)
                    chunk = stream.recv(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
                assert control.result(timeout=5)["ID"] == exec_id
        headers, separator, frames = bytes(received).partition(b"\r\n\r\n")
        assert separator and headers.split(b"\r\n", 1)[0].startswith(b"HTTP/1.1 101"), headers
        outputs = {1: bytearray(), 2: bytearray()}
        while frames:
            assert len(frames) >= 8, "truncated Docker stream header"
            channel, reserved, length = frames[0], frames[1:4], struct.unpack(">I", frames[4:8])[0]
            assert channel in outputs and reserved == b"\0\0\0"
            assert len(frames) >= 8 + length, "truncated Docker stream payload"
            outputs[channel].extend(frames[8:8 + length])
            frames = frames[8 + length:]
        assert bytes(outputs[1]) == payload
        assert bytes(outputs[2]) == stderr
        # Completion shares the original whole-operation deadline; getting all
        # bytes is insufficient if the host's completion monitor stays blocked.
        with docker.APIClient(
            base_url=f"unix://{daemon.socket}", version=client.api._version, timeout=5,
        ) as control:
            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, f"exec completion deadline exceeded at {size} bytes"
                control.timeout = min(5, remaining)
                inspected = control.exec_inspect(exec_id)
                if not inspected["Running"]:
                    assert inspected["ExitCode"] == 23
                    break
                time.sleep(min(0.01, remaining))
        assert time.monotonic() < deadline
    finally:
        container.remove(force=True)
