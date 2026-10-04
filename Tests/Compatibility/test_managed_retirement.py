"""RTM-111: short-lived managed consumers must not poison later volume starts.

Direct Docker API reduction of CMP-006; no Compose or application write race.
Four two-reader rounds exercise concurrent admission/retirement, not a guaranteed
scheduler overlap (the gated Swift unit regression supplies that proof).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import threading
import uuid

from docker.types import Mount
import pytest

from storage_backend_proof import daemon_startup_mode, verify_backend
from test_volume_discovery import ALPINE, LABELS, _cleanup


MARKER = b"rtm111-persistent-marker\n"


@pytest.fixture
def image_cache(image_cache):
    # Preserve ordinary image seeding/cache and validate startup before launch.
    from conftest import managed_storage_arguments
    managed_storage_arguments(os.environ)
    return image_cache


@pytest.fixture
def retirement_volume(client):
    previous_timeout = client.api.timeout
    client.api.timeout = 120
    containers = []
    volume = None
    try:
        volume = client.volumes.create("rtm111-" + uuid.uuid4().hex, labels=LABELS)
        yield volume, containers
    finally:
        try:
            if volume is not None:
                _cleanup(containers, volume)
        finally:
            client.api.timeout = previous_timeout


@pytest.mark.compat("RTM-111")
def test_managed_volume_short_lived_concurrent_starts(client, daemon, retirement_volume):
    volume, containers = retirement_volume
    assert daemon_startup_mode(daemon) == "lifecycle"

    def create(suffix, *, seed=False):
        script = "cat /data/marker; cat /proc/self/mountinfo"
        if seed:
            script = "printf 'rtm111-persistent-marker\\n' > /data/marker; sync; " + script
        container = client.containers.create(
            ALPINE, ["timeout", "20", "sh", "-ec", script],
            name=volume.name + "-" + suffix, labels=LABELS,
            network_mode="none", read_only=True,
            mounts=[Mount("/data", volume.name, type="volume", no_copy=True)],
        )
        containers.append(container)
        return container

    def start(container):
        # Require a real new start, not Docker's 304 already-started response.
        with client.api._post(client.api._url("/containers/{0}/start", container.id)) as response:
            client.api._raise_for_status(response)
            assert response.status_code == 204, (container.name, response.status_code)

    def completed(container):
        result = container.wait(timeout=30)
        output = container.logs(stdout=True, stderr=False)
        errors = container.logs(stdout=False, stderr=True)
        assert result["StatusCode"] == 0, (container.name, result, output, errors)
        assert not errors, (container.name, errors)
        marker, separator, mountinfo = output.partition(b"\n")
        assert marker + separator == MARKER, (container.name, output)
        proof = verify_backend(daemon.root, "shared", mountinfo.decode(),
                               startup_mode=daemon_startup_mode(daemon))
        assert proof["mode"] == "lifecycle", proof
        container.remove()
        containers.remove(container)

    # Both references precede the FIRST start: never silently select direct ext4.
    seed = create("seed", seed=True)
    final_reader = create("final")
    start(seed)
    completed(seed)

    for round_number in range(4):
        readers = [create(f"round-{round_number}-{index}") for index in range(2)]
        barrier = threading.Barrier(2, timeout=10)

        def concurrent_start(container):
            barrier.wait()
            start(container)

        # Both HTTP requests finish before removal/fixture cleanup; no retries,
        # sleeps, or API-error recovery that could conceal admission failures.
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(concurrent_start, container) for container in readers]
            for future in futures:
                future.result(timeout=135)
        for container in readers:
            completed(container)
        assert client.volumes.get(volume.name).name == volume.name

    start(final_reader)
    completed(final_reader)
    assert client.volumes.get(volume.name).name == volume.name


@pytest.mark.compat("RTM-112")
def test_managed_shared_normal_exit_preserves_status_output_and_contains_execs(
    client, daemon, retirement_volume,
):
    from docker.errors import APIError
    from test_runtime_semantics import wait_for_compat_value
    from test_volume_discovery import _exec

    volume, containers = retirement_volume
    assert daemon_startup_mode(daemon) == "lifecycle"
    marker = "rtm112-" + uuid.uuid4().hex
    script = (
        "mkfifo /tmp/rtm112-release; "
        "timeout 60 cat /tmp/rtm112-release >/dev/null; "
        f'test "$(cat /data/release)" = {marker}; '
        "printf 'rtm112-final-stdout\\n'; "
        "printf 'rtm112-final-stderr\\n' >&2; exit 23"
    )
    for suffix, command in (("main", ["sh", "-ec", script]), ("peer", ["true"])):
        containers.append(client.containers.create(
            ALPINE, command, name=marker + "-" + suffix, labels=LABELS,
            network_mode="none", mounts=[Mount("/data", volume.name, type="volume")],
        ))
    main, peer = containers
    # Both references exist before the first start, forcing shared, not ext4.
    main.start()
    assert client.api.inspect_container(peer.id)["State"]["Status"] == "created"
    wait_for_compat_value(
        lambda: _exec(main, "sh", "-ec", "if test -p /tmp/rtm112-release; then printf ready; fi"),
        b"ready", "PID 1 release gate", timeout=10,
    )
    mountinfo = _exec(main, "cat", "/proc/self/mountinfo")
    proof = verify_backend(daemon.root, "shared", mountinfo.decode(),
                           startup_mode=daemon_startup_mode(daemon))
    assert proof["mode"] == "lifecycle", proof

    exec_ids = []

    def running_execs():
        states = [client.api.exec_inspect(exec_id) for exec_id in exec_ids]
        return all(state["Running"] and state["Pid"] > 0 for state in states)

    for index in range(2):
        exec_marker = f"{marker}-exec-{index}"
        exec_id = client.api.exec_create(
            main.id, ["sh", "-ec", "sleep 60; :", exec_marker],
        )["Id"]
        exec_ids.append(exec_id)
        client.api.exec_start(exec_id, detach=True)
        wait_for_compat_value(running_execs, True, "active execs with PIDs", timeout=10)
        pid = client.api.exec_inspect(exec_id)["Pid"]
        assert exec_marker.encode() in _exec(main, "cat", f"/proc/{pid}/cmdline").split(b"\0")
    assert len(set(exec_ids)) == 2

    # A shell releases the waiting shell PID 1; neither is a lone exec.
    release_id = client.api.exec_create(main.id, [
        "timeout", "60", "sh", "-ec",
        f"printf '%s' {marker} > /data/release; printf go > /tmp/rtm112-release; :",
    ])["Id"]
    client.api.exec_start(release_id, detach=True)
    result = main.wait(timeout=60)
    output = main.logs(stdout=True, stderr=False)
    errors = main.logs(stdout=False, stderr=True)
    assert (result["StatusCode"], output, errors) == (
        23, b"rtm112-final-stdout\n", b"rtm112-final-stderr\n",
    ), (result, output, errors)
    for exec_id in exec_ids:
        def terminal_state():
            state = client.api.exec_inspect(exec_id)
            return state["Running"], state["ExitCode"] is not None

        wait_for_compat_value(
            terminal_state, (False, True), f"retired exec {exec_id}", timeout=10,
        )
    with pytest.raises(APIError) as rejected:
        client.api.exec_create(main.id, ["true"])
    assert rejected.value.status_code == 409
