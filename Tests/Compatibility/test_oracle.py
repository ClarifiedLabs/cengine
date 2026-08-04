"""Optional differential contracts against an explicitly selected Docker Engine."""

from __future__ import annotations

import json
import os
import uuid

import docker
import pytest
from docker import errors


IMAGE = os.environ.get("CENGINE_TEST_IMAGE", "alpine:latest")
pytestmark = pytest.mark.oracle


def lifecycle_contract(value: docker.DockerClient, name: str) -> dict:
    container = value.containers.create(
        IMAGE, command="top", name=name, labels={"dev.cengine.compat.oracle": name}
    )
    try:
        created = value.api.inspect_container(container.id)
        container.start()
        try:
            container.remove()
            conflict = None
        except errors.APIError as error:
            conflict = error.response.status_code
        listed = value.containers.list(all=True, filters={"label": f"dev.cengine.compat.oracle={name}"})
        container.stop(timeout=1)
        container.reload()
        return {
            "create_keys": sorted({"Id", "Name", "State", "Config", "HostConfig", "Mounts", "NetworkSettings"} & created.keys()),
            "created_status": created["State"]["Status"],
            "running_remove_status": conflict,
            "label_filter_count": len(listed),
            "final_status": container.attrs["State"]["Status"],
            "field_types": {
                "Mounts": type(created["Mounts"]).__name__,
                "Config": type(created["Config"]).__name__,
                "HostConfig": type(created["HostConfig"]).__name__,
            },
        }
    finally:
        try:
            container.remove(force=True)
        except errors.NotFound:
            pass


@pytest.mark.compat("ORC-001")
def test_container_lifecycle_matches_reference_docker(client: docker.DockerClient):
    host = os.environ.get("DOCKER_REFERENCE_HOST")
    if not host:
        pytest.skip("set DOCKER_REFERENCE_HOST to run Docker differential contracts")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        platform = reference.version().get("Platform", {}).get("Name", "")
        if platform == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must identify a reference Docker Engine, not cengine")
        reference.ping()
        reference.images.pull(IMAGE)
        suffix = uuid.uuid4().hex[:8]
        expected = lifecycle_contract(reference, f"compat-oracle-reference-{suffix}")
        actual = lifecycle_contract(client, f"compat-oracle-cengine-{suffix}")
        assert actual == expected
    finally:
        reference.close()


def image_metadata_contract(value: docker.DockerClient) -> dict:
    platform = json.dumps({"os": "linux", "architecture": "arm64"}, separators=(",", ":"))
    response = value.api._get(
        value.api._url("/images/{0}/json", IMAGE), params={"platform": platform},
    )
    value.api._raise_for_status(response)
    inspected = response.json()
    listed_response = value.api._get(
        value.api._url("/images/json"), params={"manifests": "true"},
    )
    value.api._raise_for_status(listed_response)
    listed = next(item for item in listed_response.json() if IMAGE in item.get("RepoTags", []))
    manifests = listed.get("Manifests") or []
    selected = next(
        (
            item for item in manifests
            if item.get("Kind") == "image"
            and (item.get("ImageData") or {}).get("Platform", {}).get("architecture") == "arm64"
        ),
        None,
    )
    return {
        "inspect_descriptor": isinstance(inspected.get("Descriptor"), dict),
        "inspect_identity": isinstance(inspected.get("Identity"), dict),
        "architecture": inspected.get("Architecture"),
        "os": inspected.get("Os"),
        "manifest_shape": None if selected is None else {
            "available": type(selected.get("Available")).__name__,
            "descriptor": isinstance(selected.get("Descriptor"), dict),
            "kind": selected.get("Kind"),
            "platform": (selected.get("ImageData") or {}).get("Platform"),
            "size_keys": sorted((selected.get("Size") or {}).keys()),
        },
    }


@pytest.mark.compat("ORC-002")
def test_image_metadata_matches_reference_docker(client: docker.DockerClient):
    host = os.environ.get("DOCKER_REFERENCE_HOST")
    if not host:
        pytest.skip("set DOCKER_REFERENCE_HOST to run Docker differential contracts")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        if reference.version().get("Platform", {}).get("Name", "") == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must identify a reference Docker Engine, not cengine")
        reference.images.pull(IMAGE, platform="linux/arm64")
        expected = image_metadata_contract(reference)
        if expected["manifest_shape"] is None or not expected["inspect_descriptor"]:
            pytest.skip("reference Docker Engine does not use a multi-platform image store")
        assert image_metadata_contract(client) == expected
    finally:
        reference.close()


def api_error_shape(error: errors.APIError) -> dict:
    keys: list[str] = []
    if error.response is not None:
        try:
            body = error.response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            keys = sorted(body)
    return {
        "http_class": (
            error.response.status_code // 100 if error.response is not None else None
        ),
        "response_keys": keys,
    }


def exec_outcome(
    value: docker.DockerClient,
    container_id: str,
    command: list[str],
    **options,
) -> dict:
    try:
        created = value.api.exec_create(container_id, command, **options)
    except errors.APIError as error:
        return {"phase": "create", **api_error_shape(error)}
    exec_id = created["Id"]
    try:
        output = value.api.exec_start(
            exec_id, detach=False, tty=bool(options.get("tty", False)),
        )
    except errors.APIError as error:
        return {"phase": "start", **api_error_shape(error)}
    inspected = value.api.exec_inspect(exec_id)
    exit_code = inspected.get("ExitCode")
    if exit_code == 0:
        exit_category = "success"
    elif exit_code in (126, 127):
        exit_category = str(exit_code)
    else:
        exit_category = "other"
    normalized_output = output.replace(b"\r\n", b"\n").decode(errors="replace").strip()
    outcome = {
        "phase": "complete",
        "exit_category": exit_category,
        "running": inspected.get("Running"),
    }
    if exit_category == "success":
        outcome["output"] = normalized_output
    else:
        outcome["diagnostic"] = bool(normalized_output)
    return outcome


def failed_init_outcome(
    value: docker.DockerClient, name: str, user: str,
) -> dict:
    container = value.containers.create(IMAGE, ["true"], name=name, user=user)
    try:
        try:
            container.start()
        except errors.APIError as error:
            container.reload()
            return {
                "phase": "start",
                **api_error_shape(error),
                "status": container.status,
                "running": container.attrs["State"]["Running"],
            }
        container.reload()
        return {
            "phase": "complete",
            "status": container.status,
            "running": container.attrs["State"]["Running"],
        }
    finally:
        container.remove(force=True)


def no_new_privileges_outcome(
    value: docker.DockerClient, name: str, security_opt: list[str] | None = None,
) -> dict:
    options = {} if security_opt is None else {"security_opt": security_opt}
    container = value.containers.create(
        IMAGE,
        ["sh", "-ec", "awk '/^NoNewPrivs:/ {print $2}' /proc/self/status"],
        name=name,
        **options,
    )
    try:
        container.start()
        result = container.wait(timeout=30)
        return {
            "exit_code": result["StatusCode"],
            "output": container.logs().decode(errors="replace").strip(),
        }
    finally:
        container.remove(force=True)


def runtime_process_context_contract(
    value: docker.DockerClient, name: str,
) -> dict:
    probe = (
        "printf 'uid=%s gid=%s cwd=%s context=%s tty=%s nnp=%s seccomp=%s cap=%s\\n' "
        "\"$(id -u)\" \"$(id -g)\" \"$PWD\" \"${CONTEXT-unset}\" "
        "\"$(test -t 1 && echo 1 || echo 0)\" "
        "\"$(awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status)\" "
        "\"$(awk '/^Seccomp:/ { print $2 }' /proc/self/status)\" "
        "\"$(awk '/^CapEff:/ { print $2 }' /proc/self/status)\""
    )
    container = value.containers.create(
        IMAGE, ["sh", "-ec", "while :; do sleep 1; done"],
        name=name, user="nobody", working_dir="/tmp",
        environment={"CONTEXT": "container"},
        security_opt=["no-new-privileges=true"],
    )
    try:
        container.start()
        return {
            "default_no_new_privileges": no_new_privileges_outcome(
                value, f"{name}-default-nnp",
            ),
            "explicit_false_no_new_privileges": no_new_privileges_outcome(
                value, f"{name}-false-nnp", ["no-new-privileges=false"],
            ),
            "omitted": exec_outcome(value, container.id, ["sh", "-ec", probe]),
            "explicit": exec_outcome(
                value, container.id, ["sh", "-ec", probe],
                user="root:root", workdir="/", environment={"CONTEXT": "exec"},
                tty=True, privileged=True,
            ),
            "missing_exec_user": exec_outcome(
                value, container.id, ["true"], user="oracle-missing-user",
            ),
            "missing_exec_group": exec_outcome(
                value, container.id, ["true"], user="root:oracle-missing-group",
            ),
            "missing_init_user": failed_init_outcome(
                value, f"{name}-missing-user", "oracle-missing-user",
            ),
            "missing_init_group": failed_init_outcome(
                value, f"{name}-missing-group", "root:oracle-missing-group",
            ),
        }
    finally:
        container.remove(force=True)


@pytest.mark.compat("ORC-003")
def test_runtime_process_context_matches_reference_docker(client: docker.DockerClient):
    host = os.environ.get("DOCKER_REFERENCE_HOST")
    if not host:
        pytest.skip("set DOCKER_REFERENCE_HOST to run Docker differential contracts")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        if reference.version().get("Platform", {}).get("Name", "") == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must identify a reference Docker Engine, not cengine")
        reference.ping()
        reference.images.pull(IMAGE)
        suffix = uuid.uuid4().hex[:8]
        expected = runtime_process_context_contract(
            reference, f"compat-oracle-runtime-reference-{suffix}",
        )
        actual = runtime_process_context_contract(
            client, f"compat-oracle-runtime-cengine-{suffix}",
        )
        for key in (
            "default_no_new_privileges", "explicit_false_no_new_privileges",
            "omitted", "explicit", "missing_exec_user", "missing_exec_group",
            "missing_init_user", "missing_init_group",
        ):
            assert actual[key] == expected[key]
    finally:
        reference.close()


def create_rejection_outcome(
    value: docker.DockerClient, name: str, host_config: dict,
) -> dict:
    initial_volumes = {volume.name for volume in value.volumes.list()}
    try:
        response = value.api._post_json(
            value.api._url("/containers/create"),
            params={"name": name},
            data={
                "Image": IMAGE,
                "Cmd": ["true"],
                "Volumes": {"/oracle-must-not-leak": {}},
                "HostConfig": host_config,
            }
        )
        value.api._raise_for_status(response)
    except errors.APIError as error:
        volume_delta = {volume.name for volume in value.volumes.list()} - initial_volumes
        try:
            container = value.containers.get(name)
            container_created = True
            container.remove(force=True, v=True)
        except errors.NotFound:
            container_created = False
        for volume_name in volume_delta:
            try:
                value.volumes.get(volume_name).remove(force=True)
            except errors.NotFound:
                pass
        return {
            "http_class": (
                error.response.status_code // 100 if error.response is not None else None
            ),
            "response_keys": api_error_shape(error)["response_keys"],
            "container_created": container_created,
            "volume_delta": len(volume_delta),
        }
    container = value.containers.get(name)
    volume_delta = {volume.name for volume in value.volumes.list()} - initial_volumes
    container.remove(force=True, v=True)
    return {
        "http_class": 2,
        "response_keys": [],
        "container_created": True,
        "volume_delta": len(volume_delta),
    }


def ulimit_start_outcome(
    value: docker.DockerClient, name: str, limits: list[dict],
) -> dict:
    initial_volumes = {volume.name for volume in value.volumes.list()}
    response = value.api._post_json(
        value.api._url("/containers/create"),
        params={"name": name},
        data={
            "Image": IMAGE,
            "Cmd": ["true"],
            "Volumes": {"/oracle-ulimit-volume": {}},
            "HostConfig": {"Ulimits": limits},
        },
    )
    try:
        value.api._raise_for_status(response)
    except errors.APIError as error:
        volume_delta = {volume.name for volume in value.volumes.list()} - initial_volumes
        try:
            container = value.containers.get(name)
            container_created = True
            container.remove(force=True, v=True)
        except errors.NotFound:
            container_created = False
        for volume_name in volume_delta:
            try:
                value.volumes.get(volume_name).remove(force=True)
            except errors.NotFound:
                pass
        return {
            "phase": "create",
            **api_error_shape(error),
            "container_created": container_created,
            "volume_delta": len(volume_delta),
        }
    container = value.containers.get(response.json()["Id"])
    try:
        volume_delta = {volume.name for volume in value.volumes.list()} - initial_volumes
        try:
            container.start()
        except errors.APIError as error:
            container.reload()
            return {
                "phase": "start",
                **api_error_shape(error),
                "status": container.status,
                "running": container.attrs["State"]["Running"],
                "ulimits": container.attrs["HostConfig"]["Ulimits"],
                "volume_delta": len(volume_delta),
            }
        container.wait(timeout=30)
        container.reload()
        return {
            "phase": "complete",
            "status": container.status,
            "running": container.attrs["State"]["Running"],
            "ulimits": container.attrs["HostConfig"]["Ulimits"],
            "volume_delta": len(volume_delta),
        }
    finally:
        container.remove(force=True, v=True)


def runtime_error_contract(value: docker.DockerClient, name: str) -> dict:
    container = value.containers.create(
        IMAGE, ["sh", "-ec", "while :; do sleep 1; done"], name=name,
    )
    try:
        container.start()
        return {
            "invalid_user": exec_outcome(
                value, container.id, ["true"], user="oracle-missing-user",
            ),
            "invalid_cwd": exec_outcome(
                value, container.id, ["true"], workdir="/oracle/missing/cwd",
            ),
            "invalid_command": exec_outcome(
                value, container.id, ["/oracle/missing/command"],
            ),
            "invalid_ulimit": ulimit_start_outcome(
                value, f"{name}-invalid-ulimit",
                [{"Name": "nofile", "Soft": 1024, "Hard": 512}],
            ),
            "invalid_mount": create_rejection_outcome(
                value, f"{name}-invalid-mount",
                {"Mounts": [{"Type": "volume", "Target": "relative"}]},
            ),
        }
    finally:
        container.remove(force=True)


@pytest.mark.compat("ORC-004")
def test_runtime_error_contract_against_reference_docker(client: docker.DockerClient):
    host = os.environ.get("DOCKER_REFERENCE_HOST")
    if not host:
        pytest.skip("set DOCKER_REFERENCE_HOST to run Docker differential contracts")
    reference = docker.DockerClient(base_url=host, timeout=180, version="auto")
    try:
        if reference.version().get("Platform", {}).get("Name", "") == "cengine":
            pytest.fail("DOCKER_REFERENCE_HOST must identify a reference Docker Engine, not cengine")
        reference.ping()
        reference.images.pull(IMAGE)
        suffix = uuid.uuid4().hex[:8]
        expected = runtime_error_contract(
            reference, f"compat-oracle-errors-reference-{suffix}",
        )
        actual = runtime_error_contract(
            client, f"compat-oracle-errors-cengine-{suffix}",
        )
        for key in ("invalid_cwd", "invalid_command", "invalid_mount"):
            assert actual[key] == expected[key]

        assert actual["invalid_user"] == expected["invalid_user"]
        assert actual["invalid_ulimit"] == expected["invalid_ulimit"]
    finally:
        reference.close()
