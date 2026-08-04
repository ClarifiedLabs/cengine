"""OCI/Linux runtime-semantic contracts below the Docker API surface."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import tarfile
import threading
import time
import uuid

import docker
import pytest
from docker.types import Mount
from harness import compatibility_fixture_ipv6, persisted_container_record


DIND_IMAGE = "docker:29.6.2-dind"
ALPINE_IMAGE = "alpine:latest"
PINNED_ALPINE_IMAGE = (
    "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
)
RYUK_IMAGE = "testcontainers/ryuk:0.13.0"


def wait_for_compat_value(
    probe, expected, description: str, *, timeout: float = 10, interval: float = 0.1,
):
    deadline = time.monotonic() + timeout
    observed = probe()
    while observed != expected:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            pytest.fail(
                f"timed out waiting for {description}: "
                f"observed {observed!r}, want {expected!r}"
            )
        time.sleep(min(interval, remaining))
        observed = probe()
    return observed


def load_healthcheck_image(
    client: docker.DockerClient, tag: str, healthcheck: dict,
) -> docker.models.images.Image:
    source_archive = io.BytesIO(b"".join(client.images.get(ALPINE_IMAGE).save(named=True)))
    output_archive = io.BytesIO()
    with tarfile.open(fileobj=source_archive, mode="r:*") as source:
        members = source.getmembers()
        files = {
            member.name: source.extractfile(member).read()
            for member in members if member.isfile()
        }
        index = json.loads(files["index.json"])
        archive_manifest = json.loads(files["manifest.json"])
        generated: dict[str, bytes] = {}
        config_digests: dict[str, str] = {}

        def blob_name(digest: str) -> str:
            return f"blobs/sha256/{digest.removeprefix('sha256:')}"

        def store_json(value: dict) -> tuple[str, int]:
            data = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
            generated[blob_name(digest)] = data
            return digest, len(data)

        def rewrite(descriptor: dict) -> dict:
            value = json.loads(files[blob_name(descriptor["digest"])])
            if "manifests" in value:
                value["manifests"] = [rewrite(child) for child in value["manifests"]]
            elif value.get("config", {}).get("mediaType") in {
                "application/vnd.oci.image.config.v1+json",
                "application/vnd.docker.container.image.v1+json",
            } and not value.get("artifactType") and not descriptor.get("artifactType") \
                    and descriptor.get("annotations", {}).get(
                        "vnd.docker.reference.type",
                    ) != "attestation-manifest":
                old_config = value["config"]["digest"]
                configuration = json.loads(files[blob_name(old_config)])
                configuration.setdefault("config", {})["Healthcheck"] = healthcheck
                new_config, config_size = store_json(configuration)
                value["config"]["digest"] = new_config
                value["config"]["size"] = config_size
                config_digests[old_config] = new_config
            else:
                return dict(descriptor)
            new_digest, new_size = store_json(value)
            rewritten = dict(descriptor)
            rewritten["digest"] = new_digest
            rewritten["size"] = new_size
            return rewritten

        index["manifests"] = [rewrite(descriptor) for descriptor in index["manifests"]]
        assert index["manifests"]
        annotations = index["manifests"][0].setdefault("annotations", {})
        annotations["org.opencontainers.image.ref.name"] = tag
        annotations["io.containerd.image.name"] = tag
        for entry in archive_manifest:
            old_config = "sha256:" + pathlib.PurePosixPath(entry["Config"]).name
            if old_config in config_digests:
                entry["Config"] = blob_name(config_digests[old_config])
                entry["RepoTags"] = [tag]

        generated["index.json"] = json.dumps(
            index, separators=(",", ":"), sort_keys=True,
        ).encode()
        generated["manifest.json"] = json.dumps(
            archive_manifest, separators=(",", ":"), sort_keys=True,
        ).encode()
        with tarfile.open(fileobj=output_archive, mode="w") as output:
            for member in members:
                if member.name in generated:
                    continue
                output.addfile(
                    member, io.BytesIO(files[member.name]) if member.isfile() else None,
                )
            for name, data in generated.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                member.mtime = int(time.time())
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
    output_archive.seek(0)
    client.images.load(output_archive.getvalue())
    return client.images.get(tag)


SNAPSHOT_SCRIPT = r"""
snapshot() {
    for namespace in mnt pid uts ipc net cgroup; do
        value=$(readlink "/proc/$$/ns/$namespace")
        printf 'namespace_%s=%s\n' "$namespace" "$value"
    done
    printf 'root_stat=%s\n' "$(stat -c '%d:%i' /)"
    awk '$5 == "/" { print "root_mount=" $1 ":" $3 ":" $4 ":" $6; exit }' /proc/self/mountinfo
    printf 'hostname=%s\n' "$(hostname)"
    printf 'working_directory=%s\n' "$(pwd)"
    printf 'uid=%s\n' "$(id -u)"
    printf 'gid=%s\n' "$(id -g)"
    printf 'groups=%s\n' "$(id -G | tr ' ' ',')"
    printf 'environment=%s\n' "$CONTEXT"
    awk '/^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):/ {
        key=$1; sub(":", "", key); print "status_" key "=" $2
    }' /proc/self/status
    for descriptor in 3 4 5; do
        if test -e "/proc/$$/fd/$descriptor"; then
            printf 'fd_%s=open\n' "$descriptor"
        else
            printf 'fd_%s=closed\n' "$descriptor"
        fi
    done
    printf 'snapshot_complete=1\n'
}
snapshot
"""


def parse_snapshot(output: bytes) -> dict[str, str]:
    values = {}
    for raw_line in output.decode(errors="replace").splitlines():
        key, separator, value = raw_line.partition("=")
        if separator:
            values[key] = value
    assert values.get("snapshot_complete") == "1", output.decode(errors="replace")
    return values


def wait_for_init_snapshot(container: docker.models.containers.Container) -> dict[str, str]:
    deadline = time.monotonic() + 30
    output = b""
    while time.monotonic() < deadline:
        output = container.logs()
        if b"snapshot_complete=1" in output:
            return parse_snapshot(output)
        container.reload()
        if container.status == "exited":
            break
        time.sleep(0.1)
    pytest.fail(f"init context snapshot did not complete:\n{output.decode(errors='replace')}")


@pytest.mark.compat("RTM-001")
def test_init_and_default_exec_share_runtime_context(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
    group_file = tmp_path / "group"
    group_file.write_text("root:x:0:\nnobody:x:65534:\ncompat:x:2345:nobody\n")
    privileged_container = None
    container = client.containers.create(
        ALPINE_IMAGE,
        ["sh", "-ec", SNAPSHOT_SCRIPT + "while :; do sleep 1; done"],
        hostname="runtime-context",
        user="nobody",
        working_dir="/tmp",
        environment={"CONTEXT": "container"},
        mounts=[Mount("/etc/group", str(group_file), type="bind", read_only=True)],
    )
    try:
        container.start()
        init_context = wait_for_init_snapshot(container)
        result = container.exec_run(["sh", "-ec", SNAPSHOT_SCRIPT])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        exec_context = parse_snapshot(result.output)

        semantic_keys = set(exec_context) - {"fd_3", "fd_4", "fd_5"}
        assert {key: exec_context[key] for key in semantic_keys} == {
            key: init_context[key] for key in semantic_keys
        }
        assert exec_context["working_directory"] == "/tmp"
        assert exec_context["uid"] == "65534"
        assert exec_context["gid"] == "65534"
        assert "2345" in exec_context["groups"].split(",")
        assert init_context["status_NoNewPrivs"] == "0"
        assert exec_context["status_NoNewPrivs"] == "0"
        assert all(exec_context[f"fd_{descriptor}"] == "closed" for descriptor in (3, 4, 5))

        privileged = container.exec_run(
            ["sh", "-ec", "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status"],
            privileged=True,
        )
        assert privileged.exit_code == 0, privileged.output.decode(errors="replace")
        assert privileged.output.strip() == b"0"

        privileged_container = client.containers.run(
            ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True, privileged=True,
        )
        inherited = privileged_container.exec_run([
            "sh", "-ec",
            "awk '/^CapEff:/ { print $2 } /^NoNewPrivs:/ { print $2 }' /proc/self/status",
        ])
        assert inherited.exit_code == 0, inherited.output.decode(errors="replace")
        capability_mask, no_new_privileges = inherited.output.splitlines()
        assert int(capability_mask, 16) & (1 << 21), "default exec lost container CAP_SYS_ADMIN"
        assert no_new_privileges == b"0"
    finally:
        container.remove(force=True)
        if privileged_container is not None:
            privileged_container.remove(force=True)


@pytest.mark.compat("RTM-038")
def test_invalid_init_and_exec_identities_fail_without_leaking_stages(
    daemon, client: docker.DockerClient, tmp_path: pathlib.Path,
):
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
    invalid_inits = []
    container = None
    try:
        for index, user in enumerate(("missing-init-user:staff", "app:missing-init-group")):
            invalid_response = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": f"invalid-init-identity-{suffix}-{index}"},
                data={
                    "Image": ALPINE_IMAGE, "Cmd": ["true"], "User": user,
                    "HostConfig": {
                        "Mounts": [
                            {
                                "Type": "bind", "Source": str(passwd_file),
                                "Target": "/etc/passwd", "ReadOnly": True,
                            },
                            {
                                "Type": "bind", "Source": str(group_file),
                                "Target": "/etc/group", "ReadOnly": True,
                            },
                        ],
                        "MaskedPaths": ["/etc/passwd", "/etc/group"],
                    },
                },
            )
            client.api._raise_for_status(invalid_response)
            invalid_init = client.containers.get(invalid_response.json()["Id"])
            invalid_inits.append(invalid_init)
            with pytest.raises(docker.errors.APIError) as error:
                invalid_init.start()
            assert error.value.status_code == 500
            invalid_init.reload()
            assert invalid_init.status == "created"
            assert invalid_init.attrs["State"]["Running"] is False

        response = client.api._post_json(
            client.api._url("/containers/create"),
            params={"name": f"identity-runtime-{suffix}"},
            data={
                "Image": ALPINE_IMAGE,
                "Cmd": ["top"],
                "User": "app:staff",
                "HostConfig": {
                    "Mounts": [
                        {
                            "Type": "bind", "Source": str(passwd_file),
                            "Target": "/etc/passwd", "ReadOnly": True,
                        },
                        {
                            "Type": "bind", "Source": str(group_file),
                            "Target": "/etc/group", "ReadOnly": True,
                        },
                    ],
                    "MaskedPaths": ["/etc/passwd", "/etc/group"],
                },
            },
        )
        client.api._raise_for_status(response)
        container = client.containers.get(response.json()["Id"])
        container.start()

        for user, expected in (("app:staff", b"1000 3000 3000,4000"), ("1000:3000", b"1000 3000 3000")):
            result = container.exec_run([
                "sh", "-ec",
                "printf '%s %s ' \"$(id -u)\" \"$(id -g)\"; id -G | tr ' ' ','",
            ], user=user)
            assert result.exit_code == 0, result.output.decode(errors="replace")
            assert result.output.strip() == expected

        for user in ("missing-exec-user", "app:missing-exec-group"):
            artifacts_before = sorted(daemon.root.rglob("exec-*"))
            with pytest.raises(docker.errors.APIError) as error:
                client.api.exec_create(container.id, ["true"], user=user)
            assert error.value.status_code == 400
            assert sorted(daemon.root.rglob("exec-*")) == artifacts_before
    finally:
        if container is not None:
            container.remove(force=True)
        for invalid_init in invalid_inits:
            invalid_init.remove(force=True)


@pytest.mark.compat("RTM-039")
def test_explicit_exec_context_overrides_and_omitted_values_inherit(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
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
    container = client.containers.create(
        ALPINE_IMAGE,
        ["sh", "-ec", SNAPSHOT_SCRIPT + "while :; do sleep 1; done"],
        name=f"exec-context-{suffix}",
        user="app:staff",
        working_dir="/tmp",
        environment={"CONTEXT": "container", "INHERITED": "yes"},
        mounts=[
            Mount("/etc/passwd", str(passwd_file), type="bind", read_only=True),
            Mount("/etc/group", str(group_file), type="bind", read_only=True),
        ],
    )
    try:
        container.start()
        init_context = wait_for_init_snapshot(container)
        inherited = container.exec_run(["sh", "-ec", SNAPSHOT_SCRIPT])
        assert inherited.exit_code == 0, inherited.output.decode(errors="replace")
        inherited_context = parse_snapshot(inherited.output)
        for key in (
            "namespace_mnt", "namespace_pid", "namespace_uts", "namespace_ipc",
            "namespace_net", "namespace_cgroup", "root_stat", "root_mount",
            "working_directory", "uid", "gid", "groups", "environment",
            "status_CapInh", "status_CapPrm", "status_CapEff", "status_CapBnd",
            "status_CapAmb", "status_NoNewPrivs",
        ):
            assert inherited_context[key] == init_context[key]
        assert all(inherited_context[f"fd_{descriptor}"] == "closed" for descriptor in (3, 4, 5))

        explicit_contexts = []
        explicit_script = (
            "if test -t 1; then terminal=1; else terminal=0; fi; "
            "printf 'terminal=%s\\n' \"$terminal\"; "
            + SNAPSHOT_SCRIPT
        )
        for tty in (False, True):
            result = container.exec_run(
                ["sh", "-ec", explicit_script],
                user="root:staff", workdir="/",
                environment={"CONTEXT": "exec", "EXPLICIT": "yes"},
                tty=tty, privileged=True,
            )
            assert result.exit_code == 0, result.output.decode(errors="replace")
            context = parse_snapshot(result.output)
            explicit_contexts.append(context)
            assert context["terminal"] == ("1" if tty else "0")
            assert context["working_directory"] == "/"
            assert context["uid"] == "0" and context["gid"] == "3000"
            assert "3000" in context["groups"].split(",")
            assert context["environment"] == "exec"
            assert context["status_NoNewPrivs"] == "0"
            assert int(context["status_CapEff"], 16) & (1 << 21)
            assert all(context[f"fd_{descriptor}"] == "closed" for descriptor in (3, 4, 5))
            for key in (
                "namespace_mnt", "namespace_pid", "namespace_uts", "namespace_ipc",
                "namespace_net", "namespace_cgroup", "root_stat", "root_mount",
            ):
                assert context[key] == init_context[key]
        for key in set(explicit_contexts[0]) - {"terminal"}:
            assert explicit_contexts[0][key] == explicit_contexts[1][key]

        exec_id = client.api.exec_create(
            container.id,
            ["sh", "-ec", "echo $$ >/tmp/authoritative-exec-pid; sleep 1; exit 23"],
        )["Id"]
        client.api.exec_start(exec_id, detach=True)
        running = wait_for_compat_value(
            lambda: client.api.exec_inspect(exec_id)["Running"], True,
            "explicit-context exec to become running",
        )
        assert running is True
        inspected = client.api.exec_inspect(exec_id)
        pid = int(container.exec_run(["cat", "/tmp/authoritative-exec-pid"]).output.strip())
        assert inspected["Pid"] == pid
        wait_for_compat_value(
            lambda: client.api.exec_inspect(exec_id)["ExitCode"], 23,
            "explicit-context exec terminal status",
        )
        completed = client.api.exec_inspect(exec_id)
        assert completed["Running"] is False
        assert completed["Pid"] == pid
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-002")
def test_read_only_root_applies_to_exec_but_tmpfs_stays_writable(
    client: docker.DockerClient,
):
    container = client.containers.run(
        ALPINE_IMAGE,
        ["sh", "-c", "while :; do sleep 1; done"],
        detach=True,
        read_only=True,
        tmpfs={"/writable": "rw,nosuid,nodev,mode=1777"},
    )
    try:
        result = container.exec_run([
            "sh", "-ec",
            "if touch /root-write 2>/dev/null; then exit 20; fi; "
            "touch /writable/exec-write; test -f /writable/exec-write; printf readonly-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"readonly-ok"
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-012")
def test_default_routes_are_selected_per_address_family(client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    ipv4 = client.networks.create(f"runtime-ipv4-{suffix}")
    ipv4.reload()
    ipv4_gateway = next(
        config["Gateway"] for config in ipv4.attrs["IPAM"]["Config"]
        if ":" not in config["Gateway"]
    )
    ipv6_gateway = compatibility_fixture_ipv6(4, 1, prefix=None)
    response = client.api._post_json(
        client.api._url("/networks/create"),
        data={
            "Name": f"runtime-ipv6-{suffix}",
            "EnableIPv4": False,
            "EnableIPv6": True,
            "IPAM": {"Config": [{
                "Subnet": compatibility_fixture_ipv6(4),
                "Gateway": ipv6_gateway,
            }]},
        },
    )
    client.api._raise_for_status(response)
    ipv6 = client.networks.get(response.json()["Id"])
    create = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"runtime-routes-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["top"],
            "NetworkingConfig": {"EndpointsConfig": {
                ipv4.name: {"GwPriority": 10},
                ipv6.name: {"GwPriority": 100},
            }},
        },
    )
    client.api._raise_for_status(create)
    container = client.containers.get(create.json()["Id"])
    try:
        container.start()
        ipv4_route = container.exec_run(["sh", "-c", "ip -4 route show default"])
        ipv6_route = container.exec_run(["sh", "-c", "ip -6 route show default"])
        assert ipv4_route.exit_code == 0 and ipv4_gateway.encode() in ipv4_route.output
        assert ipv6_route.exit_code == 0 and ipv6_gateway.encode() in ipv6_route.output
    finally:
        container.remove(force=True)
        ipv4.remove()
        ipv6.remove()


@pytest.mark.compat("RTM-013")
def test_active_unsupported_runtime_inputs_fail_closed(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    initial_volumes = {volume.name for volume in client.volumes.list()}
    initial_containers = {container.id for container in client.containers.list(all=True)}
    unsupported_create_cases = [
        {"Domainname": "example.test"},
        {"ArgsEscaped": True},
        {"NetworkDisabled": True},
        {"Shell": ["/bin/sh", "-c"]},
        {"HostConfig": {"CpuShares": 1024}},
        {"HostConfig": {"CpusetCpus": "0"}},
        {"HostConfig": {"MemoryReservation": 64 * 1024 * 1024}},
        {"HostConfig": {"GroupAdd": ["wheel"]}},
        {"HostConfig": {"OomScoreAdj": 1}},
        {"HostConfig": {"Isolation": "process"}},
        {"HostConfig": {"PidMode": "host"}},
        {"HostConfig": {"DeviceRequests": [{"Driver": "cdi", "Count": 1}]}},
    ] + [
        {"Mounts": [{"Type": kind, "Target": "/unsupported"}]}
        for kind in ("image", "cluster", "npipe")
    ] + [
        {"Mounts": [{
            "Type": "volume", "Source": "data", "Target": "/data",
            "VolumeOptions": {"Labels": {"unsupported": "true"}},
        }]},
        {"Mounts": [{
            "Type": "bind", "Source": "/tmp", "Target": "/data",
            "Consistency": "cached",
        }]},
    ]
    malformed_create_cases = [
        {"StopTimeout": -1},
        {"Healthcheck": {"Test": ["CMD", "true"], "Interval": 1}},
        {"HostConfig": {"OomScoreAdj": 1001}},
        {"HostConfig": {"Memory": -1}},
        {"Mounts": [{"Type": "sideways", "Target": "/data"}]},
    ]

    def assert_create_rejected(body: dict, status_code: int, index: int) -> None:
        name = f"runtime-input-{suffix}-{status_code}-{index}"
        request = {
            "Image": ALPINE_IMAGE,
            "Volumes": {"/anonymous-must-not-leak": {}},
            **body,
        }
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/create"), params={"name": name}, data=request,
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == status_code
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)
        assert {volume.name for volume in client.volumes.list()} == initial_volumes
        assert {value.id for value in client.containers.list(all=True)} == initial_containers

    for index, body in enumerate(unsupported_create_cases):
        assert_create_rejected(body, 501, index)
    for index, body in enumerate(malformed_create_cases):
        assert_create_rejected(body, 400, index)

    inert = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"runtime-inert-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Domainname": "",
            "ArgsEscaped": False,
            "NetworkDisabled": False,
            "Shell": [],
            "AttachStdout": False,
            "AttachStderr": False,
            "StdinOnce": True,
            "FutureRuntimeExtension": {"Enabled": True},
            "HostConfig": {
                "Init": True,
                "CpuShares": 0,
                "CgroupParent": "/docker/buildx",
                "BlkioWeightDevice": [],
                "DeviceRequests": [],
                "MemoryReservation": 0,
                "MemorySwap": 0,
                "MemorySwappiness": -1,
                "OomKillDisable": False,
                "CpusetCpus": "",
                "CpusetMems": "",
                "CgroupnsMode": "private",
                "IpcMode": "private",
                "Isolation": "default",
                "ConsoleSize": [0, 0],
                "ShmSize": 64 * 1024 * 1024,
                "FutureHostExtension": {"Enabled": True},
            },
        },
    )
    client.api._raise_for_status(inert)
    inert_container = client.containers.get(inert.json()["Id"])

    container = client.containers.create(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        name=f"runtime-update-{suffix}",
        mem_limit=1024 * 1024 * 1024,
    )
    try:
        unsupported_updates = [
            {"DeviceRequests": [{
                "Driver": "cdi", "DeviceIDs": ["example.com/device=one"],
            }]},
            {"CpusetCpus": "0"},
            {"MemorySwap": 3 * 1024 * 1024 * 1024},
            {"Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 1024}]},
        ]
        for update in unsupported_updates:
            with pytest.raises(docker.errors.APIError) as error:
                response = client.api._post_json(
                    client.api._url("/containers/{0}/update", container.id),
                    data={"Memory": 2 * 1024 * 1024 * 1024, **update},
                )
                client.api._raise_for_status(response)
            assert error.value.status_code == 501
            container.reload()
            assert container.attrs["HostConfig"]["Memory"] == 1024 * 1024 * 1024
            state = json.loads((daemon.root / "engine.json").read_text())
            assert persisted_container_record(state, container.id)["memoryBytes"] == 1024 * 1024 * 1024

        container.start()
        exec_artifacts = lambda: sorted(
            str(path.relative_to(daemon.root))
            for path in daemon.root.rglob("exec-*")
        )
        artifacts_before = exec_artifacts()
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/{0}/exec", container.id),
                data={"Cmd": ["true"], "DetachKeys": "ctrl-x,x"},
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 501
        assert exec_artifacts() == artifacts_before

        response = client.api._post_json(
            client.api._url("/containers/{0}/exec", container.id),
            data={"Cmd": ["true"], "ConsoleSize": [24, 80], "FutureExecExtension": True},
        )
        client.api._raise_for_status(response)
        exec_id = response.json()["Id"]
        response = client.api._post_json(
            client.api._url("/exec/{0}/start", exec_id),
            data={
                "Detach": True, "Tty": False, "ConsoleSize": [24, 80],
                "FutureExecStartExtension": True,
            },
        )
        client.api._raise_for_status(response)
    finally:
        inert_container.remove(force=True)
        container.remove(force=True)


@pytest.mark.compat("RTM-030")
def test_console_size_applies_to_container_and_exec_ptys(daemon, client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    initial_containers = {container.id for container in client.containers.list(all=True)}
    initial_volumes = {volume.name for volume in client.volumes.list()}
    for index, console_size in enumerate(([24], [-1, 80], [24, 65536], [24, 80, 0])):
        name = f"console-size-invalid-{suffix}-{index}"
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": name},
                data={
                    "Image": ALPINE_IMAGE, "Cmd": ["true"], "Tty": True,
                    "Volumes": {"/anonymous-must-not-leak": {}},
                    "HostConfig": {"ConsoleSize": console_size},
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 400
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)
        assert {volume.name for volume in client.volumes.list()} == initial_volumes
        assert {container.id for container in client.containers.list(all=True)} == initial_containers

    create = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"console-size-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": [
                "sh", "-c",
                "stty size >/tmp/container-size; "
                "trap 'stty size >/tmp/container-size' WINCH; "
                "while :; do sleep 1; done",
            ],
            "Tty": True,
            "HostConfig": {"ConsoleSize": [33, 101]},
        },
    )
    client.api._raise_for_status(create)
    container = client.containers.get(create.json()["Id"])

    def wait_for_size(path: str, expected: bytes) -> None:
        deadline = time.monotonic() + 10
        observed = b""
        while time.monotonic() < deadline:
            result = container.exec_run(["sh", "-c", f"cat {path} 2>/dev/null || true"])
            observed = result.output.strip()
            if observed == expected:
                return
            time.sleep(0.05)
        pytest.fail(f"{path} contained {observed!r}, want {expected!r}")

    try:
        container.reload()
        assert container.attrs["HostConfig"]["ConsoleSize"] == [33, 101]
        container.start()
        wait_for_size("/tmp/container-size", b"33 101")

        container.resize(height=44, width=122)
        wait_for_size("/tmp/container-size", b"44 122")

        exec_artifacts = lambda: sorted(
            str(path.relative_to(daemon.root)) for path in daemon.root.rglob("exec-*")
        )
        for console_size in ([24], [-1, 80], [24, 65536], [24, 80, 0]):
            artifacts_before = exec_artifacts()
            with pytest.raises(docker.errors.APIError) as error:
                invalid_create = client.api._post_json(
                    client.api._url("/containers/{0}/exec", container.id),
                    data={"Cmd": ["true"], "Tty": True, "ConsoleSize": console_size},
                )
                client.api._raise_for_status(invalid_create)
            assert error.value.status_code == 400
            assert exec_artifacts() == artifacts_before

        validation_exec = client.api._post_json(
            client.api._url("/containers/{0}/exec", container.id),
            data={"Cmd": ["true"], "Tty": False},
        )
        client.api._raise_for_status(validation_exec)
        validation_exec_id = validation_exec.json()["Id"]
        validation_inspect = client.api.exec_inspect(validation_exec_id)
        assert validation_inspect["Running"] is False
        for start_body in (
            {"Detach": True, "Tty": False, "ConsoleSize": [24]},
            {"Detach": True, "Tty": False, "ConsoleSize": [-1, 80]},
            {"Detach": True, "Tty": False, "ConsoleSize": [24, 65536]},
            {"Detach": True, "Tty": True, "ConsoleSize": [24, 80]},
        ):
            artifacts_before = exec_artifacts()
            with pytest.raises(docker.errors.APIError) as error:
                invalid_start = client.api._post_json(
                    client.api._url("/exec/{0}/start", validation_exec_id), data=start_body,
                )
                client.api._raise_for_status(invalid_start)
            assert error.value.status_code == 400
            inspect = client.api.exec_inspect(validation_exec_id)
            assert inspect["Running"] == validation_inspect["Running"]
            assert inspect["ExitCode"] == validation_inspect["ExitCode"]
            assert exec_artifacts() == artifacts_before
        valid_start = client.api._post_json(
            client.api._url("/exec/{0}/start", validation_exec_id),
            data={"Detach": True, "Tty": False, "ConsoleSize": [24, 80]},
        )
        client.api._raise_for_status(valid_start)

        exec_create = client.api._post_json(
            client.api._url("/containers/{0}/exec", container.id),
            data={
                "AttachStdout": False,
                "AttachStderr": False,
                "Cmd": [
                    "sh", "-c",
                    "stty size >/tmp/exec-size; "
                    "trap 'stty size >/tmp/exec-size' WINCH; "
                    "while :; do sleep 1; done",
                ],
                "Tty": True,
                "ConsoleSize": [35, 105],
            },
        )
        client.api._raise_for_status(exec_create)
        exec_id = exec_create.json()["Id"]
        exec_start = client.api._post_json(
            client.api._url("/exec/{0}/start", exec_id),
            data={"Detach": True, "Tty": True, "ConsoleSize": [45, 125]},
        )
        client.api._raise_for_status(exec_start)
        wait_for_size("/tmp/exec-size", b"45 125")

        client.api.exec_resize(exec_id, height=55, width=145)
        wait_for_size("/tmp/exec-size", b"55 145")
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-031")
def test_image_label_filters_isolate_testcontainers_cleanup_sessions(
    client: docker.DockerClient,
):
    ryuk = client.images.get(RYUK_IMAGE)
    labels = ryuk.attrs["Config"]["Labels"]
    assert labels["org.testcontainers.ryuk"] == "true"

    by_key = client.images.list(filters={"label": "org.testcontainers.ryuk"})
    assert {image.id for image in by_key} == {ryuk.id}

    by_value = client.images.list(filters={"label": "org.testcontainers.ryuk=true"})
    assert {image.id for image in by_value} == {ryuk.id}

    unrelated_session = client.images.list(filters={
        "label": f"org.testcontainers.sessionId=missing-{uuid.uuid4().hex}",
    })
    assert unrelated_session == []
    assert client.images.get(ALPINE_IMAGE).id
    assert client.images.get(RYUK_IMAGE).id == ryuk.id


@pytest.mark.compat("RTM-032")
def test_guest_wall_clock_is_synchronized_across_vm_lifecycle(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    containers: list[docker.models.containers.Container] = []
    recovered = None

    def assert_clock(
        value: docker.models.containers.Container, phase: str,
    ) -> None:
        before = time.time_ns()
        result = value.exec_run([
            "sh", "-ec",
            "probe=/tmp/cengine-clock-probe; : >$probe; stat -c '%Y|%y' $probe",
        ])
        after = time.time_ns()
        assert result.exit_code == 0, result.output.decode(errors="replace")

        epoch, separator, formatted = result.output.decode().strip().partition("|")
        assert separator, f"{phase}: unexpected stat timestamp {result.output!r}"
        fraction_separator = formatted.rfind(".")
        assert fraction_separator >= 0, f"{phase}: stat timestamp lacks subsecond precision: {formatted}"
        fraction = formatted[fraction_separator + 1:].split()[0]
        assert fraction.isdigit() and 1 <= len(fraction) <= 9, (
            f"{phase}: invalid stat timestamp fraction: {formatted}"
        )
        guest = int(epoch) * 1_000_000_000 + int(fraction.ljust(9, "0"))

        tolerance = 25_000_000
        assert before - tolerance <= guest <= after + tolerance, (
            f"{phase}: guest timestamp {guest} outside host bracket "
            f"{before}..{after} with {tolerance}ns tolerance"
        )

    def running_generation(
        container_id: str,
    ) -> tuple[pathlib.Path, dict[str, object], dict[str, object]]:
        generations = daemon.root / "containers" / container_id / "shim-generations"
        running = []
        for specification_path in generations.glob("*/spec.json"):
            specification = json.loads(specification_path.read_text())
            status_path = pathlib.Path(str(specification["socketPath"]) + ".status")
            if not status_path.exists():
                continue
            status = json.loads(status_path.read_text())
            if status["state"] in {"running", "paused"}:
                running.append((specification_path, specification, status))
        assert len(running) == 1, f"active VM shim generations: {running}"
        return running[0]

    try:
        for index in range(4):
            value = client.containers.run(
                ALPINE_IMAGE,
                ["tail", "-f", "/dev/null"],
                name=f"clock-{suffix}-{index}",
                detach=True,
            )
            containers.append(value)
            assert_clock(value, f"fresh VM {index + 1}")

        retained = containers[-1]
        retained.pause()
        time.sleep(1.25)
        retained.unpause()
        assert_clock(retained, "resume")

        specification_path, specification, status = running_generation(retained.id)
        generation = specification_path.parent.name
        shim_pid = status["processIdentifier"]

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        retained = recovered.containers.get(retained.id)
        retained.reload()
        assert retained.status == "running"

        recovered_specification_path, recovered_specification, recovered_status = (
            running_generation(retained.id)
        )
        assert recovered_specification_path.parent.name == generation
        assert recovered_specification == specification
        assert recovered_status["processIdentifier"] == shim_pid
        assert_clock(retained, "daemon recovery")

        retained.pause()
        time.sleep(1.25)
        retained.unpause()
        assert_clock(retained, "post-recovery resume")
    finally:
        cleanup_client = recovered or client
        for value in containers:
            try:
                cleanup_client.containers.get(value.id).remove(force=True)
            except docker.errors.NotFound:
                pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-033")
def test_shared_memory_size_applies_restart_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    recovered = None
    default = None
    override = None
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"runtime-shm-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["top"],
            "HostConfig": {"IpcMode": "private", "ShmSize": 32 * 1024 * 1024},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])

    def assert_generated_shared_memory(
        value: docker.models.containers.Container, size: int, blocks: bytes,
    ) -> None:
        value.reload()
        assert value.attrs["HostConfig"]["ShmSize"] == size
        result = value.exec_run([
            "sh", "-ec", "df -kP /dev/shm | awk 'NR == 2 { print $2 }'",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output.strip() == blocks
        result = value.exec_run([
            "sh", "-ec", "awk '$2 == \"/dev/shm\" { print $4 }' /proc/mounts",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        options = result.output.strip().split(b",")
        assert {b"nosuid", b"nodev", b"noexec"}.issubset(options)

    def assert_override_shared_memory(
        value: docker.models.containers.Container,
    ) -> None:
        value.reload()
        assert value.attrs["HostConfig"]["ShmSize"] == 32 * 1024 * 1024
        for target, blocks in (("/dev/shm", b"16384"), ("/dev/shm/cache", b"1024")):
            result = value.exec_run([
                "sh", "-ec", f"df -kP {target} | awk 'NR == 2 {{ print $2 }}'",
            ])
            assert result.exit_code == 0, result.output.decode(errors="replace")
            assert result.output.strip() == blocks

    try:
        container.start()
        assert_generated_shared_memory(container, 32 * 1024 * 1024, b"32768")

        response = client.api._post_json(
            client.api._url("/containers/create"),
            params={"name": f"runtime-shm-default-{suffix}"},
            data={"Image": ALPINE_IMAGE, "Cmd": ["top"]},
        )
        client.api._raise_for_status(response)
        default = client.containers.get(response.json()["Id"])
        default.start()
        assert_generated_shared_memory(default, 64 * 1024 * 1024, b"65536")

        response = client.api._post_json(
            client.api._url("/containers/create"),
            params={"name": f"runtime-shm-override-{suffix}"},
            data={
                "Image": ALPINE_IMAGE,
                "Cmd": ["top"],
                "HostConfig": {
                    "IpcMode": "none",
                    "ShmSize": 32 * 1024 * 1024,
                    "Mounts": [{
                        "Type": "tmpfs",
                        "Target": "/dev/shm/cache",
                        "TmpfsOptions": {"SizeBytes": 1024 * 1024},
                    }],
                    "Tmpfs": {"/dev/shm": "size=16777216"},
                },
            },
        )
        client.api._raise_for_status(response)
        override = client.containers.get(response.json()["Id"])
        override.start()
        assert_override_shared_memory(override)

        container.stop()
        container.start()
        assert_generated_shared_memory(container, 32 * 1024 * 1024, b"32768")
        override.stop()
        override.start()
        assert_override_shared_memory(override)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_generated_shared_memory(
            recovered.containers.get(container.id), 32 * 1024 * 1024, b"32768",
        )
        assert_generated_shared_memory(
            recovered.containers.get(default.id), 64 * 1024 * 1024, b"65536",
        )
        assert_override_shared_memory(recovered.containers.get(override.id))
    finally:
        cleanup = recovered or client
        for value in (override, default, container):
            if value is None:
                continue
            try:
                cleanup.containers.get(value.id).remove(force=True)
            except docker.errors.NotFound:
                pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-034")
def test_namespaced_sysctls_apply_after_endpoint_settings_and_survive_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    initial_containers = {container.id for container in client.containers.list(all=True)}
    initial_volumes = {volume.name for volume in client.volumes.list()}
    rejected_sysctls = [
        {"kernel.core_pattern": "core"},
        {"vm.swappiness": "10"},
        {"net..ipv4.ip_forward": "1"},
        {"net.ipv4/../ip_forward": "1"},
        {"net.ipv4.ip_forward": "1", "net/ipv4/ip_forward": "0"},
    ]
    for index, sysctls in enumerate(rejected_sysctls):
        rejected_name = f"runtime-sysctls-rejected-{suffix}-{index}"
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": rejected_name},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/anonymous-must-not-leak": {}},
                    "HostConfig": {"Sysctls": sysctls},
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 400
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(rejected_name)
        assert {volume.name for volume in client.volumes.list()} == initial_volumes
        assert {container.id for container in client.containers.list(all=True)} == initial_containers

    name = f"runtime-sysctls-{suffix}"
    endpoint_sysctls = "com.docker.network.endpoint.sysctls"
    network = client.networks.create(f"runtime-sysctls-{suffix}")
    recovered = None
    sysctls = {
        "net.ipv4.conf.eth0.forwarding": "1",
        "fs/mqueue/msg_max": "64",
        "kernel.shm_rmid_forced": "1",
        "kernel.domainname": f"rtm-{suffix}.test",
    }
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": name},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["top"],
            "HostConfig": {"Sysctls": sysctls},
            "NetworkingConfig": {"EndpointsConfig": {network.name: {
                "DriverOpts": {
                    endpoint_sysctls: "net.ipv4.conf.IFNAME.forwarding=0",
                },
            }}},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])

    def assert_sysctls(value: docker.models.containers.Container) -> None:
        value.reload()
        assert value.attrs["HostConfig"]["Sysctls"] == sysctls
        result = value.exec_run([
            "sh", "-ec",
            "cat /proc/sys/net/ipv4/conf/eth0/forwarding "
            "/proc/sys/fs/mqueue/msg_max /proc/sys/kernel/shm_rmid_forced "
            "/proc/sys/kernel/domainname",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output.splitlines() == [
            b"1", b"64", b"1", f"rtm-{suffix}.test".encode(),
        ]

    try:
        container.start()
        assert_sysctls(container)
        container.stop()
        container.start()
        assert_sysctls(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_sysctls(recovered.containers.get(container.id))
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        try:
            cleanup.networks.get(network.id).remove()
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-035")
def test_health_start_interval_image_inheritance_restart_and_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    tag = f"cengine-health-{suffix}:latest"
    healthcheck = {
        "Test": ["CMD-SHELL", "echo probe >> /tmp/health-probes; exit 1"],
        "Interval": 1_000_000_000,
        "Timeout": 1_000_000_000,
        "Retries": 1,
        "StartPeriod": 2_000_000_000,
        "StartInterval": 200_000_000,
    }
    image = load_healthcheck_image(client, tag, healthcheck)
    recovered = None
    inherited = None
    partial = None
    disabled = None

    def create(name: str, override: dict | None = None):
        data = {"Image": tag, "Cmd": ["top"]}
        if override is not None:
            data["Healthcheck"] = override
        response = client.api._post_json(
            client.api._url("/containers/create"),
            params={"name": name},
            data=data,
        )
        client.api._raise_for_status(response)
        return client.containers.get(response.json()["Id"])

    def probe_count(value: docker.models.containers.Container) -> int:
        result = value.exec_run([
            "sh", "-ec",
            "if test -f /tmp/health-probes; then wc -l < /tmp/health-probes; else echo 0; fi",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        return int(result.output.strip())

    def wait_for_probes(
        value: docker.models.containers.Container, minimum: int, timeout: float = 5,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if probe_count(value) >= minimum:
                return
            time.sleep(0.05)
        assert probe_count(value) >= minimum

    try:
        image.reload()
        assert image.attrs["Config"]["Healthcheck"] == healthcheck
        inherited = create(f"runtime-health-inherited-{suffix}")
        partial = create(
            f"runtime-health-partial-{suffix}",
            {"Test": [], "Interval": 750_000_000},
        )
        disabled = create(
            f"runtime-health-disabled-{suffix}", {"Test": ["NONE"]},
        )

        inherited.reload()
        assert inherited.attrs["Config"]["Healthcheck"] == healthcheck
        partial.reload()
        partial_health = partial.attrs["Config"]["Healthcheck"]
        assert partial_health["Test"] == healthcheck["Test"]
        assert partial_health["Interval"] == 750_000_000
        assert partial_health["StartInterval"] == healthcheck["StartInterval"]
        disabled.reload()
        assert disabled.attrs["Config"]["Healthcheck"]["Test"] == ["NONE"]
        assert "Health" not in disabled.attrs["State"]
        disabled.start()
        time.sleep(0.5)
        disabled.reload()
        assert "Health" not in disabled.attrs["State"]
        disabled.stop()

        inherited.start()
        wait_for_probes(inherited, 2)
        inherited.reload()
        assert inherited.attrs["State"]["Health"]["Status"] == "starting"
        assert inherited.attrs["State"]["Health"]["FailingStreak"] == 0

        count_before_restart = probe_count(inherited)
        inherited.restart(timeout=1)
        wait_for_probes(inherited, count_before_restart + 2)
        inherited.reload()
        assert inherited.attrs["State"]["Health"]["Status"] == "starting"
        assert inherited.attrs["State"]["Health"]["FailingStreak"] == 0

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            inherited.reload()
            if inherited.attrs["State"]["Health"]["Status"] == "unhealthy":
                break
            time.sleep(0.05)
        inherited.reload()
        assert inherited.attrs["State"]["Health"]["Status"] == "unhealthy"
        assert inherited.attrs["State"]["Health"]["FailingStreak"] >= 1

        count_before_recovery = probe_count(inherited)
        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        recovered_inherited = recovered.containers.get(inherited.id)
        wait_for_probes(recovered_inherited, count_before_recovery + 2)
        recovered_inherited.reload()
        recovered_health = recovered_inherited.attrs["Config"]["Healthcheck"]
        assert recovered_health == healthcheck
        assert recovered_inherited.attrs["State"]["Health"]["Status"] == "unhealthy"
        assert recovered_inherited.attrs["State"]["Health"]["FailingStreak"] >= 1
    finally:
        cleanup = recovered or client
        for value in (disabled, partial, inherited):
            if value is None:
                continue
            try:
                cleanup.containers.get(value.id).remove(force=True)
            except docker.errors.NotFound:
                pass
        try:
            cleanup.images.get(tag).remove(force=True)
        except docker.errors.ImageNotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-036")
def test_bind_directory_mutations_stay_coherent_across_restart_and_recovery(
    daemon, client: docker.DockerClient, tmp_path: pathlib.Path,
):
    suffix = uuid.uuid4().hex[:8]
    host_directory = tmp_path / f"bind-coherence-{suffix}"
    writable = host_directory / "writable"
    readonly = host_directory / "readonly"
    writable.mkdir(parents=True)
    readonly.mkdir()
    guest_seed = writable / "guest-file"
    guest_seed.write_bytes(b"guest-seed")
    readonly_file = readonly / "value"
    readonly_file.write_bytes(b"readonly-seed")

    container = client.containers.create(
        PINNED_ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        name=f"bind-coherence-{suffix}",
        mounts=[
            Mount(target="/shared", source=str(writable), type="bind"),
            Mount(
                target="/readonly", source=str(readonly), type="bind", read_only=True,
            ),
        ],
    )
    recovered = None
    host_atomic_payload = b"host-atomic:" + b"h" * (4 * 1024)
    guest_atomic_payload = b"g" * (4 * 1024)
    readonly_atomic_payload = b"readonly-host-atomic:" + b"o" * (4 * 1024)
    recovered_host_payload = b"after-daemon-recovery-host:" + b"d" * (4 * 1024)
    recovered_guest_payload = b"r" * (4 * 1024)

    def host_contents(path: pathlib.Path) -> bytes | None:
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def guest_contents(
        value: docker.models.containers.Container, path: str,
    ) -> bytes | None:
        result = value.exec_run([
            "sh", "-c", 'cat "$1" 2>/dev/null || exit 44', "sh", path,
        ])
        if result.exit_code == 44:
            return None
        assert result.exit_code == 0, result.output.decode(errors="replace")
        return result.output

    def wait_for_guest(
        value: docker.models.containers.Container, path: str,
        expected: bytes | None, phase: str,
    ) -> None:
        wait_for_compat_value(
            lambda: guest_contents(value, path), expected,
            f"{phase} to become visible at {path}",
        )

    def wait_for_host(path: pathlib.Path, expected: bytes | None, phase: str) -> None:
        wait_for_compat_value(
            lambda: host_contents(path), expected,
            f"{phase} to become visible at {path}",
        )

    def run_guest(value: docker.models.containers.Container, script: str) -> None:
        result = value.exec_run(["sh", "-ec", script])
        assert result.exit_code == 0, result.output.decode(errors="replace")

    def atomic_host_write(path: pathlib.Path, contents: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def assert_atomic_transition(
        probe, old: bytes, new: bytes, action, phase: str,
    ) -> None:
        ready = threading.Event()
        seen_new = threading.Event()
        stop = threading.Event()
        errors: list[BaseException] = []

        def observe() -> None:
            deadline = time.monotonic() + 10
            try:
                while not stop.is_set() and time.monotonic() < deadline:
                    contents = probe()
                    if contents not in (old, new):
                        raise AssertionError(
                            f"{phase} exposed torn payload of "
                            f"{None if contents is None else len(contents)} bytes"
                        )
                    ready.set()
                    if contents == new:
                        seen_new.set()
                        return
                    time.sleep(0.01)
                if not stop.is_set():
                    raise AssertionError(f"timed out waiting for {phase}")
            except BaseException as error:
                errors.append(error)
                ready.set()

        observer = threading.Thread(target=observe, name=f"atomic-observer-{phase}")
        observer.start()
        assert ready.wait(timeout=5), f"atomic observer did not start for {phase}"
        if errors:
            raise errors[0]
        try:
            action()
        except BaseException:
            stop.set()
            observer.join(timeout=5)
            raise
        observer.join(timeout=10)
        if observer.is_alive():
            stop.set()
            observer.join(timeout=5)
        assert not observer.is_alive(), f"atomic observer did not stop for {phase}"
        if errors:
            raise errors[0]
        assert seen_new.is_set(), f"atomic observer did not see the new value for {phase}"

    def assert_readonly_rejection(
        value: docker.models.containers.Container, phase: str,
    ) -> None:
        result = value.exec_run([
            "sh", "-c",
            "if printf changed 2>/dev/null >/readonly/value; then exit 40; fi; "
            "if touch /readonly/created 2>/dev/null; then exit 41; fi; "
            "if mv /readonly/value /readonly/renamed 2>/dev/null; then exit 42; fi; "
            "if rm /readonly/value 2>/dev/null; then exit 43; fi; "
            "printf readonly-rejected",
        ])
        assert result.exit_code == 0, (
            f"{phase}: {result.output.decode(errors='replace')}"
        )
        assert result.output == b"readonly-rejected"
        assert readonly_file.read_bytes().startswith(b"readonly-host-")
        assert not (readonly / "created").exists()
        assert not (readonly / "renamed").exists()

    try:
        container.start()

        host_created = writable / "host-created"
        host_created.write_bytes(b"host-create")
        wait_for_guest(container, "/shared/host-created", b"host-create", "host create")
        host_created.write_bytes(b"host-in-place")
        wait_for_guest(
            container, "/shared/host-created", b"host-in-place", "host in-place update",
        )
        atomic_host_write(host_created, host_atomic_payload)
        wait_for_guest(
            container, "/shared/host-created", host_atomic_payload,
            "complete host atomic replacement",
        )
        host_renamed = writable / "host-renamed"
        host_created.rename(host_renamed)
        wait_for_guest(container, "/shared/host-created", None, "host rename source removal")
        wait_for_guest(
            container, "/shared/host-renamed", host_atomic_payload,
            "host rename destination",
        )
        host_renamed.unlink()
        wait_for_guest(container, "/shared/host-renamed", None, "host delete")

        run_guest(container, "printf guest-in-place >/shared/guest-file")
        wait_for_host(guest_seed, b"guest-in-place", "guest in-place update")
        assert_atomic_transition(
            lambda: host_contents(guest_seed), b"guest-in-place", guest_atomic_payload,
            lambda: run_guest(
                container,
                "head -c 4096 /dev/zero | tr '\\000' g >/shared/.guest-file.tmp; "
                "sync /shared/.guest-file.tmp; "
                "mv /shared/.guest-file.tmp /shared/guest-file",
            ),
            "guest atomic replacement",
        )
        guest_created = writable / "guest-created"
        run_guest(container, "printf guest-create >/shared/guest-created")
        wait_for_host(guest_created, b"guest-create", "guest create")
        run_guest(container, "mv /shared/guest-created /shared/guest-renamed")
        guest_renamed = writable / "guest-renamed"
        wait_for_host(guest_created, None, "guest rename source removal")
        wait_for_host(guest_renamed, b"guest-create", "guest rename destination")
        run_guest(container, "rm /shared/guest-renamed")
        wait_for_host(guest_renamed, None, "guest delete")

        wait_for_guest(container, "/readonly/value", b"readonly-seed", "read-only seed")
        readonly_file.write_bytes(b"readonly-host-in-place")
        wait_for_guest(
            container, "/readonly/value", b"readonly-host-in-place",
            "read-only host in-place update",
        )
        atomic_host_write(readonly_file, readonly_atomic_payload)
        wait_for_guest(
            container, "/readonly/value", readonly_atomic_payload,
            "complete read-only host atomic replacement",
        )
        assert_readonly_rejection(container, "initial execution")

        lifecycle_file = writable / "lifecycle"
        lifecycle_file.write_bytes(b"before-container-restart")
        wait_for_guest(
            container, "/shared/lifecycle", b"before-container-restart",
            "pre-restart host update",
        )
        container.restart(timeout=5)
        wait_for_guest(
            container, "/shared/lifecycle", b"before-container-restart",
            "bind contents after container restart",
        )
        lifecycle_file.write_bytes(b"after-container-restart-host")
        wait_for_guest(
            container, "/shared/lifecycle", b"after-container-restart-host",
            "post-restart host update",
        )
        run_guest(container, "printf after-container-restart-guest >/shared/lifecycle")
        wait_for_host(
            lifecycle_file, b"after-container-restart-guest", "post-restart guest update",
        )
        readonly_file.write_bytes(b"readonly-host-restart")
        wait_for_guest(
            container, "/readonly/value", b"readonly-host-restart",
            "read-only host update after container restart",
        )
        assert_readonly_rejection(container, "container restart")
        boot_id_before_recovery = guest_contents(
            container, "/proc/sys/kernel/random/boot_id",
        )

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        value = recovered.containers.get(container.id)

        def recovered_status() -> str:
            value.reload()
            return value.status

        wait_for_compat_value(recovered_status, "running", "container daemon recovery")
        assert guest_contents(value, "/proc/sys/kernel/random/boot_id") == (
            boot_id_before_recovery
        )
        wait_for_guest(
            value, "/shared/lifecycle", b"after-container-restart-guest",
            "bind contents after abrupt daemon recovery",
        )
        atomic_host_write(lifecycle_file, recovered_host_payload)
        wait_for_guest(
            value, "/shared/lifecycle", recovered_host_payload,
            "complete post-recovery host atomic update",
        )
        assert_atomic_transition(
            lambda: host_contents(lifecycle_file),
            recovered_host_payload, recovered_guest_payload,
            lambda: run_guest(
                value,
                "head -c 4096 /dev/zero | tr '\\000' r >/shared/.lifecycle.tmp; "
                "sync /shared/.lifecycle.tmp; "
                "mv /shared/.lifecycle.tmp /shared/lifecycle",
            ),
            "post-recovery guest atomic update",
        )
        atomic_host_write(readonly_file, b"readonly-host-recovery")
        wait_for_guest(
            value, "/readonly/value", b"readonly-host-recovery",
            "read-only host update after daemon recovery",
        )
        assert_readonly_rejection(value, "daemon recovery")
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-037")
def test_bind_content_polling_watcher_observes_edits_across_recovery(
    daemon, client: docker.DockerClient, tmp_path: pathlib.Path,
):
    suffix = uuid.uuid4().hex[:8]
    host_directory = tmp_path / f"bind-watcher-{suffix}"
    host_directory.mkdir()
    watched = host_directory / "value"
    watched.write_bytes(b"initial-generation")
    watcher_script = r"""
set -eu
watched=/watched/value
hashes=/tmp/watcher-hashes
ready=/tmp/watcher-ready
printf 'ready\n' >>"$ready"
last=
candidate=
while :; do
    current=$(sha256sum "$watched" | awk '{print $1}')
    if test "$current" = "$candidate" && test "$current" != "$last"; then
        printf '%s\n' "$current" >>"$hashes"
        last=$current
    fi
    candidate=$current
    sleep 0.2
done
"""
    container = client.containers.create(
        PINNED_ALPINE_IMAGE,
        ["sh", "-ec", watcher_script],
        name=f"bind-watcher-{suffix}",
        mounts=[Mount(target="/watched", source=str(host_directory), type="bind")],
    )
    recovered = None

    def ready_count(value: docker.models.containers.Container) -> int:
        result = value.exec_run([
            "sh", "-c",
            "if test -f /tmp/watcher-ready; then wc -l </tmp/watcher-ready; else echo 0; fi",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        return int(result.output.strip())

    def boot_id(value: docker.models.containers.Container) -> str:
        result = value.exec_run(["cat", "/proc/sys/kernel/random/boot_id"])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        return result.output.decode().strip()

    def observed_hashes(value: docker.models.containers.Container) -> set[str]:
        result = value.exec_run([
            "sh", "-c", "cat /tmp/watcher-hashes 2>/dev/null || true",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        return set(result.output.decode().splitlines())

    def wait_for_generation(
        value: docker.models.containers.Container, contents: bytes, phase: str,
    ) -> None:
        expected = hashlib.sha256(contents).hexdigest()
        wait_for_compat_value(
            lambda: expected in observed_hashes(value), True,
            f"watcher hash for {phase}", timeout=10, interval=0.1,
        )

    def publish_in_place(
        value: docker.models.containers.Container, contents: bytes, phase: str,
    ) -> None:
        watched.write_bytes(contents)
        wait_for_generation(value, contents, phase)

    def publish_atomically(
        value: docker.models.containers.Container, contents: bytes, phase: str,
    ) -> None:
        observed_before = observed_hashes(value)
        temporary = watched.with_name(f".{watched.name}.{uuid.uuid4().hex}.tmp")
        with temporary.open("wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(watched)
        directory = os.open(watched.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        wait_for_generation(value, contents, phase)
        newly_observed = observed_hashes(value) - observed_before
        partial_hashes = {
            hashlib.sha256(contents[:length]).hexdigest()
            for length in range(len(contents))
        }
        assert not newly_observed & partial_hashes, (
            f"polling watcher published a partial atomic generation during {phase}"
        )

    try:
        container.start()
        wait_for_compat_value(
            lambda: ready_count(container), 1, "initial watcher readiness", timeout=10,
        )
        wait_for_generation(container, b"initial-generation", "initial contents")
        publish_in_place(container, b"initial-in-place-generation", "initial in-place edit")
        publish_atomically(container, b"initial-atomic-generation", "initial atomic edit")

        container.restart(timeout=5)
        wait_for_compat_value(
            lambda: ready_count(container), 2, "watcher readiness after container restart",
            timeout=10,
        )
        publish_in_place(
            container, b"restart-in-place-generation", "post-restart in-place edit",
        )
        publish_atomically(
            container, b"restart-atomic-generation", "post-restart atomic edit",
        )
        boot_id_before_recovery = boot_id(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        value = recovered.containers.get(container.id)

        def recovered_status() -> str:
            value.reload()
            return value.status

        wait_for_compat_value(
            recovered_status, "running", "watcher daemon recovery", timeout=10,
        )
        assert ready_count(value) == 2
        assert boot_id(value) == boot_id_before_recovery
        publish_in_place(
            value, b"recovery-in-place-generation", "post-recovery in-place edit",
        )
        publish_atomically(
            value, b"recovery-atomic-generation", "post-recovery atomic edit",
        )
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-014")
def test_ulimits_apply_to_init_exec_healthchecks_and_survive_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    initial_volumes = {volume.name for volume in client.volumes.list()}
    invalid_name = f"invalid-ulimit-{suffix}"
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": invalid_name},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["true"],
            "Volumes": {"/data": {}},
            "HostConfig": {
                "Ulimits": [{"Name": "nofile", "Soft": 129, "Hard": 128}],
            },
        },
    )
    client.api._raise_for_status(response)
    invalid = client.containers.get(response.json()["Id"])
    try:
        invalid.reload()
        assert invalid.status == "created"
        assert invalid.attrs["HostConfig"]["Ulimits"] == [
            {"Name": "nofile", "Soft": 129, "Hard": 128},
        ]
        assert len({volume.name for volume in client.volumes.list()} - initial_volumes) == 1
        with pytest.raises(docker.errors.APIError) as error:
            invalid.start()
        assert error.value.status_code == 500
        invalid.reload()
        assert invalid.status == "created"
        assert invalid.attrs["State"]["Running"] is False
    finally:
        invalid.remove(force=True, v=True)
    assert {volume.name for volume in client.volumes.list()} == initial_volumes

    name = f"ulimits-{suffix}"
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": name},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": [
                "sh", "-ec",
                "{ ulimit -Sn; ulimit -Hn; } >/tmp/init-ulimits; "
                "while :; do sleep 1; done",
            ],
            "Healthcheck": {
                "Test": [
                    "CMD-SHELL",
                    "test \"$(ulimit -Sn)\" = 64 && test \"$(ulimit -Hn)\" = 128",
                ],
                "Interval": 1_000_000_000,
                "Timeout": 2_000_000_000,
                "Retries": 3,
            },
            "HostConfig": {
                "Ulimits": [
                    {"Name": "NOFILE", "Soft": 64, "Hard": 128},
                    {"Name": "core", "Soft": -1, "Hard": -1},
                ],
            },
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None

    def assert_limits(value: docker.models.containers.Container) -> None:
        result = value.exec_run(["sh", "-ec", "cat /tmp/init-ulimits; ulimit -Sn; ulimit -Hn"])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output.splitlines() == [b"64", b"128", b"64", b"128"]
        value.reload()
        assert value.attrs["HostConfig"]["Ulimits"] == [
            {"Name": "NOFILE", "Soft": 64, "Hard": 128},
            {"Name": "core", "Soft": -1, "Hard": -1},
        ]

    def wait_until_healthy(value: docker.models.containers.Container) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            value.reload()
            status = value.attrs["State"].get("Health", {}).get("Status")
            if status == "healthy":
                return
            if status == "unhealthy":
                pytest.fail("ulimit healthcheck became unhealthy")
            time.sleep(0.1)
        pytest.fail("ulimit healthcheck did not become healthy")

    try:
        container.start()
        assert_limits(container)
        wait_until_healthy(container)

        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/{0}/update", container.id),
                data={"Ulimits": [{"Name": "nofile", "Soft": 96, "Hard": 128}]},
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 501
        assert_limits(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        value = recovered.containers.get(container.id)
        assert_limits(value)
        value.stop()
        value.start()
        assert_limits(value)
        wait_until_healthy(value)
    finally:
        cleanup_client = recovered or client
        try:
            cleanup_client.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-022")
def test_structured_tmpfs_execution_options_apply_restart_and_survive_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    name = f"tmpfs-execution-options-{suffix}"
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": name},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["sh", "-ec", "while :; do sleep 1; done"],
            "HostConfig": {"Mounts": [
                {"Type": "tmpfs", "Target": "/default"},
                {
                    "Type": "tmpfs", "Target": "/executable",
                    "TmpfsOptions": {"Options": [["exec"]]},
                },
                {
                    "Type": "tmpfs", "Target": "/restricted",
                    "TmpfsOptions": {"Options": [["exec"], ["noexec"]]},
                },
            ]},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None

    def assert_options(value: docker.models.containers.Container) -> None:
        result = value.exec_run([
            "sh", "-ec",
            "for path in default executable restricted; do "
            "  printf '#!/bin/sh\\nexit 0\\n' >/$path/probe; chmod 755 /$path/probe; "
            "done; "
            "if /default/probe 2>/dev/null; then exit 40; fi; "
            "/executable/probe; "
            "if /restricted/probe 2>/dev/null; then exit 41; fi; "
            "for path in default restricted; do "
            "  options=$(awk -v target=/$path '$2 == target { print $4; exit }' /proc/mounts); "
            "  case ,$options, in *,noexec,*) ;; *) exit 42 ;; esac; "
            "done; "
            "options=$(awk '$2 == \"/executable\" { print $4; exit }' /proc/mounts); "
            "case ,$options, in *,noexec,*) exit 43 ;; esac; "
            "printf tmpfs-options-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"tmpfs-options-ok"
        value.reload()
        mounts = {
            mount["Destination"]: mount for mount in value.attrs["HostConfig"]["Mounts"]
        }
        assert mounts["/executable"]["TmpfsOptions"]["Options"] == [["exec"]]
        assert mounts["/restricted"]["TmpfsOptions"]["Options"] == [
            ["exec"], ["noexec"],
        ]

    try:
        container.start()
        assert_options(container)
        state = json.loads((daemon.root / "engine.json").read_text())
        record = persisted_container_record(state, container.id)
        mounts = {mount["destination"]: mount for mount in record["mounts"]}
        assert mounts["/default"].get("tmpfsOptions") is None
        assert mounts["/executable"]["tmpfsOptions"] == [["exec"]]
        assert mounts["/restricted"]["tmpfsOptions"] == [["exec"], ["noexec"]]

        container.restart(timeout=5)
        assert_options(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_options(recovered.containers.get(container.id))

        initial_volumes = {volume.name for volume in recovered.volumes.list()}
        with pytest.raises(docker.errors.APIError) as error:
            invalid = recovered.api._post_json(
                recovered.api._url("/containers/create"),
                params={"name": f"invalid-tmpfs-option-{suffix}"},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/leaked": {}},
                    "HostConfig": {"Mounts": [{
                        "Type": "tmpfs", "Target": "/run",
                        "TmpfsOptions": {"Options": [["uid", "1000"]]},
                    }]},
                },
            )
            recovered.api._raise_for_status(invalid)
        assert error.value.status_code == 400
        assert {volume.name for volume in recovered.volumes.list()} == initial_volumes
        with pytest.raises(docker.errors.NotFound):
            recovered.containers.get(f"invalid-tmpfs-option-{suffix}")
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-023")
def test_volume_readonly_matrix_orders_nested_mounts_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    volume_names = {
        storage: {
            role: f"runtime-volume-{storage}-{role}-{suffix}"
            for role in ("rw-parent", "ro-child", "ro-parent", "rw-child")
        }
        for storage in ("block", "shared")
    }
    for names in volume_names.values():
        for name in names.values():
            client.volumes.create(
                name, labels={"dev.cengine.compat": "true"},
            )
    shared_keeper = client.containers.create(
        ALPINE_IMAGE,
        ["true"],
        name=f"runtime-volume-shared-keeper-{suffix}",
        mounts=[
            Mount(
                target=f"/keep/{role}", source=name, type="volume", no_copy=True,
            )
            for role, name in volume_names["shared"].items()
        ],
    )

    init_probe = (
        "if touch /rootfs-must-stay-readonly 2>/dev/null; then exit 40; fi; "
        "touch /etc/init-parent-rw; "
        "if touch /etc/ssl/init-child-ro 2>/dev/null; then exit 41; fi; "
        "if touch /usr/init-parent-ro 2>/dev/null; then exit 42; fi; "
        "touch /usr/bin/init-child-rw; "
        "printf 'volume-matrix-init-ok\\n'; "
        "while :; do /bin/sleep 1; done"
    )

    def create_target(storage: str) -> docker.models.containers.Container:
        names = volume_names[storage]
        # Children deliberately precede their parents. Docker depth-orders these
        # mounts so a later parent cannot hide an already-mounted child.
        return client.containers.create(
            ALPINE_IMAGE,
            ["/bin/sh", "-ec", init_probe],
            name=f"runtime-volume-{storage}-{suffix}",
            read_only=True,
            mounts=[
                Mount(
                    target="/etc/ssl", source=names["ro-child"], type="volume",
                    read_only=True,
                ),
                Mount(
                    target="/usr/bin", source=names["rw-child"], type="volume",
                ),
                Mount(target="/etc", source=names["rw-parent"], type="volume"),
                Mount(
                    target="/usr", source=names["ro-parent"], type="volume",
                    read_only=True,
                ),
            ],
        )

    targets = {
        storage: create_target(storage) for storage in ("block", "shared")
    }
    recovered = None

    def wait_for_init(value: docker.models.containers.Container) -> None:
        deadline = time.monotonic() + 30
        output = b""
        while time.monotonic() < deadline:
            output = value.logs()
            if b"volume-matrix-init-ok" in output:
                return
            value.reload()
            if value.status == "exited":
                break
            time.sleep(0.1)
        pytest.fail(
            f"volume matrix init failed for {value.name}:\n"
            + output.decode(errors="replace")
        )

    def assert_matrix(
        value: docker.models.containers.Container, stage: str,
    ) -> None:
        result = value.exec_run([
            "/bin/sh", "-ec",
            f"if touch /rootfs-{stage} 2>/dev/null; then exit 40; fi; "
            f"touch /etc/{stage}-parent-rw; "
            f"if touch /etc/ssl/{stage}-child-ro 2>/dev/null; then exit 41; fi; "
            f"if touch /usr/{stage}-parent-ro 2>/dev/null; then exit 42; fi; "
            f"touch /usr/bin/{stage}-child-rw; "
            "for entry in /etc:rw /etc/ssl:ro /usr:ro /usr/bin:rw; do "
            "  path=${entry%:*}; expected=${entry##*:}; "
            "  options=$(awk -v target=\"$path\" '$2 == target { print $4; exit }' /proc/mounts); "
            "  test -n \"$options\"; "
            "  case ,$options, in *,ro,*) actual=ro ;; *) actual=rw ;; esac; "
            "  test \"$actual\" = \"$expected\"; "
            "done; printf volume-matrix-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"volume-matrix-ok"

        value.reload()
        mounts = {
            mount["Destination"]: mount for mount in value.attrs["Mounts"]
        }
        assert mounts["/etc"]["RW"] is True
        assert mounts["/etc/ssl"]["RW"] is False
        assert mounts["/usr"]["RW"] is False
        assert mounts["/usr/bin"]["RW"] is True
        assert value.attrs["HostConfig"]["ReadonlyRootfs"] is True

    try:
        for value in targets.values():
            value.start()
            wait_for_init(value)
            assert_matrix(value, "initial")

        storage_modes = json.loads(
            (daemon.root / "volume-storage.json").read_text()
        )
        for name in volume_names["block"].values():
            assert storage_modes[name] == "block"
        for name in volume_names["shared"].values():
            assert storage_modes[name] == "shared"

        for value in targets.values():
            value.restart(timeout=5)
            wait_for_init(value)
            assert_matrix(value, "restart")

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        for original in targets.values():
            value = recovered.containers.get(original.id)
            wait_for_init(value)
            assert_matrix(value, "recovery")
    finally:
        cleanup = recovered or client
        for value in [*targets.values(), shared_keeper]:
            try:
                cleanup.containers.get(value.id).remove(force=True)
            except docker.errors.NotFound:
                pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-024")
def test_default_device_policy_blocks_vm_disks_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    container = client.containers.run(
        ALPINE_IMAGE,
        ["sh", "-ec", "while :; do sleep 1; done"],
        name=f"default-device-policy-{suffix}",
        detach=True,
    )
    recovered = None

    def assert_policy(value: docker.models.containers.Container) -> None:
        result = value.exec_run([
            "sh", "-ec",
            "rm -f /dev/cengine-root-device /dev/cengine-null-device; "
            "test ! -e /dev/vda; "
            "numbers=$(cat /sys/class/block/vda/dev); "
            "major=${numbers%:*}; minor=${numbers#*:}; "
            "mknod /dev/cengine-root-device b \"$major\" \"$minor\"; "
            "if dd if=/dev/cengine-root-device of=/dev/null bs=512 count=1 2>/dev/null; "
            "then exit 40; fi; "
            "mknod /dev/cengine-null-device c 1 3; "
            "printf device-policy-ok >/dev/cengine-null-device; "
            "printf device-policy-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"device-policy-ok"

    try:
        assert_policy(container)
        container.restart(timeout=5)
        assert_policy(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_policy(recovered.containers.get(container.id))
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-025")
def test_configured_devices_custom_rules_nonroot_io_and_stats_survive_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    volume = client.volumes.create(name=f"configured-device-{suffix}")
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"configured-device-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["tail", "-f", "/dev/null"],
            "HostConfig": {
                "Mounts": [{
                    "Type": "volume", "Source": volume.name, "Target": "/data",
                }],
                "Devices": [{
                    "PathOnHost": "/dev/vdb",
                    "PathInContainer": "/dev/cengine-volume",
                    "CgroupPermissions": "r",
                }],
                "BlkioDeviceReadBps": [{
                    "Path": "/dev/vdb", "Rate": 8 * 1024 * 1024,
                }],
            },
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None

    def inspect(value: docker.models.containers.Container) -> None:
        value.reload()
        host = value.attrs["HostConfig"]
        assert host["Devices"] == [{
            "PathOnHost": "/dev/vdb",
            "PathInContainer": "/dev/cengine-volume",
            "CgroupPermissions": "r",
        }]
        assert host["DeviceCgroupRules"] == [f"b {device_number} w"]
        assert host["BlkioDeviceReadBps"] == [{
            "Path": "/dev/vdb", "Rate": 8 * 1024 * 1024,
        }]

    def assert_mapping(value: docker.models.containers.Container, write_allowed: bool) -> None:
        script = (
            "test -b /dev/cengine-volume; "
            "dd if=/dev/cengine-volume of=/dev/null bs=512 count=1 2>/dev/null; "
            "if dd if=/dev/null of=/dev/cengine-volume count=0 2>/dev/null; "
            "then write=allowed; else write=denied; fi; "
            f"test \"$write\" = {'allowed' if write_allowed else 'denied'}"
        )
        result = value.exec_run(["sh", "-ec", script])
        assert result.exit_code == 0, result.output.decode(errors="replace")

    try:
        container.start()
        number = container.exec_run(["cat", "/sys/class/block/vdb/dev"])
        assert number.exit_code == 0, number.output.decode(errors="replace")
        device_number = number.output.decode().strip()

        assert_mapping(container, write_allowed=False)
        io_max = container.exec_run(["cat", "/sys/fs/cgroup/io.max"])
        assert io_max.exit_code == 0, io_max.output.decode(errors="replace")
        assert any(
            line.startswith(f"{device_number} ") and f"rbps={8 * 1024 * 1024}" in line
            for line in io_max.output.decode().splitlines()
        ), io_max.output.decode(errors="replace")

        update = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={"DeviceCgroupRules": [f"b {device_number} w"]},
        )
        client.api._raise_for_status(update)
        assert_mapping(container, write_allowed=True)
        inspect(container)

        daemon.publish_resource_update_failure(
            container_id=container.id, failure_after_writes=1,
        )
        with pytest.raises(docker.errors.APIError) as error:
            failed = client.api._post_json(
                client.api._url("/containers/{0}/update", container.id),
                data={
                    "Memory": 512 * 1024 * 1024,
                    "Devices": [{
                        "PathOnHost": "/dev/vdb",
                        "PathInContainer": "/dev/cengine-volume-failed",
                        "CgroupPermissions": "r",
                    }],
                    "DeviceCgroupRules": [],
                },
            )
            client.api._raise_for_status(failed)
        assert error.value.status_code == 500
        assert not daemon.resource_update_failure_file.exists()
        assert_mapping(container, write_allowed=True)
        failed_node = container.exec_run([
            "test", "!", "-e", "/dev/cengine-volume-failed",
        ])
        assert failed_node.exit_code == 0, failed_node.output.decode(errors="replace")
        inspect(container)

        generated = container.exec_run([
            "dd", "if=/dev/zero", "of=/data/accounting", "bs=1M", "count=2", "conv=fsync",
        ])
        assert generated.exit_code == 0, generated.output.decode(errors="replace")
        stats = container.stats(stream=False)
        entries = stats["blkio_stats"]["io_service_bytes_recursive"]
        major, minor = [int(value) for value in device_number.split(":", 1)]
        assert any(
            entry["major"] == major and entry["minor"] == minor and entry["value"] > 0
            for entry in entries
        ), entries

        clear = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={"Devices": [], "DeviceCgroupRules": []},
        )
        client.api._raise_for_status(clear)
        absent = container.exec_run(["test", "!", "-e", "/dev/cengine-volume"])
        assert absent.exit_code == 0, absent.output.decode(errors="replace")

        restore = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={
                "Devices": [{
                    "PathOnHost": "/dev/vdb",
                    "PathInContainer": "/dev/cengine-volume",
                    "CgroupPermissions": "r",
                }],
                "DeviceCgroupRules": [f"b {device_number} w"],
            },
        )
        client.api._raise_for_status(restore)
        assert_mapping(container, write_allowed=True)

        container.restart(timeout=5)
        assert_mapping(container, write_allowed=True)
        inspect(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        value = recovered.containers.get(container.id)
        assert_mapping(value, write_allowed=True)
        inspect(value)
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        try:
            cleanup.volumes.get(volume.name).remove(force=True)
        except (docker.errors.NotFound, docker.errors.APIError):
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-026")
def test_privileged_cgroup_delegation_and_workload_wide_accounting(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    container = client.containers.run(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        name=f"cgroup-delegation-{suffix}",
        privileged=True,
        detach=True,
    )
    unprivileged = client.containers.run(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        name=f"cgroup-readonly-{suffix}",
        detach=True,
    )
    recovered = None

    def assert_delegation(value: docker.models.containers.Container) -> None:
        result = value.exec_run([
            "sh", "-ec",
            "fail() { echo \"cgroup delegation failed: $step\" >&2; exit 1; }; "
            "step=workload-root-processes; "
            "test -z \"$(cat /sys/fs/cgroup/cgroup.procs)\" || fail; "
            "for controller in cpu io memory pids; do "
            "  step=controller-$controller; "
            "  grep -qw \"$controller\" /sys/fs/cgroup/cgroup.subtree_control || fail; "
            "done; "
            "step=create-child; mkdir /sys/fs/cgroup/nested-test || fail; "
            "step=cpu-limit; "
            "echo '50000 100000' >/sys/fs/cgroup/nested-test/cpu.max || fail; "
            "step=memory-limit; "
            "echo 16777216 >/sys/fs/cgroup/nested-test/memory.max || fail; "
            "step=pids-limit; echo 4 >/sys/fs/cgroup/nested-test/pids.max || fail; "
            "sleep 30 & child=$!; "
            "step=move-child; "
            "echo \"$child\" >/sys/fs/cgroup/nested-test/cgroup.procs || fail; "
            "step=verify-child; "
            "test -n \"$(cat /sys/fs/cgroup/nested-test/cgroup.procs)\" || fail; "
            "kill \"$child\"; wait \"$child\" 2>/dev/null || true; "
            "step=remove-child; rmdir /sys/fs/cgroup/nested-test || fail",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")

    try:
        readonly = unprivileged.exec_run([
            "mkdir", "/sys/fs/cgroup/should-not-exist",
        ])
        assert readonly.exit_code != 0
        assert_delegation(container)

        activity = container.exec_run([
            "sh", "-ec",
            "dd if=/dev/zero of=/tmp/cgroup-accounting bs=1M count=4 conv=fsync; "
            "rm /tmp/cgroup-accounting; i=0; while [ $i -lt 50000 ]; do i=$((i+1)); done",
        ])
        assert activity.exit_code == 0, activity.output.decode(errors="replace")
        stats = container.stats(stream=False)
        assert stats["pids_stats"]["current"] >= 1
        assert stats["memory_stats"]["usage"] > 0
        assert stats["memory_stats"]["max_usage"] >= stats["memory_stats"]["usage"]
        assert stats["cpu_stats"]["throttling_data"]["periods"] > 0
        assert stats["cpu_stats"]["cpu_usage"]["total_usage"] > 0
        assert any(
            (entry["major"], entry["minor"]) != (0, 0) and entry["value"] > 0
            for entry in stats["blkio_stats"]["io_service_bytes_recursive"]
        )

        container.restart(timeout=5)
        assert_delegation(container)

        unprivileged.remove(force=True)
        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_delegation(recovered.containers.get(container.id))
    finally:
        cleanup = recovered or client
        for value in (container, unprivileged):
            try:
                cleanup.containers.get(value.id).remove(force=True)
            except docker.errors.NotFound:
                pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-027")
def test_privileged_cpuset_delegation_reaches_private_cgroup_namespace(
    client: docker.DockerClient,
):
    container = client.containers.run(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        privileged=True,
        detach=True,
    )
    try:
        result = container.exec_run([
            "sh", "-ec",
            "fail() { echo \"cpuset delegation failed: $step\" >&2; exit 1; }; "
            "step=private-namespace-root; "
            "test \"$(cat /proc/1/cgroup)\" = '0::/.cengine-init' || fail; "
            "step=controller-available; "
            "grep -qw cpuset /sys/fs/cgroup/cgroup.controllers || fail; "
            "step=controller-delegated; "
            "grep -qw cpuset /sys/fs/cgroup/cgroup.subtree_control || fail; "
            "step=root-cpu-mask; cpus=$(cat /sys/fs/cgroup/cpuset.cpus.effective); "
            "test -n \"$cpus\" || fail; "
            "step=root-memory-mask; mems=$(cat /sys/fs/cgroup/cpuset.mems.effective); "
            "test -n \"$mems\" || fail; "
            "step=create-child; mkdir /sys/fs/cgroup/cpuset-test || fail; "
            "step=child-files; "
            "test -e /sys/fs/cgroup/cpuset-test/cpuset.cpus || fail; "
            "test -e /sys/fs/cgroup/cpuset-test/cpuset.mems || fail; "
            "step=set-child-cpus; "
            "echo \"$cpus\" >/sys/fs/cgroup/cpuset-test/cpuset.cpus || fail; "
            "step=set-child-mems; "
            "echo \"$mems\" >/sys/fs/cgroup/cpuset-test/cpuset.mems || fail; "
            "step=verify-child-cpus; "
            "test \"$(cat /sys/fs/cgroup/cpuset-test/cpuset.cpus)\" = \"$cpus\" || fail; "
            "sleep 30 & child=$!; "
            "step=move-child; "
            "echo \"$child\" >/sys/fs/cgroup/cpuset-test/cgroup.procs || fail; "
            "step=verify-child; "
            "test -n \"$(cat /sys/fs/cgroup/cpuset-test/cgroup.procs)\" || fail; "
            "kill \"$child\"; wait \"$child\" 2>/dev/null || true; "
            "step=remove-child; rmdir /sys/fs/cgroup/cpuset-test || fail",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-015")
def test_block_io_throttles_apply_update_enforce_and_survive_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    name = f"block-io-{suffix}"
    initial = {
        "BlkioDeviceReadBps": [{"Path": "/dev/vda", "Rate": 1024 * 1024}],
        "BlkioDeviceWriteBps": [{"Path": "/dev/vda", "Rate": 16 * 1024 * 1024}],
        "BlkioDeviceReadIOps": [{"Path": "/dev/vda", "Rate": 1000}],
        "BlkioDeviceWriteIOps": [{"Path": "/dev/vda", "Rate": 2000}],
    }
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": name},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["tail", "-f", "/dev/null"],
            "HostConfig": {"Privileged": True, **initial},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None

    def io_max(value: docker.models.containers.Container) -> dict[str, str]:
        result = value.exec_run(["cat", "/sys/fs/cgroup/io.max"])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        limits = {}
        for line in result.output.decode().splitlines():
            fields = line.split()
            if not fields:
                continue
            for field in fields[1:]:
                key, setting = field.split("=", 1)
                limits[key] = setting
        return limits

    def memory_max(value: docker.models.containers.Container) -> str:
        result = value.exec_run(["cat", "/sys/fs/cgroup/memory.max"])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        return result.output.decode().strip()

    def persisted_record() -> dict:
        state = json.loads((daemon.root / "engine.json").read_text())
        return persisted_container_record(state, container.id)

    try:
        container.start()
        container.reload()
        for field, expected in initial.items():
            assert container.attrs["HostConfig"][field] == expected
        assert io_max(container) == {
            "rbps": str(1024 * 1024),
            "wbps": str(16 * 1024 * 1024),
            "riops": "1000",
            "wiops": "2000",
        }

        # Alpine's guest-native arm64 BusyBox dd opens the root block device with
        # O_DIRECT, avoiding page-cache hits while exercising kernel enforcement.
        started = time.monotonic()
        direct_read = container.exec_run([
            "dd", "if=/dev/vda", "of=/dev/null", "bs=1M", "count=6", "iflag=direct",
        ])
        elapsed = time.monotonic() - started
        assert direct_read.exit_code == 0, direct_read.output.decode(errors="replace")
        assert elapsed >= 3.5, f"1 MiB/s direct read completed too quickly: {elapsed:.2f}s"

        response = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={
                "BlkioDeviceReadBps": [{"Path": "/dev/vda", "Rate": 8 * 1024 * 1024}],
                "BlkioDeviceWriteBps": [],
                "BlkioDeviceReadIOps": None,
            },
        )
        client.api._raise_for_status(response)
        container.reload()
        assert container.attrs["HostConfig"]["BlkioDeviceReadBps"] == [
            {"Path": "/dev/vda", "Rate": 8 * 1024 * 1024},
        ]
        assert container.attrs["HostConfig"]["BlkioDeviceWriteBps"] == []
        assert container.attrs["HostConfig"]["BlkioDeviceReadIOps"] == initial["BlkioDeviceReadIOps"]
        assert container.attrs["HostConfig"]["BlkioDeviceWriteIOps"] == initial["BlkioDeviceWriteIOps"]
        assert io_max(container) == {
            "rbps": str(8 * 1024 * 1024),
            "wbps": "max",
            "riops": "1000",
            "wiops": "2000",
        }

        legacy = docker.APIClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="1.54",
        )
        try:
            response = legacy._post_json(
                legacy._url("/containers/{0}/update", container.id),
                data={
                    "BlkioDeviceReadBps": [{"Path": "relative", "Rate": 0}],
                    "BlkioDeviceWriteIOps": [],
                },
            )
            legacy._raise_for_status(response)
        finally:
            legacy.close()
        container.reload()
        assert container.attrs["HostConfig"]["BlkioDeviceReadBps"][0]["Rate"] == 8 * 1024 * 1024
        assert container.attrs["HostConfig"]["BlkioDeviceWriteIOps"] == initial["BlkioDeviceWriteIOps"]

        before_memory = container.attrs["HostConfig"]["Memory"]
        before_memory_max = memory_max(container)
        before_io = io_max(container)
        daemon.publish_resource_update_failure(
            container_id=container.id, failure_after_writes=4,
        )
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/{0}/update", container.id),
                data={
                    "Memory": 512 * 1024 * 1024,
                    "BlkioDeviceReadBps": [{"Path": "/dev/vda", "Rate": 4 * 1024 * 1024}],
                    "BlkioDeviceReadIOps": [{"Path": "/dev/vda", "Rate": 500}],
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 500
        assert "failure after 4 successful writes" in str(error.value)
        assert not daemon.resource_update_failure_file.exists()
        container.reload()
        assert container.attrs["HostConfig"]["Memory"] == before_memory
        assert container.attrs["HostConfig"]["BlkioDeviceReadBps"][0]["Rate"] == 8 * 1024 * 1024
        assert container.attrs["HostConfig"]["BlkioDeviceReadIOps"] == initial["BlkioDeviceReadIOps"]
        assert memory_max(container) == before_memory_max
        assert io_max(container) == before_io
        persisted = persisted_record()
        assert persisted["memoryBytes"] == before_memory
        assert persisted["blockIOReadBps"] == [{"path": "/dev/vda", "rate": 8 * 1024 * 1024}]
        assert persisted["blockIOReadIOps"] == [{"path": "/dev/vda", "rate": 1000}]

        container.stop(timeout=1)
        stopped_update = {
            "BlkioDeviceReadBps": [{"Path": "/dev/vda", "Rate": 2 * 1024 * 1024}],
            "BlkioDeviceWriteBps": [{"Path": "/dev/vda", "Rate": 4 * 1024 * 1024}],
            "BlkioDeviceReadIOps": [],
            "BlkioDeviceWriteIOps": [{"Path": "/dev/vda", "Rate": 3000}],
        }
        response = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data=stopped_update,
        )
        client.api._raise_for_status(response)
        container.reload()
        for field, expected in stopped_update.items():
            assert container.attrs["HostConfig"][field] == expected
        persisted = persisted_record()
        assert persisted["blockIOReadBps"] == [
            {"path": "/dev/vda", "rate": 2 * 1024 * 1024},
        ]
        assert persisted["blockIOReadIOps"] == []

        container.start()
        container.reload()
        assert container.attrs["HostConfig"]["Memory"] == before_memory
        assert memory_max(container) == before_memory_max
        lifecycle_io = {
            "rbps": str(2 * 1024 * 1024),
            "wbps": str(4 * 1024 * 1024),
            "riops": "max",
            "wiops": "3000",
        }
        assert io_max(container) == lifecycle_io

        # Exercise Docker's explicit POST /restart path. The replacement VM
        # must rebuild both configured values and cleared cgroup-v2 max keys
        # from the durable container record.
        container.restart(timeout=1)
        container.reload()
        for field, expected in stopped_update.items():
            assert container.attrs["HostConfig"][field] == expected
        assert memory_max(container) == before_memory_max
        assert io_max(container) == lifecycle_io

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        value = recovered.containers.get(container.id)
        value.reload()
        assert value.attrs["HostConfig"]["BlkioDeviceReadBps"] == stopped_update["BlkioDeviceReadBps"]
        assert value.attrs["HostConfig"]["BlkioDeviceWriteBps"] == stopped_update["BlkioDeviceWriteBps"]
        assert value.attrs["HostConfig"]["BlkioDeviceReadIOps"] == []
        assert value.attrs["HostConfig"]["BlkioDeviceWriteIOps"] == stopped_update["BlkioDeviceWriteIOps"]
        assert value.attrs["HostConfig"]["Memory"] == before_memory
        assert memory_max(value) == before_memory_max
        assert io_max(value) == lifecycle_io
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-016")
def test_ipc_none_omits_shared_memory_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    recovered = None
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"runtime-ipc-none-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["top"],
            "HostConfig": {
                "CgroupnsMode": "private",
                "IpcMode": "none",
                "PidMode": "",
                "UTSMode": "",
                "UsernsMode": "host",
            },
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])

    def assert_namespace_state(value: docker.models.containers.Container) -> None:
        value.reload()
        host = value.attrs["HostConfig"]
        assert host["CgroupnsMode"] == "private"
        assert host["IpcMode"] == "none"
        assert host["PidMode"] == ""
        assert host["UTSMode"] == ""
        assert host["UsernsMode"] == "host"
        result = value.exec_run([
            "sh", "-ec",
            "awk '$5 == \"/dev/shm\" { found=1 } END { exit found ? 1 : 0 }' "
            "/proc/self/mountinfo",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")

    try:
        container.start()
        assert_namespace_state(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        container = recovered.containers.get(container.id)
        assert_namespace_state(container)
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-017")
def test_same_kernel_namespace_sharing_fails_closed(client: docker.DockerClient):
    suffix = uuid.uuid4().hex[:8]
    initial_volumes = {volume.name for volume in client.volumes.list()}
    host_configs = [
        {"CgroupnsMode": "host"},
        {"IpcMode": "host"},
        {"IpcMode": "shareable"},
        {"IpcMode": "container:donor"},
        {"PidMode": "host"},
        {"PidMode": "container:donor"},
        {"UTSMode": "host"},
        {"NetworkMode": "host"},
        {"NetworkMode": "container:donor"},
        {"Cgroup": "container:donor"},
    ]
    for index, host_config in enumerate(host_configs):
        name = f"runtime-namespace-gap-{suffix}-{index}"
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": name},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/data": {}},
                    "HostConfig": host_config,
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 501
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)

    with pytest.raises(docker.errors.APIError) as error:
        response = client.api._post_json(
            client.api._url("/containers/create"),
            params={"name": f"runtime-namespace-path-{suffix}"},
            data={
                "Image": ALPINE_IMAGE,
                "Volumes": {"/data": {}},
                "HostConfig": {"PidMode": "/proc/1/ns/pid"},
            },
        )
        client.api._raise_for_status(response)
    assert error.value.status_code == 400
    assert {volume.name for volume in client.volumes.list()} == initial_volumes


@pytest.mark.compat("RTM-018")
def test_masked_and_readonly_paths_apply_restart_and_survive_recovery(
    daemon, client: docker.DockerClient, tmp_path: pathlib.Path,
):
    suffix = uuid.uuid4().hex[:8]
    masked_source = tmp_path / "masked-source"
    masked_source.mkdir()
    (masked_source / "secret").write_text("not visible in the workload")
    group_file = tmp_path / "group"
    group_file.write_text("root:x:0:\npath-policy:x:2346:root\n")
    recovered = None
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"runtime-path-policy-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["top"],
            "User": "root",
            "HostConfig": {
                "Binds": [
                    f"{masked_source}:/masked-source:ro",
                    f"{group_file}:/etc/group:ro",
                ],
                "MaskedPaths": [
                    "/masked-source", "/etc/passwd", "/missing-masked-path",
                ],
                "ReadonlyPaths": ["/tmp", "/missing-readonly-path"],
            },
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])

    def assert_path_policy(value: docker.models.containers.Container) -> None:
        value.reload()
        host = value.attrs["HostConfig"]
        assert host["MaskedPaths"] == [
            "/masked-source", "/etc/passwd", "/missing-masked-path",
        ]
        assert host["ReadonlyPaths"] == ["/tmp", "/missing-readonly-path"]
        result = value.exec_run([
            "sh", "-ec",
            "test ! -e /masked-source/secret; "
            "if touch /masked-source/new 2>/dev/null; then exit 20; fi; "
            "test \"$(stat -c '%t:%T' /etc/passwd)\" = 1:3; "
            "if touch /tmp/readonly-probe 2>/dev/null; then exit 21; fi; "
            "case \" $(id -G) \" in *\" 2346 \"*) ;; *) exit 22 ;; esac; "
            "printf path-policy-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"path-policy-ok"

    try:
        container.start()
        assert_path_policy(container)

        container.restart(timeout=5)
        assert_path_policy(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        container = recovered.containers.get(container.id)
        assert_path_policy(container)
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-019")
def test_block_io_weights_are_an_architecture_gap_with_versioned_update_semantics(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    initial_volumes = {volume.name for volume in client.volumes.list()}
    for index, host_config in enumerate([
        {"BlkioWeight": 500},
        {"BlkioWeightDevice": [{"Path": "/dev/vda", "Weight": 500}]},
    ]):
        name = f"block-io-weight-gap-{suffix}-{index}"
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": name},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/data": {}},
                    "HostConfig": host_config,
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 501
        assert "per-container VMs" in str(error.value)
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)
    assert {volume.name for volume in client.volumes.list()} == initial_volumes

    container = client.containers.create(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        name=f"block-io-weight-update-{suffix}",
        mem_limit=1024 * 1024 * 1024,
    )
    try:
        container.reload()
        assert container.attrs["HostConfig"]["BlkioWeight"] == 0
        assert container.attrs["HostConfig"]["BlkioWeightDevice"] is None

        legacy = docker.APIClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="1.54",
        )
        try:
            response = legacy._post_json(
                legacy._url("/containers/{0}/update", container.id),
                data={
                    "Memory": 2 * 1024 * 1024 * 1024,
                    "BlkioWeightDevice": {"malformed": True},
                },
            )
            legacy._raise_for_status(response)
        finally:
            legacy.close()
        container.reload()
        assert container.attrs["HostConfig"]["Memory"] == 2 * 1024 * 1024 * 1024

        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/{0}/update", container.id),
                data={
                    "Memory": 3 * 1024 * 1024 * 1024,
                    "BlkioWeightDevice": [{"Path": "/dev/vda", "Weight": 500}],
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 501
        assert "per-container VMs" in str(error.value)

        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/{0}/update", container.id),
                data={"Memory": 3 * 1024 * 1024 * 1024, "BlkioWeight": 500},
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == 501

        container.reload()
        assert container.attrs["HostConfig"]["Memory"] == 2 * 1024 * 1024 * 1024
        assert container.attrs["HostConfig"]["BlkioWeight"] == 0
        assert container.attrs["HostConfig"]["BlkioWeightDevice"] is None
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-020")
def test_bind_recursion_and_readonly_modes_apply_restart_and_survive_recovery(
    daemon, client: docker.DockerClient, tmp_path: pathlib.Path,
):
    suffix = uuid.uuid4().hex[:8]
    sources = {}
    for mode in ("default", "nonrecursive", "forced", "writable"):
        source = tmp_path / mode
        source.mkdir()
        (source / "source-marker").write_text(mode)
        sources[mode] = source

    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"bind-modes-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": ["tail", "-f", "/dev/null"],
            "HostConfig": {"Mounts": [
                {
                    "Type": "bind", "Source": str(sources["default"]),
                    "Target": "/default", "ReadOnly": True,
                },
                {
                    "Type": "bind", "Source": str(sources["nonrecursive"]),
                    "Target": "/nonrecursive", "ReadOnly": True,
                    "BindOptions": {
                        "NonRecursive": True, "ReadOnlyNonRecursive": True,
                    },
                },
                {
                    "Type": "bind", "Source": str(sources["forced"]),
                    "Target": "/forced", "ReadOnly": True,
                    "BindOptions": {"ReadOnlyForceRecursive": True},
                },
                {
                    "Type": "bind", "Source": str(sources["writable"]),
                    "Target": "/writable",
                    "BindOptions": {"NonRecursive": True},
                },
            ]},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None

    def assert_bind_modes(value: docker.models.containers.Container) -> None:
        result = value.exec_run([
            "sh", "-ec",
            "for path in default nonrecursive forced; do "
            "  test \"$(cat /$path/source-marker)\" = \"$path\"; "
            "  options=$(awk -v target=\"/$path\" '$2 == target { print $4; exit }' /proc/mounts); "
            "  case ,$options, in *,ro,*) ;; *) exit 40 ;; esac; "
            "  if touch /$path/rejected 2>/dev/null; then exit 41; fi; "
            "done; "
            "test \"$(cat /writable/source-marker)\" = writable; "
            "touch /writable/accepted; printf bind-modes-ok",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output == b"bind-modes-ok"

    def assert_persisted_modes() -> None:
        state = json.loads((daemon.root / "engine.json").read_text())
        record = persisted_container_record(state, container.id)
        mounts = {mount["destination"]: mount for mount in record["mounts"]}
        assert mounts["/default"]["nonRecursive"] is False
        assert mounts["/default"]["readOnlyNonRecursive"] is False
        assert mounts["/default"]["readOnlyForceRecursive"] is False
        assert mounts["/nonrecursive"]["nonRecursive"] is True
        assert mounts["/nonrecursive"]["readOnlyNonRecursive"] is True
        assert mounts["/nonrecursive"]["readOnlyForceRecursive"] is False
        assert mounts["/forced"]["nonRecursive"] is False
        assert mounts["/forced"]["readOnlyNonRecursive"] is False
        assert mounts["/forced"]["readOnlyForceRecursive"] is True
        assert mounts["/writable"]["nonRecursive"] is True

    try:
        container.start()
        assert_bind_modes(container)
        assert_persisted_modes()

        container.restart(timeout=5)
        assert_bind_modes(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        value = recovered.containers.get(container.id)
        assert_bind_modes(value)
        assert_persisted_modes()

        initial_volumes = {volume.name for volume in recovered.volumes.list()}
        with pytest.raises(docker.errors.APIError) as error:
            conflict = recovered.api._post_json(
                recovered.api._url("/containers/create"),
                params={"name": f"conflicting-bind-modes-{suffix}"},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/leaked-volume": {}},
                    "HostConfig": {"Mounts": [{
                        "Type": "bind", "Source": str(sources["default"]),
                        "Target": "/data", "ReadOnly": True,
                        "BindOptions": {
                            "ReadOnlyNonRecursive": True,
                            "ReadOnlyForceRecursive": True,
                        },
                    }]},
                },
            )
            recovered.api._raise_for_status(conflict)
        assert error.value.status_code == 400
        assert {volume.name for volume in recovered.volumes.list()} == initial_volumes
        with pytest.raises(docker.errors.NotFound):
            recovered.containers.get(f"conflicting-bind-modes-{suffix}")
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-021")
def test_no_new_privileges_security_option_applies_restart_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    initial_containers = {container.id for container in client.containers.list(all=True)}
    initial_volumes = {volume.name for volume in client.volumes.list()}
    rejected_options = [
        (["no-new-privileges=maybe"], 400),
        (["no-new-privileges=false", "no-new-privileges"], 400),
        (["apparmor=loaded-profile"], 501),
    ]
    for index, (security_options, status_code) in enumerate(rejected_options):
        name = f"no-new-privileges-rejected-{suffix}-{index}"
        with pytest.raises(docker.errors.APIError) as error:
            response = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": name},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/anonymous-must-not-leak": {}},
                    "HostConfig": {"SecurityOpt": security_options},
                },
            )
            client.api._raise_for_status(response)
        assert error.value.status_code == status_code
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)
        assert {volume.name for volume in client.volumes.list()} == initial_volumes
        assert {container.id for container in client.containers.list(all=True)} == initial_containers

    false_options = ["no-new-privileges=false"]
    false_response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"no-new-privileges-false-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": [
                "sh", "-ec",
                "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status >/tmp/init-nnp; "
                "while :; do sleep 1; done",
            ],
            "HostConfig": {"SecurityOpt": false_options},
        },
    )
    client.api._raise_for_status(false_response)
    false_container = client.containers.get(false_response.json()["Id"])
    try:
        false_container.start()
        explicit_false = false_container.exec_run([
            "sh", "-ec",
            "test \"$(cat /tmp/init-nnp)\" = 0; "
            "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status",
        ])
        assert explicit_false.exit_code == 0, explicit_false.output.decode(errors="replace")
        assert explicit_false.output.strip() == b"0"
        false_container.reload()
        assert false_container.attrs["HostConfig"]["SecurityOpt"] == false_options
        state = json.loads((daemon.root / "engine.json").read_text())
        false_record = persisted_container_record(state, false_container.id)
        assert false_record["noNewPrivileges"] is False
    finally:
        false_container.remove(force=True)

    options = [
        "no-new-privileges=true", "seccomp=unconfined", "apparmor=unconfined",
    ]
    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"no-new-privileges-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": [
                "sh", "-ec",
                "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status >/tmp/init-nnp; "
                "while :; do sleep 1; done",
            ],
            "Healthcheck": {
                "Test": [
                    "CMD-SHELL",
                    "test \"$(awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status)\" = 1",
                ],
                "Interval": 1_000_000_000,
                "Timeout": 2_000_000_000,
                "Retries": 5,
            },
            "HostConfig": {"Privileged": True, "SecurityOpt": options},
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None

    def assert_policy(value: docker.models.containers.Container) -> None:
        deadline = time.monotonic() + 30
        result = None
        while time.monotonic() < deadline:
            result = value.exec_run([
                "sh", "-ec",
                "test \"$(cat /tmp/init-nnp)\" = 1; "
                "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status",
            ])
            value.reload()
            if result.exit_code == 0 and value.attrs["State"]["Health"]["Status"] == "healthy":
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "no-new-privileges init/exec/healthcheck policy was not ready: "
                f"{result.output.decode(errors='replace') if result else 'no exec result'}"
            )
        assert result.output.strip() == b"1"
        privileged_exec = value.exec_run(
            ["sh", "-ec", "awk '/^NoNewPrivs:/ { print $2 }' /proc/self/status"],
            privileged=True,
        )
        assert privileged_exec.exit_code == 0
        assert privileged_exec.output.strip() == b"1"
        value.reload()
        assert value.attrs["HostConfig"]["SecurityOpt"] == options

    try:
        container.start()
        assert_policy(container)
        state = json.loads((daemon.root / "engine.json").read_text())
        record = persisted_container_record(state, container.id)
        assert record["securityOptions"] == options
        assert record["noNewPrivileges"] is True

        container.restart(timeout=5)
        assert_policy(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_policy(recovered.containers.get(container.id))
    finally:
        cleanup = recovered or client
        try:
            cleanup.containers.get(container.id).remove(force=True)
        except docker.errors.NotFound:
            pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-028")
def test_default_seccomp_applies_to_init_exec_healthcheck_restart_and_recovery(
    daemon, client: docker.DockerClient,
):
    suffix = uuid.uuid4().hex[:8]
    initial_containers = {container.id for container in client.containers.list(all=True)}
    initial_volumes = {volume.name for volume in client.volumes.list()}
    rejected_options = [
        (["seccomp"], 400),
        (["seccomp="], 400),
        (["seccomp=builtin", "seccomp=unconfined"], 400),
        (["seccomp={}"], 501),
        (["seccomp=/tmp/profile.json"], 501),
    ]
    for index, (security_options, status_code) in enumerate(rejected_options):
        name = f"seccomp-rejected-{suffix}-{index}"
        with pytest.raises(docker.errors.APIError) as error:
            rejected = client.api._post_json(
                client.api._url("/containers/create"),
                params={"name": name},
                data={
                    "Image": ALPINE_IMAGE,
                    "Volumes": {"/anonymous-must-not-leak": {}},
                    "HostConfig": {"SecurityOpt": security_options},
                },
            )
            client.api._raise_for_status(rejected)
        assert error.value.status_code == status_code
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)
        assert {volume.name for volume in client.volumes.list()} == initial_volumes
        assert {container.id for container in client.containers.list(all=True)} == initial_containers

    response = client.api._post_json(
        client.api._url("/containers/create"),
        params={"name": f"default-seccomp-{suffix}"},
        data={
            "Image": ALPINE_IMAGE,
            "Cmd": [
                "sh", "-ec",
                "awk '/^Seccomp:/ { print $2 }' /proc/self/status >/tmp/init-seccomp; "
                "while :; do sleep 1; done",
            ],
            "Healthcheck": {
                "Test": [
                    "CMD-SHELL",
                    "test \"$(awk '/^Seccomp:/ { print $2 }' /proc/self/status)\" = 2",
                ],
                "Interval": 1_000_000_000,
                "Timeout": 2_000_000_000,
                "Retries": 5,
            },
        },
    )
    client.api._raise_for_status(response)
    container = client.containers.get(response.json()["Id"])
    recovered = None
    probe_ids = []

    def assert_default_profile(value: docker.models.containers.Container) -> None:
        deadline = time.monotonic() + 30
        result = None
        while time.monotonic() < deadline:
            result = value.exec_run([
                "sh", "-ec",
                "test \"$(cat /tmp/init-seccomp)\" = 2; "
                "awk '/^Seccomp:/ { print $2 }' /proc/self/status",
            ])
            value.reload()
            if result.exit_code == 0 and value.attrs["State"]["Health"]["Status"] == "healthy":
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "default seccomp init/exec/healthcheck policy was not ready: "
                f"{result.output.decode(errors='replace') if result else 'no exec result'}"
            )
        assert result.output.strip() == b"2"
        assert not value.attrs["HostConfig"]["SecurityOpt"]

    try:
        container.start()
        assert_default_profile(container)
        state = json.loads((daemon.root / "engine.json").read_text())
        record = persisted_container_record(state, container.id)
        assert record["securityOptions"] == []
        assert record.get("seccompProfile") is None

        container.restart(timeout=5)
        assert_default_profile(container)

        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        assert_default_profile(recovered.containers.get(container.id))

        probe_expectations = [
            ("unconfined", False, ["seccomp=unconfined"], b"0", b"0"),
            ("privileged-default", True, [], b"0", b"0"),
            ("privileged-builtin", True, ["seccomp=builtin"], b"2", b"0"),
            (
                "explicit-false-builtin", False,
                ["no-new-privileges=false", "seccomp=builtin"], b"2", b"0",
            ),
        ]

        def assert_probe(
            value: docker.models.containers.Container,
            security_options: list[str], expected_seccomp: bytes, expected_nnp: bytes,
        ) -> None:
            mode = value.exec_run([
                "sh", "-ec",
                "for pid in 1 self; do "
                "printf '%s %s\\n' "
                "\"$(awk '/^Seccomp:/ { print $2 }' /proc/$pid/status)\" "
                "\"$(awk '/^NoNewPrivs:/ { print $2 }' /proc/$pid/status)\"; "
                "done",
            ])
            assert mode.exit_code == 0, mode.output
            expected = expected_seccomp + b" " + expected_nnp
            assert mode.output.splitlines() == [expected, expected]
            value.reload()
            if security_options:
                assert value.attrs["HostConfig"]["SecurityOpt"] == security_options
            else:
                assert not value.attrs["HostConfig"]["SecurityOpt"]

        for name, privileged, security_options, expected_seccomp, expected_nnp in probe_expectations:
            probe = recovered.containers.run(
                ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True,
                name=f"seccomp-{name}-{suffix}", privileged=privileged,
                security_opt=security_options,
            )
            probe_ids.append(probe.id)
            assert_probe(probe, security_options, expected_seccomp, expected_nnp)

        daemon.restart(kill=True)
        recovered.close()
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        for probe_id, expectation in zip(probe_ids, probe_expectations, strict=True):
            _, _, security_options, expected_seccomp, expected_nnp = expectation
            assert_probe(
                recovered.containers.get(probe_id), security_options,
                expected_seccomp, expected_nnp,
            )
    finally:
        cleanup = recovered or client
        for container_id in [container.id, *probe_ids]:
            try:
                cleanup.containers.get(container_id).remove(force=True)
            except docker.errors.NotFound:
                pass
        if recovered is not None:
            recovered.close()


@pytest.mark.compat("RTM-004")
def test_pids_limit_enforces_live_updates_and_survives_recovery(
    daemon, client: docker.DockerClient,
):
    container = client.containers.run(
        ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True, pids_limit=8,
    )
    try:
        container.reload()
        assert container.attrs["HostConfig"]["PidsLimit"] == 8
        result = container.exec_run(["cat", "/sys/fs/cgroup/pids.max"])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        assert result.output.strip() == b"8"

        response = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={"PidsLimit": 1},
        )
        client.api._result(response, True)
        try:
            constrained = container.exec_run(["true"])
        except docker.errors.APIError:
            pass
        else:
            assert constrained.exit_code != 0, "pids.max=1 unexpectedly allowed an exec process"

        response = client.api._post_json(
            client.api._url("/containers/{0}/update", container.id),
            data={"PidsLimit": 12},
        )
        client.api._result(response, True)
        daemon.restart(kill=True)
        recovered = docker.DockerClient(
            base_url=f"unix://{daemon.socket}", timeout=180, version="auto",
        )
        try:
            value = recovered.containers.get(container.id)
            value.reload()
            assert value.attrs["HostConfig"]["PidsLimit"] == 12
            result = value.exec_run(["cat", "/sys/fs/cgroup/pids.max"])
            assert result.exit_code == 0, result.output.decode(errors="replace")
            assert result.output.strip() == b"12"
        finally:
            recovered.close()
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-005")
def test_unrealizable_bind_mount_propagation_is_rejected(
    client: docker.DockerClient, tmp_path: pathlib.Path,
):
    suffix = uuid.uuid4().hex[:8]
    initial_containers = {container.id for container in client.containers.list(all=True)}
    initial_volumes = {volume.name for volume in client.volumes.list()}
    accepted = []
    try:
        for index, propagation in enumerate(("private", "rprivate")):
            container = client.containers.create(
                ALPINE_IMAGE,
                ["tail", "-f", "/dev/null"],
                name=f"propagation-accepted-{suffix}-{index}",
                mounts=[Mount(
                    target="/propagated", source=str(tmp_path), type="bind",
                    propagation=propagation,
                )],
            )
            accepted.append(container)

        accepted_ids = {container.id for container in accepted}
        for index, propagation in enumerate(("shared", "rshared", "slave", "rslave")):
            for shape, host_config in (
                ("legacy", {"Binds": [f"{tmp_path}:/propagated:{propagation}"]}),
                ("structured", {"Mounts": [{
                    "Type": "bind", "Source": str(tmp_path), "Target": "/propagated",
                    "BindOptions": {"Propagation": propagation},
                }]}),
            ):
                name = f"propagation-rejected-{suffix}-{shape}-{index}"
                with pytest.raises(docker.errors.APIError) as error:
                    response = client.api._post_json(
                        client.api._url("/containers/create"),
                        params={"name": name},
                        data={
                            "Image": ALPINE_IMAGE,
                            "Volumes": {"/anonymous-must-not-leak": {}},
                            "HostConfig": host_config,
                        },
                    )
                    client.api._raise_for_status(response)
                assert error.value.status_code == 501
                with pytest.raises(docker.errors.NotFound):
                    client.containers.get(name)
                assert {volume.name for volume in client.volumes.list()} == initial_volumes
                assert {
                    container.id for container in client.containers.list(all=True)
                } == initial_containers | accepted_ids
    finally:
        for container in accepted:
            container.remove(force=True)


@pytest.mark.compat("RTM-006")
def test_capability_add_drop_apply_to_init_and_exec(client: docker.DockerClient):
    container = client.containers.run(
        ALPINE_IMAGE,
        [
            "sh", "-ec",
            "awk '/^CapEff:/ { print $2 }' /proc/self/status >/tmp/init-cap; "
            "while :; do sleep 1; done",
        ],
        detach=True,
        cap_drop=["ALL", "CHOWN"],
        cap_add=["CHOWN", "NET_ADMIN"],
    )
    try:
        result = container.exec_run([
            "sh", "-ec",
            "cat /tmp/init-cap; awk '/^CapEff:/ { print $2 }' /proc/self/status",
        ])
        assert result.exit_code == 0, result.output.decode(errors="replace")
        init_mask, exec_mask = (int(value, 16) for value in result.output.splitlines())
        expected = (1 << 0) | (1 << 12)  # CAP_CHOWN | CAP_NET_ADMIN
        assert init_mask == expected
        assert exec_mask == expected
        container.reload()
        assert container.attrs["HostConfig"]["CapDrop"] == ["ALL", "CAP_CHOWN"]
        assert container.attrs["HostConfig"]["CapAdd"] == ["CAP_CHOWN", "CAP_NET_ADMIN"]
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-007")
def test_container_prune_honors_filters_and_rejects_unknown_keys(client: docker.DockerClient):
    selected = client.containers.create(ALPINE_IMAGE, ["true"], labels={"prune": "yes"})
    preserved = client.containers.create(ALPINE_IMAGE, ["true"], labels={"prune": "no"})
    try:
        with pytest.raises(docker.errors.APIError) as error:
            client.containers.prune(filters={"name": [selected.name]})
        assert error.value.status_code == 400
        client.containers.get(selected.id)
        client.containers.get(preserved.id)

        response = client.containers.prune(filters={"label": ["prune=yes"]})
        assert response["ContainersDeleted"] == [selected.id]
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(selected.id)
        client.containers.get(preserved.id)
    finally:
        for container in (selected, preserved):
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass


@pytest.mark.compat("RTM-008")
def test_exec_stage_proxies_preserve_status_and_kill_timed_out_healthchecks(
    client: docker.DockerClient,
):
    healthcheck = """
        mkdir -p /tmp/healthcheck-pids
        for marker in /tmp/healthcheck-pids/*; do
            [ -f "$marker" ] || continue
            for pid in $(cat "$marker"); do
                state=$(awk '{ print $3 }' "/proc/$pid/stat" 2>/dev/null || true)
                if [ -n "$state" ] && [ "$state" != Z ]; then
                    touch /tmp/orphaned-healthcheck
                    exit 42
                fi
            done
        done
        sleep 30 &
        child=$!
        printf '%s %s' "$$" "$child" > "/tmp/healthcheck-pids/$$"
        wait "$child"
    """
    container = client.containers.run(
        ALPINE_IMAGE,
        ["tail", "-f", "/dev/null"],
        detach=True,
        healthcheck={
            "test": ["CMD-SHELL", healthcheck],
            "interval": 1_000_000_000,
            "timeout": 1_000_000_000,
            "retries": 2,
        },
    )
    try:
        failed = container.exec_run(["sh", "-c", "exit 23"])
        assert failed.exit_code == 23

        inspected_exec = client.api.exec_create(
            container.id,
            [
                "sh",
                "-c",
                "printf '%s' \"$$\" > /tmp/exec-target-pid; sleep 30",
            ],
        )["Id"]
        client.api.exec_start(inspected_exec, detach=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            observed = container.exec_run(["cat", "/tmp/exec-target-pid"])
            if observed.exit_code == 0 and observed.output.strip():
                break
            time.sleep(0.1)
        else:
            pytest.fail("exec target did not publish its workload-namespace PID")
        inspect = client.api.exec_inspect(inspected_exec)
        assert inspect["Running"] is True
        assert inspect["Pid"] == int(observed.output.strip())

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            container.reload()
            if container.attrs["State"]["Health"]["FailingStreak"] >= 2:
                break
            time.sleep(0.2)
        else:
            pytest.fail(f"healthcheck did not time out twice: {container.attrs['State']['Health']}")

        surviving_exec = client.api.exec_inspect(inspected_exec)
        assert surviving_exec["Running"] is True, "healthcheck cgroup kill reached a sibling exec"
        assert surviving_exec["Pid"] == inspect["Pid"]
        orphan = container.exec_run(["test", "-e", "/tmp/orphaned-healthcheck"])
        assert orphan.exit_code == 1, "a timed-out healthcheck target or descendant survived its exec cgroup"
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-009")
def test_attached_exec_inspect_publishes_pid_and_terminal_status(
    client: docker.DockerClient,
):
    container = client.containers.run(
        ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True,
    )
    try:
        exec_id = client.api.exec_create(
            container.id,
            [
                "sh", "-ec",
                "rm -f /tmp/release-attached-exec; "
                "while [ ! -e /tmp/release-attached-exec ]; do sleep 1; done; exit 23",
            ],
            stdout=True,
            stderr=True,
        )["Id"]
        results: list[bytes] = []
        errors: list[BaseException] = []

        def start_attached() -> None:
            try:
                results.append(client.api.exec_start(exec_id, detach=False, tty=False))
            except BaseException as error:  # surfaced after joining the worker
                errors.append(error)

        starter = threading.Thread(target=start_attached)
        starter.start()
        deadline = time.monotonic() + 10
        running = None
        while time.monotonic() < deadline:
            running = client.api.exec_inspect(exec_id)
            if running["Running"] and running["Pid"] > 0:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"attached exec did not publish a running PID: {running}")

        released = container.exec_run(["touch", "/tmp/release-attached-exec"])
        assert released.exit_code == 0, released.output
        starter.join(timeout=30)
        assert not starter.is_alive(), "attached exec stream did not close after process exit"
        assert not errors, errors
        assert results == [b""]

        completed = client.api.exec_inspect(exec_id)
        assert completed["Running"] is False
        assert completed["ExitCode"] == 23
        assert completed["Pid"] == running["Pid"]

        fast_exec = client.api.exec_create(
            container.id, ["sh", "-c", "exit 29"], stdout=True, stderr=True,
        )["Id"]
        assert client.api.exec_start(fast_exec, detach=False, tty=False) == b""
        fast_completed = client.api.exec_inspect(fast_exec)
        assert fast_completed["Running"] is False
        assert fast_completed["ExitCode"] == 29
        assert fast_completed["Pid"] > 0
    finally:
        container.remove(force=True)


@pytest.mark.compat("RTM-029")
def test_exec_create_racing_init_exit_reports_container_not_running(
    client: docker.DockerClient,
):
    rejected = 0
    for _ in range(4):
        container = client.containers.create(
            ALPINE_IMAGE, ["sh", "-c", "exit 0"],
        )
        try:
            container.start()
            try:
                client.api.exec_create(container.id, ["true"])
            except docker.errors.APIError as error:
                rejected += 1
                assert error.status_code == 409
                assert "is not running" in error.explanation
                assert "VM shim" not in error.explanation
        finally:
            container.remove(force=True)

    assert rejected > 0, "immediate init exit did not exercise exec-create rejection"


@pytest.mark.compat("RTM-010")
def test_paused_stop_restart_and_force_remove_complete(client: docker.DockerClient):
    stopped = client.containers.run(
        ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True,
    )
    restarted = client.containers.run(
        ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True,
    )
    removed = client.containers.run(
        ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True,
    )
    try:
        stopped.pause()
        stopped.stop(timeout=1)
        stopped.reload()
        assert stopped.status == "exited"

        restarted.pause()
        restarted.restart(timeout=1)
        restarted.reload()
        assert restarted.status == "running"
        responsive = restarted.exec_run(["sh", "-c", "printf restarted"])
        assert responsive.exit_code == 0
        assert responsive.output == b"restarted"

        removed.pause()
        removed.remove(force=True)
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(removed.id)
    finally:
        for container in (stopped, restarted, removed):
            try:
                container.remove(force=True)
            except docker.errors.NotFound:
                pass


@pytest.mark.compat("RTM-011")
def test_parent_stop_and_restart_terminalize_attached_and_detached_execs(
    client: docker.DockerClient,
):
    for operation in ("stop", "restart"):
        container = client.containers.run(
            ALPINE_IMAGE, ["tail", "-f", "/dev/null"], detach=True,
        )
        attached_errors: list[BaseException] = []
        try:
            detached = client.api.exec_create(container.id, ["sleep", "300"])["Id"]
            attached = client.api.exec_create(container.id, ["sleep", "300"])["Id"]
            client.api.exec_start(detached, detach=True)

            def start_attached() -> None:
                try:
                    client.api.exec_start(attached, detach=False, tty=False)
                except BaseException as error:  # surfaced after joining the worker
                    attached_errors.append(error)

            starter = threading.Thread(target=start_attached)
            starter.start()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                states = [client.api.exec_inspect(value) for value in (detached, attached)]
                if all(state["Running"] and state["Pid"] > 0 for state in states):
                    break
                time.sleep(0.05)
            else:
                pytest.fail(f"{operation} execs did not both become running: {states}")

            if operation == "stop":
                container.stop(timeout=1)
            else:
                container.restart(timeout=1)
            starter.join(timeout=15)
            assert not starter.is_alive(), (
                f"attached exec stream survived parent {operation}"
            )
            assert not attached_errors, attached_errors
            for exec_id in (detached, attached):
                def terminal_state() -> tuple[bool, bool]:
                    state = client.api.exec_inspect(exec_id)
                    return state["Running"], state["ExitCode"] is not None

                wait_for_compat_value(
                    terminal_state, (False, True),
                    f"{operation} exec {exec_id} terminal state",
                )
                inspected = client.api.exec_inspect(exec_id)
                assert inspected["Pid"] > 0
            container.reload()
            if operation == "stop":
                assert container.status == "exited"
            else:
                assert container.status == "running"
                responsive = container.exec_run(["sh", "-c", "printf restarted"])
                assert responsive.exit_code == 0
                assert responsive.output == b"restarted"
        finally:
            container.remove(force=True)


def archive_file(name: str, contents: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        info = tarfile.TarInfo(name)
        info.mode = 0o600
        info.size = len(contents)
        archive.addfile(info, io.BytesIO(contents))
    return output.getvalue()


def outer_exec(
    container: docker.models.containers.Container, command: list[str],
) -> tuple[int, str]:
    result = container.exec_run(command)
    output = result.output.decode(errors="replace")
    return result.exit_code, output


def dind_diagnostics(container: docker.models.containers.Container) -> str:
    sections = [f"outer logs:\n{container.logs().decode(errors='replace')}"]
    for name, command in [
        ("docker info", ["docker", "info"]),
        ("docker ps -a", ["docker", "ps", "-a", "--no-trunc"]),
        ("nested inspect", ["docker", "inspect", "runtime-nested"]),
    ]:
        try:
            code, output = outer_exec(container, command)
            sections.append(f"{name} (exit {code}):\n{output}")
        except docker.errors.DockerException as error:
            sections.append(f"{name}: {error}")
    return "\n\n".join(sections)


@pytest.mark.compat("RTM-003")
def test_nested_docker_exec_and_healthcheck_without_kind(client: docker.DockerClient):
    container = client.containers.create(
        DIND_IMAGE,
        ["--host=unix:///var/run/docker.sock", "--storage-driver=overlay2"],
        privileged=True,
        environment={"DOCKER_TLS_CERTDIR": ""},
        tmpfs={
            "/run": "rw,nosuid,nodev,mode=755",
            "/tmp": "rw,nosuid,nodev,mode=1777",
        },
        mem_limit=2 * 1024 * 1024 * 1024,
        nano_cpus=2_000_000_000,
    )
    try:
        container.start()
        deadline = time.monotonic() + 120
        last_info = "nested daemon readiness has not run"
        while time.monotonic() < deadline:
            code, last_info = outer_exec(container, ["docker", "info", "--format", "{{.Driver}}"])
            if code == 0 and last_info.strip() == "overlay2":
                break
            time.sleep(0.2)
        else:
            pytest.fail(
                f"nested Docker daemon did not become ready; last result: {last_info}\n\n"
                + dind_diagnostics(container)
            )

        alpine_archive = b"".join(client.images.get(ALPINE_IMAGE).save(named=True))
        assert container.put_archive("/tmp", archive_file("alpine.tar", alpine_archive))
        code, output = outer_exec(container, ["docker", "load", "--input", "/tmp/alpine.tar"])
        assert code == 0, output + "\n\n" + dind_diagnostics(container)

        code, output = outer_exec(container, [
            "docker", "run", "--detach", "--name", "runtime-nested",
            "--workdir", "/data",
            "--health-cmd", "test \"$(pwd)\" = /data",
            "--health-interval", "1s", "--health-timeout", "2s", "--health-retries", "5",
            ALPINE_IMAGE, "sh", "-c", "while :; do sleep 1; done",
        ])
        assert code == 0, output + "\n\n" + dind_diagnostics(container)

        code, output = outer_exec(container, [
            "docker", "exec", "runtime-nested", "sh", "-ec",
            "test \"$(pwd)\" = /data; printf nested-exec-ok",
        ])
        assert code == 0, output + "\n\n" + dind_diagnostics(container)
        assert output == "nested-exec-ok"

        deadline = time.monotonic() + 30
        health = "healthcheck has not run"
        while time.monotonic() < deadline:
            code, health = outer_exec(container, [
                "docker", "inspect", "--format", "{{.State.Health.Status}}", "runtime-nested",
            ])
            if code == 0 and health.strip() == "healthy":
                break
            time.sleep(0.2)
        else:
            pytest.fail(
                f"nested container did not become healthy; last result: {health}\n\n"
                + dind_diagnostics(container)
            )
    finally:
        container.remove(force=True)
