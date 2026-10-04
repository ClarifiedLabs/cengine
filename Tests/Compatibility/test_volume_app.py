"""Bounded real Redis lifecycle: root init, shared nonroot I/O, RO backup, restore.

CMP-045: Compose create/up, ordinary down retention, down -v owned/external split.
ORC-024: identical scenario on explicit reference Docker FIRST, then real cengine.
Contracts: Compose volumes external lifecycle; Docker stop/volume deletion API;
Redis SAVE RDB persistence and official root entrypoint ownership/drop-privileges.
Run only through make test-compat. No binds, parallel Redis servers, or late
block-to-shared promotion. Numeric metadata baselines remain RTM-053/055.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import docker
import pytest

from harness import managed_docker_environment
from test_compose import VolumeComposeEndpoint, volume_compose


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "Tests/Fixtures/compose/upstream-volumes/redis-backup.yaml"
REDIS = "redis@sha256:90cac51530a49aaa42eaf65712e84005677a0c44191e721e2de756927031fb9d"
ALPINE = "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
OWNER_LABEL = "dev.cengine.compat.owner"
DATA = "volume-campaign-v1\nalice\n42\nqueued\ncomplete\n"
READ_DATA = """return {redis.call('GET', 'app:version'),
redis.call('HGET', 'app:account', 'owner'),
redis.call('HGET', 'app:account', 'balance'),
redis.call('LRANGE', 'app:jobs', 0, -1)}"""


def _sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def _artifacts(daemon, endpoints):
    directory = REPO_ROOT / ".build/volume-hunt" / ("app-" + uuid.uuid4().hex)
    directory.mkdir(parents=True)
    print(f"Redis volume lifecycle artifacts: {directory}")
    environment = managed_docker_environment()
    metadata = {
        "revision": subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, check=True,
            capture_output=True, text=True, timeout=10,
        ).stdout.strip(),
        "compose_version": subprocess.run(
            ["docker", "compose", "version", "--short"], env=environment,
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip(),
        "images": [REDIS, ALPINE], "platform": "linux/arm64",
        "redis_source_revision": "8338d86bc3f7b195046138f8c31bf9a839cdedd3",
        "source_sha256": {
            str(path.relative_to(REPO_ROOT)): _sha256(path)
            for path in (Path(__file__), FIXTURE, REPO_ROOT / "Tests/Compatibility/test_compose.py")
        },
        "assets": {
            name: {"path": str(getattr(daemon, name)), "sha256": _sha256(getattr(daemon, name))}
            for name in ("binary", "kernel", "container_initramfs", "storage_initramfs")
        },
        "endpoints": {
            label: {"host": endpoint.host, "version": client.version()}
            for label, endpoint, client in endpoints
        },
        "client_state": {key: environment.get(key) for key in (
            "DOCKER_CONFIG", "BUILDX_CONFIG", "CENGINE_COMPAT_RUN_ID",
        )},
        "reference_storage": "Docker local volume control, not cengine backend proof",
        "expected_data": DATA,
        "expected_sha256": hashlib.sha256(DATA.encode()).hexdigest(),
    }
    _write(directory / "environment.json", metadata)
    shutil.copyfile(FIXTURE, directory / FIXTURE.name)
    return directory


def _failure_containers(client, project_name):
    """Read-only, best-effort evidence while failed containers still exist."""
    evidence = {"containers": [], "errors": []}
    try:
        containers = client.containers.list(
            all=True, sparse=True, filters={"label": f"com.docker.compose.project={project_name}"},
        )
    except Exception as error:
        evidence["errors"].append(f"container listing: {type(error).__name__}: {error}")
        return evidence
    for container in containers:
        captured = {"id": container.id}
        evidence["containers"].append(captured)
        # Inspect and logs are independent: a broken endpoint must not hide
        # the other evidence, prevent cleanup, or replace the original failure.
        try:
            container.reload()
            captured["inspect"] = container.attrs
        except Exception as error:
            captured["inspect_error"] = f"{type(error).__name__}: {error}"
        try:
            captured["logs"] = container.logs(
                stdout=True, stderr=True, timestamps=True, tail=200,
                stream=False, follow=False,
            ).decode(errors="replace")
        except Exception as error:
            captured["logs_error"] = f"{type(error).__name__}: {error}"
    return evidence


def _scenario(endpoint, client, directory, label):
    """One server at a time; both mount consumers exist before every startup."""
    token = uuid.uuid4().hex
    name = "cengineapp" + token
    root = endpoint.work / name
    root.mkdir(parents=True)
    shutil.copyfile(FIXTURE, root / FIXTURE.name)
    data_name, backup_name = name + "-data", name + "-backup"
    project = {
        "name": name, "root": root, "file": FIXTURE.name,
        "environment": {
            "CENGINE_APP_DATA": data_name, "CENGINE_APP_BACKUP": backup_name,
            "CENGINE_APP_OWNER": token, "CENGINE_APP_RESTORE": "0",
        },
    }
    record = {"status": "started", "project": project["environment"], "observations": [], "commands": []}
    path = directory / f"{label}.json"

    def compose(*arguments, check=True):
        command = {"arguments": arguments, "status": "started"}
        record["commands"].append(command)
        _write(path, record)
        result = volume_compose(endpoint, project, *arguments, check=False)
        command.update(status="finished", returncode=result.returncode, output=result.stdout)
        _write(path, record)
        if check:
            assert result.returncode == 0, result.stdout
        return result.stdout

    def execute(service, *arguments):
        # Bound both guest execution and the client process (helper: 300s).
        return compose("exec", "-T", service, "timeout", "20", *arguments)

    def redis(*arguments):
        return execute("server", "redis-cli", "--raw", *arguments)

    def start():
        compose("create")
        created = client.containers.list(all=True, filters={"label": f"com.docker.compose.project={name}"})
        assert len(created) == 2, [container.attrs for container in created]
        assert all(container.status == "created" for container in created)
        compose("up", "-d", "--no-recreate", "--wait", "--wait-timeout", "60")
        containers = {c.labels["com.docker.compose.service"]: c for c in created}
        for service, container in containers.items():
            container.reload()
            assert container.status == "running", container.attrs["State"]
            mounts = {mount["Destination"]: mount for mount in container.attrs["Mounts"]}
            assert all(mount["Type"] == "volume" for mount in mounts.values()), mounts
            target = "/data" if service == "server" else "/source"
            assert mounts[target]["Name"] == data_name, mounts
            assert mounts[target]["RW"] == (service == "server"), mounts
            assert mounts["/backup"]["Name"] == backup_name, mounts
            assert mounts["/backup"]["RW"] == (service == "backup"), mounts
        backend = "Docker local volume control"
        if endpoint.daemon is not None:
            backend = json.loads((endpoint.daemon.root / "volume-storage.json").read_text())
            assert backend[data_name] == "shared", backend
            assert backend[backup_name] == "shared", backend
        # Config starts root, but PID 1 must be the Redis account after init.
        assert containers["server"].attrs["Config"]["User"] == "0:0"
        uid = execute("server", "sh", "-ec", "awk '/^Uid:/ {print $2}' /proc/1/status").strip()
        assert uid == execute("server", "id", "-u", "redis").strip() and uid != "0", uid
        record["observations"].append({"server": containers["server"].id, "pid1_uid": uid, "backend": backend})
        _write(path, record)
        return containers["server"]

    def observe(phase):
        content = redis("EVAL", READ_DATA, "0")
        assert content == DATA, repr(content)
        assert redis("DBSIZE") == "3\n"
        observation = {"phase": phase, "content": content, "sha256": hashlib.sha256(content.encode()).hexdigest()}
        record["observations"].append(observation)
        _write(path, record)
        return observation["sha256"]

    def down(volumes=False):
        compose("down", *(["--volumes"] if volumes else []))
        assert not client.containers.list(all=True, filters={"label": f"com.docker.compose.project={name}"})
        assert client.volumes.get(backup_name).attrs["Labels"][OWNER_LABEL] == token
        if volumes:
            with pytest.raises(docker.errors.NotFound):
                client.volumes.get(data_name)
        else:
            assert client.volumes.get(data_name).attrs["Labels"][OWNER_LABEL] == token

    try:
        client.volumes.create(backup_name, labels={OWNER_LABEL: token})
        compose("pull")
        record["images"] = {}
        for image_name in (REDIS, ALPINE):
            image = client.images.get(image_name)
            assert image.attrs["Os"] == "linux" and image.attrs["Architecture"] == "arm64", image.attrs
            assert image_name in image.attrs.get("RepoDigests", []), image.attrs
            record["images"][image_name] = {key: image.attrs.get(key) for key in ("Id", "RepoDigests", "RootFS")}
        first = start()
        assert redis("SET", "app:version", "volume-campaign-v1") == "OK\n"
        assert redis("HSET", "app:account", "owner", "alice", "balance", "42") == "2\n"
        assert redis("RPUSH", "app:jobs", "queued", "complete") == "2\n"
        digest = observe("written")
        assert redis("SAVE") == "OK\n"
        compose("stop", "--timeout", "20", "server")
        first.reload()
        assert first.status == "exited" and first.attrs["State"]["ExitCode"] == 0, first.attrs["State"]
        snapshot = execute(
            "backup", "sh", "-ec",
            "test -s /source/dump.rdb; "
            "if touch /source/must-not-write 2>/dev/null; then exit 91; fi; "
            "cp /source/dump.rdb /backup/dump.rdb; "
            "cmp /source/dump.rdb /backup/dump.rdb; sha256sum /backup/dump.rdb",
        ).split()[0]
        assert len(snapshot) == 64 and all(c in "0123456789abcdef" for c in snapshot), snapshot
        record["snapshot_sha256"] = snapshot
        down()
        retained = start()
        assert retained.id != first.id
        observe("ordinary-down-retained")
        assert execute("backup", "sha256sum", "/backup/dump.rdb").split()[0] == snapshot
        down(volumes=True)
        # Owned data is now absent. Root init restores the retained external RDB
        # into the fresh volume, compares bytes, then runs the official entrypoint.
        project["environment"]["CENGINE_APP_RESTORE"] = "1"
        restored = start()
        assert restored.id not in (first.id, retained.id)
        observe("replacement-restored")
        assert execute("backup", "sha256sum", "/source/dump.rdb").split()[0] == snapshot
        assert execute("backup", "sha256sum", "/backup/dump.rdb").split()[0] == snapshot
        down(volumes=True)
        record["status"] = "passed"
        return digest
    except BaseException as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
        try:
            record["failure_containers"] = _failure_containers(client, name)
            _write(path, record)
        except Exception as capture_error:
            record["failure_capture_error"] = f"{type(capture_error).__name__}: {capture_error}"
        raise
    finally:
        failures = []
        if endpoint.daemon is not None:
            try:
                storage = endpoint.daemon.root / "volume-storage.json"
                if storage.exists():
                    record["final_backend_storage"] = json.loads(storage.read_text())
            except (OSError, ValueError) as error:
                failures.append(f"backend evidence capture: {error}")
        try:
            compose("down", "--volumes", "--remove-orphans")
        except Exception as error:
            failures.append(f"Compose cleanup: {error}")
        # Only unique project containers and owner-labelled volumes are eligible.
        try:
            for container in client.containers.list(all=True, filters={"label": f"com.docker.compose.project={name}"}):
                container.remove(force=True, v=True)
        except Exception as error:
            failures.append(f"container cleanup: {error}")
        for volume_name in (data_name, backup_name):
            try:
                volume = client.volumes.get(volume_name)
                assert volume.attrs.get("Labels", {}).get(OWNER_LABEL) == token, volume.attrs
                volume.remove()
            except docker.errors.NotFound:
                pass
            except Exception as error:
                failures.append(f"volume cleanup {volume_name}: {error}")
        record["cleanup_failures"] = failures
        _write(path, record)
        shutil.rmtree(root)
        if failures:
            if record["status"] == "passed":
                pytest.fail("; ".join(failures))
            print(f"Redis lifecycle cleanup failures: {failures}")


@pytest.mark.compat("CMP-045")
def test_compose_redis_volume_backup_and_replacement(daemon, client):
    endpoint = VolumeComposeEndpoint(
        f"unix://{daemon.socket}", daemon.work, managed_docker_environment(), daemon,
    )
    directory = _artifacts(daemon, [("cengine", endpoint, client)])
    _scenario(endpoint, client, directory, "cengine")


@pytest.mark.oracle
@pytest.mark.compat("ORC-024")
@pytest.mark.skipif(not os.environ.get("DOCKER_REFERENCE_HOST"), reason="requires explicit DOCKER_REFERENCE_HOST")
def test_compose_redis_volume_matches_reference(daemon, client):
    host = os.environ["DOCKER_REFERENCE_HOST"]
    assert host.startswith("unix://"), "reference must be an explicit local Docker/Colima socket"
    assert Path(host.removeprefix("unix://")).resolve() != daemon.socket.resolve()
    environment = managed_docker_environment()
    with closing(docker.DockerClient(base_url=host, timeout=180, version="auto")) as reference:
        version = reference.version()
        assert version.get("Platform", {}).get("Name", "").lower() != "cengine", version
        assert version.get("Os") == "linux" and version.get("Arch") in ("arm64", "aarch64"), version
        control = VolumeComposeEndpoint(host, daemon.work, environment, None)
        candidate = VolumeComposeEndpoint(f"unix://{daemon.socket}", daemon.work, environment, daemon)
        directory = _artifacts(daemon, [("docker", control, reference), ("cengine", candidate, client)])
        expected = _scenario(control, reference, directory, "docker")
        actual = _scenario(candidate, client, directory, "cengine")
        # RDB bytes contain engine/run metadata; compare logical data across
        # engines, but require exact snapshot/restore bytes within each run.
        assert actual == expected
        control_images = json.loads((directory / "docker.json").read_text())["images"]
        candidate_images = json.loads((directory / "cengine.json").read_text())["images"]
        for image in (REDIS, ALPINE):
            assert candidate_images[image]["RootFS"] == control_images[image]["RootFS"]
