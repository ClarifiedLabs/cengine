"""RTM-086: direct execve of volume shebang/ELF files, never interpreter bypass."""
from __future__ import annotations

import errno
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

import pytest

from storage_backend_proof import daemon_startup_mode, verify_backend
from test_volume_workflows import _campaign as workflow

IMAGE = "mirror.gcr.io/library/python@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
SOURCE = Path(__file__).parent / "fixtures/volume-exec.py"
OWNER = "dev.cengine.compat.volume-exec"
MAX_EVIDENCE = 1024 * 1024


def validate_result(value):
    assert value.get("schema") == 1 and "error" not in value, value
    assert (value.get("uid"), value.get("gid")) == (10001, 10001), value
    assert value.get("capabilities") == dict.fromkeys(
        ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), 0), value
    assert re.fullmatch("[0-9a-f]{64}", value.get("elf_sha256", "")), value
    expected = []
    for name, arguments, output in (("script", [], "rtm086-script\n"),
                                    ("echo", ["rtm086-elf"], "rtm086-elf\n"),
                                    ("script-noexec", [], None),
                                    ("echo-noexec", ["rtm086-elf"], None)):
        case = {"name": name, "argv": ["/tmp/rtm086/" + name, *arguments]}
        expected.append({**case, **({"errno": errno.EACCES} if output is None
                                   else {"exit": 0, "output": output})})
    assert value.get("cases") == expected, value


def backend_proof(daemon, volume_name, storage, value):
    with (daemon.root / "volume-storage.json").open("rb") as stream:
        raw = stream.read(MAX_EVIDENCE + 1)
    assert len(raw) <= MAX_EVIDENCE, "topology evidence exceeds bound"
    assert json.loads(raw).get(volume_name) == storage, "wrong selected volume topology"
    proof = verify_backend(daemon.root, storage, value["mountinfo"], "/tmp",
                           startup_mode=daemon_startup_mode(daemon))
    assert "noexec" not in proof["mount"]["options"], proof
    return proof


def cleanup(client, names, token):
    errors = []
    for kind, name in reversed(names):
        try:
            with workflow.api_deadline(client, time.monotonic() + 5):
                resource = getattr(client, kind + "s").get(name)
                labels = (resource.attrs.get("Config", {}).get("Labels") if kind == "container"
                          else resource.attrs.get("Labels"))
                if resource.name != name or not isinstance(labels, dict) or labels.get(OWNER) != token:
                    raise ValueError("wrong cleanup owner")
                resource.remove(**({"force": True} if kind == "container" else {}))
        except Exception as error:
            if getattr(error, "status_code", None) != 404:
                errors.append(f"{kind} {name}: {str(error)[:512]}")
    return errors


def run(daemon):
    import docker
    from docker.types import Mount, Ulimit

    token = uuid.uuid4().hex
    directory = Path(__file__).resolve().parents[2] / ".build/volume-hunt" / ("exec-" + token)
    directory.mkdir(parents=True)
    print(f"volume direct-exec evidence: {directory}")
    used = 0

    def record(value):
        nonlocal used
        data = (json.dumps(value, sort_keys=True) + "\n").encode()
        assert used + len(data) <= MAX_EVIDENCE, "direct-exec evidence exceeds bound"
        with (directory / "evidence.jsonl").open("ab") as output:
            output.write(data)
        used += len(data)

    source = SOURCE.read_text()
    assert len(source.encode()) <= 65536, "guest source exceeds bound"
    record({"phase": "plan", "image": IMAGE, "owner": token,
            "source_sha256": hashlib.sha256(source.encode()).hexdigest()})
    deadline = time.monotonic() + 240
    client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.45", timeout=30)
    names = []
    failure = None
    try:
        image = workflow.api_call(client, deadline, client.images.get, IMAGE).attrs
        assert (image.get("Os"), image.get("Architecture")) == ("linux", "arm64"), image
        assert IMAGE in image.get("RepoDigests", []), image  # No pull/build/load fallback.
        for storage in ("block", "shared"):
            volume = f"rtm086-{token}-{storage}"
            names.append(("volume", volume))  # Register before an ambiguous create.
            workflow.api_call(client, deadline, client.volumes.create, volume, labels={OWNER: token})
            containers = []
            for index in range(2 if storage == "shared" else 1):
                name = volume + f"-{index}"
                names.append(("container", name))
                container = workflow.api_call(client, deadline, client.containers.create,
                    IMAGE, name=name, entrypoint=["/usr/local/bin/python", "-I", "-B", "-c"],
                    command=[source, "seed" if index == 0 else "peer"], user="10001:10001",
                    # Copy-up preserves the image's writable /tmp mode, no root initializer.
                    mounts=[Mount("/tmp", volume, type="volume", no_copy=False)],
                    tmpfs={"/run": "rw,nosuid,nodev,noexec,size=1m,mode=1777"},
                    read_only=True, network_mode="none", working_dir="/",
                    cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
                    pids_limit=16, mem_limit="128m", labels={OWNER: token},
                    ulimits=[Ulimit(name="nofile", soft=64, hard=64),
                             Ulimit(name="core", soft=0, hard=0),
                             Ulimit(name="cpu", soft=10, hard=10),
                             Ulimit(name="fsize", soft=1048576, hard=1048576)])
                containers.append(container)
            # Both shared creates precede either start; peer executes the SAME files.
            for index, container in enumerate(containers):
                phase_deadline = min(deadline, time.monotonic() + 60)
                workflow.api_call(client, phase_deadline, container.start)
                status = workflow.api_call(client, phase_deadline, container.wait,
                                           timeout=max(0.001, phase_deadline - time.monotonic()))
                raw, stderr = workflow.read_logs(client, container, phase_deadline)
                record({"phase": "result", "storage": storage, "consumer": index,
                        "status": status, "stdout": raw.decode(errors="replace"),
                        "stderr": stderr.decode(errors="replace")})
                value = json.loads(raw)
                record({"phase": "backend", "storage": storage, "consumer": index,
                        "proof": backend_proof(daemon, volume, storage, value)})
                assert status.get("StatusCode") == 0 and not stderr, value
                validate_result(value)
            errors = cleanup(client, names, token)
            assert not errors, errors
            names.clear()  # Release block data before allocating shared.
            record({"phase": "passed", "storage": storage})
    except BaseException as error:
        failure = error
        raise
    finally:
        errors = cleanup(client, names, token)
        client.close()
        record({"phase": "cleanup", "errors": errors})
        if errors:
            if failure is not None:
                # Preserve the primary failure on Python versions without add_note too.
                failure.__notes__ = [*getattr(failure, "__notes__", []),
                                     "direct-exec cleanup: " + "; ".join(errors)]
            else:
                raise AssertionError(errors)


@pytest.mark.compat("RTM-086")
def test_volume_direct_exec_shebang_and_elf(daemon):
    run(daemon)
