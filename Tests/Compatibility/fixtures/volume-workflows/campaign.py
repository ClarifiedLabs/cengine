"""Fixed serial campaign controller. Docker is imported only by run()."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import time
from types import ModuleType
import uuid

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parents[3]
OWNER = "dev.cengine.compat.volume-workflows"
MAX_ARTIFACTS = 8 * 1024 * 1024
MAX_RESULT = 256 * 1024
PHASES = ("init-source", "init-backup", "init-restored", "install", "backup", "restore", "verify")


def load(name):
    if name not in ("wheels", "guest"):
        raise ValueError("unknown fixture module")
    path = SOURCE / (name + ".py")
    module = ModuleType("volume_workflows_" + name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


wheels = load("wheels")


class Journal:
    def __init__(self, directory):
        self.directory = directory
        self.size = 0

    def record(self, value):
        data = (json.dumps(value, sort_keys=True) + "\n").encode()
        # Reserve separate space for the original failure and cleanup evidence,
        # so an overflowing result cannot mask its cause or consume cleanup room.
        limit = {"cleanup": MAX_ARTIFACTS, "failure": MAX_ARTIFACTS - 32768}.get(
            value.get("phase"), MAX_ARTIFACTS - 65536)
        if self.size + len(data) > limit:
            raise ValueError("workflow artifact bound exceeded")
        with (self.directory / "journal.jsonl").open("ab") as output:
            output.write(data)
            output.flush()
        self.size += len(data)


def names(token, storage):
    if not isinstance(token, str) or not re.fullmatch("[0-9a-f]{32}", token) or storage not in ("block", "shared"):
        raise ValueError("invalid owner token or storage mode")
    prefix = f"vol023-{token}-{storage}"
    volumes = {role: prefix + "-" + role for role in ("source", "backup", "restored")}
    containers = {phase: [f"{prefix}-{phase}-{index}" for index in range(2 if storage == "shared" else 1)]
                  for phase in PHASES}
    return volumes, containers


def owned(resource, kind, name, token):
    labels = resource.attrs.get("Config", {}).get("Labels") if kind == "container" else resource.attrs.get("Labels")
    if resource.name != name or not isinstance(labels, dict) or labels.get(OWNER) != token:
        raise RuntimeError(f"refusing {kind} without exact name and owner: {name}")
    return resource


@contextmanager
def api_deadline(client, deadline):
    # The shared Unix transport owns the pre-connect/header watchdog and bounds
    # raw body reads before SDK JSON decoding. Import defines fixtures only; it
    # does not request a pytest fixture, build an image, or contact an engine.
    from test_volume_corpus import api_deadline as shared_deadline
    with shared_deadline(client, deadline):
        send = client.api.send
        responses = []

        def owned_send(request, **kwargs):
            request.headers["Accept-Encoding"] = "identity"
            response = send(request, **kwargs)
            responses.append(response)
            # The shared guard bounds wire bytes. Do not allow HTTP decompression
            # to expand those bytes after the final guarded socket read.
            if response.headers.get("Content-Encoding", "identity").strip().lower() not in ("", "identity"):
                raise ValueError("encoded workflow API responses are forbidden")
            return response

        client.api.send = owned_send
        failure = None
        try:
            yield
            # Raw reads are deadline-bound; reject an SDK result that completed
            # JSON decoding/model construction after the last guarded read.
            if time.monotonic() >= deadline:
                raise TimeoutError("workflow API operation exceeded absolute deadline")
        except BaseException as error:
            failure = error
            raise
        finally:
            client.api.send = send
            # SDK start/remove discard successful response bodies. Since the
            # shared guard forces stream=True, close those unconsumed responses
            # explicitly too, before any later exact-name cleanup request.
            close_errors = []
            for response in reversed(responses):
                try:
                    response.close()
                except Exception as error:
                    close_errors.append(f"{type(error).__name__}: {str(error)[:256]}")
            if close_errors:
                message = "workflow response cleanup failed: " + "; ".join(close_errors)
                if failure is not None:
                    add_note = getattr(failure, "add_note", None)
                    if add_note is not None:
                        add_note(message)
                    else:
                        # Keep primary-error identity on stdlib Python < 3.11 too.
                        failure.__notes__ = [*getattr(failure, "__notes__", []), message]
                else:
                    raise RuntimeError(message)


def api_call(client, deadline, operation, *args, **kwargs):
    # Includes every HTTP request inside compound SDK helpers such as create().
    with api_deadline(client, deadline):
        return operation(*args, **kwargs)


def read_logs(client, container, deadline):
    outputs = [bytearray(), bytearray()]
    for channel, output in enumerate(outputs):
        # Keep the shared body guard active for the lifetime of the generator,
        # including logs()'s implicit container inspect and partial-read errors.
        with api_deadline(client, deadline):
            stream = container.logs(stdout=channel == 0, stderr=channel == 1, stream=True, follow=False)
            try:
                for chunk in stream:
                    output.extend(chunk)
                    if time.monotonic() >= deadline:
                        raise TimeoutError("workflow log deadline exceeded")
                    if sum(map(len, outputs)) > MAX_RESULT:
                        raise ValueError("workflow output bound exceeded")
            finally:
                stream.close()
    return outputs


def cleanup(client, container_names, volume_names, token, *, deadline=None):
    errors = []
    for kind, selected in (("container", reversed(container_names)), ("volume", volume_names)):
        collection = client.containers if kind == "container" else client.volumes
        for name in selected:
            try:
                pair_deadline = time.monotonic() + 5
                if deadline is not None:
                    pair_deadline = min(pair_deadline, deadline)
                # Even reconciliation after an ambiguous create gets a fresh,
                # absolute deadline; no earlier watchdog can race this cleanup.
                with api_deadline(client, pair_deadline):
                    resource = owned(collection.get(name), kind, name, token)
                    resource.remove(**({"force": True} if kind == "container" else {}))
            except Exception as error:
                if getattr(error, "status_code", None) != 404:
                    errors.append(f"{kind} {name}: {type(error).__name__}: {str(error)[:512]}")
    return errors


def validate_inventory(value):
    if (not isinstance(value, dict) or set(value) != {"entries", "bytes"}
            or type(value["bytes"]) is not int or not 0 <= value["bytes"] <= 4 * 1024 * 1024
            or not isinstance(value["entries"], dict) or not 1 <= len(value["entries"]) <= 256
            or "." not in value["entries"]):
        raise ValueError("invalid inventory schema/bounds")
    total = 0
    for name, entry in value["entries"].items():
        if (not isinstance(name, str) or not name or name.startswith("/") or ".." in name.split("/")
                or not isinstance(entry, dict)):
            raise ValueError("invalid inventory entry")
        required = {"mode", "uid", "gid", "mtime_ns", "nlink", "type"}
        additions = {"file": {"size", "sha256", "links"}, "symlink": {"target"}, "directory": set()}
        kind = entry.get("type")
        if (not isinstance(kind, str) or kind not in additions or set(entry) != required | additions[kind]
                or any(type(entry[key]) is not int for key in ("mode", "uid", "gid", "mtime_ns", "nlink"))
                or entry["uid"] != 10001 or entry["gid"] != 10001 or not 0 <= entry["mode"] <= 0o777
                or not 0 <= entry["mtime_ns"] < 2 ** 63 or not 1 <= entry["nlink"] <= 256):
            raise ValueError("invalid inventory metadata")
        if kind == "file":
            if (type(entry["size"]) is not int or not 0 <= entry["size"] <= 4 * 1024 * 1024
                    or not isinstance(entry["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", entry["sha256"])
                    or not isinstance(entry["links"], list) or name not in entry["links"]
                    or len(entry["links"]) != entry["nlink"]
                    or any(not isinstance(link, str) or link not in value["entries"] for link in entry["links"])):
                raise ValueError("invalid inventory file")
            total += entry["size"]
        elif kind == "symlink" and (not isinstance(entry["target"], str) or len(entry["target"]) > 4096):
            raise ValueError("invalid inventory symlink")
    if total != value["bytes"] or value["entries"]["."]["type"] != "directory":
        raise ValueError("invalid inventory total/root")
    return value


def validate_result(value, action):
    required = {"schema", "action", "uid", "gid", "commands", "mountinfo"}
    additions = {"install": {"installed-1.0", "installed-2.0"},
                 "backup": {"inventory", "archive"}, "restore": {"inventory", "archive"},
                 "verify": {"inventory"}}.get(action, set())
    if (not isinstance(value, dict) or set(value) != required | additions or type(value.get("schema")) is not int
            or value["schema"] != 1 or value["action"] != action
            or type(value["uid"]) is not int or type(value["gid"]) is not int
            or (value["uid"], value["gid"]) != ((0, 0) if action == "initialize" else (10001, 10001))
            or not isinstance(value["commands"], list) or not 2 <= len(value["commands"]) <= 7
            or not isinstance(value["mountinfo"], list) or not 1 <= len(value["mountinfo"]) <= 3):
        raise ValueError("invalid workflow result schema")
    guest = load("guest")
    expected = ["python-version", "pip-version"] + {
        "install": ["venv", "install-1.0", "entrypoint", "install-2.0", "entrypoint"],
        "restore": ["entrypoint"], "verify": ["entrypoint"],
    }.get(action, [])
    if len(value["commands"]) != len(expected):
        raise ValueError("invalid command evidence count")
    for command, key in zip(value["commands"], expected):
        if (not isinstance(command, dict) or set(command) != {"argv", "exit", "output"}
                or command["argv"] != guest.commands()[key] or type(command["exit"]) is not int
                or command["exit"] != 0 or not isinstance(command["output"], str)
                or len(command["output"].encode()) > 65536):
            raise ValueError("invalid command evidence")
    for line in value["mountinfo"]:
        if not isinstance(line, str) or len(line) > 8192 or " - " not in line or len(line.split()) < 10:
            raise ValueError("invalid guest mount identity")
    for key in additions - {"archive"}:
        validate_inventory(value[key])
    if "archive" in additions:
        archive = value["archive"]
        if (not isinstance(archive, dict) or set(archive) != {"bytes", "sha256"}
                or type(archive["bytes"]) is not int or not 0 < archive["bytes"] <= 16 * 1024 * 1024
                or not isinstance(archive["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", archive["sha256"])):
            raise ValueError("invalid archive evidence")
    return value


def backend_evidence(value, mounted, modes, storage, *, root):
    from storage_backend_proof import verify_backend

    records = {}
    proofs = {}
    for line in value["mountinfo"]:
        before, after = line.split(" - ", 1)
        fields, filesystem = before.split(), after.split()
        if fields[4] in records:
            raise ValueError("duplicate guest mount identity")
        records[fields[4]] = (fields, filesystem)
    if "/" not in records or "ro" not in records["/"][0][5].split(","):
        raise AssertionError("guest root filesystem is not read-only")
    for target, volume, readonly in mounted:
        if target not in records or modes.get(volume) != storage:
            raise AssertionError("missing guest/JSON backend proof")
        fields, filesystem = records[target]
        if ("ro" if readonly else "rw") not in fields[5].split(","):
            raise AssertionError(f"wrong guest mount access: {records}")
        # Central proof binds the exact filesystem/source to the independently
        # captured daemon root and its immutable durable startup selection.
        proofs[target] = verify_backend(root, storage, "\n".join(value["mountinfo"]), destination=target)
    return {"expected": storage, "modes": {name: modes[name] for _, name, _ in mounted},
            "guest_mountinfo": value["mountinfo"], "mount_proofs": proofs}


def run(daemon):
    import docker
    from docker.types import Mount, Ulimit

    # This campaign uses the seeded image directly, not the Compose Dockerfile.
    # Its exact digest/platform are checked against daemon image inspection below.
    token = uuid.uuid4().hex
    directory = ROOT / ".build/volume-hunt" / ("workflows-" + token)
    directory.mkdir(parents=True)
    print(f"offline volume workflow artifacts: {directory}")
    journal = Journal(directory)
    payload = {name: base64.b64encode(data).decode() for name, data in (wheels.wheel(v) for v in wheels.VERSIONS)}
    source = (SOURCE / "guest.py").read_text()
    if len(source.encode()) > 65536:
        raise ValueError("guest fixture source bound exceeded")
    manifests = {storage: names(token, storage) for storage in ("block", "shared")}
    # Preregister ALL names, even creates whose response may be lost.
    journal.record({"phase": "plan", "schema": 1, "owner_label": OWNER, "token": token,
                    "image": wheels.IMAGE, "resources": manifests, "phases": PHASES,
                    "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in [*sorted(SOURCE.glob("*.py")),
                                                   ROOT / "Tests/Compatibility/test_volume_workflows.py",
                                                   ROOT / "Tests/Compatibility/test_volume_corpus.py",
                                                   ROOT / "Tests/Compatibility/storage_backend_proof.py"]},
                    "wheels_sha256": {name: hashlib.sha256(base64.b64decode(data)).hexdigest()
                                      for name, data in payload.items()}})
    # Save reproducible wheel inputs, but never execute them on the host.
    for name, data in payload.items():
        content = base64.b64decode(data)
        (directory / name).write_bytes(content)
        journal.size += len(content)
    deadline = time.monotonic() + 1800
    # Own SDK client: do not mutate the suite's shared client's API timeout.
    client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.45", timeout=30)
    all_containers = [name for _, consumers in manifests.values() for group in consumers.values() for name in group]
    all_volumes = [name for volumes, _ in manifests.values() for name in volumes.values()]
    try:
        image = api_call(client, min(deadline, time.monotonic() + 30),
                         client.images.get, wheels.IMAGE).attrs  # Never pull/load/build here.
        if (image.get("Os") != "linux" or image.get("Architecture") != "arm64"
                or wheels.IMAGE not in image.get("RepoDigests", [])):
            raise AssertionError(f"wrong pinned image identity: {image}")
        journal.record({"phase": "image", "inspect": image,
                        "engine": api_call(client, min(deadline, time.monotonic() + 30), client.version)})
        for storage, (volumes, consumers) in manifests.items():
            for name in volumes.values():
                owned(api_call(client, min(deadline, time.monotonic() + 30),
                               client.volumes.create, name, labels={OWNER: token}), "volume", name, token)
            observations = {}
            for phase in PHASES:
                action = "initialize" if phase.startswith("init-") else phase
                role = phase.removeprefix("init-") if action == "initialize" else (
                    "restored" if action in ("restore", "verify") else "source")
                mounted = [("/work", volumes[role], action == "backup")]
                if action in ("backup", "restore"):
                    mounted.append(("/backup", volumes["backup"], action == "restore"))
                phase_deadline = min(deadline, time.monotonic() + 120)

                def budget():
                    remaining = phase_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("workflow host phase/campaign deadline exceeded")
                    client.api.timeout = min(30, remaining)
                    return remaining

                created = []
                for index, name in enumerate(consumers[phase]):
                    selected = action if index == 0 else "identity"
                    request = {"action": selected, "wheels": payload if selected == "install" else {}}
                    budget()
                    container = api_call(client, phase_deadline, client.containers.create,
                        wheels.IMAGE, name=name, entrypoint=["/usr/local/bin/python", "-I", "-B", "-c"],
                        command=[source, json.dumps(request, sort_keys=True)],
                        user="0:0" if selected == "initialize" else "10001:10001",
                        network_mode="none", read_only=True, working_dir="/tmp",
                        tmpfs={"/tmp": "rw,nosuid,nodev,size=2m,mode=1777"},
                        environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                                     "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                                     "HOME": "/tmp", "TMPDIR": "/tmp", "LC_ALL": "C.UTF-8"},
                        mounts=[Mount(target, name, type="volume", read_only=ro, no_copy=True)
                                for target, name, ro in mounted], labels={OWNER: token},
                        cap_drop=["ALL"], cap_add=["CHOWN", "FOWNER"] if selected == "initialize" else [],
                        security_opt=["no-new-privileges:true"], pids_limit=16, mem_limit="256m",
                        ulimits=[Ulimit(name="nofile", soft=64, hard=64), Ulimit(name="core", soft=0, hard=0)],
                    )
                    created.append(owned(container, "container", name, token))
                # Both shared consumers exist before either start. Execute serially.
                for index, container in enumerate(created):
                    selected = action if index == 0 else "identity"
                    budget()
                    api_call(client, phase_deadline, container.start)
                    client.api.timeout = budget()
                    status = api_call(client, phase_deadline, container.wait, timeout=budget())
                    budget()
                    raw, stderr = read_logs(client, container, phase_deadline)
                    journal.record({"phase": "result", "storage": storage, "step": phase,
                                    "consumer": index, "status": status, "output": raw.decode(errors="replace"),
                                    "stderr": stderr.decode(errors="replace")})
                    value = json.loads(raw)
                    modes_path = daemon.root / "volume-storage.json"
                    with modes_path.open("rb") as modes_file:
                        modes_bytes = modes_file.read(1024 * 1024 + 1)
                    if len(modes_bytes) > 1024 * 1024:
                        raise ValueError("backend store evidence bound exceeded")
                    modes = json.loads(modes_bytes)
                    # Preserve guest versions/commands and raw backend identity on
                    # failing actions too, before rejecting their nonzero status.
                    journal.record({"phase": "backend", "storage": storage, "step": phase,
                                    "consumer": index, "expected": storage,
                                    "modes": {name: modes.get(name) for _, name, _ in mounted},
                                    "guest_mountinfo": value.get("mountinfo") if isinstance(value, dict) else None})
                    if status.get("StatusCode") != 0:
                        raise AssertionError(f"guest workflow failed: {value}")
                    value = validate_result(value, selected)
                    proof = backend_evidence(value, mounted, modes, storage, root=daemon.root)
                    journal.record({"phase": "backend-verified", "storage": storage, "step": phase,
                                    "consumer": index, "proof": proof})
                    if index == 0:
                        observations[action] = value
                budget()
                errors = cleanup(client, consumers[phase], [], token, deadline=phase_deadline)
                if errors:
                    raise RuntimeError("phase cleanup failed: " + "; ".join(errors))
            original = observations["install"]["installed-2.0"]
            if any(observations[action]["inventory"] != original for action in ("backup", "restore", "verify")):
                raise AssertionError("backup/restore bytes, metadata or topology differ")
            if observations["backup"]["archive"] != observations["restore"]["archive"]:
                raise AssertionError("backup archive identity changed before restore")
            journal.record({"phase": "passed", "storage": storage})
            # Do not retain the first mode's data while allocating the second:
            # two trees + one archive + both tmpfs mounts stay below 32 MiB.
            client.api.timeout = 5
            errors = cleanup(client, [], list(volumes.values()), token, deadline=deadline)
            if errors:
                raise RuntimeError("mode cleanup failed: " + "; ".join(errors))
    except BaseException as error:
        journal.record({"phase": "failure", "error": f"{type(error).__name__}: {str(error)[:4096]}"})
        raise
    finally:
        client.api.timeout = 5
        errors = cleanup(client, all_containers, all_volumes, token)
        client.close()
        journal.record({"phase": "cleanup", "errors": errors})
        if errors:
            raise RuntimeError("owned workflow cleanup failed: " + "; ".join(errors))
    return directory
