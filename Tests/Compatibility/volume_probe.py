"""Serial, endpoint-neutral volume discovery. No Docker import is needed to replay/reduce.

CENGINE_VOLUME_PROBE_PLAN selects a saved plan.json (and its adjacent fixture.tar).
Otherwise SEEDS is a comma-separated integer list; STEPS bounds each seeded trace.
Artifacts intentionally outlive the daemon under .build/volume-hunt.
Replay bundles are trusted executable inputs, like locally built images; the hash
checks corruption, not authenticity. Do not replay bundles from untrusted sources.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import random
import re
import stat
import struct
import subprocess
import sys
import time
import tarfile
import uuid

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_ROOT = REPO_ROOT / ".build" / "volume-hunt"
OPS = {"create", "open", "write_fd", "close", "rename", "link", "unlink",
       "truncate", "chmod", "snapshot", "restart"}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def same_unix_endpoint(host, socket):
    for prefix in ("unix://", "http+unix://"):
        if host.startswith(prefix):
            return Path(host[len(prefix):]).resolve() == Path(socket).resolve()
    return False


def read_bounded(path, maximum):
    # Opening nonblocking before fstat also avoids blocking on a replay FIFO.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("replay input must be a bounded regular file")
        data = source.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("replay input exceeds size bound")
        return data


def validate(plan):
    if not isinstance(plan, dict) or set(plan) - {"version", "seed", "steps"}:
        raise ValueError("unknown plan fields")
    if type(plan.get("seed")) is not int:
        raise ValueError("plan seed must be an integer")
    if plan.get("version") != 1 or not isinstance(plan.get("steps"), list):
        raise ValueError("unsupported volume plan")
    if not 1 <= len(plan["steps"]) <= 256:
        raise ValueError("plans must contain 1..256 steps")
    seen = set()
    for step in plan["steps"]:
        if (not isinstance(step, dict) or not {"id", "op", "needs"} <= set(step)
                or not isinstance(step["id"], str) or not isinstance(step["op"], str)
                or not isinstance(step["needs"], list)
                or any(not isinstance(item, str) for item in step["needs"])):
            raise ValueError("steps require string id/op and a list of dependency IDs")
        if not re.fullmatch(r"s[0-9]+", step["id"]) or step["id"] in seen:
            raise ValueError("step IDs must be unique logical IDs")
        if step["op"] not in OPS or not set(step["needs"]) <= seen:
            raise ValueError("unknown operation or non-preceding dependency")
        for key in ("path", "to", "fd"):
            if key in step and (not isinstance(step[key], str)
                                or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", step[key])):
                raise ValueError("only flat disposable relative names are allowed")
        required = {"create": ("path", "data"), "open": ("path", "fd"),
                    "write_fd": ("fd", "data"), "close": ("fd",),
                    "rename": ("path", "to"), "link": ("path", "to"),
                    "unlink": ("path",), "truncate": ("path", "size"),
                    "chmod": ("path", "mode",)}.get(step["op"], ())
        if any(key not in step for key in required):
            raise ValueError("missing operation argument")
        if set(step) - {"id", "needs", "op", *required}:
            raise ValueError("unknown operation fields")
        if len(encode(step)) > 32768:
            raise ValueError("encoded operation exceeds protocol bound")
        if "data" in step and (not isinstance(step["data"], str) or len(step["data"].encode()) > 4096):
            raise ValueError("payload too large")
        if "size" in step and (type(step["size"]) is not int or not 0 <= step["size"] <= 4096):
            raise ValueError("invalid truncate size")
        if "mode" in step and (type(step["mode"]) is not int or not 0 <= step["mode"] <= 0o777):
            raise ValueError("invalid chmod mode")
        seen.add(step["id"])
    return plan


def generate(seed=0, steps=24):
    if not 1 <= steps <= 256:
        raise ValueError("CENGINE_VOLUME_PROBE_STEPS must be 1..256")
    rng = random.Random(seed)
    result = []
    # Each file's descriptor/namespace trace is a dependency chain; independent
    # files can be removed by the reducer without invalidating surviving traces.
    while len(result) < steps:
        name = f"file{len(result)}"
        payload = f"seed-{rng.getrandbits(32):08x}"
        chain = [
            {"op": "create", "path": name, "data": payload},
            {"op": "open", "path": name, "fd": name},
            {"op": "rename", "path": name, "to": name + "-renamed"},
            {"op": "link", "path": name + "-renamed", "to": name + "-link"},
            {"op": "truncate", "path": name + "-link", "size": rng.randrange(0, 20)},
            {"op": "chmod", "path": name + "-renamed", "mode": rng.choice([0o400, 0o600, 0o640])},
            {"op": "unlink", "path": name + "-renamed"},
            {"op": "unlink", "path": name + "-link"},
            {"op": "write_fd", "fd": name, "data": payload + "-open-unlinked"},
            {"op": "close", "fd": name},
            {"op": "create", "path": name + "-durable", "data": payload},
        ]
        needs = []
        for operation in chain:
            if len(result) == steps:
                break
            step = {"id": f"s{len(result):03d}", "needs": needs, **operation}
            result.append(step)
            needs = [step["id"]]
        if len(result) < steps:
            step = {"id": f"s{len(result):03d}", "op": "restart",
                    "needs": needs}
            result.append(step)
    return validate({"version": 1, "seed": seed, "steps": result})


def plans_from_environment(environment=None):
    env = os.environ if environment is None else environment
    if env.get("CENGINE_VOLUME_PROBE_PLAN"):
        return [validate(json.loads(read_bounded(env["CENGINE_VOLUME_PROBE_PLAN"], 8 * 1024 * 1024)))]
    seeds = env.get("CENGINE_VOLUME_PROBE_SEEDS", "0,1").split(",")
    if not 1 <= len(seeds) <= 32:
        raise ValueError("select 1..32 seeds")
    return [generate(int(seed), int(env.get("CENGINE_VOLUME_PROBE_STEPS", "24"))) for seed in seeds]


def without_dependents(plan, removed):
    removed = set(removed)
    kept = []
    for step in plan["steps"]:
        if step["id"] in removed or removed.intersection(step["needs"]):
            removed.add(step["id"])
        else:
            kept.append(copy.deepcopy(step))
    return {**copy.deepcopy(plan), "steps": kept}


def reduce_plan(plan, still_fails):
    """Greedy dependency-closed reduction; predicate must replay on fresh resources.

    A mismatch predicate should preserve the original failure signature, not treat
    transport/setup failures as filesystem differences. Never runs engines itself.
    """
    current = copy.deepcopy(validate(plan))
    if not still_fails(current):
        raise ValueError("initial plan does not reproduce")
    for step in plan["steps"]:
        if not any(item["id"] == step["id"] for item in current["steps"]):
            continue
        candidate = without_dependents(current, {step["id"]})
        if candidate["steps"] and still_fails(validate(candidate)):
            current = candidate
    return current


def mismatch_signature(expected, actual):
    """First differing step's paths/values, excluding equal unrelated snapshot data.

    Raw differing values (including nlink and namespace entries) stay intact;
    equal data is omitted so removing an unrelated file can still reproduce.
    """
    if len(expected) != len(actual) or any(a["id"] != b["id"] for a, b in zip(expected, actual)):
        raise ValueError("endpoint observations must have matching step IDs")

    def differences(reference, candidate, path):
        if reference == candidate:
            return []
        if isinstance(reference, dict) and isinstance(candidate, dict):
            result = []
            for key in sorted(reference.keys() | candidate.keys()):
                if key not in reference or key not in candidate:
                    result.append({"path": path + [key],
                                   "expected": {"present": key in reference, "value": reference.get(key)},
                                   "actual": {"present": key in candidate, "value": candidate.get(key)}})
                else:
                    result.extend(differences(reference[key], candidate[key], path + [key]))
            return result
        return [{"path": path, "expected": {"present": True, "value": reference},
                 "actual": {"present": True, "value": candidate}}]

    for reference, candidate in zip(expected, actual):
        changed = differences(reference, candidate, [])
        if changed:
            return {"id": reference["id"], "differences": changed}
    return None


def reduce_endpoints(plan, fixture, reference, candidate, storage, *,
                     root=ARTIFACT_ROOT, daemon_root=None, backend_proof=None,
                     signature=None, max_attempts=32):
    """Replay dependency-closed candidates serially on fresh endpoint resources.

    Pass an optional mismatch_signature(expected, actual) from the original run
    to require that exact failure. Otherwise the first replay establishes it.
    Every attempt saves its inputs/journals; reduction.json records acceptance.
    Transport/setup/cleanup failures abort (never count as mismatches). Returns
    (reduced_plan, replay_directory) for the last accepted, fully executed plan.
    Uses the supplied immutable (archive_bytes, image) fixture without rebuilding.
    Stops executing after max_attempts (including initial replay), returning the
    best accepted plan; each attempt retains a fixture copy for standalone replay.
    """
    if type(max_attempts) is not int or not 1 <= max_attempts <= 257:
        raise ValueError("max_attempts must be 1..257")
    target = copy.deepcopy(signature)
    accepted = None
    attempts = 0

    def still_fails(replay):
        nonlocal target, accepted, attempts
        if attempts >= max_attempts:
            return False
        attempts += 1
        directory, image = prepare_artifacts(
            replay, root=root, daemon_root=daemon_root, fixture=fixture,
        )
        expected = execute(reference, replay, image, storage, directory, "docker")
        actual = execute(candidate, replay, image, storage, directory, "cengine",
                         backend_proof=backend_proof)
        observed = mismatch_signature(expected, actual)
        if target is None:
            target = copy.deepcopy(observed)
        matches = observed is not None and observed == target
        (directory / "reduction.json").write_bytes(encode({
            "target": target, "observed": observed, "accepted": matches,
        }) + b"\n")
        if matches:
            accepted = directory
        return matches

    reduced = reduce_plan(plan, still_fails)
    return reduced, accepted


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data, mode in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if data is None:
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            archive.addfile(info, None if data is None else io.BytesIO(data))
    return output.getvalue()


def build_fixture(directory):
    """One local static binary, one Docker-save archive, identical on both endpoints."""
    binary = directory / "probe"
    subprocess.run(
        ["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary),
         str(Path(__file__).parent / "fixtures" / "volume-probe.go")],
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off"},
        check=True, capture_output=True, timeout=120,
    )
    layer = tar_bytes([("probe", binary.read_bytes(), 0o755), ("data", None, 0o755)])
    config = encode({"architecture": "arm64", "os": "linux",
                     "config": {"Cmd": ["/probe", "serve", "/data/probe-tree", "/probe.sock"]},
                     "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
    digest = hashlib.sha256(config).hexdigest()
    tag = f"compat-volume-probe:{digest}"
    archive = tar_bytes([
        (digest + ".json", config, 0o644), ("layer.tar", layer, 0o644),
        ("manifest.json", encode([{"Config": digest + ".json", "RepoTags": [tag], "Layers": ["layer.tar"]}]), 0o644),
    ])
    return archive, tag


def fixture_identity(archive, image):
    """Resolve the saved tag from source bytes, including older config-ID bundles.

    Docker's containerd store may expose a manifest digest as Id, not the config
    digest. Neither that engine ID nor a mutable tag is proof of fixture identity.
    """
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as saved:
        def source(name):
            member = saved.getmember(name)
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise ValueError("invalid fixture archive member")
            content = saved.extractfile(member)
            if content is None:
                raise ValueError("missing fixture archive content")
            return content.read()

        manifest = json.loads(source("manifest.json"))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError("fixture must contain exactly one image")
        entry = manifest[0]
        config_bytes = source(entry["Config"])
        digest = hashlib.sha256(config_bytes).hexdigest()
        config = json.loads(config_bytes)
        tags = entry["RepoTags"]
        if (len(tags) != 1 or tags[0] not in (
                f"compat-volume-probe:{digest}", f"compat-volume-probe:{digest[:24]}")):
            raise ValueError("fixture requires its content-derived tag")
        if image not in (tags[0], "sha256:" + digest):
            raise ValueError("fixture config identity mismatch")
        layers = ["sha256:" + hashlib.sha256(source(name)).hexdigest()
                  for name in entry["Layers"]]
        if config["rootfs"] != {"type": "layers", "diff_ids": layers}:
            raise ValueError("fixture layer identity mismatch")
    return tags[0], config, "sha256:" + digest


def prepare_artifacts(plan, *, daemon_root=None, root=ARTIFACT_ROOT, fixture=None):
    """Persist all replay inputs before any engine calls, including image load."""
    validate(plan)
    root = Path(root).resolve()
    if daemon_root is not None and root.is_relative_to(Path(daemon_root).resolve()):
        raise ValueError("volume artifacts must be outside daemon root")
    directory = root / uuid.uuid4().hex
    directory.mkdir(parents=True)
    # Save the plan even if local compilation subsequently fails.
    (directory / "plan.json").write_bytes(encode(plan) + b"\n")
    archive, image = build_fixture(directory) if fixture is None else fixture
    metadata = {"image": image, "archive_sha256": hashlib.sha256(archive).hexdigest()}
    (directory / "fixture.tar").write_bytes(archive)
    (directory / "fixture.json").write_bytes(encode(metadata) + b"\n")
    return directory, image


def replay_fixture(plan_path):
    directory = Path(plan_path).resolve().parent
    metadata = json.loads(read_bounded(directory / "fixture.json", 4096))
    archive = read_bounded(directory / "fixture.tar", 64 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != metadata["archive_sha256"]:
        raise ValueError("saved fixture archive hash mismatch")
    return archive, metadata["image"]


def close_exec_stream(stream):
    """Close Docker's retained HTTP response before its wrapper and raw socket."""
    raw_socket = getattr(stream, "_sock", stream)
    response = getattr(stream, "_response", None)
    try:
        if response is not None:
            response.close()
    finally:
        try:
            stream.close()
        finally:
            # Closing SocketIO alone can leave the upgraded socket alive. Capture
            # it before Response.close() clears the wrapper's socket reference.
            if raw_socket is not None and raw_socket is not stream:
                raw_socket.close()


def probe(container, step, *, timeout=50):
    """Bound the hijacked exec stream; SDK exec_run clears its read timeout.

    Create/start/inspect retain the client's ordinary HTTP timeout. The stream
    has an absolute deadline, not an inactivity timeout reset by each chunk.
    """
    if not 0 < timeout <= 300:
        raise ValueError("probe timeout must be in (0, 300] seconds")
    api = container.client.api
    exec_id = api.exec_create(
        container.id, ["/probe", "request", encode(step).decode()],
        stdout=True, stderr=True, tty=False,
    )["Id"]
    stream = api.exec_start(exec_id, socket=True)
    raw_socket = getattr(stream, "_sock", stream)
    deadline = time.monotonic() + timeout
    data = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("probe exec stream deadline exceeded")
            raw_socket.settimeout(remaining)
            chunk = raw_socket.recv(65536)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("probe exec output exceeds size bound")
    finally:
        close_exec_stream(stream)
    # Preserve stderr separately: diagnostics must not corrupt a valid JSON reply.
    output, errors = bytearray(), bytearray()
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise RuntimeError("truncated probe exec frame header")
        channel, length = struct.unpack(">BxxxI", data[offset:offset + 8])
        offset += 8
        if channel not in (1, 2) or length > len(data) - offset:
            raise RuntimeError("invalid probe exec frame")
        (output if channel == 1 else errors).extend(data[offset:offset + length])
        offset += length
    exit_code = api.exec_inspect(exec_id)["ExitCode"]
    if exit_code != 0:
        raise RuntimeError(f"probe transport exit {exit_code}: stderr={bytes(errors)!r}, stdout={bytes(output)!r}")
    outcome = json.loads(output)
    if isinstance(outcome, dict) and "protocol_error" in outcome:
        raise RuntimeError(f"probe protocol error: {outcome['protocol_error']}")
    if (not isinstance(outcome, dict) or set(outcome) != {"errno", "entries"}
            or type(outcome["errno"]) is not int or not isinstance(outcome["entries"], dict)):
        raise RuntimeError("probe protocol error: invalid outcome shape")
    return outcome


# Kept separate from every historical tested image/archive. This helper has no
# workload operations and never opens the tested volume; only fixed procfs input.
MOUNT_PROBE_SOURCE = b'''package main
import ("encoding/json"; "fmt"; "io"; "os"; "time")
func main() {
    time.AfterFunc(5*time.Second, func(){ os.Exit(124) })
    f, err := os.Open("/proc/self/mountinfo")
    if err != nil { panic(err) }; defer f.Close()
    data, err := io.ReadAll(io.LimitReader(f, 65537))
    if err != nil { panic(err) }
    if len(data)>65536 { panic("mountinfo exceeds bound") }
    if err=json.NewEncoder(os.Stdout).Encode(string(data)); err!=nil { fmt.Fprintln(os.Stderr,err); os.Exit(1) }
}
'''


MOUNT_PROBE_SOURCE_SHA256 = "26978339fb655019c31cfc23815a38b1c1e42013ce140156804dc278c0a4d336"


def _mount_probe_archive(directory):
    if hashlib.sha256(MOUNT_PROBE_SOURCE).hexdigest() != MOUNT_PROBE_SOURCE_SHA256:
        raise ValueError("readonly backend probe source pin mismatch")
    source = directory / "backend-probe.go"
    binary = directory / "backend-probe"
    if not source.exists():
        source.write_bytes(MOUNT_PROBE_SOURCE)
    if source.read_bytes() != MOUNT_PROBE_SOURCE:
        raise ValueError("backend probe source changed")
    # Separate artifact, never rewrite fixture.tar or its image configuration.
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), str(source)],
                   env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64", "GOWORK": "off", "GOPROXY": "off"},
                   check=True, capture_output=True, timeout=120)
    data = read_bounded(binary, 16 * 1024 * 1024)
    digest = hashlib.sha256(data).hexdigest()
    name = "cengine-backend-proof-" + digest
    archive = tar_bytes([(name, data, 0o555)])
    (directory / "backend-probe.tar").write_bytes(archive)
    return name, archive, {"source_sha256": hashlib.sha256(MOUNT_PROBE_SOURCE).hexdigest(),
                           "binary_sha256": digest, "archive_sha256": hashlib.sha256(archive).hexdigest()}


def _backend_root(client):
    # The compatibility fixture fixes run/docker.sock and sibling root. Bind that
    # inference to its owner marker and the invoking runner's exact binary.
    adapter = client.api.adapters.get("http+docker://")
    socket_path = Path(adapter.socket_path)
    if socket_path.name != "docker.sock" or socket_path.parent.name != "run":
        raise ValueError("not the owned compatibility daemon socket")
    work = socket_path.parent.parent
    owner = read_bounded(work / ".cengine-compat-owner", 4096).decode().strip()
    if not os.environ.get("CENGINE_BINARY") or owner != str(Path(os.environ["CENGINE_BINARY"]).resolve()):
        raise ValueError("compatibility backend root owner mismatch")
    return work / "root"


def _mount_probe(container, command):
    # Reuse the tested fresh-socket transport watchdog, including header admission;
    # unlike an inactivity timeout this can interrupt an exec_start header drip.
    from test_volume_corpus import api_deadline
    api = container.client.api
    old = api.timeout
    stream = None
    deadline = time.monotonic() + 15
    try:
        api.timeout = 5
        with api_deadline(container.client, deadline):
            identity = api.exec_create(container.id, ["/" + command], stdout=True, stderr=True)["Id"]
            stream = api.exec_start(identity, socket=True)
            raw = getattr(stream, "_sock", stream)
            wire = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("mount proof stream deadline")
                raw.settimeout(remaining)
                chunk = raw.recv(65536)
                if not chunk:
                    break
                wire.extend(chunk)
                if len(wire) > 256 * 1024:
                    raise ValueError("mount proof wire exceeds bound")
            close_exec_stream(stream)
            stream = None
            output, errors = bytearray(), bytearray()
            while wire:
                if len(wire) < 8:
                    raise ValueError("truncated mount proof frame")
                channel, length = struct.unpack(">BxxxI", wire[:8])
                if channel not in (1, 2) or length > len(wire) - 8:
                    raise ValueError("invalid mount proof frame")
                (output if channel == 1 else errors).extend(wire[8:8 + length])
                del wire[:8 + length]
            if api.exec_inspect(identity)["ExitCode"] != 0:
                raise RuntimeError(f"mount proof failed: {bytes(errors)!r}")
            return json.loads(output)
    finally:
        if stream is not None:
            close_exec_stream(stream)
        api.timeout = old


def record_backend_mounts(client, containers, directory, storage, record, *, candidate):
    from storage_backend_proof import mount_identity, verify_backend
    name, archive, hashes = _mount_probe_archive(directory)
    root = _backend_root(client) if candidate else None
    record({"phase": "backend-probe-fixture", **hashes})
    for container in containers:
        if not container.put_archive("/", archive):
            raise RuntimeError("cannot install separate mount proof helper")
        text = _mount_probe(container, name)
        record({"phase": "mountinfo", "container": container.id, "raw": text})
        proof = verify_backend(root, storage, text) if candidate else {
            "reference": "Docker local-volume control", "mount": mount_identity(text)}
        record({"phase": "backend-proof", "container": container.id, "proof": proof})


def execute(client, plan, image, storage, directory, label, *, backend_proof=None):
    """Same requests for every endpoint; backend evidence is out-of-band, not normalized."""
    validate(plan)
    if storage not in ("block", "shared") or not re.fullmatch(r"[a-z-]+", label):
        raise ValueError("invalid storage/endpoint label")
    directory = Path(directory)
    if json.loads((directory / "plan.json").read_text()) != plan:
        raise ValueError("plan must be persisted before execution")
    metadata = json.loads(read_bounded(directory / "fixture.json", 4096))
    archive = read_bounded(directory / "fixture.tar", 64 * 1024 * 1024)
    if metadata["image"] != image or hashlib.sha256(archive).hexdigest() != metadata["archive_sha256"]:
        raise ValueError("fixture identity mismatch")
    containers, volume, observations = [], None, []
    intended_containers, intended_volume = [], None
    owner = uuid.uuid4().hex
    journal = directory / f"{label}-{storage}.jsonl"

    def record(value):
        with journal.open("a") as output:
            output.write(encode(value).decode() + "\n")
            output.flush()
            os.fsync(output.fileno())

    try:
        record({"phase": "load", "image": image})
        tag, source_config, config_digest = fixture_identity(archive, image)
        client.images.load(archive)
        inspected = client.images.get(tag).attrs
        if (inspected.get("Os") != source_config["os"]
                or inspected.get("Architecture") != source_config["architecture"]
                or inspected.get("RootFS") != {
                    "Type": "layers", "Layers": source_config["rootfs"]["diff_ids"]}
                or any(inspected.get("Config", {}).get(key) != value
                       for key, value in source_config["config"].items())):
            raise ValueError("loaded fixture does not match source config/RootFS")
        record({"phase": "image", "tag": tag, "config_sha256": config_digest,
                "inspect": inspected})
        name = f"volume-hunt-{owner}"
        intended_volume = name
        record({"phase": "before-volume-create", "logical": "volume0", "name": name})
        candidate = client.volumes.create(name, labels={"dev.cengine.compat.volume-hunt": owner})
        if candidate.attrs.get("Labels", {}).get("dev.cengine.compat.volume-hunt") != owner:
            raise RuntimeError("refusing to use volume without run ownership")
        volume = candidate
        record({"phase": "volume", "logical": "volume0", "id": volume.name})
        # Exactly one consumer for block; both shared creates precede either start.
        for index in range(1 if storage == "block" else 2):
            container_name = f"{name}-c{index}"
            intended_containers.append(container_name)
            record({"phase": "before-container-create", "logical": f"consumer{index}", "name": container_name})
            container = client.containers.create(
                tag, name=container_name, network_mode="none",
                volumes={volume.name: {"bind": "/data", "mode": "rw"}},
                labels={"dev.cengine.compat.volume-hunt": owner},
            )
            containers.append(container)
            record({"phase": "create", "logical": f"consumer{index}", "id": container.id})
        for container in containers:
            container.start()
        if backend_proof is not None:
            actual = backend_proof(volume.name)
            record({"phase": "backend", "expected": storage, "actual": actual})
            if actual != storage:
                raise AssertionError(f"expected {storage} volume backend, got {actual}")
        record_backend_mounts(client, containers, directory, storage, record, candidate=label == "cengine")
        for step in plan["steps"]:
            record({"phase": "before", "step": step})
            if step["op"] == "restart":
                # Graceful container restart only. No daemon crash or global prune.
                for container in containers:
                    container.restart(timeout=5)
                record_backend_mounts(client, containers, directory, storage, record, candidate=label == "cengine")
                outcome = probe(containers[0], {"op": "snapshot"})
            else:
                outcome = probe(containers[0], step)
            # Peer reads after each serialized operation catch cross-VM visibility.
            peer = probe(containers[1], {"op": "snapshot"}) if storage == "shared" else None
            observation = {"id": step["id"], "result": outcome, "peer": peer}
            observations.append(observation)
            record({"phase": "after", **observation})
        return observations
    except BaseException as error:
        record({"phase": "error", "type": type(error).__name__, "message": str(error)})
        raise
    finally:
        cleanup_errors = []
        # A create may commit server-side before its client times out. Inspect
        # only pre-registered exact names, and require this run's token even for
        # creates that returned successfully. Never list resources or prune.
        for name in reversed(intended_containers):
            try:
                container = client.containers.get(name)
                if (container.name != name or
                        (container.attrs.get("Config", {}).get("Labels") or {}).get(
                            "dev.cengine.compat.volume-hunt") != owner):
                    raise RuntimeError("refusing to remove container without exact name and run ownership")
                container.remove(force=True)
            except Exception as error:
                # Docker APIError exposes status_code; no SDK import is needed
                # by the engine-free replay/reducer helpers.
                if getattr(error, "status_code", None) != 404:
                    cleanup_errors.append(f"container cleanup {name}: {error}")
        if intended_volume is not None:
            try:
                volume = client.volumes.get(intended_volume)
                if (volume.name != intended_volume or
                        (volume.attrs.get("Labels") or {}).get("dev.cengine.compat.volume-hunt") != owner):
                    raise RuntimeError("refusing to remove volume without exact name and run ownership")
                volume.remove()  # Only this run's named volume; never force/prune.
            except Exception as error:
                if getattr(error, "status_code", None) != 404:
                    cleanup_errors.append(f"volume cleanup {intended_volume}: {error}")
        record({"phase": "cleanup", "errors": cleanup_errors})
        # The content-addressed fixture image is intentionally retained as a cache.
        if cleanup_errors and not sys.exc_info()[0]:
            raise RuntimeError(f"volume probe cleanup failed: {cleanup_errors}")
