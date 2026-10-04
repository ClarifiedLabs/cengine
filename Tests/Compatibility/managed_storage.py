"""RTM-078 engine-free proof/fixture helpers. No engine access at import time."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import uuid

OWNER = "dev.cengine.compat.managed-smoke"
SEED = b"image-copyup\n"
WRITTEN = b"retained-write\n"
MTIME = 1700000000
MAX_STATE = 1024 * 1024
MAX_PRIVATE_ERROR = 4096
SMOKE_STEPS = frozenset({
    "client-connect", "client-version", "compile-probe", "image-archive", "image-load", "image-inspect",
    "volume-create", "container-create", "container-start", "container-stop", "exec-create", "exec-start",
    "exec-read", "exec-inspect", "probe-proof", "running-receipts", "stopped-receipts", "final-proof",
    "cleanup-get", "cleanup-stop", "cleanup-remove",
})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def step_evidence(step, *, consumer=None, command=None):
    require(isinstance(step, str) and step in SMOKE_STEPS, "unknown smoke step")
    require(consumer is None or type(consumer) is int and consumer in (0, 1), "invalid smoke consumer")
    require(command is None or isinstance(command, str) and command in {"snapshot", "open", "unlink", "write", "close"}, "invalid smoke command")
    return {"step": step, "consumer": consumer, "command": command}


def error_evidence(error, *, api_error=False):
    """Closed public classification plus hash; raw rendered error stays private.

    The caller supplies isinstance(error, docker.errors.APIError), keeping this
    helper engine-free. HTTP classes describe the response, not an inferred
    runtime cause. Never publish arbitrary exception names, URLs or messages.
    """
    require(type(api_error) is bool, "invalid API error classification")
    if api_error:
        error_type = "APIError"
    else:
        error_type = next((name for kind, name in ((TimeoutError, "TimeoutError"), (ConnectionError, "ConnectionError"),
            (OSError, "OSError"), (ValueError, "ValueError"), (AssertionError, "AssertionError")) if isinstance(error, kind)), "UnexpectedError")
    response = getattr(error, "response", None) if api_error else None
    status = getattr(response, "status_code", None)
    if type(status) is not int or not 100 <= status <= 599:
        status = None
    codes = {400: "bad-request", 401: "unauthorized", 403: "forbidden", 404: "not-found", 409: "conflict",
             413: "payload-too-large", 429: "too-many-requests", 500: "internal-error", 501: "unsupported",
             502: "upstream-error", 503: "service-unavailable", 504: "upstream-timeout"}
    code = codes.get(status, "http-error" if status is not None else "no-http-status")
    raw = str(error).encode("utf-8", errors="replace")
    return {"error_type": error_type, "error_code": code, "http_status": status,
            "raw_error_sha256": digest(raw), "raw_error_bytes": len(raw)}, raw


def write_private_error(root, token, raw):
    """Preserve at most 4KiB of the first API error in the retained root only.

    Exclusive creation cannot overwrite prior evidence or follow a symlink.
    All I/O is in the campaign's supervised worker. The public return value is
    a fixed relative filename and bounds, never error contents or an absolute path.
    """
    names(token)
    require(type(raw) is bytes, "private error bytes required")
    filename = "rtm078-api-error-" + token + ".log"
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(parent)
        visible = os.stat(root, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022 and
                (info.st_dev, info.st_ino) == (visible.st_dev, visible.st_ino), "unsafe private error root")
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        try:
            os.fchmod(fd, 0o600)
            payload = raw[:MAX_PRIVATE_ERROR]
            offset = 0
            while offset < len(payload):
                try:
                    written = os.write(fd, payload[offset:])
                except InterruptedError:
                    continue
                require(0 < written <= len(payload) - offset, "private error write made no progress")
                offset += written
        finally:
            # Preserve even a partial diagnosis if a later write fails. The
            # parent sync is attempted even when syncing the file itself fails.
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
                os.fsync(parent)
    finally:
        os.close(parent)
    return {"private_error_file": filename, "private_error_bytes": len(payload),
            "private_error_truncated": len(raw) > len(payload)}


def names(token):
    require(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{32}", token), "invalid owner")
    base = "rtm078-" + token
    return {"volume": base, "containers": [base + "-a", base + "-b"],
            "image": "compat-managed-smoke:" + token, "owner": token}


def initialize_evidence(root, token, value):
    """Publish a complete plan, then sync its directory chain before engine I/O.

    The fresh token directory is exclusive. All mutation uses pinned directory
    descriptors; existing/symlink token paths are never adopted or overwritten.
    A failure leaves the exact partial evidence intact and admits no engine call.
    The caller runs inside the campaign's process-level deadline.
    """
    require(value.get("phase") == "plan" and value.get("plan") == names(token), "initial plan identity")
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    require(len(raw) <= 65536, "initial evidence bound")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        def open_directory(path, parent=None):
            fd = os.open(path, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0,
                    "evidence directory must be owned and not writable by other users")
            return fd
        parent = open_directory(root)
        for name in (".build", "managed-storage-smoke"):
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = open_directory(name, parent)
            os.fsync(parent)  # Includes a newly created .build or campaign parent.
            parent = child
        os.mkdir(token, mode=0o700, dir_fd=parent)
        directory = open_directory(token, parent)
        temporary = ".evidence.jsonl.tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        # link is atomic and fails if the final name unexpectedly exists; unlike
        # rename/replace it can never overwrite evidence. Both names are private.
        os.link(temporary, "evidence.jsonl", src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        os.fsync(parent)  # Commits the newly created token directory entry.
    return Path(root) / ".build/managed-storage-smoke" / token, len(raw)


def owned(resource, kind, name, token):
    labels = resource.attrs.get("Labels") if kind == "volume" else resource.attrs.get("Config", {}).get("Labels")
    require(isinstance(labels, dict) and labels.get(OWNER) == token, "wrong resource owner")
    if kind != "image":
        require(resource.name == name, "wrong resource name")
    else:
        require(name in resource.attrs.get("RepoTags", []), "wrong image name")
    return resource


def image_archive(binary, plan):
    require(0 < len(binary) <= 8 * 1024 * 1024, "probe binary size")
    def tar(entries):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as archive:
            for name, data, mode, uid, gid in entries:
                info = tarfile.TarInfo(name)
                info.mode, info.uid, info.gid, info.mtime = mode, uid, gid, MTIME
                if data is None:
                    info.type = tarfile.DIRTYPE
                else:
                    info.size = len(data)
                archive.addfile(info, None if data is None else io.BytesIO(data))
        return out.getvalue()
    layer = tar([("probe", binary, 0o755, 0, 0), ("run", None, 0o755, 0, 0),
                 ("data", None, 0o750, 10001, 10002), ("data/seed", SEED, 0o640, 10001, 10002)])
    config = {"architecture": "arm64", "os": "linux", "config": {
        "Cmd": ["/probe", "serve"], "User": "0:0", "Labels": {OWNER: plan["owner"]}},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(layer)]}}
    raw = json.dumps(config, sort_keys=True).encode()
    name = digest(raw) + ".json"
    manifest = json.dumps([{"Config": name, "RepoTags": [plan["image"]], "Layers": ["layer.tar"]}]).encode()
    return tar([(name, raw, 0o644, 0, 0), ("layer.tar", layer, 0o644, 0, 0),
                ("manifest.json", manifest, 0o644, 0, 0)]), config


def mount_proof(text):
    require(isinstance(text, str) and len(text.encode()) <= 65536, "mountinfo bound")
    matches = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == "/data":
            require("-" in fields, "malformed mountinfo")
            separator = fields.index("-")
            require(len(fields) == separator + 4, "malformed mountinfo tail")
            require(fields[separator + 1] == "fuse.managed-v3" and fields[separator + 2] == "managed-v3", "not the managed FUSE subtype")
            matches.append({"raw": line, "device": fields[2], "root": fields[3],
                            "filesystem": fields[separator + 1], "source": fields[separator + 2]})
    require(len(matches) == 1, "expected one exact /data mount")
    return matches[0]


def snapshot_proof(value, *, unlinked=False, written=False, closed=False):
    proof = mount_proof(value["mountinfo"])
    require(value["entries"] == ([] if unlinked else ["seed"]), "unexpected names (never filtered)")
    root = value["root"]
    require((root["mode"], root["uid"], root["gid"]) == (stat.S_IFDIR | 0o750, 10001, 10002), "copyup root attributes")
    if not unlinked:
        require(root["mtime"] == MTIME, "copyup root mtime")
    if closed:
        require("file" not in value and "sha256" not in value, "closed descriptor remains")
        return proof
    file = value["file"]
    require((file["mode"], file["uid"], file["gid"], file["nlink"]) ==
            (stat.S_IFREG | 0o640, 10001, 10002, 0 if unlinked else 1), "copyup/fstat attributes")
    expected = WRITTEN if written else SEED
    require(file["size"] == len(expected) and value["sha256"] == digest(expected), "descriptor bytes")
    if not written:
        require(file["mtime"] == MTIME, "copyup file mtime")
    return proof


def public_state(root):
    # Read only the two public journal files, never keys, boot files, or argv/logs.
    def read(name):
        path = Path(root) / "managed-storage" / name
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_STATE, "journal file bound/type")
            raw = source.read(MAX_STATE + 1)
            require(len(raw) <= MAX_STATE, "journal byte bound")
        return json.loads(raw), digest(raw)
    manifest, manifest_hash = read("manifest.json")
    state, state_hash = read("state.json")
    require(manifest.get("schema") == 1 and manifest.get("mode") == "managed", "managed manifest required")
    require(state.get("schema") == 2 and state.get("store") == manifest.get("store"), "journal store mismatch")
    return manifest, state, {"manifest_sha256": manifest_hash, "state_sha256": state_hash}


def receipt_proof(manifest, state, volume_name, containers, *, stopped=False):
    def authority(value):
        require(isinstance(value, str), "authority type")
        parsed = uuid.UUID(value)
        require(parsed.version == 4 and str(parsed) == value, "authority UUIDv4 required")
        return value
    def fingerprint(value):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "fingerprint required")
        return value
    store = authority(manifest["store"])
    require(state["store"] == store and not state["reconciliationRequired"], "unreconciled store")
    volumes = [v for v in state["volumes"].values() if v["name"] == volume_name]
    require(len(volumes) == 1, "exact volume journal required")
    volume = authority(volumes[0]["id"])
    require(type(state["revision"]) is int and 0 < state["revision"] < 2 ** 64, "journal revision")
    result = {"store": store, "volume": volume, "revision": state["revision"], "intents": []}
    attachments = set()
    for container in containers:
        require(re.fullmatch(r"[0-9a-f]{64}", container), "Docker container ID required")
        candidates = [v for v in state["intents"].values() if v["container"] == container]
        require(len(candidates) == 1, "exact launch intent required")
        intent = candidates[0]
        require(intent["store"] == store and intent["phase"] == ("retired" if stopped else "running"), "launch phase")
        require(intent["prepareCompleted"] is True and intent["cleanUnmount"] is True, "prepare close/completion required")
        public = {key: authority(intent[key]) for key in ("id", "containerInstance", "launch", "serviceEpoch", "prepare")}
        public.update({"container": container, "controllerEpoch": intent["controllerEpoch"],
                       "specificationDigest": fingerprint(intent["specificationDigest"]), "phase": intent["phase"]})
        require(type(public["controllerEpoch"]) is int and 0 < public["controllerEpoch"] < 2 ** 64, "controller epoch")
        completion = intent["guestCompletion"]
        require(all(completion[k] == intent[k] for k in ("prepare", "containerInstance", "launch")) and
                completion["succeeded"] is True and completion["cleanCopyUp"] is True, "guest completion mismatch")
        public["evidenceDigest"] = fingerprint(completion["evidenceDigest"])
        require(len(intent["mounts"]) == 1 and intent["mounts"][0] ==
                {"volume": volume, "destination": "/data", "subpath": "", "mode": "read-write"}, "mount plan")
        require(len(intent["slots"]) == 2 and {s["role"] for s in intent["slots"]} == {"prepare", "runtime"}, "slot hierarchy")
        public["slots"] = []
        for slot in intent["slots"]:
            attachment = authority(slot["attachment"])
            require(attachment not in attachments and slot["volume"] == volume and slot["mode"] == "read-write", "attachment scope")
            attachments.add(attachment)
            fingerprint(slot["key"])  # Public SPKI hash, deliberately omitted from artifacts.
            receipt = slot.get("receipt")
            if slot["role"] == "prepare" or stopped:
                # Generation-fenced receipts also name the exact shim launch they retired.
                require(isinstance(receipt, dict) and set(receipt) <= {"store", "volume", "attachment", "prepare", "launch", "revision"} and receipt["store"] == store and receipt["volume"] == volume and
                        receipt["attachment"] == attachment and receipt.get("prepare") ==
                        (intent["prepare"] if slot["role"] == "prepare" else None) and
                        receipt.get("launch") == public["launch"] and
                        type(receipt["revision"]) is int and 0 < receipt["revision"] < 2 ** 64, "exact drain receipt required")
            else:
                require(receipt is None, "runtime already drained")
            public["slots"].append({"attachment": attachment, "role": slot["role"], "receipt": receipt})
        result["intents"].append(public)
    return result
