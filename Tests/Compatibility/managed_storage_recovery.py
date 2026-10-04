"""RTM-079 public observation only: no decoded journal grants authority.

The signed helper/runtime validate ROOT signatures; this observer correlates their
public transcript. Death, drain and acknowledged bytes remain separate proofs.
"""
from __future__ import annotations
from contextlib import ExitStack, contextmanager
import base64
import copy
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import uuid

from managed_storage import digest, mount_proof, public_state, receipt_proof

OWNER = "dev.cengine.compat.managed-recovery"
SEED = b"image-copyup\n"
PAYLOAD = b"rtm079-acknowledged-linked-payload\n"
NEXT = b"rtm079-post-recovery-write\n"
MTIME = 1700000000
MAX_ARTIFACT = 4 * 1024 * 1024


class ProofFailure(ValueError):
    """Only fixed public guard names, never external error strings."""


def require(condition, message):
    if not condition:
        raise ProofFailure(message)

def names(token, rtm="RTM-079"):
    require(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{32}", token), "invalid owner")
    require(rtm in ("RTM-079", "RTM-084"), "campaign tag")
    base = rtm.lower().replace("-", "") + "-" + token
    return {"volume": base, "containers": [base + "-a", base + "-b"],
            "image": "compat-managed-recovery:" + token, "owner": token}

def initialize_evidence(root, token, value, *, rtm="RTM-079"):
    """Publish a complete plan, then sync its directory chain before engine I/O.

    The fresh token directory is exclusive. All mutation uses pinned directory
    descriptors; existing/symlink token paths are never adopted or overwritten.
    A failure leaves the exact partial evidence intact and admits no engine call.
    The caller runs inside the campaign's process-level deadline.
    """
    require(value.get("phase") == "plan" and value.get("plan") == names(token, rtm), "initial plan identity")
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
        for name in (".build", "managed-storage-recovery"):
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
    return Path(root) / ".build/managed-storage-recovery" / token, len(raw)

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


def unsigned(value, *, maximum=2 ** 64 - 1, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, "public bounded integer required")
    return value


def file_identity(value):
    require(isinstance(value, dict) and set(value) == {"device", "inode", "volumeUUID"}, "public file identity schema")
    volume = value["volumeUUID"]
    require(isinstance(volume, str) and str(uuid.UUID(volume)) == volume.lower(), "public filesystem UUID")
    return {"device": unsigned(value["device"]), "inode": unsigned(value["inode"], minimum=1), "volumeUUID": volume}


def metadata(value):
    require(isinstance(value, dict) and set(value) == {"mode", "uid", "gid", "nlink", "size", "mtime"}, "probe metadata schema")
    for key in ("mode", "uid", "gid"):
        unsigned(value[key], maximum=2 ** 32 - 1)
    unsigned(value["nlink"])
    unsigned(value["size"], maximum=2 ** 63 - 1)
    unsigned(value["mtime"], minimum=-(2 ** 63), maximum=2 ** 63 - 1)


def snapshot_proof(value, *, command, written=False):
    require(set(value) == {"command", "ack", "file_fsynced", "parent_fsynced", "entries", "root", "file", "sha256", "mountinfo"}, "probe public schema")
    metadata(value["root"])
    metadata(value["file"])
    mount = mount_proof(value["mountinfo"])
    require(re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", mount["device"]) and mount["root"] == "/", "public managed mount identity")
    # Mount options and unrelated mounts are never public artifacts.
    proof = {key: mount[key] for key in ("device", "root", "filesystem", "source")}
    require(value["command"] == command, "probe command correlation")
    ack = command in ("ack", "write")
    require(all(value[k] is ack for k in ("ack", "file_fsynced", "parent_fsynced")), "file and parent ACK required")
    require(value["entries"] == ["payload", "seed"], "exact linked namespace required")
    root, file = value["root"], value["file"]
    require((root["mode"], root["uid"], root["gid"]) == (stat.S_IFDIR | 0o750, 10001, 10002), "root metadata")
    require((file["mode"], file["uid"], file["gid"], file["nlink"], file["mtime"]) ==
            (stat.S_IFREG | 0o640, 10001, 10002, 1, MTIME), "linked payload metadata")
    expected = NEXT if written else PAYLOAD
    require(file["size"] == len(expected) and value["sha256"] == digest(expected), "acknowledged bytes changed")
    return proof


def read_public(path, limit=1024 * 1024):
    # Do not export the raw shim spec (it contains a token).
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "public file type/bound")
        raw = source.read(limit + 1)
    require(len(raw) <= limit, "public read bound")
    return json.loads(raw), digest(raw)


def exact_receipts(manifest, state, volume, containers, *, stopped=False, ids=None):
    require(len(containers) == 2 and len(set(containers)) == 2, "exact two consumers")
    selected = {}
    for container in containers:
        candidates = [i for i in state["intents"].values() if i["container"] == container and
                      (i["id"] in ids if ids is not None else i["phase"] == ("retired" if stopped else "running"))]
        require(len(candidates) == 1, "exact generation selection")
        selected[candidates[0]["id"]] = candidates[0]
    proof = receipt_proof(manifest, {**state, "intents": selected}, volume, containers, stopped=stopped)
    require(len({(i["serviceEpoch"], i["controllerEpoch"]) for i in proof["intents"]}) == 1, "mixed service/controller context")
    return proof


def historical_receipts(before, after):
    require(before["store"] == after["store"] and before["volume"] == after["volume"], "S/V changed")
    require(after["revision"] >= before["revision"], "journal rollback")
    require(before["intents"] == after["intents"], "historical P/A receipts changed")


def fresh_receipts(before, after, owner, *, rtm="RTM-079"):
    require(rtm in ("RTM-079", "RTM-084"), "campaign tag")
    require(before["store"] == after["store"] == owner["store"] and before["volume"] == after["volume"], "S/V changed")
    require(after["revision"] > before["revision"], "fresh journal revision")
    require([i["container"] for i in before["intents"]] == [i["container"] for i in after["intents"]], "consumer replacement")
    def identities(proof):
        return [i[k] for i in proof["intents"] for k in ("id", "launch", "prepare")] + [s["attachment"] for i in proof["intents"] for s in i["slots"]]
    old, new = identities(before), identities(after)
    require(len(set(new)) == len(new) and set(old).isdisjoint(new), "reused intent/P/A identity")
    for previous, current in zip(before["intents"], after["intents"]):
        require(current["containerInstance"] == previous["containerInstance"], "container instance changed")
        require(current["serviceEpoch"] == owner["serviceEpoch"] != previous["serviceEpoch"], "new E required")
        require(current["controllerEpoch"] == owner["controllerEpoch"] == previous["controllerEpoch"] + (rtm == "RTM-079"), "replacement C required")


def wire(encoded, operation):
    raw = base64.b64decode(encoded, validate=True)
    require(0 < len(raw) <= 65536, "ROOT transcript bound")
    value = json.loads(raw)
    require(set(value) == {"version", "operation", "request_id", "body"} and
            value["version"] == "bootstrap.v1" and value["operation"] == operation, "ROOT transcript envelope")
    require(str(uuid.UUID(value["request_id"])) == value["request_id"], "ROOT request ID")
    return value, digest(raw)


def owner_proof(record):
    require(record["schema"] == 1 and record["journalExpected"] is True and record["bootAttempted"] is True, "completed managed owner")
    require(all(record.get(k) is None for k in ("pendingIssue", "pendingIssued", "pendingConfirm", "pendingService")), "pending ROOT/service transition")
    root, backing = file_identity(record["root"]), file_identity(record["backing"])
    unsigned(record["bytes"], minimum=1, maximum=2 ** 63 - 1)
    unsigned(record["revision"], minimum=1)
    transitions = record["transitions"]
    require(isinstance(transitions, list) and len(transitions) <= 32, "transition bound")
    initial, _ = wire(record["initialReply"], "registerInitialController")
    current = initial["body"]["controller"]
    require(set(current) == {"epoch", "key"} and type(current["epoch"]) is int and current["epoch"] == 1 and
            isinstance(current["key"], str) and re.fullmatch(r"[0-9a-f]{64}", current["key"]), "initial controller")
    hashes = []
    for transition in transitions:
        require(isinstance(transition, dict) and set(transition) == {"issue", "issued", "confirm", "confirmed"}, "ROOT transition schema")
        issue, h1 = wire(transition["issue"], "issueTakeoverGrant")
        issued, h2 = wire(transition["issued"], "issueTakeoverGrant")
        confirm, h3 = wire(transition["confirm"], "confirmTakeover")
        confirmed, h4 = wire(transition["confirmed"], "confirmTakeover")
        require(issue["request_id"] == issued["request_id"] and confirm["request_id"] == confirmed["request_id"], "ROOT request/reply correlation")
        i, g, c = issue["body"], issued["body"]["grant"], confirm["body"]
        unsigned(i["expected_epoch"], minimum=1)
        unsigned(g["expected_epoch"], minimum=1)
        unsigned(c["controller"]["epoch"], minimum=1)
        unsigned(confirmed["body"]["controller"]["epoch"], minimum=1)
        key = digest(base64.b64decode(i["candidate"]["public_data"], validate=True))
        require(i["store"] == g["store"] == c["store"] == record["store"] and
                i["grant_id"] == g["id"] == c["grant_id"] and
                i["expected_epoch"] == g["expected_epoch"] == current["epoch"] and
                g["new_key"] == key != current["key"], "ROOT issue binding")
        require(len(base64.b64decode(issued["body"]["signature"], validate=True)) == 64, "ROOT signature shape")
        require(c["controller"] == confirmed["body"]["controller"] == {"epoch": current["epoch"] + 1, "key": key}, "ROOT confirm binding")
        current = c["controller"]
        hashes.append(dict(issue=h1, issued=h2, confirm=h3, confirmed=h4))
    services = record.get("serviceTransitions") or []
    require(len(services) <= len(transitions), "service transition count")
    boot = services[-1]["boot"] if services else record["boot"]
    for value in (record["store"], boot["binding"]["shimLaunchUUID"], boot["binding"]["guestBootNonce"],
                  boot["binding"]["ext4UUID"], boot["ready"]["serviceEpoch"]):
        require(isinstance(value, str) and str(uuid.UUID(value)) == value, "owner UUID identity")
    require(boot["ready"]["storeUUID"] == record["store"] and boot["diskIdentity"] == record["backing"], "owner boot S/backing")
    require(boot["binding"]["bytes"] == record["bytes"], "backing size")
    unsigned(boot["ready"]["revision"], minimum=1)
    if services:
        unsigned(services[-1]["afterControllerTransitions"], minimum=1, maximum=len(transitions))
    return {"store": record["store"], "backing": backing, "bytes": record["bytes"],
            "root": root, "ext4UUID": boot["binding"]["ext4UUID"],
            "shimLaunchUUID": boot["binding"]["shimLaunchUUID"], "guestBootNonce": boot["binding"]["guestBootNonce"],
            "serviceEpoch": boot["ready"]["serviceEpoch"], "controllerEpoch": current["epoch"],
            "bootRevision": boot["ready"]["revision"], "revision": record["revision"],
            "rootKeyHash": digest(base64.b64decode(record["rootPublicKey"], validate=True)),
            "transitions": hashes, "serviceTransitions": len(services),
            "serviceAfter": services[-1]["afterControllerTransitions"] if services else 0}


def recovered_owner(before, after):
    for key in ("store", "backing", "bytes", "root", "ext4UUID", "rootKeyHash"):
        require(before[key] == after[key], "persistent owner identity changed: " + key)
    for key in ("shimLaunchUUID", "guestBootNonce", "serviceEpoch"):
        require(before[key] != after[key], "replacement boot identity required: " + key)
    require(after["controllerEpoch"] == before["controllerEpoch"] + 1 and
            after["revision"] > before["revision"] and after["bootRevision"] > before["bootRevision"], "replacement revision/C+1")
    require(len(after["transitions"]) == len(before["transitions"]) + 1 and
            after["transitions"][:-1] == before["transitions"] and
            after["serviceTransitions"] == before["serviceTransitions"] + 1 and
            after["serviceAfter"] == len(after["transitions"]), "ROOT issue/confirm and service history required")


def native_proof(process):
    require(process is not None and type(process.pid) is int and process.pid > 1 and
            process.identity is not None and len(process.identity) == 3 and
            all(type(n) is int for n in process.identity) and process.identity[0] > 0 and
            0 <= process.identity[1] < 1000000 and process.identity[2] > 0 and
            type(process.pidversion) is int and 0 < process.pidversion < 2 ** 32, "native birth and pidversion required")
    return {"pid": process.pid, "birth": list(process.identity), "pidversion": process.pidversion}


def lifecycle_owner(root, *, worker=False, reader=read_public):
    """Current checkpoint + immutable physical manifest; never accept v1."""
    import managed_prepare_lifecycle_evidence as lifecycle
    import managed_prepare_worker_lifecycle_evidence as replacement

    adapter = replacement if worker else lifecycle
    value, stamp = adapter.read_owner(root, reader)
    require(lifecycle.is_v2(value), "ordinary recovery requires lifecycle-v2 owner")
    proof, _ = replacement.owner(value) if worker else lifecycle.owner_context(value)
    return value, proof, stamp


def recovered_lifecycle_owner(before, after):
    import managed_prepare_lifecycle_evidence as lifecycle

    require(lifecycle.is_v2(before) and lifecycle.is_v2(after), "ordinary cold recovery requires lifecycle-v2")
    _, context = lifecycle.owner_context(before)
    lifecycle.transition(before, after, {"scope": context}, storage=True)
    return lifecycle.owner_context(after)[0]


def lifecycle_replacement_proof(before, after, *args):
    """Ordinary two-consumer replacement, without a fabricated PREPARE arm."""
    import managed_prepare_lifecycle_evidence as lifecycle
    from managed_original_lifecycle_evidence import replacement_proof as compare

    require(lifecycle.is_v2(before) and lifecycle.is_v2(after), "ordinary worker recovery requires lifecycle-v2")
    return compare(before, after, *args)


def lifecycle_worker_history(record):
    import managed_prepare_worker_lifecycle_evidence as lifecycle

    require(lifecycle.shared.is_v2(record), "ordinary worker history requires lifecycle-v2")
    lifecycle.owner(record)
    state = record["checkpoint"]
    # Retained contexts/census can compact after fresh consumers. The completed
    # ROOT/native edge itself must not change, disappear or become pending.
    fields = ("identity", "rootPublicKey", "provenanceReference", "current", "currentService",
              "currentContext", "observedWorker", "latestServiceRequest", "latestServiceConfirmation",
              "latestServiceChange", "serviceReplacement", "nativeReplacementAttempted", "serviceLinks")
    return {key: state.get(key) for key in fields}


def backing_snapshot(root, owner):
    """Physical inode/size plus ext4 UUID/creation time, not a DTO stop proof."""
    path = Path(root) / "infrastructure/volumes.ext4"
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022
                and info.st_nlink == 1 and (info.st_dev, info.st_ino, info.st_size) ==
                (owner["backing"]["device"], owner["backing"]["inode"], owner["bytes"]), "owned physical backing")
        block = os.pread(fd, 1024, 1024)
        require(len(block) == 1024 and block[56:58] == b"\x53\xef"
                and str(uuid.UUID(bytes=block[104:120])) == owner["ext4UUID"], "actual ext4 superblock identity")
        return {"device": info.st_dev, "inode": info.st_ino, "bytes": info.st_size,
                "ext4UUID": owner["ext4UUID"], "created": block[264:268].hex()}
    finally:
        os.close(fd)


def target_matches(process, binary, root, spec_path, spec, spec_hash, launch, owner, disk_stat):
    """Retired v1 selector: never grants signal authority for a sole-v2 runtime.

    Kept as an explicit refusal for the historical RTM-079 caller. Current
    campaigns must use managed_prepare_lifecycle_evidence.storage_target with
    actual v2 owner evidence, assets and immutable native launch records.
    """
    raise ProofFailure("retired v1 storage target; lifecycle-v2 evidence required")


def exact_exit(previous, observed):
    native_proof(previous)
    if observed is None:
        return True  # _kernel_process(pid), without binary filter: native ESRCH only.
    native_proof(observed)
    require(observed.pid == previous.pid, "observer PID mismatch")
    if observed.identity == previous.identity and observed.pidversion == previous.pidversion:
        return False
    require(observed.identity[:2] != previous.identity[:2] and observed.identity[2] != previous.identity[2] and
            observed.pidversion != previous.pidversion, "ambiguous process incarnation")
    return True


def runtime_root_path(root):
    """Swift's observed /tmp spelling, not general path/UUID normalization.

    This lexical projection grants no authority: callers still validate the
    physical root, immutable input paths and the protected system alias.
    """
    root = Path(root)
    return Path("/tmp").joinpath(*root.parts[3:]) if root.parts[:3] == ("/", "private", "tmp") else root


@contextmanager
def workload_target(process, binary, work, root, plan, receipt, root_identity, expected_name, *, rtm="RTM-079"):
    """Exact live-campaign workload ownership, never storage-shim authority.

    Mirror the immutable schema-2 VMShimClient launch tuple. Hold the complete
    directory chain and bounded input FDs through the caller's signal boundary.
    Only the closed public projection leaves this context; specs contain tokens.
    """
    native = native_proof(process)
    binary, work, root = Path(binary), Path(work), Path(root)
    require(work.is_absolute() and ".." not in work.parts and root == work / "root"
            and plan == names(plan["owner"], rtm), "workload campaign root/plan")
    # Workload specs use /tmp but /private/var on Darwin (storage specs may
    # retain /var). Permit only the exact system alias, never an additional
    # campaign/ancestor symlink, before selecting the workload's lexical root.
    physical_work = work.resolve()
    require(work == physical_work or (work.parts[:2] in (("/", "tmp"), ("/", "var"))
            and physical_work == Path("/private").joinpath(*work.parts[1:])), "workload root spelling")
    root = runtime_root_path(physical_work / "root")
    alias_name = work.parts[1] if work != physical_work else ("tmp" if root != physical_work / "root" else None)
    container, instance, launch = (receipt[k] for k in ("container", "containerInstance", "launch"))
    require(isinstance(container, str) and re.fullmatch(r"[0-9a-f]{64}", container), "workload container ID")
    for value in (instance, launch):
        require(isinstance(value, str) and str(uuid.UUID(value)) == value, "workload UUID")
    args = process.arguments
    require(len(args) == 6, "workload argv length")
    require(args[1:3] == ("vm-shim", "--spec") and args[4] == "--launch-intent", "workload argv command")
    require(args[0] == str(binary) and Path(process.executable).resolve() == binary.resolve(), "workload argv executable")
    spec_path = Path(args[3])
    generation = spec_path.parent.name
    # Fixed guard names identify the failed comparison without publishing paths,
    # arbitrary argv, raw specifications or tokens into public failure records.
    require(args[3] == str(spec_path), "workload specification path spelling")
    require(re.fullmatch(r"[0-9]{20}-" + re.escape(launch), generation), "workload generation nonce")
    require(spec_path == root / "containers" / container / "shim-generations" / generation / "spec.json",
            "workload specification path root")
    require(args[5] == str(spec_path.parent / "intent.json"), "workload intent path")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        directories, files = [], []
        def identity(info):
            return info.st_dev, info.st_ino
        def stamp(info):
            return (*identity(info), info.st_uid, info.st_mode)
        def directory(name, parent=None, *, private=False, ancestor=False):
            fd = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require(info.st_uid in ((0, os.geteuid()) if ancestor else (os.geteuid(),)), "workload directory owner")
            writable = info.st_mode & (0o077 if private else 0o022)
            require(not writable or (ancestor and info.st_uid == 0 and info.st_mode & stat.S_ISVTX), "workload private directory chain")
            directories.append((parent, name, fd, stamp(info)))
            return fd
        alias_stamp = None
        if alias_name is not None:
            alias = os.lstat("/" + alias_name)
            require(stat.S_ISLNK(alias.st_mode) and alias.st_uid == 0 and not alias.st_mode & 0o022
                    and os.readlink("/" + alias_name) == "private/" + alias_name, "workload system " + alias_name + " alias")
            alias_stamp = stamp(alias)
        parent = directory("/", ancestor=True)
        for index, part in enumerate(physical_work.parts[1:], 1):
            last = index == len(physical_work.parts) - 1
            parent = directory(part, parent, private=last, ancestor=not last)
        work_fd = parent
        def read(name, parent, maximum=1024 * 1024):
            fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022
                    and info.st_nlink == 1 and info.st_size <= maximum, "workload bounded owned regular input")
            raw = os.pread(fd, maximum + 1, 0)
            require(len(raw) <= maximum, "workload input bound")
            files.append((parent, name, fd, stamp(info), raw, maximum))
            return raw
        marker = read(".cengine-compat-owner", work_fd, 4096)
        require(Path(os.fsdecode(marker).strip()).resolve() == binary.resolve(), "workload compatibility owner")
        root_fd = directory("root", work_fd)
        expected_root = file_identity(root_identity)
        require(identity(os.fstat(root_fd)) == (expected_root["device"], expected_root["inode"]), "workload native root binding")
        containers_fd = directory("containers", root_fd)
        container_fd = directory(container, containers_fd)
        generations_fd = directory("shim-generations", container_fd)
        generation_fd = directory(generation, generations_fd)
        raw = {name: read(name, generation_fd) for name in ("intent.json", "launch.json", "spec.json")}
        intent, record, spec = (json.loads(raw[name]) for name in ("intent.json", "launch.json", "spec.json"))
        common = {"schemaVersion", "nonce", "createdAt", "specificationPath", "executablePath",
                  "containerDirectoryIdentity", "generationsDirectoryIdentity", "generationDirectoryIdentity", "specification", "container"}
        require(set(intent) == common and set(record) == common | {"processIdentifier", "processStartTime", "kernelIdentity"}
                and type(intent["schemaVersion"]) is int and intent["schemaVersion"] == 2
                and all(record[k] == intent[k] for k in common), "workload immutable schema-2 launch")
        require(intent["specification"] == spec and intent["nonce"] == launch
                and intent["specificationPath"] == str(spec_path) and intent["executablePath"] == str(binary)
                and spec["kind"] == "container" and spec["workloadStorageMode"] == "managed"
                and spec["containerID"] == container and spec["shimLaunchUUID"] == launch
                and type(spec["generation"]) is int and spec["generation"] == int(generation[:20]), "workload immutable specification")
        saved = intent["container"]
        require(saved["id"] == container and str(uuid.UUID(saved["instanceID"])) == instance
                and saved["name"] == expected_name and expected_name in plan["containers"]
                and saved["labels"].get(OWNER) == plan["owner"], "workload receipted campaign container")
        for key, fd in (("containerDirectoryIdentity", container_fd), ("generationsDirectoryIdentity", generations_fd),
                        ("generationDirectoryIdentity", generation_fd)):
            expected = file_identity(intent[key])
            require(identity(os.fstat(fd)) == (expected["device"], expected["inode"])
                    and expected["volumeUUID"] == expected_root["volumeUUID"], "workload native generation binding")
        disk = os.open("root.ext4", flags | os.O_NONBLOCK, dir_fd=container_fd)
        stack.callback(os.close, disk)
        disk_info = os.fstat(disk)
        disk_identity = file_identity(spec["rootDiskIdentity"])
        require(stat.S_ISREG(disk_info.st_mode) and disk_info.st_uid == os.geteuid() and not disk_info.st_mode & 0o022
                and disk_info.st_nlink == 1 and spec["rootDiskPath"] == str(root / "containers" / container / "root.ext4")
                and spec["rootDiskReadOnly"] is False and not spec["volumeDisks"]
                and type(spec["rootDiskSize"]) is int and 0 < spec["rootDiskSize"] == disk_info.st_size
                and identity(disk_info) == (disk_identity["device"], disk_identity["inode"])
                and disk_identity["volumeUUID"] == expected_root["volumeUUID"], "workload native root disk binding")
        # RawVirtualizationBackend always adds this owned I/O share, even when
        # the campaign has no user bind mounts. No other share is authorized.
        shares = spec["bindShares"]
        require(isinstance(shares, list) and len(shares) == 1 and isinstance(shares[0], dict)
                and set(shares[0]) == {"tag", "source", "readOnly", "sourceIdentity"}, "workload I/O share schema")
        share = shares[0]
        require(share["tag"] == "cengine-io" and share["readOnly"] is False
                and share["source"] == str(root / "containers" / container / "io"), "workload exact I/O share")
        io_fd = directory("io", container_fd, private=True)
        io_identity = file_identity(share["sourceIdentity"])
        require(identity(os.fstat(io_fd)) == (io_identity["device"], io_identity["inode"])
                and io_identity["volumeUUID"] == expected_root["volumeUUID"], "workload native I/O binding")
        birth = record["kernelIdentity"]
        require(set(birth) == {"pid", "startSeconds", "startMicroseconds", "uniqueID", "bootUUID"}
                and all(type(birth[k]) is int for k in ("pid", "startSeconds", "startMicroseconds", "uniqueID"))
                and str(uuid.UUID(birth["bootUUID"])) == birth["bootUUID"]
                and birth["pid"] == record["processIdentifier"] == process.pid
                and type(record["processIdentifier"]) is int and type(record["processStartTime"]) is int
                and record["processStartTime"] == process.identity[0] * 1000000 + process.identity[1]
                and (birth["startSeconds"], birth["startMicroseconds"], birth["uniqueID"]) == process.identity, "workload native launch birth")
        def revalidate():
            if alias_name is not None:
                require(stamp(os.lstat("/" + alias_name)) == alias_stamp and os.readlink("/" + alias_name) == "private/" + alias_name,
                        "workload system " + alias_name + " alias changed")
            for parent, name, fd, expected in directories:
                require(stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected
                        and stamp(os.fstat(fd)) == expected, "workload directory changed")
            for parent, name, fd, expected, contents, maximum in files:
                visible, pinned = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(fd)
                require(stamp(visible) == stamp(pinned) == expected and pinned.st_nlink == visible.st_nlink == 1
                        and os.pread(fd, maximum + 1, 0) == contents, "workload launch input changed")
            visible_disk = os.stat("root.ext4", dir_fd=container_fd, follow_symlinks=False)
            require(stamp(visible_disk) == stamp(os.fstat(disk)) == stamp(disk_info)
                    and visible_disk.st_size == os.fstat(disk).st_size == disk_info.st_size
                    and visible_disk.st_nlink == os.fstat(disk).st_nlink == 1, "workload root disk changed")
        revalidate()
        yield {**native, "container": container, "containerInstance": instance, "launch": launch,
               "name": saved["name"], "owner": plan["owner"],
               "sha256": {name: digest(contents) for name, contents in raw.items()}}, revalidate


def terminate_drained_workloads(targets, retired, *, validate, reread, processes, inspect, record, deadline):
    """Two receipted STOPs, then exact host exits; never a storage fault or retry."""
    import ctypes
    import signal
    import harness
    from unittest.mock import patch

    require(len(targets) == 2 and len({proof["container"] for _, proof in targets}) == 2, "two captured workloads required")
    selected = {i["container"]: i for i in retired["intents"]}
    require(len(retired["intents"]) == len(selected) == 2 and set(selected) == {p["container"] for _, p in targets}, "exact drained workloads")
    for _, proof in targets:
        intent = selected[proof["container"]]
        require(intent["phase"] == "retired" and all(intent[k] == proof[k] for k in ("container", "containerInstance", "launch"))
                and {s["role"] for s in intent["slots"]} == {"prepare", "runtime"}
                and all(s["receipt"] is not None for s in intent["slots"]), "workload drain before termination")
    before = processes()
    for process, captured in targets:
        for selected_signal in (signal.SIGTERM, signal.SIGKILL):
            require(time.monotonic() < deadline, "workload termination deadline")
            historical_receipts(retired, reread())
            if exact_exit(process, inspect(process.pid)):
                break
            require(process in before, "workload missing from runtime snapshot")
            intent = selected[captured["container"]]
            with validate(process, intent) as (fresh, revalidate):
                require(fresh == captured, "captured workload ownership changed")
                record("workload-termination-intent", proof=fresh, signal=selected_signal.name)
                delivered = False
                def deliver(pid, pidversion, sig):
                    nonlocal delivered
                    require((pid, pidversion, sig) == (process.pid, process.pidversion, selected_signal), "workload audit signal binding")
                    revalidate()
                    require(time.monotonic() < deadline, "workload termination deadline")
                    token = (ctypes.c_uint32 * 8)(0, 0, 0, 0, 0, pid, 0, pidversion)
                    result = ctypes.CDLL(None, use_errno=True).proc_signal_with_audittoken(ctypes.byref(token), sig)
                    require(result == 0, "workload native signal delivery not confirmed")
                    delivered = True
                with patch.object(harness, "_signal_pid_incarnation", new=deliver):
                    harness._signal_runtime_process(process, selected_signal)
                require(delivered, "workload disappeared before signal delivery")
            record("workload-termination-delivered", process=native_proof(process), signal=selected_signal.name, native_result=0)
            until = min(deadline, time.monotonic() + 1)
            while not exact_exit(process, inspect(process.pid)) and time.monotonic() < until:
                time.sleep(min(0.05, max(0, until - time.monotonic())))
        require(time.monotonic() < deadline and exact_exit(process, inspect(process.pid)), "workload native exit deadline")
        after = processes()
        if process in before:
            unchanged_processes(before, after, process)
        else:
            require({p.pid: p for p in before} == {p.pid: p for p in after}, "unrelated runtime process changed")
        record("native-exit", process=native_proof(process), boundary="drained-workload", other_runtime_changes=0)
        before = after  # No unobserved gap may adopt unrelated runtime changes.


def signal_storage(process, *, before_signal=None):
    """Reuse the harness birth/argv guard, but require positive fault delivery.

    The general cleanup helper deliberately accepts ESRCH. In this private,
    single-campaign worker, temporarily replace only its final syscall adapter
    with the identical audit-token operation plus a strict zero-result receipt.
    No production file changes, PID-only signal, or inferred death is involved.
    The original adapter is restored on every path, including exceptions.
    An optional final observer runs after target revalidation, directly before
    the syscall. It establishes pre-signal liveness, not atomic cross-process
    ordering or the cause/time of a later exit event.
    """
    import ctypes
    import signal
    import harness
    from unittest.mock import patch

    proof = native_proof(process)
    delivered = False
    def deliver(pid, pidversion, selected_signal):
        nonlocal delivered
        require((pid, pidversion, selected_signal) == (process.pid, process.pidversion, signal.SIGKILL), "exact audit signal binding")
        token = (ctypes.c_uint32 * 8)(0, 0, 0, 0, 0, pid, 0, pidversion)
        native_signal = ctypes.CDLL(None, use_errno=True).proc_signal_with_audittoken
        pointer = ctypes.byref(token)
        if before_signal is not None: before_signal()
        result = native_signal(pointer, selected_signal)
        require(result == 0, "native SIGKILL delivery not confirmed")
        delivered = True
    with patch.object(harness, "_signal_pid_incarnation", new=deliver):
        harness._signal_runtime_process(process, signal.SIGKILL)
    require(delivered, "storage disappeared before SIGKILL delivery")
    return {**proof, "signal": "SIGKILL", "native_result": 0}


def api_exit_survivors(before, after, api, *, joined, inspect, record):
    """Refresh only direct-child lineage after the parent's exact API kill/join.

    This is a one-boundary census refresh, not relaxed process equality or signal
    authority. Every survivor must still be live with every other field exact.
    """
    from dataclasses import replace
    import signal

    require(joined == (api.pid, -signal.SIGKILL) and exact_exit(api, inspect(api.pid)),
            "joined exact API exit before survivor refresh")
    require(len({v.pid for v in before}) == len(before) and len({v.pid for v in after}) == len(after),
            "duplicate process snapshot")
    current = {v.pid: v for v in after}
    refreshed, evidence = [], []
    def proof(value):
        return dict(native_proof(value), parentPID=value.parent_pid, executable=value.executable,
                    argumentsSHA256=digest(json.dumps(list(value.arguments), separators=(",", ":")).encode()))
    for previous in before:
        if previous == api:
            refreshed.append(previous)
            continue
        observed = current.get(previous.pid)
        require(observed == previous or (previous.parent_pid == api.pid
                and observed == replace(previous, parent_pid=1)),
                "exact survivor or killed API child reparented to PID 1")
        require(inspect(observed.pid) == observed, "refreshed survivor still live and exact")
        refreshed.append(observed)
        evidence.append(dict(before=proof(previous), after=proof(observed)))
    unchanged_processes(refreshed, after, api)
    record("api-survivors-observed", api=native_proof(api), joinedPID=joined[0],
           returncode=joined[1], survivors=evidence)
    return list(after)


def unchanged_processes(before, after, removed):
    require(len({p.pid for p in before}) == len(before) and len({p.pid for p in after}) == len(after), "duplicate process snapshot")
    require(removed in before and removed not in after, "exact target removal required")
    require({p.pid: p for p in before if p != removed} == {p.pid: p for p in after}, "unrelated runtime process changed")



# RTM-084 is a public observer, never a substitute for the sealed runtime owner.
WORKER_PAYLOAD = b"rtm084-acknowledged-hardlink-payload\n"
WORKER_NEXT = b"rtm084-post-worker-write\n"
WORKER_XATTRS = {"user.rtm084.binary": base64.b64encode(b"\x00\xff\x80rtm084").decode(), "user.rtm084.empty": ""}
DISK_INCREMENT = 2 * 1024 ** 3
DISK_RESERVE = 4 * 1024 ** 3


def worker_snapshot_proof(value, *, command, written=False):
    require(set(value) == {"command", "ack", "file_fsynced", "parent_fsynced", "entries", "root", "file", "sha256", "mountinfo",
                           "root_xattrs", "file_xattrs", "seed", "seed_sha256", "inode", "seed_inode"}, "worker probe schema")
    require(value["command"] == "worker-" + command, "worker probe command")
    require(value["root_xattrs"] == value["file_xattrs"] == WORKER_XATTRS, "binary/empty root/file xattrs")
    require(value["file"] == value["seed"] and value["sha256"] == value["seed_sha256"], "hardlink peer metadata/bytes")
    require(unsigned(value["inode"], minimum=1) == unsigned(value["seed_inode"], minimum=1), "hardlink inode identity")
    require(value["file"]["nlink"] == 2 and value["root"]["mtime"] == MTIME, "hardlink count/root mtime")
    expected = WORKER_NEXT if written else WORKER_PAYLOAD
    require(value["file"]["size"] == len(expected) and value["sha256"] == digest(expected), "worker acknowledged bytes")
    # Reuse the unchanged RTM-079 FUSE, ownership, namespace and ACK guards.
    normalized = {k: copy.deepcopy(value[k]) for k in ("command", "ack", "file_fsynced", "parent_fsynced", "entries", "root", "file", "sha256", "mountinfo")}
    normalized["command"] = "ack" if command == "ack-peer" else command
    normalized["file"].update(nlink=1, size=len(NEXT if written else PAYLOAD))
    normalized["sha256"] = digest(NEXT if written else PAYLOAD)
    return snapshot_proof(normalized, command=normalized["command"], written=written)


def uuid4(value):
    require(isinstance(value, str), "worker UUID type")
    parsed = uuid.UUID(value)
    require(parsed.version == 4 and parsed.variant == uuid.RFC_4122 and str(parsed) == value, "worker canonical RFC UUIDv4")
    return value


def worker_request(operation, store, predecessor):
    require(isinstance(predecessor, dict) and set(predecessor) == {"serviceEpoch", "workerUUID"}, "worker scope schema")
    value = {"operationUUID": uuid4(operation), "store": uuid4(store),
             "predecessor": {k: uuid4(predecessor[k]) for k in ("serviceEpoch", "workerUUID")}}
    raw = json.dumps(value, separators=(",", ":")).encode()
    require(len(raw) <= 512, "worker marker bound")
    return value, raw


def worker_owner(record):
    """Observe a settled fresh-fixture history; do not fabricate a verified boot."""
    proof = owner_proof(record)
    services, workers = record.get("serviceTransitions") or [], record.get("workerReplacements") or []
    # Fresh Daemon fixture: no takeover/VM-restart baseline is silently adopted.
    require(not services and not record["transitions"] and len(workers) <= 1, "fresh worker-only fixture history")
    boot = workers[-1]["successor"] if workers else record["boot"]
    ready = boot["ready"]
    require(ready["controllerEpoch"] == proof["controllerEpoch"], "worker C binding")
    initial, _ = wire(record["initialReply"], "registerInitialController")
    require(ready["controllerKey"] == initial["body"]["controller"]["key"], "worker controller key")
    proof.update(serviceEpoch=uuid4(ready["serviceEpoch"]), workerUUID=uuid4(ready["workerUUID"]),
                 bootRevision=unsigned(ready["revision"], minimum=1))
    return proof, copy.deepcopy(boot)


def replacement_proof(before, after, pending, succeeded, request, state, hashes, containers, submitted, observed, *, prepare_recovery=None, active_ack_containers=None):
    require(type(pending.get("schema")) is int and pending["schema"] == 1 and
            type(succeeded.get("schema")) is int and succeeded["schema"] == 1, "replacement receipt schema")
    require(set(pending) == {"schema", "counter", "phase", "request", "proof"} and
            set(succeeded) == {"schema", "counter", "phase", "request", "proof", "ownerRequest", "successor", "containedContainerIDs"}, "replacement closed receipts")
    require(pending["phase"] == "pending" and succeeded["phase"] == "succeeded" and
            pending["request"] == succeeded["request"] == request, "replacement phase/request match")
    require(unsigned(pending["counter"], minimum=1, maximum=16) == unsigned(succeeded["counter"], minimum=1, maximum=16), "replacement claim counter")
    old, oldboot = worker_owner(before)
    new, newboot = worker_owner(after)
    require(request["store"] == old["store"] and request["predecessor"] == {k: old[k] for k in ("serviceEpoch", "workerUUID")}, "replacement predecessor selection")
    for key in set(before) | set(after):
        if key not in ("revision", "workerReplacements"):
            require(before.get(key) == after.get(key), "same owner/ROOT/VM identity")
    require(after["revision"] > before["revision"], "worker owner revision")
    history, prior = after.get("workerReplacements") or [], before.get("workerReplacements") or []
    require(len(history) == len(prior) + 1 and history[:-1] == prior, "one appended immutable worker history")
    item = history[-1]
    require(set(item) == {"afterControllerTransitions", "predecessor", "request", "lastObservedStatus", "successor", "localAdoption", "completed"}, "completed worker history schema")
    actual = succeeded["ownerRequest"]
    require(set(actual) == {"operationUUID", "predecessor", "nowUnixSeconds"} and actual["operationUUID"] == request["operationUUID"] and
            actual["predecessor"] == request["predecessor"] and item["request"] == actual, "actual owner request correlation")
    require(submitted <= unsigned(actual["nowUnixSeconds"], maximum=253402300799) <= observed, "actual owner request time window")
    expected = {"controllerEpoch": old["controllerEpoch"], "controllerKey": oldboot["ready"]["controllerKey"], "rootPublicKey": before["rootPublicKey"]}
    require(pending["proof"] == succeeded["proof"] == expected, "same ROOT C/key proof")
    require(active_ack_containers is None or prepare_recovery is not None, "four-owner variant requires A5")
    if prepare_recovery is None:
        require(succeeded["containedContainerIDs"] == sorted(containers) and len(set(containers)) == 2, "exact two contained IDs (not exit proof)")
    else:
        import managed_prepare_faults as prepare
        if prepare_recovery["caseName"] in prepare.STORAGE_CASES:
            # Storage-owned cuts bind the exact query/worker; the five guest cuts
            # bind the owned worker through the checkpoint carrier instead.
            prepare.storage_query(prepare_recovery, old["workerUUID"])
        if active_ack_containers is None:
            require(prepare_recovery["caseName"] in prepare.WORKER_EXIT_CASES + prepare.CHECKPOINT_EXIT_CASES
                and len(containers) == len(set(containers)) == 2
                and prepare_recovery["scope"]["container"] in containers
                and succeeded["containedContainerIDs"] == sorted(containers), "exact held/observed worker-cut full two-owned-container census (not exit proof)")
        else:
            from managed_prepare_active_ack import four_owner_ids
            four_owner_ids(containers, active_ack_containers, prepare_recovery["scope"]["container"])
            require(prepare_recovery["caseName"] == "admitted-queued" and
                succeeded["containedContainerIDs"] == sorted(containers), "exact A5 four-owner containment receipt (not exit proof)")
        for container in containers: prepare.pin(container)
        require(all(prepare_recovery["scope"][k] == old[k] for k in ("store", "serviceEpoch", "controllerEpoch"))
            and prepare_recovery["scope"]["controllerKey"] == oldboot["ready"]["controllerKey"], "A5 installed worker context")
    require(item["afterControllerTransitions"] == len(before["transitions"]) and item["successor"] == newboot, "worker history context")
    predecessor = copy.deepcopy(item["predecessor"])
    require(predecessor["ready"]["revision"] >= oldboot["ready"]["revision"], "predecessor revision rollback")
    predecessor["ready"]["revision"] = oldboot["ready"]["revision"]
    require(predecessor == oldboot, "exact predecessor boot")
    for key in ("binding", "diskIdentity", "initramfsSHA256"):
        require(newboot[key] == oldboot[key], "same storage VM/backing/guest nonce")
    for key in ("storeUUID", "controllerEpoch", "controllerKey", "bootstrapKey"):
        require(newboot["ready"][key] == oldboot["ready"][key], "persistent worker authority binding")
    for key in ("serviceEpoch", "workerUUID"):
        require(uuid4(new[key]) != old[key], "fresh worker/E required")
    for key in ("tlsRootDER", "serverDER", "serverKey"):
        require(newboot["ready"][key] != oldboot["ready"][key], "replacement TLS identity rotation")
    require(newboot["ready"]["revision"] > item["predecessor"]["ready"]["revision"], "new worker boot revision")
    require(succeeded["successor"] == {k: new[k] for k in ("serviceEpoch", "workerUUID")}, "successor receipt binding")
    require(item["lastObservedStatus"] == {"request": actual, "phase": "succeeded", "ready": newboot["ready"]}, "actual terminal worker status")
    for field in ("localAdoption", "completed"):
        evidence = item[field]
        require(set(evidence) == {"revision", "digest"} and isinstance(evidence["digest"], str) and
                re.fullmatch(r"[0-9a-f]{64}", evidence["digest"]), "worker adoption/completion evidence")
        unsigned(evidence["revision"], minimum=1)
    require(newboot["ready"]["revision"] <= item["localAdoption"]["revision"] <= item["completed"]["revision"],
            "successor/adoption/completion revision order")
    require(state["store"] == old["store"] and state["reconciliationRequired"] is False and
            item["completed"] == {"revision": state["revision"], "digest": hashes["state_sha256"]}, "completed exact settled journal raw bytes")
    return new


def retired_from_running(running, retired):
    require(running["store"] == retired["store"] and running["volume"] == retired["volume"] and
            retired["revision"] > running["revision"], "retired store/volume/revision")
    normalized = copy.deepcopy(retired["intents"])
    for intent in normalized:
        require(intent["phase"] == "retired", "terminal old generation")
        intent["phase"] = "running"
        for slot in intent["slots"]:
            if slot["role"] == "runtime":
                require(slot["receipt"] is not None, "old runtime drain")
                slot["receipt"] = None
    require(normalized == running["intents"], "old P/A/prepare receipts immutable")


def disk_budget(root, baseline=None):
    """Bound observed allocated growth, not sparse logical size; never fill a disk.

    Initially reserve the entire 2GiB growth allowance plus 4GiB untouched space.
    Later checks require the unspent growth allowance plus the same 4GiB reserve;
    shrinking below the baseline never grants more than the original allowance.
    """
    total, count, pending = 0, 0, [Path(root)]
    while pending:
        path = pending.pop()
        with os.scandir(path) as entries:
            for entry in entries:
                count += 1
                require(count <= 8192, "disk accounting entry bound")
                info = entry.stat(follow_symlinks=False)
                total += info.st_blocks * 512
                if stat.S_ISDIR(info.st_mode): pending.append(Path(entry.path))
    available = os.statvfs(root)
    free = available.f_bavail * available.f_frsize
    growth = 0 if baseline is None else max(0, total - unsigned(baseline))
    require(growth <= DISK_INCREMENT, "disk allocated increment cap")
    remaining = DISK_INCREMENT - growth
    required = DISK_RESERVE + remaining
    require(free >= required, "disk remaining allowance plus reserve")
    return {"allocated": total, "free": free, "increment_limit": DISK_INCREMENT,
            "growth": growth, "remaining": remaining, "reserve": DISK_RESERVE, "headroom": required}


@contextmanager
def replacement_queue(root, root_identity):
    """Pin the canonical owned root/queue; all marker/receipt I/O stays beneath it."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = Path(root).resolve()
    with ExitStack() as stack:
        fd = os.open("/", flags); stack.callback(os.close, fd)
        for part in root.parts[1:]:
            fd = os.open(part, flags, dir_fd=fd); stack.callback(os.close, fd)
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022 and
                (info.st_dev, info.st_ino) == (root_identity["device"], root_identity["inode"]), "replacement root binding")
        queue = os.open("managed-storage-replacement", flags, dir_fd=fd); stack.callback(os.close, queue)
        held = os.fstat(queue)
        require(held.st_uid == os.geteuid() and stat.S_IMODE(held.st_mode) == 0o700, "private replacement queue")
        def validate():
            visible = os.stat("managed-storage-replacement", dir_fd=fd, follow_symlinks=False)
            current = root.stat(follow_symlinks=False)
            require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and
                    (visible.st_dev, visible.st_ino, visible.st_mode, visible.st_uid) ==
                    (held.st_dev, held.st_ino, held.st_mode, held.st_uid), "replacement directory changed")
        validate()
        yield queue, validate


def queue_file(queue, name, maximum=1024 * 1024):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=queue)
    try:
        info = os.fstat(fd); visible = os.stat(name, dir_fd=queue, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid() and
                info.st_nlink == visible.st_nlink == 1 and info.st_size <= maximum and
                (info.st_dev, info.st_ino, info.st_mode, info.st_uid) == (visible.st_dev, visible.st_ino, visible.st_mode, visible.st_uid), "immutable queue file metadata")
        raw = os.pread(fd, maximum + 1, 0)
        require(len(raw) == info.st_size and len(raw) <= maximum, "immutable queue read bound")
        def fingerprint(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(fingerprint(os.fstat(fd)) == fingerprint(info) ==
                fingerprint(os.stat(name, dir_fd=queue, follow_symlinks=False)) and
                os.pread(fd, maximum + 1, 0) == raw, "immutable queue file changed during read")
        return raw, (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, digest(raw))
    finally:
        os.close(fd)


def publish_worker_request(queue, raw):
    import ctypes
    require(len(raw) <= 512, "worker marker bound")
    value = json.loads(raw)
    require(worker_request(value["operationUUID"], value["store"], value["predecessor"])[1] == raw, "canonical worker marker")
    temporary = value["operationUUID"] + ".submitting"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=queue)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            n = os.write(fd, raw[offset:]); require(n > 0, "marker write progress"); offset += n
        os.fsync(fd)
        require(os.fstat(fd).st_nlink == 1, "marker single link")
        rename = ctypes.CDLL(None, use_errno=True).renameatx_np
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(queue, os.fsencode(temporary), queue, b"request.json", 4) != 0:  # Darwin RENAME_EXCL
            raise OSError(ctypes.get_errno(), "exclusive marker publication failed")
        os.fsync(queue)
        return os.fstat(fd).st_dev, os.fstat(fd).st_ino
    finally:
        os.close(fd)  # Any failed temporary is preserved, never reused.


def settled_worker_artifacts(queue, operation, seen):
    """Exact fresh-fixture terminal namespace, not success-over-failure precedence."""
    uuid4(operation)
    expected = {operation + suffix for suffix in (".request.json", ".pending.json", ".succeeded.json")}
    names = set()
    with os.scandir(queue) as entries:
        for entry in entries:
            require(len(names) < 81, "replacement queue entry bound")
            names.add(entry.name)
    require(names == expected == set(seen), "exact settled replacement artifacts; no failed/writing receipt")
    for name in sorted(expected):
        require(queue_file(queue, name, 512 if name.endswith(".request.json") else 1048576) == seen[name],
                "immutable settled replacement receipt changed")
