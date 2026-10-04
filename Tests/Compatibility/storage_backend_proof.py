"""Read-only, engine-free proof of a compatibility daemon's selected backend.

Topology JSON is a separate assertion owned by callers. Never infer selection
from the guest filesystem, normalize observations, or fall back to another mode.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


class BackendProofError(ValueError):
    pass


_ROOT_PINS = {}


def capture_backend_root(root, startup_mode="lifecycle"):
    """Called by Daemon.start BEFORE Popen; pin survives API adoption/restart."""
    require(startup_mode == "lifecycle", "invalid captured startup mode")
    key = str(Path(root).absolute())
    captured = {"identity": root_identity(root), "mode": startup_mode}
    require(key not in _ROOT_PINS or _ROOT_PINS[key] == captured,
            "daemon root or mode changed after startup capture")
    _ROOT_PINS[key] = captured
    return dict(captured["identity"])


def require(condition, message):
    if not condition:
        raise BackendProofError(message)


def _identity(fd):
    _private(fd, True, "daemon root")
    return _file_identity(fd)


def _file_identity(fd):
    info = os.fstat(fd)
    result: dict = {"device": info.st_dev, "inode": info.st_ino}
    if sys.platform == "darwin":
        class AttrList(ctypes.Structure):
            _fields_ = [("bitmapcount", ctypes.c_uint16), ("reserved", ctypes.c_uint16),
                        ("common", ctypes.c_uint32), ("volume", ctypes.c_uint32),
                        ("directory", ctypes.c_uint32), ("file", ctypes.c_uint32),
                        ("fork", ctypes.c_uint32)]
        attributes = AttrList(5, 0, 0, 0x80040000, 0, 0, 0)  # ATTR_VOL_INFO | ATTR_VOL_UUID
        buffer = ctypes.create_string_buffer(20)
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.fgetattrlist
        call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
        call.restype = ctypes.c_int
        require(call(fd, ctypes.byref(attributes), buffer, 20, 0) == 0,
                "cannot verify daemon filesystem UUID")
        require(int.from_bytes(buffer.raw[:4], sys.byteorder) == 20, "invalid filesystem UUID length")
        result["volumeUUID"] = str(uuid.UUID(bytes=buffer.raw[4:20])).upper()
    return result


def root_identity(root):
    """Capture a host directory identity; also the engine-free fixture recipe."""
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return _identity(fd)
        finally:
            os.close(fd)
    except OSError as error:
        raise BackendProofError("cannot open owned daemon root") from error


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate lifecycle JSON key")
        result[key] = value
    return result


def _unescape(value):
    require(not re.search(r"\\(?!040|011|012|134)", value), "invalid mountinfo escape")
    return re.sub(r"\\(040|011|012|134)", lambda match: chr(int(match[1], 8)), value)


def mount_identity(text, destination="/data"):
    require(isinstance(text, str) and len(text.encode()) <= 65536, "mountinfo size/type")
    require(isinstance(destination, str) and destination.startswith("/") and
            all(part not in (".", "..") for part in destination.split("/")), "invalid mount destination")
    matches = []
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields, "malformed mountinfo")
        separator = fields.index("-")
        require(separator >= 6 and len(fields) == separator + 4, "malformed mountinfo tail")
        require(re.fullmatch(r"[1-9][0-9]*", fields[0]) and
                re.fullmatch(r"[0-9]+", fields[1]) and
                re.fullmatch(r"[0-9]+:[0-9]+", fields[2]), "malformed mount identity")
        if _unescape(fields[4]) != destination:
            continue
        matches.append({"raw": line, "mount_id": fields[0], "device": fields[2],
                        "root": _unescape(fields[3]), "destination": destination,
                        "filesystem": fields[separator + 1], "source": _unescape(fields[separator + 2]),
                        "options": fields[5].split(","), "super_options": fields[separator + 3].split(",")})
    require(len(matches) == 1, "expected one exact destination mount")
    return matches[0]


def daemon_startup_mode(daemon):
    """Use the fixture's captured Popen argv, not a fresh observation of the mount."""
    process = getattr(daemon, "process", None)
    arguments = getattr(process, "args", None)
    if isinstance(arguments, (list, tuple)):
        require(not any(isinstance(arg, str) and (arg == "--shared-storage" or arg.startswith("--shared-storage="))
                        for arg in arguments), "retired captured startup selector")
        return "lifecycle"
    return None


MAXIMUM_BYTES = 1_048_576
OWNER_FILES = {"lease", "manifest.json", "state.json"}


def _private(fd, directory, label):
    info = os.fstat(fd)
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == os.geteuid() and not info.st_mode & 0o7077
            and (directory or info.st_nlink == 1), f"unsafe private {label}")
    return info


def _stamp(info, directory=False, backing=False):
    # Guest IO may change backing timestamps, not its identity/size/protection.
    fixed = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
    return fixed if directory else fixed + (info.st_size,) + (() if backing else (info.st_mtime_ns, info.st_ctime_ns))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _decode(raw, label):
    value = json.loads(raw, object_pairs_hook=_object)
    require(_canonical(value) == raw, f"noncanonical {label} JSON")
    def scalars(node, key=None):
        # Python equality treats True == 1 == 1.0; Swift's typed decoder does
        # not. Reject those aliases even inside redundant correlated DTOs.
        if type(node) is dict:
            for field, child in node.items(): scalars(child, field)
        elif type(node) is list:
            for child in node: scalars(child)
        elif type(node) is bool:
            require(key in ("bootAttempted", "nativeReplacementAttempted"), "boolean in lifecycle scalar")
        elif type(node) is int:
            _uint(node)
        else:
            require(node is None or type(node) is str, "invalid lifecycle scalar type")
    scalars(value)
    return value


def _exact(value, required, optional=()):
    require(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional),
            f"invalid lifecycle object fields (expected {sorted(required)})")
    # Synthesized Swift Optional fields are omitted, not encoded as null.
    require(all(value[k] is not None for k in optional if k in value), "null optional lifecycle field")


def _uint(value, minimum=0, maximum=2**64 - 1):
    require(type(value) is int and minimum <= value <= maximum, "invalid lifecycle integer")


def _uuid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0,
            "invalid canonical lifecycle UUID")


def _digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid lifecycle digest")


def _encoded(value, size):
    require(type(value) is str and len(value) == 4 * ((size + 2) // 3), "invalid lifecycle public bytes")
    raw = base64.b64decode(value, validate=True)
    require(len(raw) == size and base64.b64encode(raw).decode() == value, "invalid canonical lifecycle public bytes")
    return raw


def _fingerprint(value):
    return hashlib.sha256(bytes.fromhex("302a300506032b6570032100") + _encoded(value, 32)).hexdigest()


def _context(value):
    _exact(value, {"serviceEpoch", "controllerEpoch", "controllerKey"})
    _uuid(value["serviceEpoch"]); _uint(value["controllerEpoch"], 1); _digest(value["controllerKey"])
    return _canonical(value)


def _grant(value, identity):
    _exact(value, {"operation", "id", "identity", "serial", "expected_epoch", "new_key"})
    _uuid(value["id"]); _uint(value["serial"], 1); _uint(value["expected_epoch"]); _digest(value["new_key"])
    require(value["identity"] == identity and value["operation"] in ("initialize", "takeover", "retire"), "invalid lifecycle grant")
    require((value["operation"] == "initialize") == (value["expected_epoch"] == 0), "invalid grant epoch")
    require(value["operation"] != "takeover" or value["expected_epoch"] < 2**64 - 1, "overflowing takeover epoch")


def _recipient(value, root_key):
    _exact(value, {"publicKey", "incarnation", "daemonUniqueID", "childUniqueID", "childPID"})
    _uuid(value["incarnation"])
    _uint(value["daemonUniqueID"], 1); _uint(value["childUniqueID"], 1); _uint(value["childPID"], 1, 2**31 - 1)
    key = _fingerprint(value["publicKey"])
    require(value["daemonUniqueID"] != value["childUniqueID"] and key != root_key, "invalid lifecycle recipient")
    return key


def _original(value, identity, root_key):
    _exact(value, {"signed", "recipient", "requestID"}, {"serviceEpoch"})
    _uuid(value["requestID"])
    signed = value["signed"]
    _exact(signed, {"grant", "signature"}); _encoded(signed["signature"], 64)
    grant = signed["grant"]; _grant(grant, identity)
    require(_recipient(value["recipient"], root_key) == grant["new_key"], "grant recipient fingerprint mismatch")
    if "serviceEpoch" in value: _uuid(value["serviceEpoch"])
    else: require(grant["operation"] == "initialize", "missing grant service epoch")
    return grant


def _receipt(value, original):
    _exact(value, {"grant", "nonce", "service_epoch", "revision"})
    _encoded(value["nonce"], 32); _uuid(value["service_epoch"]); _uint(value["revision"], 1)
    require(value["grant"] == original["signed"]["grant"] and
            original.get("serviceEpoch", value["service_epoch"]) == value["service_epoch"], "receipt/grant correlation mismatch")


def _completed(value, identity, root_key):
    _exact(value, {"original", "directResult"})
    grant = _original(value["original"], identity, root_key)
    _receipt(value["directResult"], value["original"])
    require(grant["operation"] != "retire", "retired current controller")
    return dict(serviceEpoch=value["directResult"]["service_epoch"], controllerEpoch=grant["expected_epoch"] + 1,
                controllerKey=grant["new_key"])


def _service(value, identity, root_key):
    _exact(value, {"grant", "context", "boot", "open_revision"})
    grant, context, boot = value["grant"], value["context"], value["boot"]
    _grant(grant, identity); _uint(value["open_revision"], 1)
    _exact(context, {"service_epoch", "controller_epoch", "controller_key"})
    projected = dict(serviceEpoch=context["service_epoch"], controllerEpoch=context["controller_epoch"], controllerKey=context["controller_key"])
    _context(projected)
    _exact(boot, {"identity", "service_epoch", "tls_root_sha256", "server_spki", "bootstrap_key"})
    for field in ("tls_root_sha256", "server_spki", "bootstrap_key"): _digest(boot[field])
    require(grant["operation"] != "retire" and context["controller_epoch"] == grant["expected_epoch"] + 1
            and context["controller_key"] == grant["new_key"] != root_key and boot["identity"] == identity
            and boot["service_epoch"] == context["service_epoch"] and boot["bootstrap_key"] == root_key,
            "invalid service grant/boot/context correlation")
    return projected


def _link(value):
    _exact(value, {"operationID", "predecessor", "successor", "revision"})
    _uuid(value["operationID"]); _uint(value["revision"], 1)
    old, new = value["predecessor"], value["successor"]
    _context(old); _context(new)
    require(old["serviceEpoch"] != new["serviceEpoch"] and all(old[k] == new[k] for k in
            ("controllerEpoch", "controllerKey")), "invalid same-controller service link")
    return hashlib.sha256(_canonical(value)).hexdigest()


def _pending_service(value, identity, root_key, current):
    _exact(value, {"request", "stageRequestID", "completionRequestID", "predecessorWorkerUUID", "nowUnixSeconds", "lifetimeSeconds"})
    for key in ("stageRequestID", "completionRequestID", "predecessorWorkerUUID"): _uuid(value[key])
    _uint(value["nowUnixSeconds"], 1, 253402300799); _uint(value["lifetimeSeconds"], 1, 86400)
    request = value["request"]
    _exact(request, {"operation_id", "predecessor"}); _uuid(request["operation_id"])
    _service(request["predecessor"], identity, root_key)
    require(value["stageRequestID"] != value["completionRequestID"] and current is not None
            and request["predecessor"]["grant"] == current["original"]["signed"]["grant"]
            and request["predecessor"]["open_revision"] < 2**64 - 1 and current["directResult"]["revision"] < 2**64 - 1,
            "invalid service retry correlation")


def _checkpoint(state, manifest):
    """Read-only semantic/correlation checks, NOT signature or live authority proof.

    Mirrors the checkpoint's public shape, without the restart/worker campaign
    restrictions imposed by the comparison-evidence modules.
    """
    # Common mount proof supports completed recovery only. An unresolved dead
    # disposition is public history, not evidence of a usable successor.
    require("resolvedDeadCold" not in state, "unresolved resolvedDeadCold is unsupported by mount proof")
    required = {"version", "identity", "rootPublicKey", "provenanceReference", "revision", "contexts",
                "serviceLinks", "intentRevision", "references", "pendingCold", "latestCold"}
    optional = {"current", "currentContext", "currentService", "observedWorker", "pendingService", "serviceReplacement",
                "nativeReplacementAttempted", "latestServiceRequest", "latestServiceConfirmation", "pending", "pendingTakeover",
                "adoptionRetry", "sealed", "terminal", "latestServiceChange"}
    _exact(state, required, optional)
    require(state["version"] == "storage-lifecycle.v2", "invalid checkpoint version")
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        require(state[field] == manifest[field], f"checkpoint/manifest {field} correlation mismatch")
    _uint(state["revision"], 1); _uint(state["intentRevision"])
    identity, root_key = state["identity"], _fingerprint(state["rootPublicKey"])
    for field, maximum in (("contexts", 514), ("serviceLinks", 129), ("references", 128)):
        require(type(state[field]) is list and len(state[field]) <= maximum, f"invalid checkpoint {field} census")
    current, live, service = (state.get(k) for k in ("current", "currentContext", "currentService"))
    pending, latest = state.get("pending"), state.get("latestServiceChange")
    require((current is None) == (live is None), "current controller/context mismatch")
    contexts = {}
    for row in state["contexts"]:
        _exact(row, {"context", "controller"}, {"serviceResult"})
        key = _context(row["context"])
        require(key not in contexts, "duplicate retained context")
        contexts[key] = row
        base = _completed(row["controller"], identity, root_key)
        require(live is not None and row["context"]["controllerEpoch"] <= live["controllerEpoch"]
                and row["controller"]["original"]["signed"]["grant"]["serial"] <= current["original"]["signed"]["grant"]["serial"],
                "future retained controller")
        require(all(row["context"][k] == base[k] for k in ("controllerEpoch", "controllerKey")), "retained controller mismatch")
        if row.get("serviceResult") is not None:
            _link(row["serviceResult"])
            require(row["serviceResult"]["successor"] == row["context"] and row["serviceResult"]["revision"] >
                    row["controller"]["directResult"]["revision"], "invalid folded service result")
        else: require(row["context"] == base, "retained receipt context mismatch")
    links = {}
    for link in state["serviceLinks"]:
        key = _link(link)
        require(key not in links and _context(link["predecessor"]) in contexts and _context(link["successor"]) in contexts,
                "invalid retained service link")
        links[key] = link
    needed_contexts, needed_links = set(), set()
    if current is not None:
        base = _completed(current, identity, root_key)
        key = _context(live); needed_contexts.add(key)
        require(all(base[k] == live[k] for k in ("controllerEpoch", "controllerKey")) and key in contexts
                and contexts[key]["controller"] == current and contexts[key].get("serviceResult") == latest,
                "current retained controller correlation mismatch")
    else:
        require(pending is not None and pending["signed"]["grant"]["operation"] == "initialize"
                and not contexts and not links and latest is None, "missing initialization checkpoint")
    if service is not None:
        require(_service(service, identity, root_key) == live and service["grant"] == current["original"]["signed"]["grant"],
                "current service correlation mismatch")
        if state.get("latestServiceConfirmation") is None:
            require(service["context"]["service_epoch"] == current["directResult"]["service_epoch"] and
                    service["open_revision"] <= current["directResult"]["revision"], "current service revision mismatch")
    else:
        require(not any(state.get(k) is not None for k in ("pendingService", "latestServiceConfirmation", "latestServiceChange")),
                "service retry without service")
    observation = state.get("observedWorker")
    if observation is not None:
        _exact(observation, {"context", "workerUUID"}); _context(observation["context"]); _uuid(observation["workerUUID"])
        require(service is not None and observation["context"] == live, "observed worker context mismatch")
    if pending is not None:
        grant = _original(pending, identity, root_key)
        if current is not None:
            old = current["original"]["signed"]["grant"]
            require(grant["operation"] != "initialize" and grant["serial"] > old["serial"] and grant["id"] != old["id"]
                    and grant["expected_epoch"] == live["controllerEpoch"], "pending controller mismatch")
            if grant["operation"] == "retire":
                require(pending["recipient"] == current["original"]["recipient"] and grant["new_key"] == live["controllerKey"]
                        and pending["serviceEpoch"] == live["serviceEpoch"], "retirement correlation mismatch")
            else:
                require(grant["new_key"] != live["controllerKey"] and pending["recipient"]["incarnation"] !=
                        current["original"]["recipient"]["incarnation"], "takeover recipient mismatch")
    takeover = state.get("pendingTakeover")
    if takeover is not None:
        _exact(takeover, {"requestID", "grantID", "recipient", "expectedEpoch", "serviceEpoch"})
        _uuid(takeover["requestID"]); _uuid(takeover["grantID"]); _uuid(takeover["serviceEpoch"]); _uint(takeover["expectedEpoch"], 1)
        require(current is not None and all(state.get(k) is None for k in ("pending", "pendingService", "sealed", "terminal"))
                and takeover["requestID"] != takeover["grantID"] and takeover["expectedEpoch"] == live["controllerEpoch"]
                and takeover["serviceEpoch"] == live["serviceEpoch"] and _recipient(takeover["recipient"], root_key) != live["controllerKey"]
                and takeover["recipient"]["incarnation"] != current["original"]["recipient"]["incarnation"], "invalid pending takeover")
    retry, confirmation = state.get("latestServiceRequest"), state.get("latestServiceConfirmation")
    require((retry is None) == (confirmation is None), "incomplete service confirmation tuple")
    if state.get("pendingService") is not None:
        request = state["pendingService"]
        _pending_service(request, identity, root_key, current)
        require(all(state.get(k) is None for k in ("pending", "sealed", "terminal")) and request["request"]["predecessor"] == service
                and (confirmation is None or request["request"]["operation_id"] != confirmation["request"]["operation_id"]),
                "pending service mismatch")
    if confirmation is not None:
        _pending_service(retry, identity, root_key, current)
        _exact(confirmation, {"request", "successor"})
        require(confirmation["request"] == retry["request"] and confirmation["successor"] == service, "service confirmation mismatch")
        predecessor = retry["request"]["predecessor"]
        old_context = _service(predecessor, identity, root_key)
        require(latest == dict(operationID=retry["request"]["operation_id"], predecessor=old_context, successor=live,
                              revision=service["open_revision"]), "latest service link mismatch")
        require(service["open_revision"] > max(predecessor["open_revision"], current["directResult"]["revision"])
                and all(service["boot"][k] != predecessor["boot"][k] for k in ("service_epoch", "tls_root_sha256", "server_spki")),
                "service replacement did not advance revision/E/TLS")
        historical = contexts.get(_context(old_context))
        require(historical is not None and historical["controller"] == current, "missing service predecessor")
        if historical.get("serviceResult") is not None:
            require(predecessor["open_revision"] == historical["serviceResult"]["revision"], "folded predecessor revision mismatch")
        else: require(predecessor["open_revision"] <= current["directResult"]["revision"], "predecessor revision mismatch")
    else: require(latest is None, "service link without confirmation")
    replacement = state.get("serviceReplacement")
    if "nativeReplacementAttempted" in state:
        require(state["nativeReplacementAttempted"] is True and replacement is not None, "invalid native replacement fence")
    if replacement is not None:
        request = state.get("pendingService", retry)
        require(request is not None, "replacement without request")
        _exact(replacement, {"predecessor_worker_uuid", "configuration"})
        config = replacement["configuration"]
        _exact(config, {"action", "root_public_key", "signed", "now_unix_seconds", "lifetime_seconds", "reopen"})
        _exact(config["reopen"], {"request", "signature"}); _encoded(config["reopen"]["signature"], 64)
        require(replacement["predecessor_worker_uuid"] == request["predecessorWorkerUUID"] and config == dict(action="open",
                root_public_key=state["rootPublicKey"], signed=current["original"]["signed"], now_unix_seconds=request["nowUnixSeconds"],
                lifetime_seconds=request["lifetimeSeconds"], reopen=dict(request=request["request"], signature=config["reopen"]["signature"])),
                "replacement configuration mismatch")
    if latest is not None:
        key = _link(latest); needed_links.add(key)
        require(key in links and latest["successor"] == live, "latest service link not retained")
    references = state["references"]
    require(not references or state["intentRevision"] > 0, "references without intent revision")
    require(len(_canonical(references)) <= 128 * 2048, "oversized reference census")
    ids = []
    by_id = {}
    for ref in references:
        _exact(ref, {"id", "version", "original", "superseded"}, {"recovery", "predecessor", "successor"})
        _uuid(ref["id"]); _uint(ref["version"], 1); needed_contexts.add(_context(ref["original"]))
        ids.append(ref["id"]); by_id[ref["id"]] = ref
        require(type(ref["superseded"]) is list and len(ref["superseded"]) <= 128, "invalid superseded census")
        for child in ref["superseded"]: _uuid(child)
        require(len(set(ref["superseded"])) == len(ref["superseded"]), "duplicate superseded reference")
        for field in ("predecessor", "successor"):
            if field in ref: _uuid(ref[field])
        if "recovery" in ref:
            recovery = ref["recovery"]
            _exact(recovery, {"serviceEpoch", "controllerEpoch", "controllerKey", "provenanceReference"}, {"workerHistoryReference"})
            ctx = {k: recovery[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")}
            needed_contexts.add(_context(ctx))
            require(recovery["provenanceReference"] == state["provenanceReference"] and "predecessor" in ref, "invalid recovery correlation")
            if "workerHistoryReference" in recovery:
                key = recovery["workerHistoryReference"]; _digest(key); needed_links.add(key)
                require(key in links and links[key]["predecessor"] == ctx and links[key]["successor"] == ref["original"],
                        "invalid worker recovery link")
    require(ids == sorted(set(ids)), "unsorted/duplicate intent references")
    for ref in references:
        if "predecessor" in ref:
            old = by_id.get(ref["predecessor"])
            require(old is not None and (old.get("successor") == ref["id"] or ref["id"] in old["superseded"]), "missing reciprocal predecessor")
            if ref.get("recovery", {}).get("workerHistoryReference") is not None:
                require(old["original"] == links[ref["recovery"]["workerHistoryReference"]]["predecessor"], "worker predecessor mismatch")
        for child in ref["superseded"] + ([ref["successor"]] if "successor" in ref else []):
            require(child in by_id and by_id[child].get("predecessor") == ref["id"] and child != ref["id"], "missing reciprocal successor")
        seen, ancestor = {ref["id"]}, ref.get("predecessor")
        while ancestor is not None:
            require(ancestor not in seen and ancestor in by_id, "cyclic/missing predecessor")
            seen.add(ancestor); ancestor = by_id[ancestor].get("predecessor")
    for key in needed_links:
        require(key in links, "missing required service link")
        needed_contexts.update((_context(links[key]["predecessor"]), _context(links[key]["successor"])))
    _cold_and_adoption(state, manifest, contexts, needed_contexts)
    require(set(contexts) == needed_contexts and set(links) == needed_links, "unreferenced/missing lifecycle history")
    if state.get("sealed") is not None:
        require(pending is not None and pending["signed"]["grant"]["operation"] == "retire", "seal without retirement")
        _receipt(state["sealed"], pending)
        require(state["sealed"]["revision"] > max(current["directResult"]["revision"] if current else 0,
                latest["revision"] if latest else 0), "stale retirement seal")
    if state.get("terminal") is not None:
        require(state.get("sealed") is not None, "terminal without seal"); _receipt(state["terminal"], pending)
        require(all(state["terminal"][k] == state["sealed"][k] for k in ("grant", "service_epoch", "revision")), "terminal seal mismatch")
    reserve = (65536 if state["pendingCold"] is not None else 32768) + 128 * 2048 - len(_canonical(references)) if (
        state["pendingCold"] is not None or state.get("pendingService") is not None) else 16384
    require(len(_canonical(state)) <= MAXIMUM_BYTES - reserve, "checkpoint reservation capacity exceeded")


def _origin(value, manifest):
    _exact(value, {"binding", "rootPublicKey", "shimLaunchUUID", "specSHA256"})
    _uuid(value["shimLaunchUUID"]); _digest(value["specSHA256"])
    from managed_prepare_lifecycle_evidence import manifest_binding
    physical = manifest_binding(manifest)
    require(value["rootPublicKey"] == manifest["rootPublicKey"] and value["binding"] == dict(version="storage-host-binding.v2", store=manifest["identity"]["store"],
            root=physical["root"], backing=physical["backing"]["identity"], bytes=manifest["bytes"], ext4_uuid=manifest["ext4UUID"]),
            "native origin physical binding mismatch")


def _adoption_request(value, manifest):
    _exact(value, {"version", "id", "origin", "expectedEpoch", "daemonAudit", "daemonUniqueID", "controllerAudit", "controllerUniqueID", "superseded"})
    _uuid(value["id"]); _origin(value["origin"], manifest); _uint(value["expectedEpoch"], 1, 2**64 - 2)
    for key in ("daemonUniqueID", "controllerUniqueID"): _uint(value[key], 1)
    daemon, controller = _encoded(value["daemonAudit"], 32), _encoded(value["controllerAudit"], 32)
    require(value["version"] == "storage-lifecycle-adoption.v4" and daemon != controller
            and value["daemonUniqueID"] != value["controllerUniqueID"], "invalid adoption native correlation")
    digest = hashlib.sha256(b"cengine.storage-lifecycle-adoption.owners.v4\0" + daemon + value["daemonUniqueID"].to_bytes(8, "big")
                            + controller + value["controllerUniqueID"].to_bytes(8, "big")).digest()
    if value["superseded"] is not None:
        old = value["superseded"]
        _exact(old, {"id", "epoch", "nativeIdentitySHA256"}); _uuid(old["id"]); _uint(old["epoch"], 2)
        require(old["epoch"] == value["expectedEpoch"] and old["id"] != value["id"] and
                _encoded(old["nativeIdentitySHA256"], 32) != digest, "invalid superseded adoption fence")
    return dict(id=value["id"], epoch=value["expectedEpoch"] + 1, nativeIdentitySHA256=base64.b64encode(digest).decode())


def _cold_request(request, manifest, predecessor, service):
    _exact(request, {"prepare", "recipient", "prepareRequestID", "completionRequestID"})
    for key in ("prepareRequestID", "completionRequestID"): _uuid(request[key])
    root_key = _fingerprint(manifest["rootPublicKey"])
    _completed(predecessor, manifest["identity"], root_key)
    old = _service(service, manifest["identity"], root_key)
    recipient = request["recipient"]; key = _recipient(recipient, root_key)
    prepare = request["prepare"]
    _exact(prepare, {"operationID", "identity", "expectedPredecessor", "expectedOrigin", "expectedAllocatedEpoch", "candidate",
                     "mountedGreeting", "nowUnixSeconds", "lifetimeSeconds"})
    _uuid(prepare["operationID"]); _uint(prepare["expectedAllocatedEpoch"], 1, 2**64 - 2)
    _uint(prepare["nowUnixSeconds"], 1, 253402300799); _uint(prepare["lifetimeSeconds"], 1, 86400)
    _origin(prepare["expectedOrigin"], manifest)
    require(request["prepareRequestID"] != request["completionRequestID"] and prepare["identity"] == manifest["identity"]
            and service["grant"] == predecessor["original"]["signed"]["grant"] and key != old["controllerKey"]
            and old["controllerEpoch"] < 2**64 - 1 and service["grant"]["serial"] < 2**64 - 1
            and prepare["operationID"] != service["grant"]["id"]
            and recipient["incarnation"] != predecessor["original"]["recipient"]["incarnation"], "invalid cold predecessor/recipient")
    require(prepare["expectedPredecessor"] == dict(current_grant=service["grant"], service_epoch=old["serviceEpoch"],
            controller_epoch=old["controllerEpoch"], controller_key=old["controllerKey"], open_revision=service["open_revision"],
            bootstrap_key=root_key), "cold protected predecessor mismatch")
    require(prepare["candidate"] == dict(spki=base64.b64encode(bytes.fromhex("302a300506032b6570032100") +
            _encoded(recipient["publicKey"], 32)).decode(), pid=recipient["childPID"], incarnation=recipient["incarnation"]),
            "cold candidate mismatch")
    greeting = prepare["mountedGreeting"]
    _exact(greeting, {"version", "channelID", "purpose", "daemonUniqueID", "rootPublicKey", "binding", "bootBinding", "launch", "heldBackingIdentity"})
    from managed_prepare_lifecycle_evidence import held_backing_identity
    held_backing_identity(greeting["heldBackingIdentity"], greeting["binding"]["backing"])
    _uuid(greeting["channelID"]); _uint(greeting["daemonUniqueID"], 1)
    launch = greeting["launch"]
    _exact(launch, {"shim_launch_uuid", "spec_sha256", "initramfs_sha256", "ext4_uuid", "bytes"})
    _uuid(launch["shim_launch_uuid"]); _digest(launch["spec_sha256"]); _digest(launch["initramfs_sha256"])
    require(launch["bytes"] == manifest["bytes"] and type(launch["bytes"]) is int and launch["ext4_uuid"] == manifest["ext4UUID"], "cold launch backing mismatch")
    boot = greeting["bootBinding"]
    _exact(boot, {"shimLaunchUUID", "guestBootNonce", "ext4UUID", "bytes"}); _uuid(boot["guestBootNonce"])
    require(boot == dict(shimLaunchUUID=launch["shim_launch_uuid"], guestBootNonce=boot["guestBootNonce"], ext4UUID=manifest["ext4UUID"], bytes=manifest["bytes"])
            and type(boot["bytes"]) is int and greeting["version"] == "storage-lifecycle-cold-shim.v2" and greeting["purpose"] == "cold"
            and greeting["daemonUniqueID"] == recipient["daemonUniqueID"] and greeting["rootPublicKey"] == manifest["rootPublicKey"]
            and greeting["binding"] == prepare["expectedOrigin"]["binding"]
            and launch["shim_launch_uuid"] != prepare["expectedOrigin"]["shimLaunchUUID"], "cold greeting mismatch")


def _cold_prepared(prepared, request, manifest, bridge=None):
    _exact(prepared, {"signedOpen", "successorOrigin", "baseEpoch"}, {"recoveryBridge"})
    require(prepared.get("recoveryBridge") == bridge, "cold prepared recovery bridge mismatch")
    _origin(prepared["successorOrigin"], manifest); _uint(prepared["baseEpoch"], 2)
    signed = prepared["signedOpen"]
    _exact(signed, {"request", "signature"}); _encoded(signed["signature"], 64)
    value, prepare = signed["request"], request["prepare"]
    _exact(value, {"operation_id", "predecessor", "takeover", "launch", "now_unix_seconds", "lifetime_seconds"})
    original = dict(signed=value["takeover"], recipient=request["recipient"], requestID=request["completionRequestID"],
                    serviceEpoch=prepare["expectedPredecessor"]["service_epoch"])
    grant = _original(original, manifest["identity"], _fingerprint(manifest["rootPublicKey"]))
    require(grant["operation"] == "takeover" and grant["id"] == prepare["operationID"]
            and grant["expected_epoch"] == prepare["expectedPredecessor"]["controller_epoch"]
            and grant["serial"] > prepare["expectedPredecessor"]["current_grant"]["serial"]
            and value["operation_id"] == prepare["operationID"] and value["predecessor"] == prepare["expectedPredecessor"]
            and value["launch"] == prepare["mountedGreeting"]["launch"] and value["now_unix_seconds"] == prepare["nowUnixSeconds"]
            and value["lifetime_seconds"] == prepare["lifetimeSeconds"]
            and value["lifetime_seconds"] <= 253402300799 - value["now_unix_seconds"]
            and prepared["baseEpoch"] == prepare["expectedAllocatedEpoch"] + 1, "cold prepared correlation mismatch")
    launch = value["launch"]
    require(prepared["successorOrigin"] == dict(binding=prepare["expectedOrigin"]["binding"], rootPublicKey=manifest["rootPublicKey"],
            shimLaunchUUID=launch["shim_launch_uuid"], specSHA256=launch["spec_sha256"]), "cold successor origin mismatch")


def _cold_signed_digest(prepared):
    return hashlib.sha256(b"cengine.storage-lifecycle-cold-root.signed-open.v1\0" + _canonical(prepared["signedOpen"])).hexdigest()


def _cold_controller(request, prepared, receipt):
    return dict(original=dict(signed=prepared["signedOpen"]["request"]["takeover"], recipient=request["recipient"],
        requestID=request["completionRequestID"], serviceEpoch=receipt["service_epoch"]), directResult=receipt)


def _dead_cold(resolved, state, manifest, contexts, needed_contexts):
    """Correlate one frozen failed attempt, never infer native death/authority."""
    _exact(resolved, {"attempted", "value", "anchor", "anchorService"})
    attempted, value, anchor = resolved["attempted"], resolved["value"], resolved["anchor"]
    _exact(attempted, {"request", "prepared", "bootAttempted", "resolutionRequest"})
    require(attempted["bootAttempted"] is True, "dead cold was not attempted")
    _exact(anchor, {"context", "controller"}, {"serviceResult"})
    request, prepared = attempted["request"], attempted["prepared"]
    _cold_request(request, manifest, anchor["controller"], resolved["anchorService"])
    _cold_prepared(prepared, request, manifest)  # A bridge cannot itself be bridged.
    resolution = attempted["resolutionRequest"]
    _exact(resolution, {"value", "requestID"}); _uuid(resolution["requestID"])
    resolved_request = resolution["value"]
    _exact(resolved_request, {"resolutionID", "identity", "operationID", "signedOpenSHA256"})
    _uuid(resolved_request["resolutionID"]); _uuid(resolved_request["operationID"])
    _digest(resolved_request["signedOpenSHA256"])
    require(resolution["requestID"] not in (request["prepareRequestID"], request["completionRequestID"])
            and resolved_request["identity"] == manifest["identity"]
            and resolved_request["operationID"] == request["prepare"]["operationID"]
            and resolved_request["signedOpenSHA256"] == _cold_signed_digest(prepared)
            and resolved_request["resolutionID"] not in (resolved_request["operationID"],
                anchor["controller"]["original"]["signed"]["grant"]["id"],
                state["current"]["original"]["signed"]["grant"]["id"]), "dead cold resolution correlation mismatch")
    _exact(value, {"request", "anchor", "receipt", "successor", "successorOrigin", "baseEpoch"})
    _origin(value["successorOrigin"], manifest); _uint(value["baseEpoch"], 2)
    require(value["request"] == resolved_request and value["anchor"] == resolved["anchorService"]
            and value["successorOrigin"] == prepared["successorOrigin"] and value["baseEpoch"] == prepared["baseEpoch"],
            "dead cold disposition correlation mismatch")
    root_key = _fingerprint(manifest["rootPublicKey"])
    old = _service(value["anchor"], manifest["identity"], root_key)
    fresh = _service(value["successor"], manifest["identity"], root_key)
    controller = _cold_controller(request, prepared, value["receipt"])
    require(_completed(controller, manifest["identity"], root_key) == fresh
            and value["receipt"]["grant"] == value["successor"]["grant"]
            and value["receipt"]["revision"] == value["successor"]["open_revision"], "dead cold receipt correlation mismatch")
    require(old == anchor["context"] and fresh["controllerEpoch"] == old["controllerEpoch"] + 1
            and fresh["controllerKey"] != old["controllerKey"]
            and value["successor"]["open_revision"] > max(value["anchor"]["open_revision"],
                anchor["controller"]["directResult"]["revision"], anchor.get("serviceResult", {}).get("revision", 0))
            and all(value["successor"]["boot"][k] != value["anchor"]["boot"][k]
                    for k in ("service_epoch", "tls_root_sha256", "server_spki")), "dead cold successor did not advance")
    if anchor.get("serviceResult") is not None:
        require(value["anchor"]["open_revision"] == anchor["serviceResult"]["revision"], "dead cold folded predecessor revision mismatch")
    else:
        require(value["anchor"]["open_revision"] <= anchor["controller"]["directResult"]["revision"], "dead cold predecessor revision mismatch")
    historical = dict(context=fresh, controller=controller)
    anchor_key, dead_key = _context(old), _context(fresh)
    require(contexts.get(anchor_key) == anchor and contexts.get(dead_key) == historical, "missing retained dead cold history")
    needed_contexts.update((anchor_key, dead_key))
    return historical


def _cold_and_adoption(state, manifest, contexts, needed_contexts):
    retry = state.get("adoptionRetry")
    if retry is not None:
        _exact(retry, {"status", "request", "prepareRequestID", "completeRequestID"})
        _uuid(retry["prepareRequestID"]); _uuid(retry["completeRequestID"])
        require(retry["prepareRequestID"] != retry["completeRequestID"], "duplicate adoption request IDs")
        request, status = retry["request"], retry["status"]
        _adoption_request(request, manifest)
        _exact(status, {"origin", "shimAudit", "shimUniqueID", "baseEpoch", "committedEpoch", "allocatedEpoch"}, {"pending", "latest"})
        _origin(status["origin"], manifest); _encoded(status["shimAudit"], 32)
        for key in ("shimUniqueID", "baseEpoch", "committedEpoch", "allocatedEpoch"): _uint(status[key], 1)
        require(status["baseEpoch"] <= status["committedEpoch"] <= status["allocatedEpoch"], "invalid adoption epoch order")
        for field, epoch in (("latest", "committedEpoch"), ("pending", "allocatedEpoch")):
            value = status.get(field)
            if value is not None:
                _adoption_request(value, manifest)
                require(value["origin"] == status["origin"] and value["expectedEpoch"] + 1 == status[epoch]
                        and value["expectedEpoch"] >= status["baseEpoch" if field == "latest" else "committedEpoch"], "adoption status mismatch")
            else:
                require(status[epoch] == status["baseEpoch" if field == "latest" else "committedEpoch"], "missing adoption epoch tuple")
        pending = status.get("pending")
        if pending is not None:
            require(pending["id"] != status.get("latest", {}).get("id") and (pending["superseded"] is not None or
                    pending["expectedEpoch"] == status["committedEpoch"]), "invalid pending adoption")
        require(request["origin"] == status["origin"] and request["expectedEpoch"] == status["allocatedEpoch"]
                and request["superseded"] == (_adoption_request(pending, manifest) if pending is not None else None), "adoption retry correlation mismatch")
    pending = state["pendingCold"]
    if pending is not None:
        _exact(pending, {"request", "bootAttempted"}, {"prepared"})
        require(type(pending["bootAttempted"]) is bool and all(state.get(k) is None for k in
                ("pending", "pendingTakeover", "pendingService", "sealed", "terminal"))
                and state.get("current") is not None and state.get("currentService") is not None, "invalid pending cold fence")
        _cold_request(pending["request"], manifest, state["current"], state["currentService"])
        require(state["latestCold"] is None or pending["request"]["prepare"]["operationID"] != state["latestCold"]["request"]["prepare"]["operationID"], "reused cold operation")
        if "prepared" in pending: _cold_prepared(pending["prepared"], pending["request"], manifest)
        else: require(not pending["bootAttempted"], "cold boot attempted without authorization")
    cold = state["latestCold"]
    if cold is not None:
        _exact(cold, {"request", "prepared", "completion", "predecessor", "predecessorService"}, {"deadPredecessor"})
        bridge = None
        if "deadPredecessor" in cold:
            resolved = cold["deadPredecessor"]
            historical = _dead_cold(resolved, state, manifest, contexts, needed_contexts)
            bridge = resolved["value"]
            require(cold["predecessor"] == historical and cold["predecessorService"] == bridge["successor"],
                    "cold dead predecessor mismatch")
            prepare = cold["request"]["prepare"]
            require(prepare["operationID"] not in (bridge["request"]["operationID"], bridge["request"]["resolutionID"])
                    and cold["prepared"]["baseEpoch"] == bridge["baseEpoch"] + 1
                    and cold["prepared"]["successorOrigin"]["shimLaunchUUID"] != bridge["successorOrigin"]["shimLaunchUUID"],
                    "cold bridge successor correlation mismatch")
        old = cold["predecessor"]
        _exact(old, {"context", "controller"}, {"serviceResult"})
        _cold_request(cold["request"], manifest, old["controller"], cold["predecessorService"])
        _cold_prepared(cold["prepared"], cold["request"], manifest, bridge)
        completion, prepared = cold["completion"], cold["prepared"]
        _exact(completion, {"operationID", "signedOpenSHA256", "successorOrigin", "baseEpoch", "receipt", "successor"}, {"recoveryBridge"})
        require(completion.get("recoveryBridge") == bridge, "cold completion recovery bridge mismatch")
        successor = completion["successor"]
        root_key = _fingerprint(manifest["rootPublicKey"])
        fresh = _service(successor, manifest["identity"], root_key)
        current = _cold_controller(cold["request"], prepared, completion["receipt"])
        require(_completed(current, manifest["identity"], root_key) == fresh, "cold completed controller mismatch")
        expected_digest = _cold_signed_digest(prepared)
        require(completion["operationID"] == cold["request"]["prepare"]["operationID"] and completion["signedOpenSHA256"] == expected_digest
                and completion["successorOrigin"] == prepared["successorOrigin"] and completion["baseEpoch"] == prepared["baseEpoch"]
                and type(completion["baseEpoch"]) is int and completion["receipt"]["revision"] == successor["open_revision"]
                and successor["grant"] == completion["receipt"]["grant"], "cold completion mismatch")
        prior_service = cold["predecessorService"]
        require(_service(prior_service, manifest["identity"], root_key) == old["context"]
                and fresh["controllerEpoch"] == old["context"]["controllerEpoch"] + 1
                and successor["open_revision"] > max(prior_service["open_revision"], old["controller"]["directResult"]["revision"], old.get("serviceResult", {}).get("revision", 0))
                and all(successor["boot"][k] != prior_service["boot"][k] for k in ("service_epoch", "tls_root_sha256", "server_spki")), "cold successor did not advance")
        if old.get("serviceResult") is not None:
            require(prior_service["open_revision"] == old["serviceResult"]["revision"], "cold folded predecessor revision mismatch")
        else: require(prior_service["open_revision"] <= old["controller"]["directResult"]["revision"], "cold predecessor revision mismatch")
        old_key, new_key = _context(old["context"]), _context(fresh)
        require(contexts.get(old_key) == old and new_key in contexts and contexts[new_key]["controller"] == current, "missing retained cold edge")
        needed_contexts.update((old_key, new_key))


def _inspect_backend(root, startup_mode):
    root = Path(root).absolute()
    pin = _ROOT_PINS.get(str(root))
    require(pin is not None, "daemon root was not captured before startup")
    require(startup_mode is None or startup_mode == pin["mode"], "captured startup mode mismatch")
    with ExitStack() as stack:
        opened = []
        def open_entry(name, parent=None, directory=False, backing=False):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if directory: flags |= os.O_DIRECTORY
            fd = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            info = _private(fd, directory, str(name))
            opened.append((fd, name, parent, directory, backing, _stamp(info, directory, backing)))
            return fd
        directory = open_entry(root, directory=True)
        identity = _file_identity(directory)
        require(identity == pin["identity"], "daemon root no longer matches startup pin")
        require("shared-storage-mode.json" not in os.listdir(directory), "retired mode file is unsupported")
        owner = open_entry("managed-storage-owner", directory, directory=True)
        require(set(os.listdir(owner)) == OWNER_FILES, "incomplete/extra lifecycle owner entries; repair required")
        infrastructure = open_entry("infrastructure", directory, directory=True)
        backing = open_entry("volumes.ext4", infrastructure, backing=True)
        lease = open_entry("lease", owner)
        require(os.fstat(lease).st_size == 0, "lifecycle lease must be empty")
        def read_json(name, maximum):
            fd = open_entry(name, owner)
            require(0 < os.fstat(fd).st_size <= maximum, f"invalid {name} size")
            raw = bytearray()
            while len(raw) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
                if not chunk: break
                raw.extend(chunk)
            require(len(raw) <= maximum and len(raw) == os.fstat(fd).st_size, f"oversized/changed {name}")
            return _decode(bytes(raw), name), bytes(raw)
        manifest, raw = read_json("manifest.json", MAXIMUM_BYTES)
        state, _ = read_json("state.json", MAXIMUM_BYTES)
        _exact(manifest, {"version", "identity", "rootPublicKey", "provenanceReference", "root", "backing", "directory", "lease", "bytes", "ext4UUID"})
        require(manifest["version"] == "storage-host-owner.v3", "invalid durable lifecycle version")
        _encoded(manifest["rootPublicKey"], 32); _digest(manifest["provenanceReference"])
        _uint(manifest["bytes"], 1, 2**63 - 1); _uuid(manifest["ext4UUID"])
        binding = manifest["identity"]
        _exact(binding, {"store", "generation", "binding"}); _uuid(binding["store"])
        _uint(binding["generation"], 1); _digest(binding["binding"])
        for field, fd in (("root", directory), ("directory", owner), ("lease", lease), ("backing", backing)):
            actual = _file_identity(fd)
            _exact(manifest[field], {"device", "inode", "volumeUUID"})
            _uint(manifest[field]["device"]); _uint(manifest[field]["inode"])
            require(type(manifest[field]["volumeUUID"]) is str, f"invalid {field} volume UUID")
            require(all(manifest[field][key] == actual[key] for key in ("inode", "volumeUUID")), f"manifest {field} physical identity mismatch")
        require(os.fstat(backing).st_size == manifest["bytes"], "manifest backing physical size mismatch")
        from managed_prepare_lifecycle_evidence import manifest_binding
        require(binding["binding"] == hashlib.sha256(b"cengine.storageauthority.binding.v3\0" + _canonical(manifest_binding(manifest))).hexdigest(),
                "invalid physical binding digest")
        _checkpoint(state, manifest)
        # Revalidate EVERY opened name and descriptor after all reads/decoding.
        for fd, name, parent, is_directory, is_backing, stamp in opened:
            current = _private(fd, is_directory, str(name))
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(_stamp(current, is_directory, is_backing) == stamp == _stamp(named, is_directory, is_backing),
                    f"{name} changed/replaced during lifecycle inspection")
        require(set(os.listdir(owner)) == OWNER_FILES, "lifecycle owner census changed during inspection")
        require("shared-storage-mode.json" not in os.listdir(directory), "retired mode file appeared during inspection")
        return identity, raw


def verify_backend(root, expected_topology, guest_mountinfo, destination="/data", *, startup_mode=None):
    """Return JSON-safe proof; fail closed on missing/mismatched durable selection."""
    require(expected_topology in ("block", "shared"), "invalid topology")
    require(startup_mode in (None, "lifecycle"), "invalid startup selection")
    for key in ("CENGINE_COMPAT_MANAGED_STORAGE", "CENGINE_COMPAT_SHARED_STORAGE"):
        require(key not in os.environ, "retired runner storage selector")
    try:
        identity, raw = _inspect_backend(root, startup_mode)
    except BackendProofError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError, KeyError, RecursionError) as error:
        raise BackendProofError(f"cannot inspect lifecycle backend: {error}") from error
    mount = mount_identity(guest_mountinfo, destination)
    mode = "lifecycle"
    if expected_topology == "block":
        require(mount["filesystem"] == "ext4" and mount["root"] == "/", "not a whole direct ext4 mount")
    else:
        require((mount["filesystem"], mount["source"]) == ("fuse.managed-v3", "managed-v3"),
                "not the selected managed FUSE mount")
    configured = os.environ.get("CENGINE_CORPUS_SHARED_FS")
    if expected_topology == "shared" and configured is not None:
        require(configured == "fuse.managed-v3",
                "shared filesystem override conflicts with durable selection")
    return {"schema": 1, "topology": expected_topology, "mode": mode,
            "lifecycle_manifest_sha256": hashlib.sha256(raw).hexdigest(), "root_identity": identity, "mount": mount}
