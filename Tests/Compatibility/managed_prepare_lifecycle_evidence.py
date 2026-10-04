"""PREPARE lifecycle-v2 comparison evidence, never boot or recovery authority.

The checkpoint is bounded public metadata. ROOT and native process checks remain
production responsibilities; these readers correlate their exact results without
inventing v1 transitions, certificates, or VerifiedStorageServiceBoot values.
"""
import base64
import hashlib
from pathlib import Path
import stat
import subprocess
import uuid

import managed_prepare_faults as p
from managed_storage_recovery import file_identity, runtime_root_path

VERSION = "storage-lifecycle.v2"
MANIFEST_VERSION = "storage-host-owner.v3"
BINDING_VERSION = "storage-host-binding.v2"


def is_v2(record):
    return record.get("format") == VERSION


def read_owner(root, reader):
    root = runtime_root_path(root)
    state, stamp = reader(root / "managed-storage-owner/state.json", 262144)
    if state.get("version") != VERSION:
        # Legacy shape is validated by owner_context/owner_proof at every caller.
        p.require("version" not in state, "unsupported owner evidence version")
        return state, stamp
    manifest, manifest_stamp = reader(root / "managed-storage-owner/manifest.json", 262144)
    value = dict(format=VERSION, checkpoint=state, manifest=manifest)
    owner_context(value)
    return value, p.digest(p.canonical(dict(state=stamp, manifest=manifest_stamp)))


def encoded(value, size):
    p.require(type(value) is str and len(value) == 4 * ((size + 2) // 3), "bounded public bytes")
    raw = base64.b64decode(value, validate=True)
    p.require(len(raw) == size and base64.b64encode(raw).decode() == value, "canonical public bytes")
    return raw


def fingerprint(value):
    return p.digest(bytes.fromhex("302a300506032b6570032100") + encoded(value, 32))


def manifest_binding(manifest):
    def identity(value):
        return dict(inode=value["inode"], volume_uuid=value["volumeUUID"].lower())
    return dict(store_id=manifest["identity"]["store"], root=identity(manifest["root"]),
        backing=dict(identity=identity(manifest["backing"]), size=manifest["bytes"]), expected_ext4_uuid=manifest["ext4UUID"])


def held_backing_identity(value, binding):
    # Live FD observations retain diagnostic device; persistent binding does not.
    p.exact(value, {"device", "inode", "volume_uuid"})
    p.integer(value["device"]); p.integer(value["inode"], minimum=1)
    p.require(dict(inode=value["inode"], volume_uuid=value["volume_uuid"]) == binding,
        "held backing stable identity")


def historical_controller(row, identity, bootstrap):
    """Closed retained v2 controller DTO, not a fabricated legacy replay chain."""
    context, completed = row["context"], row["controller"]
    p.exact(context, {"serviceEpoch", "controllerEpoch", "controllerKey"})
    p.uid(context["serviceEpoch"]); p.integer(context["controllerEpoch"], minimum=1); p.pin(context["controllerKey"])
    p.exact(completed, {"original", "directResult"})
    original, receipt = completed["original"], completed["directResult"]
    p.exact(original, {"signed", "recipient", "requestID"} | ({"serviceEpoch"} if "serviceEpoch" in original else set()))
    p.uid(original["requestID"])
    p.exact(original["signed"], {"grant", "signature"}); encoded(original["signed"]["signature"], 64)
    grant = original["signed"]["grant"]
    p.exact(grant, {"operation", "id", "identity", "serial", "expected_epoch", "new_key"})
    p.uid(grant["id"]); p.integer(grant["serial"], minimum=1); p.integer(grant["expected_epoch"])
    p.require(grant["identity"] == identity and grant["operation"] in ("initialize", "takeover")
        and (grant["operation"] == "initialize") == (grant["expected_epoch"] == 0)
        and grant["expected_epoch"] + 1 == context["controllerEpoch"]
        and grant["new_key"] == context["controllerKey"] != bootstrap, "retained exact controller grant")
    recipient = original["recipient"]
    p.exact(recipient, {"publicKey", "incarnation", "daemonUniqueID", "childUniqueID", "childPID"})
    p.uid(recipient["incarnation"])
    for field in ("daemonUniqueID", "childUniqueID", "childPID"): p.integer(recipient[field], minimum=1)
    p.require(recipient["daemonUniqueID"] != recipient["childUniqueID"]
        and fingerprint(recipient["publicKey"]) == grant["new_key"], "retained exact grant recipient")
    p.exact(receipt, {"grant", "nonce", "service_epoch", "revision"})
    encoded(receipt["nonce"], 32); p.integer(receipt["revision"], minimum=1)
    p.require(receipt["grant"] == grant and receipt["service_epoch"] == context["serviceEpoch"]
        and original.get("serviceEpoch", context["serviceEpoch"] if grant["operation"] == "initialize" else None)
        == context["serviceEpoch"], "retained exact direct ROOT receipt")


def intent_references(state):
    contexts = [p.canonical(row["context"]) for row in state["contexts"]]
    seen = set()
    for row in state["references"]:
        required = {"id", "version", "original", "superseded"}
        p.require(type(row) is dict and required <= set(row) <= required | {"recovery", "predecessor", "successor"},
            "closed intent reference")
        p.uid(row["id"]); p.integer(row["version"], minimum=1)
        p.require(row["id"] not in seen and p.canonical(row["original"]) in contexts, "unique reference to retained context")
        seen.add(row["id"])
        for key in ("predecessor", "successor"):
            if row.get(key) is not None: p.uid(row[key])
        p.require(type(row["superseded"]) is list and len(set(row["superseded"])) == len(row["superseded"]), "closed superseded references")
        for value in row["superseded"]: p.uid(value)
        recovery = row.get("recovery")
        if recovery is not None:
            fields = {"serviceEpoch", "controllerEpoch", "controllerKey", "provenanceReference"}
            p.exact(recovery, fields | ({"workerHistoryReference"} if "workerHistoryReference" in recovery else set()))
            p.require(p.canonical({k: recovery[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")}) in contexts,
                "retained recovery context")
            p.pin(recovery["provenanceReference"])
            p.require(recovery.get("workerHistoryReference") is None, "no same-C worker history in restart campaign")


def owner_context(record):
    p.exact(record, {"format", "checkpoint", "manifest"})
    p.require(is_v2(record), "explicit lifecycle evidence format")
    state, manifest = record["checkpoint"], record["manifest"]
    required = {"version", "identity", "rootPublicKey", "provenanceReference", "revision",
        "current", "currentContext", "currentService", "observedWorker", "contexts", "serviceLinks",
        "intentRevision", "references", "pendingCold", "latestCold"}
    optional = {"pending", "pendingTakeover", "pendingService", "sealed", "terminal", "adoptionRetry",
        "latestServiceRequest", "latestServiceConfirmation", "serviceReplacement", "nativeReplacementAttempted",
        "latestServiceChange"}
    p.require(type(state) is dict and required <= set(state) <= required | optional, "closed checkpoint schema")
    p.exact(manifest, {"version", "identity", "rootPublicKey", "provenanceReference", "root", "backing",
        "directory", "lease", "bytes", "ext4UUID"})
    p.require(state["version"] == VERSION and manifest["version"] == MANIFEST_VERSION, "v2 checkpoint/manifest")
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        p.require(state[field] == manifest[field], "immutable manifest correlation")
    for field in ("pending", "pendingTakeover", "pendingService", "pendingCold", "sealed", "terminal"):
        p.require(state.get(field) is None, "settled lifecycle owner")
    p.require("pendingCold" in state and "latestCold" in state, "explicit cold schema")
    for field in ("contexts", "serviceLinks", "references"):
        p.require(type(state[field]) is list, "required lifecycle census/history")
    p.integer(state["intentRevision"])
    p.require(not state["serviceLinks"], "no unrelated same-C service links in restart campaign")
    for field in ("latestServiceRequest", "latestServiceConfirmation", "serviceReplacement", "nativeReplacementAttempted"):
        p.require(state.get(field) is None, "no unrelated replacement tuple")
    identity = state["identity"]
    p.exact(identity, {"store", "generation", "binding"})
    p.uid(identity["store"]); p.integer(identity["generation"], minimum=1); p.pin(identity["binding"])
    p.pin(state["provenanceReference"]); p.integer(state["revision"], minimum=1)
    for field in ("root", "backing", "directory", "lease"): file_identity(manifest[field])
    p.integer(manifest["bytes"], 2**63 - 1, 1)
    filesystem = manifest["ext4UUID"]
    p.require(type(filesystem) is str and str(uuid.UUID(filesystem)) == filesystem and uuid.UUID(filesystem).int != 0,
        "nonzero canonical ext4 UUID")
    p.require(identity["binding"] == p.digest(b"cengine.storageauthority.binding.v3\0" + p.canonical(manifest_binding(manifest))), "physical manifest binding digest")
    service = state["currentService"]
    p.exact(service, {"grant", "context", "boot", "open_revision"})
    boot, context, grant = service["boot"], service["context"], service["grant"]
    p.exact(boot, {"identity", "service_epoch", "tls_root_sha256", "server_spki", "bootstrap_key"})
    p.exact(context, {"service_epoch", "controller_epoch", "controller_key"})
    p.exact(grant, {"operation", "id", "identity", "serial", "expected_epoch", "new_key"})
    p.uid(grant["id"]); p.integer(grant["serial"], minimum=1); p.integer(grant["expected_epoch"])
    p.require(grant["operation"] in ("initialize", "takeover") and
        (grant["expected_epoch"] == 0) == (grant["operation"] == "initialize"), "controller grant operation")
    p.require(boot["identity"] == grant["identity"] == identity and boot["service_epoch"] == context["service_epoch"], "service identity/E")
    p.uid(context["service_epoch"]); p.integer(context["controller_epoch"], minimum=1)
    for value in (context["controller_key"], grant["new_key"], boot["tls_root_sha256"], boot["server_spki"], boot["bootstrap_key"]): p.pin(value)
    p.require(context["controller_epoch"] == grant["expected_epoch"] + 1 and context["controller_key"] == grant["new_key"]
        and boot["bootstrap_key"] == fingerprint(state["rootPublicKey"]) != context["controller_key"], "exact ROOT/controller fingerprints")
    projected = dict(serviceEpoch=context["service_epoch"], controllerEpoch=context["controller_epoch"], controllerKey=context["controller_key"])
    observation = state["observedWorker"]
    p.exact(observation, {"context", "workerUUID"}); p.uid(observation["workerUUID"])
    for value in (state["currentContext"], observation["context"]):
        p.exact(value, set(projected)); p.integer(value["controllerEpoch"], minimum=1)
        p.require(value == projected, "exact observed worker context")
    for row in state["contexts"]:
        p.exact(row, {"context", "controller"} | ({"serviceResult"} if "serviceResult" in row else set()))
        p.exact(row["context"], set(projected))
        p.require(row.get("serviceResult") is None, "no folded service replacement")
        historical_controller(row, identity, boot["bootstrap_key"])
    p.require(len({p.canonical(row["context"]) for row in state["contexts"]}) == len(state["contexts"]),
        "unique retained contexts")
    intent_references(state)
    current = state["current"]
    p.exact(current, {"original", "directResult"})
    original, receipt = current["original"], current["directResult"]
    p.require(any(row.get("context") == projected and row.get("controller") == current and row.get("serviceResult") is None
        for row in state["contexts"]), "exact retained current controller context")
    p.exact(original, {"signed", "recipient", "requestID"} | ({"serviceEpoch"} if "serviceEpoch" in original else set()))
    if grant["operation"] == "takeover":
        p.require(original.get("serviceEpoch") == context["service_epoch"], "takeover requires selected E")
    p.exact(receipt, {"grant", "nonce", "service_epoch", "revision"})
    p.exact(original["signed"], {"grant", "signature"})
    encoded(original["signed"]["signature"], 64); encoded(receipt["nonce"], 32)
    p.uid(original["requestID"])
    recipient = original["recipient"]
    p.exact(recipient, {"publicKey", "incarnation", "daemonUniqueID", "childUniqueID", "childPID"})
    p.uid(recipient["incarnation"])
    for field in ("daemonUniqueID", "childUniqueID", "childPID"): p.integer(recipient[field], minimum=1)
    p.require(recipient["daemonUniqueID"] != recipient["childUniqueID"] and fingerprint(recipient["publicKey"]) == grant["new_key"], "ROOT grant recipient")
    p.integer(receipt["revision"], minimum=1); p.integer(service["open_revision"], minimum=1)
    # PREPARE restart campaigns do not replace a worker under the same C. Reject
    # that different contract explicitly rather than reinterpret its folded edge.
    p.require(state.get("latestServiceChange") is None and state.get("pendingService") is None, "no same-C worker replacement in restart campaign")
    p.require(receipt["grant"] == original["signed"]["grant"] == grant and
        receipt["service_epoch"] == original.get("serviceEpoch", receipt["service_epoch"]) == context["service_epoch"] and
        receipt["revision"] >= service["open_revision"], "exact ROOT confirmed grant/E/revision")
    owner = dict(format=VERSION, store=identity["store"], root=manifest["root"], backing=manifest["backing"],
        bytes=manifest["bytes"], ext4UUID=filesystem, revision=state["revision"], identity=identity,
        workerUUID=observation["workerUUID"], confirmedRevision=receipt["revision"], **projected)
    origin = None
    if state.get("latestCold") is not None:
        origin = state["latestCold"]["completion"]["successorOrigin"]
        owner["initramfsSHA256"] = state["latestCold"]["request"]["prepare"]["mountedGreeting"]["launch"]["initramfs_sha256"]
        p.pin(owner["initramfsSHA256"])
    if state.get("adoptionRetry") is not None:
        adopted = state["adoptionRetry"]["status"]["origin"]
        p.require(origin is None or adopted == origin, "same retained native origin")
        origin = adopted
    if origin is not None:
        p.exact(origin, {"binding", "rootPublicKey", "shimLaunchUUID", "specSHA256"})
        binding = manifest_binding(manifest)
        expected_binding = dict(version=BINDING_VERSION, store=identity["store"], root=binding["root"], backing=binding["backing"]["identity"],
            bytes=manifest["bytes"], ext4_uuid=filesystem)
        p.require(origin["binding"] == expected_binding and origin["rootPublicKey"] == state["rootPublicKey"],
            "native origin physical binding/ROOT key")
        p.uid(origin["shimLaunchUUID"]); p.pin(origin["specSHA256"])
        owner["shimLaunchUUID"] = origin["shimLaunchUUID"]
        owner["specSHA256"] = origin["specSHA256"]
    return owner, dict(store=identity["store"], **projected)


def public_service(record):
    owner, context = owner_context(record)
    return dict(**context, storeUUID=owner["store"], workerUUID=owner["workerUUID"], revision=owner["confirmedRevision"])


def transition(before, after, arm, *, storage):
    old, context = owner_context(before); new, fresh = owner_context(after)
    a, b = before["checkpoint"], after["checkpoint"]
    p.require(all(context[k] == arm["scope"][k] for k in context), "old actual installed context")
    p.require(before["manifest"] == after["manifest"], "immutable physical manifest")
    p.require(new["revision"] > old["revision"] and fresh["controllerEpoch"] == context["controllerEpoch"] + 1
        and fresh["controllerKey"] != context["controllerKey"] and new["confirmedRevision"] > old["confirmedRevision"], "one ROOT-confirmed C+1")
    previous, current = a["current"], b["current"]
    g0, g1 = previous["original"]["signed"]["grant"], current["original"]["signed"]["grant"]
    p.require(g1["operation"] == "takeover" and g1["id"] != g0["id"] and g1["serial"] > g0["serial"]
        and current["original"]["recipient"]["incarnation"] != previous["original"]["recipient"]["incarnation"], "fresh exact takeover grant/recipient")
    # Checkpoint compaction may discard unreferenced contexts; it may not rewrite
    # a retained predecessor or add unrelated contexts. This is not a v1 chain.
    for row in b["contexts"]:
        if row["context"] != b["currentContext"]:
            p.require(row in a["contexts"], "immutable retained historical context")
    p.require(len([row for row in b["contexts"] if row["context"] == b["currentContext"]]) == 1,
        "one exact successor context")
    old_service, service = a["currentService"], b["currentService"]
    if not storage:
        p.require(fresh["serviceEpoch"] == context["serviceEpoch"] and new["workerUUID"] == old["workerUUID"]
            and service["boot"] == old_service["boot"] and service["open_revision"] == old_service["open_revision"]
            and b["latestCold"] == a["latestCold"], "API-only same E/worker/boot/open revision")
    else:
        p.require(fresh["serviceEpoch"] != context["serviceEpoch"] and new["workerUUID"] != old["workerUUID"]
            and service["open_revision"] > old["confirmedRevision"], "cold fresh E/worker/open revision")
        for field in ("tls_root_sha256", "server_spki"):
            p.require(service["boot"][field] != old_service["boot"][field], "fresh cold TLS")
        cold = b["latestCold"]
        p.require(type(cold) is dict and cold != a["latestCold"], "actual folded cold edge")
        p.require(cold["predecessor"]["controller"] == previous and cold["predecessor"]["context"] == a["currentContext"]
            and cold["predecessorService"] == old_service, "exact cold predecessor")
        p.exact(cold, {"request", "prepared", "completion", "predecessor", "predecessorService"})
        p.exact(cold["request"], {"prepare", "recipient", "prepareRequestID", "completionRequestID"})
        p.uid(cold["request"]["prepareRequestID"])
        p.exact(cold["prepared"], {"signedOpen", "successorOrigin", "baseEpoch"})
        completion = cold["completion"]
        p.exact(completion, {"operationID", "signedOpenSHA256", "successorOrigin", "baseEpoch", "receipt", "successor"})
        signed = cold["prepared"]["signedOpen"]
        p.exact(signed, {"request", "signature"})
        request, prepare = signed["request"], cold["request"]["prepare"]
        p.exact(request, {"operation_id", "predecessor", "takeover", "launch", "now_unix_seconds", "lifetime_seconds"})
        p.exact(prepare, {"operationID", "identity", "expectedPredecessor", "expectedOrigin", "expectedAllocatedEpoch",
            "candidate", "mountedGreeting", "nowUnixSeconds", "lifetimeSeconds"})
        expected_predecessor = dict(current_grant=g0, service_epoch=context["serviceEpoch"],
            controller_epoch=context["controllerEpoch"], controller_key=context["controllerKey"],
            open_revision=old_service["open_revision"], bootstrap_key=old_service["boot"]["bootstrap_key"])
        p.require(request["predecessor"] == prepare["expectedPredecessor"] == expected_predecessor
            and prepare["identity"] == b["identity"], "exact cold protected predecessor/store generation")
        recipient = current["original"]["recipient"]
        # Candidate carries RFC 8410 SPKI DER; recipient carries its raw key.
        spki = base64.b64encode(bytes.fromhex("302a300506032b6570032100")
            + encoded(recipient["publicKey"], 32)).decode()
        p.require(prepare["candidate"] == dict(spki=spki, pid=recipient["childPID"],
            incarnation=recipient["incarnation"]), "exact cold native candidate")
        p.integer(prepare["nowUnixSeconds"], 253402300799, 1); p.integer(prepare["lifetimeSeconds"], 86400, 1)
        p.integer(prepare["expectedAllocatedEpoch"], minimum=1)
        p.require(request["now_unix_seconds"] == prepare["nowUnixSeconds"]
            and request["lifetime_seconds"] == prepare["lifetimeSeconds"], "exact cold configuration time")
        old_origin = prepare["expectedOrigin"]
        p.exact(old_origin, {"binding", "rootPublicKey", "shimLaunchUUID", "specSHA256"})
        p.uid(old_origin["shimLaunchUUID"]); p.pin(old_origin["specSHA256"])
        p.require(old_origin["rootPublicKey"] == a["rootPublicKey"]
            and old_origin["binding"] == completion["successorOrigin"]["binding"]
            and old_origin["shimLaunchUUID"] != new["shimLaunchUUID"], "exact cold origin continuity")
        for field in ("shimLaunchUUID", "specSHA256"):
            if field in old: p.require(old_origin[field] == old[field], "retained predecessor native origin")
        encoded(signed["signature"], 64)
        p.require(completion["operationID"] == cold["request"]["prepare"]["operationID"] == signed["request"]["operation_id"] == g1["id"]
            and completion["signedOpenSHA256"] == p.digest(b"cengine.storage-lifecycle-cold-root.signed-open.v1\0" + p.canonical(signed)), "exact cold operation/signed-open digest")
        p.integer(completion["baseEpoch"], minimum=2)
        p.require(completion["baseEpoch"] == cold["prepared"]["baseEpoch"] == cold["request"]["prepare"]["expectedAllocatedEpoch"] + 1, "exact cold allocation")
        greeting = cold["request"]["prepare"]["mountedGreeting"]
        p.exact(greeting, {"version", "channelID", "purpose", "daemonUniqueID", "rootPublicKey", "binding",
            "bootBinding", "launch", "heldBackingIdentity"})
        held_backing_identity(greeting["heldBackingIdentity"], greeting["binding"]["backing"])
        p.uid(greeting["channelID"]); p.integer(greeting["daemonUniqueID"], minimum=1)
        p.require(greeting["version"] == "storage-lifecycle-cold-shim.v2" and greeting["purpose"] == "cold"
            and greeting["daemonUniqueID"] == current["original"]["recipient"]["daemonUniqueID"]
            and greeting["rootPublicKey"] == b["rootPublicKey"]
            and greeting["binding"] == completion["successorOrigin"]["binding"], "exact mounted physical/native greeting")
        launch = greeting["launch"]
        p.exact(launch, {"shim_launch_uuid", "spec_sha256", "initramfs_sha256", "ext4_uuid", "bytes"})
        binding = greeting["bootBinding"]
        p.exact(binding, {"shimLaunchUUID", "guestBootNonce", "ext4UUID", "bytes"})
        p.uid(binding["guestBootNonce"])
        p.require(binding == dict(shimLaunchUUID=launch["shim_launch_uuid"], guestBootNonce=binding["guestBootNonce"],
            ext4UUID=new["ext4UUID"], bytes=new["bytes"]) and launch["spec_sha256"] == new["specSHA256"],
            "exact cold boot/launch binding")
        p.require(launch == signed["request"]["launch"] and launch["shim_launch_uuid"] == new["shimLaunchUUID"]
            and launch["bytes"] == new["bytes"] and launch["ext4_uuid"] == new["ext4UUID"], "actual cold mounted launch")
        p.require(completion["receipt"] == current["directResult"] and completion["successor"] == service
            and completion["receipt"]["revision"] == service["open_revision"]
            and cold["prepared"]["signedOpen"]["request"]["takeover"] == current["original"]["signed"]
            and cold["request"]["recipient"] == current["original"]["recipient"]
            and cold["request"]["completionRequestID"] == current["original"]["requestID"]
            and completion["successorOrigin"] == cold["prepared"]["successorOrigin"], "exact ROOT cold completion")
    return fresh


def asset_digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()


def host_boot_uuid():
    value = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], check=True,
        capture_output=True, text=True, timeout=5).stdout.strip().lower()
    p.uid(value)
    return value


def storage_target(daemon, owner, census, reader):
    """Select actual FD3 disk/FD4 lifecycle shim; never rewrite it as managed v1."""
    boot_uuid = host_boot_uuid()
    root = runtime_root_path(daemon.root)
    directory = root / "infrastructure/storage-shim-generations"
    candidates = [v for v in census if len(v.arguments) == 10 and v.arguments[1:3] == ("vm-shim", "--spec")
        and Path(v.arguments[3]).parent.parent == directory]
    p.require(len(candidates) == 1, "one actual lifecycle storage shim")
    selected = candidates[0]; p.native_proof(selected)
    path = Path(selected.arguments[3]); launch_id = path.parent.name; p.uid(launch_id)
    p.require(owner.get("shimLaunchUUID", launch_id) == launch_id, "checkpoint native origin launch")
    spec, digest = reader(path); launch, _ = reader(path.parent / "launch.json")
    p.pin(digest)
    p.require(path == directory / launch_id / "spec.json" and Path(selected.executable).resolve() == daemon.binary.resolve()
        and selected.arguments == (str(daemon.binary), "vm-shim", "--spec", str(path), "--spec-sha256", digest,
            "--storage-disk-fd", "3", "--storage-lifecycle-fd", "4"), "exact lifecycle native argv/digest")
    file_identity(spec["rootDiskIdentity"])
    p.require("storageStartupMode" not in spec, "retired storage startup selector")
    p.require(spec["kind"] == "storage" and spec["containerID"] == "cengine-storage"
        and spec["shimLaunchUUID"] == launch_id and spec["rootDiskPath"] == str(root / "infrastructure/volumes.ext4")
        and all(spec["rootDiskIdentity"][key] == owner["backing"][key] for key in ("inode", "volumeUUID")) and spec["rootDiskSize"] == owner["bytes"]
        and spec["rootDiskReadOnly"] is False and not spec["volumeDisks"] and not spec["bindShares"], "exact lifecycle backing/spec")
    p.require(Path(spec["kernelPath"]).resolve() == daemon.kernel.resolve()
        and type(spec["diskBootstrapVersion"]) is int and spec["diskBootstrapVersion"] == 1, "exact lifecycle kernel/bootstrap protocol")
    p.require(Path(spec["initialRamdiskPath"]).resolve() == daemon.storage_initramfs.resolve()
        and spec["expectedInitramfsSHA256"] == asset_digest(daemon.storage_initramfs), "actual pinned lifecycle initramfs")
    p.require(owner.get("initramfsSHA256", spec["expectedInitramfsSHA256"]) == spec["expectedInitramfsSHA256"], "cold mounted initramfs pin")
    disk = (root / "infrastructure/volumes.ext4").lstat()
    p.require(stat.S_ISREG(disk.st_mode) and (disk.st_dev, disk.st_ino, disk.st_size) ==
        (spec["rootDiskIdentity"]["device"], owner["backing"]["inode"], owner["bytes"]), "actual backing inode/size")
    p.exact(launch, {"intent", "process"})
    intent, process = launch["intent"], launch["process"]
    p.exact(intent, {"schemaVersion", "protocolVersion", "launchUUID", "specificationSHA256", "storeIdentity", "generationIdentity"})
    p.exact(process, {"pid", "startSeconds", "startMicroseconds", "uniqueID", "bootUUID"})
    persisted, _ = reader(path.parent / "intent.json")
    p.require(p.canonical(persisted) == p.canonical(intent), "exact immutable launch intent")
    p.integer(intent["schemaVersion"], 1, 1); p.integer(intent["protocolVersion"], 7, 7)
    p.integer(process["pid"], 2**31 - 1, 1); p.integer(process["startSeconds"], minimum=1)
    p.integer(process["startMicroseconds"], 999999); p.integer(process["uniqueID"], minimum=1)
    p.require(process["bootUUID"] == boot_uuid == host_boot_uuid(), "actual native host boot")
    for field, directory_path in (("storeIdentity", root / "infrastructure"), ("generationIdentity", path.parent)):
        identity = intent[field]; file_identity(identity)
        info = directory_path.lstat()
        p.require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (identity["device"], identity["inode"])
            and identity["volumeUUID"].lower() == owner["root"]["volumeUUID"].lower(), "actual store/generation directory identity")
    if "specSHA256" in owner:
        # RawDiskBootTransaction.adoptionSpecification uses this exact sorted,
        # unescaped-slash encoding, unlike the launch file's byte digest.
        p.require(owner["specSHA256"] == p.digest(p.canonical(spec)), "retained native origin specification")
    p.require(intent["specificationSHA256"] == digest and intent["launchUUID"] == launch_id and process["pid"] == selected.pid
        and (process["startSeconds"], process["startMicroseconds"], process["uniqueID"]) == selected.identity, "actual native launch birth")
    return selected
