"""RTM103 original deployed consumer shard; public records never grant authority.

Import is engine-free. Only the live signed paired carrier can produce a result.
This module adds no launcher, key export, process signal, timeout extension or
aggregate acceptance. Current-worker issued-identity Hello cases reuse the same paired fixture before
replacement. WrongV uses two actual runtime mounts; WrongMode uses an independent
authorized writer. Directory FD is not writable-file coverage.
"""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import time
import uuid

import managed_prepare_faults as p
import managed_storage_recovery as recovery
import managed_original_lifecycle_evidence as lifecycle
import managed_retained_backing as backing
import managed_root_backing as root_backing
from managed_retained_reader import RetainedReader
from managed_prepare_service_faults import api_target, storage_target
from managed_prepare_worker_faults import prepared_peer_owner, containment_inventory, surviving_hosts

CASES = (
    "same-e-existing-data", "same-e-retained-fd", "same-e-old-leaf-reconnect",
    "cross-e-existing-data", "cross-e-retained-fd", "cross-e-old-leaf-reconnect",
    "wrong-volume", "wrong-key", "wrong-role", "wrong-mode", "wrong-epoch",
    "cross-mount-root-grant", "retired-root-grant-replay", "attachment-key-reuse",
    "delayed-registration", "replayed-takeover", "legacy-connection", "second-service-exclusivity",
)
IMPLEMENTED = "cross-e-old-leaf-reconnect"
HELLO_CASES = ("wrong-volume", "wrong-key", "wrong-role", "wrong-mode", "wrong-epoch")
REGISTRATION_CASES = ("attachment-key-reuse", "delayed-registration")
SAME_E_CASES = ("same-e-existing-data", "same-e-old-leaf-reconnect")
IMPLEMENTED_CASES = ("cross-e-existing-data", IMPLEMENTED, *HELLO_CASES, *SAME_E_CASES, *backing.FD_CASES, *root_backing.ROOT_CASES, *REGISTRATION_CASES)


def wire_case(case):
    return "issued-identity-" + case if case in HELLO_CASES else case


def original_version(case):
    # v3 requires the live owner's validated GetAttr sequence-1 positive at
    # Arm/Begin; its final negative is sequence 2. The worker stays v3.
    return 6 if case in root_backing.ROOT_CASES else 7 if case == backing.FD_CASES[0] else 5 if case in backing.FD_CASES else 4 if case in (*SAME_E_CASES, *REGISTRATION_CASES) else 3 if case == "cross-e-existing-data" else 2 if case in tuple(wire_case(c) for c in HELLO_CASES) else 1


EVIDENCE_FIELDS = {"arm", "stage", "scope", "keySHA256", "mountIdentitySHA256", "serverDERSHA256",
    "signCount", "signInputSHA256", "bytesWrittenAfterSign", "clientWrittenBytes",
    "clientPrefixBytes", "clientPrefixSHA256", "localError", "fdOperation", "fdSequence", "originalOperation"}
BINDING_FIELDS = {"version", "profile", "requestID", "armDigest", "operationUUID", "caseName", "generation",
    "boot", "scope", "targetAttachment", "key", "certificateSHA256"}


def selection(profile, cases, case):
    p.require(profile == p.FULL_PROFILE and tuple(cases) == CASES, "complete explicit RTM103 catalog required")
    p.require(case in IMPLEMENTED_CASES, "RTM103 case not implemented; absence is not acceptance")
    return dict(rtm="RTM-103", profile=profile, caseName=case, coverage="1/18", fullAcceptance=False,
        missing=[name for name in CASES if name != case])


def runtime_slots(intent, case):
    slots = sorted((s for s in intent["slots"] if s["role"] == "runtime"), key=lambda s: s["attachment"])
    p.require(len(slots) == (2 if case in ("wrong-volume", wire_case("wrong-volume"), *root_backing.ROOT_CASES) else 1), "exact original runtime mount count")
    for slot in slots:
        p.uid(slot["volume"]); p.uid(slot["attachment"]); p.pin(slot["key"])
        p.require(slot.get("receipt") is None, "undrained issued original runtime")
    for key in ("volume", "attachment", "key"):
        p.require(len({s[key] for s in slots}) == len(slots), "distinct runtime " + key)
    if case in ("wrong-mode", wire_case("wrong-mode")):
        p.require(slots[0]["mode"] == "read-only", "actual RO original required")
    return slots


def independent_writer_slot(intent, case, original):
    # Attachment UUID ordering is local to a launch, not a cross-owner volume map.
    matches = [s for s in runtime_slots(intent, case) if s["volume"] == original["volume"]]
    p.require(len(matches) == 1, "one independently authorized same-volume writer")
    slot = matches[0]
    p.require(slot["mode"] == "read-write" and slot["key"] != original["key"]
        and slot["attachment"] != original["attachment"], "independently authorized same-volume writer")
    return slot


def fixture_receipts(manifest, state, plan, container, intent_id, case, extra_plan=None, *, stopped=False):
    """Validate actual journal tuples without projecting a two-mount/RO fixture to RW."""
    if case not in ("wrong-volume", "wrong-mode", *root_backing.ROOT_CASES):
        return p.running_receipts(manifest, state, plan, container, intent_id, stopped=stopped)
    i = state["intents"][intent_id]
    p.require(manifest["store"] == state["store"] == i["store"] and not state["reconciliationRequired"], "same reconciled store")
    p.require(i["container"] == container and i["phase"] == ("retired" if stopped else "running")
        and i["prepareCompleted"] is True and i["cleanUnmount"] is True, "real completed original launch")
    completion = i["guestCompletion"]
    p.require(all(completion[k] == i[k] for k in ("prepare", "containerInstance", "launch"))
        and completion["succeeded"] is True and completion["cleanCopyUp"] is True, "actual clean PREPARE")
    p.pin(completion["evidenceDigest"]); p.pin(i["specificationDigest"])
    p.integer(i["controllerEpoch"], 2**64 - 1, 1); p.integer(state["revision"], 2**64 - 1, 1)
    for key in ("id", "store", "containerInstance", "launch", "serviceEpoch", "prepare"): p.uid(i[key])
    layouts = [(plan, "/data", "read-only" if case == "wrong-mode" else "read-write")]
    if case in ("wrong-volume", *root_backing.ROOT_CASES): layouts.append((extra_plan, "/other", "read-write"))
    mounts = []
    for selected, destination, mode in layouts:
        volumes = [v for v in state["volumes"].values() if v["name"] == selected["volume"]]
        p.require(len(volumes) == 1 and volumes[0].get("createdRevision") is not None
            and all(volumes[0].get(k) is None for k in ("deletedRevision", "localDeletionRevision")), "actual live managed volume")
        mounts.append(dict(volume=p.uid(volumes[0]["id"]), destination=destination, subpath="", mode=mode))
    p.require(i["mounts"] == mounts and len(i["slots"]) == 2 * len(mounts), "complete original mount/slot plan")
    p.require(len({s["attachment"] for s in i["slots"]}) == len(i["slots"]), "unique issued attachments")
    for mount in mounts:
        slots = [s for s in i["slots"] if s["volume"] == mount["volume"]]
        p.require(len(slots) == 2 and {s["role"] for s in slots} == {"prepare", "runtime"}, "exact volume hierarchy")
        for slot in slots:
            p.uid(slot["attachment"]); p.pin(slot["key"])
            p.require(slot["mode"] == ("read-write" if slot["role"] == "prepare" else mount["mode"]), "issued access mode")
            receipt = slot.get("receipt")
            if stopped or slot["role"] == "prepare":
                p.require(type(receipt) is dict and set(receipt) <= {"store", "volume", "attachment", "prepare", "launch", "revision"}
                    and receipt["store"] == i["store"] and receipt["volume"] == slot["volume"]
                    and receipt["attachment"] == slot["attachment"] and receipt.get("launch") == i["launch"]
                    and receipt.get("prepare") == (i["prepare"] if slot["role"] == "prepare" else None), "exact drain receipt")
                p.integer(receipt["revision"], state["revision"], 1)
            else: p.require(receipt is None, "actual undrained runtime")
    if not stopped: runtime_slots(i, case)
    return i


def fixture_mounts(saved, intent, state, plan, case, extra_plan=None):
    p.require(saved["id"] == intent["container"] and str(uuid.UUID(saved["instanceID"])) == intent["containerInstance"], "actual saved container")
    layouts = [(plan, "/data", case == "wrong-mode")]
    if case in ("wrong-volume", *root_backing.ROOT_CASES): layouts.append((extra_plan, "/other", False))
    p.require(len(saved["mounts"]) == len(layouts), "complete saved mount count")
    for selected, destination, readonly in layouts:
        matches = [m for m in saved["mounts"] if m["destination"] == destination]
        p.require(len(matches) == 1, "exact saved destination")
        m = matches[0]
        p.require(m["kind"] == "volume" and m["source"] == selected["volume"] and m["readOnly"] is readonly
            and m["noCopy"] is False and m.get("subpath") in (None, ""), "actual saved volume/mode")
    runtime_slots(intent, case)


def mounted_fixture(value, case):
    from storage_backend_proof import mount_identity
    mounts = []
    for destination in (("/data", "/other") if case in ("wrong-volume", *root_backing.ROOT_CASES) else ("/data",)):
        m = mount_identity(value["mountinfo"], destination)
        p.require((m["filesystem"], m["source"]) == ("fuse.managed-v3", "managed-v3"), "actual managed runtime mount")
        mode = "ro" if case == "wrong-mode" else "rw"
        p.require(mode in m["options"] and ({"ro", "rw"} - {mode}).isdisjoint(m["options"]), "actual runtime mount mode")
        mounts.append(m)
    p.require(len({m["mount_id"] for m in mounts}) == len(mounts), "distinct mounted attachments")


def writer_positive(observe, peer, baseline):
    """Called only around actual owned peer exec; encoded ACKs grant nothing."""
    written = observe("writer", peer)
    p.snapshot(written, "writer", baseline=baseline)
    mounted_fixture(written, "writer")
    # Re-read through the actual RO original immediately after the RW mutation,
    # including exact original bytes/metadata and absence of the fixed marker.
    unchanged = observe("snapshot")
    p.snapshot(unchanged, baseline=baseline)
    mounted_fixture(unchanged, "wrong-mode")


def candidate(value, request, replacement, intent, generation):
    p.exact(value, {"request", "binding", "ownerRequest"})
    owner = value["ownerRequest"]
    p.exact(owner, {"operationUUID", "predecessor", "nowUnixSeconds"})
    p.require(owner["operationUUID"] == replacement["operationUUID"] and owner["predecessor"] == replacement["predecessor"], "exact actual replacement owner")
    p.integer(owner["nowUnixSeconds"], 253402300799, 1)
    p.require(value["request"] == request, "exact live paired capture")
    b = value["binding"]
    p.exact(b, BINDING_FIELDS)
    p.require(b["version"] == original_version(request["caseName"])
        and type(b["version"]) is int and b["profile"] == p.FULL_PROFILE,
        "exact original observer profile")
    for key in ("requestID", "operationUUID", "caseName"):
        p.require(b[key] == request[key], "candidate exact selected request")
    p.integer(b["generation"], minimum=1)
    p.pin(b["armDigest"]); p.pin(b["key"]); p.pin(b["certificateSHA256"])
    p.exact(b["scope"], p.SCOPE)
    p.require(all(intent["id" if key == "intent" else key] == value for key, value in b["scope"].items()), "original live journal scope")
    slots = runtime_slots(intent, request["caseName"])
    slot = slots[0]
    p.require(slot["attachment"] == b["targetAttachment"], "owner-selected smallest runtime attachment")
    p.require(slot["role"] == "runtime" and slot["key"] == b["key"] and slot.get("receipt") is None,
        "actually issued undrained original runtime attachment")
    p.require(b["generation"] == generation and b["boot"]["shimLaunchUUID"] == intent["launch"],
        "original native shim generation")
    p.exact(b["boot"], {"shimLaunchUUID", "guestBootNonce"})
    p.uid(b["boot"]["guestBootNonce"])
    return b


FRESH_GETATTR_CASES = ("same-e-existing-data", "cross-e-existing-data", "same-e-old-leaf-reconnect", *REGISTRATION_CASES)


def fresh_getattr(value, original, current, boot, generation):
    """Actual sealed current-client wire reply, not the mounted snapshot/stat."""
    p.exact(value, {"original", "binding", "service", "serverDERSHA256", "evidence", "released"})
    p.require(original["caseName"] in FRESH_GETATTR_CASES and value["released"] is True
        and p.canonical(value["original"]) == p.canonical(original), "released fresh proof for exact original")
    b, ready = value["binding"], boot["ready"]
    p.exact(b, BINDING_FIELDS); p.integer(b["version"], 4, 4); p.integer(b["generation"], minimum=1)
    p.require(b["profile"] == p.FULL_PROFILE and b["caseName"] == "same-e-existing-data"
        and all(b[k] == original[k] for k in ("requestID", "operationUUID", "armDigest")), "fixed positive-only v4 carrier")
    scope = {k: current["id" if k == "intent" else k] for k in p.SCOPE}
    p.require(p.canonical(b["scope"]) == p.canonical(scope) and current["phase"] == "running"
        and current["prepareCompleted"] is True, "actual fresh running journal")
    p.require(all(scope[k] == original["scope"][k] for k in ("store", "container", "containerInstance"))
        and all(scope[k] != original["scope"][k] for k in ("intent", "launch", "serviceEpoch")), "same workload, new issued current owner")
    p.require(b["generation"] == generation and generation != original["generation"], "actual fresh native generation")
    p.exact(b["boot"], {"shimLaunchUUID", "guestBootNonce"}); p.uid(b["boot"]["guestBootNonce"])
    p.require(b["boot"]["shimLaunchUUID"] == scope["launch"] and b["boot"] != original["boot"], "fresh sealed guest boot")
    slot = runtime_slots(current, "fresh-getattr")[0]
    p.require(slot["attachment"] == b["targetAttachment"] and slot["key"] == b["key"], "actual fresh issued slot")
    for key in ("key", "certificateSHA256"):
        p.pin(b[key]); p.require(b[key] != original[key], "no original credential reuse")
    p.require(b["targetAttachment"] != original["targetAttachment"], "new attachment")
    p.require(p.canonical(value["service"]) == p.canonical({k: ready[k] for k in ("serviceEpoch", "workerUUID")})
        and all(scope[k] == ready[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey"))
        and scope["store"] == ready["storeUUID"], "exact published successor service")
    from managed_prepare_storage_vm_faults import bounded_base64
    p.require(value["serverDERSHA256"] == p.digest(bounded_base64(ready["serverDER"], 16384)), "actual fresh peer pin")
    e = value["evidence"]; p.exact(e, EVIDENCE_FIELDS | {"rootRequest"})
    arm = dict(version=4, profile=p.FULL_PROFILE, requestID=b["requestID"], operationUUID=b["operationUUID"],
        caseName=b["caseName"], binding=b["boot"], scope=scope, targetAttachment=b["targetAttachment"], leafSHA256=b["certificateSHA256"])
    p.require(p.canonical(e["arm"]) == p.canonical(arm) and p.canonical(e["scope"]) == p.canonical(scope)
        and e["keySHA256"] == b["key"] and e["stage"] == "armed-mounted-positive", "actual fresh mounted Arm")
    p.pin(e["mountIdentitySHA256"])
    p.require(e["fdOperation"] == "fsync-directory", "unchanged carrier mount prerequisite")
    p.integer(e["fdSequence"], 1, 1)
    p.require(p.canonical(e["originalOperation"]) == p.canonical(dict(kind="data-getattr-root", sequence=1, errorClass="ok")), "successful actual matching wire GETATTR")
    p.exact(e["rootRequest"], {"node", "requestSequence"})
    for field in e["rootRequest"]: p.integer(e["rootRequest"][field], 2**64 - 1, 1)
    for field in ("signCount", "bytesWrittenAfterSign", "clientWrittenBytes", "clientPrefixBytes"): p.integer(e[field], 0, 0)
    for field in ("serverDERSHA256", "signInputSHA256", "clientPrefixSHA256", "localError"): p.require(e[field] == "", "no substituted negative/signature")
    return value


def correlated_result(value, binding, intent, successor_boot, baseline_ack=None):
    """Reject mismatches only; called on fresh FD-pinned live-carrier bytes."""
    version = original_version(binding["caseName"])
    p.integer(binding["version"], version, version)
    if binding["caseName"] in root_backing.ROOT_CASES:
        from managed_root_projection import result
        return result(value, binding, intent, successor_boot, EVIDENCE_FIELDS, baseline_ack)
    if binding["caseName"] in backing.FD_CASES:
        from managed_retained_projection import result
        return result(value, binding, intent, successor_boot, EVIDENCE_FIELDS, baseline_ack)
    p.integer(value["original"]["arm"]["version"], version, version)
    if binding["caseName"] in (*SAME_E_CASES, *REGISTRATION_CASES):
        return correlated_same_e_result(value, binding, intent, successor_boot)
    if binding["caseName"] in tuple(wire_case(case) for case in HELLO_CASES):
        return correlated_hello_result(value, binding, intent, successor_boot)
    p.exact(value, {"worker", "original"})
    worker, original = value["worker"], value["original"]
    p.exact(worker, {"query", "state", "selectedCount", "evidence"})
    p.require(worker["state"] == "finalized" and type(worker["selectedCount"]) is int and worker["selectedCount"] == 1,
        "one actual atomically finalized worker observation")
    q, e = worker["query"], worker["evidence"]
    p.exact(q, {"version", "profile", "requestID", "armDigest", "operationUUID", "caseName", "originalBootBinding",
        "original", "originalLeafSHA256", "workerScope"})
    case = binding["caseName"]
    p.require(case in IMPLEMENTED_CASES, "unsupported original case")
    slot = next(s for s in intent["slots"] if s["attachment"] == binding["targetAttachment"])
    runtime = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"], container=intent["container"],
        launch=intent["launch"], key=slot["key"], role="runtime", mode=slot["mode"])
    ready = successor_boot["ready"]
    expected = dict(version=3, profile=p.FULL_PROFILE, requestID=binding["requestID"], armDigest=binding["armDigest"],
        operationUUID=binding["operationUUID"], caseName=IMPLEMENTED, originalBootBinding=binding["boot"],
        original=dict(epoch=intent["serviceEpoch"], binding=runtime), originalLeafSHA256=binding["certificateSHA256"],
        workerScope={k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    p.require(q == expected, "worker actual original leaf/current successor correlation")
    p.exact(e, {"stage", "errorClass", "storeUUID", "serviceEpoch", "rejectedLeafSHA256", "byteCount", "prefixSHA256"})
    p.require(e["stage"] == "tls-client-certificate" and e["errorClass"] == "unknown-authority"
        and e["storeUUID"] == intent["store"] and e["serviceEpoch"] == ready["serviceEpoch"]
        and e["rejectedLeafSHA256"] == binding["certificateSHA256"], "actual successor certificate-verification denial")
    p.integer(e["byteCount"], 131072, 1); p.pin(e["prefixSHA256"])
    p.exact(original, EVIDENCE_FIELDS)
    arm = dict(version=version, profile=p.FULL_PROFILE, requestID=binding["requestID"], operationUUID=binding["operationUUID"],
        caseName=case, binding=binding["boot"], scope=binding["scope"], targetAttachment=binding["targetAttachment"],
        leafSHA256=binding["certificateSHA256"])
    scope = {**binding["scope"], **{k: ready[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")}}
    p.require(original["arm"] == arm and original["scope"] == scope and original["stage"] == "original-owner-prefix-correlated"
        and original["keySHA256"] == binding["key"] and original["fdOperation"] == "fsync-directory"
        and original["fdSequence"] == (2 if case == "cross-e-retained-fd" else 1)
        and type(original["fdSequence"]) is int, "same mounted original owner")
    operation = original["originalOperation"]
    p.exact(operation, {"kind", "sequence", "errorClass"})
    p.integer(operation["sequence"], 2)
    if case == IMPLEMENTED:
        p.require(operation == dict(kind="", sequence=0, errorClass=""), "no extra old-leaf operation")
    elif case == "cross-e-existing-data":
        # No positive field is added to the final schema: only the live Swift
        # owner can publish this v3 result after validating actual Arm/Begin
        # GetAttr sequence 1 / ok. A legacy v1 negative cannot stand in for it.
        p.require(operation == dict(kind="data-getattr-root", sequence=2, errorClass="client-closed-joined"),
            "original mounted DATA second operation joined rejection; not successor authentication")
    else:
        p.require(operation["kind"] == "fsync-directory" and operation["sequence"] == 2
            and operation["errorClass"] in ("eio", "enotconn", "estale", "eacces"), "exact retained FD rejection")
    p.pin(original["mountIdentitySHA256"]); p.pin(original["signInputSHA256"])
    from managed_prepare_storage_vm_faults import bounded_base64
    p.require(original["serverDERSHA256"] == p.digest(bounded_base64(ready["serverDER"], 16384)), "exact authenticated successor public server")
    p.require(original["signCount"] == 1 and type(original["signCount"]) is int, "one original private signer use")
    p.integer(original["clientWrittenBytes"], 131072, 1)
    p.integer(original["bytesWrittenAfterSign"], original["clientWrittenBytes"], 1)
    p.integer(original["clientPrefixBytes"], original["clientWrittenBytes"], 1)
    p.require(original["clientPrefixBytes"] == e["byteCount"] <= original["clientWrittenBytes"]
        and original["clientPrefixSHA256"] == e["prefixSHA256"]
        and original["localError"] in ("eof", "tls-alert-or-transport"), "actual worker-read prefix matches privately retained signed flight")
    return value


def correlated_same_e_result(value, binding, intent, predecessor_boot):
    """Current verified authority denial after the owner's real persisted Retire.

    This validates live-carrier records; encoded receipts do not grant authority.
    Actual original positive/begin and increasing DATA sequence are independently
    required by the sealed Swift owner before this post-containment publication.
    """
    registration = binding["caseName"] in REGISTRATION_CASES
    p.exact(value, {"worker", "original", "retirement"} | ({"positive", "registration"} if registration else set()))
    worker, original, retired = value["worker"], value["original"], value["retirement"]
    p.exact(worker, {"query", "state", "selectedCount", "evidence"})
    p.require(worker["state"] == "finalized", "atomic same-E finalization")
    p.integer(worker["selectedCount"], 1, 1)
    case, ready = binding["caseName"], predecessor_boot["ready"]
    p.require(case in (*SAME_E_CASES, *REGISTRATION_CASES) and ready["serviceEpoch"] == intent["serviceEpoch"]
        and ready["storeUUID"] == intent["store"]
        and ready["controllerEpoch"] == intent["controllerEpoch"]
        and ready["controllerKey"] == intent["controllerKey"], "unchanged original service/controller")
    slot = runtime_slots(intent, case)[0]
    p.require(slot["attachment"] == binding["targetAttachment"] and slot["key"] == binding["key"], "exact original mounted identity")
    runtime = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"],
        container=intent["container"], launch=intent["launch"], key=slot["key"], role="runtime", mode=slot["mode"])
    issued = dict(epoch=intent["serviceEpoch"], binding=runtime)
    query = dict(version=6 if case == SAME_E_CASES[0] or registration else 5, profile=p.FULL_PROFILE,
        requestID=binding["requestID"], armDigest=binding["armDigest"], operationUUID=binding["operationUUID"],
        caseName=SAME_E_CASES[0] if registration else case, originalBootBinding=binding["boot"], original=issued,
        originalLeafSHA256=binding["certificateSHA256"],
        workerScope={k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    p.integer(worker["query"]["version"], query["version"], query["version"])
    p.require(worker["query"] == query, "exact unchanged sealed worker and original tuple")
    p.exact(retired, {"operation", "receipt", "queryRevision", "epoch", "controller", "attachment"})
    p.uid(retired["operation"])
    p.require(retired["operation"] == slot["retireOperation"], "actual preassigned original slot retirement operation")
    receipt = retired["receipt"]
    p.exact(receipt, {"schema", "store", "volume", "attachment", "launch", "revision"})
    p.integer(receipt["schema"], 3, 3)
    p.integer(retired["queryRevision"], 2**64 - 1, 1)
    p.integer(receipt["revision"], retired["queryRevision"], 1)
    p.require(all(receipt[k] == runtime[k] for k in ("store", "volume", "attachment", "launch")), "exact real runtime receipt")
    p.require(retired["epoch"] == intent["serviceEpoch"] and retired["controller"] ==
        dict(epoch=intent["controllerEpoch"], key=intent["controllerKey"]), "receipt independently queried under original controller")
    p.integer(retired["controller"]["epoch"], 2**64 - 1, 1)
    p.require(retired["attachment"] == dict(binding=runtime, phase="DRAINED", receipt=receipt,
        retirement=retired["operation"]), "exact independently queried drained attachment")
    p.integer(retired["attachment"]["receipt"]["schema"], 3, 3)
    p.integer(retired["attachment"]["receipt"]["revision"], retired["queryRevision"], 1)
    e = worker["evidence"]
    base_fields = {"stage", "errorClass", "storeUUID", "serviceEpoch", "rejectedLeafSHA256"}
    data_case = case == SAME_E_CASES[0] or registration
    p.exact(e, base_fields | ({"admission"} if data_case else {"hello"}))
    p.require(e["stage"] == ("request-admit" if data_case else "authenticate-data") and e["errorClass"] == "blocked"
        and e["storeUUID"] == intent["store"] and e["serviceEpoch"] == intent["serviceEpoch"]
        and e["rejectedLeafSHA256"] == binding["certificateSHA256"], "actual attributable blocked authority boundary")
    p.exact(original, EVIDENCE_FIELDS | {"rootRequest"} | (set() if data_case else {"hello"}))
    arm = dict(version=4, profile=p.FULL_PROFILE, requestID=binding["requestID"], operationUUID=binding["operationUUID"],
        caseName=case, binding=binding["boot"], scope=binding["scope"], targetAttachment=binding["targetAttachment"],
        leafSHA256=binding["certificateSHA256"])
    p.require(original["arm"] == arm and original["scope"] == binding["scope"]
        and original["keySHA256"] == binding["key"] and original["fdOperation"] == "fsync-directory", "same retained mounted original")
    p.integer(original["fdSequence"], 1, 1)
    p.pin(original["mountIdentitySHA256"])
    from managed_prepare_storage_vm_faults import bounded_base64
    p.require(original["serverDERSHA256"] == p.digest(bounded_base64(ready["serverDER"], 16384)), "exact unchanged TLS server")
    p.integer(original["clientPrefixBytes"], 0, 0)
    p.require(original["clientPrefixSHA256"] == "", "same-E is not old-worker TLS prefix proof")
    root = original["rootRequest"]
    p.exact(root, {"node", "requestSequence"})
    p.integer(root["node"], 2**64 - 1, 1); p.integer(root["requestSequence"], 2**64 - 1, 2 if data_case else 1)
    operation = original["originalOperation"]
    p.exact(operation, {"kind", "sequence", "errorClass"}); p.integer(operation["sequence"], 2, 2)
    if data_case:
        admission = e["admission"]
        p.exact(admission, {"original", "requestSequence", "operation", "node", "authKind", "noHandle"})
        p.integer(admission["requestSequence"], 2**64 - 1, 2); p.integer(admission["node"], 2**64 - 1, 1)
        p.integer(admission["authKind"], 3, 3)
        p.require(admission == dict(original=issued, requestSequence=root["requestSequence"],
            operation="get_attr", node=root["node"], authKind=3, noHandle=True) and admission["noHandle"] is True,
            "actual same original GETATTR sequence/node/auth denied by Admit")
        p.require(original["stage"] == "original-data-attempt" and original["localError"] == ""
            and operation == dict(kind="data-getattr-root", sequence=2, errorClass="transport-failed"), "authentic original DATA attempt")
        for field in ("signCount", "bytesWrittenAfterSign", "clientWrittenBytes"): p.integer(original[field], 0, 0)
        p.require(original["signInputSHA256"] == "", "no substituted reconnect for existing DATA")
    else:
        p.require(e["hello"] == original["hello"] == issued, "exact original verified Hello, no changed-Hello substitution")
        p.require(original["stage"] == "original-owner-signed-flight"
            and operation == dict(kind="data-original-hello", sequence=2, errorClass="peer-closed-before-root")
            and original["localError"] in ("eof", "tls-alert-or-transport"), "exact original reconnect observation")
        p.integer(original["signCount"], 1, 1); p.pin(original["signInputSHA256"])
        p.integer(original["clientWrittenBytes"], 131072, 1)
        p.integer(original["bytesWrittenAfterSign"], original["clientWrittenBytes"], 1)
    if registration:
        from managed_registration_projection import validate
        validate(value, binding, intent, predecessor_boot)
    return value


def correlated_hello_result(value, binding, intent, predecessor_boot):
    """Current-service verifyPeer denial, never successor unknown-CA/EOF proof."""
    p.exact(value, {"worker", "original"})
    worker, original = value["worker"], value["original"]
    p.exact(worker, {"query", "state", "selectedCount", "evidence"})
    p.require(worker["state"] == "finalized" and type(worker["selectedCount"]) is int
        and worker["selectedCount"] == 1, "one finalized current worker observation")
    name = binding["caseName"]
    p.require(name in tuple(wire_case(case) for case in HELLO_CASES), "finite issued identity case")
    ready = predecessor_boot["ready"]
    p.require(ready["serviceEpoch"] == intent["serviceEpoch"] and ready["storeUUID"] == intent["store"],
        "actual CURRENT service, not replacement trust")
    slots = runtime_slots(intent, name)
    slot = slots[0]
    p.require(slot["attachment"] == binding["targetAttachment"] and slot["key"] == binding["key"], "exact primary runtime attachment/key")
    runtime = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"],
        container=intent["container"], launch=intent["launch"], key=slot["key"], role="runtime", mode=slot["mode"])
    issued = dict(epoch=intent["serviceEpoch"], binding=runtime)
    query = dict(version=4, profile=p.FULL_PROFILE, requestID=binding["requestID"], armDigest=binding["armDigest"],
        operationUUID=binding["operationUUID"], caseName=name, originalBootBinding=binding["boot"],
        original=issued, originalLeafSHA256=binding["certificateSHA256"],
        workerScope={k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    p.require(worker["query"] == query, "complete current worker/original issued tuple")
    hello = dict(epoch=issued["epoch"], binding=dict(runtime))
    if name == wire_case("wrong-volume"):
        hello["binding"]["volume"] = slots[1]["volume"]
    elif name == wire_case("wrong-mode"):
        hello["binding"]["mode"] = "read-write"
    elif name == wire_case("wrong-key"):
        alternatives = [s for s in sorted(intent["slots"], key=lambda s: s["attachment"])
            if s.get("key") is not None and s["key"] != slot["key"]]
        p.require(bool(alternatives), "another actually issued original key")
        p.pin(alternatives[0]["key"])
        hello["binding"]["key"] = alternatives[0]["key"]
    elif name == wire_case("wrong-role"):
        p.require(any(s["role"] == "prepare" and s["volume"] == slot["volume"] and s.get("key") is not None
            for s in intent["slots"]), "real originally issued PREPARE")
        hello["binding"].update(role="prepare", prepare=p.uid(intent["prepare"]))
    else:
        hello["epoch"] = ("1" if issued["epoch"][0] == "0" else "0") + issued["epoch"][1:]
        p.uid(hello["epoch"])
    evidence = worker["evidence"]
    p.exact(evidence, {"stage", "errorClass", "storeUUID", "serviceEpoch", "rejectedLeafSHA256", "byteCount", "prefixSHA256", "hello"})
    p.require(evidence["stage"] == "pki-verify-peer" and evidence["errorClass"] == "unauthorized"
        and evidence["storeUUID"] == intent["store"] and evidence["serviceEpoch"] == intent["serviceEpoch"]
        and evidence["rejectedLeafSHA256"] == binding["certificateSHA256"] and evidence["hello"] == hello,
        "actual exact issued-leaf Hello rejection before registry authentication")
    p.integer(evidence["byteCount"], 131072, 1); p.pin(evidence["prefixSHA256"])
    p.exact(original, EVIDENCE_FIELDS | {"hello"})
    arm = dict(version=2, profile=p.FULL_PROFILE, requestID=binding["requestID"], operationUUID=binding["operationUUID"],
        caseName=name, binding=binding["boot"], scope=binding["scope"], targetAttachment=binding["targetAttachment"],
        leafSHA256=binding["certificateSHA256"])
    p.require(original["arm"] == arm and original["scope"] == binding["scope"]
        and original["stage"] == "original-owner-prefix-correlated" and original["hello"] == hello
        and original["keySHA256"] == binding["key"] and original["fdOperation"] == "fsync-directory"
        and type(original["fdSequence"]) is int and original["fdSequence"] == 1, "same actual original mounted owner")
    operation = original["originalOperation"]
    p.exact(operation, {"kind", "sequence", "errorClass"}); p.integer(operation["sequence"], 1, 1)
    p.require(operation == dict(kind="data-wrong-hello", sequence=1, errorClass="peer-closed-before-root"),
        "original local observation remains separate from actual worker denial")
    from managed_prepare_storage_vm_faults import bounded_base64
    p.require(original["serverDERSHA256"] == p.digest(bounded_base64(ready["serverDER"], 16384)), "exact current TLS peer")
    p.pin(original["mountIdentitySHA256"]); p.pin(original["signInputSHA256"])
    p.require(type(original["signCount"]) is int and original["signCount"] == 1, "actual private signer used once")
    p.integer(original["clientWrittenBytes"], 131072, 1)
    p.integer(original["bytesWrittenAfterSign"], original["clientWrittenBytes"], 1)
    p.integer(original["clientPrefixBytes"], original["clientWrittenBytes"], 1)
    p.require(original["clientPrefixBytes"] == evidence["byteCount"]
        and original["clientPrefixSHA256"] == evidence["prefixSHA256"]
        and original["localError"] in ("eof", "tls-alert-or-transport"), "same private flight/Hello read by current worker")
    return value


def observes_predecessor(case):
    """Registration denial/old GETATTR belong to the unchanged current worker."""
    return case in (*HELLO_CASES, *SAME_E_CASES, *REGISTRATION_CASES,
                    "same-e-retained-fd", *root_backing.ROOT_CASES)


def run_live(daemon, *, staged, client, container, peer, peer_plan, image, volume, plan, config,
             normal, normal_process, saved, baseline, manifest, read_state, observe, target,
             start_request, joined_start, wait_exit, processes, remaining, ledger, files, record, extra_volume=None, extra_plan=None, lifecycle_peer_reader=None):
    """Invoked inside the paired fixture after its real mounted NORMAL.

    V2 callers must supply lifecycle_peer_reader(projection), returning the
    independently retained/revalidated actual public TLS peer for that service.
    The shared fixture does not yet provide this input; absence fails closed.
    """
    import harness
    case = staged["caseName"]
    p.require(staged == selection(p.FULL_PROFILE, CASES, case), "exact finite original-consumer selection")
    before, before_hash = lifecycle.read_owner(daemon.root, recovery.read_public)
    old, oldboot = lifecycle.owner(before)
    oldboot = lifecycle.peer_comparison(oldboot, lifecycle_peer_reader)
    p.require(not lifecycle.history(before), "fresh single replacement history")
    p.require(normal["store"] == old["store"] and all(normal[k] == oldboot["ready"][k]
        for k in ("serviceEpoch", "controllerEpoch", "controllerKey")),
        "original running consumer belongs to exact predecessor service/controller")
    operation, request_id = str(uuid.uuid4()), str(uuid.uuid4())
    replacement, raw = recovery.worker_request(operation, old["store"], {k: old[k] for k in ("serviceEpoch", "workerUUID")})
    slots = runtime_slots(normal, case)
    writer = None
    writer_process = None
    root_case = case in root_backing.ROOT_CASES
    retained_before = retained_after = baseline_ack = None
    if case == "wrong-mode" or case in backing.FD_CASES or root_case:
        with prepared_peer_owner(daemon, peer, peer_plan, manifest["root"], processes()) as (prepared, _, validate):
            validate(); joined_start(start_request(peer))
        wait_exit(prepared)
        manifest, writer_state, hashes = read_state()
        writers = [i for i in writer_state["intents"].values() if i["container"] == peer.id and i["phase"] == "running"]
        p.require(len(writers) == 1, "one independent actual writer")
        writer = writers[0]
        fixture_receipts(manifest, writer_state, peer_plan, peer.id, writer["id"], case if root_case else "writer", extra_plan)
        writer_slot = independent_writer_slot(writer, case if root_case else "writer", slots[0])
        with p.workload_owner(target(writer), daemon, peer_plan, writer, manifest["root"]) as (native, _, validate):
            validate()
            if root_case:
                root_backing.unchanged(observe("root-snapshot"), baseline)
                retained_before = root_backing.unchanged(observe("root-snapshot", peer), baseline)
            else:
                p.snapshot(observe("snapshot"), baseline=baseline)
            if case in backing.FD_CASES:
                retained_before = backing.retained_snapshot(observe("retained-snapshot", peer))
            elif not root_case:
                writer_positive(observe, peer, baseline)
            record("original-consumer-writer-before", native=native, journal=hashes, intent=writer["id"],
                operation="independent-prepositive-snapshot" if case in backing.FD_CASES or root_case else "exclusive-marker-write-fsync-readback-unlink-parent-fsync")
    capture = dict(version=1, profile=p.FULL_PROFILE, requestID=request_id, operationUUID=operation, caseName=wire_case(case),
        container=container.id, containerInstance=normal["containerInstance"])
    census = processes()
    api = api_target(daemon, harness._kernel_process(daemon.process.pid))
    storage = storage_target(daemon, old, census)
    with ExitStack() as stack:
        queue = stack.enter_context(p.Directory(daemon.root / "managed-prepare-compatibility"))
        replacement_queue, validate_replacement = stack.enter_context(recovery.replacement_queue(daemon.root, old["root"]))
        if writer is None:
            peer_native, peer_proof, validate_peer = stack.enter_context(prepared_peer_owner(daemon, peer, peer_plan, manifest["root"], census))
        else:
            peer_native = target(writer)
            peer_proof, _, validate_peer = stack.enter_context(p.workload_owner(peer_native, daemon, peer_plan, writer, manifest["root"]))
        _, _, validate_original = stack.enter_context(p.workload_owner(normal_process, daemon, plan, normal, manifest["root"]))
        owned = [container.id, peer.id]
        containment_inventory(daemon, owned, census, normal_process, peer_native, peer_proof, validate_peer)
        validate_original(); p.verify_full_ledger(ledger, files)
        record("original-consumer-request", request=capture, ownerSHA256=before_hash, native=p.native_proof(normal_process))
        reader = None
        if case in backing.FD_CASES or root_case:
            validate_peer()
            reader = (root_backing.RootBackingReader if root_case else RetainedReader)(client.api, peer, remaining)
            stack.callback(reader.close)
        queue.publish("original-consumer.capture.json", capture)
        submitted = int(time.time())
        marker = recovery.publish_worker_request(replacement_queue, raw)
        observed_files = {}
        def artifact(suffix, maximum=65536):
            remaining(); queue.validate(); validate_replacement()
            try: queue.read(request_id + ".original-consumer.failed.json", 65536)
            except FileNotFoundError: pass
            else: p.require(False, "actual original-consumer failed")
            try: recovery.queue_file(replacement_queue, operation + ".failed.json", 65536)
            except FileNotFoundError: pass
            else: p.require(False, "actual replacement failed")
            name = request_id + suffix
            value = queue.read(name, maximum, pin_file=True)
            if name in observed_files: p.require(observed_files[name] == value, "original carrier bytes changed")
            observed_files[name] = value
            return p.decode(value[0], maximum)
        def wait_artifact(suffix, maximum=65536):
            while True:
                try: return artifact(suffix, maximum)
                except FileNotFoundError: time.sleep(0.01)
        claimed = wait_artifact(".original-consumer.capture.json")
        p.require(claimed == capture, "exact paired original request claim")
        offered = wait_artifact(".original-consumer.candidate.json")
        binding = candidate(offered, capture, replacement, normal, int(Path(normal_process.arguments[3]).parent.name[:20]))
        validate_original(); validate_peer()
        record("original-consumer-candidate", candidate=offered)
        # These immutable markers contain the binding, not caller-supplied
        # positives. For v3 Swift first validates actual GetAttr sequence 1 / ok.
        p.require(wait_artifact(".original-consumer.armed.json") == binding, "actual original mounted Arm acknowledgment")
        if reader is not None:
            validate_original(); validate_peer()
            retained_after = root_backing.unchanged(reader.snapshot(), retained_before) if root_case else backing.retained_baseline(reader.snapshot(), retained_before)
            validate_original(); validate_peer()
            baseline_ack = (root_backing.baseline_marker(binding, normal, writer, retained_after) if root_case else
                backing.baseline_marker(binding, writer["id"], writer_slot["attachment"], writer_slot["key"], retained_after))
            # record() durably fsyncs the independent report before the public scheduling ACK.
            record("original-consumer-independent-baseline", marker=baseline_ack, readerJoin=reader.join_receipt,
                snapshot={k: v for k, v in retained_after.items() if k != "mountinfo"})
            queue.publish(request_id + ".original-consumer.baseline.json", baseline_ack)
            (root_backing if root_case else backing).baseline_accepted(wait_artifact(".original-consumer.baseline-accepted.json"), baseline_ack)
        p.require(wait_artifact(".original-consumer.begun.json") == binding, "actual Begin immediately before replacement")
        result = wait_artifact(".original-consumer.result.json", 262144)
        seen = {}
        for suffix, maximum in ((".request.json", 512), (".pending.json", 1048576), (".succeeded.json", 1048576)):
            name = operation + suffix
            while True:
                remaining(); validate_replacement()
                try: recovery.queue_file(replacement_queue, operation + ".failed.json", 65536)
                except FileNotFoundError: pass
                else: p.require(False, "production replacement failed after observation")
                try:
                    seen[name] = recovery.queue_file(replacement_queue, name, maximum)
                    break
                except FileNotFoundError: time.sleep(0.01)
        p.require(seen[operation + ".request.json"][0] == raw and seen[operation + ".request.json"][1][:2] == marker, "same production replacement claim")
        pending = p.decode(seen[operation + ".pending.json"][0], 1048576)
        succeeded = p.decode(seen[operation + ".succeeded.json"][0], 1048576)
        after, after_hash = lifecycle.read_owner(daemon.root, recovery.read_public)
        _, state, hashes = read_state()
        fresh = lifecycle.replacement_proof(before, after, pending, succeeded, replacement, state, hashes, owned, submitted, int(time.time()))
        _, newboot = lifecycle.owner(after)
        newboot = lifecycle.peer_comparison(newboot, lifecycle_peer_reader)
        p.require(offered["ownerRequest"] == succeeded["ownerRequest"], "same sealed runtime operation through final publication")
        # Wrong-Hello is attributed to the CURRENT predecessor before its real
        # replacement, never to a successor's unrelated unknown-CA rejection.
        correlated_result(result, binding, normal,
            oldboot if observes_predecessor(case) else newboot, baseline_ack)
        recovery.settled_worker_artifacts(replacement_queue, operation, seen)
        for process in (normal_process, peer_native): wait_exit(process)
        survivors = surviving_hosts(census, processes(), (normal_process, peer_native), api, storage, harness._kernel_process, contained=True)
        p.require(storage_target(daemon, fresh, survivors) == storage, "original storage VM/PID1 and disk unchanged")
        record("original-consumer-correlated-contained", evidence=result, replacement=succeeded, ownerSHA256=after_hash,
            journal=hashes, contained=[p.native_proof(normal_process), p.native_proof(peer_native)])
        # A fresh legitimate owner is required AFTER real containment/reconcile.
        # The snapshot remains disk corroboration. Data cases additionally
        # require the sealed fresh-start actual wire GETATTR artifact below.
        # WrongMode's writer preserved a/z: compare the same baseline through
        # denial/replacement, before any second writer can touch the directory.
        joined_start(start_request())
        recovered = observe("root-snapshot" if root_case else "retained-snapshot" if case in backing.FD_CASES else "snapshot")
        if root_case:
            disk_proof = root_backing.project_backing(result, baseline_ack, retained_after, recovered, normal, writer)
            record("original-consumer-root-backing-unchanged", evidence=disk_proof)
        elif case in backing.FD_CASES:
            backing.fresh_retained_snapshot(recovered, retained_after)
        else:
            p.snapshot(recovered, baseline=baseline)
        mounted_fixture(recovered, case)
        manifest, state, hashes = read_state()
        current = [i for i in state["intents"].values() if i["container"] == container.id and i["phase"] == "running"]
        p.require(len(current) == 1, "one legitimate fresh runtime owner")
        current = current[0]
        fixture_receipts(manifest, state, plan, container.id, current["id"], case, extra_plan)
        fresh_slots = [s for s in current["slots"] if s["role"] == "runtime"]
        p.require(current["serviceEpoch"] == fresh["serviceEpoch"] and current["launch"] != normal["launch"]
            and all(s["attachment"] not in {old["attachment"] for old in slots} and s["key"] not in {old["key"] for old in slots} for s in fresh_slots), "new current issued identity, never old key reuse")
        current_process = target(current)
        with p.workload_owner(current_process, daemon, plan, current, manifest["root"]) as (native, _, validate):
            validate()
            if case in FRESH_GETATTR_CASES:
                proof = fresh_getattr(wait_artifact(".original-consumer.fresh-getattr.json"), binding,
                    current, newboot, int(Path(current_process.arguments[3]).parent.name[:20]))
                validate()
                record("original-consumer-fresh-wire-getattr", evidence=proof, native=native, journal=hashes)
            if case in backing.FD_CASES:
                backing.fresh_retained_write(observe("retained-write"), recovered)
                validate()
            if root_case:
                from managed_root_projection import fresh_read
                proof = fresh_read(wait_artifact(".original-consumer.fresh-root-read.json"), result,
                    current, newboot, int(Path(current_process.arguments[3]).parent.name[:20]), EVIDENCE_FIELDS)
                validate()
                record("original-consumer-fresh-wire-root-read", evidence=proof, native=native, journal=hashes)
            record("original-consumer-fresh-owner-positive", native=native, journal=hashes)
        if case == "wrong-mode":
            joined_start(start_request(peer))
            manifest, state, hashes = read_state()
            writers = [i for i in state["intents"].values() if i["container"] == peer.id and i["phase"] == "running"]
            p.require(len(writers) == 1, "one fresh authorized writer")
            new_writer = writers[0]
            p.running_receipts(manifest, state, peer_plan, peer.id, new_writer["id"])
            new_slot = runtime_slots(new_writer, "writer")[0]
            p.require(new_writer["serviceEpoch"] == fresh["serviceEpoch"] and new_writer["launch"] != writer["launch"]
                and new_slot["volume"] == slots[0]["volume"] and new_slot["key"] != writer_slot["key"], "fresh same-volume writer identity")
            writer_process = target(new_writer)
            with p.workload_owner(writer_process, daemon, peer_plan, new_writer, manifest["root"]) as (native, _, validate):
                validate(); p.snapshot(observe("snapshot"), baseline=baseline)
                writer_positive(observe, peer, baseline)
                record("original-consumer-writer-after", native=native, journal=hashes,
                    operation="exclusive-marker-write-fsync-readback-unlink-parent-fsync")
            peer.stop(timeout=1); manifest, state, _ = read_state()
            p.running_receipts(manifest, state, peer_plan, peer.id, new_writer["id"], stopped=True)
        for name, pinned in observed_files.items(): p.require(queue.read(name, 262144) == pinned, "final immutable original evidence")
        image.reload(); p.owned(image, "image", plan)
        p.require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "original source image unchanged")
        container.stop(timeout=1); manifest, state, hashes = read_state()
        fixture_receipts(manifest, state, plan, container.id, current["id"], case, extra_plan, stopped=True)
        container.reload(); p.owned(container, "container", plan); container.remove(); wait_exit(current_process)
        peer.reload(); p.owned(peer, "container", peer_plan); peer.remove()
        if writer_process is not None: wait_exit(writer_process)
        volume.reload(); p.owned(volume, "volume", plan); volume.remove()
        if extra_volume is not None:
            extra_volume.reload(); p.owned(extra_volume, "volume", extra_plan); extra_volume.remove()
        image.reload(); p.owned(image, "image", plan); client.images.remove(image.id)
        p.require({v.pid: v for v in processes()} == {v.pid: v for v in survivors}, "unrelated native owners unchanged through cleanup")
        recovery.settled_worker_artifacts(replacement_queue, operation, seen)
        p.require(lifecycle.read_owner(daemon.root, recovery.read_public) == (after, after_hash), "immutable worker owner history through fresh work and cleanup")
        report = dict(**staged, result="case-passed", execution="actual-docker-runtime", runID=str(uuid.UUID(plan["owner"])),
            store=manifest["store"], evidenceSHA256=p.digest(p.canonical([p.digest(entry[0]) for entry in observed_files.values()])))
        record("original-consumer-case-result", **report)
        p.verify_full_ledger(ledger, files)
        return report  # Report-only, never a bearer proof or full RTM103 aggregate.
