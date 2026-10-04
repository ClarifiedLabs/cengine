"""Strict v5/v7 original-FD / v8 same-E wire projection. No authority from JSON."""
import managed_prepare_faults as p
import managed_retained_backing as backing
from managed_prepare_storage_vm_faults import bounded_base64


def file_request(value):
    p.exact(value, {"node", "handle", "requestSequence"})
    for field in value: p.integer(value[field], 2**64 - 1, 1)
    return value


def trace(value, *, positive, prior=None):
    p.require(type(value) is dict, "wire trace object")
    p.exact(value, {"writeOK", "syncOK", "write"} | ({"sync"} if "sync" in value else set()))
    p.require(value["writeOK"] is positive and value["syncOK"] is positive, "exact write/fsync response outcomes")
    write = file_request(value["write"])
    if prior is not None:
        p.require(write["node"] == prior["node"] and write["handle"] == prior["handle"]
            and write["requestSequence"] > prior["requestSequence"], "same original node/handle and increasing FIFO request")
    if positive: p.require("sync" in value, "positive wire fsync required")
    if "sync" in value:
        sync = file_request(value["sync"])
        p.require(sync["node"] == write["node"] and sync["handle"] == write["handle"]
            and sync["requestSequence"] > write["requestSequence"], "same-description write before fsync")
    return write


def result(value, binding, intent, boot, evidence_fields, baseline_ack):
    case = binding["caseName"]
    p.require(case in backing.FD_CASES, "finite writable case")
    same = case == backing.FD_CASES[0]
    p.exact(value, {"worker", "original", "positive", "baseline"} | ({"retirement"} if same else set()))
    version = backing.FD_SAME_E_GUEST_VERSION if same else backing.FD_GUEST_VERSION
    p.integer(binding["version"], version, version)
    backing.baseline_accepted(value["baseline"], baseline_ack)
    p.require(baseline_ack["binding"] == binding, "exact backing handshake binding")
    o, positive, worker = value["original"], value["positive"], value["worker"]
    arm = dict(version=version, profile=p.FULL_PROFILE, requestID=binding["requestID"], operationUUID=binding["operationUUID"],
        caseName=case, binding=binding["boot"], scope=binding["scope"], targetAttachment=binding["targetAttachment"],
        leafSHA256=binding["certificateSHA256"])
    for observed in (positive, o):
        p.exact(observed, evidence_fields | {"writable"})
        p.require(p.canonical(observed["arm"]) == p.canonical(arm) and observed["keySHA256"] == binding["key"]
            and observed["fdOperation"] == "write-file-fsync", "actual versioned original writable carrier")
        p.integer(observed["arm"]["version"], version, version)
        p.pin(observed["mountIdentitySHA256"])
        w = observed["writable"]
        p.require(type(w) is dict, "writable witness object")
        p.exact(w, {"identitySHA256", "written", "writeError", "syncError", "completed"} | ({"trace"} if "trace" in w else set()))
        p.pin(w["identitySHA256"]); p.require(w["completed"] is True, "actual completed retained syscall pair")
        p.exact(observed["originalOperation"], {"kind", "sequence", "errorClass"})
    p.require(positive["stage"] == "begun" and p.canonical(positive["scope"]) == p.canonical(binding["scope"])
        and positive["serverDERSHA256"] == positive["signInputSHA256"] == positive["clientPrefixSHA256"] == positive["localError"] == "",
        "sealed mounted positive before retirement")
    for field in ("signCount", "bytesWrittenAfterSign", "clientWrittenBytes", "clientPrefixBytes"): p.integer(positive[field], 0, 0)
    p.integer(positive["fdSequence"], 1, 1); p.integer(positive["originalOperation"]["sequence"], 1, 1)
    p.require(positive["originalOperation"] == dict(kind="write-file-fsync", sequence=1, errorClass="ok"), "real positive mutation")
    pw, nw = positive["writable"], o["writable"]
    p.integer(pw["written"], 1, 1); p.require(pw["writeError"] == pw["syncError"] == "ok", "actual guest positive write+fsync outcomes")
    trace(pw["trace"], positive=True)
    p.require(nw["identitySHA256"] == pw["identitySHA256"] and o["mountIdentitySHA256"] == positive["mountIdentitySHA256"],
        "same retained open description and original mount")
    p.integer(nw["written"], 0, 0)
    p.require(nw["writeError"] in ("eio", "enotconn", "estale", "eacces") and nw["syncError"] in ("eio", "enotconn", "estale", "eacces"), "both actual syscalls denied")
    p.integer(o["fdSequence"], 2, 2); p.integer(o["originalOperation"]["sequence"], 2, 2)
    p.require(o["originalOperation"] == dict(kind="write-file-fsync", sequence=2,
        errorClass="transport-failed" if same else "mount-closed-joined"), "exact original operation, not directory fsync")
    ready = boot["ready"]
    scope = dict(binding["scope"])
    if not same: scope.update({k: ready[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")})
    p.require(p.canonical(o["scope"]) == p.canonical(scope) and o["serverDERSHA256"] == p.digest(bounded_base64(ready["serverDER"], 16384)), "sealed actual peer/scope")
    slots = [s for s in intent["slots"] if s["role"] == "runtime"]
    p.require(len(slots) == 1, "one original runtime")
    slot = slots[0]
    p.require(slot["attachment"] == binding["targetAttachment"] and slot["key"] == binding["key"] and slot["mode"] == "read-write", "issued original writable identity")
    runtime = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"], container=intent["container"],
        launch=intent["launch"], key=slot["key"], role="runtime", mode="read-write")
    issued = dict(epoch=intent["serviceEpoch"], binding=runtime)
    p.exact(worker, {"query", "state", "selectedCount", "evidence"})
    p.require(worker["state"] == "finalized", "atomically finalized actual worker")
    p.integer(worker["selectedCount"], 1, 1)
    query = dict(version=backing.FD_WORKER_VERSION if same else 3, profile=p.FULL_PROFILE, requestID=binding["requestID"], armDigest=binding["armDigest"],
        operationUUID=binding["operationUUID"], caseName=case if same else "cross-e-old-leaf-reconnect", originalBootBinding=binding["boot"],
        original=issued, originalLeafSHA256=binding["certificateSHA256"], workerScope={k: ready[k] for k in ("storeUUID", "serviceEpoch", "workerUUID")})
    p.exact(worker["query"], set(query))
    p.integer(worker["query"]["version"], query["version"], query["version"])
    p.require(worker["query"] == query, "exact original tuple and actual worker")
    e = worker["evidence"]
    common = {"stage", "errorClass", "storeUUID", "serviceEpoch", "rejectedLeafSHA256"}
    p.exact(e, common | ({"admission"} if same else {"byteCount", "prefixSHA256"}))
    p.require(e["storeUUID"] == intent["store"] == ready["storeUUID"] and e["serviceEpoch"] == ready["serviceEpoch"]
        and e["rejectedLeafSHA256"] == binding["certificateSHA256"], "exact worker negative identity")
    if same:
        p.require(ready["serviceEpoch"] == intent["serviceEpoch"] and ready["controllerEpoch"] == intent["controllerEpoch"]
            and ready["controllerKey"] == intent["controllerKey"], "unchanged original authority")
        p.require(e["stage"] == "request-admit" and e["errorClass"] == "blocked", "actual authority Admit denial")
        negative = nw["trace"]
        p.exact(negative, {"capability", "writeOK", "syncOK"})
        p.require(negative["writeOK"] is False and negative["syncOK"] is False, "no serialized successful WRITE or FSYNC")
        capability = negative["capability"]
        p.exact(capability, {"node", "requestSequence"})
        for field in capability: p.integer(capability[field], 2**64 - 1, 1)
        prior = pw["trace"]["sync"]
        p.require(capability["node"] == prior["node"] and capability["requestSequence"] > prior["requestSequence"],
            "same retained inode and actual later FIFO request")
        admission = e["admission"]
        p.exact(admission, {"original", "requestSequence", "operation", "node", "authKind", "noHandle", "capabilityName"})
        for field in ("node", "requestSequence"): p.integer(admission[field], 2**64 - 1, 1)
        p.integer(admission["authKind"], 1, 1)
        p.require(admission["noHandle"] is True and admission == dict(original=issued, **capability, operation="get_xattr",
            authKind=1, noHandle=True, capabilityName="security.capability"), "actual same-inode killpriv request denied before WRITE")
        p.require(o["stage"] == "original-file-attempt" and o["localError"] == o["signInputSHA256"] == o["clientPrefixSHA256"] == "", "authentic live original DATA")
        for field in ("signCount", "bytesWrittenAfterSign", "clientWrittenBytes", "clientPrefixBytes"): p.integer(o[field], 0, 0)
        retired = value["retirement"]
        p.exact(retired, {"operation", "receipt", "queryRevision", "epoch", "controller", "attachment"})
        p.uid(retired["operation"]); p.require(retired["operation"] == slot["retireOperation"], "actual assigned retirement operation")
        receipt = retired["receipt"]
        p.exact(receipt, {"schema", "store", "volume", "attachment", "launch", "revision"}); p.integer(receipt["schema"], 3, 3)
        p.integer(retired["queryRevision"], 2**64 - 1, 1); p.integer(receipt["revision"], retired["queryRevision"], 1)
        p.require(all(receipt[k] == runtime[k] for k in ("store", "volume", "attachment", "launch")), "exact original receipt")
        p.exact(retired["controller"], {"epoch", "key"})
        p.integer(retired["controller"]["epoch"], 2**64 - 1, 1)
        p.require(retired["epoch"] == intent["serviceEpoch"] and retired["controller"] == dict(epoch=intent["controllerEpoch"], key=intent["controllerKey"])
            and p.canonical(retired["attachment"]) == p.canonical(dict(binding=runtime, phase="DRAINED", receipt=receipt, retirement=retired["operation"])),  "independently queried original retirement")
    else:
        p.require(ready["serviceEpoch"] != intent["serviceEpoch"] and "trace" not in nw, "cross-E actual mount join, no synthetic wire request")
        p.require(e["stage"] == "tls-client-certificate" and e["errorClass"] == "unknown-authority"
            and o["stage"] == "original-owner-prefix-correlated", "separate successor TLS denial")
        p.integer(e["byteCount"], 131072, 1); p.pin(e["prefixSHA256"])
        p.integer(o["signCount"], 1, 1); p.pin(o["signInputSHA256"])
        p.integer(o["clientWrittenBytes"], 131072, 1); p.integer(o["bytesWrittenAfterSign"], o["clientWrittenBytes"], 1)
        p.integer(o["clientPrefixBytes"], o["clientWrittenBytes"], 1)
        p.require(o["clientPrefixBytes"] == e["byteCount"] and o["clientPrefixSHA256"] == e["prefixSHA256"]
            and o["localError"] in ("eof", "tls-alert-or-transport"), "actual retained original signed prefix correlation")
    return value
