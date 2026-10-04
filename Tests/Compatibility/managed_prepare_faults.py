"""RTM-096 closed NORMAL+A7 shard helpers; no engine access at import time.

Public journals/candidates reject mismatches only. The live signed host/guest
remain the only authority for capture admission, credentials and PREPARE.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import copy
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import uuid

from managed_storage import mount_proof, receipt_proof
from managed_storage_recovery import require, native_proof, runtime_root_path

PROFILE = "rtm096-normal-a7-v1"
CASES = ("normal", "first-child-published")
MISSING = ("A1", "A2", "A3", "A4", "A5", "A6", "A8")
EARLY_PROFILE = "rtm096-early-a1-a3-v2"
EARLY_CASES = ("normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame")
EARLY_BOUNDARIES = dict(zip(EARLY_CASES[1:], ("A1", "A2", "A3")))
EARLY_COUNTERS = dict(zip(EARLY_CASES[1:], ((0, 0, 0), (1, 1, 0), (1, 1, 5))))
EARLY_FIELDS = {"version", "profile", "requestID", "armDigest", "stage", "count", "targetAttachment", "requestSequence", "prepareCommandsSent", "prepareCommandsAccepted", "dataBytesWritten"}
FULL_PROFILE = "rtm096-full-nine-v3"
FULL_CASES = (*EARLY_CASES, "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "first-child-published", "drain-durable-reply-lost")
FULL_BOUNDARIES = dict(zip(FULL_CASES, ("NORMAL", *["A" + str(n) for n in range(1, 9)])))
STORAGE_CASES = (FULL_CASES[4], FULL_CASES[5], FULL_CASES[6], FULL_CASES[8])
HELD_STORAGE_CASES = STORAGE_CASES[:2]
# Held A4/A5 admission cuts keep the distinct strict StorageRelease worker-exit
# route; A6/A8 moved to the generic checkpoint-exit route with the guest cuts.
WORKER_EXIT_CASES = ("full-frame-before-admit", "admitted-queued")
# RTM098 generic checkpoint-exit cuts: NORMAL/A7 (physical), A1/A2/A3 (early
# partial-frame), A6/A8 (storage-owned Bound/Drain). Exactly one checkpoint
# carrier is present per claim, selected by the arm's case.
CHECKPOINT_EXIT_CASES = ("normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame",
    "first-child-published", "transaction-published-bind-reply-lost", "drain-durable-reply-lost")
# A6/A8 reach retired with the durable publication surviving the worker death.
CHECKPOINT_CUT_CASES = ("transaction-published-bind-reply-lost", "drain-durable-reply-lost")
CHECKPOINT_CARRIERS = {"normal": "checkpoint", "first-child-published": "checkpoint",
    "before-prepare-send": "earlyCheckpoint", "guest-accepted-before-prepare": "earlyCheckpoint",
    "data-partial-frame": "earlyCheckpoint", "transaction-published-bind-reply-lost": "storageCheckpoint",
    "drain-durable-reply-lost": "storageCheckpoint"}

OWNER = "dev.cengine.compat.managed-prepare"
FILES = {"a": b"rtm096-image-a\n", "z": b"rtm096-image-z\x00\xff\n"}
MTIME = 1700000000
SCOPE = {"intent", "store", "serviceEpoch", "controllerEpoch", "controllerKey", "container", "containerInstance", "launch", "prepare", "specificationDigest"}
CANDIDATE = {"version", "profile", "requestID", "binding", "scope", "mounts", "slots", "credentials"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "closed schema")


def uid(value):
    require(type(value) is str, "UUID type")
    parsed = uuid.UUID(value)
    require(parsed.version == 4 and parsed.variant == uuid.RFC_4122 and str(parsed) == value, "canonical UUIDv4")
    return value


def pin(value, size=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % size, value), "lowercase hash")
    return value


def integer(value, maximum=2**64 - 1, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, "bounded integer")
    return value


def canonical(value):
    def validate(v):
        if type(v) is dict:
            require(all(type(k) is str for k in v), "JSON object keys")
            for child in v.values(): validate(child)
        elif type(v) is list:
            for child in v: validate(child)
        else:
            require(type(v) in (str, int, bool), "no null or float")
    validate(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8")


def decode(raw, maximum=65536, *, canonical_only=True):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "JSON bound")
    def pairs(items):
        value = {}
        for key, child in items:
            require(key not in value, "duplicate JSON key")
            value[key] = child
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    if canonical_only:
        require(canonical(value) == raw, "noncanonical queue bytes")
    return value


def selection(profile, cases):
    require(profile == PROFILE and tuple(cases) == CASES, "explicit closed parent profile/cases required")
    return {"profile": PROFILE, "boundaries": ["NORMAL", "A7"], "coverage": "2/9", "missing": list(MISSING), "fullAcceptance": False}


def early_selection(profile, cases, fault_case):
    """One fresh invocation covers NORMAL plus one fault, never all four cases.

    The parent must select the complete closed source shard and invoke each fault
    with a fresh Daemon. Three independent receipts are needed to aggregate 4/9.
    The prior A7 profile/receipt is separate and is never silently included here.
    """
    require(profile == EARLY_PROFILE and tuple(cases) == EARLY_CASES, "explicit closed early parent profile/cases required")
    require(type(fault_case) is str and fault_case in EARLY_BOUNDARIES, "one exact early fault per fresh invocation")
    boundary = EARLY_BOUNDARIES[fault_case]
    return {"profile": EARLY_PROFILE, "boundaries": ["NORMAL", boundary], "coverage": "2/9",
            "missing": ["A" + str(n) for n in range(1, 9) if "A" + str(n) != boundary],
            "implementedBoundaries": ["NORMAL", "A1", "A2", "A3"], "implementedCoverage": "4/9",
            "faultCase": fault_case, "fullAcceptance": False}


def full_selection(profile, cases, fault_case):
    require(profile == FULL_PROFILE and tuple(cases) == FULL_CASES, "explicit closed full parent profile/cases required")
    require(type(fault_case) is str and fault_case in FULL_CASES, "one exact full case per fresh invocation")
    return {"profile": FULL_PROFILE, "boundaries": [FULL_BOUNDARIES[fault_case]], "coverage": "1/9",
            "faultCase": fault_case, "fullAcceptance": False}


_LIVE_FULL_OUTCOMES = {}


class FullOutcome:
    """Retained direct-run result, not a deserializable acceptance credential.

    The supervising Python parent must retain these objects from nine separate
    fresh Daemon invocations. JSON receipts are report-only and cannot aggregate.
    Close after aggregation/reporting to release pinned evidence descriptors.
    """
    def __init__(self):
        raise TypeError("only the completed live fixture creates FullOutcome")

    @property
    def receipt(self):
        return copy.deepcopy(self._receipt)

    def close(self):
        _LIVE_FULL_OUTCOMES.pop(id(self), None)
        self._directory.close()

    def validate(self):
        require(_LIVE_FULL_OUTCOMES.get(id(self)) is self, "direct retained live outcome required")
        verify_full_ledger(self._directory, self._files)
        return self.receipt


def verify_full_ledger(directory, files):
    directory.validate()
    with os.scandir(directory.fd) as entries:
        require({e.name for e in entries} == set(files), "exact retained external ledger")
    for name, original in files.items():
        require(directory.read(name) == original, "external evidence changed after fsync")


def _completed_full_outcome(receipt, ledger, files):
    """Internal lifecycle completion; never import/restore receipts from disk."""
    verify_full_ledger(ledger, files)
    retained = Directory(ledger.path)
    try:
        require(Directory.stamp(os.fstat(retained.fd)) == Directory.stamp(os.fstat(ledger.fd)), "same retained evidence directory")
        pinned = {name: retained.read(name, pin_file=True) for name in files}
        require(pinned == files, "retained completion evidence unchanged")
        ordered = [decode(pinned[name][0]) for name in sorted(pinned)]
        require(ordered[-1] == {"phase": "full-case-result", **receipt}, "terminal result matches retained ledger")
        require(digest(canonical([digest(canonical(row)) for row in ordered[:-1]])) == receipt["evidenceSHA256"], "complete retained ledger hash")
        outcome = object.__new__(FullOutcome)
        outcome._receipt, outcome._directory, outcome._files = copy.deepcopy(receipt), retained, pinned
        _LIVE_FULL_OUTCOMES[id(outcome)] = outcome
        return outcome
    except BaseException:
        retained.close()
        raise


def _validate_full_receipts(outcomes):
    require(type(outcomes) is list and len(outcomes) == 9, "nine live receipts required")
    cases, runs, stores = set(), set(), set()
    for row in outcomes:
        exact(row, {"profile", "caseName", "runID", "store", "result", "evidenceSHA256", "execution", "fullAcceptance"})
        require(row["profile"] == FULL_PROFILE and row["caseName"] in FULL_CASES and row["result"] == "case-passed"
                and row["execution"] == "actual-docker-runtime" and row["fullAcceptance"] is False, "current live case receipt required")
        uid(row["runID"]); uid(row["store"]); pin(row["evidenceSHA256"])
        require(row["caseName"] not in cases and row["runID"] not in runs and row["store"] not in stores, "unique case/fresh Daemon receipts")
        cases.add(row["caseName"]); runs.add(row["runID"]); stores.add(row["store"])
    require(cases == set(FULL_CASES), "exact full nine outcomes required")


def aggregate_full(outcomes):
    """Only retained direct live results, never bearer JSON/source-only records."""
    require(type(outcomes) is list and len(outcomes) == 9, "nine retained live outcomes required")
    require(all(type(outcome) is FullOutcome for outcome in outcomes), "serialized receipts are report-only")
    rows = [outcome.validate() for outcome in outcomes]
    _validate_full_receipts(rows)
    identities = [Directory.stamp(os.fstat(outcome._directory.fd))[:2] for outcome in outcomes]
    require(len(set(identities)) == 9, "unique retained evidence directories")
    return {"profile": FULL_PROFILE, "coverage": "9/9", "fullAcceptance": True,
            "result": "full-acceptance-passed", "receiptsSHA256": digest(canonical(sorted(rows, key=lambda r: r["caseName"])))}


def full_arm_candidate(candidate, capture, previous, case, *, controller_recovery=None, service_recovery=None, worker_recovery=None):
    require(sum(context is not None for context in (controller_recovery, service_recovery, worker_recovery)) <= 1, "one recovery context")
    if worker_recovery is not None:
        exact(worker_recovery, {"store", "serviceEpoch", "controllerEpoch", "controllerKey"})
        uid(worker_recovery["store"]); uid(worker_recovery["serviceEpoch"])
        integer(worker_recovery["controllerEpoch"], minimum=1); pin(worker_recovery["controllerKey"])
        require(case == "normal" and worker_recovery["serviceEpoch"] != previous["serviceEpoch"]
            and all(worker_recovery[k] == previous[k] for k in ("store", "controllerEpoch", "controllerKey")),
            "worker recovery same S/C/key, fresh E, NORMAL only")
    if service_recovery is not None:
        exact(service_recovery, {"store", "serviceEpoch", "controllerEpoch", "controllerKey"})
        uid(service_recovery["serviceEpoch"]); integer(service_recovery["controllerEpoch"], minimum=1); pin(service_recovery["controllerKey"])
        require(case == "normal" and service_recovery["store"] == previous["store"]
            and service_recovery["serviceEpoch"] != previous["serviceEpoch"], "storage reopen same store, fresh service")
        require(service_recovery["controllerEpoch"] == previous["controllerEpoch"] + 1
            and service_recovery["controllerKey"] != previous["controllerKey"], "storage reopen exact fresh ROOT controller")
    if controller_recovery is not None:
        exact(controller_recovery, {"store", "serviceEpoch", "controllerEpoch", "controllerKey"})
        require(case == "normal" and controller_recovery["store"] == previous["store"]
            and controller_recovery["serviceEpoch"] == previous["serviceEpoch"], "API-only same storage incarnation")
        integer(controller_recovery["controllerEpoch"], minimum=1); pin(controller_recovery["controllerKey"])
        require(controller_recovery["controllerEpoch"] == previous["controllerEpoch"] + 1
            and controller_recovery["controllerKey"] != previous["controllerKey"], "exact fresh ROOT controller")
    return _arm_candidate(candidate, capture, previous, case, version=3, profile=FULL_PROFILE, cases=FULL_CASES,
        controller_recovery=controller_recovery, service_recovery=service_recovery, worker_recovery=worker_recovery)


# Natural-failure cuts (A1/A3/A6): the first attempt fails on its own and
# production may already contain the owner before any exit action. Mirrors
# test_managed_prepare_faults.NATURAL_FAILURE_CASES (AST-pinned there).
NATURAL_FAILURE_CASES = ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost")


def full_observation(value, arm):
    require(type(arm["version"]) is int and arm["version"] == 3 and arm["profile"] == FULL_PROFILE, "v3 arm required")
    if arm["caseName"] in EARLY_COUNTERS:
        exact(value, EARLY_FIELDS)
        require(type(value["version"]) is int and value["version"] == 3 and value["profile"] == FULL_PROFILE, "v3 early observation required")
        # Share the exact counter validator without weakening the public v2 API.
        translated_arm, translated = copy.deepcopy(arm), copy.deepcopy(value)
        translated_arm.update(version=2, profile=EARLY_PROFILE)
        require(value["armDigest"] == digest(canonical(arm)), "v3 early digest")
        translated.update(version=2, profile=EARLY_PROFILE, armDigest=digest(canonical(translated_arm)))
        early_observation(translated, translated_arm)
        return value
    return _physical_observation(value, arm, version=3, profile=FULL_PROFILE,
                                 cases=("normal", "first-child-published", "drain-durable-reply-lost"))


def full_retry_snapshot(value, baseline, checkpoint, arm):
    require(arm["caseName"] in ("normal", "drain-durable-reply-lost"), "successful full attempt required")
    full_observation(checkpoint, arm)
    return _retry_snapshot(value, baseline, checkpoint)


def checkpoint_carrier(case):
    require(type(case) is str and case in CHECKPOINT_CARRIERS, "closed checkpoint exit cut required")
    return CHECKPOINT_CARRIERS[case]


def storage_query(arm, worker):
    require(type(arm["version"]) is int and arm["version"] == 3 and arm["profile"] == FULL_PROFILE and arm["caseName"] in STORAGE_CASES, "full storage arm required")
    return dict(version=3, profile=FULL_PROFILE, requestID=uid(arm["requestID"]), armDigest=digest(canonical(arm)), workerUUID=uid(worker))


def storage_receipt(value, arm):
    exact(value, {"schema", "store", "volume", "attachment", "launch", "prepare", "revision"})
    target = next(s for s in arm["slots"] if s["attachment"] == arm["targetAttachment"])
    require(type(value["schema"]) is int and value["schema"] == 3, "authority receipt schema")
    require(all(value[k] == v for k, v in dict(store=arm["scope"]["store"], volume=target["volume"], attachment=target["attachment"], launch=arm["scope"]["launch"], prepare=arm["scope"]["prepare"]).items()), "actual receipt full S/P/V/A")
    integer(value["revision"], minimum=1)
    return value


def storage_bound_intent(value, arm):
    exact(value, {"id", "owner", "epoch", "root", "transaction", "manifest_digest", "manifest_size", "phase", "initial", "cleanup", "initial_captured"})
    uid(value["id"])
    scope = arm["scope"]
    target = next(s for s in arm["slots"] if s["attachment"] == arm["targetAttachment"])
    key = next(c["key"] for c in arm["credentials"] if c["attachment"] == target["attachment"])
    expected = dict(store=scope["store"], volume=target["volume"], attachment=target["attachment"], prepare=scope["prepare"], container=scope["container"], launch=scope["launch"], key=key, role="prepare", mode="read-write")
    require(value["owner"] == expected and value["epoch"] == scope["serviceEpoch"], "BOUND exact installed owner")
    require(value["phase"] == "BOUND" and value["initial_captured"] is True and type(value["manifest_size"]) is int and value["manifest_size"] == 0, "actual unsealed BOUND provenance")
    def octets(raw, length):
        pin(raw, length * 2)
        return bytes.fromhex(raw)
    require(octets(value["manifest_digest"], 32) == bytes(32), "no invented SEALED digest")
    def obj(row, *, zero=False):
        exact(row, {"inode", "generation", "file_type", "handle_type", "handle_size", "handle"})
        for k in ("inode", "generation", "file_type", "handle_type", "handle_size"): integer(row[k], 2**32 - 1)
        raw = octets(row["handle"], 8)
        if zero:
            require(not any(row[k] for k in row if k != "handle") and raw == bytes(8), "zero uncaptured object")
        else:
            require(row["inode"] > 0 and row["file_type"] == 16384 and row["handle_type"] == 1 and row["handle_size"] == 8 and struct.unpack("<II", raw) == (row["inode"], row["generation"]), "actual authority directory identity")
    root = value["root"]
    exact(root, {"store", "volume", "backing_uuid", "root"})
    require(root["store"] == scope["store"] and root["volume"] == target["volume"] and octets(root["backing_uuid"], 16) != bytes(16), "exact BOUND backing root")
    obj(root["root"]); obj(value["transaction"])
    require(root["root"]["inode"] != value["transaction"]["inode"], "distinct BOUND transaction")
    for name in ("initial", "cleanup"):
        row = value[name]
        exact(row, {"uid", "gid", "mode", "atime_seconds", "mtime_seconds", "atime_nanos", "mtime_nanos", "manifest", "staging"})
        for k in ("uid", "gid"): integer(row[k], 2**32 - 2)
        integer(row["mode"], 0o7777)
        for k in ("atime_seconds", "mtime_seconds"):
            require(type(row[k]) is str and re.fullmatch(r"0|-?[1-9][0-9]*", row[k]), "canonical signed decimal seconds")
            integer(int(row[k]), 2**63 - 1, -(2**63))
        for k in ("atime_nanos", "mtime_nanos"): integer(row[k], 10**9 - 1)
        obj(row["manifest"], zero=True); obj(row["staging"], zero=True)
        if name == "cleanup": require(all(row[k] == ("0" if k.endswith("_seconds") else 0) for k in row if k not in ("manifest", "staging")), "BOUND cleanup not captured")
    return value


def storage_observation(value, arm, worker):
    query = storage_query(arm, worker)
    stage = arm["caseName"]
    payload = "admission" if stage in HELD_STORAGE_CASES else "bound" if stage == STORAGE_CASES[2] else "drain"
    exact(value, {*query, "stage", "count", "targetAttachment", payload})
    require(all(type(value[k]) is type(v) and value[k] == v for k, v in query.items()) and value["stage"] == stage and type(value["count"]) is int and value["count"] == 1 and value["targetAttachment"] == arm["targetAttachment"], "storage checkpoint exact arm/worker")
    cut = value[payload]
    if payload == "admission":
        exact(cut, {"requestSequence", "admitted", "releaseToken"})
        integer(cut["requestSequence"], minimum=1); pin(cut["releaseToken"])
        require(cut["admitted"] is (stage == "admitted-queued"), "actual admission cut")
    elif payload == "bound":
        exact(cut, {"requestSequence", "intent"})
        integer(cut["requestSequence"], minimum=1); storage_bound_intent(cut["intent"], arm)
    else:
        exact(cut, {"retireOperation", "receipt"})
        uid(cut["retireOperation"]); storage_receipt(cut["receipt"], arm)
    require(len(canonical(value)) <= 8192, "storage observation bound")
    return value


def storage_status(value, arm, worker, *, phase, checkpoint=None):
    fields = {"query", "state", "retirementStarted", "acceptedInFlight", "lateAdmissionRejected", "receiptReplayCount"}
    exact(value, fields | ({"observation"} if value.get("state") != "armed" else set()))
    require(value["query"] == storage_query(arm, worker) and canonical(value["query"]) == canonical(storage_query(arm, worker)), "exact storage query")
    require(type(value["retirementStarted"]) is bool and type(value["lateAdmissionRejected"]) is bool, "actual status booleans")
    integer(value["acceptedInFlight"], 2**32 - 1); integer(value["receiptReplayCount"], 2**32 - 1)
    require(value["state"] in ("armed", "observed", "released", "finished") and (value["state"] != "released" or arm["caseName"] in HELD_STORAGE_CASES), "closed storage state")
    if "observation" in value:
        storage_observation(value["observation"], arm, worker)
        if checkpoint is not None: require(value["observation"] == checkpoint, "immutable first storage cut")
    if phase == "armed":
        require(value["state"] == "armed" and value["retirementStarted"] is False and value["acceptedInFlight"] == 0 and value["lateAdmissionRejected"] is False and value["receiptReplayCount"] == 0, "actual initial storage ACK")
    elif phase == "pending":
        require(arm["caseName"] in HELD_STORAGE_CASES and value["state"] == "observed" and value["retirementStarted"] is True and value["lateAdmissionRejected"] is False and value["receiptReplayCount"] == 0, "actual fenced retirement before release")
        require(value["acceptedInFlight"] > 0 if arm["caseName"] == "admitted-queued" else value["acceptedInFlight"] == 0, "exact held admission count")
    elif phase == "finished":
        require(value["state"] == "finished" and value["retirementStarted"] is True and value["acceptedInFlight"] == 0, "real storage cut completed/drained")
        require(value["lateAdmissionRejected"] is (arm["caseName"] == "full-frame-before-admit"), "actual late Admit refusal")
        require(value["receiptReplayCount"] >= 1 if arm["caseName"] == "drain-durable-reply-lost" else value["receiptReplayCount"] == 0, "production same-operation receipt replay")
    else: require(False, "closed status proof phase")
    return value


def storage_release(pending, arm, worker, checkpoint):
    storage_status(pending, arm, worker, phase="pending", checkpoint=checkpoint)
    return dict(query=storage_query(arm, worker), stage=arm["caseName"], token=checkpoint["admission"]["releaseToken"])


def failed_full_prepare(intent, arm, *, worker_interrupted=False):
    # worker_interrupted is only for the RTM098 generic route, where even the
    # NORMAL cut's first attempt is interrupted by the owned worker's exit 74.
    require(arm["profile"] == FULL_PROFILE and arm["version"] == 3
        and (worker_interrupted or arm["caseName"] not in ("normal", "drain-durable-reply-lost")), "failed v3 fault required")
    failed_prepare(intent, arm)
    require(intent.get("cleanUnmount") is False, "no fabricated successful close")
    rows = [{k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]]
    require(sorted(rows, key=lambda s: s["attachment"]) == arm["slots"], "full failed slot tuple")
    for slot in intent["slots"]:
        if slot["role"] == "prepare":
            require(slot.get("key") == next(c["key"] for c in arm["credentials"] if c["attachment"] == slot["attachment"]), "failed installed key")
            exact(slot["receipt"], {"store", "volume", "attachment", "prepare", "launch", "revision"})
    return intent


def names(token):
    pin(token, 32)
    base = "rtm096-" + token
    return {"owner": token, "volume": base, "container": base, "image": "compat-managed-prepare:" + token}


def mount(value):
    exact(value, {"index", "volume", "destination", "subpath", "mode", "noCopy"})
    integer(value["index"], 2**32 - 1); uid(value["volume"])
    require(value["destination"] == "/data" and value["subpath"] == "" and value["mode"] == "read-write" and value["noCopy"] is False, "closed a/z copy mount")


def capture_from_normal(intent, saved, volume, request):
    """Digest comes from the real completed host intent, NOT Docker JSON hashing.

    The one explicit /data mount means RawVirtualizationBackend's destination
    sort has index zero; extra mounts (including tmpfs) are rejected, not omitted.
    """
    require(saved["id"] == intent["container"] and str(uuid.UUID(saved["instanceID"])) == intent["containerInstance"], "owned saved container")
    require(len(saved["mounts"]) == 1, "exact full saved mount set")
    m = saved["mounts"][0]
    require(m["kind"] == "volume" and m["source"] == volume["name"] and m["destination"] == "/data" and m["readOnly"] is False and m["noCopy"] is False and m.get("subpath") in (None, ""), "owned copy-enabled mount")
    bound = dict(index=0, volume=uid(volume["id"]), destination="/data", subpath="", mode="read-write", noCopy=False)
    require(intent["mounts"] == [{k: bound[k] for k in ("volume", "destination", "subpath", "mode")}], "full journal mount set")
    return dict(version=1, requestID=uid(request), container=pin(intent["container"]), containerInstance=uid(intent["containerInstance"]), specificationDigest=pin(intent["specificationDigest"]), mounts=[bound])


def arm_candidate(candidate, capture, previous, case):
    return _arm_candidate(candidate, capture, previous, case, version=1, profile=PROFILE, cases=CASES)


def early_arm_candidate(candidate, capture, previous, case):
    return _arm_candidate(candidate, capture, previous, case, version=2, profile=EARLY_PROFILE, cases=EARLY_CASES)


def _arm_candidate(candidate, capture, previous, case, *, version, profile, cases, controller_recovery=None, service_recovery=None, worker_recovery=None):
    exact(candidate, CANDIDATE)
    require(candidate["version"] == version and type(candidate["version"]) is int and candidate["profile"] == profile and candidate["requestID"] == capture["requestID"] and case in cases, "candidate profile/request")
    exact(candidate["binding"], {"shimLaunchUUID", "guestBootNonce"})
    for v in candidate["binding"].values(): uid(v)
    scope = candidate["scope"]; exact(scope, SCOPE)
    for k in ("intent", "store", "serviceEpoch", "containerInstance", "launch", "prepare"): uid(scope[k])
    for k in ("controllerKey", "container", "specificationDigest"): pin(scope[k])
    integer(scope["controllerEpoch"], minimum=1)
    require(scope["launch"] == candidate["binding"]["shimLaunchUUID"], "boot launch")
    require(all(scope[k] == capture[k] for k in ("container", "containerInstance", "specificationDigest")), "capture exact selection")
    require(all(scope[k] == previous[k] for k in ("store", "container", "containerInstance", "specificationDigest")), "same owned store/container")
    epoch_context = worker_recovery if worker_recovery is not None else previous if service_recovery is None else service_recovery
    require(scope["serviceEpoch"] == epoch_context["serviceEpoch"], "exact observed service epoch")
    context = worker_recovery if worker_recovery is not None else service_recovery if service_recovery is not None else previous if controller_recovery is None else controller_recovery
    require(all(scope[k] == context[k] for k in ("controllerEpoch", "controllerKey")), "exact observed controller context")
    require(scope["intent"] != previous.get("intent", previous.get("id")) and all(scope[k] != previous[k] for k in ("launch", "prepare")), "fresh intent/launch/P")
    if "binding" in previous:
        require(candidate["binding"]["guestBootNonce"] != previous["binding"]["guestBootNonce"], "fresh guest boot nonce")
    require(type(candidate["mounts"]) is list and len(candidate["mounts"]) == 1 and candidate["mounts"] == capture["mounts"], "complete candidate mounts")
    for row in candidate["mounts"]: mount(row)
    slots = candidate["slots"]
    require(type(slots) is list and len(slots) == 2, "full PREPARE+runtime slots")
    for row in slots:
        exact(row, {"volume", "attachment", "role", "mode"}); uid(row["attachment"])
        require(row["volume"] == capture["mounts"][0]["volume"] and row["mode"] == "read-write", "slot volume/mode")
    require({s["role"] for s in slots} == {"prepare", "runtime"} and len({s["attachment"] for s in slots}) == 2, "unique slot hierarchy")
    require({s["attachment"] for s in slots}.isdisjoint(s["attachment"] for s in previous["slots"]), "fresh attachments")
    credentials = candidate["credentials"]
    require(type(credentials) is list and len(credentials) == 1, "complete installed PREPARE credentials only")
    for credential in credentials:
        exact(credential, {"attachment", "key", "certificateSHA256"})
        uid(credential["attachment"]); pin(credential["key"]); pin(credential["certificateSHA256"])
    target = next(s["attachment"] for s in slots if s["role"] == "prepare")
    require(credentials[0]["attachment"] == target, "credential actual PREPARE slot")
    require(credentials[0]["key"] not in {s.get("key") for s in previous["slots"]}, "fresh guest key")
    if "credentials" in previous:
        require(credentials[0]["certificateSHA256"] not in {c["certificateSHA256"] for c in previous["credentials"]}, "fresh issued leaf")
    arm = copy.deepcopy(candidate)
    arm.update(caseName=case, targetAttachment=target)
    arm["slots"].sort(key=lambda s: s["attachment"])
    arm["credentials"].sort(key=lambda s: s["attachment"])
    require(len(canonical(arm)) <= 65536, "arm bound")
    return arm


def observation(value, arm):
    return _physical_observation(value, arm, version=1, profile=PROFILE, cases=CASES)


def early_normal_observation(value, arm):
    require(type(arm["version"]) is int and arm["version"] == 2 and arm["profile"] == EARLY_PROFILE, "v2 normal arm required")
    return _physical_observation(value, arm, version=2, profile=EARLY_PROFILE, cases=("normal",))


def _physical_observation(value, arm, *, version, profile, cases):
    exact(value, {"version", "profile", "requestID", "armDigest", "stage", "count", "targetAttachment", "copyIntent", "filesystemUUID", "manifestDigest", "manifestSize", "root", "transaction", "published", "staged", "sourceAtimes"})
    require(type(value["version"]) is int and value["version"] == version and type(value["count"]) is int and value["count"] == 1, "one checkpoint")
    require(arm["caseName"] in cases and value["stage"] == "first-child-published" and value["profile"] == profile and value["requestID"] == arm["requestID"] and value["targetAttachment"] == arm["targetAttachment"] and value["armDigest"] == digest(canonical(arm)), "checkpoint exact arm")
    uid(value["copyIntent"]); pin(value["filesystemUUID"], 32); pin(value["manifestDigest"])
    require(value["filesystemUUID"] != "0" * 32, "nonzero filesystem")
    integer(value["manifestSize"], 64 * 1024 * 1024, 1)
    exact(value["sourceAtimes"], {"root", "a", "z"})
    for atime in value["sourceAtimes"].values(): integer(atime, 2**63 - 1)
    for key, kind in (("root", 16384), ("transaction", 16384), ("published", 32768), ("staged", 32768)):
        identity = value[key]; exact(identity, {"inode", "generation", "fileType", "handle"})
        integer(identity["inode"], 2**32 - 1, 1); integer(identity["generation"], 2**32 - 1)
        require(type(identity["fileType"]) is int and identity["fileType"] == kind, "checkpoint object type")
        pin(identity["handle"], 16)
        require(struct.unpack("<II", bytes.fromhex(identity["handle"])) == (identity["inode"], identity["generation"]), "real full object handle")
    require(len({value[k]["inode"] for k in ("root", "transaction", "published", "staged")}) == 4 and len(canonical(value)) <= 8192, "distinct physical objects/bound")
    return value


def early_observation(value, arm):
    """Selected-request counters only: no invented physical identity or Admit."""
    exact(value, EARLY_FIELDS)
    require(type(arm["version"]) is int and arm["version"] == 2 and arm["profile"] == EARLY_PROFILE and arm["caseName"] in EARLY_COUNTERS, "v2 early arm required")
    require(type(value["version"]) is int and value["version"] == 2 and value["profile"] == EARLY_PROFILE and type(value["count"]) is int and value["count"] == 1, "one exact v2 early checkpoint")
    for key in ("requestID", "targetAttachment"): uid(value[key])
    pin(value["armDigest"])
    require(value["stage"] == arm["caseName"] and value["requestID"] == arm["requestID"] and value["targetAttachment"] == arm["targetAttachment"] and value["armDigest"] == digest(canonical(arm)), "early checkpoint exact arm")
    integer(value["requestSequence"], minimum=1)
    keys = ("prepareCommandsSent", "prepareCommandsAccepted", "dataBytesWritten")
    for key in keys: integer(value[key], 2**32 - 1)
    require(tuple(value[key] for key in keys) == EARLY_COUNTERS[arm["caseName"]], "exact early selected-request counters")
    require(len(canonical(value)) <= 8192, "early checkpoint bound")
    return value


def early_retry_snapshot(value, baseline, checkpoint, arm):
    early_normal_observation(checkpoint, arm)
    return _retry_snapshot(value, baseline, checkpoint)


def _retry_snapshot(value, baseline, checkpoint):
    snapshot(baseline)
    expected = copy.deepcopy(baseline)
    expected["root"]["atimeNS"] = checkpoint["sourceAtimes"]["root"]
    for name in FILES:
        expected["files"][name]["atimeNS"] = checkpoint["sourceAtimes"][name]
    return snapshot(value, baseline=expected)


def retry_snapshot(value, baseline, checkpoint, arm):
    """Use this fresh attempt's source timestamps, never the first destination.

    The sealed checkpoint precedes successful PREPARE and carries the private
    initializer's no-follow stat snapshot from before staging source reads.
    Everything except these independently observed atimes stays byte-exact.
    """
    require(arm["caseName"] == "normal", "fresh normal retry witness required")
    observation(checkpoint, arm)
    return _retry_snapshot(value, baseline, checkpoint)


class Directory:
    """Pin a no-follow owned directory chain; permit only the system /tmp alias."""
    def __init__(self, path, *, private=True):
        path = Path(path)
        physical = path.resolve()
        require(path == physical or (path.parts[:2] == ("/", "tmp") and physical == Path("/private/tmp").joinpath(*path.parts[2:])), "directory spelling")
        self.path, self.chain, self.stack = physical, [], ExitStack()
        self.alias = None
        if path != physical:
            alias = os.lstat("/tmp")
            require(stat.S_ISLNK(alias.st_mode) and alias.st_uid == 0 and not alias.st_mode & 0o022 and os.readlink("/tmp") == "private/tmp", "protected system tmp alias")
            self.alias = self.stamp(alias)
        try:
            parent = None
            for i, part in enumerate(("/", *physical.parts[1:])):
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                self.stack.callback(os.close, fd)
                info = os.fstat(fd)
                require(info.st_uid in (0, os.geteuid()) and (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX), "directory owner/mode")
                self.chain.append((parent, part, fd, self.stamp(info)))
                parent = fd
            self.fd = self.chain[-1][2]
            info = os.fstat(self.fd)
            require(info.st_uid == os.geteuid() and not info.st_mode & (0o077 if private else 0o022), "owned leaf directory mode")
        except BaseException:
            self.stack.close(); raise

    @staticmethod
    def stamp(info):
        return info.st_dev, info.st_ino, info.st_uid, info.st_mode

    def validate(self):
        if self.alias is not None:
            require(self.stamp(os.lstat("/tmp")) == self.alias and os.readlink("/tmp") == "private/tmp", "system tmp alias changed")
        for parent, name, fd, stamp in self.chain:
            require(self.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)) == self.stamp(os.fstat(fd)) == stamp, "directory chain changed")

    def close(self): self.stack.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def read(self, name, maximum=65536, *, pin_file=False):
        require(Path(name).name == name and name not in (".", ".."), "fixed leaf")
        self.validate()
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        if pin_file: self.stack.callback(os.close, fd)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022 and info.st_nlink == 1 and info.st_size <= maximum, "owned bounded regular file")
            raw = os.pread(fd, maximum + 1, 0)
            require(len(raw) == info.st_size and len(raw) <= maximum and self.stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == self.stamp(info), "stable file read")
            return raw, (*self.stamp(info), digest(raw))
        finally:
            if not pin_file: os.close(fd)

    def publish(self, name, value):
        raw = canonical(value)
        require(len(raw) <= 65536 and Path(name).name == name and name not in (".", ".."), "publication name/bound")
        self.validate()
        temporary = "." + str(uuid.uuid4()) + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        # Darwin RENAME_EXCL (0x4): no overwrite and no transient nlink=2
        # visible to the carrier's mandatory single-link FD validation.
        rename = ctypes.CDLL(None, use_errno=True).renameatx_np
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        self.validate()
        if rename(self.fd, os.fsencode(temporary), self.fd, os.fsencode(name), 0x4) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "exclusive queue publication failed")
        os.fsync(self.fd)
        self.validate()


def snapshot(value, command="snapshot", baseline=None):
    exact(value, {"command", "entries", "root", "files", "mountinfo", "parentFsynced"})
    require(command in ("snapshot", "empty", "writer"), "closed runtime helper command")
    require(value["command"] == command and value["parentFsynced"] is (command in ("empty", "writer")), "runtime helper command/ACK")
    mount_proof(value["mountinfo"])
    require(value["entries"] == ([] if command == "empty" else ["a", "z"]), "complete namespace/no transaction")
    if command == "empty":
        require(value["files"] == {}, "empty after unlink+fsync")
        return value
    exact(value["files"], FILES)
    for name, entry in [("root", value["root"]), *value["files"].items()]:
        metadata = {"mode", "uid", "gid", "atimeNS", "mtimeNS", "xattrs"}
        exact(entry, metadata if name == "root" else metadata | {"size", "sha256", "nlink"})
        require((entry["mode"], entry["uid"], entry["gid"]) == ((stat.S_IFDIR | 0o750) if name == "root" else (stat.S_IFREG | 0o640), 10001, 10002), "exact source owner/mode")
        require(entry["mtimeNS"] == MTIME * 10**9 and entry["xattrs"] == {}, "exact source mtime/xattrs")
        integer(entry["atimeNS"], 2**63 - 1)
        if name != "root":
            require(entry["size"] == len(FILES[name]) and entry["sha256"] == digest(FILES[name]) and entry["nlink"] == 1, "complete exact image bytes")
    if baseline is not None:
        require(value["root"] == baseline["root"] and value["files"] == baseline["files"], "exact recovered metadata including atime")
    return value


def image_archive(binary, plan, *, second_mount=False, root_objects=False):
    require(0 < len(binary) <= 8 * 1024 * 1024, "probe bound")
    def tar(entries):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, data, mode, owner in entries:
                info = tarfile.TarInfo(name); info.mode = mode; info.mtime = MTIME
                info.uid, info.gid = owner
                if data is None: info.type = tarfile.DIRTYPE
                else: info.size = len(data)
                archive.addfile(info, None if data is None else io.BytesIO(data))
        return out.getvalue()
    require(type(root_objects) is bool and (not root_objects or second_mount), "root fixtures require both mounts")
    extra = [("other", None, 0o750, (10001, 10002))] if second_mount else []
    objects = [("data/" + n, b, 0o640, (10001, 10002)) for n, b in FILES.items()]
    if root_objects:
        # Separate immutable image objects; never manufacture data after capture.
        objects = [(path + "/rtm103-root-object", byte * 32, 0o640, (10001, 10002))
            for path, byte in (("data", b"A"), ("other", b"B"))]
    layer = tar(extra + [("probe", binary, 0o755, (0, 0)), ("data", None, 0o750, (10001, 10002)), *objects])
    config = {"architecture": "arm64", "os": "linux", "config": {"Cmd": ["/probe", "serve"], "User": "0:0", "Labels": {OWNER: plan["owner"]}}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(layer)]}}
    raw = canonical(config); name = digest(raw) + ".json"
    manifest = canonical([{"Config": name, "RepoTags": [plan["image"]], "Layers": ["layer.tar"]}])
    return tar([(name, raw, 0o644, (0, 0)), ("layer.tar", layer, 0o644, (0, 0)), ("manifest.json", manifest, 0o644, (0, 0))]), config


def owned(resource, kind, plan):
    labels = resource.attrs.get("Labels") if kind == "volume" else resource.attrs.get("Config", {}).get("Labels")
    require(type(labels) is dict and labels.get(OWNER) == plan["owner"], "exact resource owner")
    require(plan[kind] in resource.attrs.get("RepoTags", []) if kind == "image" else resource.name == plan[kind], "exact resource name")
    return resource


@contextmanager
def workload_owner(process, daemon, plan, intent, root_identity, *, prepared=None):
    """Pin a live canonical generation; prepared peers have no storage intent."""
    native_proof(process)
    root = runtime_root_path(daemon.root)
    if prepared is None:
        container, launch = pin(intent["container"]), uid(intent["launch"])
        instance, storage_mode = intent["containerInstance"], "managed"
    else:
        require(intent is None, "prepared peer is not a fabricated storage intent")
        exact(prepared, {"schemaVersion", "directoryIdentity", "artifacts", "currentContainer", "specification"})
        require(type(prepared["schemaVersion"]) is int and prepared["schemaVersion"] == 3
            and prepared["currentContainer"]["phase"] == "created", "canonical never-started prepared peer")
        container = pin(prepared["currentContainer"]["id"])
        launch = uid(prepared["specification"]["shimLaunchUUID"])
        instance = str(uuid.UUID(prepared["currentContainer"]["instanceID"]))
        storage_mode = "none"  # No shared-storage grant before the first start.
    args = process.arguments
    require(len(args) == 6 and args[0] == str(daemon.binary) and Path(process.executable).resolve() == daemon.binary.resolve() and args[1:3] == ("vm-shim", "--spec") and args[4] == "--launch-intent", "exact workload binary/argv")
    path = Path(args[3]); generation = path.parent.name
    require(re.fullmatch(r"[0-9]{20}-" + re.escape(launch), generation) and path == root / "containers" / container / "shim-generations" / generation / "spec.json" and args[5] == str(path.parent / "intent.json"), "exact immutable workload generation")
    with Directory(daemon.work) as work, Directory(daemon.root, private=False) as store, Directory(path.parent, private=False) as directory:
        marker, _ = work.read(".cengine-compat-owner", 4096)
        require(Path(os.fsdecode(marker).strip()).resolve() == daemon.binary.resolve(), "signed runner root ownership")
        require(Directory.stamp(os.fstat(store.fd))[:2] == (root_identity["device"], root_identity["inode"]), "owned store inode")
        inputs = {n: directory.read(n, 1024 * 1024, pin_file=True) for n in ("intent.json", "launch.json", "spec.json")}
        launch_intent, record, spec = (decode(inputs[n][0], 1024 * 1024, canonical_only=False) for n in ("intent.json", "launch.json", "spec.json"))
        common = {"schemaVersion", "nonce", "createdAt", "specificationPath", "executablePath", "containerDirectoryIdentity", "generationsDirectoryIdentity", "generationDirectoryIdentity", "specification", "container"}
        exact(launch_intent, common)
        exact(record, common | {"processIdentifier", "processStartTime"} | ({"kernelIdentity"} if prepared is None else set()))
        require(launch_intent["schemaVersion"] == 2 and all(record[k] == launch_intent[k] for k in common) and launch_intent["specification"] == spec and launch_intent["nonce"] == launch and launch_intent["executablePath"] == str(daemon.binary) and launch_intent["specificationPath"] == str(path), "immutable schema-2 launch")
        require(spec["kind"] == "container" and spec["workloadStorageMode"] == storage_mode and spec["containerID"] == container and spec["shimLaunchUUID"] == launch and spec["generation"] == int(generation[:20]), "actual owned workload storage mode")
        if prepared is not None:
            require(prepared["specification"] == spec and prepared["currentContainer"] == launch_intent["container"]
                and prepared["directoryIdentity"] == launch_intent["containerDirectoryIdentity"]
                and prepared["artifacts"]["directoryIdentity"] == prepared["directoryIdentity"], "canonical prepared generation binding")
        saved = launch_intent["container"]
        require(saved["id"] == container and str(uuid.UUID(saved["instanceID"])) == instance and saved["name"] == plan["container"] and saved["labels"].get(OWNER) == plan["owner"], "owned container instance")
        if prepared is None:
            birth = record["kernelIdentity"]
            exact(birth, {"pid", "startSeconds", "startMicroseconds", "uniqueID", "bootUUID"})
            require(birth["pid"] == record["processIdentifier"] == process.pid and (birth["startSeconds"], birth["startMicroseconds"], birth["uniqueID"]) == process.identity and record["processStartTime"] == process.identity[0] * 1000000 + process.identity[1], "native launch birth")
        else:
            # Production omits kernelIdentity for this never-started unbound peer.
            # Its immutable PID/start must still match the independent native
            # capture; prepared_peer_owner revalidates that full live identity.
            require(all(type(value) is int for value in (launch_intent["schemaVersion"], record["schemaVersion"], record["processIdentifier"], record["processStartTime"]))
                and record["processIdentifier"] == process.pid
                and record["processStartTime"] == process.identity[0] * 1000000 + process.identity[1], "native prepared launch birth")
        for key, p in (("containerDirectoryIdentity", path.parents[2]), ("generationsDirectoryIdentity", path.parents[1]), ("generationDirectoryIdentity", path.parent)):
            observed = p.lstat(); identity = launch_intent[key]
            require((observed.st_dev, observed.st_ino) == (identity["device"], identity["inode"]) and identity["volumeUUID"] == root_identity["volumeUUID"], "native directory identity")
        # Pin the actual workload disk and I/O share as in the established
        # workload_target discipline; neither a decoded spec nor PID is enough.
        container_path = path.parents[2]
        disk_path = container_path / "root.ext4"
        disk = os.open(disk_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        directory.stack.callback(os.close, disk)
        disk_info = os.fstat(disk); disk_identity = spec["rootDiskIdentity"]
        require(stat.S_ISREG(disk_info.st_mode) and disk_info.st_uid == os.geteuid() and not disk_info.st_mode & 0o022 and disk_info.st_nlink == 1 and spec["rootDiskPath"] == str(disk_path) and spec["rootDiskReadOnly"] is False and not spec["volumeDisks"] and 0 < spec["rootDiskSize"] == disk_info.st_size and (disk_info.st_dev, disk_info.st_ino) == (disk_identity["device"], disk_identity["inode"]) and disk_identity["volumeUUID"] == root_identity["volumeUUID"], "exact workload disk binding")
        require(len(spec["bindShares"]) == 1, "exact workload I/O share")
        share = spec["bindShares"][0]
        exact(share, {"tag", "source", "readOnly", "sourceIdentity"})
        require(share["tag"] == "cengine-io" and share["source"] == str(container_path / "io") and share["readOnly"] is False, "owned I/O share")
        io_directory = Directory(container_path / "io")
        directory.stack.callback(io_directory.close)
        io_identity = share["sourceIdentity"]
        require(Directory.stamp(os.fstat(io_directory.fd))[:2] == (io_identity["device"], io_identity["inode"]) and io_identity["volumeUUID"] == root_identity["volumeUUID"], "native workload I/O identity")
        def revalidate():
            work.validate(); store.validate(); directory.validate(); io_directory.validate()
            visible, held = disk_path.lstat(), os.fstat(disk)
            require(Directory.stamp(visible) == Directory.stamp(held) == Directory.stamp(disk_info) and visible.st_nlink == held.st_nlink == 1 and visible.st_size == held.st_size == disk_info.st_size, "workload disk changed")
            for n, original in inputs.items(): require(directory.read(n, 1024 * 1024) == original, "launch inputs changed")
        revalidate()
        yield {**native_proof(process), "container": container, "launch": launch, "sha256": {n: item[1][-1] for n, item in inputs.items()}}, saved, revalidate


def running_receipts(manifest, state, plan, container, intent_id, stopped=False):
    require(intent_id in state["intents"], "exact intent exists")
    selected = state["intents"][intent_id]
    receipt_proof(manifest, {**state, "intents": {intent_id: selected}}, plan["volume"], [container], stopped=stopped)
    return selected


def early_evidence_location(evidence, work, root):
    evidence, work, root = (Path(p).resolve() for p in (evidence, work, root))
    require(root == work / "root", "actual Daemon root layout required")
    require(all(evidence != other and other not in evidence.parents and evidence not in other.parents for other in (work, root)), "fresh external early evidence must be disjoint from daemon paths")


def early_empty_evidence(directory):
    directory.validate()
    with os.scandir(directory.fd) as entries:
        require(next(entries, None) is None, "fresh empty early evidence directory required")


def early_fresh_state(state, volume_name):
    """Durable tombstones prevent reusing one Daemon for multiple fault cases."""
    require(state["intents"] == {} and len(state["volumes"]) == 1, "fresh per-fault managed root required")
    volume = next(iter(state["volumes"].values()))
    require(volume["name"] == volume_name and all(volume.get(k) is None for k in ("deletedRevision", "localDeletionRevision")), "one fresh owned volume")


def failed_early_prepare(intent, arm):
    require(type(arm["version"]) is int and arm["version"] == 2 and arm["profile"] == EARLY_PROFILE and arm["caseName"] in EARLY_COUNTERS, "v2 failed early arm required")
    failed_prepare(intent, arm)
    require(intent.get("cleanUnmount") is False, "no fabricated successful PREPARE close")
    rows = [{k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]]
    require(sorted(rows, key=lambda s: s["attachment"]) == arm["slots"], "entire failed slot tuple unchanged")
    credentials = {c["attachment"]: c for c in arm["credentials"]}
    for slot in intent["slots"]:
        if slot["role"] == "prepare":
            require(slot.get("key") == credentials[slot["attachment"]]["key"], "failed installed key unchanged")
            exact(slot["receipt"], {"store", "volume", "attachment", "prepare", "launch", "revision"})
    return intent


def failed_prepare(intent, arm):
    require(all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "failed exact scope")
    require(intent["phase"] == "quarantined" and intent["prepareCompleted"] is False and intent.get("guestCompletion") is None and intent.get("quarantineReason"), "production failed-start quarantine")
    require(len(intent["slots"]) == 2 and {s["attachment"] for s in intent["slots"]} == {s["attachment"] for s in arm["slots"]}, "full failed slot set")
    for slot in intent["slots"]:
        if slot["role"] == "runtime":
            require(slot.get("key") is None and slot.get("receipt") is None, "no premature runtime credential/publication")
        else:
            receipt = slot.get("receipt")
            require(type(receipt) is dict and all(receipt.get(k) == v for k, v in {"store": intent["store"], "volume": slot["volume"], "attachment": slot["attachment"], "prepare": intent["prepare"], "launch": intent["launch"]}.items()), "actual PREPARE retire/drain")
            integer(receipt["revision"], minimum=1)
    return intent
