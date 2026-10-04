"""Finite RTM099 VM-cut carrier helpers; not a native campaign or acceptance.

The parent orchestrator must retain RTM099 actual storage-kill ownership and
production recovery. This module neither kills nor clears/reinitializes data.
"""
import copy
import re
import struct
import managed_prepare_faults as p

CASES = ("vm-private-bound", "vm-root-synced-before-cleanup", "vm-cleaning-transaction-removed")


def selection(profile, cases, case):
    p.require(profile == p.FULL_PROFILE and tuple(cases) == CASES and case in CASES,
              "closed three VM cuts")
    return dict(profile=profile, caseName=case, fullAcceptance=False,
                recovery="fresh-owner-private-replay" if case == CASES[0] else "complete-tree-readback")


def arm_candidate(candidate, capture, previous, case):
    p.require(case in CASES, "closed VM cut")
    return p._arm_candidate(candidate, capture, previous, case,
                            version=3, profile=p.FULL_PROFILE, cases=CASES)


def root_observation(value, arm):
    p.require(arm["caseName"] == CASES[1] and value["stage"] == CASES[1], "root fsync cut, never A7")
    # Same physical DTO: staged is the sealed z identity now in the public root.
    translated = copy.deepcopy(value)
    translated["stage"] = "first-child-published"
    p._physical_observation(translated, arm, version=3, profile=p.FULL_PROFILE, cases=(CASES[1],))
    return value


def storage_query(arm, worker):
    p.require(type(arm["version"]) is int and arm["version"] == 3 and
              arm["profile"] == p.FULL_PROFILE and arm["caseName"] in (CASES[0], CASES[2]),
              "closed VM storage arm")
    p.require(len(arm["mounts"]) == 1 and len(arm["slots"]) == 2 and len(arm["credentials"]) == 1,
              "single-volume VM arm")
    return dict(version=3, profile=p.FULL_PROFILE, requestID=p.uid(arm["requestID"]),
                armDigest=p.digest(p.canonical(arm)), workerUUID=p.uid(worker))


def cleaning_intent(value, arm):
    """Validate actual CLEANING metadata without mutating the retained evidence."""
    p.require(value["phase"] == "CLEANING", "actual CLEANING intent")
    p.integer(value["manifest_size"], 64 * 1024 * 1024, 1)
    p.pin(value["manifest_digest"])
    p.require(value["manifest_digest"] != "0" * 64, "sealed manifest digest")
    row = value["cleanup"]
    p.exact(row, {"uid", "gid", "mode", "atime_seconds", "mtime_seconds", "atime_nanos", "mtime_nanos", "manifest", "staging"})
    for key in ("uid", "gid"): p.integer(row[key], 2**32 - 2)
    p.integer(row["mode"], 0o7777)
    for key in ("atime_seconds", "mtime_seconds"):
        p.require(type(row[key]) is str and re.fullmatch(r"0|-?[1-9][0-9]*", row[key]), "canonical cleanup seconds")
        p.integer(int(row[key]), 2**63 - 1, -(2**63))
    for key in ("atime_nanos", "mtime_nanos"): p.integer(row[key], 10**9 - 1)
    for key, kind in (("manifest", 32768), ("staging", 16384)):
        obj = row[key]
        p.exact(obj, {"inode", "generation", "file_type", "handle_type", "handle_size", "handle"})
        for field in ("inode", "generation", "file_type", "handle_type", "handle_size"):
            p.integer(obj[field], 2**32 - 1)
        p.pin(obj["handle"], 16)
        p.require(obj["inode"] > 0 and obj["file_type"] == kind and obj["handle_type"] == 1 and obj["handle_size"] == 8 and
                  struct.unpack("<II", bytes.fromhex(obj["handle"])) == (obj["inode"], obj["generation"]), "actual cleanup object identity")
    p.require(len({value["root"]["root"]["inode"], value["transaction"]["inode"], row["manifest"]["inode"], row["staging"]["inode"]}) == 4,
              "distinct cleanup provenance objects")
    # Reuse shared exact owner/root/initial checks on a VALUE COPY only.
    bound = copy.deepcopy(value)
    zero = dict(inode=0, generation=0, file_type=0, handle_type=0, handle_size=0, handle="0" * 16)
    bound.update(phase="BOUND", manifest_size=0, manifest_digest="0" * 64,
                 cleanup=dict(uid=0, gid=0, mode=0, atime_seconds="0", mtime_seconds="0",
                              atime_nanos=0, mtime_nanos=0, manifest=zero, staging=zero))
    p.storage_bound_intent(bound, arm)
    return value


def storage_observation(value, arm, worker):
    query = storage_query(arm, worker)
    p.exact(value, {*query, "stage", "count", "targetAttachment", "bound"})
    expected = dict(**query, stage=arm["caseName"], count=1, targetAttachment=arm["targetAttachment"])
    p.require(p.canonical({k: value[k] for k in expected}) == p.canonical(expected), "exact VM checkpoint binding")
    p.exact(value["bound"], {"requestSequence", "intent"})
    p.integer(value["bound"]["requestSequence"], minimum=1)
    validator = cleaning_intent if arm["caseName"] == CASES[2] else p.storage_bound_intent
    validator(value["bound"]["intent"], arm)
    p.require(len(p.canonical(value)) <= 8192, "bounded VM observation")
    return value


def private_observation(value, arm, worker):
    p.require(arm["caseName"] == CASES[0], "private cut only")
    return storage_observation(value, arm, worker)


def cleaning_observation(value, arm, worker):
    p.require(arm["caseName"] == CASES[2], "cleaning cut only")
    return storage_observation(value, arm, worker)


def cleaning_source_observation(value, arm, checkpoint, worker):
    """Pair first-publication source metadata with the same later CLEANING hold.

    The returning physical witness does not authorize PREPARE success or release
    the storage hold. Both independent observations must be retained before death.
    """
    p.require(arm["caseName"] == CASES[2], "CLEANING source witness only")
    cleaning_observation(checkpoint, arm, worker)
    p._physical_observation(value, arm, version=3, profile=p.FULL_PROFILE, cases=(CASES[2],))
    intent = checkpoint["bound"]["intent"]
    p.require(value["copyIntent"] == intent["id"] and
              value["filesystemUUID"] == intent["root"]["backing_uuid"] and
              value["manifestDigest"] == intent["manifest_digest"] and
              value["manifestSize"] == intent["manifest_size"], "same sealed CLEANING copy and manifest")
    for name, identity in (("root", intent["root"]["root"]), ("transaction", intent["transaction"])):
        expected = dict(inode=identity["inode"], generation=identity["generation"],
                        fileType=identity["file_type"], handle=identity["handle"])
        p.require(value[name] == expected, "same actual root and transaction handles")
    cleanup = intent["cleanup"]
    p.require(len({value[k]["inode"] for k in ("root", "transaction", "published", "staged")} |
                  {cleanup[k]["inode"] for k in ("manifest", "staging")}) == 6,
              "distinct sealed children and cleanup provenance")
    p.require(value["sourceAtimes"]["root"] == int(cleanup["atime_seconds"]) * 10**9 + cleanup["atime_nanos"],
              "saved cleanup root timestamp matches the pre-read source witness")
    return value


def storage_status(value, arm, worker, *, phase="observed", checkpoint=None):
    p.require(phase in ("armed", "observed"), "VM holds never released or drained")
    fields = {"query", "state", "retirementStarted", "acceptedInFlight", "lateAdmissionRejected", "receiptReplayCount"}
    p.exact(value, fields | ({"observation"} if phase == "observed" else set()))
    p.require(p.canonical(value["query"]) == p.canonical(storage_query(arm, worker)), "current worker/query")
    p.require(value["state"] == phase and value["retirementStarted"] is False and value["lateAdmissionRejected"] is False,
              "held VM state is not retirement/drain")
    p.integer(value["acceptedInFlight"], 2**32 - 1)
    p.integer(value["receiptReplayCount"], 0)
    if phase == "armed":
        p.require(value["acceptedInFlight"] == 0, "unobserved arm")
    else:
        p.require(value["acceptedInFlight"] > 0, "actual held obligation")
        storage_observation(value["observation"], arm, worker)
        if checkpoint is not None:
            p.require(p.canonical(value["observation"]) == p.canonical(checkpoint), "immutable VM checkpoint")
    return value
