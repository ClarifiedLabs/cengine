"""Retained-FD backing checks; import is engine-free, never native acceptance.

These public observations are corroboration, never runtime authority. The
backing hash must never substitute for the original-consumer v5/v7 / same-E
worker v8 positive and negative witnesses.
"""
import copy
import stat

import managed_prepare_faults as p

FD_CASES = ("same-e-retained-fd", "cross-e-retained-fd")
FD_GUEST_VERSION = 5
FD_SAME_E_GUEST_VERSION = 7
FD_WORKER_VERSION = 8

_METADATA = {"mode", "uid", "gid", "atimeNS", "mtimeNS", "ctimeNS", "xattrs"}
_SNAPSHOT = {"command", "entries", "root", "files", "mountinfo", "parentFsynced"}


def retained_snapshot(value, command="retained-snapshot"):
    """Validate the separate bounded helper schema, not the NORMAL snapshot."""
    p.require(command in ("retained-snapshot", "retained-write"), "fixed retained command")
    writing = command == "retained-write"
    p.exact(value, _SNAPSHOT | ({"written", "completed"} if writing else set()))
    p.require(value["command"] == command and value["parentFsynced"] is False, "retained command/ACK")
    if writing:
        p.integer(value["written"], 1, 1)
        p.require(value["completed"] is True, "actual one-byte WriteAt plus Sync completion")
    mounted = p.mount_proof(value["mountinfo"])
    fields = mounted["raw"].split()
    p.require("rw" in fields[5].split(",") and "ro" not in fields[5].split(","), "actual writable runtime mount")
    p.require(value["entries"] == ["a", "z"], "exact retained namespace")
    p.exact(value["files"], p.FILES)
    for name, entry in [("root", value["root"]), *value["files"].items()]:
        regular = name != "root"
        p.exact(entry, _METADATA | ({"size", "sha256", "nlink"} if regular else set()))
        mode = (stat.S_IFREG | 0o640) if regular else (stat.S_IFDIR | 0o750)
        for key, expected in (("mode", mode), ("uid", 10001), ("gid", 10002)):
            p.integer(entry[key]); p.require(entry[key] == expected, "exact retained owner/mode")
        p.require(type(entry["xattrs"]) is dict and entry["xattrs"] == {}, "exact retained xattrs")
        for key in ("atimeNS", "mtimeNS", "ctimeNS"):
            p.integer(entry[key], 2**63 - 1, -(2**63))
        if regular:
            p.integer(entry["size"], 4096, 1)
            p.integer(entry["nlink"], 1, 1)
            p.pin(entry["sha256"])
    return value


def _content(value, first_byte):
    for name, original in p.FILES.items():
        expected = bytes([first_byte]) + original[1:] if name == "a" else original
        entry = value["files"][name]
        p.require(entry["size"] == len(expected) and entry["sha256"] == p.digest(expected),
            "exact one-byte mutation and unchanged remaining fixture bytes")


def _unchanged_except_write(value, before):
    p.require(value["root"] == before["root"] and value["files"]["z"] == before["files"]["z"],
        "unchanged root and z, including ctime")
    changed = {"sha256", "mtimeNS", "ctimeNS"}
    p.require({k: v for k, v in value["files"]["a"].items() if k not in changed} ==
        {k: v for k, v in before["files"]["a"].items() if k not in changed},
        "unchanged a metadata except write timestamps")


def retained_baseline(value, original):
    """Independent peer snapshot after armed: exact A5 and no collateral change.

    The original must itself be an earlier retained-snapshot, so ctime is never
    invented from the legacy NORMAL snapshot. This is not the guest positive
    syscall witness, which the caller must separately check in the final result.
    """
    retained_snapshot(original); retained_snapshot(value)
    _content(original, p.FILES["a"][0]); _content(value, 0xa5)
    p.require(all(entry["mtimeNS"] == p.MTIME * 10**9 for entry in
        (original["root"], *original["files"].values())), "original fixture mtimes")
    _unchanged_except_write(value, original)
    return value


def fresh_retained_snapshot(value, baseline):
    """Before any new write, require exact persisted postpositive metadata/bytes."""
    retained_snapshot(baseline); retained_snapshot(value)
    _content(baseline, 0xa5); _content(value, 0xa5)
    p.require(value["root"] == baseline["root"] and value["files"] == baseline["files"],
        "fresh legitimate owner preserves exact postpositive backing including ctime")
    return value


def fresh_retained_write(value, before):
    """Check actual WriteAt(0, 5A)+Sync witness and independent resulting bytes."""
    retained_snapshot(before); retained_snapshot(value, "retained-write")
    _content(before, 0xa5); _content(value, 0x5a)
    _unchanged_except_write(value, before)
    p.require(value["files"]["a"]["sha256"] != before["files"]["a"]["sha256"], "distinct fresh write")
    return value


def observe_fresh_retained(observe, owner, baseline):
    """Caller must pin/validate the actual fresh owner before each Docker exec."""
    before = fresh_retained_snapshot(observe("retained-snapshot", owner), baseline)
    after = fresh_retained_write(observe("retained-write", owner), before)
    return before, after


def baseline_marker(binding, reader_intent, reader_attachment, reader_key, baseline):
    """Format public scheduling input only; binding is already runtime-validated.

    snapshotSHA256 covers the canonical report projection (without mountinfo),
    which the caller must fsync into its ledger before publishing this marker.
    This does not validate the reader's live runtime tuple or authorize Begin.
    """
    p.require(type(binding) is dict and binding and len(p.canonical(binding)) <= 32768, "bounded exact binding")
    p.uid(reader_intent); p.uid(reader_attachment); p.pin(reader_key)
    retained_snapshot(baseline); _content(baseline, 0xa5)
    report = {k: v for k, v in baseline.items() if k != "mountinfo"}
    return dict(version=1, binding=copy.deepcopy(binding), readerIntent=reader_intent,
        readerAttachment=reader_attachment, readerKey=reader_key, snapshotSHA256=p.digest(p.canonical(report)))


def baseline_accepted(value, marker):
    """An exact public echo is scheduling corroboration, not reader authority."""
    fields = {"version", "binding", "readerIntent", "readerAttachment", "readerKey", "snapshotSHA256"}
    p.exact(marker, fields); p.exact(value, fields)
    p.integer(marker["version"], 1, 1)
    p.require(type(marker["binding"]) is dict and marker["binding"], "exact binding")
    p.uid(marker["readerIntent"]); p.uid(marker["readerAttachment"])
    p.pin(marker["readerKey"]); p.pin(marker["snapshotSHA256"])
    p.require(p.canonical(value) == p.canonical(marker), "exact immutable baseline accepted echo")
    return value
