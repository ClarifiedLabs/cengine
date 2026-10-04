"""Independent two-volume root backing observations; never authority or native PASS."""
import copy
import stat

import managed_prepare_faults as p
from managed_retained_reader import RetainedReader

ROOT_CASES = ("cross-mount-root-grant", "retired-root-grant-replay")
NAME = "rtm103-root-object"
CONTENTS = {"/data": b"A" * 32, "/other": b"B" * 32}
_METADATA = {"mode", "uid", "gid", "atimeNS", "mtimeNS", "ctimeNS", "xattrs"}


def snapshot(value):
    p.exact(value, {"command", "roots", "mountinfo", "completed"})
    p.require(value["command"] == "root-snapshot" and value["completed"] is True, "actual completed root reader")
    p.exact(value["roots"], CONTENTS)
    p.require(type(value["mountinfo"]) is str and len(value["mountinfo"].encode()) <= 65536, "bounded mountinfo")
    mounts = {}
    for line in value["mountinfo"].splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[4] not in CONTENTS:
            continue
        path = fields[4]
        p.require(path not in mounts and fields.count("-") == 1, "one mount per backing")
        split = fields.index("-")
        p.require(split >= 6 and len(fields) == split + 4 and fields[3] == "/"
            and fields[split + 1:split + 3] == ["fuse.managed-v3", "managed-v3"]
            and "rw" in fields[5].split(",") and "ro" not in fields[5].split(","), "actual independently writable managed mounts")
        p.require(fields[0].isdigit() and int(fields[0]) > 0, "mount identity")
        mounts[path] = fields[0]
    p.require(set(mounts) == set(CONTENTS) and len(set(mounts.values())) == 2, "two distinct installed mounts")
    for path, raw in CONTENTS.items():
        item = value["roots"][path]
        p.exact(item, {"entries", "root", "object"})
        p.require(item["entries"] == [NAME], "exclusive fixed object namespace")
        for regular, entry in ((False, item["root"]), (True, item["object"])):
            p.exact(entry, _METADATA | ({"size", "sha256", "nlink"} if regular else set()))
            for field, expected in (("mode", (stat.S_IFREG | 0o640) if regular else (stat.S_IFDIR | 0o750)), ("uid", 10001), ("gid", 10002)):
                p.integer(entry[field]); p.require(entry[field] == expected, "root exact owner/mode")
            p.require(type(entry["xattrs"]) is dict and entry["xattrs"] == {}, "root exact xattrs")
            for field in ("atimeNS", "mtimeNS", "ctimeNS"):
                p.integer(entry[field], 2**63 - 1, -(2**63))
            if regular:
                p.integer(entry["size"], 32, 32); p.integer(entry["nlink"], 1, 1)
                p.pin(entry["sha256"]); p.require(entry["sha256"] == p.digest(raw), "distinct volume-exclusive original contents")
    return value


def unchanged(value, before):
    snapshot(before); snapshot(value)
    p.require(p.canonical(value["roots"]) == p.canonical(before["roots"]),
        "both independent backings unchanged, including ctime and complete namespace")
    return value


def report(value):
    snapshot(value)
    return {k: copy.deepcopy(v) for k, v in value.items() if k != "mountinfo"}


def baseline_marker(binding, original, reader, value):
    snapshot(value)
    p.require(binding["caseName"] in ROOT_CASES and original["id"] == binding["scope"]["intent"], "root original binding")
    p.require(reader["id"] != original["id"] and reader["container"] != original["container"]
        and reader["launch"] != original["launch"] and reader["phase"] == "running" and reader["prepareCompleted"] is True,
        "independently running reader")
    for field in ("store", "serviceEpoch", "controllerEpoch", "controllerKey"):
        p.require(reader[field] == original[field], "same current reader authority context")
    source = sorted((s for s in original["slots"] if s["role"] == "runtime"), key=lambda s: s["attachment"])
    peers = [s for s in reader["slots"] if s["role"] == "runtime"]
    p.require(len(source) == len(peers) == 2 and source[0]["attachment"] == binding["targetAttachment"], "exact two mounted slots")
    p.require(len({s["volume"] for s in source}) == 2 and {s["volume"] for s in source} == {s["volume"] for s in peers}, "independent same-volume pair")
    pair = []
    for slot in source:
        peer = next(s for s in peers if s["volume"] == slot["volume"])
        p.require(slot.get("receipt") is None and peer.get("receipt") is None and peer["mode"] == "read-write"
            and peer["attachment"] != slot["attachment"] and peer["key"] != slot["key"], "undrained independent reader grant")
        mounts = [m for m in original["mounts"] if m["volume"] == slot["volume"]]
        reader_mounts = [m for m in reader["mounts"] if m["volume"] == slot["volume"]]
        p.require(len(mounts) == len(reader_mounts) == 1 and mounts[0]["destination"] in CONTENTS
            and reader_mounts[0]["destination"] == mounts[0]["destination"], "exact backing mount mapping")
        pair.append(dict(volume=p.uid(slot["volume"]), readerAttachment=p.uid(peer["attachment"]), readerKey=p.pin(peer["key"]),
            contentSHA256=value["roots"][mounts[0]["destination"]]["object"]["sha256"]))
    p.require(len({s["readerAttachment"] for s in pair}) == len({s["readerKey"] for s in pair}) == 2, "distinct independent keys/attachments")
    return dict(version=2, binding=copy.deepcopy(binding), readerIntent=p.uid(reader["id"]),
        readerAttachment=pair[0]["readerAttachment"], readerKey=pair[0]["readerKey"],
        snapshotSHA256=p.digest(p.canonical(report(value))), rootPair=pair)


def baseline_accepted(value, marker):
    fields = {"version", "binding", "readerIntent", "readerAttachment", "readerKey", "snapshotSHA256", "rootPair"}
    p.exact(value, fields); p.exact(marker, fields)
    p.integer(value["version"], 2, 2)
    p.require(p.canonical(value) == p.canonical(marker), "exact pinned root baseline echo")
    return value


def project_backing(result, marker, baseline, after, original, reader):
    """Join disk corroboration to the sealed root result; not a result validator.

    The caller must additionally validate the full authority/Admit/finalization
    projection. A successful filesystem snapshot alone is never root acceptance.
    """
    expected = baseline_marker(marker["binding"], original, reader, baseline)
    baseline_accepted(marker, expected)
    baseline_accepted(result["baseline"], marker)
    p.require(p.canonical(result["binding"]) == p.canonical(marker["binding"]), "same root generation")
    correlate_positive(result["positive"], marker)
    unchanged(after, baseline)
    return dict(baseline=report(baseline), after=report(after), snapshotSHA256=marker["snapshotSHA256"])


def correlate_positive(positive, marker):
    p.require(marker["version"] == 2 and marker["binding"]["caseName"] in ROOT_CASES, "root baseline version")
    roots = positive["roots"]
    for item, observed in zip(marker["rootPair"], (roots["source"], roots["target"]), strict=True):
        p.require(item["volume"] == observed["read"]["authority"]["binding"]["volume"]
            and item["contentSHA256"] == observed["read"]["contentSHA256"], "independent backing matches original client wire READ")


class RootBackingReader(RetainedReader):
    """Prestart before capture; trigger once after Arm on the owned stream only."""
    def __init__(self, api, owner, remaining):
        super().__init__(api, owner, remaining, command="root-wait")

    def baseline(self, before):
        return unchanged(self.snapshot(), before)
