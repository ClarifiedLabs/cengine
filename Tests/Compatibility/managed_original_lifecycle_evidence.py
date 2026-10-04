"""RTM103 ORIGINALCONSUMER v2 comparisons; no credential or native authority.

The common worker checkpoint/native selectors are reusable. PREPARE cut receipt
oracles are not: these fifteen routes observe actual original consumers. TLS
bytes must come from the caller's retained live public peer evidence, never be
invented from a checkpoint hash. Legacy branches are temporary test adapters.
"""
import managed_prepare_faults as p
import managed_prepare_worker_lifecycle_evidence as worker
import managed_storage_recovery as recovery
from managed_prepare_storage_vm_faults import bounded_base64

VERSION = worker.VERSION
read_owner = worker.read_owner
owner = worker.owner
history = worker.history
is_v2 = worker.shared.is_v2


def replacement_proof(before, after, pending, succeeded, request, state, hashes, containers, submitted, observed):
    if not is_v2(before) and not is_v2(after):
        return recovery.replacement_proof(before, after, pending, succeeded, request, state, hashes, containers, submitted, observed)
    p.require(is_v2(before) and is_v2(after), "same explicit original-consumer evidence format")
    old, _ = owner(before); new, _ = owner(after)
    a, b = before["checkpoint"], after["checkpoint"]
    p.require(not history(before) and len(history(after)) == 1, "one original-consumer replacement")
    p.require(before["manifest"] == after["manifest"] and all(a[k] == b[k] for k in
        ("identity", "rootPublicKey", "provenanceReference", "current")), "same physical ROOT/controller owner")
    p.require(new["revision"] > old["revision"] and new["workerUUID"] != old["workerUUID"], "fresh worker/checkpoint")
    change, retry = b["latestServiceChange"], b["latestServiceRequest"]
    p.require(change["predecessor"] == a["currentContext"]
        and b["latestServiceConfirmation"]["request"]["predecessor"] == a["currentService"]
        and retry["predecessorWorkerUUID"] == old["workerUUID"], "exact predecessor service/worker")
    recovery.worker_request(request["operationUUID"], request["store"], request["predecessor"])
    p.require(request["store"] == old["store"] and request["predecessor"] ==
        {k: old[k] for k in ("serviceEpoch", "workerUUID")} and change["operationID"] == request["operationUUID"], "exact replacement operation")
    proof = dict(controllerEpoch=old["controllerEpoch"], controllerKey=old["controllerKey"], rootPublicKey=a["rootPublicKey"])
    common = {"schema", "counter", "phase", "request", "proof"}
    for receipt, phase in ((pending, "pending"), (succeeded, "succeeded")):
        p.exact(receipt, common | ({"ownerRequest", "successor", "containedContainerIDs"} if phase == "succeeded" else set()))
        p.integer(receipt["schema"], 1, 1); p.integer(receipt["counter"], 1, 1)
        p.require(receipt["phase"] == phase and receipt["request"] == request and receipt["proof"] == proof, "exact original replacement receipt")
    actual = succeeded["ownerRequest"]
    p.exact(actual, {"operationUUID", "predecessor", "nowUnixSeconds"}); p.integer(actual["nowUnixSeconds"], 253402300799, 1)
    p.require(actual == dict(operationUUID=request["operationUUID"], predecessor=request["predecessor"], nowUnixSeconds=retry["nowUnixSeconds"])
        and submitted <= actual["nowUnixSeconds"] <= observed, "actual owner request/time window")
    p.require(succeeded["successor"] == {k: new[k] for k in ("serviceEpoch", "workerUUID")}, "exact successor receipt")
    p.require(len(containers) == len(set(containers)) == 2 and succeeded["containedContainerIDs"] == sorted(containers),
        "complete original/peer containment receipt, not native exit proof")
    for container in containers: p.pin(container)
    worker.census(b, state, hashes)
    return new


def server_spki(der):
    """Extract bounded DER SPKI for comparison only, not X.509 verification."""
    def item(data, at):
        p.require(at + 2 <= len(data), "bounded DER header")
        start = at; tag, size = data[at:at + 2]; at += 2
        if size & 128:
            count = size & 127
            p.require(0 < count <= 2 and at + count <= len(data) and data[at] != 0, "canonical DER length")
            size = int.from_bytes(data[at:at + count], "big"); at += count
            p.require(size >= 128, "minimal DER length")
        end = at + size
        p.require(end <= len(data), "bounded DER value")
        return tag, data[at:end], data[start:end], end
    tag, certificate, _, end = item(der, 0)
    p.require(tag == 48 and end == len(der), "one DER certificate")
    tag, tbs, _, at = item(certificate, 0)
    p.require(tag == 48, "certificate TBS sequence")
    tag, _, _, offset = item(tbs, 0)
    if tag != 160: offset = 0
    for expected in (2, 48, 48, 48, 48):
        tag, _, _, offset = item(tbs, offset)
        p.require(tag == expected, "certificate serial/signature/issuer/validity/subject")
    tag, _, spki, _ = item(tbs, offset)
    p.require(tag == 48, "certificate SPKI sequence")
    return p.digest(spki)


def comparison(projection, peer=None):
    """Tagged public comparison view for existing wire oracles, NOT a boot.

    `ready` is only their shared field vocabulary. No disk/boot binding,
    transition chain, VerifiedBoot constructor or credential is produced.
    The live caller must retain/revalidate the source of `peer` independently.
    """
    if not is_v2(projection): return projection
    ready = worker.public_service(projection)
    p.require(peer is not None, "v2 original consumer requires retained live public TLS peer evidence; shared fixture caller missing")
    p.exact(peer, {"tlsRootDER", "serverDER", "serverKey", "dataAddress"})
    root = bounded_base64(peer["tlsRootDER"], 16384)
    server = bounded_base64(peer["serverDER"], 16384)
    boot = projection["workerEvidence"]["checkpoint"]["currentService"]["boot"]
    p.require(p.digest(root) == boot["tls_root_sha256"] and
        server_spki(server) == peer["serverKey"] == boot["server_spki"], "actual public TLS bytes match ROOT-confirmed service")
    p.require(type(peer["dataAddress"]) is str and 0 < len(peer["dataAddress"].encode()) <= 256, "bounded transport, not authority")
    return dict(format=VERSION, ready={**ready, **peer},
        lifecycleIdentity=dict(projection["workerEvidence"]["checkpoint"]["identity"]))


def comparison_identity(comparison):
    """Independent owner identity for schema-4 comparisons, never result-derived."""
    if not is_v2(comparison):
        p.require("format" not in comparison and "lifecycleIdentity" not in comparison,
            "no untagged lifecycle identity or unknown comparison format")
        return None
    p.exact(comparison, {"format", "ready", "lifecycleIdentity"})
    identity = comparison["lifecycleIdentity"]
    p.exact(identity, {"store", "generation", "binding"})
    p.uid(identity["store"]); p.integer(identity["generation"], 2**64 - 1, 1); p.pin(identity["binding"])
    p.require(identity["store"] == comparison["ready"]["storeUUID"], "owner identity matches public service")
    return identity


def peer_comparison(projection, reader):
    if not is_v2(projection): return projection
    p.require(callable(reader), "v2 original consumer shared fixture lacks retained live TLS peer reader")
    return comparison(projection, reader(projection))
