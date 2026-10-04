"""Strict RTM103 follow-up lifecycle-v2 comparisons, never native authority.

Public replay publication is a Host contract, not the child's observation DTO.
Keep those boundaries separate: do not turn checkpoints into v1 histories or
invent wrappers around the authenticated Query/remote-denial observations.
"""
import base64
import copy

import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as lifecycle
import managed_storage_recovery as recovery

VERSION = lifecycle.VERSION
REGISTRY_FIELDS = {"schema", "revision", "store", "epoch", "controller", "volumes", "volume_lifecycles", "attachments", "prepares"}
is_v2 = lifecycle.is_v2


def read_owner(root):
    return lifecycle.read_owner(root, recovery.read_public)


def owner_evidence(root, record, owner_hash):
    """Ledger-only projection of the exact validated v2 public file bytes.

    Nullable checkpoint fields belong to the durable schema, not the ledger's
    null-free JSON dialect. Never prune them or reserialize a checkpoint. Pin
    both original byte hashes again so a changed file cannot replace the owner
    used for the transition comparison.
    """
    if not is_v2(record):
        owner(record)
        return record
    lifecycle.owner_context(record)
    result = dict(format=VERSION, ownerSHA256=owner_hash)
    stamps = {}
    with p.Directory(recovery.runtime_root_path(root) / "managed-storage-owner") as directory:
        for field, name in (("checkpoint", "state.json"), ("manifest", "manifest.json")):
            raw, _ = directory.read(name, 262144)
            p.require(p.decode(raw, 262144, canonical_only=False) == record[field], "unchanged replay owner " + field)
            digest = p.digest(raw)
            stamps["state" if field == "checkpoint" else field] = digest
            result[field] = dict(base64=base64.b64encode(raw).decode("ascii"), sha256=digest)
    p.require(p.digest(p.canonical(stamps)) == owner_hash, "exact replay owner byte pins")
    return result


def owner(record):
    if is_v2(record):
        return lifecycle.owner_context(record)[0]
    p.require("format" not in record and "version" not in record, "explicit supported follow-up owner format")
    return recovery.owner_proof(record)


def same_service_step(before, after):
    p.require(is_v2(before) and is_v2(after), "same explicit lifecycle-v2 format")
    _, context = lifecycle.owner_context(before)
    lifecycle.transition(before, after, dict(scope=context), storage=False)
    a, b = before["checkpoint"], after["checkpoint"]
    # The common transition validator allows compaction of unreferenced rows.
    # References to surviving original consumers must still retain their proof.
    for reference in a["references"]:
        matches = [row for row in b["references"] if row["id"] == reference["id"]]
        p.require(len(matches) == 1 and matches[0]["version"] >= reference["version"], "retained original intent reference")
        for field in ("original", "superseded", "predecessor", "successor"):
            p.require(matches[0].get(field) == reference.get(field), "unchanged original intent reference " + field)
        recovery_proof = reference.get("recovery")
        if recovery_proof is not None:
            successor_proof = matches[0].get("recovery")
            p.require(successor_proof is not None
                and successor_proof["provenanceReference"] == recovery_proof["provenanceReference"],
                "retained recovery provenance")
            if successor_proof != recovery_proof:
                p.require(matches[0]["version"] > reference["version"] and
                    {key: successor_proof[key] for key in ("serviceEpoch", "controllerEpoch", "controllerKey")}
                    == b["currentContext"], "only versioned current-controller recovery update")
        p.require(any(row == old for row in b["contexts"] for old in a["contexts"]
            if old["context"] == reference["original"]), "retained original controller proof")
    return b["current"]["original"]["signed"], b["current"]["original"]["recipient"]


def replay_observation(before, after, request_id, observation):
    """The actual private child DTO, NOT a guessed public publication wrapper.

    Host must capture OLD from validated checkpoint.current.original.signed
    before issuing the normal ROOT candidate. The trusted child/ROOT validates
    signatures and obtains UNAUTHORIZED remotely; Python only correlates bytes.
    """
    p.uid(request_id)
    pending, recipient = same_service_step(before, after)
    old = before["checkpoint"]["current"]["original"]["signed"]
    p.require(old["grant"]["operation"] == "takeover" and old["grant"]["expected_epoch"] == 1,
        "C2 OLD takeover, not initial grant")
    p.exact(observation, {"version", "requestID", "old", "pending", "incarnationID", "error"})
    p.integer(observation["version"], 1, 1)
    p.uid(observation["requestID"]); p.uid(observation["incarnationID"])
    for field in ("old", "pending"):
        signed = observation[field]
        p.exact(signed, {"grant", "signature"})
        lifecycle.encoded(signed["signature"], 64)
        grant = signed["grant"]
        p.exact(grant, {"operation", "id", "identity", "serial", "expected_epoch", "new_key"})
        p.exact(grant["identity"], {"store", "generation", "binding"})
        p.uid(grant["id"]); p.uid(grant["identity"]["store"])
        p.integer(grant["identity"]["generation"], minimum=1); p.pin(grant["identity"]["binding"])
        p.integer(grant["serial"], minimum=1); p.integer(grant["expected_epoch"], minimum=1); p.pin(grant["new_key"])
    p.require(observation["requestID"] == request_id and observation["error"] == "UNAUTHORIZED"
        and observation["incarnationID"] == recipient["incarnation"]
        and p.canonical(observation["old"]) == p.canonical(old)
        and p.canonical(observation["pending"]) == p.canonical(pending),
        "exact signed OLD, normal ROOT candidate and actual remote denial")
    return dict(controlLegVerified=True, nativeAcceptance=False, fullAcceptance=False,
        requestID=request_id, observation=copy.deepcopy(observation))


def public_control_result(before, after, request_id, begun, denied, confirmed):
    """Correlate the frozen Host v2 publications with the actual child DTO.

    Metadata comparison is not cryptographic verification: ROOT/the signed
    child authenticate grants and remote denial before Host publishes these.
    """
    result = replay_observation(before, after, request_id, denied)
    p.exact(begun, {"version", "requestID", "old", "pending", "incarnationID"})
    p.integer(begun["version"], 2, 2)
    expected = {key: denied[key] for key in ("requestID", "old", "pending", "incarnationID")}
    p.require(p.canonical(begun) == p.canonical(dict(version=2, **expected)),
        "exact captured OLD and normal ROOT candidate before denied replay")
    p.exact(confirmed, {"version", "completion"}); p.integer(confirmed["version"], 2, 2)
    p.require(p.canonical(confirmed["completion"]) == p.canonical(after["checkpoint"]["current"]),
        "actual ROOT-confirmed checkpoint completion")
    return dict(controlLegVerified=result["controlLegVerified"], nativeAcceptance=False, fullAcceptance=False,
        requestID=request_id, denied=copy.deepcopy(denied), confirmed=copy.deepcopy(confirmed))


def registry(value, record, intent):
    """Frozen Host publication of a schema-4 Query and its fenced identity.

    Swift validates the Query's outer lifecycle_identity against the SAME fenced
    owner context before publishing that context's identity with the Snapshot.
    Preserve this closed wrapper; never insert identity into the Snapshot itself.
    """
    p.exact(value, {"version", "lifecycleIdentity", "registry"})
    p.integer(value["version"], 2, 2)
    snapshot, identity = value["registry"], value["lifecycleIdentity"]
    proof = lifecycle.owner_context(record)[0]
    p.exact(identity, {"store", "generation", "binding"})
    p.uid(identity["store"]); p.integer(identity["generation"], minimum=1); p.pin(identity["binding"])
    p.require(identity == proof["identity"], "actual Query full lifecycle identity")
    p.exact(snapshot, REGISTRY_FIELDS)
    p.integer(snapshot["schema"], 4, 4); p.integer(snapshot["revision"], minimum=1)
    p.require(snapshot["revision"] >= proof["confirmedRevision"], "Query not older than ROOT-confirmed controller")
    p.exact(snapshot["controller"], {"epoch", "key"})
    p.integer(snapshot["controller"]["epoch"], minimum=1); p.pin(snapshot["controller"]["key"])
    p.require(snapshot["store"]["id"] == proof["store"] and snapshot["epoch"] == proof["serviceEpoch"]
        and snapshot["controller"] == dict(epoch=proof["controllerEpoch"], key=proof["controllerKey"]),
        "actual Query matches validated checkpoint context")
    for name in ("volumes", "volume_lifecycles", "attachments", "prepares"):
        p.require(type(snapshot[name]) is dict, "complete Query map")
    contexts = [row["context"] for row in record["checkpoint"]["contexts"]]
    original_context = {key: intent[key] for key in ("serviceEpoch", "controllerEpoch", "controllerKey")}
    p.uid(original_context["serviceEpoch"]); p.integer(original_context["controllerEpoch"], minimum=1)
    p.pin(original_context["controllerKey"])
    p.require(intent["store"] == proof["store"] and original_context in contexts,
        "actual original intent retained in full-identity checkpoint")
    for prepare in snapshot["prepares"].values():
        context = prepare["context"]
        p.exact(context, {"service_epoch", "controller_epoch", "controller_key"})
        p.uid(context["service_epoch"]); p.integer(context["controller_epoch"], minimum=1); p.pin(context["controller_key"])
        p.require(dict(serviceEpoch=context["service_epoch"], controllerEpoch=context["controller_epoch"],
            controllerKey=context["controller_key"]) in contexts, "actual prepare retained context")
    import managed_stale_consumer as stale
    slot = stale.runtime_slots(intent, "takeover")[0]
    remote = snapshot["attachments"][slot["attachment"]]
    p.require(remote["phase"] == "ACTIVE" and remote.get("receipt") is None and remote.get("retirement") is None
        and remote["binding"]["key"] == slot["key"] and remote["binding"]["volume"] == slot["volume"],
        "original DATA remains active")
    return snapshot
