"""RTM098 worker-only v2 public comparisons, never VerifiedStorageServiceBoot.

The controller receipt remains at its original E. The actual ROOT service-change
confirmation, folded context and native configuration describe the new E. No v1
boot/transition is synthesized, and the API/cold campaign's adapter stays closed.
"""
import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as shared
import managed_storage_recovery as recovery


VERSION = shared.VERSION


def read_owner(root, reader):
    root = recovery.runtime_root_path(root)
    state, stamp = reader(root / "managed-storage-owner/state.json", 262144)
    if state.get("version") != VERSION:
        p.require("version" not in state, "unsupported worker owner version")
        return state, stamp
    manifest, manifest_stamp = reader(root / "managed-storage-owner/manifest.json", 262144)
    value = dict(format=VERSION, checkpoint=state, manifest=manifest)
    owner(value)
    return value, p.digest(p.canonical(dict(state=stamp, manifest=manifest_stamp)))


def public_context(value):
    p.exact(value, {"serviceEpoch", "controllerEpoch", "controllerKey"})
    p.uid(value["serviceEpoch"]); p.integer(value["controllerEpoch"], minimum=1); p.pin(value["controllerKey"])
    return value


def scope(service):
    context = service["context"]
    p.exact(context, {"service_epoch", "controller_epoch", "controller_key"})
    p.uid(context["service_epoch"]); p.integer(context["controller_epoch"], minimum=1); p.pin(context["controller_key"])
    return dict(serviceEpoch=context["service_epoch"], controllerEpoch=context["controller_epoch"], controllerKey=context["controller_key"])


def service(value, identity, current, root_key):
    p.exact(value, {"grant", "context", "boot", "open_revision"})
    context = scope(value)
    boot = value["boot"]
    p.exact(boot, {"identity", "service_epoch", "tls_root_sha256", "server_spki", "bootstrap_key"})
    for field in ("tls_root_sha256", "server_spki", "bootstrap_key"): p.pin(boot[field])
    grant = value["grant"]
    p.require(grant == current["original"]["signed"]["grant"] and grant["identity"] == identity
        and grant["new_key"] == context["controllerKey"] and grant["expected_epoch"] + 1 == context["controllerEpoch"]
        and boot["identity"] == identity and boot["service_epoch"] == context["serviceEpoch"]
        and boot["bootstrap_key"] == shared.fingerprint(root_key), "exact service ROOT/grant/boot/context")
    p.integer(value["open_revision"], minimum=1)
    return context


def owner(record):
    if not shared.is_v2(record): return recovery.worker_owner(record)
    p.exact(record, {"format", "checkpoint", "manifest"})
    state, manifest = record["checkpoint"], record["manifest"]
    if state.get("latestServiceChange") is None:
        result, _ = shared.owner_context(record)
        p.require(len(state["contexts"]) == 1 and state["current"]["original"]["signed"]["grant"]["operation"] == "initialize"
            and state.get("latestCold") is None and state.get("adoptionRetry") is None, "fresh worker-only lifecycle fixture")
        return result, dict(format=VERSION, workerEvidence=record)
    required = {"version", "identity", "rootPublicKey", "provenanceReference", "revision", "current", "currentContext",
        "currentService", "observedWorker", "contexts", "serviceLinks", "intentRevision", "references", "pendingCold", "latestCold",
        "latestServiceRequest", "latestServiceConfirmation", "latestServiceChange", "serviceReplacement", "nativeReplacementAttempted"}
    optional = {"pending", "pendingTakeover", "pendingService", "sealed", "terminal", "adoptionRetry"}
    p.require(required <= set(state) <= required | optional, "closed worker lifecycle checkpoint")
    p.exact(manifest, {"version", "identity", "rootPublicKey", "provenanceReference", "root", "backing", "directory", "lease", "bytes", "ext4UUID"})
    p.require(state["version"] == VERSION and manifest["version"] == shared.MANIFEST_VERSION, "explicit worker lifecycle version")
    for field in ("identity", "rootPublicKey", "provenanceReference"):
        p.require(state[field] == manifest[field], "immutable manifest correlation")
    for field in (*optional, "pendingCold", "latestCold"):
        p.require(state.get(field) is None, "settled fresh worker-only checkpoint")
    identity = state["identity"]
    p.exact(identity, {"store", "generation", "binding"}); p.uid(identity["store"])
    p.integer(identity["generation"], minimum=1); p.pin(identity["binding"]); p.pin(state["provenanceReference"])
    for field in ("root", "backing", "directory", "lease"): recovery.file_identity(manifest[field])
    p.integer(manifest["bytes"], 2**63 - 1, 1)
    # ext4 UUID is not restricted to UUIDv4.
    import uuid
    p.require(str(uuid.UUID(manifest["ext4UUID"])) == manifest["ext4UUID"] and uuid.UUID(manifest["ext4UUID"]).int != 0, "canonical ext4 UUID")
    p.require(identity["binding"] == p.digest(b"cengine.storageauthority.binding.v3\0" + p.canonical(shared.manifest_binding(manifest))), "physical manifest digest")
    p.integer(state["revision"], minimum=1); p.integer(state["intentRevision"], minimum=1)
    current, change = state["current"], state["latestServiceChange"]
    p.exact(change, {"operationID", "predecessor", "successor", "revision"}); p.uid(change["operationID"])
    p.integer(change["revision"], minimum=1)
    historical = dict(context=change["predecessor"], controller=current)
    shared.historical_controller(historical, identity, shared.fingerprint(state["rootPublicKey"]))
    p.require(current["original"]["signed"]["grant"]["operation"] == "initialize", "fresh worker controller")
    context = service(state["currentService"], identity, current, state["rootPublicKey"])
    observation = state["observedWorker"]
    p.exact(observation, {"context", "workerUUID"}); p.uid(observation["workerUUID"])
    for value in (state["currentContext"], observation["context"], change["predecessor"], change["successor"]): public_context(value)
    p.require(state["currentContext"] == observation["context"] == change["successor"] == context, "exact current observed worker")
    p.require(change["predecessor"]["serviceEpoch"] != context["serviceEpoch"] and all(
        change["predecessor"][k] == context[k] for k in ("controllerEpoch", "controllerKey")), "same C/key fresh E")
    confirmation = state["latestServiceConfirmation"]
    p.exact(confirmation, {"request", "successor"}); p.exact(confirmation["request"], {"operation_id", "predecessor"})
    predecessor = confirmation["request"]["predecessor"]
    p.require(service(predecessor, identity, current, state["rootPublicKey"]) == change["predecessor"]
        and confirmation["request"]["operation_id"] == change["operationID"]
        and confirmation["successor"] == state["currentService"], "exact ROOT service-change confirmation")
    fresh_service = state["currentService"]
    p.require(change["revision"] == fresh_service["open_revision"] > max(predecessor["open_revision"], current["directResult"]["revision"]), "ROOT confirmed new open revision")
    for field in ("tls_root_sha256", "server_spki"):
        p.require(fresh_service["boot"][field] != predecessor["boot"][field], "fresh replacement TLS")
    retry = state["latestServiceRequest"]
    p.exact(retry, {"request", "stageRequestID", "completionRequestID", "predecessorWorkerUUID", "nowUnixSeconds", "lifetimeSeconds"})
    for field in ("stageRequestID", "completionRequestID", "predecessorWorkerUUID"): p.uid(retry[field])
    p.integer(retry["nowUnixSeconds"], 253402300799, 1); p.integer(retry["lifetimeSeconds"], 86400, 1)
    p.require(retry["request"] == confirmation["request"] and retry["stageRequestID"] != retry["completionRequestID"]
        and retry["predecessorWorkerUUID"] != observation["workerUUID"], "exact consumed service retry tuple")
    native = state["serviceReplacement"]
    p.exact(native, {"predecessor_worker_uuid", "configuration"})
    configuration = native["configuration"]
    p.exact(configuration, {"action", "root_public_key", "signed", "now_unix_seconds", "lifetime_seconds", "reopen"})
    p.exact(configuration["reopen"], {"request", "signature"}); shared.encoded(configuration["reopen"]["signature"], 64)
    p.require(state["nativeReplacementAttempted"] is True and native["predecessor_worker_uuid"] == retry["predecessorWorkerUUID"]
        and configuration == dict(action="open", root_public_key=state["rootPublicKey"], signed=current["original"]["signed"],
            now_unix_seconds=retry["nowUnixSeconds"], lifetime_seconds=retry["lifetimeSeconds"],
            reopen=dict(request=retry["request"], signature=configuration["reopen"]["signature"])), "exact actual native replacement configuration")
    folded = dict(context=context, controller=current, serviceResult=change)
    p.require(state["serviceLinks"] == [change] and state["contexts"] in ([historical, folded], [folded]), "one exact folded worker edge")
    p.require(type(state["references"]) is list, "required intent census")
    return dict(format=VERSION, store=identity["store"], root=manifest["root"], backing=manifest["backing"],
        bytes=manifest["bytes"], ext4UUID=manifest["ext4UUID"], revision=state["revision"], workerUUID=observation["workerUUID"],
        confirmedRevision=change["revision"], **context), dict(format=VERSION, workerEvidence=record)


def public_service(projection):
    p.exact(projection, {"format", "workerEvidence"})
    p.require(shared.is_v2(projection), "explicit v2 worker projection")
    value, _ = owner(projection["workerEvidence"])
    return dict(storeUUID=value["store"], workerUUID=value["workerUUID"], revision=value["confirmedRevision"],
        **{k: value[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")})


def history(record):
    return record["checkpoint"]["serviceLinks"] if shared.is_v2(record) else record.get("workerReplacements", [])


def census(checkpoint, state, hashes):
    p.require(state["store"] == checkpoint["identity"]["store"] and state["reconciliationRequired"] is False
        and checkpoint["intentRevision"] == state["revision"], "exact settled journal census revision")
    p.pin(hashes["state_sha256"])  # Actual raw-byte hash supplied by the pinned journal reader; not synthesized.
    p.require(type(state["intents"]) is dict and len(state["intents"]) <= 128, "bounded intent census")
    expected = []
    for identifier, intent in sorted(state["intents"].items()):
        p.uid(identifier); p.integer(intent["version"], minimum=1)
        p.require(identifier == intent["id"] and intent["store"] == state["store"], "exact journal intent identity")
        row = dict(id=identifier, version=intent["version"], original={k: intent[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")},
            superseded=intent.get("supersededSuccessors", []))
        for source, target in (("replacementRecovery", "recovery"), ("predecessor", "predecessor"), ("successor", "successor")):
            if intent.get(source) is not None: row[target] = intent[source]
        public_context(row["original"])
        p.require(type(row["superseded"]) is list and len(row["superseded"]) <= 128
            and len(set(row["superseded"])) == len(row["superseded"]), "bounded unique superseded references")
        for identifier in row["superseded"]: p.uid(identifier)
        for field in ("predecessor", "successor"):
            if field in row: p.uid(row[field])
        expected.append(row)
    p.require(len(p.canonical(expected)) <= 128 * 2048, "bounded reference bytes")
    p.require(p.canonical(checkpoint["references"]) == p.canonical(expected), "complete exact journal intent census including terminal intents")
    by_id = {row["id"]: row for row in expected}
    for row in expected:
        predecessor = row.get("predecessor")
        if predecessor is not None:
            p.require(predecessor in by_id and (by_id[predecessor].get("successor") == row["id"]
                or row["id"] in by_id[predecessor]["superseded"]), "reciprocal predecessor reference")
        for child in row["superseded"] + ([row["successor"]] if "successor" in row else []):
            p.require(child != row["id"] and child in by_id and by_id[child].get("predecessor") == row["id"], "reciprocal successor reference")
        seen = {row["id"]}
        while predecessor is not None:
            p.require(predecessor not in seen and predecessor in by_id, "acyclic reference graph")
            seen.add(predecessor); predecessor = by_id[predecessor].get("predecessor")
    contexts = [row["context"] for row in checkpoint["contexts"]]
    for row in expected:
        p.require(row["original"] in contexts, "retained original context")
        if row.get("recovery") is not None:
            value = row["recovery"]
            p.exact(value, {"serviceEpoch", "controllerEpoch", "controllerKey", "provenanceReference", "workerHistoryReference"})
            recovery_context = public_context({k: value[k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")})
            link = checkpoint["latestServiceChange"]
            p.require(recovery_context == link["predecessor"] and row["original"] == link["successor"]
                and row.get("predecessor") in by_id and by_id[row["predecessor"]]["original"] == link["predecessor"]
                and value["provenanceReference"] == checkpoint["provenanceReference"]
                and value["workerHistoryReference"] == p.digest(p.canonical(checkpoint["latestServiceChange"])), "exact same-C recovery edge reference")


def replacement_proof(before, after, pending, succeeded, request, state, hashes, containers, submitted, observed, *, prepare_recovery, active_ack_containers=None):
    if not shared.is_v2(before) and not shared.is_v2(after):
        return recovery.replacement_proof(before, after, pending, succeeded, request, state, hashes, containers, submitted, observed,
            prepare_recovery=prepare_recovery, active_ack_containers=active_ack_containers)
    p.require(shared.is_v2(before) and shared.is_v2(after), "same explicit worker evidence format")
    old, _ = owner(before); new, _ = owner(after)
    a, b = before["checkpoint"], after["checkpoint"]
    p.require(not history(before) and len(history(after)) == 1, "one worker-only replacement")
    p.require(before["manifest"] == after["manifest"] and all(a[k] == b[k] for k in ("identity", "rootPublicKey", "provenanceReference", "current")), "same ROOT/controller/native physical owner")
    p.require(new["revision"] > old["revision"] and new["workerUUID"] != old["workerUUID"], "fresh worker and checkpoint revision")
    change, retry = b["latestServiceChange"], b["latestServiceRequest"]
    p.require(change["predecessor"] == a["currentContext"] and b["latestServiceConfirmation"]["request"]["predecessor"] == a["currentService"]
        and retry["predecessorWorkerUUID"] == old["workerUUID"], "exact actual predecessor service/worker")
    recovery.worker_request(request["operationUUID"], request["store"], request["predecessor"])
    p.require(request["store"] == old["store"] and request["predecessor"] == {k: old[k] for k in ("serviceEpoch", "workerUUID")}
        and change["operationID"] == request["operationUUID"], "exact selected replacement request")
    proof = dict(controllerEpoch=old["controllerEpoch"], controllerKey=old["controllerKey"], rootPublicKey=a["rootPublicKey"])
    common = {"schema", "counter", "phase", "request", "proof"}
    for receipt, phase in ((pending, "pending"), (succeeded, "succeeded")):
        p.exact(receipt, common | ({"ownerRequest", "successor", "containedContainerIDs"} if phase == "succeeded" else set()))
        p.integer(receipt["schema"], 1, 1); p.integer(receipt["counter"], 1, 1)
        p.require(receipt["phase"] == phase and receipt["request"] == request and receipt["proof"] == proof, "exact replacement receipt")
    p.require(pending["counter"] == succeeded["counter"], "same replacement claim counter")
    actual = succeeded["ownerRequest"]
    p.exact(actual, {"operationUUID", "predecessor", "nowUnixSeconds"}); p.integer(actual["nowUnixSeconds"], 253402300799, 1)
    p.require(actual == dict(operationUUID=request["operationUUID"], predecessor=request["predecessor"], nowUnixSeconds=retry["nowUnixSeconds"])
        and submitted <= actual["nowUnixSeconds"] <= observed, "actual owner request/time window")
    p.require(succeeded["successor"] == {k: new[k] for k in ("serviceEpoch", "workerUUID")}, "exact successor receipt")
    arm = prepare_recovery
    p.require(arm["caseName"] in p.WORKER_EXIT_CASES + p.CHECKPOINT_EXIT_CASES
        and all(arm["scope"][k] == old[k] for k in ("store", "serviceEpoch", "controllerEpoch", "controllerKey")), "installed worker-cut context")
    if arm["caseName"] in p.STORAGE_CASES: p.storage_query(arm, old["workerUUID"])
    if active_ack_containers is None:
        p.require(len(containers) == len(set(containers)) == 2 and arm["scope"]["container"] in containers, "exact two-owned-container census")
    else:
        from managed_prepare_active_ack import four_owner_ids
        four_owner_ids(containers, active_ack_containers, arm["scope"]["container"])
        p.require(arm["caseName"] == "admitted-queued", "A5 four-owner cut only")
    for container in containers: p.pin(container)
    p.require(succeeded["containedContainerIDs"] == sorted(containers), "complete containment receipt, not native exit proof")
    census(b, state, hashes)
    return new
