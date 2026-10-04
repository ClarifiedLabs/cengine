"""Closed RTM099 two-volume validators used by the executable parent campaign.

Inputs are retained observations of the real host/storage, never authority.
No request is published, no receipt is installed, and no runtime action occurs.
The single-volume validators and RTM096 nine-outcome denominator stay unchanged.
"""
import copy

import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as lifecycle
from managed_prepare_storage_vm_faults import bounded_base64, current_boot, public_boot

CASE = "vm-two-volume-drain-reply-gap"
CASES = (CASE,)


def selection(profile, cases, case):
    p.require(profile == p.FULL_PROFILE and tuple(cases) == CASES and case == CASE,
              "explicit full-profile two-volume drain cut")
    return dict(profile=profile, caseName=case, fullAcceptance=False, runnable=True)


def capture_from_normal(intent, saved, volumes, request):
    """Two explicit mounts; digest comes from the actual host, not Docker JSON."""
    p.require(saved["id"] == intent["container"] and
              str(p.uuid.UUID(saved["instanceID"])) == intent["containerInstance"], "owned saved container")
    p.require(type(volumes) is list and len(volumes) == 2 and
              len({v["id"] for v in volumes}) == len({v["name"] for v in volumes}) == 2,
              "two distinct owned volumes")
    p.require(type(saved["mounts"]) is list and len(saved["mounts"]) == 2, "exact two saved mounts")
    mounts = []
    for index, (destination, volume) in enumerate(zip(("/data", "/other"), volumes)):
        matches = [m for m in saved["mounts"] if m["destination"] == destination]
        p.require(len(matches) == 1, "one mount at each fixed destination")
        m = matches[0]
        p.require(m["kind"] == "volume" and m["source"] == volume["name"] and
                  m["readOnly"] is False and m["noCopy"] is False and m.get("subpath") in (None, ""),
                  "owned copy-enabled complete mount")
        mounts.append(dict(index=index, volume=p.uid(volume["id"]), destination=destination,
                           subpath="", mode="read-write", noCopy=False))
    p.require(intent["mounts"] == [{k: m[k] for k in ("volume", "destination", "subpath", "mode")}
                                  for m in mounts], "actual full journal mounts")
    return dict(version=1, requestID=p.uid(request), container=p.pin(intent["container"]),
                containerInstance=p.uid(intent["containerInstance"]),
                specificationDigest=p.pin(intent["specificationDigest"]), mounts=mounts)


def _shape(arm):
    p.exact(arm, p.CANDIDATE | {"caseName", "targetAttachment"})
    p.exact(arm["scope"], p.SCOPE)
    scope = arm["scope"]
    for key in ("intent", "store", "serviceEpoch", "containerInstance", "launch", "prepare"): p.uid(scope[key])
    for key in ("controllerKey", "container", "specificationDigest"): p.pin(scope[key])
    p.integer(scope["controllerEpoch"], minimum=1)
    p.exact(arm["binding"], {"shimLaunchUUID", "guestBootNonce"})
    for value in arm["binding"].values(): p.uid(value)
    p.require(arm["binding"]["shimLaunchUUID"] == scope["launch"], "bound launch")
    p.uid(arm["requestID"])
    p.require(type(arm["version"]) is int and arm["version"] == 3 and
              arm["profile"] == p.FULL_PROFILE and arm["caseName"] == CASE, "closed two-volume arm")
    mounts, slots, credentials = arm["mounts"], arm["slots"], arm["credentials"]
    p.require(type(mounts) is list and len(mounts) == 2, "exact two mounts")
    for index, (m, destination) in enumerate(zip(mounts, ("/data", "/other"))):
        p.exact(m, {"index", "volume", "destination", "subpath", "mode", "noCopy"})
        p.integer(m["index"], 1)
        p.uid(m["volume"])
        p.require(m == dict(index=index, volume=m["volume"], destination=destination,
                           subpath="", mode="read-write", noCopy=False) and m["noCopy"] is False,
                  "fixed complete mounts")
    p.require(len({m["volume"] for m in mounts}) == 2, "distinct volumes")
    p.require(type(slots) is list and len(slots) == 4, "explicit four slots")
    for slot in slots:
        p.exact(slot, {"volume", "attachment", "role", "mode"})
        p.uid(slot["attachment"])
        p.require(slot["volume"] in {m["volume"] for m in mounts} and slot["mode"] == "read-write",
                  "exact slot volume/mode")
    p.require(len({s["attachment"] for s in slots}) == 4 and
              all(sorted(s["role"] for s in slots if s["volume"] == m["volume"]) == ["prepare", "runtime"]
                  for m in mounts), "one prepare/runtime pair per volume")
    p.require(type(credentials) is list and len(credentials) == 2, "two installed prepare credentials")
    for credential in credentials:
        p.exact(credential, {"attachment", "key", "certificateSHA256"})
        p.uid(credential["attachment"]); p.pin(credential["key"]); p.pin(credential["certificateSHA256"])
    p.require({c["attachment"] for c in credentials} == {s["attachment"] for s in slots if s["role"] == "prepare"}
              and len({c["key"] for c in credentials}) == len({c["certificateSHA256"] for c in credentials}) == 2,
              "distinct exact installed prepare credentials")
    p.require(arm["targetAttachment"] in {c["attachment"] for c in credentials}, "prepare target")


def _host_slots(intent, arm):
    """Return PREPARE order from the real immutable host array, never UUID sort."""
    _shape(arm)
    p.require(p.canonical({k: intent[k if k != "intent" else "id"] for k in arm["scope"]}) ==
              p.canonical(arm["scope"]), "exact immutable host owner/epoch/operation")
    rows = [{k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]]
    p.require(sorted(rows, key=lambda s: s["attachment"]) == sorted(arm["slots"], key=lambda s: s["attachment"]),
              "actual full host slot set")
    prepare = [s for s in intent["slots"] if s["role"] == "prepare"]
    p.require(prepare[1]["attachment"] == arm["targetAttachment"], "second actual immutable host prepare slot")
    operations = []
    for slot in intent["slots"]:
        for name in ("registerOperation", "retireOperation"):
            operations.append(p.uid(slot[name]))
        if slot["role"] == "prepare":
            p.require(slot["key"] == next(c["key"] for c in arm["credentials"]
                                          if c["attachment"] == slot["attachment"]), "installed host key")
        else:
            p.require(slot.get("key") is None and slot.get("receipt") is None, "no runtime issuance/drain")
    operations += [p.uid(intent[name]) for name in ("reserveOperation", "completeOperation", "replaceOperation")]
    p.require(len(set(operations)) == len(operations), "distinct actual host operations")
    return prepare


def arm_candidate(candidate, capture, previous, host_intent):
    """Require the actual current journal alongside the public queue candidate."""
    p.exact(candidate, p.CANDIDATE)
    p.exact(candidate["scope"], p.SCOPE)
    scope = candidate["scope"]
    for key in ("intent", "store", "serviceEpoch", "containerInstance", "launch", "prepare"): p.uid(scope[key])
    for key in ("controllerKey", "container", "specificationDigest"): p.pin(scope[key])
    p.integer(scope["controllerEpoch"], minimum=1)
    p.exact(candidate["binding"], {"shimLaunchUUID", "guestBootNonce"})
    for value in candidate["binding"].values(): p.uid(value)
    p.uid(candidate["requestID"])
    p.require(candidate["requestID"] == capture["requestID"] and
              candidate["binding"]["shimLaunchUUID"] == scope["launch"], "capture request/launch")
    p.require(all(scope[k] == capture[k] for k in ("container", "containerInstance", "specificationDigest")) and
              all(scope[k] == previous[k] for k in ("store", "serviceEpoch", "controllerEpoch", "controllerKey",
                                                     "container", "containerInstance", "specificationDigest")),
              "same captured owner/context")
    p.require(scope["intent"] != previous["id"] and all(scope[k] != previous[k] for k in ("launch", "prepare")),
              "fresh attempt")
    p.require(candidate["mounts"] == capture["mounts"], "complete capture mounts")
    prepare = [s for s in host_intent["slots"] if s["role"] == "prepare"]
    p.require(len(prepare) == 2, "two actual host prepare slots")
    arm = copy.deepcopy(candidate)
    arm.update(caseName=CASE, targetAttachment=prepare[1]["attachment"])
    _host_slots(host_intent, arm)
    p.require({s["attachment"] for s in arm["slots"]}.isdisjoint(s["attachment"] for s in previous["slots"])
              and {c["key"] for c in arm["credentials"]}.isdisjoint(s.get("key") for s in previous["slots"]),
              "fresh attachments and keys")
    if "binding" in previous:
        p.require(candidate["binding"]["guestBootNonce"] != previous["binding"]["guestBootNonce"], "fresh boot")
    if "credentials" in previous:
        p.require({c["certificateSHA256"] for c in arm["credentials"]}.isdisjoint(
            c["certificateSHA256"] for c in previous["credentials"]), "fresh certificates")
    arm["slots"].sort(key=lambda s: s["attachment"])
    arm["credentials"].sort(key=lambda c: c["attachment"])
    p.require(len(p.canonical(arm)) <= 65536, "bounded arm")
    return arm


def physical_observation(value, arm):
    """Returning A8 physical source witness, bound to this exact two-volume arm."""
    _shape(arm)
    return p._physical_observation(value, arm, version=3, profile=p.FULL_PROFILE, cases=CASES)


def storage_query(arm, worker):
    _shape(arm)
    return dict(version=3, profile=p.FULL_PROFILE, requestID=p.uid(arm["requestID"]),
                armDigest=p.digest(p.canonical(arm)), workerUUID=p.uid(worker))


def storage_observation(value, arm, worker):
    expected = dict(**storage_query(arm, worker), stage=CASE, count=1, targetAttachment=arm["targetAttachment"])
    p.exact(value, {*expected, "drain"})
    p.require(p.canonical({k: value[k] for k in expected}) == p.canonical(expected), "exact retained drain witness")
    p.exact(value["drain"], {"retireOperation", "receipt"})
    p.uid(value["drain"]["retireOperation"])
    p.storage_receipt(value["drain"]["receipt"], arm)
    return value


def storage_status(value, arm, worker, checkpoint):
    p.exact(value, {"query", "state", "observation", "retirementStarted", "acceptedInFlight",
                    "lateAdmissionRejected", "receiptReplayCount"})
    p.require(p.canonical(value["query"]) == p.canonical(storage_query(arm, worker)) and value["state"] == "held"
              and value["retirementStarted"] is True and value["lateAdmissionRejected"] is False,
              "successful second Retire reply still held")
    p.integer(value["acceptedInFlight"], 0); p.integer(value["receiptReplayCount"], 0)
    storage_observation(value["observation"], arm, worker)
    p.require(p.canonical(value["observation"]) == p.canonical(checkpoint), "immutable independent observation")
    # Sequence=0/Admitted=false are internal authority snapshot fields. The wire
    # DTO retains the existing Drain payload, not invented Admission fields.
    return value


def _operation(state, operation, expected):
    raw = bounded_base64(state["operations"][operation], 65536)
    p.require(raw == p.canonical(expected) and state["operationDigests"][operation] == p.digest(raw),
              "exact persisted production request and digest")


def _host_state(state, arm):
    p.require(state["store"] == arm["scope"]["store"], "same host store")
    p.integer(state["revision"], minimum=1)
    p.require(type(state["operations"]) is dict and type(state["operationDigests"]) is dict, "host ledger")
    intent = state["intents"][arm["scope"]["intent"]]
    prepare = _host_slots(intent, arm)
    p.integer(intent["version"], 2**64 - 1, 1)
    completion = intent["guestCompletion"]
    p.exact(completion, {"prepare", "containerInstance", "launch", "succeeded", "cleanCopyUp", "evidenceDigest"})
    p.require(all(completion[k] == intent[k] for k in ("prepare", "containerInstance", "launch")) and
              completion["succeeded"] is True and completion["cleanCopyUp"] is True and intent["cleanUnmount"] is True,
              "real successful guest completion and clean close")
    p.pin(completion["evidenceDigest"])
    for slot in intent["slots"]:
        if slot["role"] == "runtime":
            for key in ("registerOperation", "retireOperation"):
                p.require(all(slot[key] not in state[ledger] for ledger in ("operations", "operationDigests")),
                          "no runtime production request")
    p.require(all(intent["replaceOperation"] not in state[k] for k in ("operations", "operationDigests")),
              "successful completed-set recovery, never ReplacePrepare")
    for slot in prepare:
        _operation(state, slot["retireOperation"], {"id": 0, "retire": dict(operation=slot["retireOperation"],
            store=intent["store"], volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"])})
    return intent, prepare


def prefault_receipts(state, arm, checkpoint, worker):
    """Call and durably retain before any actual owned storage signal."""
    storage_observation(checkpoint, arm, worker)
    intent, prepare = _host_state(state, arm)
    p.require(intent["phase"] == "prepareSucceeded" and intent["prepareCompleted"] is False and
              all(intent["completeOperation"] not in state[k] for k in ("operations", "operationDigests")),
              "no premature CompletePrepare")
    p.require(intent.get("quarantineReason") is None, "no pre-fault uncertainty")
    first, second = prepare
    p.exact(first["receipt"], {"store", "volume", "attachment", "prepare", "launch", "revision"})
    expected = dict(store=intent["store"], volume=first["volume"], attachment=first["attachment"],
                    prepare=intent["prepare"], launch=intent["launch"])
    p.require(all(first["receipt"][k] == v for k, v in expected.items()), "first exact host receipt")
    p.integer(first["receipt"]["revision"], minimum=1)
    p.require(second.get("receipt") is None and checkpoint["drain"]["retireOperation"] == second["retireOperation"],
              "second receipt absent on host, exact actual operation in storage")
    p.integer(checkpoint["drain"]["receipt"]["revision"], minimum=first["receipt"]["revision"] + 1)
    return intent


def prefault_evidence(state, held, arm, checkpoint, worker):
    """Combined pre-signal proof; neither observation nor a journal alone suffices.

    The parent must fsync these original inputs and revalidate them plus positive
    native ownership immediately before the existing RTM099 audited signal.
    """
    storage_status(held, arm, worker, checkpoint)
    return prefault_receipts(state, arm, checkpoint, worker)


def prerecovery_receipts(before, stopped, arm, checkpoint, worker, *, lifecycle_v2=False):
    """Validate the quiescent journal AFTER old API exit, BEFORE recovery birth.

    Storage death may let the still-live API unwind the failed Retire, then the
    start, then its cleanup Retire. Lifecycle-v2 may additionally enter
    ManagedVolumeLifecycleCoordinator.retireLaunch: its launch-retirement
    quarantine is the fourth commit, before the next drain returns. This is
    the exact retained RTM099 v2 prefix, not permission for further retries.
    Alternatively, v2's control-loss observer can invalidate the coordinator
    before rollback: invalidate clears executions, then requireReconciliation
    commits only the global fence/revision. No intent update can follow that
    revocation. Accept only this observed zero-rollback alternative, not a
    reconciliation flag added to arbitrary quarantine prefixes.
    Successful guest completion and the mixed receipt set cannot change.
    The caller must independently prove the API exit before reading this state.
    """
    old = prefault_receipts(before, arm, checkpoint, worker)
    current, _ = _host_state(stopped, arm)
    delta = current["version"] - old["version"]
    p.require(type(lifecycle_v2) is bool, "explicit lifecycle format")
    reasons = (None, "attachment retirement incomplete", "start interrupted", "attachment retirement incomplete")
    if lifecycle_v2:
        reasons += ("launch retirement",)
    p.require(0 <= delta < len(reasons), "closed old-API rollback/launch-retirement prefix")
    expected = copy.deepcopy(before)
    if delta:
        expected["intents"][old["id"]].update(version=old["version"] + delta,
            phase="quarantined", quarantineReason=reasons[delta])
        expected["revision"] += delta
    elif (lifecycle_v2 and before.get("reconciliationRequired") is False and
          stopped.get("reconciliationRequired") is True):
        # ManagedVolumeLifecycleCoordinator.invalidate -> HostStorageIntents
        # .requireReconciliation -> commit. Intents and operation ledgers are
        # untouched; execution revocation suppresses drain/runPlanned cleanup.
        expected["reconciliationRequired"] = True
        expected["revision"] += 1
    p.require(p.canonical(stopped) == p.canonical(expected),
              "only ordered old-API quarantine updates or exact pre-rollback invalidation; "
              "receipts, requests and all other owners immutable")
    return current


def recovered_receipts(before, stopped, after, arm, checkpoint, worker, owner_record):
    """Old durable receipts, NOT the A7 new-post-boot-receipt oracle.

    The caller must separately establish actual native death/exit, explicit API
    recovery and storage_owner_transition; this pure validator cannot do so.
    """
    old = prerecovery_receipts(before, stopped, arm, checkpoint, worker,
                              lifecycle_v2=lifecycle.is_v2(owner_record))
    current, prepare = _host_state(after, arm)
    p.integer(after["revision"], minimum=stopped["revision"] + 1)
    p.require(current["phase"] == "retired" and current["prepareCompleted"] is True and
              current["guestCompletion"] == old["guestCompletion"], "production completed-set recovery")
    # recover -> quarantine (+1), drain missing receipt (+1), completion (+1),
    # retired (+1), measured from the actual quiescent old-API journal, not the
    # earlier storage cut. HostStorageIntents.update increments even for no-op bodies.
    p.require(current["version"] == old["version"] + 4, "exact four production recovery updates")
    p.require(current.get("quarantineReason") == "recovering interrupted execution",
              "exact historical recovery reason on retired intent, not active quarantine")
    mutable = {"version", "phase", "prepareCompleted", "slots", "quarantineReason"}
    p.require({k: value for k, value in current.items() if k not in mutable} ==
              {k: value for k, value in old.items() if k not in mutable}, "immutable host intent/operation identities")
    for state in (before, after):
        p.require(set(state["operations"]) == set(state["operationDigests"]), "exact request/digest ledger key parity")
    for ledger in ("operations", "operationDigests"):
        p.require(set(after[ledger]) - set(before[ledger]) == {current["completeOperation"]},
                  "only original CompletePrepare added, no new retirement operations")
        p.require(all(after[ledger].get(k) == v for k, v in before[ledger].items()), "immutable old operations/digests")
    for previous, slot in zip(old["slots"], current["slots"]):
        p.require({k: v for k, v in previous.items() if k != "receipt"} ==
                  {k: v for k, v in slot.items() if k != "receipt"}, "immutable host slot order/identity")
        if previous.get("receipt") is not None:
            p.require(p.canonical(slot["receipt"]) == p.canonical(previous["receipt"]), "preserve first receipt exactly")
    second = checkpoint["drain"]["receipt"]
    p.require(p.canonical(prepare[1]["receipt"]) == p.canonical({k: v for k, v in second.items() if k != "schema"}),
              "identical second durable receipt including original revision")
    ready = public_boot(current_boot(owner_record))
    p.require(ready["storeUUID"] == arm["scope"]["store"] and ready["serviceEpoch"] != arm["scope"]["serviceEpoch"]
              and ready["workerUUID"] != worker and
              (ready["controllerEpoch"] == arm["scope"]["controllerEpoch"] + 1
               and ready["controllerKey"] != arm["scope"]["controllerKey"] if lifecycle.is_v2(owner_record) else
               all(ready[k] == arm["scope"][k] for k in ("controllerEpoch", "controllerKey"))),
              "same-store fresh service/worker and format-specific confirmed controller")
    p.require(second["revision"] <= ready["revision"], "old durable storage receipt, not new post-boot drain")
    receipts = [dict(schema=3, **s["receipt"]) for s in prepare]
    # CompletePrepare wire receipts are canonically sorted by production; this
    # does NOT choose retirement order (the immutable host slot array does).
    receipts.sort(key=lambda r: r["attachment"])
    _operation(after, current["completeOperation"], {"id": 0, "complete_prepare": dict(
        operation=current["completeOperation"], prepare=current["prepare"], receipts=receipts,
        attestation=dict(prepare=current["prepare"], succeeded=True, clean_copy_up=True))})
    return current
