"""RTM-097/RTM-099 nine-boundary restart matrices; no engine access on import.

Every cell reuses RTM-096's exact per-case checkpoint. Only the restart action
and its recovery oracle vary with the boundary kind:

- held-guest (A2, A7): the guest holds; the start stays pending until the
  restart, production contains the old workload after the replacement API
  is born, then quarantines, drains and lets a fresh NORMAL replay succeed.
- held-storage (A4, A5): the storage authority holds an admission for the
  arming controller's carrier claim. The host never re-adopts that claim after
  a restart, so the successor controller's Retire releases the hold exactly
  once; the drain then completes and the NORMAL replay follows.
- natural (A1, A3, A6): the guest fails on its own right after the checkpoint,
  racing the restart. Both outcomes are real recoveries and are recorded as a
  variant: `interrupted` (connection lost before any reply) or
  `settled-failure` (HTTP 409 already returned by the dying API).
- successful (NORMAL, A8): PREPARE succeeds right after the checkpoint, racing
  the restart: `interrupted` recovers like a held case; `settled-success` means
  the start completed first and the replacement API must adopt the live
  runtime without any drain or replay.

A storage-VM death additionally admits `service-loss-failure` (HTTP 500): the
API observed the service loss and failed the start before its own restart.
Public journals corroborate production recovery; they never grant authority.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import copy
import os
from pathlib import Path
import select
import signal
import time

import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as lifecycle
from managed_prepare_service_faults import owner_context, api_target, storage_target, api_owner_transition, sdk_versions
from managed_prepare_storage_vm_faults import storage_owner_transition, recovered_prepare_drain, undrained_prepare, current_boot, public_boot, bounded_base64
from managed_storage_recovery import read_public, exact_exit, unchanged_processes, signal_storage

MATRICES = {"RTM-097": "api", "RTM-099": "storage"}
BOUNDARIES = p.FULL_CASES
HELD_GUEST = ("guest-accepted-before-prepare", "first-child-published")
HELD_STORAGE = p.HELD_STORAGE_CASES
NATURAL = ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost")
SUCCESSFUL = ("normal", "drain-durable-reply-lost")
KINDS = {**{c: "held-guest" for c in HELD_GUEST}, **{c: "held-storage" for c in HELD_STORAGE},
         **{c: "natural" for c in NATURAL}, **{c: "successful" for c in SUCCESSFUL}}
START_EXIT = {"interrupted": 52, "settled-failure": 49, "service-loss-failure": 50, "settled-success": 0}
VARIANTS = {
    "api": {"held-guest": ("interrupted",), "held-storage": ("interrupted",),
            "natural": ("interrupted", "settled-failure"), "successful": ("interrupted", "settled-success")},
    "storage": {"held-guest": ("interrupted",), "held-storage": ("interrupted", "settled-failure", "service-loss-failure"),
                "natural": ("interrupted", "settled-failure", "service-loss-failure"),
                "successful": ("interrupted", "settled-success", "service-loss-failure")},
}
PREFAULT_PHASES = {"held-guest": ("prepareAdmitted",), "held-storage": ("prepareAdmitted",),
                   "natural": ("prepareAdmitted", "quarantined"),
                   "successful": ("prepareAdmitted", "prepareSucceeded", "prepareDrained", "prepareCompleted", "runtimeFrozen", "running")}
_LIVE_MATRIX_OUTCOMES = {}


def kind(case):
    p.require(case in KINDS, "closed nine-boundary case")
    return KINDS[case]


def selection(rtm, profile, cases, fault_case):
    p.require(rtm in MATRICES, "closed restart matrix")
    p.require(profile == p.FULL_PROFILE and tuple(cases) == BOUNDARIES, "explicit closed full parent profile/cases required")
    p.require(type(fault_case) is str and fault_case in BOUNDARIES, "one exact boundary per fresh invocation")
    return {"rtm": rtm, "restart": MATRICES[rtm], "profile": p.FULL_PROFILE, "caseName": fault_case,
            "boundary": p.FULL_BOUNDARIES[fault_case], "kind": kind(fault_case), "coverage": "1/9", "fullAcceptance": False}


def validate_checkpoint(checkpoint, arm, worker):
    """The storage-owned cuts carry the storage observation; the rest are guest observations."""
    if arm["caseName"] in p.STORAGE_CASES:
        p.require(worker is not None, "storage checkpoint requires the observed worker")
        return p.storage_observation(checkpoint, arm, worker)
    return p.full_observation(checkpoint, arm)


def prefault_intent(state, intent, arm, case):
    """Boundaries that race the restart may already be settled; held ones may not."""
    p.require(state["store"] == arm["scope"]["store"] and state["intents"][arm["scope"]["intent"]] == intent, "exact pre-fault host intent")
    p.require(all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "pre-fault intent scope")
    p.require(intent["phase"] in PREFAULT_PHASES[kind(case)], "boundary-consistent pre-fault phase: " + intent["phase"])
    rows = [{k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]]
    p.require(sorted(rows, key=lambda s: s["attachment"]) == arm["slots"], "complete pre-fault slot tuple")
    for slot in intent["slots"]:
        if slot["role"] == "prepare":
            p.require(slot.get("key") == next(c["key"] for c in arm["credentials"] if c["attachment"] == slot["attachment"]), "actual installed PREPARE key")
        elif intent["phase"] in ("prepareAdmitted", "quarantined"):
            p.require(slot.get("key") is None, "no runtime issued before PREPARE completion")
    if intent["phase"] == "prepareAdmitted":
        undrained_prepare(state, intent, arm)
    return intent["phase"]


def start_variant(start, restart, case, remaining):
    """The joined real Docker start decides the variant; nothing is inferred."""
    code = start.wait(timeout=remaining())
    allowed = VARIANTS[restart][kind(case)]
    exits = {START_EXIT[v]: v for v in allowed}
    p.require(type(code) is int and code in exits, "restart-consistent Docker start exit %r for %s" % (code, case))
    return exits[code]


def recovered_successful_drain(before, after, arm, owner_record):
    """NORMAL/A8 interrupted by storage death and quarantined: the same new-epoch
    drain proof as a failed fault, minus the failed-fault case-name requirement.
    The pre-fault ledger must hold no drain and the quarantined PREPARE slot must
    carry a receipt issued by the reopened authority after its boot revision."""
    previous = before["intents"][arm["scope"]["intent"]]
    undrained_prepare(before, previous, arm)
    current = p.failed_prepare(after["intents"][previous["id"]], arm)
    p.require(current.get("cleanUnmount") is False, "no fabricated successful close")
    p.integer(after["revision"], minimum=before["revision"] + 1)
    p.require(after["store"] == before["store"], "same post-recovery host store")
    for key in ("operations", "operationDigests"):
        p.require(all(after[key].get(k) == v for k, v in before[key].items()), "immutable pre-fault operations")
    boot_revision = public_boot(current_boot(owner_record))["revision"]
    receipts = []
    for old in previous["slots"]:
        slot = next(s for s in current["slots"] if s["attachment"] == old["attachment"])
        p.require({k: v for k, v in slot.items() if k != "receipt"} == {k: v for k, v in old.items() if k != "receipt"}, "immutable drained slot identity")
        operation = old["retireOperation"]
        if old["role"] == "runtime":
            p.require(operation not in after["operations"] and operation not in after["operationDigests"], "unissued runtime not retired")
            continue
        raw = bounded_base64(after["operations"][operation], 65536)
        expected = {"id": 0, "retire": dict(operation=operation, store=current["store"],
            volume=slot["volume"], attachment=slot["attachment"], launch=current["launch"])}
        p.require(raw == p.canonical(expected) and after["operationDigests"][operation] == p.digest(raw), "exact persisted production Retire request")
        receipt = slot["receipt"]
        p.integer(receipt["revision"], minimum=boot_revision + 1)
        receipts.append(dict(operation=operation, requestSHA256=p.digest(raw), receipt=receipt))
    return dict(bootRevision=boot_revision, hostRevision=after["revision"], drains=receipts)


def recovered_intent(state, arm, variant, checkpoint):
    """Post-recovery host intent oracle per variant; receipts are production's.

    Interrupted successful boundaries (NORMAL/A8) may recover either way:
    quarantined when the host never recorded PREPARE completion, or retired
    when the replayed drain proved the interrupted PREPARE had completed. Both
    leave every issued attachment drained; neither is a running owner.
    """
    intent = state["intents"][arm["scope"]["intent"]]
    if variant == "settled-success":
        p.require(intent["phase"] == "running" and intent["prepareCompleted"] is True, "adopted live runtime after restart")
        return intent
    if arm["caseName"] in SUCCESSFUL and intent["phase"] == "retired":
        p.require(intent["prepareCompleted"] is True and intent.get("quarantineReason"), "production retirement of the completed interrupted PREPARE")
        p.require(all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "retired exact scope")
        p.require(len(intent["slots"]) == 2 and {s["attachment"] for s in intent["slots"]} == {s["attachment"] for s in arm["slots"]}, "full retired slot set")
        rows = [{k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]]
        p.require(sorted(rows, key=lambda s: s["attachment"]) == arm["slots"], "complete retired slot tuple")
        for slot in intent["slots"]:
            receipt = slot.get("receipt")
            if slot["role"] == "runtime" and slot.get("key") is None and receipt is None:
                p.require(all(slot[operation] not in state[journal]
                              for operation in ("registerOperation", "retireOperation")
                              for journal in ("operations", "operationDigests")), "unissued runtime has no persisted operation")
                continue
            p.pin(slot.get("key"))
            if slot["role"] == "prepare":
                p.require(slot["key"] == next(c["key"] for c in arm["credentials"] if c["attachment"] == slot["attachment"]),
                          "actual installed PREPARE key")
            p.require(type(receipt) is dict and all(receipt.get(k) == v for k, v in {"store": intent["store"], "volume": slot["volume"],
                "attachment": slot["attachment"], "launch": intent["launch"],
                "prepare": intent["prepare"] if slot["role"] == "prepare" else None}.items()), "every issued attachment drained")
            p.integer(receipt["revision"], minimum=1)
    else:
        p.require(intent["phase"] == "quarantined" and intent["prepareCompleted"] is False, "production quarantine after restart")
        p.failed_prepare(intent, arm)
        if arm["caseName"] not in SUCCESSFUL:
            p.failed_full_prepare(intent, arm)
    if arm["caseName"] == "drain-durable-reply-lost":
        # The pre-death receipt was already durable; recovery must replay the
        # same operation and install that exact receipt, never a fresh one.
        durable = {k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
        actual = next(s["receipt"] for s in intent["slots"] if s["attachment"] == arm["targetAttachment"])
        p.require(actual == durable, "same-operation receipt replay after restart")
    return intent


def _kill_api(daemon, api, record, phase, **extra):
    daemon.stop(kill=True)  # Actual Popen child; wait pins its PID until reaped.
    import harness
    p.require(daemon.process.returncode == -signal.SIGKILL and exact_exit(api, harness._kernel_process(api.pid)), "actual API SIGKILL and native exit")
    record(phase, api=p.native_proof(api), **extra)


def _api_exit_survivors(daemon, api, before, after, record, *, exited_workload=None):
    """Refresh lineage after the positively joined matrix API SIGKILL.

    Equality stays strict everywhere else. Darwin may reparent a direct child
    to launchd; no other field or lineage transition is admitted here.
    """
    import harness
    p.require(daemon.process.pid == api.pid and daemon.process.returncode == -signal.SIGKILL
              and exact_exit(api, harness._kernel_process(api.pid)), "joined exact API exit before survivor refresh")
    if exited_workload is not None:
        p.require(exited_workload in before and exited_workload != api
                  and harness._kernel_process(exited_workload.pid) is None, "exact natural workload absence")
    current = {v.pid: v for v in after}
    refreshed = []
    evidence = []
    def proof(value):
        return dict(p.native_proof(value), parentPID=value.parent_pid, executable=value.executable,
                    argumentsSHA256=p.digest(p.canonical(list(value.arguments))))
    for previous in before:
        if previous == api or previous == exited_workload:
            refreshed.append(previous)
            continue
        observed = current.get(previous.pid)
        p.require(observed == previous or (previous.parent_pid == api.pid
                  and observed == replace(previous, parent_pid=1)), "exact survivor or killed API child reparented to PID 1")
        refreshed.append(observed)
        evidence.append(dict(before=proof(previous), after=proof(observed)))
    unchanged_processes(refreshed, list(after) + ([] if exited_workload is None else [exited_workload]), api)
    record("matrix-api-survivors-observed", api=p.native_proof(api), survivors=evidence,
           **({} if exited_workload is None else {"exitedWorkload": p.native_proof(exited_workload)}))
    return refreshed


def _restart_api_observing(daemon, api, workload, workload_live, require_no_exit_before_birth, record, remaining, phase):
    """Restart the API; return (fresh_api, exit_event_seen). Exit watching is exact-owner."""
    import harness
    fresh_api = None
    seen_exit = False
    with closing(select.kqueue()) as waiter:
        if workload_live:
            waiter.control([select.kevent(workload.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
            p.require(harness._kernel_process(workload.pid) == workload, "same workload after exit watcher registration")
        def observe_spawn():
            nonlocal fresh_api
            p.require(fresh_api is None, "one production API spawn")
            remaining()
            if workload_live and require_no_exit_before_birth:
                p.require(not waiter.control(None, 1, 0), "workload exited before replacement API birth observation")
            fresh_api = api_target(daemon, harness._kernel_process(daemon.process.pid))
            p.require(fresh_api != api and exact_exit(api, harness._kernel_process(api.pid)), "fresh API incarnation")
            if workload_live and require_no_exit_before_birth:
                p.require(harness._kernel_process(workload.pid) == workload, "held workload live after replacement API birth")
                p.require(not waiter.control(None, 1, 0), "workload exit preceded completed API birth observation")
            record(phase, api=p.native_proof(fresh_api))
        remaining(); daemon.start(on_spawn=observe_spawn)
        p.require(fresh_api is not None and api_target(daemon, harness._kernel_process(daemon.process.pid)) == fresh_api, "same observed API became ready")
        if workload_live:
            events = waiter.control(None, 1, 0)
            if events:
                p.require(len(events) == 1 and events[0].ident == workload.pid and events[0].filter == select.KQ_FILTER_PROC
                          and not events[0].flags & select.KQ_EV_ERROR and events[0].fflags & select.KQ_NOTE_EXIT, "native workload exit event")
                seen_exit = True
    return fresh_api, seen_exit


def _await_exit(process, remaining):
    import harness
    while not exact_exit(process, harness._kernel_process(process.pid)):
        remaining(); time.sleep(0.025)


def restart_api(daemon, workload, census, intent, arm, checkpoint, ledger, files, record, processes, remaining, start, read_state, *, worker=None):
    """RTM-097 cell: API-only SIGKILL at the exact boundary, production reconciliation."""
    import harness
    case = arm["caseName"]
    boundary_kind = kind(case)
    p.require(arm["profile"] == p.FULL_PROFILE and arm["version"] == 3, "full v3 arm required")
    validate_checkpoint(checkpoint, arm, worker)
    _, prefault_state, prefault_hashes = read_state()
    phase = prefault_intent(prefault_state, intent, arm, case)
    old_record, old_hash = lifecycle.read_owner(daemon.root, read_public)
    owner, context = owner_context(old_record)
    p.require(all(context[k] == arm["scope"][k] for k in context), "live owner matches installed scope")
    storage = storage_target(daemon, owner, census)
    api = api_target(daemon, harness._kernel_process(daemon.process.pid))
    p.require(len({api.pid, storage.pid, workload.pid}) == 3 and api in census and workload in census, "three independent incarnations")
    p.require({v.pid: v for v in processes()} == {v.pid: v for v in census}, "unchanged complete census at injection")
    workload_live = harness._kernel_process(workload.pid) == workload
    if boundary_kind in ("held-guest", "held-storage"):
        p.require(start.poll() is None and workload_live, "live held PREPARE before API death")
    elif boundary_kind == "successful":
        p.require(workload_live, "successful boundary keeps its workload alive")
    with p.Directory(daemon.work) as work, p.Directory(daemon.root, private=False) as root:
        marker, _ = work.read(".cengine-compat-owner", 4096)
        p.require(Path(os.fsdecode(marker).strip()).resolve() == daemon.binary.resolve(), "retained root owner")
        p.require(p.Directory.stamp(os.fstat(root.fd))[:2] == (owner["root"]["device"], owner["root"]["inode"]), "same physical root")
        record("matrix-api-SIGKILL-intent", rtm="RTM-097", boundary=p.FULL_BOUNDARIES[case], kind=boundary_kind, prefaultPhase=phase,
               startPending=start.poll() is None, workloadLive=workload_live, api=p.native_proof(api), workload=p.native_proof(workload),
               storage=p.native_proof(storage), ownerSHA256=old_hash, armDigest=checkpoint["armDigest"], journal=prefault_hashes, sdkVersions=sdk_versions())
        p.verify_full_ledger(ledger, files); work.validate(); root.validate(); remaining()
        p.require(harness._kernel_process(api.pid) == api and harness._kernel_process(storage.pid) == storage, "API and storage live immediately before API-only death")
        _kill_api(daemon, api, record, "matrix-api-only-death-joined")
        variant = start_variant(start, "api", case, remaining)
        observed_workload = harness._kernel_process(workload.pid)
        workload_live = observed_workload is not None
        if boundary_kind != "natural":
            p.require(workload_live, "workload survived API-only death")
        after = list(processes())
        if workload_live:
            p.require(observed_workload in after, "observed workload in surviving census")
        # A naturally reaped owner retains its historical entry only for the
        # shared tail's exact-removal check, never as survivor evidence.
        census = _api_exit_survivors(daemon, api, census, after, record,
                                     exited_workload=None if workload_live else workload)
        storage = next(v for v in census if v.pid == storage.pid)
        workload = next(v for v in census if v.pid == workload.pid)
        p.require(harness._kernel_process(storage.pid) == storage, "storage survived API-only death")
        if workload_live:
            p.require(harness._kernel_process(workload.pid) == workload, "same workload after survivor refresh")
        record("matrix-api-start-joined", variant=variant, returncode=start.returncode, workloadLive=workload_live)
        require_no_exit_before_birth = variant != "settled-failure"
        fresh_api, seen_exit = _restart_api_observing(daemon, api, workload, workload_live, require_no_exit_before_birth,
                                                     record, remaining, "matrix-api-replacement-born")
        remaining(); work.validate(); root.validate()
    new_record, new_hash = lifecycle.read_owner(daemon.root, read_public)
    fresh = api_owner_transition(old_record, new_record, arm)
    # The returned census keeps the old workload entry: the shared lifecycle
    # tail proves its exact removal (or, after adoption, its survival) itself.
    expected = [fresh_api if v == api else v for v in census]
    if variant == "settled-success":
        p.require(not seen_exit and harness._kernel_process(workload.pid) == workload, "live runtime adopted, not contained")
        p.require({v.pid: v for v in processes()} == {v.pid: v for v in expected}, "adoption leaves the census intact")
        workload_exited = False
    else:
        if workload_live:
            _await_exit(workload, remaining)
        survivors = [v for v in expected if v != workload]
        p.require({v.pid: v for v in processes()} == {v.pid: v for v in survivors}
                  and all(harness._kernel_process(v.pid) == v for v in survivors), "old workload contained, everything else unchanged")
        workload_exited = True
    p.require(harness._kernel_process(storage.pid) == storage, "same storage VM after reconciliation")
    _, recovered_state, recovered_hashes = read_state()
    recovered_intent(recovered_state, arm, variant, checkpoint)
    record("matrix-api-reconciled", api=p.native_proof(fresh_api), variant=variant, oldWorkloadExited=workload_exited,
           storage=p.native_proof(storage), ownerSHA256=new_hash, context=fresh, journal=recovered_hashes)
    return expected, fresh, (new_record, new_hash), variant, workload_exited


def restart_storage(daemon, workload, census, intent, arm, checkpoint, ledger, files, record, processes, remaining, start, read_state, storage_initramfs_sha256, *, worker=None):
    """RTM-099 cell: storage-VM SIGKILL at the exact boundary, then explicit API recovery."""
    import harness
    case = arm["caseName"]
    boundary_kind = kind(case)
    p.require(arm["profile"] == p.FULL_PROFILE and arm["version"] == 3, "full v3 arm required")
    validate_checkpoint(checkpoint, arm, worker)
    old_record, old_hash = lifecycle.read_owner(daemon.root, read_public)
    owner, context = owner_context(old_record)
    p.require(all(context[k] == arm["scope"][k] for k in context), "actual installed context")
    if "filesystemUUID" in checkpoint:
        p.require(checkpoint["filesystemUUID"] == owner["ext4UUID"].replace("-", ""), "physical witness on exact storage filesystem")
    if worker is not None:
        p.require(public_boot(current_boot(old_record))["workerUUID"] == worker, "exact observed worker")
    p.pin(storage_initramfs_sha256)
    p.require((lifecycle.asset_digest(daemon.storage_initramfs) if lifecycle.is_v2(old_record) else current_boot(old_record)["initramfsSHA256"]) == storage_initramfs_sha256, "actual pinned storage initramfs")
    _, prefault_state, prefault_hashes = read_state()
    phase = prefault_intent(prefault_state, intent, arm, case)
    storage = storage_target(daemon, owner, census)
    api = api_target(daemon, harness._kernel_process(daemon.process.pid))
    p.require(len({api.pid, storage.pid, workload.pid}) == 3 and api in census and workload in census, "three independent incarnations")
    workload_live = harness._kernel_process(workload.pid) == workload
    current, expected = {v.pid: v for v in processes()}, {v.pid: v for v in census}
    if boundary_kind == "natural" and not workload_live:
        expected.pop(workload.pid)  # A natural failure may reap its workload before the injection.
    p.require(current == expected, "complete unchanged injection census")
    if boundary_kind in ("held-guest", "held-storage"):
        p.require(start.poll() is None and workload_live, "live held PREPARE before storage VM death")
    elif boundary_kind == "successful":
        p.require(workload_live, "successful boundary keeps its workload alive")
    with p.Directory(daemon.work) as work, p.Directory(daemon.root, private=False) as root:
        marker, _ = work.read(".cengine-compat-owner", 4096)
        p.require(Path(os.fsdecode(marker).strip()).resolve() == daemon.binary.resolve(), "retained root owner")
        p.require(p.Directory.stamp(os.fstat(root.fd))[:2] == (owner["root"]["device"], owner["root"]["inode"]), "same physical root")
        record("matrix-storage-SIGKILL-intent", rtm="RTM-099", boundary=p.FULL_BOUNDARIES[case], kind=boundary_kind, prefaultPhase=phase,
               startPending=start.poll() is None, workloadLive=workload_live, storage=p.native_proof(storage), api=p.native_proof(api),
               workload=p.native_proof(workload), ownerSHA256=old_hash, armDigest=checkpoint["armDigest"], journal=prefault_hashes, sdkVersions=sdk_versions())
        p.verify_full_ledger(ledger, files); work.validate(); root.validate(); remaining()
        with closing(select.kqueue()) as storage_waiter:
            storage_waiter.control([select.kevent(storage.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
            p.require(harness._kernel_process(api.pid) == api and harness._kernel_process(storage.pid) == storage, "API and storage live before storage-only death")
            current_record, current_hash = lifecycle.read_owner(daemon.root, read_public)
            p.require(current_hash == old_hash, "unchanged current VM owner at signal")
            delivery = signal_storage(storage)  # Strict audit-token SIGKILL; never PID-only or inferred delivery.
            record("matrix-storage-SIGKILL-delivered", proof=delivery)
            events = storage_waiter.control(None, 1, remaining())
            p.require(len(events) == 1 and events[0].ident == storage.pid and events[0].filter == select.KQ_FILTER_PROC
                      and not events[0].flags & select.KQ_EV_ERROR and events[0].fflags & select.KQ_NOTE_EXIT, "actual selected storage exit event")
        _await_exit(storage, remaining)
        p.require(harness._kernel_process(api.pid) == api, "API survived independently through storage exit")
        if boundary_kind in ("held-guest",):
            p.require(harness._kernel_process(workload.pid) == workload and start.poll() is None, "guest-held PREPARE survives storage-only death")
        record("matrix-storage-only-death-joined", storage=p.native_proof(storage), apiSurvived=True,
               workloadLive=harness._kernel_process(workload.pid) == workload, startPending=start.poll() is None)
        survivors = [v for v in census if v != storage]
        # Restart is an explicit SECOND recovery step, never mislabeled API-only.
        record("matrix-api-recovery-SIGKILL-intent", api=p.native_proof(api))
        p.verify_full_ledger(ledger, files); work.validate(); root.validate(); remaining()
        p.require(harness._kernel_process(api.pid) == api and exact_exit(storage, harness._kernel_process(storage.pid)), "same isolated storage-death boundary before API recovery")
        _kill_api(daemon, api, record, "matrix-api-recovery-death-joined")
        variant = start_variant(start, "storage", case, remaining)
        observed_workload = harness._kernel_process(workload.pid)
        workload_live = observed_workload is not None
        if boundary_kind == "held-guest":
            p.require(workload_live, "guest-held workload survives until recovery API birth")
        after = list(processes())
        if workload_live:
            p.require(observed_workload in after, "observed workload in surviving census")
        survivors = _api_exit_survivors(daemon, api, survivors, after, record,
                                        exited_workload=None if workload_live else workload)
        # The dead storage incarnation remains historical, not survivor evidence:
        # the shared tail still replaces that exact entry with the reopened VM.
        refreshed = {v.pid: v for v in survivors}
        census = [storage if v == storage else refreshed[v.pid] for v in census]
        workload = refreshed[workload.pid]
        if workload_live:
            p.require(harness._kernel_process(workload.pid) == workload, "same workload after survivor refresh")
        record("matrix-storage-start-joined", variant=variant, returncode=start.returncode, workloadLive=workload_live)
        fresh_api, seen_exit = _restart_api_observing(daemon, api, workload, workload_live, boundary_kind == "held-guest",
                                                     record, remaining, "matrix-storage-recovery-api-born")
        remaining(); work.validate(); root.validate()
    new_record, new_hash = lifecycle.read_owner(daemon.root, read_public)
    fresh = storage_owner_transition(old_record, new_record, arm)
    _, recovered_state, recovered_hashes = read_state()
    recovered_phase = recovered_state["intents"][arm["scope"]["intent"]]["phase"]
    if phase == "prepareAdmitted" and variant in ("interrupted", "service-loss-failure") \
            and not (boundary_kind == "successful" and recovered_phase == "retired"):
        drain = (recovered_successful_drain if boundary_kind == "successful" else recovered_prepare_drain)(
            prefault_state, recovered_state, arm, new_record)
        record("matrix-storage-new-epoch-drain", proof=drain, journal=recovered_hashes)
    else:
        # A completed interrupted PREPARE (NORMAL/A8) retires with its pre-death
        # receipts; recovered_intent checks that exact replay, not a new-epoch drain.
        record("matrix-storage-recovered-journal", journal=recovered_hashes, prefaultPhase=phase, variant=variant, recoveredPhase=recovered_phase)
    if workload_live:
        _await_exit(workload, remaining)  # Any storage restart interrupts shared-volume workloads.
    new_owner, _ = owner_context(new_record)
    fresh_storage = storage_target(daemon, new_owner, processes())
    p.require(fresh_storage != storage and exact_exit(storage, harness._kernel_process(storage.pid)), "old storage exited, distinct current storage incarnation")
    expected = [fresh_api if v == api else fresh_storage if v == storage else v for v in census]
    survivors = [v for v in expected if v != workload]
    p.require({v.pid: v for v in processes()} == {v.pid: v for v in survivors}
              and all(harness._kernel_process(v.pid) == v for v in survivors), "old workload contained, fresh API/storage, everything else unchanged")
    recovered = recovered_state["intents"][arm["scope"]["intent"]]
    p.require(recovered["phase"] in ("quarantined", "retired") and all(s.get("receipt") is not None for s in recovered["slots"] if s.get("key") is not None),
              "storage recovery drained every issued attachment")
    record("matrix-storage-reopened-reconciled", api=p.native_proof(fresh_api), storage=p.native_proof(fresh_storage),
           context=fresh, ownerSHA256=new_hash, variant=variant, oldWorkloadExited=True, recoveredPhase=recovered["phase"])
    return expected, fresh, (new_record, new_hash), variant, True


class MatrixOutcome:
    """Retained direct-run result of one matrix cell; never a deserializable credential."""
    def __init__(self):
        raise TypeError("only the completed live fixture creates MatrixOutcome")

    @property
    def receipt(self):
        return copy.deepcopy(self._receipt)

    def close(self):
        _LIVE_MATRIX_OUTCOMES.pop(id(self), None)
        self._directory.close()

    def validate(self):
        p.require(_LIVE_MATRIX_OUTCOMES.get(id(self)) is self, "direct retained live outcome required")
        p.verify_full_ledger(self._directory, self._files)
        return self.receipt


def completed_matrix_outcome(receipt, ledger, files):
    """Internal lifecycle completion; never import/restore receipts from disk."""
    p.verify_full_ledger(ledger, files)
    retained = p.Directory(ledger.path)
    try:
        p.require(p.Directory.stamp(os.fstat(retained.fd)) == p.Directory.stamp(os.fstat(ledger.fd)), "same retained evidence directory")
        pinned = {name: retained.read(name, pin_file=True) for name in files}
        p.require(pinned == files, "retained completion evidence unchanged")
        ordered = [p.decode(pinned[name][0]) for name in sorted(pinned)]
        p.require(ordered[-1] == {"phase": "matrix-case-result", **receipt}, "terminal result matches retained ledger")
        p.require(p.digest(p.canonical([p.digest(p.canonical(row)) for row in ordered[:-1]])) == receipt["evidenceSHA256"], "complete retained ledger hash")
        outcome = object.__new__(MatrixOutcome)
        outcome._receipt, outcome._directory, outcome._files = copy.deepcopy(receipt), retained, pinned
        _LIVE_MATRIX_OUTCOMES[id(outcome)] = outcome
        return outcome
    except BaseException:
        retained.close()
        raise


RECEIPT_FIELDS = {"rtm", "restart", "profile", "caseName", "boundary", "kind", "variant", "runID", "store", "result", "evidenceSHA256", "execution", "fullAcceptance"}


def validate_receipt(row, rtm):
    p.exact(row, RECEIPT_FIELDS)
    p.require(row["rtm"] == rtm and row["restart"] == MATRICES[rtm] and row["profile"] == p.FULL_PROFILE and row["caseName"] in BOUNDARIES
              and row["boundary"] == p.FULL_BOUNDARIES[row["caseName"]] and row["kind"] == kind(row["caseName"])
              and row["variant"] in VARIANTS[MATRICES[rtm]][row["kind"]] and row["result"] == "matrix-case-passed"
              and row["execution"] == "actual-docker-runtime" and row["fullAcceptance"] is False, "current live matrix cell receipt required")
    p.uid(row["runID"]); p.uid(row["store"]); p.pin(row["evidenceSHA256"])
    return row


def aggregate_matrix(outcomes, rtm):
    """Only retained direct live results, never bearer JSON/source-only records."""
    p.require(rtm in MATRICES, "closed restart matrix")
    p.require(type(outcomes) is list and len(outcomes) == 9, "nine retained live outcomes required")
    p.require(all(type(outcome) is MatrixOutcome for outcome in outcomes), "serialized receipts are report-only")
    rows = [validate_receipt(outcome.validate(), rtm) for outcome in outcomes]
    cases, runs, stores = set(), set(), set()
    for row in rows:
        p.require(row["caseName"] not in cases and row["runID"] not in runs and row["store"] not in stores, "unique case/fresh Daemon receipts")
        cases.add(row["caseName"]); runs.add(row["runID"]); stores.add(row["store"])
    p.require(cases == set(BOUNDARIES), "exact nine boundaries required")
    identities = [p.Directory.stamp(os.fstat(outcome._directory.fd))[:2] for outcome in outcomes]
    p.require(len(set(identities)) == 9, "unique retained evidence directories")
    return {"rtm": rtm, "restart": MATRICES[rtm], "profile": p.FULL_PROFILE, "coverage": "9/9", "fullAcceptance": True,
            "result": "matrix-acceptance-passed", "variants": {row["caseName"]: row["variant"] for row in rows},
            "receiptsSHA256": p.digest(p.canonical(sorted(rows, key=lambda r: r["caseName"])))}
