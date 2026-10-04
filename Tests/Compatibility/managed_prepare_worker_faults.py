"""RTM098 held A4/A5 worker exit and the generic checkpoint-exit route.

No engine access on import. JSON corroborates the authenticated PID1 WaitResult
and sealed replacement, never grants containment or retirement authority.
"""
from contextlib import contextmanager
from dataclasses import replace
import os
import signal
from pathlib import Path
import time
import uuid

import managed_prepare_faults as p
import managed_storage_recovery as recovery
import managed_prepare_worker_lifecycle_evidence as lifecycle
from managed_prepare_service_faults import api_target, storage_target
from managed_prepare_storage_vm_faults import public_boot as legacy_public_boot, undrained_prepare, bounded_base64


def public_boot(boot):
    if lifecycle.shared.is_v2(boot): return lifecycle.public_service(boot)
    return legacy_public_boot(boot)


def worker_exit_request(arm, checkpoint, boot):
    ready = public_boot(boot)
    p.require(arm["caseName"] in p.WORKER_EXIT_CASES, "worker exit held A4/A5 only")
    p.require(ready["storeUUID"] == arm["scope"]["store"] and all(ready[k] == arm["scope"][k]
        for k in ("serviceEpoch", "controllerEpoch", "controllerKey")), "current public worker installed context")
    p.storage_observation(checkpoint, arm, ready["workerUUID"])
    return dict(query=p.storage_query(arm, ready["workerUUID"]), stage=arm["caseName"],
        token=checkpoint["admission"]["releaseToken"])


def worker_wait(value, arm, checkpoint, boot):
    expected = worker_exit_request(arm, checkpoint, boot)
    p.exact(value, {"query", "stage", "token", "requestSequence", "workerPID", "exitCode", "reaped"})
    p.require(p.canonical({k: value[k] for k in expected}) == p.canonical(expected), "exact worker wait request")
    p.integer(value["requestSequence"], 2**64 - 1, 1)
    p.require(value["requestSequence"] == checkpoint["admission"]["requestSequence"], "exact held admission request sequence")
    p.integer(value["workerPID"], 2**31 - 1, 2)
    p.require(type(value["exitCode"]) is int and value["exitCode"] == 74 and value["reaped"] is True,
        "actual PID1 reaped worker exit 74, not EOF")
    return value


# Generic route artifacts mirror the .storage-worker-exit.json flow: the parent
# publishes <requestID>.checkpoint-worker-exit.json; the carrier claims it
# exclusively into .checkpoint-worker-exit.claimed.json (the exact ACK claim
# echo) and PID1's sole actual Wait projection lands in
# .checkpoint-worker-wait.json. These exact names are the contract (docs
# docker-compatibility.md RTM-098 row; ManagedPrepareCompatibilityQueue opens
# and publishes precisely these suffixes).
CHECKPOINT_EXIT_SUFFIXES = (".checkpoint-worker-exit.json", ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json")


def checkpoint_exit_request(arm, checkpoint, boot):
    """RTM098 generic full-profile-only claim; exactly one checkpoint carrier.

    The carrier is the arm plus the one checkpoint selected by the arm's case:
    physical Observation for NORMAL/A7, EarlyObservation for A1/A2/A3, and the
    exact actually retained storage Bound/Drain observation for A6/A8. It never
    carries a storage Admission, release token, or made-up sequence.
    """
    ready = public_boot(boot)
    p.require(type(arm.get("version")) is int and arm["version"] == 3 and arm["profile"] == p.FULL_PROFILE
        and arm["caseName"] in p.CHECKPOINT_EXIT_CASES, "checkpoint exit seven cuts only")
    p.require(ready["storeUUID"] == arm["scope"]["store"] and all(ready[k] == arm["scope"][k]
        for k in ("serviceEpoch", "controllerEpoch", "controllerKey")), "current public worker installed context")
    worker = p.uid(ready["workerUUID"])
    if arm["caseName"] in p.STORAGE_CASES:
        p.storage_observation(checkpoint, arm, worker)
    else:
        p.full_observation(checkpoint, arm)
    request = dict(arm=arm, workerUUID=worker)
    request[p.checkpoint_carrier(arm["caseName"])] = checkpoint
    p.require(len(p.canonical(request)) <= 65536, "checkpoint exit frame bound")
    return request


def checkpoint_wait(value, arm, checkpoint, boot):
    """Strict PID1 Wait projection: the exact sealed claim echo plus the sole
    actual Wait proof (live worker PID bounds, exit 74, reaped)."""
    expected = checkpoint_exit_request(arm, checkpoint, boot)
    carrier = p.checkpoint_carrier(arm["caseName"])
    p.exact(value, {"arm", carrier, "workerUUID", "workerPID", "exitCode", "reaped"})
    p.require(p.canonical({k: value[k] for k in expected}) == p.canonical(expected), "exact checkpoint wait claim echo")
    p.integer(value["workerPID"], 2**31 - 1, 2)
    p.require(type(value["exitCode"]) is int and value["exitCode"] == 74 and value["reaped"] is True,
        "actual PID1 reaped worker exit 74, not EOF")
    return value


def retired_checkpoint_cut(intent, arm, checkpoint):
    """A8 retired-cut oracle: the durable publication survived the worker
    death and production retired the completed interrupted PREPARE exactly once.
    Every issued attachment is drained; A8's slot receipt is the exact pre-death
    durable same-operation replay."""
    p.require(arm["caseName"] == "drain-durable-reply-lost", "A8 completed checkpoint cut only")
    p.require(all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "retired exact scope")
    p.require(intent["phase"] == "retired" and intent["prepareCompleted"] is True
        and intent.get("quarantineReason"), "production retirement of the completed interrupted PREPARE")
    p.require(len(intent["slots"]) == 2 and {s["attachment"] for s in intent["slots"]} == {s["attachment"] for s in arm["slots"]}, "full retired slot set")
    for slot in intent["slots"]:
        receipt = slot.get("receipt")
        expected = {"store": intent["store"], "volume": slot["volume"], "attachment": slot["attachment"], "launch": intent["launch"]}
        if slot["role"] == "prepare": expected["prepare"] = intent["prepare"]
        p.require(type(receipt) is dict and all(receipt.get(k) == v for k, v in expected.items()), "every issued attachment drained")
        p.integer(receipt["revision"], minimum=1)
    if arm["caseName"] == "drain-durable-reply-lost":
        # The pre-death receipt was already durable in the surviving authority;
        # recovery replays the same operation and installs that exact receipt.
        durable = {k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
        actual = next(s["receipt"] for s in intent["slots"] if s["attachment"] == arm["targetAttachment"])
        p.require(actual == durable, "same-operation receipt replay after worker replacement")
    return intent


def recovered_checkpoint_intent(intent, arm, checkpoint):
    """Post-replacement intent oracle for the seven generic cuts: A8 retired
    after successful guest completion; A6 and the guest cuts quarantined and drained
    (NORMAL included: the owned worker's exit 74 interrupted the first attempt)."""
    p.require(arm["caseName"] in p.CHECKPOINT_EXIT_CASES, "checkpoint exit cut only")
    if arm["caseName"] == "drain-durable-reply-lost":
        return retired_checkpoint_cut(intent, arm, checkpoint)
    return p.failed_full_prepare(intent, arm, worker_interrupted=True)


def recovered_worker_cut(before, after, arm, boot, checkpoint):
    """A8 worker-exit recovery oracle: the authority survives the worker
    death holding the durable drain; the replacement worker adopts and
    production retires the completed interrupted PREPARE exactly once.
    A6 has no successful guest completion and uses recovered_worker_drain.
    """
    previous = before["intents"][arm["scope"]["intent"]]
    undrained_prepare(before, previous, arm, interrupted=True, checkpoint=checkpoint)  # cut containment/publication may journal its planned Retire
    current = after["intents"][previous["id"]]
    p.integer(after["revision"], minimum=before["revision"] + 1)
    p.require(after["store"] == before["store"], "same post-recovery host store")
    for key in ("operations", "operationDigests"):
        p.require(all(after[key].get(k) == v for k, v in before[key].items()), "immutable pre-fault operations")
    retired_checkpoint_cut(current, arm, checkpoint)
    return dict(phase=current["phase"], hostRevision=after["revision"], completed=current["prepareCompleted"])


def recovered_worker_drain(before, after, arm, boot, *, worker_interrupted=False):
    previous = before["intents"][arm["scope"]["intent"]]
    undrained_prepare(before, previous, arm, interrupted=worker_interrupted)
    current = p.failed_full_prepare(after["intents"][previous["id"]], arm, worker_interrupted=worker_interrupted)
    ready = public_boot(boot)
    p.require(ready["storeUUID"] == before["store"] == after["store"]
        and ready["serviceEpoch"] != arm["scope"]["serviceEpoch"]
        and all(ready[k] == arm["scope"][k] for k in ("controllerEpoch", "controllerKey")), "current worker recovery authority")
    p.integer(after["revision"], minimum=before["revision"] + 1)
    for key in ("operations", "operationDigests"):
        p.require(all(after[key].get(k) == v for k, v in before[key].items()), "immutable pre-fault operations")
    drains = []
    for old in previous["slots"]:
        slot = next(s for s in current["slots"] if s["attachment"] == old["attachment"])
        p.require({k: v for k, v in slot.items() if k != "receipt"} == {k: v for k, v in old.items() if k != "receipt"}, "immutable drained slot identity")
        operation = old["retireOperation"]
        if old["role"] == "runtime":
            p.require(operation not in after["operations"] and operation not in after["operationDigests"], "unissued runtime not retired")
            continue
        raw = bounded_base64(after["operations"][operation], 65536)
        expected = dict(id=0, retire=dict(operation=operation, store=current["store"],
            volume=slot["volume"], attachment=slot["attachment"], launch=current["launch"]))
        p.require(raw == p.canonical(expected) and after["operationDigests"][operation] == p.digest(raw), "exact production Retire operation")
        replay = worker_interrupted and operation in before["operations"]
        # A natural cut may already have committed Retire before worker death.
        # Replaying those exact durable bytes returns the original revision;
        # newly submitted drains must still follow the replacement's boot.
        p.integer(slot["receipt"]["revision"], minimum=1 if replay else ready["revision"] + 1)
        if old.get("receipt") is not None:
            p.require(slot["receipt"] == old["receipt"], "immutable pre-fault drain receipt")
        drains.append(dict(operation=operation, requestSHA256=p.digest(raw), receipt=slot["receipt"], replay=replay))
    return dict(bootRevision=ready["revision"], hostRevision=after["revision"], drains=drains)


def checkpoint_prefault_intent(state, previous, arm, checkpoint):
    """Re-read a live cut without mistaking normal journal progress for mutation.

    The immutable plan, previously installed keys/receipts, and completed guest
    evidence cannot change. Only the cut's validated production phases advance.
    """
    current = state["intents"][arm["scope"]["intent"]]
    undrained_prepare(state, current, arm, interrupted=True, checkpoint=checkpoint)
    mutable = {"phase", "version", "prepareCompleted", "cleanUnmount", "guestCompletion", "quarantineReason", "slots"}
    p.require({k: v for k, v in previous.items() if k not in mutable} ==
        {k: v for k, v in current.items() if k not in mutable}, "immutable pre-fault intent plan")
    p.require(current.get("version", 1) >= previous.get("version", 1), "monotonic intent version")
    # Quarantine diagnostics may advance from start interruption to launch
    # retirement; unlike the completion evidence, their text is not immutable.
    for key in ("prepareCompleted", "cleanUnmount", "guestCompletion"):
        if previous.get(key): p.require(current.get(key) == previous[key], "immutable pre-fault completion evidence")
    old_slots = {s["attachment"]: s for s in previous["slots"]}
    for slot in current["slots"]:
        old = old_slots[slot["attachment"]]
        p.require({k: v for k, v in old.items() if k not in ("key", "receipt")} ==
            {k: v for k, v in slot.items() if k not in ("key", "receipt")}, "immutable pre-fault slot plan")
        for key in ("key", "receipt"):
            if old.get(key) is not None: p.require(slot.get(key) == old[key], "immutable pre-fault slot evidence")
    return current


@contextmanager
def prepared_peer_owner(daemon, peer, plan, root_identity, census):
    """The never-started Docker peer has a canonical shim with no storage grant."""
    import harness
    p.owned(peer, "container", plan)
    p.require(peer.attrs["State"]["Running"] is False and peer.attrs["State"]["Status"] == "created", "never-started owned peer")
    container = p.pin(peer.id)
    root = recovery.runtime_root_path(daemon.root)
    with p.Directory(root / "containers" / container, private=False) as directory:
        original = directory.read("prepared-shim.json", 1024 * 1024, pin_file=True)
        prepared = p.decode(original[0], 1024 * 1024, canonical_only=False)
        spec = prepared["specification"]
        p.require(prepared["currentContainer"]["id"] == spec["containerID"] == container, "exact prepared peer ID")
        generation = "%020d-%s" % (p.integer(spec["generation"], minimum=1), p.uid(spec["shimLaunchUUID"]))
        spec_path = root / "containers" / container / "shim-generations" / generation / "spec.json"
        selected = [v for v in census if len(v.arguments) == 6 and v.arguments[1:3] == ("vm-shim", "--spec")
            and v.arguments[3] == str(spec_path) and v.arguments[4:] == ("--launch-intent", str(spec_path.parent / "intent.json"))]
        p.require(len(selected) == 1, "one actual prepared peer native generation, not assumed absence")
        process = selected[0]
        with p.workload_owner(process, daemon, plan, None, root_identity, prepared=prepared) as (native, _, validate_launch):
            def validate_files():
                directory.validate(); validate_launch()
                p.require(directory.read("prepared-shim.json", 1024 * 1024) == original, "immutable prepared peer changed")
            def validate():
                validate_files()
                p.require(harness._kernel_process(process.pid) == owner[0], "same live prepared peer incarnation")
            refreshed = False
            def api_joined_refresh(api, survivors):
                nonlocal refreshed
                # Called only with the strict exit monitor's refreshed census.
                # Retain the original proof; update only this live comparison pin
                # (also used when descriptors are reopened after API reattachment).
                p.require(not refreshed and daemon.process.pid == api.pid
                    and daemon.process.returncode == -signal.SIGKILL
                    and recovery.exact_exit(api, harness._kernel_process(api.pid)),
                    "joined exact API exit before prepared peer refresh")
                selected = [v for v in survivors if v.pid == process.pid]
                p.require(len(selected) == 1, "one refreshed prepared peer")
                current = selected[0]
                p.require(current == process or (process.parent_pid == api.pid
                    and current == replace(process, parent_pid=1)), "exact prepared peer API reparenting")
                validate_files()
                p.require(harness._kernel_process(process.pid) == current, "same refreshed live prepared peer")
                owner[0] = current
                refreshed = True
            validate.api_joined_refresh = api_joined_refresh
            owner = [process, {**native, "preparedSHA256": original[1][-1], "containerInstance": str(uuid.UUID(prepared["currentContainer"]["instanceID"]))}, validate]
            validate()
            yield owner


def containment_inventory(daemon, owned_containers, census, workload, peer, peer_proof, validate_peer):
    p.require(len(owned_containers) == len(set(owned_containers)) == 2, "exact two owned containers")
    for container in owned_containers: p.pin(container)
    p.require(peer_proof["container"] in owned_containers and workload != peer, "separate prepared peer ownership")
    p.require(all(v in census for v in (workload, peer)), "both captured native owners in pre-fault census")
    root = recovery.runtime_root_path(daemon.root)
    with p.Directory(root / "containers", private=False) as directory:
        p.require(sorted(os.listdir(directory.fd)) == sorted(owned_containers), "complete canonical two-container directory census")
    selected = []
    for process in census:
        args = process.arguments
        if len(args) >= 4 and args[1:3] == ("vm-shim", "--spec") and root / "containers" in Path(args[3]).parents:
            selected.append(process)
    p.require({v.pid: v for v in selected} == {v.pid: v for v in (workload, peer)}, "complete native owned generation census")
    validate_peer()


def surviving_hosts(census, current, workloads, api, storage, inspect, *, contained=False):
    """Only positive native exit proof permits either intentionally contained shim to vanish."""
    p.require(len({v.pid for v in census}) == len(census) and len({v.pid for v in current}) == len(current), "unique process census")
    p.require(len({v.pid for v in workloads}) == len(workloads) and all(v in census for v in workloads), "captured containment owners")
    p.require(api in census and storage in census and api not in workloads and storage not in workloads, "independent host owners")
    absent = []
    for workload in workloads:
        if workload in current:
            p.require(not contained and inspect(workload.pid) == workload, "contained workload still live or changed")
        else:
            p.require(recovery.exact_exit(workload, inspect(workload.pid)), "positive natural workload exit")
            absent.append(workload)
    expected = [v for v in census if v not in absent]
    p.require({v.pid: v for v in current} == {v.pid: v for v in expected}, "unrelated runtime process changed")
    p.require(all(inspect(v.pid) == v for v in expected), "independent API/storage/unrelated native owners unchanged")
    return current


def restart_worker_at_a5(daemon, workload, census, intent, arm, checkpoint, queue, wait_artifact, artifact,
                        ledger, files, record, processes, remaining, start, read_state, wait_exit,
                        join_failed_start, storage_initramfs_sha256, *, owned_containers, peer_owner, active_ack=None,
                        checkpoint_exit=False):
    import harness
    # The route is derived from the cut: held A4/A5 keep the strict StorageRelease
    # worker-exit path; the seven checkpoint cuts use the generic carrier.
    p.require(type(checkpoint_exit) is bool and checkpoint_exit == (arm["caseName"] in p.CHECKPOINT_EXIT_CASES),
        "route matches the cut")
    # A1/A3/A6 are natural cuts: the interrupted start already quarantined the
    # intent and production may already have contained the owner before this
    # flow runs. The sealed claim + PID1 Wait + replacement still apply.
    natural = checkpoint_exit and arm["caseName"] in p.NATURAL_FAILURE_CASES
    before, owner_hash = lifecycle.read_owner(daemon.root, recovery.read_public)
    old, boot = lifecycle.owner(before)
    p.require(not lifecycle.history(before), "fresh worker-only owner history")
    request = checkpoint_exit_request(arm, checkpoint, boot) if checkpoint_exit else worker_exit_request(arm, checkpoint, boot)
    p.pin(storage_initramfs_sha256)
    p.require((lifecycle.shared.asset_digest(daemon.storage_initramfs) if lifecycle.shared.is_v2(before)
        else boot["initramfsSHA256"]) == storage_initramfs_sha256, "pinned storage initramfs")
    _, prefault, prefault_hashes = read_state()
    if checkpoint_exit: intent = checkpoint_prefault_intent(prefault, intent, arm, checkpoint)
    else: undrained_prepare(prefault, intent, arm)
    api = api_target(daemon, harness._kernel_process(daemon.process.pid))
    storage = storage_target(daemon, old, census)
    peer, peer_proof, validate_peer = peer_owner
    workloads = (workload, peer) + (tuple(active_ack.processes) if active_ack is not None else ())
    def inventory():
        if active_ack is None:
            containment_inventory(daemon, owned_containers, census, workload, peer, peer_proof, validate_peer)
        else:
            from managed_prepare_active_ack import four_owner_inventory
            active_ack.validate(arm)
            four_owner_inventory(daemon, owned_containers, census, workload, peer, peer_proof, validate_peer, active_ack)
    p.require(len({api.pid, storage.pid, workload.pid, peer.pid}) == 4 and all(v in census for v in (api, storage, *workloads)), "independent live owners")
    p.require(intent["container"] in owned_containers and peer_proof["container"] != intent["container"], "exact interrupted and peer container ownership")
    inventory()
    surviving_hosts(census, processes(), workloads, api, storage, harness._kernel_process)
    if not natural:
        p.require(harness._kernel_process(workload.pid) == workload and start.poll() is None, "live held admission before exit intention")
    p.verify_full_ledger(ledger, files)
    artifact(".storage-checkpoint.json" if arm["caseName"] in p.STORAGE_CASES else ".checkpoint.json", 8192)
    _, current, current_hashes = read_state()
    if checkpoint_exit:
        intent = checkpoint_prefault_intent(current, intent, arm, checkpoint)
        p.require(current["revision"] >= prefault["revision"] and
            all(current[key].get(k) == v for key in ("operations", "operationDigests") for k, v in prefault[key].items()),
            "immutable pre-fault operations across live progress")
        prefault, prefault_hashes = current, current_hashes
    else:
        undrained_prepare(current, intent, arm)
        p.require(current == prefault and current_hashes == prefault_hashes, "unchanged held journal before exit action")
    p.require(lifecycle.read_owner(daemon.root, recovery.read_public) == (before, owner_hash),
        "unchanged owner before exit action")
    record("checkpoint-exit-intent" if checkpoint_exit else "worker-exit-intent", request=request, ownerSHA256=owner_hash, journal=prefault_hashes,
        api=p.native_proof(api), storage=p.native_proof(storage), peer=peer_proof, ownedContainerIDs=sorted(owned_containers),
        prepareReceiptsAbsent=all(s.get("receipt") is None for s in intent["slots"] if s["role"] == "prepare"),
        retireOperationsAbsent=all(s["retireOperation"] not in prefault["operations"] for s in intent["slots"]))
    p.verify_full_ledger(ledger, files)
    remaining(); queue.validate()
    inventory()
    if not natural:
        p.require(start.poll() is None and all(harness._kernel_process(v.pid) == v for v in census), "same live owners at exit publication")
    exit_suffix = ".checkpoint-worker-exit" if checkpoint_exit else ".storage-worker-exit"
    queue.publish(arm["requestID"] + exit_suffix + ".json", request)
    claimed = wait_artifact(exit_suffix + ".claimed.json")
    p.require(p.canonical(claimed) == p.canonical(request), "immutable exact exit claim")
    waited = (checkpoint_wait if checkpoint_exit else worker_wait)(wait_artifact(".checkpoint-worker-wait.json" if checkpoint_exit else ".storage-worker-wait.json"), arm, checkpoint, boot)
    surviving_hosts(census, processes(), workloads, api, storage, harness._kernel_process)
    p.require(lifecycle.read_owner(daemon.root, recovery.read_public) == (before, owner_hash), "same public storage boot through actual Wait")
    record("checkpoint-PID1-reaped" if checkpoint_exit else "worker-PID1-reaped", wait=waited, apiSurvived=True, storageShimSurvived=True)
    # Join before independent replacement. RawManagedStorageBackend's explicit
    # worker-exit-selected gate awaits the real serviceLost callback; the cleared
    # EngineRuntime lifecycle token fixes HTTP 409 before any dead-worker rollback.
    join_failed_start()
    replacement, raw = recovery.worker_request(str(uuid.uuid4()), old["store"],
        {k: old[k] for k in ("serviceEpoch", "workerUUID")})
    with recovery.replacement_queue(daemon.root, old["root"]) as (replacement_queue, validate):
        submitted = int(time.time())
        record("worker-replacement-intent", request=replacement, submittedUnixSeconds=submitted)
        p.verify_full_ledger(ledger, files); validate(); remaining()
        marker = recovery.publish_worker_request(replacement_queue, raw)
        seen = {}
        def receipt(name, maximum=1048576):
            entry = recovery.queue_file(replacement_queue, name, maximum)
            if name in seen: p.require(seen[name] == entry, "immutable replacement artifact")
            seen[name] = entry
            return entry
        stem = replacement["operationUUID"]
        while True:
            remaining(); validate()
            try: recovery.queue_file(replacement_queue, stem + ".failed.json")
            except FileNotFoundError: pass
            else: p.require(False, "production worker replacement failed")
            try:
                claimed, stamp = receipt(stem + ".request.json", 512)
                p.require(claimed == raw and stamp[:2] == marker, "same replacement operation ownership")
                pending = p.decode(receipt(stem + ".pending.json")[0], 1048576)
                succeeded = p.decode(receipt(stem + ".succeeded.json")[0], 1048576)
                break
            except FileNotFoundError: time.sleep(0.025)
        observed = int(time.time())
        recovery.settled_worker_artifacts(replacement_queue, stem, seen)
        for process in workloads: wait_exit(process)
        survivors = surviving_hosts(census, processes(), workloads, api, storage, harness._kernel_process, contained=True)
        after, after_hash = lifecycle.read_owner(daemon.root, recovery.read_public)
        _, state, hashes = read_state()
        fresh = lifecycle.replacement_proof(before, after, pending, succeeded, replacement, state, hashes,
            owned_containers, submitted, observed, prepare_recovery=arm,
            active_ack_containers=active_ack.ids if active_ack is not None else None)
        _, newboot = lifecycle.owner(after)
        if checkpoint_exit and arm["caseName"] == "drain-durable-reply-lost":
            drain = recovered_worker_cut(prefault, state, arm, newboot, checkpoint)
        else:
            drain = recovered_worker_drain(prefault, state, arm, newboot, worker_interrupted=checkpoint_exit)
        p.require(storage_target(daemon, fresh, processes()) == storage, "same storage shim/VM/PID1 boot/backing")
        context = dict(store=fresh["store"], serviceEpoch=fresh["serviceEpoch"],
            controllerEpoch=fresh["controllerEpoch"], controllerKey=public_boot(newboot)["controllerKey"])
        record("worker-replacement-drained", request=replacement, ownerRequest=succeeded["ownerRequest"],
            pending=pending, succeeded=succeeded, ownerSHA256=after_hash, context=context, drain=drain,
            historySHA256=p.digest(p.canonical(lifecycle.history(after))), journal=hashes,
            artifacts={name: entry[1][-1] for name, entry in seen.items()},
            containedNative=[p.native_proof(v) for v in workloads], survivingNative=[p.native_proof(v) for v in survivors])
        def final_check():
            with recovery.replacement_queue(daemon.root, old["root"]) as (final_queue, revalidate):
                recovery.settled_worker_artifacts(final_queue, stem, seen); revalidate()
            p.require(lifecycle.read_owner(daemon.root, recovery.read_public) == (after, after_hash), "immutable final worker owner/history")
            current = processes()
            p.require({v.pid: v for v in current} == {v.pid: v for v in survivors}
                and all(harness._kernel_process(v.pid) == v for v in survivors), "exact surviving native census after all cleanup")
            p.require(storage_target(daemon, fresh, current) == storage, "same API/storage after retry and cleanup")
        return context, final_check, tuple(survivors)
