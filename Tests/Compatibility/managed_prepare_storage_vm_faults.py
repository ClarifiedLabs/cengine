"""RTM099 initial ACTIVE PREPARE A7 storage-VM death, then explicit API recovery.

No engine access on import. Public histories corroborate, never authorize, the
real ROOT takeover and same-backing reopen. Quarantine alone is not recovery.
"""
from contextlib import closing, nullcontext
import copy
import base64
from pathlib import Path
import os
import select
import signal
import time
import uuid

import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as lifecycle
from managed_prepare_service_faults import owner_context, api_target, storage_target, sdk_versions
from managed_storage_recovery import read_public, recovered_owner, exact_exit, unchanged_processes, signal_storage, file_identity


def current_boot(record):
    # Tagged comparison projection; deliberately not a legacy Boot DTO.
    if lifecycle.is_v2(record): return dict(format=lifecycle.VERSION, evidence=record)
    return record["serviceTransitions"][-1]["boot"] if record.get("serviceTransitions") else record["boot"]


def public_boot(boot):
    """Closed public Boot DTO or explicit v2 comparison, never authority."""
    if lifecycle.is_v2(boot):
        p.exact(boot, {"format", "evidence"})
        return lifecycle.public_service(boot["evidence"])
    p.exact(boot, {"binding", "ready", "diskIdentity", "initramfsSHA256"})
    p.pin(boot["initramfsSHA256"])
    p.exact(boot["binding"], {"shimLaunchUUID", "guestBootNonce", "ext4UUID", "bytes"})
    for key in ("shimLaunchUUID", "guestBootNonce"): p.uid(boot["binding"][key])
    filesystem = boot["binding"]["ext4UUID"]
    p.require(type(filesystem) is str and str(uuid.UUID(filesystem)) == filesystem
        and uuid.UUID(filesystem).int != 0, "nonzero canonical ext4 UUID, any UUID version")
    p.integer(boot["binding"]["bytes"], 2**63 - 1, 1)
    # Foundation UUID emits uppercase and filesystem UUIDs need not be v4.
    # Keep the existing physical-file contract and exact identity comparisons.
    file_identity(boot["diskIdentity"])
    ready = boot["ready"]
    p.exact(ready, {"storeUUID", "serviceEpoch", "workerUUID", "controllerEpoch", "controllerKey", "revision",
        "bootstrapKey", "tlsRootDER", "serverDER", "serverKey"})
    for key in ("storeUUID", "serviceEpoch", "workerUUID"): p.uid(ready[key])
    for key in ("controllerEpoch", "revision"): p.integer(ready[key], minimum=1)
    for key in ("controllerKey", "bootstrapKey", "serverKey"): p.pin(ready[key])
    for key in ("tlsRootDER", "serverDER"): bounded_base64(ready[key], 16384)
    return ready


def bounded_base64(value, maximum):
    p.require(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3), "bounded public encoded bytes")
    raw = base64.b64decode(value, validate=True)
    p.require(0 < len(raw) <= maximum and base64.b64encode(raw).decode() == value, "canonical public encoded bytes")
    return raw


def undrained_prepare(state, intent, arm, *, interrupted=False, checkpoint=None):
    """The real pre-fault ledger must contain no prior drain for this A/P.

    interrupted=True admits exactly the checkpoint-exit route's observed
    pre-death envelope: A8's adopted durable drain replay (receipt equal to the
    checkpoint's drain receipt) and/or the cut's own containment or durable
    publication journaling its exact planned Retire (A1/A3/A6). Nothing else.
    """
    p.require(state["store"] == arm["scope"]["store"] and state["intents"][arm["scope"]["intent"]] == intent,
        "exact pre-fault host intent")
    p.integer(state["revision"], minimum=1)
    p.require(type(state["operations"]) is dict and type(state["operationDigests"]) is dict, "host operation ledger")
    # The held A4/A5 route demands the actual ACTIVE PREPARE. The generic
    # checkpoint-exit route interrupts all seven cuts with the owned worker's
    # exit 74 and may first observe each cut's actual pre-death shape (below).
    shapes = {("prepareAdmitted", False)}
    if interrupted:
        p.require(arm["caseName"] in p.CHECKPOINT_EXIT_CASES, "checkpoint exit cut only")
        if arm["caseName"] in p.NATURAL_FAILURE_CASES:
            shapes.add(("quarantined", False))
        if arm["caseName"] == "drain-durable-reply-lost":
            # A8 can race the production replay, completion, and runtime freeze.
            shapes.update({("prepareSucceeded", False), ("prepareDrained", False),
                ("prepareCompleted", True), ("runtimeFrozen", True),
                ("quarantined", False), ("quarantined", True)})
    p.require(type(intent["prepareCompleted"]) is bool and (intent["phase"], intent["prepareCompleted"]) in shapes
        and all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "actual ACTIVE PREPARE")
    completion = intent.get("guestCompletion")
    if interrupted and arm["caseName"] == "drain-durable-reply-lost":
        if completion is not None:
            p.exact(completion, {"prepare", "containerInstance", "launch", "succeeded", "cleanCopyUp", "evidenceDigest"})
            p.require(all(completion[k] == intent[k] for k in ("prepare", "containerInstance", "launch"))
                and completion["succeeded"] is True and completion["cleanCopyUp"] is True, "exact guest completion")
            p.pin(completion["evidenceDigest"])
        if intent["prepareCompleted"] or intent.get("cleanUnmount"):
            p.require(completion is not None, "guest completion before durable completion")
    elif interrupted:
        p.require(completion is None and intent.get("cleanUnmount") is False, "no premature guest completion")
    rows = [{k: s[k] for k in ("volume", "attachment", "role", "mode")} for s in intent["slots"]]
    p.require(sorted(rows, key=lambda s: s["attachment"]) == arm["slots"], "complete pre-fault slot tuple")
    durable = drain_operation = None
    if interrupted and type(checkpoint) is dict and type(checkpoint.get("drain")) is dict:
        durable = {k: v for k, v in checkpoint["drain"]["receipt"].items() if k != "schema"}
        drain_operation = p.uid(checkpoint["drain"]["retireOperation"])
    operations = []
    for slot in intent["slots"]:
        operation = p.uid(slot["retireOperation"]); operations.append(operation)
        receipt = slot.get("receipt")
        replay = durable is not None and slot["attachment"] == checkpoint["targetAttachment"]
        if replay:
            # A8's durable drain may already be adopted: the only admitted
            # pre-fault receipt is the exact pre-death same-operation replay.
            p.require(operation == drain_operation and (receipt is None or receipt == durable),
                "no pre-fault receipt or Retire operation")
        elif interrupted and arm["caseName"] in p.NATURAL_FAILURE_CASES and slot["role"] == "prepare" and receipt is not None:
            # Natural failure containment may receive its Retire reply before
            # the parent kills the worker; it is still the same planned drain.
            expected = dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"],
                prepare=intent["prepare"], launch=intent["launch"])
            p.exact(receipt, {*expected, "revision"})
            p.require(all(receipt[k] == v for k, v in expected.items()) and operation in state["operations"],
                "exact natural-cut planned drain receipt")
            p.integer(receipt["revision"], minimum=1)
        else:
            p.require(receipt is None, "no pre-fault receipt or Retire operation")
        if operation in state["operations"] or operation in state["operationDigests"]:
            # A1/A3/A6's own containment (and A6's durable publication) may
            # already journal the exact planned Retire. Only the interrupted
            # route admits it, and only as the exact planned request plus digest.
            p.require(interrupted and operation in state["operations"] and operation in state["operationDigests"],
                "no pre-fault receipt or Retire operation")
            raw = bounded_base64(state["operations"][operation], 65536)
            expected = dict(id=0, retire=dict(operation=operation, store=intent["store"],
                volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"]))
            p.require(raw == p.canonical(expected) and state["operationDigests"][operation] == p.digest(raw),
                "exact pre-fault planned Retire request")
        if slot["role"] == "prepare":
            p.require(slot.get("key") == next(c["key"] for c in arm["credentials"] if c["attachment"] == slot["attachment"]), "actual installed PREPARE key")
        elif interrupted and arm["caseName"] == "drain-durable-reply-lost" and intent["prepareCompleted"]:
            if slot.get("key") is not None: p.pin(slot["key"])
        else:
            p.require(slot.get("key") is None, "no runtime issued")
    p.require(len(set(operations)) == len(operations), "distinct planned Retire operations")


def recovered_prepare_drain(before, after, arm, owner_record):
    """New receipts follow the reopened authority revision, not merely new E."""
    previous = before["intents"][arm["scope"]["intent"]]
    undrained_prepare(before, previous, arm)
    current = p.failed_full_prepare(after["intents"][previous["id"]], arm)
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
        # ControlRequest.durableBytes has id=0; the child assigns TLS sequence later.
        p.require(raw == p.canonical(expected) and after["operationDigests"][operation] == p.digest(raw), "exact persisted production Retire request")
        receipt = slot["receipt"]
        p.integer(receipt["revision"], minimum=boot_revision + 1)
        receipts.append(dict(operation=operation, requestSHA256=p.digest(raw), receipt=receipt))
    return dict(bootRevision=boot_revision, hostRevision=after["revision"], drains=receipts)


def storage_owner_transition(before, after, arm):
    if lifecycle.is_v2(before) or lifecycle.is_v2(after):
        return lifecycle.transition(before, after, arm, storage=True)
    old, context = owner_context(before)
    new, fresh = owner_context(after)
    p.require(all(context[k] == arm["scope"][k] for k in context), "old installed storage context")
    recovered_owner(old, new)
    p.require(before["boot"] == after["boot"] and before.get("workerReplacements") == after.get("workerReplacements"), "immutable initial boot/worker history")
    p.require(after["transitions"][:-1] == before["transitions"]
        and (after.get("serviceTransitions") or [])[:-1] == (before.get("serviceTransitions") or []), "exact ROOT/service history prefixes")
    event = after["serviceTransitions"][-1]
    p.exact(event, {"afterControllerTransitions", "boot"})
    p.integer(event["afterControllerTransitions"], minimum=1)
    p.require(event["afterControllerTransitions"] == len(after["transitions"]), "service boot committed with exact ROOT takeover")
    old_boot, boot = current_boot(before), event["boot"]
    previous, ready = public_boot(old_boot), public_boot(boot)
    p.require(boot["diskIdentity"] == old_boot["diskIdentity"] == after["backing"]
        and boot["initramfsSHA256"] == old_boot["initramfsSHA256"]
        and ready["bootstrapKey"] == previous["bootstrapKey"], "same backing/assets/bootstrap identity")
    root_key = bounded_base64(after["rootPublicKey"], 32)
    p.require(len(root_key) == 32 and ready["bootstrapKey"] == p.digest(bytes.fromhex("302a300506032b6570032100") + root_key), "actual Ed25519 ROOT fingerprint")
    # connect() stores pendingService.boot BEFORE C+1 takeover/reconciliation.
    p.require(ready["controllerEpoch"] == context["controllerEpoch"] and ready["controllerKey"] == context["controllerKey"], "reopened boot uses previous installed controller")
    p.require(all(ready[k] != previous[k] for k in ("workerUUID", "tlsRootDER", "serverDER", "serverKey"))
        and fresh["controllerKey"] != context["controllerKey"], "fresh worker/TLS and takeover controller")
    return fresh


def unchanged_owner_at_signal(old_record, old_hash, current_record, current_hash):
    current_owner, current_context = owner_context(current_record)
    if lifecycle.is_v2(old_record) or lifecycle.is_v2(current_record):
        p.require(lifecycle.is_v2(old_record) and lifecycle.is_v2(current_record), "same owner evidence format at signal")
        # Closed v2 checkpoints intentionally publish null cold fields. The hash
        # pins both exact source files; do not feed them to the legacy canonicalizer.
        unchanged = current_record == old_record
    else:
        unchanged = p.canonical(current_record) == p.canonical(old_record)
    p.require(current_hash == old_hash and unchanged, "unchanged current VM owner at signal")
    return current_owner, current_context


def restart_storage_at_vm_cut(daemon, workload, census, intent, arm, checkpoint, ledger, files, record, processes, remaining, start, read_state, storage_initramfs_sha256, *, active_ack=None, peer_owner=None, held_reader=None, source_witness=None):
    """Closed staged VM cuts, sharing A7's actual ownership and recovery flow."""
    import managed_prepare_vm_boundaries as vm
    vm.selection(arm["profile"], vm.CASES, arm["caseName"])
    from managed_prepare_vm_exits import VMExposedOwnerExits
    exposed = (workload,) if active_ack is None else (workload, *active_ack.processes)
    with VMExposedOwnerExits(exposed, processes, remaining, record) as exits:
        return restart_storage_at_a7(daemon, workload, census, intent, arm, checkpoint, ledger, files, record,
            processes, remaining, start, read_state, storage_initramfs_sha256, vm_cut=True,
            active_ack=active_ack, peer_owner=peer_owner, held_reader=held_reader,
            source_witness=source_witness, owner_exits=exits)


def restart_storage_at_two_volume_drain(daemon, workload, census, intent, arm, checkpoint, ledger, files, record, processes, remaining, start, read_state, storage_initramfs_sha256, *, held_reader, worker, physical, peer_owner):
    """Successful completed-set cut: old durable receipts, never A7 failed drain."""
    import managed_prepare_two_volume_drain as two
    two.selection(arm["profile"], two.CASES, arm["caseName"])
    two.physical_observation(physical, arm)
    from managed_prepare_vm_exits import VMExposedOwnerExits
    # Only the held owner is exposed; the stopped peer remains protected.
    with VMExposedOwnerExits((workload,), processes, remaining, record) as exits:
        return restart_storage_at_a7(daemon, workload, census, intent, arm, checkpoint, ledger, files, record,
            processes, remaining, start, read_state, storage_initramfs_sha256,
            two_volume=(held_reader, worker, physical), peer_owner=peer_owner, owner_exits=exits)


def restart_storage_at_a7(daemon, workload, census, intent, arm, checkpoint, ledger, files, record, processes, remaining, start, read_state, storage_initramfs_sha256, *, vm_cut=False, two_volume=None, active_ack=None, peer_owner=None, held_reader=None, source_witness=None, owner_exits=None):
    p.require((vm_cut or two_volume is not None) == (owner_exits is not None) and (active_ack is None or vm_cut),
        "VM cuts require their continuous native exit monitor")
    if owner_exits is not None:
        exposed = (workload,) if active_ack is None else (workload, *active_ack.processes)
        p.require(owner_exits.owners == exposed, "exact selected exposed owner set")
    p.require(source_witness is None or (vm_cut and two_volume is None and arm["caseName"] == "vm-cleaning-transaction-removed"),
              "source witness restricted to CLEANING VM cut")
    if two_volume is not None:
        import managed_prepare_two_volume_drain as two
        two.selection(arm["profile"], two.CASES, arm["caseName"])
        held_reader, worker, physical = two_volume
        two.physical_observation(physical, arm)
    elif vm_cut:
        import managed_prepare_vm_boundaries as vm
        vm.selection(arm["profile"], vm.CASES, arm["caseName"])
    else:
        p.require(arm["profile"] == p.FULL_PROFILE and arm["caseName"] == "first-child-published", "physical A7 only")
        p.full_observation(checkpoint, arm)
    import harness
    workloads = (workload,)
    def validate_two_volume_peer():
        if two_volume is None: return
        p.require(active_ack is None and peer_owner is not None, "exclusive two-volume peer ownership")
        peer, peer_proof, validate_peer = peer_owner
        p.require(peer != workload and peer in census and peer_proof["container"] != intent["container"]
            and peer_proof["phase"] == "retired" and peer_proof["prepareCompleted"] is True,
            "exact distinct stopped retired peer before storage death")
        validate_peer()
        p.require(harness._kernel_process(peer.pid) == peer, "exact live stopped peer incarnation")
    if two_volume is not None:
        validate_two_volume_peer()
        workloads = (workload, peer_owner[0])
    def validate_ack():
        if active_ack is None: return
        from managed_prepare_active_ack import four_owner_inventory, unexposed_vm_peer
        p.require(vm_cut and two_volume is None and arm["caseName"] == "vm-private-bound",
            "active ACK is restricted to the private BOUND VM cut")
        peer, peer_proof, validate_peer = peer_owner
        unexposed_vm_peer(prefault_state, peer_proof)
        active_ack.validate(arm)
        four_owner_inventory(daemon, [intent["container"], peer_proof["container"], *active_ack.ids],
            census, workload, peer, peer_proof, validate_peer, active_ack)
        held = held_reader()
        vm.storage_status(held, arm, worker, phase="observed", checkpoint=checkpoint)
    if active_ack is not None:
        p.require(peer_owner is not None and callable(held_reader), "independent held observer and prepared peer required")
        workloads = (workload, peer_owner[0], *active_ack.processes)
    p.require(intent["phase"] == ("prepareSucceeded" if two_volume is not None else "prepareAdmitted") and intent["prepareCompleted"] is False
        and all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "actual ACTIVE PREPARE before VM death")
    p.require(all(s.get("key") is None and s.get("receipt") is None for s in intent["slots"] if s["role"] == "runtime"), "no runtime issued")
    old_record, old_hash = lifecycle.read_owner(daemon.root, read_public)
    owner, context = owner_context(old_record)
    p.require(all(context[k] == arm["scope"][k] for k in context), "actual installed context")
    if two_volume is not None:
        p.require(public_boot(current_boot(old_record))["workerUUID"] == worker, "exact held observer worker")
        filesystem = physical["filesystemUUID"]
    elif vm_cut:
        import managed_prepare_vm_boundaries as vm
        worker = public_boot(current_boot(old_record))["workerUUID"]
        validator = dict(zip(vm.CASES, (vm.private_observation, vm.root_observation, vm.cleaning_observation)))[arm["caseName"]]
        if arm["caseName"] == vm.CASES[1]: validator(checkpoint, arm)
        else: validator(checkpoint, arm, worker)
        if arm["caseName"] == vm.CASES[2]:
            vm.cleaning_source_observation(source_witness, arm, checkpoint, worker)
        filesystem = checkpoint["filesystemUUID"] if arm["caseName"] == vm.CASES[1] else checkpoint["bound"]["intent"]["root"]["backing_uuid"]
    else:
        filesystem = checkpoint["filesystemUUID"]
    p.require(filesystem == owner["ext4UUID"].replace("-", ""), "physical witness on exact storage filesystem")
    public_boot(current_boot(old_record))
    p.pin(storage_initramfs_sha256)
    p.require((lifecycle.asset_digest(daemon.storage_initramfs) if lifecycle.is_v2(old_record) else current_boot(old_record)["initramfsSHA256"]) == storage_initramfs_sha256, "actual pinned storage initramfs")
    _, prefault_state, prefault_hashes = read_state()
    if two_volume is not None:
        held = held_reader()
        p.require(two.prefault_evidence(prefault_state, held, arm, checkpoint, worker) == intent, "exact successful pre-fault intent")
        record("two-volume-host-gap-external-fsync", state=prefault_state, held=held, checkpoint=checkpoint,
            physical=physical, ownerSHA256=old_hash, journal=prefault_hashes)
    else:
        undrained_prepare(prefault_state, intent, arm)
    validate_ack()
    validate_two_volume_peer()
    storage = storage_target(daemon, owner, census)
    api = api_target(daemon, harness._kernel_process(daemon.process.pid))
    p.require(len({api.pid, storage.pid, workload.pid}) == 3 and api in census and workload in census, "three independent incarnations")
    p.require({v.pid: v for v in processes()} == {v.pid: v for v in census}, "complete unchanged injection census")
    with p.Directory(daemon.work) as work, p.Directory(daemon.root, private=False) as root:
        marker, _ = work.read(".cengine-compat-owner", 4096)
        p.require(Path(marker.decode().strip()).resolve() == daemon.binary.resolve(), "retained root owner")
        p.require(p.Directory.stamp(os.fstat(root.fd))[:2] == (owner["root"]["device"], owner["root"]["inode"]), "same physical root")
        record("storage-SIGKILL-intent", storage=p.native_proof(storage), api=p.native_proof(api), workload=p.native_proof(workload),
            ownerSHA256=old_hash, armDigest=checkpoint["armDigest"], sdkVersions=sdk_versions(), journal=prefault_hashes,
            prepareReceiptsAbsent=two_volume is None, retireOperationsAbsent=two_volume is None)
        p.verify_full_ledger(ledger, files); work.validate(); root.validate(); remaining()
        with closing(select.kqueue()) as storage_waiter:
            storage_waiter.control([select.kevent(storage.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
            p.require(harness._kernel_process(api.pid) == api and harness._kernel_process(workload.pid) == workload
                and harness._kernel_process(storage.pid) == storage and start.poll() is None, "all independent owners live before storage-only death")
            _, final_state, final_hashes = read_state()
            if two_volume is not None:
                final_held = held_reader()
                two.prefault_evidence(final_state, final_held, arm, checkpoint, worker)
                p.require(p.canonical(final_held) == p.canonical(held), "independent held witness unchanged at signal")
            else:
                undrained_prepare(final_state, intent, arm)
            p.require(final_state == prefault_state and final_hashes == prefault_hashes, "pre-fault ledger unchanged at signal")
            if vm_cut or two_volume is not None:
                current_record, current_hash = lifecycle.read_owner(daemon.root, read_public)
                current_owner, current_context = unchanged_owner_at_signal(old_record, old_hash, current_record, current_hash)
                p.require(current_context == context and storage_target(daemon, current_owner, processes()) == storage,
                    "exact current storage target at signal")
            validate_ack()
            validate_two_volume_peer()
            if two_volume is not None:
                record("storage-two-volume-owners-before-kill", native=[p.native_proof(v) for v in workloads])
            # Last exposed-owner observation occurs inside the strict audited
            # adapter, after its independent storage birth/argv revalidation.
            delivery = (signal_storage(storage) if owner_exits is None else
                signal_storage(storage, before_signal=owner_exits.before_signal))
            if owner_exits is not None: owner_exits.delivered()
            record("storage-SIGKILL-delivered", proof=delivery)
            events = storage_waiter.control(None, 1, remaining())
            p.require(len(events) == 1 and events[0].ident == storage.pid
                and events[0].filter == select.KQ_FILTER_PROC and not events[0].flags & select.KQ_EV_ERROR
                and events[0].fflags & select.KQ_NOTE_EXIT, "actual selected storage exit event")
        while not exact_exit(storage, harness._kernel_process(storage.pid)):
            remaining(); time.sleep(0.025)
        survivors = [v for v in census if v != storage]
        if owner_exits is None:
            unchanged_processes(census, processes(), storage)
            p.require(harness._kernel_process(api.pid) == api and harness._kernel_process(workload.pid) == workload
                and start.poll() is None, "API and held workload survived independently through storage exit")
        else:
            # Production may eagerly contain exposed owners as soon as storage
            # disappears. Only pre-watched native exits may change this census.
            owner_exits.observe(survivors, "storage-exit-joined")
        record("storage-only-death-joined", storage=p.native_proof(storage), apiSurvived=True,
            workloadSurvived=harness._kernel_process(workload.pid) == workload)
        # Restart is an explicit SECOND recovery step, never mislabeled API-only.
        with (closing(select.kqueue()) if owner_exits is None else nullcontext()) as waiter:
            if owner_exits is None:
                waiter.control([select.kevent(workload.pid, filter=select.KQ_FILTER_PROC,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
            record("api-recovery-SIGKILL-intent", api=p.native_proof(api))
            p.verify_full_ledger(ledger, files); work.validate(); root.validate(); remaining()
            p.require(harness._kernel_process(api.pid) == api and exact_exit(storage, harness._kernel_process(storage.pid)),
                "same isolated storage-death boundary before API recovery")
            if owner_exits is None:
                p.require(harness._kernel_process(workload.pid) == workload and start.poll() is None,
                    "held workload survives until API recovery")
            else:
                owner_exits.observe(survivors, "before-api-kill")
            if two_volume is not None:
                validate_two_volume_peer()
            daemon.stop(kill=True)
            p.require(daemon.process.returncode == -signal.SIGKILL and exact_exit(api, harness._kernel_process(api.pid)), "actual recovery API SIGKILL and join")
            if owner_exits is None:
                if two_volume is None:
                    unchanged_processes(survivors, processes(), api)
                else:
                    from managed_prepare_restart_matrix import _api_exit_survivors
                    survivors = _api_exit_survivors(daemon, api, survivors, processes(), record)
                    peer_owner[2].api_joined_refresh(api, survivors)
                    refreshed = {v.pid: v for v in survivors}
                    census = [refreshed.get(v.pid, v) for v in census]
                    workload = refreshed[workload.pid]
                    workloads = (workload, peer_owner[0])
            else:
                survivors = owner_exits.api_joined_refresh(daemon, api, survivors)
                if active_ack is not None or two_volume is not None:
                    peer_owner[2].api_joined_refresh(api, survivors)
                refreshed = {v.pid: v for v in survivors}
                census = [refreshed.get(v.pid, v) for v in census]
            if two_volume is not None:
                # Old API rollback may commit after storage death. Only this
                # post-exit snapshot is a quiescent recovery version baseline.
                _, prerecovery_state, prerecovery_hashes = read_state()
                # Retain the exact stopped producer state even if validation
                # fails; never reconstruct a failed prefix from a later journal.
                record("two-volume-api-exited-journal-external-fsync", state=prerecovery_state,
                    journal=prerecovery_hashes, api=p.native_proof(api))
                two.prerecovery_receipts(prefault_state, prerecovery_state, arm, checkpoint, worker,
                    lifecycle_v2=lifecycle.is_v2(old_record))
            fresh_api = None
            def observe_spawn():
                nonlocal fresh_api
                p.require(fresh_api is None, "one recovery API birth")
                if owner_exits is None:
                    p.require(not waiter.control(None, 1, 0), "workload live before recovery API birth")
                remaining()
                if two_volume is not None:
                    peer = peer_owner[0]
                    p.require(harness._kernel_process(peer.pid) == peer, "stopped peer live at recovery API birth")
                fresh_api = api_target(daemon, harness._kernel_process(daemon.process.pid))
                p.require(fresh_api != api and exact_exit(api, harness._kernel_process(api.pid)), "fresh API birth after old API exit")
                if owner_exits is None:
                    p.require(harness._kernel_process(workload.pid) == workload, "fresh API birth while old workload still owned")
                    p.require(not waiter.control(None, 1, 0), "workload exit follows observed API birth")
                else:
                    owner_exits.observe([fresh_api if v == api else v for v in survivors], "api-birth")
                record("storage-recovery-api-born", api=p.native_proof(fresh_api))
            remaining(); daemon.start(on_spawn=observe_spawn)
            p.require(fresh_api is not None and api_target(daemon, harness._kernel_process(daemon.process.pid)) == fresh_api, "same fresh API became ready")
            if owner_exits is None:
                events = waiter.control(None, 1, remaining())
                p.require(len(events) == 1 and events[0].ident == workload.pid
                    and events[0].filter == select.KQ_FILTER_PROC and not events[0].flags & select.KQ_EV_ERROR
                    and events[0].fflags & select.KQ_NOTE_EXIT, "production contains old workload after recovery API birth")
        remaining(); work.validate(); root.validate()
    new_record, new_hash = lifecycle.read_owner(daemon.root, read_public)
    fresh = storage_owner_transition(old_record, new_record, arm)
    _, recovered_state, recovered_hashes = read_state()
    if two_volume is not None:
        drain = two.recovered_receipts(prefault_state, prerecovery_state, recovered_state, arm, checkpoint, worker, new_record)
        record("storage-identical-old-completed-set", proof=drain, journal=recovered_hashes)
    else:
        drain = recovered_prepare_drain(prefault_state, recovered_state, arm, new_record)
        record("storage-new-epoch-drain", proof=drain, journal=recovered_hashes)
    if owner_exits is None:
        while not exact_exit(workload, harness._kernel_process(workload.pid)):
            remaining(); time.sleep(0.025)
    new_owner, _ = owner_context(new_record)
    fresh_storage = storage_target(daemon, new_owner, processes())
    p.require(fresh_storage != storage and exact_exit(storage, harness._kernel_process(storage.pid)), "old storage exited, distinct current storage incarnation")
    expected = [fresh_api if v == api else fresh_storage if v == storage else v for v in census]
    if two_volume is not None:
        # RawManagedStorageBackend.reconcileExecutions contains terminal peers
        # too; terminal storage receipts are not native process-exit evidence.
        peer = peer_owner[0]
        while not exact_exit(peer, harness._kernel_process(peer.pid)):
            remaining(); time.sleep(0.025)
        expected = [v for v in expected if v != peer]
        survivors = owner_exits.join_all(expected, "recovery-ready")
        unchanged_processes(expected, survivors, workload)
        record("storage-two-volume-owners-contained", native=[p.native_proof(v) for v in workloads])
    elif active_ack is None:
        if owner_exits is not None:
            survivors = owner_exits.join_all(expected, "recovery-ready")
            unchanged_processes(expected, survivors, workload)
            record("storage-exposed-owners-contained", native=[p.native_proof(workload)])
        else:
            unchanged_processes(expected, processes(), workload)
    else:
        from managed_prepare_active_ack import unexposed_vm_peer
        # The fourth owner is an unchanged, never-started legacy prepared shim,
        # not an old managed-storage consumer. API recovery preserves it; every
        # storage-exposed owner still requires positive native exit, not receipts.
        contained = (workload, *active_ack.processes)
        expected = owner_exits.join_all(expected, "recovery-ready")
        peer_owner[2]()
        _, contained_state, _ = read_state()
        unexposed_vm_peer(contained_state, peer_owner[1])
        p.require({v.pid: v for v in processes()} == {v.pid: v for v in expected}
            and all(harness._kernel_process(v.pid) == v for v in expected), "exact exposed-owner containment and unstarted peer survival")
        record("storage-exposed-owners-contained", native=[p.native_proof(v) for v in contained], preservedPeer=peer_owner[1])
    record("storage-reopened-reconciled", api=p.native_proof(fresh_api), storage=p.native_proof(fresh_storage),
        context=fresh, ownerSHA256=new_hash, oldWorkloadExited=True)
    return expected, fresh, (new_record, new_hash)


def complete_tree_owner(previous, current, context):
    """Public receipts corroborate a fresh unarmed owner, never grant authority."""
    p.require(current["phase"] == "running" and current["prepareCompleted"] is True, "completed fresh PREPARE")
    p.require(all(current[k] == previous[k] for k in ("store", "container", "containerInstance", "specificationDigest")), "same complete-tree container")
    p.require(all(current[k] == context[k] for k in ("store", "serviceEpoch", "controllerEpoch", "controllerKey")), "exact reopened context")
    p.require(all(current[k] != previous[k] for k in ("id", "launch", "prepare")), "fresh complete-tree owner")
    old, new = previous["slots"], current["slots"]
    p.require(len(new) == 2 and {s["role"] for s in new} == {"prepare", "runtime"}, "complete fresh slot pair")
    p.require({s["attachment"] for s in new}.isdisjoint(s["attachment"] for s in old), "fresh complete-tree attachments")
    p.require({s["volume"] for s in new} == {s["volume"] for s in old}
        and all(s["mode"] == "read-write" for s in new), "same volume and modes")
    for slot in new:
        p.uid(slot["attachment"]); p.pin(slot["key"])
        p.require(slot["key"] not in {s.get("key") for s in old}, "fresh installed key")
    return current


def complete_tree_snapshot(value, baseline, checkpoint, arm, *, source_witness=None):
    """Read-only existing a/z tree; no NORMAL checkpoint or source restoration."""
    import managed_prepare_vm_boundaries as vm
    p.require(arm["caseName"] in vm.CASES[1:], "complete-tree cuts only")
    expected = copy.deepcopy(baseline)
    if arm["caseName"] == vm.CASES[1]:
        p.require(source_witness is None, "root cut uses its own physical checkpoint")
        vm.root_observation(checkpoint, arm)
        expected["root"]["atimeNS"] = checkpoint["sourceAtimes"]["root"]
        for name in p.FILES:
            expected["files"][name]["atimeNS"] = checkpoint["sourceAtimes"][name]
    else:
        vm.cleaning_source_observation(source_witness, arm, checkpoint, checkpoint["workerUUID"])
        for name in p.FILES:
            expected["files"][name]["atimeNS"] = source_witness["sourceAtimes"][name]
        cleanup = checkpoint["bound"]["intent"]["cleanup"]
        expected["root"].update(uid=cleanup["uid"], gid=cleanup["gid"], mode=16384 | cleanup["mode"],
            atimeNS=int(cleanup["atime_seconds"]) * 10**9 + cleanup["atime_nanos"],
            mtimeNS=int(cleanup["mtime_seconds"]) * 10**9 + cleanup["mtime_nanos"])
    p.snapshot(expected)
    return p.snapshot(value, baseline=expected)
