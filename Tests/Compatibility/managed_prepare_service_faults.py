"""RTM097 initial API-only A7 recovery proof; no engine access on import.

Public records corroborate production ROOT takeover; they never grant authority.
The actual retained Daemon is the sole API process owner. No guest/storage signal.
"""
from contextlib import closing
from pathlib import Path
import os
import re
import select
import signal
import time

import managed_prepare_faults as p
import managed_prepare_lifecycle_evidence as lifecycle
from managed_storage_recovery import owner_proof, read_public, wire, exact_exit, unchanged_processes, runtime_root_path


def owner_context(record):
    if lifecycle.is_v2(record): return lifecycle.owner_context(record)
    owner = owner_proof(record)
    reply = record["transitions"][-1]["confirmed"] if record["transitions"] else record["initialReply"]
    decoded, _ = wire(reply, "confirmTakeover" if record["transitions"] else "registerInitialController")
    controller = decoded["body"]["controller"]
    return owner, dict(store=owner["store"], serviceEpoch=owner["serviceEpoch"],
        controllerEpoch=controller["epoch"], controllerKey=controller["key"])


def api_owner_transition(before, after, arm):
    if lifecycle.is_v2(before) or lifecycle.is_v2(after):
        return lifecycle.transition(before, after, arm, storage=False)
    old, context = owner_context(before)
    new, fresh = owner_context(after)
    p.require(all(context[k] == arm["scope"][k] for k in context), "old API actual installed context")
    for key in ("store", "backing", "bytes", "root", "ext4UUID", "rootKeyHash", "shimLaunchUUID", "guestBootNonce", "serviceEpoch", "bootRevision", "serviceTransitions", "serviceAfter"):
        p.require(old[key] == new[key], "API-only storage identity unchanged")
    p.require(before["boot"] == after["boot"] and before.get("workerReplacements") == after.get("workerReplacements")
        and before.get("serviceTransitions") == after.get("serviceTransitions"), "no hidden service/worker replacement")
    p.require(new["controllerEpoch"] == old["controllerEpoch"] + 1 and new["revision"] > old["revision"]
        and fresh["controllerKey"] != context["controllerKey"], "one real fresh controller takeover")
    p.require(new["transitions"][:-1] == old["transitions"] and len(new["transitions"]) == len(old["transitions"]) + 1,
        "immutable ROOT issue/confirm history plus one")
    return fresh


def api_target(daemon, observed):
    p.native_proof(observed)
    process = daemon.process
    args = observed.arguments
    p.require(process is not None and process.pid == observed.pid and process.poll() is None, "actual unreaped Daemon child")
    p.require(Path(observed.executable).resolve() == daemon.binary.resolve() and len(args) == 16
        and args[:6] == (str(daemon.binary), "daemon", "--root", str(daemon.root), "--socket", str(daemon.socket))
        and args[6:12] == ("--kernel", str(daemon.kernel), "--container-initramfs", str(daemon.container_initramfs), "--storage-initramfs", str(daemon.storage_initramfs))
        and args[12] == "--automatic-ipv4-pool" and args[14] == "--automatic-ipv6-prefix", "exact retained API launch")
    return observed


def storage_target(daemon, owner, census):
    p.require(lifecycle.is_v2(owner), "lifecycle-v2 storage owner required")
    return lifecycle.storage_target(daemon, owner, census, read_public)


def verify_api_owner_final(daemon, retained):
    """The observed C+1 owner/history must survive the whole retry and cleanup."""
    expected, expected_hash = retained
    current, current_hash = lifecycle.read_owner(daemon.root, read_public)
    owner_context(current)  # Still complete: no pending ROOT/service transition.
    p.require(current == expected and current_hash == expected_hash, "exact post-takeover owner/history unchanged")
    return current_hash


def sdk_versions():
    """Bounded observational versions, never admission or recovery authority."""
    import docker
    import requests
    versions = {}
    for name, module in (("docker", docker), ("requests", requests)):
        value = getattr(module, "__version__", None)
        p.require(type(value) is str and 1 <= len(value) <= 64
            and re.fullmatch(r"[0-9]+\.[0-9]+[A-Za-z0-9.+-]*", value) is not None, "bounded loaded SDK version")
        versions[name] = value
    return versions


def restart_api_at_a7(daemon, workload, census, intent, arm, checkpoint, ledger, files, record, processes, remaining):
    import harness
    p.require(arm["profile"] == p.FULL_PROFILE and arm["caseName"] == "first-child-published", "physical A7 only")
    p.full_observation(checkpoint, arm)
    p.require(intent["phase"] == "prepareAdmitted" and intent["prepareCompleted"] is False
        and all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()), "actual still-pending PREPARE")
    p.require(all(s.get("key") is None and s.get("receipt") is None for s in intent["slots"] if s["role"] == "runtime"), "no runtime issued")
    old_record, old_hash = lifecycle.read_owner(daemon.root, read_public)
    owner, context = owner_context(old_record)
    p.require(all(context[k] == arm["scope"][k] for k in context), "live owner matches installed scope")
    storage = storage_target(daemon, owner, census)
    api = api_target(daemon, harness._kernel_process(daemon.process.pid))
    p.require(len({api.pid, storage.pid, workload.pid}) == 3 and api in census and workload in census, "three independent incarnations")
    p.require({v.pid: v for v in processes()} == {v.pid: v for v in census}, "unchanged complete census at injection")
    with p.Directory(daemon.work) as work, p.Directory(daemon.root, private=False) as root:
        marker, _ = work.read(".cengine-compat-owner", 4096)
        p.require(Path(marker.decode().strip()).resolve() == daemon.binary.resolve(), "retained root owner")
        p.require(p.Directory.stamp(os.fstat(root.fd))[:2] == (owner["root"]["device"], owner["root"]["inode"]), "same physical root")
        record("api-SIGKILL-intent", api=p.native_proof(api), workload=p.native_proof(workload), storage=p.native_proof(storage), ownerSHA256=old_hash, armDigest=checkpoint["armDigest"], sdkVersions=sdk_versions())
        p.verify_full_ledger(ledger, files); work.validate(); root.validate(); remaining()
        p.require(harness._kernel_process(api.pid) == api and harness._kernel_process(workload.pid) == workload
            and harness._kernel_process(storage.pid) == storage, "all live immediately before API-only death")
        with closing(select.kqueue()) as waiter:
            waiter.control([select.kevent(workload.pid, filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
            p.require(harness._kernel_process(workload.pid) == workload, "same workload after exit watcher registration")
            daemon.stop(kill=True)  # Actual Popen child; wait pins its PID until reaped.
            p.require(daemon.process.returncode == -signal.SIGKILL and exact_exit(api, harness._kernel_process(api.pid)), "actual API SIGKILL and native exit")
            unchanged_processes(census, processes(), api)
            record("api-only-death-joined", api=p.native_proof(api), workloadSurvived=True, storageSurvived=True)
            fresh_api = None
            def observe_spawn():
                nonlocal fresh_api
                p.require(fresh_api is None, "one production API spawn")
                remaining()
                # Reject an exit already queued BEFORE inspecting the new birth.
                p.require(not waiter.control(None, 1, 0), "workload exited before replacement API birth observation")
                fresh_api = api_target(daemon, harness._kernel_process(daemon.process.pid))
                p.require(fresh_api != api and exact_exit(api, harness._kernel_process(api.pid)), "fresh API incarnation")
                # This positive same-incarnation liveness check follows the new
                # birth lookup. A late/missed observation fails, never assumes order.
                p.require(harness._kernel_process(workload.pid) == workload
                    and harness._kernel_process(storage.pid) == storage, "held workload and storage live after replacement API birth")
                p.require(not waiter.control(None, 1, 0), "workload exit preceded completed API birth observation")
                record("api-replacement-born", api=p.native_proof(fresh_api), workload=p.native_proof(workload))
            remaining(); daemon.start(on_spawn=observe_spawn)
            p.require(fresh_api is not None and api_target(daemon, harness._kernel_process(daemon.process.pid)) == fresh_api, "same observed API became ready")
            events = waiter.control(None, 1, remaining())
            p.require(len(events) == 1 and events[0].ident == workload.pid
                and events[0].filter == select.KQ_FILTER_PROC and not events[0].flags & select.KQ_EV_ERROR
                and events[0].fflags & select.KQ_NOTE_EXIT, "native workload exit after production API birth")
        remaining(); work.validate(); root.validate()
    new_record, new_hash = lifecycle.read_owner(daemon.root, read_public)
    fresh = api_owner_transition(old_record, new_record, arm)
    while not exact_exit(workload, harness._kernel_process(workload.pid)):
        remaining(); time.sleep(0.025)
    expected = [fresh_api if v == api else v for v in census]
    unchanged_processes(expected, processes(), workload)
    p.require(harness._kernel_process(storage.pid) == storage, "same storage VM after reconciliation")
    record("api-reconciled", api=p.native_proof(fresh_api), oldWorkloadExited=True, storage=p.native_proof(storage),
        ownerSHA256=new_hash, context=fresh)
    return expected, fresh, (new_record, new_hash)
