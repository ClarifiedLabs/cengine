"""RTM096: one full aggregate registration, plus an explicitly invoked 2/9 shard.

Parent owns signed assets, helper compilation, isolated Daemon setup/retention,
180-second worker supervision and final daemon/storage teardown. Import and call
run_staged_shard with that *actual* Daemon; no fixture fabricates a Session or VM.
The registered full test never treats a staged receipt as full acceptance.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import ctypes
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import time
import uuid

import pytest
import managed_prepare_faults as proof
from managed_storage_recovery import exact_exit, unchanged_processes, read_public


# Authenticated PREPARE/channel failures map to conflict; externally killed shims
# lose the host transport and map to internal error. This is not an either/or oracle.
NATURAL_FAILURE_CASES = ("before-prepare-send", "data-partial-frame", "transaction-published-bind-reply-lost")


@pytest.fixture(autouse=True)
def verify_docker_cli_target():
    # Full aggregate refusal must not boot the ordinary conftest daemon.
    pass


@pytest.fixture(autouse=True)
def daemon_survived():
    # The separate staged caller owns its actual Daemon and finalizers.
    pass


@pytest.mark.compat("RTM-096")
def test_managed_prepare_ambiguity_full_acceptance():
    pytest.fail("RTM-096 incomplete: NORMAL+A7 is a separate 2/9 shard; A1-A6/A8 required", pytrace=False)


@pytest.mark.compat("RTM-097")
def test_managed_prepare_api_restart_recovery():
    pytest.fail("RTM-097 requires parent-owned API crash campaign; initial A7 is not the full host matrix", pytrace=False)


@pytest.mark.compat("RTM-098")
def test_managed_prepare_worker_restart_recovery():
    pytest.fail("RTM-098 requires parent-owned storage worker crash campaign; initial A5 is not the full worker matrix", pytrace=False)


@pytest.mark.compat("RTM-099")
def test_managed_prepare_storage_vm_recovery():
    pytest.fail("RTM-099 requires parent-owned storage VM crash campaign; initial A7 is not the full VM matrix", pytrace=False)


@pytest.mark.compat("RTM-100")
def test_managed_prepare_io_failures():
    pytest.fail("RTM-100 requires parent-owned signed 46-case IO campaign; ordinary pytest cannot supply native acceptance", pytrace=False)


@contextmanager
def bounded_parent(deadline):
    proof.require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "parent timer already owned")
    old = signal.getsignal(signal.SIGALRM)
    def expired(*_): raise TimeoutError("RTM096 parent budget")
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
    try: yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def create_shared_consumers(client, image, volume, plan, *, original_consumer_case=None, extra_volume=None, two_volume=False):
    # Storage mode is selected at first start. Two references must already exist;
    # merely enabling the managed daemon leaves a single consumer block-backed.
    peer_plan = {**plan, "container": plan["container"] + "-peer"}
    from managed_root_backing import ROOT_CASES
    proof.require((extra_volume is not None) == (two_volume or original_consumer_case in ("wrong-volume", *ROOT_CASES)), "exact selected two-volume fixture")
    containers = []
    for selected in (plan, peer_plan):
        mounts = {volume.name: {"bind": "/data", "mode": "ro" if selected is plan and original_consumer_case == "wrong-mode" else "rw"}}
        if extra_volume is not None: mounts[extra_volume.name] = {"bind": "/other", "mode": "rw"}
        if two_volume and selected is peer_plan:
            # The fixed pinned probe reads /data: reverse the peer mapping so
            # both physical volumes are independently observed without a new helper.
            mounts = {extra_volume.name: {"bind": "/data", "mode": "rw"}, volume.name: {"bind": "/other", "mode": "rw"}}
        container = client.containers.create(image.id, name=selected["container"],
            network_mode="none", read_only=True, mem_limit="128m", pids_limit=32,
            volumes=mounts,
            labels={proof.OWNER: plan["owner"]})
        containers.append(proof.owned(container, "container", selected))
    # The peer remains unstarted throughout NORMAL, interruption and retry.
    return containers[0], containers[1], peer_plan


def run_staged_shard(daemon, *, profile, cases, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """Closed parent-only selection; return NOT full RTM096 acceptance.

    `probe` is the parent's pinned offline linux/arm64 build of the adjacent new
    Go helper. `source_sha256` is the exact approved compatibility guest source
    inventory pin in disk-bootstrap.json. `evidence` is a fresh private directory
    outside daemon.work, created/retained by the parent before this call.
    """
    staged = proof.selection(profile, cases)  # Fail before engine I/O.
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="first-child-published", early=False,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit, evidence=evidence)


def run_early_shard(daemon, *, profile, cases, fault_case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """Select all four v2 cases, execute NORMAL plus ONE fault on a fresh root.

    Invoke separately for A1, A2 and A3 with independently supervised actual
    Daemons/evidence directories. No loop expands the existing 180-second budget;
    this invocation's receipt is only 2/9, not a four-case or full-ID PASS.
    """
    staged = proof.early_selection(profile, cases, fault_case)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=fault_case, early=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit, evidence=evidence)


def run_full_shard(daemon, *, profile, cases, fault_case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One exact v3 case per fresh Daemon; nine receipts required to aggregate.

    NORMAL and A8 use successful PREPARE/Retire; other faults require failed
    start, full drain and a fresh observed NORMAL replacement on this same image.
    """
    staged = proof.full_selection(profile, cases, fault_case)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=fault_case, early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit, evidence=evidence)


def run_io_shard(daemon, *, profile, cases, fault_case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One exact returned-error cut; sticky containment is never liveness proof."""
    import managed_prepare_io_faults as io_proof
    staged = io_proof.require_deployed_case(profile, cases, fault_case)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=fault_case, early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, io_case=io_proof.case_definition(fault_case))


def run_api_a7_shard(daemon, *, profile, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """RTM097 initial API-only A7 cut, not the complete host crash matrix."""
    proof.require(profile == proof.FULL_PROFILE, "exact signed full profile required")
    staged = dict(rtm="RTM-097", boundary="api-only-first-child-published", fullAcceptance=False)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="first-child-published", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, api_restart=True)


def run_storage_a7_shard(daemon, *, profile, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """RTM099 initial ACTIVE PREPARE storage-VM cut plus explicit API recovery."""
    proof.require(profile == proof.FULL_PROFILE, "exact signed full profile required")
    staged = dict(rtm="RTM-099", boundary="storage-vm-first-child-published", fullAcceptance=False)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="first-child-published", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, storage_restart=True)


def run_storage_private_shard(daemon, *, profile, cases, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """Staged RTM099 vm-private-bound; native acceptance NOT RUN."""
    import managed_prepare_vm_boundaries as vm_proof
    staged = dict(vm_proof.selection(profile, cases, "vm-private-bound"), rtm="RTM-099", boundary="vm-private-bound")
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="vm-private-bound", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, storage_restart=True, vm_cut="vm-private-bound")


def run_storage_private_active_ack_shard(daemon, *, profile, probe, probe_sha256, ack_probe, ack_probe_sha256,
                                         source_sha256, expected_commit, evidence):
    """One parent-only RTM099 private BOUND/active ACK pairing; no matrix expansion."""
    proof.require(profile == proof.FULL_PROFILE, "exact signed full profile required")
    proof.pin(ack_probe_sha256)
    return _run_prepare_case(daemon, profile=profile,
        staged=dict(rtm="RTM-099", boundary="vm-private-bound-active-ack", fullAcceptance=False),
        fault_case="vm-private-bound", vm_cut="vm-private-bound", storage_restart=True, early=True, full=True,
        active_ack_probe=(ack_probe, ack_probe_sha256), probe=probe, probe_sha256=probe_sha256,
        source_sha256=source_sha256, expected_commit=expected_commit, evidence=evidence)


def run_storage_root_shard(daemon, *, profile, cases, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """Staged RTM099 vm-root-synced-before-cleanup; native acceptance NOT RUN."""
    import managed_prepare_vm_boundaries as vm_proof
    staged = dict(vm_proof.selection(profile, cases, "vm-root-synced-before-cleanup"), rtm="RTM-099", boundary="vm-root-synced-before-cleanup")
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="vm-root-synced-before-cleanup", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, storage_restart=True, vm_cut="vm-root-synced-before-cleanup")


def run_storage_cleaning_shard(daemon, *, profile, cases, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """Staged RTM099 vm-cleaning-transaction-removed; native acceptance NOT RUN."""
    import managed_prepare_vm_boundaries as vm_proof
    staged = dict(vm_proof.selection(profile, cases, "vm-cleaning-transaction-removed"), rtm="RTM-099", boundary="vm-cleaning-transaction-removed")
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="vm-cleaning-transaction-removed", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, storage_restart=True, vm_cut="vm-cleaning-transaction-removed")


def run_two_volume_drain_shard(daemon, *, profile, cases, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One executable two-volume completed-set cut; never native/full acceptance."""
    import managed_prepare_two_volume_drain as drain
    staged = dict(drain.selection(profile, cases, drain.CASE), runnable=True, rtm="RTM-099", boundary=drain.CASE)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=drain.CASE, early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, storage_restart=True, two_volume=True)


def run_restart_matrix_shard(daemon, *, rtm, profile, cases, fault_case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One RTM-097 (API) or RTM-099 (storage VM) restart-matrix cell per fresh Daemon.

    Nine retained live MatrixOutcome objects from nine fresh Daemons aggregate
    through managed_prepare_restart_matrix.aggregate_matrix; a receipt alone
    never does. The accepted A7/A5 initial cuts keep their own entries above.
    """
    import managed_prepare_restart_matrix as matrix_proof
    staged = matrix_proof.selection(rtm, profile, cases, fault_case)  # Fail before engine I/O.
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=fault_case, early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, api_restart=staged["restart"] == "api", storage_restart=staged["restart"] == "storage", matrix=staged)


def run_worker_a5_shard(daemon, *, profile, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """RTM098 initial admitted A5 worker-only cut; never full acceptance."""
    proof.require(profile == proof.FULL_PROFILE, "exact signed full profile required")
    staged = dict(rtm="RTM-098", boundary="worker-admitted-queued", fullAcceptance=False)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="admitted-queued", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, worker_restart=True)


def run_worker_admission_shard(daemon, *, profile, fault_case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One observed held A4/A5 worker exit on the strict StorageRelease route."""
    proof.require(profile == proof.FULL_PROFILE and fault_case in proof.WORKER_EXIT_CASES,
        "exact signed held admission cut required")
    staged = dict(rtm="RTM-098", caseName=fault_case, boundary="worker-" + fault_case, fullAcceptance=False)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=fault_case, early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, worker_restart=True)


def run_checkpoint_exit_shard(daemon, *, profile, fault_case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One observed generic checkpoint-exit cut (NORMAL/A1-A3/A7/A6/A8).

    Not the complete nine-cut matrix and never an aggregate: A4/A5 stay on the
    distinct strict StorageRelease worker-exit route.
    """
    proof.require(profile == proof.FULL_PROFILE and fault_case in proof.CHECKPOINT_EXIT_CASES,
        "exact signed checkpoint exit cut required")
    staged = dict(rtm="RTM-098", caseName=fault_case, boundary="checkpoint-" + fault_case, fullAcceptance=False)
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case=fault_case, early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, worker_restart=True, checkpoint_exit=True)


def run_worker_a5_active_ack_shard(daemon, *, profile, probe, probe_sha256, ack_probe, ack_probe_sha256,
                                    source_sha256, expected_commit, evidence):
    """Dedicated parent-only RTM098 addon; ordinary pytest still refuses."""
    proof.require(profile == proof.FULL_PROFILE, "exact signed full profile required")
    proof.pin(ack_probe_sha256)
    return _run_prepare_case(daemon, profile=profile,
        staged=dict(rtm="RTM-098", boundary="worker-a5-active-ack", fullAcceptance=False),
        fault_case="admitted-queued", early=True, full=True, worker_restart=True,
        active_ack_probe=(ack_probe, ack_probe_sha256), probe=probe, probe_sha256=probe_sha256,
        source_sha256=source_sha256, expected_commit=expected_commit, evidence=evidence)


def run_original_consumer_shard(daemon, *, profile, cases, case, probe, probe_sha256, source_sha256, expected_commit, evidence):
    """One actual originally mounted consumer case; never full RTM103 acceptance."""
    from managed_stale_consumer import selection
    staged = selection(profile, cases, case)  # Unsupported cases fail before engine IO.
    return _run_prepare_case(daemon, profile=profile, staged=staged, fault_case="normal", early=True, full=True,
        probe=probe, probe_sha256=probe_sha256, source_sha256=source_sha256, expected_commit=expected_commit,
        evidence=evidence, original_consumer_case=case)


def run_takeover_original_followup(daemon, *, profile, cases, container, reader, plan, reader_plan, remaining, record):
    """Source-ready live entry; NOT deployed/native RTM103 acceptance.

    Parent supplies two owned, never-started full-image containers and its
    existing outer campaign deadline. The 165s PREPARE runner cannot contain
    two existing 195s stop/start bounds; neither bound is changed here.
    """
    from managed_takeover_original import followup_selection, run_original_restarts
    selected = followup_selection(profile, cases, "replayed-takeover")
    record("rtm103-source-selected", selection=selected)
    return run_original_restarts(daemon, container=container, reader=reader, plan=plan,
        reader_plan=reader_plan, remaining=remaining, record=record)


def run_service_isolation_followup(daemon, *, profile, cases, case, container, reader, plan, reader_plan, remaining, record):
    """Source-ready current C2+ route; native acceptance is a separate gate."""
    from managed_takeover_original import followup_selection, run_service_isolation
    selected = followup_selection(profile, cases, case)
    proof.require(selected["executionRoute"] == "service-isolation", "exact isolation route")
    record("rtm103-source-selected", selection=selected)
    return run_service_isolation(daemon, case=case, container=container, reader=reader, plan=plan,
        reader_plan=reader_plan, remaining=remaining, record=record)


def _run_prepare_case(daemon, *, profile, staged, fault_case, early, probe, probe_sha256, source_sha256, expected_commit, evidence, full=False, api_restart=False, storage_restart=False, worker_restart=False, io_case=None, original_consumer_case=None, vm_cut=None, two_volume=False, active_ack_probe=None, matrix=None, checkpoint_exit=False):
    """Shared actual lifecycle; no injected transports, owners or success replies."""
    import docker
    import harness
    from volume_probe import close_exec_stream
    import managed_prepare_io_faults as io_proof
    import managed_prepare_vm_boundaries as vm_proof

    proof.require(vm_cut is None or (vm_cut in vm_proof.CASES and vm_cut == fault_case and storage_restart
        and not api_restart and not worker_restart and full and early and io_case is None and original_consumer_case is None), "closed VM parent selection")
    proof.require(io_case is None or (full and early and not api_restart and not storage_restart and not worker_restart
        and io_case == io_proof.case_definition(fault_case)), "closed IO campaign selection")

    import managed_prepare_two_volume_parent as two
    proof.require(not two_volume or (full and early and storage_restart and not api_restart and not worker_restart
        and vm_cut is None and io_case is None and original_consumer_case is None and fault_case == two.drain.CASE), "closed two-volume parent selection")
    pending_owner = None
    pending_intent = None
    controller_recovery = None
    service_recovery = None
    recovered_owner = None
    worker_recovery = None
    worker_final = None
    worker_survivors = None
    active_ack = None
    matrix_variant = None
    matrix_workload_exited = True
    proof.require(active_ack_probe is None or (not two_volume and ((worker_restart and fault_case == "admitted-queued") or vm_cut == "vm-private-bound")),
        "active ACK only with actual A5 worker exit or private BOUND VM death")
    from managed_stale_consumer import IMPLEMENTED_CASES
    proof.require(original_consumer_case is None or (not api_restart and not storage_restart and not worker_restart
        and full and early and fault_case == "normal" and original_consumer_case in IMPLEMENTED_CASES), "closed original runtime observation")
    proof.require(checkpoint_exit == (worker_restart and fault_case in proof.CHECKPOINT_EXIT_CASES), "checkpoint exit route matches the worker cut")
    proof.require(not worker_restart or (not api_restart and not storage_restart and full and early
        and fault_case in proof.WORKER_EXIT_CASES + proof.CHECKPOINT_EXIT_CASES), "closed worker recovery cut")
    import managed_prepare_restart_matrix as matrix_proof
    proof.require(matrix is None or (full and early and (api_restart != storage_restart) and not worker_restart and vm_cut is None
        and io_case is None and original_consumer_case is None and not two_volume and active_ack_probe is None
        and matrix == matrix_proof.selection(matrix["rtm"], profile, proof.FULL_CASES, fault_case)
        and (matrix["restart"] == "api") == api_restart), "closed restart matrix selection")
    proof.require(not storage_restart or (not api_restart and full and early and (two_volume or matrix is not None or (fault_case == "first-child-published" if vm_cut is None else fault_case == vm_cut))), "closed storage VM recovery cut")
    proof.require(not api_restart or (full and early and (matrix is not None or fault_case == "first-child-published")), "closed API recovery cut")
    proof.pin(probe_sha256); proof.pin(source_sha256)
    proof.require(harness.compatibility_root_retained(daemon.work), "signed managed retained parent fixture required")
    deadline = time.monotonic() + 165
    plan = proof.names(uuid.uuid4().hex)
    evidence = Path(evidence)
    proof.require(evidence.resolve() != daemon.work.resolve() and daemon.work.resolve() not in evidence.resolve().parents, "external evidence directory required")
    if early:
        proof.early_evidence_location(evidence, daemon.work, daemon.root)
    starts = []
    client = None
    peer = None
    sequence = 0
    evidence_chain = []
    evidence_files = {}
    with bounded_parent(deadline + 8), proof.Directory(evidence) as ledger:
        if early:
            proof.early_empty_evidence(ledger)
        def record(phase, **value):
            nonlocal sequence
            sequence += 1
            proof.require(sequence <= 60, "evidence count bound")
            event = {"phase": phase, **value}
            name = "%03d-%s.json" % (sequence, phase)
            ledger.publish(name, event)
            if full:
                published = ledger.read(name, pin_file=True)
                proof.require(published[0] == proof.canonical(event), "external fsynced evidence bytes")
                evidence_files[name] = published
            evidence_chain.append(proof.digest(proof.canonical(event)))
        def complete_io_result(receipt):
            # This registrar exists only inside the actual lifecycle. There is no
            # public receipt/JSON-to-live-outcome constructor in the proof module.
            proof.require(io_case is not None and client is not None and len(starts) >= 3
                          and all(process.poll() is not None for process in starts), "joined live IO lifecycle required")
            proof.verify_full_ledger(ledger, evidence_files)
            retained = proof.Directory(ledger.path)
            try:
                proof.require(proof.Directory.stamp(os.fstat(retained.fd)) == proof.Directory.stamp(os.fstat(ledger.fd)), "same retained IO ledger")
                pinned = {name: retained.read(name, pin_file=True) for name in evidence_files}
                proof.require(pinned == evidence_files, "retained IO evidence unchanged")
                io_proof.validate_case_evidence([proof.decode(pinned[name][0]) for name in sorted(pinned)], receipt)
                result = object.__new__(io_proof.IOOutcome)
                result._receipt, result._directory, result._files = receipt.copy(), retained, pinned
                io_proof._LIVE_OUTCOMES[id(result)] = result
                return result
            except BaseException:
                retained.close()
                raise
        def remaining():
            proof.require(time.monotonic() < deadline, "campaign deadline")
            return max(0.001, deadline - time.monotonic())
        def ack_budget(census=None, *, reserve=0, memory_reserve=0):
            from managed_prepare_active_ack import resource_budget
            from managed_prepare_worker_faults import prepared_peer_owner
            if census is None:
                census = harness.compatibility_runtime_processes(daemon.binary, roots=(daemon.root, Path("/")))
            idle = ()
            # A created, never-booted prepared shim is a process, not an allocated VM.
            # Keep it in the process count; exempt memory only under positive ownership.
            root = None
            if peer is not None:
                from managed_storage_recovery import runtime_root_path
                root = runtime_root_path(daemon.root) / "containers" / peer.id
            if root is not None and any(len(v.arguments) >= 4 and root in Path(v.arguments[3]).parents
                    for v in census if v.arguments[1:3] == ("vm-shim", "--spec")):
                current_manifest, _, _ = read_state()
                # Native/canonical ownership remains inspectable while the API is dead.
                with prepared_peer_owner(daemon, peer, peer_plan, current_manifest["root"], census) as owned_peer:
                    owned_peer[2]()
                    idle = (owned_peer[0],)
                    resource_budget(census, starts, reserve=reserve, memory_reserve=memory_reserve, idle=idle)
            else:
                resource_budget(census, starts, reserve=reserve, memory_reserve=memory_reserve)
        def processes():
            census = harness.compatibility_runtime_processes(daemon.binary, roots=(daemon.root, Path("/")))
            if two_volume: two.resource_budget(census, starts)
            if active_ack_probe is not None: ack_budget(census)
            return census
        def wait_exit(process):
            while not exact_exit(process, harness._kernel_process(process.pid)):
                remaining(); time.sleep(0.025)
        def read_state():
            with proof.Directory(daemon.root / "managed-storage", private=False) as journal:
                manifest_raw, _ = journal.read("manifest.json", 1024 * 1024)
                state_raw, _ = journal.read("state.json", 1024 * 1024)
                manifest = proof.decode(manifest_raw, 1024 * 1024, canonical_only=False)
                state = proof.decode(state_raw, 1024 * 1024, canonical_only=False)
                hashes = dict(manifest_sha256=proof.digest(manifest_raw), state_sha256=proof.digest(state_raw))
            proof.require(manifest.get("schema") == 1 and manifest.get("mode") == "managed" and state.get("schema") == 2 and state["store"] == manifest["store"], "same managed journal store")
            return manifest, state, hashes
        def only_intent(state, phase):
            selected = [i for i in state["intents"].values() if i["container"] == container.id and i["phase"] == phase]
            proof.require(len(selected) == 1, "exact phase intent")
            return selected[0]
        def target(intent):
            candidates = [p for p in processes() if len(p.arguments) == 6 and p.arguments[1:3] == ("vm-shim", "--spec") and p.arguments[4] == "--launch-intent" and Path(p.arguments[3]).parent.name.endswith("-" + intent["launch"])]
            proof.require(len(candidates) == 1, "one live exact workload")
            return candidates[0]
        def observe(command, selected=None):
            selected = container if selected is None else selected
            remaining()
            exec_id = client.api.exec_create(selected.id, ["/probe", "worker-verify" if command == "worker-verify-written" else command], stdout=True, stderr=True)["Id"]
            stream = client.api.exec_start(exec_id, socket=True)
            sock = getattr(stream, "_sock", stream)
            raw = bytearray()
            try:
                while True:
                    sock.settimeout(min(5, remaining()))
                    chunk = sock.recv(min(65536, 131073 - len(raw)))
                    if not chunk: break
                    raw.extend(chunk); proof.require(len(raw) <= 131072, "bounded exec output")
            finally: close_exec_stream(stream)
            output, errors, offset = bytearray(), bytearray(), 0
            while offset < len(raw):
                proof.require(len(raw) - offset >= 8, "exec frame header")
                channel, length = struct.unpack(">BxxxI", raw[offset:offset + 8])
                proof.require(raw[offset+1:offset+4] == b"\0\0\0" and channel in (1, 2), "exec channel")
                offset += 8
                proof.require(length <= len(raw) - offset, "exec frame length")
                (output if channel == 1 else errors).extend(raw[offset:offset+length]); offset += length
            status = client.api.exec_inspect(exec_id)
            proof.require(status["Running"] is False and status["ExitCode"] == 0 and not errors, "real runtime exec succeeded")
            value = proof.decode(bytes(output), 131072, canonical_only=False)
            if command.startswith("worker-"):
                from managed_storage_recovery import worker_snapshot_proof
                worker_snapshot_proof(value, command="verify" if command == "worker-verify-written" else command[7:],
                    written=command in ("worker-write", "worker-verify-written"))
            elif command == "root-snapshot":
                from managed_root_backing import snapshot
                snapshot(value)
            elif command in ("retained-snapshot", "retained-write"):
                from managed_retained_backing import retained_snapshot
                retained_snapshot(value, command)
            else:
                proof.snapshot(value, command)
            # Never retain raw mountinfo or arbitrary stderr.
            record("runtime-" + command, container=selected.id, value={k: v for k, v in value.items() if k != "mountinfo"})
            return value
        def start_request(selected=None):
            selected = container if selected is None else selected
            if active_ack_probe is not None: ack_budget(reserve=1)
            from managed_prepare_start_diagnostic import spawn
            process = spawn([sys.executable, "-B", __file__, "--docker-start", str(daemon.socket), selected.id], popen=subprocess.Popen)
            starts.append(process)
            return process
        def joined_start(process, failed=False, *, disconnected=False, worker_failed=False, io_phase="initial-failure", expected_exit=None, vm_recovery=False):
            code = process.wait(timeout=remaining())
            proof.require(type(code) is int and -signal.NSIG < code <= 255, "bounded Docker start exit")
            from managed_prepare_start_diagnostic import receive
            diagnostic = receive(process)
            # The closed wire uses None for absent fields; the evidence ledger
            # permits no JSON null. Omit only absent advisory fields, not guards.
            if type(diagnostic) is dict:
                diagnostic = {key: value for key, value in diagnostic.items() if value is not None}
            record("docker-start-joined", failed=failed, returncode=code, diagnostic=diagnostic)
            # Natural channel failure is HTTP 409; explicit host SIGKILL is 500.
            # The explicit worker-exit-selected gate in RawManagedStorageBackend
            # joins the real serviceLost callback before returning this start failure.
            # EngineRuntime.fenceStorageWork clears its lifecycle token: exact 409,
            # before rollback can attempt cleanup against the dead worker.
            expected = 49 if worker_failed else io_proof.expected_start_exit(io_case, phase=io_phase) if io_case is not None else 52 if disconnected else 49 if early and fault_case in NATURAL_FAILURE_CASES else 50
            if expected_exit is not None: expected = expected_exit  # A restart-matrix cell's joined live variant.
            if vm_recovery:
                from managed_prepare_active_ack import vm_start_failure
                from managed_prepare_vm_boundaries import CASES
                from managed_prepare_two_volume_drain import CASE as TWO_VOLUME_CASE
                proof.require(failed and disconnected and storage_restart
                    and (vm_cut in CASES or (vm_cut is None and full and two_volume and fault_case == TWO_VOLUME_CASE))
                    and expected_exit is None and not worker_failed, "VM cut start outcome only after storage recovery")
                expected = vm_start_failure(code, diagnostic)
            proof.require(code == (expected if failed else 0), "real Docker start response")
        def reattach_one():
            nonlocal client, container, peer, volume, image
            ids = container.id, peer.id, volume.name, image.id
            client.close()
            client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
            proof.require(client.version().get("GitCommit") == expected_commit, "same signed restarted API")
            container = proof.owned(client.containers.get(ids[0]), "container", plan)
            peer = proof.owned(client.containers.get(ids[1]), "container", peer_plan)
            volume = proof.owned(client.volumes.get(ids[2]), "volume", plan)
            image = proof.owned(client.images.get(ids[3]), "image", plan)
        def reattach_two():
            nonlocal client, container, peer, volume, extra_volume, image
            ids = container.id, peer.id, volume.name, extra_volume.name, image.id
            client.close()
            client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
            proof.require(client.version().get("GitCommit") == expected_commit, "same signed restarted API")
            container = proof.owned(client.containers.get(ids[0]), "container", plan)
            peer = proof.owned(client.containers.get(ids[1]), "container", peer_plan)
            volume = proof.owned(client.volumes.get(ids[2]), "volume", plan)
            extra_volume = proof.owned(client.volumes.get(ids[3]), "volume", extra_plan)
            image = proof.owned(client.images.get(ids[4]), "image", plan)
            return client, container, peer, volume, extra_volume, image
        def queue_start(queue, previous, case):
            nonlocal pending_owner, pending_intent
            capture = (two.drain.capture_from_normal(normal, saved, volume_records, str(uuid.uuid4())) if two_volume
                else proof.capture_from_normal(normal, saved, volume_record, str(uuid.uuid4())))
            request = capture["requestID"]
            record("capture-intent", capture=capture, case=case)
            queue.publish("capture.json", capture)
            process = start_request()
            seen = {}
            def artifact(suffix, maximum=65536):
                name = request + suffix
                value = queue.read(name, maximum, pin_file=True) if worker_restart or two_volume or active_ack_probe is not None else queue.read(name, maximum)
                if name in seen: proof.require(seen[name] == value, "immutable carrier artifact changed")
                seen[name] = value
                return proof.decode(value[0], maximum)
            def wait_artifact(suffix, maximum=65536, *, worker_exit=False):
                while True:
                    remaining(); queue.validate()
                    try: return artifact(suffix, maximum)
                    except FileNotFoundError:
                        status = process.poll()
                        if early and (suffix in (".armed.json", ".arm.claimed.json", ".checkpoint.json",
                                                 ".checkpoint-worker-exit.claimed.json", ".checkpoint-worker-wait.json") or suffix.startswith(".storage-")):
                            # Natural A1/A3 teardown (and unheld NORMAL) may beat
                            # publication by the independently retained observer.
                            # Wait boundedly for REAL evidence, never synthesize it.
                            expected = 0 if case in ("normal", "drain-durable-reply-lost") else 49 if worker_exit else io_proof.expected_start_exit(io_case, phase="initial-failure") if io_case is not None else 49 if case in NATURAL_FAILURE_CASES else 50
                            # Retain the finite API reason before rejecting an
                            # unexpected exit; joining never replaces the artifact.
                            if status is not None and status != expected: joined_start(process)
                            proof.require(status in (None, expected), "unexpected settled start before checkpoint")
                        else:
                            # Preserve the finite child diagnostic before rejecting a
                            # settled start with missing carrier evidence. Success
                            # still cannot substitute for the missing artifact.
                            if status is not None: joined_start(process)
                            proof.require(status is None, "start ended before carrier evidence")
                        time.sleep(0.025)
            claimed = wait_artifact(".capture.json")
            proof.require(proof.canonical(claimed) == proof.canonical(capture), "exact durable capture claim")
            candidate = wait_artifact(".candidate.json")
            if two_volume:
                _, candidate_state, _ = read_state()
                arm = two.drain.arm_candidate(candidate, capture, previous, candidate_state["intents"][candidate["scope"]["intent"]])
            elif vm_cut is not None and case == vm_cut:
                arm = vm_proof.arm_candidate(candidate, capture, previous, case)
            elif io_case is not None and case != "normal":
                arm = io_proof.arm_candidate(candidate, capture, previous, case)
            elif worker_recovery is not None:
                arm = proof.full_arm_candidate(candidate, capture, previous, case, worker_recovery=worker_recovery)
            elif controller_recovery is not None:
                arm = proof.full_arm_candidate(candidate, capture, previous, case, controller_recovery=controller_recovery)
            elif service_recovery is not None:
                arm = proof.full_arm_candidate(candidate, capture, previous, case, service_recovery=service_recovery)
            else:
                arm = (proof.full_arm_candidate if full else proof.early_arm_candidate if early else proof.arm_candidate)(candidate, capture, previous, case)
            # Public state corroborates the live candidate; it never grants admission.
            _, live, _ = read_state()
            intent = live["intents"][arm["scope"]["intent"]]
            proof.require(all(intent[k if k != "intent" else "id"] == v for k, v in arm["scope"].items()) and intent["phase"] == "prepareAdmitted", "candidate exact current host intent")
            proof.require(all(s.get("key") is None for s in intent["slots"] if s["role"] == "runtime"), "runtime not yet issued")
            for credential in arm["credentials"]:
                proof.require(any(s["attachment"] == credential["attachment"] and s.get("key") == credential["key"] for s in intent["slots"]), "installed guest key matches frozen host key")
            if early:
                # The candidate rendezvous still owns this live generation.
                # Capture it BEFORE releasing the arm: A1/A3 can naturally exit
                # before the fixture ever sees their immutable checkpoint.
                candidate_process = target(intent)
                with proof.workload_owner(candidate_process, daemon, plan, intent, manifest["root"]) as (native, _, validate):
                    validate()
                    native_before = processes()
                    proof.require(candidate_process in native_before and harness._kernel_process(candidate_process.pid) == candidate_process, "live candidate owner before early arm")
                    record("early-owner-before-arm", native=native)
                    pending_owner = candidate_process, native_before
                    pending_intent = intent
            record("arm-intent", arm=arm)
            queue.publish(request + ".arm.json", arm)
            armed = wait_artifact(".armed.json")
            proof.require(proof.canonical(armed) == proof.canonical(dict(version=3 if full else 2 if early else 1, requestID=request, armDigest=proof.digest(proof.canonical(arm)))), "actual guest arm acknowledgment")
            claimed_arm = wait_artifact(".arm.claimed.json")
            proof.require(proof.canonical(claimed_arm) == proof.canonical(arm), "exact immutable arm claim")
            record("guest-armed", value=armed)
            return process, arm, wait_artifact, artifact, seen
        try:
            record("plan", plan=plan, staged=staged, sourceSHA256=source_sha256, probeSHA256=probe_sha256)
            metadata, metadata_sha = read_public(daemon.kernel.parent / "disk-bootstrap.json", 16384)
            proof.require(metadata.get("prepareCompatibilityProfile") == profile
                and metadata.get("prepareCompatibilitySourceSHA256") == source_sha256
                and all(type(metadata.get(key)) is int and metadata[key] == version for key, version in {
                    "schemaVersion": 1, "protocolVersion": 1, "storageServiceBootVersion": 2,
                    "storageLifecycleVersion": 2, "workloadStorageBootVersion": 1,
                }.items()), "exact explicit compatible asset metadata")
            for path, key in ((daemon.container_initramfs, "containerInitramfsSHA256"), (daemon.storage_initramfs, "storageInitramfsSHA256")):
                # Observation only; runtime independently verifies signed/profile capabilities.
                import hashlib
                h = hashlib.sha256(); count = 0
                with Path(path).open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        count += len(chunk); proof.require(count <= 512 * 1024 * 1024, "asset bound"); h.update(chunk)
                proof.require(h.hexdigest() == metadata[key], "selected asset pin")
            probe_path = Path(probe)
            proof.require(probe_path.lstat().st_size <= 8 * 1024 * 1024 and not probe_path.is_symlink(), "bounded pinned helper file")
            with probe_path.open("rb") as source:
                raw_probe = source.read(8 * 1024 * 1024 + 1)
            proof.require(proof.digest(raw_probe) == probe_sha256, "exact parent-built probe pin")
            from managed_root_backing import ROOT_CASES
            root_case = original_consumer_case in ROOT_CASES
            archive, config = (two.image_archive(raw_probe, plan) if two_volume else
                proof.image_archive(raw_probe, plan, second_mount=original_consumer_case == "wrong-volume" or root_case,
                    root_objects=root_case))
            client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
            proof.require(client.version().get("GitCommit") == expected_commit, "exact signed parent engine commit")
            record("assets", metadataSHA256=metadata_sha, archiveSHA256=proof.digest(archive))
            client.images.load(archive)
            image = proof.owned(client.images.get(plan["image"]), "image", plan)
            proof.require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "full image source pin")
            volume = proof.owned(client.volumes.create(plan["volume"], labels={proof.OWNER: plan["owner"]}), "volume", plan)
            extra_plan = extra_volume = None
            if two_volume or original_consumer_case == "wrong-volume" or root_case:
                extra_plan = {**plan, "volume": plan["volume"] + "-other"}
                extra_volume = proof.owned(client.volumes.create(extra_plan["volume"], labels={proof.OWNER: plan["owner"]}), "volume", extra_plan)
            container, peer, peer_plan = create_shared_consumers(client, image, volume, plan,
                original_consumer_case=original_consumer_case, extra_volume=extra_volume, two_volume=two_volume)
            record("both-created", containers=[container.id, peer.id])
            if early:
                _, fresh_state, _ = read_state()
                if two_volume or original_consumer_case == "wrong-volume" or root_case:
                    proof.require(fresh_state["intents"] == {} and len(fresh_state["volumes"]) == 2
                        and {v["name"] for v in fresh_state["volumes"].values()} == {plan["volume"], extra_plan["volume"]}, "fresh two-volume fixture")
                else: proof.early_fresh_state(fresh_state, plan["volume"])
            joined_start(start_request())  # FIRST start unarmed, same full image a/z.
            manifest, state, hashes = read_state()
            normal = only_intent(state, "running")
            from managed_stale_consumer import fixture_receipts, fixture_mounts, mounted_fixture
            if two_volume:
                two.receipts(manifest, state, plan, extra_plan, container, normal)
            elif original_consumer_case in ("wrong-volume", "wrong-mode") or root_case:
                fixture_receipts(manifest, state, plan, container.id, normal["id"], original_consumer_case, extra_plan)
            else:
                proof.running_receipts(manifest, state, plan, container.id, normal["id"])
            baseline = observe("root-snapshot" if root_case else "snapshot")  # Receipts precede runtime probe.
            volume_record = next(v for v in state["volumes"].values() if v["name"] == plan["volume"])
            if two_volume:
                volume_records = [next(v for v in state["volumes"].values() if v["name"] == name)
                    for name in (plan["volume"], extra_plan["volume"])]
                two.mounts(baseline)
            normal_process = target(normal)
            with proof.workload_owner(normal_process, daemon, plan, normal, manifest["root"]) as (native, saved, validate):
                validate(); record("normal-owned", native=native, journal=hashes)
                if two_volume:
                    two.drain.capture_from_normal(normal, saved, volume_records, str(uuid.uuid4()))
                elif original_consumer_case is None:
                    proof.capture_from_normal(normal, saved, volume_record, str(uuid.uuid4()))
                else:
                    fixture_mounts(saved, normal, state, plan, original_consumer_case, extra_plan)
                    mounted_fixture(baseline, original_consumer_case)
            if original_consumer_case is not None:
                from managed_stale_consumer import run_live
                from managed_original_lifecycle_peer import PeerReader
                # Retain both selected-configuration observations through run_live's
                # native workload proof, fresh positive, and complete cleanup.
                with PeerReader(daemon, processes) as lifecycle_peer_reader:
                    return run_live(daemon, staged=staged, client=client, container=container, peer=peer, peer_plan=peer_plan,
                        image=image, volume=volume, plan=plan, config=config, normal=normal, normal_process=normal_process,
                        saved=saved, baseline=baseline, manifest=manifest, read_state=read_state, observe=observe, target=target,
                        start_request=start_request, joined_start=joined_start, wait_exit=wait_exit, processes=processes,
                        remaining=remaining, ledger=ledger, files=evidence_files, record=record, extra_volume=extra_volume, extra_plan=extra_plan,
                        lifecycle_peer_reader=lifecycle_peer_reader)
            if two_volume:
                return two.run(daemon, staged=staged, client=client, container=container, peer=peer, peer_plan=peer_plan,
                    image=image, volume=volume, extra_volume=extra_volume, plan=plan, extra_plan=extra_plan,
                    config=config, normal=normal, normal_process=normal_process, baseline=baseline,
                    manifest=manifest, volume_records=volume_records, read_state=read_state, observe=observe, target=target,
                    start_request=start_request, joined_start=joined_start, wait_exit=wait_exit, processes=processes,
                    remaining=remaining, ledger=ledger, files=evidence_files, record=record, queue_start=queue_start,
                    pending=lambda: pending_owner, reattach=reattach_two, metadata=metadata)
            observe("empty")  # Actual runtime unlink(a,z), fsync(empty directory).
            container.stop(timeout=1)
            manifest, state, hashes = read_state()
            proof.running_receipts(manifest, state, plan, container.id, normal["id"], stopped=True)
            # stop releases the VM; its host shim can remain until replacement.
            record("normal-stopped-drained", journal=hashes)
            if active_ack_probe is not None:
                from managed_prepare_active_ack import ActiveACK
                active_ack = ActiveACK(daemon, client, *active_ack_probe, read_state=read_state, target=target,
                    observe=observe, start=start_request, join=joined_start, processes=processes, remaining=remaining,
                    record=record, ledger=ledger, files=evidence_files, wait_exit=wait_exit, budget_check=ack_budget)
                active_ack.interrupted = container.id
            with proof.Directory(daemon.root / "managed-prepare-compatibility") as queue:
                start, arm, wait_artifact, artifact, seen = queue_start(queue, {**normal, "intent": normal["id"]}, fault_case)
                wait_exit(normal_process)  # Replacement positively terminates its predecessor.
                worker = None
                storage_checkpoint = None
                source_witness = None
                # The worker route interrupts even NORMAL/A8 first attempts with the
                # owned worker's exit 74, so no worker-restart case is successful here.
                successful_case = full and fault_case in ("normal", "drain-durable-reply-lost") and not worker_restart
                io_storage = io_case is not None and io_case.owner == "storage-authority"
                vm_storage = vm_cut in (vm_proof.CASES[0], vm_proof.CASES[2])
                if vm_storage:
                    storage_armed = wait_artifact(".storage-armed.json")
                    worker = proof.uid(storage_armed["query"]["workerUUID"])
                    vm_proof.storage_status(storage_armed, arm, worker, phase="armed")
                    proof.require(storage_armed["state"] == "armed", "VM storage armed before checkpoint")
                    record("storage-armed", status=storage_armed)
                    validator = vm_proof.private_observation if vm_cut == vm_proof.CASES[0] else vm_proof.cleaning_observation
                    checkpoint = storage_checkpoint = validator(wait_artifact(".storage-checkpoint.json", 8192), arm, worker)
                    if vm_cut == vm_proof.CASES[2]:
                        source_witness = vm_proof.cleaning_source_observation(wait_artifact(".checkpoint.json", 8192), arm, checkpoint, worker)
                        record("cleaning-source-witness-external-fsync", physical=source_witness, checkpoint=checkpoint)
                elif vm_cut == vm_proof.CASES[1]:
                    checkpoint = vm_proof.root_observation(wait_artifact(".checkpoint.json", 8192), arm)
                elif full and (fault_case in proof.STORAGE_CASES or io_storage):
                    storage_armed = wait_artifact(".storage-armed.json")
                    worker = proof.uid(storage_armed["query"]["workerUUID"])
                    if io_storage: io_proof.armed_status(storage_armed, arm, worker)
                    else: proof.storage_status(storage_armed, arm, worker, phase="armed")
                    record("storage-armed", status=storage_armed)
                    storage_checkpoint = (io_proof.observation if io_storage else proof.storage_observation)(wait_artifact(".storage-checkpoint.json", 8192), arm, worker)
                    checkpoint = storage_checkpoint
                elif io_case is not None:
                    checkpoint = io_proof.observation(wait_artifact(".checkpoint.json", 8192), arm)
                else:
                    checkpoint = (proof.full_observation if full else proof.early_observation if early else proof.observation)(wait_artifact(".checkpoint.json", 8192), arm)
                # External file AND parent fsync completes before any fault signal.
                record("checkpoint-external-fsync", checkpoint=checkpoint)
                if not successful_case or matrix is not None:
                    if matrix is None or matrix["kind"] != "successful":
                        container.reload(); proof.require(container.attrs["State"]["Running"] is False, "no premature runtime publication")
                    natural_failure = io_case is not None or (early and fault_case in NATURAL_FAILURE_CASES)
                    if matrix is not None: natural_failure = False  # A1/A3/A6 cells race the restart instead.
                    if checkpoint_exit: natural_failure = False  # all seven checkpoint cuts end in the owned worker's exit 74 route
                    if natural_failure:
                        proof.require(pending_owner is not None, "captured early candidate owner required")
                        process, before = pending_owner
                        # No late target lookup, liveness prerequisite or signal:
                        # production may already have contained this exact owner.
                    elif worker_restart:
                        from managed_prepare_worker_faults import prepared_peer_owner, restart_worker_at_a5
                        proof.require(start.poll() is None and pending_owner is not None, "live held PREPARE before worker exit")
                        process, before = pending_owner
                        _, held_state, _ = read_state()
                        interrupted = held_state["intents"][arm["scope"]["intent"]]
                        with prepared_peer_owner(daemon, peer, peer_plan, manifest["root"], before) as peer_owner:
                            worker_recovery, worker_final, worker_survivors = restart_worker_at_a5(daemon, process, before, interrupted, arm,
                                checkpoint, queue, lambda suffix: wait_artifact(suffix, worker_exit=True), artifact, ledger, evidence_files, record, processes,
                                remaining, start, read_state, wait_exit, lambda: joined_start(start, failed=True, worker_failed=True), metadata["storageInitramfsSHA256"],
                                owned_containers=[container.id, peer.id] + (active_ack.ids if active_ack is not None else []),
                                peer_owner=peer_owner, active_ack=active_ack, checkpoint_exit=checkpoint_exit)
                        if active_ack is not None: active_ack.recover(worker_recovery)
                    elif api_restart and matrix is not None:
                        proof.require(pending_owner is not None, "captured candidate owner required before API death")
                        process, before = pending_owner
                        _, held_state, _ = read_state()
                        interrupted = held_state["intents"][arm["scope"]["intent"]]
                        before, controller_recovery, recovered_owner, matrix_variant, matrix_workload_exited = matrix_proof.restart_api(
                            daemon, process, before, interrupted, arm, checkpoint, ledger, evidence_files, record, processes, remaining,
                            start, read_state, worker=worker)
                        # RTM-097 returns the positively observed post-API-exit lineage.
                        process = next(v for v in before if v.pid == process.pid)
                        pending_owner = process, before
                        joined_start(start, failed=matrix_variant != "settled-success", expected_exit=matrix_proof.START_EXIT[matrix_variant])
                        reattach_one()
                    elif api_restart:
                        from managed_prepare_service_faults import restart_api_at_a7
                        proof.require(start.poll() is None and pending_owner is not None, "live held PREPARE before API death")
                        process, before = pending_owner
                        _, held_state, _ = read_state()
                        interrupted = held_state["intents"][arm["scope"]["intent"]]
                        before, controller_recovery, recovered_owner = restart_api_at_a7(daemon, process, before, interrupted, arm,
                            checkpoint, ledger, evidence_files, record, processes, remaining)
                        # Close the old SDK transport; reattach only the same owned
                        # persisted resources through the new real API process.
                        ids = container.id, peer.id, volume.name, image.id
                        client.close()
                        client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
                        proof.require(client.version().get("GitCommit") == expected_commit, "same signed restarted API")
                        container = proof.owned(client.containers.get(ids[0]), "container", plan)
                        peer = proof.owned(client.containers.get(ids[1]), "container", peer_plan)
                        volume = proof.owned(client.volumes.get(ids[2]), "volume", plan)
                        image = proof.owned(client.images.get(ids[3]), "image", plan)
                    elif storage_restart and matrix is not None:
                        proof.require(pending_owner is not None, "captured candidate owner required before storage VM death")
                        process, before = pending_owner
                        _, held_state, _ = read_state()
                        interrupted = held_state["intents"][arm["scope"]["intent"]]
                        before, service_recovery, recovered_owner, matrix_variant, matrix_workload_exited = matrix_proof.restart_storage(
                            daemon, process, before, interrupted, arm, checkpoint, ledger, evidence_files, record, processes, remaining,
                            start, read_state, metadata["storageInitramfsSHA256"], worker=worker)
                        # RTM-099 also joins API death before refreshing survivor lineage.
                        process = next(v for v in before if v.pid == process.pid)
                        pending_owner = process, before
                        joined_start(start, failed=matrix_variant != "settled-success", expected_exit=matrix_proof.START_EXIT[matrix_variant])
                        reattach_one()
                    elif storage_restart:
                        from managed_prepare_storage_vm_faults import restart_storage_at_a7
                        proof.require(start.poll() is None and pending_owner is not None, "live held PREPARE before storage VM death")
                        process, before = pending_owner
                        _, held_state, _ = read_state()
                        interrupted = held_state["intents"][arm["scope"]["intent"]]
                        if vm_cut is not None:
                            from managed_prepare_storage_vm_faults import restart_storage_at_vm_cut
                            artifact(".storage-checkpoint.json" if vm_storage else ".checkpoint.json", 8192)
                            if source_witness is not None:
                                vm_proof.cleaning_source_observation(artifact(".checkpoint.json", 8192), arm, checkpoint, worker)
                            if vm_storage:
                                # The checkpoint alone does not prove an active hold.
                                # Require the independently observed storage status
                                # before entering any storage-only kill/recovery flow.
                                held = wait_artifact(".storage-held.json")
                                vm_proof.storage_status(held, arm, worker, phase="observed", checkpoint=checkpoint)
                                record("storage-held-external-fsync", status=held)
                                artifact(".storage-held.json")
                            from contextlib import nullcontext
                            from managed_prepare_worker_faults import prepared_peer_owner
                            peer_context = (prepared_peer_owner(daemon, peer, peer_plan, manifest["root"], before)
                                if active_ack is not None else nullcontext(None))
                            with peer_context as peer_owner:
                                before, service_recovery, recovered_owner = restart_storage_at_vm_cut(daemon, process, before, interrupted, arm,
                                    checkpoint, ledger, evidence_files, record, processes, remaining, start, read_state, metadata["storageInitramfsSHA256"],
                                    active_ack=active_ack, peer_owner=peer_owner,
                                    held_reader=(lambda: wait_artifact(".storage-held.json")) if active_ack is not None else None,
                                    source_witness=source_witness)
                            if active_ack is not None:
                                # Shared tail expects the interrupted owner excluded, all other survivors unchanged.
                                before = [*before, process]
                        else:
                            before, service_recovery, recovered_owner = restart_storage_at_a7(daemon, process, before, interrupted, arm,
                                checkpoint, ledger, evidence_files, record, processes, remaining, start, read_state, metadata["storageInitramfsSHA256"])
                        # Close the old SDK transport; reattach only the same owned
                        # persisted resources through the new real API process.
                        ids = container.id, peer.id, volume.name, image.id
                        client.close()
                        client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
                        proof.require(client.version().get("GitCommit") == expected_commit, "same signed restarted API")
                        container = proof.owned(client.containers.get(ids[0]), "container", plan)
                        peer = proof.owned(client.containers.get(ids[1]), "container", peer_plan)
                        volume = proof.owned(client.volumes.get(ids[2]), "volume", plan)
                        image = proof.owned(client.images.get(ids[3]), "image", plan)
                        if active_ack is not None:
                            from managed_prepare_active_ack import revalidate_vm_peer
                            revalidate_vm_peer(daemon, client, peer, peer_plan, manifest["root"], processes(),
                                [v for v in before if v != process], peer_owner[:2],
                                [container.id, peer.id, *active_ack.ids], read_state, record)
                    else:
                        proof.require(start.poll() is None, "PREPARE held, no runtime publication")
                        manifest, state, _ = read_state(); interrupted = state["intents"][arm["scope"]["intent"]]
                        process = target(interrupted); before = processes()
                        if early:
                            proof.require(pending_owner is not None and pending_owner[0] == process and {p.pid: p for p in pending_owner[1]} == {p.pid: p for p in before}, "A2 exact candidate owner/surroundings unchanged")
                        with proof.workload_owner(process, daemon, plan, interrupted, manifest["root"]) as (native, _, validate):
                            proof.require(process in before and harness._kernel_process(process.pid) == process, "live positive workload incarnation")
                            with closing(select.kqueue()) as waiter:
                                waiter.control([select.kevent(process.pid, filter=select.KQ_FILTER_PROC, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
                                record("owned-SIGKILL-intent", native=native, armDigest=checkpoint["armDigest"])
                                validate(); artifact(".storage-checkpoint.json" if worker is not None else ".checkpoint.json", 8192)
                                if full: proof.verify_full_ledger(ledger, evidence_files)
                                proof.require(harness._kernel_process(process.pid) == process, "native ownership at signal")
                                token = (ctypes.c_uint32 * 8)(0, 0, 0, 0, 0, process.pid, 0, process.pidversion)
                                result = ctypes.CDLL(None, use_errno=True).proc_signal_with_audittoken(ctypes.byref(token), signal.SIGKILL)
                                proof.require(result == 0, "positive audited SIGKILL delivery")
                                record("owned-SIGKILL-delivered", native=native, nativeResult=0)
                                events = waiter.control(None, 1, remaining())
                                proof.require(len(events) == 1 and events[0].ident == process.pid and events[0].fflags & select.KQ_NOTE_EXIT, "native workload exit Wait")
                            wait_exit(process)
                    if full and fault_case in proof.HELD_STORAGE_CASES and not worker_restart and matrix is None:
                        # Retire may block the failed Docker response. Observe the
                        # independent fenced status, then release exactly once.
                        pending = wait_artifact(".storage-pending.json")
                        release = proof.storage_release(pending, arm, worker, storage_checkpoint)
                        _, held_state, held_hashes = read_state()
                        held = held_state["intents"][arm["scope"]["intent"]]
                        proof.require(held.get("successor") is None and held["prepareCompleted"] is False
                            and all(i["id"] == held["id"] or i["launch"] == normal["launch"] for i in held_state["intents"].values()), "no fresh successor mutation while held")
                        record("storage-retirement-pending", status=pending, journal=held_hashes)
                        artifact(".storage-checkpoint.json", 8192); artifact(".storage-pending.json")
                        record("storage-release-intent", release=release)
                        proof.verify_full_ledger(ledger, evidence_files)
                        queue.publish(arm["requestID"] + ".storage-release.json", release)
                        finished = wait_artifact(".storage-finished.json")
                        proof.storage_status(finished, arm, worker, phase="finished", checkpoint=storage_checkpoint)
                        record("storage-finished", status=finished)
                    if (api_restart or storage_restart) and matrix is None:
                        joined_start(start, failed=True, disconnected=True, vm_recovery=vm_cut is not None)
                        # VM cuts permit eager HTTP failure; other cuts require exact SDK disconnect.
                        if active_ack is not None:
                            active_ack.reattach(client)
                            active_ack.recover(service_recovery, storage_vm=True)
                    elif not worker_restart and matrix is None:
                        joined_start(start, failed=True)  # Real failed HTTP response.
                    if full and worker is not None and fault_case not in proof.HELD_STORAGE_CASES and not worker_restart and io_case is None and vm_cut is None and matrix is None:
                        finished = wait_artifact(".storage-finished.json")
                        proof.storage_status(finished, arm, worker, phase="finished", checkpoint=storage_checkpoint)
                        record("storage-finished", status=finished)
                    if natural_failure:
                        wait_exit(process)
                        record("production-channel-failure-contained", native=proof.native_proof(process), signalDelivered=False)
                    if early and matrix_variant != "settled-success":
                        container.reload(); proof.require(container.attrs["State"]["Running"] is False, "failed API did not publish runtime")
                    if worker_restart:
                        proof.require({v.pid: v for v in processes()} == {v.pid: v for v in worker_survivors}, "exact post-containment census before retry")
                    elif matrix is not None and not matrix_workload_exited:
                        proof.require({v.pid: v for v in processes()} == {v.pid: v for v in before}, "adopted census unchanged before readback")
                    else:
                        unchanged_processes(before, processes(), process)
                    manifest, state, hashes = read_state()
                    if io_case is not None and io_case.expected == "sticky-uncertainty":
                        failed = io_proof.sticky_intent(state, arm)
                        record("sticky-quarantine-no-drain", intent=failed, journal=hashes)
                        before_retry = state
                        before_carrier = io_proof.carrier_census(queue)
                        io_proof.preserve_observed_carrier(before_carrier, seen)
                        rejected = start_request()  # No new arm and no evidence repair.
                        joined_start(rejected, failed=True, io_phase="quarantine-retry")
                        container.reload()
                        proof.require(container.attrs["State"]["Running"] is False, "uncertain retry did not publish runtime")
                        _, after_retry, retry_hashes = read_state()
                        io_proof.sticky_unchanged(before_retry, after_retry, arm)
                        proof.require(retry_hashes == hashes, "uncertain retry left exact durable journals unchanged")
                        unchanged_processes(before, processes(), process)
                        proof.require(io_proof.carrier_census(queue) == before_carrier,
                                      "uncertain retry preserved complete carrier identity/content census")
                        # Do not delete volumes, repair manifests, clear poison, or
                        # restart an authority. Parent owns final native containment
                        # and must retain this uncertainty-bearing backing evidence.
                        daemon._retain_root = True
                        record("sticky-evidence-retained", noRepair=True, noDrain=True, noSuccessor=True, journal=retry_hashes)
                        result = dict(rtm="RTM-100", profile=profile, caseName=fault_case,
                            runID=str(uuid.UUID(plan["owner"])), store=manifest["store"],
                            result="sticky-uncertainty-passed", expected=io_case.expected,
                            execution="actual-docker-runtime", fullAcceptance=False,
                            evidenceSHA256=proof.digest(proof.canonical(evidence_chain)))
                        record("io-case-result", **result)
                        return complete_io_result(result)
                    if matrix is not None:
                        failed = matrix_proof.recovered_intent(state, arm, matrix_variant, checkpoint)
                    elif worker_restart and checkpoint_exit:
                        from managed_prepare_worker_faults import recovered_checkpoint_intent
                        failed = recovered_checkpoint_intent(state["intents"][arm["scope"]["intent"]], arm, checkpoint)
                    else:
                        failed = (proof.failed_full_prepare if full else proof.failed_early_prepare if early else proof.failed_prepare)(state["intents"][arm["scope"]["intent"]], arm)
                    record("production-quarantine-drain" if failed["phase"] != "running" else "matrix-adopted-runtime",
                           intent={k: failed[k] for k in ("id", "phase", "prepareCompleted", "slots")}, journal=hashes)
                    previous = {**failed, "intent": failed["id"], "credentials": arm["credentials"], "binding": arm["binding"]}
                    if matrix_variant == "settled-success":
                        # The replacement API adopted the live runtime: no drain,
                        # no ReplacePrepare and no fresh-owner replay. Read back the
                        # complete tree beneath the adopted owner instead.
                        retry_seen = {}
                        successor = {"scope": {"intent": failed["id"]}}
                        physical = checkpoint if fault_case == "normal" else proof.full_observation(artifact(".checkpoint.json", 8192), arm)
                        recovered = observe("snapshot")
                        proof.full_retry_snapshot(recovered, baseline, physical, arm)
                        record("matrix-adopted-readback", firstPublicationRequired=False)
                    elif (matrix is not None and fault_case in matrix_proof.SUCCESSFUL) or (worker_restart and (fault_case == "drain-durable-reply-lost" or (checkpoint_exit and fault_case == "normal"))):
                        # NORMAL returns after its observation write (unlike held A7),
                        # so copy-up can finish before the worker exit. NORMAL/A8 use
                        # the complete-tree path; the original physical snapshot stays
                        # mandatory even if an earlier exit instead caused rollback.
                        # Production quarantined and
                        # drained the interrupted owner, and the replacement owner now
                        # starts unarmed over the complete tree. An armed NORMAL replay
                        # would fail closed on the nonempty destination by design.
                        from managed_prepare_storage_vm_faults import complete_tree_owner
                        retry_seen = {}
                        joined_start(start_request())
                        manifest, state, hashes = read_state()
                        current = only_intent(state, "running")
                        proof.running_receipts(manifest, state, plan, container.id, current["id"])
                        complete_tree_owner(previous, current, worker_recovery if worker_restart else
                            controller_recovery if controller_recovery is not None else service_recovery)
                        successor = {"scope": {"intent": current["id"]}}
                        physical = checkpoint if fault_case == "normal" else proof.full_observation(artifact(".checkpoint.json", 8192), arm)
                        recovered = observe("snapshot")
                        proof.full_retry_snapshot(recovered, baseline, physical, arm)
                        record("worker-complete-tree-readback" if worker_restart else "matrix-complete-tree-readback",
                            journal=hashes, firstPublicationRequired=False,
                            **({} if worker_restart else {"variant": matrix_variant}))
                    elif vm_cut in vm_proof.CASES[1:]:
                        # Existing complete tree: no capture/arm, emptying, or
                        # NORMAL first-publication observer on this replacement.
                        from managed_prepare_storage_vm_faults import complete_tree_owner, complete_tree_snapshot
                        retry_seen = {}
                        joined_start(start_request())
                        manifest, state, hashes = read_state()
                        current = only_intent(state, "running")
                        proof.running_receipts(manifest, state, plan, container.id, current["id"])
                        complete_tree_owner(previous, current, service_recovery)
                        successor = {"scope": {"intent": current["id"]}}
                        recovered = observe("snapshot")
                        complete_tree_snapshot(recovered, baseline, checkpoint, arm, source_witness=source_witness)
                        record("complete-tree-readback", case=vm_cut, journal=hashes, firstPublicationRequired=False)
                    else:
                        retry, successor, retry_wait, _, retry_seen = queue_start(queue, previous, "normal")
                        # Private pending production drain precedes fresh-owner
                        # NORMAL replay; its own source atimes are authoritative.
                        retry_checkpoint = (proof.full_observation if full else proof.early_normal_observation if early else proof.observation)(retry_wait(".checkpoint.json", 8192), successor)
                        record("retry-source-witness", checkpoint=retry_checkpoint)
                        joined_start(retry)
                        recovered = observe("snapshot")
                        if full:
                            proof.full_retry_snapshot(recovered, baseline, retry_checkpoint, successor)
                        elif early:
                            proof.early_retry_snapshot(recovered, baseline, retry_checkpoint, successor)
                        else:
                            proof.retry_snapshot(recovered, baseline, retry_checkpoint, successor)
                else:
                    # A8 succeeds only via the production same-operation Retire
                    # retry. The fixture never sends Retire or fabricates a reply.
                    process, before = pending_owner
                    successor, retry_seen = arm, {}
                    retry_checkpoint = proof.full_observation(wait_artifact(".checkpoint.json", 8192), arm)
                    record("retry-source-witness", checkpoint=retry_checkpoint)
                    joined_start(start)
                    if worker is not None:
                        finished = wait_artifact(".storage-finished.json")
                        proof.storage_status(finished, arm, worker, phase="finished", checkpoint=storage_checkpoint)
                        record("storage-finished", status=finished)
                    recovered = observe("snapshot")
                    proof.full_retry_snapshot(recovered, baseline, retry_checkpoint, arm)
                manifest, state, hashes = read_state()
                current = proof.running_receipts(manifest, state, plan, container.id, successor["scope"]["intent"])
                if matrix is not None and matrix_variant == "settled-success":
                    proof.require(current["id"] == failed["id"] and current["slots"] == failed["slots"], "adopted runtime intent unchanged")
                elif (matrix is not None or worker_restart) and failed["phase"] == "retired":
                    old = state["intents"][failed["id"]]
                    proof.require(old["phase"] == "retired" and old.get("successor") is None and current.get("predecessor") is None
                                  and old["slots"] == failed["slots"], "retired predecessor stays terminal beside the fresh owner")
                elif not successful_case or matrix is not None:
                    old = state["intents"][failed["id"]]
                    proof.require(old["phase"] == "replaced" and old["successor"] == current["id"] and current["predecessor"] == old["id"], "production ReplacePrepare historical link")
                    proof.require(old["slots"] == failed["slots"], "old drain receipts immutable")
                elif worker is not None:
                    actual_receipt = next(s["receipt"] for s in current["slots"] if s["attachment"] == arm["targetAttachment"])
                    proof.require(actual_receipt == {k: v for k, v in storage_checkpoint["drain"]["receipt"].items() if k != "schema"}, "running intent uses exact immutable dropped/replayed receipt")
                current_process = target(current)
                with proof.workload_owner(current_process, daemon, plan, current, manifest["root"]) as (native, _, validate):
                    validate(); record("recovered-runtime", native=native, journal=hashes)
                for n, original in {**seen, **retry_seen}.items(): proof.require(queue.read(n, 8192 if n.endswith(".checkpoint.json") else 65536) == original, "final carrier evidence immutable")
                # Same image layers, same Docker instance; no source restoration.
                image.reload(); proof.owned(image, "image", plan)
                proof.require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "source image unchanged")
                container.stop(timeout=1)
                manifest, state, hashes = read_state()
                proof.running_receipts(manifest, state, plan, container.id, current["id"], stopped=True)
                container.reload(); proof.owned(container, "container", plan); container.remove()
                wait_exit(current_process)  # Owned removal shuts down the stopped host shim.
                cleanup_survivors = worker_survivors if worker_restart else [v for v in before if v != process]
                proof.require({p.pid: p for p in processes()} == {p.pid: p for p in cleanup_survivors}, "same daemon/storage through cleanup")
                peer.reload(); proof.owned(peer, "container", peer_plan); peer.remove()
                volume.reload(); proof.owned(volume, "volume", plan); volume.remove()
                image.reload(); proof.owned(image, "image", plan); client.images.remove(image.id)
                record("owned-cleanup", journal=hashes, workloadJoined=True)
            if matrix is not None:
                from managed_prepare_service_faults import verify_api_owner_final
                owner_hash = verify_api_owner_final(daemon, recovered_owner)
                record("final-matrix-owner-unchanged", ownerSHA256=owner_hash)
                result = dict(rtm=matrix["rtm"], restart=matrix["restart"], profile=profile, caseName=fault_case,
                    boundary=matrix["boundary"], kind=matrix["kind"], variant=matrix_variant,
                    runID=str(uuid.UUID(plan["owner"])), store=manifest["store"], result="matrix-case-passed",
                    execution="actual-docker-runtime", fullAcceptance=False,
                    evidenceSHA256=proof.digest(proof.canonical(evidence_chain)))
                record("matrix-case-result", **result)
                return matrix_proof.completed_matrix_outcome(result, ledger, evidence_files)
            if api_restart:
                from managed_prepare_service_faults import verify_api_owner_final
                owner_hash = verify_api_owner_final(daemon, recovered_owner)
                record("final-api-owner-unchanged", ownerSHA256=owner_hash)
                result = dict(staged, profile=profile, result="initial-cut-passed", execution="actual-docker-runtime",
                    runID=str(uuid.UUID(plan["owner"])), store=manifest["store"], evidenceSHA256=proof.digest(proof.canonical(evidence_chain)))
                record("service-cut-result", **result)
                proof.verify_full_ledger(ledger, evidence_files)
                return result  # Deliberately not a RTM096 FullOutcome or full RTM097 PASS.
            if storage_restart:
                from managed_prepare_service_faults import verify_api_owner_final
                owner_hash = verify_api_owner_final(daemon, recovered_owner)
                record("final-storage-recovery-owner-unchanged", ownerSHA256=owner_hash)
                result = dict(staged, profile=profile, result="initial-cut-passed", execution="actual-docker-runtime",
                    runID=str(uuid.UUID(plan["owner"])), store=manifest["store"], evidenceSHA256=proof.digest(proof.canonical(evidence_chain)))
                record("storage-vm-cut-result", **result)
                proof.verify_full_ledger(ledger, evidence_files)
                return result  # R only after exact metadata, real drain/ReplacePrepare and cleanup; not whole RTM099.
            if worker_restart:
                worker_final()
                record("final-worker-owner-unchanged")
                result = dict(staged, profile=profile, result="initial-cut-passed", execution="actual-docker-runtime",
                    runID=str(uuid.UUID(plan["owner"])), store=manifest["store"], evidenceSHA256=proof.digest(proof.canonical(evidence_chain)))
                record("worker-cut-result", **result)
                proof.verify_full_ledger(ledger, evidence_files)
                return result  # Deliberately not a FullOutcome or full RTM098 acceptance.
            if io_case is not None:
                proof.require(io_case.expected == "recoverable", "sticky cases cannot claim recovery")
                result = dict(rtm="RTM-100", profile=profile, caseName=fault_case,
                    runID=str(uuid.UUID(plan["owner"])), store=manifest["store"],
                    result="recoverable-passed", expected=io_case.expected, execution="actual-docker-runtime",
                    evidenceSHA256=proof.digest(proof.canonical(evidence_chain)), fullAcceptance=False)
                record("io-case-result", **result)
                return complete_io_result(result)
            if full:
                result = dict(profile=profile, caseName=fault_case, runID=str(uuid.UUID(plan["owner"])), store=manifest["store"],
                    result="case-passed", evidenceSHA256=proof.digest(proof.canonical(evidence_chain)), execution="actual-docker-runtime", fullAcceptance=False)
                record("full-case-result", **result)
                return proof._completed_full_outcome(result, ledger, evidence_files)
            record("staged-result", **staged, result="staged-only-passed")
            return {**staged, "result": "staged-only-passed"}
        except BaseException:
            daemon._retain_root = True
            # No claim that worker cleanup terminates a held VM. Parent retains
            # the root and performs exact-owner containment on every failure.
            if early:
                def failure_record(phase, **value):
                    # Broken evidence must fail the case, not prevent owned
                    # emergency containment or turn it into a successful fault.
                    try: record(phase, **value)
                    except Exception: pass
                failure_record("failure", fullAcceptance=False, result="failed-retained")
                if pending_owner is not None:
                    # A2 has no guest timeout. If the normal fault path was cut
                    # short, contain only this captured owner. Validation failure
                    # never permits PID-kill; parent root teardown stays required.
                    try:
                        _contain_early_owner(pending_owner[0], pending_intent, daemon, plan, manifest["root"], failure_record,
                            deadline=min(deadline + 6, time.monotonic() + 3))
                    except Exception:
                        failure_record("early-emergency-containment-incomplete", fullAcceptance=False)
            else:
                record("failure", fullAcceptance=False, result="failed-retained")
            raise
        finally:
            if active_ack is not None: active_ack.stack.close()
            for process in starts:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=max(0.001, deadline + 7 - time.monotonic()))
            from managed_prepare_start_diagnostic import discard
            for process in starts: discard(process)
            if client is not None: client.close()


def _contain_early_owner(process, intent, daemon, plan, root_identity, record, *, deadline):
    """Failure-only bounded containment; no fault PASS and no stale-owner signal."""
    import harness
    def remaining():
        proof.require(time.monotonic() < deadline, "early containment deadline")
        return deadline - time.monotonic()
    if exact_exit(process, harness._kernel_process(process.pid)):
        record("early-emergency-owner-already-exited", native=proof.native_proof(process), signalDelivered=False)
        return
    with proof.workload_owner(process, daemon, plan, intent, root_identity) as (native, _, validate):
        with closing(select.kqueue()) as waiter:
            waiter.control([select.kevent(process.pid, filter=select.KQ_FILTER_PROC, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE, fflags=select.KQ_NOTE_EXIT)], 0)
            record("early-emergency-owned-SIGKILL-intent", native=native, fullAcceptance=False)
            validate(); remaining()
            current = harness._kernel_process(process.pid)
            if exact_exit(process, current):
                record("early-emergency-owner-already-exited", native=native, signalDelivered=False)
                return
            proof.require(current == process, "emergency exact live owner")
            token = (ctypes.c_uint32 * 8)(0, 0, 0, 0, 0, process.pid, 0, process.pidversion)
            result = ctypes.CDLL(None, use_errno=True).proc_signal_with_audittoken(ctypes.byref(token), signal.SIGKILL)
            proof.require(result == 0, "positive emergency audited SIGKILL")
            record("early-emergency-owned-SIGKILL-delivered", native=native, nativeResult=0, fullAcceptance=False)
            events = waiter.control(None, 1, remaining())
            proof.require(len(events) == 1 and events[0].ident == process.pid and events[0].fflags & select.KQ_NOTE_EXIT, "emergency native exit Wait")
        while not exact_exit(process, harness._kernel_process(process.pid)):
            time.sleep(min(0.025, remaining()))
    record("early-emergency-owner-exited", native=native, fullAcceptance=False)


def _docker_start(socket, container, diagnostic_fd=None):
    import docker
    from managed_prepare_start_diagnostic import classify, emit
    diagnostic = "UNKNOWN"
    proof.pin(container)
    client = docker.DockerClient(base_url=f"unix://{socket}", version="1.47", timeout=165)
    try:
        client.api.start(container)
        diagnostic = "SUCCESS"
        return 0
    except docker.errors.APIError as error:
        status = error.response.status_code if error.response is not None else None
        diagnostic = classify(status, getattr(error, "explanation", None))
        return 49 if status == 409 else 50 if status == 500 else 51
    except Exception as error:
        # Only the SDK's exact connection-loss class has this exit. Builtin
        # ConnectionError, timeouts and unrelated exceptions still fail distinctly.
        if type(error).__module__ != "requests.exceptions": raise
        from requests.exceptions import ConnectionError as RequestsConnectionError
        if type(error) is not RequestsConnectionError: raise
        diagnostic = "CONNECTION_LOST"
        return 52
    finally:
        try: client.close()
        finally: emit(diagnostic_fd, diagnostic)


if __name__ == "__main__":
    # Not a second compatibility selector. Parent calls run_staged_shard above;
    # this closed subprocess only owns one blocking real Docker start request.
    if len(sys.argv) == 5 and sys.argv[1] == "--docker-start":
        sys.exit(_docker_start(sys.argv[2], sys.argv[3], int(sys.argv[4])))
    raise SystemExit("parent must explicitly call run_staged_shard(profile, cases, pinned inputs)")
