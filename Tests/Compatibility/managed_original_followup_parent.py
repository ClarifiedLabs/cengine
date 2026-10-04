"""Parent-owned RTM103 follow-up routes; separate from the 165s PREPARE shard.

Each route runs on the caller's fresh retained Daemon with its own external
evidence directory. The parent supplies two owned, created never-started
full-image containers on one managed volume (plans named/owned exactly like
_run_prepare_case) and a finite per-route budget: replayed-takeover must fit
the two existing 195s stop/start bounds without altering them; the isolation
routes first confirm C2 through one owned API restart before any diagnostic.

Source readiness only. No selector here grants native or full acceptance, and
a route report is an exact per-route outcome, never the shard's
result == "case-passed".
"""
from __future__ import annotations

import os
from pathlib import Path
import time
import uuid

import managed_prepare_faults as p
import managed_takeover_lifecycle_evidence as lifecycle
import managed_stale_consumer as stale
import managed_takeover_original as followup

# Fixed route catalog re-exported for the campaign runner; owned by
# managed_takeover_original.FOLLOWUP_CASES and unchanged here.
FOLLOWUP_CASES = followup.FOLLOWUP_CASES

# Existing stop/start bound owned by the fixture restart helpers; unchanged here.
RESTART_BOUND = 195

# Finite per-route totals. replayed-takeover joins two existing 195s bounds
# (>= 390) plus setup/teardown margin; the isolation routes fit one owned
# C1 -> C2 API restart bound plus their live diagnostic.
ROUTE_BUDGETS = {
    "replayed-takeover": 2 * RESTART_BOUND + 30,
    "legacy-connection": RESTART_BOUND + 45,
    "second-service-exclusivity": RESTART_BOUND + 45,
}


def route_budget(case):
    p.require(case in FOLLOWUP_CASES, "fixed follow-up route")
    budget = ROUTE_BUDGETS[case]
    minimum = 2 * RESTART_BOUND if case == "replayed-takeover" else RESTART_BOUND
    p.require(type(budget) is int and budget >= minimum, "route budget covers existing restart bounds")
    return budget


def _store(daemon):
    with p.Directory(daemon.root / "managed-storage", private=False) as journal:
        manifest = p.decode(journal.read("manifest.json", 1024 * 1024)[0], 1024 * 1024, canonical_only=False)
    p.require(manifest.get("schema") == 1 and manifest.get("mode") == "managed", "actual managed journal")
    return manifest["store"]


def confirm_controller_successor(daemon, *, remaining, record):
    """One owned API restart confirms C2 before any isolation diagnostic."""
    p.require(daemon.process is not None and daemon.process.poll() is None, "live owned daemon before restart")
    p.require(remaining() >= RESTART_BOUND, "bounded owned C1 -> C2 restart")
    before, _ = lifecycle.read_owner(daemon.root)
    before_proof = lifecycle.owner(before)
    p.require(before_proof["controllerEpoch"] == 1, "fresh C1 owner")
    if lifecycle.is_v2(before):
        p.require(before["checkpoint"]["current"]["original"]["signed"]["grant"]["operation"] == "initialize",
            "actual lifecycle C1 initialization")
    else:
        p.require(not before["transitions"], "fresh legacy C1 history")
    daemon.restart(kill=True)
    p.require(daemon.process is not None and daemon.process.poll() is None, "live owned daemon after restart")
    after, after_hash = lifecycle.read_owner(daemon.root)
    after_proof = lifecycle.owner(after)
    remaining()
    from managed_takeover_replay import same_service_step
    same_service_step(before, after)
    p.require(after_proof["controllerEpoch"] == before_proof["controllerEpoch"] + 1, "confirmed C2 via owned API restart")
    if not lifecycle.is_v2(before):
        p.require(len(after["transitions"]) == len(before["transitions"]) + 1, "exact legacy controller successor")
    record("route-controller-successor", beforeEpoch=before_proof["controllerEpoch"],
        afterEpoch=after_proof["controllerEpoch"], ownerSHA256=after_hash)


def _validate_route_result(case, route_result):
    p.require(type(route_result) is dict, "exact live route result required")
    p.require(route_result.get("fullAcceptance") is False and route_result.get("nativeAcceptance") is False,
        "no acceptance toggle on a follow-up route")
    if case == "replayed-takeover":
        p.require("caseName" not in route_result or route_result["caseName"] == case, "exact replayed route report")
        keys = ("controlLegVerified", "originalOperationVerified", "registryVerified", "backingVerified", "freshGetattrVerified")
    else:
        p.require(route_result.get("caseName") == case, "exact isolation route report")
        keys = ("originalOperationVerified", "registryVerified", "backingVerified", "freshGetattrVerified")
    for key in keys:
        p.require(route_result.get(key) is True, "exact follow-up route outcome " + key)


def run_followup_route(daemon, *, case, profile, cases, probe, probe_sha256, source_sha256, expected_commit, evidence, log=lambda message: None):
    """One follow-up route per fresh retained Daemon/evidence directory.

    `probe` is the parent's pinned offline linux/arm64 helper build; its exact
    bytes both pin the source and become the full-image both containers share.
    Failures retain the root and evidence; no report is synthesized.
    """
    import docker
    import harness

    p.require(profile == p.FULL_PROFILE and tuple(cases) == stale.CASES, "complete explicit RTM103 catalog required")
    selected = followup.followup_selection(profile, cases, case)  # Fail before engine I/O.
    budget = route_budget(case)
    p.pin(probe_sha256); p.pin(source_sha256)
    p.require(harness.compatibility_root_retained(daemon.work), "signed managed retained parent fixture required")
    deadline = time.monotonic() + budget
    def remaining():
        p.require(time.monotonic() < deadline, "route budget")
        return max(0.001, deadline - time.monotonic())
    plan = p.names(uuid.uuid4().hex)
    evidence = Path(evidence)
    p.require(evidence.resolve() != daemon.work.resolve() and daemon.work.resolve() not in evidence.resolve().parents,
        "external evidence directory required")
    import test_managed_prepare_faults as fixture  # pytest module: lazy, caller-side
    sequence = 0
    evidence_chain = []
    with fixture.bounded_parent(deadline), p.Directory(evidence) as ledger:
        def record(phase, **value):
            nonlocal sequence
            sequence += 1
            event = {"phase": phase, **value}
            ledger.publish("%03d-%s.json" % (sequence, phase), event)
            evidence_chain.append(p.digest(p.canonical(event)))
        client = None
        try:
            record("route-plan", route=selected, budget=budget)
            p.require(daemon.process is not None and daemon.process.poll() is None, "live owned daemon before route")
            probe_path = Path(probe)
            p.require(probe_path.lstat().st_size <= 8 * 1024 * 1024 and not probe_path.is_symlink(), "bounded pinned helper file")
            with probe_path.open("rb") as source:
                raw_probe = source.read(8 * 1024 * 1024 + 1)
            p.require(p.digest(raw_probe) == probe_sha256, "exact parent-built probe pin")
            archive, config = p.image_archive(raw_probe, plan)
            client = docker.DockerClient(base_url=f"unix://{daemon.socket}", version="1.47", timeout=15)
            p.require(client.version().get("GitCommit") == expected_commit, "exact signed parent engine commit")
            client.images.load(archive)
            image = p.owned(client.images.get(plan["image"]), "image", plan)
            p.require(image.attrs["RootFS"]["Layers"] == config["rootfs"]["diff_ids"], "full image source pin")
            volume = p.owned(client.volumes.create(plan["volume"], labels={p.OWNER: plan["owner"]}), "volume", plan)
            container, reader, reader_plan = fixture.create_shared_consumers(client, image, volume, plan)
            p.require(container.id != reader.id and plan["volume"] == reader_plan["volume"], "distinct same-volume original/reader")
            record("route-fixtures", containers=[container.id, reader.id], volume=volume.name)
            if case == "replayed-takeover":
                route_result = fixture.run_takeover_original_followup(daemon, profile=profile, cases=cases,
                    container=container, reader=reader, plan=plan, reader_plan=reader_plan,
                    remaining=remaining, record=record)
            else:
                confirm_controller_successor(daemon, remaining=remaining, record=record)
                route_result = fixture.run_service_isolation_followup(daemon, profile=profile, cases=cases, case=case,
                    container=container, reader=reader, plan=plan, reader_plan=reader_plan,
                    remaining=remaining, record=record)
            _validate_route_result(case, route_result)
            store = _store(daemon)
            # Preserve the cleanup boundary even if the outer deadline fires
            # mid-removal: a retained root need not still contain every fixture.
            for kind, item, owner in (("container", container, plan), ("container", reader, reader_plan),
                                      ("volume", volume, plan), ("image", image, plan)):
                remaining()
                item.reload(); p.owned(item, kind, owner)
                identity = item.name if kind == "volume" else item.id
                record("route-cleanup-intent", kind=kind, identity=identity)
                if kind == "image":
                    client.images.remove(item.id)
                else:
                    item.remove()
                record("route-cleanup-completed", kind=kind, identity=identity)
            remaining()
            record("route-owned-cleanup")
            report = dict(rtm="RTM-103", profile=profile, caseName=case, coverage=selected["coverage"],
                executionRoute=selected["executionRoute"], execution="actual-docker-runtime",
                result="followup-route-passed", fullAcceptance=False, nativeAcceptance=False,
                runID=str(uuid.UUID(plan["owner"])), store=store,
                evidenceSHA256=p.digest(p.canonical(evidence_chain)))
            record("route-result", **report)
            log(f"RTM-103 {case}: follow-up route report accepted (source-ready, native gated)")
            return report
        except BaseException as error:
            daemon._retain_root = True
            # Broken evidence must fail the route, never become a success report.
            try:
                record("failure", fullAcceptance=False, nativeAcceptance=False, result="failed-retained",
                    errorType=type(error).__name__, error=str(error)[:2000])
            except Exception:
                pass
            raise
        finally:
            if client is not None:
                client.close()
