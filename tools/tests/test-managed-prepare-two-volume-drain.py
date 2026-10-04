#!/usr/bin/env python3
"""Engine-free negative proofs only; never a VM/native acceptance receipt."""
import base64
import copy
import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_prepare_two_volume_drain as v

FULL = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-full.py"))


def uid(): return str(uuid.uuid4())


def fixture():
    previous, saved, volume, _, candidate = FULL["V1"]["values"]()
    volumes = [volume, dict(id=uid(), name="owned-second")]
    saved["mounts"].append(dict(kind="volume", source=volumes[1]["name"], destination="/other", readOnly=False, noCopy=False))
    previous["mounts"].append(dict(volume=volumes[1]["id"], destination="/other", subpath="", mode="read-write"))
    capture = v.capture_from_normal(previous, saved, volumes, uid())
    # First host prepare UUID deliberately sorts AFTER the second. Sorting the
    # wire arm must not change which actual production retirement is selected.
    prepare_ids = ["ffffffff-ffff-4fff-bfff-ffffffffffff", "00000000-0000-4000-8000-000000000001"]
    slots = [dict(volume=volume["id"], attachment=prepare_ids[i] if role == "prepare" else uid(),
                  role=role, mode="read-write")
             for i, volume in enumerate(volumes) for role in ("prepare", "runtime")]
    candidate.update(version=3, profile=p.FULL_PROFILE, requestID=capture["requestID"], mounts=capture["mounts"], slots=slots,
        credentials=[dict(attachment=a, key=str(i + 7) * 64, certificateSHA256=str(i + 3) * 64)
                     for i, a in enumerate(prepare_ids)])
    intent = {("id" if k == "intent" else k): value for k, value in candidate["scope"].items()}
    intent.update(version=12, slots=copy.deepcopy(slots), phase="prepareSucceeded", prepareCompleted=False, cleanUnmount=True,
                  reserveOperation=uid(), completeOperation=uid(), replaceOperation=uid(), mounts=previous["mounts"])
    intent["guestCompletion"] = dict(prepare=intent["prepare"], containerInstance=intent["containerInstance"],
        launch=intent["launch"], succeeded=True, cleanCopyUp=True, evidenceDigest="5" * 64)
    for slot in intent["slots"]:
        slot.update(registerOperation=uid(), retireOperation=uid())
        if slot["role"] == "prepare":
            slot["key"] = next(c["key"] for c in candidate["credentials"] if c["attachment"] == slot["attachment"])
    arm = v.arm_candidate(candidate, capture, previous, intent)
    worker = uid()
    prepare = [s for s in intent["slots"] if s["role"] == "prepare"]
    def receipt(slot, revision):
        return dict(store=intent["store"], volume=slot["volume"], attachment=slot["attachment"],
                    prepare=intent["prepare"], launch=intent["launch"], revision=revision)
    prepare[0]["receipt"] = receipt(prepare[0], 20)
    checkpoint = dict(**v.storage_query(arm, worker), stage=v.CASE, count=1, targetAttachment=arm["targetAttachment"],
        drain=dict(retireOperation=prepare[1]["retireOperation"], receipt=dict(schema=3, **receipt(prepare[1], 21))))
    state = dict(store=intent["store"], revision=50, intents={intent["id"]: intent}, operations={}, operationDigests={})
    for slot in prepare:
        request = dict(id=0, retire=dict(operation=slot["retireOperation"], store=intent["store"],
                                        volume=slot["volume"], attachment=slot["attachment"], launch=intent["launch"]))
        persist(state, slot["retireOperation"], request)
    return previous, saved, volumes, capture, candidate, intent, arm, worker, checkpoint, state


def persist(state, operation, value):
    raw = p.canonical(value)
    state["operations"][operation] = base64.b64encode(raw).decode()
    state["operationDigests"][operation] = p.digest(raw)


def stopped(state, commits):
    """Each prefix of the old API's failed drain/start/cleanup unwind."""
    result = copy.deepcopy(state)
    intent = next(iter(result["intents"].values()))
    for reason in ("attachment retirement incomplete", "start interrupted",
                   "attachment retirement incomplete")[:commits]:
        intent.update(version=intent["version"] + 1, phase="quarantined", quarantineReason=reason)
        result["revision"] += 1
    return result


def recovered(state, checkpoint):
    after = copy.deepcopy(state); after["revision"] += 5
    intent = next(iter(after["intents"].values()))
    # Production ManagedVolumeLifecycleCoordinator.recover (236, 284-295),
    # drain (1402-1414), HostStorageIntents.update (359): four CAS updates.
    def update(**values):
        intent.update(values); intent["version"] += 1
    update(phase="quarantined", quarantineReason="recovering interrupted execution")
    prepare = [s for s in intent["slots"] if s["role"] == "prepare"]
    prepare[1]["receipt"] = {k: value for k, value in checkpoint["drain"]["receipt"].items() if k != "schema"}
    update()  # drain's receipt installation commits once, not once per slot.
    receipts = sorted([dict(schema=3, **s["receipt"]) for s in prepare], key=lambda r: r["attachment"])
    persist(after, intent["completeOperation"], dict(id=0, complete_prepare=dict(operation=intent["completeOperation"],
        prepare=intent["prepare"], receipts=receipts, attestation=dict(prepare=intent["prepare"], succeeded=True, clean_copy_up=True))))
    update(prepareCompleted=True)
    update(phase="retired")
    return after


class TwoVolumeDrain(unittest.TestCase):
    def test_fixture_progression_is_tied_to_production_recovery_and_containment(self):
        # Source-contract check supplements execution of the Python validator:
        # these are the real Swift statements, not assumptions in our fixture.
        source = ROOT / "Sources/CEngineRuntime"
        lifecycle = (source / "ManagedVolumeLifecycleCoordinator.swift").read_text()
        recover = lifecycle.split("    func recover(", 1)[1].split("    private func replayOK", 1)[0]
        drain = lifecycle.split("    private func drain(", 1)[1].split("    ///", 1)[0]
        start = lifecycle.split("    private func runPlanned(", 1)[1].split("    ///", 1)[0]
        unwind = start.split("        } catch {", 1)[1]
        self.assertIn('return try await runPlanned(token, execution: execution, guest: guest)', lifecycle)
        self.assertLess(start.index('token = try await drain(token, role: .prepare, execution: execution)'),
                        start.index('        } catch {'))
        rollback = ['if executions[plan.id] == execution', 'token = try journal.token(for: plan.id)',
                    'token = try journal.quarantine(token, reason: "start interrupted")',
                    '_ = try? await drain(token, role: nil, execution: execution)', 'throw error']
        self.assertEqual(sorted(rollback, key=unwind.index), rollback)
        failed_drain = ['if let firstError', 'if executions[token.intent] == execution',
                        '_ = try? journal.quarantine(token, reason: "attachment retirement incomplete")',
                        'throw firstError']
        self.assertEqual(sorted(failed_drain, key=drain.index), failed_drain)
        self.assertEqual(unwind.count('journal.quarantine('), 1)
        self.assertEqual(drain.count('journal.quarantine('), 1)
        journal = (source / "HostStorageIntents.swift").read_text()
        backend = (source / "RawManagedStorageBackend.swift").read_text()
        wire = (source / "ManagedStorageControlProtocol.swift").read_text()
        attestation = wire.split('public struct Attestation:', 1)[1].split('public struct ReserveRequest:', 1)[0]
        self.assertIn('cleanCopyUp = "clean_copy_up"', attestation)
        self.assertIn('changed.version = old.version + 1', journal)
        updates = ['journal.quarantine(token, reason: "recovering interrupted execution")',
                   'token = try await drain(token, role: nil, execution: execution)',
                   'journal.update(token) { $0.prepareCompleted = true }',
                   'journal.update(token) { $0.phase = .retired }']
        self.assertEqual(sorted(updates, key=recover.index), updates)
        self.assertNotIn('quarantineReason = nil', recover)
        self.assertIn('slot.key != nil && slot.receipt == nil', drain)
        self.assertIn('next.slots[index].receipt = .init(receipt)', drain)
        retirement = lifecycle.split('    private func retireLaunch(', 1)[1].split('    func canDelete', 1)[0]
        self.assertLess(retirement.index('journal.quarantine(token, reason: "launch retirement")'),
                        retirement.index('token = try await drain(token, role: nil, execution: execution)'))
        self.assertIn('try await lifecycle.retireLaunch(intent.id)', backend)
        self.assertIn('for intent in ordered { proofs.append(try await prepare(intent)) }', backend)
        self.assertIn('for intent in ordered where !intent.isTerminal { try await settle(intent) }', backend)
        self.assertIn('for launch in launches where !preserved.contains(where: { $0.protects(launch.client) }) { try await launch.client.terminate() }', lifecycle)
        *_, intent, arm, worker, checkpoint, before = fixture()
        after = recovered(before, checkpoint)["intents"][intent["id"]]
        self.assertEqual(after["version"], intent["version"] + 4)
        self.assertEqual(after["quarantineReason"], "recovering interrupted execution")
        self.assertEqual(after["phase"], "retired")

    def test_invalidation_alternative_is_tied_to_ordered_producer_fence(self):
        source = ROOT / "Sources/CEngineRuntime"
        coordinator = (source / "ManagedVolumeLifecycleCoordinator.swift").read_text()
        invalidate = coordinator.split('    func invalidate() async {', 1)[1].split('    init(', 1)[0]
        ordered = ['invalidated = true', 'executions.removeAll()', 'control.revoke()',
                   'try? journal.requireReconciliation()', 'await task.result', 'await control.invalidate()']
        self.assertEqual(sorted(ordered, key=invalidate.index), ordered)
        self.assertEqual(invalidate.count('journal.'), 1)
        self.assertIn('guard !invalidated, executions[token.intent] == execution', coordinator)
        backend = (source / "RawManagedStorageBackend.swift").read_text()
        observer = backend.split('    func observeRetirements(', 1)[1]
        self.assertLess(observer.index('await lifecycle.invalidate()'), observer.index('await owner.close()'))
        journal = (source / "HostStorageIntents.swift").read_text()
        self.assertIn('func requireReconciliation() throws { try commit { $0.reconciliationRequired = true } }', journal)
        self.assertIn('var next = state; try mutate(&next); next.revision += 1', journal)

    def test_retained_native_v2_pre_rollback_invalidation_and_negative_mutations(self):
        # Exact 5xqj5g6b external snapshots, not a manufactured quarantine prefix.
        # Every intent, receipt, request, digest and volume is unchanged.
        with (ROOT / "tools/tests/fixtures/rtm099-v2-two-volume-invalidation.json").open("rb") as stream:
            raw = stream.read(131073)
        self.assertLessEqual(len(raw), 131072)
        data = json.loads(raw)
        before, quiescent, arm, checkpoint, worker = (data[k] for k in
            ("before", "stopped", "arm", "checkpoint", "worker"))
        owner = arm["scope"]["intent"]
        old, current = before["intents"][owner], quiescent["intents"][owner]
        self.assertEqual((old["version"], current["version"], before["revision"], quiescent["revision"]),
                         (7, 7, 66, 67))
        self.assertIs(before["reconciliationRequired"], False)
        self.assertIs(quiescent["reconciliationRequired"], True)
        self.assertEqual({k for k in before if p.canonical(before[k]) != p.canonical(quiescent[k])},
                         {"revision", "reconciliationRequired"})
        self.assertEqual((len(before["intents"]), len(before["operations"])), (3, 27))
        retained = copy.deepcopy(data)
        self.assertIs(v.prerecovery_receipts(before, quiescent, arm, checkpoint, worker, lifecycle_v2=True), current)
        self.assertEqual(data, retained)
        with self.assertRaises(ValueError):
            v.prerecovery_receipts(before, quiescent, arm, checkpoint, worker)
        peer = next(i for i in before["intents"] if i != owner)
        operation = current["slots"][0]["retireOperation"]
        changes = [
            lambda s: s.update(reconciliationRequired=False),
            lambda s: s.update(reconciliationRequired=1),
            lambda s: s.pop("reconciliationRequired"),
            lambda s: s.update(revision=66),
            lambda s: s.update(revision=68),
            lambda s: s.update(revision=67.0),
            lambda s: s["intents"][owner].update(version=8),
            lambda s: s["intents"][owner].update(phase="quarantined", quarantineReason="start interrupted"),
            lambda s: s["intents"][owner].update(prepareCompleted=True),
            lambda s: s["intents"][owner]["guestCompletion"].update(evidenceDigest="0" * 64),
            lambda s: s["intents"][owner]["slots"][0]["receipt"].update(revision=999),
            lambda s: s["intents"][owner]["slots"][2].update(receipt=checkpoint["drain"]["receipt"]),
            lambda s: s["intents"][owner]["slots"][1].update(key="a" * 64),
            lambda s: s["intents"][peer].update(version=999),
            lambda s: s["intents"].pop(peer),
            lambda s: s["volumes"][current["slots"][0]["volume"]].update(createdRevision=999),
            lambda s: s["operations"].pop(operation),
            lambda s: s["operations"].update({operation: base64.b64encode(b'{}').decode()}),
            lambda s: s["operationDigests"].update({operation: "0" * 64}),
            lambda s: persist(s, current["completeOperation"], dict(id=0)),
            lambda s: s.update(unexpected=None),
        ]
        for mutate in changes:
            bad = copy.deepcopy(quiescent); mutate(bad)
            with self.subTest(mutation=changes.index(mutate)), self.assertRaises((ValueError, KeyError)):
                v.prerecovery_receipts(before, bad, arm, checkpoint, worker, lifecycle_v2=True)
        # This is one exact alternative, never an optional fence on all prefixes.
        for delta, reason in enumerate(("attachment retirement incomplete", "start interrupted",
                                         "attachment retirement incomplete", "launch retirement"), 1):
            bad = copy.deepcopy(quiescent)
            bad["intents"][owner].update(version=7 + delta, phase="quarantined", quarantineReason=reason)
            bad["revision"] += delta
            with self.subTest(delta=delta), self.assertRaises(ValueError):
                v.prerecovery_receipts(before, bad, arm, checkpoint, worker, lifecycle_v2=True)
        for flag in (True, 0, None):
            bad_before = copy.deepcopy(before); bad_before["reconciliationRequired"] = flag
            with self.subTest(before_flag=flag), self.assertRaises(ValueError):
                v.prerecovery_receipts(bad_before, quiescent, arm, checkpoint, worker, lifecycle_v2=True)

    def test_retained_native_v2_four_update_prefix_and_negative_mutations(self):
        # Exact hgu_w9f6 evidence, not generated expected journal updates. The
        # run stopped before recovery birth; this is NOT native recovery proof.
        data = json.loads((ROOT / "tools/tests/fixtures/rtm099-v2-two-volume-rollback.json").read_text())
        before, quiescent, arm, checkpoint, worker = (data[k] for k in
            ("before", "stopped", "arm", "checkpoint", "worker"))
        owner = arm["scope"]["intent"]
        old, current = before["intents"][owner], quiescent["intents"][owner]
        self.assertEqual((old["version"], current["version"], before["revision"], quiescent["revision"]),
                         (7, 11, 66, 70))
        self.assertEqual(current["quarantineReason"], "launch retirement")
        retained = copy.deepcopy(data)
        self.assertIs(v.prerecovery_receipts(before, quiescent, arm, checkpoint, worker, lifecycle_v2=True), current)
        self.assertEqual(data, retained)
        with self.assertRaises(ValueError):
            v.prerecovery_receipts(before, quiescent, arm, checkpoint, worker)
        peer = next(i for i in before["intents"] if i != owner)
        operation = current["slots"][0]["retireOperation"]
        changes = [
            lambda s: s["intents"][owner].update(quarantineReason="attachment retirement incomplete"),
            lambda s: s["intents"][owner].update(quarantineReason="start interrupted"),
            lambda s: s["intents"][owner].update(phase="retired"),
            lambda s: s["intents"][owner].update(prepareCompleted=True),
            lambda s: s["intents"][owner]["guestCompletion"].update(cleanCopyUp=False),
            lambda s: s["intents"][owner]["slots"][0]["receipt"].update(revision=999),
            lambda s: s["intents"][owner]["slots"][2].update(receipt=checkpoint["drain"]["receipt"]),
            lambda s: s["intents"][owner]["slots"][1].update(key="a" * 64),
            lambda s: s["intents"][peer].update(version=999),
            lambda s: s["operations"].pop(operation),
            lambda s: s["operationDigests"].update({operation: "0" * 64}),
            lambda s: persist(s, current["completeOperation"], dict(id=0)),
            lambda s: s.update(revision=71),
            lambda s: s.update(reconciliationRequired=True),
            lambda s: s.update(unexpected=None),
        ]
        for mutate in changes:
            bad = copy.deepcopy(quiescent); mutate(bad)
            with self.subTest(mutation=changes.index(mutate)), self.assertRaises((ValueError, KeyError)):
                v.prerecovery_receipts(before, bad, arm, checkpoint, worker, lifecycle_v2=True)
        for count in (-1, 0, 1, 2, 3, 5, 6):
            bad = copy.deepcopy(quiescent)
            bad["intents"][owner]["version"] = old["version"] + count
            bad["revision"] = before["revision"] + count
            with self.subTest(count=count), self.assertRaises(ValueError):
                v.prerecovery_receipts(before, bad, arm, checkpoint, worker, lifecycle_v2=True)

    def test_explicit_closed_shape_and_actual_host_order(self):
        previous, saved, volumes, capture, candidate, intent, arm, *_ = fixture()
        self.assertEqual(len(p.FULL_CASES), 9)
        self.assertTrue(v.selection(p.FULL_PROFILE, v.CASES, v.CASE)["runnable"])
        self.assertEqual(arm["targetAttachment"], "00000000-0000-4000-8000-000000000001")
        self.assertNotEqual(arm["targetAttachment"], sorted(s["attachment"] for s in arm["slots"] if s["role"] == "prepare")[1])
        with self.assertRaises(ValueError): p.full_arm_candidate(candidate, capture, previous, "normal")
        with self.assertRaises(ValueError): p.capture_from_normal(previous, saved, volumes[0], uid())
        for profile, cases in ((p.PROFILE, v.CASES), (p.FULL_PROFILE, p.FULL_CASES)):
            with self.assertRaises(ValueError): v.selection(profile, cases, v.CASE)
        for mutate in (lambda c: c["slots"].pop(), lambda c: c["credentials"].pop(),
                       lambda c: c["mounts"].pop(), lambda c: c["scope"].update(serviceEpoch=uid()),
                       lambda c: c["scope"].update(controllerEpoch=True),
                       lambda c: c["credentials"][1].update(key=c["credentials"][0]["key"])):
            bad = copy.deepcopy(candidate); mutate(bad)
            with self.assertRaises(ValueError): v.arm_candidate(bad, capture, previous, intent)

    def test_capture_no_extra_foreign_mount_or_owner(self):
        previous, saved, volumes, *_ = fixture()
        for mutate in (lambda s: s["mounts"].pop(), lambda s: s["mounts"].append(s["mounts"][0]),
                       lambda s: s["mounts"][1].update(source="foreign"), lambda s: s.update(instanceID=uid()),
                       lambda s: s["mounts"][1].update(noCopy=True)):
            bad = copy.deepcopy(saved); mutate(bad)
            with self.assertRaises(ValueError): v.capture_from_normal(previous, bad, volumes, uid())

    def test_held_drain_dto_not_admission_and_observer_loss(self):
        *_, arm, worker, checkpoint, state = fixture()
        held = dict(query=v.storage_query(arm, worker), state="held", observation=checkpoint,
            retirementStarted=True, acceptedInFlight=0, lateAdmissionRejected=False, receiptReplayCount=0)
        self.assertIs(v.storage_status(held, arm, worker, checkpoint), held)
        self.assertIs(v.prefault_evidence(state, held, arm, checkpoint, worker), state["intents"][arm["scope"]["intent"]])
        for key in p.SCOPE:
            bad = copy.deepcopy(arm); del bad["scope"][key]
            with self.assertRaises(ValueError): v.storage_query(bad, worker)
        for key, wrong in (("state", "finished"), ("state", "observed"), ("state", "released"),
                           ("retirementStarted", False), ("acceptedInFlight", 1), ("acceptedInFlight", False),
                           ("receiptReplayCount", 1), ("observation", None)):
            bad = copy.deepcopy(held); bad[key] = wrong
            with self.assertRaises(ValueError): v.storage_status(bad, arm, worker, checkpoint)
        for mutate in (lambda c: c.update(count=2), lambda c: c.update(count=True),
                       lambda c: c.update(workerUUID=uid()), lambda c: c.update(requestID=uid()),
                       lambda c: c.update(armDigest="0" * 64), lambda c: c.update(admission={}),
                       lambda c: c["drain"]["receipt"].update(prepare=uid()),
                       lambda c: c["drain"]["receipt"].update(volume=uid())):
            bad = copy.deepcopy(checkpoint); mutate(bad)
            with self.assertRaises(ValueError): v.storage_observation(bad, arm, worker)
        bad = copy.deepcopy(held); bad["observation"]["drain"]["receipt"]["revision"] += 1
        with self.assertRaises(ValueError): v.storage_status(bad, arm, worker, checkpoint)

    def test_prefault_mixed_receipts_and_no_premature_completion_runtime(self):
        *_, intent, arm, worker, checkpoint, state = fixture()
        self.assertIs(v.prefault_receipts(state, arm, checkpoint, worker), intent)
        changes = [lambda i: i["slots"][0].pop("receipt"),
            lambda i: i["slots"][2].update(receipt=checkpoint["drain"]["receipt"]),
            lambda i: i["slots"][1].update(key="1" * 64), lambda i: i.update(prepareCompleted=True),
            lambda i: i.update(phase="running"), lambda i: i.update(cleanUnmount=False),
            lambda i: i.update(quarantineReason="uncertain"),
            lambda i: i["guestCompletion"].update(launch=uid()), lambda i: i["guestCompletion"].update(succeeded=False),
            lambda i: i["slots"].reverse(), lambda i: i["slots"][2].update(retireOperation=uid())]
        for mutate in changes:
            bad = copy.deepcopy(state); mutate(bad["intents"][intent["id"]])
            with self.assertRaises((ValueError, KeyError)): v.prefault_receipts(bad, arm, checkpoint, worker)
        for operation in (intent["completeOperation"], intent["replaceOperation"], intent["slots"][1]["registerOperation"]):
            bad = copy.deepcopy(state); bad["operationDigests"][operation] = "0" * 64
            with self.assertRaises(ValueError): v.prefault_receipts(bad, arm, checkpoint, worker)
        bad = copy.deepcopy(checkpoint); bad["drain"]["retireOperation"] = uid()
        with self.assertRaises(ValueError): v.prefault_receipts(state, arm, bad, worker)

    def test_prerecovery_accepts_only_exact_rollback_prefixes_without_mutation(self):
        *_, intent, arm, worker, checkpoint, before = fixture()
        peer = uid()
        before["intents"][peer] = dict(id=peer, version=1, phase="retired", prepareCompleted=True)
        before["volumes"] = {intent["slots"][0]["volume"]: dict(createdRevision=1)}
        for commits, reason in enumerate((None, "attachment retirement incomplete", "start interrupted",
                                          "attachment retirement incomplete")):
            with self.subTest(commits=commits):
                quiescent = stopped(before, commits)
                retained = copy.deepcopy((before, quiescent, arm, checkpoint))
                current = v.prerecovery_receipts(before, quiescent, arm, checkpoint, worker)
                self.assertIs(current, quiescent["intents"][intent["id"]])
                self.assertEqual(current["version"], intent["version"] + commits)
                self.assertEqual(quiescent["revision"], before["revision"] + commits)
                self.assertEqual(current["phase"], "quarantined" if commits else "prepareSucceeded")
                self.assertEqual(current.get("quarantineReason"), reason)
                self.assertEqual((before, quiescent, arm, checkpoint), retained)

    def test_prerecovery_rejects_wrong_phase_reason_count_and_global_revision(self):
        *_, intent, arm, worker, checkpoint, before = fixture()
        for commits in range(4):
            valid = stopped(before, commits)
            mutations = [
                ("phase", lambda s: s["intents"][intent["id"]].update(phase="retired")),
                ("running", lambda s: s["intents"][intent["id"]].update(phase="running")),
                ("prefix-phase", lambda s: s["intents"][intent["id"]].update(
                    phase="quarantined" if commits == 0 else "prepareSucceeded")),
                ("missing-reason", lambda s: s["intents"][intent["id"]].update(quarantineReason=None)),
                ("recovery-reason", lambda s: s["intents"][intent["id"]].update(quarantineReason="recovering interrupted execution")),
                ("wrong-prefix-reason", lambda s: s["intents"][intent["id"]].update(
                    quarantineReason="attachment retirement incomplete" if commits == 2 else "start interrupted")),
                ("global-revision", lambda s: s.update(revision=s["revision"] + 1)),
                ("global-revision-backwards", lambda s: s.update(revision=s["revision"] - 1)),
                ("global-revision-float", lambda s: s.update(revision=float(s["revision"]))),
                ("global-revision-bool", lambda s: s.update(revision=True)),
                ("version-float", lambda s: s["intents"][intent["id"]].update(version=float(intent["version"] + commits))),
                ("version-bool", lambda s: s["intents"][intent["id"]].update(version=True)),
            ]
            for name, mutate in mutations:
                bad = copy.deepcopy(valid); mutate(bad)
                with self.subTest(commits=commits, mutation=name), self.assertRaises(ValueError):
                    v.prerecovery_receipts(before, bad, arm, checkpoint, worker)
        for commits in (-1, 4, 5):
            bad = stopped(before, 3)
            bad["intents"][intent["id"]]["version"] = intent["version"] + commits
            bad["revision"] = before["revision"] + commits
            with self.subTest(count=commits), self.assertRaises(ValueError):
                v.prerecovery_receipts(before, bad, arm, checkpoint, worker)

    def test_prerecovery_rejects_receipt_request_owner_store_and_type_identity_changes(self):
        *_, intent, arm, worker, checkpoint, before = fixture()
        peer = uid()
        before["intents"][peer] = dict(id=peer, version=1, phase="retired", prepareCompleted=True)
        before["volumes"] = {intent["slots"][0]["volume"]: dict(createdRevision=1)}
        operation = intent["slots"][0]["retireOperation"]
        request = dict(id=0, retire=dict(operation=operation, store=intent["store"],
            volume=intent["slots"][0]["volume"], attachment=intent["slots"][0]["attachment"], launch=intent["launch"]))
        changes = [
            ("receipt", lambda s: s["intents"][intent["id"]]["slots"][0]["receipt"].update(revision=21)),
            ("receipt-type", lambda s: s["intents"][intent["id"]]["slots"][0]["receipt"].update(revision=20.0)),
            ("second-receipt", lambda s: s["intents"][intent["id"]]["slots"][2].update(receipt=checkpoint["drain"]["receipt"])),
            ("request", lambda s: persist(s, operation, {**request, "id": 1})),
            ("request-type", lambda s: persist(s, operation, {**request, "id": False})),
            ("extra-request", lambda s: persist(s, uid(), request)),
            ("missing-request", lambda s: s["operations"].pop(operation)),
            ("digest", lambda s: s["operationDigests"].update({operation: "0" * 64})),
            ("other-owner", lambda s: s["intents"][peer].update(phase="quarantined")),
            ("other-owner-type", lambda s: s["intents"][peer].update(prepareCompleted=1)),
            ("missing-owner", lambda s: s["intents"].pop(peer)),
            ("extra-owner", lambda s: s["intents"].update({uid(): before["intents"][peer]})),
            ("store", lambda s: s.update(store=uid())),
            ("volume", lambda s: s["volumes"][intent["slots"][0]["volume"]].update(createdRevision=2)),
            ("volume-type", lambda s: s["volumes"][intent["slots"][0]["volume"]].update(createdRevision=True)),
            ("completion-type", lambda s: s["intents"][intent["id"]].update(prepareCompleted=0)),
            ("scope-type", lambda s: s["intents"][intent["id"]].update(controllerEpoch=float(intent["controllerEpoch"]))),
            ("extra-field", lambda s: s.update(unexpected=None)),
        ]
        for commits in range(4):
            for name, mutate in changes:
                bad = stopped(before, commits); mutate(bad)
                with self.subTest(commits=commits, mutation=name), self.assertRaises((ValueError, KeyError)):
                    v.prerecovery_receipts(before, bad, arm, checkpoint, worker)

    def test_recovery_counts_exactly_four_updates_from_every_quiescent_prefix(self):
        *_, intent, arm, worker, checkpoint, before = fixture()
        ready = dict(revision=30, storeUUID=arm["scope"]["store"], serviceEpoch=uid(), workerUUID=uid(),
                     controllerEpoch=arm["scope"]["controllerEpoch"], controllerKey=arm["scope"]["controllerKey"])
        with patch.object(v, "public_boot", return_value=ready):
            for commits in range(4):
                quiescent = stopped(before, commits)
                after = recovered(quiescent, checkpoint)
                retained = copy.deepcopy((before, quiescent, after))
                with self.subTest(commits=commits):
                    current = v.recovered_receipts(before, quiescent, after, arm, checkpoint, worker, {"boot": {}})
                    self.assertIs(current, after["intents"][intent["id"]])
                    self.assertEqual(current["version"], intent["version"] + commits + 4)
                    self.assertEqual((before, quiescent, after), retained)
                for count in (0, 1, 2, 3, 5, 6, 7):
                    bad = copy.deepcopy(after)
                    bad["intents"][intent["id"]]["version"] = quiescent["intents"][intent["id"]]["version"] + count
                    with self.subTest(commits=commits, recovery_updates=count), self.assertRaises(ValueError):
                        v.recovered_receipts(before, quiescent, bad, arm, checkpoint, worker, {"boot": {}})
                bad = copy.deepcopy(quiescent); bad["revision"] += 1
                with self.subTest(commits=commits, invalid_baseline=True), self.assertRaises(ValueError):
                    v.recovered_receipts(before, bad, after, arm, checkpoint, worker, {"boot": {}})

    def test_explicit_v2_cold_completion_preserves_old_receipts(self):
        evidence = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-lifecycle-evidence.py"))
        *_, intent, arm, worker, checkpoint, before = fixture()
        old = evidence["owner"]()
        old["checkpoint"]["identity"]["store"] = arm["scope"]["store"]
        old["checkpoint"]["identity"]["binding"] = p.digest(b"cengine.storageauthority.binding.v3\0" +
            p.canonical(v.lifecycle.manifest_binding(old["manifest"])))
        arm["scope"].update(v.lifecycle.owner_context(old)[1])
        intent.update(**{k: arm["scope"][k] for k in ("serviceEpoch", "controllerEpoch", "controllerKey")})
        checkpoint.update(v.storage_query(arm, worker))
        current = evidence["successor"](old, True)
        current["checkpoint"]["current"]["directResult"]["revision"] = 30
        current["checkpoint"]["currentService"]["open_revision"] = 30
        v.lifecycle.transition(old, current, arm, storage=True)
        quiescent = stopped(before, 3)
        quiescent["revision"] += 1
        quiescent["intents"][intent["id"]].update(version=intent["version"] + 4, quarantineReason="launch retirement")
        after = recovered(quiescent, checkpoint)
        saved = copy.deepcopy((before, after, current))
        self.assertIs(v.recovered_receipts(before, quiescent, after, arm, checkpoint, worker, current),
                      after["intents"][intent["id"]])
        self.assertEqual((before, after, current), saved)
        for revision in (22, 21.0):
            bad = copy.deepcopy(after)
            bad["intents"][intent["id"]]["slots"][2]["receipt"]["revision"] = revision
            with self.assertRaises(ValueError):
                v.recovered_receipts(before, quiescent, bad, arm, checkpoint, worker, current)
        # A valid same-E API takeover, or the old C, cannot stand in for cold completion.
        for wrong in (old, evidence["successor"](old)):
            with self.assertRaises(ValueError):
                v.recovered_receipts(before, quiescent, after, arm, checkpoint, worker, wrong)

    def test_identical_old_receipts_operations_digests_and_complete_set(self):
        *_, intent, arm, worker, checkpoint, state = fixture()
        after = recovered(state, checkpoint)
        # public_boot's full schema is separately covered by RTM099. Only its
        # validated revision feeds this pure old-receipt ordering oracle.
        ready = dict(revision=30, storeUUID=arm["scope"]["store"], serviceEpoch=uid(), workerUUID=uid(),
                     controllerEpoch=arm["scope"]["controllerEpoch"], controllerKey=arm["scope"]["controllerKey"])
        with patch.object(v, "public_boot", return_value=ready):
            owner = {"boot": {}}
            self.assertIs(v.recovered_receipts(state, state, after, arm, checkpoint, worker, owner), after["intents"][intent["id"]])
            request = p.decode(base64.b64decode(after["operations"][intent["completeOperation"]]), 65536)
            self.assertEqual(request["complete_prepare"]["attestation"],
                             dict(prepare=intent["prepare"], succeeded=True, clean_copy_up=True))
            wrong_wire = copy.deepcopy(after)
            attestation = request["complete_prepare"]["attestation"]
            attestation["cleanCopyUp"] = attestation.pop("clean_copy_up")
            persist(wrong_wire, intent["completeOperation"], request)
            with self.assertRaisesRegex(ValueError, "exact persisted production request and digest"):
                v.recovered_receipts(state, state, wrong_wire, arm, checkpoint, worker, owner)
            for mutate in (lambda i: i["slots"][0]["receipt"].update(revision=22),
                           lambda i: i["slots"][2]["receipt"].update(revision=31),
                           lambda i: i["slots"][2]["receipt"].update(attachment=uid()),
                           lambda i: i.update(prepareCompleted=False), lambda i: i.update(phase="quarantined"),
                           lambda i: i["guestCompletion"].update(evidenceDigest="6" * 64),
                           lambda i: i["slots"].reverse(), lambda i: i.update(completeOperation=uid()),
                           lambda i: i.update(reserveOperation=uid()), lambda i: i.update(controllerEpoch=True),
                           lambda i: i.update(quarantineReason="uncertain"),
                           lambda i: i.pop("quarantineReason"), lambda i: i.update(quarantineReason=None),
                           *(lambda i, delta=delta: i.update(version=intent["version"] + delta)
                             for delta in (0, 1, 2, 3, 5)),
                           lambda i: i.update(version=True), lambda i: i.pop("version")):
                bad = copy.deepcopy(after); mutate(bad["intents"][intent["id"]])
                with self.assertRaises((ValueError, KeyError)): v.recovered_receipts(state, state, bad, arm, checkpoint, worker, owner)
            for extra in ("operations", "operationDigests", "both"):
                bad = copy.deepcopy(after); operation = uid()
                for ledger in ("operations", "operationDigests"):
                    if extra in (ledger, "both"): bad[ledger][operation] = "0" * 64
                with self.assertRaises((ValueError, KeyError)): v.recovered_receipts(state, state, bad, arm, checkpoint, worker, owner)
            for operation in (intent["slots"][0]["retireOperation"], intent["slots"][2]["retireOperation"], intent["completeOperation"]):
                for ledger in ("operations", "operationDigests"):
                    bad = copy.deepcopy(after); bad[ledger][operation] = "0" * 64
                    with self.assertRaises((ValueError, KeyError)): v.recovered_receipts(state, state, bad, arm, checkpoint, worker, owner)
        for key, wrong in (("revision", 19), ("storeUUID", uid()), ("serviceEpoch", arm["scope"]["serviceEpoch"]),
                           ("workerUUID", worker), ("controllerKey", "0" * 64)):
            with patch.object(v, "public_boot", return_value={**ready, key: wrong}):
                with self.assertRaises((ValueError, KeyError)): v.recovered_receipts(state, state, after, arm, checkpoint, worker, {"boot": {}})


if __name__ == "__main__": unittest.main()
