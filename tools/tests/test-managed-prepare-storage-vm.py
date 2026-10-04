#!/usr/bin/env python3
"""Engine-free RTM099 initial A7 checks; never VM or full-acceptance evidence.

ROOT envelopes below are in-memory test inputs only. The real fixture remains
read-only over production journals; every native/process/SDK edge is doubled.
"""
import ast
import base64
import copy
import ctypes
from contextlib import ExitStack
from dataclasses import replace
import errno
from pathlib import Path
import runpy
import signal
import stat
import sys
from types import MethodType, ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import harness
import managed_prepare_faults as p
import managed_prepare_service_faults as service
import managed_prepare_storage_vm_faults as vm

# run_path does not execute either test file's __main__ block.
SERVICE = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-service.py"))
uid, encode, envelope = (SERVICE[name] for name in ("uid", "encode", "envelope"))
FIXTURE = SERVICE["FIXTURE"]


def reopen(before):
    """Append one authentic-shaped issue/confirm and service boot transcript."""
    after = copy.deepcopy(before)
    context = service.owner_context(before)[1]
    public = ("test-public-" + uid()).encode()
    key, grant, store = p.digest(public), uid(), before["store"]
    epoch = context["controllerEpoch"]
    issue = envelope("issueTakeoverGrant", dict(grant_id=grant, store=store,
        expected_epoch=epoch, candidate=dict(public_data=base64.b64encode(public).decode())))
    issued = envelope("issueTakeoverGrant", dict(grant=dict(id=grant, store=store,
        expected_epoch=epoch, new_key=key), signature=base64.b64encode(b"x" * 64).decode()), issue["request_id"])
    confirm = envelope("confirmTakeover", dict(store=store, grant_id=grant,
        controller=dict(epoch=epoch + 1, key=key)))
    confirmed = envelope("confirmTakeover", dict(controller=dict(epoch=epoch + 1, key=key)), confirm["request_id"])
    after["transitions"].append(dict(zip(("issue", "issued", "confirm", "confirmed"),
        map(encode, (issue, issued, confirm, confirmed)))))
    boot = copy.deepcopy(vm.current_boot(before))
    boot["binding"].update(shimLaunchUUID=uid(), guestBootNonce=uid())
    boot["ready"].update(serviceEpoch=uid(), workerUUID=uid(), revision=boot["ready"]["revision"] + 10,
        controllerEpoch=context["controllerEpoch"], controllerKey=context["controllerKey"],
        tlsRootDER=encode(uid()), serverDER=encode(uid()), serverKey=p.digest(uid().encode()))
    after.setdefault("serviceTransitions", []).append(dict(boot=boot, afterControllerTransitions=len(after["transitions"])))
    after["revision"] += 10
    return after


def owners():
    before, _, _ = SERVICE["owners"]()
    before["rootPublicKey"] = base64.b64encode(b"r" * 32).decode()
    before["boot"]["initramfsSHA256"] = "a" * 64
    before["boot"]["ready"].update(workerUUID=uid(), controllerEpoch=1, controllerKey="c" * 64,
        bootstrapKey=p.digest(bytes.fromhex("302a300506032b6570032100") + b"r" * 32),
        tlsRootDER=encode("original TLS root"), serverDER=encode("original server"), serverKey="b" * 64)
    before["workerReplacements"] = []
    return before, reopen(before), dict(scope=service.owner_context(before)[1])


def retry_values():
    previous, _, _, capture, candidate = SERVICE["V1"]["values"]()
    previous["binding"] = dict(shimLaunchUUID=previous["launch"], guestBootNonce=uid())
    previous["credentials"] = [dict(certificateSHA256="3" * 64)]
    candidate.update(version=3, profile=p.FULL_PROFILE)
    context = {k: previous[k] for k in ("store", "serviceEpoch", "controllerEpoch", "controllerKey")}
    context.update(serviceEpoch=uid(), controllerEpoch=previous["controllerEpoch"] + 1, controllerKey="2" * 64)
    candidate["scope"].update(context)
    return previous, capture, candidate, context


def drain_states(intent, arm, recovered_owner):
    before = dict(store=arm["scope"]["store"], revision=10, intents={intent["id"]: copy.deepcopy(intent)}, operations={}, operationDigests={})
    after = copy.deepcopy(before); after["revision"] += 3
    failed = after["intents"][intent["id"]]; failed.update(phase="quarantined", cleanUnmount=False, quarantineReason="recovering interrupted execution")
    for slot in failed["slots"]:
        if slot["role"] != "prepare": continue
        operation = slot["retireOperation"]
        raw = p.canonical(dict(id=0, retire=dict(operation=operation, store=failed["store"],
            volume=slot["volume"], attachment=slot["attachment"], launch=failed["launch"])))
        after["operations"][operation] = base64.b64encode(raw).decode()
        after["operationDigests"][operation] = p.digest(raw)
        slot["receipt"] = dict(store=failed["store"], volume=slot["volume"], attachment=slot["attachment"],
            prepare=failed["prepare"], launch=failed["launch"],
            revision=vm.current_boot(recovered_owner)["ready"]["revision"] + 2)
    return before, after


class SelectionAndContextTests(unittest.TestCase):
    def test_closed_storage_selector_and_no_full_acceptance(self):
        dispatch = Mock(return_value=object())
        run = SERVICE["function"]("run_storage_a7_shard", _run_prepare_case=dispatch)
        args = dict(probe=None, probe_sha256=None, source_sha256=None, expected_commit=None, evidence=None)
        daemon = object()
        for profile in (None, "", "*", True, p.PROFILE, p.EARLY_PROFILE, p.FULL_PROFILE + " "):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                run(daemon, profile=profile, **args)
        dispatch.assert_not_called()
        self.assertIs(run(daemon, profile=p.FULL_PROFILE, **args), dispatch.return_value)
        dispatch.assert_called_once_with(daemon, profile=p.FULL_PROFILE,
            staged=dict(rtm="RTM-099", boundary="storage-vm-first-child-published", fullAcceptance=False),
            fault_case="first-child-published", early=True, full=True, storage_restart=True, **args)
        with self.assertRaises(ValueError):
            p.aggregate_full([dispatch.call_args.kwargs["staged"]] * 9)

    def test_service_retry_exact_context_and_unchanged_inputs(self):
        previous, capture, candidate, context = retry_values()
        snapshot = copy.deepcopy((previous, capture, candidate, context))
        arm = p.full_arm_candidate(candidate, capture, previous, "normal", service_recovery=context)
        self.assertEqual({k: arm["scope"][k] for k in context}, context)
        self.assertEqual((previous, capture, candidate, context), snapshot)
        self.assertIsNot(arm, candidate)
        with self.assertRaises(ValueError):
            p.full_arm_candidate(candidate, capture, previous, "normal")

    def test_service_context_requires_exact_new_e_same_s_c_plus_one_fresh_key(self):
        previous, capture, candidate, context = retry_values()
        changes = [("store", uid()), ("serviceEpoch", previous["serviceEpoch"]),
            ("serviceEpoch", "not-uuid"), ("serviceEpoch", True),
            ("controllerEpoch", True), ("controllerEpoch", 0), ("controllerEpoch", 1),
            ("controllerEpoch", 3), ("controllerKey", previous["controllerKey"]),
            ("controllerKey", "F" * 64)]
        contexts = [{**context, k: value} for k, value in changes]
        contexts += [{k: v for k, v in context.items() if k != missing} for missing in context]
        contexts += [{**context, "extra": 1}]
        for bad in contexts:
            with self.subTest(context=bad), self.assertRaises(ValueError):
                p.full_arm_candidate(candidate, capture, previous, "normal", service_recovery=bad)
        for key in context:
            bad = copy.deepcopy(candidate)
            bad["scope"][key] = previous[key]
            if key == "store": bad["scope"][key] = uid()
            with self.subTest(candidate=key), self.assertRaises(ValueError):
                p.full_arm_candidate(bad, capture, previous, "normal", service_recovery=context)

    def test_recovery_is_normal_only_and_mutually_exclusive(self):
        previous, capture, candidate, context = retry_values()
        for case in p.FULL_CASES:
            if case == "normal": continue
            with self.subTest(case=case), self.assertRaises(ValueError):
                p.full_arm_candidate(candidate, capture, previous, case, service_recovery=context)
        with self.assertRaisesRegex(ValueError, "one recovery context"):
            p.full_arm_candidate(candidate, capture, previous, "normal",
                service_recovery=context, controller_recovery=context)

    def test_default_and_old_controller_recovery_contract_unchanged(self):
        previous, capture, candidate, context = retry_values()
        candidate["scope"].update({k: previous[k] for k in context})
        self.assertEqual(p.full_arm_candidate(candidate, capture, previous, "normal")["scope"], candidate["scope"])
        old_controller_context = {**context, "serviceEpoch": previous["serviceEpoch"]}
        candidate["scope"].update(old_controller_context)
        self.assertEqual(p.full_arm_candidate(candidate, capture, previous, "normal",
            controller_recovery=old_controller_context)["scope"], candidate["scope"])
        with self.assertRaises(ValueError):
            p.full_arm_candidate(candidate, capture, previous, "normal", service_recovery=old_controller_context)
        candidate["scope"].update(context)
        with self.assertRaises(ValueError):
            p.full_arm_candidate(candidate, capture, previous, "normal", controller_recovery=context)

    def test_service_retry_still_requires_fresh_guest_and_prepare_credentials(self):
        previous, capture, candidate, context = retry_values()
        changes = [lambda c: c["scope"].update(intent=previous["id"]),
            lambda c: c["scope"].update(prepare=previous["prepare"]),
            lambda c: (c["scope"].update(launch=previous["launch"]), c["binding"].update(shimLaunchUUID=previous["launch"])),
            lambda c: c["binding"].update(guestBootNonce=previous["binding"]["guestBootNonce"]),
            lambda c: c["slots"][1].update(attachment=previous["slots"][1]["attachment"]),
            lambda c: c["credentials"][0].update(key=previous["slots"][0]["key"]),
            lambda c: c["credentials"][0].update(certificateSHA256="3" * 64)]
        for index, change in enumerate(changes):
            bad = copy.deepcopy(candidate); change(bad)
            with self.subTest(change=index), self.assertRaises(ValueError):
                p.full_arm_candidate(bad, capture, previous, "normal", service_recovery=context)

    def test_fixture_missing_pending_owner_or_settled_start_fails_before_restart(self):
        tree = ast.parse(FIXTURE.read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and isinstance(n.test, ast.Name) and n.test.id == "storage_restart"
            and "restart_storage_at_a7" in ast.unparse(n))
        guard = compile(ast.Module(body=[branch.body[1]], type_ignores=[]), "actual-storage-guard", "exec")
        for status, pending in ((None, None), (0, object()), (52, object()), (-9, object())):
            start = Mock(); start.poll.return_value = status
            with self.subTest(status=status, pending=pending), self.assertRaisesRegex(ValueError, "live held PREPARE"):
                exec(guard, dict(proof=p, start=start, pending_owner=pending))
        text = ast.unparse(ast.Module(body=branch.body, type_ignores=[]))
        self.assertNotIn("publish(", text)
        self.assertNotIn("SIGKILL", text)
        self.assertIn("remaining, start, read_state, metadata['storageInitramfsSHA256'])", text)


class OwnerTests(unittest.TestCase):
    def test_exact_initial_and_nonempty_history_reopen(self):
        before, after, arm = owners()
        for _ in range(2):
            saved = copy.deepcopy((before, after, arm))
            result = vm.storage_owner_transition(before, after, arm)
            self.assertEqual(result, service.owner_context(after)[1])
            self.assertEqual(result["controllerEpoch"], arm["scope"]["controllerEpoch"] + 1)
            self.assertNotEqual(result["serviceEpoch"], arm["scope"]["serviceEpoch"])
            self.assertEqual(after["boot"], before["boot"])
            self.assertEqual((before, after, arm), saved)
            before = after; after = reopen(before); arm = dict(scope=service.owner_context(before)[1])

    def test_persistent_backing_initial_boot_worker_and_current_boot_invariants(self):
        before, after, arm = owners()
        changes = [lambda n: n.update(store=uid()), lambda n: n["root"].update(inode=5),
            lambda n: n["backing"].update(inode=41), lambda n: n.update(bytes=8192),
            lambda n: n.update(rootPublicKey=encode("changed-key")),
            lambda n: n["boot"]["binding"].update(guestBootNonce=uid()),
            lambda n: n.update(workerReplacements=[dict(unexpected=True)]),
            lambda n: n.update(revision=before["revision"]),
            lambda n: vm.current_boot(n)["ready"].update(revision=before["boot"]["ready"]["revision"]),
            lambda n: vm.current_boot(n)["ready"].update(workerUUID=before["boot"]["ready"]["workerUUID"]),
            lambda n: vm.current_boot(n)["ready"].pop("workerUUID"),
            lambda n: vm.current_boot(n)["ready"].update(workerUUID="invalid"),
            lambda n: vm.current_boot(n)["ready"].update(serviceEpoch=before["boot"]["ready"]["serviceEpoch"]),
            lambda n: vm.current_boot(n)["binding"].update(ext4UUID=uid()),
            lambda n: vm.current_boot(n)["binding"].update(shimLaunchUUID=before["boot"]["binding"]["shimLaunchUUID"]),
            lambda n: vm.current_boot(n)["binding"].update(guestBootNonce=before["boot"]["binding"]["guestBootNonce"]),
            lambda n: n["serviceTransitions"][-1].update(afterControllerTransitions=0)]
        changes += [lambda n, key=k: n.update({key: "pending"})
            for k in ("pendingIssue", "pendingIssued", "pendingConfirm", "pendingService")]
        for index, change in enumerate(changes):
            bad = copy.deepcopy(after); change(bad)
            with self.subTest(change=index), self.assertRaises((ValueError, KeyError)):
                vm.storage_owner_transition(before, bad, arm)
        for key, value in arm["scope"].items():
            bad = copy.deepcopy(arm); bad["scope"][key] = value + 1 if type(value) is int else uid()
            with self.subTest(scope=key), self.assertRaises(ValueError):
                vm.storage_owner_transition(before, after, bad)

    def test_exact_root_and_service_history_prefixes_not_just_counts(self):
        initial, before, _ = owners()
        after, arm = reopen(before), dict(scope=service.owner_context(before)[1])
        changes = [lambda n: n["transitions"].pop(), lambda n: n["serviceTransitions"].pop(),
            lambda n: n["serviceTransitions"][0]["boot"]["ready"].update(workerUUID=uid()),
            lambda n: n["serviceTransitions"][-1].update(afterControllerTransitions=1),
            lambda n: n["transitions"][0].update(issue=encode(envelope("wrong-operation", {})))]
        # Reformatting an otherwise valid envelope still changes retained history.
        changes.append(lambda n: n["transitions"][0].update(issue=base64.b64encode(
            base64.b64decode(n["transitions"][0]["issue"]) + b"\n").decode()))
        for index, change in enumerate(changes):
            bad = copy.deepcopy(after); change(bad)
            with self.subTest(change=index), self.assertRaises(ValueError):
                vm.storage_owner_transition(before, bad, arm)
        with self.assertRaises(ValueError):
            vm.storage_owner_transition(initial, after, dict(scope=service.owner_context(initial)[1]))
        with self.assertRaises(ValueError):
            vm.storage_owner_transition(before, before, arm)


class SecurityRegressionTests(unittest.TestCase):
    def test_filesystem_uuid_uses_native_spelling_without_v4_assumption(self):
        before, _, _ = owners()
        filesystem = "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6"
        before["backing"]["volumeUUID"] = filesystem
        before["boot"]["diskIdentity"]["volumeUUID"] = filesystem
        before["boot"]["binding"]["ext4UUID"] = filesystem.lower()
        after = reopen(before); arm = dict(scope=service.owner_context(before)[1])
        saved = copy.deepcopy((before, after))
        vm.storage_owner_transition(before, after, arm)
        self.assertEqual((before, after), saved)
        nil_boot = copy.deepcopy(vm.current_boot(after))
        nil_boot["binding"]["ext4UUID"] = "00000000-0000-0000-0000-000000000000"
        with self.assertRaisesRegex(ValueError, "nonzero canonical ext4 UUID"): vm.public_boot(nil_boot)
        for value in (None, "", "invalid", True, filesystem.lower()):
            bad = copy.deepcopy(after); vm.current_boot(bad)["diskIdentity"]["volumeUUID"] = value
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                vm.storage_owner_transition(before, bad, arm)

    def test_new_boot_requires_exact_old_controller_and_full_security_binding(self):
        before, after, arm = owners()
        ready = vm.current_boot(after)["ready"]
        mutations = [lambda n: vm.current_boot(n)["ready"].update(controllerEpoch=2),
            lambda n: vm.current_boot(n)["ready"].update(controllerEpoch=True),
            lambda n: vm.current_boot(n)["ready"].update(controllerKey="d" * 64),
            lambda n: vm.current_boot(n).update(initramfsSHA256="d" * 64),
            lambda n: vm.current_boot(n)["ready"].update(bootstrapKey="d" * 64),
            lambda n: n.update(rootPublicKey=base64.b64encode(b"x" * 32).decode()),
            lambda n: n["serviceTransitions"][-1].update(extra=True),
            lambda n: n["serviceTransitions"][-1].update(afterControllerTransitions=True)]
        mutations += [lambda n, k=k: vm.current_boot(n)["ready"].update({k: before["boot"]["ready"][k]})
            for k in ("workerUUID", "serverKey", "tlsRootDER", "serverDER")]
        for part in (None, "binding", "ready", "diskIdentity"):
            mutations.append(lambda n, part=part: (vm.current_boot(n) if part is None else vm.current_boot(n)[part]).update(extra=1))
        for k in ready:
            mutations.append(lambda n, k=k: vm.current_boot(n)["ready"].pop(k))
        for k in ("tlsRootDER", "serverDER"):
            for value in ("", "!", "YQ==\n", base64.b64encode(b"x" * 16385).decode(), True):
                mutations.append(lambda n, k=k, value=value: vm.current_boot(n)["ready"].update({k: value}))
        for i, change in enumerate(mutations):
            bad = copy.deepcopy(after); change(bad)
            with self.subTest(change=i), self.assertRaises((ValueError, KeyError, TypeError)):
                vm.storage_owner_transition(before, bad, arm)

    def test_pre_and_post_reopen_drain_are_distinct_durable_events(self):
        owner_before, owner_after, _ = owners()
        previous, capture, candidate, _ = retry_values()
        candidate["scope"].update(service.owner_context(owner_before)[1]); previous.update(service.owner_context(owner_before)[1])
        arm = p.full_arm_candidate(candidate, capture, previous, "first-child-published")
        intent = {("id" if k == "intent" else k): v for k, v in arm["scope"].items()}
        intent.update(phase="prepareAdmitted", prepareCompleted=False, cleanUnmount=False, slots=copy.deepcopy(arm["slots"]))
        for slot in intent["slots"]:
            slot.update(retireOperation=uid(), registerOperation=uid())
            if slot["role"] == "prepare": slot["key"] = arm["credentials"][0]["key"]
        before, after = drain_states(intent, arm, owner_after)
        prepared = next(s for s in intent["slots"] if s["role"] == "prepare")
        op = prepared["retireOperation"]
        result = vm.recovered_prepare_drain(before, after, arm, owner_after)
        self.assertEqual(result["drains"][0]["operation"], op)
        self.assertGreater(result["drains"][0]["receipt"]["revision"], result["bootRevision"])
        for which in ("receipt", "operation", "digest"):
            bad = copy.deepcopy(before)
            if which == "receipt": next(s for s in bad["intents"][intent["id"]]["slots"] if s["role"] == "prepare")["receipt"] = {}
            elif which == "operation": bad["operations"][op] = after["operations"][op]
            else: bad["operationDigests"][op] = after["operationDigests"][op]
            with self.subTest(prefault=which), self.assertRaises(ValueError): vm.recovered_prepare_drain(bad, after, arm, owner_after)
        def receipt(state): return next(s for s in state["intents"][intent["id"]]["slots"] if s["role"] == "prepare")["receipt"]
        mutations = [lambda n: n["operations"].pop(op), lambda n: n["operationDigests"].update({op:"0" * 64}),
            lambda n: receipt(n).update(revision=result["bootRevision"]), lambda n: receipt(n).update(revision=True),
            lambda n: receipt(n).update(attachment=uid()), lambda n: n.update(revision=before["revision"]),
            lambda n: n["operations"].update({op:base64.b64encode(p.canonical(dict(id=1,retire={}))).decode()})]
        for i, mutate in enumerate(mutations):
            bad = copy.deepcopy(after); mutate(bad)
            with self.subTest(postfault=i), self.assertRaises((ValueError, KeyError)):
                vm.recovered_prepare_drain(before, bad, arm, owner_after)


class RestartTests(unittest.TestCase):
    def run_restart(self, fault=None, *, vm_cut=False, two_volume=False, exit_phase="api-ready", start_exit=None):
        """Real parent restart + Daemon.start; native selection/edges are doubles.

        Legacy journal inputs here exercise parent ordering, not current native
        launch selection (covered by test-managed-prepare-lifecycle-evidence).
        """
        before, after, _ = owners()
        previous, _, _, capture, candidate = SERVICE["V1"]["values"]()
        candidate.update(version=3, profile=p.FULL_PROFILE)
        candidate["scope"].update(service.owner_context(before)[1])
        previous.update(service.owner_context(before)[1])
        arm = p.full_arm_candidate(candidate, capture, previous, "first-child-published")
        checkpoint = SERVICE["V1"]["observed"](arm)
        checkpoint.update(version=3, profile=p.FULL_PROFILE,
            filesystemUUID=before["boot"]["binding"]["ext4UUID"].replace("-", ""))
        intent = {("id" if k == "intent" else k): v for k, v in arm["scope"].items()}
        intent.update(phase="prepareAdmitted", prepareCompleted=False, slots=copy.deepcopy(arm["slots"]), cleanUnmount=False)
        for slot in intent["slots"]:
            slot.update(retireOperation=uid(), registerOperation=uid())
            if slot["role"] == "prepare": slot["key"] = arm["credentials"][0]["key"]
        pre_state, post_state = drain_states(intent, arm, after)
        if fault == "prefault-receipt": next(s for s in pre_state["intents"][intent["id"]]["slots"] if s["role"] == "prepare")["receipt"] = {}
        if fault == "prefault-retire": pre_state["operations"][intent["slots"][0]["retireOperation"]] = "prior"
        if fault == "stale-drain": next(s for s in post_state["intents"][intent["id"]]["slots"] if s["role"] == "prepare")["receipt"]["revision"] = vm.current_boot(after)["ready"]["revision"]
        if fault == "missing-drain-operation": post_state["operations"].clear()
        if fault == "wrong-filesystem": checkpoint["filesystemUUID"] = "1" * 32
        if fault == "completed-prepare": intent["prepareCompleted"] = True
        if fault == "runtime-issued":
            next(s for s in intent["slots"] if s["role"] == "runtime")["key"] = "1" * 64
        d = SimpleNamespace(binary=Path("/owned/cengine"), root=Path("/owned/root"), socket=Path("/owned/run/socket"),
            kernel=Path("/assets/kernel"), container_initramfs=Path("/assets/init"), storage_initramfs=Path("/assets/storage"),
            work=Path("/owned"), log_path=Mock(), resource_update_failure_file=Path("/owned/failure"), root_retained=True)
        args = (str(d.binary), "daemon", "--root", str(d.root), "--socket", str(d.socket), "--kernel", str(d.kernel),
            "--container-initramfs", str(d.container_initramfs), "--storage-initramfs", str(d.storage_initramfs),
            "--automatic-ipv4-pool", "10.192.0.0/12", "--automatic-ipv6-prefix", "fdcc::/16")
        api = harness.RuntimeProcess(42, executable=str(d.binary), arguments=args, identity=(10, 2, 300), pidversion=8)
        fresh_api = replace(api, pid=43, identity=(11, 3, 301), pidversion=9)
        workload = harness.RuntimeProcess(44, identity=(10, 4, 302), pidversion=10)
        def storage_process(owner_record, pid):
            owner = service.owner_context(owner_record)[0]
            generation = d.root / "infrastructure/storage-shim-generations" / owner["shimLaunchUUID"]
            digest = "a" * 64
            proc = harness.RuntimeProcess(pid, executable=str(d.binary), identity=(pid, 5, pid + 300), pidversion=pid,
                arguments=(str(d.binary), "vm-shim", "--spec", str(generation / "spec.json"), "--spec-sha256", digest, "--storage-disk-fd", "9"))
            return proc
        storage, fresh_storage = storage_process(before, 45), storage_process(after, 46)
        def storage_target(daemon, owner, census):
            # Select only storage-generation shims, just like the native selector;
            # ACK workloads/peers are also vm-shims but live under containers/.
            # Still require the exact pinned storage incarnation in this census.
            self.assertIs(daemon, d)
            expected = {service.owner_context(before)[0]["shimLaunchUUID"]: (before, storage),
                service.owner_context(after)[0]["shimLaunchUUID"]: (after, fresh_storage)}
            record, process = expected[owner["shimLaunchUUID"]]
            p.require(owner == service.owner_context(record)[0], "exact test owner projection")
            directory = daemon.root / "infrastructure/storage-shim-generations"
            selected = [v for v in census if len(v.arguments) >= 4
                and v.arguments[1:3] == ("vm-shim", "--spec")
                and Path(v.arguments[3]).parent.parent == directory]
            p.require(selected == [process], "exact test storage incarnation and census")
            return process
        protected = [replace(workload, pid=47, identity=(12, 5, 303), pidversion=11)] if vm_cut else []
        if fault == "api-reparent":
            workload = replace(workload, parent_pid=api.pid)
            protected = [replace(v, parent_pid=api.pid) for v in protected]
        census = [api, workload, storage, *protected]
        live = {v.pid: v for v in census}
        queues = {storage.pid: [], workload.pid: []}
        order, records, waiters = [], [], []
        start = Mock(); start.poll.return_value = 0 if fault == "settled-start-before" else None
        old_handle = Mock(pid=api.pid, returncode=None); old_handle.poll.return_value = None
        fresh_handle = Mock(pid=fresh_api.pid, returncode=None); fresh_handle.poll.return_value = None
        d.process = old_handle
        def event(pid):
            return SimpleNamespace(ident=pid, filter=vm.select.KQ_FILTER_PROC, flags=0, fflags=vm.select.KQ_NOTE_EXIT)
        def workload_exit():
            if fault != "workload-still-live": live.pop(workload.pid, None)
            queues[workload.pid].append(event(workload.pid)); order.append("workload-exit")
            if fault == "wrong-workload-exit": queues[workload.pid][-1].ident += 1
            if fault == "error-workload-exit": queues[workload.pid][-1].flags = vm.select.KQ_EV_ERROR
            if fault == "missing-workload-event": queues[workload.pid].clear()
        def scheduled_exit(phase):
            if (vm_cut or two_volume) and exit_phase == phase:
                workload_exit()
                start.poll.return_value = start_exit
        def kqueue():
            waiter = Mock(); selected = None
            def control(changes, maximum, timeout=None):
                nonlocal selected
                if changes is not None:
                    selected = changes[0].ident
                    self.assertEqual(changes[0].filter, vm.select.KQ_FILTER_PROC)
                    self.assertEqual(changes[0].fflags, vm.select.KQ_NOTE_EXIT)
                    self.assertEqual(len(changes), 1)
                    if (vm_cut or two_volume) and selected == workload.pid:
                        self.assertEqual((maximum, timeout), (0, 0))
                        self.assertEqual(changes[0].flags, vm.select.KQ_EV_ADD |
                            vm.select.KQ_EV_ENABLE | vm.select.KQ_EV_ONESHOT)
                        if fault == "prekill-workload-loss": live.pop(workload.pid)
                    order.append("watch-" + str(selected)); return []
                if timeout == 0: order.append("birth-watch-check")
                values = queues[selected][:maximum]; del queues[selected][:maximum]
                return values
            waiter.control.side_effect = control; waiters.append(waiter)
            return waiter
        def deliver(token, selected_signal):
            self.assertEqual(list(token._obj), [0, 0, 0, 0, 0, storage.pid, 0, storage.pidversion])
            self.assertEqual(selected_signal, signal.SIGKILL)
            order.append("storage-syscall")
            if vm_cut or two_volume: self.assertIn("watch-44", order)
            if fault == "bad-delivery": return errno.ESRCH
            if fault != "storage-still-live": live.pop(storage.pid)
            queues[storage.pid].append(event(storage.pid))
            if fault == "wrong-storage-exit": queues[storage.pid][0].ident += 1
            if fault == "error-storage-exit": queues[storage.pid][0].flags = vm.select.KQ_EV_ERROR
            if fault == "wrong-storage-filter": queues[storage.pid][0].filter = 0
            if fault == "missing-storage-note": queues[storage.pid][0].fflags = 0
            if fault == "missing-storage-event": queues[storage.pid].clear()
            if fault == "early-api-loss": live.pop(api.pid)
            if fault == "early-workload-loss": workload_exit()
            if fault == "early-storage-replacement": live[fresh_storage.pid] = fresh_storage
            if fault == "ambiguous-storage-exit": live[storage.pid] = replace(storage, pidversion=storage.pidversion + 1)
            if fault == "settled-start-after-storage": start.poll.return_value = 52
            if fault == "protected-loss": live.pop(protected[0].pid)
            if fault == "protected-replaced": live[protected[0].pid] = replace(protected[0], pidversion=999)
            scheduled_exit("storage")
            return 0
        native_call = Mock(side_effect=deliver)
        def stop(*, kill=False):
            order.append("api-stop")
            live.pop(d.process.pid, None)
            d.process.returncode = -signal.SIGTERM if fault == "bad-api-exit" or not kill else -signal.SIGKILL
            d.process.poll.return_value = d.process.returncode
            if kill and fault == "exit-before-start": workload_exit()
            scheduled_exit("api-stop")
            if fault == "api-reparent":
                for pid, value in list(live.items()):
                    if value.parent_pid == api.pid: live[pid] = replace(value, parent_pid=1)
        d.stop = Mock(side_effect=stop); d.retain_root = Mock()
        def spawned(command, **kwargs):
            self.assertEqual(command, list(args))
            if fault == "exit-before-birth": workload_exit()
            order.append("api-spawn"); live[fresh_api.pid] = fresh_api
            scheduled_exit("api-birth")
            return fresh_handle
        def ready(*args, **kwargs):
            order.append("api-ready")
            self.assertIn("storage-recovery-api-born", order)
            if fault == "startup-failure": raise RuntimeError("mock readiness failure")
            if not (vm_cut or two_volume): workload_exit()
            scheduled_exit("api-ready")
            live[fresh_storage.pid] = fresh_storage
            if fault == "wrong-new-storage-identity": live[fresh_storage.pid] = replace(fresh_storage, identity=(99, 6, 999))
            if fault == "old-storage-returned": live[storage.pid] = storage
            return SimpleNamespace(returncode=0, stdout="OK")
        subprocess = SimpleNamespace(Popen=Mock(side_effect=spawned), run=Mock(side_effect=ready), DEVNULL=-3, STDOUT=-2, PIPE=-1)
        def fail(*args, **kwargs): raise RuntimeError("mock retained startup failure")
        d._qualify_root_permissions = False
        d.start = MethodType(SERVICE["production_daemon_start"](subprocess=subprocess,
            time=SimpleNamespace(monotonic=lambda: 1, sleep=Mock()), os=SimpleNamespace(environ={}),
            managed_storage_arguments=lambda _: [], compatibility_environment=lambda: {},
            pytest=SimpleNamespace(fail=fail), terminate_compatibility_runtime=Mock()), d)
        def record(phase, **values):
            order.append(phase); records.append((phase, values))
            if phase == "storage-only-death-joined":
                expected_live = [api, *protected]
                if not (vm_cut or two_volume) or exit_phase != "storage": expected_live.append(workload)
                self.assertEqual(live, {v.pid: v for v in expected_live})
                self.assertEqual(values["workloadSurvived"], workload in expected_live)
                if (vm_cut or two_volume) and exit_phase == "storage": self.assertEqual(start.poll(), start_exit)
                else: self.assertIsNone(start.poll())
                if fault == "settled-start-before-api": start.poll.return_value = 52
            if phase == "storage-SIGKILL-intent" and fault == "wrong-old-storage-identity":
                live[storage.pid] = replace(storage, identity=(99, 6, 999))
        def native(pid):
            if pid == fresh_api.pid and fault == "bad-api-birth": return replace(fresh_api, identity=None)
            if pid == fresh_api.pid and fault == "exit-during-birth-lookup":
                # Queued exit wins even if the native workload result still matches.
                queues[workload.pid].append(event(workload.pid))
            if pid == workload.pid and "birth-watch-check" in order and fault == "exit-during-birth":
                workload_exit(); return None
            return live.get(pid)
        directory = Mock(); directory.__enter__ = Mock(return_value=directory); directory.__exit__ = Mock(return_value=False)
        directory.fd = 999; directory.read.return_value = (b"/owned/cengine\n", None)
        directories = Mock(return_value=directory); directories.stamp.return_value = (3, 4)
        capture_module = ModuleType("storage_backend_proof"); capture_module.capture_backend_root = Mock()
        docker, requests = ModuleType("docker"), ModuleType("requests")
        docker.__version__, requests.__version__ = "7.1.0", "2.32.3"
        def no_sleep(_): raise TimeoutError("mock exit deadline")
        state_reads = [(record, p.digest(p.canonical(record))) for record in (before, after)]
        second_pre = copy.deepcopy(pre_state)
        if fault == "late-prefault-retire": second_pre["operations"][intent["slots"][0]["retireOperation"]] = "late"
        read_state = Mock(side_effect=[(None, v, dict(state_sha256=p.digest(p.canonical(v)))) for v in (pre_state, second_pre, post_state)])
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"storage_backend_proof": capture_module, "docker": docker, "requests": requests}))
            stack.enter_context(patch.object(vm.select, "kqueue", side_effect=kqueue))
            stack.enter_context(patch.object(vm.select, "kevent", side_effect=lambda ident, **kw: SimpleNamespace(ident=ident, **kw)))
            stack.enter_context(patch.object(ctypes, "CDLL", return_value=SimpleNamespace(proc_signal_with_audittoken=native_call)))
            stack.enter_context(patch.object(harness, "_kernel_process", side_effect=native))
            stack.enter_context(patch.object(p, "Directory", directories))
            stack.enter_context(patch.object(vm.os, "fstat", return_value=None))
            stack.enter_context(patch.object(p, "verify_full_ledger", side_effect=lambda *_: order.append("ledger-verified")))
            stack.enter_context(patch.object(vm.time, "sleep", side_effect=no_sleep))
            stack.enter_context(patch.object(vm, "read_public", side_effect=state_reads))
            stack.enter_context(patch.object(vm, "storage_target", side_effect=storage_target))
            stack.enter_context(patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=3, st_ino=40, st_size=4096)))
            stack.enter_context(patch.object(Path, "resolve", lambda path: path))
            stack.enter_context(patch.object(Path, "unlink"))
            stack.enter_context(patch.object(Path, "exists", return_value=True))
            if fault == "no-delivery": stack.enter_context(patch.object(harness, "_signal_runtime_process"))
            try:
                result = vm.restart_storage_at_a7(d, workload, census, intent, arm, checkpoint, None, {}, record,
                    lambda: list(live.values()), lambda: 1, start, read_state,
                    "0" * 64 if fault == "wrong-asset" else before["boot"]["initramfsSHA256"])
            finally:
                for waiter in waiters: waiter.close.assert_called_once_with()
        if fault == "api-reparent": protected = [replace(v, parent_pid=1) for v in protected]
        # Retain the workload sentinel for the single-owner shared parent tail.
        self.assertEqual(result, ([fresh_api, workload, fresh_storage, *protected], service.owner_context(after)[1], state_reads[1]))
        d.stop.assert_called_once_with(kill=True)
        native_call.assert_called_once()
        self.assertEqual(len(waiters), 2)
        self.assertEqual(order.count("ledger-verified"), 2)
        phases = ["storage-SIGKILL-intent", "ledger-verified", "watch-45", "storage-syscall", "storage-SIGKILL-delivered",
            "storage-only-death-joined", "watch-44", "api-recovery-SIGKILL-intent", "api-stop", "api-spawn",
            "storage-recovery-api-born", "api-ready", "workload-exit", "storage-reopened-reconciled"]
        if vm_cut or two_volume:
            phases.remove("watch-44"); phases.insert(0, "watch-44")
            phases.remove("workload-exit")
            exit_after = {"storage": "storage-syscall", "api-stop": "api-stop",
                "api-birth": "api-spawn", "api-ready": "api-ready"}[exit_phase]
            phases.insert(phases.index(exit_after) + 1, "workload-exit")
            contained_phase = "storage-two-volume-owners-contained" if two_volume else "storage-exposed-owners-contained"
            phases.insert(phases.index("storage-reopened-reconciled"), contained_phase)
            phase = {"storage": "storage-exit-joined", "api-stop": "api-exit-joined",
                "api-birth": "api-birth", "api-ready": "recovery-ready"}[exit_phase]
            self.assertEqual([v for name, v in records if name == "storage-exposed-owner-exit-observed"],
                [dict(native=p.native_proof(workload), observedAt=phase)])
            if not two_volume:
                self.assertEqual(dict(records)["storage-exposed-owners-contained"], dict(native=[p.native_proof(workload)]))
            self.assertEqual(live, {v.pid: v for v in (fresh_api, fresh_storage, *protected)})
            self.assertLess(order.index("storage-identical-old-completed-set" if two_volume else "storage-new-epoch-drain"), order.index(contained_phase))
        self.assertEqual(sorted(phases, key=order.index), phases)
        self.assertEqual(dict(records)["storage-SIGKILL-delivered"]["proof"],
            {**p.native_proof(storage), "signal": "SIGKILL", "native_result": 0})
        self.assertEqual(dict(records)["storage-SIGKILL-intent"]["sdkVersions"], {"docker": "7.1.0", "requests": "2.32.3"})
        self.assertEqual(dict(records)["storage-reopened-reconciled"]["context"], result[1])
        return result

    def test_complete_storage_only_death_then_explicit_api_recovery(self):
        self.run_restart()

    def test_bad_delivery_and_storage_exit_never_authorize_recovery(self):
        for fault in ("bad-delivery", "no-delivery", "wrong-storage-exit", "error-storage-exit",
                "wrong-storage-filter", "missing-storage-note", "missing-storage-event", "ambiguous-storage-exit"):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.run_restart(fault)
        with self.assertRaisesRegex(TimeoutError, "mock exit deadline"): self.run_restart("storage-still-live")

    def test_early_api_or_workload_loss_and_storage_replacement_fail_closed(self):
        for fault in ("early-api-loss", "early-workload-loss", "early-storage-replacement", "wrong-old-storage-identity"):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.run_restart(fault)

    def test_pending_start_required_at_every_death_boundary(self):
        for fault in ("settled-start-before", "settled-start-after-storage", "settled-start-before-api"):
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.run_restart(fault)

    def test_workload_death_before_or_during_fresh_api_birth_rejected(self):
        for fault in ("exit-before-start", "exit-before-birth", "exit-during-birth", "exit-during-birth-lookup"):
            with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)): self.run_restart(fault)

    def test_recovery_requires_good_api_birth_exit_and_exact_new_storage(self):
        for fault in ("bad-api-exit", "bad-api-birth", "startup-failure", "wrong-workload-exit",
                "error-workload-exit", "missing-workload-event", "wrong-new-storage-identity", "old-storage-returned"):
            with self.subTest(fault=fault), self.assertRaises((ValueError, RuntimeError)): self.run_restart(fault)

    def test_active_prepare_and_exact_physical_witness_required(self):
        for fault in ("wrong-filesystem", "completed-prepare", "runtime-issued", "wrong-asset", "prefault-receipt", "prefault-retire",
                "late-prefault-retire", "stale-drain", "missing-drain-operation"):
            with self.subTest(fault=fault), self.assertRaises((ValueError, KeyError)): self.run_restart(fault)

    def test_fixture_never_writes_owner_journals_or_claims_full_acceptance(self):
        source = ast.parse((ROOT / "Tests/Compatibility/managed_prepare_storage_vm_faults.py").read_text())
        restart = next(n for n in source.body if isinstance(n, ast.FunctionDef) and n.name == "restart_storage_at_a7")
        text = ast.unparse(restart)
        for forbidden in ("write_text", "write_bytes", "publish(", "os.kill", "killpg", "confirmed", "serviceTransitions"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("signal_storage(storage)"), 1)
        self.assertEqual(text.count("daemon.stop(kill=True)"), 1)
        tree = ast.parse(FIXTURE.read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
            and isinstance(n.test, ast.Name) and n.test.id == "storage_restart"
            and "storage-vm-cut-result" in ast.unparse(n))
        result_text = ast.unparse(branch)
        self.assertIn("verify_api_owner_final(daemon, recovered_owner)", result_text)
        self.assertIn("initial-cut-passed", result_text)
        self.assertNotIn("_completed_full_outcome", result_text)


if __name__ == "__main__":
    unittest.main()
