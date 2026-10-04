#!/usr/bin/env python3
"""Engine-free regression only. No native ACK durability claim."""
import argparse
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_active_ack as a
import managed_prepare_faults as p
import managed_storage_recovery as r
import managed_original_followup_parent as followup_parent
import managed_prepare_restart_matrix as matrix
import managed_prepare_vm_boundaries as vm
import managed_stale_consumer as stale
import harness
W = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-worker.py"))
R = W["RECOVERY"]


class ActiveACKTests(unittest.TestCase):
    def test_parent_entry_closed_and_separate(self):
        dispatch = Mock()
        run = W["SERVICE"]["function"]("run_worker_a5_active_ack_shard", _run_prepare_case=dispatch)
        args = dict(probe=None, probe_sha256=None, ack_probe=None, ack_probe_sha256="a" * 64,
            source_sha256=None, expected_commit=None, evidence=None)
        with self.assertRaises(ValueError): run(None, profile=p.PROFILE, **args)
        dispatch.assert_not_called()
        run(None, profile=p.FULL_PROFILE, **args)
        self.assertEqual(dispatch.call_args.kwargs["staged"], dict(rtm="RTM-098", boundary="worker-a5-active-ack", fullAcceptance=False))
        self.assertEqual(len(p.FULL_CASES), 9)

    def test_ack_rejects_early_ack_and_modified_metadata(self):
        fixture = R["WorkerReplacementTests"]()
        before, after = fixture.worker_snapshot(), fixture.worker_snapshot("verify")
        a.unchanged_ack(before, after, command="verify")
        for key in ("ack", "file_fsynced", "parent_fsynced"):
            bad = copy.deepcopy(before); bad[key] = False
            with self.subTest(key=key), self.assertRaises(ValueError): a.unchanged_ack(bad, after, command="verify")
        for key in ("root", "file", "seed"):
            for field in ("mode", "uid", "gid", "mtime", "size", "nlink"):
                bad = copy.deepcopy(after); bad[key][field] += 1
                with self.subTest(key=key, field=field), self.assertRaises(ValueError): a.unchanged_ack(before, bad, command="verify")
        for key, value in (("entries", ["seed"]), ("sha256", "a" * 64), ("file_xattrs", {}), ("inode", 124)):
            bad = copy.deepcopy(after); bad[key] = value
            with self.assertRaises(ValueError): a.unchanged_ack(before, bad, command="verify")

    def test_four_owner_replacement_does_not_weaken_defaults(self):
        args, arm, _, _, _ = W["values"]()
        ack = ["1" * 64, "2" * 64]; args[7] += ack
        args[3]["containedContainerIDs"] = sorted(args[7])
        r.replacement_proof(*args, prepare_recovery=arm, active_ack_containers=ack)
        for kw in ({}, dict(prepare_recovery=arm), dict(active_ack_containers=ack)):
            with self.assertRaises(ValueError): r.replacement_proof(*args, **kw)
        for bad in (ack[:1], [ack[0]] * 2, [arm["scope"]["container"], ack[0]], [ack[0], "3" * 64]):
            with self.assertRaises(ValueError): r.replacement_proof(*args, prepare_recovery=arm, active_ack_containers=bad)
        for change in ("stale-E", "wrong-VM", "missing-owner"):
            bad = copy.deepcopy(args)
            boot = bad[1]["workerReplacements"][-1]["successor"]
            if change == "stale-E": boot["ready"]["serviceEpoch"] = bad[0]["boot"]["ready"]["serviceEpoch"]
            if change == "wrong-VM": boot["binding"]["guestBootNonce"] = W["uid"]()
            if change == "missing-owner": bad[3]["containedContainerIDs"].pop()
            with self.subTest(change=change), self.assertRaises(ValueError): r.replacement_proof(*bad, prepare_recovery=arm, active_ack_containers=ack)

    def test_retired_runtime_or_submitted_retire_rejected(self):
        manifest, state, ids = R["SMOKE"]["journal"]()
        plan = dict(volume="owned-volume")
        epoch = W["uid"]()
        for intent in state["intents"].values(): intent["serviceEpoch"] = epoch
        state.setdefault("operations", {}); state.setdefault("operationDigests", {})
        for intent in state["intents"].values():
            for slot in intent["slots"]: slot["retireOperation"] = W["uid"]()
        a.active_receipts(manifest, state, plan["volume"], ids)
        intent = next(iter(state["intents"].values()))
        runtime = next(s for s in intent["slots"] if s["role"] == "runtime")
        for field in ("operations", "operationDigests"):
            bad = copy.deepcopy(state); bad[field][runtime["retireOperation"]] = "submitted"
            with self.assertRaises(ValueError): a.active_receipts(manifest, bad, plan["volume"], ids)
        bad = copy.deepcopy(state); bad["intents"][intent["id"]]["phase"] = "retired"
        with self.assertRaises(ValueError): a.active_receipts(manifest, bad, plan["volume"], ids)

    def test_active_receipt_evidence_preserves_absence_without_null(self):
        manifest, state, ids = R["SMOKE"]["journal"]()
        epoch = W["uid"]()
        state.setdefault("operations", {}); state.setdefault("operationDigests", {})
        for intent in state["intents"].values():
            intent["serviceEpoch"] = epoch
            for slot in intent["slots"]: slot["retireOperation"] = W["uid"]()
        receipts = a.active_receipts(manifest, state, "owned-volume", ids)
        original = copy.deepcopy(receipts)
        projected = a.receipt_evidence(receipts)
        self.assertEqual(receipts, original)
        self.assertEqual(p.decode(p.canonical(projected)), projected)
        for before, after in zip(receipts["intents"], projected["intents"]):
            for old, new in zip(before["slots"], after["slots"]):
                if old["role"] == "runtime":
                    self.assertIsNone(old["receipt"])
                    self.assertFalse(new["receiptPresent"])
                    self.assertNotIn("receipt", new)
                else:
                    self.assertTrue(new["receiptPresent"])
                    self.assertEqual(new["receipt"], old["receipt"])
        for field in ("prepare-receipt", "phase", "other-null"):
            bad = copy.deepcopy(receipts)
            if field == "prepare-receipt":
                next(s for s in bad["intents"][0]["slots"] if s["role"] == "prepare")["receipt"] = None
            elif field == "phase": bad["intents"][0]["phase"] = "retired"
            else: bad["unknown"] = None
            with self.subTest(field=field), self.assertRaises(ValueError): a.receipt_evidence(bad)
        # Execute the actual record call sites, including canonical event encoding.
        tree = ast.parse((ROOT / "Tests/Compatibility/managed_prepare_active_ack.py").read_text())
        phases = {"active-ack-external-fsync", "active-ack-preserved-before-write"}
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and node.args
                 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                 and node.args[0].value in phases]
        events = []
        def record(phase, **values): events.append(p.decode(p.canonical(dict(phase=phase, **values))))
        obj = SimpleNamespace(ids=ids, receipts=receipts, ack={"ack": True}, record=record)
        for call in calls:
            eval(compile(ast.Expression(call), "<actual-receipt-record>", "eval"),
                 dict(self=obj, record=record, receipt_evidence=a.receipt_evidence, hashes={}, context={}, current=receipts))
        self.assertEqual({e["phase"] for e in events}, phases)
        self.assertTrue(all(e["receipts"] == projected for e in events))

    def test_premature_native_death_and_budget_fail_before_cut(self):
        obj = object.__new__(a.ActiveACK)
        obj.remaining = Mock(); obj.receipts = dict(intents=[], volume="v")
        obj.read_state = lambda: ({}, {}, {})
        obj.volume = SimpleNamespace(name="v"); obj.ids = ["1" * 64, "2" * 64]
        proc = harness.RuntimeProcess(40, identity=(1, 2, 3), pidversion=4)
        obj.processes = [proc]; obj.census = lambda: [proc]
        obj.containers = [SimpleNamespace(reload=Mock(), attrs={"State": {"Running": True}})]
        obj.validators = [Mock()]; obj.ledger = object(); obj.files = {}
        with patch.object(a, "active_receipts", return_value=obj.receipts), patch.object(p, "verify_full_ledger"), patch.object(harness, "_kernel_process", return_value=None):
            with self.assertRaisesRegex(ValueError, "prematurely"): obj.validate()
        obj.census = lambda: [proc] * 9
        with patch.object(a, "active_receipts", return_value=obj.receipts):
            with self.assertRaisesRegex(ValueError, "eight-process"): obj.validate()

    def test_recover_live_order_and_bad_readback_never_rewrites(self):
        from contextlib import ExitStack, nullcontext
        for damaged in (False, True):
            obj = object.__new__(a.ActiveACK)
            obj.stack = ExitStack(); obj.daemon = object(); obj.client = Mock()
            obj.plan = dict(owner="a" * 32, image="owned-image", volume="owned-volume")
            obj.ids = ["1" * 64, "2" * 64]
            obj.containers = [Mock(id=i, name="ack-" + str(n)) for n, i in enumerate(obj.ids)]
            obj.volume = Mock(); obj.volume.name = "owned-volume"; obj.image = Mock()
            obj.receipts = dict(intents=[dict(id="old1"), dict(id="old2")])
            current = dict(intents=[dict(id="new1", slots=[]), dict(id="new2", slots=[])])
            obj.read_state = lambda: (dict(root={}), {}, {})
            obj.remaining = Mock(); obj.census = lambda: []; obj.target = lambda i: i["id"]
            obj.wait_exit = Mock(); obj.ledger = object(); obj.files = {}
            events = []; obj.record = lambda name, **kw: events.append(name)
            obj.start = lambda c: events.append("start")
            obj.join = Mock()
            snapshots = R["WorkerReplacementTests"]()
            obj.ack = snapshots.worker_snapshot()
            def observe(command, c):
                events.append(command)
                if command == "worker-verify":
                    v = snapshots.worker_snapshot("verify")
                    if damaged: v["file"]["uid"] += 1
                    return v
                return snapshots.worker_snapshot("write" if command == "worker-write" else "verify", written=True)
            obj.observe = observe
            with patch.object(a, "active_receipts", return_value=current), patch.object(r, "fresh_receipts") as fresh, \
                 patch.object(p, "workload_owner", side_effect=lambda *a: nullcontext(({}, {}, lambda: None))), \
                 patch.object(p, "verify_full_ledger"), patch.object(r, "exact_receipts"), patch.object(r, "owned"):
                if damaged:
                    with self.assertRaises(ValueError): obj.recover({})
                    self.assertNotIn("worker-write", events)
                    for c in obj.containers: c.stop.assert_not_called()
                else:
                    obj.recover({})
                    self.assertEqual([x for x in events if x.startswith("worker-")],
                        ["worker-verify", "worker-verify", "worker-write", "worker-verify-written"])
                    fresh.assert_called_once()
                    for c in obj.containers: c.stop.assert_called_once_with(timeout=1)
                    self.assertEqual(obj.wait_exit.call_count, 2)

    def test_reservation_refuses_before_mutating_at_cap(self):
        obj = object.__new__(a.ActiveACK); obj.remaining = Mock(); obj.census = lambda: [object()] * 8
        obj.budget()
        with self.assertRaisesRegex(ValueError, "eight-process"): obj.budget(reserve=1)

    def test_memory_budget_uses_capacity_and_keeps_the_two_gib_ceiling(self):
        from contextlib import nullcontext
        # One 1 GiB storage VM, three 256 MiB workloads, and a never-booted
        # peer. The retired predecessor is conservatively counted until exit.
        sizes = [1024, 256, 256, 256, 256]
        census = [harness.RuntimeProcess(100 + i,
            arguments=('cengine', 'vm-shim', '--spec', f'/owned/{i}/spec.json')) for i in range(len(sizes))]
        def directory(path, **kwargs):
            size = sizes[int(Path(path).name)] * 1024**2
            return nullcontext(SimpleNamespace(read=lambda *args: (p.canonical(dict(memoryBytes=size)), None)))
        with patch.object(p, 'Directory', side_effect=directory):
            a.resource_budget(census, [], idle=(census[-1],), memory_reserve=a.ACK_VM_CAPACITY)
            a.resource_budget(census, [])  # Exactly 2 GiB, no idle exemption.
            with self.assertRaisesRegex(ValueError, 'two-GiB'):
                a.resource_budget(census, [], memory_reserve=1)
            sizes[2] = 512
            with self.assertRaisesRegex(ValueError, 'two-GiB'):
                a.resource_budget(census, [])
            sizes[2] = 128  # A hard limit must never masquerade as a VM capacity.
            with self.assertRaises(ValueError): a.resource_budget(census, [])
        self.assertEqual(a.ACK_VM_CAPACITY, 256 * 1024**2)
        source = (ROOT / 'Sources/CEngineCore/VirtualMachineMemory.swift').read_text()
        self.assertIn('minimumContainerCapacityBytes: UInt64 = 256 * mebibyte', source)
        self.assertIn('fixedGuestReserveBytes: UInt64 = 64 * mebibyte', source)
        init = next(n for n in ast.walk(ast.parse((ROOT / 'Tests/Compatibility/managed_prepare_active_ack.py').read_text()))
                    if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        self.assertIn('memory_reserve=ACK_VM_CAPACITY', ast.unparse(init))

    def test_terminal_cleanup_refresh_runs_for_delete_before_removal(self):
        source = (ROOT / 'Sources/CEngineRuntime/RawVirtualizationBackend.swift').read_text()
        cleanup = source.split('private func cleanupContainer(', 1)[1].split('public func cleanupOrphans(', 1)[0]
        refresh = cleanup.index('try await managedStorage?.refreshTerminalContainment(')
        terminated = cleanup.rindex('try await terminateEveryShim(', 0, refresh)
        ownership = cleanup.index('guard stateDirectory.pathStillNamesThisDirectory()', refresh)
        self.assertLess(terminated, refresh)
        self.assertLess(refresh, ownership)
        self.assertLess(ownership, cleanup.index('knownContainers.removeValue', refresh))
        self.assertLess(refresh, cleanup.index('finalizeContainerRemoval'))
        # The call is outside the earlier non-delete/nonterminal settlement branch.
        self.assertNotIn('if ', cleanup[terminated:refresh])
        self.assertIn('try requireServiceGeneration(epoch)', cleanup[terminated:refresh])
        self.assertIn('try requireServiceGeneration(epoch)', cleanup[refresh:ownership])

    def test_recovery_verifies_both_before_any_write(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/managed_prepare_active_ack.py").read_text())
        method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "recover")
        source = ast.unparse(method)
        self.assertLess(source.index("unchanged_ack("), source.index("'worker-write'"))
        self.assertLess(source.index("fresh_receipts("), source.index("unchanged_ack("))
        init = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "__init__")
        for forbidden in (".stop(", ".remove(", "unmount", '"worker-write"'):
            self.assertNotIn(forbidden, ast.unparse(init))


RUNNER = ROOT / "tools/managed_prepare_matrix.py"
RUNNER_TREE = ast.parse(RUNNER.read_text())
ACK_CASE = "worker-a5-active-ack"


def runner_namespace() -> dict:
    """Execute runner functions/constants only, never import its engine fixtures."""
    namespace = dict(Path=Path, argparse=argparse, hashlib=hashlib, json=json, os=os,
        subprocess=subprocess, sys=sys, tempfile=tempfile, time=time, REPO_ROOT=ROOT,
        proof=p, stale=stale, vm=vm,
        followup_parent=SimpleNamespace(FOLLOWUP_CASES=followup_parent.FOLLOWUP_CASES, run_followup_route=Mock()),
        matrix=SimpleNamespace(MATRICES=matrix.MATRICES, MatrixOutcome=matrix.MatrixOutcome, aggregate_matrix=Mock()),
        conftest=SimpleNamespace(Daemon=Mock()), fixture=Mock(),
        harness=Mock(terminate_compatibility_runtime=Mock(return_value=[]),
                     compatibility_runtime_processes=Mock(return_value=[])))
    nodes = []
    for node in RUNNER_TREE.body:
        if isinstance(node, ast.FunctionDef):
            nodes.append(node)
        elif isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(ast.unparse(target).split("[")[0] in ("CAMPAIGNS", "ADDON_CASES") for target in targets):
                nodes.append(node)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(RUNNER), "exec"), namespace)
    return namespace


def ack_report():
    return dict(rtm="RTM-098", boundary=ACK_CASE, result="initial-cut-passed", fullAcceptance=False,
        profile=p.FULL_PROFILE, execution="actual-docker-runtime", runID=W["uid"](), store=W["uid"](),
        evidenceSHA256="e" * 64)


class ActiveACKRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ack-", dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.ns = runner_namespace()
        self.ns["WORK_PARENT"] = self.base / "work"
        self.probe = self.base / "probe"
        self.probe.write_bytes(b"fixed ACK helper")
        self.pin = hashlib.sha256(self.probe.read_bytes()).hexdigest()
        self.evidence = self.base / "evidence"
        self.evidence.mkdir()
        self.daemon = SimpleNamespace(start=Mock(), stop=Mock(), root=self.base / "root",
            _retain_root=False, process=SimpleNamespace(poll=lambda: 0))
        self.ns["conftest"].Daemon.return_value = self.daemon
        self.report = ack_report()
        self.ns["fixture"].run_worker_a5_active_ack_shard.return_value = self.report
        self.args = dict(binary=self.base / "binary", assets=self.base / "assets", probe=self.base / "prepare-probe",
            probe_sha256="a" * 64, source_sha256="b" * 64, commit="c0ffee0", evidence_root=self.evidence, log=Mock())

    def run_main(self, rtm, cases=None, *, evidence=None):
        argv = [str(RUNNER), "--rtm", rtm, "--assets", str(self.base / "assets"),
                "--evidence", str(evidence or self.evidence)]
        for case in cases or []: argv += ["--case", case]
        env = dict(CENGINE_COMPAT_NETWORK_HELPER_FINGERPRINT="test",
                   CENGINE_BINARY=str(self.probe))
        with patch.object(sys, "argv", argv), patch.dict(os.environ, env), patch.object(sys, "stdout", io.StringIO()):
            return self.ns["main"]()

    def mock_main_work(self):
        self.ns.update(admit_environment=Mock(return_value=self.base / "binary"),
            asset_metadata=Mock(return_value={"prepareCompatibilitySourceSHA256": "b" * 64}),
            build_probe=Mock(side_effect=[(self.base / "prepare-probe", "a" * 64), (self.probe, self.pin)]),
            expected_commit=Mock(return_value="c0ffee0"), prepare_descriptor_budget=Mock(return_value=2048),
            run_cell=Mock(return_value=self.report))

    def test_closed_optin_leaves_all_defaults_unchanged(self):
        self.assertEqual(self.ns["ADDON_CASES"], {"RTM-098": (ACK_CASE,),
            "RTM-099": ("vm-two-volume-drain-reply-gap", "vm-private-bound", "vm-root-synced-before-cleanup",
                        "vm-cleaning-transaction-removed", "vm-private-bound-active-ack")})
        for rtm in ("RTM-097", "RTM-098", "RTM-099"):
            self.assertEqual(self.ns["CAMPAIGNS"][rtm], list(p.FULL_CASES))
            self.assertEqual(len(self.ns["selected_cases"](rtm)), 9)
        self.assertEqual(self.ns["CAMPAIGNS"]["RTM-103"], list(stale.IMPLEMENTED_CASES) + list(followup_parent.FOLLOWUP_CASES))
        for rtm, defaults in self.ns["CAMPAIGNS"].items():
            self.assertEqual(self.ns["selected_cases"](rtm), defaults)
            self.assertNotIn(ACK_CASE, defaults)
        self.assertEqual(self.ns["selected_cases"]("RTM-098", [ACK_CASE]), [ACK_CASE])

    def test_main_rejects_foreign_unknown_and_duplicates_before_any_work(self):
        self.mock_main_work()
        invalid = [(rtm, [ACK_CASE]) for rtm in ("RTM-097", "RTM-099", "RTM-103")]
        invalid += [("RTM-098", [case]) for case in ("unknown", "worker-a4-active-ack", "vm-private-bound-active-ack")]
        invalid += [("RTM-098", [ACK_CASE, ACK_CASE]), ("RTM-098", ["normal", "normal"])]
        invalid += [("RTM-098", ["normal", "unknown"])]
        for rtm, cases in invalid:
            with self.subTest(rtm=rtm, cases=cases), self.assertRaises(ValueError):
                self.run_main(rtm, cases, evidence=self.base / "must-not-exist")
        self.assertFalse((self.base / "must-not-exist").exists())
        for name in ("run_cell", "build_probe", "asset_metadata", "expected_commit", "prepare_descriptor_budget"):
            self.ns[name].assert_not_called()
        with self.assertRaises(ValueError): self.ns["selected_cases"]("RTM-000", [ACK_CASE])

    def test_main_builds_ack_only_for_explicit_selection_and_passes_only_to_that_cell(self):
        selections = ([ACK_CASE], ["normal", ACK_CASE, "admitted-queued"], [ACK_CASE, *p.FULL_CASES[:-1]])
        for index, cases in enumerate(selections):
            self.evidence = self.base / f"evidence-{index}"
            self.mock_main_work()
            self.assertEqual(self.run_main("RTM-098", cases), 0)
            builds = self.ns["build_probe"].call_args_list
            self.assertEqual(len(builds), 2)
            self.assertEqual(builds[0].args, (self.evidence / "probe",))
            self.assertEqual(builds[0].kwargs, {})
            self.assertEqual(builds[1].args, (self.evidence / "ack-probe",))
            self.assertEqual(builds[1].kwargs, {"active_ack": True})
            calls = self.ns["run_cell"].call_args_list
            self.assertEqual([c.args for c in calls], [("RTM-098", case) for case in cases])
            for call in calls:
                if call.args[1] == ACK_CASE:
                    self.assertEqual(call.kwargs["ack_probe"], self.probe)
                    self.assertEqual(call.kwargs["ack_probe_sha256"], self.pin)
                else:
                    self.assertNotIn("ack_probe", call.kwargs)
                    self.assertNotIn("ack_probe_sha256", call.kwargs)
            result = json.loads(next(self.evidence.glob("runner-RTM-098-*-result.json")).read_text())
            self.assertIs(result["fullAcceptance"], False)
            self.assertNotIn("aggregate", result)
            self.assertEqual(set(result["cases"]), set(cases))
            self.assertEqual(result["cases"][ACK_CASE], self.report)
            self.ns["matrix"].aggregate_matrix.assert_not_called()

    def test_nonaddon_campaigns_never_build_ack_probe(self):
        for rtm, cases in (("RTM-098", None), ("RTM-097", ["normal"]), ("RTM-099", ["normal"]),
                           ("RTM-103", None)):
            self.mock_main_work()
            self.assertEqual(self.run_main(rtm, cases), 0)
            self.ns["build_probe"].assert_called_once_with(self.evidence / "probe")
            self.assertEqual([c.args[1] for c in self.ns["run_cell"].call_args_list], cases or self.ns["CAMPAIGNS"][rtm])
            for call in self.ns["run_cell"].call_args_list:
                self.assertNotIn("ack_probe", call.kwargs)
                self.assertNotIn("ack_probe_sha256", call.kwargs)
            self.ns["matrix"].aggregate_matrix.assert_not_called()

    def test_fixed_offline_pinned_linux_arm64_build_and_real_digest(self):
        def fake_run(argv, **kwargs):
            if argv[0] == "/bin/sh": return SimpleNamespace(stdout="/pinned/go\n")
            Path(argv[argv.index("-o") + 1]).write_bytes(b"mock compiled probe")
        run = Mock(side_effect=fake_run)
        self.ns["subprocess"] = SimpleNamespace(run=run, PIPE=subprocess.PIPE)
        for active_ack, name in ((False, "managed-prepare-faults"), (True, "managed-storage-recovery")):
            run.reset_mock()
            output = self.base / name
            probe, pin = self.ns["build_probe"](output, **({"active_ack": True} if active_ack else {}))
            self.assertEqual(probe, output / name)
            self.assertEqual(pin, hashlib.sha256(b"mock compiled probe").hexdigest())
            self.assertEqual(run.call_count, 2)
            toolchain, build = run.call_args_list
            self.assertEqual(toolchain.args[0], ["/bin/sh", str(ROOT / "Scripts/ensure-go-toolchain.sh")])
            self.assertTrue(toolchain.kwargs["check"])
            self.assertEqual(build.args[0], ["/pinned/go", "build", "-mod=vendor", "-trimpath", "-buildvcs=false",
                "-ldflags=-s -w -buildid=", "-o", str(probe), f"../Tests/Compatibility/fixtures/{name}.go"])
            self.assertEqual(build.kwargs["cwd"], ROOT / "Guest")
            self.assertTrue(build.kwargs["check"])
            env = build.kwargs["env"]
            for key, value in dict(GOENV="off", GOFLAGS="", GOWORK="off", GO111MODULE="on", GOTOOLCHAIN="local",
                    GOPROXY="off", GOSUMDB="off", CGO_ENABLED="0", GOOS="linux", GOARCH="arm64", GOARM64="v8.0").items():
                self.assertEqual(env[key], value)
            self.assertEqual(env["GOCACHE"], str(output / "go-cache/build"))
            self.assertEqual(env["GOMODCACHE"], str(output / "go-cache/mod"))
        run.reset_mock()
        for bad in ("arbitrary.go", Path("arbitrary.go"), 1, None):
            with self.assertRaises(ValueError): self.ns["build_probe"](self.base / "rejected", active_ack=bad)
        run.assert_not_called()
        self.assertFalse((self.base / "rejected").exists())

    def test_dispatch_matches_existing_parent_without_case_name(self):
        result = self.ns["run_cell"]("RTM-098", ACK_CASE, **self.args, ack_probe=self.probe, ack_probe_sha256=self.pin)
        self.assertIs(result, self.report)
        self.ns["fixture"].run_worker_a5_active_ack_shard.assert_called_once_with(self.daemon,
            profile=p.FULL_PROFILE, probe=self.args["probe"], probe_sha256="a" * 64,
            ack_probe=self.probe, ack_probe_sha256=self.pin, source_sha256="b" * 64, expected_commit="c0ffee0",
            evidence=next(self.evidence.iterdir()))
        self.assertNotIn("caseName", result)
        self.assertEqual(len(self.ns["fixture"].mock_calls), 1)
        self.daemon.start.assert_called_once()
        self.daemon.stop.assert_called_once()

    def test_invalid_or_missing_ack_pin_is_rejected_before_work(self):
        bad_args = [{}, {"ack_probe": self.probe}, {"ack_probe_sha256": self.pin},
            dict(ack_probe=self.base / "missing", ack_probe_sha256=self.pin),
            dict(ack_probe=self.base, ack_probe_sha256=self.pin)]
        bad_args += [dict(ack_probe=self.probe, ack_probe_sha256=pin) for pin in ("", "X" * 64, "a" * 64, 4)]
        mkdtemp = Mock(side_effect=AssertionError("work must not start"))
        self.ns["tempfile"] = SimpleNamespace(mkdtemp=mkdtemp)
        for args in bad_args:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.ns["run_cell"]("RTM-098", ACK_CASE, **self.args, **args)
        for rtm, case in (("RTM-097", ACK_CASE), ("RTM-099", ACK_CASE), ("RTM-103", ACK_CASE),
                          ("RTM-098", "unknown"), ("RTM-098", "normal"), ("RTM-103", stale.IMPLEMENTED_CASES[0])):
            with self.subTest(rtm=rtm, case=case), self.assertRaises(ValueError):
                self.ns["run_cell"](rtm, case, **self.args, ack_probe=self.probe, ack_probe_sha256=self.pin)
        self.assertFalse(self.ns["WORK_PARENT"].exists())
        self.assertEqual(list(self.evidence.iterdir()), [])
        mkdtemp.assert_not_called()
        self.ns["conftest"].Daemon.assert_not_called()
        self.daemon.start.assert_not_called()
        self.ns["harness"].assert_not_called()
        self.assertEqual(self.ns["harness"].mock_calls, [])
        self.assertEqual(self.ns["fixture"].mock_calls, [])

    def test_inexact_or_wrongly_bound_report_refused_without_root_removal(self):
        changes = dict(rtm="RTM-099", boundary="admitted-queued", result="case-passed", fullAcceptance=True,
            profile=p.PROFILE, execution="replayed", runID="invalid", store="invalid", evidenceSHA256="A" * 64)
        bad_reports = [dict(self.report, **{key: value}) for key, value in changes.items()]
        bad_reports += [{key: value for key, value in self.report.items() if key != missing} for missing in self.report]
        bad_reports += [dict(self.report, caseName=ACK_CASE), dict(self.report, nativeAcceptance=False),
                        dict(self.report, fullAcceptance=0), list(self.report.items()), None,
                        type("ReportSubclass", (dict,), {})(self.report)]
        for report in bad_reports:
            self.ns["fixture"].run_worker_a5_active_ack_shard.return_value = report
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.ns["run_cell"]("RTM-098", ACK_CASE, **self.args, ack_probe=self.probe, ack_probe_sha256=self.pin)
        self.assertEqual(self.daemon.stop.call_count, len(bad_reports))
        self.ns["harness"].release_compatibility_root.assert_not_called()
        self.ns["harness"].remove_compatibility_root.assert_not_called()


if __name__ == "__main__": unittest.main()
