#!/usr/bin/env python3
"""Engine-free prepared-peer refresh regressions; all native edges are doubled."""
import ast
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import copy
import runpy
import signal
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_prepare_faults as p
import managed_prepare_worker_faults as worker

WORKER = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-worker.py"))
EXITS = runpy.run_path(str(ROOT / "tools/tests/test-managed-prepare-vm-exits.py"))


class PreparedPeerRefreshTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with WORKER["prepared_fixture"](["c" * 64, "e" * 64]) as data:
            daemon, peer, plan, root, process, prepared, generation = data
            edge = EXITS["APIJoinedRefreshTests"]().edge()
            process = replace(process, parent_pid=edge.api.pid)
            edge.idle = process
            edge.expected = [edge.api, process, *edge.owners]
            edge.native = {v.pid: v for v in edge.expected}
            edge.runtime = edge.native.copy()
            daemon.process = edge.daemon.process
            with edge.patches(), edge.monitor() as monitor:
                with worker.prepared_peer_owner(daemon, peer, plan, root, edge.expected) as owner:
                    yield daemon, peer, plan, root, edge, monitor, owner, generation

    def join(self, edge, monitor):
        monitor.delivered()
        EXITS["APIJoinedRefreshTests"]().reparent(edge)
        return monitor.api_joined_refresh(edge.daemon, edge.api, edge.expected)

    def test_exact_join_refreshes_live_callback_and_reopened_owner_not_history(self):
        with self.fixture() as (daemon, peer, plan, root, edge, monitor, owner, _):
            original = owner[0]
            historical = copy.deepcopy(owner[1])
            exposed = monitor.owners
            survivors = self.join(edge, monitor)
            with self.assertRaises(ValueError): owner[2]()  # Stale pin is still strict.
            owner[2].api_joined_refresh(edge.api, survivors)
            self.assertEqual(owner[0], replace(original, parent_pid=1))
            self.assertEqual(owner[1], historical)
            self.assertEqual(monitor.owners, exposed)
            owner[2]()
            with worker.prepared_peer_owner(daemon, peer, plan, root, survivors) as reopened:
                self.assertEqual(reopened[:2], owner[:2])
                reopened[2]()
            edge.kill_all()
            current = monitor.join_all([v for v in survivors if v != edge.api], "recovery-ready")
            self.assertEqual(current, [owner[0]])
            self.assertEqual([value["native"] for _, value in edge.records],
                [p.native_proof(v) for v in exposed])
            with self.assertRaises(ValueError): owner[2].api_joined_refresh(edge.api, survivors)
            edge.native[original.pid] = replace(owner[0], parent_pid=77)
            with self.assertRaises(ValueError): owner[2]()

    def test_actual_restart_threads_trusted_census_into_peer_callback(self):
        tree = ast.parse((ROOT / "Tests/Compatibility/managed_prepare_storage_vm_faults.py").read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "owner_exits is None"
            and "owner_exits.api_joined_refresh" in ast.unparse(node))
        code = compile(ast.Module(body=branch.orelse, type_ignores=[]), "actual-api-join-refresh", "exec")
        for reparent in (False, True):
            with self.subTest(reparent=reparent), self.fixture() as (daemon, _, _, _, edge, monitor, owner, _):
                original = owner[0]
                monitor.delivered()
                if reparent: EXITS["APIJoinedRefreshTests"]().reparent(edge)
                else: edge.die(edge.api, note=False)
                env = dict(owner_exits=monitor, daemon=daemon, api=edge.api,
                    survivors=edge.expected, census=edge.expected, active_ack=object(), peer_owner=owner)
                exec(code, env)
                expected = replace(original, parent_pid=1) if reparent else original
                self.assertEqual(owner[0], expected)
                self.assertIn(expected, env["census"])
                owner[2]()

    def test_refuses_unjoined_wrong_api_and_wrong_signal_without_updating_pin(self):
        for fault in ("unjoined", "wrong-pid", "wrong-signal", "live-api", "ambiguous-api"):
            with self.subTest(fault=fault), self.fixture() as (_, _, _, _, edge, monitor, owner, _):
                original = owner[0]
                survivors = self.join(edge, monitor)
                if fault == "unjoined": edge.daemon.process.returncode = None
                if fault == "wrong-pid": edge.daemon.process.pid += 1
                if fault == "wrong-signal": edge.daemon.process.returncode = -signal.SIGTERM
                if fault == "live-api": edge.native[edge.api.pid] = edge.api
                if fault == "ambiguous-api": edge.native[edge.api.pid] = replace(edge.api, pidversion=999)
                with self.assertRaises(ValueError): owner[2].api_joined_refresh(edge.api, survivors)
                self.assertEqual(owner[0], original)

    def test_refuses_changed_identity_lineage_or_canonical_files(self):
        changes = [dict(pid=99), dict(identity=(11, 44, 144)), dict(pidversion=99),
            dict(executable="/other"), dict(arguments=("other",)), dict(command="changed"),
            dict(parent_pid=77), dict(parent_pid=None)]
        for change in changes:
            with self.subTest(change=change), self.fixture() as (_, _, _, _, edge, monitor, owner, _):
                original = owner[0]
                survivors = self.join(edge, monitor)
                changed = replace(owner[0], **change)
                survivors = [changed if v.pid == original.pid else v for v in survivors]
                edge.native[original.pid] = changed
                with self.assertRaises(ValueError): owner[2].api_joined_refresh(edge.api, survivors)
                self.assertEqual(owner[0], original)
        for filename in ("prepared-shim.json", "launch.json", "spec.json", "intent.json"):
            with self.subTest(filename=filename), self.fixture() as (_, _, _, _, edge, monitor, owner, generation):
                original = owner[0]
                survivors = self.join(edge, monitor)
                path = generation.parent.parent / filename if filename == "prepared-shim.json" else generation / filename
                path.write_bytes(path.read_bytes() + b" ")
                with self.assertRaises(ValueError): owner[2].api_joined_refresh(edge.api, survivors)
                self.assertEqual(owner[0], original)

    def test_refuses_missing_duplicate_or_native_drift_after_trusted_refresh(self):
        for fault in ("missing", "duplicate", "native-drift"):
            with self.subTest(fault=fault), self.fixture() as (_, _, _, _, edge, monitor, owner, _):
                original = owner[0]
                survivors = self.join(edge, monitor)
                if fault == "missing": survivors = [v for v in survivors if v.pid != original.pid]
                if fault == "duplicate": survivors.append(replace(original, parent_pid=1))
                if fault == "native-drift": edge.native[original.pid] = replace(original, pidversion=99)
                with self.assertRaises(ValueError): owner[2].api_joined_refresh(edge.api, survivors)
                self.assertEqual(owner[0], original)


if __name__ == "__main__": unittest.main()
