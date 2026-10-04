#!/usr/bin/env python3
"""Engine-free run_live boundary tests, not a public peer producer or VM proof.

Keep the actual lifecycle reader/owner/comparison path under test. Only the
lowest-level owner file reads use synthetic fixtures; stop before native IO.
The actual shared fixture branch is extracted below to check reader lifetime.
"""
import ast
import copy
import inspect
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_stale_consumer as consumer

FIXTURES = runpy.run_path(str(ROOT / "tools/tests/test-managed-original-lifecycle-evidence.py"))


class ReachedNativeBoundary(Exception):
    pass


class OriginalLifecycleCallerTests(unittest.TestCase):
    def call(self, before, reader, *, normal_mutation=None):
        owner, _ = consumer.lifecycle.owner(before)
        normal = dict(store=owner["store"], **{key: owner[key] for key in
            ("serviceEpoch", "controllerEpoch", "controllerKey")})
        normal.update(normal_mutation or {})
        arguments = {name: None for name, parameter in inspect.signature(consumer.run_live).parameters.items()
            if parameter.default is inspect.Parameter.empty}
        arguments.update(daemon=SimpleNamespace(root=Path("/not-a-live-daemon")),
            staged=consumer.selection(consumer.p.FULL_PROFILE, consumer.CASES, consumer.IMPLEMENTED),
            normal=normal, lifecycle_peer_reader=reader)
        # No adapter, owner selector, or peer_comparison mock: the actual caller
        # reads the explicit v2 checkpoint/manifest and invokes the supplied reader.
        public_reads = Mock(side_effect=[(before["checkpoint"], "a" * 64), (before["manifest"], "b" * 64)])
        with patch.object(consumer.recovery, "read_public", public_reads), \
                patch.object(consumer, "runtime_slots", side_effect=ReachedNativeBoundary) as boundary:
            try:
                consumer.run_live(**arguments)
            finally:
                self.assertEqual(public_reads.call_count, 2)
                self.boundary_calls = boundary.call_count

    def test_actual_v2_caller_reaches_reader_and_checks_bytes(self):
        arguments, peers = FIXTURES["fixture"]()
        before = arguments[0]
        received = []
        def reader(projection):
            received.append(copy.deepcopy(projection))
            return peers[0]
        with self.assertRaises(ReachedNativeBoundary):
            self.call(before, reader)
        self.assertEqual(received, [consumer.lifecycle.owner(before)[1]])
        self.assertEqual(self.boundary_calls, 1)

    def test_missing_or_successor_peer_fails_before_native_work(self):
        arguments, peers = FIXTURES["fixture"]()
        for reader in (None, lambda _: peers[1]):
            with self.subTest(reader=reader), self.assertRaises(ValueError):
                self.call(arguments[0], reader)
            self.assertEqual(self.boundary_calls, 0)

    def test_correct_peer_does_not_bypass_original_tuple_correlation(self):
        arguments, peers = FIXTURES["fixture"]()
        for field, value in (("store", FIXTURES["WORKER"]["uid"]()),
                ("serviceEpoch", FIXTURES["WORKER"]["uid"]()),
                ("controllerEpoch", 999), ("controllerKey", "0" * 64)):
            reader = Mock(return_value=peers[0])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "exact predecessor"):
                self.call(arguments[0], reader, normal_mutation={field: value})
            reader.assert_called_once()
            self.assertEqual(self.boundary_calls, 0)


PEER = runpy.run_path(str(ROOT / "tools/tests/test-managed-original-lifecycle-peer.py"))


class SharedFixtureInjectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.fixture = PEER["Fixture"](Path(temporary.name).resolve())
        boot = patch.object(PEER["e"].lifecycle, "host_boot_uuid", return_value=self.fixture.boot)
        boot.start(); self.addCleanup(boot.stop)

    def extracted(self):
        # Compile the actual production fixture branch, not a reconstructed call.
        tree = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        shared = next(node for node in tree.body if getattr(node, "name", "") == "_run_prepare_case")
        branch = next(node for node in ast.walk(shared) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "original_consumer_case is not None"
            and any(isinstance(child, ast.ImportFrom) and child.module == "managed_original_lifecycle_peer"
                for child in node.body))
        function = ast.parse("def extracted():\n    pass\n").body[0]
        function.body = branch.body
        module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
        names = {node.id: None for node in ast.walk(function) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        f = self.fixture; owner, _ = consumer.lifecycle.owner(f.records[0])
        names.update(daemon=f.daemon, processes=lambda: [f.process],
            staged=consumer.selection(consumer.p.FULL_PROFILE, consumer.CASES, consumer.IMPLEMENTED),
            normal=dict(store=owner["store"], **{key: owner[key] for key in ("serviceEpoch", "controllerEpoch", "controllerKey")}))
        exec(compile(module, "<actual-shared-fixture>", "exec"), names)
        return names["extracted"]

    def test_shared_fixture_passes_real_reader_into_actual_run_live(self):
        f = self.fixture
        reads = Mock(side_effect=[(f.records[0]["checkpoint"], "a" * 64), (f.records[0]["manifest"], "b" * 64)])
        retained = []
        original = consumer.run_live
        def invoke(*args, **kwargs):
            retained.append(kwargs["lifecycle_peer_reader"])
            return original(*args, **kwargs)
        with patch.object(consumer, "run_live", side_effect=invoke), \
                patch.object(consumer.recovery, "read_public", reads), \
                patch.object(consumer, "runtime_slots", side_effect=ReachedNativeBoundary):
            with self.assertRaises(ReachedNativeBoundary): self.extracted()()
        self.assertEqual(len(retained), 1)
        self.assertIn(f.paths[0], retained[0].files)
        self.assertEqual(reads.call_count, 2)

    def test_shared_fixture_retains_validator_until_after_run_live_finishes(self):
        f = self.fixture
        for index in (None, 0, 1):
            f.publish(0); f.publish(1)
            def finish(*args, **kwargs):
                reader = kwargs["lifecycle_peer_reader"]
                self.assertEqual(reader(f.projections[0]), f.peers[0])
                self.assertEqual(reader(f.projections[1]), f.peers[1])
                if index is not None:
                    f.paths[index].write_bytes(f.paths[index].read_bytes() + b" ")
                return {"finished": True}
            with self.subTest(index=index), patch.object(consumer, "run_live", side_effect=finish):
                if index is None: self.assertEqual(self.extracted()(), {"finished": True})
                else:
                    with self.assertRaisesRegex(ValueError, "immutable"):
                        self.extracted()()


if __name__ == "__main__":
    unittest.main()
