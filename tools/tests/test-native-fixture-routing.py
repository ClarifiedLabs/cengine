#!/usr/bin/env python3
"""Offline native qualification routing; never builds fixtures or starts a VM."""
import ast
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
import managed_fuse_artifact as artifact

SOURCE = ROOT / "Tests/Compatibility/test_managed_fuse_interrupt.py"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def functions():
    nodes = []
    for node in ast.parse(SOURCE.read_text()).body:
        if isinstance(node, ast.FunctionDef) and node.name in ("fixture_inputs", "load_inputs", "image_cache"):
            node.decorator_list = []
            nodes.append(node)
    namespace = dict(artifact=artifact, smoke=SimpleNamespace(require=require), os=os, REPO_ROOT=ROOT)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), namespace)
    return SimpleNamespace(**namespace)


class NativeRoutingTests(unittest.TestCase):
    def test_distinct_bundles_for_each_case_in_one_process(self):
        f = functions()
        environment = {}
        for case in artifact.SELECTIONS:
            prefix = "CENGINE_" + case.replace("-", "") + "_FIXTURE"
            environment[prefix] = "/fixtures/" + case
            environment[prefix + "_SHA256"] = artifact.digest(case.encode())
        with patch.dict(os.environ, environment, clear=True), patch.object(artifact, "load_fixture") as load:
            for case in artifact.SELECTIONS:
                f.load_inputs(case)
                load.assert_called_with("/fixtures/" + case, artifact.digest(case.encode()), ROOT, case)

    def test_single_case_legacy_pair_retains_exact_case_validation(self):
        f = functions()
        with patch.dict(os.environ, {"CENGINE_RTM081_FIXTURE": "/legacy", "CENGINE_RTM081_FIXTURE_SHA256": "a" * 64}, clear=True):
            with patch.object(artifact, "load_fixture", side_effect=ValueError("fixture case/package/tag/selector proof")) as load:
                with self.assertRaisesRegex(ValueError, "case/package"):
                    f.load_inputs("RTM-082")
                load.assert_called_once_with("/legacy", "a" * 64, ROOT, "RTM-082")

    def test_missing_or_incomplete_case_pair_never_falls_back(self):
        f = functions()
        legacy = {"CENGINE_RTM081_FIXTURE": "/legacy", "CENGINE_RTM081_FIXTURE_SHA256": "a" * 64}
        for selected in ({}, {"CENGINE_RTM082_FIXTURE": "/case"},
                         {"CENGINE_RTM082_FIXTURE_SHA256": "b" * 64},
                         {"CENGINE_RTM082_FIXTURE": "", "CENGINE_RTM082_FIXTURE_SHA256": "b" * 64}):
            env = {} if not selected else {**legacy, **selected}
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                f.fixture_inputs("RTM-082", env)
        with self.assertRaises(ValueError):
            f.fixture_inputs("RTM-UNKNOWN", legacy)

    def test_bundle_and_fsx_validated_before_daemon_fixture(self):
        f = functions()
        conftest = ModuleType("conftest")
        conftest.managed_storage_arguments = Mock()
        sentinel = object()
        namespace = f.image_cache.__globals__
        for case in ("RTM-081", "RTM-085"):
            request = SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda _: SimpleNamespace(args=(case,))))
            with self.subTest(case=case), patch.dict(sys.modules, {"conftest": conftest}), \
                    patch.dict(namespace, {"load_inputs": Mock(side_effect=ValueError("stale bundle"))}), \
                    patch.object(artifact, "load_fsx") as fsx:
                with self.assertRaisesRegex(ValueError, "stale bundle"):
                    f.image_cache(sentinel, request)
                fsx.assert_not_called()
        request = SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda _: SimpleNamespace(args=("RTM-085",))))
        with patch.dict(sys.modules, {"conftest": conftest}), patch.dict(namespace, {"load_inputs": Mock()}), \
                patch.object(artifact, "load_fsx", side_effect=ValueError("missing fsx")):
            with self.assertRaisesRegex(ValueError, "missing fsx"):
                f.image_cache(sentinel, request)

    def test_qualification_marker_and_unchanged_native_no_skip_proof(self):
        tree = ast.parse(SOURCE.read_text())
        marker = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets))
        self.assertEqual(ast.unparse(marker.value), "pytest.mark.qualification")
        proof = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "native_proof")
        self.assertIn("exact native test pass/no-skip required", ast.unparse(proof))
        preflight = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "image_cache")
        self.assertNotIn("skip", ast.unparse(preflight))


if __name__ == "__main__":
    unittest.main()
