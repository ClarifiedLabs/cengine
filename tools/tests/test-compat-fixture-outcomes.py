#!/usr/bin/env python3
"""Offline pytest outcome/retention regressions; never run engine or helper code."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
# Reuse dependencies only; never install packages or run the compatibility suite.
if importlib.util.find_spec("pytest") is None:
    python = ROOT / ".build/compat-venv/bin/python"
    if not python.is_file() or Path(sys.executable) == python:
        raise SystemExit("requires existing compatibility pytest environment")
    os.execv(str(python), [str(python), __file__, *sys.argv[1:]])

import pytest

SOURCE = ROOT / "Tests/Compatibility/conftest.py"
TREE = ast.parse(SOURCE.read_text())
HOOK = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
            and node.name == "pytest_runtest_makereport")
# Extract only the real hook, including its decorator. Loading the full conftest
# as a plugin would run session ownership checks and native version commands.
HOOK_SOURCE = ast.unparse(HOOK)


def report(outcome="passed", **attributes):
    return SimpleNamespace(passed=outcome == "passed", failed=outcome == "failed",
                           skipped=outcome == "skipped", **attributes)


class FixtureOutcomeTests(unittest.TestCase):
    def run_hook(self, *, setup=report(), call=report(), teardown=report(),
                 retained=False, pending=True, release=True, remove=True):
        namespace = dict(pytest=pytest, release_compatibility_root=Mock(return_value=release),
                         remove_compatibility_root=Mock(return_value=remove))
        exec(compile(HOOK_SOURCE, str(SOURCE), "exec"), namespace)
        value = SimpleNamespace(work=Path("/not-a-real-root"), owner_binary=Path("/not-a-binary"),
                                _retain_root=retained, _managed_fixture_retention=True)
        receipt = object()
        item = SimpleNamespace(report_setup=setup, report_call=call)
        if pending:
            item._managed_root_cleanup = (value, receipt)
        hook = namespace["pytest_runtest_makereport"](item, SimpleNamespace(when="teardown"))
        next(hook)
        with self.assertRaises(StopIteration):
            hook.send(SimpleNamespace(get_result=lambda: teardown))
        return value, receipt, namespace

    def test_only_pass_or_expected_call_xfail_can_release(self):
        for call in (report(), report("skipped", wasxfail="known gap"),
                     report("skipped", wasxfail="")):
            with self.subTest(call=call):
                value, receipt, ns = self.run_hook(call=call)
                ns["release_compatibility_root"].assert_called_once_with(
                    value.work, value.owner_binary, receipt)
                ns["remove_compatibility_root"].assert_called_once_with(value.work, value.owner_binary)
                self.assertFalse(value._managed_fixture_retention)

    def test_failures_xpasses_skips_and_uncertainty_retain(self):
        expected_xfail = report("skipped", wasxfail="known gap")
        for phase in ("setup", "call", "teardown"):
            for outcome in (None, report("failed"), report("skipped"),
                            report("passed", wasxfail="unexpected pass"),
                            report("failed", wasxfail="not an expected failure"),
                            report("skipped", wasxfail=None),
                            *([expected_xfail] if phase != "call" else [])):
                with self.subTest(phase=phase, outcome=outcome):
                    args = dict(call=expected_xfail)
                    args[phase] = outcome
                    value, _, ns = self.run_hook(**args)
                    ns["release_compatibility_root"].assert_not_called()
                    ns["remove_compatibility_root"].assert_not_called()
                    self.assertTrue(value._managed_fixture_retention)
        for args in (dict(retained=True), dict(pending=False)):
            value, _, ns = self.run_hook(call=expected_xfail, **args)
            ns["release_compatibility_root"].assert_not_called()
            ns["remove_compatibility_root"].assert_not_called()
            self.assertTrue(value._managed_fixture_retention)

    def test_expected_xfail_does_not_bypass_receipt_or_removal_guards(self):
        for release, remove in ((False, True), (True, False)):
            value, _, ns = self.run_hook(call=report("skipped", wasxfail="gap"),
                                         release=release, remove=remove)
            self.assertTrue(value._managed_fixture_retention)
            self.assertEqual(ns["remove_compatibility_root"].call_count, int(release))

    def test_remount_cleanup_is_exact_type_pass_only_and_never_generic(self):
        sys.path.insert(0, str(ROOT / "Tests/Compatibility"))
        import storage_lifecycle_v2_remount as remount
        for call in (report(), report("skipped", wasxfail="gap"), report("failed"),
                     report("passed", wasxfail="unexpected")):
            for teardown in (report(), report("failed")):
                ns = dict(pytest=pytest, release_compatibility_root=Mock(), remove_compatibility_root=Mock())
                exec(compile(HOOK_SOURCE, str(SOURCE), "exec"), ns)
                transaction = object.__new__(remount.OfflineRemount)
                transaction.value = SimpleNamespace(_retain_root=False, work=Path("/never-remove"))
                transaction.retention = object()
                item = SimpleNamespace(report_setup=report(), report_call=call,
                                       _managed_remount_cleanup=transaction)
                with patch.object(remount.OfflineRemount, "final_cleanup") as cleanup:
                    hook = ns["pytest_runtest_makereport"](item, SimpleNamespace(when="teardown"))
                    next(hook)
                    with self.assertRaises(StopIteration):
                        hook.send(SimpleNamespace(get_result=lambda: teardown))
                    self.assertEqual(cleanup.call_count, int(call.passed and not hasattr(call, "wasxfail")
                                                           and teardown.passed))
                ns["release_compatibility_root"].assert_not_called()
                ns["remove_compatibility_root"].assert_not_called()
        ns = dict(pytest=pytest, release_compatibility_root=Mock(), remove_compatibility_root=Mock())
        exec(compile(HOOK_SOURCE, str(SOURCE), "exec"), ns)
        item = SimpleNamespace(_managed_remount_cleanup=Mock(), _managed_root_cleanup=(Mock(), object()))
        hook = ns["pytest_runtest_makereport"](item, SimpleNamespace(when="teardown"))
        next(hook)
        with self.assertRaises(StopIteration):
            hook.send(SimpleNamespace(get_result=report))
        ns["release_compatibility_root"].assert_not_called()
        ns["remove_compatibility_root"].assert_not_called()

    def test_real_pytest_outcomes_and_late_finalizers(self):
        plugin = '''
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

actions = {}
reports = {}
def release_compatibility_root(work, owner, receipt):
    actions.setdefault(work, []).append("release")
    return True
def remove_compatibility_root(work, owner):
    actions[work].append("remove")
    return True
@pytest.fixture(autouse=True)
def pending_cleanup(request):
    yield
    value = SimpleNamespace(work=request.node.name, owner_binary="never-executed",
        _retain_root=False, _managed_fixture_retention=True)
    request.node._managed_root_cleanup = (value, object())
@pytest.fixture
def setup_xfail():
    pytest.xfail("setup uncertainty")
@pytest.fixture
def late_failure(request):
    request.addfinalizer(lambda: pytest.fail("late cleanup failure"))
@pytest.fixture
def late_xfail(request):
    request.addfinalizer(lambda: pytest.xfail("late uncertainty"))
def pytest_runtest_logreport(report):
    reports.setdefault(report.nodeid.split("::")[-1], {})[report.when] = dict(
        outcome=report.outcome, wasxfail=getattr(report, "wasxfail", None))
def pytest_sessionfinish(session):
    Path("outcomes.json").write_text(json.dumps(dict(actions=actions, reports=reports)))
'''
        tests = '''
import pytest

def test_pass(): pass
@pytest.mark.xfail(strict=True, reason="unsupported direct build")
def test_expected_strict(): assert False
@pytest.mark.xfail(strict=False, reason="known gap")
def test_expected_nonstrict(): assert False
def test_explicit_xfail(): pytest.xfail("known gap")
def test_failure(): assert False
def test_skip(): pytest.skip("not run")
@pytest.mark.xfail(strict=True)
def test_strict_xpass(): pass
@pytest.mark.xfail(strict=False)
def test_nonstrict_xpass(): pass
def test_setup_xfail(setup_xfail): pass
@pytest.mark.xfail(strict=True)
def test_teardown_failure(late_failure): assert False
@pytest.mark.xfail(strict=True)
def test_teardown_xfail(late_xfail): assert False
@pytest.mark.xfail(strict=True, raises=ValueError)
def test_wrong_exception(): raise RuntimeError("real failure")
'''
        with tempfile.TemporaryDirectory(prefix="fixture-outcome-offline-") as temporary:
            root = Path(temporary)
            (root / "conftest.py").write_text(plugin + "\n" + HOOK_SOURCE)
            (root / "test_outcomes.py").write_text(tests)
            (root / "pytest.ini").write_text("[pytest]\n")
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith("PYTEST_")}
            environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
            result = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                                     "--confcutdir", str(root), "-c", str(root / "pytest.ini"), str(root)],
                                    cwd=root, env=environment, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            evidence = json.loads((root / "outcomes.json").read_text())
        self.assertEqual(evidence["actions"], {
            name: ["release", "remove"] for name in (
                "test_pass", "test_expected_strict", "test_expected_nonstrict", "test_explicit_xfail")})
        strict = evidence["reports"]["test_expected_strict"]
        self.assertEqual(strict["call"], dict(outcome="skipped", wasxfail="unsupported direct build"))
        self.assertEqual(strict["setup"]["outcome"], "passed")
        self.assertEqual(strict["teardown"]["outcome"], "passed")
        self.assertEqual(evidence["reports"]["test_strict_xpass"]["call"]["outcome"], "failed")
        self.assertEqual(evidence["reports"]["test_nonstrict_xpass"]["call"]["outcome"], "passed")
        self.assertIsNotNone(evidence["reports"]["test_nonstrict_xpass"]["call"]["wasxfail"])


if __name__ == "__main__":
    unittest.main()
