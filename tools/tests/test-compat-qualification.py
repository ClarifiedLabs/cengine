#!/usr/bin/env python3
"""Offline selection/dispatch regressions; never build, install helpers or boot VMs."""
import ast
import configparser
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "Scripts/run-compat-tests.sh"
DISPATCHER = ROOT / "Scripts/run-compat-qualification.sh"


def environment(**changes):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CENGINE_", "XCODE", "PREPARE_", "PYTEST_", "QUALIFICATION", "MAKE"))}
    env.update(changes)
    return env


def selection_script():
    source = RUNNER.read_text()
    # Compose the actual early argv policy with the actual pytest dispatch.
    # Omit only the middle block that owns claims/builds/signing/helpers/VMs.
    prefix = source[:source.index("# shellcheck source=Scripts/compat-network-helper.sh")]
    tail = source[source.index('if [ "$#" -eq 0 ]; then'):]
    return prefix + '\nRESET=:\nstage() { :; }\n' + tail


class QualificationTests(unittest.TestCase):
    def sandbox(self, directory):
        root = Path(directory).resolve()
        (root / "Scripts").mkdir()
        recorder = root / "record.py"
        recorder.write_text(
            '#!' + sys.executable + '\nimport json, os, sys\n'
            'with open(os.environ["CALLS"], "a") as output:\n'
            '    output.write(json.dumps([os.environ.get("CENGINE_TEST_SEED", ""), *sys.argv[1:]]) + "\\n")\n'
            'sys.exit(int(os.environ.get("STATUS", "0")))\n')
        recorder.chmod(0o755)
        python = root / ".build/compat-venv/bin/python"
        python.parent.mkdir(parents=True)
        python.symlink_to(recorder)
        script = root / "Scripts/selection.sh"
        script.write_text(selection_script())
        return root, script

    def test_actual_marker_argv_and_soak_seeds(self):
        for mode, marker, seeds in (("suite", "not qualification", [""]),
                                     ("soak", "not qualification", ["101", "202", "303"]),
                                     ("qualification", "qualification", [""])):
            for selection in ([], ["-x", "-k", "exact case", "Tests/Compatibility/test_selected.py"]):
                with self.subTest(mode=mode, selection=selection), tempfile.TemporaryDirectory() as directory:
                    root, script = self.sandbox(directory)
                    calls = root / "calls"
                    result = subprocess.run(["sh", str(script), mode, *selection],
                        env=environment(CALLS=str(calls)), capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    selected = selection or [str(root / "Tests/Compatibility")]
                    self.assertEqual([json.loads(line) for line in calls.read_text().splitlines()],
                        [[seed, "-m", "pytest", f"--rootdir={root}", "-c",
                          str(root / "Tests/Compatibility/pytest.ini"), "-m", marker, *selected]
                         for seed in seeds])

    def test_empty_qualification_status_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root, script = self.sandbox(directory)
            result = subprocess.run(["sh", str(script), "qualification", "-k", "no_such_test"],
                env=environment(CALLS=str(root / "calls"), STATUS="5"), capture_output=True, text=True)
            self.assertEqual(result.returncode, 5, result.stderr)

    def test_invalid_runner_selection_fails_before_any_external_work(self):
        selections = (("unknown",), ("qualification", "Tests/Compatibility/test_oracle.py"),
                      ("qualification", "--markexpr=oracle"), ("qualification", "-m", "oracle"),
                      ("suite", "-mqualification"), ("soak", "--markexpr", "qualification"))
        with tempfile.TemporaryDirectory() as directory:
            # No source helpers exist here: only the real initial policy may run.
            root = Path(directory)
            (root / "Scripts").mkdir()
            runner = root / "Scripts/run-compat-tests.sh"
            shutil.copyfile(RUNNER, runner)
            for selection in selections:
                with self.subTest(selection=selection):
                    result = subprocess.run(["sh", str(runner), *selection], env=environment(),
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn("cannot open", result.stderr)
                    self.assertFalse((root / ".build").exists())

    def test_dispatcher_and_make_delegate_to_real_entry_points(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _ = self.sandbox(directory)
            dispatcher = root / "Scripts/run-compat-qualification.sh"
            shutil.copyfile(DISPATCHER, dispatcher)
            dispatcher.chmod(0o755)
            shutil.copyfile(ROOT / "Makefile", root / "Makefile")
            (root / "tools").mkdir()
            recorder = root / "record.py"
            for name, label in (("Scripts/run-compat-tests.sh", "runner"),
                                ("tools/managed-prepare-matrix.sh", "matrix")):
                path = root / name
                path.write_text('#!/bin/sh\nexec ' + shlex.quote(str(recorder)) + ' ' + label + ' "$@"\n')
                path.chmod(0o755)
            calls = root / "calls"
            env = environment(CALLS=str(calls))
            for mode, args, expected in (
                ("native", ["-k", "bundle and proof"], ["runner", "qualification",
                    str(root / "Tests/Compatibility/test_managed_fuse_interrupt.py"), "-k", "bundle and proof"]),
                ("prepare", ["--rtm", "RTM-096", "--evidence", "retained evidence"],
                    ["matrix", "--rtm", "RTM-096", "--evidence", "retained evidence"]),
            ):
                calls.unlink(missing_ok=True)
                result = subprocess.run(["make", "--no-print-directory", "test-compat-qualification",
                    f"QUALIFICATION={mode}", "QUALIFICATION_ARGS=" + shlex.join(args)], cwd=root,
                    env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(calls.read_text()), ["", *expected])
            for mode in ("", "unknown", "oracle"):
                calls.unlink(missing_ok=True)
                result = subprocess.run(["make", "--no-print-directory", "test-compat-qualification",
                    f"QUALIFICATION={mode}"], cwd=root, env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("QUALIFICATION=native|prepare", result.stderr)
                self.assertFalse(calls.exists())
            literal = '$(touch should-not-exist)'
            result = subprocess.run(["sh", str(dispatcher), "prepare", "--evidence", literal],
                cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(calls.read_text()), ["", "matrix", "--evidence", literal])
            self.assertFalse((root / "should-not-exist").exists())

    def test_marker_registered_and_prepare_refusals_intact(self):
        config = configparser.ConfigParser()
        config.read(ROOT / "Tests/Compatibility/pytest.ini")
        self.assertIn("qualification:", config["pytest"]["markers"])
        source = ast.parse((ROOT / "Tests/Compatibility/test_managed_prepare_faults.py").read_text())
        marker = next(node for node in source.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets))
        self.assertEqual(ast.unparse(marker.value), "pytest.mark.qualification")
        tests = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]
        self.assertEqual(len(tests), 5)
        for test in tests:
            self.assertEqual(len(test.body), 1)
            self.assertEqual(ast.unparse(test.body[0].value.func), "pytest.fail")
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("@python3 tools/tests/test-compat-qualification.py", makefile)
        self.assertIn("QUALIFICATION=native|prepare", makefile)

    def collection_sandbox(self, directory, ledger_ids=("REG-001", "QLF-001")):
        python = ROOT / ".build/compat-venv/bin/python"
        if not python.is_file():
            self.skipTest("compatibility pytest virtualenv not installed")
        root, script = self.sandbox(directory)
        stub = root / ".build/compat-venv/bin/python"
        stub.unlink()
        stub.write_text('#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' "$@"\n')
        stub.chmod(0o755)
        suite = root / "Tests/Compatibility"
        suite.mkdir(parents=True)
        shutil.copyfile(ROOT / "Tests/Compatibility/pytest.ini", suite / "pytest.ini")
        # Run the real collection hooks under pytest, without loading runtime
        # fixtures, runner ownership checks, helpers, Docker clients or VMs.
        tree = ast.parse((ROOT / "Tests/Compatibility/conftest.py").read_text())
        hooks = [ast.unparse(node) for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in (
                     "pytest_collection_modifyitems", "pytest_collection_finish",
                     "validate_compatibility_collection")]
        (suite / "conftest.py").write_text(
            'from __future__ import annotations\nimport os, pathlib, random, re, pytest\n'
            'REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]\n' + '\n\n'.join(hooks))
        (root / "docs").mkdir()
        (root / "docs/docker-compatibility.md").write_text(
            ''.join(f'| `{compat_id}` | contract |\n' for compat_id in ledger_ids))
        (suite / "test_selection.py").write_text(
            'import pytest\n@pytest.mark.compat("REG-001")\ndef test_regular(): pass\n'
            '@pytest.mark.qualification\n@pytest.mark.compat("QLF-001")\n'
            'def test_qualification(): pass\n')
        return root, script, suite

    def collect(self, root, script, mode="suite", *selection):
        return subprocess.run(
            ["sh", str(script), mode, "--collect-only", "-q", *selection], cwd=root,
            env=environment(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"), capture_output=True, text=True)

    def test_full_collection_rejects_missing_ordinary_and_qualification_ledger_ids(self):
        for missing in ("REG-002", "QLF-002"):
            for mode in ("suite", "qualification"):
                with self.subTest(missing=missing, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root, script, _ = self.collection_sandbox(directory, ("REG-001", "QLF-001", missing))
                    result = self.collect(root, script, mode)
                    self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
                    self.assertIn("compatibility ledger IDs have no tests: " + missing, result.stderr)

    def test_full_collection_validates_deselected_qualification_markers(self):
        for marker, message in (
            ('', "is missing one @pytest.mark.compat ID"),
            ('@pytest.mark.compat("QLF-999")\n', "QLF-999 is missing from docs/docker-compatibility.md"),
            ('@pytest.mark.compat("REG-001")\n', "duplicate compatibility ID: REG-001"),
        ):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                root, script, suite = self.collection_sandbox(directory)
                (suite / "test_selection.py").write_text(
                    'import pytest\n@pytest.mark.compat("REG-001")\ndef test_regular(): pass\n'
                    '@pytest.mark.qualification\n' + marker + 'def test_qualification(): pass\n')
                result = self.collect(root, script)
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)

    def test_focused_module_and_node_collection_allow_other_ledger_ids(self):
        for selection in ("Tests/Compatibility/test_selection.py",
                          "Tests/Compatibility/test_selection.py::test_regular"):
            with self.subTest(selection=selection), tempfile.TemporaryDirectory() as directory:
                root, script, _ = self.collection_sandbox(directory, ("REG-001", "QLF-001", "REG-002"))
                result = self.collect(root, script, "suite", selection)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("::test_regular", result.stdout)

    def test_keyword_collection_allows_other_ledger_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root, script, _ = self.collection_sandbox(directory, ("REG-001", "QLF-001", "REG-002"))
            result = self.collect(root, script, "suite", "-k", "regular")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("::test_regular", result.stdout)
            self.assertNotIn("::test_qualification", result.stdout)

    def test_valid_full_collection_allows_qualification_deselection(self):
        for mode, included, excluded in (("suite", "test_regular", "test_qualification"),
                                         ("qualification", "test_qualification", "test_regular")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, script, _ = self.collection_sandbox(directory)
                result = self.collect(root, script, mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("::" + included, result.stdout)
                self.assertNotIn("::" + excluded, result.stdout)

    def test_real_pytest_collection_excludes_qualification_and_empty_fails(self):
        python = ROOT / ".build/compat-venv/bin/python"
        if not python.is_file():
            self.skipTest("compatibility pytest virtualenv not installed")
        with tempfile.TemporaryDirectory() as directory:
            root, script = self.sandbox(directory)
            stub = root / ".build/compat-venv/bin/python"
            stub.unlink()
            stub.write_text('#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' "$@"\n')
            stub.chmod(0o755)
            suite = root / "Tests/Compatibility"
            suite.mkdir(parents=True)
            shutil.copyfile(ROOT / "Tests/Compatibility/pytest.ini", suite / "pytest.ini")
            (suite / "test_selection.py").write_text(
                'import pytest\ndef test_regular(): pass\n'
                '@pytest.mark.qualification\ndef test_qualification(): pass\n')
            for mode, included, excluded in (("suite", "test_regular", "test_qualification"),
                                               ("qualification", "test_qualification", "test_regular")):
                result = subprocess.run(["sh", str(script), mode, "--collect-only", "-q"], cwd=root,
                    env=environment(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("::" + included, result.stdout)
                self.assertNotIn("::" + excluded, result.stdout)
            result = subprocess.run(["sh", str(script), "qualification", "-k", "no_such_test", "-q"],
                cwd=root, env=environment(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"), capture_output=True, text=True)
            self.assertEqual(result.returncode, 5, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
