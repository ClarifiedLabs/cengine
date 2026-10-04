#!/usr/bin/env python3
"""Engine-free RTM-081/082/083/085/087 guards. Never execute Docker, Go, helper or a VM."""
from __future__ import annotations

import ast
import copy
from contextlib import nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
COMPAT = ROOT / "Tests/Compatibility"
sys.path.insert(0, str(COMPAT))
import managed_fuse_artifact as artifact
import managed_storage as smoke
import storage_backend_proof as backend
from volume_probe import read_bounded


def load(path, namespace):
    tree = ast.parse(path.read_text())
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            node = copy.deepcopy(node)
            node.decorator_list = []
            nodes.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            nodes.append(node)
    module = ModuleType(path.stem)
    module.__dict__.update(namespace, __file__=str(path))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), module.__dict__)
    return module, tree


common = dict(json=json, os=os, Path=Path, re=re, shutil=shutil, signal=signal, stat=stat, subprocess=subprocess,
              sys=sys, threading=threading, time=time, SimpleNamespace=SimpleNamespace, uuid=__import__("uuid"), smoke=smoke,
              backend=backend, artifact=artifact, REPO_ROOT=ROOT, read_bounded=read_bounded)
direct, _ = load(COMPAT / "test_volume_xattrs.py", dict(common, hashlib=hashlib, io=io, struct=struct, tarfile=tarfile))
xattrs, _ = load(COMPAT / "test_managed_volume_xattrs.py", dict(common, direct=direct))
case, TREE = load(COMPAT / "test_managed_fuse_interrupt.py", dict(common, direct=direct,
    EvidenceJournal=xattrs.EvidenceJournal, file_stamp=xattrs.file_stamp, Mount=lambda **kwargs: kwargs))


def proof(case_id="RTM-081"):
    def fs(kind, device, ro, size):
        return dict(type=kind, device=device, read_only=ro, bytes=size)
    return dict(case=case_id, test=case.selected_test(case_id), success=True, exit=0, passes=len(artifact.selection(case_id)["expected"]), skips=0, passed_tests=artifact.selection(case_id)["expected"],
        kernel="6.18.8-cengine", architecture="arm64", root=fs(0xef53, 1, True, 1 << 30),
        scratch=fs(0xef53, 2, False, 512 << 30), tmp=fs(0x01021994, 3, False, 32 << 20),
        fusectl=True, uring_enabled=True, protected_hardlinks=True, test_sha256="a" * 64,
        log_sha256="b" * 64, log_bytes=512, bounded=fs(0xef53, 4, False, 128 << 20),
        backing_bytes=128 << 20, loop_autoclear=True, loop_clean=True, formatter_sha256="c" * 64, formatter_checked=True)


STATE = dict(Running=False, ExitCode=0, OOMKilled=False)


# Exercise the existing streaming reader without importing its engine modules.
_log_source = ast.parse((COMPAT / "fixtures/volume-workflows/campaign.py").read_text())
_log_namespace = dict(time=time, MAX_RESULT=1 << 20, api_deadline=lambda *args: nullcontext())
exec(compile(ast.Module(body=[node for node in _log_source.body if isinstance(node, ast.FunctionDef)
    and node.name == "read_logs"], type_ignores=[]), "workflow-read-logs", "exec"), _log_namespace)


def diagnostic_fixture(stdout=b'{"success":false}', stderr=b"private failure"):
    plan = smoke.names("a" * 32)
    streams = []
    class Stream:
        def __init__(self, data):
            self.data, self.close = data, Mock()
        def __iter__(self):
            return iter([self.data])
    def logs(**kwargs):
        stream = Stream(stdout if kwargs["stdout"] else stderr)
        streams.append(stream)
        return stream
    container = SimpleNamespace(id="c" * 64, name=plan["containers"][0], attrs={"Config": {
        "Cmd": ["/setup", "RTM-082"], "Labels": {smoke.OWNER: plan["owner"],
        case.CASE_LABEL: "RTM-082", case.TEST_LABEL: case.TESTS["RTM-082"]}}, "State": dict(STATE, Running=True)},
        logs=Mock(side_effect=logs))
    client = SimpleNamespace(containers=SimpleNamespace(get=Mock(return_value=container)))
    campaign = SimpleNamespace(api_deadline=Mock(side_effect=lambda *args: nullcontext()),
        read_logs=Mock(side_effect=_log_namespace["read_logs"]))
    return campaign, client, container, plan, streams


class InterruptGuards(unittest.TestCase):
    def test_closed_case_selection_binds_argv_labels_and_proof(self):
        expected = {"RTM-081": "TestNativeMountedManagedV3InterruptGraceful",
                    "RTM-082": "TestNativeMountedManagedV3WriteBurstGraceful",
                    "RTM-083": "TestNativeMountedManagedV3SparseMmapGraceful",
                    "RTM-085": "TestNativeMountedManagedV3FsxGraceful",
                    "RTM-087": "TestNativeIssuedDataTLSRejectsRetiredAndPreviousServiceCredentials"}
        expected.update({key: artifact.selection(key)["test"] for key in ("RTM-089", "RTM-090", "RTM-091", "RTM-092", "RTM-093", "RTM-094", "RTM-095", "RTM-101", "RTM-102", "RTM-104", "RTM-107", "RTM-108", "RTM-109", "RTM-110", "RTM-113")})
        self.assertEqual(case.TESTS, expected)
        plan = smoke.names("a" * 32)
        tags = set()
        for case_id, test in expected.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(case.selected_test(case_id), test)
                args = ["runner", "--worker", "/binary", "/root", "/socket", "/work", "1", "{}", case_id]
                self.assertEqual(case.worker_case(args), case_id)
                with patch.object(artifact, "validate_fsx", return_value=b"pinned-fsx") as validate:
                    _, config, tag = case.image_archive(b"native", b"setup", b"formatter", plan, case_id,
                                                        fsx=b"pinned-fsx" if case_id == "RTM-085" else None)
                    if case_id == "RTM-085": validate.assert_called_once_with(b"pinned-fsx")
                    else: validate.assert_not_called()
                tags.add(tag)
                self.assertRegex(tag, r"^compat-managed-fuse-interrupt:[0-9a-f]{64}$")
                self.assertEqual(config["config"]["Cmd"], ["/setup", case_id])
                self.assertEqual(config["config"]["Labels"], {smoke.OWNER: plan["owner"],
                    case.CASE_LABEL: case_id, case.TEST_LABEL: test})
                value = proof(case_id)
                self.assertEqual(case.native_proof(json.dumps(value).encode(), STATE, "a" * 64, "c" * 64, case_id), value)
                other = "RTM-082" if case_id == "RTM-081" else "RTM-081"
                for wrong in (proof(other), dict(value, case=other), dict(value, test=expected[other])):
                    with self.assertRaises(ValueError):
                        case.native_proof(json.dumps(wrong).encode(), STATE, "a" * 64, "c" * 64, case_id)
                entry = {"RTM-081": case.test_native_managed_fuse_interrupt,
                         "RTM-082": case.test_native_managed_fuse_write_burst,
                         "RTM-083": case.test_native_managed_fuse_sparse_mmap,
                         "RTM-085": case.test_native_managed_fuse_full_fsx,
                         "RTM-087": case.test_native_managed_data_stale_credentials,
                         "RTM-089": case.test_native_service_faults, "RTM-090": case.test_native_fault_tuple_regression,
                         "RTM-091": case.test_native_symlink_root_rollback, "RTM-092": case.test_native_managed_valid_capability,
                         "RTM-093": case.test_native_issued_prepare_initializer_preflight,
                         "RTM-094": case.test_native_pending_prepare_fresh_mount_replay,
                         "RTM-095": case.test_native_prepare_ext4_identity_and_cleanup,
                         "RTM-101": case.test_native_prepare_snapshot_fence,
                         "RTM-102": case.test_native_prepare_ext4_identity_authenticity,
                         "RTM-104": case.test_native_prepare_process_poll_eintr,
                         "RTM-107": case.test_native_durability_fail_closed_policy,
                         "RTM-108": case.test_native_retirement_completion_recovery,
                         "RTM-109": case.test_native_copy_data_recovery,
                         "RTM-110": case.test_native_prepare_retirement_recovery,
                         "RTM-113": case.test_native_storage_lifecycle_checkpoint}[case_id]
                with patch.object(case, "run_native_case") as run:
                    entry("owned-daemon")
                    run.assert_called_once_with("owned-daemon", case_id)
        self.assertEqual(len(tags), 20)
        for wrong in ("RTM-084", "RTM-086", "RTM-088", "RTM-107 ", "RTM-108 ", "RTM-109 ", "RTM-110 ", "RTM-111", "rtm-108", "rtm-109", "rtm-110", expected["RTM-110"], "TestNativePrepareRetirementWorker", expected["RTM-109"], "TestNativeCopyDataRecoveryWorker", expected["RTM-108"], expected["RTM-107"], "RTM-087 ", "RTM-083 ", "RTM-082 ", ".*", expected["RTM-087"], expected["RTM-082"], "", None, True, {}):
            with self.subTest(wrong=wrong):
                for operation in (lambda: case.selected_test(wrong),
                    lambda: case.image_archive(b"native", b"setup", b"formatter", plan, wrong),
                    lambda: case.native_proof(b"", STATE, "a" * 64, "c" * 64, wrong),
                    lambda: case.worker_case(["runner", "--worker", "", "", "", "", "", "", wrong]),
                    lambda: case.run_campaign(None, 0, wrong), lambda: case.run_native_case(None, wrong)):
                    with self.assertRaises(ValueError): operation()
        for args in (["runner"], ["runner", "--worker"] + [""] * 6,
                     ["runner", "--worker"] + [""] * 7 + ["RTM-082"],
                     ["runner", "--other"] + [""] * 6 + ["RTM-082"]):
            with self.assertRaises(ValueError): case.worker_case(args)

    def test_helper_closed_selector_and_exact_entrypoints(self):
        source = (COMPAT / "fixtures/managed-fuse-native.go").read_text()
        selector = re.search(r'func selectedTest\(caseID string\) \(string, error\) \{(.*?)\n\}', source, re.S).group(1)
        choices = re.findall(r'case "([^"]+)":\s*return "([^"]+)", nil', selector)
        self.assertEqual(len(choices), 20)
        self.assertEqual(dict(choices), case.TESTS)
        self.assertIn('default:', selector)
        self.assertIn('errors.New("unknown native case")', selector)
        self.assertIn('testName, err := selectedTest(os.Args[2])', source)
        self.assertIn('testName, err := selectedTest(r.Case)', source)
        self.assertIn('err != nil || r.Test != testName', source)
        self.assertIn('exec.CommandContext(ctx, "/setup", "--native-child", r.Case)', source)
        self.assertIn('testName, selectionErr := selectedTest(os.Args[1])', source)
        self.assertNotIn('os.Getenv', source)
        registered = {}
        for node in TREE.body:
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and ast.unparse(decorator.func) == "pytest.mark.compat":
                        identifier = ast.literal_eval(decorator.args[0])
                        self.assertNotIn(identifier, registered)
                        registered[identifier] = node.name
        self.assertEqual(registered, {"RTM-081": "test_native_managed_fuse_interrupt",
                                     "RTM-082": "test_native_managed_fuse_write_burst",
                                     "RTM-083": "test_native_managed_fuse_sparse_mmap",
                                     "RTM-085": "test_native_managed_fuse_full_fsx",
                                     "RTM-087": "test_native_managed_data_stale_credentials",
                                     "RTM-089": "test_native_service_faults", "RTM-090": "test_native_fault_tuple_regression",
                                     "RTM-091": "test_native_symlink_root_rollback", "RTM-092": "test_native_managed_valid_capability",
                                     "RTM-093": "test_native_issued_prepare_initializer_preflight",
                                     "RTM-094": "test_native_pending_prepare_fresh_mount_replay",
                                     "RTM-095": "test_native_prepare_ext4_identity_and_cleanup",
                                     "RTM-101": "test_native_prepare_snapshot_fence",
                                     "RTM-102": "test_native_prepare_ext4_identity_authenticity",
                                     "RTM-104": "test_native_prepare_process_poll_eintr",
                                     "RTM-107": "test_native_durability_fail_closed_policy",
                                     "RTM-108": "test_native_retirement_completion_recovery",
                                     "RTM-109": "test_native_copy_data_recovery",
                                     "RTM-110": "test_native_prepare_retirement_recovery",
                                     "RTM-113": "test_native_storage_lifecycle_checkpoint"})

    def test_prepare_v4_registrations_and_native_parents_are_unique(self):
        wanted = {
            "RTM-093": "test_native_issued_prepare_initializer_preflight",
            "RTM-094": "test_native_pending_prepare_fresh_mount_replay",
            "RTM-095": "test_native_prepare_ext4_identity_and_cleanup",
            "RTM-101": "test_native_prepare_snapshot_fence",
            "RTM-102": "test_native_prepare_ext4_identity_authenticity",
            "RTM-104": "test_native_prepare_process_poll_eintr",
        }
        found = {identifier: [] for identifier in wanted}
        for path in COMPAT.glob("test_*.py"):
            for node in ast.parse(path.read_text()).body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                for decorator in node.decorator_list:
                    if (isinstance(decorator, ast.Call) and
                            ast.unparse(decorator.func) == "pytest.mark.compat" and
                            decorator.args and isinstance(decorator.args[0], ast.Constant)):
                        identifier = decorator.args[0].value
                        if identifier in found:
                            found[identifier].append((path.name, node.name))
        docs = (ROOT / "docs/docker-compatibility.md").read_text()
        for identifier, name in wanted.items():
            self.assertEqual(found[identifier], [("test_managed_fuse_interrupt.py", name)])
            self.assertEqual(docs.count("| `" + identifier + "` | `" + name + "` |"), 1)
            self.assertEqual(len(re.findall(r"^\| `" + identifier + r"` \|", docs, re.M)), 1)
            selected = artifact.selection(identifier)
            package = ROOT / "Guest" / selected["package"].removeprefix("./")
            source = "\n".join(path.read_text() for path in package.glob("*_test.go"))
            for parent in selected["test"].split("|"):
                self.assertEqual(len(re.findall(r"^func " + parent + r"\(t \*testing.T\)", source, re.M)), 1)

    def test_helper_fixed_case_budgets_reject_unknown_ids(self):
        source = (COMPAT / "fixtures/managed-fuse-native.go").read_text()
        budget = re.search(r'func selectedCaseBudget\(caseID string\) \(string, time.Duration, error\) \{(.*?)\n\}', source, re.S).group(1)
        # Exact static policy: no fallback allowance, prefix matching, caller
        # duration, environment override, or test-name pattern can select a budget.
        self.assertEqual(" ".join(budget.split()), " ".join('''
            switch caseID {
            case "RTM-081", "RTM-082", "RTM-083", "RTM-087", "RTM-104":
                return "-test.timeout=90s", 95 * time.Second, nil
            case "RTM-085", "RTM-089", "RTM-091", "RTM-092", "RTM-093", "RTM-094", "RTM-095", "RTM-101", "RTM-102", "RTM-107", "RTM-108", "RTM-109", "RTM-110":
                return "-test.timeout=180s", 190 * time.Second, nil
            case "RTM-090":
                return "-test.timeout=120s", 130 * time.Second, nil
            case "RTM-113": // 65 real TLS takeovers; no widening of existing cases.
                return "-test.timeout=180s", 190 * time.Second, nil
            default:
                return "", 0, errors.New("unknown native case")
            }
        '''.split()))
        self.assertEqual(source.count('selectedCaseBudget('), 3)
        child = source.split('func nativeChild() error {', 1)[1].split('\n}', 1)[0]
        runner = source.split('func run(r *result, l *ownedLoop) error {', 1)[1].split('\n}', 1)[0]
        self.assertIn('testTimeout, _, err := selectedCaseBudget(os.Args[2])\n\tif err != nil {\n\t\treturn err\n\t}', child)
        self.assertIn('"-test.count=1", testTimeout, "-test.run=^(" + testName + ")$"', child)
        self.assertIn('_, outerLimit, err := selectedCaseBudget(r.Case)\n\tif err != nil {\n\t\treturn err\n\t}', runner)
        self.assertIn('context.WithTimeout(context.Background(), outerLimit)', runner)
        self.assertNotIn('os.Getenv', source)
        self.assertNotIn('os.LookupEnv', source)
        protocol = (ROOT / "Guest/internal/storagefuse/native_fsx_protocol_test.go").read_text()
        self.assertRegex(protocol, r'fsxChildLimit\s*=\s*150 \* time.Second')
        self.assertRegex(protocol, r'fsxDiagnosticAfter\s*=\s*20 \* time.Second')
        self.assertIn('"-N", "1000"', protocol)
        self.assertIn('"-d", "-S", "1"', protocol)
        native = (ROOT / "Guest/internal/storagefuse/native_fsx_linux_test.go").read_text()
        self.assertIn('child-seconds=%d\\n", fsxSHA256, fsxBinaryBytes, int(fsxChildLimit/time.Second)', native)
        self.assertIn('budget := min(time.Second, time.Until(started.Add(fsxChildLimit)))', native)
        self.assertIn('hard := time.NewTimer(time.Until(started.Add(fsxChildLimit)))', native)
        wrapper = ast.unparse(TREE)
        self.assertIn('work_deadline, final_deadline = (started + 210, started + 232)', wrapper)
        self.assertIn('started + 234 - time.monotonic()', wrapper)
        self.assertIn('retain_failure(daemon, started + 240)', wrapper)

    def test_stale_credentials_is_standalone_native_component_with_strict_rejections(self):
        native = (ROOT / "Guest/internal/storagefuse/native_stale_credentials_linux_test.go").read_text()
        self.assertFalse((ROOT / "Guest/internal/storageserver/stale_credentials_linux_test.go").exists())
        self.assertIn('package storagefuse_test', native)
        self.assertEqual(re.findall(r'func (Test\w+)\(', native), [case.TESTS["RTM-087"]])
        self.assertEqual(native.count('t.Skip('), 1)
        self.assertIn('if os.Geteuid() != 0 {\n\t\tt.Skip(', native)
        self.assertLess(native.index('filepath.Clean(os.TempDir()) != "/scratch"'), native.index('os.MkdirTemp('))
        for required in ('unix.EXT4_SUPER_MAGIC', '"6.18."', 'os.MkdirTemp("/scratch",', 'if !t.Failed()',
                         's.InitializeLifecycle(', 's.ReopenLifecycle(', 'service.ServeControl', 'service.ServeAttachmentCSR',
                         'p.NewAttachmentKey(p.RuntimeRole)', 'key.CSR(binding)', 's.RequestLifecycleAttachmentCertificate(',
                         'cert.WithKey(key)', 'service.ServeData', 'p.ClientTLSConfig(', 'conn.Handshake()',
                         'p.VerifyServer(conn.ConnectionState(), root, server, ready.ServerKey)',
                         'cfg.GetClientCertificate =', 'len(verification.UnverifiedCertificates) != 1',
                         'bytes.Equal(verification.UnverifiedCertificates[0].Raw, oldIdentity.Certificate().DER())',
                         'errors.As(serverErr, &verification)', 'errors.As(serverErr, &unknown)',
                         'x509.UnknownAuthorityError', 'tls.CertificateVerificationError',
                         'staleDataTLS(t, next, nextReady, oldIdentity, true)',
                         'before.Epoch != hello.Epoch', 'after.Revision != before.Revision',
                         'currentState.Revision != nextReady.Revision', 'a.Drained',
                         'staleCreate(t, conn, 1, "before-retire")', 'staleCreate(t, fresh, 1, "after-reopen")',
                         'staleMust(t, next.Close())', 'case <-time.After(10 * time.Second):',
                         'unexpected admission, NOT evidence of transport rejection'):
            self.assertIn(required, native)
        self.assertEqual(native.count('!errors.Is(err, a.ErrBlocked)'), 2)
        for name in ('retired-live', 'retired-reconnect', 'previous-epoch'):
            self.assertIn(f'staleAbsent(t, path, "{name}")', native)
        for forbidden in ('InsecureSkipVerify', 'KeyLogWriter', 'MarshalPrivateKey', 'PrivateKeyPEM',
                          'os.WriteFile', 't.TempDir()', 'exec.Command', 'unix.Mount(', 'nativeMountedManagedV3('):
            self.assertNotIn(forbidden, native)
        plan = smoke.names("a" * 32)
        archive, config, _ = case.image_archive(b"native", b"setup", b"formatter", plan, "RTM-087")
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            layer = outer.extractfile("blobs/sha256/" + config["rootfs"]["diff_ids"][0].split(":")[1]).read()
            with tarfile.open(fileobj=io.BytesIO(layer)) as inner:
                self.assertEqual(inner.getnames(), ["native.test", "setup", "mke2fs", "mke2fs.sha256", "scratch", "tmp"])
        docs = (ROOT / "docs/docker-compatibility.md").read_text()
        self.assertEqual(docs.count('| `RTM-087` |'), 1)
        row = next(line for line in docs.splitlines() if line.startswith('| `RTM-087` |'))
        for required in ('test_native_managed_data_stale_credentials', 'component', 'RTM-084',
                         '90s', '95s', '240s', '128-MiB', 'fsync(2)', 'TLS 1.3'):
            self.assertIn(required, row)

    def test_stale_credentials_rejects_skip_and_incomplete_cleanup_proofs(self):
        value = proof("RTM-087")
        for key, wrong in (("skips", 1), ("passes", 0), ("passes", 2), ("loop_clean", False),
                           ("loop_autoclear", False), ("formatter_checked", False), ("success", False)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, **{key: wrong})).encode(), STATE, "a" * 64, "c" * 64, "RTM-087")

    def test_exact_pass_proof_and_negative_vector(self):
        value = proof()
        self.assertEqual(case.native_proof(json.dumps(value).encode(), STATE, "a" * 64, "c" * 64), value)
        for key, values in {"success": (False, 1), "passes": (0, 2, True), "skips": (1, False),
            "exit": (1, False), "test": ("other",), "test_sha256": ("c" * 64,), "log_sha256": ("SECRET",),
            "log_bytes": (0, True, (128 << 10) + 1), "kernel": ("6.17.1", "6.18.1 SECRET"),
            "architecture": ("amd64",), "fusectl": (False, 1), "uring_enabled": (False,), "protected_hardlinks": (False,),
            "loop_clean": (False, 1), "loop_autoclear": (False,), "backing_bytes": ((128 << 20) + 1, True),
            "formatter_sha256": ("e" * 64,), "formatter_checked": (False, 1)}.items():
            for wrong in values:
                with self.subTest(key=key, wrong=wrong), self.assertRaises((ValueError, TypeError)):
                    case.native_proof(json.dumps(dict(value, **{key: wrong})).encode(), STATE, "a" * 64, "c" * 64)
        for state in (dict(STATE, Running=True), dict(STATE, ExitCode=1), dict(STATE, ExitCode=False),
                      dict(STATE, OOMKilled=True), {}):
            with self.subTest(state=state), self.assertRaises(ValueError):
                case.native_proof(json.dumps(value).encode(), state, "a" * 64, "c" * 64)
        for raw in (b"", b"{}", b"x" * 8193, json.dumps(value).encode() + b'\n{}',
                    json.dumps(dict(value, token="PRIVATE")).encode(),
                    json.dumps(value).replace('"passes": 1', '"passes": 1, "passes": 1').encode()):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                case.native_proof(raw, STATE, "a" * 64, "c" * 64)

    def test_durability_process_death_rejects_hash_schema_skip_and_incomplete_names(self):
        value = proof("RTM-107")
        self.assertEqual(value["passes"], 8)
        for key, wrong in (("test_sha256", "d" * 64), ("formatter_sha256", "d" * 64),
                           ("log_sha256", "invalid"), ("passes", 1), ("passes", 7),
                           ("passes", 9), ("skips", 1), ("loop_clean", False)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, **{key: wrong})).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-107")
        for raw in (json.dumps(dict(value, recovery="accepted")).encode(),
                    json.dumps({key: item for key, item in value.items() if key != "passed_tests"}).encode(),
                    json.dumps(value).replace('"passes": 8', '"passes": 8, "passes": 8').encode()):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                case.native_proof(raw, STATE, "a" * 64, "c" * 64, "RTM-107")
        names = value["passed_tests"]
        self.assertEqual(names[0], "TestDurabilityPolicyHelpers")
        for wrong in ([names[0]], names[1:], names[:-1], names + [names[0]],
                      names + [names[0] + "/negative"],
                      names[:-1] + [names[-1] + "Extra"], list(reversed(names))):
            with self.subTest(names=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, passed_tests=wrong)).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-107")

    def test_retirement_recovery_rejects_bad_proof_and_incomplete_names(self):
        value = proof("RTM-108")
        helper = "TestNativeRetirementRecoveryHelpers"
        name = "TestNativeRetirementRecoveryProcessDeath"
        names = [helper, name, name + "/candidate", name + "/certified", name + "/completed",
                 name + "/prepared", name + "/published"]
        self.assertEqual(value["passed_tests"], names)
        self.assertEqual(value["passes"], 7)
        self.assertEqual(case.native_proof(json.dumps(value).encode(), STATE,
                                          "a" * 64, "c" * 64, "RTM-108"), value)
        for key, wrong in (("case", "RTM-107"), ("test", name), ("success", False), ("success", 1),
                           ("test_sha256", "d" * 64), ("formatter_sha256", "d" * 64),
                           ("log_sha256", "invalid"), ("passes", 1), ("passes", 5),
                           ("passes", 6), ("passes", 8), ("skips", 1), ("loop_clean", False),
                           ("backing_bytes", (128 << 20) + 1)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, **{key: wrong})).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-108")
        for raw in (json.dumps(dict(value, recovery="accepted")).encode(),
                    json.dumps({key: item for key, item in value.items() if key != "passed_tests"}).encode(),
                    json.dumps(value).replace('"passes": 7', '"passes": 7, "passes": 7').encode()):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                case.native_proof(raw, STATE, "a" * 64, "c" * 64, "RTM-108")
        wrong_names = [[names[0]], names + ["TestForeign"], names[:-1] + [names[-1] + "Extra"],
                       list(reversed(names))]
        for index in range(len(names)):
            wrong_names.extend((names[:index] + names[index + 1:], names + [names[index]]))
        for wrong in wrong_names:
            with self.subTest(names=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, passed_tests=wrong)).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-108")

    def test_retirement_recovery_registration_is_unique(self):
        found = []
        for path in COMPAT.glob("test_*.py"):
            for node in ast.parse(path.read_text()).body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                for decorator in node.decorator_list:
                    if (isinstance(decorator, ast.Call) and
                            ast.unparse(decorator.func) == "pytest.mark.compat" and
                            decorator.args and isinstance(decorator.args[0], ast.Constant) and
                            decorator.args[0].value == "RTM-108"):
                        found.append((path.name, node.name))
        self.assertEqual(found, [("test_managed_fuse_interrupt.py", "test_native_retirement_completion_recovery")])

    def test_copy_data_recovery_rejects_bad_proof_and_incomplete_names(self):
        value = proof("RTM-109")
        helper = "TestNativeCopyDataRecoveryHelpers"
        name = "TestNativeCopyDataRecoveryProcessDeath"
        names = [helper, name, name + "/cleaning-tail", name + "/completed-tail",
                 name + "/rename", name + "/root-metadata", name + "/sealed-tail"]
        self.assertEqual(value["passed_tests"], names)
        self.assertEqual(value["passes"], 7)
        self.assertEqual(case.native_proof(json.dumps(value).encode(), STATE,
                                          "a" * 64, "c" * 64, "RTM-109"), value)
        for key, wrong in (("case", "RTM-108"), ("test", name), ("success", False), ("success", 1),
                           ("test_sha256", "d" * 64), ("formatter_sha256", "d" * 64),
                           ("log_sha256", "invalid"), ("passes", 1), ("passes", 5),
                           ("passes", 6), ("passes", 8), ("skips", 1), ("loop_clean", False),
                           ("backing_bytes", (128 << 20) + 1)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, **{key: wrong})).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-109")
        for raw in (json.dumps(dict(value, recovery="accepted")).encode(),
                    json.dumps(dict(value, waiver=True)).encode(),
                    json.dumps({key: item for key, item in value.items() if key != "passed_tests"}).encode(),
                    json.dumps(value).replace('"passes": 7', '"passes": 7, "passes": 7').encode()):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                case.native_proof(raw, STATE, "a" * 64, "c" * 64, "RTM-109")
        wrong_names = [[names[0]], names + ["TestForeign"], names[:-1] + [names[-1] + "Extra"],
                       names + ["TestNativeCopyDataRecoveryWorker"], list(reversed(names))]
        for index in range(len(names)):
            wrong_names.extend((names[:index] + names[index + 1:], names + [names[index]]))
        for wrong in wrong_names:
            with self.subTest(names=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, passed_tests=wrong)).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-109")

    def test_copy_data_recovery_registration_is_unique(self):
        found = []
        for path in COMPAT.glob("test_*.py"):
            for node in ast.parse(path.read_text()).body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                for decorator in node.decorator_list:
                    if (isinstance(decorator, ast.Call) and
                            ast.unparse(decorator.func) == "pytest.mark.compat" and
                            decorator.args and isinstance(decorator.args[0], ast.Constant) and
                            decorator.args[0].value == "RTM-109"):
                        found.append((path.name, node.name))
        self.assertEqual(found, [("test_managed_fuse_interrupt.py", "test_native_copy_data_recovery")])

    def test_prepare_retirement_rejects_bad_proof_and_incomplete_names(self):
        value = proof("RTM-110")
        helper = "TestNativePrepareRetirementHelpers"
        name = "TestNativePrepareRetirementProcessDeath"
        names = [helper, name, name + "/completed", name + "/inside-barrier", name + "/published"]
        self.assertEqual(value["passed_tests"], names)
        self.assertEqual(value["passes"], 5)
        self.assertEqual(case.native_proof(json.dumps(value).encode(), STATE,
                                          "a" * 64, "c" * 64, "RTM-110"), value)
        for key, wrong in (("case", "RTM-109"), ("test", name), ("success", False), ("success", 1),
                           ("test_sha256", "d" * 64), ("formatter_sha256", "d" * 64),
                           ("log_sha256", "invalid"), ("passes", 1), ("passes", 4),
                           ("passes", 6), ("skips", 1), ("loop_clean", False),
                           ("backing_bytes", (128 << 20) + 1)):
            with self.subTest(key=key, wrong=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, **{key: wrong})).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-110")
        for raw in (json.dumps(dict(value, recovery="accepted")).encode(),
                    json.dumps(dict(value, waiver=True)).encode(),
                    json.dumps({key: item for key, item in value.items() if key != "passed_tests"}).encode(),
                    json.dumps(value).replace('"passes": 5', '"passes": 5, "passes": 5').encode()):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                case.native_proof(raw, STATE, "a" * 64, "c" * 64, "RTM-110")
        wrong_names = [[names[0]], names + ["TestForeign"], names[:-1] + [names[-1] + "Extra"],
                       names + ["TestNativePrepareRetirementWorker"], list(reversed(names))]
        for index in range(len(names)):
            wrong_names.extend((names[:index] + names[index + 1:], names + [names[index]]))
        for wrong in wrong_names:
            with self.subTest(names=wrong), self.assertRaises(ValueError):
                case.native_proof(json.dumps(dict(value, passed_tests=wrong)).encode(), STATE,
                                  "a" * 64, "c" * 64, "RTM-110")

    def test_prepare_retirement_registration_is_unique(self):
        found = []
        for path in COMPAT.glob("test_*.py"):
            for node in ast.parse(path.read_text()).body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                for decorator in node.decorator_list:
                    if (isinstance(decorator, ast.Call) and
                            ast.unparse(decorator.func) == "pytest.mark.compat" and
                            decorator.args and isinstance(decorator.args[0], ast.Constant) and
                            decorator.args[0].value == "RTM-110"):
                        found.append((path.name, node.name))
        self.assertEqual(found, [("test_managed_fuse_interrupt.py", "test_native_prepare_retirement_recovery")])

    def test_filesystem_direct_root_tmp_limits(self):
        for name, key, wrong in (("root", "read_only", False), ("scratch", "read_only", True),
            ("scratch", "device", 1), ("scratch", "type", 0x65735546), ("scratch", "bytes", (512 << 30) + 1),
            ("tmp", "bytes", (32 << 20) + 1), ("tmp", "bytes", 0), ("tmp", "type", 0xef53),
            ("root", "device", True), ("root", "type", True), ("bounded", "device", 2),
            ("bounded", "bytes", (128 << 20) + 1), ("bounded", "read_only", True)):
            value = proof(); value[name][key] = wrong
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                case.native_proof(json.dumps(value).encode(), STATE, "a" * 64, "c" * 64)

    def test_archive_exact_oci_hashes_one_image_static_root(self):
        plan = smoke.names("a" * 32)
        result = case.image_archive(b"native", b"setup", b"formatter", plan)
        self.assertEqual(result, case.image_archive(b"native", b"setup", b"formatter", plan))
        archive, config, tag = result
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            self.assertEqual(json.loads(outer.extractfile("oci-layout").read()), {"imageLayoutVersion": "1.0.0"})
            index = json.loads(outer.extractfile("index.json").read())
            self.assertEqual(len(index["manifests"]), 1)
            def data(desc):
                raw = outer.extractfile("blobs/sha256/" + desc["digest"].split(":")[1]).read()
                self.assertEqual(len(raw), desc["size"]); self.assertEqual(direct._digest(raw), desc["digest"])
                return raw
            desc = index["manifests"][0]
            self.assertEqual(set(desc["annotations"].values()), {tag})
            self.assertTrue(tag.endswith(desc["digest"].split(":")[1]))
            manifest = json.loads(data(desc)); self.assertEqual(len(manifest["layers"]), 1)
            self.assertEqual(json.loads(data(manifest["config"])), config)
            layer = data(manifest["layers"][0])
            self.assertEqual(config["rootfs"]["diff_ids"], [direct._digest(layer)])
            self.assertEqual(config["config"]["Labels"][smoke.OWNER], plan["owner"])
            self.assertEqual(config["config"]["Cmd"], ["/setup", "RTM-081"])
            self.assertEqual(config["config"]["User"], "0:0")
            with tarfile.open(fileobj=io.BytesIO(layer)) as inner:
                self.assertEqual(inner.getnames(), ["native.test", "setup", "mke2fs", "mke2fs.sha256", "scratch", "tmp"])
                for name, raw in (("native.test", b"native"), ("setup", b"setup")):
                    self.assertEqual(inner.extractfile(name).read(), raw)
                    self.assertEqual(inner.getmember(name).mode, 0o755)
                self.assertTrue(inner.getmember("scratch").isdir())
        for native, helper in ((b"", b"x"), (b"x", b"")):
            with self.assertRaises(ValueError): case.image_archive(native, helper, b"formatter", plan)
        other = case.image_archive(b"native", b"setup", b"formatter", smoke.names("b" * 32))
        self.assertNotEqual(other[2], tag)  # Owned image cannot deduplicate another campaign's config.

    def test_fsx_image_requires_exact_input_and_leaves_old_cases_unchanged(self):
        plan = smoke.names("a" * 32)
        for raw in (None, b"", b"not-pinned"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                case.image_archive(b"native", b"setup", b"formatter", plan, "RTM-085", fsx=raw)
        for case_id in ("RTM-081", "RTM-082", "RTM-083", "RTM-087"):
            with self.assertRaises(ValueError):
                case.image_archive(b"native", b"setup", b"formatter", plan, case_id, fsx=b"extra")
        raw = b"pinned-fsx"
        with patch.object(artifact, "validate_fsx", return_value=raw) as validate:
            archive, config, _ = case.image_archive(b"native", b"setup", b"formatter", plan, "RTM-085", fsx=raw)
            validate.assert_called_once_with(raw)
        with tarfile.open(fileobj=io.BytesIO(archive)) as outer:
            layer = outer.extractfile("blobs/sha256/" + config["rootfs"]["diff_ids"][0].split(":")[1]).read()
            with tarfile.open(fileobj=io.BytesIO(layer)) as inner:
                member = inner.getmember("fsx")
                self.assertTrue(member.isreg()); self.assertEqual(member.mode, 0o755)
                self.assertEqual(member.uid, 0); self.assertEqual(member.gid, 0)
                self.assertEqual(inner.extractfile(member).read(), raw)
                self.assertEqual(inner.getnames().count("fsx"), 1)
        source = ast.unparse(next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "run_campaign"))
        self.assertIn("if case_id == 'RTM-085':", source)
        self.assertLess(source.index('artifact.load_fsx'), source.index('client.images.load'))
        self.assertIn("record('fsx-input', bytes=len(fsx), sha256=smoke.digest(fsx))", source)

    def test_wrapper_private_group_original_pin_timeout_retains(self):
        root = Path("/private/owned-root")
        daemon = SimpleNamespace(root=root, binary=Path("/private/bin"), socket=Path("/private/socket"), work=Path("/private/work"))
        pin = {"mode": "lifecycle", "identity": [1, 2]}
        process = Mock(pid=12345, returncode=None)
        process.wait.side_effect = [subprocess.TimeoutExpired("private", 234), 0]
        fail = Mock(side_effect=ValueError("public failure"))
        with patch.dict(backend._ROOT_PINS, {str(root.absolute()): pin}), \
             patch.dict(case.__dict__, pytest=SimpleNamespace(fail=fail), retain_failure=Mock()) as _ignored, \
             patch.object(subprocess, "Popen", return_value=process) as popen, \
             patch.object(os, "killpg") as kill, patch.object(time, "monotonic", return_value=100):
            with self.assertRaisesRegex(ValueError, "public failure"): case.test_native_managed_fuse_interrupt(daemon)
            self.assertTrue(daemon._retain_root)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertEqual(json.loads(popen.call_args.args[0][-2]), pin)
            self.assertEqual(popen.call_args.args[0][-1], "RTM-081")
            self.assertEqual(process.wait.call_args_list[0].kwargs["timeout"], 234)
            kill.assert_called_once_with(12345, signal.SIGKILL)
            case.retain_failure.assert_called_once_with(daemon, 340)
            self.assertFalse(fail.call_args.kwargs["pytrace"])

    def test_fixture_requires_source_pins_without_startup_optin(self):
        fake = SimpleNamespace(managed_storage_arguments=lambda env: [])
        with patch.dict(sys.modules, conftest=fake), patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "parent-built pinned fixture"):
                case.image_cache("no-cache")
        with patch.dict(sys.modules, conftest=fake), patch.dict(os.environ, CENGINE_RTM081_FIXTURE="/owned", CENGINE_RTM081_FIXTURE_SHA256="a"*64):
            self.assertEqual(case.image_cache("no-cache"), "no-cache")
        self.assertIsNone(case.verify_docker_cli_target())

    def test_private_failure_logs_bounded_streaming_and_redacted(self):
        secret = b'SECRET_TOKEN=/private/key traceback panic password'
        for stdout, stderr in ((b'{"success":false,"secret":"' + secret + b'"}', secret),
                               (b'{malformed:' + secret, secret), (secret * 1000, secret)):
            with self.subTest(size=len(stdout)), tempfile.TemporaryDirectory() as temp:
                campaign, client, container, plan, streams = diagnostic_fixture(stdout, stderr)
                with patch.object(time, "monotonic", return_value=100):
                    result = case.failure_logs(campaign, client, Path(temp), plan, "RTM-082", container.id, 332)
                self.assertEqual(result["status"], "retained")
                self.assertEqual(set(result), {"status", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256", "limit_reached"})
                out = stdout[:case.FAILURE_LOG_BYTES]
                err = stderr[:case.FAILURE_LOG_BYTES - len(out)]
                self.assertEqual((result["stdout_bytes"], result["stderr_bytes"]), (len(out), len(err)))
                self.assertEqual((result["stdout_sha256"], result["stderr_sha256"]), (smoke.digest(out), smoke.digest(err)))
                self.assertEqual(result["limit_reached"], len(out + err) == case.FAILURE_LOG_BYTES)
                self.assertNotIn("SECRET", json.dumps(result)); self.assertNotIn(temp, json.dumps(result))
                payload = bytearray()
                for index in range((len(out + err) + 4095) // 4096):
                    token = smoke.digest((plan["owner"] + ":native-failure:" + str(index)).encode())[:32]
                    path = Path(temp) / ("rtm078-api-error-" + token + ".log")
                    info = path.lstat()
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                    self.assertEqual(info.st_nlink, 1)
                    self.assertLessEqual(info.st_size, 4096)
                    payload.extend(path.read_bytes())
                self.assertEqual(bytes(payload), out + err)
                self.assertLessEqual(len(payload), 16384)
                self.assertEqual(len(list(Path(temp).iterdir())), (len(payload) + 4095) // 4096)
                for stream in streams: stream.close.assert_called_once()
                client.containers.get.assert_called_once_with(container.id)
                self.assertEqual(campaign.api_deadline.call_args.args[-1], 103)
                self.assertEqual(campaign.read_logs.call_args.args[-1], 103)
                # Fresh files only: a second capture never overwrites evidence.
                with patch.object(time, "monotonic", return_value=100):
                    self.assertEqual(case.failure_logs(campaign, client, Path(temp), plan, "RTM-082", container.id, 332),
                                     {"status": "unavailable"})

    def test_failure_logs_reject_identity_missing_and_expired(self):
        for mutation in ("id", "name", "owner", "case", "test", "extra-label", "cmd", "missing", "unselected", "expired"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                campaign, client, container, plan, _ = diagnostic_fixture()
                selected = container.id
                if mutation == "id": container.id = "d" * 64
                if mutation == "name": container.name = "other"
                if mutation in ("owner", "case", "test", "extra-label"):
                    key = {"owner": smoke.OWNER, "case": case.CASE_LABEL, "test": case.TEST_LABEL, "extra-label": "extra"}[mutation]
                    container.attrs["Config"]["Labels"][key] = "PRIVATE"
                if mutation == "cmd": container.attrs["Config"]["Cmd"] = ["/setup", "RTM-081"]
                if mutation == "missing": client.containers.get.side_effect = ValueError("PRIVATE missing")
                if mutation == "unselected": selected = None
                with patch.object(time, "monotonic", return_value=100):
                    result = case.failure_logs(campaign, client, Path(temp), plan, "RTM-082", selected,
                                               100 if mutation == "expired" else 332)
                self.assertNotEqual(result["status"], "retained")
                campaign.read_logs.assert_not_called(); container.logs.assert_not_called()
                self.assertEqual(list(Path(temp).iterdir()), [])
                self.assertNotIn("PRIVATE", json.dumps(result))
                if mutation in ("expired", "unselected"): client.containers.get.assert_not_called()

    def test_failure_logs_deadline_shared_and_private_root_safety(self):
        for failure in (None, "inspect-late", "logs-late", "logs-error", "write-error", "root-link", "file-link", "root-mode"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "root"; root.mkdir(mode=0o700)
                campaign, client, container, plan, _ = diagnostic_fixture()
                now = [100]
                def inspect(_):
                    if failure == "inspect-late": now[0] = 101
                    return container
                client.containers.get.side_effect = inspect
                if failure == "logs-late":
                    def late(*args):
                        now[0] = 101
                        return b"PRIVATE", b""
                    campaign.read_logs.side_effect = late
                if failure == "logs-error": campaign.read_logs.side_effect = TimeoutError("PRIVATE")
                if failure == "root-link":
                    link = Path(temp) / "link"; link.symlink_to(root, target_is_directory=True); root = link
                if failure == "file-link":
                    target = Path(temp) / "target"; target.write_bytes(b"unchanged")
                    token = smoke.digest((plan["owner"] + ":native-failure:0").encode())[:32]
                    (root / ("rtm078-api-error-" + token + ".log")).symlink_to(target)
                if failure == "root-mode": root.chmod(0o777)
                writer = patch.object(smoke, "write_private_error", side_effect=OSError("PRIVATE")) if failure == "write-error" else nullcontext()
                with patch.object(time, "monotonic", side_effect=lambda: now[0]), writer:
                    result = case.failure_logs(campaign, client, root, plan, "RTM-082", container.id, 101)
                self.assertEqual(result["status"], "retained" if failure is None else "unavailable")
                self.assertEqual(campaign.api_deadline.call_args.args[-1], 101)
                if failure == "inspect-late": campaign.read_logs.assert_not_called()
                else: self.assertEqual(campaign.read_logs.call_args.args[-1], 101)
                if failure == "file-link": self.assertEqual(target.read_bytes(), b"unchanged")
                if failure in ("inspect-late", "logs-late", "logs-error", "write-error", "root-link", "root-mode"):
                    self.assertEqual(list(root.iterdir()), [])

    def test_failure_private_writer_stall_does_not_hold_cleanup_budget(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def blocked(*args):
            entered.set()
            try:
                release.wait(5)
            finally:
                finished.set()
        with tempfile.TemporaryDirectory() as temp, patch.object(smoke, "write_private_error", side_effect=blocked):
            campaign, client, container, plan, _ = diagnostic_fixture()
            started = time.monotonic()
            try:
                result = case.failure_logs(campaign, client, Path(temp), plan, "RTM-082", container.id, started + 0.1)
                self.assertTrue(entered.is_set())
                self.assertEqual(result, {"status": "unavailable"})
                self.assertLess(time.monotonic() - started, 1)
                self.assertFalse(finished.is_set())
            finally:
                release.set()
                self.assertTrue(finished.wait(1))

    def test_campaign_real_journal_owned_cleanup_and_failed_evidence(self):
        from contextlib import nullcontext
        class Missing(Exception):
            status_code = 404
        token = "a" * 32
        self.enterContext(patch.object(artifact, "validate_fsx", side_effect=lambda raw: raw))
        fsx_loader = self.enterContext(patch.object(artifact, "load_fsx", return_value=b"pinned-fsx"))
        for case_id, failure in [(selected, failure) for selected in case.TESTS
                                 for failure in (None, "native", "source", "image-owner", "image-tag", "image-layer", "image-command", "image-labels",
                                                 "owner", "selection", "container-name", "volume-name", "proof-case", "proof-test", "running", "malformed", "stderr", "cleanup")]:
            with self.subTest(case_id=case_id, failure=failure), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                retained, creates, removed, stopped = [], [], [], []
                plan = smoke.names(token)
                native, helper = b"native", b"helper"
                fsx_loader.reset_mock()
                _, config, tag = case.image_archive(native, helper, b"formatter", plan, case_id,
                    fsx=b"pinned-fsx" if case_id == "RTM-085" else None)
                labels = {smoke.OWNER: token}
                image = SimpleNamespace(id="sha256:owned", attrs={"RepoTags": [tag], "Architecture": "arm64", "Os": "linux",
                    "Config": copy.deepcopy(config["config"]), "RootFS": {"Layers": config["rootfs"]["diff_ids"]}})
                volume = SimpleNamespace(name=plan["volume"], attrs={"Labels": labels})
                container = SimpleNamespace(id="c" * 64, name=plan["containers"][0], attrs={"Config": copy.deepcopy(config["config"]),
                    "State": dict(STATE, Running=failure == "running")}, start=Mock(), reload=Mock())
                inventories = {"image": {}, "volume": {}, "container": {}}
                def collection(kind, value):
                    def create(*args, **kwargs):
                        creates.append((kind, kwargs)); inventories[kind][getattr(value, "name", tag)] = value
                        # Pre-start inspect exposes the submitted command, not a
                        # boot-time resolution of an omitted image default.
                        if kind == "container": value.attrs["Config"]["Cmd"] = kwargs.get("command", [])
                        if kind == "image" and failure == "image-owner": value.attrs["Config"]["Labels"] = {smoke.OWNER: "b" * 32}
                        if kind == "image" and failure == "image-tag": value.attrs["RepoTags"] = ["unowned:tag"]
                        if kind == "image" and failure == "image-layer": value.attrs["RootFS"]["Layers"] = ["sha256:" + "e" * 64]
                        if kind == "image" and failure == "image-command": value.attrs["Config"]["Cmd"] = ["/setup", "RTM-084"]
                        if kind == "image" and failure == "image-labels": value.attrs["Config"]["Labels"][case.TEST_LABEL] = "other"
                        if kind == "container" and failure == "container-name": value.name = "unowned"
                        if kind == "volume" and failure == "volume-name": value.name = "unowned"
                        if kind == "container" and failure == "owner": value.attrs["Config"]["Labels"] = {smoke.OWNER: "b" * 32}
                        if kind == "container" and failure == "selection": value.attrs["Config"]["Cmd"] = ["/setup", "RTM-084"]
                        return value
                    def get(name):
                        if kind == "container" and name == container.id and inventories[kind]: return container
                        if name not in inventories[kind]: raise Missing()
                        return inventories[kind][name]
                    def remove(*args, **kwargs):
                        removed.append(kind)
                        if not (failure == "cleanup" and kind == "container"):
                            inventories[kind].clear()
                    value.remove = remove
                    value.stop = lambda **kwargs: stopped.append(kind)
                    return SimpleNamespace(create=create, get=get, remove=remove,
                        load=lambda archive: [create()])
                client = SimpleNamespace(version=lambda: {"GitCommit": "commit"}, close=Mock(), api=SimpleNamespace(),
                    images=collection("image", image), volumes=collection("volume", volume), containers=collection("container", container))
                observed = proof(case_id); observed["test_sha256"] = smoke.digest(native); observed["formatter_sha256"] = smoke.digest(b"formatter")
                if failure == "native": observed["skips"] = 1
                if failure == "proof-case": observed["case"] = "RTM-082" if case_id == "RTM-081" else "RTM-081"
                if failure == "proof-test": observed["test"] = case.TESTS["RTM-082" if case_id == "RTM-081" else "RTM-081"]
                if failure == "running": observed.update(success=False, exit=1, passes=0)
                logs = [bytearray(json.dumps(observed).encode()), bytearray()]
                if failure == "malformed": logs[0] = bytearray(b'{malformed SECRET_TOKEN=/private/key traceback')
                if failure == "stderr": logs[1] = bytearray(b'SECRET_TOKEN=/private/key traceback')
                def read_logs(*args):
                    self.assertEqual(stopped, [])  # Capture precedes failure cleanup.
                    return logs
                campaign = SimpleNamespace(api_call=lambda client, deadline, operation, *a, **kw: operation(*a, **kw),
                    api_deadline=lambda *a: nullcontext(), read_logs=Mock(side_effect=read_logs))
                daemon = SimpleNamespace(binary=Path("/owned/bin"), socket=Path("/owned/socket"), root=root,
                                         retain_root=lambda **kw: retained.append(kw))
                def load_fake(selected):
                    self.assertEqual(selected, case_id)
                    if failure == "source": raise ValueError("source mismatch")
                    return {"sources": {"Guest/go.mod": "d" * 64}, "builder": {}, "toolchain": {}, "cleanup": {}}, {"native.test": native, "setup": helper, "mke2fs": b"formatter"}
                namespace = dict(REPO_ROOT=root, MAX_PROBES=2, load_inputs=load_fake,
                    uuid=SimpleNamespace(uuid4=lambda: SimpleNamespace(hex=token)),
                    docker=SimpleNamespace(DockerClient=lambda **kwargs: client, errors=SimpleNamespace(APIError=Missing)))
                with patch.dict(case.__dict__, namespace), patch.dict(sys.modules,
                    conftest=SimpleNamespace(expected_git_commit=lambda binary: "commit"),
                    test_volume_workflows=SimpleNamespace(_campaign=campaign)), \
                    patch.dict(os.environ, CENGINE_RTM081_FIXTURE_SHA256="a" * 64, CENGINE_RTM085_FSX="/owned/fsx"), \
                    patch.object(shutil, "disk_usage", return_value=SimpleNamespace(free=4 << 30)), patch.object(time, "sleep"):
                    if failure:
                        with self.assertRaises((ValueError, TimeoutError)) as raised:
                            case.run_campaign(daemon, time.monotonic(), case_id)
                        if failure == "running":
                            self.assertIs(type(raised.exception), TimeoutError)
                            self.assertEqual(str(raised.exception), "native probe count")
                    else:
                        case.run_campaign(daemon, time.monotonic(), case_id)
                lines = [json.loads(line) for line in (root / ".build/managed-storage-smoke" / token / "evidence.jsonl").read_text().splitlines()]
                self.assertEqual(lines[0]["selected_containers"], [plan["containers"][0]])
                self.assertEqual((lines[0]["case"], lines[0]["test"]), (case_id, case.TESTS[case_id]))
                self.assertEqual(lines[-1]["phase"], "cleanup")
                self.assertEqual(lines[-1]["retained"], failure is not None)
                self.assertEqual(bool(retained), failure is not None)
                client.close.assert_called_once()
                fsx_rows = [line for line in lines if line["phase"] == "fsx-input"]
                if case_id == "RTM-085" and failure != "source":
                    fsx_loader.assert_called_once_with("/owned/fsx")
                    self.assertEqual(fsx_rows, [{"phase": "fsx-input", "bytes": len(b"pinned-fsx"),
                                                "sha256": smoke.digest(b"pinned-fsx")}])
                else:
                    fsx_loader.assert_not_called(); self.assertEqual(fsx_rows, [])
                if failure is None:
                    self.assertEqual([kind for kind, _ in creates], ["image", "volume", "container"])
                    self.assertEqual(removed, ["container", "volume", "image"])
                    self.assertEqual(stopped, [])
                    self.assertEqual(len([v for v in lines if v["phase"] == "native-pass"]), 1)
                    expected = config["config"]
                    self.assertEqual(creates[-1][1]["labels"], expected["Labels"])
                    self.assertEqual(creates[-1][1]["command"], expected["Cmd"])
                    self.assertEqual(expected["Cmd"], ["/setup", case_id])
                elif failure != "cleanup":
                    self.assertEqual(removed, [])
                if failure in ("owner", "container-name"): self.assertEqual(stopped, [])
                if failure == "source": self.assertEqual(creates, [])
                self.assertNotIn("SECRET_TOKEN", json.dumps(lines))
                self.assertNotIn("/private/key", json.dumps(lines))
                if failure in ("native", "proof-case", "proof-test", "running", "malformed", "stderr"):
                    diagnostic = next(line for line in lines if line["phase"] == "failure-logs")
                    self.assertEqual(diagnostic["status"], "retained")
                    self.assertEqual(diagnostic["stdout_sha256"], smoke.digest(logs[0]))
                    self.assertEqual(diagnostic["stderr_sha256"], smoke.digest(logs[1]))
                    self.assertEqual(stopped, ["container"])
                    self.assertFalse(any(line["phase"] == "native-pass" for line in lines))
                    self.assertEqual(campaign.read_logs.call_count, 1 if failure == "running" else 2)
                    self.assertEqual(sum(path.stat().st_size for path in root.glob("rtm078-api-error-*.log")), sum(map(len, logs)))

    def test_static_exact_single_owned_resources_no_exec_no_assert(self):
        calls = [node for node in ast.walk(TREE) if isinstance(node, ast.Call)]
        creates = [node for node in calls if ast.unparse(node.func) == "call" and node.args and ast.unparse(node.args[0]) == "client.containers.create"]
        self.assertEqual(len(creates), 1)
        kw = {item.arg: ast.literal_eval(item.value) for item in creates[0].keywords if item.arg in
              {"privileged", "read_only", "network_mode", "mem_limit", "nano_cpus", "pids_limit", "tmpfs"}}
        self.assertEqual(kw, dict(privileged=True, read_only=True, network_mode="none", mem_limit="768m",
            nano_cpus=1000000000, pids_limit=128, tmpfs={"/tmp": "rw,nosuid,nodev,size=32m"}))
        mounts = [node for node in calls if ast.unparse(node.func) == "Mount"]
        self.assertEqual(len(mounts), 1)
        self.assertTrue(next(ast.literal_eval(k.value) for k in mounts[0].keywords if k.arg == "no_copy"))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(TREE)))
        self.assertFalse(any("exec_" in ast.unparse(node.func) or "prune" in ast.unparse(node.func) for node in calls))
        source = (COMPAT / "fixtures/managed-fuse-native.go").read_text()
        for required in ('"-test.count=1"', '"-test.timeout=90s"', '"-test.run=^(" + testName + ")$"',
                         '"TMPDIR=/scratch"', 'syscall.SIGKILL', 'proofErr != nil', 'len(runs) != len(expected)', 'len(passes) != len(expected)',
                         'r.Root.Device == r.Scratch.Device', 'fields[separator+1] != "ext4"', 'unix.O_EXCL'):
            self.assertIn(required, source)
        for required in ('LOOP_CONFIGURE', 'IoctlLoopConfigure', 'LO_FLAGS_AUTOCLEAR', 'Sizelimit: backingBytes',
                         'backingBytes = 128 << 20', 'command.ExtraFiles = []*os.File{l.backing}',
                         '"/proc/self/fd/3", "32768"', 'Cloneflags: unix.CLONE_NEWNS', 'syscall.Exec("/native.test"',
                         'LoopClean = true', 'FormatterChecked = true'):
            self.assertIn(required, source)
        self.assertNotIn("asyncpreemptoff", source)
        self.assertNotIn("signal.Ignore", source)
        self.assertGreaterEqual(source.count('exec.CommandContext('), 1)
        self.assertNotIn('compile_binaries', ast.unparse(TREE))
        self.assertFalse(any(ast.unparse(node.func) == 'subprocess.run' for node in calls))
        self.assertIn('if command.ProcessState != nil', source)
        native = (ROOT / "Guest/internal/storagefuse/native_interrupt_linux_test.go").read_text()
        for required in ("gate.entered", "unix.Tgkill", "runtime.LockOSThread", "completedInterrupt", "deliveredDespiteInterrupt"):
            self.assertIn(required, native)
        docs = (ROOT / "docs/docker-compatibility.md").read_text()
        self.assertEqual(docs.count('| `RTM-081` |'), 1)
        self.assertEqual(docs.count('| `RTM-082` |'), 1)
        row = next(line for line in docs.splitlines() if line.startswith('| `RTM-082` |'))
        self.assertIn('test_native_managed_fuse_write_burst', row)
        self.assertIn('pwrite(2)', row)
        self.assertEqual(docs.count('| `RTM-083` |'), 1)
        row = next(line for line in docs.splitlines() if line.startswith('| `RTM-083` |'))
        self.assertIn('test_native_managed_fuse_sparse_mmap', row)
        for contract in ('mmap(2)', 'msync(2)', 'ftruncate(2)', 'stat(2)', 'lseek(2)'):
            self.assertIn(contract, row)
        # Execution status belongs to dated VM receipts, not source-only guards.


if __name__ == "__main__":
    unittest.main()
